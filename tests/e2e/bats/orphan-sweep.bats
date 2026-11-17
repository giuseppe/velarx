# SPDX-License-Identifier: Apache-2.0
# What a crash of the machine leaves of the `--rm` containers whose rows it
# lost (their rows are volatile, their files are not): the first command of
# the next boot, an engine of its own process (no engine service), removes the
# files no row names, and nothing else; a command of the same boot does not
# look; the engine service does when it starts.  The loss is made as it
# happens: the processes are killed, the rows are deleted from the database
# (what the log that never reached the disk would have held), and the state
# directory loses its boot marker (a boot empties a tmpfs).
# Run it as an ordinary user, or as root.

load helpers
load wait
load run_lib

setup_file () {
    export E2E_NO_DAEMON=1
    run_setup_file
    export DB=$XDG_DATA_HOME/velarx/db.sqlite
    export DATA=$XDG_DATA_HOME/velarx
}

teardown_file () {
    run_teardown_file
}

# sql_ STATEMENT [ARG]: a statement on the store, read or written with no
# velarx command (a command would open the store and sweep)
sql_ () {
    python3 -I - "$DB" "$1" "${2:-}" << 'EOT'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None, timeout=30)
c.execute("pragma foreign_keys = on")
args = (sys.argv[3],) if sys.argv[3] else ()
for row in c.execute(sys.argv[2], args).fetchall():
    print(*row)
EOT
}

id_of () { sql_ "select id from containers where name = ?" "$1"; }

# lose_row ID: the volatile row of the container is not on the disk
lose_row () { sql_ "delete from containers where id = ?" "$1" > /dev/null; }

# the processes of a container and its monitor are gone, as with the power
kill_container () {
    local id=$1 p
    for p in "$(cat "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}/monitor.pid")" "$(cat "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}/pid")"; do
        kill -9 "$p" 2> /dev/null
        e2e_wait_exit "$p" 30
    done
}

# a new boot: the state directory has no marker of this one
new_boot () { rm -f "$XDG_RUNTIME_DIR/velarx/boot-id"; }

# present ID...: which of the files of the containers are there
present () {
    local id found=
    for id in "$@"; do
        for f in "bundles/$id" "logs/$id" "secrets/$id" "podman-api/containers/$id.json"; do
            test -e "$DATA/$f" && found="$found $f"
        done
    done
    echo "$found"
}

# the volumes' directories, by name
volume_dirs () { ls "$DATA/volumes" 2> /dev/null | sort | tr '\n' ' '; }

@test "a power loss loses the row of an --rm container: the first command of the boot removes its files" {
    sh_ volume create named1 > /dev/null || exit 1
    sh_ container create --name keep1 --network none -v named1:/n "$IMAGE" true > /dev/null || exit 1
    sh_ container run -d --rm --name lost1 --network none --log-driver k8s-file -v /anon "$IMAGE" sleep 600 > /dev/null || exit 1
    local lost keep
    lost=$(id_of lost1)
    keep=$(id_of keep1)
    check_match "ids" "^[0-9a-f]{64}$" "$lost"
    # (what the API kept of it, and its secrets: made by the commands that need them)
    mkdir -p "$DATA/podman-api/containers" "$DATA/secrets/$lost"
    echo '{}' > "$DATA/podman-api/containers/$lost.json"
    echo s > "$DATA/secrets/$lost/s"
    anon=$(sql_ "select name from volumes where name not in ('named1')")
    check_match "an anonymous volume" "^[0-9a-f]{64}$" "$anon"
    # (one that `rm` without -v keeps, as podman: no sweep takes it)
    sh_ container create --name rmkept1 --network none -v /kept "$IMAGE" true > /dev/null || exit 1
    sh_ container rm rmkept1 > /dev/null || exit 1
    kept=$(sql_ "select name from volumes where name not in ('named1', '$anon')")
    check_match "the volume rm kept" "^[0-9a-f]{64}$" "$kept"
    kill_container "$lost"
    lose_row "$lost"
    new_boot
    check "its files are on the disk" "bundles/$lost logs/$lost secrets/$lost podman-api/containers/$lost.json" \
        "$(present "$lost" | xargs)"
    check "its anonymous volume is" "$(printf '%s\n' "$anon" "$kept" named1 | sort | tr '\n' ' ')" "$(volume_dirs)"
    # the first command of the boot
    sh_ container list -a > /dev/null
    check "its files are gone" "" "$(present "$lost" | xargs)"
    check "the anonymous volume is gone, the named one and the one rm kept stay" \
        "$(printf '%s\n' "$kept" named1 | sort | tr '\n' ' ')" "$(volume_dirs)"
    check "the row of the volume is gone" "$(printf '%s\n' "$kept" named1 | sort | xargs)" \
        "$(sql_ "select name from volumes order by name" | xargs)"
    check "a container with a row keeps its files" "bundles/$keep podman-api/containers/$keep.json" "$(present "$keep" | xargs)"
    sh_ container rm "$keep" > /dev/null
    sh_ volume rm named1 "$kept" > /dev/null
}

@test "a command of the same boot does not look" {
    local id
    id=$(printf 'c%.0s' $(seq 64))
    mkdir -p "$DATA/bundles/$id/overlay/upper" "$DATA/logs/$id"
    sh_ container run --rm --network none "$IMAGE" true > /dev/null || exit 1
    sh_ container list -a > /dev/null
    check "a command that finds the boot done leaves it" "bundles/$id logs/$id" "$(present "$id" | xargs)"
}

@test "the engine service removes what no row names when it starts" {
    local id
    id=$(printf 'c%.0s' $(seq 64))
    check "left by a process killed while it made the container" "bundles/$id logs/$id" "$(present "$id" | xargs)"
    E2E_NO_DAEMON= start_daemon
    check "the service removed it" "" "$(present "$id" | xargs)"
    stop_daemon
}

@test "a name that is not a container id is left alone" {
    mkdir -p "$DATA/bundles/not-an-id" "$DATA/logs/xyz"
    new_boot
    sh_ container list -a > /dev/null
    check "not ours" 0 "$(test -d "$DATA/bundles/not-an-id" && test -d "$DATA/logs/xyz"; echo $?)"
    rmdir "$DATA/bundles/not-an-id" "$DATA/logs/xyz"
}
