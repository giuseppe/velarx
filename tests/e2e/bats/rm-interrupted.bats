# SPDX-License-Identifier: Apache-2.0
# End to end tests of an `--rm` container whose monitor is killed (SIGKILL)
# while it ends the container, with no engine service running: every command
# is an engine of its own process, and the next one that opens the store
# finishes what the monitor left, whichever step it was at.  The OCI runtime
# of the file is a script that blocks in `delete` while the file `hold` is
# there: the monitor has recorded the exit and has not removed the container.
# Run it as an ordinary user, or as root.

load helpers
load wait
load run_lib

setup_file () {
    export E2E_NO_DAEMON=1
    run_setup_file
    export RT=$WORKDIR/rt
    mkdir -p "$RT"
    cat > "$WORKDIR/hook-runtime" << EOT
#!/bin/sh
# crun, except that the first \`delete\` of a monitor while \$RT/hold is there tells who asked and waits
for a in "\$@"; do
    if [ "\$a" = delete ] && [ -e "$RT/hold" ] && grep -q '^velarx-monitor\$' /proc/\$PPID/comm && mkdir "$RT/hold.taken" 2> /dev/null; then
        echo \$PPID > "$RT/hold.monitor"
        echo \$\$ > "$RT/hold.pid"
        echo held >> "$RT/held"
        exec sleep 3600
    fi
done
exec $(command -v crun) "\$@"
EOT
    chmod +x "$WORKDIR/hook-runtime"
    sed -i "s|^\[server\]|[server]\nruntime = \"$WORKDIR/hook-runtime\"|" "$CONFIG"
}

teardown_file () {
    [ -z "${RT:-}" ] || kill "$(cat "$RT/hold.pid" 2> /dev/null)" 2> /dev/null
    run_teardown_file
}

# the row as the database has it, read with no velarx command (a command would
# open the store and finish what is left)
store_row () {
    python3 -I - "$XDG_DATA_HOME/velarx/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
r = c.execute("select state, exit_code, removing from containers where name = ?", (sys.argv[2],)).fetchone()
print("gone" if r is None else "%s %s %s" % r)
EOT
}

# the id of a container, from the store
id_of () {
    python3 -I - "$XDG_DATA_HOME/velarx/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
r = c.execute("select id from containers where name = ?", (sys.argv[2],)).fetchone()
print("" if r is None else r[0])
EOT
}

# held_run NAME [OPTIONS...]: an --rm container that exits at once, whose
# monitor blocks in the runtime's delete; the monitor is killed there, and so
# is the delete.  The exit is in the store (stopped, the removal due), the
# container is not removed.  $id is its id.
held_run () {
    local name=$1 mon
    shift
    rm -rf "$RT/held" "$RT/hold.monitor" "$RT/hold.pid" "$RT/hold.taken"
    : > "$RT/held"
    touch "$RT/hold"
    sh_ container run -d --rm --name "$name" --network none "$@" "${RUN_IMAGE:-$IMAGE}" sh -c 'exit 3' > /dev/null
    check "$name: it starts" 0 $?
    e2e_wait_line "$RT/held" '^held$' 30 || e2e_die "the monitor of $name did not reach the delete"
    mon=$(cat "$RT/hold.monitor")
    id=$(id_of "$name")
    check "$name: the exit is recorded and the removal is due" "stopped 3 1" "$(store_row "$name")"
    kill -9 "$mon"
    e2e_wait_exit "$mon" 30
    kill "$(cat "$RT/hold.pid")"
    rm -f "$RT/hold"
    check "$name: nothing removed it" "stopped 3 1" "$(store_row "$name")"
    test -d "$XDG_DATA_HOME/velarx/bundles/$id"
    check "$name: its bundle is there" 0 $?
}

# the number of names of the repository $1, read with no velarx command
tags_of () {
    python3 -I - "$XDG_DATA_HOME/velarx/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
print(c.execute("select count(*) from image_tags where repository = ?", (sys.argv[2],)).fetchone()[0])
EOT
}

removed_events () {
    sh_ events --stream=false --since 1h --filter event=remove 2>&1 | grep -c "$1"
}

@test "the monitor is killed before it removes an --rm container: a listing finishes the removal" {
    held_run ri1
    out=$(sh_ container list -a 2>&1)
    check "the listing does not show it" 0 "$(echo "$out" | grep -c ri1)"
    check "its row is gone" gone "$(store_row ri1)"
    check "its bundle is gone" no "$(test -e "$XDG_DATA_HOME/velarx/bundles/$id" && echo yes || echo no)"
    check "its monitor directory is gone" no "$(test -e "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}" && echo yes || echo no)"
    check "its removal is an event, once" 1 "$(removed_events "$id")"
    # (nothing is left for the next command)
    sh_ container list -a > /dev/null
    check "the removal is not told again" 1 "$(removed_events "$id")"
}

@test "the monitor is killed before it removes an --rm container: the name is free for the next run" {
    held_run ri2
    out=$(sh_ container run --rm --name ri2 --network none "$IMAGE" echo again 2>&1)
    check "the same name runs again" again "$out"
    check "and goes" gone "$(store_row ri2)"
}

@test "the monitor is killed before it removes an --rm container: rm and start find it gone" {
    held_run ri3
    out=$(sh_ container start ri3 2>&1)
    check "start finds no container" 1 "$(test $? != 0 && echo 1)"
    check_match "start says there is none" "no such container|not found|No such" "$out"
    check "its row is gone" gone "$(store_row ri3)"
}

@test "the monitor is killed before it removes an --rm --rmi container: the name it was made with goes" {
    sh_ image tag "$IMAGE" localhost/ri-rmi:1 > /dev/null
    RUN_IMAGE=localhost/ri-rmi:1 held_run ri4 --rmi
    check "the name is still there" 1 "$(tags_of localhost/ri-rmi)"
    sh_ container list -a > /dev/null
    check "its row is gone" gone "$(store_row ri4)"
    # (the image has another name: only the one the container was made with is untagged)
    check "the name goes" 1 "$(sh_ image exists localhost/ri-rmi:1 > /dev/null 2>&1; echo $?)"
    check "the image stays under its other name" 0 "$(sh_ image exists "$IMAGE" > /dev/null 2>&1; echo $?)"
}

@test "a removal left half done (files gone, the exit file too) is finished" {
    held_run ri5
    # the removal had begun: the logs and the exit file were removed
    rm -rf "$XDG_DATA_HOME/velarx/logs/$id" "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}/exit"
    sh_ container list -a > /dev/null
    check "its row is gone" gone "$(store_row ri5)"
    check "its bundle is gone" no "$(test -e "$XDG_DATA_HOME/velarx/bundles/$id" && echo yes || echo no)"
    check "its monitor directory is gone" no "$(test -e "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}" && echo yes || echo no)"
}

@test "a monitor that lives is left to finish: no command removes under it" {
    rm -rf "$RT/held" "$RT/hold.monitor" "$RT/hold.pid" "$RT/hold.taken"
    : > "$RT/held"
    touch "$RT/hold"
    sh_ container run -d --rm --name ri6 --network none "$IMAGE" sh -c 'exit 4' > /dev/null
    e2e_wait_line "$RT/held" '^held$' 30 || e2e_die "the monitor of ri6 did not reach the delete"
    id=$(id_of ri6)
    check "the removal is due" "stopped 4 1" "$(store_row ri6)"
    sh_ container list -a > /dev/null
    sh_ container run --rm --network none "$IMAGE" true > /dev/null
    check "commands leave it to its monitor" "stopped 4 1" "$(store_row ri6)"
    test -d "$XDG_DATA_HOME/velarx/bundles/$id"
    check "its bundle stays" 0 $?
    # the delete fails (killed), the monitor goes on with the removal
    rm -f "$RT/hold"
    kill "$(cat "$RT/hold.pid")"
    wait_removed ri6 || e2e_die "its monitor did not remove ri6"
    check "its row is gone" gone "$(store_row ri6)"
    check "removed once" 1 "$(removed_events "$id")"
}

# the monitor is killed after the container ended, while its exit is not in
# the store (the database is held): the exit file says what happened, and the
# next command records it and removes the container
@test "the monitor is killed before it records the exit of an --rm container: the next command does" {
    local release=$WORKDIR/ri7.release mon
    rm -rf "$release" "$WORKDIR/ri7"
    mkfifo "$release"
    mkdir "$WORKDIR/ri7"
    mkfifo "$WORKDIR/ri7/go"
    # (it exits once the database is held)
    sh_ container run -d --rm --name ri7 --network none -v "$WORKDIR/ri7:/x:z" "$IMAGE" sh -c 'cat /x/go; exit 5' > /dev/null
    check "it starts" 0 $?
    id=$(id_of ri7)
    mon=$(monitor_of ri7)
    check_match "its monitor" "^[0-9]+$" "$mon"
    python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None, timeout=30)
c.execute("BEGIN IMMEDIATE")
print("held", flush=True)
open(sys.argv[2]).read()
c.execute("ROLLBACK")
' "$XDG_DATA_HOME/velarx/db.sqlite" "$release" > "$WORKDIR/ri7.held" 2>&1 3>&- &
    local holder=$!
    e2e_wait_line "$WORKDIR/ri7.held" '^held$' 10 || e2e_die "the database is not held"
    echo > "$WORKDIR/ri7/go"
    # (the exit file is written first, then the monitor waits for the store)
    e2e_wait_path "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}/exit" 30 || e2e_die "no exit file"
    kill -9 "$mon"
    e2e_wait_exit "$mon" 30
    echo > "$release"
    wait "$holder"
    rm -rf "$release" "$WORKDIR/ri7"
    check_match "the exit is not in the store" "^running" "$(store_row ri7)"
    sh_ container list -a > /dev/null
    check "its row is gone" gone "$(store_row ri7)"
    check "its exit is told, once" 1 "$(sh_ events --stream=false --since 1h --filter event=died 2>&1 | grep -c "$id")"
    check "its removal is told, once" 1 "$(removed_events "$id")"
}

# the engine service follows the monitors of the containers it started: one
# that is killed after it recorded the exit of an --rm container has its
# removal finished by the service at once, with no command and no new start
# of the service
@test "the monitor is killed before it removes an --rm container: the engine service that follows it finishes the removal" {
    E2E_NO_DAEMON= start_daemon
    rm -rf "$RT/held" "$RT/hold.monitor" "$RT/hold.pid" "$RT/hold.taken"
    : > "$RT/held"
    touch "$RT/hold"
    sc container run -d --rm --name ri8 --network none "$IMAGE" sh -c 'exit 6' > /dev/null 3>&-
    check "it starts" 0 $?
    e2e_wait_line "$RT/held" '^held$' 30 || e2e_die "the monitor of ri8 did not reach the delete"
    local mon
    mon=$(cat "$RT/hold.monitor")
    id=$(id_of ri8)
    check "the removal is due" "stopped 6 1" "$(store_row ri8)"
    rm -f "$RT/hold"
    kill -9 "$mon"
    e2e_wait_exit "$mon" 30
    kill "$(cat "$RT/hold.pid")"
    # (asked of the service, which builds its services only at its start: a
    # command of its own would finish the removal itself)
    timeout 30 "$SH" --socket "$ESOCK" container wait --condition removed ri8 > /dev/null 2>&1 3>&-
    check "the service removed it" gone "$(store_row ri8)"
    check "its bundle is gone" no "$(test -e "$XDG_DATA_HOME/velarx/bundles/$id" && echo yes || echo no)"
    check "removed once" 1 "$(removed_events "$id")"
    stop_daemon
}
