# SPDX-License-Identifier: Apache-2.0
# A lazy pull is a pull in progress, not an image of the store: its layers are
# in the staging area (<store>/staging) until they are complete.  It is the
# engine service's of the store (`velarx varlink`, found or started by the
# command that pulls): it fetches the files nobody reads and commits each
# layer to the store and the image with the last, `image pulls` lists the
# pull (`image list --lazy` too), a container with --lazy attaches to it, a
# run without --lazy completes it first, a service that is killed is
# replaced by the next one, an error that retrying cannot mend stops the
# completion with the reason in `image pulls`, rmi cancels the pull, and
# `system df -v` counts it.  With a daemon (the service), and without one (the command starts the service,
# which outlives it; the next command starts another after a kill); a pull
# made with `--creds` keeps them in memory only.  Rootless and root.
#
#   VELARX_BINDIR=target/debug E2E_IMAGE=image bats tests/e2e/bats/lazy-complete.bats
#
# The daemon completes nothing in the background (`[pull] lazy_completers =
# 0`): a pull stays a pull while the test looks at it, until a command waits
# for it.
#
# (LAZY_IMAGE_SEALED=1: the image has the fs-verity digests in its TOCs
# already, as velarx writes them, and is used as it is)

load helpers


setup_file () {
    command -v curl > /dev/null || skip "no curl"
    command -v flock > /dev/null || skip "no flock"
    command -v sqlite3 > /dev/null || skip "no sqlite3"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    cat > "$WORKDIR/sh.toml" <<EOF
[engine]
socket = "$WORKDIR/sh.sock"
[server]
socket = "$WORKDIR/sh.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$WORKDIR/store"
[pull]
EOF
    e2e_hold_completions "$WORKDIR/sh.toml"
    export IMAGE=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    start_daemon

    # Only the layers whose TOCs give the fs-verity digests of their files,
    # which the layer writer gives and containers/storage does not, stay lazy
    # (the others are refused): the image is pushed again by velarx
    # (gzip, and back as zstd:chunked), then the store starts empty.
    if [ -z "${LAZY_IMAGE_SEALED:-}" ]; then
        local sealed=$E2E_REGISTRY/velarx-e2e/lazy-complete-$$
        { sh_ image pull --tls-verify=false "$IMAGE" &&
          sh_ image push --tls-verify=false --compression-format gzip "$IMAGE" "$sealed:gzip" &&
          sh_ image pull --tls-verify=false "$sealed:gzip" &&
          sh_ image push --tls-verify=false --compression-format zstd:chunked "$sealed:gzip" "$sealed:zstd"
        } > "$WORKDIR/seal.log" 2>&1 || { echo "cannot make the image"; cat "$WORKDIR/seal.log"; exit 1; }
        IMAGE=$sealed:zstd
        fresh_store
    fi
    echo "IMAGE=$IMAGE" > "$WORKDIR/vars"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    local p
    for p in $(cat "$WORKDIR/auth.pids" 2> /dev/null); do kill "$p" 2> /dev/null; done
    . "$E2E_DIR/cleanup.sh"
    e2e_remove_containers "$BIN/velarx" "$WORKDIR/sh.sock"
    stop_daemon
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    e2e_teardown_file
}

setup () {
    set +e
    BASE=$WORKDIR/store/staging
    PULLS=$BASE/pulls
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -f "$WORKDIR/vars" ]; then . "$WORKDIR/vars"; fi
}

start_daemon () {
    # (READY=1 when it serves: no loop of attempts on the socket)
    E2E_SPAWN_LOG=$WORKDIR/sh.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --config "$WORKDIR/sh.toml" varlink || {
        echo "the daemon does not start"; cat "$WORKDIR/sh.log"; return 1; }
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    return 0
}
stop_daemon () {
    kill -INT "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID" 10
    kill -KILL "$DAEMON_PID" 2> /dev/null || :
    DAEMON_PID=
    rm -f "$WORKDIR/daemon.pid"
}
# a store with nothing in it, the daemon restarted on it
fresh_store () {
    stop_daemon
    rm -rf "$WORKDIR/store" "$WORKDIR/root" "$WORKDIR/state"
    start_daemon
}
sh_ () { "$BIN/velarx" --socket "$WORKDIR/sh.sock" "$@"; }

files_in_store () { find "$WORKDIR/store/objects" -type f 2> /dev/null | wc -l; }
# the files staged in the staging directories of the layers
files_in_pool () { find "$BASE/layers" -path '*/files/*' -type f 2> /dev/null | wc -l; }
# the layers a lazy pull staged
staged_layers () { find "$BASE/meta" -name layer.json 2> /dev/null | wc -l; }
db () { sqlite3 "file:$WORKDIR/store/db.sqlite?mode=ro" "$1" 2> /dev/null; }
pulls () { sh_ image pulls --format '{{.State}}' 2>&1; }

# whether a process holds the lease of the pull in progress
lease_held () {
    local id
    id=$(sh_ image pulls -q --no-trunc)
    [ -n "$id" ] || { echo no-pull; return; }
    flock -n "$PULLS/$id/lease" true && echo free || echo held
}

@test "a lazy pull is a pull in progress: the store has nothing of it, image pulls lists it" {
    local out
    out=$(sh_ image pull --lazy --tls-verify=false "$IMAGE" 2>&1)
    check_match "a lazy pull says it goes on in the background" "Pulled \(lazy\)" "$out"
    check "no file is in the store" 0 "$(files_in_store)"
    check "no image is in the store" 0 "$(db 'SELECT count(*) FROM images')"
    check "no layer is in the store" 0 "$(db 'SELECT count(*) FROM layers')"
    check "images does not list it" "" "$(sh_ image list -q)"
    check "its table is podman's" "REPOSITORY TAG IMAGE ID CREATED SIZE" "$(sh_ image list | tr -s ' ' | sed 's/ $//')"
    check_match "images --lazy lists it, LAZY yes" "^${IMAGE%:*} .* yes$" "$(sh_ image list --lazy | tail -n +2 | tr -s ' ')"
    check_match "with its column" " SIZE +LAZY$" "$(sh_ image list --lazy | head -1)"
    check "the filter lazy=true lists it, {{.Lazy}} is true" true "$(sh_ image list --filter lazy=true --format '{{.Lazy}}')"
    check_match "and so does --format json" '"Lazy": true' "$(sh_ image list --filter lazy=true --format json)"
    check_match "image pulls lists it" "^queued$" "$(pulls)"
    check_match "system df -v counts it in the store's usage" "^Pulling +1 +[0-9.]+[kMG]?B " \
        "$(sh_ system df -v 2>&1 | grep '^Pulling')"
    check_match "and the images in podman's rows do not" "^Images +0 " "$(sh_ system df 2>&1 | grep '^Images')"
    check_match "the table has its progress" "^[0-9a-f]{12} .*queued .*[0-9]+%" "$(sh_ image pulls | tail -n +2)"
    sh_ image inspect "$IMAGE" > /dev/null 2>&1
    check "inspect finds no image" yes "$([ $? != 0 ] && echo yes)"
    check_match "another command says it is being pulled" "is being pulled" "$(sh_ image push "$IMAGE" localhost:1/x:1 2>&1)"
    check_match "and so does tag" "is being pulled" "$(sh_ image tag "$IMAGE" localhost/x:1 2>&1)"
    check "the staging has the layer, not the store" yes "$([ "$(staged_layers)" -gt 0 ] && echo yes)"
    check "the engine service holds the pull" held "$(lease_held)"
    check "the state names the service" "\"pid\":$DAEMON_PID" \
        "$(grep -o '"pid":[0-9]*' "$PULLS/$(sh_ image pulls -q --no-trunc)/state.json")"
}

@test "a container attaches with --lazy and reads files into the staging of its layers; the store is still empty" {
    local i
    sh_ container run -d --lazy --network none --name lz "$IMAGE" sleep 600 > /dev/null 2>&1
    check "the container runs on the pull" 0 $?
    check_match "it reads a file of the image" "^[0-9]+\.[0-9]+" "$(sh_ container exec lz cat /etc/alpine-release 2>&1)"
    check_match "the file is in the staging of its layer" "^[1-9][0-9]*$" "$(files_in_pool)"
    check "the store has no file" 0 "$(files_in_store)"
    check "no image is in the store" 0 "$(db 'SELECT count(*) FROM images')"
    check_match "the pull is listed with its container" "^[0-9a-f]{12} .* 1( |$)" "$(sh_ image pulls | tail -n +2)"
    # a container made on a pull in progress holds it: rmi refuses
    check_match "rmi of a pull a container uses is refused" "in use by a container" "$(sh_ image rm "$IMAGE" 2>&1)"
}

@test "the files of a lazy container are fetched by the image server of its root, not by the monitor" {
    local id log srv t name unconfined=
    id=$(sh_ container inspect lz | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    log=$(find "$WORKDIR/state" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat)
    check_match "the root is the image server's mount" "image server of the root file system: pid" "$log"
    check "the monitor serves no file system of its own" 0 "$(printf '%s\n' "$log" | grep -c 'root file system: \(FUSE\|composefs\)')"
    srv=$(printf '%s\n' "$log" | sed -n 's/.*image server of the root file system: pid \([0-9]*\),.*/\1/p' | head -1)
    [ -n "$srv" ] || e2e_die "the monitor does not name the image server"
    check_match "the process is the image server" "image server" "$(tr '\0' ' ' < /proc/$srv/cmdline)"
    # every thread is confined: those that read what the container or a
    # fetcher sends, and the workers that fetch (they read the staging of the
    # staging area and connect to the fetchers), the one that saves the
    # profile and the one that waits for the notices of the file system
    # (`watch`), each with a domain of its own (`confine::fetch_thread`)
    for t in /proc/"$srv"/task/*; do
        name=$(cat "$t/comm")
        grep -q '^Seccomp:[[:space:]]*2$' "$t/status" && grep -q '^NoNewPrivs:[[:space:]]*1$' "$t/status" ||
            unconfined="$unconfined $name"
    done
    check "no thread is unconfined" "" "$unconfined"
    check "the main thread is confined" 2 "$(awk '/^Seccomp:/ {print $2}' /proc/$srv/task/$srv/status)"
    check_match "the server holds the connection to the fetcher" "socket" "$(for f in /proc/$srv/fd/*; do readlink "$f"; done)"
    check_match "and fetched the file into the staging of its layer" "^[1-9][0-9]*$" "$(files_in_pool)"
    echo "$srv" > "$WORKDIR/lazy-server.pid"
}

@test "a server killed under its lazy container: the next start has a new one that fetches" {
    local srv new log id
    srv=$(cat "$WORKDIR/lazy-server.pid" 2> /dev/null)
    [ -n "$srv" ] || { echo "no server of the earlier test (it failed or did not run)" >&2; exit 1; }
    kill -KILL "$srv"
    e2e_wait_exit "$srv" 10
    sh_ container stop -t 0 lz > /dev/null 2>&1
    sh_ container start lz > /dev/null 2>&1
    check "the container starts again" 0 $?
    id=$(sh_ container inspect lz | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    log=$(find "$WORKDIR/state" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat)
    new=$(printf '%s\n' "$log" | sed -n 's/.*image server of the root file system: pid \([0-9]*\),.*/\1/p' | tail -1)
    check "another server" 1 "$([ -n "$new" ] && [ "$new" != "$srv" ] && echo 1)"
    check_match "it reads and fetches files" "^[0-9]+\.[0-9]+" "$(sh_ container exec lz cat /etc/os-release /etc/alpine-release 2>&1)"
}

@test "image complete finishes the pull: layers, then the image, the container goes on" {
    local files before
    # (the service completes it at once: a command waits)
    sh_ image complete "$IMAGE" > /dev/null 2>&1
    check "image complete" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check_match "the image is listed" "$(basename "${IMAGE%:*}")" "$(sh_ image list --format '{{.Repository}}')"
    check "as an image that is not lazy" "false no" "$(sh_ image list --lazy --format '{{.Lazy}} {{.LazyColumn}}')"
    files=$(files_in_store)
    check_match "the files are in the store" "^[1-9][0-9]*$" "$files"
    check "the staging area is empty" "0 0" "$(files_in_pool) $(( $(staged_layers) + $(find "$PULLS" -mindepth 1 2> /dev/null | wc -l) ))"
    check_match "the image of the layer is the store's" "^layer-toc-sha256-[0-9a-f]{64}\.v5\.erofs$" "$(ls "$WORKDIR/store/composefs" | grep erofs)"
    check "the layer and the image are rows" "1 1" "$(db 'SELECT count(*) FROM layers') $(db 'SELECT count(*) FROM images')"
    check_match "the container goes on" "^[0-9]+\.[0-9]+" "$(sh_ container exec lz cat /etc/alpine-release 2>&1)"
    # every file of the container is content of the store (the objects)
    find "$WORKDIR/store/objects" -type f -exec sha256sum {} + | cut -d' ' -f1 | sort -u > "$WORKDIR/stored.sums"
    sh_ container exec lz sh -c 'find /bin /lib /usr/bin /usr/lib /etc -xdev -type f -size +0 | head -300 | xargs sha256sum' 2>&1 \
        | grep -v '  /etc/\(hostname\|hosts\|resolv.conf\)$' | cut -d' ' -f1 | sort -u > "$WORKDIR/read.sums"
    check "what it reads is content of the store" 0 "$(comm -13 "$WORKDIR/stored.sums" "$WORKDIR/read.sums" | grep -vc '^$')"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    check "system check" 0 "$(sh_ system check > /dev/null 2>&1; echo $?)"
}

@test "a run without --lazy completes the pull first, and runs from the store" {
    local out
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "the pull is queued" queued "$(pulls)"
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "it runs the complete image" "^[0-9]+\.[0-9]+" "$out"
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "the image is in the store" 1 "$(db 'SELECT count(*) FROM images')"
    check_match "the files are in the store" "^[1-9][0-9]*$" "$(files_in_store)"
}

@test "a pull is resumed after the engine service is gone, by the next one at its start" {
    local id
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    id=$(sh_ image pulls -q --no-trunc)
    check "the service holds the pull" held "$(lease_held)"
    # as a crash: the service is killed, its lease goes with it
    kill -KILL "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID" 10
    check "nobody holds the pull" free "$(flock -n "$PULLS/$id/lease" true && echo free || echo held)"
    start_daemon
    # (the service takes the pull over at its start, before it serves)
    check "the next service holds it" held "$(lease_held)"
    sh_ image complete "$IMAGE" > /dev/null 2>&1
    check "image complete" 0 $?
    check "the image is in the store" 1 "$(db 'SELECT count(*) FROM images')"
}

@test "a reboot discards a lazy pull: nothing of it was made durable" {
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a pull in progress" 1 "$(sh_ image pulls -q | wc -l)"
    kill -KILL "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID" 10
    # (the staging says it is of another boot)
    printf 'an earlier boot\n' > "$BASE/boot"
    start_daemon
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "no layer is staged" 0 "$(staged_layers)"
    check "the store has no image" 0 "$(db 'SELECT count(*) FROM images')"
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "it is pulled again" 1 "$(sh_ image pulls -q | wc -l)"
    check "the staging is of this boot" "$(cat /proc/sys/kernel/random/boot_id)" "$(cat "$BASE/boot")"
}

@test "an error that retrying cannot mend stops the completion, keeps the staging and image pulls says why" {
    local layer toc out id
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    layer=$(ls "$BASE/meta" | head -1)
    toc=$BASE/meta/$layer/toc.json
    # the table lies about the content of a file: no fetch can satisfy it
    python3 -I - "$toc" << 'PY'
import json, sys
t = json.load(open(sys.argv[1]))
for e in t["entries"]:
    if e.get("type") == "reg" and e.get("size", 0) > 0 and e.get("fsverity"):
        v = e["fsverity"]
        e["fsverity"] = v[:-1] + ("0" if v[-1] != "0" else "1")
        break
json.dump(t, open(sys.argv[1], "w"))
PY
    check_match "a command that waits is told why" "failed" "$(sh_ image complete "$IMAGE" 2>&1)"
    check "the completion let the pull go" free "$(lease_held)"
    check_match "image pulls says it failed" "^failed$" "$(pulls)"
    out=$(sh_ image pulls --format '{{.Error}}' 2>&1)
    check_match "and why" "." "$out"
    check "the staging is kept" yes "$([ -f "$BASE/meta/$layer/layer.json" ] && echo yes)"
    check "nothing is in the store" "0 0" "$(db 'SELECT count(*) FROM images') $(db 'SELECT count(*) FROM layers')"
    # the pull is cancelled with its staging
    id=$(sh_ image pulls -q)
    sh_ image pulls --cancel "$id" > /dev/null 2>&1
    check "cancelled" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "nothing of it is staged" 0 "$( (find "$BASE/meta" -name layer.json; find "$PULLS" -mindepth 1) 2> /dev/null | wc -l)"
}

@test "rmi of a pull in progress cancels it: its completion stops and the staging goes" {
    local id
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    id=$(sh_ image pulls -q --no-trunc)
    sh_ image rm "$IMAGE" > /dev/null 2>&1
    check "rmi" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "its staging is gone" "" "$(ls "$PULLS" 2> /dev/null | grep "$id")"
    check "the store has nothing" "0 0 0" "$(files_in_store) $(db 'SELECT count(*) FROM images') $(db 'SELECT count(*) FROM layers')"
}

# the files the container looked up are the startup profile, next to the
# record of the store

@test "the files it looked up are the startup profile of the image" {
    local profile
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ container run -d --lazy --network none --name lp "$IMAGE" sleep 120 > /dev/null 2>&1
    check "the container runs" 0 $?
    check_match "it reads a file" "^[0-9]+\.[0-9]+" "$(sh_ container exec lp cat /etc/alpine-release 2>&1)"
    e2e_wait_glob "$WORKDIR/store/composefs/*.profile.json" 30
    profile=$(ls "$WORKDIR"/store/composefs/*.profile.json 2> /dev/null | head -1)
    [ -n "$profile" ] || { echo "FAIL no startup profile in the store" >&2; exit 1; }
    check_match "the files it looked up are noted for the next run" '^\{"v":1,"files":\["fsverity-sha256-12:[0-9a-f]{64}"' "$(cat "$profile")"
    cp "$profile" "$WORKDIR/profile.json"
    basename "$profile" > "$WORKDIR/profile.name"
    sh_ image complete "$IMAGE" > /dev/null 2>&1
    check "the image is complete" "" "$(sh_ image pulls -q)"
    check_match "the profile is next to the record of the image" "profile.json$" "$(ls "$WORKDIR/store/composefs" | grep profile)"
    sh_ container rm -t 0 -f lp > /dev/null 2>&1
}

# A new store with the pull again: a container that finds a profile (the
# recorded one, a garbage one, one that names what is not in the image) runs
# all the same.

@test "a container runs with the profile it recorded, a garbage one and one of what is not in the image" {
    local profile_name composefs
    profile_name=$(cat "$WORKDIR/profile.name" 2> /dev/null)
    [ -n "$profile_name" ] || { echo "no profile of the earlier test (it failed or did not run)" >&2; exit 1; }
    fresh_store
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    composefs=$WORKDIR/store/composefs
    run_lazy () { sh_ container run --rm --lazy --network none "$IMAGE" cat /etc/alpine-release 2>&1; }
    cp "$WORKDIR/profile.json" "$composefs/$profile_name"
    check_match "a container runs with the profile it recorded" "^[0-9]+\.[0-9]+" "$(run_lazy)"
    printf 'not json at all \377\376' > "$composefs/$profile_name"
    check_match "a container runs with a garbage profile" "^[0-9]+\.[0-9]+" "$(run_lazy)"
    printf '{"v":1,"files":["../../etc/shadow","fsverity-sha256-12:%064d","","fsverity-sha256-12:xyz"]}' 0 > "$composefs/$profile_name"
    check_match "a container runs with a profile of what is not in the image" "^[0-9]+\.[0-9]+" "$(run_lazy)"
}

# Without a daemon: each command is an engine of its own, and a lazy pull is
# handed to the engine service of the store, which the command starts on the
# engine's socket: it outlives the command, owns the pull and the one socket
# its containers ask (`image-fetch/engine`), and leaves when it has nothing
# to do.  Killed, the next command of the store, whatever it is, starts
# another, which takes the pull over and completes it with no command
# waiting for it.  A second command uses the same service.

@test "without a daemon the engine service outlives the command; the next command replaces a killed one" {
    local cfg=$WORKDIR/nd.toml id state pid next out
    # (the sockets in a directory of their own: the services of a store are
    # those of the directory of its socket)
    sed "s#$WORKDIR/\(state\|root\|store\)\"#$WORKDIR/nd-\1\"#; s#$WORKDIR/sh.sock#$WORKDIR/nd/nd.sock#g; s#^\[engine\]\$#[engine]\nidle_exit = 2#" \
        "$WORKDIR/sh.toml" > "$cfg"
    nd () { "$BIN/velarx" --config "$cfg" "$@"; }
    mkdir -p -m 700 "$WORKDIR/nd-store"
    check "no service runs" "" "$(e2e_service_pid "$WORKDIR/nd/nd.sock")"
    nd image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a lazy pull with no daemon" 0 $?
    pid=$(e2e_service_pid "$WORKDIR/nd/nd.sock")
    check_match "the command started the engine service" "^[0-9]+$" "$pid"
    check "it outlives the command" alive "$(e2e_alive "$pid")"
    check_match "it is the engine service" "varlink" "$(tr '\0' ' ' < "/proc/$pid/cmdline")"
    id=$(nd image pulls -q --no-trunc)
    state=$WORKDIR/nd-store/staging/pulls/$id/state.json
    check "it owns the pull" "\"pid\":$pid" "$(grep -o '"pid":[0-9]*' "$state")"
    check "and the one socket of the containers of the store" yes \
        "$([ -S "$WORKDIR/nd/services/image-fetch/engine" ] && echo yes)"
    # a second command, a container on the pull: the same service
    out=$(nd container run --rm --lazy --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "a container of a second command reads through it" "^[0-9]+\.[0-9]+" "$out"
    check "still one service" "$pid" "$(e2e_service_pid "$WORKDIR/nd/nd.sock")"
    kill -KILL "$pid"
    e2e_wait_exit "$pid" 10
    # in the background now: the next service completes it alone
    sed -i '/^lazy_completers = 0$/d' "$cfg"
    nd image list > /dev/null 2>&1
    next=$(e2e_service_pid "$WORKDIR/nd/nd.sock")
    check_match "a command started another service" "^[0-9]+$" "$([ "$next" != "$pid" ] && echo "$next")"
    # it completes alone: the pull is gone from the staging, 120 s at most
    [ -n "$id" ] || e2e_die "no pull id"
    e2e_wait_gone "$WORKDIR/nd-store/staging/pulls/$id" 120
    # (with nothing to do it leaves, its socket with it)
    e2e_wait_exit "$next" 60
    check "the service left" gone "$(e2e_alive "$next")"
    check "no pull is left" "" "$(nd image pulls -q)"
    check "the image is in the store" 1 "$(sqlite3 "file:$WORKDIR/nd-store/db.sqlite?mode=ro" 'SELECT count(*) FROM images')"
    check "nothing is staged" 0 "$( (find "$WORKDIR/nd-store/staging/meta" -name layer.json; find "$WORKDIR/nd-store/staging/pulls" -mindepth 1) 2> /dev/null | wc -l)"
    check "system check" 0 "$(nd system check > /dev/null 2>&1; echo $?)"
}

# A pull made with the credentials of the command (`--creds`): the engine
# service keeps them in memory and they are never stored.  A service that is
# killed takes them with it: the one that resumes the pull has none and waits
# for them (`needs-credentials`); `image complete --creds` brings them.

@test "a pull with --creds: a resumed pull waits for the credentials, image complete brings them" {
    local port authreg ref id out pid i
    command -v python3 > /dev/null || skip "no python3"
    python3 -I "$E2E_DIR/auth_registry.py" "$E2E_REGISTRY" e2e:s3cr3t-of-the-pull > "$WORKDIR/auth.port" 2> "$WORKDIR/auth.log" &
    authreg=$!
    echo "$authreg" >> "$WORKDIR/auth.pids"
    e2e_wait_content "$WORKDIR/auth.port" '[0-9]' 10
    port=$(head -1 "$WORKDIR/auth.port")
    ref=127.0.0.1:$port/${IMAGE#*/}
    fresh_store
    out=$(sh_ image pull --lazy --tls-verify=false "$ref" 2>&1)
    check_match "a pull without them is refused" "(nauthorized|401|redential|uthenticat)" "$out"
    sh_ image pull --lazy --tls-verify=false --creds e2e:s3cr3t-of-the-pull "$ref" > /dev/null 2>&1
    check "a lazy pull with --creds" 0 $?
    pid=$DAEMON_PID
    check "the secret is in no file of the store, the run root or the logs" "" \
        "$(grep -rl 's3cr3t-of-the-pull' "$WORKDIR/store" "$WORKDIR/state" "$WORKDIR/root" "$WORKDIR/sh.log" 2> /dev/null)"
    check "nor in the environment of the service" 1 "$(grep -qa s3cr3t /proc/$pid/environ; echo $?)"
    kill -KILL "$pid"
    e2e_wait_exit "$pid" 10
    start_daemon
    # (resumed by the next service, with no credentials: a command that
    # waits is told it needs them)
    check_match "a command that waits is told so" "credentials" "$(sh_ image complete "$ref" 2>&1)"
    check "a resumed pull waits for the credentials" needs-credentials "$(pulls)"
    out=$(sh_ image complete --creds e2e:s3cr3t-of-the-pull "$ref" 2>&1)
    check "image complete --creds ($out)" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "the image is in the store" 1 "$(db 'SELECT count(*) FROM images')"
    check "the secret is still in no file" "" \
        "$(grep -rl 's3cr3t-of-the-pull' "$WORKDIR/store" "$WORKDIR/state" "$WORKDIR/root" "$WORKDIR/sh.log" 2> /dev/null)"
    kill "$authreg" 2> /dev/null
}
