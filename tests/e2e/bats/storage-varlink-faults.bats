# SPDX-License-Identifier: Apache-2.0
# The varlink storage driver when something goes wrong: the engine killed in the
# middle of a pull, the service killed or stopped (in a pull, a collection, a
# removal, a create, a run), a store that is not the one the engine knew, and a
# service that lies (malformed replies, descriptors of the wrong number, order or
# kind, a path that leaves the work directory, a reply that never ends).  The
# service is the reference server behind tests/e2e/storage-proxy.py, which
# relays the calls and makes the fault the test asks for in the reply of one
# call; the engine must fail closed (an error naming what is wrong), not wait
# longer than its deadline, keep no descriptor and run nothing it was not
# asked to.  Run it as an ordinary user for the rootless daemon, or as root.
#
#   E2E_REGISTRY=localhost:5360 VELARX_BINDIR=target/debug bats tests/e2e/bats/storage-varlink-faults.bats
#
# The bytes a pull fetched are counted by tests/e2e/registry_log.py, a registry
# in front of E2E_REGISTRY that logs what it served: the pulls that are measured
# go through it (`via`).

load helpers
load run_lib
load storage_lib

# the engine's deadline: short, so that a service that stalls costs seconds
TMO=3

start_proxy () {
    : > "$VDIR/faults"
    setsid python3 -I "$E2E_DIR/storage-proxy.py" "$VDIR/p.sock" "$VDIR/s.sock" "$VDIR/faults" \
        "$VDIR/server.pid" >> "$VDIR/proxy.log" 2>&1 3>&- &
    echo $! > "$VDIR/proxy.pid"
    e2e_wait_path "$VDIR/p.sock" 10
}
stop_proxy () {
    local pid
    pid=$(cat "$VDIR/proxy.pid" 2> /dev/null)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null
    [ -z "$pid" ] || e2e_wait_exit "$pid" 10
    rm -f "$VDIR/proxy.pid"
}
before_daemon () {
    [ -x "$BIN/velarx-storage-server" ] || skip "cannot find $BIN/velarx-storage-server"
    command -v python3 > /dev/null || skip "no python3"
    start_storage 4
    start_proxy
}

setup_file () {
    export VDIR
    VDIR=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-varlink-faults.XXXXXX")
    export E2E_STORAGE_LINES="storage.driver = \"varlink\"
storage.varlink.socket = \"$VDIR/p.sock\"
storage.varlink.timeout_secs = $TMO
storage.varlink.name = \"velarx-storage-ref\"
pull.lazy_completers = 0"
    export E2E_BEFORE_DAEMON=before_daemon
    run_setup_file
    # (not a child of the shell of the setup: bats waits for those)
    ( setsid python3 -I "$E2E_DIR/registry_log.py" "$E2E_REGISTRY" "$VDIR/reg.log" > "$VDIR/reg.port" 2> "$VDIR/reg.err" 3>&- &
      echo $! > "$VDIR/reg.pid" )
    e2e_wait_content "$VDIR/reg.port" '[0-9]' 10
    : >> "$VDIR/reg.log"
}

# a test that failed puts the service, the proxy and the faults back before the
# daemon of the file is restarted
teardown () {
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] && return 0
    no_faults
    # (the mount of the case of a directory root, as root)
    [ "$(id -u)" != 0 ] || umount "$(store)/varlink/work/sub/mnt" 2> /dev/null
    kill -CONT "$(cat "$VDIR/server.pid" 2> /dev/null)" 2> /dev/null
    kill -0 "$(cat "$VDIR/server.pid" 2> /dev/null)" 2> /dev/null || start_storage 4
    kill -0 "$(cat "$VDIR/proxy.pid" 2> /dev/null)" 2> /dev/null || start_proxy
    run_test_teardown
}

teardown_file () {
    set +e
    run_teardown_file
    stop_proxy
    stop_storage
    if [ -s "${VDIR:-}/reg.pid" ]; then
        kill "$(cat "$VDIR/reg.pid")" 2> /dev/null
        e2e_wait_exit "$(cat "$VDIR/reg.pid")" 10
    fi
    [ -z "${VDIR:-}" ] || [ -n "${E2E_KEEP:-}" ] || { chmod -R u+rwX "$VDIR" 2> /dev/null; rm -rf "$VDIR"; }
}

# fault METHOD ACTION [ARGUMENT] [; ACTION [ARGUMENT]]...: the proxy makes them at
# the next call of METHOD
fault () {
    local method=$1 line rest
    shift
    rest="$*"
    while [ -n "$rest" ]; do
        line=${rest%% ; *}
        printf '%s %s\n' "$method" "$line" >> "$VDIR/faults"
        [ "$line" = "$rest" ] && break
        rest=${rest#* ; }
    done
}
wait_fault () { e2e_wait_content "$VDIR/faults" '\A\Z' 10 || e2e_die "the fault $(cat "$VDIR/faults") was not used"; }
no_faults () { : > "$VDIR/faults"; }

# via REF: the image REF of E2E_REGISTRY as the registry that logs names it;
# cpull REF: its pull through that registry
via () { echo "127.0.0.1:$(head -1 "$VDIR/reg.port")/${1#*/}"; }
cpull () { timeout 100 "$SH" --socket "$ESOCK" image pull --tls-verify=false "$(via "$1")" 3>&-; }
# the layer bytes that registry served since the mark (a range request has the
# size of its part)
mark () { wc -l < "$VDIR/reg.log"; }
served () { # MARK
    tail -n +"$(($1 + 1))" "$VDIR/reg.log" | grep -E '^GET /v2/[^ ]*/blobs/sha256:[0-9a-f]{64} ' |
        awk '{ n += $4 } END { print n + 0 }'
}
layers () { if [ -e "$(sdir)/db" ]; then sqlite3 "$(sdir)/db" 'SELECT count(*) FROM layers'; else echo 0; fi; }

# ec ARGS: the command line against the engine of the file, a deadline on it (a
# command with no --socket starts an engine of its own when it cannot reach
# the daemon)
ec () { timeout 60 "$SH" --socket "$ESOCK" "$@" 3>&-; }

# kill_engine: SIGKILL, as an out of memory kill does
kill_engine () {
    local pid
    pid=$(cat "$WORKDIR/api.pid" 2> /dev/null)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null
    rm -f "$WORKDIR/api.pid" "$SOCK"
    kill -KILL "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID" 10
    DAEMON_PID=
    rm -f "$WORKDIR/daemon.pid" "$ESOCK"
}
# the descriptors of the engine
fds () { ls "/proc/$(cat "$WORKDIR/daemon.pid")/fd" | wc -l; }

# forget_all: the images and containers go and the service drops the store
# (system prune), so that the next pull fetches everything
forget_all () {
    sh_ container rm -f -t 0 -a > /dev/null 2>&1
    sh_ system prune --all --volumes --force > /dev/null 2>&1
}

@test "the engine killed after the service staged a pull: the next pull of the layers is not held up by its claims" {
    forget_all
    check "the service has no layer" 0 "$(layers)"
    fault ReadObjects hold 25
    "$SH" --socket "$ESOCK" image pull "$IMAGE" > "$WORKDIR/killed.log" 2>&1 3>&- &
    pull=$!
    wait_fault
    kill_engine
    kill "$pull" 2> /dev/null
    start_daemon
    started=$(date +%s)
    out=$(timeout 100 "$SH" --socket "$ESOCK" image pull "$IMAGE" 2>&1)
    check "the pull again" 0 $?
    [ $(($(date +%s) - started)) -lt 40 ]
    check "it did not wait for the claims of the dead pull ($out)" 0 $?
    check "the layers are there" 1 "$(layers)"
    check "the image runs" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "the engine killed while the service is fetching: the service lets the pull go, the next pull completes" {
    forget_all
    fault BeginPull stop-server
    "$SH" --socket "$ESOCK" image pull "$IMAGE" > "$WORKDIR/killed.log" 2>&1 3>&- &
    pull=$!
    wait_fault
    kill_engine
    kill "$pull" 2> /dev/null
    # (the service wakes up to an engine that is gone)
    kill -CONT "$(cat "$VDIR/server.pid")"
    start_daemon
    started=$(date +%s)
    out=$(timeout 100 "$SH" --socket "$ESOCK" image pull "$IMAGE" 2>&1)
    check "the pull again ($out)" 0 $?
    [ $(($(date +%s) - started)) -lt 40 ]
    check "it did not wait for the dead pull" 0 $?
    check "the layers are there" 1 "$(layers)"
    check "the image runs" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "the service killed in the middle of a pull: the pull fails, the pull again after its restart fetches no more than a whole one" {
    forget_all
    m=$(mark)
    cpull "$IMAGE" > /dev/null
    check "a whole pull" 0 $?
    whole=$(served "$m")
    [ "$whole" -gt 1000000 ]
    check "a whole pull fetches the layer ($whole bytes)" 0 $?
    forget_all
    fault BeginPull kill-server 100
    out=$(cpull "$IMAGE" 2>&1)
    check "the pull of a service that dies fails" 125 $?
    check_match "and says why" 'storage|service' "$out"
    check "the image is not there" 125 "$(sh_ image inspect "$(via "$IMAGE")" > /dev/null 2>&1; echo $?)"
    check "the engine is up" 0 "$(timeout 60 "$SH" --socket "$ESOCK" info > /dev/null 2>&1; echo $?)"
    start_storage 4
    m=$(mark)
    out=$(cpull "$IMAGE" 2>&1)
    check "the pull after the restart ($out)" 0 $?
    [ "$(served "$m")" -le "$whole" ]
    check "it fetched no more than a whole pull ($(served "$m") of $whole)" 0 $?
    check "the image runs" ok "$(sh_ container run --rm --network none "$(via "$IMAGE")" echo ok)"
}

@test "a pull of an image with a layer the service has fetches only the other" {
    forget_all
    two_layer_image
    two=$E2E_REGISTRY/e2e/varlink-two:1
    sh_ image pull "$IMAGE" > /dev/null
    m=$(mark)
    out=$(cpull "$two" 2>&1)
    check "the pull ($out)" 0 $?
    [ "$(served "$m")" -gt 0 ] && [ "$(served "$m")" -lt 100000 ]
    check "only the other layer is fetched ($(served "$m") bytes)" 0 $?
    check "two layers" 2 "$(layers)"
    check "the image runs" two "$(sh_ container run --rm --network none "$(via "$two")" cat /two)"
    sh_ image rm -f "$(via "$two")" > /dev/null 2>&1
}

# the records of containers the service keeps for this store
records () { find "$(sdir)/containers" -name '*.json' ! -name 'read-*' 2> /dev/null | wc -l; }

@test "the service killed in a create, a removal and a collection: the call fails, the same call after the restart is done once" {
    sh_ image pull "$IMAGE" > /dev/null
    # CreateRoot
    fault CreateRoot kill-server 0
    started=$(date +%s)
    out=$(timeout 60 "$SH" --socket "$ESOCK" container create --name k1 --network none "$IMAGE" sleep 1000 2>&1)
    check "a create while the service dies fails" 125 $?
    [ $(($(date +%s) - started)) -lt 30 ]
    check "and does not wait for the deadline" 0 $?
    check_match "it says to start the service" 'start the storage service' "$out"
    start_storage 4
    sh_ container rm -f -t 0 k1 > /dev/null 2>&1
    sh_ container create --name k1 --network none "$IMAGE" sleep 1000 > /dev/null
    check "the same create after the restart" 0 $?
    sh_ container start k1 > /dev/null
    check "and the container runs" ok "$(sh_ container exec k1 echo ok)"
    check "the service has one record for it" 1 "$(records)"
    # RemoveRoot
    fault RemoveRoot kill-server 0
    out=$(timeout 60 "$SH" --socket "$ESOCK" container rm -f -t 0 k1 2>&1)
    check "a removal while the service dies fails" 125 $?
    check_match "it says to start the service" 'start the storage service' "$out"
    start_storage 4
    sh_ container rm -f -t 0 k1 > /dev/null
    check "the same removal after the restart" 0 $?
    check "the container is gone" 0 "$(sh_ container list -a -q | wc -l)"
    check "and the service has no record of it" 0 "$(records)"
    check "its root is gone" 0 "$(ls "$(store)/varlink/work" | wc -l)"
    # Collect
    sh_ container run --rm --network none "$IMAGE" true > /dev/null
    fault Collect kill-server 0
    out=$(timeout 60 "$SH" --socket "$ESOCK" system gc 2>&1)
    check "a collection while the service dies fails" 125 $?
    check_match "it says to start the service" 'start the storage service' "$out"
    start_storage 4
    sh_ system gc > /dev/null
    check "the same collection after the restart" 0 $?
    check "the image is there" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
    check "the check of the store passes" 0 "$(sh_ system check > /dev/null 2>&1; echo $?)"
}

@test "the service stopped while containers live: run, create, remove and collect say to start it, a running container goes on, all works after the restart" {
    sh_ image pull "$IMAGE" > /dev/null
    sh_ container run -d --name w1 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container run -d --name w2 --network none "$IMAGE" sleep 1000 > /dev/null
    stop_storage
    fds_before=$(fds)
    started=$(date +%s)
    for c in "container run --rm --network none $IMAGE true" "container create --name w3 --network none $IMAGE true" \
        "container rm -f -t 0 w2" "system gc" "system check"; do
        out=$(ec $c 2>&1)
        check "$c fails" 125 $?
        check_match "$c says to start the service" 'start the storage service' "$out"
    done
    [ $(($(date +%s) - started)) -lt 40 ]
    check "none of them waited for the deadline" 0 $?
    check "a container that runs goes on" hi "$(ec container exec w1 echo hi 2>&1)"
    [ "$(fds)" -le "$fds_before" ]
    check "the engine keeps no descriptor of the calls ($fds_before, $(fds))" 0 $?
    start_storage 4
    sh_ container rm -f -t 0 w2 > /dev/null
    check "the removal after the restart" 0 $?
    sh_ container create --name w3 --network none "$IMAGE" true > /dev/null
    check "a create after the restart" 0 $?
    check "gc" 0 "$(sh_ system gc > /dev/null 2>&1; echo $?)"
    check "the container that ran goes on" hi "$(sh_ container exec w1 echo hi)"
    sh_ container rm -f -t 0 w1 w3 > /dev/null
    check "no record is left" 0 "$(records)"
}

# svc METHOD [JSON]: a call on the service itself (the administrator's)
svc () { python3 -I "$E2E_DIR/storage-call.py" "$VDIR/s.sock" "$@"; }
engine_files () { rm -f "$(store)"/db.sqlite*; }

@test "the database of the engine rebuilt: the store id is kept, the service's layers are found, nothing is fetched" {
    forget_all
    sh_ image pull "$IMAGE" > /dev/null
    id=$(cat "$(store)/varlink/store-id")
    stop_daemon
    engine_files
    start_daemon
    check "the same store" "$id" "$(cat "$(store)/varlink/store-id")"
    check "the engine has no image" 0 "$(sh_ image list -q | wc -l)"
    m=$(mark)
    cpull "$IMAGE" > /dev/null
    check "the pull" 0 $?
    [ "$(served "$m")" -lt 100000 ]
    check "fetched nothing but the manifest ($(served "$m") bytes)" 0 $?
    check "the image runs" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "the store id lost: a new store, the old one is listed and dropped by the administrator (system stores), never by the engine on its own" {
    forget_all
    sh_ image pull "$IMAGE" > /dev/null
    old=$(cat "$(store)/varlink/store-id")
    stop_daemon
    engine_files
    rm -f "$(store)/varlink/store-id"
    start_daemon
    ec image pull "$IMAGE" > /dev/null
    new=$(cat "$(store)/varlink/store-id")
    [ "$new" != "$old" ]
    check "another id" 0 $?
    out=$(svc ListStores)
    check_match "the service lists the old store" "\"store\": \"$old\"" "$out"
    check_match "and the new" "\"store\": \"$new\"" "$out"
    check "the new store runs the image" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
    # a store with a container is not dropped, a name that is no id is refused
    sh_ container create --name d1 --network none "$IMAGE" true > /dev/null
    out=$(svc DropStore "{\"store\": \"$new\"}")
    check "a store with a container is busy" 1 $?
    check_match "and the error says so" '^error Busy' "$out"
    sh_ container rm -f -t 0 d1 > /dev/null
    out=$(svc DropStore '{"store": "../etc"}')
    check_match "a name that is no store id is refused" '^error Failed.*not a store id' "$out"
    check "nothing was removed by it" 1 "$(test -d "$VDIR/root/$(id -u)/$new"; echo $((1 - $?)))"
    # the administrator's command: both stores are listed, the engine's own is
    # marked and is not dropped, a name that is no id is refused
    out=$(sh_ system stores)
    check_match "system stores lists the old store" "^$old " "$out"
    check_match "and marks the engine's own" "^$new .*\\(this engine\\)" "$out"
    out=$(ec system stores --drop "$new" 2>&1)
    check "the store of the engine is not dropped" 125 $?
    check_match "and the error says whose it is" 'store of this engine' "$out"
    out=$(ec system stores --drop ../etc 2>&1)
    check "a name that is no store id is refused" 125 $?
    sh_ system stores --drop "$old" > /dev/null
    check "the old store is dropped" 0 $?
    check "its directory is gone" 1 "$(test -e "$VDIR/root/$(id -u)/$old"; echo $?)"
    svc DropStore "{\"store\": \"$old\"}" > /dev/null
    check "a second drop is the same" 0 $?
    check "the new store is as it was" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "image rm -f while the service is down: the containers of the image are as they were, and start after the restart" {
    sh_ image pull "$IMAGE" > /dev/null
    sh_ container run --name rf1 --network none "$IMAGE" true > /dev/null
    check "the container ran" 0 $?
    stop_storage
    out=$(ec image rm -f "$IMAGE" 2>&1)
    [ $? -ne 0 ]
    check "the removal fails" 0 $?
    check_match "it says to start the service" 'start the storage service' "$out"
    check "the container is listed" rf1 "$(ec container list -a --format '{{.Names}}')"
    start_storage 4
    sh_ container start rf1 > /dev/null
    check "and starts after the restart" 0 $?
    sh_ image rm -f "$IMAGE" > /dev/null
    check "the same removal after the restart" 0 $?
    check "the container is gone with the image" 0 "$(sh_ container list -a -q | wc -l)"
    check "and the service has no record of it" 0 "$(records)"
}

@test "a service whose stores are gone: the engine says to pull the image again, and the pull makes it good" {
    sh_ image pull "$IMAGE" > /dev/null
    stop_storage
    rm -rf "$VDIR/root"
    start_storage 4
    out=$(ec container run --rm --network none "$IMAGE" echo ok 2>&1)
    check "a run of the image the service lost" 125 $?
    check_match "it says the layer is not stored and what to do" 'is not stored: pull the image again' "$out"
    ec image pull "$IMAGE" > /dev/null
    check "the pull" 0 $?
    check "the image runs" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "a store whose only record is the copy of an image is dropped: by system prune, by the administrator, also when the service has not opened it since it started" {
    forget_all
    sh_ image pull "$IMAGE" > /dev/null
    # (--user: the engine reads the image's /etc/passwd from MountImage, the
    # copy; the removal of the container is done when rm returns)
    sh_ container run --name u1 --network none --user daemon "$IMAGE" true > /dev/null
    check "the run" 0 $?
    sh_ container rm u1 > /dev/null
    check "the copy of the image" 1 "$(find "$(sdir)/containers" -name 'read-*.json' | wc -l)"
    check "and no container" 0 "$(records)"
    id=$(cat "$(store)/varlink/store-id")
    out=$(ec system prune --all --volumes --force 2>&1)
    check "system prune ($out)" 0 $?
    check "the store is dropped" 1 "$(test -e "$VDIR/root/$(id -u)/$id"; echo $?)"
    # (the engine's store is made again by the next pull)
    sh_ image pull "$IMAGE" > /dev/null
    sh_ container run --name u1 --network none --user daemon "$IMAGE" true > /dev/null
    sh_ container rm u1 > /dev/null
    check "and no container" 0 "$(records)"
    check "the copy of the image, again" 1 "$(find "$(sdir)/containers" -name 'read-*.json' | wc -l)"
    out=$(svc DropStore "{\"store\": \"$id\"}")
    check "dropped by the administrator while the service has it open ($out)" 0 $?
    check "its directory is gone" 1 "$(test -e "$VDIR/root/$(id -u)/$id"; echo $?)"
    sh_ image pull "$IMAGE" > /dev/null
    sh_ container run --name u1 --network none --user daemon "$IMAGE" true > /dev/null
    sh_ container rm u1 > /dev/null
    check "the copy of the image, once more" 1 "$(find "$(sdir)/containers" -name 'read-*.json' | wc -l)"
    stop_storage
    start_storage 4
    out=$(svc DropStore "{\"store\": \"$id\"}")
    check "dropped by a service that did not open it since it started ($out)" 0 $?
    check "its directory is gone, again" 1 "$(test -e "$VDIR/root/$(id -u)/$id"; echo $?)"
}

# refused WHAT PATTERN COMMAND...: the command (against the engine) fails the way
# a command fails (125, not a timeout of the harness), within a few deadlines,
# and says PATTERN; the faults it did not use are dropped
refused () {
    local what=$1 pat=$2 out rc started
    shift 2
    started=$(date +%s)
    out=$(ec "$@" 2>&1)
    rc=$?
    [ -z "${HOSTILE_VERBOSE:-}" ] || echo "# $what: rc=$rc $(($(date +%s) - started))s: $(printf '%s' "$out" | head -c 300 | tr '\n' ' ')" >&3
    no_faults
    check "$what: fails" 125 "$rc"
    [ $(($(date +%s) - started)) -le $((TMO * 4 + 5)) ]
    check "$what: within the deadlines" 0 $?
    check_match "$what: says why" "$pat" "$out"
}
# alive: the engine answers and has the descriptors it had
alive () {
    check "$1: the engine answers" 0 "$(ec info > /dev/null 2>&1; echo $?)"
}

@test "a service that lies in the reply of a call the engine starts with: the engine does not start, within its deadline, and says which key" {
    sh_ image pull "$IMAGE" > /dev/null
    stop_daemon
    for f in "garbage" "huge" "stall" "error Failed" "patch proto=7" "patch name=\"\\u0000\"" "patch limits=17" \
        "dupkey proto=7"; do
        no_faults
        fault GetInfo $f
        started=$(date +%s)
        out=$(timeout 60 "$BIN/velarx" --config "$CONFIG" varlink 2>&1)
        rc=$?
        [ -z "${HOSTILE_VERBOSE:-}" ] || echo "# GetInfo $f: rc=$rc $(($(date +%s) - started))s: $(printf '%s' "$out" | head -c 300 | tr '\n' ' ')" >&3
        check "GetInfo $f: the engine does not start" 125 "$rc"
        [ $(($(date +%s) - started)) -le $((TMO * 4 + 5)) ]
        check "GetInfo $f: within the deadlines" 0 $?
        check_match "GetInfo $f: it names the key" 'storage\] driver = "varlink"' "$out"
    done
    no_faults
    start_daemon
    check "the engine starts with an honest service" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "a service that lies while an image is pulled: the pull fails, nothing is recorded, the next pull is whole" {
    forget_all
    fds_before=$(fds)
    for f in "HasLayers garbage" "HasLayers huge" "HasLayers stall" "HasLayers patch have=[true,true,true]" "HasLayers patch have=[]" \
        "BeginPull garbage" "BeginPull error Busy" "BeginPull stall" "BeginPull patch kind=\"later\"" \
        "ReadObjects garbage" "ReadObjects stall" "ReadObjects error Corrupt" "ReadObjects morebytes 7" \
        "HasLayers dupkey have=[false]" "Commit error Failed" "Commit garbage"; do
        fault $f
        refused "$f" 'storage|service|layer' image pull "$IMAGE"
        check "$f: no image is recorded" 0 "$(sh_ image list -q | wc -l)"
        alive "$f"
    done
    [ "$(fds)" -le $((fds_before + 2)) ]
    check "the engine's descriptors ($fds_before, $(fds))" 0 $?
    out=$(ec image pull "$IMAGE" 2>&1)
    check "a pull of an honest service ($out)" 0 $?
    check "the image runs" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

# the lazy image: staged by the engine, pulled into the service when its files
# are all there; the completion tries again after an error.  The engine
# completes nothing in the background (`pull.lazy_completers = 0`): the
# completion starts when a command waits for it (complete_in_background).
lazy_pull () {
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    sh_ image rm -f "$LAZY" > /dev/null 2>&1
    sh_ image pull --lazy --tls-verify=false "$LAZY" > /dev/null 2>&1 || e2e_die "the lazy pull"
}
# complete_in_background: a command waits for the pull, in the background
# ($BG_COMPLETE): the engine completes it from now on
complete_in_background () {
    timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" > "$WORKDIR/bg-complete.log" 2>&1 3>&- &
    BG_COMPLETE=$!
}
# the command that waited in the background ends (with the pull, or with an
# error)
bg_complete_over () { [ -z "${BG_COMPLETE:-}" ] || wait "$BG_COMPLETE"; BG_COMPLETE=; }

@test "the service killed while a lazy pull is completed: the completion tries again, and when the service is back the layers are in it whole" {
    forget_all
    lazy_pull
    fault BeginPull kill-server 100
    complete_in_background
    wait_fault
    e2e_wait_exit "$(cat "$VDIR/server.pid")" 10
    check "the image is not there while the service is down" "" "$(sh_ image list -q)"
    start_storage 4
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
    check "the pull completes after the restart ($out)" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check_match "the service has the layer" '^toc:sha256:' "$(sqlite3 "$(sdir)/db" 'SELECT id FROM layers')"
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    bg_complete_over
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "a service that lies while a lazy pull is completed: the layers are not recorded as pulled until the service has proved them, and the pull completes with an honest one" {
    forget_all
    for f in "ReadObjects garbage" "ReadObjects error Corrupt" "ReadObjects morebytes 7" "Commit error Failed" "BeginPull garbage"; do
        lazy_pull
        fault $f
        complete_in_background
        wait_fault
        check "$f: the engine is up" 0 "$(timeout 60 "$SH" --socket "$ESOCK" info > /dev/null 2>&1; echo $?)"
        out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
        check "$f: the pull completes with the honest service ($out)" 0 $?
        check "$f: the image runs" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
        bg_complete_over
        sh_ image rm -f "$LAZY" > /dev/null
    done
}

# what the engine keeps of a lazy image (see storage-varlink.bats): its objects,
# the EROFS images of its layers, and the pins of the containers it serves
engine_objects () { find "$(store)/objects" -type f 2> /dev/null | wc -l; }
engine_images () { find "$(store)/composefs" -type f -name 'layer-*' 2> /dev/null | wc -l; }
engine_pins () { find "$(store)/lazy-pins" -type f 2> /dev/null | wc -l; }
engine_copy_gone () {
    check "$1: no object of the engine's copy" 0 "$(engine_objects)"
    check "$1: no EROFS image of the engine's copy" 0 "$(engine_images)"
    check "$1: no pin" 0 "$(engine_pins)"
}
engine_copy_there () {
    check_match "$1: the engine's objects" '^[1-9][0-9]*$' "$(engine_objects)"
    check_match "$1: the EROFS images" '^[1-9][0-9]*$' "$(engine_images)"
}

@test "the engine killed at each step of a completion: the next completion repeats the steps, ends with no copy in the engine and the image in the service" {
    for call in BeginPull ReadObjects Commit; do
        forget_all
        lazy_pull
        fault $call hold 60
        complete_in_background
        wait_fault
        kill_engine
        bg_complete_over
        no_faults
        start_daemon
        check "$call: the engine has the copy the dead engine made" 0 "$([ "$(engine_objects)" -gt 0 ] && [ "$(engine_images)" -gt 0 ]; echo $?)"
        check "$call: the pull is still a pull" 1 "$(sh_ image pulls -q | wc -l)"
        out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
        check "$call: the next completion ($out)" 0 $?
        check "$call: no pull is left" "" "$(sh_ image pulls -q)"
        engine_copy_gone "$call: no container was made on the pull"
        check_match "$call: the service has the layer" '^toc:sha256:' "$(sqlite3 "$(sdir)/db" 'SELECT id FROM layers')"
        check "$call: the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
        out=$(sh_ system check 2>&1)
        check "$call: system check ($out)" 0 $?
        sh_ image rm -f "$LAZY" > /dev/null
    done
}

@test "the service killed during the commit of a completion: the engine's copy stays, nothing is recorded, and when the service is back the completion ends and drops it" {
    forget_all
    lazy_pull
    fault Commit kill-server 0
    complete_in_background
    wait_fault
    e2e_wait_exit "$(cat "$VDIR/server.pid")" 10
    check "the image is not there while the service is down" "" "$(sh_ image list -q)"
    engine_copy_there "the service is down"
    start_storage 4
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
    check "the pull completes after the restart ($out)" 0 $?
    engine_copy_gone "the completion ended"
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    bg_complete_over
    sh_ image rm -f "$LAZY" > /dev/null
}

# a completion in progress: it waits for the reply of the service to CALL,
# which the service holds (the one that comes late is past its deadline and
# the completion tries again)
completion_in_progress () { # CALL
    fault "$1" hold 30
    complete_in_background
    wait_fault
    check "the pull is in progress" 1 "$(sh_ image pulls -q | wc -l)"
}

@test "a container made while the pull is being completed keeps its root for its life, and the copy goes with it" {
    forget_all
    lazy_pull
    completion_in_progress BeginPull
    sh_ container run -d --lazy --network none --name dur "$LAZY" sleep 600 > /dev/null
    made=$?
    pinned=$(engine_pins)
    check "a container is made during the completion" 0 $made
    check "it is pinned" 1 "$pinned"
    sh_ container exec dur sh -c 'echo during > /root/made'
    bg_complete_over
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check_match "the image is in the list" 'varlink-lazy' "$(sh_ image list --format '{{.Repository}}')"
    engine_copy_there "the container holds the copy"
    check_match "it goes on" 'during' "$(sh_ container exec dur cat /root/made 2>&1)"
    sh_ container stop -t 0 dur > /dev/null
    sh_ container start dur > /dev/null
    check "it starts again" 0 $?
    check_match "from its own layer" 'during' "$(sh_ container exec dur cat /root/made 2>&1)"
    check_match "and the files of the image" '^[0-9]+\.[0-9]+' "$(sh_ container exec dur cat /etc/alpine-release 2>&1)"
    check "a container made after is the service's" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    sh_ container rm -f -t 0 dur > /dev/null
    engine_copy_gone "the container is removed"
    out=$(sh_ system check 2>&1)
    check "system check ($out)" 0 $?
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "the container removed while the pull is being completed: the copy stays while the pull needs it and goes when it ends" {
    forget_all
    lazy_pull
    sh_ container run -d --lazy --network none --name gone "$LAZY" sleep 600 > /dev/null
    completion_in_progress BeginPull
    sh_ container rm -f -t 0 gone > /dev/null
    removed=$?
    pins=$(engine_pins)
    objects=$(engine_objects)
    images=$(engine_images)
    check "the container is removed" 0 $removed
    check "its pin is gone" 0 "$pins"
    check_match "the pull in progress holds the files" '^[1-9][0-9]*$' "$objects"
    check_match "and the images of the layers" '^[1-9][0-9]*$' "$images"
    bg_complete_over
    check "no pull is left" "" "$(sh_ image pulls -q)"
    engine_copy_gone "the pull ended and no container is left"
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "the image removed while the pull is being completed: it is refused while a container is on it, a forced removal takes the container and the pull, and no copy is left" {
    forget_all
    lazy_pull
    sh_ container run -d --lazy --network none --name rmi "$LAZY" sleep 600 > /dev/null
    completion_in_progress BeginPull
    out=$(sh_ image rm "$LAZY" 2>&1)
    plain=$?
    sh_ container exec rmi true
    still=$?
    sh_ image rm -f "$LAZY" > "$WORKDIR/rmi.log" 2>&1
    forced=$?
    [ "$plain" != 0 ]
    check "a removal of the image with a container on it is refused ($out)" 0 $?
    check_match "and says why" 'in use by a container' "$out"
    check "the container kept its root" 0 $still
    check "the forced removal ($(cat "$WORKDIR/rmi.log"))" 0 $forced
    # (the command that waited is told the pull was cancelled)
    bg_complete_over
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "no container is left" "" "$(sh_ container list -a -q)"
    check "no image is left" "" "$(sh_ image list -q)"
    check "no file is staged" 0 "$(find "$(store)/staging/layers" -path "*/files/*" -type f 2> /dev/null | wc -l)"
    # (the files the dead pull linked before the service was asked have no row:
    # the collection finds them)
    sh_ system gc > /dev/null 2>&1
    engine_copy_gone "the pull and the container are gone"
    out=$(sh_ system check 2>&1)
    check "system check ($out)" 0 $?
    check "the image pulls again" 0 "$(sh_ image pull --tls-verify=false "$LAZY" > /dev/null 2>&1; echo $?)"
    check "and runs" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "the engine killed after the image is recorded and before the copy is dropped: a collection drops it, also from a drop that stopped half way" {
    forget_all
    lazy_pull
    # a create is in flight for as long as the test holds the lock: the release at the end of the completion is skipped
    ( exec 9> "$(store)/storage.lock"; flock -s 9; touch "$WORKDIR/lock.held"; exec sleep 3600 ) > /dev/null 2>&1 3>&- < /dev/null &
    holder=$!
    e2e_wait_path "$WORKDIR/lock.held" 10
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
    check "the pull completes ($out)" 0 $?
    check_match "the image is in the list" 'varlink-lazy' "$(sh_ image list --format '{{.Repository}}')"
    engine_copy_there "the store was busy: nothing was dropped"
    kill_engine
    kill "$holder" 2> /dev/null
    start_daemon
    engine_copy_there "the engine is back"
    # (a drop killed after its objects and before its images: the state it leaves)
    find "$(store)/objects" -type f -delete
    check "the objects are gone, the images are not" 0 "$([ "$(engine_objects)" = 0 ] && [ "$(engine_images)" -gt 0 ]; echo $?)"
    out=$(sh_ system gc 2>&1)
    check "a collection ($out)" 0 $?
    engine_copy_gone "the collection finished the drop"
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    out=$(sh_ system check 2>&1)
    check "system check ($out)" 0 $?
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "a collection never drops the copy a container holds, and a pin that cannot be read holds everything" {
    forget_all
    lazy_pull
    sh_ container run -d --lazy --network none --name pinned "$LAZY" sleep 600 > /dev/null
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
    check "the pull completes ($out)" 0 $?
    sh_ system gc > /dev/null 2>&1
    engine_copy_there "a collection with a container on the pull"
    check_match "the container reads the image" '^[0-9]+\.[0-9]+' "$(sh_ container exec pinned cat /etc/alpine-release 2>&1)"
    pin=$(find "$(store)/lazy-pins" -type f | head -1)
    cp "$pin" "$WORKDIR/pin.good"
    sh_ container stop -t 0 pinned > /dev/null
    echo "not a layer key" > "$pin"
    sh_ system gc > /dev/null 2>&1
    engine_copy_there "an unreadable pin"
    cp "$WORKDIR/pin.good" "$pin"
    sh_ container start pinned > /dev/null
    check "the container starts again" 0 $?
    sh_ container rm -f -t 0 pinned > /dev/null
    engine_copy_gone "the container is removed"
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "a layer one completion released and the service lost: the completion of the second pull fails, a pull again, without a cancel, makes the image whole" {
    forget_all
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    python3 -I "$E2E_DIR/registry_images.py" variant "$E2E_REGISTRY" e2e/varlink-lazy zstd other > /dev/null ||
        e2e_die "the variant of the lazy image"
    OTHER=$E2E_REGISTRY/e2e/varlink-lazy:other
    sh_ image pull --lazy --tls-verify=false "$LAZY" > /dev/null 2>&1 || e2e_die "the first lazy pull"
    sh_ image pull --lazy --tls-verify=false "$OTHER" > /dev/null 2>&1 || e2e_die "the second lazy pull"
    check "two pulls share the layer" 2 "$(sh_ image pulls -q | wc -l)"
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$LAZY" 2>&1)
    check "the first completes ($out)" 0 $?
    stop_storage
    rm -rf "$VDIR/root"
    start_storage 4
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$OTHER" 2>&1)
    check "the second completion fails ($out)" 125 $?
    check_match "it names the layer and says what to do" 'layer toc:sha256:.*pull the image again' "$out"
    check "the pull is failed" "failed" "$(sh_ image pulls --format '{{.State}}')"
    sh_ image pull --lazy --tls-verify=false "$OTHER" > /dev/null 2>&1 || e2e_die "the pull again"
    out=$(timeout 120 "$SH" --socket "$ESOCK" image complete "$OTHER" 2>&1)
    check "the completion of the pull again ($out)" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check_match "the service has the layer again" '^toc:sha256:' "$(sqlite3 "$(sdir)/db" 'SELECT id FROM layers')"
    engine_copy_gone "no container was made"
    check "the second image runs from the service" ok "$(sh_ container run --rm --network none "$OTHER" echo ok)"
    sh_ image rm -f "$LAZY" "$OTHER" > /dev/null
}

# the directory a root that escapes would be: the container writes a file in it
decoy () { echo "$(store)/varlink/decoy"; }

@test "a service that lies about a root: no container is made or run, nothing outside the work directory is used" {
    sh_ image pull "$IMAGE" > /dev/null
    mkdir -p "$(decoy)"
    fds_before=$(fds)
    # a root at create
    for f in "CreateRoot garbage" "CreateRoot huge" "CreateRoot stall" "CreateRoot extrafds 1" \
        "CreateRoot error Missing" \
        "CreateRoot patch root.path=\"../decoy\"" "CreateRoot patch root.path=\"$(decoy)\"" \
        "CreateRoot patch root.path=\"a/../../decoy\"" "CreateRoot patch root.path=\"\"" "CreateRoot patch root.path=\".\"" \
        "CreateRoot patch root.kind=\"mount_fd\" root.fd=0" "CreateRoot patch root.path=null" "CreateRoot patch root=null"; do
        fault $f
        refused "$f" 'storage|service|root' container create --name x1 --network none "$IMAGE" sh -c 'touch /ESCAPED'
        check "$f: no container" 0 "$(sh_ container list -a -q | wc -l)"
        check "$f: nothing in the decoy" 0 "$(ls "$(decoy)" | wc -l)"
    done
    alive "creates"
    # a root that is a plain name but a link to the decoy or a file: the create
    # takes the name, the start does not run on it (the monitor opens the way
    # down without following a link; rootless, a directory is the root)
    if [ "$(id -u)" != 0 ]; then
        ln -sfn "$(decoy)" "$(store)/varlink/work/link"
        touch "$(store)/varlink/work/afile"
        for p in link afile; do
            fault CreateRoot patch "root.path=\"$p\""
            ec container create --name x2 --network none "$IMAGE" sh -c 'touch /ESCAPED' > /dev/null 2>&1
            refused "a root at $p" 'storage|service|root|directory|link|not a directory' container start x2
            state=$(state_of x2)
            [ "$state" != running ] && [ "$state" != exited ]
            check "a root at $p: the container did not run ($state)" 0 $?
            check "a root at $p: nothing in the decoy" 0 "$(ls "$(decoy)" | wc -l)"
            sh_ container rm -f -t 0 x2 > /dev/null 2>&1
        done
        rm -f "$(store)/varlink/work/link" "$(store)/varlink/work/afile"
    fi
    [ "$(fds)" -le $((fds_before + 2)) ]
    check "the engine's descriptors ($fds_before, $(fds))" 0 $?
}

@test "a service that lies about the descriptors of a mount, or a path: the container does not run, nothing outside the work directory is used (root)" {
    skip_unless_root
    sh_ image pull "$IMAGE" > /dev/null
    mkdir -p "$(decoy)"
    ln -s "$(decoy)" "$(store)/varlink/work/link"
    fds_before=$(fds)
    ec container create --name h1 --network none --mount "type=image,source=$IMAGE,destination=/mnt/i" "$IMAGE" \
        sh -c 'touch /ESCAPED /mnt/i/ESCAPED; sleep 1000' > /dev/null
    check "an honest create" 0 $?
    for f in "Mounts garbage" "Mounts huge" "Mounts stall" "Mounts error Unavailable" \
        "Mounts nofds" "Mounts extrafds 1" "Mounts extrafds 17" "Mounts filefd" "Mounts filefd /dev/null" "Mounts sockfd" \
        "Mounts patch volumes.0.fd=1" "Mounts patch volumes.0.fd=-1" \
        "Mounts patch volumes.0.kind=\"directory\" volumes.0.path=\"../decoy\"" \
        "Mounts patch volumes.0.kind=\"directory\" volumes.0.path=\"$(decoy)\"" \
        "Mounts patch volumes.0.kind=\"directory\" volumes.0.path=\"link\"" \
        "Mounts patch root={\"kind\":\"directory\",\"path\":\"../decoy\",\"idmap\":\"none\",\"label\":\"none\"}" \
        "Mounts patch root={\"kind\":\"directory\",\"path\":\"$(decoy)\",\"idmap\":\"none\",\"label\":\"none\"}" \
        "Mounts patch root={\"kind\":\"directory\",\"path\":\"link\",\"idmap\":\"none\",\"label\":\"none\"}" \
        "Mounts patch root={\"kind\":\"mount_fd\",\"fd\":0,\"idmap\":\"none\",\"label\":\"none\"} volumes.0.fd=0" \
        "Mounts patch volumes=[]"; do
        fault $f
        refused "$f" 'storage|service|root|mount|descriptor|volume' container start h1
        state=$(state_of h1)
        [ "$state" != running ]
        check "$f: the container did not run ($state)" 0 $?
        check "$f: nothing in the decoy" 0 "$(ls "$(decoy)" | wc -l)"
    done
    alive "starts"
    sh_ container start h1 > /dev/null
    check "an honest start" 0 $?
    sh_ container rm -f -t 0 h1 > /dev/null
    [ "$(fds)" -le $((fds_before + 2)) ]
    check "the engine's descriptors ($fds_before, $(fds))" 0 $?
}

# a directory root as the service makes it, as the fault of a create and of a
# start
dir_root () { printf 'root={"kind":"directory","path":"%s","idmap":"none","label":"none"}' "$1"; }

@test "a directory root with a mount below it: the container has the directory, not the mount (root)" {
    skip_unless_root
    sh_ image pull "$IMAGE" > /dev/null
    sub=$(store)/varlink/work/sub
    # (the files of the image, exported from a container of the honest service)
    sh_ container create --name src --network none "$IMAGE" true > /dev/null
    mkdir -p "$sub"
    ec container export src | tar -x -C "$sub"
    check "the files of the image" 0 "${PIPESTATUS[0]}"
    sh_ container rm -f -t 0 src > /dev/null
    mkdir -p "$sub/mnt"
    mount -t tmpfs tmpfs "$sub/mnt"
    echo mounted > "$sub/mnt/m"
    fault CreateRoot patch "$(dir_root sub)"
    # (no SELinux label: the engine labels the root WritableRoot gives, which
    # a fault cannot change, so the files of this one keep the test's label)
    ec container create --name sm --network none --security-opt label=disable "$IMAGE" sh -c 'ls /mnt > /seen' > /dev/null
    check "a create with a directory root" 0 $?
    fault Mounts patch "$(dir_root sub)"
    ec container start --attach sm > /dev/null
    check "it ran" 0 $?
    no_faults
    check "it wrote in the directory" 1 "$(test -e "$sub/seen"; echo $((1 - $?)))"
    check "and did not see the mount" "" "$(cat "$sub/seen" 2> /dev/null)"
    umount "$sub/mnt"
    sh_ container rm -f -t 0 sm > /dev/null
    rm -rf "$sub"
}

@test "a service that lies about the descriptor of an image or of a container's files: the engine reads nothing from it" {
    sh_ image pull "$IMAGE" > /dev/null
    fds_before=$(fds)
    # the image (MountImage: read for --user, --workdir, --tz)
    for f in "MountImage garbage" "MountImage stall" "MountImage nofds" "MountImage extrafds 2" "MountImage filefd" \
        "MountImage filefd /dev/null" "MountImage sockfd" "MountImage error Missing"; do
        fault $f
        refused "$f" 'storage|service|image|descriptor|directory' container create --name m1 --network none --user daemon "$IMAGE" true
        check "$f: no container" 0 "$(sh_ container list -a -q | wc -l)"
    done
    # the files of a container (WritableRoot: cp, diff, export of one)
    ec container create --name m2 --network none --user daemon "$IMAGE" true > /dev/null
    check "an honest create" 0 $?
    for f in "WritableRoot garbage" "WritableRoot stall" "WritableRoot nofds" "WritableRoot extrafds 2" "WritableRoot filefd" \
        "WritableRoot filefd /dev/null" "WritableRoot sockfd" "WritableRoot error NotFound"; do
        fault $f
        refused "$f" 'storage|service|container|descriptor|directory|injected' cp m2:/etc/passwd -
    done
    check "cp from the honest service" 1 "$(ec cp m2:/etc/passwd - | tar -xO | grep -c '^daemon:')"
    sh_ container rm -f -t 0 m2 > /dev/null
    alive "descriptors"
    [ "$(fds)" -le $((fds_before + 2)) ]
    check "the engine's descriptors ($fds_before, $(fds))" 0 $?
}

@test "a service that lies in a collection, a check or a removal: the command fails and says so, the store is as it was" {
    sh_ image pull "$IMAGE" > /dev/null
    for f in "Collect garbage" "Collect huge" "Collect stall" "Collect error Busy" "Collect patch bytes_freed=\"x\"" \
        "Collect patch bytes_freed=-1" "Collect patch bytes_freed=18446744073709551616" "Collect dupkey bytes_freed=0" \
        "Check garbage" "Check stall" "Check patch problems=7"; do
        fault $f
        case "$f" in
        Check*) refused "$f" 'storage|service|check' system check ;;
        *) refused "$f" 'storage|service|collect|injected' system gc ;;
        esac
    done
    alive "the collections"
    # (what the service keeps of a removed image is the collection's to remove: a
    # service that says no to RemoveImage does not keep the image)
    fault RemoveImage error Failed
    ec image rm -f "$IMAGE" > /dev/null 2>&1
    check "an image removed while the service fails" 125 "$(sh_ image inspect "$IMAGE" > /dev/null 2>&1; echo $?)"
    no_faults
    sh_ system gc > /dev/null
    check "the collection after it" 0 $?
    sh_ image pull "$IMAGE" > /dev/null
    check "the image is there" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
    check "gc of an honest service" 0 "$(sh_ system gc > /dev/null 2>&1; echo $?)"
    check "the check of an honest service" 0 "$(sh_ system check > /dev/null 2>&1; echo $?)"
}

@test "the service killed while a layer made by a commit or a build is stored: the command fails, no image is made, the container is as it was, the next one is done" {
    sh_ image pull "$IMAGE" > /dev/null
    sh_ container run -d --name cf1 --network none "$IMAGE" sh -c 'echo made > /root/made; echo ready; sleep 1000' > /dev/null
    e2e_wait_log cf1 '^ready$' || e2e_die "cf1 does not run its command"
    fault BeginPull kill-server 100
    out=$(ec container commit cf1 localhost/e2e/fault:1 2>&1)
    check "the commit of a service that dies fails ($out)" 125 $?
    check_match "and says why" 'storage|service' "$out"
    check "the image is not there" 125 "$(sh_ image inspect localhost/e2e/fault:1 > /dev/null 2>&1; echo $?)"
    check "the engine is up" 0 "$(ec info > /dev/null 2>&1; echo $?)"
    start_storage 4
    check "the container is as it was" made "$(sh_ container exec cf1 cat /root/made)"
    out=$(ec container commit cf1 localhost/e2e/fault:1 2>&1)
    check "the commit after the restart ($out)" 0 $?
    check "the image runs" made "$(sh_ container run --rm --network none localhost/e2e/fault:1 cat /root/made)"
    # a build, whose steps are layers made the same way
    ctx=$WORKDIR/fctx
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN echo built > /built\n' "$IMAGE" > "$ctx/Dockerfile"
    fault BeginPull kill-server 100
    out=$(ec build -t localhost/e2e/fault-b:1 "$ctx" 2>&1)
    check "the build of a service that dies fails" 125 $?
    check "no image is made" 125 "$(sh_ image inspect localhost/e2e/fault-b:1 > /dev/null 2>&1; echo $?)"
    start_storage 4
    out=$(ec build -t localhost/e2e/fault-b:1 "$ctx" 2>&1)
    check "the build after the restart ($out)" 0 $?
    check "the image runs" built "$(sh_ container run --rm --network none localhost/e2e/fault-b:1 cat /built)"
    sh_ container rm -f -t 0 cf1 > /dev/null
    sh_ image rm -f localhost/e2e/fault:1 localhost/e2e/fault-b:1 > /dev/null
    sh_ image prune -f > /dev/null
}

@test "a service that lies while a layer made by a commit is stored: the commit fails, no image is made, nothing is left in the engine's scratch" {
    sh_ image pull "$IMAGE" > /dev/null
    sh_ container run -d --name cf2 --network none "$IMAGE" sh -c 'echo made > /root/made; echo ready; sleep 1000' > /dev/null
    e2e_wait_log cf2 '^ready$' || e2e_die "cf2 does not run its command"
    fds_before=$(fds)
    for f in "HasLayers garbage" "HasLayers patch have=[true,true,true]" "BeginPull garbage" "BeginPull error Busy" "BeginPull stall" \
        "ReadObjects garbage" "ReadObjects stall" "ReadObjects error Corrupt" "ReadObjects morebytes 7" "Commit error Failed" "Commit garbage"; do
        fault $f
        refused "$f" 'storage|service|layer' container commit cf2 localhost/e2e/lie:1
        check "$f: no image is made" 125 "$(sh_ image inspect localhost/e2e/lie:1 > /dev/null 2>&1; echo $?)"
        check "$f: the container is as it was" made "$(sh_ container exec cf2 cat /root/made)"
        alive "$f"
    done
    [ "$(fds)" -le $((fds_before + 2)) ]
    check "the engine's descriptors ($fds_before, $(fds))" 0 $?
    check "nothing is left in the scratch directory" 0 "$(find "$(store)/varlink/scratch" -type f | wc -l)"
    out=$(ec container commit cf2 localhost/e2e/lie:1 2>&1)
    check "a commit of an honest service ($out)" 0 $?
    check "the image runs" made "$(sh_ container run --rm --network none localhost/e2e/lie:1 cat /root/made)"
    sh_ container rm -f -t 0 cf2 > /dev/null
    sh_ image rm -f localhost/e2e/lie:1 > /dev/null
}
