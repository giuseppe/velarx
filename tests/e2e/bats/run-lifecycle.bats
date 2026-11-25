# SPDX-License-Identifier: Apache-2.0
# End to end tests of the container life cycle (run, stop, kill, the
# monitors, the restart of the daemon and of the server, restart policy),
# through a daemon of its own.  Run it as an ordinary user for the rootless
# daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

@test "run of a command prints its output" {
    out=$(sh_ container run --rm --network none "$IMAGE" echo hello 2>&1)
    check "run echo" "hello" "$out"
}

# The monitor of a container records what happens to it itself: no process
# of the engine is started for the exit.
@test "the exit of a container is recorded by its monitor: no engine process is started" {
    sh_ container run -d --name rec0 --network none "$IMAGE" sh -c 'sleep 1; exit 2' > /dev/null
    check "it runs" 0 $?
    wait_state rec0 exited 30
    check "its exit is recorded" 0 $?
    check "with its code" 2 "$(inspect_of rec0 exit_code)"
    sh_ container rm rec0 > /dev/null
}

# The store as the database has it, read with no velarx command (a command
# would reconcile it first).
store_row () {
    python3 -I - "$XDG_DATA_HOME/velarx/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
r = c.execute("select state, exit_code from containers where name = ?", (sys.argv[2],)).fetchone()
print("gone" if r is None else "%s %s" % r)
EOT
}

# The engine is killed while the container runs: the monitor records the
# exit, releases what it holds and removes an `--rm` container by itself.
@test "the engine is killed before the container ends: the monitor records and removes" {
    sh_ container run -d --name kill1 --network none "$IMAGE" sh -c 'sleep 3; exit 3' > /dev/null
    sh_ container run -d --rm --name kill2 --network none "$IMAGE" sh -c 'sleep 3; exit 0' > /dev/null
    pid1=$(inspect_of kill1 pid)
    pid2=$(inspect_of kill2 pid)
    mon1=$(monitor_of kill1)
    mon2=$(monitor_of kill2)
    id2=$(inspect_of kill2 id)
    kill "$(cat "$WORKDIR/api.pid")"
    rm -f "$WORKDIR/api.pid" "$SOCK"
    kill -9 "$DAEMON_PID"
    wait "$DAEMON_PID" 2> /dev/null || true
    DAEMON_PID=
    e2e_wait_exit "$pid1" 30 && e2e_wait_exit "$mon1" 30 && e2e_wait_exit "$mon2" 30 \
        || e2e_die "the containers and their monitors did not end within 30 s"
    check "the exit is in the store, recorded by the monitor" "stopped 3" "$(store_row kill1)"
    check "the --rm container is gone from the store" gone "$(store_row kill2)"
    check "its bundle is gone" no "$(test -e "$XDG_DATA_HOME/velarx/bundles/$id2" && echo yes || echo no)"
    start_daemon
    # (what the monitors wrote, in the journal or the file of the events)
    timeout 8 "$SH" events --since 5m --stream > "$WORKDIR/kill.ev" 2>&1 3>&- || true
    check "the events say died and remove" 2 "$(grep -c -E "container (died|remove) .*name=kill2" "$WORKDIR/kill.ev" || true)"
    sh_ container rm kill1 > /dev/null
}

# The socket of the engine: 0600 and for its user only when rootless, a
# live engine keeps it, and `--time` makes an idle one exit.
@test "the socket of the API, a second daemon, an idle daemon" {
    if test "$(id -u)" != 0; then
        check "a rootless engine's socket is 0600" 600 "$(stat -c %a "$ESOCK")"
    fi
    # (a second daemon is no error: it holds the first, quietly, as long as it runs)
    out=$(timeout 3 "$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check "a second daemon does not take the socket, it holds the first until stopped" 124 $?
    check "and says nothing of it" "" "$out"
    "$SH" --socket "$ESOCK" image list > /dev/null
    check "the first daemon still answers" 0 $?

    # idle: it leaves, the containers (their monitors) run on
    stop_daemon
    daemon_spawn_ready "$BIN/velarx" --config "$CONFIG" varlink --time 3
    sh_ container run -d --name idle1 --network none "$IMAGE" sleep 1000 > /dev/null
    check "a container runs under the idle engine" 0 $?
    e2e_wait_exit "$DAEMON_PID" 30 || e2e_die "the idle engine did not exit within 30 s"
    check "then it exits" gone "$(e2e_alive "$DAEMON_PID")"
    wait "$DAEMON_PID"
    check "with status 0" 0 $?
    DAEMON_PID=
    rm -f "$WORKDIR/daemon.pid"
    check "and removes its socket" no "$(test -e "$ESOCK" && echo yes || echo no)"
    start_daemon
    check "the container runs on" running "$(state_of idle1)"
    sh_ container rm -t 0 -f idle1 > /dev/null
}

# A start that waits (here for the lock of the boot, held by a process of
# this test) ends with SIGTERM like a daemon that serves, and takes its
# socket away.
@test "a daemon that is not ready yet ends with SIGTERM" {
    stop_daemon
    local trace=$WORKDIR/start.trace held=$WORKDIR/boot-held
    (
        exec 9> "$XDG_RUNTIME_DIR/velarx/boot.lock"
        flock 9 && echo held > "$held"
        exec sleep infinity
    ) 3>&- &
    local holder=$!
    e2e_wait_line "$held" held 30 || e2e_die "the lock of the boot was not taken"
    VELARX_TRACE_FILE=$trace daemon_spawn "$BIN/velarx" --config "$CONFIG" varlink
    # (the daemon waits for the lock of the boot; its signals are taken
    # long before: the store opened by the join of the rootless namespaces,
    # before them, says `db ready` too)
    e2e_wait_line "$trace" 'boot lock' 30 || e2e_die "the daemon did not come to the lock of the boot"
    kill -TERM "$DAEMON_PID"
    e2e_wait_exit "$DAEMON_PID" 30 || e2e_die "the daemon that is not ready did not end on SIGTERM"
    wait "$DAEMON_PID" || true
    DAEMON_PID=
    rm -f "$WORKDIR/daemon.pid"
    check "it removes its socket" no "$(test -e "$ESOCK" && echo yes || echo no)"
    kill "$holder"
    wait "$holder" 2> /dev/null || true
    start_daemon
}

@test "exit codes of run and exec, as podman" {
    sh_ container run --rm --network none "$IMAGE" sh -c 'exit 3' > /dev/null 2>&1
    check "exit code propagation" 3 $?

    sh_ container run --rm --network none "$IMAGE" true > /dev/null 2>&1
    check "exit code 0" 0 $?

    sh_ container run --rm --network none "$IMAGE" sh -c 'exit 255' > /dev/null 2>&1
    check "exit code 255" 255 $?

    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'exit 126' 2>&1)
    check "a command that ends 126 by itself" "126" "$?"
    check "says nothing" "" "$out"
    sh_ container run --rm --network none "$IMAGE" /does/not/exist > /dev/null 2>&1
    check "missing executable" 127 $?
    sh_ container run -d --rm --network none "$IMAGE" /does/not/exist > /dev/null 2>&1
    check "missing executable, detached" 127 $?
    sh_ container run --rm --network none "$IMAGE" /etc > /dev/null 2>&1
    check "an executable that cannot be run" 126 $?
    out=$(sh_ container run --rm --network none "$IMAGE" /does/not/exist 2>&1)
    check "missing executable, podman's words" "Error: crun: executable file \`/does/not/exist\` not found: No such file or directory: OCI runtime attempted to invoke a command that was not found" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" /etc 2>&1)
    check "an executable that cannot be run, podman's words" "Error: crun: the path \`/etc\` is not a regular file: Operation not permitted: OCI permission denied" "$out"
    out=$(sh_ container run --rm --network none --workdir /i/do/not/exist "$IMAGE" pwd 2>&1)
    check "a workdir the image lacks is 126" "126" "$?"
    check_match "and podman's words" 'Error: workdir "/i/do/not/exist" does not exist on container' "$out"
    mkdir -p "$WORKDIR/wdvol"
    echo vc > "$WORKDIR/wdvol/content"
    check "a workdir on a volume is made by the runtime" vc "$(sh_ container run --rm --network none --workdir /IamNotOnTheImage -v "$WORKDIR/wdvol:/IamNotOnTheImage:z" "$IMAGE" cat content 2>&1)"
    check "a workdir of the image" "/tmp" "$(sh_ container run --rm --network none --workdir /tmp "$IMAGE" pwd 2>&1)"
    sh_ container run -d --name ec1 --network none "$IMAGE" sleep 100 > /dev/null 2>&1
    out=$(sh_ container exec -d ec1 /does/not/exist 2>&1)
    check "exec -d of a command that cannot start is 125" 125 $?
    check_match "and says why" "crun: executable file .*OCI runtime attempted to invoke a command that was not found" "$out"
    sh_ container exec -d ec1 sleep 1 > /dev/null 2>&1
    check "exec -d of a command that starts" 0 $?
    sh_ container exec ec1 /etc > /dev/null 2>&1
    check "exec of a path that cannot run is 126" 126 $?
    sh_ container exec -d ec1 /etc > /dev/null 2>&1
    check "exec -d of a path that cannot run is 125" 125 $?
    sh_ container exec -d ec1 sh -c 'exit 127' > /dev/null 2>&1
    check "exec -d of a command that starts and ends 127 by itself" 0 $?
    sh_ container exec ec1 sh -c 'echo "the path \`/x\` is not a regular file" >&2; exit 3' > /dev/null 2>&1
    check "exec of a command that says what the runtime says, and ends 3" 3 $?
    sh_ container exec -w /nonexistent ec1 true > /dev/null 2>&1
    check "exec in a missing directory is 127, as podman" 127 $?
    sh_ container rm -f -t 0 ec1 > /dev/null 2>&1
}

@test "stdout, stderr and stdin of run" {
    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'echo out; echo err >&2' 2> /dev/null)
    check "stdout separated" "out" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'echo out; echo err >&2' 2>&1 > /dev/null)
    check "stderr separated" "err" "$out"

    out=$(echo from-stdin | sh_ container run --rm -i --network none "$IMAGE" cat)
    check "stdin with -i" "from-stdin" "$out"

    out=$(echo from-stdin | sh_ container run --rm --network none "$IMAGE" cat)
    check "no stdin without -i" "" "$out"

    big=$(sh_ container run --rm --network none "$IMAGE" sh -c 'i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); done' | md5sum)
    check "a lot of output" "$(i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); done | md5sum)" "$big"
}

@test "run --rm leaves nothing behind" {
    sh_ container run --rm --network none "$IMAGE" true
    out=$(sh_ container list -a | wc -l)
    check "--rm leaves nothing behind" 1 "$out"
}

# The plan of the root file system is in the bundle from the create on: a
# container whose bundle has none (made by another version, or the file was
# removed) is refused, never run on the empty directory of the bundle.
@test "a container whose bundle has no rootfs.json is refused at the start" {
    id=$(sh_ container create --network none "$IMAGE" true) || e2e_die "create"
    local plan=$XDG_DATA_HOME/velarx/bundles/$id/rootfs.json
    [ -f "$plan" ] || e2e_die "no plan at $plan"
    rm -f "$plan"
    out=$(sh_ container start "$id" 2>&1)
    check_match "refused, by the name of the file" "its bundle has no rootfs.json, the plan of its root file system" "$out"
    sh_ container rm -t 0 -f "$id" > /dev/null
}

# The plan of the root file system is data the monitor, which can be
# privileged, reads.  That of a mount of the storage driver names no path
# and no descriptor, only the place of the descriptor among those the engine
# passes (the engine checks the place and writes the plan again at every
# start, from the driver's answer); a plan of a kind this version does not
# have (a `composefs` plan, of an engine before the driver handed the mounts
# over, or any other) is invalid: the start is refused, naming the file,
# before anything is opened, written or mounted.
@test "a rootfs.json of another kind or with edited members is refused or made again: nothing is written or mounted" {
    id=$(sh_ container create --name tamper-cfs --network none "$IMAGE" sh -c 'echo ran > /tmp/ran; sleep 1000') || e2e_die "create"
    local bundle=$XDG_DATA_HOME/velarx/bundles/$id
    local plan=$bundle/rootfs.json victim=$WORKDIR/victim
    [ -f "$plan" ] || e2e_die "no plan at $plan"
    cp "$plan" "$WORKDIR/plan.good"
    check "the plan is a mount of the driver" mount-fd \
        "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["kind"])' "$plan")"
    check "and names no path" "fd_index kind" \
        "$(python3 -I -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1])))))' "$plan")"
    mkdir -p "$victim/dir"
    echo mine > "$victim/file"
    local before row text want
    before=$(find "$victim" | sort; cat "$victim/file")
    # refused: the text of the plan, and what the message says
    for row in \
        '{"kind":"composefs","layers":[],"image_id":"a","objects":"'$victim'/dir"}|composefs' \
        '{"kind":"squashfs"}|squashfs' \
        '{"kind":"mount-fd","fd_index":99}|fd_index 99' \
        '{"fd_index":0}|kind' \
        '{|rootfs.json'; do
        text=${row%|*}; want=${row##*|}
        printf '%s' "$text" > "$plan"
        out=$(sh_ container start tamper-cfs 2>&1); rc=$?
        [ "$rc" -ne 0 ] || e2e_die "$text: the start succeeded: $out"
        check_match "$text: the message names the file" "$bundle/rootfs.json" "$out"
        check_match "$text: and what is wrong with it" "$want" "$out"
        check "$text: the container did not run" 0 "$(sh_ container inspect --format '{{.State.Running}}' tamper-cfs | grep -c true)"
        [ ! -e "$bundle/rootfs/etc/passwd" ] || e2e_die "$text: a root file system was mounted"
        check "$text: nothing was written outside the store" "$before" "$(find "$victim" | sort; cat "$victim/file")"
        check "$text: the plan is left as it was" "$text" "$(cat "$plan")"
    done
    # made again: members that are not the plan's (a path, a layer) are not
    # read, and the monitor gets the driver's plan
    for row in \
        '{"kind":"mount-fd","fd_index":0,"profile":"'$victim'/file","objects":"'$victim'/dir"}' \
        '{"kind":"mount-fd","fd_index":0,"layers":[{"layer":"sha256:0","image":"/etc/passwd"}]}' \
        '{"kind":"mount-fd","fd_index":0,"idmap":true,"server":true}'; do
        printf '%s' "$row" > "$plan"
        sh_ container start tamper-cfs > /dev/null || e2e_die "$row: the start failed"
        check "$row: the plan is the driver's" "fd_index kind" \
            "$(python3 -I -c 'import json,sys; print(" ".join(sorted(k for k in json.load(open(sys.argv[1])) if k not in ("idmap", "server"))))' "$plan")"
        check "$row: the container runs on the root of the driver" ran "$(sh_ container exec tamper-cfs cat /tmp/ran)"
        check "$row: nothing was written outside the store" "$before" "$(find "$victim" | sort; cat "$victim/file")"
        sh_ container stop -t 0 tamper-cfs > /dev/null || e2e_die "$row: stop"
    done
    cp "$WORKDIR/plan.good" "$plan"
    sh_ container start tamper-cfs > /dev/null || e2e_die "start with the good plan"
    check "the container runs on the plan of the store" ran "$(sh_ container exec tamper-cfs cat /tmp/ran)"
    sh_ container rm -f -t 0 tamper-cfs > /dev/null
}

@test "exit code and finish time of a detached container" {
    id=$(sh_ container run -d --name dx --network none "$IMAGE" sh -c 'sleep 0.3; exit 6')
    check "run -d exit code" 0 $?
    check_match "run -d prints the id" "^[0-9a-f]{64}$" "$id"
    check "running" running "$(state_of dx)"
    out=$(sh_ container wait dx)
    check_match "wait gives the exit code of a detached container" "^6$" "$out"
    check "stopped" exited "$(state_of dx)"
    out=$(sh_ container inspect dx)
    check_match "inspect has the exit code" '"exit_code": 6' "$out"
    check_match "inspect has the finish time" '"finished_ns": [1-9][0-9]{18}' "$out"

    sh_ container start dx > /dev/null
    check "start an exited container" 0 $?
    out=$(sh_ container wait dx)
    check_match "the second run has its own exit code" "^6$" "$out"
    sh_ container rm dx > /dev/null
}

@test "stop and kill: the signal handler, the timeout, kill, a signal name" {
    sh_ container run -d --name sk --log-driver k8s-file --network none "$IMAGE" sh -c 'trap "exit 7" TERM; echo ready; while :; do sleep 0.1; done' > /dev/null
    wait_log sk ready
    start=$(now_ms)
    sh_ container stop -t 10 sk > /dev/null
    check "stop exit code" 0 $?
    elapsed=$(( $(now_ms) - start ))
    test $elapsed -lt 3000
    check "stop returns as soon as the container exits (${elapsed}ms)" 0 $?
    out=$(sh_ container wait sk)
    check_match "exit code of the stop signal handler" "^7$" "$out"

    sh_ container run -d --name sk2 --network none "$IMAGE" sleep 1000 > /dev/null
    start=$(now_ms)
    sh_ container stop -t 1 sk2 > /dev/null
    elapsed=$(( $(now_ms) - start ))
    test $elapsed -ge 900 -a $elapsed -lt 5000
    check "stop kills after the timeout (${elapsed}ms)" 0 $?
    out=$(sh_ container wait sk2)
    check_match "exit code after SIGKILL" "^137$" "$out"

    sh_ container run -d --name sk3 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container kill sk3 > /dev/null
    out=$(sh_ container wait sk3)
    check_match "kill" "^137$" "$out"

    sh_ container run -d --name sk4 --log-driver k8s-file --network none "$IMAGE" sh -c 'trap "exit 12" USR1; echo ready; while :; do sleep 0.1; done' > /dev/null
    wait_log sk4 ready
    sh_ container kill -s USR1 sk4 > /dev/null
    out=$(sh_ container wait sk4)
    check_match "kill with a signal name" "^12$" "$out"
    sh_ container rm -t 0 -f sk sk2 sk3 sk4 > /dev/null
}

# The deadline of a stop is the monitor's: the engine that asked for it is
# killed (SIGKILL) while the container ignores the signal, and the monitor
# kills the container at the deadline all the same.
@test "the engine is killed after a stop: the monitor kills the container at its deadline" {
    sh_ container run -d --name ek --log-driver k8s-file --network none "$IMAGE" sh -c 'trap "" TERM; echo ready; while :; do sleep 0.1; done' > /dev/null
    wait_log ek ready
    pid=$(inspect_of ek pid)
    sh_ container stop -t 2 ek > /dev/null 2>&1 3>&- &
    wait_state ek stopping
    check "the stop is under way" 0 $?
    kill "$(cat "$WORKDIR/api.pid")"
    rm -f "$WORKDIR/api.pid" "$SOCK"
    kill -9 "$DAEMON_PID"
    wait "$DAEMON_PID" 2> /dev/null || true
    DAEMON_PID=
    e2e_wait_exit "$pid" 5
    check "the container is gone at the deadline" 0 $?
    start_daemon
    check "stopped" exited "$(state_of ek)"
    sh_ container rm ek > /dev/null
}

# stop without -t: the container's stop signal and stop timeout
@test "stop without -t: the stop signal and the stop timeout of the container" {
    sh_ container run -d --name sk5 --log-driver k8s-file --stop-signal USR2 --network none "$IMAGE" \
        sh -c 'trap "exit 13" USR2; echo ready; while :; do sleep 0.1; done' > /dev/null
    wait_log sk5 ready
    sh_ container stop sk5 > /dev/null
    check_match "stop sends the stop signal" "^13$" "$(sh_ container wait sk5)"
    sh_ container run -d --name sk6 --stop-timeout 1 --network none "$IMAGE" sleep 1000 > /dev/null
    start=$(now_ms)
    sh_ container stop sk6 > /dev/null
    elapsed=$(( $(now_ms) - start ))
    test $elapsed -ge 900 -a $elapsed -lt 5000
    check "stop waits for the stop timeout (${elapsed}ms)" 0 $?
    sh_ container rm -t 0 -f sk5 sk6 > /dev/null
}

@test "kill with a real-time signal, an unknown signal, an invalid stop signal" {
    # SIGRTMIN is 34 for the C library of the host: RTMIN+6 is 40
    sh_ container run -d --name sk7 --log-driver k8s-file --network none "$IMAGE" \
        sh -c 'trap "exit 21" 40; echo ready; while :; do sleep 0.1; done' > /dev/null
    wait_log sk7 ready
    sh_ container kill -s SIGRTMIN+6 sk7 > /dev/null
    check_match "kill with a real-time signal" "^21$" "$(timeout 20 "$SH" container wait sk7)"
    sh_ container run -d --name sk8 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container kill -s BOGUS sk8 > /dev/null 2>&1
    check "an unknown signal is an error" yes "$(test $? -ne 0 && echo yes)"
    check "and the container still runs" running "$(state_of sk8)"
    sh_ container run -d --name sk9 --network none "$IMAGE" sh -c 'exit 0' > /dev/null
    sh_ container wait sk9 > /dev/null
    sh_ container create --name sk10 --stop-signal NOPE --network none "$IMAGE" true > /dev/null 2>&1
    check "an invalid stop signal is refused" yes "$(test $? -ne 0 && echo yes)"
    sh_ container rm -t 0 -f sk7 sk8 sk9 > /dev/null
}

# The daemon goes away and comes back; the monitors and the containers go on.
@test "the monitors and the containers outlive the daemon" {
    sh_ container run -d --name dr1 --network none "$IMAGE" sh -c 'sleep 5; exit 9' > /dev/null
    sh_ container run -d --name dr2 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container run -d --name dr3 --network none "$IMAGE" sh -c 'exit 4' > /dev/null
    wait_state dr3 exited
    stop_daemon
    n=$(e2e_monitors "$WORKDIR" | wc -l)
    test "$n" -ge 2
    check "monitors outlive the daemon" 0 $?

    start_daemon
    check "adopted: running" running "$(state_of dr1)"
    check "adopted: long running" running "$(state_of dr2)"
    out=$(sh_ container wait dr3)
    check_match "exited while the daemon was away" "^4$" "$out"
    out=$(sh_ container wait dr1)
    check_match "wait on an adopted container" "^9$" "$out"

    sh_ container stop -t 1 dr2 > /dev/null
    out=$(sh_ container wait dr2)
    check_match "stop an adopted container" "^137$" "$out"
    sh_ container rm dr1 dr2 dr3 > /dev/null
}

# A monitor that is killed (SIGKILL, a crash, the OOM killer) while its
# container runs: the server follows the container's process in its
# place; the container stays running, stop and kill reach it, its end is
# recorded (255: no status) with its died event and its restart policy
# applies.  So does the next server for one that lost its monitor while it
# was away, and the exit of one that ended then is a died event.
died_of () {
    sh_ events --stream=false --filter container="$1" --filter event=died 2>&1 | grep -c died
}

@test "a killed monitor: the container runs on, exec is refused, its end is recorded" {
    sh_ container run -d --name mk1 --log-driver k8s-file --network none "$IMAGE" sh -c 'echo hello; exec sleep 1000' > /dev/null
    # (written to the log before the monitor goes: a shell whose output has
    # no reader any more dies of SIGPIPE, and its line is lost)
    wait_log mk1 hello
    mon=$(monitor_of mk1)
    pid=$(inspect_of mk1 pid)
    check_match "mk1: its monitor" "^[0-9]+$" "$mon"
    kill_monitor mk1
    check "a killed monitor: the container still runs" running "$(state_of mk1)"
    check "its process too" 0 "$(kill -0 "$pid" 2> /dev/null; echo $?)"
    out=$(sh_ container exec mk1 true 2>&1)
    check_match "exec says why it cannot" "lost its monitor: exec and attach are unavailable" "$out"
    check "its log is still read" hello "$(sh_ container logs mk1 2>&1)"
    kill -9 "$pid"
    wait_state mk1 exited
    check "its process ends: stopped" exited "$(state_of mk1)"
    check "with 255" 255 "$(inspect_of mk1 exit_code)"
    check "and one died event" 1 "$(died_of mk1)"
    sh_ container rm mk1 > /dev/null
    check "and it is removed" 0 $?
}

# the same refusals through the REST API: 409 (podman's "container state
# improper")
@test "a killed monitor: the REST API refuses exec and attach with a 409" {
    e2e_need_api
    sh_ container run -d --name mka --network none "$IMAGE" sleep 1000 > /dev/null
    kill_monitor mka
    check "a killed monitor: the container still runs" running "$(state_of mka)"
    eid=$(curl -s --unix-socket "$SOCK" -XPOST -H 'Content-Type: application/json' -d '{"Cmd":["true"]}' \
        http://d/v1.41/containers/mka/exec | sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p')
    check_match "the API creates the exec" "^[0-9a-f]+$" "$eid"
    check "and refuses its start, with a 409" 409 "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" \
        -XPOST -H 'Content-Type: application/json' -d '{"Detach":false}' "http://d/v1.41/exec/$eid/start")"
    check "and an attach" 409 "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" \
        -XPOST "http://d/v1.41/containers/mka/attach?stream=1&stdout=1")"
    sh_ container rm -t 0 -f mka > /dev/null
    check "and it is removed" 0 $?
}

@test "stop and kill of a container without its monitor" {
    sh_ container run -d --name mk2 --network none "$IMAGE" sleep 1000 > /dev/null
    pid=$(inspect_of mk2 pid)
    kill_monitor mk2
    sh_ container stop -t 1 mk2 > /dev/null
    check "stop of a container without its monitor" 0 $?
    check "stopped" exited "$(state_of mk2)"
    check "its process is gone" 1 "$(kill -0 "$pid" 2> /dev/null; echo $?)"
    sh_ container rm mk2 > /dev/null

    sh_ container run -d --name mk6 --network none "$IMAGE" sleep 1000 > /dev/null
    kill_monitor mk6
    sh_ container kill mk6 > /dev/null
    check "kill of a container without its monitor" 0 $?
    wait_state mk6 exited
    check "stopped" exited "$(state_of mk6)"
    sh_ container rm mk6 > /dev/null
}

@test "a restart policy without the monitor" {
    sh_ container run -d --name mk3 --network none --restart always "$IMAGE" sleep 1000 > /dev/null
    pid=$(inspect_of mk3 pid)
    # (the engine follows the container to its end once it has seen the monitor
    # go: the container is killed after that, else its end is seen by no one)
    # (the stream is live once it shows the kept event of a marker made before; the
    # start of the container is its second start event)
    sh_ container create --name evmark --network none "$IMAGE" true > /dev/null
    "$SH" events --since 5m --stream > "$WORKDIR/mk3.ev" 2>&1 3>&- &
    local evp=$!
    e2e_wait_line "$WORKDIR/mk3.ev" 'container create .*name=evmark' 30 || e2e_die "the events stream does not start"
    sh_ container rm evmark > /dev/null
    kill_monitor mk3
    kill -9 "$pid"
    e2e_wait_line "$WORKDIR/mk3.ev" 'container start .*name=mk3' 30 2 || e2e_die "mk3 was not started again within 30 s"
    kill "$evp" 2> /dev/null
    wait "$evp" 2> /dev/null
    check "--restart always without its monitor: started again" running "$(state_of mk3)"
    check_match "by a new monitor" "^[0-9]+$" "$(monitor_of mk3)"
    sh_ container rm -f -t 0 mk3 > /dev/null
}

@test "a monitor killed while the daemon is away" {
    sh_ container run -d --name mk4 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container run -d --name mk5 --network none "$IMAGE" sleep 1000 > /dev/null
    mon4=$(monitor_of mk4)
    pid4=$(inspect_of mk4 pid)
    mon5=$(monitor_of mk5)
    pid5=$(inspect_of mk5 pid)
    stop_daemon
    kill -9 "$mon4" "$pid4" "$mon5"
    start_daemon
    check "monitor and container killed while the daemon was away: stopped" exited "$(state_of mk4)"
    check "with a died event" 1 "$(died_of mk4)"
    check "a monitor killed while the daemon was away: still running" running "$(state_of mk5)"
    kill -9 "$pid5"
    wait_state mk5 exited
    check "followed by the next daemon: stopped when it ends" exited "$(state_of mk5)"
    check "with a died event" 1 "$(died_of mk5)"
    sh_ container rm mk4 mk5 > /dev/null
    check "and they are removed" 0 $?
}

# The server starts again: `system restart` and SIGHUP execute it
# again, same pid, socket kept, configuration read again, containers on;
# varlink URI; the shutdown timeout.
@test "system restart and SIGHUP execute the server again" {
    sh_ container run -d --name srs --network none "$IMAGE" sleep 1000 > /dev/null
    pid=$DAEMON_PID
    daemon_forget_log
    sh_ system restart > /dev/null
    check "system restart" 0 $?
    wait_daemon_started
    "$SH" --socket "$ESOCK" health > /dev/null 2>&1
    check "the server answers again" 0 $?
    check "the container runs on" running "$(state_of srs)"
    check "as the same process" "$pid" "$(pgrep -f -- "--config $CONFIG varlink" | grep -x "$pid")"
    check_match "it says so" "Restarting" "$(cat "$WORKDIR/daemon.log")"
    # SIGHUP: the configuration is read again
    cp "$CONFIG" "$CONFIG.orig"
    printf 'events_logger = "none"\n' >> "$CONFIG"
    stop_daemon
    start_daemon
    { cat "$CONFIG.orig"; printf 'events_logger = "file"\nevents_logfile_path = "%s"\n' "$WORKDIR/reload-events.log"; } > "$CONFIG"
    daemon_forget_log
    kill -HUP "$DAEMON_PID"
    wait_daemon_started
    # (in the server: a command runs in its own engine)
    sh_ --socket "$ESOCK" container run --rm --name srh --network none "$IMAGE" true > /dev/null 2>&1
    e2e_wait_line "$WORKDIR/reload-events.log" '"Name":"srh"' 30
    grep -q '"Name":"srh"' "$WORKDIR/reload-events.log" 2> /dev/null
    check "SIGHUP reads the configuration again" 0 $?
    check "the container ran on" running "$(state_of srs)"
    sh_ container rm -t 0 -f srs > /dev/null
    stop_daemon
    mv "$CONFIG.orig" "$CONFIG"
}

# A restart lets the calls that change something finish: a create held by a
# precreate hook goes on while the engine restarts (a second SIGHUP meanwhile
# changes nothing), and a command issued during the restart waits for the
# engine that comes next, on the socket that stayed open.
@test "a restart lets a create in progress finish" {
    hd=$WORKDIR/slow-hooks.d
    mkdir -p "$hd"
    rm -f "$WORKDIR/slow.started" "$WORKDIR/slow.go"
    mkfifo "$WORKDIR/slow.go"
    cat > "$WORKDIR/slow.sh" << EOT
#!/bin/sh
touch "$WORKDIR/slow.started"
read -r _ < "$WORKDIR/slow.go"
exec cat
EOT
    chmod +x "$WORKDIR/slow.sh"
    printf '{"version":"1.0.0","hook":{"path":"%s"},"when":{"annotations":{"^e2e.slow$":"^yes$"}},"stages":["precreate"]}\n' \
        "$WORKDIR/slow.sh" > "$hd/10-slow.json"
    events_daemon "[containers]
hooks_dir = [\"$hd\"]"
    pid=$DAEMON_PID
    "$SH" --socket "$ESOCK" container create --name slowc --network none --annotation e2e.slow=yes \
        "$IMAGE" true > "$WORKDIR/slow.out" 2>&1 3>&- &
    creator=$!
    e2e_wait_path "$WORKDIR/slow.started"
    check "the create is in progress" 0 $?
    daemon_forget_log
    kill -HUP "$pid"
    e2e_wait_line "$WORKDIR/daemon.log" Restarting 30 || e2e_die "the engine did not restart within 30 s"
    kill -HUP "$pid"
    "$SH" --socket "$ESOCK" container list -a --format '{{.Names}}' > "$WORKDIR/slow.list" 2>&1 3>&- &
    lister=$!
    timeout 30 sh -c ': > "$1"' sh "$WORKDIR/slow.go" || e2e_die "the hook does not read its FIFO"
    wait "$creator"
    check "the create finished across the restart ($(cat "$WORKDIR/slow.out"))" 0 $?
    wait "$lister"
    check "a command issued during the restart is answered ($(cat "$WORKDIR/slow.list"))" 0 $?
    kill -0 "$pid"
    check "the same process serves (the second SIGHUP did not end it)" 0 $?
    check "the container is there" created "$(state_of slowc)"
    check "nothing was cut" "" "$(grep "cut by the restart" "$WORKDIR/daemon.log")"
    sh_ container rm -t 0 -f slowc > /dev/null
    rm -rf "$hd" "$WORKDIR"/slow.*
    events_daemon ""
}

# a restart runs the binary that runs, even replaced on disk
@test "a restart runs the binary that runs, even replaced on disk" {
    stop_daemon
    cp "$BIN/velarx" "$WORKDIR/velarx-old"
    daemon_spawn_ready "$WORKDIR/velarx-old" --config "$CONFIG" varlink
    cp "$BIN/velarx" "$WORKDIR/velarx-new" && mv -f "$WORKDIR/velarx-new" "$WORKDIR/velarx-old"
    daemon_forget_log
    sh_ system restart > /dev/null
    check "restart of a binary replaced on disk" 0 $?
    wait_daemon_started
    "$SH" --socket "$ESOCK" health > /dev/null 2>&1
    check "it serves again" 0 $?
    srv=$(pgrep -f "^$WORKDIR/velarx-old --config" | while read -r p; do [ "$(cat "/proc/$p/comm")" = velarx-server ] && echo "$p"; done | head -1)
    [ -z "$srv" ] && srv=$DAEMON_PID
    check_match "it runs the binary that ran (deleted on disk)" "velarx-old \\(deleted\\)$" "$(readlink "/proc/$srv/exe")"
    stop_daemon
    rm -f "$WORKDIR/velarx-old"
    start_daemon
}

# The lease of a pause (ContainerPause with `lease`, what the CRI's checkpoint
# takes): it ends the pause by itself unless somebody unpaused before, in
# whatever way; it is in the database, so an engine that restarts ends it.
@test "the lease of a pause: ended by any unpause, kept across a restart" {
    sh_ container run -d --name pls --network none "$IMAGE" sleep 1000 > /dev/null
    # (the pause is required: a container without a cgroup of its own to
    # freeze fails the test, it is not skipped)
    sh_ pause pls > /dev/null 2>&1 || e2e_die "pause of pls failed"
    sh_ unpause pls > /dev/null
    # (the state of the freezer of its cgroup: the record says running)
    frozen () {
        local pid cg
        pid=$(inspect_of "$1" pid)
        cg=$(sed -n 's/^0:://p' "/proc/$pid/cgroup")
        if [ "$(cat "/sys/fs/cgroup$cg/cgroup.freeze")" = 1 ]; then echo paused; else echo running; fi
    }
    lease () {
        varlinkctl call "unix:$ESOCK" org.velarx.Engine.ContainerPause \
            "{\"name\": \"$1\", \"pause\": true, \"lease\": $2}" > /dev/null
    }
    lease pls 2
    check "a pause with a lease" paused "$(frozen pls)"
    # an unpause that is not the lease's, then a pause of its own: the lease
    # is over and does not end that pause
    sh_ unpause pls > /dev/null
    sh_ pause pls > /dev/null
    # (a window: the lease of 2 s would have ended the pause by then)
    sleep 4
    check "the lease does not end another pause" paused "$(frozen pls)"
    sh_ unpause pls > /dev/null
    # the lease ends by itself (the freezer says so in cgroup.events)
    thawed () {
        e2e_wait_content "/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$(inspect_of pls pid)/cgroup")/cgroup.events" '^frozen 0$' 30 ||
            e2e_die "the pause of pls was not ended within 30 s"
    }
    lease pls 2
    thawed
    check "the lease ends the pause" running "$(frozen pls)"
    # the engine restarts meanwhile: the lease is armed again
    lease pls 4
    daemon_forget_log
    sh_ system restart > /dev/null
    wait_daemon_started
    thawed
    check "the lease ends the pause after a restart" running "$(frozen pls)"
    sh_ container rm -t 0 -f pls > /dev/null
}

# A paused container is alive, its monitor holds it: a start of it is
# refused as podman's, before anything is made, and what a container needs
# when it joins its namespaces does not start it either.  It stays paused,
# keeps its network, and unpause works.
@test "the start of a paused container is refused" {
    sh_ container run -d --name stp "$IMAGE" sleep 300 > /dev/null
    pid=$(inspect_of stp pid)
    nets () { sh_ container exec stp ls /sys/class/net | tr '\n' ' '; }
    net=$(nets)
    sh_ pause stp > /dev/null 2>&1 || e2e_die "pause of stp failed"
    out=$(sh_ container start stp 2>&1)
    check "the start fails" 125 $?
    id=$(inspect_of stp id)
    check "and says why" "Error: unable to start container \"$id\": container $id must be in Created or Stopped state to be started: container state improper" "$out"
    out=$(sh_ container run --rm --pid container:stp "$IMAGE" true 2>&1)
    check "a container that joins it fails" 125 $?
    check_match "and says why too" "must be in Created or Stopped state to be started" "$out"
    check "it stays paused" paused "$(state_of stp)"
    check "its monitor is the only one" 1 "$(pgrep -fc -- "^velarx-monitor: $(inspect_of stp id | cut -c1-12) ")"
    sh_ unpause stp > /dev/null
    check "unpause works" running "$(state_of stp)"
    check "it is the same process" "$pid" "$(inspect_of stp pid)"
    check "it has its network" "$net" "$(nets)"
    sh_ container rm -t 0 -f stp > /dev/null
}

# the shutdown timeout: a client that stays is cut at its end
@test "the shutdown timeout" {
    stop_daemon
    cp "$CONFIG" "$CONFIG.orig"
    printf 'shutdown_timeout_secs = 1\n' > "$WORKDIR/st.toml"
    python3 -I - "$CONFIG" << 'EOT'
import sys
p = sys.argv[1]
s = open(p).read().replace("[server]\n", "[server]\nshutdown_timeout_secs = 1\n", 1)
open(p, "w").write(s)
EOT
    start_daemon
    # (the stream is live once it shows the kept event of a marker made before)
    "$SH" --socket "$ESOCK" container create --name evmark --network none "$IMAGE" true > /dev/null
    "$SH" --socket "$ESOCK" events --since 5m --stream > "$WORKDIR/ev.out" 2>&1 3>&- &
    ev=$!
    e2e_wait_line "$WORKDIR/ev.out" 'container create .*name=evmark' 30 || e2e_die "the events stream does not start"
    start=$(now_ms)
    stop_daemon
    took=$(( $(now_ms) - start ))
    test "$took" -lt 4000
    check "the shutdown does not wait for a client that stays more than its timeout (${took}ms)" 0 $?
    kill "$ev" 2> /dev/null
    wait "$ev" 2> /dev/null
    mv "$CONFIG.orig" "$CONFIG"
    start_daemon
    sh_ container rm evmark > /dev/null
    # without clients, the default timeout (30 s) is not waited
    sh_ container list > /dev/null
    start=$(now_ms)
    stop_daemon
    took=$(( $(now_ms) - start ))
    test "$took" -lt 3000
    check "a shutdown without requests in progress is quick (${took}ms)" 0 $?
    start_daemon
}

# A container that exits while the daemon is away is --rm removed when it
# comes back.
@test "a --rm container that exits while the daemon is away is removed" {
    sh_ container run -d --rm --name drr --network none "$IMAGE" sh -c 'sleep 1; exit 3' > /dev/null
    pid=$(inspect_of drr pid)
    mon=$(monitor_of drr)
    stop_daemon
    e2e_wait_exit "$pid" 30 && e2e_wait_exit "$mon" 30 || e2e_die "the container and its monitor did not end within 30 s"
    start_daemon
    out=$(sh_ container list -a | grep -c drr)
    check "--rm container removed after the restart" 0 "$out"
}

# [server] runtime names the OCI runtime, like podman's --runtime; one that
# is not there is refused.
@test "the OCI runtime of the configuration" {
    stop_daemon
    cp "$CONFIG" "$CONFIG.orig"
    python3 -I - "$CONFIG" << 'EOT'
import sys
p = sys.argv[1]
s = open(p).read().replace("[server]\n", '[server]\nruntime = "crun"\n', 1)
open(p, "w").write(s)
EOT
    start_daemon
    sh_ container run --rm --network none "$IMAGE" printenv PATH > /dev/null 2>&1
    check "the runtime named in the configuration runs the container" 0 $?
    stop_daemon
    python3 -I - "$CONFIG" << 'EOT'
import sys
p = sys.argv[1]
s = open(p).read().replace('runtime = "crun"', 'runtime = "/no/such/runtime"', 1)
open(p, "w").write(s)
EOT
    out=$("$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check_match "a runtime that is not there is refused" \
        "no valid executable found for OCI runtime /no/such/runtime" "$out"
    mv "$CONFIG.orig" "$CONFIG"
    start_daemon
}

@test "run --timeout" {
    start=$(now_ms)
    sh_ container run --rm --timeout 2 --network none "$IMAGE" sleep 100 > /dev/null 2>&1
    rc=$?
    elapsed=$(( $(now_ms) - start ))
    check "--timeout kills the container: podman's -1, a run's 255" 255 $rc
    test $elapsed -ge 1800 -a $elapsed -lt 6000
    check "--timeout after its time (${elapsed}ms)" 0 $?
    sh_ container run --rm --timeout 5 --network none "$IMAGE" true
    check "a container that is done in time is left alone" 0 $?
    # The reason is recorded.
    sh_ container run -d --name to1 --timeout 1 --network none "$IMAGE" sleep 100 > /dev/null
    sh_ container wait to1 > /dev/null
    check "inspect says the time limit ended it" true "$(field timed_out to1)"
    sh_ container start to1 > /dev/null
    check "and forgets it when it starts again" false "$(field timed_out to1)"
    sh_ container rm -t 0 -f to1 > /dev/null
}

@test "restart policies" {
    sh_ container run -d --name rp1 --restart on-failure:2 --network none "$IMAGE" sh -c 'exit 1' > /dev/null
    wait_restarts rp1 2
    check "on-failure:2 restarts twice" 0 $?
    wait_state rp1 exited 5
    # (a window: no third run may follow)
    sleep 1.5
    check "and then gives up" 2 "$(field restart_count rp1)"
    check "stopped at the end" exited "$(state_of rp1)"
    check "with the exit code" 1 "$(field exit_code rp1)"
    sh_ container rm rp1 > /dev/null

    sh_ container run -d --name rp2 --restart on-failure --network none "$IMAGE" true > /dev/null
    wait_state rp2 exited
    # (a window: no restart may follow)
    sleep 1
    check "on-failure does not restart a success" 0 "$(field restart_count rp2)"
    sh_ container rm rp2 > /dev/null

    sh_ container run -d --name rp3 --restart always --network none "$IMAGE" sh -c 'sleep 0.3' > /dev/null
    wait_restarts rp3 3
    check "always restarts a success" 0 $?
    # The delay grows: 100 ms, 200 ms, 400 ms.
    sh_ container stop -t 1 rp3 > /dev/null
    n=$(field restart_count rp3)
    # (a window: no restart may follow, the delays of the policy are up to 400 ms)
    sleep 2
    check "stop ends the restarts" "$n" "$(field restart_count rp3)"
    check "and the container stays stopped" exited "$(state_of rp3)"
    sh_ container start rp3 > /dev/null
    wait_restarts rp3 $((n + 1)) 10
    check "a start brings the policy back" 0 $?
    sh_ container rm -t 0 -f rp3 > /dev/null

    sh_ container run -d --name rp4 --restart no --network none "$IMAGE" sh -c 'exit 3' > /dev/null
    wait_state rp4 exited
    # (a window: no restart may follow)
    sleep 1.5
    check "no policy, no restart" 0 "$(field restart_count rp4)"
    sh_ container rm rp4 > /dev/null

}

# The monitor restarts the container while the daemon is away.
@test "the monitor restarts the container while the daemon is away" {
    sh_ container run -d --name rp5 --log-driver k8s-file --restart always --network none "$IMAGE" sh -c 'echo run; sleep 1; exit 5' > /dev/null
    log=$XDG_DATA_HOME/velarx/logs/$(inspect_of rp5 id)/container.log
    stop_daemon
    # (the monitor starts the second run on its own: its second line)
    e2e_wait_line "$log" ' stdout F run$' 30 2 || e2e_die "rp5 was not restarted within 30 s"
    start_daemon
    test "$(field restart_count rp5)" -ge 1
    check "the container restarts while the daemon is away" 0 $?
    wait_state rp5 running 5
    check "and the daemon finds it running" 0 $?
    sh_ container rm -t 0 -f rp5 > /dev/null

}

# The restarts join the network namespace of the first run: the network
# the daemon set up for it is still there.
@test "the restarts join the network namespace of the first run" {
    sh_ container run -d --name rp7 --log-driver k8s-file --restart on-failure:1 "$IMAGE" \
        sh -c 'echo "net=$(ls /sys/class/net | grep -cv "^lo$") $(cat /proc/net/route | wc -l)"; sleep 0.3; exit 1' > /dev/null
    wait_log rp7 'net=.*' 30 2
    wait_state rp7 exited
    out=$(sh_ container logs rp7)
    check "the runs see the same network" 1 "$(echo "$out" | sort -u | wc -l)"
    # A root container gets a bridge network: the restart has it too.
    if test "$(id -u)" = 0; then
        check_match "the network stays across restarts" "^net=[1-9][0-9]* [0-9]+$" "$(echo "$out" | tail -1)"
    fi
    sh_ container rm -t 0 -f rp7 > /dev/null

}

# The containers whose namespaces a container joins are what it needs, as
# those it requires: the one that is stopped is started first.
@test "a container that joins the namespaces of a stopped container starts it" {
    sh_ container run -d --name jn1 --network none "$IMAGE" sleep 300 > /dev/null
    for mode in "--network container:jn1" "--pid container:jn1" "--ipc container:jn1" \
        "--uts container:jn1" "--cgroupns container:jn1"; do
        sh_ container stop -t 0 jn1 > /dev/null
        check "jn1 is stopped" exited "$(state_of jn1)"
        out=$(sh_ container run --rm $mode --name jn2 "$IMAGE" true 2>&1)
        check "run $mode" 0 $?
        check "$mode: the target runs" running "$(state_of jn1)"
    done
    # the target is the container named at the create, whatever its name is
    # now and whichever container has its old name
    sh_ container create --name jn3 --network container:jn1 "$IMAGE" sleep 300 > /dev/null
    sh_ container stop -t 0 jn1 > /dev/null
    sh_ container rename jn1 jn1-old
    sh_ container create --name jn1 --pid container:jn3 "$IMAGE" sleep 300 > /dev/null
    sh_ container start jn3 > /dev/null
    check "a renamed target is started" running "$(state_of jn1-old)"
    check "not the container of its old name" created "$(state_of jn1)"
    for c in jn1 jn3 jn1-old; do sh_ container rm -t 0 -f $c > /dev/null; done
    # a target that cannot start: the container does not start either
    sh_ container create --name jn4 "$IMAGE" /nonexistent > /dev/null
    sh_ container create --name jn5 --network container:jn4 "$IMAGE" true > /dev/null
    out=$(sh_ container start jn5 2>&1)
    check "the target cannot start: the start fails" 125 $?
    check_match "and says which" "cannot start $(inspect_of jn4 id), which the container needs: .*/nonexistent" "$out"
    check "the container is not started" created "$(state_of jn5)"
    sh_ container rm -t 0 -f jn5 > /dev/null
    sh_ container rm -t 0 -f jn4 > /dev/null
}

# A container that runs for a while waits less before its restart, but
# its restarts still count against the limit.
@test "a container that runs for a while is still bound by the limit" {
    sh_ container run -d --name rp6 --restart on-failure:1 --network none "$IMAGE" sh -c 'sleep 12; exit 1' > /dev/null
    wait_restarts rp6 1 40
    check "a long run is restarted" 0 $?
    # (a window: the second run ends after 12 s, no third may follow)
    wait_restarts rp6 2 20
    check "but only up to the limit" 1 $?
    check "the restarts are counted" 1 "$(field restart_count rp6)"
    sh_ container rm -t 0 -f rp6 > /dev/null
}

# The processes are named by what they do.
@test "the server process is named velarx-server" {
    n=0
    for p in $(pgrep -f -- "--config $CONFIG"); do
        test "$(cat "/proc/$p/comm" 2> /dev/null)" = velarx-server && n=$((n + 1))
    done
    check "the server is velarx-server" 1 "$n"
}

# Stopped and started again at once, 20 times: every start mounts the root
# file system where the previous monitor had it.
@test "20 stops and starts in a row, restarts" {
    sh_ container run -d --name qr --network none "$IMAGE" \
        sh -c 'trap "exit 0" TERM; cat /etc/alpine-release > /dev/null; while :; do sleep 0.1; done' > /dev/null
    failed=0
    for i in $(seq 20); do
        if ! out=$(sh_ container stop -t 2 qr 2>&1); then
            failed=$((failed + 1))
            echo "     stop $i: $out"
        fi
        if ! out=$(sh_ container start qr 2>&1); then
            failed=$((failed + 1))
            echo "     start $i: $out"
        fi
    done
    check "20 stops and starts in a row" 0 "$failed"
    check "and it runs" running "$(state_of qr)"
    out=$(sh_ container exec qr cat /etc/alpine-release 2>&1)
    check_match "with its root file system" "^[0-9.]+$" "$out"
    for i in $(seq 10); do
        if ! out=$(sh_ container restart -t 0 qr 2>&1); then
            failed=$((failed + 1))
            echo "     restart $i: $out"
        fi
    done
    check "10 restarts in a row" 0 "$failed"
    sh_ container rm -t 0 -f qr > /dev/null
    n=$(awk -v d="$WORKDIR" 'index($5, d "/") == 1' /proc/self/mountinfo | wc -l)
    check "nothing stays mounted" 0 "$n"
}
