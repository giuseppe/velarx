# SPDX-License-Identifier: Apache-2.0
# velarx - container runtime
#
# End to end test of `pod logs` and `pod logs --follow` as podman has them:
# the logs of the containers of a pod (the infra container too) merged by
# time as they are written, a line that starts with the ID or the name of its
# container, the containers that join the pod while it is followed left
# alone, the end with the infra container, the errors, and the daemon
# letting go of the logs when the client goes away.
#
# Environment:
#   VELARX_BINDIR  the directory with velarx, velarx-client and
#                    velarx-monitor
#   E2E_REGISTRY     registry with alpine:chunked (default localhost:5000)
#
# Run it as an ordinary user for the rootless daemon, or as root.  The pids
# of the followers the tests start are in $WORKDIR/followers.

load helpers


setup_file () {
    local b
    for b in velarx velarx-client velarx-monitor; do
        [ -x "${BIN:-${VELARX_BINDIR:-target/debug}}/$b" ] || skip "cannot find $b"
    done
    command -v crun > /dev/null || skip "crun is missing"
    curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    chmod 700 "$XDG_RUNTIME_DIR"
    mkdir -p "$XDG_CONFIG_HOME/velarx" "$XDG_DATA_HOME"
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" << EOF
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOF
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf
    export IMAGE=$E2E_REGISTRY/alpine:chunked
    e2e_start_daemon || exit 1
    "$SH" image pull "$IMAGE" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMAGE" "$WORKDIR/pull.log"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local p c dir=$WORKDIR
    for p in $(cat "$WORKDIR/followers" 2> /dev/null); do
        kill "$p" 2> /dev/null
    done
    if [ -n "$(cat "$WORKDIR/daemon.pid" 2> /dev/null)" ]; then
        for p in $(sh_ pod list -q 2> /dev/null); do
            sh_ pod rm -t 0 -f "$p" > /dev/null 2>&1
        done
        for c in $(sh_ container list -a 2> /dev/null | awk 'NR > 1 { print $1 }'); do
            sh_ container rm -t 0 -f "$c" > /dev/null 2>&1
        done
    fi
    e2e_detach_mounts "$dir"
    e2e_teardown_file
    [ -n "${E2E_KEEP:-}" ] || e2e_check_left "$dir"
}

sh_ () {
    "$SH" "$@"
}

# wait_exit PID SECONDS: the process ends in time; its status
wait_exit () {
    e2e_wait_exit "$1" "$2" || return 255
    wait "$1"
}

# the inotify watches of the daemon (its processes): one per log directory
# it follows (its one instance stays)
watches () {
    local n=0 p
    for p in $(pgrep -f -- "--config $XDG_CONFIG_HOME/velarx/config.toml varlink"); do
        n=$((n + $(cat /proc/$p/fdinfo/* 2> /dev/null | grep -c '^inotify wd:')))
    done
    echo $n
}

# the lines of a file on one line
flat () {
    tr '\n' ' ' | sed 's/ $//'
}

# pod_create NAME: a pod that runs
pod_create () {
    sh_ pod create --network none "$1" > /dev/null 2>&1 &&
        sh_ pod start "$1" > /dev/null 2>&1
}

# pod_run POD NAME SCRIPT
pod_run () {
    sh_ container run -d --pod "$1" --name "$2" --log-driver k8s-file "$IMAGE" sh -c "$3" > /dev/null
}

# the 12 first digits of the ID of a container
short_id () {
    sh_ container inspect "$1" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["id"][:12])'
}

@test "following a pod merges the containers by time, labelled with the names" {
    pod_create lf
    check "pod create" 0 $?
    # a prints at 0, 1, 2 s and b half a second later
    pod_run lf lf-a 'for i in 1 2 3; do echo a$i; sleep 1; done'
    pod_run lf lf-b 'sleep 0.5; for i in 1 2 3; do echo b$i; sleep 1; done'
    "$SH" pod logs --follow --names lf > "$WORKDIR/lf.out" 2> "$WORKDIR/lf.err" 3>&- &
    local pid=$!
    echo $pid >> "$WORKDIR/followers"
    e2e_wait_line "$WORKDIR/lf.out" 'lf-a a1' 20
    check "the first line arrives while the containers run" 0 $?
    check "the containers are still running" running \
        "$(sh_ container inspect lf-b | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["state"])')"
    e2e_wait_line "$WORKDIR/lf.out" 'lf-b b3' 20
    check "the last line arrives" 0 $?
    # as podman's: the infra container runs as long as the pod does, and the
    # following goes on with it (a window: it must not end on its own)
    sleep 1
    kill -0 $pid 2> /dev/null
    check "the command goes on while the infra container runs" 0 $?
    sh_ pod stop -t 0 lf > /dev/null 2>&1
    wait_exit $pid 60
    check "the command ends with the pod" 0 $?
    check "the lines are merged by time and labelled with the names" \
        "lf-a a1 lf-b b1 lf-a a2 lf-b b2 lf-a a3 lf-b b3" \
        "$(flat < "$WORKDIR/lf.out")"
    check "no error output" "" "$(cat "$WORKDIR/lf.err")"
}

@test "pod logs options: IDs, timestamps, --container, --tail, --since and errors" {
    local ida idb out rc
    ida=$(short_id lf-a)
    idb=$(short_id lf-b)
    check "the lines start with the ID of the container, as podman's" \
        "$ida a1 $idb b1 $ida a2 $idb b2 $ida a3 $idb b3" \
        "$(sh_ pod logs --follow lf 2>&1 | flat)"
    out=$(sh_ pod logs --follow --timestamps --names lf 2>&1 | head -1)
    case $out in
        "lf-a 20"*[Z0-9]" a1") ;;
        *) echo "FAIL --timestamps: actual: $out" >&2; exit 1 ;;
    esac
    check "--timestamps has the nine digits of podman's" yes \
        "$(echo "$out" | grep -qE '^lf-a [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}\.[0-9]{9}(Z|[+-][0-9]{2}:[0-9]{2}) a1$' && echo yes)"
    check "--container: one container has no prefix" "b1 b2 b3" \
        "$(sh_ pod logs --follow --container lf-b lf 2>&1 | flat)"
    check "--tail is of each container" "lf-a a3 lf-b b3" \
        "$(sh_ pod logs --follow --tail 1 --names lf 2>&1 | flat)"
    check "--tail 0 gives nothing of a pod that ended" "" \
        "$(sh_ pod logs --follow --tail 0 lf 2>&1 | flat)"
    check "the same lines without --follow" \
        "lf-a a1 lf-b b1 lf-a a2 lf-b b2 lf-a a3 lf-b b3" \
        "$(sh_ pod logs --names lf 2>&1 | flat)"
    check "--tail without --follow" "lf-a a3 lf-b b3" \
        "$(sh_ pod logs --tail 1 --names lf 2>&1 | flat)"
    check "--tail -1 is all of it" 6 "$(sh_ pod logs --tail -1 lf 2>&1 | wc -l)"
    check "--since after the lines" "" "$(sh_ pod logs --follow --since 1m lf 2>&1 | grep -c . | sed 's/^6$//')"
    out=$(sh_ pod logs --follow --container nope lf 2>&1)
    rc=$?
    check "--container of a container that is not in the pod" \
        "Error: container nope is not in pod lf: no such container 125" "$out $rc"
    out=$(sh_ pod logs --container nope lf 2>&1)
    check "the same without --follow" "Error: container nope is not in pod lf: no such container" "$out"
    out=$(sh_ pod logs --follow --since nonsense lf 2>&1)
    rc=$?
    check "--since that is not a time" \
        "Error: parsing --since \"nonsense\": unable to interpret time value 125" "$out $rc"
    out=$(sh_ pod logs --follow nopod 2>&1)
    rc=$?
    check "a pod that is not there" "Error: no pod with name or ID nopod found: no such pod 125" "$out $rc"
    out=$(sh_ pod logs 2>&1)
    rc=$?
    check "no pod" "Error: specify at least one pod name or ID to log 125" "$out $rc"
}

@test "stdout and stderr of the containers, --color, the none log driver" {
    pod_create ls
    pod_run ls ls-a 'echo out; echo err >&2; sleep 1'
    pod_run ls ls-b 'sleep 0.3; echo second'
    sh_ container wait ls-a ls-b > /dev/null
    sh_ pod stop -t 0 ls > /dev/null 2>&1
    sh_ pod logs --names ls > "$WORKDIR/ls.out" 2> "$WORKDIR/ls.err"
    check "the stdout of the containers" "ls-a out ls-b second" "$(flat < "$WORKDIR/ls.out")"
    check "the stderr of the containers goes to stderr" "ls-a err" "$(flat < "$WORKDIR/ls.err")"
    sh_ pod logs --follow --names ls > "$WORKDIR/ls.out" 2> "$WORKDIR/ls.err"
    check "the same while following" "ls-a err" "$(flat < "$WORKDIR/ls.err")"
    esc=$(printf '\033')
    check "--color gives each container a color, the infra container the first" \
        "${esc}[31mls-a out${esc}[0m ${esc}[33mls-b second${esc}[0m" \
        "$(sh_ pod logs --color --names ls 2> /dev/null | flat)"

    # a log driver that keeps no log is an error before anything is shown
    pod_create ln
    sh_ container run -d --pod ln --name ln-a "$IMAGE" echo hi > /dev/null
    sh_ container run -d --pod ln --name ln-n --log-driver none "$IMAGE" echo hi > /dev/null
    sh_ container wait ln-a ln-n > /dev/null
    out=$(sh_ pod logs ln 2>&1)
    rc=$?
    check "a container with the none log driver" \
        "Error: this container is using the 'none' log driver, cannot read logs: this container is not logging output 125" \
        "$out $rc"
    out=$(sh_ pod logs --follow ln 2>&1)
    check "and while following" \
        "Error: this container is using the 'none' log driver, cannot read logs: this container is not logging output" "$out"
    check "the other containers can be read" "hi" "$(sh_ pod logs -c ln-a ln 2>&1)"
}

@test "a pod whose containers have not started" {
    sh_ pod create --network none lns > /dev/null 2>&1
    sh_ container create --pod lns --name lns-a "$IMAGE" echo hi > /dev/null
    timeout 20 "$SH" pod logs --follow lns > "$WORKDIR/lns.out" 2>&1
    check "a pod whose containers have not started: the command ends at once" 0 $?
    check "with nothing to show" "" "$(cat "$WORKDIR/lns.out")"
}

@test "a container that joins the pod while it is followed is not followed" {
    pod_create lj
    pod_run lj lj-x 'echo x-early; sleep 2; echo x-late; sleep 1'
    "$SH" pod logs --follow --names lj > "$WORKDIR/lj.out" 2>&1 3>&- &
    local pid=$!
    echo $pid >> "$WORKDIR/followers"
    # (the containers it follows are known once it shows the first line)
    e2e_wait_line "$WORKDIR/lj.out" 'x-early' 20
    # added to the pod while it is followed: as with podman, it is not
    pod_run lj lj-y 'echo y-joined; sleep 1; echo y-done'
    e2e_wait_line "$WORKDIR/lj.out" 'x-late' 20
    check "the containers of the pod when the following starts are followed" 0 $?
    sh_ container wait lj-y > /dev/null
    sh_ pod stop -t 0 lj > /dev/null 2>&1
    wait_exit $pid 60
    check "the command ends with the pod" 0 $?
    check "a container that joins is not followed" "lj-x x-early lj-x x-late" "$(flat < "$WORKDIR/lj.out")"
}

@test "a restarted container is followed to the end" {
    pod_create lr
    sh_ container run -d --pod lr --name lr-a --restart on-failure:2 "$IMAGE" \
        sh -c 'echo run; sleep 0.3; exit 1' > /dev/null
    "$SH" pod logs --follow --container lr-a lr > "$WORKDIR/lr.out" 2>&1 3>&- &
    local pid=$!
    echo $pid >> "$WORKDIR/followers"
    e2e_wait_line "$WORKDIR/lr.out" 'run' 20
    e2e_wait_line "$WORKDIR/lr.out" '^run$' 30 3
    check "the runs of a restarted container" 3 "$(grep -c '^run$' "$WORKDIR/lr.out")"
    wait_exit $pid 60
    check "the command ends after the last restart" 0 $?
}

@test "the daemon lets go of the log when the client goes away" {
    pod_create ld
    pod_run ld ld-a 'echo up; sleep 300'
    local before
    before=$(watches)
    # (in the daemon, whose watches are counted)
    "$SH" --socket "$ESOCK" pod logs --follow --container ld-a ld > "$WORKDIR/ld.out" 2>&1 3>&- &
    local pid=$!
    echo $pid >> "$WORKDIR/followers"
    e2e_wait_line "$WORKDIR/ld.out" 'up' 20
    check "a running pod is followed" 0 $?
    check "the daemon watches the log" yes "$(test "$(watches)" -gt "$before" && echo yes)"
    kill -INT $pid
    wait $pid 2> /dev/null
    check "an interrupt ends the command with the status 1, as podman's" 1 $?
    # (a poll of a kernel count: the inotify watches of the daemon have no notification)
    local deadline=$((SECONDS + 20))
    while test "$(watches)" -gt "$before" && test $SECONDS -lt $deadline; do
        sleep 0.1
    done
    check "the daemon lets go of the log when the client goes away" "$before" "$(watches)"
    sh_ pod rm -t 0 -f ld > /dev/null 2>&1
}

