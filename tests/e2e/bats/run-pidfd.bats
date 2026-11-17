# SPDX-License-Identifier: Apache-2.0
# End to end tests of the way the monitor follows the container process: by
# its pidfd, with no timer.  Run it as an ordinary user for the rootless
# daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# The voluntary context switches of a process: how often it went to sleep
# to wait.  A loop with a timer shows here, an event does not.
switches_of () {
    awk '/voluntary_ctxt_switches/ { n += $2 } END { print n }' "/proc/$1/status"
}

# The pidfds the process $1 holds, of the process $2 when given (the "Pid:"
# line of their fdinfo): the monitor holds one of the image server of its
# root file system too, which names that server.
pidfds_of () {
    local n=0 l f
    for f in /proc/"$1"/fd/*; do
        l=$(readlink "$f" 2> /dev/null)
        case "$l" in *'anon_inode:[pidfd]') ;; *) continue ;; esac
        if [ -n "$2" ]; then
            grep -qx "Pid:[[:space:]]*$2" "/proc/$1/fdinfo/${f##*/}" 2> /dev/null || continue
        fi
        n=$((n + 1))
    done
    echo "$n"
}

@test "kill -9 of the container process from outside is seen at once" {
    sh_ container run -d --name pf1 --network none "$IMAGE" sleep 1000 > /dev/null
    pid=$(inspect_of pf1 pid)
    check_match "its pid" "^[0-9]+$" "$pid"
    sh_ container wait pf1 > "$WORKDIR/pf1.wait" &
    waiter=$!
    wait_state pf1 running || e2e_die "pf1 is not running"
    t=$(now_ms)
    kill -9 "$pid"
    wait "$waiter"
    took=$(( $(now_ms) - t ))
    echo "# exit of the container seen by 'wait' ${took} ms after kill -9" >&3
    check "the status is 137" 137 "$(cat "$WORKDIR/pf1.wait")"
    test "$took" -lt 500
    check "seen within 500 ms (no polling interval)" 0 $?
    sh_ container rm pf1 > /dev/null
}

@test "an idle monitor with a running container does not wake up" {
    sh_ container run -d --name pf2 --network none "$IMAGE" sleep 1000 > /dev/null
    mon=$(monitor_of pf2)
    check_match "its monitor" "^[0-9]+$" "$mon"
    wait_state pf2 running || e2e_die "pf2 is not running"
    before=$(switches_of "$mon")
    # (a window: the wake-ups of 3 s of idleness are counted)
    sleep 3
    after=$(switches_of "$mon")
    echo "# monitor wake-ups in 3 s of idleness: $((after - before))" >&3
    test $((after - before)) -le 3
    check "no periodic wake-up" 0 $?
    sh_ container rm -f -t 0 pf2 > /dev/null
}

@test "no pidfd or inotify descriptor of the monitor reaches the container or its commands" {
    sh_ container run -d --name pf3 --network none "$IMAGE" sleep 1000 > /dev/null
    out=$(sh_ container exec pf3 ls -l /proc/self/fd 2>&1)
    check "no descriptor of the monitor in an exec" "" "$(echo "$out" | grep -E 'anon_inode:.?(pidfd|inotify)')"
    out=$(sh_ container exec pf3 ls -l /proc/1/fd 2>&1)
    check "none in the init" "" "$(echo "$out" | grep -E 'anon_inode:.?(pidfd|inotify)')"
    mon=$(monitor_of pf3)
    check "the monitor holds the pidfd of the init" 1 "$(pidfds_of "$mon" "$(inspect_of pf3 pid)")"
    sh_ container rm -f -t 0 pf3 > /dev/null
}

@test "a restart replaces the pidfd of the monitor" {
    sh_ container run -d --name pf4 --log-driver k8s-file --network none --restart always "$IMAGE" sh -c 'echo up; exec sleep 1000' > /dev/null
    wait_log pf4 up
    mon=$(monitor_of pf4)
    pid=$(inspect_of pf4 pid)
    # (the image server's pidfd stays; the init's is replaced)
    all=$(pidfds_of "$mon")
    for i in 1 2 3; do
        kill -9 "$pid"
        # (the old process gone, then the next run of the policy: running,
        # with a process of its own)
        e2e_wait_exit "$pid" 30 || e2e_die "the killed process $pid of run $i is still there"
        # (every run says "up": the line of the next run, then its state)
        wait_log pf4 up 30 $((i + 1))
        wait_state pf4 running || e2e_die "pf4 does not run again"
        new=$(inspect_of pf4 pid)
        test "$new" != "$pid"
        check "run $i has a new process" 0 $?
        pid=$new
        check "one pidfd of an init, the one of this run" 1 "$(pidfds_of "$mon" "$pid")"
        check "no pidfd is left of the runs before" "$all" "$(pidfds_of "$mon")"
    done
    sh_ container rm -f -t 0 pf4 > /dev/null
}

@test "a stop that is not obeyed ends with the kill after its timeout" {
    sh_ container run -d --name pf5 --network none "$IMAGE" sh -c 'trap "" TERM; while :; do sleep 1; done' > /dev/null
    wait_state pf5 running || e2e_die "pf5 is not running"
    t=$(now_ms)
    sh_ container stop -t 1 pf5 > /dev/null
    took=$(( $(now_ms) - t ))
    echo "# stop -t 1 of a container that ignores SIGTERM took ${took} ms" >&3
    test "$took" -ge 1000 && test "$took" -lt 3000
    check "killed after the timeout" 0 $?
    check "with 137" 137 "$(inspect_of pf5 exit_code)"
    sh_ container rm pf5 > /dev/null
}

@test "a command that ends at once gives its own status, never a lost one" {
    sh_ container run -d --name pf4 --log-driver k8s-file --network none "$IMAGE" sleep 1000 > /dev/null
    # right after the container started, as ExecSync and a health check do
    deadline=$(( $(now_ms) + 60000 ))
    n=0 bad=0
    while [ "$n" -lt "${EXEC_LOOP:-300}" ] && [ "$(now_ms)" -lt "$deadline" ]; do
        sh_ container exec pf4 true > /dev/null 2>&1 || bad=$((bad + 1))
        rc=0
        sh_ container exec pf4 sh -c 'exit 3' > /dev/null 2>&1 || rc=$?
        [ "$rc" -eq 3 ] || bad=$((bad + 1))
        n=$((n + 1))
    done
    echo "# $n rounds of two execs, $bad with a wrong status" >&3
    check "no wrong status" 0 "$bad"
    test "$n" -ge 20
    check "the loop ran" 0 $?
    sh_ container rm -f -t 0 pf4 > /dev/null
}
