# SPDX-License-Identifier: Apache-2.0
# The overlay of the root file system of a container that is thrown away
# (`--rm`, a step of a build) is mounted `volatile` as podman's is, and the
# overlay of any other container is not: seen in the mounts of the container.
# Run it as an ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# options_of ARGS...: the options of the root file system of a container
# that runs `cat /proc/self/mountinfo` (`volatile` is shown by the kernel as
# `volatile` or, in the newer ones, as `fsync=volatile`).
options_of () {
    sh_ container run --network none "$@" cat /proc/self/mountinfo | grep ' - overlay ' | head -1
}

is_volatile () {
    grep -Eq '(^|[ ,])(fsync=)?volatile(,|$)' <<< "$1" && echo volatile || echo plain
}

@test "volatile: --rm yes, without --rm no, with a restart policy no" {
    check "run --rm" volatile "$(is_volatile "$(options_of --rm "$IMAGE")")"
    check "run" plain "$(is_volatile "$(options_of "$IMAGE")")"
    check "run --restart always" plain "$(is_volatile "$(options_of --restart always "$IMAGE")")"
    sh_ container rm -t 0 -af > /dev/null 2>&1
}

@test "volatile: create --rm then start; the containers of a pod" {
    id=$(sh_ container create --rm --network none "$IMAGE" sleep 60)
    sh_ container start "$id" > /dev/null
    out=$(sh_ container exec "$id" cat /proc/self/mountinfo | grep ' - overlay ' | head -1)
    check "create --rm, start" volatile "$(is_volatile "$out")"
    sh_ container rm -t 0 -f "$id" > /dev/null
    sh_ pod create --name vpod --network none > /dev/null || exit 1
    for rm in --rm ""; do
        out=$(sh_ container run $rm --pod vpod "$IMAGE" cat /proc/self/mountinfo | grep ' - overlay ' | head -1)
        check "a container of a pod ($rm)" "$([ -n "$rm" ] && echo volatile || echo plain)" "$(is_volatile "$out")"
    done
    sh_ pod rm -t 0 -f vpod > /dev/null
}

@test "volatile: --rm with a restart policy other than no and on-failure is refused, as podman does" {
    local msg='Error: the --rm option conflicts with --restart, when the restartPolicy is not "" and "no"'
    local before
    before=$(sh_ container list -aq | wc -l)
    for policy in always unless-stopped on-failure:3; do
        for verb in run create; do
            run "$SH" container $verb --rm --restart "$policy" --network none "$IMAGE" true
            check "$verb --rm --restart $policy" "125 $msg" "$status $output"
        done
    done
    check "run --rm --restart on-failure" volatile "$(is_volatile "$(options_of --rm --restart on-failure "$IMAGE")")"
    check "run --rm --restart no" volatile "$(is_volatile "$(options_of --rm --restart no "$IMAGE")")"
    check "nothing was made" "$before" "$(sh_ container list -aq | wc -l)"
}

@test "volatile: the mark the kernel left in the work directory does not stop the next mount" {
    id=$(sh_ container create --rm --network none "$IMAGE" cat /proc/self/mountinfo)
    # (what a volatile mount of a run that crashed leaves)
    mkdir -p "$XDG_DATA_HOME/velarx/bundles/$id/overlay/work/work/incompat/volatile/dirty" || exit 1
    out=$(sh_ container start -a "$id" | grep ' - overlay ' | head -1)
    check "started with the mark there" volatile "$(is_volatile "$out")"
}

@test "volatile: commit, export, diff, cp, top and exec of a running --rm container" {
    id=$(sh_ container run -d --rm --network none "$IMAGE" sleep 120)
    sh_ container exec "$id" sh -c 'echo kept > /data; sync' || exit 1
    check "exec sees the file" kept "$(sh_ container exec "$id" cat /data)"
    check_match "diff" "/data" "$(sh_ container diff "$id")"
    sh_ container cp "$id:/data" "$WORKDIR/data" || exit 1
    check "cp" kept "$(cat "$WORKDIR/data")"
    echo in > "$WORKDIR/in"
    sh_ container cp "$WORKDIR/in" "$id:/in" || exit 1
    check "cp into it" in "$(sh_ container exec "$id" cat /in)"
    check_match "top" "sleep" "$(sh_ container top "$id")"
    sh_ container export "$id" > "$WORKDIR/export.tar" || exit 1
    check "export has the file" 1 "$(tar -tf "$WORKDIR/export.tar" | grep -c '^data$')"
    sh_ container commit "$id" localhost/volatile-commit:1 > /dev/null || exit 1
    check "the image of the commit has the file" kept \
        "$(sh_ container run --rm --network none localhost/volatile-commit:1 cat /data)"
    sh_ container rm -t 0 -f "$id" > /dev/null
    check "the --rm container is gone" 0 "$(sh_ container list -a | grep -c "${id:0:12}")"
}

@test "volatile: the steps of a build are, the image they make is not" {
    mkdir -p "$WORKDIR/vctx"
    cat > "$WORKDIR/vctx/Containerfile" << EOF2
FROM $IMAGE
RUN grep ' - overlay ' /proc/self/mountinfo | grep -Eq '(^|[ ,])(fsync=)?volatile(,|\$)' && echo volatile > /step1
RUN echo two > /step2
EOF2
    sh_ image build -q -t localhost/volatile-build:1 "$WORKDIR/vctx" > "$WORKDIR/build.out" 2>&1 || { cat "$WORKDIR/build.out" >&2; exit 1; }
    check "a RUN step is volatile" volatile \
        "$(sh_ container run --rm --network none localhost/volatile-build:1 cat /step1)"
    check "and what the steps wrote is in the layers" two \
        "$(sh_ container run --rm --network none localhost/volatile-build:1 cat /step2)"
    check "a container of the image is not" plain \
        "$(is_volatile "$(options_of localhost/volatile-build:1)")"
    sh_ container rm -t 0 -af > /dev/null 2>&1
}

@test "volatile: a --rm container that lost its monitor is removed when it ends, with its upper layer" {
    sh_ container run -d --rm --name vcrash --network none "$IMAGE" sleep 1000 > /dev/null
    id=$(inspect_of vcrash id)
    pid=$(inspect_of vcrash pid)
    kill_monitor vcrash
    kill -9 "$pid"
    sh_ container wait vcrash > /dev/null 2>&1
    check "gone" 0 "$(sh_ container list -a | grep -c vcrash)"
    check "and its directory" 0 "$(find "$XDG_DATA_HOME" -maxdepth 4 -type d -name "$id" | wc -l)"
}

@test "volatile: a --rm container that lost its monitor while the engine was down is removed at its start" {
    sh_ container run -d --rm --name vdown --network none "$IMAGE" sleep 1000 > /dev/null
    id=$(inspect_of vdown id)
    pid=$(inspect_of vdown pid)
    mon=$(monitor_of vdown)
    stop_daemon
    kill -9 "$mon" "$pid"
    start_daemon
    # (the engine sets right what it finds as it starts, the monitors that
    # are gone too)
    e2e_wait_gone "$XDG_DATA_HOME/velarx/bundles/$id" 30
    check "gone" 0 "$(sh_ container list -a | grep -c vdown)"
    check "and its directory" 0 "$(find "$XDG_DATA_HOME" -maxdepth 4 -type d -name "$id" | wc -l)"
}

# podman's restart does not remove an `--rm` container: it stops and starts it
@test "--rm: restart keeps the container, its upper layer and the volatile mount" {
    id=$(sh_ container run -d --rm --name rmrestart --network none "$IMAGE" sleep 1000)
    sh_ container exec rmrestart sh -c 'echo kept > /data; sync' || exit 1
    pid=$(inspect_of rmrestart pid)
    out=$(sh_ container restart -t 0 rmrestart 2>&1)
    check "restart prints the name, exits 0" "0 rmrestart" "$? $out"
    check "it runs" running "$(state_of rmrestart)"
    check "the same container" "$id" "$(inspect_of rmrestart id)"
    test "$(inspect_of rmrestart pid)" != "$pid"
    check "a new process" 0 $?
    check "the upper layer is reused" kept "$(sh_ container exec rmrestart cat /data)"
    check "still volatile" volatile \
        "$(is_volatile "$(sh_ container exec rmrestart cat /proc/self/mountinfo | grep ' - overlay ' | head -1)")"
    sh_ container restart -t 0 rmrestart > /dev/null
    check "and again" running "$(state_of rmrestart)"
    sh_ container stop -t 0 rmrestart > /dev/null
    check "a stop removes it" 0 "$(sh_ container list -a | grep -c rmrestart)"
    sh_ container start rmrestart > /dev/null 2>&1
    check "and it cannot be started" 125 $?
}

@test "--rm: restart --all keeps the container, a kill removes it" {
    sh_ container run -d --rm --name rmall --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container restart --all -t 0 > /dev/null
    check "restart --all keeps it" running "$(state_of rmall)"
    sh_ container kill rmall > /dev/null
    wait_removed rmall
    check "a kill removes it" 0 "$(sh_ container list -a | grep -c rmall)"
}

# podman's pod restart keeps its `--rm` members, its pod stop leaves them
# stopped (until they start again); a stop or a kill of one removes it
@test "--rm: the members of a pod: pod restart, pod stop, pod start, stop, pod kill" {
    # (a member that ends at once on SIGTERM: pod restart has no -t)
    local quick='trap "exit 0" TERM; sleep 1000 & wait'
    sh_ pod create --name rmpod --network none > /dev/null || exit 1
    sh_ container run -d --rm --pod rmpod --name rmpod-a "$IMAGE" sh -c "$quick" > /dev/null
    sh_ container run -d --pod rmpod --name rmpod-b "$IMAGE" sh -c "$quick" > /dev/null
    pid=$(inspect_of rmpod-a pid)
    out=$(sh_ pod restart rmpod 2>&1)
    check "pod restart" 0 $?
    check "the --rm member runs again" running "$(state_of rmpod-a)"
    test "$(inspect_of rmpod-a pid)" != "$pid"
    check "a new process" 0 $?
    check "and the other" running "$(state_of rmpod-b)"
    sh_ pod stop -t 0 rmpod > /dev/null
    check "pod stop leaves the --rm member stopped" exited "$(state_of rmpod-a)"
    sh_ pod start rmpod > /dev/null
    check "pod start starts it" running "$(state_of rmpod-a)"
    sh_ pod stop -t 0 rmpod > /dev/null
    out=$(sh_ container stop rmpod-a 2>&1)
    check "a stop of the stopped member prints its name" "0 rmpod-a" "$? $out"
    check "and removes it" 0 "$(sh_ container list -a | grep -c rmpod-a)"
    sh_ pod start rmpod > /dev/null
    sh_ container run -d --rm --pod rmpod --name rmpod-a "$IMAGE" sh -c "$quick" > /dev/null
    sh_ pod kill rmpod > /dev/null
    wait_removed rmpod-a
    check "pod kill removes it" 0 "$(sh_ container list -a | grep -c rmpod-a)"
    check "not the other" exited "$(state_of rmpod-b)"
    sh_ pod rm -t 0 -f rmpod > /dev/null
}

# podman's stop removes an `--rm` container that does not run, and one that
# other containers depend on is not removed as it exits
@test "--rm: stop of a created container removes it; a dependency stays" {
    sh_ container create --rm --name rmcreated "$IMAGE" true > /dev/null
    out=$(sh_ container stop rmcreated 2>&1)
    check "stop of a created --rm container" "0 rmcreated" "$? $out"
    check "removes it" 0 "$(sh_ container list -a | grep -c rmcreated)"
    sh_ container run -d --rm --name rmdep --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container run -d --requires rmdep --name rmuser --network none "$IMAGE" sleep 1000 > /dev/null
    out=$(sh_ container stop -t 0 rmdep 2>&1)
    check_match "the stop says why it is not removed" "has dependent containers which must be removed before it: [0-9a-f]{64}: container already exists" "$out"
    check "it stays stopped" exited "$(state_of rmdep)"
    sh_ container rm -f -t 0 rmuser > /dev/null
    sh_ container rm rmdep > /dev/null
    check "and goes with rm" 0 "$(sh_ container list -a | grep -c rmdep)"
}

# podman accepts `--rm --restart on-failure` (without a count) and restarts
# the container on a failure; it is removed when it ends for good
@test "--rm --restart on-failure: restarted on a failure, removed when it ends" {
    mkdir -p "$WORKDIR/rmfail"
    # (fails the first run, ends well the second: the file of its upper layer
    # tells the runs apart, the one of the directory counts them)
    id=$(sh_ container run -d --rm --restart on-failure --name rmfail --network none \
        -v "$WORKDIR/rmfail:/m:z" "$IMAGE" \
        sh -c 'echo run >> /m/runs; if [ -e /flag ]; then exit 0; fi; touch /flag; exit 3')
    wait_removed rmfail
    check "gone" 0 "$(sh_ container list -a | grep -c rmfail)"
    check "it ran twice" 2 "$(wc -l < "$WORKDIR/rmfail/runs")"
    e2e_wait_gone "$XDG_DATA_HOME/velarx/bundles/$id" 30
    check "and its directory" 0 "$(find "$XDG_DATA_HOME" -maxdepth 4 -type d -name "$id" | wc -l)"
}

@test "--rm --restart on-failure: a stop ends the restarts and removes it" {
    sh_ container run -d --rm --restart on-failure --name rmstop --network none "$IMAGE" sh -c 'sleep 0.2; exit 1' > /dev/null
    wait_restarts rmstop 2 || exit 1
    check "a restarting container is there" 1 "$(sh_ container list -a | grep -c rmstop)"
    sh_ container stop -t 0 rmstop > /dev/null
    check "stopped, so removed" 0 "$(sh_ container list -a | grep -c rmstop)"
}

@test "--rm --restart on-failure: an exit 0 removes it; with no policy the exit code is the container's" {
    sh_ container run -d --rm --restart on-failure --name rmok --network none "$IMAGE" true > /dev/null
    wait_removed rmok
    check "removed after a success" 0 "$(sh_ container list -a | grep -c rmok)"
    check "foreground exit code" 7 "$(sh_ container run --rm --restart no --network none "$IMAGE" sh -c 'exit 7' > /dev/null; echo $?)"
}
