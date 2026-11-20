# SPDX-License-Identifier: Apache-2.0
# End to end tests of the health checks, the OOM killer, the device cgroup,
# sdnotify, the cgroup modes and the root file system served by the monitor
# of a lazily pulled image, through a daemon of its own.  Run it as an
# ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# (the lazy test moves XDG_DATA_HOME to a store of its own)
teardown () {
    export XDG_DATA_HOME=$HOME/data
    run_test_teardown
}

@test "health check with a startup check" {
    # the startup check fails until /tmp/started exists: the status stays
    # starting meanwhile, then the regular check runs
    mkdir -p "$WORKDIR/hlog"
    sh_ container run -d --name hs1 --network none --health-cmd true --health-interval 1s \
        --health-startup-cmd 'test -f /tmp/started' --health-startup-interval 1s \
        --health-log-destination "$WORKDIR/hlog" --health-max-log-count 3 "$IMAGE" sleep 1000 > /dev/null
    # (a window: the startup check fails at 1 s intervals, the status must stay)
    sleep 3
    check "starting while the startup check fails" starting "$(field status hs1)"
    sh_ container exec hs1 touch /tmp/started
    wait_health hs1 healthy
    check "healthy once it passed and the regular check ran" 0 $?
    id=$(sh_ container inspect hs1 | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    check "the health log is in the directory" 1 "$(ls "$WORKDIR/hlog" | grep -c "^$id-healthcheck.log$")"
    wait_for 15 sh -c "test \$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))[\"log\"]))' '$WORKDIR/hlog/$id-healthcheck.log') -eq 3"
    check "with at most --health-max-log-count results" 0 $?
    sh_ container rm -t 0 -f hs1 > /dev/null
    # a startup check that always fails, with retries: the container restarts
    sh_ container run -d --name hs2 --network none --health-cmd true \
        --health-startup-cmd false --health-startup-interval 1s --health-startup-retries 2 \
        "$IMAGE" sleep 1000 > /dev/null
    wait_restarts hs2 1 20
    check "a startup check that fails its retries restarts it" 0 $?
    sh_ container rm -t 0 -f hs2 > /dev/null
    out=$(sh_ container run --rm --network none --health-startup-cmd true "$IMAGE" true 2>&1)
    check_match "a startup check needs a health check" "need a health check" "$out"
}

@test "health checks: starting, unhealthy, healthy, healthcheck run" {
    sh_ container run -d --name hc1 --network none --health-cmd 'test -f /tmp/ok' --health-interval 1s \
        --health-retries 2 --health-timeout 5s "$IMAGE" sleep 1000 > /dev/null
    check_match "starting" 'starting' "$(sh_ healthcheck ls | grep hc1)"
    wait_health hc1 unhealthy
    check "unhealthy after the retries" 0 $?
    out=$(sh_ healthcheck inspect hc1)
    check_match "the failures are counted" 'Failure Count: [2-9]' "$out"
    sh_ container exec hc1 touch /tmp/ok
    wait_health hc1 healthy
    check "healthy once the command passes" 0 $?
    out=$(sh_ healthcheck run hc1)
    check "healthcheck run: nothing when it passes" "0 " "$? $out"
    sh_ container exec hc1 rm /tmp/ok
    out=$(sh_ healthcheck run hc1)
    check "healthcheck run fails: unhealthy, 1" "1 unhealthy" "$? $out"
    sh_ container rm -t 0 -f hc1 > /dev/null
}

@test "health checks: the failure actions kill, restart and stop" {
    sh_ container run -d --name hc2 --network none --health-cmd 'exit 1' --health-interval 1s --health-retries 1 \
        --health-on-failure kill "$IMAGE" sleep 1000 > /dev/null
    out=$(sh_ container wait hc2)
    check_match "on-failure kill" "^137$" "$out"
    sh_ container rm hc2 > /dev/null

    sh_ container run -d --name hc3 --network none --health-cmd 'exit 1' --health-interval 1s --health-retries 1 \
        --health-on-failure restart "$IMAGE" sleep 1000 > /dev/null
    wait_restarts hc3 1
    check "on-failure restart restarts the container" 0 $?
    sh_ container rm -t 0 -f hc3 > /dev/null

    sh_ container run -d --name hc4 --network none --health-cmd 'exit 1' --health-interval 1s --health-retries 1 \
        --health-on-failure stop --restart always "$IMAGE" sh -c 'trap "exit 0" TERM; while :; do sleep 0.1; done' > /dev/null
    wait_state hc4 exited 20
    check "on-failure stop stops the container" 0 $?
    # (a window: the restart policy would have started it by now)
    sleep 1.5
    check "and it is not restarted" exited "$(state_of hc4)"
    sh_ container rm -t 0 -f hc4 > /dev/null

}

@test "health checks: a start period, and after a daemon restart" {
    # A start period: failures do not count.
    sh_ container run -d --name hc5 --network none --health-cmd 'exit 1' --health-interval 1s --health-retries 1 \
        --health-start-period 4s "$IMAGE" sleep 1000 > /dev/null
    # (a window: the failures of the first seconds do not count)
    sleep 2.5
    check "inside the start period" starting "$(field status hc5)"
    wait_health hc5 unhealthy
    check "after the start period" 0 $?
    sh_ container rm -t 0 -f hc5 > /dev/null

    # The checks go on, and are remembered, after the daemon restarts.
    sh_ container run -d --name hc6 --network none --health-cmd 'true' --health-interval 1s "$IMAGE" sleep 1000 > /dev/null
    wait_health hc6 healthy
    stop_daemon
    start_daemon
    check "healthy after a daemon restart" healthy "$(field status hc6)"
    sh_ container rm -t 0 -f hc6 > /dev/null
}

@test "the OOM killer" {
    skip_unless_root
    sh_ container run -d --name oom --memory 24m --memory-swap 24m --network none "$IMAGE" \
        sh -c 'x=$(head -c 200000000 /dev/zero | tr "\0" a); echo survived' > /dev/null
    out=$(sh_ container wait oom)
    check_match "the OOM killer kills it" "^137$" "$out"
    check "oom_killed is recorded" true "$(field oom_killed oom)"
    sh_ container rm oom > /dev/null

    sh_ container run -d --name noom --memory 64m --network none "$IMAGE" sh -c 'exit 3' > /dev/null
    sh_ container wait noom > /dev/null
    check "no oom, no flag" false "$(field oom_killed noom)"
    sh_ container rm noom > /dev/null
}

# The device cgroup: a container that can mknod still cannot open a
# block device of the host (the one under /), only the defaults of /dev.
@test "the device cgroup" {
    skip_unless_root
    dev=$(mountpoint -d /)
    out=$(sh_ container run --rm --cap-add mknod --network none "$IMAGE" \
        sh -c "mknod /tmp/disk b ${dev%%:*} ${dev#*:} && head -c 512 /tmp/disk | wc -c" 2>&1)
    check_match "a host block device cannot be read" "Operation not permitted|Permission denied" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'head -c 4 /dev/urandom | wc -c; echo x > /dev/null && echo null' 2>&1)
    check "the default devices work" "4 null" "$(echo $out)"
}

@test "health check: retries and timeout below one are refused, as podman's CLI does" {
    run sh_ container run -d --health-cmd true --health-retries 0 "$IMAGE" sleep 1
    check "retries 0" 125 "$status"
    check_match "the retries message" "healthcheck-retries must be greater than 0" "$output"
    run sh_ container run -d --health-cmd true --health-timeout 0 "$IMAGE" sleep 1
    check "timeout 0" 125 "$status"
    check_match "the timeout message" "healthcheck-timeout must be at least 1 second" "$output"
    run sh_ container run -d --health-cmd true --health-startup-cmd true --health-startup-timeout 0s "$IMAGE" sleep 1
    check "startup timeout 0" 125 "$status"
    check_match "the startup timeout message" "healthcheck-timeout must be at least 1 second" "$output"
    # 0 and 0s are --health-interval=disable: the checks of healthcheck run only
    sh_ container run -d --name hz0 --network none --health-cmd false --health-interval 0s \
        --health-retries 1 "$IMAGE" sleep 1000 > /dev/null
    check "no timer: the interval is 0" 0s "$(sh_ inspect --format '{{.Config.Healthcheck.Interval}}' hz0)"
    sh_ healthcheck run hz0 > /dev/null 2>&1
    check "healthcheck run: one failure of one retry is unhealthy" unhealthy "$(field status hz0)"
    sh_ container rm -t 0 -f hz0 > /dev/null
}

# The check of an image takes podman's defaults for the times it does not
# give; a check of its own keeps what it says.
@test "health check: the image's has the defaults" {
    mkdir -p "$WORKDIR/hcimg"
    printf 'FROM %s\nHEALTHCHECK CMD false\n' "$IMAGE" > "$WORKDIR/hcimg/Containerfile"
    sh_ image build -q -t localhost/hcimg:1 "$WORKDIR/hcimg" > /dev/null
    sh_ container run -d --name hi1 --network none localhost/hcimg:1 sleep 1000 > /dev/null
    check "30 s, 30 s, 3 retries" "30s 30s 3" \
        "$(sh_ inspect --format '{{.Config.Healthcheck.Interval}} {{.Config.Healthcheck.Timeout}} {{.Config.Healthcheck.Retries}}' hi1)"
    sh_ healthcheck run hi1 > /dev/null 2>&1
    check "one failure of 3 retries is not unhealthy" starting "$(field status hi1)"
    sh_ container rm -t 0 -f hi1 > /dev/null
    sh_ image rm localhost/hcimg:1 > /dev/null
}

# The server cannot start a monitor in the cgroup of the caller, so it
# refuses what needs one (the monitor's own behavior is tested in
# tests/integration/monitor_tests.rs, where the test gives it the NOTIFY_SOCKET).
@test "sdnotify" {
    sock=$WORKDIR/notify.sock
    # The server cannot be in the cgroup of its client: it refuses.
    for mode in conmon container healthy; do
        out=$(sh_ --socket "$ESOCK" container run -d --sdnotify $mode --network none "$IMAGE" sleep 5 2>&1)
        check_match "$mode through the server is refused" "needs the monitor to run in the caller's cgroup|needs a health check" "$out"
    done
    # Under a service manager the client does not send it to the server...
    out=$(NOTIFY_SOCKET=$sock sh_ --socket "$ESOCK" container run --rm --network none "$IMAGE" true 2>&1)
    check_match "under a service manager the server is not used" "systemd unit" "$out"
    # ...but runs it in the engine, whose monitor notifies the manager.
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(sys.argv[1]); s.settimeout(30)
print(s.recv(4096).decode(errors="replace").replace("\n", " "))
' "$sock" > "$WORKDIR/notify.out" 2>&1 3>&- &
    reader=$!
    e2e_wait_path "$sock"
    NOTIFY_SOCKET=$sock sh_ container run -d --rm --sdnotify conmon --network none "$IMAGE" sleep 2 > /dev/null 2>&1
    check "under a service manager the engine runs it" 0 $?
    wait $reader
    check_match "and its monitor says it is ready" "READY=1 MAINPID=[0-9]+" "$(cat "$WORKDIR/notify.out")"
    out=$(NOTIFY_SOCKET=$sock sh_ container run --rm --sdnotify ignore --network none "$IMAGE" sh -c 'echo "[$NOTIFY_SOCKET]"')
    check "ignore: no socket for the container" "[]" "$out"
    out=$(sh_ container run -d --sdnotify healthy --network none "$IMAGE" sleep 5 2>&1)
    check_match "healthy without a health check is refused" "needs a health check" "$out"
}

@test "cgroups modes and limits without cgroups" {
    # (split through the server is the layout of the server: below the cgroup it
    # owns; a server with no delegated cgroup refuses it, see cgroups_mode.rs)
    out=$(sh_ --socket "$ESOCK" container run --rm --cgroups=split --cgroupns=host --network none "$IMAGE" cat /proc/self/cgroup 2>&1)
    if [ $? = 0 ]; then
        check_match "split through a server with a cgroup of its own puts the container below it" "/container$" "$out"
    else
        check_match "split through a server with no cgroup of its own is refused" "has no cgroup it owns" "$out"
    fi
    out=$(sh_ container run --rm --cgroups=disabled --cgroup-parent x --network none "$IMAGE" true 2>&1)
    check_match "disabled with --cgroup-parent is refused" "cannot set cgroup parent if not creating cgroups" "$out"
    check "and exits 125" 125 "$(sh_ container run --rm --cgroups=disabled --cgroup-parent x --network none "$IMAGE" true > /dev/null 2>&1; echo $?)"
    # a limit has no cgroup to be applied to: an error, whatever the way it is asked
    for flag in --memory=64m --memory-swap=128m --memory-reservation=32m --cpus=1 --cpu-shares=100 \
        --cpu-period=100000 --cpu-quota=50000 --cpuset-cpus=0 --cpuset-mems=0 --pids-limit=50 \
        --blkio-weight=100 --device-read-bps=/dev/null:1mb --device-write-bps=/dev/null:1mb \
        --device-read-iops=/dev/null:100 --device-write-iops=/dev/null:100 \
        --cgroup-conf=memory.high=1000000 --oom-kill-disable --device-cgroup-rule="c 1:3 rwm"; do
        for verb in run create; do
            out=$(sh_ container $verb --cgroups=disabled --network none "$flag" "$IMAGE" true 2>&1)
            rc=$?
            check "disabled with ${flag%%=*} ($verb) exits 125" 125 "$rc"
            check_match "and says why" "cannot set .* without cgroups" "$out"
        done
    done
    # (what is no cgroup setting is allowed)
    out=$(sh_ container run --rm --cgroups=disabled --network none --ulimit nofile=1024 --shm-size=16m \
        --oom-score-adj=100 "$IMAGE" true 2>&1)
    check "disabled with --ulimit, --shm-size and --oom-score-adj runs" 0 $?
    out=$(sh_ container run --rm --cgroups=disabled --network none "$IMAGE" sh -c 'cat /proc/self/cgroup' 2>&1)
    check_match "disabled: the container runs" "^0::" "$out"
    out=$(sh_ container run --rm --cgroups=bogus --network none "$IMAGE" true 2>&1)
    check_match "an unknown mode is refused" "invalid value" "$out"
}

# The root file system of a rootless container is served by its monitor:
# a lazily pulled image is fetched by the files that are read, and the
# container goes on reading when the daemon is stopped.
@test "a lazily pulled image is served by the monitor" {
    # Only an image whose tables of contents give the fs-verity digest of
    # every file is pulled lazily: the image pushed again by velarx (gzip,
    # and back as zstd:chunked).
    local src=$IMAGE IMAGE=$E2E_REGISTRY/velarx-e2e/run-health-$$
    { sh_ image push --tls-verify=false --compression-format gzip "$src" "$IMAGE:gzip" &&
      sh_ image pull --tls-verify=false "$IMAGE:gzip" &&
      sh_ image push --tls-verify=false --compression-format zstd:chunked "$IMAGE:gzip" "$IMAGE:zstd"
    } > "$WORKDIR/seal.log" 2>&1 || { cat "$WORKDIR/seal.log" >&2; exit 1; }
    IMAGE=$IMAGE:zstd
    # A store of its own: nothing of the image is in it.
    stop_daemon
    saved_data=$XDG_DATA_HOME
    export XDG_DATA_HOME=$WORKDIR/lazy-data
    mkdir -p "$XDG_DATA_HOME"
    # (the configuration names the directories: root has no other default)
    cp "$CONFIG" "$CONFIG.saved"
    sed -i "s#$saved_data/velarx#$XDG_DATA_HOME/velarx#" "$CONFIG"
    start_daemon
    if ! sh_ image pull --lazy "$IMAGE" > "$WORKDIR/lazy.log" 2>&1; then
        cat "$WORKDIR/lazy.log" >&2
        exit 1
    fi
    # Nothing of the image is in the store: the monitor fetches what is read.
    out=$(sh_ container run --lazy --name fz0 --network none "$IMAGE" sh -c 'cat /etc/alpine-release; echo done' 2>&1)
    check_match "a file that is missing is fetched by the monitor" "^[0-9.]+ done$" "$(echo "$out" | tr '\n' ' ' | sed 's/ *$//')"
    # (in the store, or still in the staging of the layers)
    n=$(find "$XDG_DATA_HOME" -type f \( -path '*/objects/*' -o -path '*/staging/layers/*/files/*' \) 2> /dev/null | wc -l)
    test "$n" -gt 0
    check "and stored" 0 $?
    case "$out" in done) ;; *) cat "$XDG_RUNTIME_DIR"/velarx/mon/*/monitor.log 2> /dev/null | tail -5 ;; esac
    sh_ container rm fz0 > /dev/null 2>&1

    sh_ container run --lazy -d --name fz1 --network none "$IMAGE" sh -c 'sleep 2; cat /etc/os-release; cat /bin/busybox | wc -c' > /dev/null
    cpid=$(inspect_of fz1 pid)
    # (a miss is fetched through the engine, and the completion waits for
    # the start to be quiet: the image is completed before the engine goes)
    sh_ image complete "$IMAGE" > /dev/null
    stop_daemon
    e2e_wait_exit "$cpid"
    start_daemon
    out=$(sh_ container wait fz1)
    check_match "the container read its files with the daemon away" "^0$" "$out"
    out=$(sh_ container logs fz1)
    check_match "and got them" "Alpine" "$out"
    sh_ container rm fz1 > /dev/null
    # The monitors unmount what they mounted when they end, and the /dev/shm
    # the engine mounted for a container goes at its exit (also when the
    # monitor that removed an --rm container records it).
    n=$(awk -v d="$WORKDIR" 'index($5, d "/") == 1' /proc/self/mountinfo | wc -l)
    check "nothing stays mounted when the containers are gone" 0 "$n"

    # Everything is in the store now: no fetching is needed.
    out=$(sh_ container run --lazy --rm --network none "$IMAGE" cat /etc/alpine-release)
    check_match "an image that is local" "^[0-9.]+$" "$out"
    stop_daemon
    export XDG_DATA_HOME=$saved_data
    mv "$CONFIG.saved" "$CONFIG"
    start_daemon
}
