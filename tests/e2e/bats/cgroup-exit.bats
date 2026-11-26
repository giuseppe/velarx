# SPDX-License-Identifier: Apache-2.0
# A daemon with no systemd manager makes the cgroup `velarx-<pid>` next to
# the one it started in and lives in `velarx-<pid>/engine`; when it ends
# cleanly (SIGTERM, SIGINT, idle, a failure) it goes back into the cgroup
# it started in and removes the tree, so that no empty cgroup is left for
# every run.  A restart (SIGHUP) keeps the tree, and the end after it
# removes it.
# A container that still runs in the tree keeps it (the kernel refuses to
# remove it).  Not the case of a daemon killed with SIGKILL, nor of one
# that owns its cgroup or runs in a scope of the manager: those are not
# made here and not touched.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/cgroup-exit.bats   # as an ordinary user, or as root
#
# Skipped without crun, or where the daemon owns its cgroup (then it makes
# no cgroup).  The cgroup it started in must be a leaf that still exists
# when it ends (the test's is).

load helpers
. "$BATS_TEST_DIRNAME/../cleanup.sh"

setup_file () {
    e2e_setup_file
    command -v crun > /dev/null || skip "crun is missing"
    [ -x "$BIN/velarx-monitor" ] || skip "cannot find $BIN/velarx-monitor"
    export STARTED
    STARTED=$(cgroup_of $$)
    e2e_start_daemon
    e2e_make_image
}

teardown_file () {
    # (what a failed test left)
    find "/sys/fs/cgroup$(dirname "$STARTED")" -maxdepth 1 -name 'velarx-*' -newer "$WORKDIR/daemon.pid" \
        -exec find {} -depth -type d -empty -delete \; 2> /dev/null
    e2e_teardown_file
}

cgroup_of () { sed -n 's/^0:://p' "/proc/$1/cgroup" 2> /dev/null; }

# stop_daemon: SIGTERM, and wait until the daemon is gone
stop_daemon () {
    local pid
    pid=$(cat "$WORKDIR/daemon.pid")
    kill -TERM "$pid"
    e2e_wait_exit "$pid" 30 || e2e_die "the daemon does not end"
}

# own_cgroup: cg, the directory velarx-<pid> of the daemon, as it started
# (not in a subshell: it skips the test)
own_cgroup () {
    local pid
    pid=$(cat "$WORKDIR/daemon.pid")
    cg=$(cgroup_of "$pid")
    case $cg in
        */velarx-"$pid"/engine) ;;
        *) stop_daemon; skip "the daemon owns its cgroup here ($cg): it makes none" ;;
    esac
    cg=/sys/fs/cgroup${cg%/engine}
}

@test "a clean end of the daemon removes its cgroup" {
    own_cgroup
    [ -d "$cg" ] || e2e_die "no $cg"
    stop_daemon
    check "the cgroup of the daemon is gone" no "$([ -e "$cg" ] && echo yes || echo no)"
}

@test "a restart keeps the cgroup, the end after it removes it" {
    : > "$WORKDIR/daemon.log"
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --log-level info --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink ||
        e2e_die "the daemon does not start"
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    own_cgroup
    kill -HUP "$DAEMON_PID"
    # (the daemon executed again starts; it answers once it serves)
    e2e_wait_line "$WORKDIR/daemon.log" 'Starting velarx daemon' 30 2 || e2e_die "the daemon does not restart"
    sc info > /dev/null || e2e_die "the daemon does not answer after the restart"
    check "the restart keeps the cgroup" "${cg#/sys/fs/cgroup}/engine" "$(cgroup_of "$DAEMON_PID")"
    stop_daemon
    check "the cgroup of the daemon is gone" no "$([ -e "$cg" ] && echo yes || echo no)"
}

@test "a daemon that fails removes its cgroup" {
    # (an engine socket that cannot be bound: it fails after the cgroup is made)
    sed 's|^socket = "'"$ESOCK"'"$|socket = "/proc/1/none/engine.sock"|' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/fail.toml"
    "$BIN/velarx" --config "$WORKDIR/fail.toml" varlink 2> "$WORKDIR/fail.log" &
    pid=$!
    wait "$pid" && e2e_die "the daemon did not fail"
    grep -q 'cannot listen on /proc/1/none/engine.sock' "$WORKDIR/fail.log" || e2e_die "$(cat "$WORKDIR/fail.log")"
    check "the cgroup of the daemon is gone" no "$([ -e "/sys/fs/cgroup$(dirname "$STARTED")/velarx-$pid" ] && echo yes || echo no)"
}

@test "a container that runs keeps the cgroup of the daemon" {
    e2e_start_daemon
    own_cgroup
    sc run -d --name keeper --network none --cgroups=split "$IMG" sleep 1000 > /dev/null || e2e_die "the container does not start"
    pid=$(sc inspect --format '{{.State.Pid}}' keeper)
    monitor=$(sc inspect --format '{{.State.ConmonPid}}' keeper)
    stop_daemon
    check "the cgroup of the daemon stays" yes "$([ -d "$cg" ] && echo yes || echo no)"
    check "the container runs in it" "${cg#/sys/fs/cgroup}" "$(cgroup_of "$pid" | sed 's|/[^/]*/[^/]*$||')"
    # (a daemon again removes the container, and its monitor goes with it)
    e2e_start_daemon
    sc rm -t 0 -f keeper > /dev/null
    stop_daemon
    e2e_wait_exit "$monitor" 10
    find "$cg" -depth -type d -delete
}
