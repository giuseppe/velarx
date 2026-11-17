# SPDX-License-Identifier: Apache-2.0
# The daemon under a systemd user manager: it has to send READY=1 (the unit is
# Type=notify), STOPPING=1 on SIGTERM, and take its API socket from systemd:
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/systemd.bats
#
# Transient units only; the daemon runs in a scratch HOME ($WORKDIR) and the
# units are stopped and reset at the end.

load helpers

prop () { systemctl --user show -P "$2" "$1"; }

vars () {
    SOCK=$WORKDIR/api.sock
    CONF=$WORKDIR/config.toml
    UNITS=(sh-e2e-notify sh-e2e-act sh-e2e-wd)
    DAEMON=(-p Type=notify -p NotifyAccess=all -p TimeoutStartSec=60
            -p Environment=HOME="$WORKDIR/home"
            "$BIN/velarx" --config "$CONF" varlink)
}

stop_units () {
    local u
    for u in "${UNITS[@]}"; do
        systemctl --user stop "$u.service" "$u.socket" 2> /dev/null || true
        systemctl --user reset-failed "$u.service" "$u.socket" 2> /dev/null || true
    done
    return 0
}

setup () { set +e; [ -z "${WORKDIR:-}" ] || vars; }

setup_file () {
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}
    skip_unless_systemd_user
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export WORKDIR; WORKDIR=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-systemd.XXXXXX")
    mkdir -p "$WORKDIR/home" "$WORKDIR/data"
    vars
    cat > "$CONF" <<TOML
[engine]
socket = "$SOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/data/root"
[storage]
root = "$WORKDIR/data/storage"
TOML
    stop_units
}

# the units stop after each test, a failed one too
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    stop_units
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    vars
    stop_units
    e2e_teardown_file
}

@test "the daemon is Type=notify and its SIGTERM is a clean exit" {
    # READY=1: systemd-run returns once the unit is active.
    timeout 90 systemd-run --user --quiet --unit=sh-e2e-notify "${DAEMON[@]}"
    check "Type=notify unit starts" 0 $?
    check "the unit is active" active "$(prop sh-e2e-notify.service ActiveState)"
    check "STATUS= is shown" Ready "$(prop sh-e2e-notify.service StatusText)"
    [ -S "$SOCK" ]
    check "the API socket exists" 0 $?
    "$BIN/velarx" --socket "$SOCK" health > /dev/null
    check "the daemon answers" 0 $?
    systemctl --user stop sh-e2e-notify.service
    check "stop" 0 $?
    check "a SIGTERM is a clean exit" success "$(prop sh-e2e-notify.service Result)"
    check "the socket file is removed" 1 "$([ -e "$SOCK" ] && echo 0 || echo 1)"
    systemctl --user reset-failed sh-e2e-notify.service 2> /dev/null
}

@test "socket activation starts the daemon on the first connection" {
    # Nothing runs until the first connection.
    timeout 30 systemd-run --user --quiet --unit=sh-e2e-act --socket-property=ListenStream="$SOCK" "${DAEMON[@]}"
    check "socket unit starts" 0 $?
    check "the service waits for a connection" inactive "$(prop sh-e2e-act.service ActiveState)"
    timeout 90 "$BIN/velarx" --socket "$SOCK" health > /dev/null
    check "the first request starts the daemon" 0 $?
    check "the service is active" active "$(prop sh-e2e-act.service ActiveState)"
    check "the service sent READY" Ready "$(prop sh-e2e-act.service StatusText)"
    systemctl --user stop sh-e2e-act.service 2> /dev/null
    check "stop the activated daemon" success "$(prop sh-e2e-act.service Result)"
    [ -S "$SOCK" ]
    check "systemd keeps its socket" 0 $?
    timeout 90 "$BIN/velarx" --socket "$SOCK" health > /dev/null
    check "the socket activates it again" 0 $?
}

@test "the watchdog is fed" {
    # Without WATCHDOG=1 the unit would be killed after 2 seconds.
    systemctl --user stop sh-e2e-act.service sh-e2e-act.socket 2> /dev/null
    timeout 90 systemd-run --user --quiet --unit=sh-e2e-wd -p WatchdogSec=2 "${DAEMON[@]}"
    check "unit with WatchdogSec starts" 0 $?
    # (a window: the unit lives through several watchdog periods)
    sleep 7
    check "the watchdog is fed" active "$(prop sh-e2e-wd.service ActiveState)"
    check "no watchdog timeout" 0 "$(prop sh-e2e-wd.service NRestarts)"
}
