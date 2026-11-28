# SPDX-License-Identifier: Apache-2.0
# Shared by the run-*.bats files (the container life cycle: monitor, logs,
# attach, exec, restart policy, health checks, OOM ...), which were the
# tests of the old run script.
#
#   load helpers
#   load run_lib
#   setup_file () { run_setup_file; }
#   teardown_file () { run_teardown_file; }
#
# Environment:
#   VELARX_BINDIR  the directory with velarx, velarx-client and
#                    velarx-monitor (default: target/debug)
#   E2E_REGISTRY     registry with alpine:chunked (default localhost:5000)
#   E2E_STORAGE_LINES  lines of dotted keys of the root table added to the
#                    configuration (`pull.lazy_completers = 0`)
#   E2E_BEFORE_DAEMON  the function run (with the work directory made) before
#                    the daemon starts, for what it needs running
#   E2E_NO_DAEMON    1: start no daemon, the commands serve the engine of their
#                    own process and ask it through the client (the tests that
#                    need the service of the user fail)
#
# Run it as an ordinary user for the rootless daemon, or as root.  The files
# are skipped when the registry or crun is missing.

. "$BATS_TEST_DIRNAME/../cleanup.sh"

# run_setup_file: the work directory and the daemon of the file, the image
# of the registry pulled.
run_setup_file () {
    e2e_setup_file
    local b
    for b in velarx velarx-registry velarx-dir velarx-client velarx-monitor; do
        [ -x "$BIN/$b" ] || skip "cannot find $BIN/$b"
    done
    command -v crun > /dev/null || skip "crun is missing"
    curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    export IMAGE=$E2E_REGISTRY/alpine:chunked
    export PTY_RUN="python3 -I $E2E_DIR/pty_run.py"
    export CONFIG=$XDG_CONFIG_HOME/velarx/config.toml
    mkdir -p "$HOME/.config/velarx" "$XDG_DATA_HOME"
    chmod 700 "$XDG_RUNTIME_DIR"
    # (systemd-run --scope asks the private socket of the user's manager in the
    # runtime directory)
    if test "$(id -u)" != 0 && test -d "/run/user/$(id -u)/systemd"; then
        ln -s "/run/user/$(id -u)/systemd" "$XDG_RUNTIME_DIR/systemd"
    fi
    cat > "$HOME/.config/velarx/registries.conf" << EOF
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOF
    # a root daemon reads only the system file unless it is told
    export VELARX_REGISTRIES_CONF="$HOME/.config/velarx/registries.conf"
    cat > "$CONFIG" << EOF
storage.root = "$XDG_DATA_HOME/velarx"
${E2E_STORAGE_LINES:-}
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$XDG_RUNTIME_DIR/velarx"
root_dir = "$XDG_DATA_HOME/velarx"
EOF
    [ "$(e2e_count_processes "$WORKDIR")" = 0 ] || echo "# processes of $WORKDIR before the start" >&3
    # (a file that needs something running before the engine: E2E_BEFORE_DAEMON
    # names the function that starts it)
    "${E2E_BEFORE_DAEMON:-true}" || return 1
    start_daemon
    sh_ image pull "$IMAGE" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMAGE" "$WORKDIR/pull.log"
}

# hostile_image: import (once per file) an image of host binaries (sh, head,
# grep) with device nodes of its own: the character devices 1:3 (null) and 1:5
# (zero), which the default device cgroup allows, and the block device 7:0
# (loop0), which it does not, in /evil.  $EVIL is its name.
hostile_image () {
    [ -z "${EVIL:-}" ] || return 0
    BINARIES="sh head grep" e2e_make_image localhost/e2e-evil:1
    python3 -I - "$WORKDIR/rootfs.tar" "$WORKDIR/evil.tar" << 'PY'
import sys, tarfile
src, dst = sys.argv[1:3]
with tarfile.open(src) as s, tarfile.open(dst, "w") as t:
    for m in s:
        t.addfile(m, s.extractfile(m) if m.isreg() else None)
    d = tarfile.TarInfo("evil"); d.type = tarfile.DIRTYPE; d.mode = 0o755
    t.addfile(d)
    for name, typ, major, minor in (("null", tarfile.CHRTYPE, 1, 3), ("zero", tarfile.CHRTYPE, 1, 5),
                                    ("loop0", tarfile.BLKTYPE, 7, 0)):
        i = tarfile.TarInfo("evil/" + name); i.type = typ; i.mode = 0o666
        i.devmajor, i.devminor = major, minor
        t.addfile(i)
PY
    sc image import "$WORKDIR/evil.tar" localhost/e2e-evil:1 > /dev/null
    export EVIL=localhost/e2e-evil:1
}

# run_teardown_file: the containers go, the daemon, what a monitor that was
# killed leaves mounted below the work directory, the work directory.
run_teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    local rc=0 cfg c
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2> /dev/null; then
        for c in $(sh_ container list -a 2> /dev/null | awk 'NR > 1 { print $1 }'); do
            sh_ container rm -t 0 -f "$c" > /dev/null 2>&1
        done
    fi
    stop_daemon
    e2e_detach_mounts "$WORKDIR"
    if [ -n "${E2E_KEEP:-}" ]; then
        e2e_teardown_file
        return 0
    fi
    # (the wrapper and the configuration of the file are in the directory to
    # remove: the removal in the user namespaces gets copies outside it)
    cfg=$(mktemp "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-cfg.XXXXXX")
    cp "$CONFIG" "$cfg"
    e2e_remove_workdir "$WORKDIR" "$BIN/velarx" --config "$cfg" || rc=1
    rm -f "$cfg"
    e2e_teardown_file
    e2e_check_left "$WORKDIR" || rc=1
    return $rc
}

# Each test finds the daemon of the file; one that failed puts the daemon
# and the configuration back for the next.
setup () {
    set +e
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    # (the containers of the tests before: a failed test removes the others)
    CONTAINERS_BEFORE=" $(sh_ container list -a 2> /dev/null | awk 'NR > 1 { print $1 }' | tr '\n' ' ') "
}

# run_test_teardown: after a test that failed, the background commands it
# started end, the daemon and the configuration are put back, and the
# containers it made go (the next test may use their names).
run_test_teardown () {
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] && return 0
    local f c
    stop_daemon
    kill $(jobs -pr) 2> /dev/null
    for f in orig saved; do
        [ -e "$CONFIG.$f" ] && mv "$CONFIG.$f" "$CONFIG"
    done
    start_daemon
    for c in $(sh_ container list -a 2> /dev/null | awk 'NR > 1 { print $1 }'); do
        case "$CONTAINERS_BEFORE" in
        *" $c "*) ;;
        *) sh_ container rm -f -t 0 "$c" > /dev/null 2>&1 ;;
        esac
    done
    return 0
}

teardown () {
    run_test_teardown
}

# check_match_lines WHAT REGEXP ACTUAL: like check_match, for a REGEXP
# anchored to a line (^ or $) of an output of several lines: some line has
# to match (the old scripts matched line by line, with grep -E).
check_match_lines () {
    local l
    while IFS= read -r l; do
        if [[ "$l" =~ $2 ]]; then return 0; fi
    done <<< "$3"
    echo "FAIL $1: no line of '$3' matches '$2'" >&2
    exit 1
}

now_ms () {
    date +%s%3N
}

# the commands on the configuration of the file (--config of the wrapper);
# what they start must not keep the descriptor of bats
sh_ () {
    "$SH" "$@" 3>&-
}

# daemon_spawn COMMAND...: a daemon in its own session, in the background:
# DAEMON_PID, and the pid file of the file for the teardown.
daemon_spawn () {
    setsid "$@" >> "$WORKDIR/daemon.log" 2>&1 3>&- &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
}

start_daemon () {
    # (E2E_NO_DAEMON=1: the commands run the engine of their own process, the
    # way a command does when no engine service runs)
    [ -z "${E2E_NO_DAEMON:-}" ] || return 0
    # (the daemon says READY=1 when it serves)
    # (|| : the shell of bats exits at a failure, without the pid file the
    # teardown stops the daemon by)
    local ready=0
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready DAEMON_PID setsid \
        "$BIN/velarx" --config "$CONFIG" varlink || ready=$?
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    if [ "$ready" = 0 ]; then
        start_api
        return 0
    fi
    echo "the daemon did not start" >&2
    cat "$WORKDIR/daemon.log" >&2
    exit 1
}

# The REST API, in front of the engine of the file (the tests that drive it
# with curl, after e2e_need_api), on $SOCK.
start_api () {
    [ -x "$BIN/velarx-api" ] || return 0
    setsid "$BIN/velarx-api" --config "$CONFIG" --no-start-engine --idle-exit 0 \
        --listen "unix://$SOCK" >> "$WORKDIR/api.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/api.pid"
    e2e_wait_path "$SOCK" 10
}

# Stop the daemon the way systemd does: SIGTERM, the containers go on.
stop_daemon () {
    if [ -s "$WORKDIR/api.pid" ]; then
        kill "$(cat "$WORKDIR/api.pid")" 2> /dev/null
        rm -f "$WORKDIR/api.pid" "$SOCK"
    fi
    if test -n "$DAEMON_PID"; then
        kill "$DAEMON_PID" 2> /dev/null
        # (it ends after its shutdown timeout at the latest, 30 s by default)
        e2e_wait_exit "$DAEMON_PID" 120
        wait "$DAEMON_PID" 2> /dev/null || true
        DAEMON_PID=
    fi
    rm -f "$WORKDIR/daemon.pid"
}

# The state of a container as velarx's inspect shows it (podman's words:
# exited, running...); nothing for a container that is not there.
state_of () {
    sh_ container inspect "$1" 2> /dev/null |
        python3 -I -c 'import json, sys; print(json.load(sys.stdin)["state"])' 2> /dev/null
}

# The socket of the manager the engine asks: the system's for root, else
# the user's.
manager_bus () {
    local bus=${DBUS_SESSION_BUS_ADDRESS:-}
    bus=${bus#unix:path=}
    if test "$(id -u)" = 0; then
        bus=/run/systemd/private
    elif ! test -S "$bus"; then
        bus=$XDG_RUNTIME_DIR/bus
    fi
    echo "$bus"
}

inspect_of () {
    sh_ container inspect "$1" 2> /dev/null |
        python3 -I -c 'import json, sys; c = json.load(sys.stdin); print(c[sys.argv[1]])' "$2" 2> /dev/null
}
monitor_of () {
    pgrep -f -- "^velarx-monitor: $(inspect_of "$1" id | cut -c1-12) "
}
# wait_state CONTAINER STATE [LIMIT]: until the container is in the state (the
# wait of the engine follows its events; 15 s at most by default).
wait_state () {
    timeout "${3:-15}" "$SH" container wait --condition "$2" "$1" > /dev/null 2>&1
    test "$(state_of "$1")" = "$2"
}

# wait_removed CONTAINER [LIMIT]: until the container is gone (the wait of the
# engine follows its events; 30 s at most by default).  A container that
# was removed before the wait began is gone as well.
wait_removed () {
    timeout "${2:-30}" "$SH" container wait --condition removed "$1" > /dev/null 2>&1 3>&-
    ! sh_ container exists "$1"
}

# wait_health CONTAINER STATUS [LIMIT]: until its health check says healthy or
# unhealthy (the same wait).
wait_health () {
    timeout "${3:-15}" "$SH" container wait --condition "$2" "$1" > /dev/null 2>&1
    test "$(field status "$1")" = "$2"
}

# wait_restarts CONTAINER N [LIMIT]: until the container was restarted N times
# in all, by its restart events (--since replays the earlier ones, so the
# stream may begin after them; the id: a name may have been used before).
wait_restarts () {
    local id out rc evp
    id=$(inspect_of "$1" id)
    out=$(mktemp "${E2E_TMPDIR:-${WORKDIR:-/var/tmp}}/restarts.XXXXXX")
    "$SH" events --since 10m --stream --filter container="$id" --filter event=restart > "$out" 2>&1 3>&- &
    evp=$!
    e2e_wait_line "$out" 'container restart ' "${3:-30}" "$2"
    rc=$?
    kill "$evp" 2> /dev/null
    wait "$evp" 2> /dev/null
    rm -f "$out"
    return $rc
}

# wait_log CONTAINER REGEX [LIMIT [COUNT]]: until COUNT (1) lines of the
# output of the container match REGEX (inotify on its log file; LIMIT, 30 s by default,
# is an upper bound).  A command that must have set a trap prints a line
# after it, and the test waits for that line.
wait_log () {
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$(inspect_of "$1" id)/container.log" " stdout F $2\$" "${3:-30}" "${4:-1}" ||
        e2e_die "the container $1 printed no '$2' within ${3:-30} s"
}

# events_in_a_file: the events of the engine are kept in a file (an
# E2E_BEFORE_DAEMON): the journal of a busy host drops what the units of a
# user send above its rate limit, and the tests are not about it.
events_in_a_file () {
    sed -i '/^\[server\]/a events_logger = "file"' "$CONFIG"
}

# daemon_forget_log / wait_daemon_started: the engine that restarts (system
# restart, SIGHUP) says so as it begins to, and the socket stays open: a
# request waits for the engine that comes next.  Forget the log before the
# restart, wait for the line and the answer after.
daemon_forget_log () {
    : > "$WORKDIR/daemon.log"
}

wait_daemon_started () {
    e2e_wait_line "$WORKDIR/daemon.log" Restarting 30 || e2e_die "the engine did not restart within 30 s"
    timeout 60 "$SH" --socket "$ESOCK" health > /dev/null 2>&1 3>&- ||
        e2e_die "the engine did not serve again within 60 s"
}

# kill_monitor CONTAINER: SIGKILL for its monitor; returns once the engine
# has seen it go and follows the process of the container.
kill_monitor () {
    local id mon
    id=$(inspect_of "$1" id)
    mon=$(monitor_of "$1")
    kill -9 "$mon"
    e2e_wait_line "$WORKDIR/daemon.log" "The monitor of container $id is gone" 30 ||
        e2e_die "the engine did not see the monitor of $1 go within 30 s"
}

# daemon_spawn_ready COMMAND...: a daemon in its own session, in the
# background, as daemon_spawn, returned once it said READY=1.
daemon_spawn_ready () {
    local ready=0
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready DAEMON_PID setsid "$@" || ready=$?
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    [ "$ready" = 0 ] || e2e_die "the daemon did not say READY=1"
}

# journal_cursor: the cursor of the end of the journal (nothing when it
# cannot be read).  wait_journal CURSOR MATCH...: until an entry after the
# cursor matches (journalctl follows, so no entry is missed; 30 s at most).
# It does not fail: a journal that keeps nothing of this user makes the
# test look and skip.
journal_cursor () {
    journalctl --no-pager -n 0 --show-cursor 2> /dev/null | sed -n 's/^-- cursor: //p'
}

wait_journal () {
    local cursor=$1 jpid
    shift
    test -n "$cursor" || return 0
    timeout 30 journalctl --after-cursor="$cursor" -f -o cat "$@" > "$WORKDIR/journal.wait" 2> /dev/null 3>&- &
    jpid=$!
    e2e_wait_line "$WORKDIR/journal.wait" . 30 2> /dev/null || :
    kill "$jpid" 2> /dev/null
    # (killed: its status is of no interest)
    wait "$jpid" 2> /dev/null || :
}

# wait_for SECONDS COMMAND...: until the command succeeds.
wait_for () {
    local limit=$(( $(now_ms) + $1 * 1000 ))
    shift
    while ! "$@" > /dev/null 2>&1; do
        test "$(now_ms)" -lt "$limit" || return 1
        sleep 0.1
    done
}

# field NAME CONTAINER: a number or word of the inspect output.
field () {
    sh_ container inspect "$2" | sed -n "s/.*\"$1\": \"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}\$/\1/p" | head -1
}

field_is () {
    test "$(field "$1" "$2")" = "$3"
}

state_is () {
    test "$(state_of "$1")" = "$2"
}

restarts_at_least () {
    test "$(field restart_count "$2")" -ge "$1"
}

# The daemon again, with these lines of TOML added to its configuration
# ($1: keys of its last section, [server], then other sections; none: the
# configuration of the file): the events
# outlive the daemon in the journal or in a file, and nowhere with
# events_logger=none.
events_daemon () {
    stop_daemon
    [ -e "$CONFIG.orig" ] || cp "$CONFIG" "$CONFIG.orig"
    if test -n "$1"; then
        { cat "$CONFIG.orig"; printf '%s\n' "$1"; } > "$CONFIG"
    else
        mv "$CONFIG.orig" "$CONFIG"
    fi
    start_daemon
}
