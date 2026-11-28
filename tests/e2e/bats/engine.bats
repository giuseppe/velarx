# SPDX-License-Identifier: Apache-2.0
# The engine service (`velarx varlink`, the varlink
# interface org.velarx.Engine on engine.sock):
#
# * by hand: it binds the socket in a private directory, answers GetInfo and
#   Ping, leaves when it was idle for `[engine] idle_exit` seconds, and takes
#   its socket away;
# * the engine that a frontend starts: the socket and a lifeline are passed
#   as descriptors 3 and 4, and the engine stops when the lifeline closes;
# * started by the socket units: a connection starts the engine, it leaves
#   when idle, the socket stays and the next connection starts it again.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/engine.bats
#                                  # user units (rootless), or as root the
#                                  # system units
#
# The activation test links copies of velarx-engine.*, renamed
# shi-<pid>-engine.*, with the paths of $WORKDIR, into the runtime unit
# directory; they are stopped and unlinked at the end.  E2E_NO_UNITS=1 skips
# it (as root run the rest in a private mount namespace: the units are linked
# into the service manager of the machine).
# Skipped without python3.

load helpers

# varlink METHOD [SOCKET]: the reply of a call, as the engine's client makes
# it (JSON ended by a NUL byte)
varlink () {
    python3 -I - "$1" "${2:-$SOCK}" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(60)
s.connect(sys.argv[2])
s.sendall(('{"method":"org.velarx.Engine.%s"}' % sys.argv[1]).encode() + b"\0")
buf = b""
while not buf.endswith(b"\0"):
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
sys.stdout.write(buf.rstrip(b"\0").decode())
PY
}
alive () { e2e_alive "$1"; }

setup_file () {
    command -v python3 > /dev/null || skip "no python3"
    e2e_setup_file
    export top_srcdir; top_srcdir=$(cd "$E2E_DIR/../.." && pwd)
    chmod 700 "$XDG_RUNTIME_DIR"
    export RUN=$XDG_RUNTIME_DIR/velarx
    export CONF=$XDG_CONFIG_HOME/velarx/config.toml
    cat > "$CONF" <<TOML
$(e2e_bridge_toml)
[server]
socket = "$RUN/velarx.sock"
state_dir = "$RUN"
root_dir = "$XDG_DATA_HOME/velarx"
[storage]
root = "$XDG_DATA_HOME/velarx"
[engine]
idle_exit = 2
TOML
    export SOCK=$RUN/engine/engine.sock
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR_REAL:-/run/user/$(id -u)}
    export version
    version=$("$BIN/velarx" --config "$CONF" --version | awk '{print $3}')
    # (the digest of the interface, as a client in another language makes
    # it: the FNV-1a of the definition file)
    export digest
    digest=$(python3 -I -c '
import sys
h = 0xcbf29ce484222325
for path in sys.argv[1:]:
    for b in open(path, "rb").read():
        h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
print("%016x" % h)' "$top_srcdir/interfaces/org.velarx.Engine.varlink")
    export U=shi-$$
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pid
    for pid in $(cat "$WORKDIR/pids" 2> /dev/null); do kill "$pid" 2> /dev/null; e2e_wait_exit "$pid"; done
    if [ -e "$WORKDIR/units.linked" ]; then
        local sctl=(systemctl)
        [ "$(id -u)" = 0 ] || sctl=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemctl --user)
        local units="$U-engine.socket $U-engine.service"
        "${sctl[@]}" stop $units 2> /dev/null
        "${sctl[@]}" disable --runtime $units > /dev/null 2>&1
        "${sctl[@]}" reset-failed $units 2> /dev/null
        "${sctl[@]}" daemon-reload
    fi
    e2e_teardown_file
}

@test "by hand: the engine answers, leaves when idle and takes its socket away" {
    # (--time: an engine started by hand stays until it is stopped, unless it is told)
    "$BIN/velarx" --config "$CONF" varlink --time 2 > "$WORKDIR/engine.log" 2>&1 3>&- &
    ENGINE=$!
    echo $ENGINE > "$WORKDIR/pids"
    e2e_wait_path "$SOCK"
    check "by hand: the socket is in a private directory" 700 "$(stat -c %a "$RUN")"
    check "by hand: the socket is its user's" 600 "$(stat -c %a "$SOCK")"
    info=$(varlink GetInfo)
    echo "$info" > "$WORKDIR/info"
    check "by hand: GetInfo says who it is" \
        "{\"parameters\":{\"name\":\"velarx\",\"version\":\"$version\",\"interface\":1,\"digest\":\"$digest\",\"rootful\":$([ "$(id -u)" = 0 ] && echo true || echo false)},\"continues\":false}" "$info"
    check "by hand: Ping" '{"parameters":{},"continues":false}' "$(varlink Ping)"
    reply=$(varlink NoSuchMethod)
    check "by hand: a method it does not have is an error" yes "$(echo "$reply" | grep -q '"error"' && echo yes)"
    # --time 2: it leaves, with its socket
    e2e_wait_exit "$ENGINE"
    check "by hand: the idle engine leaves" gone "$(alive $ENGINE)"
    check "by hand: ...and takes its socket away" none "$([ -e "$SOCK" ] && echo socket || echo none)"
    check "by hand: it says nothing" "" "$(cat "$WORKDIR/engine.log")"
    rm -f "$WORKDIR/pids"
}

# Started by a frontend: the socket is descriptor 3, the lifeline 4
@test "started by a frontend: the lifeline keeps it, closing the lifeline stops it" {
    mkdir -p -m 700 "$RUN" "$RUN/engine"
    mkfifo "$WORKDIR/ctl"
    exec 7<> "$WORKDIR/ctl"
    cat > "$WORKDIR/frontend.py" <<'PY'
import fcntl, os, socket, subprocess, sys
sock_path, argv = sys.argv[1], sys.argv[2:]
listener = socket.socket(socket.AF_UNIX)
listener.bind(sock_path)
listener.listen(16)
mine, theirs = socket.socketpair()
def descriptors():
    # (out of the way of 3 and 4 first: the sockets may be those numbers)
    high = [fcntl.fcntl(f.fileno(), fcntl.F_DUPFD, 10) for f in (listener, theirs)]
    os.dup2(high[0], 3)
    os.dup2(high[1], 4)
    os.set_inheritable(3, True)
    os.set_inheritable(4, True)
proc = subprocess.Popen(
    argv + ["varlink", "--listen-fd", "3", "--lifeline-fd", "4", "--time", "0"],
    close_fds=False, preexec_fn=descriptors)
print(proc.pid, flush=True)
sys.stdin.readline()   # until the test says so
mine.close()           # the frontend is gone
try:
    proc.wait(timeout=30)
    print("stopped", flush=True)
except subprocess.TimeoutExpired:
    print("still running", flush=True)
    proc.kill()
PY
    python3 -I "$WORKDIR/frontend.py" "$SOCK" "$BIN/velarx" --config "$CONF" <&7 > "$WORKDIR/lifeline.out" 2>&1 3>&- &
    FRONT=$!
    echo $FRONT > "$WORKDIR/pids"
    e2e_wait_line "$WORKDIR/lifeline.out" . || e2e_die "the frontend did not start the engine"
    ENGINE=$(head -1 "$WORKDIR/lifeline.out")
    echo "$ENGINE" >> "$WORKDIR/pids"
    check "started by a frontend: GetInfo" yes "$(varlink GetInfo | grep -q "\"version\":\"$version\"" && echo yes)"
    check "started by a frontend: it runs as long as the lifeline" alive "$(alive "$ENGINE")"
    # (a window: an engine that would leave when idle does so within 3 s)
    sleep 3
    check "started by a frontend: --time 0 keeps it" alive "$(alive "$ENGINE")"
    # a restart (SIGHUP) executes it again with the socket and the lifeline
    kill -HUP "$ENGINE"
    # (it says so before it executes itself: the socket stays open, the
    # request waits for the next engine)
    e2e_wait_line "$WORKDIR/lifeline.out" '^Restarting' 30 || e2e_die "the engine did not restart within 30 s"
    check "started by a frontend: it answers after a restart" yes "$(varlink GetInfo | grep -q "\"version\":\"$version\"" && echo yes)"
    echo close >&7
    e2e_reap "$FRONT" "the frontend that started the engine"
    rm -f "$WORKDIR/pids"
    check "started by a frontend: it stops when the lifeline closes" stopped "$(tail -1 "$WORKDIR/lifeline.out")"
    check "started by a frontend: ...and takes the socket away" none "$([ -e "$SOCK" ] && echo socket || echo none)"
    exec 7>&-
}

@test "socket activation: a connection starts the engine, it leaves when idle, the next one starts it again" {
    [ -z "${E2E_NO_UNITS:-}" ] || skip "E2E_NO_UNITS: the activation test is skipped"
    local MODE SCTL mainpid
    if [ "$(id -u)" = 0 ]; then
        MODE=system
        SCTL=(systemctl)
    else
        MODE=user
        SCTL=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemctl --user)
    fi
    state=$("${SCTL[@]}" is-system-running 2>&1)
    if [ "$state" != running ] && [ "$state" != degraded ]; then
        skip "no service manager ($state): the activation test is skipped"
    fi
    info=$(cat "$WORKDIR/info" 2> /dev/null)
    [ -n "$info" ] || info=$(
        "$BIN/velarx" --config "$CONF" varlink > /dev/null 2>&1 3>&- &
        e2e_wait_path "$SOCK"
        varlink GetInfo
        kill $!
    )
    local MAKE=(make -s -C "$top_srcdir" TARGETDIR="$BIN")
    local P=$WORKDIR/pfx
    e2e_need_man
    "${MAKE[@]}" install-files PREFIX="$P"
    check "install into a PREFIX" 0 $?
    mkdir -p "$WORKDIR/units"
    if [ "$MODE" = system ] && command -v selinuxenabled > /dev/null && selinuxenabled; then
        chcon -t bin_t "$P"/bin/* || exit 1
    fi
    if [ "$MODE" = user ]; then
        # the engine reaches the user manager through its runtime directory
        ln -sfn "$REAL_RUNTIME_DIR/systemd" "$XDG_RUNTIME_DIR/systemd"
    fi
    unit () { # the installed unit, with the paths of this test
        sed -e "s|^ListenStream=.*|ListenStream=$SOCK|" \
            -e "s|^ExecStart=\(.*velarx\) varlink|ExecStart=\1 --config $CONF varlink|" \
            -e "s|velarx-engine.socket|$U-engine.socket|g" \
            -e "/^\[Service\]/a Environment=HOME=$HOME XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" \
            -e '/^RuntimeDirectory=/d' -e '/^StateDirectory=/d' \
            "$P/lib/systemd/$MODE/$1"
    }
    unit velarx-engine.socket > "$WORKDIR/units/$U-engine.socket"
    unit velarx-engine.service > "$WORKDIR/units/$U-engine.service"
    touch "$WORKDIR/units.linked"
    SERVICE_ARGS=$(sed -n 's/^ExecStart=//p' "$WORKDIR/units/$U-engine.service")
    check "the unit starts the engine service" "$P/bin/velarx --config $CONF varlink" "$SERVICE_ARGS"
    "${SCTL[@]}" link --runtime "$WORKDIR"/units/$U-* > /dev/null 2>&1
    "${SCTL[@]}" start "$U-engine.socket"
    active () { "${SCTL[@]}" show -P ActiveState "$1"; }
    check "the socket listens" active "$(active $U-engine.socket)"
    check "the engine waits for a connection" inactive "$(active $U-engine.service)"
    check "a connection starts the engine" "$info" "$(varlink GetInfo)"
    mainpid=$("${SCTL[@]}" show -P MainPID "$U-engine.service")
    check "the engine runs" active "$(active $U-engine.service)"
    # (the engine process ends by itself: a pidfd; the manager then only has
    # to say the unit is inactive)
    [ "${mainpid:-0}" -le 0 ] || e2e_wait_exit "$mainpid" 30
    e2e_wait_unit_state "$U-engine.service" inactive 20
    check "the idle engine leaves (idle_exit = 2)" inactive "$(active $U-engine.service)"
    check "...cleanly" success "$("${SCTL[@]}" show -P Result "$U-engine.service")"
    check "the socket stays" active "$(active $U-engine.socket)"
    check "the next connection starts it again" '{"parameters":{},"continues":false}' "$(varlink Ping)"
    check "...and it runs" active "$(active $U-engine.service)"
}
