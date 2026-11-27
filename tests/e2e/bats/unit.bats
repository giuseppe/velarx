# SPDX-License-Identifier: Apache-2.0
# Containers supervised by the systemd unit that runs them: the
# monitor is in the unit's cgroup, is its main process, notifies it, exits
# with the container's status, and cleans up without the engine service.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/unit.bats               # user units, rootless
#   VELARX_BINDIR=target/debug MODE=system bats tests/e2e/bats/unit.bats   # system units, as root
#
# IMAGE is any image with a shell (default localhost:5000/alpine:chunked,
# pulled over plain HTTP).  Transient units only (systemd-run), named
# shu-<pid>-*; they are stopped and reset at the end.  The store and the
# runtime directory are in $WORKDIR.
#
# This file talks to the user's systemd manager and times the start of its
# units (TimeoutStartSec): a daemon-reload of the manager in the middle cuts
# the extension, so the files that reload it (quadlet.bats, units.bats,
# engine.bats and engine-api.bats) have to end before this one starts; do not
# run them alongside it.

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

vars () {
    CONF=$WORKDIR/config.toml
    SOCK=$WORKDIR/api.sock
    if [ "$MODE" = user ]; then
        SCTL=(systemctl --user)
        SRUN=(systemd-run --user)
        JCTL=(journalctl --user)
    else
        SCTL=(systemctl)
        SRUN=(systemd-run)
        JCTL=(journalctl)
    fi
    # The units run with the scratch HOME and runtime directory.
    ENVP=(-p Environment=HOME="$WORKDIR/home" -p Environment=XDG_RUNTIME_DIR="$WORKDIR/run")
    SH=("$BIN/velarx" --config "$CONF")
    ENGINE=(env HOME="$WORKDIR/home" XDG_RUNTIME_DIR="$WORKDIR/run" "$BIN/velarx" --config "$CONF")
    RUN=(container run -d --replace --rm --sdnotify=conmon --tls-verify=false)
    NIMG=localhost/velarx-notify:1
    NRUN=(container run -d --replace --rm --network none --log-driver=passthrough)
}

setup () {
    set +e
    [ -z "${WORKDIR:-}" ] || vars
    UNITS_BEFORE=$(wc -l < "$WORKDIR/units.list" 2> /dev/null || echo 0)
}

# After a test that failed: the units and the engine service it started go, and
# the background commands.
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    if [ -n "${netd:-}" ]; then
        kill -INT "$netd" 2> /dev/null
        wait "$netd" 2> /dev/null
        rm -f "$SOCK"
    fi
    [ -n "${trap_pid:-}" ] && kill "$trap_pid" 2> /dev/null
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] && return 0
    local u
    for u in $(tail -n +"$((UNITS_BEFORE + 1))" "$WORKDIR/units.list" 2> /dev/null); do
        "${SCTL[@]}" stop "$u.service" "$u.socket" 2> /dev/null
    done
    return 0
}

prop () { "${SCTL[@]}" show -P "$2" "$1.service"; }
# unit NAME [-p PROP...] -- CMD...: start a Type=notify unit like Quadlet's.
unit () {
    local name=$1; shift
    local props=()
    while [ "$1" != -- ]; do props+=("$1"); shift; done
    shift
    echo "$name" >> "$WORKDIR/units.list"
    timeout 120 "${SRUN[@]}" --quiet --unit="$name" -p Type=notify -p NotifyAccess=all \
        -p Delegate=yes -p KillMode=mixed -p TimeoutStartSec=90 "${ENVP[@]}" "${props[@]}" "$@"
}
row () { "${ENGINE[@]}" container list --all --format '{{.Names}} {{.State}}' 2> /dev/null | awk -v n="$1" '$1 == n {print $2}'; }
procs () { # the processes in the cgroup of a unit (none when it is gone)
    local cg
    cg=$(prop "$1" ControlGroup)
    [ -n "$cg" ] && cat "/sys/fs/cgroup$cg/cgroup.procs" 2> /dev/null
}
# The mounts of the store: in the mount namespace of the rootless engines.
mounts () {
    if [ "$MODE" = user ]; then
        "${ENGINE[@]}" unshare cat /proc/self/mountinfo
    else
        cat /proc/self/mountinfo
    fi | grep -c " $WORKDIR/state/"
}

setup_file () {
    export MODE=${MODE:-user}
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    if [ "$MODE" = system ]; then
        skip_unless_root
    else
        skip_unless_systemd_user
    fi
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    # (a work directory of its own, in /var/tmp: /tmp is a small tmpfs, and the
    # store is big; it is removed at the end)
    export WORKDIR; WORKDIR=$(realpath "$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-unit.XXXXXX")")
    export P=shu-$$
    export PORT=$((18200 + $$ % 500))
    mkdir -p "$WORKDIR/home" "$WORKDIR/run" "$WORKDIR/vol"
    chmod 700 "$WORKDIR/run"
    # (the events go to a file the tests read, empty at the start)
    cat > "$WORKDIR/config.toml" <<TOML
[engine]
socket = "$WORKDIR/api.sock"
[server]
socket = "$WORKDIR/api.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/data/root"
events_logger = "file"
events_logfile_path = "$WORKDIR/events/events.log"
[storage]
root = "$WORKDIR/data/storage"
TOML
    if [ "$MODE" = system ]; then
        # (system services may only run binaries labelled as such: all of
        # them, the helpers the engine starts too)
        e2e_system_bin
    else
        # The units have the scratch runtime directory; they reach the user
        # manager (systemd-run --user --scope for the monitors) through it.
        ln -sfn "/run/user/$(id -u)/systemd" "$WORKDIR/run/systemd"
    fi
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    vars
    local u rc=0
    for u in $(cat "$WORKDIR/units.list" 2> /dev/null); do
        "${SCTL[@]}" stop "$u.service" "$u.socket" 2> /dev/null
        "${SCTL[@]}" reset-failed "$u.service" "$u.socket" 2> /dev/null
    done
    "${ENGINE[@]}" container rm -t 0 -f -i t1 t2 t3 t4 t5 t6 t8 t8s t9 t10 t12 t13 t14 t15 t16 t18 t18b t18c tn tl-p tl-j tapi 2> /dev/null > /dev/null
    e2e_check_left "$WORKDIR" || rc=1
    [ -n "${E2E_KEEP:-}" ] || e2e_remove_workdir "$WORKDIR" "${ENGINE[@]}"
    e2e_teardown_file
    return $rc
}

@test "the monitor is the main process of the unit and in its cgroup, and so is the container" {
    # T1: the monitor is the main process of the unit and in its cgroup, and so
    # is the container.
    unit "$P-t1" -- "${SH[@]}" "${RUN[@]}" --name t1 "$IMAGE" sleep inf
    check "T1 run -d in a Type=notify unit" 0 $?
    check "T1 the unit is active" active "$(prop "$P-t1" ActiveState)"
    main=$(prop "$P-t1" MainPID)
    check "T1 MainPID is the monitor" velarx-monitor "$(cat "/proc/$main/comm" 2> /dev/null)"
    check "T1 the monitor is in the unit" yes "$(procs "$P-t1" | grep -qx "$main" && echo yes)"
    ctr=$(pgrep -P "$main" -x sleep)
    check "T1 the container is in the unit" yes "$([ -n "$ctr" ] && procs "$P-t1" | grep -qx "$ctr" && echo yes)"
    check "T1 the container is recorded" running "$(row t1)"
}

@test "stopping the unit stops the container and leaves nothing" {
    # T2: stopping the unit stops the container and leaves nothing.
    check "T2 the unit of T1 runs" active "$(prop "$P-t1" ActiveState)"
    "${SCTL[@]}" stop "$P-t1.service"
    check "T2 stop" inactive "$(prop "$P-t1" ActiveState)"
    check "T2 a requested stop is a clean end" success "$(prop "$P-t1" Result)"
    check "T2 no process is left" "" "$(procs "$P-t1")"
    check "T2 no row is left (--rm)" "" "$(row t1)"
    check "T2 no mount is left" 0 "$(mounts)"
    check "T2 no bundle is left" 0 "$(ls "$WORKDIR/data/root/bundles" | wc -l)"
}

@test "the exit status of the container is the unit's" {
    # T3: the exit status of the container is the unit's, and Restart=on-failure
    # makes exactly one new container.
    unit "$P-t3" -- "${SH[@]}" "${RUN[@]}" --name t3 "$IMAGE" sh -c 'sleep 1; exit 3'
    e2e_wait_unit_state "$P-t3" failed 15
    check "T3 a container exiting 3 fails the unit" failed "$(prop "$P-t3" ActiveState)"
    check "T3 with status 3" 3 "$(prop "$P-t3" ExecMainStatus)"
    check "T3 the monitor removed it (--rm)" "" "$(row t3)"
    check "T3 the monitor kept its died event, once" 1 \
        "$(grep '"Status":"died"' "$WORKDIR/events/events.log" 2> /dev/null | grep '"Name":"t3"' | grep -c '"containerExitCode":"3"')"
}

@test "Restart=on-failure makes exactly one new container" {
    rm -f "$WORKDIR/vol/once"
    unit "$P-t4" -p Restart=on-failure -p RestartSec=1 -- "${SH[@]}" "${RUN[@]}" --name t4 \
        -v "$WORKDIR/vol:/vol" "$IMAGE" \
        sh -c 'if [ -e /vol/once ]; then exec sleep inf; fi; touch /vol/once; sleep 1; exit 3'
    # (a poll: NRestarts and ActiveState are the manager's, no notification to a shell)
    for i in $(seq 50); do [ "$(prop "$P-t4" NRestarts)" = 1 ] && [ "$(row t4)" = running ] && break; sleep 0.2; done
    check "T3 Restart=on-failure restarts once" 1 "$(prop "$P-t4" NRestarts)"
    check "T3 the unit is active again" active "$(prop "$P-t4" ActiveState)"
    check "T3 one container" 1 "$("${ENGINE[@]}" container list --all --format '{{.Names}}' 2> /dev/null | awk '$1 == "t4"' | wc -l)"
    "${SCTL[@]}" stop "$P-t4.service"
}

@test "a monitor killed with SIGKILL: ExecStopPost cleans up" {
    # T4: a monitor killed with SIGKILL: ExecStopPost cleans up.
    unit "$P-t5" -p "ExecStopPost=-$BIN/velarx --config $CONF container rm -t 0 -v -f -i t5" -- \
        "${SH[@]}" "${RUN[@]}" --name t5 "$IMAGE" sleep inf
    kill -9 "$(prop "$P-t5" MainPID)"
    e2e_wait_unit_state "$P-t5" failed 15
    check "T4 the unit fails with the monitor" failed "$(prop "$P-t5" ActiveState)"
    check "T4 ExecStopPost removed the container" "" "$(row t5)"
    check "T4 no process is left" "" "$(procs "$P-t5")"
    check "T4 no mount is left" 0 "$(mounts)"
    check "T4 no bundle is left" 0 "$(ls "$WORKDIR/data/root/bundles" | wc -l)"
}

@test "passthrough and journald write to the unit's journal" {
    # T5: passthrough and journald write to the unit's journal.
    for d in passthrough journald; do
        unit "$P-log-$d" -- "${SH[@]}" "${RUN[@]}" --name "tl-${d:0:1}" --log-driver=$d "$IMAGE" \
            sh -c "echo out-$d-$$; echo err-$d-$$ >&2; sleep 1"
    done
    for d in passthrough journald; do
        e2e_wait_unit_state "$P-log-$d" inactive 15
        check "T5 $d: the unit ends cleanly" success "$(prop "$P-log-$d" Result)"
        # (the journal is read again from its start, followed until both lines are in)
        timeout 30 "${JCTL[@]}" -u "$P-log-$d.service" -o cat --no-pager -n all -f > "$WORKDIR/jlog-$d.out" 2> /dev/null 3>&- &
        jp=$!
        e2e_wait_line "$WORKDIR/jlog-$d.out" "^out-$d-$$\$" || true
        e2e_wait_line "$WORKDIR/jlog-$d.out" "^err-$d-$$\$" || true
        kill "$jp" 2> /dev/null
        wait "$jp" 2> /dev/null
        out=$("${JCTL[@]}" -u "$P-log-$d.service" -o cat --no-pager | grep -c -e "^out-$d-$$\$" -e "^err-$d-$$\$")
        check "T5 $d: stdout and stderr are in journalctl -u" 2 "$out"
    done
}

@test "a unit's container has pasta and its published port" {
    { [ "$MODE" = user ] && [ "$(id -u)" != 0 ]; } || skip "rootless only"
    command -v pasta > /dev/null || skip "no pasta"
    # T7: rootless, a container of a unit has the network of the engine: pasta,
    # its published port, and pasta goes with the unit.
    port=$PORT
    unit "$P-net" -- "${SH[@]}" "${RUN[@]}" --name tn -p "$port:80" "$IMAGE" \
        sh -c 'grep -q "^nameserver 169.254.1.1" /etc/resolv.conf && exec nc -lk -p 80 -e echo from-unit'
    out=$(python3 -I -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
s.settimeout(3)
print(s.recv(4096).decode().strip())
' "$port" 2>&1)
    check "T7 a unit's container has pasta and its published port" from-unit "$out"
    check "T7 pasta runs for it" 1 "$(ls "$WORKDIR/state/networks/pasta/" 2> /dev/null | grep -c '\.pid$')"
    "${SCTL[@]}" stop "$P-net.service"
    check "T7 pasta goes with the unit" 0 "$(ls "$WORKDIR/state/networks/pasta/" 2> /dev/null | grep -c '\.pid$')"
    check "T7 no namespace of a container is left" 0 "$(e2e_netns_records "$WORKDIR/data/storage/db.sqlite")"
}

@test "a unit's container on a rootless bridge network has its port through the forwarder" {
    { [ "$MODE" = user ] && [ "$(id -u)" != 0 ]; } || skip "rootless only"
    command -v pasta > /dev/null || skip "no pasta"
    # On a bridge network: the rootless network namespace, the port through
    # the forwarder, which goes with the unit.
    # (network create needs the engine service: one for the time of it)
    "${ENGINE[@]}" varlink > "$WORKDIR/netd.log" 2>&1 3>&- &
    netd=$!
    e2e_wait_path "$SOCK"
    "${SH[@]}" --socket "$SOCK" network create --subnet 10.213.70.0/24 unet > /dev/null
    check "T7 a rootless bridge network" 0 $?
    kill -INT "$netd"
    wait "$netd" 2> /dev/null
    netd=
    rm -f "$SOCK"
    port=$((PORT + 1))
    unit "$P-bnet" -- "${SH[@]}" "${RUN[@]}" --name tb --network unet -p "$port:80" "$IMAGE" \
        nc -lk -p 80 -e echo from-bridge-unit
    out=$(python3 -I -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
s.settimeout(3)
print(s.recv(4096).decode().strip())
' "$port" 2>&1)
    check "T7 a unit's container on a bridge has its published port" from-bridge-unit "$out"
    check "T7 a forwarder runs for it" 1 "$(ls "$WORKDIR/state/networks/portfwd/" 2> /dev/null | grep -c '\.pid$')"
    "${SCTL[@]}" stop "$P-bnet.service"
    check "T7 the forwarder goes with the unit" 0 "$(ls "$WORKDIR/state/networks/portfwd/" 2> /dev/null | grep -c '\.pid$')"
    # (a poll of the kernel: the port is released when the forwarder has gone; there is no
    # event for a port that is free)
    check "T7 the port is free again" free "$(python3 -I -c '
import socket, sys, time
for i in range(50):
    try:
        # SO_REUSEADDR: the connection of the check lingers in TIME_WAIT.
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", int(sys.argv[1])))
        s.listen()
        print("free")
        break
    except OSError:
        time.sleep(0.1)
else:
    print("in use")' "$port")"
    "${ENGINE[@]}" varlink > "$WORKDIR/netd.log" 2>&1 3>&- &
    netd=$!
    e2e_wait_path "$SOCK"
    "${SH[@]}" --socket "$SOCK" network rm unet > /dev/null
    check "T7 network rm" 0 $?
    # (pasta of the namespace ends with the last bridge: its pid is waited for)
    pasta=$(pgrep -f "[p]asta.*$WORKDIR/state/networks/rootless-netns.pasta.pid" | head -1)
    if [ -n "$pasta" ]; then e2e_wait_exit "$pasta" 10 || true; fi
    check "T7 the rootless network namespace goes with the last bridge" "" \
        "$(ps -eo args | grep "[p]asta.*$WORKDIR/state/networks/rootless-netns.pasta.pid")"
    kill -INT "$netd"
    wait "$netd" 2> /dev/null
    netd=
    rm -f "$SOCK"
}

@test "socket activation gives the container the sockets of the unit" {
    # T8: socket activation (Quadlet's .socket units): the container gets the
    # sockets as its descriptors 3, ... with LISTEN_FDS and LISTEN_PID=1.
    LSOCK=$WORKDIR/listen.sock
    echo "$P-t8" >> "$WORKDIR/units.list"
    # The SELinux policy does not let container_t use the sockets of a system
    # unit (init_t's): SELinux would give the container /dev/null for them.
    T8OPT=()
    if [ "$MODE" = system ] && command -v selinuxenabled > /dev/null && selinuxenabled; then
        T8OPT=(--security-opt label=disable)
    fi
    timeout 60 "${SRUN[@]}" --quiet --unit="$P-t8" --socket-property=ListenStream="$LSOCK" \
        --socket-property=FileDescriptorName=web \
        -p Type=notify -p NotifyAccess=all -p Delegate=yes -p KillMode=mixed "${ENVP[@]}" \
        "${SH[@]}" "${RUN[@]}" --name t8 --log-driver=passthrough "${T8OPT[@]}" "$IMAGE" \
        sh -c 'echo "fds=$LISTEN_FDS pid=$LISTEN_PID names=$LISTEN_FDNAMES"; echo "fd3=$(readlink /proc/1/fd/3)"; ls -l /proc/1/fd; echo listed; sleep inf'
    check "T8 the socket waits for a connection" inactive "$(prop "$P-t8" ActiveState)"
    python3 -I -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' "$LSOCK"
    e2e_wait_unit_state "$P-t8" active 30
    check "T8 a connection starts the unit" active "$(prop "$P-t8" ActiveState)"
    # (the journal of the unit, followed until the container has listed its descriptors)
    coproc T8LOG { "${JCTL[@]}" -u "$P-t8.service" -o cat --no-pager -n all -f; }
    out=
    while read -r -t 60 -u "${T8LOG[0]}" line; do
        out+=$line$'\n'
        [ "$line" = listed ] && break
    done
    kill "$T8LOG_PID" 2> /dev/null
    check "T8 the container has the sockets in its environment" 1 "$(grep -c '^fds=1 pid=1 names=web$' <<< "$out")"
    check "T8 its descriptor 3 is the socket" 1 "$(grep -c '^fd3=socket:\[' <<< "$out")"
    # The output of a program the container runs, ls, is in the journal too.
    # Under a user manager the journal attributes a line to the unit by the
    # cgroup of the process that wrote it, and a process that is gone when the
    # journal looks (ls exits at once) leaves a line `journalctl -u` does not
    # select: the same for any program in any unit, without a container.  The
    # lines of the stream of the unit are all there.
    sid=$("${JCTL[@]}" -u "$P-t8.service" -o json --no-pager | grep -o '"_STREAM_ID" *: *"[0-9a-f]*"' | head -n 1 | grep -o '[0-9a-f]\{32\}')
    check "T8 the stream of the unit is known" 32 "${#sid}"
    lines=$("${JCTL[@]}" -m _STREAM_ID="$sid" -o cat --no-pager | grep -c ' -> ')
    check "T8 the output of ls reaches the stream of the unit" ok "$([ "$lines" -ge 4 ] && echo ok)"
    "${SCTL[@]}" stop "$P-t8.service" "$P-t8.socket"
    check "T8 stop" "" "$(row t8)"
}

@test "the engine says when the policy withholds a socket of the unit from the container" {
    [ "$MODE" = system ] && command -v selinuxenabled > /dev/null && selinuxenabled || skip "needs system units and SELinux"
    # T8s: the engine says when the policy withholds a socket of the unit from
    # the container (the sockets of a unit of an executable labelled bin_t are
    # unconfined_service_t's), and says nothing when the executable is the
    # container runtime's (container_runtime_exec_t: the sockets get a type the
    # containers may use).
    mkdir -p "$WORKDIR/bin-rt"
    cp --reflink=auto "$BIN"/velarx* "$WORKDIR/bin-rt/" || exit 1
    chcon -t container_runtime_exec_t "$WORKDIR"/bin-rt/* || exit 1
    for v in bin bin-rt; do
        n=$P-t8s-${v#bin}
        echo "$n" >> "$WORKDIR/units.list"
        timeout 60 "${SRUN[@]}" --quiet --unit="$n" --socket-property=ListenStream="$WORKDIR/$v.sock" \
            --socket-property=FileDescriptorName=web \
            -p Type=notify -p NotifyAccess=all -p Delegate=yes -p KillMode=mixed "${ENVP[@]}" \
            "$WORKDIR/$v/velarx" --config "$CONF" "${RUN[@]}" --name t8s --log-driver=passthrough "$IMAGE" sleep inf
        python3 -I -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' "$WORKDIR/$v.sock"
        e2e_wait_unit_state "$n" active 30
        check "T8s the unit is active" active "$(prop "$n" ActiveState)"
        if [ "$v" = bin ]; then
            timeout 30 "${JCTL[@]}" -u "$n.service" -o cat --no-pager -n all -f > "$WORKDIR/jwarn.out" 2> /dev/null 3>&- &
            jp=$!
            e2e_wait_line "$WORKDIR/jwarn.out" 'does not let container_t use the socket `web`' || true
            kill "$jp" 2> /dev/null
            wait "$jp" 2> /dev/null
        else
            # (a window: the engine says nothing, and a line that does not come has no event)
            sleep 1
        fi
        warned=$("${JCTL[@]}" -u "$n.service" -o cat --no-pager | grep -c 'does not let container_t use the socket `web`')
        if [ "$v" = bin ]; then
            check "T8s the engine says the policy withholds the socket (bin_t)" 1 "$warned"
        else
            check "T8s and says nothing when the executable is container_runtime_exec_t" 0 "$warned"
        fi
        "${SCTL[@]}" stop "$n.service" "$n.socket"
    done
}

@test "--cgroups=split puts the monitor and the container in cgroups of the unit" {
    # T9: --cgroups=split: the monitor goes to <unit>/runtime, the container to
    # <unit>/velarx-payload-<id>, where its limits apply.
    unit "$P-t9" -- "${SH[@]}" "${RUN[@]}" --name t9 --cgroups=split --memory 64m --pids-limit 50 \
        "$IMAGE" sleep inf
    check "T9 a split unit runs" active "$(prop "$P-t9" ActiveState)"
    cg=$(prop "$P-t9" ControlGroup)
    main=$(prop "$P-t9" MainPID)
    check "T9 the monitor is in <unit>/runtime" "0::$cg/runtime" "$(cat "/proc/$main/cgroup" 2> /dev/null)"
    ctr=$(pgrep -P "$main" -x sleep)
    id=$("${ENGINE[@]}" container list --all --no-trunc --format '{{.ID}} {{.Names}}' 2> /dev/null | awk '$2 == "t9" {print $1}')
    check "T9 the container is in <unit>/velarx-payload-<id>" "0::$cg/velarx-payload-${id:0:12}" \
        "$(cat "/proc/$ctr/cgroup" 2> /dev/null)"
    check "T9 --memory applies there" 67108864 "$(cat "/sys/fs/cgroup$cg/velarx-payload-${id:0:12}/memory.max" 2> /dev/null)"
    check "T9 --pids-limit applies there" 50 "$(cat "/sys/fs/cgroup$cg/velarx-payload-${id:0:12}/pids.max" 2> /dev/null)"
    "${SCTL[@]}" stop "$P-t9.service"
    check "T9 stop" success "$(prop "$P-t9" Result)"
    check "T9 no row is left" "" "$(row t9)"
}

@test "--cgroups=split works for every command of a unit, not once" {
    # The first split moves the shell of the unit to <unit>/runtime; the
    # commands after it still run in a unit.
    echo "$P-t9b" >> "$WORKDIR/units.list"
    out=$(timeout 120 "${SRUN[@]}" --quiet --wait --pipe --unit="$P-t9b" -p Type=exec -p Delegate=yes \
        "${ENVP[@]}" bash -c '
        for i in 1 2 3; do
            "$@" container run --rm --tls-verify=false --network none --cgroups=split --memory 64m \
                '"$IMAGE"' cat /sys/fs/cgroup/memory.max 2> /dev/null || echo "rc=$?"
        done' bash "${SH[@]}")
    check "T9b three splits in one unit" "$(printf '67108864\n67108864\n67108864')" "$out"
}

@test "a container of a pod is split too" {
    # A container of a pod is split too (Quadlet's .container with Pod=): in its
    # unit's cgroup, in the namespaces of the pod.
    "${ENGINE[@]}" pod create --name t11pod --network none > /dev/null 2>&1
    "${ENGINE[@]}" pod start t11pod > /dev/null 2>&1
    unit "$P-t11" -- "${SH[@]}" "${RUN[@]}" --name t11 --cgroups=split --pod t11pod "$IMAGE" sleep inf
    check "T11 a split container of a pod runs" active "$(prop "$P-t11" ActiveState)"
    cg=$(prop "$P-t11" ControlGroup)
    ctr=$(pgrep -P "$(prop "$P-t11" MainPID)" -x sleep)
    check_prefix=$(cat "/proc/$ctr/cgroup" 2> /dev/null)
    check "T11 in its unit's cgroup" "0::$cg/velarx-payload-" "${check_prefix%????????????}"
    "${SCTL[@]}" stop "$P-t11.service"
    "${ENGINE[@]}" pod rm -t 0 -f t11pod > /dev/null 2>&1
}

@test "limits without --cgroups=split are refused" {
    # Limits without a cgroup of the container are refused, not dropped.
    unit "$P-t10" -- "${SH[@]}" "${RUN[@]}" --name t10 --memory 64m "$IMAGE" sleep inf 2> /dev/null
    check "T10 limits without --cgroups=split are refused" failed "$(prop "$P-t10" ActiveState)"
}

@test "an engine service under systemd keeps its MainPID and sees the units' containers" {
    # T6: with an engine service under systemd: it keeps its own MainPID while
    # units with --sdnotify start and stop, it sees the containers the units run,
    # it may be killed under them, and it never takes a socket from a client.
    unit "$P-daemon" -p KillMode=process -- "$BIN/velarx" --config "$CONF" varlink
    check "T6 the engine service runs" active "$(prop "$P-daemon" ActiveState)"
    dmain=$(prop "$P-daemon" MainPID)
    unit "$P-t6" -- "${SH[@]}" "${RUN[@]}" --name t6 "$IMAGE" sleep inf
    check "T6 a unit runs its container with a server up" active "$(prop "$P-t6" ActiveState)"
    check "T6 its main process is its monitor" velarx-monitor "$(cat "/proc/$(prop "$P-t6" MainPID)/comm" 2> /dev/null)"
    check "T6 the server sees the container" yes \
        "$("${SH[@]}" --socket "$SOCK" container list --all --format '{{.Names}}' 2> /dev/null | awk '$1 == "t6" {print "yes"}')"
    "${SCTL[@]}" stop "$P-t6.service"
    check "T6 the server keeps its MainPID" "$dmain" "$(prop "$P-daemon" MainPID)"
    check "T6 the server is still active" active "$(prop "$P-daemon" ActiveState)"
    check "T6 the server sees the container go" "" \
        "$("${SH[@]}" --socket "$SOCK" container list --all --format '{{.Names}}' 2> /dev/null | awk '$1 == "t6"')"
}

@test "an image with systemd-notify is imported" {
    # T12-T15: --sdnotify through the monitor's proxy.  An image of the
    # host's systemd-notify and shell, made here.
    NROOT=$WORKDIR/notify-root
    mkdir -p "$NROOT"/{bin,tmp,run,proc,sys,dev,etc}
    for b in bash sleep touch systemd-notify; do
        p=$(command -v "$b")
        cp "$p" "$NROOT/bin/$b"
        ldd "$p" | grep -o '/[^ ]*' | while read -r l; do
            mkdir -p "$NROOT$(dirname "$l")"
            cp -L "$l" "$NROOT$l" 2> /dev/null
        done
    done
    ln -sf bash "$NROOT/bin/sh"
    tar -C "$NROOT" -cf "$WORKDIR/notify-root.tar" .
    "${SH[@]}" --socket "$SOCK" image import "$WORKDIR/notify-root.tar" localhost/velarx-notify:1 > /dev/null
    check "T12 an image with systemd-notify" 0 $?
}

@test "--sdnotify=container: the unit waits for the container's READY" {
    # container: the unit waits for the container's READY; meanwhile its main
    # process is the monitor; STATUS reaches it, MAINPID does not.
    unit "$P-t12" --no-block -- "${SH[@]}" "${NRUN[@]}" --name t12 --sdnotify=container "$NIMG" \
        sh -c 'sleep 4; systemd-notify --status="from the container" MAINPID=1; systemd-notify --ready; sleep inf'
    # (a window: the container is ready after 4 s)
    sleep 2
    check "T12 container: activating until the container is ready" activating "$(prop "$P-t12" ActiveState)"
    check "T12 container: the main process is the monitor" velarx-monitor \
        "$(cat "/proc/$(prop "$P-t12" MainPID)/comm" 2> /dev/null)"
    e2e_wait_unit_state "$P-t12" active 20
    check "T12 container: READY of the container activates the unit" active "$(prop "$P-t12" ActiveState)"
    check "T12 container: STATUS of the container" "from the container" "$(prop "$P-t12" StatusText)"
    check "T12 container: MAINPID of the container is not taken" velarx-monitor \
        "$(cat "/proc/$(prop "$P-t12" MainPID)/comm" 2> /dev/null)"
    "${SCTL[@]}" stop "$P-t12.service"
}

@test "NOTIFY_SOCKET and no --sdnotify means container" {
    # NOTIFY_SOCKET and no --sdnotify: container, as podman.
    unit "$P-t13" --no-block -- "${SH[@]}" "${NRUN[@]}" --name t13 "$NIMG" \
        sh -c 'sleep 4; systemd-notify --ready; sleep inf'
    # (a window: the container is ready after 4 s)
    sleep 2
    check "T13 the default under a manager is container" activating "$(prop "$P-t13" ActiveState)"
    e2e_wait_unit_state "$P-t13" active 20
    check "T13 and the container's READY activates it" active "$(prop "$P-t13" ActiveState)"
    "${SCTL[@]}" stop "$P-t13.service"
}

@test "--sdnotify=healthy: READY after the first passing check, past TimeoutStartSec" {
    # healthy: READY after the first passing check, with more time to start
    # than TimeoutStartSec while the check fails (EXTEND_TIMEOUT_USEC).  The
    # container is healthy well after TimeoutStartSec, which is long enough for
    # the engine to start it on a loaded machine (the extension comes from the
    # monitor, once the container runs).
    # A daemon-reload of the manager (the quadlet tests of a suite running
    # alongside) re-arms the start timeout from TimeoutStartSec and forgets
    # EXTEND_TIMEOUT_USEC: past TimeoutStartSec the unit times out at once.
    # That is systemd's; such a run is tried again.
    for try in 1 2 3; do
        since=$(date +%s)
        unit "$P-t14" --no-block -p TimeoutStartSec=40 -- "${SH[@]}" "${NRUN[@]}" --name t14 \
            --sdnotify=healthy --health-cmd 'test -e /tmp/ok' --health-interval 2s --health-start-period 2m \
            "$NIMG" sh -c 'sleep 55; touch /tmp/ok; sleep inf'
        e2e_wait_unit_state "$P-t14" active 120
        t14=$(prop "$P-t14" ActiveState)
        [ "$t14" = failed ] && [ "$(prop "$P-t14" Result)" = timeout ] &&
            "${JCTL[@]}" --since "@$since" -o cat 2> /dev/null | grep -q '^Reloading finished' || break
        echo "     (T14: a daemon-reload of the manager cut the extended start timeout; again)"
        "${SCTL[@]}" stop "$P-t14.service" 2> /dev/null
        "${SCTL[@]}" reset-failed "$P-t14.service" 2> /dev/null
    done
    check "T14 healthy: active after the first passing check, past TimeoutStartSec" active "$t14"
    "${SCTL[@]}" stop "$P-t14.service"
}

@test "--sdnotify=healthy without a health check is refused" {
    unit "$P-t15" -- "${SH[@]}" "${NRUN[@]}" --name t15 --sdnotify=healthy "$NIMG" sleep inf 2> /dev/null
    check "T15 healthy without a health check is refused" failed "$(prop "$P-t15" ActiveState)"
}

@test "run --no-monitor in a unit" {
    # T16: run --no-monitor in a unit: no monitor process, the main
    # process of the unit stays the one it started, READY of the container
    # reaches the unit, a stop ends the container and the unit cleanly.
    unit "$P-t16" --no-block -- "${SH[@]}" container run --replace --rm --network none --no-monitor \
        --name t16 --sdnotify=container "$NIMG" \
        sh -c 'sleep 2; systemd-notify --ready; trap "exit 0" TERM; sleep inf & wait'
    e2e_wait_unit_state "$P-t16" active 20
    check "T16 --no-monitor: READY of the container activates the unit" active "$(prop "$P-t16" ActiveState)"
    check "T16 the main process is the one the unit started" velarx \
        "$(cat "/proc/$(prop "$P-t16" MainPID)/comm" 2> /dev/null)"
    # (the image server of a rootless run is a velarx-monitor too, and not the
    # monitor of the container: its title says which)
    check "T16 no monitor process" 0 \
        "$(for p in $(procs "$P-t16"); do
            tr '\0' ' ' < "/proc/$p/cmdline" 2> /dev/null | grep -v 'image server' | grep -c '^velarx-monitor'
        done | grep -c '^[1-9]')"
    check "T16 the container is recorded" running "$(row t16)"
    "${SCTL[@]}" stop "$P-t16.service"
    check "T16 a stop is a clean end" success "$(prop "$P-t16" Result)"
    check "T16 nothing is left (--rm)" "" "$(row t16)"
}

@test "the watchdog of the unit is fed by the container" {
    # T18: the watchdog of the unit.  The container learns its period
    # (WATCHDOG_USEC) and its WATCHDOG=1 reaches the unit through the proxy:
    # a container that pings lives past several periods, one that stops
    # pinging ends the unit with the watchdog.
    unit "$P-t18" -p WatchdogSec=3 -- "${SH[@]}" "${NRUN[@]}" --name t18 --sdnotify=container "$NIMG" \
        sh -c 'echo "usec=$WATCHDOG_USEC pid=$WATCHDOG_PID"; systemd-notify --ready; while :; do systemd-notify WATCHDOG=1; sleep 1; done'
    check "T18 watchdog: a unit with WatchdogSec runs" active "$(prop "$P-t18" ActiveState)"
    # (a window: the unit lives through several watchdog periods)
    sleep 8
    check "T18 watchdog: the pings of the container keep it alive past several periods" active "$(prop "$P-t18" ActiveState)"
    check "T18 watchdog: the container has the period of the unit" "usec=3000000 pid=" \
        "$("${JCTL[@]}" -u "$P-t18.service" -o cat --no-pager | grep -o '^usec=.*' | head -1)"
    "${SCTL[@]}" stop "$P-t18.service"
    unit "$P-t18b" -p WatchdogSec=3 -p Restart=no -- "${SH[@]}" "${NRUN[@]}" --name t18b --sdnotify=container "$NIMG" \
        sh -c 'systemd-notify --ready; sleep inf'
    e2e_wait_unit_state "$P-t18b" failed 15
    check "T18 watchdog: a container that does not ping fails the unit" watchdog "$(prop "$P-t18b" Result)"
    "${SCTL[@]}" reset-failed "$P-t18b.service" 2> /dev/null
}

@test "the watchdog with --no-monitor" {
    # --no-monitor: the unit's main process is velarx, WATCHDOG_PID is its pid.
    unit "$P-t18c" -p WatchdogSec=3 -- "${SH[@]}" container run --replace --rm --network none --no-monitor \
        --log-driver=passthrough --name t18c --sdnotify=container "$NIMG" \
        sh -c 'echo "usec=$WATCHDOG_USEC"; systemd-notify --ready; while :; do systemd-notify WATCHDOG=1; sleep 1; done'
    # (a window: the unit lives through several watchdog periods)
    sleep 8
    check "T18 watchdog: --no-monitor keeps the unit alive too" active "$(prop "$P-t18c" ActiveState)"
    check "T18 watchdog: --no-monitor passes the period" "usec=3000000" \
        "$("${JCTL[@]}" -u "$P-t18c.service" -o cat --no-pager | grep -o '^usec=.*' | head -1)"
    "${SCTL[@]}" stop "$P-t18c.service"
}

@test "the server never takes a socket from a client" {
    # A socket of our own: nothing may arrive on it.
    TRAP=$WORKDIR/trap.sock
    rm -f "$TRAP"
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(sys.argv[1]); s.settimeout(12)
try: print(s.recv(4096).decode(errors="replace"))
except socket.timeout: print("nothing")
' "$TRAP" > "$WORKDIR/trap.out" 3>&- &
    trap_pid=$!
    e2e_wait_path "$TRAP"
    NOTIFY_SOCKET=$TRAP "${SH[@]}" --socket "$SOCK" container run -d --name tapi --tls-verify=false "$IMAGE" true > /dev/null 2> "$WORKDIR/err"
    check "T6 the client refuses a unit's container over the API" 125 $?
    check "T6 and says why" 1 "$(grep -c -- --socket "$WORKDIR/err")"
    # (a container through the engine service: nothing reaches the socket)
    "${SH[@]}" --socket "$SOCK" container create --name tapi --tls-verify=false "$IMAGE" true > /dev/null 2>&1
    "${SH[@]}" --socket "$SOCK" container start tapi > /dev/null 2>&1
    "${SH[@]}" --socket "$SOCK" container wait tapi > /dev/null 2>&1
    wait "$trap_pid"
    trap_pid=
    check "T6 the server sent nothing to a client's socket" nothing "$(cat "$WORKDIR/trap.out")"
    "${SH[@]}" --socket "$SOCK" container rm -t 0 -f tapi > /dev/null 2>&1
}

@test "a unit of generate systemd starts and stops its container" {
    # T17: a unit of `generate systemd` starts and stops its container:
    # Type=forking, the monitor's pid file.
    "${ENGINE[@]}" container create --name tg --tls-verify=false "$IMAGE" sleep inf > /dev/null 2>&1
    # (the REST API in front of the engine service, for the time of the request)
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --idle-exit 0 --listen "unix://$WORKDIR/rest.sock" \
        > "$WORKDIR/rest.log" 2>&1 3>&- &
    rest=$!
    e2e_wait_path "$WORKDIR/rest.sock"
    curl -s -m 20 --unix-socket "$WORKDIR/rest.sock" 'http://d/v5.0.0/libpod/generate/tg/systemd?useName=true' > "$WORKDIR/gen.json"
    kill "$rest" 2> /dev/null; wait "$rest" 2> /dev/null
    python3 -I - "$WORKDIR/gen.json" > "$WORKDIR/gen.props" << 'EOT'
import json, sys
unit = json.load(open(sys.argv[1]))["container-tg"].replace(" \\\n\t", " ")
for line in unit.splitlines():
    k, _, v = line.partition("=")
    if k in ("ExecStart", "ExecStop", "PIDFile", "Type"):
        print(f"{k}={v}")
EOT
    gen () { sed -n "s/^$1=//p" "$WORKDIR/gen.props"; }
    check "T17 the unit forks" forking "$(gen Type)"
    read -r -a start <<< "$(gen ExecStart)"
    echo "$P-t17" >> "$WORKDIR/units.list"
    timeout 120 "${SRUN[@]}" --quiet --unit="$P-t17" -p Type=forking -p PIDFile="$(gen PIDFile)" \
        -p ExecStop="$(gen ExecStop)" -p Delegate=yes -p TimeoutStartSec=90 "${ENVP[@]}" "${start[@]}"
    check "T17 it runs" active "$(prop "$P-t17" ActiveState)"
    check "T17 its main process is the monitor" velarx-monitor "$(cat "/proc/$(prop "$P-t17" MainPID)/comm" 2> /dev/null)"
    check "T17 the container runs" running "$(row tg)"
    "${SCTL[@]}" stop "$P-t17.service"
    check "T17 the stop stops the container" exited "$(row tg)"
    "${ENGINE[@]}" container rm -t 0 -f tg > /dev/null 2>&1
}

@test "the server killed under a unit: the unit and its container go on" {
    unit "$P-t7" -- "${SH[@]}" "${RUN[@]}" --name t2 "$IMAGE" sleep inf
    "${SCTL[@]}" kill --kill-whom=main -s KILL "$P-daemon.service"
    e2e_wait_unit_state "$P-daemon" failed 15
    check "T6 the server was killed" failed "$(prop "$P-daemon" ActiveState)"
    check "T6 the unit survives the server" active "$(prop "$P-t7" ActiveState)"
    "${SCTL[@]}" stop "$P-t7.service"
    check "T6 and stops cleanly without it" success "$(prop "$P-t7" Result)"
    check "T6 nothing is left of it" "" "$(row t2)"
    check "T6 no mount is left" 0 "$(mounts)"
}
