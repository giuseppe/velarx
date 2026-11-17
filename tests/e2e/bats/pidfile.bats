# SPDX-License-Identifier: Apache-2.0
# The pid files of Type=forking units: --conmon-pidfile (the monitor,
# the unit's main process), --pidfile (the init process of the container)
# and pod create --infra-conmon-pidfile (Quadlet's .pod units).
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/pidfile.bats                  # user units
#   VELARX_BINDIR=target/debug MODE=system bats tests/e2e/bats/pidfile.bats      # system units, as root
#
# Transient units only (systemd-run), named shp-<pid>-*, stopped and reset
# at the end; the store and the runtime directory are in $WORKDIR.

load helpers

vars () {
    CONF=$WORKDIR/config.toml
    SOCK=$WORKDIR/api.sock
    PIDS=$WORKDIR/pids
    if [ "$MODE" = system ]; then
        SCTL=(systemctl)
        SRUN=(systemd-run)
    else
        SCTL=(systemctl --user)
        SRUN=(systemd-run --user)
    fi
    ENVP=(-p Environment=HOME="$WORKDIR/home" -p Environment=XDG_RUNTIME_DIR="$WORKDIR/run")
    SH=("$BIN/velarx" --config "$CONF")
    ENGINE=(env HOME="$WORKDIR/home" XDG_RUNTIME_DIR="$WORKDIR/run" "$BIN/velarx" --config "$CONF")
}

setup () { set +e; [ -z "${WORKDIR:-}" ] || vars; }

prop () { "${SCTL[@]}" show -P "$2" "$1.service"; }
# unit NAME TYPE [-p PROP...] -- CMD...
unit () {
    local name=$1 type=$2; shift 2
    local props=()
    while [ "$1" != -- ]; do props+=("$1"); shift; done
    shift
    echo "$name" >> "$WORKDIR/units.list"
    timeout 120 "${SRUN[@]}" --quiet --unit="$name" -p Type="$type" -p Delegate=yes \
        -p KillMode=mixed -p TimeoutStartSec=90 "${ENVP[@]}" "${props[@]}" "$@"
}
row () { "${ENGINE[@]}" container list --all --format '{{.Names}} {{.State}}' 2> /dev/null | awk -v n="$1" '$1 == n {print $2}'; }
procs () {
    local cg
    cg=$(prop "$1" ControlGroup)
    [ -n "$cg" ] && cat "/sys/fs/cgroup$cg/cgroup.procs" 2> /dev/null
}
# (the REST API of the test: velarx-api in front of the engine service, started
# at the first request)
rest_up () {
    [ -S "$WORKDIR/rest.sock" ] && return 0
    env HOME="$WORKDIR/home" XDG_RUNTIME_DIR="$WORKDIR/run" setsid "$BIN/velarx-api" --config "$CONF" \
        --no-start-engine --idle-exit 0 --listen "unix://$WORKDIR/rest.sock" \
        > "$WORKDIR/rest.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/rest.pid"
    e2e_wait_path "$WORKDIR/rest.sock" 10
}
api () { rest_up; curl -s -m 30 --unix-socket "$WORKDIR/rest.sock" -H 'Content-Type: application/json' "$@"; }
insp () { rest_up; curl -s -m 30 --unix-socket "$WORKDIR/rest.sock" "http://d/v4.0.0/libpod/containers/$1/json" \
    | python3 -c 'import json, sys; d = json.load(sys.stdin); print(d["ConmonPidFile"], d["PidFile"])'; }

setup_file () {
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}
    export MODE=${MODE:-user}
    if [ "$MODE" = system ]; then
        skip_unless_root
    else
        skip_unless_systemd_user
    fi
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export WORKDIR; WORKDIR=$(realpath "$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-pidfile.XXXXXX")")
    export P=shp-$$
    mkdir -p "$WORKDIR/home" "$WORKDIR/run" "$WORKDIR/pids"
    chmod 700 "$WORKDIR/run"
    cat > "$WORKDIR/config.toml" <<TOML
[engine]
socket = "$WORKDIR/api.sock"
[server]
socket = "$WORKDIR/api.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/data/root"
[storage]
root = "$WORKDIR/data/storage"
TOML
    if [ "$MODE" = system ]; then
        # (system services may only run binaries labelled as such: all of
        # them, the helpers the engine starts too)
        e2e_system_bin
    else
        ln -sfn "/run/user/$(id -u)/systemd" "$WORKDIR/run/systemd"
    fi
}

# the directory of the pid files of the pod unit (system units)
teardown () {
    [ "$MODE" = system ] && rmdir "/run/$P" 2> /dev/null
    return 0
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    vars
    local u
    for u in $(cat "$WORKDIR/units.list" 2> /dev/null); do
        "${SCTL[@]}" stop "$u.service" 2> /dev/null
        "${SCTL[@]}" reset-failed "$u.service" 2> /dev/null
    done
    [ -s "$WORKDIR/rest.pid" ] && kill "$(cat "$WORKDIR/rest.pid")" 2> /dev/null
    "${ENGINE[@]}" container rm -t 0 -f -i pf1 pf2 pf3 2> /dev/null > /dev/null
    e2e_teardown_file
}

@test "Type=forking with PIDFile=: the unit's main process is the monitor" {
    # The unit's main process is the monitor, read from --conmon-pidfile once
    # `run -d` returned.
    unit "$P-f1" forking -p PIDFile="$PIDS/f1.pid" -- "${SH[@]}" container run -d --network none --replace \
        --tls-verify=false --name pf1 --conmon-pidfile "$PIDS/f1.pid" --pidfile "$PIDS/f1.init" \
        "$IMAGE" sleep inf
    check "forking unit starts" 0 $?
    check "the unit is active" active "$(prop "$P-f1" ActiveState)"
    main=$(prop "$P-f1" MainPID)
    check "MainPID is the monitor" velarx-monitor "$(cat "/proc/$main/comm" 2> /dev/null)"
    check "the conmon pid file has it" "$main" "$(cat "$PIDS/f1.pid" 2> /dev/null)"
    check "the monitor is in the unit" yes "$(procs "$P-f1" | grep -qx "$main" && echo yes)"
    init=$(cat "$PIDS/f1.init" 2> /dev/null)
    check "the pid file has the init process" sleep "$(cat "/proc/$init/comm" 2> /dev/null)"
    check "the pid files are readable by all" "644 644" \
        "$(stat -c %a "$PIDS/f1.pid" 2> /dev/null) $(stat -c %a "$PIDS/f1.init" 2> /dev/null)"
    "${SCTL[@]}" stop "$P-f1.service"
    check "stop" inactive "$(prop "$P-f1" ActiveState)"
    check "the container stopped" exited "$(row pf1 | tr A-Z a-z | sed 's/stopped/exited/')"
    "${ENGINE[@]}" container rm pf1 > /dev/null 2>&1
    check "rm removes the pid files" "no no" \
        "$([ -e "$PIDS/f1.pid" ] && echo yes || echo no) $([ -e "$PIDS/f1.init" ] && echo yes || echo no)"
}

@test "a relative pid file path is the caller's directory, a directory is refused" {
    (cd "$PIDS" && "${ENGINE[@]}" container run -d --network none --tls-verify=false --name pf2 --conmon-pidfile rel.pid "$IMAGE" sleep inf > /dev/null 2>&1)
    check "a relative path is the caller's" yes "$([ -s "$PIDS/rel.pid" ] && echo yes)"
    "${ENGINE[@]}" container rm -t 0 -f pf2 > /dev/null 2>&1
    out=$("${ENGINE[@]}" container run -d --network none --tls-verify=false --name pf3 --pidfile "$PIDS/" "$IMAGE" true 2>&1)
    check "a directory is refused" 1 "$(echo "$out" | grep -c 'not an absolute file path')"
}

@test "a Quadlet .pod unit: pod create --infra-conmon-pidfile, then pod start" {
    # pod create --infra-conmon-pidfile, then Type=forking `pod start`
    # (through the engine service).
    unit "$P-daemon" notify -p NotifyAccess=all -p KillMode=process -- \
        "$BIN/velarx" --config "$CONF" varlink
    # systemd takes the pid of a process outside the unit only from a file
    # whose path the manager's user owns: %t of a system manager is /run
    PODPIDS=$PIDS
    if [ "$MODE" = system ]; then
        PODPIDS=/run/$P
        mkdir -p "$PODPIDS"
    fi
    api -d "{\"name\": \"$P-pod\", \"infra_image\": \"$IMAGE\", \"infra_command\": [\"sleep\", \"inf\"],
        \"infra_conmon_pid_file\": \"$PODPIDS/pod.pid\", \"netns\": {\"nsmode\": \"none\"}}" \
        http://d/v4.0.0/libpod/pods/create > "$WORKDIR/pod.json"
    check "pod create (podman API)" 1 "$(grep -c '"Id"' "$WORKDIR/pod.json")"
    unit "$P-pod" forking -p PIDFile="$PODPIDS/pod.pid" -- "${SH[@]}" pod start "$P-pod"
    check "pod unit starts" 0 $?
    check "the pod unit is active" active "$(prop "$P-pod" ActiveState)"
    main=$(prop "$P-pod" MainPID)
    check "its MainPID is the infra monitor" velarx-monitor "$(cat "/proc/$main/comm" 2> /dev/null)"
    check "the infra pid file has it" "$main" "$(cat "$PODPIDS/pod.pid" 2> /dev/null)"
    infra=$(api "http://d/v4.0.0/libpod/pods/$P-pod/json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["InfraContainerID"])')
    # A file not asked for shows the monitor's own, as podman shows conmon's.
    check_match "inspect of the infra container" "^$PODPIDS/pod.pid /.+/pid$" "$(insp "$infra")"
    "${SH[@]}" container run -d --network none --name pf3 --pidfile "$PIDS/api.init" "$IMAGE" sleep inf > /dev/null 2>&1
    check_match "inspect of a container" "^/.+/monitor.pid $PIDS/api.init$" "$(insp pf3)"
    check "through the server too" sleep "$(cat "/proc/$(cat "$PIDS/api.init" 2> /dev/null)/comm" 2> /dev/null)"
    "${SH[@]}" container rm -t 0 -f pf3 > /dev/null 2>&1
    "${SCTL[@]}" stop "$P-pod.service"
    "${SH[@]}" pod rm -t 0 -f "$P-pod" > /dev/null 2>&1
    check "pod rm removes the pid file" no "$([ -e "$PODPIDS/pod.pid" ] && echo yes || echo no)"
}

@test "pod create --infra-conmon-pidfile of the CLI is made absolute" {
    # the CLI's flag, made absolute
    check "the engine service of the test before runs" active "$(prop "$P-daemon" ActiveState)"
    (cd "$PIDS" && "${SH[@]}" pod create --network none --infra-image "$IMAGE" --infra-conmon-pidfile cli.pid \
        "$P-pod2" > /dev/null)
    infra=$(api "http://d/v4.0.0/libpod/pods/$P-pod2/json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["InfraContainerID"])')
    check_match "pod create --infra-conmon-pidfile" "^$PIDS/cli.pid /.+/pid$" "$(insp "$infra")"
    "${SH[@]}" pod rm -t 0 -f "$P-pod2" > /dev/null 2>&1
    "${SCTL[@]}" stop "$P-daemon.service"
}
