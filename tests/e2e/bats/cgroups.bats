# SPDX-License-Identifier: Apache-2.0
# The cgroups of the containers of the engine service.  `--cgroups=split`
# (the default where the daemon owns a cgroup): the daemon splits its cgroup at
# its start, itself in <cgroup>/engine, and with either manager a container is
# <cgroup>/[<pod>/]<id>/container (the full ids; the runtime makes its init in
# it, limits on it) with its monitor in <id>/runtime, which a stop or a
# restart of the unit stops (KillMode=control-group, as the unit we ship:
# systemd could not start it again while the containers' cgroups use its
# controllers; a reload keeps them); an error where the daemon owns no
# cgroup.  `--cgroups=scope`: every container
# is a scope of the manager outside the daemon's cgroup, velarx-<id>.scope (no
# limits: its monitor in `monitor` below it, the container in `container`;
# limits: made by the runtime, the monitor in velarx-monitor-<id>.scope), a
# pod's members are scopes in the default slice or in the slice of a pod with
# limits; `systemctl restart` of the daemon's unit keeps them.
# The cgroup is the daemon's own when a unit with Delegate=yes holds it alone;
# a daemon started by hand (a session, a shell) asks the manager for a new
# scope with Delegate=yes around itself first, and with `cgroup_manager =
# "systemd"` it is an error when it neither owns its cgroup nor finds a
# manager; rootless a user unit without Delegate=yes is not the daemon's
# either.  --cgroup-parent with "systemd" is a slice.  The containers survive
# a reload and the empty cgroups go with them.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/cgroups.bats   # as root, or as a user
#
# IMAGE is any image with a shell (default localhost:5000/alpine:chunked).
# Skipped without systemd.  The daemon runs in $WORKDIR.

load helpers
. "$BATS_TEST_DIRNAME/../cleanup.sh"

# (grep -E, as the script was: the patterns are extended regular expressions)
check_match () { # what pattern actual
    if printf '%s' "$3" | grep -Eq -- "$2"; then return 0; fi
    echo "FAIL $1: '$3' does not match '$2'" >&2
    exit 1
}
# the arrays do not cross the processes of bats: every test makes them
init_arrays () {
    unset SH
    SH=("$BIN/velarx" --config "$WORKDIR/config.toml" --socket "$WORKDIR/engine.sock")
    if [ "$(id -u)" = 0 ]; then
        SCTL=(systemctl)
    else
        SCTL=(env XDG_RUNTIME_DIR="${REAL_RUNTIME_DIR:-/run/user/$(id -u)}" systemctl --user)
    fi
}
# main_env: what the tests of the daemon started by hand know of it
main_env () {
    init_arrays
    DAEMON=$(cat "$WORKDIR/daemon.pid")
    dcg=$(sed -n 's/^0:://p' "/proc/$DAEMON/cgroup")
    DSCOPE=velarx-$DAEMON.scope
    TREE=$(dirname "$dcg")
    # (the slice of the scopes of the containers)
    if [ "$(id -u)" = 0 ]; then SLICE=machine.slice; else SLICE=user.slice; fi
}
inspect () { # container go-template-ish key of HostConfig
    curl -s --unix-socket "$SOCK" "http://d/v4.0.0/libpod/containers/$1/json" |
        python3 -I -c 'import json, sys; print(json.load(sys.stdin)["HostConfig"][sys.argv[1]])' "$2"
}
# The cgroup of the container's process, relative to the hierarchy.
cg_of () { # name
    local pid
    pid=$(curl -s --unix-socket "$SOCK" "http://d/v4.0.0/libpod/containers/$1/json" |
        python3 -I -c 'import json, sys; print(json.load(sys.stdin)["State"]["Pid"])')
    # the runtime puts the processes in a leaf of the scope
    sed -n 's/^0:://p' "/proc/$pid/cgroup" 2> /dev/null | sed 's|/container$||'
}
api () { # METHOD path [json]: the status; the body is in $WORKDIR/api.out
    curl -s -o "$WORKDIR/api.out" -w '%{http_code}' --unix-socket "$SOCK" \
        -H 'Content-Type: application/json' -X "$1" "http://d/v4.0.0/libpod/$2" ${3:+-d "$3"}
}
mk () { # JSON fragment of the spec
    api POST containers/create "{\"image\":\"$IMAGE\",\"cgroups_mode\":\"disabled\",\"command\":[\"sleep\",\"inf\"]$1}"
}
unit_cleanup () {
    "${U[@]}" container rm -t 0 -f -i u1 u2 u3 > /dev/null 2>&1
    "${U[@]}" pod rm -t 0 -f -i upod > /dev/null 2>&1
    "${SCTL[@]}" stop "$UNIT.service" > /dev/null 2>&1
}
ctr_id () { "${U[@]}" container inspect "$1" | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1; }
cgroup_of () { sed -n 's/^0:://p' "/proc/$1/cgroup"; }
cgdirs () { # the cgroups below the unit's (not the pull workers', not `exiting`, where the monitors that end leave), relative to it
    (cd "$UCG" && find . -mindepth 1 -type d ! -name .control | sed 's|^\./||' | grep -v '^pulls' | grep -v '^exiting$' | sort)
}
# The daemon of a unit with Delegate=yes owns the cgroup of the unit: no scope
# of its own, with either manager.
# unit_env MANAGER: what the tests of the daemon in a unit know of it (the
# unit, its cgroup, the containers: kept in files of its directory by the
# tests before)
unit_env () { # MANAGER [need [FILES]]
    UMGR=$1
    local d=$WORKDIR/u-$UMGR v
    init_arrays
    mkdir -p "$d"
    [ -f "$d/unit" ] || echo "velarx-e2e-cg-$UMGR-$$" > "$d/unit"
    UNIT=$(cat "$d/unit")
    USOCK=$d/api.sock
    U=("$BIN/velarx" --config "$WORKDIR/u-$UMGR/config.toml" --socket "$USOCK")
    UENV=(--setenv=HOME="$HOME" --setenv=VELARX_REGISTRIES_CONF="$VELARX_REGISTRIES_CONF")
    if [ "$(id -u)" = 0 ]; then
        SRUN=(systemd-run)
    else
        SRUN=(env XDG_RUNTIME_DIR="/run/user/$(id -u)" systemd-run --user)
        UENV+=(--setenv=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR")
    fi
    if [ -f "$d/urel" ]; then
        UREL=$(cat "$d/urel")
        UCG=/sys/fs/cgroup$UREL
    fi
    # (the steps of a manager are in order: a missing record is a failed step before)
    if [ "${2:-}" = need ]; then
        for v in urel ${3:-}; do
            if [ ! -s "$d/$v" ]; then
                echo "FAIL $UMGR: no $v of the previous test (it failed or did not run)" >&2
                exit 1
            fi
        done
    fi
    for v in pod id1 id2 pid1 pid2; do
        [ ! -f "$d/$v" ] || printf -v "$v" %s "$(cat "$d/$v")"
    done
}

setup_file () {
    local rc=0
    e2e_setup_file
    e2e_system_bin
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    init_arrays
    "${SCTL[@]}" is-system-running > /dev/null 2>&1 || rc=$?
    case $rc in 0|1) ;; *) skip "no systemd manager" ;; esac

    mkdir -p "$HOME/.config/velarx"
    chmod 700 "$XDG_RUNTIME_DIR"
    cat > "$WORKDIR/config.toml" <<TOML
[engine]
socket = "$WORKDIR/engine.sock"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/data/root"
cgroup_manager = "systemd"
[containers]
cgroups = "scope"
[storage]
root = "$WORKDIR/data/storage"
TOML
    cat > "$WORKDIR/registries.conf" <<EOF
[[registry]]
location = "${IMAGE%%/*}"
insecure = true
EOF
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # The rootless daemon has its own runtime directory; the user's manager is
    # reached through the bus.
    if [ "$(id -u)" != 0 ]; then
        export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}
        # (the private socket of the user's manager, which the daemon asks for
        # its scope)
        ln -s "/run/user/$(id -u)/systemd" "$XDG_RUNTIME_DIR/systemd"
    fi
    "$BIN/velarx" --config "$WORKDIR/config.toml" varlink > "$WORKDIR/daemon.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/daemon.pid"
    local i
    e2e_wait_path "$WORKDIR/engine.sock"
    if [ ! -S "$WORKDIR/engine.sock" ]; then
        echo "the daemon does not start" >&2
        cat "$WORKDIR/daemon.log" >&2
        exit 1
    fi
    # the REST API in front of it (the tests that use curl)
    "$BIN/velarx-api" --config "$WORKDIR/config.toml" --no-start-engine --idle-exit 0 \
        --listen "unix://$SOCK" > "$WORKDIR/api.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/api.pid"
    e2e_wait_path "$SOCK"
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    main_env
    local d p
    "${SH[@]}" container rm -t 0 -f -i c1 c2 c3 c4 c6 nolimit > /dev/null 2>&1
    "${SH[@]}" pod rm -t 0 -f -i cpod lpod clipod iopod > /dev/null 2>&1
    [ ! -s "$WORKDIR/loop" ] || losetup -d "$(cat "$WORKDIR/loop")"
    kill "$DAEMON" 2> /dev/null
    # what a failed test left: the units of the daemons, the daemons and the monitors
    for d in "$WORKDIR"/u-*; do
        [ -f "$d/unit" ] || continue
        unit_env "${d##*/u-}"
        unit_cleanup
    done
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do
        kill -INT "$p" 2> /dev/null
    done
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR" "${SH[@]}"
    fi
    e2e_teardown_file
}

unit_start () { # MANAGER [DELEGATE]: a daemon in a unit; MANAGER scope*: --cgroups=scope, default*: none
    unit_env "$1"
    local mgr=$UMGR mode=split
    case $UMGR in
        scope*) mgr=cgroupfs mode=scope ;;
        default*) mgr=cgroupfs mode="" ;;
    esac
    mkdir -p "$WORKDIR/u-$UMGR"
    chmod 700 "$WORKDIR/u-$UMGR"
    cat > "$WORKDIR/u-$UMGR/config.toml" <<TOML
[engine]
socket = "$WORKDIR/u-$UMGR/api.sock"
[containers]
cgroups = "$mode"
[server]
cgroup_manager = "$mgr"
socket = "$WORKDIR/u-$UMGR/api.sock"
state_dir = "$WORKDIR/u-$UMGR/state"
root_dir = "$WORKDIR/u-$UMGR/data/root"
[storage]
root = "$WORKDIR/u-$UMGR/data/storage"
TOML
    # (the KillMode of the unit we ship, control-group, the default)
    "${SRUN[@]}" --quiet --unit="$UNIT" -p Delegate="${2:-yes}" -p Type=exec \
        -p ExecReload='/bin/kill -HUP $MAINPID' "${UENV[@]}" \
        "$BIN/velarx" --config "$WORKDIR/u-$UMGR/config.toml" varlink
    e2e_wait_path "$USOCK"
    UREL=$("${SCTL[@]}" show -P ControlGroup "$UNIT.service")
    UCG=/sys/fs/cgroup$UREL
    MAIN=$("${SCTL[@]}" show -P MainPID "$UNIT.service")
    [ "${2:-yes}" = yes ] || return 0
    check "$UMGR: the daemon is in <unit>/engine" "$UREL/engine" "$(cgroup_of "$MAIN")"
    check "$UMGR: no scope was made for it" inactive \
        "$("${SCTL[@]}" show -P ActiveState "velarx-$MAIN.scope" 2> /dev/null)"
    echo "$UREL" > "$WORKDIR/u-$UMGR/urel"
}

unit_containers () {
    unit_env "$1" need
    "${U[@]}" container run -d --name u1 --tls-verify=false --network none --memory 64m --pids-limit 40 \
        "$IMAGE" sleep inf > /dev/null
    check "$UMGR: a container runs in the daemon's unit" 0 $?
    pod=$("${U[@]}" pod create --name upod --network none --memory 128m)
    "${U[@]}" container run -d --name u2 --pod upod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    id1=$(ctr_id u1)
    id2=$(ctr_id u2)
    pid1=$("${U[@]}" container inspect u1 --format '{{.State.Pid}}')
    pid2=$("${U[@]}" container inspect u2 --format '{{.State.Pid}}')
    check "$UMGR: a container is <id>/container" "$UREL/$id1/container" "$(cgroup_of "$pid1")"
    check "$UMGR: a container of a pod is <pod>/<id>/container" "$UREL/$pod/$id2/container" "$(cgroup_of "$pid2")"
    check "$UMGR: the limits of the pod are on <pod>" 134217728 "$(cat "$UCG/$pod/memory.max")"
    mpid=$(cat "$WORKDIR/u-$UMGR/state/mon/${id1:0:12}/monitor.pid")
    check "$UMGR: its monitor is <id>/runtime" "$UREL/$id1/runtime" "$(cgroup_of "$mpid")"
    check "$UMGR: --memory is on <id>/container" 67108864 "$(cat "$UCG/$id1/container/memory.max")"
    check "$UMGR: --pids-limit is on <id>/container" 40 "$(cat "$UCG/$id1/container/pids.max")"
    check "$UMGR: the monitor has no limit" max "$(cat "$UCG/$id1/runtime/memory.max" 2> /dev/null || echo max)"
    "${U[@]}" stats --no-stream u1 > /dev/null 2>&1
    check "$UMGR: stats read <id>/container" 0 $?
    "${U[@]}" container run -d --name u4 --tls-verify=false --network none --cgroups=split "$IMAGE" sleep inf > /dev/null
    check "$UMGR: --cgroups=split is the mode the daemon has" 0 $?
    id4=$(ctr_id u4)
    check "$UMGR: it is <id>/container, the full digest" "$UREL/$id4/container" \
        "$(cgroup_of "$("${U[@]}" container inspect u4 --format '{{.State.Pid}}')")"
    check "$UMGR: the id is the 64 hex digits of the digest" 64 "${#id4}"
    check "$UMGR: the cgroups are not shared with another container" 1 \
        "$(find "$UCG" -maxdepth 1 -name "$id4" | wc -l)"
    "${U[@]}" container rm -t 0 -f u4 > /dev/null
    "${U[@]}" container run -d --name u3 --tls-verify=false --network none --cgroups=disabled "$IMAGE" sleep inf > /dev/null
    check "$UMGR: --cgroups=disabled makes no cgroup" no "$([ -e "$UCG/$(ctr_id u3)" ] && echo yes || echo no)"
    check "$UMGR: the container is in the daemon's cgroup" "$UREL/engine" \
        "$(cgroup_of "$("${U[@]}" container inspect u3 --format '{{.State.Pid}}')")"
    for v in pod id1 id2 pid1 pid2; do printf '%s\n' "${!v}" > "$WORKDIR/u-$UMGR/$v"; done
}

unit_reload () {
    unit_env "$1" need "pod id1 id2 pid1 pid2"
    # A reload executes the daemon again: the containers go on and are found again.
    "${SCTL[@]}" reload "$UNIT.service"
    # (the socket stays open: a request waits for the daemon that comes next)
    timeout 60 "${U[@]}" ps > /dev/null 2>&1
    check "$UMGR: after a reload the container runs" running "$("${U[@]}" container inspect u1 --format '{{.State.Status}}')"
    check "$UMGR: in the same cgroup" "$UREL/$id1/container" "$(cgroup_of "$pid1")"
    "${U[@]}" container stop -t 1 u1 > /dev/null 2>&1
    "${U[@]}" container start u1 > /dev/null
    check "$UMGR: a container started again runs" running "$("${U[@]}" container inspect u1 --format '{{.State.Status}}')"
    check "$UMGR: in <id>/container again" "$UREL/$id1/container" \
        "$(cgroup_of "$("${U[@]}" container inspect u1 --format '{{.State.Pid}}')")"
    check "$UMGR: with its new monitor in <id>/runtime" "$UREL/$id1/runtime" \
        "$(cgroup_of "$(cat "$WORKDIR/u-$UMGR/state/mon/${id1:0:12}/monitor.pid")")"
}

unit_restart () {
    unit_env "$1" need "pod id1 id2 pid1 pid2"
    # The containers are processes of the unit: `systemctl restart` stops them
    # (each monitor with the container's stop signal and timeout) and starts
    # the unit again, which an emptied cgroup allows (systemd starts a unit in
    # its own cgroup: containers left in it would make that fail, EBUSY).
    pid1=$("${U[@]}" container inspect u1 --format '{{.State.Pid}}')
    "${SCTL[@]}" restart "$UNIT.service"
    check "$UMGR: systemctl restart with live containers works" 0 $?
    check "$UMGR: the unit is active again" active "$("${SCTL[@]}" show -P ActiveState "$UNIT.service")"
    check "$UMGR: the container stopped with the unit" 1 "$(kill -0 "$pid1" 2> /dev/null; echo $?)"
    e2e_wait_path "$USOCK" 60
    timeout 60 "${U[@]}" ps > /dev/null 2>&1
    check "$UMGR: the daemon is in <unit>/engine again" "$UREL/engine" \
        "$(cgroup_of "$("${SCTL[@]}" show -P MainPID "$UNIT.service")")"
    local c
    for c in u1 u2 u3; do
        check "$UMGR: $c is recorded as exited" exited \
            "$("${U[@]}" container inspect $c --format '{{.State.Status}}')"
    done
    check "$UMGR: only the daemon is in the unit's cgroup" engine "$(cgdirs)"
    "${U[@]}" container start u1 > /dev/null
    check "$UMGR: a container starts again in <id>/container" "$UREL/$id1/container" \
        "$(cgroup_of "$("${U[@]}" container inspect u1 --format '{{.State.Pid}}')")"
    "${U[@]}" container rm -t 0 -f u1 u2 u3 > /dev/null
    "${U[@]}" pod rm -t 0 -f upod > /dev/null
    e2e_wait_gone "$UCG/$id1" 30 || true
}

unit_gone () {
    unit_env "$1" need
    check "$UMGR: the cgroups go with the containers and the pod" engine "$(cgdirs)"
    unit_cleanup
    e2e_remove_workdir "$WORKDIR/u-$UMGR" "${U[@]}" > /dev/null 2>&1
}

@test "the daemon is in the engine of a scope of its own" {
    main_env
    check "the daemon is in the engine of a scope of its own" "$DSCOPE/engine" "${dcg#"${dcg%/velarx-*}/"}"
    check "the scope is a unit with Delegate=yes" "active yes" \
        "$("${SCTL[@]}" show -P ActiveState "$DSCOPE") $("${SCTL[@]}" show -P Delegate "$DSCOPE")"
}

@test "a container is a scope of its own, with its monitor" {
    main_env
    "${SH[@]}" container run -d --name c1 --tls-verify=false --network none "$IMAGE" sleep inf > /dev/null
    check "a container runs" 0 $?
    id=$("${SH[@]}" container inspect c1 --format '{{.Id}}')
    pid1=$("${SH[@]}" container inspect c1 --format '{{.State.Pid}}')
    cg=$(cgroup_of "$pid1")
    check "it is <scope>/container" "velarx-$id.scope/container" "${cg#"${cg%/*/*}/"}"
    check "the scope is outside the daemon's cgroup" outside "$(case $cg in "$TREE"/*) echo inside ;; *) echo outside ;; esac)"
    check "the scope is a unit of the manager in its default slice" "active $SLICE" \
        "$("${SCTL[@]}" show -P ActiveState "velarx-$id.scope") $("${SCTL[@]}" show -P Slice "velarx-$id.scope")"
    mpid=$(cat "$WORKDIR/state/mon/${id:0:12}/monitor.pid")
    check "its monitor is <scope>/monitor" "${cg%/container}/monitor" "$(cgroup_of "$mpid")"
    check "inspect: CgroupManager" systemd "$(inspect c1 CgroupManager)"
    check "inspect: Cgroups" default "$(inspect c1 Cgroups)"
    "${SH[@]}" stats --no-stream c1 > /dev/null 2>&1
    check "stats read its cgroup" 0 $?
    echo "$id" > "$WORKDIR/id"
}

@test "a container with limits is a scope the runtime made" {
    main_env
    "${SH[@]}" container run -d --name c6 --tls-verify=false --network none --memory 64m --pids-limit 40 \
        "$IMAGE" sleep inf > /dev/null
    check "a container with limits runs" 0 $?
    id=$("${SH[@]}" container inspect c6 --format '{{.Id}}')
    cg=$(cg_of c6)
    check "it is velarx-<id>.scope" "velarx-$id.scope" "$(basename "$cg")"
    check "outside the daemon's cgroup" outside "$(case $cg in "$TREE"/*) echo inside ;; *) echo outside ;; esac)"
    check "--memory is the scope's" 67108864 "$("${SCTL[@]}" show -P MemoryMax "velarx-$id.scope")"
    check "--pids-limit is the scope's" 40 "$("${SCTL[@]}" show -P TasksMax "velarx-$id.scope")"
    mpid=$(cat "$WORKDIR/state/mon/${id:0:12}/monitor.pid")
    check "its monitor is a scope of its own" "velarx-monitor-$id.scope" "$(basename "$(cgroup_of "$mpid")")"
    check "inspect: CgroupManager" systemd "$(inspect c6 CgroupManager)"
    "${SH[@]}" stats --no-stream c6 > /dev/null 2>&1
    check "stats read its cgroup" 0 $?
    "${SH[@]}" container rm -t 0 -f c6 > /dev/null
}

@test "--cgroups=split needs a cgroup the daemon owns" {
    main_env
    # (this daemon owns the scope it made around itself: split is next to its engine)
    "${SH[@]}" container run -d --name c7 --tls-verify=false --network none --cgroups=split "$IMAGE" sleep inf > /dev/null
    check "--cgroups=split in the cgroup of the daemon's scope" 0 $?
    id=$("${SH[@]}" container inspect c7 --format '{{.Id}}')
    cg=$(cgroup_of "$("${SH[@]}" container inspect c7 --format '{{.State.Pid}}')")
    check "it is <root>/<id>/container" "$TREE/$id/container" "$cg"
    check "inspect: Cgroups is podman's default" default "$(inspect c7 Cgroups)"
    "${SH[@]}" container rm -t 0 -f c7 > /dev/null
    "${SH[@]}" pod create --cgroups=split --network none upod2 > /dev/null 2>&1
    check "pod create --cgroups=split" 0 $?
    "${SH[@]}" pod rm -t 0 -f upod2 > /dev/null 2>&1
    "${SH[@]}" container run --rm --tls-verify=false --network none --cgroups=disabled "$IMAGE" true > /dev/null 2>&1
    check "--cgroups=disabled touches nothing" 0 $?
    "${SH[@]}" container run --rm --tls-verify=false --network none --cgroups=slice "$IMAGE" true > /dev/null 2>&1
    check "an unknown mode is refused" 125 $?
    "${SH[@]}" container run --rm --tls-verify=false --network none --cgroups=unit "$IMAGE" true > /dev/null 2>&1
    check "unit is not a mode any more" 125 $?
}

@test "a container of a pod is a scope in the slice of the pod" {
    main_env
    "${SH[@]}" pod create --name cpod --network none > /dev/null
    "${SH[@]}" container run -d --name c3 --pod cpod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    id3=$("${SH[@]}" container inspect c3 --format '{{.Id}}')
    cg=$(cg_of c3)
    check "a container of a pod without limits is a scope in the default slice" \
        "$SLICE/velarx-$id3.scope" "$(basename "$(dirname "$cg")")/$(basename "$cg")"
    out=$("${SH[@]}" container run --rm --pod cpod --cgroups=split --tls-verify=false "$IMAGE" true 2>&1)
    check "a member cannot have another mode" 125 $?
    check_match "...and says why" "was made with --cgroups=scope" "$out"
    "${SH[@]}" pod rm -t 0 -f cpod > /dev/null
}

@test "the cgroups go with the container" {
    main_env
    id=$(cat "$WORKDIR/id" 2> /dev/null)
    [ -n "$id" ] || { echo "no container id: the test 'a container is a scope of its own' failed or did not run" >&2; exit 1; }
    scg=$("${SCTL[@]}" show -P ControlGroup "velarx-$id.scope")
    "${SH[@]}" container rm -t 0 -f c1 > /dev/null
    # (the monitor ends a moment after the container: the cgroup of the scope goes
    # with it, which is notified)
    if [ -n "$scg" ]; then e2e_wait_gone "/sys/fs/cgroup$scg" 30 || true; fi
    check "the scope goes with the container" inactive "$("${SCTL[@]}" show -P ActiveState "velarx-$id.scope")"
}

@test "--cgroup-parent names a slice" {
    main_env
    "${SH[@]}" container run -d --name c2 --tls-verify=false --network none --cgroup-parent velarx-test.slice \
        "$IMAGE" sleep inf > /dev/null
    check "--cgroup-parent names a slice" 0 $?
    cg=$(cg_of c2)
    check "the container is a scope of the manager in that slice" velarx-test.slice "$(basename "$(dirname "$cg")")"
    check "inspect: CgroupParent" velarx-test.slice "$(inspect c2 CgroupParent)"
    check "inspect: CgroupManager of the scope" systemd "$(inspect c2 CgroupManager)"
    "${SH[@]}" container rm -t 0 -f c2 > /dev/null
}

@test "a pod with limits has a slice of its own, the parent of its containers" {
    main_env
    check "api: a pod with limits" 201 \
        "$(api POST pods/create '{"name":"lpod","resource_limits":{"memory":{"limit":134217728},"cpu":{"quota":50000,"period":100000,"shares":512}}}')"
    pod=$(sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p' "$WORKDIR/api.out")
    slice=${SLICE%.slice}-velarx_pod_$pod.slice
    check "the slice of the pod is a unit of the manager" active "$("${SCTL[@]}" show -P ActiveState "$slice")"
    check "MemoryMax of the slice" 134217728 "$("${SCTL[@]}" show -P MemoryMax "$slice")"
    check "CPUQuotaPerSecUSec of the slice" 500ms "$("${SCTL[@]}" show -P CPUQuotaPerSecUSec "$slice")"
    "${SH[@]}" container run -d --name c4 --pod lpod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    check "a container of the pod runs" 0 $?
    cg=$(cg_of c4)
    check "the container is a scope in the slice of the pod" "$slice" "$(basename "$(dirname "$cg")")"
    check "update of the limits" 200 \
        "$(api POST pods/lpod/update '{"memory":{"limit":201326592,"swap":268435456}}')"
    check "MemoryMax after the update" 201326592 "$("${SCTL[@]}" show -P MemoryMax "$slice")"
    check "CPUQuotaPerSecUSec after the update (replaced, not merged)" infinity \
        "$("${SCTL[@]}" show -P CPUQuotaPerSecUSec "$slice")"
    check "update with what a pod cannot limit" 400 "$(api POST pods/lpod/update '{"pids":{"limit":10}}')"
    check "the limits cannot be below swap" 400 "$(api POST pods/lpod/update '{"memory":{"limit":200,"swap":100}}')"
    # the command line has podman's flags for the limits
    cpod=$("${SH[@]}" pod create --memory 100m --memory-swap 150m --cpus 0.5 --cpu-shares 256 clipod)
    cslice=${SLICE%.slice}-velarx_pod_$cpod.slice
    check "pod create --memory" 104857600 "$("${SCTL[@]}" show -P MemoryMax "$cslice")"
    check "pod create --memory-swap" 52428800 "$("${SCTL[@]}" show -P MemorySwapMax "$cslice")"
    check "pod update replaces the limits" "$cpod" "$("${SH[@]}" pod update --memory 200m clipod)"
    check "MemoryMax after pod update" 209715200 "$("${SCTL[@]}" show -P MemoryMax "$cslice")"
    "${SH[@]}" pod create --blkio-weight 100 iopod > /dev/null
    check "pod create --blkio-weight" 100 "$("${SCTL[@]}" show -P IOWeight "$("${SH[@]}" pod inspect -f '{{.Id}}' iopod | sed "s/^/${SLICE%.slice}-velarx_pod_/;s/$/.slice/")")"
    out=$("${SH[@]}" pod create --device-read-bps /dev/null:1mb nopod 2>&1)
    check "a device limit of what is no block device is refused" 125 $?
    check_match "...as podman does" "/dev/null: not a block device" "$out"
    "${SH[@]}" pod rm -t 0 -f iopod > /dev/null
    "${SH[@]}" pod rm -t 0 -f clipod > /dev/null
    check "the update of a pod that is not there" 404 "$(api POST pods/nopod/update '{}')"
    "${SH[@]}" pod rm -t 0 -f lpod > /dev/null
    check "the slice goes with the pod" inactive "$("${SCTL[@]}" show -P ActiveState "$slice")"
}

# A loop device in a mount namespace of the test (skipped as a user: the io
# controller is not delegated, and a loop device needs root).
@test "a pod has the block IO limits of podman's flags in its slice" {
    skip_unless_root
    main_env
    lofile=$WORKDIR/disk.img
    fallocate -l 1M "$lofile"
    loop=$(losetup --show -f "$lofile") || e2e_die "no loop device"
    # (detached by teardown_file, whatever this test does)
    echo "$loop" > "$WORKDIR/loop"
    lomajmin=$(losetup -l --noheadings --output MAJ:MIN "$loop" | tr -d ' ')
    pod=$("${SH[@]}" pod create --blkio-weight 50 --device-read-bps "$loop:1mb" \
        --device-write-bps "$loop:2mb" --blkio-weight-device "$loop:200" iopod)
    slice=${SLICE%.slice}-velarx_pod_$pod.slice
    check "IOWeight" 50 "$("${SCTL[@]}" show -P IOWeight "$slice")"
    check "IOReadBandwidthMax" "/dev/block/$lomajmin 1048576" "$("${SCTL[@]}" show -P IOReadBandwidthMax "$slice")"
    check "IOWriteBandwidthMax" "/dev/block/$lomajmin 2097152" "$("${SCTL[@]}" show -P IOWriteBandwidthMax "$slice")"
    check "IODeviceWeight" "/dev/block/$lomajmin 200" "$("${SCTL[@]}" show -P IODeviceWeight "$slice")"
    "${SH[@]}" container run -d --name ioc --pod iopod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    check "a container of the pod runs" 0 $?
    cgdir=/sys/fs/cgroup$(dirname "$(cg_of ioc)")
    check "io.max of the cgroup of the pod" "$lomajmin rbps=1048576 wbps=2097152 riops=max wiops=max" "$(cat "$cgdir/io.max")"
    # the update replaces them, none takes them away
    "${SH[@]}" pod update --device-read-bps "$loop:3mb" iopod > /dev/null
    check "io.max after the update" "$lomajmin rbps=3145728 wbps=max riops=max wiops=max" "$(cat "$cgdir/io.max")"
    check "IOWeight is gone" "[not set]" "$("${SCTL[@]}" show -P IOWeight "$slice")"
    "${SH[@]}" pod rm -t 0 -f iopod > /dev/null
    losetup -d "$loop" && rm "$WORKDIR/loop"
}

@test "a pod in a slice has a slice of its own" {
    main_env
    code=$(api POST pods/create '{"name":"spod","cgroup_parent":"velarx-test.slice","resource_limits":{"memory":{"limit":134217728},"cpu":{"quota":50000,"period":100000,"cpus":"0"}}}')
    [ "$code" = 201 ] || cat "$WORKDIR/api.out" >&2
    check "api: a pod with limits in a slice" 201 "$code"
    pod=$(sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p' "$WORKDIR/api.out")
    slice=velarx-test-velarx_pod_$pod.slice
    check "the slice of the pod is a unit of the manager" active "$("${SCTL[@]}" show -P ActiveState "$slice")"
    check "MemoryMax of the slice" 134217728 "$("${SCTL[@]}" show -P MemoryMax "$slice")"
    check "CPUQuotaPerSecUSec of the slice" 500ms "$("${SCTL[@]}" show -P CPUQuotaPerSecUSec "$slice")"
    "${SH[@]}" container run -d --name c5 --pod spod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    check "a container of the pod runs" 0 $?
    cg=$(cg_of c5)
    check "the container is a scope in the slice of the pod" "$slice" "$(basename "$(dirname "$cg")")"
    check "the slice of the pod is below the slice of the parent" velarx-test.slice \
        "$(basename "$(dirname "$(dirname "$cg")")")"
    check "update of the limits" 200 "$(api POST pods/spod/update '{"memory":{"limit":201326592}}')"
    check "MemoryMax of the slice after the update" 201326592 "$("${SCTL[@]}" show -P MemoryMax "$slice")"
    check "CPUQuotaPerSecUSec after the update (replaced)" infinity "$("${SCTL[@]}" show -P CPUQuotaPerSecUSec "$slice")"
    check "memory.max of the cgroup of the slice" 201326592 "$(cat "/sys/fs/cgroup$(dirname "$cg")/memory.max")"
    # the manager forgets the slice (it restarted, or the last container ended):
    # a member that starts alone finds it again with the limits of the pod
    api GET pods/spod/json > /dev/null
    infra=$(sed -n 's/.*"InfraContainerID":"\([0-9a-f]*\)".*/\1/p' "$WORKDIR/api.out")
    [ -n "$infra" ] || e2e_die "the pod has no infra container"
    "${SH[@]}" container stop -t 1 c5 "$infra" > /dev/null
    "${SCTL[@]}" stop "$slice"
    check "the slice is gone" inactive "$("${SCTL[@]}" show -P ActiveState "$slice")"
    "${SH[@]}" container start c5 > /dev/null
    check "a member started alone runs" 0 $?
    check "the slice is made again" active "$("${SCTL[@]}" show -P ActiveState "$slice")"
    check "with the limits of the pod" 201326592 "$("${SCTL[@]}" show -P MemoryMax "$slice")"
    "${SH[@]}" pod rm -t 0 -f spod > /dev/null
    check "the slice goes with the pod" inactive "$("${SCTL[@]}" show -P ActiveState "$slice")"
    # (a pod without limits has none: its containers are in the parent)
    "${SH[@]}" pod create --name npod --cgroup-parent velarx-test.slice --network none > /dev/null
    check "a pod without limits has no slice" 400 "$(api POST pods/npod/update '{"memory":{"limit":134217728}}')"
    "${SH[@]}" pod rm -t 0 -f npod > /dev/null
}

@test "a path is not a slice" {
    main_env
    out=$("${SH[@]}" container run --rm --tls-verify=false --network none --cgroup-parent /not/a/slice "$IMAGE" true 2>&1)
    case "$out" in *"takes a slice"*) out=refused ;; esac
    check "a path is not a slice" refused "$out"
}

@test "--cgroups=disabled makes no scope" {
    main_env
    out=$("${SH[@]}" container run --rm --tls-verify=false --network none --cgroups=disabled "$IMAGE" sh -c 'cat /proc/self/cgroup')
    case "$out" in *velarx-*.scope*) out=scope ;; *) out=none ;; esac
    check "--cgroups=disabled makes no scope" none "$out"
}

@test "the API refuses limits without cgroups" {
    main_env
    # a limit has no cgroup to be applied to: an error through the API too, and
    # the update of a container made without cgroups
    check "api: a memory limit with cgroups disabled is refused" 400 \
        "$(mk ',"resource_limits":{"memory":{"limit":67108864}}')"
    check_match "api: and says why" "cannot set --memory without cgroups" "$(cat "$WORKDIR/api.out")"
    check "api: a pids limit" 400 "$(mk ',"resource_limits":{"pids":{"limit":10}}')"
    check "api: a cpu share" 400 "$(mk ',"resource_limits":{"cpu":{"shares":100}}')"
    check "api: a weight device" 400 \
        "$(mk ',"resource_limits":{"blockIO":{"weightDevice":[{"major":8,"minor":0,"weight":100}]}}')"
    check "api: a device rule of the limits" 400 \
        "$(mk ',"resource_limits":{"devices":[{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"}]}')"
    check "api: a cgroup parent" 400 "$(mk ',"cgroup_parent":"x.slice"')"
    check "api: no limit is created" 201 "$(mk ',"name":"nolimit"')"
    check "api: update of such a container is refused" 409 \
        "$(api POST containers/nolimit/update '{"memory":{"limit":67108864}}')"
    check_match "api: and says why" "--cgroups=disabled" "$(cat "$WORKDIR/api.out")"
    "${SH[@]}" container rm -t 0 -f nolimit > /dev/null 2>&1
}

@test "the systemd manager's containers need no cgroup of the daemon" {
    main_env
    # (a scope of the manager is no cgroup the daemon makes for the monitor)
    check "the systemd manager's containers need no cgroup of the daemon" 0 \
        "$(grep -c 'No cgroup for the monitor' "$WORKDIR/daemon.log")"
}

@test "cgroupfs: a daemon in a unit with Delegate=yes owns its cgroup" {
    unit_start cgroupfs
}

@test "cgroupfs: containers in the daemon's unit" {
    unit_containers cgroupfs
}

@test "cgroupfs: a reload keeps the containers" {
    unit_reload cgroupfs
}

@test "cgroupfs: a restart stops the live containers and the unit starts again" {
    unit_restart cgroupfs
}

@test "cgroupfs: the cgroups go with the containers and the pod" {
    unit_gone cgroupfs
}

@test "systemd: a daemon in a unit with Delegate=yes owns its cgroup" {
    unit_start systemd
}

@test "systemd: containers in the daemon's unit" {
    unit_containers systemd
}

@test "systemd: a reload keeps the containers" {
    unit_reload systemd
}

@test "systemd: a restart stops the live containers and the unit starts again" {
    unit_restart systemd
}

@test "systemd: the cgroups go with the containers and the pod" {
    unit_gone systemd
}

is_outside () { # PID: whether the process is outside the unit's cgroup
    case $(cgroup_of "$1") in "$UREL"/*) echo inside ;; *) echo outside ;; esac
}

unit_scope_restart () {
    unit_env "$1" need
    # --cgroups=scope: the containers are not in the unit's
    # cgroup, and `systemctl restart` of the unit keeps them
    "${U[@]}" container run -d --name u1 --tls-verify=false --network none "$IMAGE" sleep inf > /dev/null
    check "$UMGR: a container runs" 0 $?
    "${U[@]}" container run -d --name u2 --tls-verify=false --network none --memory 64m "$IMAGE" sleep inf > /dev/null
    check "$UMGR: a container with limits runs" 0 $?
    "${U[@]}" pod create --name upod --network none --memory 128m > /dev/null
    "${U[@]}" container run -d --name u3 --pod upod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    check "$UMGR: a container of a pod with limits runs" 0 $?
    local c pid before
    for c in u1 u2 u3; do
        pid=$("${U[@]}" container inspect $c --format '{{.State.Pid}}')
        printf -v "pid_$c" %s "$pid"
        check "$UMGR: $c is outside the unit's cgroup" outside "$(is_outside "$pid")"
    done
    check "$UMGR: only the daemon is in the unit's cgroup" engine "$(cgdirs)"
    # an explicit --cgroups=split in a unit: below it
    out=$("${U[@]}" container run --rm --tls-verify=false --network none --cgroups=split "$IMAGE" true 2>&1)
    check "$UMGR: --cgroups=split runs in a unit" 0 $?
    # the cgroupfs manager takes a path as the cgroup parent, a slice is
    # refused in either mode (podman's error)
    out=$("${U[@]}" container run --rm --tls-verify=false --network none --cgroup-parent x.slice "$IMAGE" true 2>&1)
    check "$UMGR: cgroupfs: a slice parent is refused" 125 $?
    check_match "$UMGR: with podman's words" "systemd slice received as cgroup parent when using cgroupfs" "$out"
    out=$("${U[@]}" pod create --name xpod --network none --cgroup-parent x.slice 2>&1)
    check "$UMGR: cgroupfs: a pod's slice parent is refused" 125 $?
    "${SCTL[@]}" restart "$UNIT.service"
    check "$UMGR: systemctl restart with live containers works" 0 $?
    check "$UMGR: the unit is active again" active "$("${SCTL[@]}" show -P ActiveState "$UNIT.service")"
    e2e_wait_path "$USOCK" 60
    timeout 60 "${U[@]}" ps > /dev/null 2>&1
    check "$UMGR: the daemon is in <unit>/engine again" "$UREL/engine" \
        "$(cgroup_of "$("${SCTL[@]}" show -P MainPID "$UNIT.service")")"
    for c in u1 u2 u3; do
        before=pid_$c
        check "$UMGR: $c runs on, found again by the new daemon" "running ${!before}" \
            "$("${U[@]}" container inspect $c --format '{{.State.Status}} {{.State.Pid}}')"
    done
    "${U[@]}" container stop -t 1 u1 > /dev/null
    "${U[@]}" container start u1 > /dev/null
    check "$UMGR: a container started again keeps its mode" outside \
        "$(is_outside "$("${U[@]}" container inspect u1 --format '{{.State.Pid}}')")"
    "${U[@]}" container rm -t 0 -f u1 u2 u3 > /dev/null
    "${U[@]}" pod rm -t 0 -f upod > /dev/null
    unit_cleanup
    e2e_remove_workdir "$WORKDIR/u-$UMGR" "${U[@]}" > /dev/null 2>&1
}

@test "scope: a daemon in a unit with Delegate=yes owns its cgroup" {
    unit_start scope
}

@test "scope: systemctl restart of the unit keeps the live containers" {
    unit_scope_restart scope
}

unit_default () {
    unit_env "$1" need
    # no [containers] cgroups: split is the default
    local c pid
    # two containers at once, and a pod with a member
    "${U[@]}" container run -d --name u1 --tls-verify=false --network none "$IMAGE" sleep inf > /dev/null &
    local p1=$!
    "${U[@]}" container run -d --name u2 --tls-verify=false --network none --memory 64m "$IMAGE" sleep inf > /dev/null &
    local p2=$!
    wait $p1
    check "$UMGR: the first of two containers at once runs" 0 $?
    wait $p2
    check "$UMGR: the second of two containers at once runs" 0 $?
    pod=$("${U[@]}" pod create --name upod --network none --memory 128m)
    "${U[@]}" container run -d --name u3 --pod upod --tls-verify=false "$IMAGE" sleep inf > /dev/null
    check "$UMGR: a member of a pod runs" 0 $?
    id1=$(ctr_id u1); id2=$(ctr_id u2); id3=$(ctr_id u3)
    check "$UMGR: the first is <id>/container" "$UREL/$id1/container" \
        "$(cgroup_of "$("${U[@]}" container inspect u1 --format '{{.State.Pid}}')")"
    check "$UMGR: the second is <id>/container" "$UREL/$id2/container" \
        "$(cgroup_of "$("${U[@]}" container inspect u2 --format '{{.State.Pid}}')")"
    check "$UMGR: the member is <pod>/<id>/container" "$UREL/$pod/$id3/container" \
        "$(cgroup_of "$("${U[@]}" container inspect u3 --format '{{.State.Pid}}')")"
    check "$UMGR: the monitor of a member is <pod>/<id>/runtime" "$UREL/$pod/$id3/runtime" \
        "$(cgroup_of "$(cat "$WORKDIR/u-$UMGR/state/mon/${id3:0:12}/monitor.pid")")"
    check "$UMGR: --memory is on <id>/container" 67108864 "$(cat "$UCG/$id2/container/memory.max")"
    check "$UMGR: the infra container is in the pod too" 1 \
        "$(find "$UCG/$pod" -mindepth 2 -maxdepth 2 -name container | wc -l | awk '{ print ($1 >= 2) }')"
    for c in u1 u2 u3; do
        pid=$("${U[@]}" container inspect $c --format '{{.State.Pid}}')
        printf -v "pid_$c" %s "$pid"
    done
    # the daemon runs again while they run: nothing moves, it finds them by id
    "${SCTL[@]}" reload "$UNIT.service"
    timeout 60 "${U[@]}" ps > /dev/null 2>&1
    check "$UMGR: the daemon is in <unit>/engine still" "$UREL/engine" \
        "$(cgroup_of "$("${SCTL[@]}" show -P MainPID "$UNIT.service")")"
    for c in u1 u2 u3; do
        before=pid_$c
        check "$UMGR: $c runs on, found again" "running ${!before}" \
            "$("${U[@]}" container inspect $c --format '{{.State.Status}} {{.State.Pid}}')"
    done
    check "$UMGR: in the same cgroup" "$UREL/$id1/container" "$(cgroup_of "$pid_u1")"
    "${U[@]}" container rm -t 0 -f u1 u2 u3 > /dev/null
    "${U[@]}" pod rm -t 0 -f upod > /dev/null
    for d in $id1 $id2 $pod; do e2e_wait_gone "$UCG/$d" 30 || true; done
    check "$UMGR: the cgroups of the containers and the pod are gone" engine "$(cgdirs)"
    unit_cleanup
    e2e_remove_workdir "$WORKDIR/u-$UMGR" "${U[@]}" > /dev/null 2>&1
}

@test "default: a daemon in a unit with Delegate=yes splits its cgroup" {
    unit_start default
}

@test "default: split containers, a reload that keeps them, cleanup" {
    unit_default default
}

@test "rootless: a user unit without Delegate=yes is not the daemon's" {
    [ "$(id -u)" != 0 ] || skip "root: the mark of Delegate= is in the cgroup"
    unit_start scope-nodelegate no
    check "the daemon asked for a scope of its own" "velarx-$MAIN.scope" \
        "$(basename "$(dirname "$(cgroup_of "$MAIN")")")"
    # (the scope is a cgroup the daemon owns: it splits that one)
    local scg id
    scg=$(dirname "$(cgroup_of "$MAIN")")
    "${U[@]}" container run -d --name ns1 --tls-verify=false --network none --cgroups=split "$IMAGE" sleep inf > /dev/null
    check "--cgroups=split runs in the daemon's scope" 0 $?
    id=$(ctr_id ns1)
    check "the container is <scope>/<id>/container" "$scg/$id/container" \
        "$(cgroup_of "$("${U[@]}" container inspect ns1 --format '{{.State.Pid}}')")"
    "${U[@]}" container rm -t 0 -f ns1 > /dev/null
    unit_cleanup
    kill "$MAIN" 2> /dev/null
    e2e_remove_workdir "$WORKDIR/u-$UMGR" "${U[@]}" > /dev/null 2>&1
}

@test "no cgroup of its own and no manager: the daemon does not start" {
    init_arrays
    # A cgroup the daemon does not own (the one of this script is shared) and no
    # manager that makes a scope: with `cgroup_manager = "systemd"` an error that
    # names the cause, not a silent fallback.
    mkdir -p "$WORKDIR/n/run"
    chmod 700 "$WORKDIR/n/run"
    cat > "$WORKDIR/n/config.toml" <<TOML
[engine]
socket = "$WORKDIR/n/api.sock"
[server]
cgroup_manager = "systemd"
socket = "$WORKDIR/n/api.sock"
state_dir = "$WORKDIR/n/state"
root_dir = "$WORKDIR/n/data/root"
[storage]
root = "$WORKDIR/n/data/storage"
TOML
    if [ "$(id -u)" = 0 ]; then
        NOMGR=(unshare -m sh -c 'mount -t tmpfs tmpfs /run/systemd && exec "$@"' sh)
    else
        NOMGR=(env XDG_RUNTIME_DIR="$WORKDIR/n/run")
    fi
    out=$(timeout 30 "${NOMGR[@]}" "$BIN/velarx" --config "$WORKDIR/n/config.toml" varlink 2>&1)
    rc=$?
    check "no cgroup of its own and no manager: the daemon does not start" fails "$([ $rc -ne 0 ] && echo fails || echo "ran: $rc")"
    case "$out" in *"does not own"*"manager does not make it a scope"*) out=named ;; esac
    check "and says why" named "$out"
    check "(the cgroup_manager is named)" 1 "$(printf '%s' "$(timeout 30 "${NOMGR[@]}" "$BIN/velarx" --config "$WORKDIR/n/config.toml" varlink 2>&1)" | grep -c 'cgroup_manager = "systemd"')"
}

@test "the daemon did not panic" {
    init_arrays
    if grep -q "panicked" "$WORKDIR/daemon.log"; then
        echo "FAIL the daemon panicked" >&2
        exit 1
    fi
}
