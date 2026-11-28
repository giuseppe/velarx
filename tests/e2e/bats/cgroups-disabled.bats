# SPDX-License-Identifier: Apache-2.0
# `--cgroups=disabled` makes no cgroup at all: the payload, its monitor and
# every other process of the container stay in the cgroup of the process that
# started them, no cgroup is made (no mkdir below /sys/fs/cgroup, no scope
# asked of a manager) and the OCI runtime is told as well (crun's
# --cgroup-manager disabled).  Checked for a command (strace of `run`, then
# create + start, restart, exec, a pod) and for the engine service in both of
# its cgroup managers.  Also: `start`, `restart` and `exec` do not connect
# to the manager; `[containers] cgroups = "disabled"` of config.toml is
# the default of run, create and pod create (the infra); `pod
# create --cgroups=disabled`; the holder of the rootless network namespace
# that a disabled container starts stays in the caller's cgroup.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/cgroups-disabled.bats   # as root, or as a user
#
# The image is made here from the shell and a few tools of the host (the
# files of an image that are all root's map in a user namespace of one id,
# which is what strace needs: it cannot follow newuidmap).  Skipped without
# crun, strace or systemd.  Run it as root only in a mount namespace of its
# own (the e2e scripts mount things).

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
    SH=("$BIN/velarx" --config "$WORKDIR/config.toml")
    if [ "$(id -u)" = 0 ]; then
        SCTL=(systemctl)
        SRUN=(systemd-run)
    else
        SCTL=(env XDG_RUNTIME_DIR="/run/user/$(id -u)" systemctl --user)
        SRUN=(env XDG_RUNTIME_DIR="/run/user/$(id -u)" systemd-run --user)
    fi
}
cgroup_of () { sed -n 's/^0:://p' "/proc/$1/cgroup" 2> /dev/null; }
# The number of cgroups below $1 (cgroup.stat): none is made
descendants () { sed -n 's/^nr_descendants //p' "/sys/fs/cgroup$1/cgroup.stat" 2> /dev/null; }
# State.Pid and State.ConmonPid of a container
pids () { # CLI... name
    local n=${!#}
    "${@:1:$#-1}" container inspect --format '{{.State.Pid}} {{.State.ConmonPid}}' "$n"
}
in_cgroup () { # what cgroup CLI... name
    local what=$1 want=$2
    shift 2
    local p m
    read -r p m <<< "$(pids "$@")"
    check "$what: the payload" "$want" "$(cgroup_of "${p:-0}")"
    check "$what: and its monitor" "$want" "$(cgroup_of "${m:-0}")"
}
# traced FILE CMD...: run CMD under strace -f (into FILE), its exit code.
# strace attaches to it (-p) and is interrupted once CMD returned: it
# detaches from what CMD leaves running (a monitor, a container, the holder
# of a network namespace), which a strace that started CMD would kill.  A
# container of the store keeps the user namespace of the rootless user
# alive: the traced command joins it (it cannot run newuidmap, a setuid
# program, to make a new one)
traced () {
    local f=$1 cp sp i
    shift
    if [ "$(id -u)" != 0 ] && [ "$("${SH[@]}" container inspect --format '{{.State.Status}}' keeper 2> /dev/null)" != running ]; then
        "${SH[@]}" rm -t 0 -f keeper > /dev/null 2>&1
        "${SH[@]}" run -d --name keeper --network none --cgroups=disabled "$IMAGE" sleep 1000 > /dev/null
    fi
    rm -f "$f" "$f.err"
    sh -c 'kill -STOP $$; exec "$@" > "$0.out" 2>&1' "$f" "$@" &
    cp=$!
    # (a poll: the stop of a process is not notified to a shell that is not its parent
    # in a way a file can be waited on)
    for i in $(seq 100); do grep -q '^State:.*T' "/proc/$cp/status" 2> /dev/null && break; sleep 0.05; done
    strace -f -o "$f" -e trace=execve,mkdir,mkdirat,openat,connect -p "$cp" 2> "$f.err" &
    sp=$!
    e2e_wait_line "$f.err" attached 10
    kill -CONT "$cp"
    wait "$cp"
    echo $?
    kill -INT "$sp" 2> /dev/null
    wait "$sp" 2> /dev/null
}
# untouched WHAT FILE: the strace of FILE made no cgroup, wrote none and did
# not connect to a manager
untouched () {
    # (a strace that could not attach, ptrace_scope 1 or more, traced nothing)
    check_match "$1: the command was traced" 'execve\(' "$(grep -m1 'execve(' "$2")"
    check "$1: no directory made in the cgroup tree" 0 \
        "$(grep -c 'mkdir[a-z]*(.*/sys/fs/cgroup' "$2")"
    check "$1: no cgroup file created or written" 0 \
        "$(grep -Ec '"/sys/fs/cgroup[^"]*", O_(WRONLY|RDWR|CREAT)' "$2")"
    check "$1: no connection to a manager or a bus" 0 \
        "$(grep -Ec 'connect\(.*(systemd/private|/bus"|system_bus_socket)' "$2")"
    check "$1: no systemd-run" 0 "$(grep -c 'execve("[^"]*systemd-run"' "$2")"
}
# the configuration of the store with `[containers] cgroups = MODE`
cgroups_conf () { # mode
    { cat "$WORKDIR/config.toml"; printf '[containers]\ncgroups = "%s"\n' "$1"; } > "$WORKDIR/cg-$1.toml"
    echo "$WORKDIR/cg-$1.toml"
}
daemon_case () { # manager
    local m=$1 d=$WORKDIR/$1 unit= pid
    mkdir -p "$d"
    chmod 700 "$d"
    cat > "$d/config.toml" <<TOML
$(e2e_bridge_toml)
[engine]
socket = "$d/api.sock"
[server]
socket = "$d/api.sock"
state_dir = "$d/state"
root_dir = "$d/data/root"
cgroup_manager = "$m"
[storage]
root = "$d/data/storage"
TOML
    local S=("$BIN/velarx" --config "$d/config.toml" --socket "$d/api.sock")
    if [ "$m" = cgroupfs ]; then
        # a unit that owns its cgroup
        unit=velarx-e2e-cgd-$$
        local env=(--setenv=HOME="$HOME" --setenv=VELARX_REGISTRIES_CONF="${VELARX_REGISTRIES_CONF:-/dev/null}")
        [ "$(id -u)" = 0 ] || env+=(--setenv=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR")
        "${SRUN[@]}" --quiet --unit="$unit" -p Delegate=yes -p KillMode=process -p Type=exec \
            "${env[@]}" "${S[@]:0:3}" varlink
        pid=$("${SCTL[@]}" show -P MainPID "$unit.service")
    else
        "${S[@]}" varlink > "$d/daemon.log" 2>&1 3>&- &
        pid=$!
    fi
    local i
    e2e_wait_path "$d/api.sock"
    "${S[@]}" image import "$WORKDIR/img.tar" "$IMAGE" > /dev/null
    local dcg tree
    dcg=$(cgroup_of "$pid")
    # (the cgroup the daemon owns: it sits in `monitor` of it)
    tree=$(dirname "$dcg")
    local n=$(descendants "$tree")
    "${S[@]}" run -d --name s1 --network none --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    in_cgroup "$m: run -d, in the daemon's cgroup" "$dcg" "${S[@]}" s1
    "${S[@]}" restart -t 0 s1 > /dev/null
    in_cgroup "$m: restart" "$dcg" "${S[@]}" s1
    "${S[@]}" stop -t 0 s1 > /dev/null
    "${S[@]}" start s1 > /dev/null
    in_cgroup "$m: stop and start" "$dcg" "${S[@]}" s1
    check "$m: exec" "0::/" "$("${S[@]}" exec s1 cat /proc/self/cgroup)"
    "${S[@]}" create --name s2 --network none --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    "${S[@]}" start s2 > /dev/null
    in_cgroup "$m: create + start" "$dcg" "${S[@]}" s2
    check "$m: no cgroup made for them" "$n" "$(descendants "$tree")"
    # a pod with a parent: its member that has no cgroup does not take it
    "${S[@]}" pod create --name sp --cgroup-parent "$( [ "$m" = systemd ] && echo velarx-cgd.slice || echo "$tree")" > /dev/null
    "${S[@]}" run -d --name s3 --pod sp --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    check "$m: a member of a pod with a parent runs" running \
        "$("${S[@]}" container inspect --format '{{.State.Status}}' s3)"
    in_cgroup "$m: and is in the daemon's cgroup" "$dcg" "${S[@]}" s3
    "${S[@]}" rm -t 0 -f s1 s2 s3 > /dev/null 2>&1
    "${S[@]}" pod rm -t 0 -f sp > /dev/null 2>&1
    if [ -n "$unit" ]; then
        "${SCTL[@]}" stop "$unit.service" > /dev/null 2>&1
    else
        kill "$pid" 2> /dev/null
        wait "$pid" 2> /dev/null
    fi
    e2e_remove_workdir "$d" "${S[@]}" > /dev/null 2>&1
}

setup_file () {
    local tool rc=0
    for tool in crun strace; do
        command -v "$tool" > /dev/null || skip "no $tool"
    done
    e2e_setup_file
    e2e_system_bin
    init_arrays
    "${SCTL[@]}" is-system-running > /dev/null 2>&1 || rc=$?
    case $rc in 0|1) ;; *) skip "no systemd manager" ;; esac

    mkdir -p "$HOME/.config/velarx" "$XDG_DATA_HOME"
    chmod 700 "$XDG_RUNTIME_DIR"
    if [ "$(id -u)" != 0 ]; then
        # the private socket of the user's manager, which systemd-run --scope asks
        ln -s "/run/user/$(id -u)/systemd" "$XDG_RUNTIME_DIR/systemd"
        export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus
    fi
    # (everything in the work directory: as root the defaults are the system's)
    cat > "$WORKDIR/config.toml" <<TOML
$(e2e_bridge_toml)
[engine]
socket = "$WORKDIR/none.sock"
[server]
socket = "$WORKDIR/none.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/data/root"
[storage]
root = "$WORKDIR/data/storage"
TOML

    # The image: bash, cat, sleep and ls with the libraries they need, all root's.
    IMG=$WORKDIR/img
    mkdir -p "$IMG/usr/bin" "$IMG/proc" "$IMG/dev" "$IMG/tmp"
    ln -s usr/bin "$IMG/bin"
    for f in /usr/bin/bash /usr/bin/cat /usr/bin/sleep /usr/bin/ls; do
        for l in $f $(ldd $f | awk '/=>/ { print $3 } /^[ \t]*\// { print $1 }'); do
            mkdir -p "$IMG$(dirname "$l")"
            cp -L "$l" "$IMG$(dirname "$l")/"
        done
    done
    tar --owner=0 --group=0 --numeric-owner -C "$IMG" -cf "$WORKDIR/img.tar" .
    export IMAGE=localhost/cgd:1
    "${SH[@]}" image import "$WORKDIR/img.tar" "$IMAGE" > /dev/null || { echo "cannot import the image"; exit 1; }

    export OWN
    OWN=$(cgroup_of self)
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    init_arrays
    local d p u
    "${SH[@]}" rm -t 0 -f -a > /dev/null 2>&1
    "${SH[@]}" pod rm -t 0 -f -a > /dev/null 2>&1
    for d in systemd cgroupfs; do
        if [ -S "$WORKDIR/$d/api.sock" ]; then
            "$BIN/velarx" --config "$WORKDIR/$d/config.toml" --socket "$WORKDIR/$d/api.sock" rm -t 0 -f -a > /dev/null 2>&1
            "$BIN/velarx" --config "$WORKDIR/$d/config.toml" --socket "$WORKDIR/$d/api.sock" pod rm -t 0 -f -a > /dev/null 2>&1
        fi
    done
    # what a failed test left: the units of the daemons, the daemons and the monitors
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do
        u=$(sed -n 's/^0:://p' "/proc/$p/cgroup" 2> /dev/null | grep -o 'velarx-e2e-cgd-[0-9]*\.service' | head -1)
        [ -z "$u" ] || "${SCTL[@]}" stop "$u" > /dev/null 2>&1
        kill -INT "$p" 2> /dev/null
    done
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR" "${SH[@]}"
    fi
    e2e_teardown_file
}

# The calls of the runtime under strace FILE, but its `features` (which the
# engine reads for the options the runtime has)
runtime_calls () { grep 'execve("[^"]*crun"' "$1" | grep -v '"features"\]'; }

@test "run: no cgroup, no manager, the runtime told" {
    init_arrays
    rm -f "$WORKDIR"/st-*
    # (strace cannot follow newuidmap, whose failure is an error: as a
    # rootless user, the traced command joins the namespaces a container
    # that runs holds)
    if [ "$(id -u)" != 0 ]; then
        "${SH[@]}" run -d --name holder --network none --cgroups=disabled "$IMAGE" sleep 1000 > /dev/null
    fi
    out=$(strace -f -o "$WORKDIR/st-run" -e trace=execve,mkdir,mkdirat,openat,connect \
        "${SH[@]}" run --rm --network none --cgroups=disabled "$IMAGE" ls / 2> /dev/null)
    check_match "run: it ran" "usr" "$out"
    check "run: no directory made in the cgroup tree" 0 \
        "$(grep -c 'mkdir[a-z]*(.*/sys/fs/cgroup' "$WORKDIR/st-run")"
    check "run: no cgroup file created or written" 0 \
        "$(grep -Ec '"/sys/fs/cgroup[^"]*", O_(WRONLY|RDWR|CREAT)' "$WORKDIR/st-run")"
    check "run: no connection to a manager" 0 \
        "$(grep -Ec 'connect\(.*(systemd/private|/bus"|system_bus_socket)' "$WORKDIR/st-run")"
    check "run: no systemd-run" 0 "$(grep -c 'execve("[^"]*systemd-run"' "$WORKDIR/st-run")"
    ncrun=$(runtime_calls "$WORKDIR/st-run" | grep -c .)
    check "run: every call of the runtime says --cgroup-manager disabled" "$ncrun" \
        "$(runtime_calls "$WORKDIR/st-run" | grep -c '"--cgroup-manager", "disabled"')"
    check_match "run: and there were calls" '^[3-9]' "$ncrun"
    "${SH[@]}" rm -t 0 -f holder > /dev/null 2>&1 || true
}

@test "an implicit pull makes no scope for its workers" {
    init_arrays
    # an implicit pull: its workers get no scope either (the container itself
    # may fail to start here: strace cannot follow newuidmap)
    REGISTRY=$E2E_REGISTRY
    curl -s --max-time 2 "http://$REGISTRY/v2/" > /dev/null || skip "no registry at $REGISTRY"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$REGISTRY" > "$HOME/.config/velarx/registries.conf"
    export VELARX_REGISTRIES_CONF=$HOME/.config/velarx/registries.conf
    strace -f -o "$WORKDIR/st-pull" -e trace=execve,mkdir,mkdirat,connect \
        "${SH[@]}" run --rm --network none --cgroups=disabled "$REGISTRY/alpine:chunked" true > /dev/null 2>&1
    check_match "pull: the image came" "." "$("${SH[@]}" image list --format '{{.Repository}}' 2>&1)"
    check "pull: no systemd-run for the workers" 0 "$(grep -c 'execve("[^"]*systemd-run"' "$WORKDIR/st-pull")"
    check "pull: no directory made in the cgroup tree" 0 "$(grep -c 'mkdir[a-z]*(.*/sys/fs/cgroup' "$WORKDIR/st-pull")"
    check "pull: no connection to a manager" 0 \
        "$(grep -Ec 'connect\(.*(systemd/private|/bus"|system_bus_socket)' "$WORKDIR/st-pull")"
}

@test "the bundle names no cgroup" {
    init_arrays
    # the runtime's configuration names no cgroup
    "${SH[@]}" create --name d0 --network none --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    id0=$("${SH[@]}" container inspect --format '{{.Id}}' d0)
    spec=$(find "$WORKDIR" -path "*/bundles/$id0/config.json" | head -1)
    check "the bundle: no cgroupsPath, no resources" "None None" \
        "$(python3 -I -c 'import json, sys; l = json.load(open(sys.argv[1]))["linux"]; print(l.get("cgroupsPath"), l.get("resources"))' "$spec")"
}

@test "create + start, restart and exec stay in the cgroup of the caller" {
    init_arrays
    # (the mode is known before anything asks the manager: start, restart
    # and exec do not even connect to it)
    check "start" 0 "$(traced "$WORKDIR/st-start" "${SH[@]}" start d0)"
    untouched "start" "$WORKDIR/st-start"
    in_cgroup "create + start" "$OWN" "${SH[@]}" d0
    check "restart" 0 "$(traced "$WORKDIR/st-restart" "${SH[@]}" restart -t 0 d0)"
    untouched "restart" "$WORKDIR/st-restart"
    in_cgroup "restart" "$OWN" "${SH[@]}" d0
    # (inside its cgroup namespace a process of the container's cgroup is `/`)
    check "exec: in the container's cgroup" "0::/" "$("${SH[@]}" exec d0 cat /proc/self/cgroup)"
    check "exec" 0 "$(traced "$WORKDIR/st-exec" "${SH[@]}" exec d0 ls /)"
    untouched "exec" "$WORKDIR/st-exec"
    ncrun=$(runtime_calls "$WORKDIR/st-restart" | grep -c .)
    check "restart: every call of the runtime says --cgroup-manager disabled" "$ncrun" \
        "$(runtime_calls "$WORKDIR/st-restart" | grep -c '"--cgroup-manager", "disabled"')"
}

@test "config.toml: cgroups = disabled is the default of run and create" {
    init_arrays
    local conf
    conf=$(cgroups_conf disabled)
    check "run" 0 "$(traced "$WORKDIR/st-conf" \
        "${SH[@]}" --config "$conf" run --rm --network none "$IMAGE" ls /)"
    untouched "run with the default of the configuration" "$WORKDIR/st-conf"
    "${SH[@]}" --config "$conf" run -d --name c1 --network none "$IMAGE" sleep 100 > /dev/null
    in_cgroup "run -d with the default of the configuration" "$OWN" "${SH[@]}" c1
    check "inspect says disabled" disabled \
        "$("${SH[@]}" container inspect --format '{{.HostConfig.Cgroups}}' c1)"
    "${SH[@]}" --config "$conf" create --name c2 --network none "$IMAGE" sleep 100 > /dev/null
    check "create too" disabled \
        "$("${SH[@]}" container inspect --format '{{.HostConfig.Cgroups}}' c2)"
    # a limit with that default is an error, as with the flag
    rc=0
    out=$("${SH[@]}" --config "$conf" run --rm --network none --memory 64m "$IMAGE" true 2>&1) || rc=$?
    check "a limit with the default: exit 125" 125 "$rc"
    check_match "and says why" "without cgroups" "$out"
    # the flag wins over the file
    "${SH[@]}" --config "$conf" create --name c3 --network none --cgroups=enabled "$IMAGE" sleep 100 > /dev/null
    check "--cgroups=enabled wins" default \
        "$("${SH[@]}" container inspect --format '{{.HostConfig.Cgroups}}' c3)"
    # a value podman does not have is an error of the file
    rc=0
    out=$("${SH[@]}" --config "$(cgroups_conf off)" run --rm --network none "$IMAGE" true 2>&1) || rc=$?
    check_match "a bad value is refused" 'cgroups = "off": one of enabled, scope, disabled, no-conmon, split' "$out"
    "${SH[@]}" rm -t 0 -f c1 c2 c3 > /dev/null 2>&1
}

@test "pod create --cgroups=disabled: the pod, its infra and its members make no cgroup" {
    init_arrays
    # (no network: as root the default bridge asks firewalld on the system
    # bus, which has nothing to do with cgroups)
    "${SH[@]}" pod create --name pd --network none --cgroups=disabled > /dev/null
    # the member's run starts the infra container: neither makes anything
    check "a member" 0 "$(traced "$WORKDIR/st-pod" "${SH[@]}" run -d --name p1 --pod pd "$IMAGE" sleep 100)"
    untouched "a member that starts the infra" "$WORKDIR/st-pod"
    in_cgroup "the member, disabled with its pod" "$OWN" "${SH[@]}" p1
    pdinfra=$("${SH[@]}" pod inspect --format '{{.InfraContainerID}}' pd)
    in_cgroup "the infra container" "$OWN" "${SH[@]}" "$pdinfra"
    check "the infra is disabled" disabled \
        "$("${SH[@]}" container inspect --format '{{.HostConfig.Cgroups}}' "$pdinfra")"
    rc=0
    out=$("${SH[@]}" run --rm --pod pd --cgroups=enabled "$IMAGE" true 2>&1) || rc=$?
    check "a member that asks for a cgroup: exit 125" 125 "$rc"
    check_match "and says why" "made with --cgroups=disabled" "$out"
    # a limit of a member: refused before anything asks the manager
    check "a member with a limit: exit 125" 125 \
        "$(traced "$WORKDIR/st-podlim" "${SH[@]}" run --rm --pod pd --memory 64m "$IMAGE" true)"
    untouched "a member with a limit" "$WORKDIR/st-podlim"
    check_match "and says why" "without cgroups" "$(cat "$WORKDIR/st-podlim.out")"
    # the configuration's mode is a default: the pod's wins
    "${SH[@]}" --config "$(cgroups_conf no-conmon)" run -d --name p2 --pod pd "$IMAGE" sleep 100 > /dev/null
    check "a member with the configuration's no-conmon" disabled \
        "$("${SH[@]}" container inspect --format '{{.HostConfig.Cgroups}}' p2)"
    "${SH[@]}" rm -t 0 -f p2 > /dev/null
    # the pod has no cgroup to limit
    check "pod update with a limit: exit 125" 125 \
        "$(traced "$WORKDIR/st-podupd" "${SH[@]}" pod update --memory 64m pd)"
    untouched "pod update" "$WORKDIR/st-podupd"
    check_match "and says why" "without cgroups" "$(cat "$WORKDIR/st-podupd.out")"
    "${SH[@]}" pod stop -t 0 pd > /dev/null
    check "pod start" 0 "$(traced "$WORKDIR/st-podstart" "${SH[@]}" pod start pd)"
    untouched "pod start" "$WORKDIR/st-podstart"
    in_cgroup "the member after pod start" "$OWN" "${SH[@]}" p1
    "${SH[@]}" pod rm -t 0 -f pd > /dev/null
    for bad in "--cgroup-parent /x" "--memory 64m"; do
        rc=0
        # shellcheck disable=SC2086
        out=$("${SH[@]}" pod create --name pbad --cgroups=disabled $bad 2>&1) || rc=$?
        check "pod create --cgroups=disabled $bad: exit 125" 125 "$rc"
        check_match "and says why" "cgroup parent|without cgroups" "$out"
    done
    # split is a command's in a unit, not a pod's (podman has no such flag)
    rc=0
    "${SH[@]}" pod create --name pbad --cgroups=split > /dev/null 2>&1 || rc=$?
    check "pod create --cgroups=split: exit 125" 125 "$rc"
}

@test "config.toml: a pod made with cgroups = disabled" {
    init_arrays
    local conf
    conf=$(cgroups_conf disabled)
    "${SH[@]}" --config "$conf" pod create --name pc --network none > /dev/null
    # (the pod keeps its mode: the member's command has the default
    # configuration)
    check "a member" 0 "$(traced "$WORKDIR/st-podc" "${SH[@]}" run -d --name q1 --pod pc "$IMAGE" sleep 100)"
    untouched "a member of a pod made with the default" "$WORKDIR/st-podc"
    in_cgroup "the member" "$OWN" "${SH[@]}" q1
    in_cgroup "the infra container" "$OWN" "${SH[@]}" "$("${SH[@]}" pod inspect --format '{{.InfraContainerID}}' pc)"
    "${SH[@]}" pod rm -t 0 -f pc > /dev/null
    # the RUN containers of a build do not take it (buildah does not): a
    # limit of the build is not refused
    mkdir -p "$WORKDIR/bctx"
    printf 'FROM %s\nRUN ["ls", "/"]\n' "$IMAGE" > "$WORKDIR/bctx/Containerfile"
    rc=0
    out=$("${SH[@]}" --config "$conf" build --memory 64m -t localhost/cgdb:1 \
        "$WORKDIR/bctx" 2>&1) || rc=$?
    check "build with a limit and that default: $out" 0 "$rc"
    "${SH[@]}" rmi localhost/cgdb:1 > /dev/null 2>&1
}

@test "the holder of the rootless network namespace started for a disabled container" {
    init_arrays
    [ "$(id -u)" != 0 ] || skip "root has no rootless network namespace"
    command -v pasta > /dev/null || skip "no pasta"
    skip_unless_bridges
    check "network create" 0 "$("${SH[@]}" network create cgdnet > /dev/null 2>&1; echo $?)"
    local h
    # the holder of the rootless network namespace, as the namespaces tables
    # of the store have it
    holder_pid () {
        python3 -I - "$WORKDIR/data/storage/db.sqlite" << 'EOT'
import os, sqlite3, sys
if os.path.exists(sys.argv[1]):
    for row in sqlite3.connect(sys.argv[1]).execute("select pid from holders where scope = 'rootless-netns' and role = 'netns'"):
        print(*row)
EOT
    }
    # (as podman, `network create` makes no namespace: no container would
    # be there to release it, and its holder would stay for good)
    check "network create starts no holder" "" "$(holder_pid)"
    check "run" 0 "$(traced "$WORKDIR/st-net" "${SH[@]}" run --rm --network cgdnet --cgroups=disabled "$IMAGE" ls /)"
    untouched "a disabled container that starts the holder" "$WORKDIR/st-net"
    check_match "the holder was started" "netns-holder" "$(grep 'execve(' "$WORKDIR/st-net")"
    "${SH[@]}" run -d --name n1 --network cgdnet --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    h=$(holder_pid)
    check "the holder is in the caller's cgroup" "$OWN" "$(cgroup_of "${h:-0}")"
    in_cgroup "the container on the network" "$OWN" "${SH[@]}" n1
    "${SH[@]}" rm -t 0 -f n1 > /dev/null 2>&1
    "${SH[@]}" network rm cgdnet > /dev/null 2>&1
}

@test "run -d, a pod member and pause" {
    init_arrays
    "${SH[@]}" run -d --name d1 --network none --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    in_cgroup "run -d" "$OWN" "${SH[@]}" d1
    "${SH[@]}" pod create --name dp > /dev/null
    "${SH[@]}" run -d --name d2 --pod dp --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    in_cgroup "a member of a pod" "$OWN" "${SH[@]}" d2
    out=$("${SH[@]}" pause d1 2>&1)
    check_match "pause: there is no cgroup to freeze" "no cgroup of its own" "$out"
    "${SH[@]}" rm -t 0 -f -a > /dev/null 2>&1
    "${SH[@]}" pod rm -t 0 -f dp > /dev/null 2>&1
}

@test "the engine service with the systemd manager" {
    init_arrays
    daemon_case systemd
}

@test "the engine service with the cgroupfs manager" {
    init_arrays
    daemon_case cgroupfs
}
