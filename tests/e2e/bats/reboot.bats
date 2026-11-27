# SPDX-License-Identifier: Apache-2.0
# Containers, volumes and pods across a reboot, simulated: every
# process of the store is killed (the daemon, the monitors, the containers,
# the helpers: with them go the rootless namespaces), the state directory is emptied as
# a boot empties a tmpfs, and the daemon starts again.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/reboot.bats        # as root, or as a user
#
# IMAGE is any image with a shell (default localhost:5000/alpine:chunked).
# Everything is in $WORKDIR; the transient unit is stopped and reset.

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

vars () {
    STATE=$WORKDIR/state
    if [ "$(id -u)" = 0 ]; then
        SCTL=(systemctl)
        SRUN=(systemd-run)
    else
        SCTL=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemctl --user)
        SRUN=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemd-run --user)
    fi
    SH=("$BIN/velarx" --config "$WORKDIR/config.toml")
    RUN=(container run --tls-verify=false --network none)
    ENVP=(-p Environment=HOME="$HOME" -p Environment=XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR"
          -p Environment=VELARX_REGISTRIES_CONF="$VELARX_REGISTRIES_CONF")
}

setup () { set +e; [ -z "${WORKDIR:-}" ] || vars; }

skip_unless_manager () { [ "$(id -u)" = 0 ] || skip_unless_systemd_user; }

state_of () {
    "${SH[@]}" container inspect "$1" 2> /dev/null |
        python3 -I -c 'import json, sys; print(json.load(sys.stdin)["state"])' 2> /dev/null
}
pid_of () {
    "${SH[@]}" container inspect "$1" 2> /dev/null | python3 -I -c '
import json, sys
try: print(json.load(sys.stdin).get("pid") or "")
except ValueError: print("")'
}

# the daemon is a child of the test that started it: its pid is in a file
start_daemon () {
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --config "$WORKDIR/config.toml" varlink || {
        echo "the daemon did not start"; tail "$WORKDIR/daemon.log"; exit 1; }
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
}
stop_daemon () {
    local pid
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    [ -n "$pid" ] || return 0
    kill "$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    e2e_wait_exit "$pid" 10
    rm -f "$WORKDIR/daemon.pid"
}
# Everything a power cut takes: the processes, the mounts, the tmpfs.
reboot () {
    local f p c mons pids=()
    # the processes of the containers, while the daemon answers
    for c in alw unl unl2 norestart rmme madeinit; do
        p=$(pid_of "$c")
        [ -z "$p" ] || pids+=("$p")
    done
    # the daemon and the monitors first: either starts a container whose
    # process is killed again by its restart policy, in the scope of the
    # container, which outlives them all (no reboot leaves a process)
    p=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -n "$p" ]; then
        kill -9 "$p" 2> /dev/null
        wait "$p" 2> /dev/null
        e2e_wait_exit "$p" 10 || e2e_die "the killed daemon $p is still there"
        rm -f "$WORKDIR/daemon.pid"
    fi
    mons=$(e2e_monitors "$STATE")
    for p in $mons; do kill -9 "$p" 2> /dev/null; done
    for p in $mons; do e2e_wait_exit "$p" 10 || e2e_die "the killed monitor $p is still there"; done
    for p in "${pids[@]}"; do kill -9 "$p" 2> /dev/null; done
    # (gone, as after a boot: one still dying, a zombie that a killed monitor
    # left to be reaped, would be taken for one that runs)
    for p in "${pids[@]}"; do e2e_wait_exit "$p" 10 || e2e_die "the killed container process $p is still there"; done
    # the monitors of this store, by their run directory
    mons=$(e2e_monitors "$STATE")
    for p in $mons; do kill -9 "$p" 2> /dev/null; done
    for p in $mons; do e2e_wait_exit "$p" 10 || e2e_die "the killed monitor $p is still there"; done
    # the pasta of the network of the pod (rootless), by its pid file: no
    # engine knows of it once the state is gone
    for f in $(find "$STATE/networks/pasta" -name '*.pid' 2> /dev/null); do
        p=$(cat "$f" 2> /dev/null)
        case "$(cat "/proc/${p:-0}/comm" 2> /dev/null)" in
        pasta*) ;;
        *) continue ;;
        esac
        kill -9 "$p" 2> /dev/null
        e2e_wait_exit "$p" 10 || e2e_die "the killed pasta $p is still there"
    done
    if [ "$(id -u)" = 0 ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    rm -rf "$STATE"
}
# exec in a container prints what the command does
alpine () { "${SH[@]}" container exec "$1" cat /etc/alpine-release > /dev/null 2>&1 && echo yes; }

setup_file () {
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export WORKDIR; WORKDIR=$(realpath "$(mktemp -d "${TMPDIR:-/var/tmp}/velarx-reboot.XXXXXX")")
    export UNIT=shr-$$
    if [ "$(id -u)" = 0 ]; then
        # (system services may only run binaries labelled as such: all of
        # them, the helpers the engine starts too)
        e2e_system_bin
    fi
    mkdir -p "$WORKDIR/home" "$WORKDIR/run"
    chmod 700 "$WORKDIR/run"
    # the commands reach the user's manager on its private socket, as in a
    # session (they make the scopes of their containers, and stop those a
    # reboot left loaded)
    [ "$(id -u)" = 0 ] || ln -sfn "$REAL_RUNTIME_DIR/systemd" "$WORKDIR/run/systemd"
    export HOME=$WORKDIR/home XDG_RUNTIME_DIR=$WORKDIR/run
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
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "${IMAGE%%/*}"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
}

# after a test that failed: the transient units stop
teardown () {
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] && return 0
    "${SCTL[@]}" stop "$UNIT.service" "$UNIT-c.service" 2> /dev/null
    return 0
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    vars
    "${SCTL[@]}" stop "$UNIT.service" "$UNIT-c.service" 2> /dev/null
    "${SCTL[@]}" reset-failed "$UNIT.service" "$UNIT-c.service" 2> /dev/null
    "${SH[@]}" container rm -t 0 -f -i keep alw unl unl2 norestart rmme unitc made maderm madeinit > /dev/null 2>&1
    "${SH[@]}" pod rm -t 0 -f p1 > /dev/null 2>&1
    stop_daemon
    [ -n "${E2E_KEEP:-}" ] || e2e_remove_workdir "$WORKDIR" "${SH[@]}"
    e2e_teardown_file
}

@test "containers, a volume and a pod before the reboot" {
    start_daemon
    "${SH[@]}" volume create v1 > /dev/null
    "${SH[@]}" "${RUN[@]}" --rm -v v1:/data "$IMAGE" sh -c 'echo kept > /data/f'
    check "data written to a volume" 0 $?
    "${SH[@]}" pod create --infra-image "$IMAGE" p1 > /dev/null
    check "a pod" 1 "$("${SH[@]}" pod list --all 2> /dev/null | grep -cw p1)"
    "${SH[@]}" "${RUN[@]}" --name keep "$IMAGE" sh -c 'echo changed > /etc/motd' > /dev/null
    check "a container that ended" exited "$(state_of keep)"
    "${SH[@]}" "${RUN[@]}" -d --name alw --restart always "$IMAGE" sleep inf > /dev/null
    "${SH[@]}" "${RUN[@]}" -d --name unl --restart unless-stopped "$IMAGE" sleep inf > /dev/null
    "${SH[@]}" "${RUN[@]}" -d --name unl2 --restart unless-stopped "$IMAGE" sleep inf > /dev/null
    "${SH[@]}" "${RUN[@]}" -d --name norestart "$IMAGE" sleep inf > /dev/null
    "${SH[@]}" "${RUN[@]}" -d --name rmme --rm "$IMAGE" sleep inf > /dev/null
    "${SH[@]}" container stop -t 1 unl2 > /dev/null
    "${SH[@]}" container create --name made "$IMAGE" true > /dev/null
    "${SH[@]}" container create --rm --name maderm "$IMAGE" true > /dev/null
    "${SH[@]}" container create --name madeinit "$IMAGE" true > /dev/null
    "${SH[@]}" container init madeinit > /dev/null
    check "created before the reboot" "created created initialized" \
        "$(state_of made) $(state_of maderm) $(state_of madeinit)"
    check "running before the reboot" "running running exited running running" \
        "$(state_of alw) $(state_of unl) $(state_of unl2) $(state_of norestart) $(state_of rmme)"
}

@test "a daemon restart is no reboot: everything stays" {
    stop_daemon
    start_daemon
    check "a daemon restart keeps the stopped containers" exited "$(state_of keep)"
    check "and the running ones" running "$(state_of alw)"
}

@test "a state directory without its marker is no proof of a reboot" {
    # (emptied by hand, not a tmpfs): what runs is left alone.
    rm -f "$STATE/boot-id"
    stop_daemon
    start_daemon
    check "no marker: the running containers still run" "running running" "$(state_of alw) $(state_of rmme)"
    check "no marker: their root file system is there, exec works" yes "$(alpine alw)"
    check "no marker: the marker is written" yes "$([ -s "$STATE/boot-id" ] && echo yes)"
}

@test "without a marker, the engine leaves the container of a unit alone" {
    skip_unless_manager
    # The same through the engine, with a container that a unit runs.
    timeout 120 "${SRUN[@]}" --quiet --unit="$UNIT-c" -p Type=notify -p NotifyAccess=all -p Delegate=yes \
        -p KillMode=mixed "${ENVP[@]}" "${SH[@]}" "${RUN[@]}" -d --sdnotify=conmon --name unitc "$IMAGE" sleep inf
    check "a unit runs a container" running "$(state_of unitc)"
    rm -f "$STATE/boot-id"
    "$BIN/velarx" --config "$WORKDIR/config.toml" container list > /dev/null 2>&1
    check "no marker, engine: the unit's container still runs" "running running" "$(state_of unitc) $(state_of alw)"
    check "no marker, engine: exec works in it" yes "$(alpine unitc)"
    check "no marker, engine: the unit is active" active "$("${SCTL[@]}" show -P ActiveState "$UNIT-c.service")"
    "${SCTL[@]}" stop "$UNIT-c.service"
}

@test "after a reboot the running containers are stopped, the rest is kept" {
    reboot
    start_daemon
    check "after the reboot the running containers are stopped" "exited exited exited" \
        "$(state_of alw) $(state_of unl) $(state_of norestart)"
    check "a stopped one is still there" exited "$(state_of keep)"
    check "the pod is still there" 1 "$("${SH[@]}" pod list --all 2> /dev/null | grep -cw p1)"
    check "--rm ones that ran are gone" "" "$(state_of rmme)"
    check "created ones are still created, as podman's" "created created created" \
        "$(state_of made) $(state_of maderm) $(state_of madeinit)"
    "${SH[@]}" container start -a made > /dev/null 2>&1
    check "a created one starts after the reboot" 0 $?
    "${SH[@]}" container start -a madeinit > /dev/null 2>&1
    check "an initialized one starts after the reboot" 0 $?
    "${SH[@]}" container rm -f -t 0 maderm > /dev/null 2>&1
    out=$("${SH[@]}" "${RUN[@]}" --rm -v v1:/data "$IMAGE" cat /data/f 2>&1)
    check "the volume keeps its data" kept "$out"
    "${SH[@]}" container start -a keep > /dev/null 2>&1
    check "a stopped container starts again" 0 $?
    "${SH[@]}" container cp keep:/etc/motd "$WORKDIR/motd" > /dev/null 2>&1
    out=$(cat "$WORKDIR/motd" 2> /dev/null)
    check "with its own changes" changed "$out"
    "${SH[@]}" container run --rm --tls-verify=false --network none "$IMAGE" true > /dev/null
    check "new containers run" 0 $?
}

@test "start --all --filter should-start-on-boot and stop --all --service" {
    "${SH[@]}" container start --all --filter should-start-on-boot=true > /dev/null
    check "start --all --filter should-start-on-boot=true" "running running exited exited exited" \
        "$(state_of alw) $(state_of unl) $(state_of unl2) $(state_of norestart) $(state_of keep)"
    "${SH[@]}" container stop --all --service -t 1 > /dev/null
    check "stop --all, as the service manager does" "exited exited" "$(state_of alw) $(state_of unl)"
}

@test "the restart unit of the boot starts and stops the containers" {
    skip_unless_manager
    # The unit of the boot: velarx-restart.service, as a transient unit.
    "${SH[@]}" container start alw > /dev/null && "${SH[@]}" container stop -t 1 alw > /dev/null
    check "a stop by the user" exited "$(state_of alw)"
    timeout 120 "${SRUN[@]}" --quiet --wait --unit="$UNIT" -p Type=oneshot -p RemainAfterExit=yes "${ENVP[@]}" \
        -p "ExecStop=${SH[*]} container stop --all --service -t 1" \
        "${SH[@]}" container start --all --filter should-start-on-boot=true > /dev/null 2>&1 3>&- &
    waiter=$!
    e2e_wait_unit_state "$UNIT.service" active 20
    check "the restart unit runs" active "$("${SCTL[@]}" show -P ActiveState "$UNIT.service")"
    check "it starts always and unless-stopped ones, not one its user stopped" "running running exited exited" \
        "$(state_of alw) $(state_of unl) $(state_of unl2) $(state_of norestart)"
    "${SCTL[@]}" stop "$UNIT.service"
    wait "$waiter" 2> /dev/null
    check "stopping the unit stops them" "exited exited" "$(state_of alw) $(state_of unl)"
}

@test "the daemon never panicked" {
    check "the daemon did not panic" 0 "$(grep -c panicked "$WORKDIR/daemon.log")"
}
