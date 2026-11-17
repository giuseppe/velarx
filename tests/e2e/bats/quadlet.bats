# SPDX-License-Identifier: Apache-2.0
# Quadlet units with velarx: podman's own generator writes the
# units of .container, .volume, .network and .pod files with
# PODMAN=velarx, and they run under systemd as with podman.  Then
# velarx's generator (systemd/generators/velarx-generator) and
# `velarx quadlet enable|disable` on a fake root.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/quadlet.bats               # user units, rootless
#   VELARX_BINDIR=target/debug MODE=system bats tests/e2e/bats/quadlet.bats   # system units, as root
#
# Nothing touches the generators or the unit directories of the host: the
# generator writes in $WORKDIR, the units are linked as runtime units
# (shq-<pid>-*) and unlinked at the end; the store is in $WORKDIR.  Skipped
# without podman's generator.
#
# This file talks to the user's systemd manager and reloads it (daemon-reload):
# unit.bats times its units' start (TimeoutStartSec) and a daemon-reload of the
# manager in the middle cuts the extension, so the files that reload it
# (this one, units.bats, engine.bats and engine-api.bats) have to end before
# unit.bats starts; do not run them alongside it.

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

vars () {
    CONF=$WORKDIR/config.toml
    if [ "$MODE" = system ]; then
        SCTL=(systemctl)
        QMODE=
    else
        SCTL=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemctl --user)
        QMODE=-user
    fi
    SH=(env HOME="$WORKDIR/home" XDG_RUNTIME_DIR="$WORKDIR/run" "$BIN/velarx" --config "$CONF")
}

setup () { set +e; [ -z "${WORKDIR:-}" ] || vars; }

# after a test that failed: its units stop
teardown () {
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] && return 0
    local f
    for f in "$WORKDIR"/gen/*.service; do
        [ -e "$f" ] && "${SCTL[@]}" stop "$(basename "$f")" 2> /dev/null
    done
    return 0
}

prop () { "${SCTL[@]}" show -P "$2" "$1"; }

setup_file () {
    export MODE=${MODE:-user}
    export QUADLET=${QUADLET:-/usr/libexec/podman/quadlet}
    if ! [ -x "$QUADLET" ]; then
        skip "no podman generator at $QUADLET"
    fi
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    if [ "$MODE" = system ]; then
        skip_unless_root
    else
        skip_unless_systemd_user
    fi
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export top_srcdir; top_srcdir=$(cd "$E2E_DIR/../.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export WORKDIR; WORKDIR=$(realpath "$(mktemp -d "${TMPDIR:-/var/tmp}/velarx-quadlet.XXXXXX")")
    export P=shq-$$
    mkdir -p "$WORKDIR/home" "$WORKDIR/run" "$WORKDIR/quadlet" "$WORKDIR/gen"
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
[containers]
log_driver = "k8s-file"
TOML
    if [ "$MODE" = system ]; then
        # System services may only run binaries labelled as such.
        mkdir -p "$WORKDIR/bin"
        local b
        for b in velarx velarx-monitor velarx-registry velarx-kube; do cp "$BIN/$b" "$WORKDIR/bin/"; done
        BIN=$WORKDIR/bin
        if command -v selinuxenabled > /dev/null && selinuxenabled; then
            chcon -t bin_t "$BIN"/*
        fi
    else
        # the units reach the user manager (the monitors' scopes) through it
        ln -sfn "$REAL_RUNTIME_DIR/systemd" "$WORKDIR/run/systemd"
    fi
    vars

    "${SH[@]}" image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || true

    # The Quadlet files: what a user writes, with the scratch store of the test
    # (GlobalArgs=--config, the environment of the units).
    QENV="Environment=HOME=$WORKDIR/home XDG_RUNTIME_DIR=$WORKDIR/run"
    cat > "$WORKDIR/quadlet/$P-net.network" <<EOT
[Network]
GlobalArgs=--config $CONF
[Service]
$QENV
EOT
    cat > "$WORKDIR/quadlet/$P-vol.volume" <<EOT
[Volume]
GlobalArgs=--config $CONF
[Service]
$QENV
EOT
    cat > "$WORKDIR/quadlet/$P-web.container" <<EOT
[Container]
GlobalArgs=--config $CONF
Image=$IMAGE
PodmanArgs=--tls-verify=false
Network=$P-net.network
Volume=$P-vol.volume:/data
Exec=sh -c 'echo hello-quadlet > /data/f; echo hello-quadlet; exec sleep inf'
[Service]
$QENV
EOT
    cat > "$WORKDIR/quadlet/$P-hc.container" <<EOT
[Container]
GlobalArgs=--config $CONF
Image=$IMAGE
PodmanArgs=--tls-verify=false
Network=none
Notify=healthy
HealthCmd=test -e /tmp/ok
HealthInterval=1s
HealthStartPeriod=1m
Exec=sh -c 'sleep 4; touch /tmp/ok; exec sleep inf'
[Service]
$QENV
EOT
    cat > "$WORKDIR/quadlet/$P-pod.pod" <<EOT
[Pod]
GlobalArgs=--config $CONF
Network=none
[Service]
$QENV
EOT
    cat > "$WORKDIR/quadlet/$P-pc.container" <<EOT
[Container]
GlobalArgs=--config $CONF
Image=$IMAGE
PodmanArgs=--tls-verify=false
Pod=$P-pod.pod
Exec=sleep inf
[Service]
$QENV
EOT

    # .kube: the pod of a YAML, played by `velarx kube play` (velarx-kube) and
    # taken down when the unit stops
    cat > "$WORKDIR/$P-kube.yaml" <<EOT
apiVersion: v1
kind: Pod
metadata:
  name: $P-kpod
spec:
  hostNetwork: false
  containers:
  - name: main
    image: $IMAGE
    command: ["sleep", "inf"]
EOT
    cat > "$WORKDIR/quadlet/$P-k.kube" <<EOT
[Kube]
GlobalArgs=--config $CONF
Yaml=$WORKDIR/$P-kube.yaml
Network=none
[Service]
$QENV
EOT

    # .artifact: an artifact of the registry pulled by its unit, and a
    # container that mounts it
    export ART=${IMAGE%%/*}/velarx-quadlet/$P:v1
    echo "hello-artifact" > "$WORKDIR/art.txt"
    "${SH[@]}" artifact add "$ART" "$WORKDIR/art.txt" > /dev/null 2>&1 || true
    "${SH[@]}" artifact push --tls-verify=false -q "$ART" > /dev/null 2>&1 || true
    "${SH[@]}" artifact rm "$ART" > /dev/null 2>&1 || true
    cat > "$WORKDIR/quadlet/$P-art.artifact" <<EOT
[Artifact]
GlobalArgs=--config $CONF
Artifact=$ART
TLSVerify=false
Retry=1
[Service]
$QENV
EOT
    cat > "$WORKDIR/quadlet/$P-am.container" <<EOT
[Container]
GlobalArgs=--config $CONF
Image=$IMAGE
PodmanArgs=--tls-verify=false
Network=none
Mount=type=artifact,source=$ART,destination=/artifacts
Exec=sh -c 'cat /artifacts; exec sleep inf'
[Unit]
Requires=$P-art-artifact.service
After=$P-art-artifact.service
[Service]
$QENV
EOT
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    vars
    local f u
    for f in "$WORKDIR"/gen/*.service; do
        [ -e "$f" ] || continue
        u=$(basename "$f")
        "${SCTL[@]}" stop "$u" 2> /dev/null
        "${SCTL[@]}" reset-failed "$u" 2> /dev/null
    done
    for f in "$WORKDIR"/gen/*.service; do
        [ -e "$f" ] || continue
        "${SCTL[@]}" disable --runtime "$(basename "$f")" > /dev/null 2>&1
    done
    "${SCTL[@]}" daemon-reload
    "${SH[@]}" container rm -t 0 -f -i "systemd-$P-web" "systemd-$P-hc" "systemd-$P-pc" "systemd-$P-am" > /dev/null 2>&1
    "${SH[@]}" pod rm -t 0 -f "systemd-$P-pod" "$P-kpod" > /dev/null 2>&1
    [ -n "${E2E_KEEP:-}" ] || e2e_remove_workdir "$WORKDIR" "${SH[@]}"
    e2e_teardown_file
}

@test "podman's generator writes the units, which run velarx" {
    # podman's generator, with PODMAN=velarx, into the work directory
    PODMAN=$BIN/velarx QUADLET_UNIT_DIRS=$WORKDIR/quadlet "$QUADLET" -no-kmsg-log $QMODE "$WORKDIR/gen" \
        2> "$WORKDIR/gen.log"
    check "the generator ran" 0 $?
    check_match "the units run velarx" "ExecStart=$BIN/velarx --config $CONF run " \
        "$(grep ^ExecStart= "$WORKDIR/gen/$P-web.service")"
    "${SCTL[@]}" link --runtime "$WORKDIR"/gen/*.service > /dev/null 2>&1
    "${SCTL[@]}" daemon-reload
}

@test ".container with its .network and .volume" {
    timeout 120 "${SCTL[@]}" start "$P-web.service"
    check "the container unit starts" 0 $?
    check "it is active" active "$(prop "$P-web.service" ActiveState)"
    check "its main process is the monitor" velarx-monitor \
        "$(cat "/proc/$(prop "$P-web.service" MainPID)/comm" 2> /dev/null)"
    check "the network unit ran" active "$(prop "$P-net-network.service" ActiveState)"
    check_match "the network" "systemd-$P-net" "$("${SH[@]}" network ls 2>&1)"
    check_match "the volume" "systemd-$P-vol" "$("${SH[@]}" volume list 2>&1)"
    check "the container" running \
        "$("${SH[@]}" container list -a --format '{{.Names}} {{.State}}' 2> /dev/null | awk -v n="systemd-$P-web" '$1 == n {print $2}')"
    check_match "its output" "hello-quadlet" "$("${SH[@]}" logs "systemd-$P-web" 2>&1)"
    check "it writes the volume" "hello-quadlet" "$("${SH[@]}" exec "systemd-$P-web" cat /data/f 2>&1)"
    "${SCTL[@]}" stop "$P-web.service"
    check "a stop is a clean end" success "$(prop "$P-web.service" Result)"
    check "the container goes (--rm)" "" \
        "$("${SH[@]}" container list -a --format '{{.Names}}' 2> /dev/null | awk -v n="systemd-$P-web" '$1 == n')"
}

@test "Notify=healthy: active once the health check passes" {
    "${SCTL[@]}" start --no-block "$P-hc.service"
    # (a window: the service stays activating while the health check has not passed)
    sleep 2
    check "healthy: activating until healthy" activating "$(prop "$P-hc.service" ActiveState)"
    e2e_wait_unit_state "$P-hc.service" active 60
    check "healthy: then active" active "$(prop "$P-hc.service" ActiveState)"
    "${SCTL[@]}" stop "$P-hc.service"
}

@test ".pod: its container units start with it" {
    timeout 120 "${SCTL[@]}" start "$P-pod-pod.service"
    check "the pod unit starts" 0 $?
    e2e_wait_unit_state "$P-pc.service" active 60
    check "its container unit too" active "$(prop "$P-pc.service" ActiveState)"
    check_match "the container is in the pod" "systemd-$P-pod" \
        "$("${SH[@]}" container inspect "systemd-$P-pc" 2>&1 | grep -o "systemd-$P-pod" | head -1)"
    "${SCTL[@]}" stop "$P-pod-pod.service"
    e2e_wait_unit_state "$P-pc.service" inactive 30
    check "stopping the pod stops its container" inactive "$(prop "$P-pc.service" ActiveState)"
}

@test ".kube: its unit plays the YAML with velarx-kube and takes it down" {
    check_match "the unit plays the YAML" "ExecStart=$BIN/velarx --config $CONF kube play --replace --service-container=true " \
        "$(grep ^ExecStart= "$WORKDIR/gen/$P-k.service")"
    check_match "and takes it down" "ExecStopPost=$BIN/velarx --config $CONF kube down " \
        "$(grep ^ExecStopPost= "$WORKDIR/gen/$P-k.service")"
    timeout 120 "${SCTL[@]}" start "$P-k.service"
    check "the kube unit starts" 0 $?
    check "it is active" active "$(prop "$P-k.service" ActiveState)"
    check "the pod runs" running \
        "$("${SH[@]}" pod inspect --format '{{.State}}' "$P-kpod" 2> /dev/null | tr 'A-Z' 'a-z')"
    "${SCTL[@]}" stop "$P-k.service"
    check "a stop is a clean end" success "$(prop "$P-k.service" Result)"
    check "the pod is gone" 1 "$("${SH[@]}" pod exists "$P-kpod" > /dev/null 2>&1; echo $?)"
}

@test ".artifact: its unit pulls the artifact, a container unit mounts it" {
    check_match "the artifact unit runs velarx" "ExecStart=$BIN/velarx --config $CONF artifact pull " \
        "$(grep ^ExecStart= "$WORKDIR/gen/$P-art-artifact.service" 2> /dev/null)"
    timeout 120 "${SCTL[@]}" start "$P-am.service"
    check "the container of the artifact starts" 0 $?
    check "the artifact unit pulled it" active "$(prop "$P-art-artifact.service" ActiveState)"
    check "the artifact is in the store" "${ART%:v1}" "$("${SH[@]}" artifact ls --format '{{.Repository}}' 2>&1)"
    # (the line of its command that read it, in its log file below root_dir)
    id=$("${SH[@]}" container inspect --format '{{.Id}}' "systemd-$P-am" 2> /dev/null)
    check_match "the container of the artifact unit" "^[0-9a-f]{64}$" "$id"
    e2e_wait_line "$WORKDIR/data/root/logs/$id/container.log" ' stdout F hello-artifact$' 30 ||
        e2e_die "no hello-artifact in the log of the container within 30 s"
    check "the container reads the artifact" "hello-artifact" "$("${SH[@]}" logs "systemd-$P-am" 2>&1)"
    "${SCTL[@]}" stop "$P-am.service" "$P-art-artifact.service"
}

@test "velarx's generator and quadlet enable|disable on a fake root" {
    FAKE=$WORKDIR/fake
    kind=${QMODE:+user}
    kind=${kind:-system}
    mkdir -p "$FAKE/usr/lib/systemd/$kind-generators" "$FAKE/etc/systemd" "$WORKDIR/gen2"
    : > "$FAKE/usr/lib/systemd/$kind-generators/podman-$kind-generator"
    cp "$top_srcdir/systemd/generators/velarx-generator" "$FAKE/usr/lib/systemd/$kind-generators/velarx-$kind-generator"
    gen=$FAKE/usr/lib/systemd/$kind-generators/velarx-$kind-generator
    # the generator looks at the real paths: in a mount namespace of its own
    # (a user namespace maps root), the fake root is bound over the
    # directories of systemd
    run_generator () {
        QUADLET_UNIT_DIRS=$WORKDIR/quadlet unshare -rm sh -c \
            'mount --bind "$1/usr/lib/systemd" /usr/lib/systemd && mount --bind "$1/etc/systemd" /etc/systemd && exec "$2" -no-kmsg-log "$3"' \
            sh "$FAKE" "$gen" "$WORKDIR/gen2"
    }
    qflag=${QMODE:+--user}
    check "status: podman's generator" podman "$("${SH[@]}" quadlet status $qflag --root "$FAKE")"
    check "the generator runs on the fake root" 0 "$(run_generator >&2; echo $?)"
    check "velarx's generator does nothing while podman's is active" 0 "$(ls "$WORKDIR/gen2" | wc -l)"
    "${SH[@]}" quadlet enable $qflag --root "$FAKE" > /dev/null
    check "enable masks podman's" /dev/null "$(readlink "$FAKE/etc/systemd/$kind-generators/podman-$kind-generator")"
    check "status: velarx's generator" velarx "$("${SH[@]}" quadlet status $qflag --root "$FAKE")"
    check "the generator runs on the fake root again" 0 "$(run_generator >&2; echo $?)"
    check_match "then it makes the units, with velarx" "ExecStart=/usr/bin/velarx --config $CONF run " \
        "$(grep ^ExecStart= "$WORKDIR/gen2/$P-web.service" 2> /dev/null)"
    "${SH[@]}" quadlet disable $qflag --root "$FAKE" > /dev/null
    check "disable unmasks it" podman "$("${SH[@]}" quadlet status $qflag --root "$FAKE")"
}
