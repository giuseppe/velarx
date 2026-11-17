#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# A kubelet on velarx-cri: a node that runs static pods, with no API server.
#
#   tests/cri/kubelet.sh BINDIR [KUBELET]       # as root
#
# BINDIR has velarx, velarx-monitor and velarx-cri (the engine is `velarx varlink`;
# velarx-cri talks to its socket and starts nothing).  KUBELET is the
# kubelet binary (default: $KUBELET, then `kubelet` in the PATH; a release
# binary is enough: https://dl.k8s.io/release/vX.Y.Z/bin/linux/amd64/kubelet).
# It needs root (the kubelet's own requirement), crun and a registry the engine
# can pull IMAGE from (OCI format; default docker.io/library/alpine:3.20;
# IMAGE=localhost:5000/alpine:chunked with REGISTRY_INSECURE=localhost:5000 for a
# local one).  It prints "SKIP: reason" and ends with 0 when the kubelet, root,
# or crun is missing, and "PASS" when the node did all of:
#
#  * the node is Ready as far as a standalone kubelet says (the runtime and
#    the network report ready: the kubelet's /healthz and the runtime status);
#  * a static pod of two containers with a hostPath volume runs: both write a
#    file in the shared directory, the pod and its containers are Running;
#  * the kubelet's read-write API serves the logs (/containerLogs) and runs a
#    command (/run, an ExecSync) in a container;
#  * an exec readiness probe makes the pod Ready;
#  * removing the manifest makes the kubelet stop and remove the pod.
#
# Everything runs in a mount namespace of its own under /var/tmp, and ends with
# whatever it started.  The kubelet's fixed paths (/var/lib/kubelet, where it
# puts the device plugin socket whatever its root directory) are bind mounts
# of the work directory, its pod logs are there too, and the kernel settings
# it changes at start (vm.overcommit_memory, kernel.panic, kernel.panic_on_oops...)
# get their values back at the end.  The output of the kubelet, velarx-cri and the engine is
# kept in $KUBELET_LOGS (default: the work directory, removed at the end unless
# the run failed).
set -u
# the waits of the end to end tests (READY=1, inotify, pidfd)
. "$(dirname "$(realpath "$0")")/../e2e/bats/wait.bash"
IMAGE=${IMAGE:-docker.io/library/alpine:3.20}
TIMEOUT=${KUBELET_TIMEOUT:-180}
SYSCTLS="vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxkeys kernel.keys.root_maxbytes"

skip () { echo "SKIP: $*"; exit 0; }
fail () { echo "FAIL: $*" >&2; dump; exit 1; }

# wait_for SECONDS COMMAND...: run COMMAND until it succeeds (every 0.2 s): for
# the answers of the kubelet's HTTP server and the states of its pod, which tell nobody
wait_for () {
    local deadline=$((SECONDS + $1))
    shift
    until "$@" 2> /dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 0.2
    done
}

dump () {
    [ -n "${W:-}" ] || return 0
    echo "--- logs in $W" >&2
    local f
    for f in kubelet.log cri.log engine.log; do
        [ -f "$W/$f" ] && { echo "--- $f (tail)" >&2; tail -n 40 "$W/$f" >&2; }
    done
    KEEP=1
}

main () {
    [ "$(id -u)" = 0 ] || skip "the kubelet needs root"
    local bin kubelet
    bin=$(realpath "${1:?usage: kubelet.sh BINDIR [KUBELET]}")
    kubelet=${2:-${KUBELET:-$(command -v kubelet || true)}}
    [ -n "$kubelet" ] && [ -x "$kubelet" ] || skip "no kubelet binary (KUBELET=... or the second argument)"
    for t in crun crictl curl; do command -v "$t" > /dev/null || skip "$t is not installed"; done
    for t in velarx-cri velarx-monitor; do [ -x "$bin/$t" ] || skip "$bin/$t is not built"; done
    [ -x "$bin/velarx" ] || skip "$bin/velarx is not built"
    # the work directory is not inherited: the namespace has its own mounts
    exec unshare -m --propagation private "$0" in-namespace "$bin" "$kubelet"
}

registries_conf () {
    : > "$1"
    local r
    for r in ${REGISTRY_INSECURE:-}; do
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$r" >> "$1"
    done
}

in_namespace () {
    local bin=$1 kubelet=$2
    W=$(mktemp -d /var/tmp/velarx-kubelet.XXXXXX)
    KEEP=0
    trap cleanup EXIT
    mkdir -p "$W/run" "$W/data" "$W/etc" "$W/manifests" "$W/kubelet" "$W/hostdir" "$W/pod-logs"
    local t
    for t in $SYSCTLS; do echo "$t=$(sysctl -n "$t")"; done > "$W/sysctls" || fail "cannot read the kernel settings"
    if [ ! -d /var/lib/kubelet ]; then
        mkdir /var/lib/kubelet || fail "cannot make /var/lib/kubelet"
        MADE_VARLIB=1
    fi
    # with SELinux, a container may write the shared directory only when it is labelled for them
    if command -v selinuxenabled > /dev/null && selinuxenabled; then
        chcon -t container_file_t "$W/hostdir" || fail "cannot label the shared directory"
    fi
    mount --bind "$W/kubelet" /var/lib/kubelet || fail "cannot mount over /var/lib/kubelet"
    cat > "$W/etc/config.toml" <<TOML
storage.root = "$W/data"
[engine]
socket = "$W/engine.sock"
[server]
state_dir = "$W/run"
root_dir = "$W/data"
shutdown_timeout_secs = 5
TOML
    registries_conf "$W/etc/registries.conf"
    export VELARX_REGISTRIES_CONF=$W/etc/registries.conf
    printf '#!/bin/sh\nexec %s --config %s "$@"\n' "$bin/velarx" "$W/etc/config.toml" > "$W/velarx"
    chmod +x "$W/velarx"
    # (the engine and velarx-cri in sessions of their own: a Ctrl-C of the caller's
    # process group does not stop them before the cleanup removed the pods through them)
    E2E_SPAWN_LOG=$W/engine.log e2e_spawn_ready ENGINEPID setsid "$W/velarx" varlink || fail "the engine did not say READY=1"

    CRISOCK=$W/cri.sock
    setsid "$bin/velarx-cri" --socket "$CRISOCK" --engine-socket "$W/engine.sock" \
        --checkpoint-dir "$W/checkpoints" > "$W/cri.log" 2>&1 &
    CRIPID=$!
    e2e_wait_path_of "$CRISOCK" "$CRIPID" 60 || fail "velarx-cri did not listen"
    printf 'runtime-endpoint: unix://%s\nimage-endpoint: unix://%s\ntimeout: 60\n' "$CRISOCK" "$CRISOCK" > "$W/crictl.yaml"

    # the image is pulled first so that the kubelet's pull is a lookup
    cc pull "$IMAGE" > "$W/pull.log" 2>&1 || { cat "$W/pull.log" >&2; fail "cannot pull $IMAGE"; }

    local driver
    driver=$(cc runtime-config 2> /dev/null | sed -n 's/^cgroup driver: *\([A-Za-z]*\).*/\1/p' | head -n 1 | tr '[:upper:]' '[:lower:]')
    [ -n "$driver" ] || fail "crictl runtime-config does not tell the cgroup driver"

    cat > "$W/kubelet.yaml" <<YAML
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: 127.0.0.1
port: 0
readOnlyPort: 0
healthzBindAddress: 127.0.0.1
healthzPort: 0
authentication:
  anonymous: {enabled: true}
  webhook: {enabled: false}
authorization: {mode: AlwaysAllow}
staticPodPath: $W/manifests
fileCheckFrequency: 1s
syncFrequency: 2s
cgroupDriver: $driver
cgroupsPerQOS: false
enforceNodeAllocatable: []
failSwapOn: false
podLogsDir: $W/pod-logs
containerRuntimeEndpoint: unix://$CRISOCK
imageGCHighThresholdPercent: 100
imageGCLowThresholdPercent: 99
evictionHard: {}
YAML
    # the ports are fixed: a standalone kubelet has no API object that says where it listens
    local port=$((20000 + $$ % 20000)) hport=$((40000 + $$ % 20000))
    sed -i "s/^port: 0/port: $port/; s/^healthzPort: 0/healthzPort: $hport/" "$W/kubelet.yaml"
    "$kubelet" --config "$W/kubelet.yaml" --root-dir /var/lib/kubelet --hostname-override velarx-node --v=2 > "$W/kubelet.log" 2>&1 &
    KPID=$!
    local kpid=$!
    local api=https://127.0.0.1:$port
    k () { curl -sk -m 20 "$@"; }

    wait_for 60 curl -sf -m 5 "http://127.0.0.1:$hport/healthz" > /dev/null || fail "the kubelet is not healthy"
    echo "kubelet up (healthz)"

    cat > "$W/manifests/two.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: two
  namespace: default
  labels: {app: two}
spec:
  restartPolicy: Always
  volumes:
  - name: shared
    hostPath: {path: $W/hostdir, type: Directory}
  containers:
  - name: a
    image: $IMAGE
    command: ["sh", "-c", "echo from-a > /data/a; echo log-of-a; exec sleep 100000"]
    volumeMounts: [{name: shared, mountPath: /data}]
    readinessProbe:
      exec: {command: ["test", "-f", "/data/b"]}
      periodSeconds: 1
  - name: b
    image: $IMAGE
    command: ["sh", "-c", "echo from-b > /data/b; exec sleep 100000"]
    volumeMounts: [{name: shared, mountPath: /data}]
YAML

    wait_for "$TIMEOUT" test -f "$W/hostdir/a" -a -f "$W/hostdir/b" \
        || fail "the two containers did not run (no file in the hostPath)"
    [ "$(cat "$W/hostdir/a")" = from-a ] && [ "$(cat "$W/hostdir/b")" = from-b ] || fail "wrong content in the hostPath"
    echo "both containers wrote the hostPath"

    local running
    running=$(cc ps -q --state running | wc -l)
    [ "$running" = 2 ] || fail "$running containers running, not 2"
    cc pods --state ready -q | grep -q . || fail "no ready sandbox"

    # the kubelet's API: the pod list says Running and Ready, the logs and a command
    ready () { k "$api/pods" | grep -q '"type":"Ready","status":"True"'; }
    wait_for 60 ready || fail "the pod is not Ready (the exec probe)"
    echo "pod Ready (exec probe)"
    log () { [ "$(k "$api/containerLogs/default/two-velarx-node/a")" = log-of-a ]; }
    wait_for 30 log || fail "the kubelet does not serve the log of a: $(k "$api/containerLogs/default/two-velarx-node/a")"
    echo "logs served"
    local out
    out=$(k -X POST "$api/run/default/two-velarx-node/b?cmd=cat%20/data/a")
    [ "$out" = from-a ] || fail "run in b printed '$out'"
    echo "command run in a container (ExecSync)"

    rm "$W/manifests/two.yaml"
    none () { [ -z "$(cc ps -aq)" ] && [ -z "$(cc pods -q)" ]; }
    wait_for 120 none || fail "the pod was not removed with its manifest"
    echo "pod removed"
    kill -0 "$kpid" || fail "the kubelet ended"
    echo PASS
}

cc () { crictl --config "$W/crictl.yaml" "$@"; }

cleanup () {
    local p t left
    # the kubelet first (it does not stop its pods), then what it left
    [ -z "${KPID:-}" ] || { kill -INT "$KPID" 2> /dev/null; wait "$KPID" 2> /dev/null; }
    if [ -n "${CRIPID:-}" ] && [ -f "$W/crictl.yaml" ]; then
        cc rmp -fa > /dev/null 2>&1
        cc rm -fa > /dev/null 2>&1
    fi
    [ -z "${CRIPID:-}" ] || { kill -INT "$CRIPID" 2> /dev/null; wait "$CRIPID" 2> /dev/null; }
    [ -z "${ENGINEPID:-}" ] || { kill -INT "$ENGINEPID" 2> /dev/null; wait "$ENGINEPID" 2> /dev/null; }
    [ -f "$W/sysctls" ] && while IFS= read -r t; do sysctl -q -w "$t"; done < "$W/sysctls"
    # whatever still runs under the work directory (the monitors), a directory of mktemp
    # shellcheck disable=SC2009
    left=$(ps -eo pid,args | grep -F "$W" | grep -v grep | awk '{ print $1 }')
    for p in $left; do kill -INT "$p" 2> /dev/null; done
    for p in $left; do e2e_wait_exit "$p" 10 2> /dev/null; done
    local m
    # (mount points of mktemp's names: no white space)
    # shellcheck disable=SC2013
    for m in $(awk -v w="$W" 'index($2, w) == 1 { print $2 }' /proc/self/mounts | sort -r); do umount -l "$m" 2> /dev/null; done
    mountpoint -q /var/lib/kubelet && umount -l /var/lib/kubelet
    [ "${MADE_VARLIB:-0}" = 1 ] && rmdir /var/lib/kubelet
    if [ "${KEEP:-0}" = 1 ] && [ -z "${KUBELET_LOGS:-}" ]; then
        echo "kept: $W" >&2
    else
        [ -n "${KUBELET_LOGS:-}" ] && mkdir -p "$KUBELET_LOGS" && cp "$W"/*.log "$KUBELET_LOGS"/ 2> /dev/null
        chmod -R u+rwX "$W" 2> /dev/null
        rm -rf --one-file-system "$W"
    fi
}

case ${1:-} in
in-namespace) shift; in_namespace "$@" ;;
"" | -h | --help) sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//; /^set -u/d' >&2; exit 2 ;;
*) main "$@" ;;
esac
