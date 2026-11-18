#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# A real single-node cluster on velarx-cri: etcd, kube-apiserver,
# kube-controller-manager and kube-scheduler, and a kubelet that registers its node
# and drives velarx-cri, with the reference CNI plugins (bridge, host-local).
#
#   tests/cri/cluster.sh BINDIR TOOLS CNIDIR       # as root
#
# BINDIR has velarx, velarx-monitor and velarx-cri.  TOOLS has etcd, kube-apiserver,
# kube-controller-manager, kube-scheduler, kubelet and kubectl (the versions of
# tests/cri/versions; run-all.sh downloads them).  CNIDIR has the plugins bridge and
# host-local.  Needs root, crun, crictl, curl and openssl, a registry the engine can
# pull IMAGE from (see kubelet.sh).  It prints "SKIP: reason" and ends with 0 when
# something is missing, and "PASS" when all of this worked:
#
#  * the node registers and is Ready; a Deployment (2 replicas) and pods reach
#    Running with an IP of the CNI bridge, reachable from the host; kubectl logs
#  * kubectl exec (with and without stdin), attach and port-forward
#  * a pod of each QoS class (Guaranteed, Burstable, BestEffort) is in the cgroup the
#    kubelet makes for its class, with the limits and weight of its resources
#  * deleting the Deployment and the pods removes the containers, sandboxes,
#    cgroups, IP leases and network namespaces
#  * under a memory pressure threshold the eviction manager evicts a pod
#
# Everything runs in a mount namespace of its own under /var/tmp and ends with what it
# started (as kubelet.sh), with a bridge, a cgroup and a CNI state directory of its own.
set -u
. "$(dirname "$(realpath "$0")")/../e2e/bats/wait.bash"
IMAGE=${IMAGE:-docker.io/library/alpine:3.20}
TIMEOUT=${CLUSTER_TIMEOUT:-120}
SYSCTLS="net.ipv4.ip_forward vm.overcommit_memory vm.panic_on_oom kernel.panic kernel.panic_on_oops kernel.keys.root_maxkeys kernel.keys.root_maxbytes"
BRIDGE=vxcri0
CGROOT=velarx-cri-test

skip () { echo "SKIP: $*"; exit 0; }
fail () { echo "FAIL: $*" >&2; dump; exit 1; }

# wait_for SECONDS COMMAND...: run COMMAND until it succeeds (every 0.2 s)
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
    for f in kubelet cri engine apiserver controller-manager scheduler etcd; do
        [ -f "$W/$f.log" ] && { echo "--- $f.log (tail)" >&2; tail -n 15 "$W/$f.log" >&2; }
    done
    echo "--- cgroups" >&2
    find "/sys/fs/cgroup/$CGROOT" -type d 2> /dev/null | sed "s|/sys/fs/cgroup/||" >&2
    local id
    for id in $(cc ps -aq 2> /dev/null); do echo "--- container $id" >&2; cc inspect "$id" 2> /dev/null | grep -E '"(exitCode|reason|message)"' >&2; cc logs "$id" 2>&1 | tail -n 5 >&2; done
    [ -n "${KUBECONFIG:-}" ] && { kubectl get pods -A -o wide >&2; kubectl get events -A >&2; } 2> /dev/null
    KEEP=1
}

main () {
    [ "$(id -u)" = 0 ] || skip "the kubelet needs root"
    local bin tools cni
    bin=$(realpath "${1:?usage: cluster.sh BINDIR TOOLS CNIDIR}")
    tools=$(realpath "${2:?usage: cluster.sh BINDIR TOOLS CNIDIR}")
    cni=$(realpath "${3:?usage: cluster.sh BINDIR TOOLS CNIDIR}")
    for t in crun crictl curl openssl; do command -v "$t" > /dev/null || skip "$t is not installed"; done
    for t in velarx velarx-cri velarx-monitor; do [ -x "$bin/$t" ] || skip "$bin/$t is not built"; done
    for t in etcd kube-apiserver kube-controller-manager kube-scheduler kubelet kubectl; do
        [ -x "$tools/$t" ] || skip "no $tools/$t"
    done
    for t in bridge host-local; do [ -x "$cni/$t" ] || skip "no CNI plugin $cni/$t"; done
    exec unshare -m --propagation private "$0" in-namespace "$bin" "$tools" "$cni"
}

in_namespace () {
    local bin=$1 tools=$2 cni=$3
    W=$(mktemp -d /var/tmp/velarx-cluster.XXXXXX)
    KEEP=0
    trap cleanup EXIT
    mkdir -p "$W/run" "$W/data" "$W/etc" "$W/kubelet" "$W/pki" "$W/cni/net.d" "$W/cni/ipam" "$W/cni/cache"
    export PATH=$tools:$PATH
    local t
    for t in $SYSCTLS; do echo "$t=$(sysctl -n "$t")"; done > "$W/sysctls" || fail "cannot read the kernel settings"
    if [ ! -d /var/lib/kubelet ]; then
        mkdir /var/lib/kubelet || fail "cannot make /var/lib/kubelet"
        MADE_VARLIB=1
    fi
    mount --bind "$W/kubelet" /var/lib/kubelet || fail "cannot mount over /var/lib/kubelet"
    # (the kubelet's log directories: the host's stay as they are)
    for t in pods containers; do
        [ -d "/var/log/$t" ] || { mkdir "/var/log/$t" && MADE_VARLOG="${MADE_VARLOG:-} /var/log/$t"; }
        mkdir "$W/$t" && mount --bind "$W/$t" "/var/log/$t" || fail "cannot mount over /var/log/$t"
    done

    # the bridge has the node's address (a loopback address is no node address); the plugin takes it as it is
    ip link add "$BRIDGE" type bridge && ip addr add 10.213.77.1/24 dev "$BRIDGE" && ip link set "$BRIDGE" up || fail "cannot make the bridge $BRIDGE"
    # the pod network: the reference bridge and host-local plugins, the pods' addresses in a private /24
    cat > "$W/cni/net.d/10-test.conflist" <<JSON
{"cniVersion": "1.0.0", "name": "velarx-cluster", "plugins": [
  {"type": "bridge", "bridge": "$BRIDGE", "isGateway": true, "ipMasq": false, "hairpinMode": true,
   "ipam": {"type": "host-local", "dataDir": "$W/cni/ipam", "ranges": [[{"subnet": "10.213.77.0/24"}]],
            "routes": [{"dst": "0.0.0.0/0"}]}}
]}
JSON
    cat > "$W/etc/config.toml" <<TOML
storage.root = "$W/data"
[engine]
socket = "$W/engine.sock"
[server]
state_dir = "$W/run"
root_dir = "$W/data"
shutdown_timeout_secs = 5
[network.cni]
conf_dir = "$W/cni/net.d"
bin_dirs = ["$cni"]
cache_dir = "$W/cni/cache"
TOML
    : > "$W/etc/registries.conf"
    local r
    for r in ${REGISTRY_INSECURE:-}; do
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$r" >> "$W/etc/registries.conf"
    done
    export VELARX_REGISTRIES_CONF=$W/etc/registries.conf
    printf '#!/bin/sh\nexec %s --config %s "$@"\n' "$bin/velarx" "$W/etc/config.toml" > "$W/velarx"
    chmod +x "$W/velarx"
    E2E_SPAWN_LOG=$W/engine.log e2e_spawn_ready ENGINEPID setsid "$W/velarx" varlink || fail "the engine did not say READY=1"
    CRISOCK=$W/cri.sock
    setsid "$bin/velarx-cri" --socket "$CRISOCK" --engine-socket "$W/engine.sock" --pod-network cni:velarx-cluster \
        --checkpoint-dir "$W/checkpoints" > "$W/cri.log" 2>&1 &
    CRIPID=$!
    e2e_wait_path_of "$CRISOCK" "$CRIPID" 60 || fail "velarx-cri did not listen"
    printf 'runtime-endpoint: unix://%s\nimage-endpoint: unix://%s\ntimeout: 60\n' "$CRISOCK" "$CRISOCK" > "$W/crictl.yaml"
    cc pull "$IMAGE" > "$W/pull.log" 2>&1 || { cat "$W/pull.log" >&2; fail "cannot pull $IMAGE"; }
    local driver
    driver=$(cc runtime-config 2> /dev/null | sed -n 's/^cgroup driver: *\([A-Za-z]*\).*/\1/p' | head -n 1 | tr '[:upper:]' '[:lower:]')
    [ "$driver" = cgroupfs ] || fail "the cgroup driver is '$driver', the test runs the kubelet with cgroupfs"

    # the control plane: etcd, the API server (token of system:masters), the controllers
    local base=$((20000 + $$ % 20000)) etcd api
    etcd=http://127.0.0.1:$base
    api=https://127.0.0.1:$((base + 2))
    local token
    token=$(openssl rand -hex 16)
    echo "$token,admin,admin,system:masters" > "$W/pki/tokens.csv"
    openssl genrsa -out "$W/pki/sa.key" 2048 2> /dev/null && openssl rsa -in "$W/pki/sa.key" -pubout -out "$W/pki/sa.pub" 2> /dev/null \
        || fail "openssl cannot make the service account key"
    cat > "$W/kubeconfig" <<YAML
apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "$api", insecure-skip-tls-verify: true}}]
users: [{name: admin, user: {token: "$token"}}]
contexts: [{name: c, context: {cluster: c, user: admin}}]
current-context: c
YAML
    export KUBECONFIG=$W/kubeconfig
    etcd --data-dir "$W/etcd" --listen-client-urls "$etcd" --advertise-client-urls "$etcd" \
        --listen-peer-urls "http://127.0.0.1:$((base + 1))" --initial-advertise-peer-urls "http://127.0.0.1:$((base + 1))" \
        --initial-cluster "default=http://127.0.0.1:$((base + 1))" > "$W/etcd.log" 2>&1 &
    ETCDPID=$!
    kube-apiserver --etcd-servers "$etcd" --secure-port $((base + 2)) --bind-address 127.0.0.1 --advertise-address 127.0.0.1 \
        --cert-dir "$W/pki" --service-cluster-ip-range 10.96.0.0/24 --token-auth-file "$W/pki/tokens.csv" \
        --authorization-mode RBAC --service-account-issuer https://kubernetes.default.svc \
        --service-account-key-file "$W/pki/sa.pub" --service-account-signing-key-file "$W/pki/sa.key" \
        --allow-privileged --endpoint-reconciler-type none --kubelet-preferred-address-types InternalIP > "$W/apiserver.log" 2>&1 &
    APIPID=$!
    wait_for 120 kubectl get --raw /readyz || fail "the API server is not ready"
    echo "control plane: etcd and kube-apiserver up"
    kube-controller-manager --kubeconfig "$W/kubeconfig" --service-account-private-key-file "$W/pki/sa.key" \
        --leader-elect=false --controllers='*' --bind-address 127.0.0.1 --secure-port 0 > "$W/controller-manager.log" 2>&1 &
    CMPID=$!
    kube-scheduler --kubeconfig "$W/kubeconfig" --leader-elect=false --bind-address 127.0.0.1 --secure-port 0 > "$W/scheduler.log" 2>&1 &
    SCHEDPID=$!

    kubelet_config "$W/kubelet.yaml" '{}'
    kubelet_config "$W/kubelet-evict.yaml" '{memory.available: "99%"}'
    mkdir -p "/sys/fs/cgroup/$CGROOT" || fail "cannot make the cgroup $CGROOT"
    cat /sys/fs/cgroup/cgroup.controllers | sed 's/\([a-z]*\)/+\1/g' > "/sys/fs/cgroup/$CGROOT/cgroup.subtree_control" 2> /dev/null
    start_kubelet "$W/kubelet.yaml"
    node_ready () { [ "$(kubectl get node velarx-node -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" = True ]; }
    wait_for 120 node_ready || fail "the node did not become Ready"
    echo "node Ready"
    wait_for 60 kubectl -n default get serviceaccount default > /dev/null || fail "no default service account"

    workloads
    qos
    cleanup_check
    evict
    echo PASS
}

# kubelet_config FILE EVICTIONHARD
kubelet_config () {
    cat > "$1" <<YAML
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: 10.213.77.1
port: $((20000 + $$ % 20000 + 3))
readOnlyPort: 0
healthzPort: 0
authentication:
  anonymous: {enabled: true}
  webhook: {enabled: false}
authorization: {mode: AlwaysAllow}
syncFrequency: 2s
cgroupDriver: cgroupfs
cgroupRoot: /$CGROOT
cgroupsPerQOS: true
failSwapOn: false
containerRuntimeEndpoint: unix://$CRISOCK
imageGCHighThresholdPercent: 100
imageGCLowThresholdPercent: 99
evictionHard: $2
evictionPressureTransitionPeriod: 5s
evictionMonitoringPeriod: 2s
YAML
}

start_kubelet () {
    kubelet --config "$1" --kubeconfig "$W/kubeconfig" --root-dir /var/lib/kubelet --hostname-override velarx-node \
        --node-ip 10.213.77.1 --v=2 >> "$W/kubelet.log" 2>&1 &
    KPID=$!
}

stop_kubelet () {
    kill -INT "$KPID" 2> /dev/null
    wait "$KPID" 2> /dev/null
    KPID=
}

phase () { # POD PHASE
    [ "$(kubectl get pod "$1" -o jsonpath='{.status.phase}')" = "$2" ]
}

workloads () {
    kubectl apply -f - > /dev/null <<YAML || fail "kubectl apply"
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - name: web
        image: $IMAGE
        command: ["sh", "-c", "mkdir /www; echo hello-web > /www/index.html; echo web-log; while true; do cat /www/index.html | nc -l -p 8080; done"]
---
apiVersion: v1
kind: Pod
metadata: {name: cat}
spec:
  containers:
  - name: cat
    image: $IMAGE
    command: ["cat"]
    stdin: true
YAML
    rollout () { [ "$(kubectl get deploy web -o jsonpath='{.status.readyReplicas}')" = 2 ]; }
    wait_for "$TIMEOUT" rollout || fail "the Deployment has no 2 ready replicas"
    wait_for 60 phase cat Running || fail "the pod cat is not Running"
    echo "Deployment (2 replicas) and a pod Running"

    # the CNI plugins gave the pods addresses of the bridge, reachable from the host
    local ip
    for ip in $(kubectl get pods -l app=web -o jsonpath='{.items[*].status.podIP}'); do
        case $ip in 10.213.77.*) ;; *) fail "the pod IP $ip is not of the CNI subnet" ;; esac
        [ "$(curl -s --http0.9 -m 5 "http://$ip:8080/")" = hello-web ] || fail "the pod $ip does not answer from the host"
    done
    ip link show "$BRIDGE" > /dev/null || fail "no bridge $BRIDGE"
    [ "$(leases)" = 3 ] || fail "host-local has $(leases) leases, not 3"
    echo "pods have the IPs of the CNI bridge and answer from the host"

    local pod out
    pod=$(kubectl get pods -l app=web -o jsonpath='{.items[0].metadata.name}')
    log () { kubectl logs "$pod" | grep -qx web-log; }
    wait_for 30 log || fail "kubectl logs: $(kubectl logs "$pod")"
    echo "kubectl logs"

    out=$(kubectl exec "$pod" -- cat /www/index.html) || fail "kubectl exec"
    [ "$out" = hello-web ] || fail "kubectl exec printed '$out'"
    out=$(echo from-stdin | kubectl exec -i "$pod" -- sh -c 'cat; echo " and $0" >&2' 2>&1) || fail "kubectl exec -i"
    [ "$out" = "from-stdin
 and sh" ] || fail "kubectl exec -i printed '$out'"
    kubectl exec "$pod" -- sh -c 'exit 7' 2> /dev/null
    [ $? = 7 ] || fail "kubectl exec did not give the exit code 7"
    echo "kubectl exec (output, stdin, exit code)"

    echo ping-attach | timeout 30 kubectl attach -i cat > "$W/attach.out" 2> "$W/attach.err"
    [ "$(cat "$W/attach.out")" = ping-attach ] || fail "kubectl attach -i printed '$(cat "$W/attach.out")' and said '$(cat "$W/attach.err")'"
    echo "kubectl attach (stdin and stdout)"

    kubectl port-forward "$pod" :8080 > "$W/portforward.log" 2>&1 &
    local pfpid=$! lport
    forwarding () { lport=$(sed -n 's/^Forwarding from 127.0.0.1:\([0-9]*\) .*/\1/p' "$W/portforward.log"); [ -n "$lport" ]; }
    wait_for 30 forwarding || { kill "$pfpid"; fail "kubectl port-forward does not listen: $(cat "$W/portforward.log")"; }
    [ "$(curl -s --http0.9 -m 10 "http://127.0.0.1:$lport/")" = hello-web ] || { kill "$pfpid"; fail "kubectl port-forward does not reach the pod: $(cat "$W/portforward.log")"; }
    kill "$pfpid"
    wait "$pfpid" 2> /dev/null
    echo "kubectl port-forward"
}

# pod_cgroup POD CLASSDIR: the cgroup directory of the pod, by its UID
pod_cgroup () {
    echo "/sys/fs/cgroup/$CGROOT/kubepods$2/pod$(kubectl get pod "$1" -o jsonpath='{.metadata.uid}')"
}

qos () {
    kubectl apply -f - > /dev/null <<YAML || fail "kubectl apply of the QoS pods"
apiVersion: v1
kind: Pod
metadata: {name: guaranteed}
spec:
  containers:
  - name: c
    image: $IMAGE
    command: ["sleep", "100000"]
    resources: {requests: {cpu: 200m, memory: 64Mi}, limits: {cpu: 200m, memory: 64Mi}}
---
apiVersion: v1
kind: Pod
metadata: {name: burstable}
spec:
  containers:
  - name: c
    image: $IMAGE
    command: ["sleep", "100000"]
    resources: {requests: {cpu: 500m, memory: 32Mi}, limits: {memory: 128Mi}}
---
apiVersion: v1
kind: Pod
metadata: {name: besteffort}
spec:
  containers:
  - name: c
    image: $IMAGE
    command: ["sleep", "100000"]
YAML
    local p
    for p in guaranteed burstable besteffort; do
        wait_for "$TIMEOUT" phase $p Running || fail "the pod $p is not Running"
    done
    local g b e
    g=$(pod_cgroup guaranteed "")
    b=$(pod_cgroup burstable /burstable)
    e=$(pod_cgroup besteffort /besteffort)
    for p in "$g" "$b" "$e"; do
        [ -d "$p" ] || fail "no cgroup $p"
        [ -n "$(find "$p" -name cgroup.procs -exec cat {} + )" ] || fail "no process under $p"
    done
    # the limits of the pods (the kubelet) and of their containers (the runtime)
    [ "$(cat "$g/memory.max")" = $((64 * 1024 * 1024)) ] || fail "guaranteed pod memory.max $(cat "$g/memory.max")"
    [ "$(cat "$g/cpu.max")" = "20000 100000" ] || fail "guaranteed pod cpu.max $(cat "$g/cpu.max")"
    [ "$(cat "$b/memory.max")" = $((128 * 1024 * 1024)) ] || fail "burstable pod memory.max $(cat "$b/memory.max")"
    [ "$(cat "$e/memory.max")" = max ] || fail "besteffort pod memory.max $(cat "$e/memory.max")"
    local w
    w=$(cat "$b/cpu.weight")
    [ "$w" -gt "$(cat "$e/cpu.weight")" ] || fail "the burstable pod weight ($w) is not above the besteffort pod's"
    echo "cgroups per QoS class: $g, $b, $e"
    # (the runtime applies the container's limit below the pod's cgroup)
    grep -rqx "$((64 * 1024 * 1024))" "$g" --include=memory.max || fail "no cgroup below $g has the memory limit 64Mi"
    grep -rqx "$((128 * 1024 * 1024))" "$b" --include=memory.max || fail "no cgroup below $b has the memory limit 128Mi"
    echo "limits applied to the pod and container cgroups"
}

cleanup_check () {
    kubectl delete deployment web --wait --timeout 120s > /dev/null || fail "kubectl delete deployment"
    kubectl delete pod --all --wait --timeout 120s --grace-period 2 > /dev/null || fail "kubectl delete pods"
    none () { [ -z "$(cc ps -aq)" ] && [ -z "$(cc pods -q)" ]; }
    wait_for 120 none || fail "the containers or sandboxes were not removed"
    nocg () { [ -z "$(find "/sys/fs/cgroup/$CGROOT/kubepods" -mindepth 2 -maxdepth 3 -name 'pod*' -o -mindepth 2 -maxdepth 3 -name 'cri*' 2> /dev/null)" ]; }
    wait_for 60 nocg || fail "cgroups of the pods are left: $(find "/sys/fs/cgroup/$CGROOT/kubepods" -mindepth 2 -type d)"
    noleases () { [ "$(leases)" = 0 ]; }
    wait_for 30 noleases || fail "IP leases are left: $(ls "$W/cni/ipam/velarx-cluster")"
    [ -z "$(ip -o link show master "$BRIDGE")" ] || fail "interfaces are left on the bridge: $(ip -o link show master "$BRIDGE")"
    echo "pods deleted: containers, sandboxes, cgroups, leases and interfaces are gone"
}

evict () {
    kubectl apply -f - > /dev/null <<YAML || fail "kubectl apply of the eviction pods"
apiVersion: v1
kind: Pod
metadata: {name: victim}
spec:
  containers:
  - name: c
    image: $IMAGE
    command: ["sleep", "100000"]
YAML
    wait_for "$TIMEOUT" phase victim Running || fail "the pod victim is not Running"
    # the node's memory is below 99 % of its capacity available: the manager must evict
    stop_kubelet
    start_kubelet "$W/kubelet-evict.yaml"
    evicted () { [ "$(kubectl get pod victim -o jsonpath='{.status.reason}')" = Evicted ]; }
    wait_for 120 evicted || fail "the pod was not evicted: $(kubectl get pod victim -o jsonpath='{.status}')"
    pressure () { [ "$(kubectl get node velarx-node -o jsonpath='{.status.conditions[?(@.type=="MemoryPressure")].status}')" = True ]; }
    wait_for 30 pressure || fail "the node has no MemoryPressure"
    gone () { [ -z "$(cc ps -q --state running)" ]; }
    wait_for 60 gone || fail "the evicted pod's container still runs"
    echo "eviction manager: the pod is Evicted, the node has MemoryPressure"
}

cc () { crictl --config "$W/crictl.yaml" "$@"; }

# leases: how many addresses host-local gave
leases () {
    local f n=0
    for f in "$W"/cni/ipam/velarx-cluster/10.*; do [ -e "$f" ] && n=$((n + 1)); done
    echo "$n"
}

cleanup () {
    local p t left
    [ -z "${KPID:-}" ] || stop_kubelet
    for p in "${SCHEDPID:-}" "${CMPID:-}" "${APIPID:-}" "${ETCDPID:-}"; do
        [ -z "$p" ] || { kill -TERM "$p" 2> /dev/null; wait "$p" 2> /dev/null; }
    done
    if [ -n "${CRIPID:-}" ] && [ -f "$W/crictl.yaml" ]; then
        cc rmp -fa > /dev/null 2>&1
        cc rm -fa > /dev/null 2>&1
    fi
    [ -z "${CRIPID:-}" ] || { kill -INT "$CRIPID" 2> /dev/null; wait "$CRIPID" 2> /dev/null; }
    [ -z "${ENGINEPID:-}" ] || { kill -INT "$ENGINEPID" 2> /dev/null; wait "$ENGINEPID" 2> /dev/null; }
    [ -f "$W/sysctls" ] && while IFS= read -r t; do sysctl -q -w "$t"; done < "$W/sysctls"
    # shellcheck disable=SC2009
    left=$(ps -eo pid,args | grep -F "$W" | grep -v grep | awk '{ print $1 }')
    for p in $left; do kill -INT "$p" 2> /dev/null; done
    for p in $left; do e2e_wait_exit "$p" 10 2> /dev/null; done
    # the cgroups of the kubelet and the runtime, deepest first
    if [ -d "/sys/fs/cgroup/$CGROOT" ]; then
        echo 1 > "/sys/fs/cgroup/$CGROOT/cgroup.kill"
        wait_for 10 grep -qx 'populated 0' "/sys/fs/cgroup/$CGROOT/cgroup.events"
        find "/sys/fs/cgroup/$CGROOT" -depth -type d -exec rmdir {} + 2> /dev/null
    fi
    ip link show "$BRIDGE" > /dev/null 2>&1 && ip link del "$BRIDGE"
    local m
    # shellcheck disable=SC2013
    for m in $(awk -v w="$W" 'index($2, w) == 1 { print $2 }' /proc/self/mounts | sort -r); do umount -l "$m" 2> /dev/null; done
    for m in /var/lib/kubelet /var/log/pods /var/log/containers; do mountpoint -q "$m" && umount -l "$m"; done
    [ "${MADE_VARLIB:-0}" = 1 ] && rmdir /var/lib/kubelet
    for m in ${MADE_VARLOG:-}; do rmdir "$m"; done
    if [ "${KEEP:-0}" = 1 ] && [ -z "${CLUSTER_LOGS:-}" ]; then
        echo "kept: $W" >&2
    else
        [ -n "${CLUSTER_LOGS:-}" ] && mkdir -p "$CLUSTER_LOGS" && cp "$W"/*.log "$CLUSTER_LOGS"/ 2> /dev/null
        chmod -R u+rwX "$W" 2> /dev/null
        rm -rf --one-file-system "$W"
    fi
}

case ${1:-} in
in-namespace) shift; in_namespace "$@" ;;
"" | -h | --help) sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//; /^set -u/d' >&2; exit 2 ;;
*) main "$@" ;;
esac
