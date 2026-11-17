# SPDX-License-Identifier: Apache-2.0
# contrib/velarx-kubeadm in --dry-run, with fake kubeadm, kubelet, kubectl,
# crictl and systemctl in a directory of their own: what it would write and
# run, and that it reports every missing prerequisite at once.  Nothing is
# installed or changed (the root of the script is a user namespace).
#
#   bats tests/e2e/bats/kubeadm-script.bats

SCRIPT=$BATS_TEST_DIRNAME/../../../contrib/velarx-kubeadm
UNSHARE=$(command -v unshare)

setup_file () {
    export FAKE; FAKE=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-kubeadm-script.XXXXXX")
    mkdir "$FAKE/full" "$FAKE/bare" "$FAKE/cni"
    local t
    # the tools the script itself uses
    for t in bash env id stat mktemp cat cmp chmod mv sed awk grep head cut sort tr dirname ps ss swapon sysctl modprobe curl rm mkdir ls rmdir ip getenforce; do
        p=$(command -v "$t") || continue
        ln -s "$p" "$FAKE/bare/$t"
        ln -s "$p" "$FAKE/full/$t"
    done
    for t in kubelet kubeadm kubectl crictl velarx velarx-cri velarx-monitor systemctl crun iptables iptables-save; do
        cat > "$FAKE/full/$t" <<'SH'
#!/bin/sh
# (every call is written down: a dry run makes none that changes anything)
echo "${0##*/} $*" >> "$FAKE/calls"
case "${0##*/} $*" in
    "kubelet --version") echo "Kubernetes v1.37.1" ;;
    "kubeadm config images list"*) echo registry.k8s.io/kube-apiserver:v1.37.1; echo registry.k8s.io/pause:3.10.2 ;;
    "kubeadm version"*) echo v1.37.1 ;;
    "kubectl version"*) echo "Client Version: v1.37.1" ;;
    "crictl"*runtime-config*) echo 'cgroup driver:   SYSTEMD' ;;
    "systemctl cat kubelet.service") echo 'ExecStart=/usr/bin/kubelet $KUBELET_KUBEADM_ARGS' ;;
    "iptables-save -t filter")
        echo '*filter'
        echo ':INPUT ACCEPT [0:0]'
        echo ':KUBE-FIREWALL - [0:0]'
        echo ':KUBE-SERVICES - [0:0]'
        echo ':OTHER - [0:0]'
        echo '-A INPUT -m comment --comment "kubernetes health check service ports" -j KUBE-NODEPORTS'
        echo '-A INPUT -j KUBE-FIREWALL'
        echo '-A INPUT -j OTHER'
        echo '-A KUBE-FIREWALL ! -s 127.0.0.0/8 -d 127.0.0.0/8 -j DROP'
        echo 'COMMIT' ;;
    "iptables-save -t"*) echo '*other'; echo ':INPUT ACCEPT [0:0]'; echo 'COMMIT' ;;
esac
exit 0
SH
        chmod +x "$FAKE/full/$t"
    done
    # (the CNI plugins are searched in /opt/cni/bin and /usr/libexec/cni: the
    # script's dry run does not need them in the fake world when they exist on
    # this host; a test that does not have them reports them missing)
}

setup () { "$UNSHARE" -rm true 2> /dev/null || skip "no user namespaces"; }

teardown_file () { rm -rf "$FAKE"; }

# as root of a user namespace: the root check passes, nothing is changed
kv () { PATH=$FAKE/full "$UNSHARE" -rm "$SCRIPT" "$@"; }

@test "shellcheck is clean" {
    command -v shellcheck > /dev/null || skip "no shellcheck"
    shellcheck -s bash "$SCRIPT"
}

@test "up --dry-run: the kubeadm configuration" {
    run kv up --dry-run --allow-swap --no-host-config --kubernetes-version v1.36.2
    echo "$output"
    [[ $output == *"criSocket: unix:///run/velarx/cri.sock"* ]]
    [[ $output == *"imagePullPolicy: IfNotPresent"* ]]
    [[ $output == *"taints: []"* ]]
    [[ $output == *"kubernetesVersion: v1.36.2"* ]]
    [[ $output == *"podSubnet: 10.244.0.0/16"* ]]
    [[ $output == *"cgroupDriver: systemd"* ]]
    [[ $output == *"failSwapOn: false"* ]]
    [[ $output == *"+ kubeadm init --config /etc/kubernetes/velarx-kubeadm.yaml"* ]]
    # (kubeadm's own release unless another is asked for: nothing is looked up)
    run kv up --dry-run --allow-swap --no-host-config
    [[ $output == *"kubernetesVersion: v1.37.1"* ]]
}

@test "a dry run runs nothing that changes the host" {
    rm -f "$FAKE/calls"
    # (its status is that of the prerequisites of this host)
    run kv up --dry-run --allow-swap --smoke
    echo "$output"
    [[ $output == *"(dry run: nothing was changed)"* ]]
    run kv reset --dry-run --purge
    echo "$output"
    [ "$status" -eq 0 ]
    cat "$FAKE/calls"
    # (only what looks: versions, the units and their state, the rules)
    run grep -Ev '^(kubelet --version|kubeadm version|kubeadm config images list|kubectl version|crictl .*(runtime-config|version)|systemctl (show|cat|is-active|is-enabled) |iptables-save |ip6tables-save |crun --version)' "$FAKE/calls"
    echo "$output"
    [ -z "$output" ]
}

@test "up --dry-run: velarx-cri, the CNI configuration and the images" {
    run kv up --dry-run --allow-swap --no-host-config --pod-cidr 10.1.0.0/16
    echo "$output"
    [[ $output == *"--pod-network cni:velarx --sandbox-image registry.k8s.io/pause:3.10.2"* ]]
    [[ $output == *'"ipRanges": true'* ]]
    [[ $output == *'"type": "host-local"'* ]]
    [[ $output == *"podSubnet: 10.1.0.0/16"* ]]
    [[ $output == *"+ crictl --runtime-endpoint unix:///run/velarx/cri.sock pull registry.k8s.io/pause:3.10.2"* ]]
    [[ $output == *"+ kubeadm config images pull"* ]]
}

@test "up --dry-run: another socket and no CNI file" {
    run kv up --dry-run --allow-swap --no-host-config --cni none --cri-socket unix:///run/x/cri.sock --sandbox-image example.com/pause:1
    echo "$output"
    [[ $output == *"criSocket: unix:///run/x/cri.sock"* ]]
    [[ $output == *"velarx-cri --pod-network cni: --sandbox-image example.com/pause:1"* ]]
    # (under its socket unit velarx-cri serves the socket systemd passes)
    [[ $output == *"velarx-cri.socket.d/10-kubernetes.conf"* ]]
    [[ $output == *"ListenStream=/run/x/cri.sock"* ]]
    [[ $output != *"10-velarx.conflist"* ]]
}

@test "up --dry-run: the kernel settings" {
    run kv up --dry-run --allow-swap
    echo "$output"
    [[ $output == *"net.bridge.bridge-nf-call-iptables = 1"* ]]
    [[ $output == *"br_netfilter"* ]]
}

@test "every missing prerequisite is reported at once" {
    run env PATH=$FAKE/bare "$UNSHARE" -rm "$SCRIPT" check
    echo "$output"
    [ "$status" -ne 0 ]
    local t
    for t in kubelet kubeadm kubectl crictl velarx velarx-cri velarx-monitor; do
        [[ $output == *"$t is not in the PATH"* ]]
    done
}

# (as a user who is not root also where the test runs as root: uid 1000 of a
# user namespace of its own, the owner there of the files of the test)
@test "a user who is not root is refused" {
    "$UNSHARE" -U --map-user=1000 --map-group=1000 true 2> /dev/null || skip "unshare cannot map a user who is not root"
    run env PATH=$FAKE/full "$UNSHARE" -U --map-user=1000 --map-group=1000 "$SCRIPT" check
    echo "$output"
    [ "$status" -ne 0 ]
    [[ $output == *"run as root"* ]]
}

@test "reset --dry-run removes only what the script wrote" {
    run kv reset --dry-run --purge
    echo "$output"
    [ "$status" -eq 0 ]
    [[ $output == *"+ kubeadm reset -f --cri-socket unix:///run/velarx/cri.sock"* ]]
    [[ $output != *"rm -rf /var/lib/velarx"* ]]
    # the KUBE-* chains kubeadm leaves, and the jumps to them; no other rule
    [[ $output == *'-D INPUT -m comment --comment "kubernetes health check service ports" -j KUBE-NODEPORTS'* ]]
    [[ $output == *"-D INPUT -j KUBE-FIREWALL"* ]]
    [[ $output == *"-X KUBE-FIREWALL"* ]]
    [[ $output == *"-X KUBE-SERVICES"* ]]
    [[ $output != *"OTHER"* ]]
    [[ $output != *"*other"* ]]
}

@test "bad options are refused" {
    run kv up --cni nonsense
    [ "$status" -ne 0 ]
    run kv up --timeout soon
    [ "$status" -ne 0 ]
    run kv frobnicate
    [ "$status" -ne 0 ]
}
