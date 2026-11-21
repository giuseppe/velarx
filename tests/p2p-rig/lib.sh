#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# The rig of the peer-to-peer layer: real velarx engines and velarx-p2p
# services, one network namespace per node, joined by a bridge in a hub
# namespace, and a registry in a namespace of its own.  What the in-process
# tests cannot show: many processes, real routing, tc shaping, processes that
# are killed or stopped.  Sourced by the scenarios of this directory:
#
#   rollout.sh       N pullers pull a new image at once (registry load, spread)
#   holder-loss.sh   the only holder dies or goes silent in the middle of a pull
#   certificates.sh  a swarm admitted by certificates: refused nodes, revocation, expiry
#   netem.sh         pulls from three seeds over links with jitter, reordering and loss (tc netem)
#   repull.sh        one honest puller pulls again and again: every pull comes from the peer
#   mute-member.sh   the only peer has a stuck store: the pull goes to the registry in seconds
#   overlay.sh       the overlay nodes (`velarx-p2p overlay`, a swarm of their own) carry the
#                    containers of two nodes
#
# Run them as root (ip netns); the nodes run as RIG_USER (default: the user
# that called sudo, else root).  Needs `registry` or `docker-registry`
# (distribution), nsenter, setpriv, tc and the binaries velarx and
# velarx-p2p in VELARX_BINDIR (default target/debug of the source tree).  RIG_DIR is the work directory (default a
# new one in /var/tmp; the nodes' stores and logs are in it, it is not deleted).
#
# Every scenario calls `rig_down` when it ends, however it ends: processes
# stopped, namespaces and mounts gone, the sysctls put back.  The rig raises
# net.ipv4.neigh.default.gc_thresh1/2/3 (the neighbour table is shared by all
# the namespaces and a full mesh of 50 nodes overflows the default 1024).
#
# Addresses: registry 10.77.0.1, builder 10.77.0.2, node I 10.77.(I/250+1).(I%250+1).
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
[ "$(id -u)" = 0 ] || { echo "the rig needs root (ip netns)" >&2; exit 2; }
BIN=$(realpath "${VELARX_BINDIR:-${CARGO_TARGET_DIR:-$TOP/target}/debug}")
for f in velarx velarx-p2p; do
    [ -x "$BIN/$f" ] || { echo "no $BIN/$f (cargo build)" >&2; exit 2; }
done
REGISTRY_BIN=$(command -v registry || command -v docker-registry) || { echo "no registry (distribution) in PATH" >&2; exit 2; }
# the names of the namespaces start with RIG_PREFIX: rigs of two users of the
# machine at once need two
NSP=${RIG_PREFIX:-rig}
RUSER=${RIG_USER:-${SUDO_USER:-root}}
W=${RIG_DIR:-$(mktemp -d /var/tmp/p2p-rig.XXXXXX)}
REG=10.77.0.1:5000
SYSCTLS="net.ipv4.neigh.default.gc_thresh1 net.ipv4.neigh.default.gc_thresh2 net.ipv4.neigh.default.gc_thresh3"

ip_of () { [ "$1" = b ] && { echo 10.77.0.2; return; }; echo "10.77.$(($1 / 250 + 1)).$(($1 % 250 + 1))"; }
ns_of () { [ "$1" = reg ] && echo ${NSP}-reg || echo "${NSP}-n$1"; }
log () { echo "[$(date +%T)] $*" | tee -a "$OUT/summary.txt"; }
as_user () { setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups "$@"; }

# the namespace NAME with the address ADDR, a port of the hub bridge
mkns () {
    local ns=$1 addr=$2 h
    h=v$(echo "$ns" | tr -d -c 'a-z0-9' | tail -c 12)
    ip netns add "$ns"
    ip link add "$h" type veth peer name eth0 netns "$ns"
    ip link set "$h" netns ${NSP}-hub
    ip -n ${NSP}-hub link set "$h" master br0 up
    ip -n "$ns" link set lo up
    ip -n "$ns" addr add "$addr/16" dev eth0
    ip -n "$ns" link set eth0 up
}

# rig_up N: the namespaces of the registry, the builder and the nodes 0..N-1
rig_up () {
    local i
    install -d -m 755 -o "$RUSER" -g "$RUSER" "$W"
    if [ ! -e "$W/sysctl.saved" ]; then
        for i in $SYSCTLS; do echo "$i $(sysctl -n "$i")"; done > "$W/sysctl.saved"
    fi
    for i in $SYSCTLS; do sysctl -qw "$i=$((($1 + 3) * ($1 + 3) * 2 + 4096))"; done
    ip netns add ${NSP}-hub
    ip -n ${NSP}-hub link add br0 type bridge
    ip -n ${NSP}-hub link set br0 up
    ip -n ${NSP}-hub link set lo up
    mkns ${NSP}-reg 10.77.0.1
    mkns ${NSP}-nb 10.77.0.2
    for i in $(seq 0 $(($1 - 1))); do mkns "${NSP}-n$i" "$(ip_of "$i")"; done
    install -d -o "$RUSER" -g "$RUSER" "$W/nodes"
    [ -f "$W/swarm.key" ] || as_user env HOME="$W" "$BIN/velarx-p2p" generate-key "$W/swarm.key" > /dev/null
}

# rig_down: stop what runs in the namespaces, delete them, put the sysctls back
rig_down () {
    local ns pid i
    trap - EXIT
    for ns in $(ip netns list | awk -v p="^$NSP-" '$0 ~ p{print $1}'); do
        for pid in $(ip netns pids "$ns"); do kill -INT "$pid" 2> /dev/null; done
    done
    sleep 2
    for ns in $(ip netns list | awk -v p="^$NSP-" '$0 ~ p{print $1}'); do
        for pid in $(ip netns pids "$ns"); do kill -KILL "$pid" 2> /dev/null; done
    done
    sleep 0.5
    for ns in $(ip netns list | awk -v p="^$NSP-" '$0 ~ p{print $1}'); do ip netns del "$ns"; done
    findmnt -rn -o TARGET | grep "^$W/" | sort -r | while read -r m; do umount -l "$m"; done
    if [ -f "$W/sysctl.saved" ]; then
        while read -r i v; do sysctl -qw "$i=$v"; done < "$W/sysctl.saved"
        rm -f "$W/sysctl.saved"
    fi
}

# the environment of node I
envof () {
    local d=$W/nodes/n$1
    echo "HOME=$d/home XDG_RUNTIME_DIR=$d/run XDG_CONFIG_HOME=$d/home/.config XDG_DATA_HOME=$d/home/data VELARX_REGISTRIES_CONF=$W/registries.conf PATH=$BIN:/usr/bin:/usr/sbin"
}
# x I CMD...: CMD as RIG_USER in the namespace of node I
x () {
    local i=$1; shift
    # shellcheck disable=SC2046
    nsenter --net=/run/netns/"$(ns_of "$i")" setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups \
        env -i $(envof "$i") RUST_LOG="${RUST_LOG:-info}" "$@"
}
v () { local i=$1; shift; x "$i" "$BIN/velarx" --config "$W/nodes/n$i/engine.toml" "$@"; }
p () { local i=$1; shift; x "$i" "$BIN/velarx-p2p" --config "$W/nodes/n$i/engine.toml" --p2p-config "$W/nodes/n$i/p2p.toml" "$@"; }

# the registry, access log in $W/registry.log (started again: empty store)
reg () {
    [ -f "$W/registry.pid" ] && { kill "$(cat "$W/registry.pid")" 2> /dev/null; sleep 1; rm -rf "$W/registry"; }
    install -d -o "$RUSER" -g "$RUSER" "$W/registry"
    cat > "$W/reg.yml" <<EOT
version: 0.1
log:
  level: info
  accesslog:
    disabled: false
storage:
  filesystem:
    rootdirectory: $W/registry
  delete:
    enabled: true
http:
  addr: $REG
EOT
    nsenter --net=/run/netns/${NSP}-reg setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups \
        setsid "$REGISTRY_BIN" serve "$W/reg.yml" >> "$W/registry.log" 2>&1 < /dev/null &
    echo $! > "$W/registry.pid"
    disown
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$REG" > "$W/registries.conf"
    chown "$RUSER:" "$W/registries.conf" "$W/reg.yml"
    for _ in $(seq 50); do ip netns exec ${NSP}-reg curl -sf "http://$REG/v2/" > /dev/null && return 0; sleep 0.2; done
    echo "the registry does not start" >&2
    return 1
}

# node I [EXTRA_P2P_TOML_FILE]: engine + p2p service, the bootstrap peers are
# the nodes of BOOTN (default 0; none for node 0 and with NOBOOT).  EXTRA is
# appended to p2p.toml.  NOP2P=1: the engine only (sources = registry).
# NOKEY=1: no swarm key (the node has a certificate).  ENGINE_EXTRA: a file
# appended to engine.toml.
node () {
    local i=$1 extra=${2:-} d=$W/nodes/n$1 boot="" a b sources='["peers", "registry"]'
    a=$(ip_of "$i")
    install -d -m 700 -o "$RUSER" -g "$RUSER" "$d" "$d/home" "$d/run" "$d/home/.config" "$d/home/data"
    [ -n "${NOP2P:-}" ] && sources='["registry"]'
    cat > "$d/engine.toml" <<EOT
[engine]
socket = "$d/sh.sock"
[server]
socket = "$d/sh.sock"
state_dir = "$d/state"
root_dir = "$d/root"
store_service = true
[storage]
root = "$d/store"
[pull]
sources = $sources
[[sources.external]]
name = "peers"
socket = "$d/services/p2p-fetcher.sock"
idle_timeout_secs = 30
EOT
    [ -n "${ENGINE_EXTRA:-}" ] && cat "$ENGINE_EXTRA" >> "$d/engine.toml"
    if [ "$i" != 0 ] && [ -z "${NOBOOT:-}" ]; then
        for b in ${BOOTN:-0}; do
            boot="$boot${boot:+, }\"/ip4/$(ip_of "$b")/tcp/4001/p2p/$(cat "$W/nodes/n$b/peerid")\""
        done
    fi
    {
        echo 'mdns = false'
        [ -z "${NOKEY:-}" ] && echo "private_key_path = \"$W/swarm.key\""
        echo "listen_addresses = [\"/ip4/$a/tcp/4001\"]"
        echo "bootstrap_peers = [$boot]"
        echo "socket = \"$d/services/p2p.sock\""
        [ -n "$extra" ] && cat "$extra"
    } > "$d/p2p.toml"
    chown "$RUSER:" "$d/engine.toml" "$d/p2p.toml"
    # shellcheck disable=SC2046
    nsenter --net=/run/netns/"$(ns_of "$i")" setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups \
        env -i $(envof "$i") RUST_LOG=info setsid "$BIN/velarx" --config "$d/engine.toml" varlink \
        >> "$d/engine.log" 2>&1 < /dev/null &
    echo $! > "$d/engine.pid"
    disown
    for _ in $(seq 100); do [ -S "$d/sh.sock" ] && break; sleep 0.1; done
    [ -n "${NOP2P:-}" ] && return 0
    # shellcheck disable=SC2046
    nsenter --net=/run/netns/"$(ns_of "$i")" setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups \
        env -i $(envof "$i") RUST_LOG="${P2P_LOG:-info}" setsid "$BIN/velarx-p2p" --config "$d/engine.toml" --p2p-config "$d/p2p.toml" \
        >> "$d/p2p.log" 2>&1 < /dev/null &
    echo $! > "$d/p2p.pid"
    disown
    for _ in $(seq 300); do grep -q 'Chunk provider set' "$d/p2p.log" 2> /dev/null && break; sleep 0.1; done
    grep -oE 'P2P node 12D3KooW[A-Za-z0-9]+ started' "$d/p2p.log" | cut -d' ' -f3 | tail -1 > "$d/peerid"
    grep -q 'Chunk provider set' "$d/p2p.log" || { echo "node $i: p2p not ready" >&2; tail -5 "$d/p2p.log" >&2; return 1; }
}

# stop_node I: SIGINT, then SIGKILL; the node's directory goes with forget_node
stop_node () {
    local i=$1 f pid
    for f in p2p engine; do
        pid=$(cat "$W/nodes/n$i/$f.pid" 2> /dev/null) || continue
        kill -INT "$pid" 2> /dev/null
        for _ in $(seq 50); do kill -0 "$pid" 2> /dev/null || break; sleep 0.1; done
        kill -KILL "$pid" 2> /dev/null
        rm -f "$W/nodes/n$i/$f.pid"
    done
}
forget_nodes () { local i; for i in "$@"; do stop_node "$i"; rm -rf "${W:?}/nodes/n$i"; done; }
# signal_node I SIG: a signal to every process of the node (KILL, STOP, CONT)
signal_node () { local f; for f in p2p engine; do pkill -"$2" -s "$(cat "$W/nodes/n$1/$f.pid")" 2> /dev/null; done; true; }

# cpu ticks and peak/current rss (kB) of the engine and p2p trees of node I
res () {
    local i=$1 f pid all q s t hwm rss
    for f in engine p2p; do
        pid=$(cat "$W/nodes/n$i/$f.pid" 2> /dev/null) || continue
        all=$(pgrep -s "$pid" | tr '\n' ' ')
        t=0 hwm=0 rss=0
        for q in $all; do
            s=$(cut -d' ' -f14-17 "/proc/$q/stat" 2> /dev/null) || continue
            # shellcheck disable=SC2086
            set -- $s; t=$((t + $1 + $2 + $3 + $4))
            hwm=$((hwm + $(awk '/VmHWM/{print $2}' "/proc/$q/status" 2> /dev/null || echo 0)))
            rss=$((rss + $(awk '/VmRSS/{print $2}' "/proc/$q/status" 2> /dev/null || echo 0)))
        done
        echo "$f ticks=$t hwm_kb=$hwm rss_kb=$rss procs=$(echo "$all" | wc -w)"
    done
}

# image NAME MB_LAYER1 [MB_LAYER2 ...]: build an image of random files (a
# layer for each argument, files of 1..8 MiB) on the builder and push it as
# zstd:chunked to the registry as $REG/NAME:latest.
image () {
    local name=$1 ctx cf="FROM scratch" l=0 mb left k sz
    shift
    ctx=$W/ctx-$name
    install -d -o "$RUSER" -g "$RUSER" "$ctx"
    for mb in "$@"; do
        l=$((l + 1))
        mkdir -p "$ctx/l$l"
        left=$((mb * 1024 * 1024)) k=0
        while [ $left -gt 0 ]; do
            sz=$(((RANDOM % 8 + 1) * 1024 * 1024))
            [ $sz -gt $left ] && sz=$left
            head -c $sz /dev/urandom > "$ctx/l$l/f$k"
            left=$((left - sz)) k=$((k + 1))
        done
        cf="$cf
COPY l$l /l$l"
    done
    echo "$cf" > "$ctx/Containerfile"
    chown -R "$RUSER:" "$ctx"
    NOP2P=1 node b > /dev/null 2>&1
    v b build -f "$ctx/Containerfile" -t "localhost/$name:latest" "$ctx" &&
        v b image push --tls-verify=false --compression-format zstd:chunked "localhost/$name:latest" "$REG/$name:latest"
    local rc=$?
    stop_node b
    rm -rf "$ctx" "$W/nodes/nb"
    return $rc
}

# scenario_start NAME NODES: the output directory, the namespaces; the end of
# the scenario (or a signal) takes everything down
scenario_start () {
    OUT=$W/results/$1
    rm -rf "$OUT" "${W:?}/nodes" "$W/ovl"
    mkdir -p "$OUT"
    chown "$RUSER:" "$W/results" "$OUT" 2> /dev/null
    trap rig_down EXIT
    trap 'exit 130' INT TERM
    rig_up "$2" && reg
}

# overlay_node I: the overlay node of node I, as root, in the directory
# ovl/nI (root-owned: the node has no capability to enter the directories of
# RIG_USER once confined), with the overlay address 10.77.x.y:4002; it
# bootstraps from the overlay node 0, whose peer id is in ovl/n0/peerid.  The
# content service of node I (made with `node`) is not needed.
overlay_node () {
    local i=$1 o=$W/ovl/n$1 boot=""
    install -d -m 755 "$W/ovl"
    install -d -m 700 "$o"
    install -m 600 "$W/swarm.key" "$o/swarm.key"
    [ "$i" != 0 ] && boot="\"/ip4/$(ip_of 0)/tcp/4002/p2p/$(cat "$W/ovl/n0/peerid")\""
    cat > "$o/engine.toml" <<EOT
[server]
socket = "$o/sh.sock"
state_dir = "$o/state"
root_dir = "$o/root"
[storage]
root = "$o/store"
EOT
    cat > "$o/p2p.toml" <<EOT
private_key_path = "$o/swarm.key"
socket = "$o/p2p.sock"
[overlay]
listen_addresses = ["/ip4/$(ip_of "$i")/tcp/4002"]
bootstrap_peers = [$boot]
EOT
    nsenter --net=/run/netns/"$(ns_of "$i")" env -i PATH="$BIN:/usr/bin:/usr/sbin" RUST_LOG="${P2P_LOG:-info}" \
        setsid "$BIN/velarx-p2p" --config "$o/engine.toml" --p2p-config "$o/p2p.toml" overlay \
        >> "$o/overlay.log" 2>&1 < /dev/null &
    echo $! > "$o/overlay.pid"
    disown
    for _ in $(seq 100); do grep -q 'TUN overlay network initialized' "$o/overlay.log" 2> /dev/null && break; sleep 0.1; done
    grep -q 'TUN overlay network initialized' "$o/overlay.log" || { echo "node $i: overlay not ready" >&2; tail -5 "$o/overlay.log" >&2; return 1; }
    grep -oE 'P2P overlay node 12D3KooW[A-Za-z0-9]+ started' "$o/overlay.log" | cut -d' ' -f4 | tail -1 > "$o/peerid"
}

# overlay_container I: a container (the namespace NSP-cI) on the overlay of
# node I, made through the calls of the network provider as the engine makes
# them; its address is in ovl/nI/cip
overlay_container () {
    local i=$1 id host name ip call
    id=$(printf '%02x' "$i")abcdef0123abcdef01
    call () { python3 -I "$HERE/network-call.py" "$W/ovl/n$i/p2p-network.sock" "$@"; }
    ip netns add "${NSP}-c$i"
    ip -n "${NSP}-c$i" link set lo up
    read -r host name < <(call org.velarx.Network.Prepare "{\"id\":\"$id\"}" |
        python3 -I -c 'import json,sys;d=json.load(sys.stdin)["parameters"]["devices"][0];print(d["host"],d["container"])')
    ip=$(ip -n "$(ns_of "$i")" -o -4 addr show dev "$host" | awk '{print $4}')
    ip -n "$(ns_of "$i")" link set "$host" netns "${NSP}-c$i" name "$name"
    ip -n "${NSP}-c$i" addr add "$ip" dev "$name"
    call org.velarx.Network.Start "{\"id\":\"$id\",\"name\":\"c$i\",\"default_route\":true}" "/run/netns/${NSP}-c$i" > /dev/null
    echo "${ip%/*}" > "$W/ovl/n$i/cip"
}
