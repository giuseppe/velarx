# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2046  # (ev: the words of the environment)
# A node of two-hosts.sh on a real host: velarx and velarx-p2p in $D, with
# their own config.toml (the settings of the service in those of the source
# p2p), store and sockets.  Sourced, here and on the other host; D (the
# directory) and BIN (the binaries) may be set first.
D=${D:-/var/tmp/two-hosts/node}
BIN=${BIN:-$D/bin}
# (TRACE, when set: the file of the trace points of every process)
ev () { echo "HOME=$D/home XDG_RUNTIME_DIR=$D/run XDG_CONFIG_HOME=$D/home/.config XDG_DATA_HOME=$D/home/data PATH=$BIN:/usr/bin:/usr/sbin${TRACE:+ VELARX_TRACE_FILE=$TRACE}"; }
v () { env -i $(ev) RUST_LOG=warn "$BIN/velarx" --config "$D/config.toml" "$@"; }
vc () { env -i $(ev) RUST_LOG=warn "$BIN/velarx-client" --config "$D/config.toml" "$@"; }
p () { env -i $(ev) RUST_LOG=warn "$BIN/velarx-p2p" --config "$D/config.toml" "$@"; }
# setup LISTEN_IP PORT [BOOTSTRAP_ADDRESS...] (SOURCES: the sources of a
# pull, default "p2p", "registry")
setup () {
    local ip=$1 port=$2 boot="" b sources=${SOURCES:-'"p2p", "registry"'}
    shift 2
    mkdir -p "$D/home/.config" "$D/home/data" "$D/run" "$D/services"
    chmod 700 "$D" "$D/home" "$D/run" "$D/services"
    for b in "$@"; do boot="$boot${boot:+, }\"$b\""; done
    cat > "$D/config.toml" <<EOT
[engine]
socket = "$D/sh.sock"
[server]
socket = "$D/sh.sock"
state_dir = "$D/state"
root_dir = "$D/root"
[storage]
root = "$D/store"
[pull]
sources = [$sources]
[[sources.external]]
name = "p2p"
socket = "$D/services/p2p-fetcher.sock"
[sources.external.settings]
mdns = false
private_key_path = "$D/swarm.key"
listen_addresses = ["/ip4/$ip/tcp/$port"]
bootstrap_peers = [$boot]
socket = "$D/services/p2p.sock"
EOT
}
# run_as NAME CMD...: CMD in the background, the leader of a session of its
# own (NAME.pid), its output in NAME.log
run_as () {
    local name=$1
    shift
    setsid sh -c 'echo $$ > "$0"; exec "$@"' "$D/$name.pid" "$@" >> "$D/$name.log" 2>&1 < /dev/null &
}
# the engine, the p2p service
eng () {
    run_as engine env -i $(ev) RUST_LOG=info "$BIN/velarx" --config "$D/config.toml" varlink
    for _ in $(seq 100); do [ -S "$D/sh.sock" ] && return 0; sleep 0.1; done
    return 1
}
p2p () {
    run_as p2p env -i $(ev) RUST_LOG=info "$BIN/velarx-p2p" --config "$D/config.toml"
    for _ in $(seq 100); do [ -S "$D/services/p2p-fetcher.sock" ] && return 0; sleep 0.1; done
    return 1
}
# stop NAME [KILL]: SIGINT (or SIGKILL), then the rest of its session
stop () {
    local pid
    pid=$(cat "$D/$1.pid" 2> /dev/null) || return 0
    kill -"${2:-INT}" "$pid" 2> /dev/null
    for _ in $(seq 50); do kill -0 "$pid" 2> /dev/null || break; sleep 0.1; done
    pkill -KILL -s "$pid" 2> /dev/null
    rm -f "$D/$1.pid"
}
stop_all () { stop p2p; stop engine; }
# t CMD...: CMD, then its wall time in ms on standard error
t () {
    local s rc
    s=$(date +%s%N)
    "$@"
    rc=$?
    echo "$(( ($(date +%s%N) - s) / 1000000 )) ms rc=$rc" >&2
    return $rc
}
# what the status says: peers connected, received (from each peer), served
counters () {
    p status | python3 -I -c 'import json,sys
d=json.load(sys.stdin)
got=" ".join("%s:req=%d,fail=%d,bytes=%d,wrong=%d" % (x["peer_id"][-6:], x["requests"], x["failures"], x["bytes_received"], x["chunks_wrong"]) for x in d["peers"])
l=d["lookups"]
print("peers=%d received[%s] served=%d/%dB filter_hits=%d probes_has=%d dht_found=%d" % (d["connected_peers"], got, d["chunks_sent"], d["bytes_sent"], l["filter_hits"], l["probes_has"], l["dht_found"]))'
}
