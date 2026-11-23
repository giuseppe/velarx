#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2034  # (D and BIN of a, b and c are host-node.sh's)
# two-hosts.sh B_HOST [bench [N]]: velarx-p2p between two real hosts: node A here (as the
# caller), node B on B_HOST (`ssh B_HOST`, as the user of the login), each
# with its config.toml (`[[sources.external]] name = "p2p"` with its
# settings: a swarm key, B's bootstrap peer A's address without a peer id;
# `[pull] sources = ["p2p", "registry"]`).  What it checks, with the times:
#
#   - an image pulled on A after its service started is announced, and B
#     pulls it lazily by digest from A with no registry (B's HTTPS blocked)
#   - run --lazy by digest with no registry, by tag with it; again: no pull
#   - the background completion of B comes from A
#   - a gzip image, eagerly by digest, from the peer with no registry
#   - the other way: B pulls, A takes it from B
#   - the services killed and started again: B still finds A's images
#   - a node C on this host with a damaged copy of an image, and A with a
#     good one: B's pull takes what checks out
#
# Needs: velarx, velarx-p2p, velarx-monitor and velarx-registry in VELARX_BINDIR here (default
# target/release), the same built for B's libc in B_BINDIR on B (default
# /var/tmp/two-hosts/bin); A_IP (default: the address that routes to B);
# TCP and UDP PORT and PORT + 1 open on A, PORT on B (`firewall-cmd
# --add-port=4001/tcp --add-port=4001/udp`); on B `firewall-cmd --direct`
# (it blocks B's HTTPS for a while, to make the registry unreachable).
# Images: IMG (zstd:chunked, default docker.io/gscrivano/zstd-chunked:nginx),
# GZ and GZ2 (gzip, default docker.io/library/alpine and
# docker.io/library/nginx).  The nodes are in /var/tmp/two-hosts on both
# hosts, removed at the end (KEEP=1 keeps them).  PORT (default 4001) is the
# port of A and B, PORT + 1 the one of C.
#
# `bench [N]`: A seeds IMG once (a complete pull); then N times (default 10)
# B starts cold: its node directory emptied but for the swarm key (no store,
# no database, no manifest, tag or signature kept, nothing of an earlier
# run), `[pull] sources = ["p2p"]`, its HTTPS blocked; it runs
# `velarx-client run --rm --lazy REF echo hello` (REF: IMG by its digest),
# timed from before the process starts to its exit, then the same again on
# that store (warm).  Prints the median, min and max of both, the stages of
# the cold run from B's trace (metadata: manifest to probed, verify: probed
# to tables verified, pull: start to end, run: the rest), and the packets B
# sent to port 443 during the runs (the counter of the rule that blocks
# them: 0 is p2p only).
set -u
B=${1:?usage: two-hosts.sh B_HOST [bench [N]]}
MODE=${2:-}
N=${3:-10}
PORT=${PORT:-4001}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BIN=$(realpath "${VELARX_BINDIR:-$HERE/../../target/release}")
B_BINDIR=${B_BINDIR:-/var/tmp/two-hosts/bin}
IMG=${IMG:-docker.io/gscrivano/zstd-chunked:nginx}
GZ=${GZ:-docker.io/library/alpine:latest}
GZ2=${GZ2:-docker.io/library/nginx:latest}
W=/var/tmp/two-hosts
B_IP=$(ssh "$B" hostname -I | awk '{print $1}')
A_IP=${A_IP:-$(ip -o route get "$B_IP" | sed -n 's/.* src \([0-9.]*\).*/\1/p')}
fail=0
log () { echo "[$(date +%T)] $*"; }
check () { if eval "$2"; then log "ok: $1"; else log "FAIL: $1"; fail=1; fi; }
# a: node A; c: node C (this host too); b: node B, over ssh
a () { (D=$W/a BIN=$BIN; . "$HERE/host-node.sh"; "$@"); }
c () { (D=$W/c BIN=$BIN; . "$HERE/host-node.sh"; "$@"); }
b () { ssh "$B" "D=$W/b BIN=$B_BINDIR TRACE=${TRACE:-} SOURCES=$(printf '%q' "${SOURCES:-}"); . $W/host-node.sh; $(printf '%q ' "$@")"; }
b_https () { ssh "$B" "firewall-cmd -q --direct --$1-rule ipv4 filter OUTPUT 0 -p tcp --dport 443 -j DROP"; }
cleanup () {
    a stop_all; c stop_all; b stop_all
    b_https remove 2> /dev/null
    [ -n "${KEEP:-}" ] || { rm -rf "$W/a" "$W/c"; ssh "$B" "rm -rf $W/b $W/host-node.sh"; }
}
trap cleanup EXIT

mkdir -p "$W/a" "$W/c"
"$BIN/velarx-p2p" generate-key "$W/a/swarm.key" > /dev/null
cp "$W/a/swarm.key" "$W/c/swarm.key"
ssh "$B" "mkdir -p $W/b" && scp -q "$HERE/host-node.sh" "$B:$W/" && scp -q "$W/a/swarm.key" "$B:$W/b/"
a setup "$A_IP" "$PORT"
b setup "$B_IP" "$PORT" "/ip4/$A_IP/tcp/$PORT"
a eng && a p2p && b eng && b p2p || { log "the services do not start"; exit 1; }
for _ in $(seq 30); do b counters | grep -q '^peers=1' && break; sleep 1; done
check "B connects to A by its address alone" "b counters | grep -q '^peers=1'"

# 1. A pulls after its service started; B pulls it from A
t_a=$( { a t a v pull -q "$IMG" > /dev/null; } 2>&1 )
log "A pulls $IMG from the registry: $t_a"
DIG=$(a v image inspect --format '{{.Digest}}' "$IMG")
REF=${IMG%:*}@$DIG
for _ in $(seq 20); do grep -q 'Announcing [1-9][0-9]* new layers' "$W/a/p2p.log" && break; sleep 0.5; done
check "A announces the image it pulled" "grep -q 'Announcing [1-9][0-9]* new layers' $W/a/p2p.log"
sleep 3
b_https add
log "B's HTTPS blocked"
if [ "$MODE" = bench ]; then
    export TRACE=$W/b/trace SOURCES='"p2p"'
    rm -f "$W/bench.txt" "$W"/trace.*
    # (what B sent to port 443: the counter of the rule that drops it)
    https_packets () { ssh "$B" "iptables -nvxL OUTPUT | awk '/dpt:443/ {n += \$1} END {print n + 0}'"; }
    sent=$(https_packets)
    for i in $(seq "$N"); do
        b stop_all
        ssh "$B" "find $W/b -mindepth 1 ! -name swarm.key -delete"
        b setup "$B_IP" "$PORT" "/ip4/$A_IP/tcp/$PORT"
        b eng && b p2p || { log "B does not start"; exit 1; }
        for _ in $(seq 30); do b counters | grep -q '^peers=1' && break; sleep 0.5; done
        sleep 2
        b v info > /dev/null
        for kind in cold warm; do
            ms=$(b t vc run --rm --lazy --network none "$REF" echo hello 2>&1 > /dev/null |
                sed -n 's/^\([0-9]*\) ms rc=0$/\1/p')
            [ -n "$ms" ] || { log "FAIL: $kind run $i"; fail=1; }
            ssh "$B" "cat $W/b/trace; : > $W/b/trace" > "$W/trace.$kind.$i"
            echo "$kind $i ${ms:-0}" >> "$W/bench.txt"
        done
        log "run $i: $(grep " $i " "$W/bench.txt" | tr '\n' ' ')"
    done
    sent=$(( $(https_packets) - sent ))
    log "packets B sent to port 443 during the runs: $sent"
    [ "$sent" = 0 ] || { log "FAIL: B reached for a registry"; fail=1; }
    python3 -I - "$W" << 'PY'
import statistics, sys
w = sys.argv[1]
runs = [l.split() for l in open(f"{w}/bench.txt")]
def stats(v):
    return f"median {statistics.median(v):.1f} min {min(v):.1f} max {max(v):.1f} (n={len(v)})"
stages = {"metadata": [], "verify": [], "pull": [], "run": []}
for kind, i, ms in runs:
    if kind != "cold":
        continue
    pts = {}
    for line in open(f"{w}/trace.{kind}.{i}"):
        p = line.rstrip("\n").split(" ", 2)
        if len(p) == 3:
            pts.setdefault(p[2], int(p[1]))
    d = lambda a, b: (pts[b] - pts[a]) / 1e6 if a in pts and b in pts else None
    for name, a, b in [("metadata", "pull manifest", "pull probed"),
                       ("verify", "pull probed", "pull tocs verified"),
                       ("pull", "pull start", "pull end")]:
        if d(a, b) is not None:
            stages[name].append(d(a, b))
    if d("pull start", "pull end") is not None:
        stages["run"].append(float(ms) - d("pull start", "pull end"))
for kind in ("cold", "warm"):
    print(f"{kind} run --lazy ms: " + stats([float(ms) for k, _, ms in runs if k == kind]))
for name, v in stages.items():
    if v:
        print(f"  cold {name} ms: " + stats(v))
PY
    exit $fail
fi
log "B pull --lazy --sources p2p by digest: $( { b t v pull -q --lazy --sources p2p "$REF" > /dev/null; } 2>&1 )"
log "B: $(b counters)"
log "B run --lazy by digest: $( { b t v run --rm --lazy --network none "$REF" true; } 2>&1 )"
check "B gets no tag without the registry" "! b v pull -q --retry 0 --lazy '$IMG' > /dev/null 2>&1"
b_https remove
for i in 1 2 3; do log "B run --lazy by tag ($i): $( { b t v run --rm --lazy --network none "$IMG" true; } 2>&1 )"; done
for _ in $(seq 60); do [ -z "$(b v image pulls -q 2> /dev/null)" ] && break; sleep 1; done
check "B completes the image" "[ -z \"\$(b v image pulls -q)\" ]"
log "A: $(a counters)"
log "B: $(b counters)"
check "A's stats count what it served" "a p stats | grep -q '\"bytes_sent\": [1-9]'"

# 2. a gzip image, eagerly by digest, from the peer
a v pull -q "$GZ" > /dev/null
GZREF=${GZ%:*}@$(a v image inspect --format '{{.Digest}}' "$GZ")
sleep 3
b_https add
log "B pull --sources p2p of a gzip image by digest: $( { b t v pull -q --sources p2p "$GZREF" > /dev/null; } 2>&1 )"
b_https remove
check "B has the gzip image" "b v image exists '$GZREF'"

# 3. the other way: B pulls, A takes it from B
b v pull -q "$GZ2" > /dev/null
GZ2REF=${GZ2%:*}@$(b v image inspect --format '{{.Digest}}' "$GZ2")
sleep 3
log "A pull --sources p2p of B's image by digest: $( { a t v pull -q --sources p2p "$GZ2REF" > /dev/null; } 2>&1 )"
log "A: $(a counters)"

# 4. both services of both nodes killed and started again
for n in a b; do $n stop p2p KILL; $n stop engine KILL; done
a eng && a p2p && b eng && b p2p
for _ in $(seq 30); do b counters | grep -q '^peers=1' && break; sleep 1; done
check "B reconnects to A" "b counters | grep -q '^peers=1'"
b v rmi -f "$GZREF" > /dev/null
sleep 3
b_https add
log "B pull --sources p2p after the restarts: $( { b t v pull -q --sources p2p "$GZREF" > /dev/null; } 2>&1 )"
b_https remove

# 5. C has a damaged copy, A a good one: B takes what checks out
c setup "$A_IP" $((PORT + 1)) "/ip4/$A_IP/tcp/$PORT"
c eng && c v pull -q "$IMG" > /dev/null
find "$W/c/store/objects" -type f -size +100k | while read -r f; do
    chmod u+w "$f" && printf 'damaged' | dd of="$f" bs=1 seek=4096 conv=notrunc status=none
done
c p2p
b stop_all
ssh "$B" "rm -rf $W/b/store $W/b/state $W/b/root"
b setup "$B_IP" "$PORT" "/ip4/$A_IP/tcp/$PORT" "/ip4/$A_IP/tcp/$((PORT + 1))"
b eng && b p2p
for _ in $(seq 30); do b counters | grep -q '^peers=2' && break; sleep 1; done
sleep 3
b_https add
log "B pull --sources p2p with a damaged peer: $( { b t v pull -q --sources p2p "$REF" > /dev/null; } 2>&1 )"
b_https remove
log "B: $(b counters)"
check "B drops the chunks C sent wrong" "b counters | grep -q 'wrong=[1-9]'"
check "B's copy checks out" "b v image exists '$REF' && b v run --rm --network none '$REF' nginx -v"
exit $fail
