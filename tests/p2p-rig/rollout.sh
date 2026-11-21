#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# rollout.sh [-n PULLERS] [-m MB_LAYER1[,MB_LAYER2]] [-s NETEM]: a new image
# lands on N nodes at once; node 0 has it (pulled from the registry), the
# others pull it with sources p2p, registry.  Reports how the pulls were
# fed (registry share, load of the registry, spread over the peers); see
# analyze.py.  Links of 1 Gbit/s; -s shapes the registry's egress (netem
# arguments, e.g. "delay 10ms").  Defaults: 8 pullers, layers of 20 and 5 MB.
. "$(dirname "$0")/lib.sh"
n=8 mb=20,5 shape="delay 10ms"
while getopts n:m:s: o; do
    case $o in n) n=$OPTARG ;; m) mb=$OPTARG ;; s) shape=$OPTARG ;; *) exit 2 ;; esac
done
scenario_start rollout "$((n + 1))" || exit 1
img=$REG/rollout:latest

image rollout ${mb//,/ } > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }
node 0 || exit 1
v 0 image pull --tls-verify=false "$img" > "$OUT/seed-pull.log" 2>&1
# the pullers start in batches of 10
for i in $(seq 1 "$n"); do
    node "$i" > "$OUT/start-$i.log" 2>&1 &
    [ $((i % 10)) = 0 ] && wait
done
wait
# every puller has a peer (60 s at most)
for _ in $(seq 60); do
    lonely=0
    for i in $(seq 1 "$n"); do
        [ "$(p "$i" peers 2> /dev/null | grep -c '"peer_id"')" -gt 0 ] || lonely=$((lonely + 1))
    done
    [ $lonely = 0 ] && break
    sleep 1
done
log "pullers without a peer before the pull: $lonely"
sleep 5
tc -n ${NSP}-reg qdisc add dev eth0 root handle 1: netem $shape limit 100000
for i in $(seq 0 "$n"); do tc -n "${NSP}-n$i" qdisc replace dev eth0 root tbf rate 1gbit burst 1m latency 300ms; done
for i in $(seq 0 "$n"); do res "$i" > "$OUT/res-before-$i.txt"; done
L=$(wc -l < "$W/registry.log")
t0=$(date +%s.%N)
for i in $(seq 1 "$n"); do
    ( s=$(date +%s.%N)
      v "$i" image pull --tls-verify=false "$img" > "$OUT/pull-$i.log" 2>&1
      echo "rc=$? wall=$(echo "$(date +%s.%N) - $s" | bc)" >> "$OUT/pull-$i.log" ) &
done
wait
t1=$(date +%s.%N)
tail -n +$((L + 1)) "$W/registry.log" > "$OUT/registry.log"
for i in $(seq 0 "$n"); do res "$i" > "$OUT/res-after-$i.txt"; p "$i" stats > "$OUT/stats-$i.json" 2> /dev/null; done
log "all pulls done in $(echo "$t1 - $t0" | bc) s"
python3 -I "$HERE/analyze.py" "$OUT" "$n" | tee "$OUT/analysis.txt"
