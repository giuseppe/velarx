#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# netem.sh [-m MB] [-r RUNS] [-t SECONDS] [-u MBIT] [-l SHAPE]...: three seeds
# hold an image, a new puller pulls it from them (sources peers, registry) over
# a link shaped by each SHAPE (netem arguments, both directions, e.g.
# "delay 5ms 2ms" or "delay 25ms loss 1%"), RUNS times each, SECONDS at most.
# The QUIC connections of the peers must stay fast under jitter, reordering
# and loss; the table says how long each pull took and how much of it came
# from the peers.  -u: upload limit of the seeds in Mbit/s.  Defaults: 200 MB,
# 3 runs, 120 s, no limit, the shapes "" (none), "delay 5ms 2ms" and
# "delay 50ms 1ms".
. "$(dirname "$0")/lib.sh"
mb=200 runs=3 limit=120 up=0 shapes=()
while getopts m:r:t:u:l: o; do
    case $o in m) mb=$OPTARG ;; r) runs=$OPTARG ;; t) limit=$OPTARG ;; u) up=$OPTARG ;; l) shapes+=("$OPTARG") ;; *) exit 2 ;; esac
done
[ ${#shapes[@]} = 0 ] && shapes=("" "delay 5ms 2ms" "delay 50ms 1ms")
scenario_start netem 4 || exit 1
img=$REG/netem:latest

image netem "$mb" > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }
printf '[serving]\nupload_limit_mbit = %s\n' "$up" > "$W/serving.toml"
node 0 "$W/serving.toml" || exit 1
v 0 image pull --tls-verify=false "$img" > "$OUT/seed-pull.log" 2>&1
for i in 1 2; do
    BOOTN=0 node "$i" "$W/serving.toml" || exit 1
    v "$i" image pull --tls-verify=false "$img" > "$OUT/seed-pull-$i.log" 2>&1
done
# the puller's veth in the hub: shaping both of its ends shapes both directions
hub=v$(echo "${NSP}-n3" | tr -d -c 'a-z0-9' | tail -c 12)
n=0
for shape in "${shapes[@]}"; do
    for r in $(seq "$runs"); do
        n=$((n + 1))
        BOOTN="0 1 2" node 3 > "$OUT/start-$n.log" 2>&1 || exit 1
        for _ in $(seq 60); do
            [ "$(p 3 peers 2> /dev/null | grep -c '"peer_id"')" -ge 3 ] && break
            sleep 1
        done
        sleep 3
        if [ -n "$shape" ]; then
            read -r -a args <<< "$shape"
            tc -n "${NSP}-n3" qdisc replace dev eth0 root netem "${args[@]}" limit 100000
            tc -n "${NSP}-hub" qdisc replace dev "$hub" root netem "${args[@]}" limit 100000
        fi
        s=$(date +%s.%N)
        x 3 timeout "$limit" "$BIN/velarx" --config "$W/nodes/n3/engine.toml" image pull --tls-verify=false "$img" > "$OUT/pull-$n.log" 2>&1
        rc=$?
        w=$(echo "$(date +%s.%N) - $s" | bc)
        tc -n "${NSP}-n3" qdisc del dev eth0 root 2> /dev/null
        tc -n "${NSP}-hub" qdisc del dev "$hub" root 2> /dev/null
        log "[${shape:-none}] run $r: rc=$rc wall=${w}s $(grep -o '[0-9.]*% registry, [0-9.]*% peers' "$OUT/pull-$n.log")"
        forget_nodes 3
    done
done
