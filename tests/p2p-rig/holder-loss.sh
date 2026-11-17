#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# holder-loss.sh: the only holder of an image dies (SIGKILL) or goes silent
# (SIGSTOP) in the middle of a transfer to another node (its link is 200
# Mbit/s so that the pull takes a while): the pull must end, from the
# registry, and not hang.  Prints the outcome of each case; the pull ends in
# 300 s at most.
. "$(dirname "$0")/lib.sh"
scenario_start holder-loss 2 || exit 1
img=$REG/holder:latest
image holder 300 > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }
fail=0
case1 () {  # TAG SIGNAL
    local tag=$1 sig=$2 s rc
    forget_nodes 0 1
    node 0 > /dev/null 2>&1
    v 0 image pull --tls-verify=false "$img" > /dev/null 2>&1
    tc -n ${NSP}-n0 qdisc replace dev eth0 root tbf rate 200mbit burst 256k latency 100ms
    node 1 > /dev/null 2>&1
    sleep 3
    ( sleep 3; signal_node 0 "$sig"; log "$sig to the only holder n0" ) &
    s=$(date +%s.%N)
    x 1 timeout 300 "$BIN/velarx" --config "$W/nodes/n1/engine.toml" image pull --tls-verify=false "$img" > "$OUT/pull-$tag.log" 2>&1
    rc=$?
    wait
    signal_node 0 CONT
    tc -n ${NSP}-n0 qdisc del dev eth0 root
    log "$tag: rc=$rc wall=$(printf %.1f "$(echo "$(date +%s.%N) - $s" | bc)")s $(grep -o 'Total:.*' "$OUT/pull-$tag.log")"
    [ $rc = 0 ] || fail=1
    grep -E "WARN|ERROR|left to the next source" "$W/nodes/n1/p2p.log" | cut -c1-230 | head -20 > "$OUT/p2p-$tag.txt"
}
case1 kill-only-holder KILL
case1 sigstop-only-holder STOP
exit $fail
