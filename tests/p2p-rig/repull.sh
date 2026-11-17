#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# repull.sh [-m MB_LAYER1[,MB_LAYER2]] [-k PULLS]: one honest puller pulls an
# image from a seed, removes it, prunes and pulls it again, PULLS times in a
# row: every pull must come from the peer, none from the registry (a node does
# not ration what a member asks for).  Prints the share of the peers in each
# pull.  Defaults: two layers of 40 MB, 6 pulls.
. "$(dirname "$0")/lib.sh"
mb=40,40 pulls=6
while getopts m:k: o; do
    case $o in m) mb=$OPTARG ;; k) pulls=$OPTARG ;; *) exit 2 ;; esac
done
scenario_start repull 2 || exit 1
img=$REG/repull:latest
image repull ${mb//,/ } > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }
node 0 || exit 1
v 0 image pull --tls-verify=false "$img" > "$OUT/seed-pull.log" 2>&1
node 1 || exit 1
for _ in $(seq 30); do [ "$(p 1 peers 2> /dev/null | grep -c '"peer_id"')" -gt 0 ] && break; sleep 1; done
fail=0
for run in $(seq "$pulls"); do
    v 1 image pull --tls-verify=false "$img" > "$OUT/pull-$run.log" 2>&1
    rc=$?
    log "pull $run: rc=$rc $(grep -o 'Total:.*' "$OUT/pull-$run.log")"
    [ $rc = 0 ] || fail=1
    grep -q ' 100.0% registry' "$OUT/pull-$run.log" && fail=1
    v 1 image rm "$img" > /dev/null 2>&1
    v 1 image prune -a -f > /dev/null 2>&1
done
p 0 serving > "$OUT/serving.txt" 2>&1
exit $fail
