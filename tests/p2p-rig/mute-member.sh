#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# mute-member.sh [-m MB_LAYER1[,MB_LAYER2]]: the only peer of a puller is a
# member whose store is stuck (it answers the handshakes and no request for
# data; `cargo build --example mute-member`).  The pull must end from the
# registry in seconds (under 15), and the second pull must not ask the peer
# again.  Prints the wall time of two pulls (the registry alone takes well
# under a second).  Defaults: two layers of 60 MB.
. "$(dirname "$0")/lib.sh"
mb=60,60
while getopts m: o; do
    case $o in m) mb=$OPTARG ;; *) exit 2 ;; esac
done
scenario_start mute-member 2 || exit 1
MUTE=$BIN/examples/mute-member
[ -x "$MUTE" ] || { echo "no $MUTE (cargo build --example mute-member -p velarx-p2p)" >&2; exit 2; }
img=$REG/mute:latest
image mute ${mb//,/ } > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }
install -d -o "$RUSER" -g "$RUSER" "$W/nodes/n0"
nsenter --net=/run/netns/"$(ns_of 0)" setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups \
    env -i RUST_LOG=info setsid "$MUTE" "$W/swarm.key" "$(ip_of 0)" > "$W/nodes/n0/mute.log" 2>&1 < /dev/null &
disown
for _ in $(seq 100); do grep -q '^mute member' "$W/nodes/n0/mute.log" && break; sleep 0.1; done
awk '/^mute member/{print $3}' "$W/nodes/n0/mute.log" > "$W/nodes/n0/peerid"
node 1 || exit 1
for _ in $(seq 30); do [ "$(p 1 peers 2> /dev/null | grep -c '"peer_id"')" -gt 0 ] && break; sleep 1; done
fail=0
for run in 1 2; do
    s=$(date +%s.%N)
    v 1 image pull --tls-verify=false "$img" > "$OUT/pull-$run.log" 2>&1
    rc=$?
    wall=$(printf %.1f "$(echo "$(date +%s.%N) - $s" | bc)")
    log "pull $run: rc=$rc wall=${wall}s $(grep -o 'Total:.*' "$OUT/pull-$run.log")"
    [ $rc = 0 ] && [ "${wall%.*}" -lt 15 ] || fail=1
    v 1 image rm "$img" > /dev/null 2>&1
    v 1 image prune -a -f > /dev/null 2>&1
done
p 1 explain > "$OUT/explain.txt" 2>&1
exit $fail
