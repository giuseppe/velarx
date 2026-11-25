#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# certificates.sh: a swarm admitted by certificates.  Nodes 0..3 and 4 are
# signed by the swarm's CA, node 5 has the swarm key only, node 6 a
# certificate of another CA, node 7 the certificate of node 1 (another key).
# Checks that node 7 does not start, that nodes 5 and 6 are not peers of node 0, that a revoked node
# (3) is dropped by the others within 40 s, and, with libfaketime, that node
# 4, whose certificate ends EXP seconds after the start, is dropped after it.
. "$(dirname "$0")/lib.sh"
EXP=${EXP:-90}
scenario_start certificates 8 || exit 1
P=$BIN/velarx-p2p
img=$REG/certs:latest
fail=0
check () { if eval "$1"; then log "ok: $2"; else log "FAILED: $2"; fail=1; fi; }
faketime=$(ls /usr/lib*/libfaketime.so.1 /usr/lib/*/faketime/libfaketime.so.1 2> /dev/null | head -1)
# the offset is in seconds, without a unit: a suffix such as "s" is refused
# by libfaketime and the program is then not started
back=$((30 * 86400 - EXP))
if [ -z "$faketime" ]; then
    log "SKIPPED: no libfaketime, the expiry of node 4's certificate is not checked"
elif [ "$(LD_PRELOAD="$faketime" FAKETIME="-$back" date +%s 2> /dev/null)" -gt $(($(date +%s) - back + 60)) ] 2> /dev/null; then
    log "SKIPPED: libfaketime does not move the clock, the expiry of node 4's certificate is not checked"
    faketime=
fi

image certs 4 > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }
as_user "$P" ca init "$W/ca" > /dev/null
as_user "$P" ca init "$W/ca2" > /dev/null
for i in $(seq 0 7); do
    install -d -m 700 -o "$RUSER" -g "$RUSER" "$W/nodes/n$i" "$W/nodes/n$i/p2p"
    as_user "$P" ca request --identity "$W/nodes/n$i/p2p/identity.key" > "$W/nodes/n$i/request" || exit 1
done
for i in 0 1 2 3; do
    as_user "$P" ca sign --ca "$W/ca" --name "node$i" --zone z1 --days 30 -o "$W/nodes/n$i/node.crt" "$W/nodes/n$i/request" > /dev/null
done
# node 4: valid from now-30d+EXP s for 30 days
if [ -n "$faketime" ]; then
    as_user env LD_PRELOAD="$faketime" FAKETIME="-$back" \
        "$P" ca sign --ca "$W/ca" --name node4 --days 30 -o "$W/nodes/n4/node.crt" "$W/nodes/n4/request" > /dev/null || exit 1
else
    as_user "$P" ca sign --ca "$W/ca" --name node4 --days 30 -o "$W/nodes/n4/node.crt" "$W/nodes/n4/request" > /dev/null
fi
expires=$(($(date +%s) + EXP))
as_user "$P" ca sign --ca "$W/ca2" --name rogue6 -o "$W/nodes/n6/node.crt" "$W/nodes/n6/request" > /dev/null
cp "$W/nodes/n1/node.crt" "$W/nodes/n7/node.crt"
chown "$RUSER:" "$W/nodes/n7/node.crt"
# the first revocation list (a key no node has)
as_user "$P" ca revoke --ca "$W/ca" 12D3KooWPhpGGnTyUNmTMdAs27G6hUKMjt8bEuUYHVXcwMiskdNC > /dev/null
for i in 0 1 2 3 4 6 7; do
    cat > "$W/n$i.ca.toml" <<EOT
ca_path = "$W/ca/ca.crt"
certificate_path = "$W/nodes/n$i/node.crt"
identity_path = "$W/nodes/n$i/p2p/identity.key"
ca_sweep_secs = 10
EOT
done
# nodes 0, 1, 4 and 7 read the list; 2 and 3 have only what their peers pass on
for i in 0 1 4 7; do printf 'revocation_path = "%s"\n' "$W/ca/revoked" >> "$W/n$i.ca.toml"; done
sed -i "s|ca/ca.crt|ca2/ca.crt|" "$W/n6.ca.toml"
printf 'identity_path = "%s"\n' "$W/nodes/n5/p2p/identity.key" > "$W/n5.ca.toml"
chown "$RUSER:" "$W"/n?.ca.toml
for i in 0 1 2 3 4 6; do NOKEY=1 node "$i" "$W/n$i.ca.toml" > "$OUT/start-$i.log" 2>&1 || { log "FAILED: node $i did not start"; fail=1; }; done
check "! NOKEY=1 node 7 $W/n7.ca.toml > $OUT/start-7.log 2>&1" "node 7, with the certificate of another key, does not start"
node 5 "$W/n5.ca.toml" > "$OUT/start-5.log" 2>&1 || { log "FAILED: node 5 did not start"; fail=1; }
v 0 image pull --tls-verify=false "$img" > "$OUT/pull-0.log" 2>&1
sleep 8
peers_of () { p "$1" peers 2> /dev/null | grep -oE '"peer_id": "[^"]+"' | cut -d'"' -f4; }
for i in 5 6; do
    check "! peers_of 0 | grep -q $(cat "$W/nodes/n$i/peerid")" "node $i, not admitted, is not a peer of node 0"
done
for i in 1 2; do
    check "peers_of 0 | grep -q $(cat "$W/nodes/n$i/peerid")" "node $i is a peer of node 0"
done
# revoke node 3 (and node 4 is there to expire)
check "peers_of 0 | grep -q $(cat "$W/nodes/n3/peerid")" "node 3 is a peer of node 0 before it is revoked"
check "peers_of 0 | grep -q $(cat "$W/nodes/n4/peerid")" "node 4 is a peer of node 0 before its certificate ends"
as_user "$P" ca revoke --ca "$W/ca" "$(cat "$W/nodes/n3/peerid")" > "$OUT/revoke.log" 2>&1
gone () {  # ID NODES...: none of the nodes has the peer, within 40 s
    local id=$1 j; shift
    for _ in $(seq 40); do
        for j in "$@"; do peers_of "$j" | grep -q "$id" && { sleep 1; continue 2; }; done
        return 0
    done
    return 1
}
check "gone $(cat "$W/nodes/n3/peerid") 0 1 2 4" "node 3, revoked, is dropped within 40 s"
if [ -n "$faketime" ]; then
    now=$(date +%s)
    [ $now -lt $expires ] && sleep $((expires - now))
    check "gone $(cat "$W/nodes/n4/peerid") 0 1 2" "node 4, its certificate ended, is dropped within 40 s"
fi
exit $fail
