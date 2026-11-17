#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# overlay.sh: two nodes, each with the content service (velarx-p2p)
# and the overlay node (velarx-p2p overlay, root, a swarm of its own on port
# 4002), and a container on each, made through the calls of the network
# provider.  Checks that the containers ping and that TCP brings 8 MiB over
# the tunnel.  The two swarms are apart: the content nodes are not peers of
# the overlay ones.  The engines (root: they move the provider's veth into a container) run a
# container of a static busybox on each node (`--network provider:overlay`):
# the one of node 1 resolves the name of the one of node 0 and fetches a file
# of its HTTP server.
RIG_USER=root
. "$(dirname "$0")/lib.sh"
BUSYBOX=$(command -v busybox) || { echo "no busybox (static) in PATH" >&2; exit 2; }
scenario_start overlay 2 || exit 1
fail=0
check () { if eval "$1"; then log "ok: $2"; else log "FAILED: $2"; fail=1; fi; }
ctx=$W/ctx-bb
install -d "$ctx"
install -m 755 "$BUSYBOX" "$ctx/busybox"
printf 'FROM scratch\nCOPY busybox /bin/busybox\n' > "$ctx/Containerfile"
NOP2P=1 node b > /dev/null 2>&1
{ v b build -f "$ctx/Containerfile" -t localhost/bb:latest "$ctx" &&
    v b image push --tls-verify=false localhost/bb:latest "$REG/bb:latest"; } > "$OUT/build-bb.log" 2>&1 ||
    { echo "the busybox image is not built, see $OUT/build-bb.log" >&2; exit 1; }
stop_node b
for i in 0 1; do
    printf '[[network.providers]]\nname = "overlay"\nsocket = "%s"\n' "$W/ovl/n$i/p2p-network.sock" > "$W/provider-$i.toml"
done
ENGINE_EXTRA=$W/provider-0.toml node 0 || exit 1
ENGINE_EXTRA=$W/provider-1.toml node 1 || exit 1
overlay_node 0 && overlay_node 1 || exit 1
overlay_container 0 && overlay_container 1 || exit 1
c0=$(cat "$W/ovl/n0/cip") c1=$(cat "$W/ovl/n1/cip")
log "containers: c0=$c0 c1=$c1"
inc () { ip netns exec "${NSP}-c$1" "${@:2}"; }
ok=
for _ in $(seq 30); do inc 0 ping -c 1 -W 1 "$c1" > /dev/null 2>&1 && { ok=1; break; }; done
check "[ -n \"$ok\" ]" "the containers ping over the tunnel (the overlay nodes found each other)"
tcp () {
    ip netns exec ${NSP}-c1 python3 -I -c 'import socket;s=socket.socket();s.setsockopt(1,2,1);s.bind(("0.0.0.0",5001));s.listen(1);c,_=s.accept();n=0
while True:
    d=c.recv(65536)
    if not d: break
    n+=len(d)
print(n)' > "$OUT/tcp.out" &
    sleep 1
    inc 0 python3 -I -c "import socket;c=socket.create_connection(('$c1',5001),timeout=10);c.sendall(b'x'*(8<<20));c.close()"
    wait
}
tcp
check "[ \"\$(cat $OUT/tcp.out)\" = 8388608 ]" "TCP brings 8 MiB between the containers"
check "p 0 peers | grep -q $(cat "$W/nodes/n1/peerid")" "the content nodes are peers of each other"
check "! p 0 peers | grep -q $(cat "$W/ovl/n1/peerid")" "the overlay node is not a peer of the content node"
bb () { local i=$1; shift; v "$i" --remote run --network provider:overlay --tls-verify=false "$@"; }
veths () { ip -n "${NSP}-n0" -o link show type veth | wc -l; }
before=$(veths)
bb 0 -d --name web0 "$REG/bb:latest" /bin/busybox httpd -f -p 8080 -h /bin > "$OUT/web0.log" 2>&1
bb 1 --rm "$REG/bb:latest" /bin/busybox wget -qO /dev/null -T 10 http://web0:8080/busybox > "$OUT/cli1.log" 2>&1
check "[ $? = 0 ]" "a container of the engine of node 1 fetches a file of the one of node 0 by its name"
v 0 --remote rm -f -t 0 web0 > /dev/null 2>&1
check "[ \$(veths) = $before ]" "the veth of a removed container is gone"
for i in 0 1; do
    check "! grep -q 'ERROR' $W/ovl/n$i/overlay.log" "no error in the log of the overlay node $i"
    check "[ \"\$(grep -E '^CapEff' /proc/\$(cat $W/nodes/n$i/p2p.pid)/status | awk '{print \$2}')\" = 0000000000000000 ]" "the content service of node $i has no capability"
done
exit $fail
