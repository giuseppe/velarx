# SPDX-License-Identifier: Apache-2.0
# Two nodes of a swarm (a daemon and a P2P service each), rootless: node A has
# pulled an image; node B pulls it lazily and its container reads files of it.
# The files come from A (its P2P service sends chunks), in a window after the
# first miss, and the first container leaves a startup profile that the second
# one finds.  A third node, C, without a profile of the image, gets the one of
# a peer for its first container.  Nodes announce nothing by default and the
# peers find what they have in each other's filter of layers (node A tells
# one); node D, with `announce_images`, announces its images too.  Needs `velarx-p2p`, curl and a registry
# with an image for the lazy pull.
#
# What a test learns for the next ones (the peer id of node A, the profile of
# B) is in $WORKDIR/state; the pids of the nodes' processes in $WORKDIR/pids.
#
#   VELARX_BINDIR=target/debug E2E_IMAGE=image bats tests/e2e/bats/lazy-peers.bats
#
# LAZY_DIGEST=sha512 makes the image one of sha512 digests first (a build
# --digest sha512 --squash-all of it), and the nodes pull that.

load helpers

PORT_A=${E2E_PEERS_PORT:-4311}

setup_file () {
    [ -x "${BIN:-${VELARX_BINDIR:-target/debug}}/velarx-p2p" ] ||
        skip "no velarx-p2p (build with cargo build -p velarx-p2p-bin)"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    "$BIN/velarx-p2p" generate-key "$WORKDIR/swarm.key" > /dev/null
    export IMAGE=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}

    # Only the layers whose TOCs give the fs-verity digests of their files,
    # which the layer writer gives and containers/storage does not, stay lazy
    # (the others are refused): the image is pushed again by velarx
    # (gzip, and back as zstd:chunked) from a node of its own
    # (LAZY_IMAGE_SEALED=1: it has them already)
    if [ -z "${LAZY_IMAGE_SEALED:-}" ]; then
        node s $((PORT_A + 3))
        local sealed=$E2E_REGISTRY/velarx-e2e/lazy-peers-$$
        { sh_ s image pull --tls-verify=false "$IMAGE" &&
          sh_ s image push --tls-verify=false --compression-format gzip "$IMAGE" "$sealed:gzip" &&
          sh_ s image pull --tls-verify=false "$sealed:gzip" &&
          sh_ s image push --tls-verify=false --compression-format zstd:chunked "$sealed:gzip" "$sealed:zstd"
        } > "$WORKDIR/seal.log" 2>&1 || { echo "cannot make the image"; cat "$WORKDIR/seal.log"; exit 1; }
        IMAGE=$sealed:zstd
    fi

    # Two versions of one big file in two images (the second one changes 16
    # bytes in the middle of it), as zstd:chunked layers of the fs-verity
    # digests: a node that pulled both has the chunks of the first in the file
    # of the second
    if [ -z "${E2E_NO_VERSIONS:-}" ]; then
        [ -n "${LAZY_IMAGE_SEALED:-}" ] && node s $((PORT_A + 3))
        local ctx=$WORKDIR/ctx-versions
        mkdir -p "$ctx"
        head -c 3145728 /dev/urandom > "$ctx/big.bin"
        cp "$ctx/big.bin" "$ctx/big2.bin"
        head -c 16 /dev/urandom | dd of="$ctx/big2.bin" bs=1 seek=1572864 conv=notrunc status=none
        printf 'FROM %s\nCOPY big.bin /data/big.bin\n' "$IMAGE" > "$ctx/Containerfile.1"
        printf 'FROM %s\nCOPY big2.bin /data/big.bin\n' "$IMAGE" > "$ctx/Containerfile.2"
        VERSIONS=$E2E_REGISTRY/velarx-e2e/lazy-peers-versions-$$
        { sh_ s build -f "$ctx/Containerfile.1" -t localhost/versions:1 "$ctx" &&
          sh_ s build -f "$ctx/Containerfile.2" -t localhost/versions:2 "$ctx" &&
          sh_ s image push --tls-verify=false --compression-format zstd:chunked localhost/versions:1 "$VERSIONS:1" &&
          sh_ s image push --tls-verify=false --compression-format zstd:chunked localhost/versions:2 "$VERSIONS:2"
        } > "$WORKDIR/versions.log" 2>&1 || { echo "cannot make the versions"; cat "$WORKDIR/versions.log"; exit 1; }
        export VERSIONS
    fi

    # LAZY_DIGEST=sha512: the same files as an image of sha512 digests (one
    # zstd:chunked layer, its TOC and chunks sha512), which the nodes pull as
    # NAME:TAG@sha512:D, and the peers send the sha512 chunks of
    if [ "${LAZY_DIGEST:-}" = sha512 ]; then
        [ -z "${LAZY_IMAGE_SEALED:-}" ] || { node s $((PORT_A + 3)); sh_ s image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1; }
        local big=$E2E_REGISTRY/velarx-e2e/lazy-peers-512-$$
        mkdir -p "$WORKDIR/ctx512"
        printf 'FROM %s\n' "$IMAGE" > "$WORKDIR/ctx512/Containerfile"
        { sh_ s build --digest sha512 --squash-all -t localhost/lazy512:1 "$WORKDIR/ctx512" &&
          sh_ s image push --tls-verify=false --compression-format zstd:chunked localhost/lazy512:1 "$big:zstd"
        } > "$WORKDIR/seal512.log" 2>&1 || { echo "cannot make the sha512 image"; cat "$WORKDIR/seal512.log"; exit 1; }
        IMAGE=$big:zstd@$(sh_ s image inspect --format '{{.Digest}}' localhost/lazy512:1)
        check_match "the image is a sha512 one" '@sha512:[0-9a-f]{128}$' "$IMAGE"
    fi
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pid i
    for pid in $(cat "$WORKDIR/pids" 2> /dev/null); do kill -INT "$pid" 2> /dev/null; done
    for pid in $(cat "$WORKDIR/pids" 2> /dev/null); do
        e2e_wait_exit "$pid"
        kill -KILL "$pid" 2> /dev/null
    done
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    e2e_teardown_file
}

setup () {
    set +e
    if [ -f "$WORKDIR/state" ]; then . "$WORKDIR/state"; fi
}

# node NAME LISTEN-PORT [BOOTSTRAP [P2P-LOG-LEVEL [ANNOUNCE]]]: its configuration,
# daemon and P2P service
node () {
    local n=$1 port=$2 boot=${3:-} level=${4:-info} announce=${5:-false} i
    mkdir -p "$WORKDIR/$n"
    chmod 700 "$WORKDIR/$n"
    cat > "$WORKDIR/$n.toml" <<EOT
[engine]
socket = "$WORKDIR/$n/sh.sock"
[server]
socket = "$WORKDIR/$n/sh.sock"
state_dir = "$WORKDIR/$n/state"
root_dir = "$WORKDIR/$n/root"
store_service = true
[storage]
root = "$WORKDIR/$n/store"
[pull]
sources = ["p2p", "registry"]
# (no background completion: a pull stays a pull, its containers lazy)
lazy_completers = 0
[[sources.external]]
name = "p2p"
socket = "$WORKDIR/$n/services/p2p-fetcher.sock"
idle_timeout_secs = 30
[sources.external.settings]
mdns = false
private_key_path = "$WORKDIR/swarm.key"
listen_addresses = ["/ip4/127.0.0.1/tcp/$port"]
bootstrap_peers = [${boot:+\"$boot\"}]
announce_images = $announce
# (every node of the test is on this host)
dial_allow = ["127.0.0.0/8"]
EOT
    E2E_SPAWN_LOG=$WORKDIR/$n.log e2e_spawn_ready ENGINE_PID "$BIN/velarx" --config "$WORKDIR/$n.toml" varlink ||
        { echo "the engine of node $n does not start"; cat "$WORKDIR/$n.log"; return 1; }
    echo "$ENGINE_PID" >> "$WORKDIR/pids"
    RUST_LOG=$level "$BIN/velarx-p2p" --config "$WORKDIR/$n.toml" >> "$WORKDIR/$n.p2p.log" 2>&1 3>&- &
    echo $! >> "$WORKDIR/pids"
    # (the service says so once it listens and serves the chunks; its control
    # socket answers then)
    e2e_wait_line "$WORKDIR/$n.p2p.log" 'Chunk provider set' || { echo "the P2P service of node $n does not start"; cat "$WORKDIR/$n.p2p.log"; return 1; }
}
# chunks_sent NODE: the chunks the P2P service of the node has sent
chunks_sent () { p2p_ "$1" stats | grep -oE '"chunks_sent": *[0-9]+' | grep -oE '[0-9]+$'; }
sh_ () { local n=$1; shift; "$BIN/velarx" --socket "$WORKDIR/$n/sh.sock" "$@"; }
# p2p_ NODE ARGS: `velarx-p2p`, which asks the P2P service of the node itself
p2p_ () { local n=$1; shift; "$BIN/velarx-p2p" --config "$WORKDIR/$n.toml" "$@"; }

# wait_profile: until the store of node b has a startup profile (5 s at most)
wait_profile () { e2e_wait_glob "$WORKDIR/b/store/composefs/*.profile.json" 5; }

@test "node a pulls the image and tells no list" {
    local i
    node a "$PORT_A" "" debug
    peer_id=$(p2p_ a status 2>&1 | grep -oE '12D3KooW[A-Za-z0-9]+' | head -1)
    [ -n "$peer_id" ] || { echo "no peer id for node a"; p2p_ a status; cat "$WORKDIR/a.p2p.log"; exit 1; }
    echo "peer_id=$peer_id" >> "$WORKDIR/state"
    sh_ a image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "node a pulls the image" 0 $?
    # (what a pulled is told to the swarm as a filter of its layers, which is
    # not a list: its images and its DHT records need `announce_images`)
    e2e_wait_line "$WORKDIR/a.p2p.log" 'Announcing [1-9][0-9]* new layers' 30 || true
    check_match "node a puts its layers in its filter" "Announcing [1-9][0-9]* new layers" "$(cat "$WORKDIR/a.p2p.log")"
    ! grep -q 'layers to the DHT' "$WORKDIR/a.p2p.log"
    check "node a announces nothing in the DHT" 0 $?
}

@test "node b is connected to node a" {
    local i
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    node b $((PORT_A + 1)) "/ip4/127.0.0.1/tcp/$PORT_A/p2p/$peer_id" debug
    # (a loaded machine takes its time: 30 s)
    e2e_wait_line "$WORKDIR/b.p2p.log" "Connected to $peer_id" 30 || true
    check_match "node b is connected to node a" "$peer_id" "$(p2p_ b peers 2>&1)"
    # (a told its filter when b connected: a layer is in it)
    e2e_wait_line "$WORKDIR/b.p2p.log" "$peer_id told a filter of [1-9][0-9]* layers" 30 || true
    check_match "node b has the filter of node a" '"keys": *[1-9]' "$(p2p_ b peers 2>&1)"
}

@test "node b pulls lazily, its container reads files from node a and leaves a startup profile" {
    local sent_before sent_after out i profile
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    sh_ b image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "node b pulls it lazily" 0 $?
    sent_before=$(chunks_sent a)
    out=$(sh_ b container run --rm --lazy --network none "$IMAGE" sh -c 'cat /etc/alpine-release; ls /bin | head -20 | while read f; do cat /bin/$f > /dev/null; done; echo done' 2>&1)
    check_match "its container reads files of the image" "^[0-9]+\.[0-9]+.*done$" "$(echo "$out" | tr '\n' ' ' | sed 's/ *$//')"
    sent_after=$(chunks_sent a)
    check_match "the chunks came from node a" "^[1-9][0-9]*$" "$((${sent_after:-0} - ${sent_before:-0}))"
    : "${sent_after:-}"
    wait_profile || true
    profile=$(ls "$WORKDIR"/b/store/composefs/*.profile.json 2> /dev/null | head -1)
    [ -n "$profile" ] || { echo "FAIL node b left no startup profile" >&2; exit 1; }
    echo "profile=$profile" >> "$WORKDIR/state"
    check_match "the first container left a startup profile" '^\{"v":1,"files":\["fsverity-(sha256-12:[0-9a-f]{64}|sha512-12:[0-9a-f]{128})"' "$(cat "$profile" 2> /dev/null)"
    out=$(sh_ b container run --rm --lazy --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "the next container runs with it" "^[0-9]+\.[0-9]+" "$out"
    # b asked a for the chunks because its filter said maybe; a does not list
    # what it has
    ! grep -q 'layers to the DHT' "$WORKDIR/a.p2p.log"
    check "node a still announced nothing in the DHT" 0 $?
    ! p2p_ b images 2>&1 | grep -q "$peer_id"
    check "node b is not given the images of node a" 0 $?
    # (the pull of node b goes on: the next test completes it)
}

# A has the image whole (it runs no lazy container, so it records no profile):
# give it B's, as if one of its lazy runs had made it.  C has none.

@test "node c gets the startup profile of node a for its first container" {
    local out i
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    [ -f "${profile:-}" ] || { echo "no startup profile of node b (the earlier test failed or did not run)" >&2; exit 1; }
    cp "$profile" "$WORKDIR/a/store/composefs/$(basename "$profile")"
    node c $((PORT_A + 2)) "/ip4/127.0.0.1/tcp/$PORT_A/p2p/$peer_id" debug
    e2e_wait_line "$WORKDIR/c.p2p.log" "Connected to $peer_id" 30 || true
    sh_ c image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "node c pulls it lazily" 0 $?
    out=$(sh_ c container run --rm --lazy --network none "$IMAGE" sh -c 'cat /etc/alpine-release; sleep 1' 2>&1)
    check_match "its first container runs" "^[0-9]+\.[0-9]+" "$out"
    e2e_wait_line "$WORKDIR/c.p2p.log" "startup profile of .* from $peer_id" 30 || true
    check_match "it got the startup profile of node a" "startup profile of .* from $peer_id" "$(grep -o "startup profile of .*" "$WORKDIR/c.p2p.log")"
    check_match "node c's status counts what came from node a" "\"peer_id\": \"$peer_id\"" "$(p2p_ c status 2>&1)"
}

# With `announce_images = true` a node tells the swarm what it pulled, and the
# peers can list it: node d announces its layers and the image, node a (which
# announces nothing) sees the image of node d.
@test "node d, with announce_images, announces what it pulled to the swarm" {
    local i d_id
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    node d $((PORT_A + 5)) "/ip4/127.0.0.1/tcp/$PORT_A/p2p/$peer_id" debug true
    d_id=$(p2p_ d status 2>&1 | grep -oE '12D3KooW[A-Za-z0-9]+' | head -1)
    [ -n "$d_id" ] || { echo "no peer id for node d"; exit 1; }
    e2e_wait_line "$WORKDIR/d.p2p.log" "Connected to $peer_id" 30 || true
    sh_ d image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "node d pulls the image" 0 $?
    e2e_wait_line "$WORKDIR/d.p2p.log" 'Announcing [1-9][0-9]* layers to the DHT' 30 || true
    check_match "node d announces what it pulled" "Announcing [1-9][0-9]* layers to the DHT" "$(cat "$WORKDIR/d.p2p.log")"
    # (a, at debug level, logs what the gossip tells it of a peer)
    e2e_wait_line "$WORKDIR/a.p2p.log" "Peer $d_id announced" 30 || true
    check_match "node a sees the image of node d" "$d_id" "$(p2p_ a images 2>&1)"
}

# Node e pulled two versions of a big file, the second made of the chunks of
# the first that its store had: that layer is not given to peers (not every
# byte of it came from the registry), and the chunks the versions share are in
# the file of the second.  The first version is still given: node f, which
# has only node e for a peer, takes it from there, the registry gives only the
# metadata.
@test "a node that pulled two versions of a file gives the first one" {
    local out i e_id
    [ -n "${VERSIONS:-}" ] || skip "no versions of the file (E2E_NO_VERSIONS)"
    node e $((PORT_A + 6)) "" debug
    e_id=$(p2p_ e status 2>&1 | grep -oE '12D3KooW[A-Za-z0-9]+' | head -1)
    [ -n "$e_id" ] || { echo "no peer id for node e"; exit 1; }
    sh_ e image pull --tls-verify=false "$VERSIONS:1" > /dev/null 2>&1
    check "node e pulls the first version" 0 $?
    sh_ e image pull --tls-verify=false "$VERSIONS:2" > /dev/null 2>&1
    check "node e pulls the second version" 0 $?
    node f $((PORT_A + 7)) "/ip4/127.0.0.1/tcp/$((PORT_A + 6))/p2p/$e_id" debug
    e2e_wait_line "$WORKDIR/f.p2p.log" "Connected to $e_id" 30 || true
    out=$(sh_ f image pull --tls-verify=false "$VERSIONS:1" 2>&1)
    check "node f pulls the first version" 0 $?
    # (the text of the pull: "Total: 3.2 MB (0.4% registry, ..., 99.5% p2p)")
    check_match "the registry gave only the metadata" "\([0-4]\.[0-9]% registry" "$out"
    check_match "the peer gave the file" "(9[5-9]|100)\.[0-9]% p2p" "$out"
}
