# SPDX-License-Identifier: Apache-2.0
# A pull by name and tag among peers, with no registry: node a pulled a signed
# image and answers for its name; node b has `[pull] sources = ["p2p"]` and
# `names = ["p2p"]` (no registry in either), a signature policy that names the
# key of the publisher, and pulls (and runs, lazily too) the image by its tag.
# The tag is taken from the signed record of the platform pulled for only
# (a pull for another platform finds none): other nodes show that with
# `names` off the tag is not resolved, that a node that does not serve names
# gives none, that a key the policy does not name is not believed, and that a
# name whose policy asks for no signature has nobody to say what it names.  A
# pull by digest of a signed image takes its signatures from the peers too.
# Needs `velarx-p2p`, curl and a registry with an image for the lazy pull.
#
#   VELARX_BINDIR=target/debug E2E_IMAGE=image bats tests/e2e/bats/names-peers.bats

load helpers

PORT_A=${E2E_NAMES_PORT:-4331}

setup_file () {
    [ -x "${BIN:-${VELARX_BINDIR:-target/debug}}/velarx-p2p" ] ||
        skip "no velarx-p2p (build with cargo build -p velarx-p2p-bin)"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME" "$WORKDIR/registries.d"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    "$BIN/velarx-p2p" generate-key "$WORKDIR/swarm.key" > /dev/null
    echo e2e-pass > "$WORKDIR/pass"
    local k
    for k in key other; do
        "$BIN/velarx" image generate-sigstore-key --output-prefix "$WORKDIR/$k" --passphrase-file "$WORKDIR/pass" > /dev/null || exit 1
    done
    printf 'docker:\n  %s:\n    use-sigstore-attachments: true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.d/e2e.yaml"
    export REPO=$E2E_REGISTRY/velarx-e2e/names-$$
    # (the publisher's key for the image; a repository nobody signs; `other`
    # is the policy of a node that trusts another key)
    policy "$WORKDIR/policy.json" key
    policy "$WORKDIR/policy-other.json" other
    export IMAGE=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
}

# policy FILE KEY: the policy that names KEY for $REPO/app and nothing for the
# rest
policy () {
    cat > "$1" <<JSON
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {"docker": {"$REPO/app": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/$2.pub"}]}}
}
JSON
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pid
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

# node NAME LISTEN-PORT [BOOTSTRAP]: its configuration, daemon and P2P service;
# SOURCES, NAMES (the lists of `[pull]`), POLICY and SERVE (`serve_names`) are
# the variables a test sets for it
node () {
    local n=$1 port=$2 boot=${3:-}
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
sources = ${SOURCES:-[\"p2p\", \"registry\"]}
${NAMES:+names = $NAMES}
policy_path = "${POLICY:-$WORKDIR/policy.json}"
registries_d = "$WORKDIR/registries.d"
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
serve_names = ${SERVE:-false}
# (every node of the test is on this host)
dial_allow = ["127.0.0.0/8"]
EOT
    E2E_SPAWN_LOG=$WORKDIR/$n.log e2e_spawn_ready ENGINE_PID "$BIN/velarx" --config "$WORKDIR/$n.toml" varlink ||
        { echo "the engine of node $n does not start"; cat "$WORKDIR/$n.log"; return 1; }
    echo "$ENGINE_PID" >> "$WORKDIR/pids"
    RUST_LOG=debug "$BIN/velarx-p2p" --config "$WORKDIR/$n.toml" >> "$WORKDIR/$n.p2p.log" 2>&1 3>&- &
    echo $! >> "$WORKDIR/pids"
    e2e_wait_line "$WORKDIR/$n.p2p.log" 'Chunk provider set' || { echo "the P2P service of node $n does not start"; cat "$WORKDIR/$n.p2p.log"; return 1; }
}
sh_ () { local n=$1; shift; "$BIN/velarx" --socket "$WORKDIR/$n/sh.sock" "$@"; }
p2p_ () { local n=$1; shift; "$BIN/velarx-p2p" --config "$WORKDIR/$n.toml" "$@"; }

# joined NAME: node NAME is connected to the first node (a)
joined () {
    e2e_wait_line "$WORKDIR/$1.p2p.log" "Connected to $peer_id" 30 || true
    check_match "node $1 is connected to node a" "$peer_id" "$(p2p_ "$1" peers 2>&1)"
}

@test "node a pulls the image signed by its publisher and serves its name" {
    local out
    # (a node of its own signs: the image goes to the registry as gzip, and
    # back as the zstd:chunked layers of the lazy pulls, with a signature)
    SOURCES='["registry"]' node s $((PORT_A + 9))
    { sh_ s image pull --tls-verify=false "$IMAGE" &&
      sh_ s image push --tls-verify=false --compression-format gzip "$IMAGE" "$REPO/base:gzip" &&
      sh_ s image pull --tls-verify=false "$REPO/base:gzip" &&
      sh_ s image push --tls-verify=false --compression-format zstd:chunked --sign-by-sigstore-private-key "$WORKDIR/key.private" --sign-passphrase-file "$WORKDIR/pass" "$REPO/base:gzip" "$REPO/app:1" &&
      sh_ s image push --tls-verify=false --compression-format zstd:chunked "$REPO/base:gzip" "$REPO/plain:1"
    } > "$WORKDIR/seal.log" 2>&1 || { echo "cannot make the images"; cat "$WORKDIR/seal.log"; exit 1; }
    SERVE=true node a "$PORT_A"
    peer_id=$(p2p_ a status 2>&1 | grep -oE '12D3KooW[A-Za-z0-9]+' | head -1)
    [ -n "$peer_id" ] || { echo "no peer id for node a"; cat "$WORKDIR/a.p2p.log"; exit 1; }
    echo "peer_id=$peer_id" >> "$WORKDIR/state"
    # (the policy of a names the key: what a pulls is kept with its signature)
    out=$(sh_ a image pull --tls-verify=false "$REPO/app:1" 2>&1)
    check "node a pulls the signed image under the policy" 0 $?
    sh_ a image pull --tls-verify=false "$REPO/plain:1" > /dev/null 2>&1
    check "node a pulls the image nobody signed" 0 $?
    digest=$(sh_ a image inspect --format '{{.Digest}}' "$REPO/app:1")
    check_match "the image has a digest" '^sha256:[0-9a-f]{64}$' "$digest"
    echo "digest=$digest" >> "$WORKDIR/state"
}

@test "node b pulls the image by its tag from node a, with no registry" {
    local out
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    SOURCES='["p2p"]' NAMES='["p2p"]' node b $((PORT_A + 1)) "/ip4/127.0.0.1/tcp/$PORT_A/p2p/$peer_id"
    joined b
    out=$(sh_ b image pull --tls-verify=false "$REPO/app:1" 2>&1)
    check "node b pulls the image by its tag" 0 $?
    check "the tag names the image node a has" "$digest" "$(sh_ b image inspect --format '{{.Digest}}' "$REPO/app:1")"
    out=$(sh_ b container run --rm --network none "$REPO/app:1" cat /etc/alpine-release 2>&1)
    check_match "its container runs" "^[0-9]+\.[0-9]+" "$out"
    # (the policy of b is judged on the pulled image: the signature came with it)
    out=$(sh_ b container run --rm --network none --security-opt signature=require "$REPO/app:1" cat /etc/alpine-release 2>&1)
    check "a signature is required of the container, and found" 0 $?
}

@test "node b runs a lazy container of the image by its tag" {
    local out
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    sh_ b image rm -f "$REPO/app:1" > /dev/null 2>&1
    out=$(sh_ b container run --rm --lazy --network none "$REPO/app:1" sh -c 'cat /etc/alpine-release; echo done' 2>&1)
    check_match "its lazy container runs, the files coming from node a" "[0-9]+\.[0-9]+.*done$" "$(echo "$out" | tr '\n' ' ' | sed 's/ *$//')"
}

@test "a tag is not taken from the record of another platform" {
    local out
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    # (the record of node a is of the image of this host's platform)
    out=$(sh_ b image pull --tls-verify=false --platform linux/s390x "$REPO/app:1" 2>&1)
    check "node b does not pull the tag for linux/s390x" 125 $?
    check_match "it says no record is for that platform" "no source has a signed record of the tag for linux/s390x" "$out"
}

@test "with names off the tag is not resolved, the digest is, by its signatures from the peers" {
    local out
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    SOURCES='["p2p"]' node c $((PORT_A + 2)) "/ip4/127.0.0.1/tcp/$PORT_A/p2p/$peer_id"
    joined c
    out=$(sh_ c image pull --tls-verify=false "$REPO/app:1" 2>&1)
    check "node c cannot pull the tag" 125 $?
    check_match "it says the registry is not a source" "registry. is not one of the sources" "$out"
    # (the digest is the capability: the policy asks for a signature, the
    # peers give it with the manifest, and the registry is not asked)
    out=$(sh_ c image pull --tls-verify=false "$REPO/app@$digest" 2>&1)
    check "node c pulls the digest, the signature from the peers" 0 $?
}

@test "a node that serves no names gives none, and the tag is not taken from a peer that does not sign" {
    local out d_id
    # (node d has the image and serves no names; node g knows only d)
    node d $((PORT_A + 3))
    sh_ d image pull --tls-verify=false "$REPO/app:1" > /dev/null 2>&1
    check "node d pulls the signed image from the registry" 0 $?
    d_id=$(p2p_ d status 2>&1 | grep -oE '12D3KooW[A-Za-z0-9]+' | head -1)
    echo "d_id=$d_id" >> "$WORKDIR/state"
    SOURCES='["p2p"]' NAMES='["p2p"]' node g $((PORT_A + 4)) "/ip4/127.0.0.1/tcp/$((PORT_A + 3))/p2p/$d_id"
    e2e_wait_line "$WORKDIR/g.p2p.log" "Connected to $d_id" 30 || true
    out=$(sh_ g image pull --tls-verify=false "$REPO/app:1" 2>&1)
    check "node g cannot resolve the tag" 125 $?
    check_match "no source has a record" "no source has a signed record of the tag" "$out"
    # (the digest of the same image is given by that peer: no name asked)
    out=$(sh_ g image pull --tls-verify=false "$REPO/app@$digest" 2>&1)
    check "node g pulls the digest from node d" 0 $?
}

@test "a record of a key the policy does not name is not believed" {
    local out
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    # (node h trusts `other` for the name; node a has the record of `key`)
    SOURCES='["p2p"]' NAMES='["p2p"]' POLICY=$WORKDIR/policy-other.json node h $((PORT_A + 5)) "/ip4/127.0.0.1/tcp/$PORT_A/p2p/$peer_id"
    joined h
    out=$(sh_ h image pull --tls-verify=false "$REPO/app:1" 2>&1)
    check "node h does not pull the tag" 125 $?
    check_match "it says no key of the policy signed it" "none signed by a key the policy accepts" "$out"
    out=$(sh_ h image pull --tls-verify=false "$REPO/app@$digest" 2>&1)
    check "nor the digest, whose signature is not by its key" 125 $?
    check_match "it says the signature is not accepted" "Source image rejected" "$out"
}

@test "a name whose policy asks for no signature is not resolved from peers" {
    local out
    [ -n "${peer_id:-}" ] || { echo "no peer id of node a (the first test failed or did not run)" >&2; exit 1; }
    out=$(sh_ h image pull --tls-verify=false "$REPO/plain:1" 2>&1)
    check "the tag of an unsigned name is not pulled" 125 $?
    check_match "it says no signature names the tag" "names no key for it" "$out"
}
