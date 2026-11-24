# SPDX-License-Identifier: Apache-2.0
# The chain of trust held by default: where the store has fs-verity, an
# image made from a digest (`NAME@sha256:D`) is held to it at every start with
# no option: the manifest hashes to D, each layer is held to the digest of
# the manifest or, where the manifest states none, to the one the engine
# recorded when it made the EROFS image, and the overlay checks the files.
# An image named by a tag that no signature vouches for is held to nothing,
# `--security-opt verity=off` turns the default off.  The repository is the
# file's own (velarx-e2e/verity-default-PID) in the local registry.
#
# Needs a store on a file system with fs-verity, as verity-start.bats (root:
# a loop device of the work directory, in a mount namespace of its own;
# rootless: VELARX_VERITY_DIR); the tests skip without one.
#
#   VELARX_VERITY_DIR=/path VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/verity-default.bats

load helpers
load verity

reg () { python3 -I "$E2E_DIR/registry_images.py" "$@"; }

run_in () { # store, image, arguments of run (before the image)...
    local store=$1 image=$2
    shift 2
    shs "$store" run --rm --network none "$@" "$image" cat /etc/alpine-release 2>&1
}

dbg () { # store, arguments: the CLI at debug level; the lines of the chain only
    local store=$1
    shift
    "$SH" --root "$store" --log-level=debug "$@" 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p'
}

# conf FILE LINE...: the configuration of the test with more keys, each LINE
# "TABLE KEY = VALUE" (a configuration of its own would have other
# directories: as root, another run root than the one the store records)
conf () {
    local f=$1 l
    shift
    cp "$XDG_CONFIG_HOME/velarx/config.toml" "$f"
    for l in "$@"; do
        if grep -q "^\[${l%% *}\]" "$f"; then
            sed -i "/^\[${l%% *}\]/a ${l#* }" "$f"
        else
            sed -i "1i ${l%% *}.${l#* }" "$f"
        fi
    done
}

# no_verity STORE: every EROFS image of the layers replaced by a copy
# without fs-verity
no_verity () {
    local f
    for f in "$1"/composefs/layer-*.v5.erofs; do
        cp "$f" "$f.copy" && rm -f "$f" && mv "$f.copy" "$f" || return 1
    done
}

setup_file () {
    export REG=$E2E_REGISTRY
    command -v curl > /dev/null || skip "no curl"
    command -v python3 > /dev/null || skip "no python3"
    command -v crun > /dev/null || skip "no crun"
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    export IMG=$REG/alpine:chunked
    export NAME=velarx-e2e/verity-default-$$
    export REPO=$REG/$NAME
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$REG"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # an image velarx made, whose layer states the digest of its EROFS
    # image, and the same image whose layer states none (another writer's)
    shs "$WORKDIR/seal" image pull --tls-verify=false "$IMG" > /dev/null || e2e_die "pull"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format gzip "$IMG" "$REPO:gz" > /dev/null || e2e_die "push"
    shs "$WORKDIR/seal" image pull --tls-verify=false "$REPO:gz" > /dev/null || e2e_die "pull again"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format zstd:chunked "$REPO:gz" "$REPO:zstd" > /dev/null || e2e_die "push zstd"
    export D; D=$(reg digest "$REG" "$NAME" zstd) || e2e_die "digest"
    export B; B=$(reg annotate "$REG" "$NAME" zstd bare 1) || e2e_die "annotate"
    # a repository the policy requires a signature of, and an image signed
    # for it
    export SREPO=$REG/velarx-e2e/verity-default-signed-$$
    echo e2e-pass > "$WORKDIR/pass"
    $SH image generate-sigstore-key --output-prefix "$WORKDIR/key" --passphrase-file "$WORKDIR/pass" > /dev/null || e2e_die "key"
    mkdir -p "$XDG_CONFIG_HOME/velarx/registries.d"
    printf 'docker:\n  %s:\n    use-sigstore-attachments: true\n' "$REG" > "$XDG_CONFIG_HOME/velarx/registries.d/e2e.yaml"
    cat > "$WORKDIR/policy.json" <<JSON
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {"docker": {"$SREPO": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/key.pub"}]}}
}
JSON
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[pull]
policy_path = "$WORKDIR/policy.json"
registries_d = "$XDG_CONFIG_HOME/velarx/registries.d"
TOML
    shs "$WORKDIR/seal" image tag "$IMG" "$SREPO:v1" > /dev/null || e2e_die "tag"
    shs "$WORKDIR/seal" image push --tls-verify=false --sign-by-sigstore-private-key "$WORKDIR/key.private" \
        --sign-passphrase-file "$WORKDIR/pass" "$SREPO:v1" > /dev/null 2>&1 || e2e_die "signed push"
    e2e_verity_store
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -z "${VS:-}" ] || [ "$(id -u)" = 0 ] || rm -rf "$VS"
    e2e_teardown_file
}

@test "an image made from a digest is held to it with no option" {
    need_verity
    store=$VS/digest
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none "$REPO@$D" true)
    check_match "its root is the digest" "root typed $D" "$out"
    check_match "the layer is held to the manifest's digest" "layer 1 annotation sha256:[0-9a-f]{64} == erofs fd" "$out"
    check_match "the overlay checks the files" "-> overlay verity=require" "$out"
    check_match "and the chain is complete" "COMPLETE $D" "$out"
    check_match "it runs" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$REPO@$D")"
}

@test "a manifest that states no digest is held to the record of the pull" {
    need_verity
    store=$VS/record
    shs "$store" image pull --tls-verify=false "$REPO@$B" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none "$REPO@$B" true)
    check_match "the layer is held to the record" "layer 1 blob -> sha256:[0-9a-f]{64} record" "$out"
    check_match "measured as it" "layer 1 record sha256:[0-9a-f]{64} == erofs fd" "$out"
    check_match "complete" "COMPLETE $B" "$out"
    check_match "it runs" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$REPO@$B")"
}

@test "a plain start of a container made from a digest goes by the recorded digest" {
    need_verity
    store=$VS/plain
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" create --name plain --network none "$REPO@$D" cat /etc/alpine-release > /dev/null || exit 1
    out=$(dbg "$store" start -a plain)
    check_match "the recorded digest is the root" "root RECORDED $D" "$out"
    check_match "complete" "COMPLETE $D" "$out"
    check_match "it runs" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a plain 2>&1)"
    # a digest typed is compared with the image too, a wrong one is refused
    out=$(shs "$store" start -a --verify-image "sha256:$(printf 'a%.0s' $(seq 64))" plain 2>&1)
    check_match "another digest" "the stored manifest hashes to $D, not sha256:a{64}" "$out"
    shs "$store" rm -t 0 -f plain > /dev/null 2>&1
}

@test "a layer image replaced by a copy without fs-verity is refused with no option" {
    need_verity
    for what in "$D" "$B"; do
        store=$VS/tampered-$what
        store=${store/sha256:/}
        shs "$store" image pull --tls-verify=false "$REPO@$what" > /dev/null || exit 1
        shs "$store" create --name tampered --network none "$REPO@$what" cat /etc/alpine-release > /dev/null || exit 1
        check_match "it runs" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a tampered 2>&1)"
        no_verity "$store" || exit 1
        out=$(shs "$store" start -a tampered 2>&1)
        check_match "refused, the manifest ${what:0:14}" "cannot be measured|has no fs-verity" "$out"
        check "not run" 0 "$(printf '%s\n' "$out" | grep -cE '^[0-9]+\.[0-9]+')"
        shs "$store" rm -t 0 -f tampered > /dev/null 2>&1
    done
}

# (the overlay's own check of the objects holds with the chain off too: the
# test says that the chain held by default adds `verity=require`, which refuses
# a stub whose object has no fs-verity at all, and that by tag the file is
# refused as before)
@test "an object replaced by a copy without fs-verity is not read, by digest and by tag" {
    need_verity
    local n=0
    for what in "$REPO@$D" "$REPO:zstd"; do
        # (a short name: the kernel takes a path of at most 256 bytes as
        # the upper directory of an overlay, and the store of root is deep)
        n=$((n + 1))
        store=$VS/object-$n
        shs "$store" image pull --tls-verify=false "$what" > /dev/null || exit 1
        # (the file /etc/alpine-release: a version and a newline, no other file is so short)
        obj=$(find "$store/objects" -type f -size -16c -exec grep -lE '^[0-9]+\.[0-9]+\.[0-9]+$' {} + | head -1)
        [ -n "$obj" ] || e2e_die "no object holds the version"
        shs "$store" create --name object --network none "$what" cat /etc/alpine-release > /dev/null || exit 1
        { cat "$obj"; printf 'x'; } > "$obj.copy" && rm -f "$obj" && mv "$obj.copy" "$obj" || exit 1
        out=$(dbg "$store" start -a object)
        case $what in
        *@*) check_match "the chain says the overlay requires the digests of the files" "-> overlay verity=require" "$out" ;;
        *) check "by tag the chain is off" "OFF (no digest or signature)" "$(printf '%s\n' "$out" | head -1)" ;;
        esac
        out=$(shs "$store" start -a object 2>&1)
        check "the changed file is not read ($what)" 0 "$(printf '%s\n' "$out" | grep -cE '^[0-9]+\.[0-9]+\.[0-9]+x?$')"
        shs "$store" rm -t 0 -f object > /dev/null 2>&1
    done
}

@test "an image made from a tag, with no signature, is held to nothing, as before" {
    need_verity
    store=$VS/tag
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none "$REPO:zstd" true)
    check "off, and why" "OFF (no digest or signature)" "$out"
    shs "$store" create --name tag --network none "$REPO:zstd" cat /etc/alpine-release > /dev/null || exit 1
    no_verity "$store" || exit 1
    check_match "an image without fs-verity is mounted as before" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a tag 2>&1)"
    shs "$store" rm -t 0 -f tag > /dev/null 2>&1
}

@test "verity=off turns the default off" {
    need_verity
    store=$VS/off
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none --security-opt verity=off "$REPO@$D" true)
    check "off, and why" "OFF (--security-opt verity=off)" "$out"
    shs "$store" create --name off --network none --security-opt verity=off "$REPO@$D" cat /etc/alpine-release > /dev/null || exit 1
    no_verity "$store" || exit 1
    check_match "an image without fs-verity is mounted" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a off 2>&1)"
    shs "$store" rm -t 0 -f off > /dev/null 2>&1
}

@test "verity=off is refused where the chain is required" {
    need_verity
    store=$VS/refused
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    out=$(run_in "$store" "$REPO@$D" --security-opt verity=off --security-opt verity=enforce)
    check_match "contradicts enforce" "contradict" "$out"
    # (a node that turns the chain off and requires what it holds does not
    # start, and the node that turns it off)
    conf "$WORKDIR/off.toml" 'storage verity_chain = "off"' 'storage composefs_digests = "require"'
    out=$(shs "$store" --config "$WORKDIR/off.toml" run --rm --network none "$REPO@$D" true 2>&1)
    check_match "composefs_digests" 'verity_chain = "off": \[storage\] composefs_digests = "require" is held by the chain of trust' "$out"
    conf "$WORKDIR/off.toml" 'containers image_signature = "require"' 'storage verity_chain = "off"'
    out=$(shs "$store" --config "$WORKDIR/off.toml" run --rm --network none "$REPO@$D" true 2>&1)
    check_match "image_signature" 'verity_chain = "off": \[containers\] image_signature = "require" is held by the chain of trust' "$out"
    conf "$WORKDIR/off.toml" 'storage verity_chain = "off"'
    out=$("$SH" --config "$WORKDIR/off.toml" --root "$store" --log-level=debug run --rm --network none "$REPO@$D" true 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p')
    check "the node turns it off" 'OFF ([storage] verity_chain is "off")' "$out"
}

@test "nothing is said of the default at the default level" {
    need_verity
    store=$VS/quiet
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    out=$(run_in "$store" "$REPO@$D")
    check_match "the command's output only" '^[0-9]+\.[0-9]+(\.[0-9]+)?$' "$out"
    check "no word of the chain" 0 "$(printf '%s\n' "$out" | grep -ac 'verity')"
}

@test "a digest typed on the start of a container made from a tag holds its image" {
    need_verity
    store=$VS/typed
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    shs "$store" create --name typed --network none "$REPO:zstd" cat /etc/alpine-release > /dev/null || exit 1
    out=$(dbg "$store" start -a --verify-image "$D" typed)
    check_match "its root is the digest typed" "root typed $D" "$out"
    check_match "complete" "COMPLETE $D" "$out"
    out=$(shs "$store" start -a --verify-image "sha256:$(printf 'a%.0s' $(seq 64))" typed 2>&1)
    check_match "another digest holds no image" "the digests of its images are not held \(no digest or signature\)" "$out"
    shs "$store" rm -t 0 -f typed > /dev/null 2>&1
}

@test "layers made without fs-verity are held to nothing until a pull or a check seals them" {
    need_verity
    store=$VS/legacy
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" create --name legacy --network none "$REPO@$D" cat /etc/alpine-release > /dev/null || exit 1
    nullify () {
        python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1]); c.execute("UPDATE layers SET sealed = NULL"); c.commit()' "$store/db.sqlite"
    }
    nullify
    out=$(dbg "$store" start -a legacy)
    check_match "off, and why" "OFF \(layer made without fs-verity\)" "$out"
    check_match "it starts" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a legacy 2>&1)"
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    check_match "the pull seals the layers it can measure" "COMPLETE $D" "$(dbg "$store" start -a legacy)"
    nullify
    shs "$store" system check > /dev/null 2>&1
    check_match "a full check seals them too" "COMPLETE $D" "$(dbg "$store" start -a legacy)"
    # (a layer that cannot be measured is never sealed: the copy has no fs-verity)
    nullify
    no_verity "$store" || exit 1
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" system check > /dev/null 2>&1
    check_match "still off" "OFF \(layer made without fs-verity\)" "$(dbg "$store" start -a legacy)"
    shs "$store" rm -t 0 -f legacy > /dev/null 2>&1
}

@test "a signature the policy accepts holds an image made from a tag" {
    need_verity
    store=$VS/signed
    shs "$store" image pull --tls-verify=false "$SREPO:v1" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none "$SREPO:v1" true)
    check_match "its root is the signature" "root SIGNATURE sha256:[0-9a-f]{64}" "$out"
    check_match "complete" "COMPLETE " "$out"
    shs "$store" create --name signed --network none "$SREPO:v1" cat /etc/alpine-release > /dev/null || exit 1
    no_verity "$store" || exit 1
    out=$(shs "$store" start -a signed 2>&1)
    check_match "refused when a layer image loses fs-verity" "cannot be measured|has no fs-verity" "$out"
    # the policy of now accepts anything: the signature is no root
    cp "$WORKDIR/policy.json" "$WORKDIR/policy.signed"
    printf '{"default": [{"type": "insecureAcceptAnything"}]}\n' > "$WORKDIR/policy.json"
    out=$(dbg "$store" start -a signed)
    cp "$WORKDIR/policy.signed" "$WORKDIR/policy.json"
    check "off" "OFF (no digest or signature)" "$(printf '%s\n' "$out" | head -1)"
    shs "$store" rm -t 0 -f signed > /dev/null 2>&1
}

@test "verity_chain = require refuses what it cannot hold" {
    need_verity
    store=$VS/require
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    conf "$WORKDIR/require.toml" 'storage verity_chain = "require"'
    node () { "$SH" --config "$WORKDIR/require.toml" --root "$store" "$@"; }
    check_match "a digest runs" '^[0-9]+\.[0-9]+' "$(node run --rm --network none "$REPO@$D" cat /etc/alpine-release 2>&1)"
    out=$(node run --rm --network none "$REPO:zstd" true 2>&1)
    check_match "a tag with no signature is refused, with the reason" 'verity_chain is "require".*no digest or signature' "$out"
    out=$(node run --rm --network none --security-opt verity=off "$REPO@$D" true 2>&1)
    check_match "verity=off is refused" 'verity=off: \[storage\] verity_chain is "require"' "$out"
}

@test "a node with fsverity = false holds nothing, and says why; with require it refuses" {
    need_verity
    store=$VS/nofsverity
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    conf "$WORKDIR/nofsverity.toml" 'storage fsverity = false'
    out=$("$SH" --config "$WORKDIR/nofsverity.toml" --root "$store" --log-level=debug run --rm --network none "$REPO@$D" true 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p')
    check "off, and why" "OFF (fs-verity is off)" "$out"
    conf "$WORKDIR/nofsverity.toml" 'storage fsverity = false' 'storage verity_chain = "require"'
    out=$("$SH" --config "$WORKDIR/nofsverity.toml" --root "$store" run --rm --network none "$REPO@$D" true 2>&1)
    check_match "refused, with the reason" 'verity_chain is "require".*fs-verity is off' "$out"
}

running () { # store: the names of the running containers, one line
    shs "$1" ps --format '{{.Names}}' | sort | tr '\n' ' '
}

@test "a pod starts its members held by default, with no digest or with one" {
    need_verity
    store=$VS/pod
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    shs "$store" pod create --infra=false --name p > /dev/null || exit 1
    shs "$store" create --pod p --name m --network none "$REPO@$D" sleep 300 > /dev/null || exit 1
    # a plain start: the member goes by its recorded digest, and is held
    out=$(dbg "$store" pod start p)
    check_match "held to the recorded digest" "root RECORDED $D" "$out"
    check_match "complete" "COMPLETE $D" "$out"
    check "it runs" "m " "$(running "$store")"
    shs "$store" pod stop -t 1 p > /dev/null || exit 1
    # the digest it was made from is accepted, another is not
    out=$(dbg "$store" pod start --verify-image "$D" p)
    check_match "typed" "root typed $D" "$out"
    check "it runs again" "m " "$(running "$store")"
    shs "$store" pod stop -t 1 p > /dev/null || exit 1
    out=$(shs "$store" pod start --verify-image "sha256:$(printf 'a%.0s' $(seq 64))" p 2>&1)
    check_match "a digest of no image" "it names no image of the containers that start" "$out"
    shs "$store" pod rm -t 0 -f p > /dev/null 2>&1
    # a member made from a tag, held by the digest of its manifest
    shs "$store" pod create --infra=false --name q > /dev/null || exit 1
    shs "$store" create --pod q --name t --network none "$REPO:zstd" sleep 300 > /dev/null || exit 1
    out=$(dbg "$store" pod start --verify-image "$D" q)
    check_match "the manifest digest holds the image of a tag" "COMPLETE $D" "$out"
    check "it runs" "t " "$(running "$store")"
    shs "$store" pod rm -t 0 -f q > /dev/null 2>&1
}
