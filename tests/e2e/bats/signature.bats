# SPDX-License-Identifier: Apache-2.0
# Signatures: images pushed by podman to a plain HTTP registry,
# signed with a GPG key (simple signing, in lookaside storage) or with a
# sigstore key (attachments), pulled by a daemon (root or rootless) in a
# scratch HOME
# under policies that require them.  podman, gpg and skopeo make the
# signatures, as a user would.
#
# The tests share the daemon, the policy and the registries.d file of the
# run, and change them in order.
#
#   VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/signature.bats

load helpers

REG=$E2E_REGISTRY

setup_file () {
    local tool
    for tool in podman gpg skopeo curl; do
        command -v $tool > /dev/null || skip "no $tool"
    done
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    # (setup_file and teardown_file run in one process, which loaded this file
    # before there was a work directory)
    PODMAN="podman --root $WORKDIR/podman/root --runroot $WORKDIR/podman/run --storage-driver vfs"
    chmod 700 "$XDG_RUNTIME_DIR"
    export GNUPGHOME=$WORKDIR/gnupg
    mkdir -p "$XDG_CONFIG_HOME/velarx/registries.d"
    mkdir -m 700 "$GNUPGHOME"
    # a repository of this run only
    export REPO=$REG/velarx-e2e-sig/r$$-$RANDOM

    # Where podman writes the signatures and velarx reads them (podman,
    # which signs, reads its own directory: the same files)
    mkdir -p "$XDG_CONFIG_HOME/containers"
    ln -s "$XDG_CONFIG_HOME/velarx/registries.d" "$XDG_CONFIG_HOME/containers/registries.d"
    cat > "$XDG_CONFIG_HOME/velarx/registries.d/e2e.yaml" <<YAML
docker:
  $REG:
    lookaside: file://$WORKDIR/sigstore
    use-sigstore-attachments: true
YAML

    # The keys.
    gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "e2e <e2e@example.com>" ed25519 sign 0 2> /dev/null
    gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "other <other@example.com>" ed25519 sign 0 2> /dev/null
    export FPR OTHER
    FPR=$(gpg --list-keys --with-colons e2e@example.com 2> /dev/null | awk -F: '/^fpr/{print $10; exit}')
    OTHER=$(gpg --list-keys --with-colons other@example.com 2> /dev/null | awk -F: '/^fpr/{print $10; exit}')
    gpg --export e2e@example.com > "$WORKDIR/key.gpg"
    echo e2e-pass > "$WORKDIR/pass"
    skopeo generate-sigstore-key --output-prefix "$WORKDIR/sigstore-key" --passphrase-file "$WORKDIR/pass" > /dev/null
    skopeo generate-sigstore-key --output-prefix "$WORKDIR/sigstore-other" --passphrase-file "$WORKDIR/pass" > /dev/null

    cat > "$WORKDIR/policy.json" <<JSON
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {
    "docker": {
      "$REPO/gpg": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/key.gpg"}],
      "$REPO/gpg-other": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/key.gpg"}],
      "$REPO/unsigned": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/key.gpg"}],
      "$REPO/repo": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/key.gpg",
                      "signedIdentity": {"type": "matchRepository"}}],
      "$REPO/sigstore": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/sigstore-key.pub"}],
      "$REPO/sigstore-other": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/sigstore-key.pub"}],
      "$REPO/rejected": [{"type": "reject"}]
    }
  }
}
JSON

    cp "$WORKDIR/policy.json" "$WORKDIR/policy.orig"
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[pull]
policy_path = "$WORKDIR/policy.json"
registries_d = "$XDG_CONFIG_HOME/velarx/registries.d"
TOML
    # the registry is plain HTTP for every pull of the daemon, also those a
    # container create makes (the same as root and rootless: a root daemon
    # does not read the files of a user)
    cat > "$WORKDIR/registries.conf" <<CONF
[[registry]]
location = "$REG"
insecure = true
CONF
    VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf e2e_start_daemon || exit 1
}

# a failing check must not leave the containers, nor the policy the test
# changed
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    sc container rm -t 0 -f c1 c2 c3 c4 c5 c6 c7 > /dev/null 2>&1
    [ ! -f "$WORKDIR/policy.orig" ] || cp "$WORKDIR/policy.orig" "$WORKDIR/policy.json"
    return 0
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    gpgconf --kill gpg-agent 2> /dev/null
    if [ -z "${E2E_KEEP:-}" ]; then
        if [ "$(id -u)" = 0 ]; then
            rm -rf "$WORKDIR/podman"
        else
            $PODMAN unshare rm -rf "$WORKDIR/podman" 2> /dev/null
        fi
    fi
    e2e_teardown_file
}

PODMAN="podman --root ${WORKDIR:-/nonexistent}/podman/root --runroot ${WORKDIR:-/nonexistent}/podman/run --storage-driver vfs"

# The images to push: one file each, a different image per repository
# (the tags of a repository share theirs), so that what one name allows
# does not depend on another.
mkimg () { # name
    rm -rf "$WORKDIR/rootfs"; mkdir -p "$WORKDIR/rootfs/etc"
    echo "$1 $$" > "$WORKDIR/rootfs/etc/content"
    tar -C "$WORKDIR/rootfs" -cf "$WORKDIR/rootfs.tar" .
    $PODMAN import -q "$WORKDIR/rootfs.tar" "localhost/e2e-sig:$1" > /dev/null
}
push () { # name:tag, then podman push options
    local name=$1; shift
    $PODMAN push -q --tls-verify=false "$@" "localhost/e2e-sig:${name%%:*}" "$REPO/$name" > "$WORKDIR/push.log" 2>&1 \
        || { echo "# push $name failed"; cat "$WORKDIR/push.log"; exit 1; }
}
pull () { sc image pull --tls-verify=false "$REPO/$1" 2>&1; }

@test "podman makes the images and signs them" {
    local f
    for f in gpg gpg-other unsigned repo sigstore sigstore-other rejected free; do mkimg $f; done
    check "podman makes the images" 0 $?
    push gpg:v1 --sign-by "$FPR"
    push gpg-other:v1 --sign-by "$OTHER"
    push unsigned:v1
    push repo:v1 --sign-by "$FPR"
    push sigstore:v1 --sign-by-sigstore-private-key "$WORKDIR/sigstore-key.private" --sign-passphrase-file "$WORKDIR/pass"
    push sigstore-other:v1 --sign-by-sigstore-private-key "$WORKDIR/sigstore-other.private" --sign-passphrase-file "$WORKDIR/pass"
    push rejected:v1
    push free:v1
    # the manifest of gpg:v1 again, as gpg:v2: the signature says v1
    push gpg:v2
    push repo:v2
    ls "$WORKDIR/sigstore" > /dev/null 2>&1
    check "podman wrote the GPG signatures in lookaside storage" 0 $?
}

@test "GPG signatures: the trusted key is accepted, others, none and another tag are refused" {
    local out
    out=$(pull gpg:v1)
    check "a GPG signature by the trusted key is accepted" 0 $?
    check "the image is there" 1 "$(sc image list | grep -c "velarx-e2e-sig/r.*/gpg")"
    out=$(pull gpg-other:v1)
    check "a signature by another key is refused" 125 $?
    check_match "it says why" "Source image rejected.*no trusted key" "$out"
    out=$(pull unsigned:v1)
    check "an unsigned image is refused" 125 $?
    check_match "it says why" "no signature exists" "$out"
    out=$(pull gpg:v2)
    check "a signature for another tag is refused" 125 $?
    check_match "it says why" "identity" "$out"
    out=$(pull repo:v2)
    check "matchRepository accepts another tag of the repository" 0 $?
}

@test "sigstore signatures and reject" {
    local out
    out=$(pull sigstore:v1)
    check "a sigstore signature by the trusted key is accepted" 0 $?
    out=$(pull sigstore-other:v1)
    check "a sigstore signature by another key is refused" 125 $?
    check_match "it says why" "Source image rejected" "$out"

    out=$(pull rejected:v1)
    check "reject refuses" 125 $?
}

# Without the attachments in registries.d, the sigstore signature is not
# looked for.

@test "without attachments, the sigstore signature is not found" {
    local out
    sed -i 's/use-sigstore-attachments: true/use-sigstore-attachments: false/' \
        "$XDG_CONFIG_HOME/velarx/registries.d/e2e.yaml"
    sc image rm -f "$REPO/sigstore:v1" > /dev/null 2>&1
    out=$(pull sigstore:v1)
    check "without attachments, the sigstore signature is not found" 125 $?
}

# Containers of a pulled image: the policy of now, with the signatures of
# the pull.

@test "containers of a pulled image follow the policy of now" {
    local out
    sc container create --name c1 "$REPO/gpg:v1" /etc/content > /dev/null 2>&1
    check "a container of a verified image is made" 0 $?
    sc container rm -t 0 -f c1 > /dev/null 2>&1
    gpg --export other@example.com > "$WORKDIR/other.gpg"
    sed -i "s|\"$REPO/gpg\": \[{\"type\": \"signedBy\", \"keyType\": \"GPGKeys\", \"keyPath\": \"$WORKDIR/key.gpg\"|\"$REPO/gpg\": [{\"type\": \"signedBy\", \"keyType\": \"GPGKeys\", \"keyPath\": \"$WORKDIR/other.gpg\"|" "$WORKDIR/policy.json"
    grep -q other.gpg "$WORKDIR/policy.json"
    check "the policy now trusts another key" 0 $?
    out=$(sc container create --name c2 "$REPO/gpg:v1" /etc/content 2>&1)
    check "a container of an image the policy no longer accepts is refused" 125 $?
    check_match "it says why" "Source image rejected" "$out"
    # an image that was not pulled is not checked, as by podman
    sed -i 's/"default": \[{"type": "insecureAcceptAnything"}\]/"default": [{"type": "reject"}]/' "$WORKDIR/policy.json"
    sc image import "$WORKDIR/rootfs.tar" localhost/e2e-local:1 > /dev/null
    sc container create --name c3 localhost/e2e-local:1 /etc/content > /dev/null 2>&1
    check "a container of a local image is made under a reject default" 0 $?
    sc container rm -t 0 -f c3 > /dev/null 2>&1
    out=$(sc container create --name c4 "$REPO/repo:v2" /etc/content 2>&1)
    check "a container of a pulled image still accepted is made" 0 $?
    sc container rm -t 0 -f c4 > /dev/null 2>&1
    cp "$WORKDIR/policy.json" "$WORKDIR/policy.strict.json"
    sed -i 's/"default": \[{"type": "reject"}\]/"default": [{"type": "insecureAcceptAnything"}]/' "$WORKDIR/policy.json"
    sed -i "s|$WORKDIR/other.gpg|$WORKDIR/key.gpg|" "$WORKDIR/policy.json"
}

# An image pulled from a repository without requirements, then tagged with
# the name of one that requires signatures: neither name runs it.

@test "an image tagged with the name of a protected repository does not run" {
    local out
    out=$(pull free:v1)
    check "an image of a repository without requirements is pulled" 0 $?
    sc image tag "$REPO/free:v1" "$REPO/gpg:evil" > /dev/null
    out=$(sc container create --name c5 "$REPO/free:v1" /etc/content 2>&1)
    check "a pulled image tagged with a protected name does not run" 125 $?
    check_match "it says why" "Source image rejected" "$out"
    out=$(sc container create --name c6 "$REPO/gpg:evil" /etc/content 2>&1)
    check "nor by that name" 125 $?
    # an archive loaded under a protected name
    sc image save -o "$WORKDIR/evil.tar" "$REPO/gpg:evil" > /dev/null
    sc image rm -f "$REPO/gpg:evil" "$REPO/free:v1" > /dev/null 2>&1
    sc image load -i "$WORKDIR/evil.tar" > /dev/null
    out=$(sc container create --name c7 "$REPO/gpg:evil" /etc/content 2>&1)
    check "an archive loaded under a protected name does not run" 125 $?
    # what reads a remote image without verifying it refuses it
    sc manifest create localhost/e2e-list > /dev/null
    out=$(sc manifest add --tls-verify=false localhost/e2e-list "$REPO/gpg:v1" 2>&1)
    check "manifest add of an image that must be signed is refused" 125 $?
    check_match "it says why" "does not verify signatures" "$out"
}

# Without any policy.json (none in the scratch HOME, none in /etc/velarx) a
# pull works: the built-in default accepts every image.

@test "a pull works without a policy.json" {
    [ ! -e /etc/velarx/policy.json ] || skip "/etc/velarx/policy.json exists"
    local conf=$XDG_CONFIG_HOME/velarx/config.toml out
    cp "$conf" "$WORKDIR/config.signed"
    grep -v '^policy_path' "$WORKDIR/config.signed" > "$conf"
    kill "$(cat "$WORKDIR/daemon.pid")"; wait "$(cat "$WORKDIR/daemon.pid")" 2> /dev/null
    VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf e2e_start_daemon
    out=$(pull unsigned:v1)
    check "a pull of an image the signed policy would refuse works" 0 $?
    sc image rm -f "$REPO/unsigned:v1" > /dev/null 2>&1
    cp "$WORKDIR/config.signed" "$conf"
    kill "$(cat "$WORKDIR/daemon.pid")"; wait "$(cat "$WORKDIR/daemon.pid")" 2> /dev/null
    VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf e2e_start_daemon
}

# podman agrees with each decision.

@test "podman agrees with each decision" {
    [ -n "${E2E_PODMAN:-}" ] || skip "E2E_PODMAN is not set"
    local t p s
    sed -i 's/use-sigstore-attachments: false/use-sigstore-attachments: true/' \
        "$XDG_CONFIG_HOME/velarx/registries.d/e2e.yaml"
    for t in gpg:v1 gpg-other:v1 unsigned:v1 gpg:v2 repo:v2 sigstore:v1 sigstore-other:v1 rejected:v1; do
        $PODMAN pull -q --tls-verify=false --signature-policy "$WORKDIR/policy.json" "$REPO/$t" > /dev/null 2>&1
        p=$?
        pull "$t" > /dev/null
        s=$?
        check "podman and velarx agree on $t" "$([ $p = 0 ] && echo 0 || echo 125)" "$s"
    done
}
