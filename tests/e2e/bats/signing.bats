# SPDX-License-Identifier: Apache-2.0
# Signing: velarx signs what it pushes with a sigstore private key (a sigstore
# attachment in the registry), pulls under a sigstoreSigned policy, skopeo
# verifies what velarx signed (with a key velarx generated), a tampered image fails, and the images of a
# container are required to have signatures at create and at every start; with
# signature=check the policy of then (reject included) is judged at every
# start, and without it the signature rules at the create only.
#
#   VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/signing.bats

load helpers

REG=$E2E_REGISTRY

setup_file () {
    local tool
    for tool in skopeo curl; do
        command -v $tool > /dev/null || skip "no $tool"
    done
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    mkdir -p "$XDG_CONFIG_HOME/velarx/registries.d"
    export REPO=$REG/velarx-e2e-signing/r$$-$RANDOM
    echo e2e-pass > "$WORKDIR/pass"
    $SH image generate-sigstore-key --output-prefix "$WORKDIR/key" --passphrase-file "$WORKDIR/pass" > /dev/null
    $SH image generate-sigstore-key --output-prefix "$WORKDIR/other" --passphrase-file "$WORKDIR/pass" > /dev/null
    cat > "$XDG_CONFIG_HOME/velarx/registries.d/e2e.yaml" <<YAML
docker:
  $REG:
    use-sigstore-attachments: true
YAML
    cat > "$WORKDIR/policy.json" <<JSON
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {
    "docker": {
      "$REPO/signed": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/key.pub"}],
      "$REPO/foreign": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/key.pub"}],
      "$REPO/unsigned": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/key.pub"}]
    }
  }
}
JSON
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[pull]
policy_path = "$WORKDIR/policy.json"
registries_d = "$XDG_CONFIG_HOME/velarx/registries.d"
TOML
    cat > "$WORKDIR/registries.conf" <<CONF
[[registry]]
location = "$REG"
insecure = true
CONF
    VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf e2e_start_daemon || exit 1
    e2e_make_image
}

teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    [ ! -f "$WORKDIR/policy.orig" ] || mv "$WORKDIR/policy.orig" "$WORKDIR/policy.json"
    sc container rm -t 0 -f c1 c2 c3 c4 c5 c6 c7 c8 c9 > /dev/null 2>&1
    return 0
}

teardown_file () {
    e2e_teardown_file
}

# A different image for each name (the tags of an image share its signatures,
# and a name of a protected repository needs a signature of its own): the
# image of the file with one more file.
mkimg () { # name
    rm -rf "$WORKDIR/img-$1"; cp -a "$WORKDIR/rootfs" "$WORKDIR/img-$1"
    echo "$1 $$" > "$WORKDIR/img-$1/etc/content"
    tar -C "$WORKDIR/img-$1" -cf "$WORKDIR/img-$1.tar" .
    sc image import "$WORKDIR/img-$1.tar" "localhost/e2e-$1:1" > /dev/null
}
push () { # name:tag, then the options of push
    local name=$1; shift
    mkimg "${name%%:*}" || return 1
    sc image tag "localhost/e2e-${name%%:*}:1" "$REPO/$name" > /dev/null
    sc image push --tls-verify=false "$@" "$REPO/$name" 2>&1
    local status=$?
    sc image rm -f "$REPO/$name" "localhost/e2e-${name%%:*}:1" > /dev/null 2>&1
    return $status
}
pull () { sc image pull --tls-verify=false "$REPO/$1" 2>&1; }

@test "image generate-sigstore-key writes a key pair and replaces nothing" {
    local out
    out=$($SH image generate-sigstore-key --output-prefix "$WORKDIR/gen" --passphrase-file "$WORKDIR/pass" 2>&1)
    check "a key pair is generated" 0 $?
    check_match "it names the files" "^Key written to \"$WORKDIR/gen.private\" and \"$WORKDIR/gen.pub\"" "$out"
    check "the private key is 0600" "600" "$(stat -c %a "$WORKDIR/gen.private")"
    check "the public key is 0644" "644" "$(stat -c %a "$WORKDIR/gen.pub")"
    check_match "the public key is a PEM" "^-----BEGIN PUBLIC KEY-----" "$(cat "$WORKDIR/gen.pub")"
    out=$($SH image generate-sigstore-key --output-prefix "$WORKDIR/gen" --passphrase-file "$WORKDIR/pass" 2>&1)
    check "an existing key is not replaced" 125 $?
    check_match "it names the file" "gen.private exists" "$out"
    out=$($SH image generate-sigstore-key --output-prefix "$WORKDIR/gen2" < /dev/null 2>&1)
    check "no passphrase and no terminal is an error" 125 $?
    check_match "it says what to do" "give --passphrase-file" "$out"
    ! [ -e "$WORKDIR/gen2.private" ]
    check "and writes nothing" 0 $?
}

@test "a key of skopeo signs what velarx accepts, and velarx keys work in skopeo" {
    local out
    skopeo generate-sigstore-key --output-prefix "$WORKDIR/skey" --passphrase-file "$WORKDIR/pass" > /dev/null
    out=$(push skeyed:v1 --sign-by-sigstore-private-key "$WORKDIR/skey.private" --sign-passphrase-file "$WORKDIR/pass")
    check "velarx signs with a key of skopeo" 0 $?
    # (the image velarx signed with its own key, copied by skopeo with it)
    mkimg skeyed2
    sc image tag localhost/e2e-skeyed2:1 "$REPO/skeyed:v2" > /dev/null
    sc image push --tls-verify=false "$REPO/skeyed:v2" > /dev/null 2>&1
    mkdir -p "$WORKDIR/skopeo-registries.d"
    printf 'docker:\n  %s:\n    use-sigstore-attachments: true\n' "$REG" > "$WORKDIR/skopeo-registries.d/e2e.yaml"
    skopeo --registries.d "$WORKDIR/skopeo-registries.d" copy --src-tls-verify=false --dest-tls-verify=false \
        --sign-by-sigstore-private-key "$WORKDIR/key.private" --sign-passphrase-file "$WORKDIR/pass" \
        "docker://$REPO/skeyed:v2" "docker://$REPO/signed:v5" > "$WORKDIR/skopeo.log" 2>&1
    check "skopeo signs with a key of velarx" 0 $?
    out=$(pull signed:v5)
    check "velarx accepts what skopeo signed with the key of velarx" 0 $?
}

@test "cosign verifies what velarx signed" {
    command -v cosign > /dev/null || skip "no cosign"
    local out
    mkimg cosigned
    sc image tag localhost/e2e-cosigned:1 "$REPO/cosigned:v1" > /dev/null
    sc image push --tls-verify=false --sign-by-sigstore-private-key "$WORKDIR/key.private" \
        --sign-passphrase-file "$WORKDIR/pass" "$REPO/cosigned:v1" > /dev/null 2>&1
    check "the push is signed" 0 $?
    out=$(cosign verify --key "$WORKDIR/key.pub" --insecure-ignore-tlog=true \
        --allow-insecure-registry --allow-http-registry "$REPO/cosigned:v1" 2>&1)
    check "cosign verifies it with the public key velarx made" 0 $?
    out=$(cosign verify --key "$WORKDIR/other.pub" --insecure-ignore-tlog=true \
        --allow-insecure-registry --allow-http-registry "$REPO/cosigned:v1" 2>&1)
    [ $? -ne 0 ]
    check "cosign does not verify it with another key" 0 $?
}

@test "push signs the manifest with a sigstore key" {
    local out
    out=$(push signed:v1 --sign-by-sigstore-private-key "$WORKDIR/key.private" --sign-passphrase-file "$WORKDIR/pass")
    check "a signed push works" 0 $?
    out=$(push foreign:v1 --sign-by-sigstore-private-key "$WORKDIR/other.private" --sign-passphrase-file "$WORKDIR/pass")
    check "a push signed by another key works" 0 $?
    out=$(push unsigned:v1)
    check "an unsigned push works" 0 $?
    out=$(push signed:v2 --sign-by-sigstore-private-key "$WORKDIR/key.private" --sign-passphrase-file "$WORKDIR/wrong" 2>&1)
    check "a push with a missing passphrase file is refused" 125 $?
    echo wrong > "$WORKDIR/wrong"
    out=$(push signed:v2 --sign-by-sigstore-private-key "$WORKDIR/key.private" --sign-passphrase-file "$WORKDIR/wrong" 2>&1)
    check "a push with a wrong passphrase is refused" 125 $?
    check_match "it says why" "wrong passphrase" "$out"
    out=$(push signed:v2 --sign-by-sigstore /p 2>&1)
    check "keyless signing is refused by name" 125 $?
    check_match "it names the option" "^Error: --sign-by-sigstore is not supported" "$out"
}

@test "push --sign-by and image sign make GPG signatures that signedBy verifies" {
    command -v gpg > /dev/null || skip "no gpg"
    local out g
    # (a short path: the socket of the agent)
    g=$(mktemp -d /tmp/vxg.XXXXXX)
    export GNUPGHOME=$g
    gpg --batch --quiet --passphrase '' --quick-gen-key "e2e <e2e@example.org>" ed25519 sign never 2> /dev/null
    gpg --export e2e > "$WORKDIR/gpg.pub"
    # (put back by teardown)
    cp "$WORKDIR/policy.json" "$WORKDIR/policy.orig"
    cat > "$WORKDIR/policy.json" <<JSON
{
  "default": [{"type": "insecureAcceptAnything"}],
  "transports": {
    "docker": {
      "$REPO/gpgsigned": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/gpg.pub"}],
      "$REPO/gpglater": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/gpg.pub"}],
      "$REPO/gpgunsigned": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "$WORKDIR/gpg.pub"}]
    }
  }
}
JSON
    out=$(push gpgsigned:v1 --sign-by e2e 2>&1)
    check "a push signed with GPG works" 0 $?
    out=$(push gpgunsigned:v1 2>&1)
    check "an unsigned push works" 0 $?
    out=$(push gpglater:v1 2>&1)
    check "a push to sign later works" 0 $?
    out=$(pull gpgsigned:v1)
    check "the image signed by the key is pulled" 0 $?
    out=$(pull gpgunsigned:v1)
    check "an image with no signature is refused" 125 $?
    check_match "...as a missing signature" "a signature was required, but no signature exists" "$out"
    out=$(sc image sign --sign-by e2e --tls-verify=false "docker://$REPO/gpglater:v1" 2>&1)
    check "image sign signs an image of the registry" 0 $?
    out=$(pull gpglater:v1)
    check "...and it is pulled" 0 $?
    out=$(sc image sign --sign-by e2e --tls-verify=false --directory "$WORKDIR/sigs" "$REPO/gpglater:v1" 2>&1)
    check "image sign --directory writes there" "0 1" "$? $(find "$WORKDIR/sigs" -path "*/gpglater@sha256=*/signature-1" | wc -l)"
    out=$(sc image sign --sign-by nobody@example.org --tls-verify=false "$REPO/gpgunsigned:v1" 2>&1)
    check "a key that is not in the keyring is refused" 125 $?
    check_match "...says why" "gpg failed to sign with nobody@example.org" "$out"
    gpgconf --kill gpg-agent 2> /dev/null
    rm -rf "$g"
    unset GNUPGHOME
}

@test "skopeo verifies what velarx signed" {
    local d
    d=$(sc image inspect --format '{{.Digest}}' "$REPO/signed:v1" 2>/dev/null)
    cat > "$WORKDIR/skopeo-policy.json" <<JSON
{"default": [{"type": "reject"}],
 "transports": {"docker": {"$REPO/signed": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/key.pub"}]}}}
JSON
    mkdir -p "$WORKDIR/skopeo-registries.d"
    cat > "$WORKDIR/skopeo-registries.d/e2e.yaml" <<YAML
docker:
  $REG:
    use-sigstore-attachments: true
YAML
    skopeo --policy "$WORKDIR/skopeo-policy.json" --registries.d "$WORKDIR/skopeo-registries.d" \
        copy --src-tls-verify=false "docker://$REPO/signed:v1" "dir:$WORKDIR/skopeo-out" > "$WORKDIR/skopeo.log" 2>&1
    check "skopeo accepts the image under the key of the signature" 0 $?
    # (an imported image is velarx's: the manifest signed states the digest
    # of the EROFS image of its layer)
    check_match "the signed manifest states the layer digest" '"io.containers.composefs.digest":"sha256:[0-9a-f]{64}"' \
        "$(tr -d ' \n' < "$WORKDIR/skopeo-out/manifest.json")"
    cat > "$WORKDIR/skopeo-policy.json" <<JSON
{"default": [{"type": "reject"}],
 "transports": {"docker": {"$REPO/signed": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/other.pub"}]}}}
JSON
    rm -rf "$WORKDIR/skopeo-out"
    skopeo --policy "$WORKDIR/skopeo-policy.json" --registries.d "$WORKDIR/skopeo-registries.d" \
        copy --src-tls-verify=false "docker://$REPO/signed:v1" "dir:$WORKDIR/skopeo-out" > "$WORKDIR/skopeo.log" 2>&1
    check "skopeo refuses it under another key" 1 $?
}

@test "a pull under a sigstoreSigned policy accepts the signed image only" {
    local out
    out=$(pull signed:v1)
    check "the image signed by the key is pulled" 0 $?
    out=$(pull foreign:v1)
    check "the image signed by another key is refused" 125 $?
    check_match "it says why" "Source image rejected" "$out"
    out=$(pull unsigned:v1)
    check "the unsigned image is refused" 125 $?
}

@test "with no use-sigstore-attachments for the registry the refusal names it" {
    local out host=127.0.0.1:${REG##*:}
    [ "${REG%%:*}" = localhost ] || skip "the registry is not localhost:PORT"
    # (registries.d names the registry as localhost only)
    cat > "$WORKDIR/noattach.json" <<JSON
{"default": [{"type": "insecureAcceptAnything"}],
 "transports": {"docker": {"$host": [{"type": "sigstoreSigned", "keyPath": "$WORKDIR/key.pub"}]}}}
JSON
    out=$($SH image pull --tls-verify=false --signature-policy "$WORKDIR/noattach.json" "$host/${REPO#*/}/signed:v1" 2>&1)
    check "the signed image is refused" 125 $?
    check_match "it names the setting" "no signature exists \(registries.d sets no use-sigstore-attachments for $host/" "$out"
    out=$(pull unsigned:v1)
    check "with attachments an unsigned image is refused" 125 $?
    check_match "without the note" "no signature exists$" "$out"
}

@test "a signature of a manifest does not cover another manifest" {
    local out
    # the manifest of signed:v1 under another tag: the signature says v1
    sc image tag "$REPO/signed:v1" "$REPO/signed:v3" > /dev/null
    sc image push --tls-verify=false "$REPO/signed:v3" > /dev/null 2>&1
    sc image rm -f "$REPO/signed:v1" "$REPO/signed:v3" > /dev/null 2>&1
    out=$(pull signed:v3)
    check "the signature is for the tag it was made for" 125 $?
    # an edited manifest has another digest: no signature
    local tmp=$WORKDIR/edit
    mkdir -p "$tmp"
    skopeo copy --src-tls-verify=false --dest-tls-verify=false --format oci \
        "docker://$REPO/signed:v1" "dir:$tmp" > /dev/null 2>&1
    sed -i 's/"schemaVersion":2/"schemaVersion":2,"annotations":{"tampered":"1"}/' "$tmp/manifest.json"
    skopeo copy --dest-tls-verify=false --format oci "dir:$tmp" "docker://$REPO/signed:v4" > /dev/null 2>&1
    out=$(pull signed:v4)
    check "a tampered manifest fails" 125 $?
}

@test "signature=require refuses an image without a valid signature at create and at start" {
    local out
    sc image rm -f "$REPO/signed:v1" > /dev/null 2>&1
    pull signed:v1 > /dev/null
    sc container create --name c1 --security-opt signature=require "$REPO/signed:v1" /bin/true > /dev/null 2>&1
    check "a signed image is accepted under require" 0 $?
    sc container start c1 > /dev/null 2>&1
    check "and runs" 0 $?
    sc container rm -t 0 -f c1 > /dev/null 2>&1
    # the free default of the policy accepts it without a signature
    sc image pull --tls-verify=false "$REPO/unsigned:v1" > /dev/null 2>&1 || true
    mkimg unsigned-local
    out=$(sc container create --name c2 --security-opt signature=require localhost/e2e-unsigned-local:1 /bin/true 2>&1)
    check "an image the policy accepts without a signature is refused" 125 $?
    check_match "it says why" "accepts it without a signature" "$out"
    # an image mounted in the container is judged too
    out=$(sc container create --name c2 --security-opt signature=require \
        --mount type=image,source=localhost/e2e-unsigned-local:1,target=/m "$REPO/signed:v1" /bin/true 2>&1)
    check "an unsigned image mounted is refused" 125 $?
    check_match "it says why" "localhost/e2e-unsigned-local:1: the signature policy .* accepts it without a signature" "$out"
    # an image with no tag is judged by the names it was pulled by
    local id d
    id=$(sc image inspect --format '{{.Id}}' "$REPO/signed:v1")
    d=$(sc image inspect --format '{{.Digest}}' "$REPO/signed:v1")
    sc image untag "$REPO/signed:v1" > /dev/null 2>&1
    sc container create --name c3 --security-opt signature=require "$id" /bin/true > /dev/null 2>&1
    check "an untagged image is judged by the name it was pulled by" 0 $?
    sc container rm -t 0 -f c3 > /dev/null 2>&1
    sc image rm -f "$id" > /dev/null 2>&1
    pull "signed@$d" > /dev/null
    id=$(sc image inspect --format '{{.Id}}' "$REPO/signed@$d")
    sc container create --name c3 --security-opt signature=require "$id" /bin/true > /dev/null 2>&1
    check "an image pulled by its digest only is judged by that name" 0 $?
    sc container start c3 > /dev/null 2>&1
    check "and runs" 0 $?
    sc container rm -t 0 -f c3 > /dev/null 2>&1
    sc image rm -f "$id" > /dev/null 2>&1
    # an image with no name: no tag, never pulled
    mkimg noname
    id=$(sc image inspect --format '{{.Id}}' localhost/e2e-noname:1)
    sc image untag localhost/e2e-noname:1 > /dev/null 2>&1
    out=$(sc container create --name c3 --security-opt signature=require "$id" /bin/true 2>&1)
    check "an image with no name is refused" 125 $?
    check_match "it says why" "has no name the signature policy can be applied to \(it has no tag and was never pulled\), and --security-opt signature=require" "$out"
    out=$(sc container create --name c3 --security-opt signature=bogus "$id" /bin/true 2>&1)
    check "a bad value is refused" 125 $?
    check_match "it says why" "must be \"check\" or \"require\"" "$out"
}

@test "signature=check judges the policy of now at every start, a container without it does not" {
    local out
    cp "$WORKDIR/policy.json" "$WORKDIR/policy.orig"
    pull signed:v1 > /dev/null
    sc container create --name c6 --security-opt signature=check "$REPO/signed:v1" /bin/true > /dev/null 2>&1
    check "a container is made with check" 0 $?
    sc container create --name c7 "$REPO/signed:v1" /bin/true > /dev/null 2>&1
    check "and one without" 0 $?
    sc container inspect c6 > /dev/null 2>&1
    # the key is removed from the policy: no signature of the image satisfies it
    sed "s#$WORKDIR/key.pub#$WORKDIR/other.pub#" "$WORKDIR/policy.orig" > "$WORKDIR/policy.json"
    out=$(sc container start c6 2>&1)
    check "the start is refused" 125 $?
    check_match "it says why" "Source image rejected" "$out"
    out=$(sc container create --name c8 --security-opt signature=check "$REPO/signed:v1" /bin/true 2>&1)
    check "so is a new create" 125 $?
    sc container start c7 > /dev/null 2>&1
    check "a container made without the option starts" 0 $?
    # the key is back
    cp "$WORKDIR/policy.orig" "$WORKDIR/policy.json"
    sc container start c6 > /dev/null 2>&1
    check "it starts again" 0 $?
    # (at debug level, the engine of the command says what it judged)
    sed "s#$ESOCK#$WORKDIR/no-engine.sock#" "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/in-process.toml"
    out=$("$BIN/velarx" --config "$WORKDIR/in-process.toml" --log-level=debug container start c6 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p')
    check_match "the debug log says the policy checked" '^signature check -> sha256:[0-9a-f]{64} manifest$' "$out"
    # the policy of the image accepts it without a signature: check runs it
    sed "s#\"$REPO/signed\": \[[^]]*\]#\"$REPO/signed\": [{\"type\": \"insecureAcceptAnything\"}]#" "$WORKDIR/policy.orig" > "$WORKDIR/policy.json"
    grep -q 'signed": \[{"type": "insecureAcceptAnything"}\]' "$WORKDIR/policy.json" || e2e_die "no policy"
    sc container start c6 > /dev/null 2>&1
    check "check starts an image the policy accepts without a signature" 0 $?
    out=$(sc container create --name c8 --security-opt signature=require "$REPO/signed:v1" /bin/true 2>&1)
    check "require does not" 125 $?
    check_match "it says why" "accepts it without a signature" "$out"
    cp "$WORKDIR/policy.orig" "$WORKDIR/policy.json"
    sc container rm -t 0 -f c6 c7 > /dev/null 2>&1
}

@test "a reject rule refuses the create and the start of a container made with check or require, not one made without" {
    local out
    cp "$WORKDIR/policy.json" "$WORKDIR/policy.orig"
    pull signed:v1 > /dev/null
    sc container create --name c6 --security-opt signature=check "$REPO/signed:v1" /bin/true > /dev/null 2>&1 || exit 1
    sc container create --name c7 "$REPO/signed:v1" /bin/true > /dev/null 2>&1 || exit 1
    sc container create --name c8 --security-opt signature=require "$REPO/signed:v1" /bin/true > /dev/null 2>&1 || exit 1
    sed "s#\"$REPO/signed\": \[[^]]*\]#\"$REPO/signed\": [{\"type\": \"reject\"}]#" "$WORKDIR/policy.orig" > "$WORKDIR/policy.json"
    grep -q 'signed": \[{"type": "reject"}\]' "$WORKDIR/policy.json" || e2e_die "no policy"
    for opt in "--security-opt signature=check" "--security-opt signature=require"; do
        # shellcheck disable=SC2086
        out=$(sc container create --name c9 $opt "$REPO/signed:v1" /bin/true 2>&1)
        check "create is refused ($opt)" 125 $?
        check_match "it names the policy and the scope ($opt)" "$REPO/signed:v1: the signature policy .* rejects it \(scope $REPO/signed\)" "$out"
        case "$out" in *"without a signature"*) e2e_die "misleading: $out";; esac
    done
    # as podman, the default of a create runs an image of the store whatever
    # reject says (reject is for pulls)
    sc container create --name c9 "$REPO/signed:v1" /bin/true > /dev/null 2>&1
    check "a create without the option is not refused by reject" 0 $?
    sc container rm -t 0 -f c9 > /dev/null 2>&1
    for c in c6 c8; do
        out=$(sc container start $c 2>&1)
        check "the start of $c is refused" 125 $?
        check_match "it says why ($c)" "rejects it \(scope $REPO/signed\)" "$out"
    done
    sc container start c7 > /dev/null 2>&1
    check "a container made without the option starts: it was judged at its create" 0 $?
    # a reject rule beside a signature rule
    sed "s#\"$REPO/signed\": \[[^]]*\]#\"$REPO/signed\": [{\"type\": \"sigstoreSigned\", \"keyPath\": \"$WORKDIR/key.pub\"}, {\"type\": \"reject\"}]#" "$WORKDIR/policy.orig" > "$WORKDIR/policy.json"
    out=$(sc container start c6 2>&1)
    check "a reject beside a signature rule refuses" 125 $?
    check_match "it says why" "rejects it" "$out"
    # a default that rejects: an image built or loaded here, by a localhost/
    # name or by the name of a registry it was never pulled from, is made by
    # the default of a create, and judged with check
    cat > "$WORKDIR/policy.json" <<JSON
{"default": [{"type": "reject"}], "transports": {"docker": {"$REG": [{"type": "insecureAcceptAnything"}]}}}
JSON
    sc image tag localhost/e2e-unsigned-local:1 quay.io/velarx-e2e/built:1 || exit 1
    for image in localhost/e2e-unsigned-local:1 quay.io/velarx-e2e/built:1; do
        sc container create --name c9 $image /bin/true > /dev/null 2>&1
        check "$image is made by the default of a create" 0 $?
        sc container rm -t 0 -f c9 > /dev/null 2>&1
        out=$(sc container create --name c5 --security-opt signature=check $image /bin/true 2>&1)
        check "$image is judged with check" 125 $?
        check_match "it names the default ($image)" "rejects it \(the default of the docker transport\)|rejects it \(the default\)" "$out"
    done
    sc image untag localhost/e2e-unsigned-local:1 quay.io/velarx-e2e/built:1 > /dev/null 2>&1
    sc image inspect localhost/e2e-unsigned-local:1 > /dev/null 2>&1 || e2e_die "the local image lost its name"
    cp "$WORKDIR/policy.orig" "$WORKDIR/policy.json"
    sc container rm -t 0 -f c5 c6 c7 c8 c9 > /dev/null 2>&1
}

@test "signature=check refuses an image without a name, a tag lets it run" {
    local out id
    mkimg unnamed
    id=$(sc image inspect --format '{{.Id}}' localhost/e2e-unnamed:1)
    sc image untag localhost/e2e-unnamed:1 > /dev/null 2>&1
    out=$(sc container create --name c5 --security-opt signature=check "$id" /bin/true 2>&1)
    check "an image without a name is refused under check" 125 $?
    check_match "it says why" "image ${id:0:12} has no name the signature policy can be applied to" "$out"
    sc container create --name c6 "$id" /bin/true > /dev/null 2>&1
    check "a container without the option is made" 0 $?
    sc image tag "$id" localhost/e2e-unnamed:1 > /dev/null 2>&1
    sc container create --name c5 --security-opt signature=check "$id" /bin/true > /dev/null 2>&1
    check "the image with a tag is accepted" 0 $?
    sc container start c5 > /dev/null 2>&1
    check "and runs" 0 $?
    # (its last tag removed after the create: the next start is refused)
    sc image untag localhost/e2e-unnamed:1 > /dev/null 2>&1
    out=$(sc container start c5 2>&1)
    check "a start once the image has no name is refused" 125 $?
    check_match "it says why" "has no name the signature policy can be applied to" "$out"
    sc container rm -t 0 -f c5 c6 > /dev/null 2>&1
    sc image rm -f "$id" > /dev/null 2>&1
}

@test "[containers] image_signature = require is checked at every start" {
    local out
    pull signed:v1 > /dev/null
    sc container create --name c4 "$REPO/signed:v1" /bin/true > /dev/null 2>&1
    check "a container is made with the default" 0 $?
    sc container create --name c5 localhost/e2e-unsigned-local:1 /bin/true > /dev/null 2>&1
    check "a container of an unsigned image is made with the default" 0 $?
    sed -i '/^\[containers\]/a image_signature = "require"' "$XDG_CONFIG_HOME/velarx/config.toml"
    kill "$(cat "$WORKDIR/daemon.pid")"; wait "$(cat "$WORKDIR/daemon.pid")" 2> /dev/null
    VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf e2e_start_daemon
    sc container start c4 > /dev/null 2>&1
    check "a signed image starts under require" 0 $?
    # (the engine of the command, at debug level: the signature it checked
    # is a line of the chain of trust)
    sed "s#$ESOCK#$WORKDIR/no-engine.sock#" "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/in-process.toml"
    out=$("$BIN/velarx" --config "$WORKDIR/in-process.toml" --log-level=debug container start c4 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p')
    check_match "the debug log says the signature checked" '^signature require -> sha256:[0-9a-f]{64} manifest$' "$out"
    sc container rm -t 0 -f c4 > /dev/null 2>&1
    out=$(sc container start c5 2>&1)
    check "a container of an unsigned image is refused at start" 125 $?
    check_match "it says why" "accepts it without a signature, and \[containers\] image_signature" "$out"
    sc container rm -t 0 -f c5 > /dev/null 2>&1
    sc container create --name c5 localhost/e2e-unsigned-local:1 /bin/true > /dev/null 2>&1
    check "an unsigned image is refused at create" 125 $?
    out=$(sc container create --name c5 --security-opt signature=check "$REPO/signed:v1" /bin/true 2>&1)
    check "a request for less than the configuration is an error" 125 $?
    check_match "it says why" "a container cannot ask for less" "$out"
}

@test "image trust sets and shows the policy, --signature-policy replaces it" {
    local out p=$WORKDIR/trust-policy.json
    cp "$WORKDIR/policy.json" "$p"
    out=$(sc image trust show --policypath "$p" --registrypath "$XDG_CONFIG_HOME/velarx/registries.d" 2>&1)
    check "show works" 0 $?
    check_match "the default is accept" "all +default +accept" "$out"
    check_match "a scope of the policy is shown" "repository +$REPO/signed +sigstoreSigned" "$out"
    $SH image trust set --policypath "$p" -t reject default
    check "set the default" 0 $?
    out=$($SH image trust show --policypath "$p" --json)
    check_match "the default is reject" '"type": "reject"' "$out"
    $SH image trust set --policypath "$p" -t sigstoreSigned -f "$WORKDIR/key.pub" "$REPO/other"
    check "set sigstoreSigned for a scope" 0 $?
    out=$(cat "$p")
    check_match "the key is in the policy" "\"keyPath\": \"$WORKDIR/key.pub\"" "$out"
    out=$($SH image trust set --policypath "$p" -t signedBy "$REPO/x" 2>&1)
    check "signedBy without a key is refused" 125 $?
    check_match "it says why" "at least one public key" "$out"
    # --signature-policy replaces the policy of the configuration, for the engine of the command
    cp "$WORKDIR/policy.json" "$WORKDIR/accept-all.json"
    echo '{"default":[{"type":"reject"}]}' > "$WORKDIR/reject.json"
    out=$($SH image pull --tls-verify=false --signature-policy "$WORKDIR/reject.json" "$REPO/unsigned:v1" 2>&1)
    check "a pull under a rejecting policy file fails" 125 $?
    check_match "it says why" "rejected by the signature policy" "$out"
    out=$(sc image pull --tls-verify=false --signature-policy "$WORKDIR/reject.json" "$REPO/unsigned:v1" 2>&1)
    check "an engine service has its own policy" 125 $?
    check_match "it says why" "--signature-policy is not supported with an engine service" "$out"
}
