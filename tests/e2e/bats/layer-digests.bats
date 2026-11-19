# SPDX-License-Identifier: Apache-2.0
# The fs-verity digest of the EROFS image of each layer in the manifest
# (io.containers.composefs.digest): a push writes it, a pull checks it (eager
# and lazy) against its own record and ignores the values that are not those
# of the images made here, and `[storage] composefs_digests = "require"`
# refuses an image without one of them.  The
# repositories are the file's own (velarx-e2e/layer-digests-PID).
#
#   VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/layer-digests.bats

load helpers

KEY=io.containers.composefs.digest

setup_file () {
    export REG=$E2E_REGISTRY
    command -v curl > /dev/null || skip "no curl"
    command -v python3 > /dev/null || skip "no python3"
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    export IMG=$REG/alpine:chunked
    export REPO=velarx-e2e/layer-digests-$$
    # the CLI on a configuration that requires the digests
    sed '1i storage.composefs_digests = "require"' \
        "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require.toml"
    grep -q composefs_digests "$WORKDIR/require.toml" || e2e_die "no require configuration"
    printf '#!/bin/sh\nexec %s --config %s --root %s "$@"\n' "$BIN/velarx" "$WORKDIR/require.toml" "$WORKDIR/require-store" > "$WORKDIR/velarx-require"
    chmod +x "$WORKDIR/velarx-require"
    export SHR=$WORKDIR/velarx-require
    # the manifest of $REPO:TAG as JSON; edit TAG NEWTAG PYTHON-EXPRESSION puts
    # the manifest of TAG, changed, as NEWTAG
    cat > "$WORKDIR/edit.py" <<'PY'
import json, sys, urllib.request
reg, repo, tag, new, expr = sys.argv[1:6]
accept = "application/vnd.oci.image.manifest.v1+json"
req = urllib.request.Request(f"http://{reg}/v2/{repo}/manifests/{tag}", headers={"Accept": accept})
m = json.load(urllib.request.urlopen(req))
exec(expr)
body = json.dumps(m).encode()
if new == "-":
    print(json.dumps(m))
    sys.exit(0)
put = urllib.request.Request(f"http://{reg}/v2/{repo}/manifests/{new}", data=body, method="PUT",
                             headers={"Content-Type": accept})
urllib.request.urlopen(put).read()
PY
}

teardown_file () {
    e2e_teardown_file
}

manifest () { # tag: its layer annotations, one a line
    python3 -I "$WORKDIR/edit.py" "$REG" "$REPO" "$1" - 'pass' \
        | python3 -I -c 'import json,sys; [print(l.get("annotations", {}).get("'$KEY'", "-")) for l in json.load(sys.stdin)["layers"]]'
}

@test "a push writes the digest of the EROFS image of each layer" {
    $SH image pull --tls-verify=false "$IMG" > /dev/null || exit 1
    $SH image push --tls-verify=false --compression-format gzip "$IMG" "$REG/$REPO:gz" > /dev/null || exit 1
    $SH image pull --tls-verify=false "$REG/$REPO:gz" > /dev/null || exit 1
    $SH image push --tls-verify=false --compression-format zstd:chunked "$REG/$REPO:gz" "$REG/$REPO:zstd" > /dev/null || exit 1
    for tag in gz zstd; do
        local n=0
        while read -r d; do
            n=$((n + 1))
            check_match "$tag layer $n states a digest" '^sha256:[0-9a-f]{64}$' "$d"
        done < <(manifest "$tag")
        [ "$n" -gt 0 ] || e2e_die "no layer"
    done
    # the same layers, the same images
    check "the same digests" "$(manifest gz)" "$(manifest zstd)"
}

@test "a pull checks them, eager and lazy, and image inspect shows them" {
    for mode in "" "--lazy"; do
        rm -rf "$WORKDIR/store-pull"
        $SH --root "$WORKDIR/store-pull" image pull --tls-verify=false $mode "$REG/$REPO:zstd" > /dev/null || exit 1
        # (a lazy pull is an image of the store when its completion ends)
        $SH --root "$WORKDIR/store-pull" image complete "$REG/$REPO:zstd" > /dev/null || exit 1
        local seen
        seen=$($SH --root "$WORKDIR/store-pull" image inspect "$REG/$REPO:zstd" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)[0]
print("\n".join(",".join(l["Fsverity"]) for l in d["Composefs"]["Layers"]))')
        check "inspect shows what the manifest states ($mode)" "$(manifest zstd)" "$seen"
        $SH --root "$WORKDIR/store-pull" system check > /dev/null 2>&1
        check "system check ($mode)" 0 $?
    done
}

@test "a list of digests is accepted when one is the image's" {
    python3 -I "$WORKDIR/edit.py" "$REG" "$REPO" zstd list \
        "for l in m['layers']: l['annotations']['$KEY'] = 'sha256:' + 'ab' * 32 + ',' + l['annotations']['$KEY']" || exit 1
    for mode in "" "--lazy"; do
        rm -rf "$WORKDIR/store-list"
        $SH --root "$WORKDIR/store-list" image pull --tls-verify=false $mode "$REG/$REPO:list" > /dev/null 2>&1
        check "pull of a list ($mode)" 0 $?
    done
}

@test "a digest that is none of the images made here is foreign: pulled, held to the record, refused when required" {
    # (the last digest of a manifest edited, or the one of another writer)
    python3 -I "$WORKDIR/edit.py" "$REG" "$REPO" zstd bad \
        "m['layers'][-1]['annotations']['$KEY'] = 'sha256:' + 'ab' * 32" || exit 1
    # (a store of its own for each pull: the engine service of a store stays
    # a while after its last command, and a store removed under it is no
    # store to pull into)
    for mode in "" "--lazy"; do
        bad="$WORKDIR/store-bad${mode:+-lazy}"
        $SH --root "$bad" image pull --tls-verify=false $mode "$REG/$REPO:bad" > /dev/null 2>&1
        check "the pull works ($mode)" 0 $?
        $SH --root "$bad" image complete "$REG/$REPO:bad" > /dev/null 2>&1
        $SH --root "$bad" image inspect "$REG/$REPO:bad" > /dev/null 2>&1
        check "the image is stored ($mode)" 0 $?
        rm -rf "$WORKDIR/require-store"
        out=$($SHR image pull --tls-verify=false $mode "$REG/$REPO:bad" 2>&1)
        check "required: the pull fails ($mode)" 125 $?
        check_match "the message says why ($mode)" "composefs digest: layer [0-9]+ of [0-9]+ .*its EROFS image has the fs-verity digest sha256:[0-9a-f]{64}, the manifest says sha256:abab.*composefs_digests is \"require\"" "$out"
        $SHR image inspect "$REG/$REPO:bad" > /dev/null 2>&1
        check "required: no image is stored ($mode)" 125 $?
    done
    # not a list of digests at all, or of another writer's: not looked at
    for value in nonsense "sha512:$(printf '%0128d' 1)" "" "sha256:zz,"; do
        python3 -I "$WORKDIR/edit.py" "$REG" "$REPO" zstd junk \
            "m['layers'][0]['annotations']['$KEY'] = '$value'" || exit 1
        junk=$((${junk:-0} + 1))
        $SH --root "$WORKDIR/store-junk-$junk" image pull --tls-verify=false "$REG/$REPO:junk" > /dev/null 2>&1
        check "[$value] is ignored" 0 $?
        out=$($SHR image pull --tls-verify=false "$REG/$REPO:junk" 2>&1)
        check "[$value] is refused when required" 125 $?
        check_match "[$value]: the layer named" "layer 1 of [0-9]+ .*composefs_digests is \"require\"" "$out"
    done
}

@test "composefs_digests = require refuses an image that states none" {
    # (an image of another writer that velarx pulls: the layers of velarx
    # without the digests of their EROFS images)
    python3 -I "$WORKDIR/edit.py" "$REG" "$REPO" zstd foreign \
        "[l.get('annotations', {}).pop('$KEY', None) for l in m['layers']]" || exit 1
    out=$($SHR image pull --tls-verify=false "$REG/$REPO:foreign" 2>&1)
    check "the image of another writer" 125 $?
    check_match "the message names the option" 'composefs_digests is "require"' "$out"
    $SHR image pull --tls-verify=false "$REG/$REPO:zstd" > /dev/null 2>&1
    check "an image of velarx" 0 $?
    $SHR system check > /dev/null 2>&1
    check "system check" 0 $?
}
