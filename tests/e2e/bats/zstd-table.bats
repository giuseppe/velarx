# SPDX-License-Identifier: Apache-2.0
# The binary table of a zstd:chunked layer: velarx writes it beside the JSON
# table of contents (annotations table-position and table-checksum, in the
# algorithm of the image's digests), pulls a layer that has one by it, lazily
# or not, and pulls a layer without one by its JSON table of contents.  The
# image without the annotations of the table is what a reader that does not
# know it sees: it pulls by the JSON TOC of the same blobs.  A table that
# cannot be used fails the pull.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/zstd-table.bats

load helpers

setup_file () {
    command -v curl > /dev/null || skip "no curl"
    command -v sqlite3 > /dev/null || skip "no sqlite3"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    export REPO=$E2E_REGISTRY/velarx-e2e/zstd-table-$$
    # an image of a directory, a file of a few chunks and a hard link
    mkdir -p "$WORKDIR/ctx/d"
    head -c 300000 /dev/urandom > "$WORKDIR/ctx/d/big"
    echo hello > "$WORKDIR/ctx/d/small"
    ln "$WORKDIR/ctx/d/small" "$WORKDIR/ctx/d/link"
    printf 'FROM scratch\nCOPY d /d\n' > "$WORKDIR/ctx/Containerfile"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    e2e_teardown_file
}

setup () {
    set +e
}

# v STORE ARGS...: velarx on the store STORE of the work directory
v () {
    local s=$WORKDIR/$1
    shift
    mkdir -p -m 700 "$s"
    printf '[storage]\nroot = "%s/store"\n[server]\nstate_dir = "%s/state"\nroot_dir = "%s/root"\n[engine]\nsocket = "%s/sh.sock"\n' \
        "$s" "$s" "$s" "$s" > "$s/config.toml"
    "$BIN/velarx" --config "$s/config.toml" "$@"
}

# annotation REF NAME: the zstd:chunked annotation NAME of the layer of REF
annotation () {
    local repo=${1%:*} tag=${1##*:}
    curl -sf -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
        "http://$E2E_REGISTRY/v2/${repo#"$E2E_REGISTRY"/}/manifests/$tag" |
        python3 -I -c 'import json,sys
a=json.load(sys.stdin)["layers"][0].get("annotations",{})
print(a.get("io.github.containers.zstd-chunked."+sys.argv[1],""))' "$2"
}

# retag REF NEW EDIT: the manifest of REF put as the tag NEW of the same
# repository, its layers' annotations changed by the python EDIT of `a`
retag () {
    local repo=${1%:*} tag=${1##*:}
    python3 -I - "http://$E2E_REGISTRY/v2/${repo#"$E2E_REGISTRY"/}/manifests" "$tag" "$2" "$3" << 'PY'
import json, sys, urllib.request
base, tag, new, edit = sys.argv[1:]
media = "application/vnd.oci.image.manifest.v1+json"
req = urllib.request.Request(f"{base}/{tag}", headers={"Accept": media})
m = json.load(urllib.request.urlopen(req))
for layer in m["layers"]:
    a = layer["annotations"]
    exec(edit)
body = json.dumps(m).encode()
req = urllib.request.Request(f"{base}/{new}", data=body, method="PUT", headers={"Content-Type": media})
urllib.request.urlopen(req)
PY
}

@test "a layer velarx writes has its binary table, in the algorithm of the image" {
    v a build -q -t localhost/t256 "$WORKDIR/ctx" > /dev/null
    check "build" 0 $?
    v a build -q --digest sha512 -t localhost/t512 "$WORKDIR/ctx" > /dev/null
    check "build --digest sha512" 0 $?
    for alg in 256 512; do
        v a image push -q --tls-verify=false "localhost/t$alg" "$REPO:t$alg" > /dev/null
        check "push of sha$alg" 0 $?
        check_match "table checksum of sha$alg" "^sha$alg:" "$(annotation "$REPO:t$alg" table-checksum)"
        check_match "table position of sha$alg" '^[0-9]+:[0-9]+:[0-9]+$' "$(annotation "$REPO:t$alg" table-position)"
        check_match "JSON TOC of sha$alg" "^sha$alg:" "$(annotation "$REPO:t$alg" manifest-checksum)"
    done
}

@test "a layer with a binary table is pulled by it, lazily or not, in either algorithm" {
    for alg in 256 512; do
        v "e$alg" image pull -q --tls-verify=false "$REPO:t$alg" > /dev/null
        check "pull of sha$alg" 0 $?
        key=$(sqlite3 "file:$WORKDIR/e$alg/store/db.sqlite?mode=ro" "select id from layers")
        check_match "the layer of sha$alg is the table's" "toc:$(annotation "$REPO:t$alg" table-checksum)" "$key"
        v "l$alg" image pull -q --lazy --tls-verify=false "$REPO:t$alg" > /dev/null
        check "lazy pull of sha$alg" 0 $?
        v "l$alg" image pull -q --tls-verify=false "$REPO:t$alg" > /dev/null
        check "completion of the lazy pull of sha$alg" 0 $?
        key=$(sqlite3 "file:$WORKDIR/l$alg/store/db.sqlite?mode=ro" "select id from layers")
        check_match "the lazy layer of sha$alg is the table's" "toc:$(annotation "$REPO:t$alg" table-checksum)" "$key"
    done
}

@test "the image without the annotations of the table is pulled by its JSON TOC" {
    retag "$REPO:t256" json 'a.pop("io.github.containers.zstd-chunked.table-checksum"); a.pop("io.github.containers.zstd-chunked.table-position")'
    check "the image without the table" 0 $?
    [ -z "$(annotation "$REPO:json" table-checksum)" ]
    check "no table annotation" 0 $?
    v c image pull -q --tls-verify=false "$REPO:json" > /dev/null
    check "pull by the JSON TOC" 0 $?
    key=$(sqlite3 "file:$WORKDIR/c/store/db.sqlite?mode=ro" "select id from layers")
    check_match "the layer is the JSON TOC's" "toc:$(annotation "$REPO:json" manifest-checksum)" "$key"
}

@test "a table that cannot be used fails the pull, the JSON TOC is not read instead" {
    retag "$REPO:t256" bad 'a["io.github.containers.zstd-chunked.table-checksum"] = "sha256:" + "0" * 64'
    out=$(v d image pull --tls-verify=false "$REPO:bad" 2>&1)
    check "pull of a table that is not its checksum's" 125 $?
    check_match "the error names the layer" "layer sha256:" "$out"
    retag "$REPO:t256" half 'a.pop("io.github.containers.zstd-chunked.table-checksum")'
    out=$(v d image pull --tls-verify=false "$REPO:half" 2>&1)
    check "pull of half a table" 125 $?
    check_match "the error says why" "position and the checksum of its table" "$out"
}
