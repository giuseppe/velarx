# SPDX-License-Identifier: Apache-2.0
# The tree the EROFS images of the layers of an image make is the one podman
# makes of the same image: for each image, the images a pull makes in a store
# (read as the engine reads them, and stacked as the overlay of a container
# stacks them) against `podman export`.
# The checks are in tests/integration/merged_tree_tests.rs.  Rootless; nothing is
# mounted.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/merged-tree.bats
#
# MERGED_TREE_IMAGES: the images, separated by spaces (default
# $E2E_REGISTRY/alpine:chunked); MERGED_TREE_TEST: the test binary of
# `cargo test --test integration --no-run` (default: the newest of
# $BIN/deps/integration-*).
#
# With CFSCTL (the `cfsctl` of composefs-rs) and skopeo, the digest of the
# merged EROFS velarx computes for a sealed manifest is also compared with
# the one composefs-rs computes for the same image.

load helpers

sh_ () { "$BIN/velarx" --socket "$WORKDIR/sh.sock" "$@"; }

# merged_tree_image IMAGE: the checks of the script for one image; a failed
# check does not stop the others.
merged_tree_image () {
    local image=$1 failed=0 id layers i store out repo expect cid
    local PODMAN="podman --root $WORKDIR/podman/root --runroot $WORKDIR/podman/run --storage-driver ${PODMAN_DRIVER:-overlay}"
    if ! sh_ image pull --tls-verify=false "$image" > "$WORKDIR/pull.log" 2>&1; then
        echo "FAIL $image: cannot pull it"; cat "$WORKDIR/pull.log"; exit 1
    fi
    # (the store names an image by the digest of its manifest)
    id=$(sh_ image inspect --format '{{.Digest}}' "$image")
    id=${id#sha256:}
    # the layers of the image and their tables of contents, from the store
    layers=$WORKDIR/layers.json
    python3 -I - "$WORKDIR/store/db.sqlite" "$id" "$layers" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
rows = db.execute("SELECT l.id, l.toc FROM layers l JOIN image_layers il ON l.id = il.layer_id "
                  "WHERE il.image_id = ? ORDER BY il.layer_index", (sys.argv[2],)).fetchall()
json.dump(rows, open(sys.argv[3], "w"))
PY
    # (named by the key of the layer: `toc:sha256:<hex>` makes `toc-sha256-<hex>`)
    for i in $(python3 -I -c 'import json,sys; print(" ".join(d.replace("toc:", "toc-").replace(":", "-") for d, _ in json.load(open(sys.argv[1]))))' "$layers"); do
        if [ ! -f "$WORKDIR/store/composefs/layer-$i.v4.erofs" ]; then
            echo "FAIL $image: the pull made no EROFS image of the layer $i"; exit 1
        fi
    done
    store=$WORKDIR/store/objects
    # (a container reads the files of the image: the kernel's overlay follows
    # the redirects of the stubs into the objects of the store)
    if out=$(sh_ container run --rm --network none "$image" /bin/sh -c 'echo ran' 2>&1) && [ "$out" = ran ]; then
        echo "ok   $image: a container runs on it"
    else
        echo "FAIL $image: a container does not run on it: $out"; failed=1
    fi
    if ! $PODMAN pull -q --tls-verify=false "$image" > /dev/null 2>&1; then
        echo "skip $image: podman cannot pull it"
        [ "$failed" = 0 ] || exit 1
        skip "podman cannot pull $image"
    fi
    # the id of the image of composefs-rs (`cfsctl`, from its repository, with
    # the algorithm of the fs-verity of the kernel: fsverity-sha256-12)
    if [ -n "${CFSCTL:-}" ] && command -v skopeo > /dev/null; then
        repo=$WORKDIR/cfs-repo
        [ -d "$repo" ] || "$CFSCTL" init --insecure --algorithm fsverity-sha256-12 "$repo" > /dev/null 2>&1
        rm -rf "$WORKDIR/oci"
        if skopeo copy -q --src-tls-verify=false "docker://$image" "oci:$WORKDIR/oci:x" 2> /dev/null \
            && "$CFSCTL" --repo "$repo" oci pull "oci:$WORKDIR/oci:x" cfs-image > /dev/null 2>&1; then
            expect=$("$CFSCTL" --repo "$repo" oci compute-id cfs-image 2> /dev/null | tail -1)
            if CFS_FILES=$store CFS_LAYERS=$layers CFS_EXPECT_ID=$expect \
                "$MERGED_TREE_TEST" --ignored --nocapture merged_tree_tests::the_merged_image_has_the_id > "$WORKDIR/id.log" 2>&1; then
                echo "ok   $image: the merged EROFS has composefs-rs's id ($expect)"
            else
                echo "FAIL $image: the merged EROFS is not composefs-rs's ($expect)"; tail -5 "$WORKDIR/id.log"; failed=1
            fi
            "$CFSCTL" --repo "$repo" oci untag cfs-image > /dev/null 2>&1
        else
            echo "skip $image: cfsctl cannot import it"
        fi
    fi
    cid=$($PODMAN create "$image" /nonexistent 2> /dev/null) || { [ "$failed" = 0 ] || exit 1; skip "podman cannot create $image"; }
    $PODMAN export "$cid" -o "$WORKDIR/export.tar" 2> /dev/null || { [ "$failed" = 0 ] || exit 1; skip "podman cannot export $image"; }
    $PODMAN rm -f "$cid" > /dev/null 2>&1
    # (what podman adds to a container)
    if CFS_FILES=$store CFS_LAYERS=$layers CFS_TAR=$WORKDIR/export.tar \
        CFS_IGNORE="dev,proc,sys,etc/hosts,etc/hostname,etc/resolv.conf,etc/mtab,run/.containerenv,.containerenv,run/secrets" \
        "$MERGED_TREE_TEST" --ignored --nocapture merged_tree_tests::an_image_of_the_store > "$WORKDIR/check.log" 2>&1; then
        echo "ok   $image: $(grep -E 'paths in' "$WORKDIR/check.log")"
    else
        echo "FAIL $image"; grep -vE '^(running|test |$)' "$WORKDIR/check.log" | head -50; failed=1
    fi
    [ "$failed" = 0 ] || exit 1
}

# one test for each image
for image in ${MERGED_TREE_IMAGES:-$E2E_REGISTRY/alpine:chunked}; do
    eval "merged_tree_test_$((i = ${i:-0} + 1)) () { merged_tree_image '$image'; }"
    bats_test_function --description "the tree of the EROFS images of the layers of $image is podman's" -- "merged_tree_test_$i"
done

setup_file () {
    local t
    for t in podman curl python3; do
        command -v $t > /dev/null || skip "no $t"
    done
    BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export MERGED_TREE_TEST=${MERGED_TREE_TEST:-$(ls -t "$BIN"/deps/integration-* 2> /dev/null | grep -v '\.d$' | head -1)}
    [ -x "$MERGED_TREE_TEST" ] || skip "no test binary (cargo test --test integration --no-run)"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    cat > "$WORKDIR/sh.toml" <<EOT
[engine]
socket = "$WORKDIR/sh.sock"
[server]
socket = "$WORKDIR/sh.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$WORKDIR/store"
[pull]
EOT
    # (the daemon says READY=1 when it serves)
    E2E_SPAWN_LOG=$WORKDIR/sh.log e2e_spawn_ready daemon_pid "$BIN/velarx" --config "$WORKDIR/sh.toml" varlink
    ready=$?
    echo "$daemon_pid" > "$WORKDIR/daemon.pid"
    [ "$ready" = 0 ] || { echo "the daemon does not start"; cat "$WORKDIR/sh.log"; exit 1; }
    "$BIN/velarx" --socket "$WORKDIR/sh.sock" image list > /dev/null 2>&1 || { echo "the daemon does not answer"; cat "$WORKDIR/sh.log"; exit 1; }
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pid i
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if test -n "$pid"; then
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid"
        kill -KILL "$pid" 2> /dev/null
    fi
    if test -z "${E2E_KEEP:-}"; then
        # (podman's files belong to its user namespace)
        podman --root "$WORKDIR/podman/root" --runroot "$WORKDIR/podman/run" unshare rm -rf "$WORKDIR" 2> /dev/null
    fi
    e2e_teardown_file
}
