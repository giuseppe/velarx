# SPDX-License-Identifier: Apache-2.0
# The test images of lazy pulls (tools/make-lazy-fixtures): the fs-verity
# digest that the generator computes for the content of a file is the one the
# kernel measures (`fsverity measure`, on a file system with fs-verity: as
# verity.bats, a loop device of the work directory as root, or
# VELARX_VERITY_DIR), and the three images it pushes have the tables of
# contents their names say: lazy-verity gives the fs-verity digest and the
# sha256 of every file, chunked-sha256-only the sha256 only, gzip has none.
# The source is $E2E_REGISTRY/alpine:chunked and the images are pushed to a
# repository of the file's own in the same registry.
#
#   cargo build -p velarx-content --example lazy_fixture
#   sudo unshare -m --propagation private env VELARX_BINDIR=target/debug \
#       bats tests/e2e/bats/lazy-fixtures.bats

load helpers
load verity

setup_file () {
    command -v fsverity > /dev/null || skip "no fsverity (fsverity-utils)"
    command -v skopeo > /dev/null || skip "no skopeo"
    command -v zstd > /dev/null || skip "no zstd"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    export LF=$BIN/examples/lazy_fixture
    [ -x "$LF" ] || e2e_die "no $LF (cargo build -p velarx-content --example lazy_fixture)"
    e2e_verity_store
    export REPO=$E2E_REGISTRY/velarx-e2e/lazy-fixtures-$$
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    # (the engine service a lazy pull started)
    local pid
    pid=$(e2e_service_pid "$WORKDIR/lf/lf.sock" 2> /dev/null)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -z "${VS:-}" ] || [ "$(id -u)" = 0 ] || rm -rf "$VS"
    e2e_teardown_file
}

@test "the fs-verity digest of the generator is the kernel's" {
    need_verity
    mkdir -p "$VS"
    local n f want got
    # empty, one byte, around a block, around a node of the tree (128
    # blocks), a megabyte and a byte
    for n in 0 1 4095 4096 4097 524288 524289 1048577; do
        f=$VS/f$n
        head -c "$n" /dev/urandom > "$f"
        fsverity enable --hash-alg=sha256 --block-size=4096 "$f"
        want=$(fsverity measure "$f" | cut -d' ' -f1)
        got=$("$LF" digest "$f" | cut -d' ' -f1)
        echo "$n: kernel $want, generator $got"
        [ "$want" = "$got" ]
    done
}

@test "the images are made and pushed" {
    run "$E2E_DIR/../../tools/make-lazy-fixtures" --example "$LF" "$E2E_REGISTRY/alpine:chunked" "$REPO"
    echo "$output"
    [ "$status" = 0 ]
}

@test "lazy-verity: every file has its fs-verity digest and its sha256" {
    run python3 -I "$E2E_DIR/lazy_toc.py" "$E2E_REGISTRY" "${REPO#*/}" lazy-verity
    echo "$output"
    [ "$status" = 0 ]
    set -- $output
    [ "$1" = chunked ] && [ "$2" -gt 0 ] && [ "$3" = "$2" ] && [ "$4" = "$2" ]
}

@test "chunked-sha256-only: the sha256 of every file and no fs-verity digest" {
    run python3 -I "$E2E_DIR/lazy_toc.py" "$E2E_REGISTRY" "${REPO#*/}" chunked-sha256-only
    echo "$output"
    [ "$status" = 0 ]
    set -- $output
    [ "$1" = chunked ] && [ "$2" -gt 0 ] && [ "$3" = 0 ] && [ "$4" = "$2" ]
}

@test "gzip: no table of contents" {
    run python3 -I "$E2E_DIR/lazy_toc.py" "$E2E_REGISTRY" "${REPO#*/}" gzip
    [ "$status" = 0 ]
    [ "$output" = gzip ]
}

# A lazy pull of each: the engine of a store of its own, daemonless (the
# command starts the engine service of the store, the teardown stops it).
lf () {
    mkdir -p -m 700 "$WORKDIR/lf" "$WORKDIR/lf-store"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/lf-registries.conf"
    cat > "$WORKDIR/lf.toml" <<EOF
[engine]
socket = "$WORKDIR/lf/lf.sock"
idle_exit = 2
[server]
socket = "$WORKDIR/lf/lf.sock"
state_dir = "$WORKDIR/lf-state"
root_dir = "$WORKDIR/lf-root"
[storage]
root = "$WORKDIR/lf-store"
EOF
    VELARX_REGISTRIES_CONF=$WORKDIR/lf-registries.conf "$BIN/velarx" --config "$WORKDIR/lf.toml" "$@"
}

@test "lazy-verity is pulled lazily" {
    run lf image pull --lazy --tls-verify=false "$REPO:lazy-verity"
    echo "$output"
    [ "$status" = 0 ]
    [[ "$output" == *"Pulled (lazy)"* ]]
}

@test "chunked-sha256-only is refused, lazily or not: no fs-verity digests" {
    for lazy in --lazy ""; do
        run lf image pull $lazy --tls-verify=false "$REPO:chunked-sha256-only"
        echo "$output"
        [ "$status" != 0 ]
        [[ "$output" == *"its table of contents has no fs-verity digest for"* ]]
        # (refused before anything exists: no image)
        run lf image exists "$REPO:chunked-sha256-only"
        [ "$status" != 0 ]
    done
}

@test "gzip is refused with ImageNotLazy: no table of contents" {
    run lf image pull --lazy --tls-verify=false "$REPO:gzip"
    echo "$output"
    [ "$status" != 0 ]
    [[ "$output" == *"cannot be pulled lazily"* ]]
    [[ "$output" == *"has no table of contents"* ]]
    run lf image exists "$REPO:gzip"
    [ "$status" != 0 ]
}
