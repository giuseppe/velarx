# SPDX-License-Identifier: Apache-2.0
# The inline threshold N: `pull --inline-threshold=N` and `[storage]
# inline_threshold` put every regular file of 1..N bytes (-1: every file)
# into the EROFS image of its layer, so that a store on NFS has fewer, bigger
# files; the bigger files stay objects of the store and a lazy pull still
# fetches them on demand.  What is tested: the files that are held and the
# ones that are not (objects, rows of `layers.inline` and `inlined_files`),
# the content a container reads (the kernel's overlay as root, the image
# server rootless), a lazy pull with the registry gone, a layer that needs
# nothing outside of itself (-1), additional image stores, the layers a
# build, a commit, a load and an import make, push, save and cp of an inlined
# image, the first threshold kept for a layer, `rmi` and a pull again,
# `composefs_digests = "require"`, `system check`, and the memory of a layer
# of many hundred MiB.  Rootless and root, one after the other.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/inline-threshold.bats
#   sudo VELARX_BINDIR=target/debug bats tests/e2e/bats/inline-threshold.bats
#
# The registry is one of the file's own (`registry` of distribution in PATH),
# on a port of its own, which a test stops while a pull has to do without.
# E2E_HUGE_MB (default 512) is the size of the file of the memory test.  The
# tests of the verity use a store on a file system with fs-verity (root: a
# loop device; rootless: VELARX_VERITY_DIR) and say so when there is none.
#
# The peers (a node that serves an inlined layer, a node with another N) are
# tests/p2p-rig/inline.sh; the two machines of an NFS export, inline-nfs.bats.

load helpers
load verity
load inline

setup_file () {
    inline_setup_file
    e2e_verity_store
    # the contents of the build tests (every file of a size of its own)
    mkdir -p "$WORKDIR/ctx"
    local s
    for s in 101 5001 200003; do
        head -c "$s" /dev/urandom > "$WORKDIR/ctx/b$s"
        touch -d @1000000000 "$WORKDIR/ctx/b$s"
    done
    printf 'FROM %s\nCOPY b101 /s\nCOPY b5001 /m\nCOPY b200003 /b\nRUN cp /s /s2\n' "$IMAGE" > "$WORKDIR/ctx/Containerfile"
    printf 'FROM %s\nCOPY --from=localhost/inl-built:1 /m /m2\n' "$IMAGE" > "$WORKDIR/ctx/Containerfile.from"
    # what the files of /data say, by the names the build tests use
    (cd "$WORKDIR/ctx" && sha256sum b101 b5001 b200003) > "$WORKDIR/ctx.sums"
}

teardown_file () {
    inline_teardown_file
}

teardown () {
    inline_teardown
}

# the three files of the build tests as a container of IMAGE says them
built_sums () { # image
    sh_ container run --rm --pull=never --network none "$1" sh -c 'sha256sum /s /m /b /s2 /m2 2> /dev/null' |
        sed 's|/s2$|s2|; s|/m2$|m2|; s|/s$|b101|; s|/m$|b5001|; s|/b$|b200003|'
}

# --- the pull -----------------------------------------------------------------

@test "N=0 is the pull of today: every file is an object, no file is held" {
    inline_fresh n0
    pull_n 0 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 0
    expect_inlined "$STORE" 0
    check "no file is held" 0 "$(db "$STORE" 'SELECT count(*) FROM inlined_files')"
    content_ok "$IMAGE"
}

@test "a pull without the flag and without the setting is N=0" {
    inline_fresh default
    sh_ image pull --tls-verify=false "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 0
    check "the layer has no threshold" 0 "$(layer_inlines "$STORE")"
    check "and holds no file" 0 "$(db "$STORE" 'SELECT count(*) FROM inlined_files')"
    check "and nothing is said of it" 0 "$(grep -ci 'inline' "$WORKDIR/pull.out")"
}

@test "N=64 holds the files of up to 64 bytes, the others are objects" {
    inline_fresh n64
    pull_n 64 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 64
    expect_inlined "$STORE" 64
    content_ok "$IMAGE"
}

@test "N=4096 holds the file of 4096 bytes and not the one of 4097" {
    inline_fresh n4096
    pull_n 4096 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 4096
    expect_inlined "$STORE" 4096
    content_ok "$IMAGE"
}

@test "N=65537 holds a file of more than a block that is not a whole number of blocks" {
    inline_fresh n65537
    pull_n 65537 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 65537
    expect_inlined "$STORE" 65537
    content_ok "$IMAGE"
}

@test "N=-1 holds every file: the store has no object, and the container reads the same bytes" {
    inline_fresh nall
    pull_n -1 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" -1
    expect_inlined "$STORE" -1
    content_ok "$IMAGE"
    # the same files in a container that stays, and how it is served
    sh_ container run -d --name c1 --network none --pull=never "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a detached container runs" 0 $?
    check "it reads the biggest file" "$(sed -n 's/^\([0-9a-f]*\)  f3145745$/\1/p' "$WORKDIR/data.sums")" \
        "$(sh_ container exec c1 sha256sum /data/f3145745 | cut -d' ' -f1)"
    if [ "$(id -u)" = 0 ]; then
        check_match "as root, the kernel's overlay serves it" "root file system: mount descriptor 0 of the storage driver" "$(monitor_log c1)"
    else
        check_match "rootless, the image server serves it" "image server of the root file system: pid" "$(monitor_log c1)"
    fi
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
}

@test "a gzip layer is held as a zstd:chunked one is" {
    local n
    for n in 64 -1; do
        inline_fresh "gz$n"
        pull_n "$n" "$IMAGE_GZIP" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
        expect_objects "$STORE" "$n"
        expect_inlined "$STORE" "$n"
        content_ok "$IMAGE_GZIP"
    done
}

@test "[storage] inline_threshold is the threshold of a pull, the flag the one of a pull" {
    inline_fresh cfg4096 "inline_threshold = 4096"
    sh_ image pull --tls-verify=false "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 4096
    expect_inlined "$STORE" 4096
    content_ok "$IMAGE"
    inline_fresh cfgflag "inline_threshold = 4096"
    pull_n 0 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" 0
    expect_inlined "$STORE" 0
    inline_fresh cfgall "inline_threshold = -1"
    sh_ image pull --tls-verify=false "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    expect_objects "$STORE" -1
}

@test "a threshold below -1 or that is no number is refused before anything is pulled" {
    inline_fresh bad
    local out rc
    for n in -2 many 1.5; do
        out=$(pull_n "$n" "$IMAGE" 2>&1); rc=$?
        check "--inline-threshold=$n fails" 1 "$([ $rc != 0 ] && echo 1 || echo 0)"
        check_match "and names the flag" "inline-threshold" "$out"
    done
    check "nothing was pulled" 0 "$(objects "$STORE")"
    inline_stop
    cat > "$WORKDIR/badcfg.toml" <<EOT
[storage]
root = "$WORKDIR/badcfg-store"
inline_threshold = -2
EOT
    out=$("$BIN/velarx" --config "$WORKDIR/badcfg.toml" image list 2>&1); rc=$?
    check "a setting below -1 fails" 1 "$([ $rc != 0 ] && echo 1 || echo 0)"
    check_match "and names the setting" "inline_threshold" "$out"
}

# --- the first threshold wins --------------------------------------------------

@test "a layer that is in the store keeps its threshold, silently" {
    inline_fresh first
    pull_n 0 "$IMAGE" > /dev/null 2>&1 || e2e_die "the first pull fails"
    out=$(pull_n -1 "$IMAGE" 2>&1) || e2e_die "the second pull fails: $out"
    check "the layer is still N=0" 0 "$(layer_inlines "$STORE")"
    expect_objects "$STORE" 0
    check "and the second pull says nothing of it" 0 "$(printf '%s\n' "$out" | grep -ci 'inline')"
    content_ok "$IMAGE"
    inline_fresh first2
    pull_n -1 "$IMAGE" > /dev/null 2>&1 || e2e_die "the first pull fails"
    out=$(pull_n 4096 "$IMAGE" 2>&1) || e2e_die "the second pull fails: $out"
    check "the layer is still N=-1" -1 "$(layer_inlines "$STORE")"
    expect_objects "$STORE" -1
    check "and the second pull says nothing of it" 0 "$(printf '%s\n' "$out" | grep -ci 'inline')"
    content_ok "$IMAGE"
}

@test "rmi and a pull again make the layer with the new threshold" {
    inline_fresh again
    pull_n 0 "$IMAGE" > /dev/null 2>&1 || e2e_die "the first pull fails"
    sh_ image rm "$IMAGE" > /dev/null 2>&1
    check "the image is removed" 0 $?
    pull_n -1 "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the second pull fails"; }
    check "the layer has the new threshold" -1 "$(layer_inlines "$STORE")"
    sh_ system gc > /dev/null 2>&1
    expect_objects "$STORE" -1
    expect_inlined "$STORE" -1
    content_ok "$IMAGE"
    sh_ image rm "$IMAGE" > /dev/null 2>&1
    sh_ system gc > /dev/null 2>&1
    check "gc leaves no row of a held file" 0 "$(db "$STORE" 'SELECT count(*) FROM inlined_files')"
    check "and no object" 0 "$(objects "$STORE")"
    pull_n 64 "$IMAGE" > /dev/null 2>&1 || e2e_die "the third pull fails"
    expect_objects "$STORE" 64
    expect_inlined "$STORE" 64
    content_ok "$IMAGE"
}

# --- a layer that is held by its image alone -----------------------------------

@test "N=-1: the layer runs with the objects directory moved aside" {
    inline_fresh aside
    pull_n -1 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
    check "no object" 0 "$(objects "$STORE")"
    inline_stop
    mv "$STORE/objects" "$WORKDIR/objects.away"
    inline_use aside
    content_ok "$IMAGE"
    check "the engine made no object to read it" 0 "$(objects "$STORE")"
    sh_ system check > "$WORKDIR/check.out" 2>&1
    check "a check of the store without an objects directory" 0 $?
}

@test "N=-1: an additional image store that is a copy without objects runs the image" {
    inline_fresh fill
    pull_n -1 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
    inline_stop
    rm -rf "$WORKDIR/copy"
    cp -a "$STORE" "$WORKDIR/copy"
    rm -rf "$WORKDIR/copy/objects"
    chmod -R a-w,go-rwx "$WORKDIR/copy"
    inline_fresh withcopy "additional_image_stores = [\"$WORKDIR/copy\"]"
    check "its image is listed, read-only" "$IMAGE true" \
        "$(sh_ image list --format '{{.Repository}}:{{.Tag}} {{.ReadOnly}}' 2>&1)"
    content_ok "$IMAGE"
    check "the copy has no object and the store got none" 0 "$(objects "$STORE")"
    sh_ system check > "$WORKDIR/check.out" 2>&1
    check "a check with the copy as a store" 0 $?
    sh_ container run -d --name c1 --network none --pull=never "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a detached container of it runs" 0 $?
    check_match "and reads it" "^[0-9a-f]{64}  " "$(sh_ container exec c1 sha256sum /data/f4096 2>&1)"
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
    chmod -R u+w "$WORKDIR/copy"
}

@test "an additional image store of N=64 is used with its objects and its held files" {
    inline_fresh fill64
    pull_n 64 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
    inline_stop
    rm -rf "$WORKDIR/ro64"
    cp -a "$STORE" "$WORKDIR/ro64"
    expect_inlined "$WORKDIR/ro64" 64
    chmod -R a-w,go-rwx "$WORKDIR/ro64"
    before=$(find "$WORKDIR/ro64" -type f -exec sha256sum {} + | sort | sha256sum)
    inline_fresh with64 "additional_image_stores = [\"$WORKDIR/ro64\"]"
    content_ok "$IMAGE"
    sh_ image push --tls-verify=false --compression-format gzip "$IMAGE" "$REG/thr/ro64:1" > "$WORKDIR/push.out" 2>&1 ||
        { cat "$WORKDIR/push.out" >&2; e2e_die "the image of the other store is not pushed"; }
    sh_ system prune -a -f > /dev/null 2>&1
    check "a prune leaves the image" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    check "nothing was copied from the other store" 0 "$(objects "$STORE")"
    inline_stop
    check "nothing in the other store changed" "$before" "$(find "$WORKDIR/ro64" -type f -exec sha256sum {} + | sort | sha256sum)"
    chmod -R u+w "$WORKDIR/ro64"
}

# --- a lazy pull ---------------------------------------------------------------

@test "lazy, N=4096: the held files are read with the registry gone, a bigger one waits for it" {
    inline_fresh lazy
    pull_n 4096 "$IMAGE" --lazy > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the lazy pull fails"; }
    before=$(find "$STORE" -name '*.erofs' -printf '%i\n' | sort | tr '\n' ' ')
    [ -n "$before" ] || e2e_die "the lazy pull made no image of its layer"
    # (sh, sha256sum and their libraries are above N: one run fetches them
    # on demand while the registry is there, as it does no file of /data)
    timeout 60 "$BIN/velarx" --socket "$SOCK" container run --rm --lazy --pull=never --network none "$IMAGE" sha256sum /data/f1 > "$WORKDIR/warm.out" 2>&1 ||
        { cat "$WORKDIR/warm.out" >&2; e2e_die "the first run of the lazy image fails"; }
    inline_registry_stop
    # (a lazy layer holds nothing in the database until it is complete)
    local small='f1 f50 f100 f4095 f4096 hl sl' f out want
    for f in $small; do
        out=$(timeout 60 "$BIN/velarx" --socket "$SOCK" container run --rm --lazy --pull=never --network none "$IMAGE" sha256sum "/data/$f" 2>&1)
        want=$(grep "  $f\$" "$WORKDIR/data.sums" | sed "s|  $f\$|  /data/$f|")
        check "the held file $f is read with the registry gone" "$want" "$out"
    done
    # a file above N is not in the image: its read waits for the registry
    timeout 20 "$BIN/velarx" --socket "$SOCK" container run --name c1 --lazy --pull=never --network none "$IMAGE" sha256sum /data/f4097 > "$WORKDIR/big.out" 2>&1
    check "the file of 4097 bytes is not read without the registry" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
    inline_registry_start
    sh_ image complete "$IMAGE" > "$WORKDIR/complete.out" 2>&1 || { cat "$WORKDIR/complete.out" >&2; e2e_die "the completion fails"; }
    expect_objects "$STORE" 4096
    expect_inlined "$STORE" 4096
    check "the image of the layer is the file of the lazy pull" "$before" \
        "$(find "$STORE" -name '*.erofs' -printf '%i\n' | sort | tr '\n' ' ')"
    content_ok "$IMAGE"
}

@test "lazy, N=-1: nothing is lazy, the pull is complete when it ends" {
    inline_fresh lazyall
    pull_n -1 "$IMAGE" --lazy > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the lazy pull fails"; }
    inline_registry_stop
    check "no pull is in progress" 0 "$(sh_ image pulls 2>&1 | grep -c 'thr/data')"
    expect_objects "$STORE" -1
    expect_inlined "$STORE" -1
    content_ok "$IMAGE"
    inline_registry_start
}

# --- the layers a build, a commit, a load and an import make ----------------------

@test "build and commit make layers with the configured threshold" {
    local n
    for n in 4096 -1; do
        inline_fresh "make$n" "inline_threshold = $n"
        pull_n 0 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
        sh_ image build -q --network none --timestamp 1000000000 -t localhost/inl-built:1 -f "$WORKDIR/ctx/Containerfile" "$WORKDIR/ctx" > "$WORKDIR/build.out" 2>&1 ||
            { cat "$WORKDIR/build.out" >&2; e2e_die "the build fails with N=$n"; }
        # (the files of the new layer: 101 and 5001 and 200003 bytes, the copy of the first)
        check "the file of 101 bytes is held (N=$n)" 0 "$(objects_of_size "$STORE" 101)"
        check "the file of 5001 bytes (N=$n)" "$([ "$n" = -1 ] && echo 0 || echo 1)" "$(objects_of_size "$STORE" 5001)"
        check "the file of 200003 bytes (N=$n)" "$([ "$n" = -1 ] && echo 0 || echo 1)" "$(objects_of_size "$STORE" 200003)"
        check "the files of the new layers that N holds are rows" "$([ "$n" = -1 ] && echo 1 || echo 0)" \
            "$(db "$STORE" 'SELECT count(*) FROM inlined_files WHERE size = 5001')"
        check "so is the file of 101 bytes" 1 \
            "$([ "$(db "$STORE" 'SELECT count(*) FROM inlined_files WHERE size = 101')" -ge 1 ] && echo 1 || echo 0)"
        check "the layers are the base's (N=0) and the new ones" "$([ "$n" = -1 ] && echo '-1 0' || echo '0 4096')" "$(layer_inlines "$STORE")"
        check "the image runs, with the files and the copy of the first" "$(cat "$WORKDIR/ctx.sums"; echo "$(sed -n 's/  b101$//p' "$WORKDIR/ctx.sums")  s2")" \
            "$(built_sums localhost/inl-built:1 | grep -v ' m2$')"
        # a second build is the cache: the same image
        sh_ image build -q --network none --timestamp 1000000000 -t localhost/inl-built:2 -f "$WORKDIR/ctx/Containerfile" "$WORKDIR/ctx" > /dev/null 2>&1
        check "a second build is the image of the first" "$(sh_ image inspect --format '{{.Id}}' localhost/inl-built:1)" \
            "$(sh_ image inspect --format '{{.Id}}' localhost/inl-built:2)"
        # COPY --from reads the held file back
        sh_ image build -q --network none --timestamp 1000000000 -t localhost/inl-from:1 -f "$WORKDIR/ctx/Containerfile.from" "$WORKDIR/ctx" > "$WORKDIR/build.out" 2>&1 ||
            { cat "$WORKDIR/build.out" >&2; e2e_die "COPY --from of a held file fails with N=$n"; }
        check "COPY --from gives the file" "$(sed -n 's/^\([0-9a-f]*\)  b5001$/\1/p' "$WORKDIR/ctx.sums")" \
            "$(sh_ container run --rm --pull=never --network none localhost/inl-from:1 sha256sum /m2 | cut -d' ' -f1)"
        # a commit: a file of 13 bytes and one of 200008
        sh_ container run -d --name c1 --network none --pull=never localhost/inl-built:1 sleep 300 > /dev/null 2>&1
        sh_ container exec c1 sh -c 'echo commit-small > /cs; cp /b /cb; echo more >> /cb' > /dev/null 2>&1
        sh_ container commit c1 localhost/inl-committed:1 > "$WORKDIR/commit.out" 2>&1 ||
            { cat "$WORKDIR/commit.out" >&2; e2e_die "the commit fails with N=$n"; }
        sh_ container rm -t 0 -f c1 > /dev/null 2>&1
        check "the commit holds what N holds: the file of 200008 bytes is an object iff N=4096" "$([ "$n" = -1 ] && echo 0 || echo 1)" \
            "$(objects_of_size "$STORE" 200008)"
        check "the file of 13 bytes is not" 0 "$(objects_of_size "$STORE" 13)"
        check "the committed image has the file" "commit-small" \
            "$(sh_ container run --rm --pull=never --network none localhost/inl-committed:1 cat /cs)"
        check "and the big one" "$( (cat "$WORKDIR/ctx/b200003"; echo more) | sha256sum | cut -d' ' -f1)" \
            "$(sh_ container run --rm --pull=never --network none localhost/inl-committed:1 sha256sum /cb | cut -d' ' -f1)"
        # (the squash of the image reads every held file back)
        sh_ image build -q --network none --squash-all --timestamp 1000000000 -t localhost/inl-squashed:1 -f "$WORKDIR/ctx/Containerfile" "$WORKDIR/ctx" > "$WORKDIR/build.out" 2>&1 ||
            { cat "$WORKDIR/build.out" >&2; e2e_die "the squashed build fails with N=$n"; }
        check "the squashed image has the files" "$(cat "$WORKDIR/ctx.sums"; echo "$(sed -n 's/  b101$//p' "$WORKDIR/ctx.sums")  s2")" \
            "$(built_sums localhost/inl-squashed:1 | grep -v ' m2$')"
    done
}

@test "load and import make layers with the configured threshold" {
    local n
    inline_fresh saver
    pull_n 0 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
    sh_ image save -o "$WORKDIR/saved.tar" "$IMAGE" > /dev/null 2>&1 || e2e_die "the save fails"
    for n in 4096 -1; do
        inline_fresh "load$n" "inline_threshold = $n"
        sh_ image load -q -i "$WORKDIR/saved.tar" > "$WORKDIR/load.out" 2>&1 ||
            { cat "$WORKDIR/load.out" >&2; e2e_die "the load fails with N=$n"; }
        expect_objects "$STORE" "$n"
        expect_inlined "$STORE" "$n"
        content_ok "$IMAGE"
        inline_fresh "import$n" "inline_threshold = $n"
        sh_ image import "$WORKDIR/rootfs.tar" localhost/inl-imported:1 > "$WORKDIR/import.out" 2>&1 ||
            { cat "$WORKDIR/import.out" >&2; e2e_die "the import fails with N=$n"; }
        expect_objects "$STORE" "$n"
        expect_inlined "$STORE" "$n"
        content_ok localhost/inl-imported:1
    done
    rm -f "$WORKDIR/saved.tar"
}

# --- push, save and cp of an inlined image ----------------------------------------

@test "an image of N=-1 is pushed as the image of N=0 is, and pulls back with the same layers" {
    local n t c
    for n in 0 -1 64; do
        t=${n/-/m}
        inline_fresh "push$t"
        pull_n "$n" "$IMAGE_GZIP" > /dev/null 2>&1 || e2e_die "the pull fails"
        for c in gzip zstd; do
            sh_ image push --tls-verify=false --compression-format "${c/zstd/zstd:chunked}" "$IMAGE_GZIP" "$REG/thr/pushed:$c-$t" > "$WORKDIR/push.out" 2>&1 ||
                { cat "$WORKDIR/push.out" >&2; e2e_die "the push of N=$n as $c fails"; }
        done
    done
    for c in gzip zstd; do
        for t in m1 64; do
            check "the manifest pushed as $c from N=$t is the one of N=0" \
                "$(skopeo inspect --raw --tls-verify=false "docker://$REG/thr/pushed:$c-0" | sha256sum)" \
                "$(skopeo inspect --raw --tls-verify=false "docker://$REG/thr/pushed:$c-$t" | sha256sum)"
        done
    done
    # pulled back with another N: the layers are the original's
    inline_fresh pushback
    pull_n 0 "$IMAGE_GZIP" > /dev/null 2>&1
    want=$(sh_ image inspect --format '{{.RootFS.Layers}}' "$IMAGE_GZIP")
    inline_fresh pushback2
    pull_n -1 "$REG/thr/pushed:gzip-m1" > /dev/null 2>&1 || e2e_die "the pull of the pushed image fails"
    check "the layers of the image pushed from N=-1 are the original's" "$want" \
        "$(sh_ image inspect --format '{{.RootFS.Layers}}' "$REG/thr/pushed:gzip-m1")"
    content_ok "$REG/thr/pushed:gzip-m1"
}

@test "an image of N=-1 is saved, copied out of a container and loaded again" {
    inline_fresh saveall
    pull_n -1 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
    sh_ image save -o "$WORKDIR/all.tar" "$IMAGE" > /dev/null 2>&1 || e2e_die "the save fails"
    sh_ container run -d --name c1 --network none --pull=never "$IMAGE" sleep 300 > /dev/null 2>&1
    local s f
    for f in $(ls "$WORKDIR/rootfs/data"); do
        rm -f "$WORKDIR/out"
        sh_ container cp "c1:/data/$f" "$WORKDIR/out" > /dev/null 2>&1
        check "cp of $f" 0 $?
        check "gives the file" "$(sha256sum < "$WORKDIR/rootfs/data/$f")" "$(sha256sum < "$WORKDIR/out")"
    done
    sh_ container export c1 -o "$WORKDIR/export.tar" > /dev/null 2>&1
    check "an export" 0 $?
    check "has the biggest file" "$(sha256sum < "$WORKDIR/rootfs/data/f3145745")" \
        "$(tar -xOf "$WORKDIR/export.tar" data/f3145745 2> /dev/null | sha256sum)"
    # a file a container writes to is copied up: the bytes of the held file and the new ones
    sh_ container exec c1 sh -c 'echo more >> /data/f50 && echo more >> /data/f3145745' > /dev/null 2>&1
    check "a write to a held file" 0 $?
    check "copies it up" "$( (cat "$WORKDIR/rootfs/data/f50"; echo more) | sha256sum | cut -d' ' -f1)" \
        "$(sh_ container exec c1 sha256sum /data/f50 | cut -d' ' -f1)"
    check "also the biggest one" "$( (cat "$WORKDIR/rootfs/data/f3145745"; echo more) | sha256sum | cut -d' ' -f1)" \
        "$(sh_ container exec c1 sha256sum /data/f3145745 | cut -d' ' -f1)"
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
    inline_fresh loaded
    sh_ image load -q -i "$WORKDIR/all.tar" > "$WORKDIR/load.out" 2>&1 || { cat "$WORKDIR/load.out" >&2; e2e_die "the load fails"; }
    expect_objects "$STORE" 0
    content_ok "$IMAGE"
    rm -f "$WORKDIR/all.tar" "$WORKDIR/export.tar" "$WORKDIR/out"
}

# --- verity -----------------------------------------------------------------------

@test "a start that demands the manifest's digests fails for a held layer, the same image at N=0 starts" {
    need_verity
    mkdir -p "$VS"
    export INLINE_ROOT=$VS
    local ref out rc
    inline_fresh vctl
    pull_n 0 "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
    ref=${IMAGE%:*}@$(sh_ image inspect --format '{{.Digest}}' "$IMAGE")
    out=$(sh_ container run --rm --pull=never --network none --security-opt verity=enforce "$ref" true 2>&1)
    check "N=0 starts with verity=enforce" 0 $?
    for n in 64 -1; do
        inline_fresh "venf$n"
        pull_n "$n" "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
        ref=${IMAGE%:*}@$(sh_ image inspect --format '{{.Digest}}' "$IMAGE")
        out=$(sh_ container run --rm --pull=never --network none --security-opt verity=enforce "$ref" true 2>&1); rc=$?
        check "N=$n does not start with verity=enforce" 1 "$([ $rc != 0 ] && echo 1 || echo 0)"
        check_match "and says that the digest is not the manifest's" "digest" "$out"
    done
    unset INLINE_ROOT
}

@test "composefs_digests = require: the pull or the start of a held layer fails with the digest, N=0 is fine" {
    need_verity
    mkdir -p "$VS"
    export INLINE_ROOT=$VS
    local out rc rc2 n
    inline_fresh vreq0 'composefs_digests = "require"'
    out=$(pull_n 0 "$IMAGE" 2>&1) || { echo "$out" >&2; e2e_die "the pull of N=0 fails under require"; }
    content_ok "$IMAGE"
    for n in 64 -1; do
        inline_fresh "vreq$n" 'composefs_digests = "require"'
        out=$(pull_n "$n" "$IMAGE" 2>&1); rc=$?
        rc2=0
        if [ $rc = 0 ]; then
            out="$out
$(sh_ container run --rm --pull=never --network none "$IMAGE" true 2>&1)"
            rc2=$?
        fi
        check "N=$n under require fails, at the pull or at the start" 1 "$([ $rc != 0 ] || [ $rc2 != 0 ] && echo 1 || echo 0)"
        check_match "with the digest as the reason" "digest" "$out"
    done
    unset INLINE_ROOT
}

# --- system check -----------------------------------------------------------------

@test "check passes a store of held files; a damaged held file is found, and --repair fetches nothing" {
    local n out rc before extent
    for n in 64 -1; do
        inline_fresh "chk$n" "fsverity = false"
        pull_n "$n" "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull fails"
        out=$(sh_ system check 2>&1); rc=$?
        check "a full check of N=$n passes" 0 $rc
        check "silently" "" "$out"
        # the first byte of the biggest held file, in the image of the layer
        extent=$(db "$STORE" "SELECT offset FROM inlined_files WHERE size = $([ "$n" = -1 ] && echo 3145745 || echo 50) LIMIT 1")
        [ -n "$extent" ] || e2e_die "no extent in inlined_files"
        img=$(ls "$STORE"/composefs/layer-*.erofs | head -1)
        chmod u+w "$img"
        printf '\xff\xfe\xfd' | dd of="$img" bs=1 seek="$((extent + 5))" conv=notrunc 2> /dev/null
        chmod a-w "$img"
        sh_ system check --quick > /dev/null 2>&1
        check "a quick check does not read the files" 0 $?
        out=$(sh_ system check 2>&1); rc=$?
        check "a flipped byte of a held file fails the check (N=$n)" 125 $rc
        check_match "which names the layer's image" "layer-.*\.erofs|erofs" "$out"
        before=$(registry_requests)
        out=$(sh_ --log-level=debug system check --repair 2>&1); rc=$?
        check_match "the repair says in the debug log that it fetches nothing and what to do" "inline" "$out$(cat "$WORKDIR/chk$n.log")"
        check_match "(rmi, then a pull)" "rmi|image rm" "$out$(cat "$WORKDIR/chk$n.log")"
        check "the repair asked the registry for nothing" "$before" "$(registry_requests)"
        check "the layer is still marked as held" "$n" "$(layer_inlines "$STORE")"
        check "the image is still listed" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
        # the user's remedy: rmi, a pull again
        sh_ image rm -f "$IMAGE" > /dev/null 2>&1
        sh_ system gc > /dev/null 2>&1
        pull_n "$n" "$IMAGE" > /dev/null 2>&1 || e2e_die "the pull after the rmi fails"
        out=$(sh_ system check 2>&1); rc=$?
        check "after rmi and a pull the check passes" 0 $rc
        content_ok "$IMAGE"
    done
}

# --- memory -----------------------------------------------------------------------

@test "a layer of hundreds of MiB is written by the engine and served by the image server with bounded memory" {
    local mb=${E2E_HUGE_MB:-512} dir=$WORKDIR/hugefs
    local avail
    avail=$(df -Pk /var/tmp | awk 'NR == 2 { print $4 }')
    [ "$avail" -gt $((mb * 1024 * 6 + 15 * 1024 * 1024)) ] || skip "less than $((mb * 6 / 1024 + 15)) GiB free in /var/tmp for E2E_HUGE_MB=$mb"
    rm -rf "$dir"
    cp -a "$WORKDIR/rootfs" "$dir"
    head -c "$((mb * 1024 * 1024))" /dev/urandom > "$dir/data/huge"
    printf 'tail' >> "$dir/data/huge"
    tar -C "$dir" -cf "$WORKDIR/huge.tar" .
    huge_sum=$(sha256sum < "$dir/data/huge" | cut -d' ' -f1)
    rm -rf "$dir"
    inline_use src
    sh_ image import "$WORKDIR/huge.tar" localhost/inline-huge:1 > "$WORKDIR/huge.log" 2>&1 &&
        sh_ image push --tls-verify=false --compression-format zstd:chunked localhost/inline-huge:1 "$REG/thr/huge:chunked" >> "$WORKDIR/huge.log" 2>&1 ||
        { cat "$WORKDIR/huge.log" >&2; e2e_die "cannot make the big image"; }
    rm -f "$WORKDIR/huge.tar"
    sh_ image rm localhost/inline-huge:1 > /dev/null 2>&1

    inline_fresh huge
    local hwm_before hwm_after
    hwm_before=$(rss_kb "$DAEMON_PID" VmHWM)
    pull_n -1 "$REG/thr/huge:chunked" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    hwm_after=$(rss_kb "$DAEMON_PID" VmHWM)
    echo "# the engine's peak: $hwm_before kB before the pull, $hwm_after kB after, for a layer of $mb MiB" >&3
    [ "$hwm_after" -lt $((hwm_before + 200 * 1024)) ] || e2e_die "the engine's peak grew by $((hwm_after - hwm_before)) kB for a layer of $mb MiB: the writer does not stream"
    check "the store has the file in the image of its layer" 0 "$(objects_of_size "$STORE" "$((mb * 1024 * 1024 + 4))")"
    sh_ container run -d --name c1 --network none --pull=never "$REG/thr/huge:chunked" sleep 300 > /dev/null 2>&1
    check "a container runs" 0 $?
    local pid=
    if [ "$(id -u)" != 0 ]; then
        pid=$(monitor_log c1 | server_pid)
        [ -n "$pid" ] || e2e_die "no image server in the log of the monitor"
        sh_ container exec c1 ls -l /data > /dev/null 2>&1
        echo "# the image server's peak when the container started: $(rss_kb "$pid" VmHWM) kB" >&3
        [ "$(rss_kb "$pid" VmHWM)" -lt $((mb * 1024 / 4)) ] ||
            e2e_die "the image server's peak is $(rss_kb "$pid" VmHWM) kB for an image of $mb MiB: it holds the image in memory"
    fi
    check "the container reads the whole file" "$huge_sum" "$(sh_ container exec c1 sha256sum /data/huge | cut -d' ' -f1)"
    if [ -n "$pid" ]; then
        echo "# the image server's anonymous memory after the read: $(rss_kb "$pid" RssAnon) kB" >&3
        [ "$(rss_kb "$pid" RssAnon)" -lt $((mb * 1024 / 4)) ] ||
            e2e_die "the image server holds $(rss_kb "$pid" RssAnon) kB of anonymous memory after a read of $mb MiB"
    fi
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
}
