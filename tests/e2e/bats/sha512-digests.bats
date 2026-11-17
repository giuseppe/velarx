# SPDX-License-Identifier: Apache-2.0
# Images whose digests are sha512: every digest of the image is checked with
# its own algorithm, an image is named by `NAME@sha512:D` or by
# `NAME:TAG@sha512:D` (the tag is where a registry that addresses its manifests
# by sha256 only is asked for the bytes, which D then checks), its id is the 128
# hex digits of its sha512, and the chain of trust of a start names the
# algorithm of every link.  One store holds the sha256 and the sha512 objects
# (names of 62 and 126 digits), an image of sha512 layers pulls, runs, is
# removed and collected, and is seen by `system check`.  The registries are the file's own (tests/e2e/sha512_registry.py: one that
# addresses manifests by sha256 only, as registry:2 and registry:3 do, and one
# that takes the sha512 too, as zot does).
#
# The tests that enforce the digests need a store on a file system with
# fs-verity, as verity-digest.bats (root: a loop device of the work directory,
# in a mount namespace of its own; rootless: VELARX_VERITY_DIR); the others
# skip.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/sha512-digests.bats

load helpers
load verity

images () { python3 -I "$E2E_DIR/sha512_images.py" "$@"; }

setup_file () {
    command -v python3 > /dev/null || skip "no python3"
    command -v curl > /dev/null || skip "no curl"
    e2e_setup_file
    start_registry distribution
    export DIST=$REGISTRY
    start_registry zot
    export ZOT=$REGISTRY
    curl -sf -m 5 "http://$DIST/v2/" > /dev/null || e2e_die "no registry at $DIST"
    curl -sf -m 5 "http://$ZOT/v2/" > /dev/null || e2e_die "no registry at $ZOT"
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$DIST"
insecure = true

[[registry]]
location = "$ZOT"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # (a signature of the sigstore kind goes to a lookaside: the guard on
    # sha512 manifests is reached after the destination is checked)
    mkdir -p "$XDG_CONFIG_HOME/velarx/registries.d"
    cat > "$XDG_CONFIG_HOME/velarx/registries.d/e2e.yaml" <<YAML
docker:
  $DIST:
    lookaside: file://$WORKDIR/sigstore
    use-sigstore-attachments: true
YAML
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[pull]
registries_d = "$XDG_CONFIG_HOME/velarx/registries.d"
TOML
    e2e_start_daemon
    e2e_make_image localhost/e2e-base:1
    export REPO=sha512/img
    local reg
    for reg in "$DIST" "$ZOT"; do
        sc image push --tls-verify=false --compression-format gzip localhost/e2e-base:1 "$reg/$REPO:base" > /dev/null || e2e_die "push to $reg"
    done
    export MIXED; MIXED=$(images mixed "$DIST" "$REPO" base mixed) || e2e_die "mixed in $DIST"
    export ALL; ALL=$(images all "$DIST" "$REPO" base all) || e2e_die "all in $DIST"
    export MIXED_ZOT; MIXED_ZOT=$(images mixed "$ZOT" "$REPO" base mixed) || e2e_die "mixed in $ZOT"
    export ALL_ZOT; ALL_ZOT=$(images all "$ZOT" "$REPO" base all) || e2e_die "all in $ZOT"
    # a store on a file system with fs-verity, where there is one
    e2e_verity_store
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -z "${VS:-}" ] || [ "$(id -u)" = 0 ] || rm -rf "$VS"
    local pid
    for pid in $(cat "$WORKDIR/registry.pids" 2> /dev/null); do kill "$pid" 2> /dev/null; done
    e2e_teardown_file
}

# the manifests are sha512 digests
@test "the images are made: sha512 manifests over sha256 and sha512 layers" {
    check_match "the mixed image" '^sha512:[0-9a-f]{128}$' "$MIXED"
    check_match "the image of sha512 layers" '^sha512:[0-9a-f]{128}$' "$ALL"
}

@test "NAME:TAG@sha512:D pulls an image of a sha512 manifest, configuration and diff ids, whichever the registry" {
    for pair in "$DIST $MIXED" "$ZOT $MIXED_ZOT"; do
        reg=${pair% *} d=${pair#* }
        store=$WORKDIR/pull-${reg##*:}
        out=$(shs "$store" image pull --tls-verify=false "$reg/$REPO:mixed@$d" 2>&1)
        check "pull from $reg" 0 $?
        id=$(shs "$store" image inspect --format '{{.Id}}' "$reg/$REPO@$d") || exit 1
        # (the id podman shows is the config's digest, here a sha512)
        check_match "the id is 128 hex digits" '^[0-9a-f]{128}$' "$id"
        check "the digest" "$d" "$(shs "$store" image inspect --format '{{.Digest}}' "$reg/$REPO@$d")"
        out=$(shs "$store" image inspect --format '{{range .RepoDigests}}{{.}} {{end}}' "$reg/$REPO@$d")
        check_match "the repo digest names its algorithm" "$reg/$REPO@$d" "$out"
        shs "$store" system check > /dev/null 2>&1
        check "system check" 0 $?
    done
}

@test "a registry that addresses manifests by sha256 only is told by name; one that takes the sha512 pulls NAME@sha512:D" {
    store=$WORKDIR/bare-dist
    out=$(shs "$store" image pull --tls-verify=false "$DIST/$REPO@$MIXED" 2>&1)
    check "the bare digest on a distribution registry" 125 $?
    check_match "named" "may not address manifests by sha512; name the tag as well \(NAME:TAG@$MIXED\)" "$out"
    store=$WORKDIR/bare-zot
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$MIXED_ZOT" > /dev/null 2>&1
    check "the bare digest on a registry that has it" 0 $?
}

@test "a sha512 that is not the manifest's is refused, naming the digests" {
    wrong=sha512:$(printf '%0128d' 1)
    store=$WORKDIR/wrong
    out=$(shs "$store" image pull --tls-verify=false "$DIST/$REPO:mixed@$wrong" 2>&1)
    check "refused" 125 $?
    check_match "both named" "digest mismatch: expected $wrong, got $MIXED" "$out"
    check "nothing stored" "" "$(shs "$store" image ls -q 2> /dev/null)"
}

@test "pulled by its tag, the image is named by the sha512 of its manifest (its configuration's algorithm) and its sha512 links are checked" {
    store=$WORKDIR/by-tag
    shs "$store" image pull --tls-verify=false "$DIST/$REPO:mixed" > /dev/null 2>&1
    check "pull" 0 $?
    check "named by its sha512" "$MIXED" "$(shs "$store" image inspect --format '{{.Digest}}' "$DIST/$REPO:mixed")"
    check_match "the id is 128 hex digits" '^[0-9a-f]{128}$' "$(shs "$store" image inspect --format '{{.Id}}' "$DIST/$REPO:mixed")"
    shs "$store" system check > /dev/null 2>&1
    check "system check" 0 $?
}

# the names of the objects of a store, by the number of digits after the directory
objects_of () { # store, digits
    find "$1/objects" -mindepth 2 -type f -name "$(printf '%*s' "$2" '' | tr ' ' '?')" 2> /dev/null | wc -l
}

@test "an image of sha512 layers pulls, runs, is removed and collected, in a store that holds sha256 objects too" {
    store=$WORKDIR/all
    # (an image of sha256 layers first: both kinds of objects in one store)
    shs "$store" image pull --tls-verify=false "$DIST/$REPO:base" > /dev/null 2>&1 || exit 1
    sha256_objects=$(objects_of "$store" 62)
    [ "$sha256_objects" -gt 0 ] || exit 1
    out=$(shs "$store" image pull --tls-verify=false "$DIST/$REPO:all@$ALL" 2>&1)
    check "pull" 0 $?
    check_match "named by its sha512" "$ALL" "$(shs "$store" image inspect --format '{{.Digest}}' "$DIST/$REPO@$ALL")"
    if [ "$(objects_of "$store" 126)" -eq 0 ]; then
        echo "no object of 126 digits"; exit 1
    fi
    # (the same content under the two algorithms is two objects: the
    # sha256 ones are still all there)
    check "the sha256 objects are untouched" "$sha256_objects" "$(objects_of "$store" 62)"
    check_match "the EROFS images are of the layers' algorithm" "layer-sha512-[0-9a-f]{128}\\.v4\\.erofs" "$(ls "$store/composefs")"
    out=$(shs "$store" run --rm --network none "$DIST/$REPO@$ALL" echo from-sha512 2>&1)
    check "run" 0 $?
    check_match "ran" "from-sha512" "$out"
    shs "$store" system check > /dev/null 2>&1
    check "system check" 0 $?
    shs "$store" image rm "$DIST/$REPO@$ALL" > /dev/null 2>&1
    check "rm" 0 $?
    shs "$store" system prune -f > /dev/null 2>&1
    check "the sha512 objects are collected" 0 "$(objects_of "$store" 126)"
    check "the sha256 objects stay" "$sha256_objects" "$(objects_of "$store" 62)"
    shs "$store" system check > /dev/null 2>&1
    check "system check after the collection" 0 $?
    shs "$store" run --rm --network none "$DIST/$REPO:base" true > /dev/null 2>&1
    check "the sha256 image still runs" 0 $?
}

@test "the same content under both algorithms is two objects, and a mixed image runs next to them" {
    store=$WORKDIR/both
    shs "$store" image pull --tls-verify=false "$DIST/$REPO:base" > /dev/null 2>&1 || exit 1
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO:all@$ALL_ZOT" > /dev/null 2>&1 || exit 1
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO:mixed@$MIXED_ZOT" > /dev/null 2>&1 || exit 1
    # (the layers have the same files: as many sha512 objects as sha256 ones)
    check "as many objects of both" "$(objects_of "$store" 62)" "$(objects_of "$store" 126)"
    for img in "$ZOT/$REPO@$ALL_ZOT" "$ZOT/$REPO@$MIXED_ZOT"; do
        out=$(shs "$store" run --rm --network none "$img" echo ok 2>&1)
        check "run $img" 0 $?
    done
    shs "$store" system check > /dev/null 2>&1
    check "system check" 0 $?
    # no merged-tree annotation for the mixed image
    check "none" 0 "$(shs "$store" image inspect --format '{{json .Annotations}}' "$ZOT/$REPO@$MIXED_ZOT" | grep -c 'composefs.merged')"
    # (the mixed image shares the sha256 layers of the base, under its sha512
    # diff ids: its archive has the layers by those, and loads elsewhere)
    shs "$store" image save --format oci-archive -o "$WORKDIR/mixed.tar" "$ZOT/$REPO@$MIXED_ZOT" > /dev/null 2>&1
    check "save of the mixed image" 0 $?
    shs "$WORKDIR/loaded" image load -i "$WORKDIR/mixed.tar" > /dev/null 2>&1
    check "load of it" 0 $?
    out=$(shs "$WORKDIR/loaded" run --rm --network none "$(shs "$WORKDIR/loaded" image list -q | head -1)" echo loaded 2>&1)
    check_match "and it runs" "loaded" "$out"
    # removing the sha256 image leaves the sha512 objects of the same content
    sha512_objects=$(objects_of "$store" 126)
    shs "$store" image rm "$DIST/$REPO:base" > /dev/null 2>&1
    check "rm of the sha256 image" 0 $?
    shs "$store" system prune -f > /dev/null 2>&1
    check "the sha512 objects stay" "$sha512_objects" "$(objects_of "$store" 126)"
    out=$(shs "$store" run --rm --network none "$ZOT/$REPO@$ALL_ZOT" echo still 2>&1)
    check_match "the sha512 image still runs" "still" "$out"
    shs "$store" system check > /dev/null 2>&1
    check "system check after the removal" 0 $?
}

@test "a mixed image over the layers of a sha256 image is enforced, pushed and pulled again from the store" {
    need_verity
    store=$VS/shared
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO:base" > /dev/null 2>&1 || exit 1
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$MIXED_ZOT" > /dev/null 2>&1
    check "pull of the mixed image over the same layers" 0 $?
    # (each image's diff ids are held against those recorded in its algorithm)
    for img in "$ZOT/$REPO:base" "$ZOT/$REPO@$MIXED_ZOT"; do
        out=$(shs "$store" run --rm --network none --security-opt verity=enforce "$img" echo enforced 2>&1)
        check_match "enforced run of $img" "enforced" "$out"
    done
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$MIXED_ZOT" > /dev/null 2>&1
    check "pulled again" 0 $?
    shs "$store" image push --tls-verify=false "$ZOT/$REPO@$MIXED_ZOT" "$ZOT/$REPO:mixed-again" > /dev/null 2>&1
    check "push of the mixed image" 0 $?
}

@test "an image of sha512 layers is seen and run from a read-only additional store" {
    ro=$WORKDIR/ro
    shs "$ro" image pull --tls-verify=false "$ZOT/$REPO@$ALL_ZOT" > /dev/null 2>&1 || exit 1
    cat > "$WORKDIR/extra.toml" <<EOT
[storage]
root = "$WORKDIR/main"
additional_image_stores = ["$ro"]
EOT
    out=$("$SH" --config "$WORKDIR/extra.toml" image list --format '{{.Digest}} {{.ReadOnly}}' 2>&1)
    check_match "its image is listed, read-only" "$ALL_ZOT true" "$out"
    out=$("$SH" --config "$WORKDIR/extra.toml" run --rm --pull=never --network none "$ZOT/$REPO@$ALL_ZOT" echo from-extra 2>&1)
    check "it runs without a pull" 0 $?
    check_match "ran" "from-extra" "$out"
    check "the main store took no object of it" 0 "$(objects_of "$WORKDIR/main" 126)"
}

@test "push --sign-by* of an image with a sha512 manifest digest is refused by name" {
    store=$WORKDIR/sign
    shs "$store" image pull --tls-verify=false "$DIST/$REPO:mixed@$MIXED" > /dev/null 2>&1 || exit 1
    printf 'pass' > "$WORKDIR/pass"
    "$SH" image generate-sigstore-key --output-prefix "$WORKDIR/key" --passphrase-file "$WORKDIR/pass" > /dev/null 2>&1 || exit 1
    out=$(shs "$store" image push --tls-verify=false --sign-by-sigstore-private-key "$WORKDIR/key.private" --sign-passphrase-file "$WORKDIR/pass" "$DIST/$REPO:mixed@$MIXED" "$DIST/$REPO:signed" 2>&1)
    check "refused" 125 $?
    check_match "named" "signing an image with a sha512 manifest digest is not supported yet" "$out"
    check "nothing pushed" 404 "$(curl -s -o /dev/null -w '%{http_code}' "http://$DIST/v2/$REPO/manifests/signed")"
}

@test "an enforced run by NAME@sha512:D verifies every link with its own algorithm and says so" {
    need_verity
    store=$VS/chain
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$MIXED_ZOT" > /dev/null || exit 1
    out=$(shs "$store" --log-level=debug run --rm --network none --security-opt verity=enforce "$ZOT/$REPO@$MIXED_ZOT" true 2>&1)
    check "run" 0 $?
    chain=$(printf '%s\n' "$out" | sed -n 's/^.*verity chain: //p')
    check_match "the root is the sha512" "^root typed $MIXED_ZOT" "$chain"
    check_match "the manifest and its config" "$MIXED_ZOT manifest -> sha512:[0-9a-f]{128} config" "$chain"
    check_match "the layer blob is the sha256 of its descriptor" "$MIXED_ZOT manifest -> sha256:[0-9a-f]{64} layer 1 blob -> " "$chain"
    printf '%s\n' "$chain" | sed 's/^/verity chain: /' | python3 -I "$E2E_DIR/verity_chain.py" --expect complete > /dev/null
    check "the chain is well formed" 0 $?
    id=$(shs "$store" create --network none --security-opt verity=enforce "$ZOT/$REPO@$MIXED_ZOT" true) || exit 1
    shs "$store" start -a --verify-image "$MIXED_ZOT" "$id" > /dev/null 2>&1 < /dev/null
    check "--verify-image sha512:D" 0 $?
    out=$(shs "$store" start -a --verify-image "sha512:$(printf '%0128d' 1)" "$id" 2>&1 < /dev/null)
    check_match "another sha512 is refused" "the stored manifest hashes to $MIXED_ZOT, not sha512:0+1" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "--verify-image of the image's sha256 is refused by name for an image named by its sha512" {
    need_verity
    store=$VS/other
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$MIXED_ZOT" > /dev/null || exit 1
    id=$(shs "$store" create --network none --security-opt verity=enforce "$ZOT/$REPO@$MIXED_ZOT" true) || exit 1
    sha256=sha256:$(shs "$store" image inspect --format '{{.Digest}}' "$ZOT/$REPO@$MIXED_ZOT" | sha256sum | cut -d' ' -f1)
    out=$(shs "$store" start -a --verify-image "$sha256" "$id" 2>&1 < /dev/null)
    check_match "named by sha512" "the image is named by $MIXED_ZOT, not by a sha256 digest: pass that digest" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "an enforced run of an image of sha512 layers checks the EROFS images with SHA-512 fs-verity" {
    need_verity
    command -v fsverity > /dev/null || skip "no fsverity tool"
    store=$VS/enforced-all
    out=$(shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$ALL_ZOT" 2>&1)
    check "pull on a file system with fs-verity" 0 $?
    # (the EROFS image of the layer has SHA-512 fs-verity: the digest a
    # manifest states for it, and the objects are of 126 digits)
    erofs=$(fsverity measure "$store"/composefs/layer-sha512-*.v4.erofs | awk '{print $1}')
    check_match "the image has a SHA-512 digest" '^sha512:[0-9a-f]{128}$' "$erofs"
    [ "$(objects_of "$store" 126)" -gt 0 ] || exit 1
    # a manifest of the same image that states it (the image is then one the
    # digests of which can be enforced)
    stated=$(images state "$ZOT" "$REPO" all all-stated "$erofs") || exit 1
    shs "$store" image pull --tls-verify=false "$ZOT/$REPO:all-stated@$stated" > /dev/null 2>&1
    check "pull of the stated image" 0 $?
    out=$(shs "$store" --log-level=debug run --rm --network none --security-opt verity=enforce "$ZOT/$REPO@$stated" true 2>&1)
    rc=$?
    [ "$rc" = 0 ] || printf '%s\n' "$out" | tail -15 >&2
    check "run" 0 $rc
    chain=$(printf '%s\n' "$out" | sed -n 's/^.*verity chain: //p')
    check_match "the layers are named by sha512" "$stated manifest -> sha512:[0-9a-f]{128} layer 1 blob -> sha512:" "$chain"
    printf '%s\n' "$chain" | sed 's/^/verity chain: /' | python3 -I "$E2E_DIR/verity_chain.py" --expect complete > /dev/null
    check "the chain is well formed" 0 $?
    id=$(shs "$store" create --network none --security-opt verity=enforce "$ZOT/$REPO@$stated" true) || exit 1
    shs "$store" start -a --verify-image "$stated" "$id" > /dev/null 2>&1 < /dev/null
    check "--verify-image sha512:D" 0 $?
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the image not stating it is refused by name, not run unchecked
    out=$(shs "$store" run --rm --network none --security-opt verity=enforce "$ZOT/$REPO@$ALL_ZOT" true 2>&1)
    check "unstated is refused" 125 $?
    check_match "named" "its EROFS image is recorded with the fs-verity digest sha512:" "$out"
}

# A kernel without the SHA-512 hash of fs-verity, under a store whose file
# system has fs-verity: the ioctl that enables it says ENOPKG for SHA-512
# (an LD_PRELOAD of the test makes it say so: this kernel has the hash).
@test "a store whose fs-verity lacks SHA-512 refuses the pull of a sha512 image by name, and stores nothing of it" {
    need_verity
    command -v cc > /dev/null || skip "no C compiler"
    cat > "$WORKDIR/nosha512.c" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <linux/fsverity.h>
int ioctl(int fd, unsigned long request, ...)
{
    static int (*real)(int, unsigned long, ...);
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (!real)
        real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    if (request == FS_IOC_ENABLE_VERITY && arg != NULL
        && ((struct fsverity_enable_arg *) arg)->hash_algorithm == FS_VERITY_HASH_ALG_SHA512) {
        errno = ENOPKG;
        return -1;
    }
    return real(fd, request, arg);
}
C
    cc -shared -fPIC -o "$WORKDIR/nosha512.so" "$WORKDIR/nosha512.c" -ldl || skip "cannot build the preload library"
    store=$VS/nosha512
    LD_PRELOAD=$WORKDIR/nosha512.so shs "$store" image pull --tls-verify=false "$DIST/$REPO:base" > /dev/null 2>&1
    check "a sha256 image pulls" 0 $?
    out=$(LD_PRELOAD=$WORKDIR/nosha512.so shs "$store" image pull --tls-verify=false "$ZOT/$REPO@$ALL_ZOT" 2>&1)
    check "the sha512 image is refused" 125 $?
    check_match "naming the hash" "fs-verity with SHA-512 is not available here" "$out"
    check "no object of it" 0 "$(objects_of "$store" 126)"
    shs "$store" image exists "$ZOT/$REPO@$ALL_ZOT" 2> /dev/null
    check "no image of it" 1 $?
}
