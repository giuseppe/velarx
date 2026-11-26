# SPDX-License-Identifier: Apache-2.0
# The check at every start of a container: the stored manifest against its
# image id, the digests of the layers from that manifest handed to the monitor
# (monitor.json of its run directory), `--security-opt verity=enforce` and
# `[storage] composefs_digests = "require"`.  The repository is the file's own
# (velarx-e2e/verity-start-PID) in the local registry.
#
# The tests that enforce the digests need a store on a file system with
# fs-verity: as root a loop device of the work directory (ext4 -O verity), made
# in the mount namespace of the file (run it as
# `unshare -m --propagation private bats ...`, tests/e2e/run-all.sh does not),
# rootless a directory of the user on such a file system, VELARX_VERITY_DIR; the
# others skip.
#
#   VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/verity-start.bats

load helpers
load verity

run_in () { # store, image, arguments of run (before the image)...
    local store=$1 image=$2
    shift 2
    shs "$store" run --rm --network none "$@" "$image" cat /etc/alpine-release 2>&1
}

setup_file () {
    export REG=$E2E_REGISTRY
    command -v curl > /dev/null || skip "no curl"
    command -v python3 > /dev/null || skip "no python3"
    command -v crun > /dev/null || skip "no crun"
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    export SEALED=$REG/velarx-e2e/verity-start-$$:zstd
    # an image whose layers state no digest of their EROFS images (another
    # writer's): the one of the registry with the digests taken off, whoever
    # wrote it
    export IMG=$REG/velarx-e2e/verity-start-plain-$$:1
    python3 -I "$E2E_DIR/registry_images.py" copy "$REG" alpine chunked "velarx-e2e/verity-start-plain-$$" 1 > /dev/null ||
        e2e_die "an image without digests"
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$REG"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # an image velarx made: its layers state the digests of their EROFS images
    shs "$WORKDIR/seal" image pull --tls-verify=false "$IMG" > /dev/null || e2e_die "pull"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format gzip "$IMG" "${SEALED%:*}:gz" > /dev/null || e2e_die "push"
    shs "$WORKDIR/seal" image pull --tls-verify=false "${SEALED%:*}:gz" > /dev/null || e2e_die "pull again"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format zstd:chunked "${SEALED%:*}:gz" "$SEALED" > /dev/null || e2e_die "push zstd"
    # a store on a file system with fs-verity, where there is one
    e2e_verity_store
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -z "${VS:-}" ] || [ "$(id -u)" = 0 ] || rm -rf "$VS"
    e2e_teardown_file
}

db_of () { echo "$1/db.sqlite"; }

@test "a start without enforcement runs an image with and without the digests" {
    for image in "$SEALED" "$IMG"; do
        out=$(shs "$WORKDIR/plain" image pull --tls-verify=false "$image" 2>&1) || { echo "$out"; exit 1; }
        out=$(run_in "$WORKDIR/plain" "$image")
        check_match "the image runs ($image)" '^[0-9]+\.[0-9]+' "$out"
    done
}

@test "verity takes enforce only" {
    out=$(shs "$WORKDIR/plain" run --rm --network none --security-opt verity=on "$IMG" true 2>&1)
    check "refused" 125 $?
    check "the message" 'Error: invalid --security-opt verity value "on", must be "enforce" or "off"' "$out"
}

@test "an edited manifest in the database is refused at the start" {
    store=$WORKDIR/edited
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    check "it runs" 0 "$(run_in "$store" "$SEALED" > /dev/null; echo $?)"
    python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE images SET manifest = manifest || char(10)")
c.commit()' "$(db_of "$store")" || exit 1
    out=$(run_in "$store" "$SEALED")
    check_match "the manifest is not the one its id names" "the stored manifest of image [0-9a-f]{12} is not the one its id names .*pull the image again" "$out"
}

@test "the digest of a layer edited in the database is refused at an enforced start" {
    need_verity
    store=$VS/recorded
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("UPDATE layers SET erofs = \"sha256:\" || printf(\"%064d\", 7) WHERE erofs IS NOT NULL")
c.commit()' "$(db_of "$store")" || exit 1
    out=$(run_in "$store" "$SEALED" --security-opt verity=enforce)
    check_match "the record is not what the manifest states" "layer 1 of [0-9]+ .*recorded with the fs-verity digest sha256:0+7, the manifest says sha256:[0-9a-f]{64}.*--security-opt verity=enforce" "$out"
}

@test "enforcing needs fs-verity of the store, never a silent downgrade" {
    [ -z "$VS" ] || skip "this machine has a store with fs-verity"
    store=$WORKDIR/noverity
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    out=$(run_in "$store" "$SEALED" --security-opt verity=enforce)
    check_match "an error" "digests of the EROFS images are enforced and the image .* has no fs-verity" "$out"
}

@test "an enforced start of an image that states its digests runs" {
    need_verity
    store=$VS/enforced
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    out=$(run_in "$store" "$SEALED" --security-opt verity=enforce)
    check_match "by the container" '^[0-9]+\.[0-9]+' "$out"
    # the volume of an image: the same chain
    out=$(shs "$store" run --rm --network none --security-opt verity=enforce \
        --mount "type=image,source=$SEALED,destination=/img" "$SEALED" cat /img/etc/alpine-release 2>&1)
    check_match "an image mount" '^[0-9]+\.[0-9]+' "$out"
}

@test "an enforced start of an image without annotations is refused" {
    need_verity
    store=$VS/unannotated
    shs "$store" image pull --tls-verify=false "$IMG" > /dev/null || exit 1
    check_match "it runs when it is not enforced" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$IMG")"
    out=$(run_in "$store" "$IMG" --security-opt verity=enforce)
    check_match "refused, the layer and the option named" "layer 1 of [0-9]+ .*states no EROFS digest .*--security-opt verity=enforce" "$out"
    # an image mount of such an image is refused too
    out=$(shs "$store" run --rm --network none --security-opt verity=enforce \
        --mount "type=image,source=$IMG,destination=/img" "$IMG" true 2>&1)
    check_match "an image mount" "states no EROFS digest" "$out"
}

@test "a layer image replaced by a copy without fs-verity is refused when enforced" {
    need_verity
    store=$VS/tampered
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    check_match "it runs" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$SEALED" --security-opt verity=enforce)"
    shs "$store" create --name tampered --network none --security-opt verity=enforce "$SEALED" cat /etc/alpine-release > /dev/null || exit 1
    for f in "$store"/composefs/layer-*.v5.erofs; do
        cp "$f" "$f.copy" && rm -f "$f" && mv "$f.copy" "$f"
    done
    out=$(shs "$store" start -a tampered 2>&1)
    check "refused" 1 "$([ "$out" != "${out#*Error}" ] && echo 1 || echo 0)"
    check_match "at the start (the driver measures the images of a root engine, the monitor those of the plans it mounts)" "cannot be measured .*digests are enforced" "$out"
    # (a container made now is refused when it is created)
    out=$(run_in "$store" "$SEALED" --security-opt verity=enforce)
    check_match "and a new one at its creation" "enforced and the image .* has no fs-verity" "$out"
}

@test "a symlink in place of a layer image is refused, even to the verified file" {
    need_verity
    store=$VS/linked
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" create --name linked --network none --security-opt verity=enforce "$SEALED" cat /etc/alpine-release > /dev/null || exit 1
    for f in "$store"/composefs/layer-*.v5.erofs; do
        mv "$f" "$f.moved" && ln -s "$(basename "$f.moved")" "$f"
    done
    # (the file the link names has the digest the manifest states: the name is
    # what is refused, the image is opened by a name that is no link)
    out=$(shs "$store" start -a linked 2>&1)
    check_match "refused by the monitor" "layer-(toc-)?sha256-[0-9a-f]{64}\\.v5\\.erofs: .*symbolic links" "$out"
    for f in "$store"/composefs/layer-*.v5.erofs; do
        rm -f "$f" && mv "$f.moved" "$f"
    done
    out=$(shs "$store" start -a linked 2>&1)
    check_match "and it runs with the file in place" '^[0-9]+\.[0-9]+' "$out"
    shs "$store" rm -t 0 -f linked > /dev/null 2>&1
}

@test "a layer image replaced by another file with fs-verity is refused by its digest" {
    need_verity
    store=$VS/swapped
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" create --name swapped --network none --security-opt verity=enforce "$SEALED" cat /etc/alpine-release > /dev/null || exit 1
    # the image and one byte more (an EROFS that mounts, of another digest),
    # with fs-verity
    for f in "$store"/composefs/layer-*.v5.erofs; do
        { cat "$f"; printf x; } > "$f.other" || exit 1
        python3 -I -c '
import fcntl, os, struct, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
# FS_IOC_ENABLE_VERITY: version 1, SHA-256, blocks of 4096 bytes, no salt
fcntl.ioctl(fd, 0x40806685, struct.pack("=IIIIQIIQ88x", 1, 1, 4096, 0, 0, 0, 0, 0))' "$f.other" || exit 1
        chmod 0444 "$f.other"
        mv "$f" "$f.moved" && mv "$f.other" "$f"
    done
    out=$(shs "$store" start -a swapped 2>&1)
    check_match "refused at the start" "layer-(toc-)?sha256-[0-9a-f]{64}\\.v5\\.erofs has the fs-verity digest sha256:[0-9a-f]{64}, expected" "$out"
    check "not run" 1 "$([ "$out" != "${out#*Error}" ] && echo 1 || echo 0)"
    for f in "$store"/composefs/layer-*.v5.erofs; do
        rm -f "$f" && mv "$f.moved" "$f"
    done
    out=$(shs "$store" start -a swapped 2>&1)
    check_match "and it runs with its own image" '^[0-9]+\.[0-9]+' "$out"
    shs "$store" rm -t 0 -f swapped > /dev/null 2>&1
}

# One byte of an image changed, the size kept (an image with fs-verity cannot
# be written: a copy changed and sealed again takes its place): the driver
# measures each image on the descriptor it hands over, so the start is
# refused before anything is mounted, and no image server is left to serve
# it (rootless, the server is what would serve these layers).
@test "a layer image with one byte changed is refused at an enforced start, and nothing serves it" {
    need_verity
    store=$VS/onebyte
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" create --name onebyte --network none --security-opt verity=enforce "$SEALED" cat /etc/alpine-release > /dev/null || exit 1
    id=$(shs "$store" inspect --format '{{.Id}}' onebyte)
    for f in "$store"/composefs/layer-*.v5.erofs; do
        python3 -I -c '
import fcntl, os, struct, sys
src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
# a byte in the middle of the image, flipped
data[len(data) // 2] ^= 0x01
with open(dst, "wb") as out:
    out.write(data)
fd = os.open(dst, os.O_RDONLY)
# FS_IOC_ENABLE_VERITY: version 1, SHA-256, blocks of 4096 bytes, no salt
fcntl.ioctl(fd, 0x40806685, struct.pack("=IIIIQIIQ88x", 1, 1, 4096, 0, 0, 0, 0, 0))' "$f" "$f.other" || exit 1
        check "the same size" "$(stat -c %s "$f")" "$(stat -c %s "$f.other")"
        chmod 0444 "$f.other"
        mv "$f" "$f.moved" && mv "$f.other" "$f"
    done
    out=$(shs "$store" start -a onebyte 2>&1)
    check "not run" 1 "$([ "$out" != "${out#*Error}" ] && echo 1 || echo 0)"
    check_match "refused by its digest" "layer-(toc-)?sha256-[0-9a-f]{64}\\.v5\\.erofs has the fs-verity digest sha256:[0-9a-f]{64}, expected" "$out"
    check "no image server serves it" "" "$(image_server_of "$id")"
    for f in "$store"/composefs/layer-*.v5.erofs; do
        rm -f "$f" && mv "$f.moved" "$f"
    done
    out=$(shs "$store" start -a onebyte 2>&1)
    check_match "and it runs with its own image" '^[0-9]+\.[0-9]+' "$out"
    shs "$store" rm -t 0 -f onebyte > /dev/null 2>&1
}

# Not enforced, the image of a layer is still measured at every start against
# the digest the engine recorded for it at the pull: by the storage driver
# where it makes the kernel mount (a root engine), by the monitor where it
# mounts or serves the plan.  A file put in its place with another digest, or
# a link to it, is refused; the image back in place runs.
@test "a layer image replaced by another file with fs-verity, or a link, is refused at a start that does not enforce" {
    need_verity
    store=$VS/swapped-off
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" create --name swapped-off --network none "$SEALED" cat /etc/alpine-release > /dev/null || exit 1
    for f in "$store"/composefs/layer-*.v5.erofs; do
        { cat "$f"; printf x; } > "$f.other" || exit 1
        python3 -I -c '
import fcntl, os, struct, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
# FS_IOC_ENABLE_VERITY: version 1, SHA-256, blocks of 4096 bytes, no salt
fcntl.ioctl(fd, 0x40806685, struct.pack("=IIIIQIIQ88x", 1, 1, 4096, 0, 0, 0, 0, 0))' "$f.other" || exit 1
        chmod 0444 "$f.other"
        mv "$f" "$f.moved" && mv "$f.other" "$f"
    done
    out=$(shs "$store" start -a swapped-off 2>&1)
    check_match "refused by its digest" "layer-(toc-)?sha256-[0-9a-f]{64}\\.v5\\.erofs has the fs-verity digest sha256:[0-9a-f]{64}, expected" "$out"
    check "not run" 1 "$([ "$out" != "${out#*Error}" ] && echo 1 || echo 0)"
    for f in "$store"/composefs/layer-*.v5.erofs; do
        rm -f "$f" && ln -s "$(basename "$f.moved")" "$f"
    done
    out=$(shs "$store" start -a swapped-off 2>&1)
    check_match "a link in its place is refused" "layer-(toc-)?sha256-[0-9a-f]{64}\\.v5\\.erofs: .*symbolic links" "$out"
    for f in "$store"/composefs/layer-*.v5.erofs; do
        rm -f "$f" && mv "$f.moved" "$f"
    done
    out=$(shs "$store" start -a swapped-off 2>&1)
    check_match "and it runs with its own image" '^[0-9]+\.[0-9]+' "$out"
    shs "$store" rm -t 0 -f swapped-off > /dev/null 2>&1
}

@test "an enforced container whose bundle lost rootfs.json is refused" {
    need_verity
    store=$VS/nospec
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    id=$(shs "$store" create --network none --security-opt verity=enforce "$SEALED" cat /etc/alpine-release) || exit 1
    rm -f "$store/bundles/$id/rootfs.json"
    [ ! -e "$store/bundles/$id/rootfs.json" ] || e2e_die "no bundle file at $store/bundles/$id"
    out=$(shs "$store" start -a "$id" 2>&1)
    check_match "refused, not run from the bundle's directory" "verity=enforce: its root file system is not made from the layers of its image" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "require makes the node enforce the digests" {
    need_verity
    sed '1i storage.composefs_digests = "require"' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require.toml"
    store=$VS/require
    out=$("$BIN/velarx" --config "$WORKDIR/require.toml" --root "$store" image pull --tls-verify=false "$IMG" 2>&1)
    check_match "an image without them is not pulled" 'composefs_digests is "require"' "$out"
    "$BIN/velarx" --config "$WORKDIR/require.toml" --root "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    out=$("$BIN/velarx" --config "$WORKDIR/require.toml" --root "$store" run --rm --network none "$SEALED" cat /etc/alpine-release 2>&1)
    check_match "the image of velarx runs" '^[0-9]+\.[0-9]+' "$out"
    # an image stored before require was set
    shs "$store" image pull --tls-verify=false "$IMG" > /dev/null || exit 1
    out=$("$BIN/velarx" --config "$WORKDIR/require.toml" --root "$store" run --rm --network none "$IMG" true 2>&1)
    check_match "is refused at the start" 'states no EROFS digest .*composefs_digests is "require"' "$out"
}

# rootless: a user namespace's overlay follows the stubs of every layer or of
# the lowest only (the probe); in the second case the files of the layers above
# the lowest are opened by the FUSE file system, which does the kernel's check
# on each when the digests are enforced.  Both start; the chain says who checks
@test "rootless: an enforced start of several layers runs, the chain says who checks the files" {
    skip_if_root
    need_verity
    store=$VS/probe
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" run --name mk --network none "$SEALED" sh -c 'echo second > /second' > /dev/null 2>&1 || exit 1
    shs "$store" commit mk localhost/verity-start-two:1 > /dev/null 2>&1 || exit 1
    shs "$store" rm -t 0 -f mk > /dev/null 2>&1
    out=$(shs "$store" run --rm --network none localhost/verity-start-two:1 cat /second 2>&1)
    check "not enforced, it runs" second "$out"
    out=$(shs "$store" run --rm --network none --security-opt verity=enforce localhost/verity-start-two:1 sh -c 'cat /second; cat /etc/alpine-release' 2>&1)
    check_match "enforced, it runs" '^second
[0-9]+\.[0-9]+' "$out"
    out=$(shs "$store" --log-level=debug run --rm --network none --security-opt verity=enforce localhost/verity-start-two:1 true 2>&1 | sed -n 's/^.*verity chain: //p')
    erofs="sha256:[0-9a-f]{64},sha256:[0-9a-f]{64}"
    if [ "$(expected_stubs "$WORKDIR")" = lowest ]; then
        check_match "the chain says who checks which files" "^erofs fd $erofs -> overlay verity=require \\(files of layer 1\\), fuse verity=require \\(files of layer 2\\)$" "$out"
    else
        check_match "the overlay checks them all" "^erofs fd $erofs -> overlay verity=require$" "$out"
    fi
    check_match "the chain is complete" "^COMPLETE " "$out"
}

# a file of a layer above the lowest that the FUSE file system refuses at an
# open (its object was replaced by zeros with fs-verity) is EIO, and the line
# that says which object is in the log of the image server, in the directory of
# the container (the server's standard error: the engine opens it)
@test "rootless: the image server logs the file its FUSE file system refuses" {
    skip_if_root
    need_verity
    command -v fsverity > /dev/null || skip "no fsverity"
    [ "$(expected_stubs "$WORKDIR")" = lowest ] || skip "the overlay follows the stubs of every layer: no FUSE check"
    store=$VS/serverlog
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" run --name mk --network none "$SEALED" sh -c 'yes second-file-of-layer-2 | head -c 20000 > /second' > /dev/null 2>&1 || exit 1
    shs "$store" commit mk localhost/verity-start-log:1 > /dev/null 2>&1 || exit 1
    shs "$store" rm -t 0 -f mk > /dev/null 2>&1
    # (the object of the file: the one of its size that holds it)
    obj=
    for f in $(find "$store/objects" -type f -size 20000c); do
        [ "$(head -c 20 "$f")" = second-file-of-layer ] && obj=$f
    done
    test -n "$obj" || e2e_die "the object of /second is not in the store"
    name=$(basename "$(dirname "$obj")")/$(basename "$obj")
    rm -f "$obj"
    head -c 20000 /dev/zero > "$obj"
    fsverity enable "$obj" || e2e_die "cannot enable fs-verity on the replaced object"
    out=$(shs "$store" --log-level=debug run --name brk --network none --security-opt verity=enforce localhost/verity-start-log:1 cat /second 2>&1)
    check_match "the open is refused" "I/O error|Input/output error" "$out"
    log=$(find "$store" -name image-server.log 2> /dev/null | head -1)
    test -n "$log" || e2e_die "the image server kept no log"
    check_match "the log names the object and the digests" "verity chain: BROKEN fuse object $name expected [^ ]+:[0-9a-f]{64} found [^ ]+:[0-9a-f]{64}" "$(cat "$log")"
    check "the log is private" 600 "$(stat -c %a "$log")"
    shs "$store" rm -t 0 -f brk > /dev/null 2>&1
}

# the FUSE file system of a rootless container is served by threads of its
# monitor: the session's, confined before it reads a request, and the I/O
# threads, which it makes once confined, at the first time it is busy (none
# when the requests come one at a time: the unit tests of image_fs make
# them); what the kernel says of each task
# the pid of the image server of the root of the container with this id
image_server_of () {
    local p
    for p in /proc/[0-9]*; do
        case $(tr '\0' ' ' < "$p/cmdline" 2> /dev/null) in
        "velarx-monitor: image server ${1:0:12} root"*) echo "${p#/proc/}"; return ;;
        esac
    done
}
fuse_threads () { # pid of the process that serves the files (the image server): "name seccomp no_new_privs" per thread
    local t
    for t in /proc/"$1"/task/*; do
        case $(cat "$t/comm") in
        fuse | fuse-io-*) echo "$(cat "$t/comm") $(awk '/^Seccomp:/ {s = $2} /^NoNewPrivs:/ {n = $2} END {print s, n}' "$t/status")" ;;
        esac
    done
}

@test "rootless: every thread of the FUSE file system is confined, enforced or not" {
    skip_if_root
    need_verity
    store=$VS/threads
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    for how in plain enforced; do
        opts=()
        [ $how = plain ] || opts=(--security-opt verity=enforce)
        shs "$store" run -d --name "t-$how" --network none "${opts[@]}" "$SEALED" sleep 600 > /dev/null || exit 1
        id=$(shs "$store" inspect --format '{{.Id}}' "t-$how")
        srv=$(image_server_of "$id")
        test -n "$srv" || e2e_die "no image server for the root of t-$how"
        threads=$(fuse_threads "$srv")
        shs "$store" rm -f "t-$how" > /dev/null 2>&1
        check_match "$how: the session's thread" "^fuse " "$threads"
        check "$how: every one under seccomp, with no_new_privs" "" "$(printf '%s\n' "$threads" | grep -v ' 2 1$')"
    done
}

# the object of a file of an upper layer put in place by something else: the
# FUSE file system measures the file it opens, as the kernel's overlay does
# for the stubs of the lowest layer, and fails the open with EIO
@test "rootless: a data object replaced under an enforced start is EIO for the files FUSE serves" {
    skip_if_root
    need_verity
    command -v fsverity > /dev/null || skip "no fsverity"
    [ "$(expected_stubs "$WORKDIR")" = lowest ] || skip "the kernel's overlay follows the stubs of every layer: no file is served by FUSE"
    store=$VS/fusechk
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" run --name mk --network none "$SEALED" sh -c 'echo second > /second; echo third > /third' > /dev/null 2>&1 || exit 1
    shs "$store" commit mk localhost/verity-start-fuse:1 > /dev/null 2>&1 || exit 1
    shs "$store" rm -t 0 -f mk > /dev/null 2>&1
    obj=$(find "$store/objects" -type f -size 7c -exec grep -l '^second$' {} + | head -1)
    [ -n "$obj" ] || { echo "# no object for /second"; exit 1; }
    cat_second () { shs "$store" run --rm --network none --security-opt verity=enforce localhost/verity-start-fuse:1 sh -c 'cat /second; echo "rc=$?"; cat /third; cat /etc/alpine-release' 2>&1; }
    check_match "untouched: all served" '^second
rc=0
third
[0-9]+\.[0-9]+$' "$(cat_second)"
    mv "$obj" "$obj.orig"
    for how in copy other symlink fifo directory deleted; do
        rm -rf "$obj"
        case $how in
        copy) cp "$obj.orig" "$obj" ;;
        other) printf 'secons\n' > "$obj"; fsverity enable "$obj" ;;
        symlink) ln -s "$obj.orig" "$obj" ;;
        fifo) mkfifo "$obj" ;;
        directory) mkdir "$obj" ;;
        deleted) ;;
        esac
        out=$(cat_second)
        check_match "$how: EIO for that file" "cat: .*/second.*(Input/output|I/O) error" "$out"
        check_match "$how: the other files are served" '^third
[0-9]+\.[0-9]+$' "$(printf '%s\n' "$out" | grep -v '^cat: \|^rc=')"
    done
    rm -rf "$obj"
    mv "$obj.orig" "$obj"
    check_match "put back: served again" '^second
rc=0' "$(cat_second)"
}

# a file open before the object is replaced keeps the content that was
# measured; the next open is measured again
@test "rootless: an open file keeps its verified content, the next open measures again" {
    skip_if_root
    need_verity
    command -v fsverity > /dev/null || skip "no fsverity"
    [ "$(expected_stubs "$WORKDIR")" = lowest ] || skip "the kernel's overlay follows the stubs of every layer: no file is served by FUSE"
    store=$VS/fuseopen
    shs "$store" image pull --tls-verify=false "$SEALED" > /dev/null || exit 1
    shs "$store" run --name mk --network none "$SEALED" sh -c 'echo second > /second' > /dev/null 2>&1 || exit 1
    shs "$store" commit mk localhost/verity-start-open:1 > /dev/null 2>&1 || exit 1
    shs "$store" rm -t 0 -f mk > /dev/null 2>&1
    obj=$(find "$store/objects" -type f -size 7c -exec grep -l '^second$' {} + | head -1)
    [ -n "$obj" ] || { echo "# no object for /second"; exit 1; }
    # (two FIFOs: the container says it has the file open, then waits to
    # be told the object was replaced)
    sync=$WORKDIR/fuseopen-sync
    mkdir -p "$sync"
    mkfifo "$sync/opened" "$sync/go"
    shs "$store" run --rm --network none --security-opt verity=enforce -v "$sync:/sync:z" localhost/verity-start-open:1 sh -c '
        exec 3< /second; echo > /sync/opened; read -r _ < /sync/go
        echo "old: $(cat <&3)"; cat /second 2>&1; echo "rc=$?"' > "$WORKDIR/fuseopen.out" 2>&1 &
    pid=$!
    timeout 120 sh -c 'read -r _ < "$1"' _ "$sync/opened" || { kill "$pid"; cat "$WORKDIR/fuseopen.out"; echo "# the container did not open the file"; exit 1; }
    mv "$obj" "$obj.orig"
    printf 'secons\n' > "$obj"
    fsverity enable "$obj"
    timeout 60 sh -c 'echo > "$1"' _ "$sync/go" || { kill "$pid"; echo "# the container went away"; exit 1; }
    wait "$pid"
    out=$(cat "$WORKDIR/fuseopen.out")
    mv -f "$obj.orig" "$obj"
    check_match "the open file keeps the content" '^old: second$' "$out"
    check_match "the next open fails" "cat: .*/second.*(Input/output|I/O) error" "$out"
}
