# SPDX-License-Identifier: Apache-2.0
# fs-verity of the store, checked when the files of an image are opened,
# as root: the store is on an ext4 file system made with
# `-O verity` in a loop device of the work directory (under /var/tmp),
# removed at the end.  The lazy image is pushed to the registry, unless
# E2E_LAZY_IMAGE names one.
#
#   sudo VELARX_BINDIR=target/debug bats tests/e2e/bats/verity.bats

load helpers

stop_daemon () {
    local pid i
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if test -n "$pid"; then
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid"
        kill -KILL "$pid" 2> /dev/null
        rm -f "$WORKDIR/daemon.pid"
    fi
}

config () { # name, storage root, extra lines of [storage]
    cat > "$WORKDIR/$1.toml" <<EOT
[engine]
socket = "$WORKDIR/$1.sock"
[server]
socket = "$WORKDIR/$1.sock"
state_dir = "$WORKDIR/$1/state"
root_dir = "$WORKDIR/$1/root"
[storage]
root = "$2"
$3
# the images of the layers served by FUSE (composefs.bats has them
# mounted by the kernel): the overlay checks the files all the same
composefs = "off"
[pull]
# (no background completion: a lazy pull stays a pull until the test ends)
lazy_completers = 0
EOT
}
start_daemon () { # name
    # (one daemon at a time on the store; every pid is kept for the teardown)
    stop_daemon
    SOCK=$WORKDIR/$1.sock
    : > "$WORKDIR/$1.log"
    E2E_SPAWN_LOG=$WORKDIR/$1.log e2e_spawn_ready DAEMON_PID "$BIN/velarx" --config "$WORKDIR/$1.toml" varlink || return 1
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
}
sh_ () { "$BIN/velarx" --socket "$SOCK" "$@"; }
# lazy_image: an image whose layers a pull leaves lazy (their tables of
# contents give the fs-verity digests of their files, which the layer writer
# gives): the image pushed again by velarx, gzip and back as zstd:chunked,
# from a store of its own; or E2E_LAZY_IMAGE
lazy_image () {
    local sealed
    if [ -n "${E2E_LAZY_IMAGE:-}" ]; then
        echo "$E2E_LAZY_IMAGE"
        return 0
    fi
    if [ ! -e "$WORKDIR/sealed" ]; then
        # (the name is kept: each test is a process of its own)
        sealed=$E2E_REGISTRY/velarx-e2e/verity-$$
        config seal "$WORKDIR/seal/store"
        start_daemon seal > /dev/null || return 1
        { sh_ image pull --tls-verify=false "$IMAGE" &&
          sh_ image push --tls-verify=false --compression-format gzip "$IMAGE" "$sealed:gzip" &&
          sh_ image pull --tls-verify=false "$sealed:gzip" &&
          sh_ image push --tls-verify=false --compression-format zstd:chunked "$sealed:gzip" "$sealed:zstd"
        } > "$WORKDIR/seal.log" 2>&1 || return 1
        stop_daemon
        echo "$sealed" > "$WORKDIR/sealed"
    fi
    echo "$(cat "$WORKDIR/sealed"):zstd"
}
# lazy_pull STORE IMAGE: the image pulled lazily, with no file fetched (and
# none until the end of the test: the configurations complete nothing in the
# background)
lazy_pull () {
    local out rc
    out=$(sh_ image pull --lazy --tls-verify=false "$2" 2>&1)
    rc=$?
    [ $rc = 0 ] || echo "$out" >&2
    check "a lazy pull" 0 $rc
    check "a lazy pull fetches no file" 0 "$(find "$1/objects" -type f 2> /dev/null | wc -l)"
}
# staging_elsewhere STORE: the staging of the lazy pulls of STORE on a file
# system of its own, a tmpfs, which has no fs-verity (unmounted with the rest
# of what is under the work directory)
staging_elsewhere () {
    mkdir -p "$1/staging"
    mount -t tmpfs -o mode=0700 tmpfs "$1/staging"
}
monitor_log () { # name of the configuration: the logs of its monitors
    find "$WORKDIR/$1" -name monitor.log 2> /dev/null | xargs -r cat
}
# the options of the overlay of the root that the container sees, from the
# output of a command that printed /proc/self/mountinfo's line of it
overlay_of () { printf '%s\n' "$1" | grep ' - overlay ' | head -1; }
# the command that prints that line, after what the container does
SHOW_OVERLAY='grep " - overlay " /proc/self/mountinfo | head -1'

setup_file () {
    skip_unless_root
    local t
    for t in mkfs.ext4 crun curl; do
        command -v $t > /dev/null || skip "no $t"
    done
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    export IMAGE=$E2E_REGISTRY/alpine:chunked
    export MNT=$WORKDIR/mnt
    mkdir -p "$XDG_DATA_HOME" "$MNT"
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    truncate -s 2G "$WORKDIR/verity.img"
    mkfs.ext4 -q -O verity "$WORKDIR/verity.img" || skip "cannot make an ext4 with verity"
    mount -o loop "$WORKDIR/verity.img" "$MNT" || skip "cannot mount the loop device"
}

# a failing check must not leak the container
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then
        sh_ container rm -t 0 -f bad lz > /dev/null 2>&1
    fi
    return 0
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    stop_daemon
    # what is still mounted under the work directory, deepest first
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    e2e_teardown_file
}

# fs-verity on (the default): enabled, recorded, checked at open
@test "pull and run onto a store with fs-verity" {
    config on "$MNT/on" "fsverity = true"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull onto a store with fs-verity" 0 $?
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "the files of the image are read" "^[0-9]+\.[0-9]+" "$out"
    digest=sha256:$(printf '%s\n' "$out" | sha256sum | cut -d' ' -f1)
    store_file=$(grep -rlxF -- "$out" "$MNT/on/objects" | head -1)
    echo "$store_file" > "$WORKDIR/store_file"
    [ -n "$store_file" ] && [ -f "$store_file" ]
    check "the file is in the store" 0 $?
    # (the flags of lsattr, without the name, which says "verity")
    lsattr "$store_file" 2> /dev/null | cut -d' ' -f1 | grep -q V
    check "the file of the store has fs-verity" 0 $?
}

# another content, without fs-verity, under its name
@test "a file of the store replaced is not served" {
    SOCK=$WORKDIR/on.sock
    store_file=$(cat "$WORKDIR/store_file" 2> /dev/null)
    if [ -z "$store_file" ] || ! sh_ image inspect "$IMAGE" > /dev/null 2>&1; then
        echo "needs the test 'pull and run onto a store with fs-verity' (daemon, image, store file)" >&2
        exit 1
    fi
    rm -f "$store_file"
    echo "not the release" > "$store_file"
    out=$(sh_ container run --name bad --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check "a file of the store replaced is not served" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "it fails to read" "I/O error|Input/output error" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/os-release 2>&1)
    check_match "the other files are still served" "Alpine" "$out"
    sh_ container rm -t 0 -f bad > /dev/null 2>&1
    stop_daemon
}

# a lazy image: the files fetched for it are in the staging of the
# container, `staging` of the store: on the file system of the store,
# which has fs-verity here, so that the overlay checks them (`verity=on`)
@test "a lazy image runs on a store with fs-verity" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazy "$MNT/lazy" "fsverity = true"
    start_daemon lazy || { echo "the daemon does not start"; cat "$WORKDIR/lazy.log"; exit 1; }
    lazy_pull "$MNT/lazy" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none "$lazy" \
        sh -c 'cat /etc/alpine-release; grep " - overlay " /proc/self/mountinfo | head -1' 2>&1)
    check_match "the files are fetched and served" "^[0-9]+\.[0-9]+" "$out"
    check_match "the overlay checks them" "verity=on" "$(printf '%s\n' "$out" | grep ' - overlay ')"
    check_match "the image server serves and fetches for the root" "image server of the root file system: pid" "$(monitor_log lazy)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# the staging of a lazy pull is on the file system of the store (the files
# fetched there get their fs-verity, and their names, the same way): another
# is refused, not served unchecked
@test "a lazy pull is refused with its staging on another file system" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazyoff "$MNT/lazyoff" "fsverity = true"
    staging_elsewhere "$MNT/lazyoff"
    start_daemon lazyoff || { echo "the daemon does not start"; cat "$WORKDIR/lazyoff.log"; exit 1; }
    out=$(sh_ image pull --lazy --tls-verify=false "$lazy" 2>&1)
    check "the pull is refused" 125 $?
    check_match "it says why" "not on the file system of the store" "$out"
    stop_daemon
}

# a lazy image mounted in a container: the store holds only complete images,
# so the mount completes the pull first, and the container has the `verity`
# of the store (not a lazy overlay)
@test "a lazy image with an image mount of it is complete" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazymnt "$MNT/lazymnt" "fsverity = true"
    start_daemon lazymnt || { echo "the daemon does not start"; cat "$WORKDIR/lazymnt.log"; exit 1; }
    lazy_pull "$MNT/lazymnt" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none \
        --mount "type=image,source=$lazy,destination=/img" "$lazy" \
        sh -c "cat /etc/alpine-release; head -1 /img/etc/os-release; $SHOW_OVERLAY" 2>&1)
    check_match "the files are fetched and served" "^[0-9]+\.[0-9]+" "$out"
    check_match "and those of the image mount" "Alpine" "$out"
    check_match "the overlay checks them" "verity=on" "$(overlay_of "$out")"
    check_match "the image server serves the complete image" "image server of the root file system: pid" "$(monitor_log lazymnt)"
    check_match "the image is in the store" "^${lazy%:*} " "$(sh_ image ls 2>&1)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# fs-verity required, a lazy image: with its staging on the file system of
# the store, the overlay checks the files (`verity=require`)
@test "a lazy image runs with fs-verity required" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazyreq "$MNT/lazyreq" "fsverity_require = true"
    start_daemon lazyreq || { echo "the daemon does not start"; cat "$WORKDIR/lazyreq.log"; exit 1; }
    lazy_pull "$MNT/lazyreq" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none "$lazy" \
        sh -c 'cat /etc/alpine-release; grep " - overlay " /proc/self/mountinfo | head -1' 2>&1)
    check_match "the files are fetched and served" "^[0-9]+\.[0-9]+" "$out"
    check_match "the overlay checks them" "verity=require" "$(printf '%s\n' "$out" | grep ' - overlay ')"
    check_match "the image server serves and fetches for the root" "image server of the root file system: pid" "$(monitor_log lazyreq)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# fs-verity required, a lazy image mounted in a container: as above, the
# mount completes the pull, and the files have the fs-verity of the store
@test "a lazy image mount with fs-verity required" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazymntreq "$MNT/lazymntreq" "fsverity_require = true"
    start_daemon lazymntreq || { echo "the daemon does not start"; cat "$WORKDIR/lazymntreq.log"; exit 1; }
    lazy_pull "$MNT/lazymntreq" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none \
        --mount "type=image,source=$lazy,destination=/img" "$lazy" \
        sh -c "cat /etc/alpine-release; head -1 /img/etc/os-release; $SHOW_OVERLAY" 2>&1)
    check_match "the files are fetched and served" "^[0-9]+\.[0-9]+" "$out"
    check_match "and those of the image mount" "Alpine" "$out"
    check_match "the overlay checks them all" "verity=require" "$(overlay_of "$out")"
    check_match "the image server serves the complete image" "image server of the root file system: pid" "$(monitor_log lazymntreq)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# fs-verity required: a store on a file system without it is refused
@test "a store without fs-verity is refused when it is required" {
    config req-xfs "$WORKDIR/req-xfs" "fsverity_require = true"
    findmnt -no FSTYPE -T "$WORKDIR" | grep -qv '^ext4$\|^btrfs$\|^f2fs$' ||
        skip "the store without fs-verity: $WORKDIR has it"
    start_daemon req-xfs
    check "a store without fs-verity is refused when it is required" 1 $?
    check_match "it says why" "fsverity_require" "$(cat "$WORKDIR/req-xfs.log")"
    stop_daemon
}

# and on the file system that has it, the image is pulled and runs
@test "the image is pulled and runs with fs-verity required" {
    config req "$MNT/req" "fsverity_require = true"
    start_daemon req || { echo "the daemon does not start"; cat "$WORKDIR/req.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull with fs-verity required" 0 $?
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "the files are served" "^[0-9]+\.[0-9]+" "$out"
    stop_daemon
}

# a file system whose blocks are smaller than 4096 bytes: its fs-verity
# digests are not those that name the files (without the orphan file, which
# a kernel refuses to mount on blocks this small)
small_fs () {
    mountpoint -q "$WORKDIR/small" 2> /dev/null && return 0
    truncate -s 600M "$WORKDIR/small.img"
    # (a mkfs.ext4 older than the orphan file does not know its name)
    mkfs.ext4 -q -b 1024 -N 131072 -O verity,^orphan_file "$WORKDIR/small.img" 2> /dev/null ||
        mkfs.ext4 -q -b 1024 -N 131072 -O verity "$WORKDIR/small.img" || skip "cannot make an ext4 of 1 KiB blocks with verity"
    mkdir -p "$WORKDIR/small"
    mount -o loop "$WORKDIR/small.img" "$WORKDIR/small" || skip "cannot mount the loop device"
}

# there fs-verity required is refused at the start, naming the block size
@test "fs-verity required is refused on a file system of small blocks" {
    small_fs
    config req-small "$WORKDIR/small/req" "fsverity_require = true"
    start_daemon req-small
    check "the start is refused" 1 $?
    check_match "it says why" "fsverity_require.*blocks of 1024 bytes" "$(cat "$WORKDIR/req-small.log")"
    stop_daemon
}

# and fs-verity on runs, with `verity=off`
@test "fs-verity on runs on a file system of small blocks, not checked" {
    small_fs
    config on-small "$WORKDIR/small/on" "fsverity = true"
    start_daemon on-small || { echo "the daemon does not start"; cat "$WORKDIR/on-small.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull onto a store of small blocks" 0 $?
    out=$(sh_ container run --name lz --network none "$IMAGE" sh -c "cat /etc/alpine-release; $SHOW_OVERLAY" 2>&1)
    check_match "the files are served" "^[0-9]+\.[0-9]+" "$out"
    check "the overlay does not check them (verity=off is not shown)" "" "$(overlay_of "$out" | grep -o 'verity=[a-z]*')"
    check_match "the image server serves the image" "image server of the root file system: pid" "$(monitor_log on-small)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}
