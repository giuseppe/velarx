# SPDX-License-Identifier: Apache-2.0
# fs-verity of the store, checked when the files of an image are opened,
# rootless: the overlay of the user namespace (`userxattr`) follows the stubs
# into the store and checks the digest of the stub of a file with `verity=`,
# as root; the files of the layers above the lowest are opened by the overlay
# too, or served and checked by the FUSE file system where the kernel follows
# the stubs of its lowest layer only.  Needs
# a directory of the user on a file system with fs-verity (ext4, btrfs or
# f2fs), given in VELARX_VERITY_DIR.  The lazy image is pushed to the
# registry, unless E2E_LAZY_IMAGE names one.
#
#   VELARX_VERITY_DIR=/path VELARX_BINDIR=target/debug bats tests/e2e/bats/verity-rootless.bats

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

config () { # name, storage root, extra lines of [storage], root_dir
    cat > "$WORKDIR/$1.toml" <<EOT
[engine]
socket = "$WORKDIR/$1.sock"
[server]
socket = "$WORKDIR/$1.sock"
state_dir = "$WORKDIR/$1/state"
root_dir = "${4:-$WORKDIR/$1/root}"
[storage]
root = "$2"
$3
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
# replace_object FILE: the object FILE of the store, replaced by a copy of
# it without fs-verity (the same content)
replace_object () {
    cp "$1" "$WORKDIR/object" && rm -f "$1" && cp "$WORKDIR/object" "$1" && rm -f "$WORKDIR/object"
}
# (the flags of lsattr, without the name, which may say "verity")
has_verity () { lsattr "$1" 2> /dev/null | cut -d' ' -f1 | grep -q V; }
# upper_image STORE: an image of two layers, the file /upper.txt in the upper
# one (committed); its object in the store is printed
upper_image () {
    local marker="a file of the upper layer"
    sh_ container run --name mk --network none "$IMAGE" sh -c "seq 1 2000 | sed 's/^/$marker /' > /upper.txt" > /dev/null 2>&1 || return 1
    sh_ container commit mk localhost/verity-upper > /dev/null 2>&1 || return 1
    sh_ container rm -t 0 -f mk > /dev/null 2>&1
    grep -rlxF -- "$marker 1" "$1/objects" | head -1
}
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
        sealed=$E2E_REGISTRY/velarx-e2e/verity-rootless-$$
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
# lazy_pull STORE IMAGE: the image pulled lazily, with no file fetched; the
# configurations complete nothing in the background, so the image is still
# lazy when the container is made of it
lazy_pull () {
    sh_ image pull --lazy --tls-verify=false "$2" > /dev/null 2>&1
    check "a lazy pull" 0 $?
    check "a lazy pull fetches no file" 0 "$(find "$1/objects" -type f 2> /dev/null | wc -l)"
}
monitor_log () { # name of the configuration: the logs of its monitors
    find "$WORKDIR/$1" "$MNT/$1" -name monitor.log 2> /dev/null | xargs -r cat
}

setup_file () {
    skip_if_root
    local t
    for t in crun curl; do
        command -v $t > /dev/null || skip "no $t"
    done
    [ -d "${VELARX_VERITY_DIR:-}" ] || skip "VELARX_VERITY_DIR is not a directory on a file system with fs-verity"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    export IMAGE=$E2E_REGISTRY/alpine:chunked
    export MNT
    MNT=$(mktemp -d "$VELARX_VERITY_DIR/store.XXXXXX")
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
}

teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then
        sh_ container rm -t 0 -f bad mk keep lz > /dev/null 2>&1
    fi
    return 0
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    stop_daemon
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -n "${MNT:-}" ] && rm -rf "$MNT"
    e2e_teardown_file
}

# fs-verity on: the digest of the stub, checked by the kernel at open
@test "rootless: a file of the store replaced is not served" {
    config on "$MNT/on" "fsverity = true"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull onto a store with fs-verity" 0 $?
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "the files of the image are read" "^[0-9]+\.[0-9]+" "$out"
    store_file=$(grep -rlxF -- "$out" "$MNT/on/objects" | head -1)
    [ -n "$store_file" ] && [ -f "$store_file" ]
    check "the file is in the store" 0 $?
    has_verity "$store_file"
    check "the file of the store has fs-verity" 0 $?
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

# fs-verity on: a file of an upper layer is checked by the overlay too
@test "rootless: a file of an upper layer replaced is not served" {
    config up "$MNT/up" "fsverity = true"
    start_daemon up || { echo "the daemon does not start"; cat "$WORKDIR/up.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull onto a store with fs-verity" 0 $?
    store_file=$(upper_image "$MNT/up")
    [ -n "$store_file" ] && [ -f "$store_file" ]
    check "the file of the upper layer is in the store" 0 $?
    has_verity "$store_file"
    check "the file of the store has fs-verity" 0 $?
    sh_ container run -d --name keep --network none localhost/verity-upper sleep 600 > /dev/null 2>&1
    check "a container of the image" 0 $?
    out=$(sh_ container exec keep head -1 /upper.txt 2>&1)
    check "the file is read" "a file of the upper layer 1" "$out"
    # the same content, without fs-verity: refused as the overlay's
    # `verity=on` refuses a file of a stub that has no fs-verity (the
    # overlay of the running container keeps the file it checked)
    replace_object "$store_file"
    has_verity "$store_file"
    check "the copy has no fs-verity" 1 $?
    out=$(sh_ container run --name bad --network none localhost/verity-upper cat /upper.txt 2>&1)
    check "a new container does not read it either" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "it fails to read" "I/O error|Input/output error" "$out"
    out=$(sh_ container run --rm --network none \
        --mount "type=image,source=localhost/verity-upper,destination=/img" "$IMAGE" cat /img/upper.txt 2>&1)
    check "nor an image mount" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "it fails to read" "I/O error|Input/output error" "$out"
    out=$(sh_ container exec keep cat /etc/alpine-release 2>&1)
    check_match "the files of the lower layer are still served" "^[0-9]+\.[0-9]+" "$out"
    sh_ container rm -t 0 -f keep bad > /dev/null 2>&1
    stop_daemon
}

# fs-verity on, a store on a file system without it: nothing is measured,
# the overlay has `verity=off`
@test "rootless: a store without fs-verity runs with fsverity on" {
    config plain "$WORKDIR/plain/store" "fsverity = true"
    start_daemon plain || { echo "the daemon does not start"; cat "$WORKDIR/plain.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull onto a store without fs-verity" 0 $?
    store_file=$(upper_image "$WORKDIR/plain/store")
    [ -n "$store_file" ] && ! has_verity "$store_file"
    check "the file of the store has no fs-verity" 0 $?
    out=$(sh_ container run --rm --network none localhost/verity-upper sh -c 'cat /etc/alpine-release; head -1 /upper.txt' 2>&1)
    check_match "the files of the lowest layer are served" "^[0-9]+\.[0-9]+" "$out"
    check_match "the files of the upper layer are served" "^a file of the upper layer 1$" "$out"
    stop_daemon
}

# a lazy image: its files are fetched into the staging area of the store
# (`<store>/staging`), on the file system of the store wherever the run
# root is (here another one): a staged file has fs-verity or no name, and the
# overlay checks them (`verity=on`)
@test "rootless: a lazy image runs on a store with fs-verity" {
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

# the staging on the file system of the store: a staged file has fs-verity
# or no name, the overlay checks them (`verity=on`)
@test "rootless: a lazy image with its staging on the file system of the store" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazyfs "$MNT/lazyfs/store" "fsverity = true" "$MNT/lazyfs/root"
    start_daemon lazyfs || { echo "the daemon does not start"; cat "$WORKDIR/lazyfs.log"; exit 1; }
    lazy_pull "$MNT/lazyfs/store" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none "$lazy" \
        sh -c 'cat /etc/alpine-release; grep " - overlay " /proc/self/mountinfo | head -1' 2>&1)
    check_match "the files are fetched and served" "^[0-9]+\.[0-9]+" "$out"
    check_match "the overlay checks them" "verity=on" "$(printf '%s\n' "$out" | grep ' - overlay ')"
    check_match "the image server serves and fetches for the root" "image server of the root file system: pid" "$(monitor_log lazyfs)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# a lazy image mounted in a container: the store holds only complete images,
# so the mount completes the pull first (as root, verity.bats), and the root of
# the container is the complete image too, served by its image server with the
# `verity` of the store (not a lazy overlay)
@test "rootless: a lazy image with an image mount of it is complete" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazymnt "$MNT/lazymnt" "fsverity = true"
    start_daemon lazymnt || { echo "the daemon does not start"; cat "$WORKDIR/lazymnt.log"; exit 1; }
    lazy_pull "$MNT/lazymnt" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none \
        --mount "type=image,source=$lazy,destination=/img" "$lazy" \
        sh -c 'cat /etc/alpine-release; head -1 /img/etc/os-release; grep " - overlay " /proc/self/mountinfo | head -1' 2>&1)
    check_match "the files are served" "^[0-9]+\.[0-9]+" "$out"
    check_match "and those of the image mount" "Alpine" "$out"
    check_match "the overlay checks them" "verity=on" "$(printf '%s\n' "$out" | grep ' - overlay ')"
    check_match "the image server serves the root" "image server of the root file system: pid" "$(monitor_log lazymnt)"
    check_match "the image is in the store" "^${lazy%:*} " "$(sh_ image ls 2>&1)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# fs-verity required, a lazy image: its staging is on the file system of the
# store, the overlay checks the files (`verity=require`); a staged file that
# lost its fs-verity is refused (EIO), not served unchecked
@test "rootless: a lazy image runs with fs-verity required" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazyreq "$MNT/lazyreq/store" "fsverity_require = true" "$MNT/lazyreq/root"
    start_daemon lazyreq || { echo "the daemon does not start"; cat "$WORKDIR/lazyreq.log"; exit 1; }
    lazy_pull "$MNT/lazyreq/store" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none "$lazy" \
        sh -c 'cat /etc/alpine-release; grep " - overlay " /proc/self/mountinfo | head -1' 2>&1)
    check_match "the files are fetched and served" "^[0-9]+\.[0-9]+" "$out"
    check_match "the overlay checks them" "verity=require" "$(printf '%s\n' "$out" | grep ' - overlay ')"
    check_match "the image server serves and fetches for the root" "image server of the root file system: pid" "$(monitor_log lazyreq)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    staged=$(grep -rlxF -- "$(printf '%s\n' "$out" | head -1)" "$MNT/lazyreq/store/staging" 2> /dev/null | head -1)
    [ -n "$staged" ] && has_verity "$staged"
    check "the fetched file is staged with fs-verity" 0 $?
    replace_object "$staged"
    has_verity "$staged"
    check "the copy has no fs-verity" 1 $?
    out=$(sh_ container run --name lz --lazy --network none "$lazy" cat /etc/alpine-release 2>&1)
    check "a staged file without fs-verity is refused" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "it fails to read" "I/O error|Input/output error" "$out"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# fs-verity required, a lazy image mounted in a container: as above, the mount
# completes the pull, and the files have the fs-verity of the store
@test "rootless: a lazy image mount with fs-verity required" {
    lazy=$(lazy_image) || { echo "cannot make the lazy image"; cat "$WORKDIR/seal.log"; exit 1; }
    config lazymntreq "$MNT/lazymntreq" "fsverity_require = true"
    start_daemon lazymntreq || { echo "the daemon does not start"; cat "$WORKDIR/lazymntreq.log"; exit 1; }
    lazy_pull "$MNT/lazymntreq" "$lazy"
    out=$(sh_ container run --name lz --lazy --network none \
        --mount "type=image,source=$lazy,destination=/img" "$lazy" \
        sh -c 'cat /etc/alpine-release; head -1 /img/etc/os-release; grep " - overlay " /proc/self/mountinfo | head -1' 2>&1)
    check_match "the files are served" "^[0-9]+\.[0-9]+" "$out"
    check_match "and those of the image mount" "Alpine" "$out"
    check_match "the overlay checks them all" "verity=require" "$(printf '%s\n' "$out" | grep ' - overlay ')"
    check_match "the image server serves the root" "image server of the root file system: pid" "$(monitor_log lazymntreq)"
    sh_ container rm -t 0 -f lz > /dev/null 2>&1
    stop_daemon
}

# verity=require
@test "rootless: the image is pulled and runs with fs-verity required" {
    config req "$MNT/req" "fsverity_require = true"
    start_daemon req || { echo "the daemon does not start"; cat "$WORKDIR/req.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull with fs-verity required" 0 $?
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "the files are served" "^[0-9]+\.[0-9]+" "$out"
    store_file=$(grep -rlxF -- "$out" "$MNT/req/objects" | head -1)
    [ -n "$store_file" ] && has_verity "$store_file"
    check "the file of the store has fs-verity" 0 $?
    upper_file=$(upper_image "$MNT/req")
    [ -n "$upper_file" ] && has_verity "$upper_file"
    check "the file of the upper layer has fs-verity" 0 $?
    replace_object "$store_file"
    replace_object "$upper_file"
    out=$(sh_ container run --name bad --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check "a file of the lowest layer replaced is not served" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "it fails to read" "I/O error|Input/output error" "$out"
    sh_ container rm -t 0 -f bad > /dev/null 2>&1
    out=$(sh_ container run --name bad --network none localhost/verity-upper cat /upper.txt 2>&1)
    check "a file of the upper layer replaced is not served" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "it fails to read" "I/O error|Input/output error" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/os-release 2>&1)
    check_match "the other files are still served" "Alpine" "$out"
    sh_ container rm -t 0 -f bad > /dev/null 2>&1
    stop_daemon
}

# the container writes files of the image: the overlay copies them up from
# the store (and opens their stubs only for their inode flags)
@test "rootless: the files of the image are copied up with their content" {
    config cl "$MNT/cl" "fsverity = true"
    start_daemon cl || { echo "the daemon does not start"; cat "$WORKDIR/cl.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    want=$(sh_ container run --rm --network none "$IMAGE" sh -c 'md5sum /etc/services /etc/protocols; head -c 5 /etc/inittab | md5sum' 2>&1)
    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'echo more >> /etc/services; tail -1 /etc/services; head -c $(($(wc -c < /etc/services) - 5)) /etc/services | md5sum; chmod 600 /etc/protocols; stat -c %a /etc/protocols; md5sum /etc/protocols; truncate -s 5 /etc/inittab; md5sum < /etc/inittab; echo new > /etc/shells; cat /etc/shells' 2>&1)
    set -- $want
    check "appended to" "more" "$(echo "$out" | sed -n 1p)"
    check "the rest is the file of the image" "$1" "$(echo "$out" | sed -n 2p | cut -d' ' -f1)"
    check "the mode changed" "600" "$(echo "$out" | sed -n 3p)"
    check "the content kept" "$3" "$(echo "$out" | sed -n 4p | cut -d' ' -f1)"
    check "cut" "$5" "$(echo "$out" | sed -n 5p | cut -d' ' -f1)"
    check "written over" "new" "$(echo "$out" | sed -n 6p)"
    stop_daemon
}

# the same for a file of an upper layer
@test "rootless: a file of an upper layer can be appended to" {
    config cu "$MNT/cu" "fsverity = true"
    start_daemon cu || { echo "the daemon does not start"; cat "$WORKDIR/cu.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    upper_image "$MNT/cu" > /dev/null
    out=$(sh_ container run --rm --network none localhost/verity-upper sh -c 'echo more >> /upper.txt; head -1 /upper.txt; tail -1 /upper.txt' 2>&1)
    check "the content is kept at the copy-up" "a file of the upper layer 1 more" "$(echo $out)"
    stop_daemon
}

# the stubs the overlay of a user namespace follows are found once, when an
# image of more than one layer first needs it; the files of every layer are
# served either way
@test "rootless: the stubs followed are found, and a multi-layer image runs" {
    config st "$MNT/st" "fsverity = true"
    start_daemon st || { echo "the daemon does not start"; cat "$WORKDIR/st.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "an image of one layer needs no answer" none "$(stubs_answer "$WORKDIR/st/state")"
    upper_image "$MNT/st" > /dev/null
    out=$(sh_ container run --rm --network none localhost/verity-upper sh -c 'cat /etc/alpine-release; head -1 /upper.txt' 2>&1)
    check_match "the files of the lowest layer are served" "^[0-9]+\.[0-9]+" "$out"
    check_match "the files of the upper layer are served" "^a file of the upper layer 1$" "$out"
    want=$(expected_stubs "$WORKDIR")
    check "the answer is the kernel's" "$want" "$(stubs_answer "$WORKDIR/st/state")"
    out=$(sh_ container run --rm --network none localhost/verity-upper sh -c 'echo more >> /upper.txt; tail -1 /upper.txt' 2>&1)
    check "a file of the upper layer is copied up" more "$out"
    check "the answer is kept" "$want" "$(stubs_answer "$WORKDIR/st/state")"
    stop_daemon
}

# with `redirect_dir=followdata` the overlay follows the stub of every layer:
# the engine finds it and the files of the upper layers come from the data-only
# layer, not from FUSE
@test "rootless: an image of several layers is mounted with redirect_dir=followdata" {
    skip_unless_followdata "$WORKDIR"
    config fd "$MNT/fd" "fsverity = true"
    start_daemon fd || { echo "the daemon does not start"; cat "$WORKDIR/fd.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    upper_image "$MNT/fd" > /dev/null
    out=$(sh_ container run --rm --network none localhost/verity-upper sh -c 'cat /etc/alpine-release; head -1 /upper.txt' 2>&1)
    check_match "the files of the lowest layer" "^[0-9]+\.[0-9]+" "$out"
    check_match "the files of the upper layer" "a file of the upper layer 1" "$out"
    check "the engine found every layer is followed" every "$(stubs_answer "$WORKDIR/fd/state")"
    stop_daemon
}
