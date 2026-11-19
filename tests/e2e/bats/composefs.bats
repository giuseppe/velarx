# SPDX-License-Identifier: Apache-2.0
# composefs root file systems of root containers, as root: the store
# is on an ext4 file system made with `-O verity` in a loop device of the
# work directory (under /var/tmp), removed at the end.
#
#   sudo VELARX_BINDIR=target/debug bats tests/e2e/bats/composefs.bats

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

config () { # name, extra lines of [storage]
    cat > "$WORKDIR/$1.toml" <<EOT
[engine]
socket = "$WORKDIR/$1.sock"
[server]
socket = "$WORKDIR/$1.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$MNT/store"
$2
EOT
}
start_daemon () { # name
    # (one daemon at a time on the store; every pid is kept for the teardown)
    stop_daemon
    SOCK=$WORKDIR/$1.sock
    : > "$WORKDIR/$1.log"
    E2E_SPAWN_LOG=$WORKDIR/$1.log e2e_spawn_ready DAEMON_PID "${DAEMON_BIN:-$BIN/velarx}" --log-level info --config "$WORKDIR/$1.toml" varlink || return 1
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
}
sh_ () { "$BIN/velarx" --socket "$SOCK" "$@"; }
# need_daemon: the daemon of the first test (composefs on) runs; the tests
# after it use its pulled image
need_daemon () {
    SOCK=$WORKDIR/on.sock
    if ! sh_ image inspect "$IMAGE" > /dev/null 2>&1; then
        echo "the daemon with the pulled image is not there: the test 'pull onto a store with composefs' failed or did not run" >&2
        exit 1
    fi
}
# what the monitor of the container `name` said of its root file system
root_path () {
    grep -rhs --include=monitor.log "root file system:" "$WORKDIR/state" "$WORKDIR/run" "$WORKDIR/root" 2> /dev/null \
        | grep -c "$1"
}
# the pid of the image server the monitor log (stdin) names
server_pid () {
    sed -n 's/.*image server of the root file system: pid \([0-9]*\),.*/\1/p' | head -1
}
monitor_log () { # container
    local id
    id=$(sh_ container inspect "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    # (its directory is named by the short id)
    find "$WORKDIR/state" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat
}


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

# a failing check must not leak the containers, the moved composefs
# directory or the daemon
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    local c
    [ -d "$MNT/store/composefs.away" ] && mv "$MNT/store/composefs.away" "$MNT/store/composefs"
    if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then
        for c in c1 ci ciu cu cu2 ce cm c2 c3 c4 pm; do sh_ container rm -t 0 -f "$c" > /dev/null 2>&1; done
        sh_ image rm -f localhost/e2e-cfs-commit:1 localhost/e2e-cfs-deep:1 > /dev/null 2>&1
    fi
    return 0
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    stop_daemon
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    e2e_teardown_file
}

@test "pull onto a store with composefs" {
    config on "fsverity = true"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    check_match "the daemon uses composefs" "composefs: root file systems from the EROFS images of the layers" "$(cat "$WORKDIR/on.log")"
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull" 0 $?
}

# Whether the kernel mounts an EROFS image from a file (file-backed EROFS,
# Linux 6.12 and later) is found out when the engine starts, by mounting an
# empty image written next to the images of the store, and kept for the boot
# as the feature erofs-file of the run root (the marker erofs-file-yes or
# erofs-file-no, with the boot and the images it is about).  Where it does,
# a second answer, the feature erofs-lock, says whether the mount keeps the
# lock of the image (Linux 7.3 and later: the image is given to the kernel as
# the source, an open file).
@test "the engine finds out at its start whether the kernel mounts an EROFS image from a file" {
    need_daemon
    local features=$WORKDIR/state/features key
    key="$(cat /proc/sys/kernel/random/boot_id) $MNT/store/objects"
    if [ -f "$features/erofs-file-yes" ]; then
        check "the other answer is not kept" 0 "$(ls "$features" | grep -c '^erofs-file-no$')"
        check_match "the kernel mounts the root file systems" "composefs: root file systems from the EROFS images of the layers" "$(cat "$WORKDIR/on.log")"
        check "the probe left no image in the store" 0 "$(ls -A "$MNT/store/composefs" | grep -c '^\.tmp-probe-')"
        check "one marker of the lock" 1 "$(ls "$features" | grep -c '^erofs-lock-')"
        # (the kernel keeps the lock from Linux 7.3: FSCONFIG_SET_FD of the
        # source of an EROFS)
        if [ "$(printf '7.3\n%s\n' "$(uname -r)" | sort -V | head -1)" = 7.3 ]; then
            check "this kernel keeps the lock" 1 "$(ls "$features" | grep -c '^erofs-lock-yes$')"
        else
            check "an older kernel keeps none" 1 "$(ls "$features" | grep -c '^erofs-lock-no$')"
        fi
        check "the lock marker says which boot and which images" "$key" "$(cat "$features"/erofs-lock-* | head -1)"
    else
        check "no answer but no" 1 "$(ls "$features" | grep -c '^erofs-file-no$')"
        check_match "the image server serves them, and the reason says why" "the kernel cannot mount an EROFS image from a file" "$(cat "$WORKDIR/on.log")"
        check "the lock is not asked where nothing is mounted" 0 "$(ls "$features" | grep -c '^erofs-lock-')"
    fi
    check "the marker says which boot and which images" "$key" "$(cat "$features"/erofs-file-* | head -1)"
    check "one marker" 1 "$(ls "$features" | grep -c '^erofs-file-')"
}

@test "an engine told that the kernel does not mount an EROFS image from a file serves the root by the image server" {
    need_daemon
    local features=$WORKDIR/state/features key
    key="$(cat /proc/sys/kernel/random/boot_id) $MNT/store/objects"
    stop_daemon
    rm -f "$features"/erofs-file-* "$features"/erofs-lock-*
    printf '%s\n' "$key" > "$features/erofs-file-no"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    check_match "the reason is said" "the kernel cannot mount an EROFS image from a file" "$(cat "$WORKDIR/on.log")"
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null
    check "run" 0 $?
    check_match "the image server serves the root" "image server of the root file system" "$(monitor_log c1)"
    check "the container reads its files" 0 "$(sh_ container exec c1 cat /etc/alpine-release > /dev/null 2>&1; echo $?)"
    check "there was no kernel mount to fail" 0 "$(grep -c 'the kernel mount of the root file system failed' "$WORKDIR/on.log")"
    sh_ container rm -t 0 -f c1 > /dev/null
    # a marker of another boot is none: the engine finds out again
    stop_daemon
    printf 'another-boot %s\n' "$MNT/store/objects" > "$features/erofs-file-no"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    check "found out again" "$key" "$(cat "$features"/erofs-file-* | head -1)"
}

@test "the monitor mounts the composefs image" {
    need_daemon
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null
    check_match "the monitor attaches the mount of the driver" "root file system: mount descriptor 0 of the storage driver" "$(monitor_log c1)"
    check_match "an overlay of the images of the layers, whose files the kernel checks" "verity=on" \
        "$(sh_ container exec c1 cat /proc/self/mountinfo | grep ' - overlay ' | head -1)"
    release=$(sh_ container exec c1 cat /etc/alpine-release 2>&1)
    check_match "the files are read" "^[0-9]+\.[0-9]+" "$release"
    [ -n "$release" ] || exit 1
    echo "$release" > "$WORKDIR/release"
    sh_ container exec c1 sh -c 'echo w > /etc/written && cat /etc/written' > /dev/null 2>&1
    check "the container writes in its upper layer" 0 $?
    images=$(ls "$MNT/store/composefs"/layer-*.erofs 2> /dev/null | wc -l)
    check "the image of the layer is in the store" 1 "$images"
    sh_ container rm -t 0 -f c1 > /dev/null
}

@test "image mounts from their composefs images" {
    need_daemon
    release=$(cat "$WORKDIR/release" 2> /dev/null)
    [ -n "$release" ] || { echo "no release of the test 'the monitor mounts the composefs image'" >&2; exit 1; }
    # image mounts from their composefs images
    sh_ container run -d --name ci --network none \
        --mount "type=image,source=$IMAGE,destination=/img" \
        --mount "type=image,source=$IMAGE,destination=/imgetc,subpath=/etc" "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a container with image mounts runs" 0 $?
    check "the image mount reads the image" "$release $release" \
        "$(sh_ container exec ci sh -c 'cat /img/etc/alpine-release; cat /imgetc/alpine-release' 2>&1 | tr '\n' ' ' | sed 's/ $//')"
    check "both from composefs" 2 "$(monitor_log ci | grep -c 'image mount .*: mount descriptor [0-9]* of the storage driver')"
    sh_ container exec ci sh -c 'echo x > /img/new' > /dev/null 2>&1
    check "an image mount is read-only" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    sh_ container rm -t 0 -f ci > /dev/null
    sh_ container run -d --name ciu --userns auto --network none \
        --mount "type=image,source=$IMAGE,destination=/img" "$IMAGE" sleep 300 > /dev/null 2>&1
    check "an image mount with a user namespace" "0 0" "$(sh_ container exec ciu stat -c '%u %g' /img/etc/alpine-release 2>&1)"
    check "from composefs" 1 "$(monitor_log ciu | grep -c 'image mount .*: mount descriptor [0-9]* of the storage driver')"
    sh_ container rm -t 0 -f ciu > /dev/null
}

# The digests enforced (`--security-opt verity=enforce`): the driver measures
# the EROFS image of each layer against the lists of the manifest, on the
# descriptor it mounts, and hands the overlay over with verity=require; the
# monitor looks at the mount it attaches.  An image of velarx states those
# digests, the pulled image gets them by a push and a pull.
@test "enforced digests: the driver measures the images and the overlay has verity=require" {
    need_daemon
    local sealed=$E2E_REGISTRY/velarx-e2e/composefs-enforce-$$
    sh_ image push --tls-verify=false --compression-format gzip "$IMAGE" "$sealed:gz" > /dev/null 2>&1 || e2e_die "push"
    sh_ image pull --tls-verify=false "$sealed:gz" > /dev/null 2>&1 || e2e_die "pull"
    sh_ image push --tls-verify=false --compression-format zstd:chunked "$sealed:gz" "$sealed:zstd" > /dev/null 2>&1 || e2e_die "push zstd"
    sh_ image pull --tls-verify=false "$sealed:zstd" > /dev/null 2>&1 || e2e_die "pull zstd"
    sh_ container run -d --name ce --network none --security-opt verity=enforce "$sealed:zstd" sleep 300 > /dev/null 2>&1
    check "an enforced container runs" 0 $?
    check_match "the monitor attaches the mount of the driver" "root file system: mount descriptor 0 of the storage driver" "$(monitor_log ce)"
    check_match "an overlay whose files the kernel checks, every one" "verity=require" \
        "$(sh_ container exec ce cat /proc/self/mountinfo | grep ' - overlay ' | head -1)"
    check_match "the files are read" "^[0-9]+\.[0-9]+" "$(sh_ container exec ce cat /etc/alpine-release 2>&1)"
    sh_ container rm -t 0 -f ce > /dev/null
    sh_ image rm -f "$sealed:gz" "$sealed:zstd" > /dev/null 2>&1
}

@test "a container with a user namespace: the layers on idmapped mounts" {
    need_daemon
    # a container with a user namespace: the layers on idmapped mounts
    sh_ container run -d --name cu --userns auto --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a container with a user namespace runs" 0 $?
    check_match "on composefs, the mount of the driver" "root file system: mount descriptor 0 of the storage driver" "$(monitor_log cu)"
    check "its root owns the files of the image" "0 0" \
        "$(sh_ container exec cu stat -c '%u %g' /etc/alpine-release 2>&1)"
    sh_ container exec cu sh -c 'echo w > /etc/written && cat /etc/written' > /dev/null 2>&1
    check "and writes in its upper layer" 0 $?
    sh_ container rm -t 0 -f cu > /dev/null
}

# (where the kernel shares the superblock of the mounts of an image, each mount
# has its own mapping all the same)
@test "two containers with a user namespace each: their own mappings on the layers of one image" {
    need_daemon
    sh_ container run -d --name cu --userns auto --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    check "the first runs" 0 $?
    sh_ container run -d --name cu2 --userns auto --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    check "the second runs" 0 $?
    check "the first sees its root as the owner" "0 0" "$(sh_ container exec cu stat -c '%u %g' /etc/alpine-release 2>&1)"
    check "the second too" "0 0" "$(sh_ container exec cu2 stat -c '%u %g' /etc/alpine-release 2>&1)"
    sh_ container rm -t 0 -f cu > /dev/null
    check "the second after the first is gone" "0 0" "$(sh_ container exec cu2 stat -c '%u %g' /etc/alpine-release 2>&1)"
    sh_ container rm -t 0 -f cu2 > /dev/null
}

@test "changes of a container on composefs" {
    need_daemon
    # changes of a container on composefs: a mode only, a renamed directory, a
    # data change; its diff is podman's, its commit has them, without the
    # overlay's own attributes
    CMDS='chmod 600 /etc/alpine-release && mv /etc/apk /etc/apk2 && echo more >> /etc/os-release'
    sh_ container run --name cm --network none "$IMAGE" sh -c "$CMDS" > /dev/null 2>&1
    check "a container changes its files" 0 $?
    ours=$(sh_ container diff cm | sort)
    PODMAN="podman --root $WORKDIR/podman/root --runroot $WORKDIR/podman/run --storage-driver overlay"
    if $PODMAN pull -q --tls-verify=false "$IMAGE" > /dev/null 2>&1 \
        && $PODMAN run --name pm --network none "$IMAGE" sh -c "$CMDS" > /dev/null 2>&1; then
        check "the diff is podman's" "$($PODMAN diff pm | sort)" "$ours"
        $PODMAN rm -f pm > /dev/null 2>&1
    else
        echo "skip the diff of podman: podman cannot run the image"
    fi
    check_match "the diff has the three changes" "C /etc/alpine-release.*A /etc/apk2.*C /etc/os-release|A /etc/apk2.*C /etc/alpine-release" "$(echo $ours)"
    sh_ container commit cm localhost/e2e-cfs-commit:1 > /dev/null 2>&1
    check "the container is committed" 0 $?
    out=$(sh_ container run --rm --network none localhost/e2e-cfs-commit:1 sh -c \
        'stat -c %a /etc/alpine-release; test -d /etc/apk2 && echo renamed; test -e /etc/apk || echo gone; tail -1 /etc/os-release' 2>&1)
    check "the committed image has the changes" "600 renamed gone more" "$(echo $out)"
    sh_ image save -o "$WORKDIR/commit.tar" localhost/e2e-cfs-commit:1 > /dev/null
    # (the file the append changed: /etc/os-release is a link to
    # ../usr/lib/os-release in an alpine since 3.21, the file in older ones)
    osrel=$(sh_ container run --rm --network none "$IMAGE" readlink -f /etc/os-release 2>/dev/null)
    osrel=${osrel#/}
    check_match "the file /etc/os-release is" "os-release$" "$osrel"
    layer=$(python3 -I - "$WORKDIR/commit.tar" "$osrel" <<'PY'
import json, sys, tarfile
def layers(t):
    blob = lambda d: t.extractfile("blobs/sha256/" + d.split(":")[1]).read()
    index = json.load(t.extractfile("index.json"))
    manifest = json.loads(blob(index["manifests"][0]["digest"]))
    return ["blobs/sha256/" + l["digest"].split(":")[1] for l in manifest["layers"]]
t = tarfile.open(sys.argv[1])
last = tarfile.open(fileobj=t.extractfile(layers(t)[-1]))
names, overlay = [], 0
for e in last.getmembers():
    names.append(e.name.removeprefix("./"))
    overlay += sum(1 for k in e.pax_headers if "overlay." in k)
want = ["etc/alpine-release", "etc/apk2/", "etc/.wh.apk", sys.argv[2]]
print(" ".join(w for w in want if any(n.rstrip("/") == w.rstrip("/") or n.startswith(w) for n in names)), "overlay:", overlay)
PY
    )
    check "the layer has the changes and no overlay attributes" "etc/alpine-release etc/apk2/ etc/.wh.apk $osrel overlay: 0" "$layer"
    sh_ container rm -t 0 -f cm > /dev/null
    sh_ image rm -f localhost/e2e-cfs-commit:1 > /dev/null
}

@test "a tree the container made, 2000 levels deep: diff, and a commit that is refused" {
    need_daemon
    # (the walks of the upper recurse once for each level: a stack overflow
    # aborts the daemon; a layer holds paths of 512 components at most)
    sh_ container run --name c2 --network none "$IMAGE" sh -c \
        'cd /tmp; i=0; while [ $i -lt 2000 ]; do mkdir d; cd d; i=$((i+1)); done' > /dev/null 2>&1
    check "a container makes a tree 2000 levels deep" 0 $?
    check "the diff lists the tree" 2000 "$(sh_ container diff c2 | grep -c '^A /tmp/d')"
    check_match "the commit is refused" "too deep" "$(sh_ container commit c2 localhost/e2e-cfs-deep:1 2>&1)"
    check "the daemon is still there" 2000 "$(sh_ container diff c2 | grep -c '^A /tmp/d')"
    sh_ container rm -t 0 -f c2 > /dev/null
}

@test "a file of the store replaced by another content is refused" {
    need_daemon
    release=$(cat "$WORKDIR/release" 2> /dev/null)
    [ -n "$release" ] || { echo "no release of the test 'the monitor mounts the composefs image'" >&2; exit 1; }
    # a file of the store replaced by another content, without fs-verity: the
    # kernel refuses it
    digest=sha256:$(printf '%s\n' "$release" | sha256sum | cut -d' ' -f1)
    store_file=$(grep -rlxF -- "$release" "$MNT/store/objects" | head -1)
    [ -n "$store_file" ] || { echo "no file of the store has the release" >&2; exit 1; }
    rm -f "$store_file"
    echo "not the release" > "$store_file"
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "a replaced file of the store is not read" "I/O error|Input/output error" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/os-release 2>&1)
    check_match "the other files are" "Alpine" "$out"
}

@test "the image of a layer gone: the layer is incomplete, a pull makes it again" {
    need_daemon
    # the images of the layers are the store's: one that is gone is not made
    # again behind the user's back; the layer is marked incomplete, and a pull
    # brings it back
    # (a container made before: its root is a mount the driver makes again at
    # each start, from the images of the layers)
    sh_ container create --name cgone --network none "$IMAGE" echo again > /dev/null || exit 1
    mv "$MNT/store/composefs" "$MNT/store/composefs.away"
    out=$(sh_ container start -a cgone 2>&1)
    check_match "a container made before does not start, and says which and what to do" "the image $IMAGE is damaged \\(layer (toc:)?sha256:[0-9a-f]{64} has no EROFS image\\): pull it again" "$out"
    out=$(sh_ container run --rm --name c2 --network none "$IMAGE" true 2>&1); rc=$?
    check "a container whose image of a layer is gone is not made" 125 $rc
    check_match "it says which and what to do" "the image $IMAGE is damaged \\(layer (toc:)?sha256:[0-9a-f]{64} has no EROFS image\\): pull it again" "$out"
    check "the image stays" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}')"
    out=$(sh_ container run --rm --name c2 --network none "$IMAGE" true 2>&1); rc=$?
    check "it fails the same again" 125 $rc
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "the pull succeeds" 0 $?
    check "it made the image of the layer again" 1 "$(ls "$MNT"/store/composefs/layer-*.erofs | wc -l)"
    out=$(sh_ container run --rm --name c2 --network none "$IMAGE" echo back 2>&1)
    check "and the container runs" "back" "$out"
    check "and the one made before" "again" "$(sh_ container start -a cgone 2>&1)"
    sh_ container rm -t 0 -f cgone > /dev/null
    rm -rf "$MNT/store/composefs.away"
    # (for the next test: a container whose root is a mount of the driver)
    sh_ container create --name cfd --network none "$IMAGE" cat /etc/os-release > /dev/null || exit 1
    stop_daemon
}

@test "composefs off: the image server" {
    # composefs off: no kernel mount, the image server serves the layers
    config off 'composefs = "off"'
    start_daemon off || { echo "the daemon does not start"; cat "$WORKDIR/off.log"; exit 1; }
    check_match "the daemon says composefs is off" "composefs: not used \(\[storage\] composefs is off\)" "$(cat "$WORKDIR/off.log")"
    sh_ container run -d --name c3 --network none "$IMAGE" sleep 300 > /dev/null
    check_match "the monitor attaches the mount of the driver" "root file system: mount descriptor 0 of the storage driver" "$(monitor_log c3)"
    srv=$(monitor_log c3 | server_pid)
    test -n "$srv" || e2e_die "the monitor does not name the image server"
    check_match "the layers are served by the image server" "image server" "$(tr '\0' ' ' < /proc/$srv/cmdline)"
    check_match "and the files are read" "Alpine" "$(sh_ container exec c3 cat /etc/os-release 2>&1)"
    sh_ container rm -t 0 -f c3 > /dev/null
    e2e_wait_exit "$srv" 10
    check "the server ends with the container: nobody tells it to stop" 1 "$(test -d /proc/$srv && echo 0 || echo 1)"
    # a container made while the driver made the mounts: the driver now leaves
    # its root to the monitor, which serves it by FUSE
    check_match "a root that was a mount of the driver runs on the plan" "Alpine" "$(sh_ container start -a cfd 2>&1)"
    check_match "served by the image server" "image server of the root file system" "$(monitor_log cfd)"
    sh_ container rm -t 0 -f cfd > /dev/null
    stop_daemon
}

@test "owners squashed in a user namespace: the image server" {
    # owners squashed in a user namespace: the image server serves the images of the
    # layers, and the container writes the files of its image (the overlay
    # opens their stubs through FUSE at the copy-up, for their inode flags)
    config squash 'fsverity = true
    [userns]
    squash_unmapped_owners = true'
    start_daemon squash || { echo "the daemon does not start"; cat "$WORKDIR/squash.log"; exit 1; }
    sh_ container run -d --name c4 --userns auto --network none "$IMAGE" sleep 300 > /dev/null
    check_match "squashed owners: the image server serves the images of the layers" \
        "image server of the root file system" "$(monitor_log c4)"
    out=$(sh_ container exec c4 sh -c 'echo w >> /etc/services && chmod 600 /etc/services && tail -n 1 /etc/services && stat -c %a /etc/services' 2>&1)
    check "and the container writes the files of its image" "w 600" "$(echo $out)"
    sh_ container rm -t 0 -f c4 > /dev/null
    stop_daemon
}

@test "owners outside the mapping: the driver refuses at the create and at the start" {
    # owners outside the mapping: the storage driver refuses, whoever would
    # mount the image (the kernel as root, the image server), with the reason,
    # at the create already, and nothing is made
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    need_daemon
    local out
    out=$(sh_ container create --name cm --uidmap 0:300000:30 --gidmap 0:300000:30 --network none "$IMAGE" true 2>&1)
    check "no container is made" 0 "$(sh_ container ls -a --format '{{.Names}}' | grep -cx cm)"
    check_match "with the owner and the remedy" "image has files owned by (uid|gid) [0-9]+, which is not mapped in the user namespace.*/etc/subuid" "$out"
    out=$(sh_ container run --rm --name cm --uidmap 0:300000:30 --gidmap 0:300000:30 --network none "$IMAGE" true 2>&1)
    check_match "and so is the run" "image has files owned by (uid|gid) [0-9]+, which is not mapped" "$out"
    # the image server's mounts say the same (composefs off: no kernel mount)
    config off 'composefs = "off"'
    start_daemon off || { echo "the daemon does not start"; cat "$WORKDIR/off.log"; exit 1; }
    out=$(sh_ container run --rm --name cm --uidmap 0:300000:30 --gidmap 0:300000:30 --network none "$IMAGE" true 2>&1)
    check_match "also when the image server would serve the image" "image has files owned by (uid|gid) [0-9]+, which is not mapped" "$out"
    check "no image server is left" 0 "$(find "$WORKDIR/state" -name monitor.log 2> /dev/null | xargs -r grep -l 'image server of the root file system: pid' | wc -l)"
    stop_daemon
}

@test "an image server that cannot start is a start error with its reason" {
    # a monitor binary that cannot be the image server: the start fails and
    # says why; the plan is not left to the monitor
    config off 'composefs = "off"'
    local bin=$WORKDIR/bin-no-server
    mkdir -p "$bin"
    cp -f "$BIN/velarx" "$bin/velarx"
    cat > "$bin/velarx-monitor" <<EOT
#!/bin/sh
case "\$1" in --image-server) echo "no /dev/fuse here" >&2; exit 3 ;; esac
exec "$BIN/velarx-monitor" "\$@"
EOT
    chmod 755 "$bin/velarx-monitor"
    DAEMON_BIN=$bin/velarx start_daemon off || { echo "the daemon does not start"; cat "$WORKDIR/off.log"; exit 1; }
    local out
    out=$(sh_ container run --rm --name cm --network none "$IMAGE" true 2>&1)
    check_match "with the reason" "the image server cannot serve the root file system" "$out"
    check "and the monitor has mounted nothing" 0 "$(find "$WORKDIR/state" -name monitor.log 2> /dev/null | xargs -r grep -l 'root file system:' | wc -l)"
    stop_daemon
}

@test "the image removed: the images of its layers go with it" {
    # the image removed: the images of its layers and an orphan go at the
    # next collection
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    need_daemon
    touch -d '2 hours ago' "$MNT/store/composefs/orphan.v2.erofs"
    sh_ image rm -f "$IMAGE" > /dev/null
    check "rmi" 0 $?
    sh_ system gc > /dev/null 2>&1
    check "the collection removes an orphan" 0 "$(ls "$MNT/store/composefs" | wc -l)"
    stop_daemon

}

# The lock of an image: what mounts or serves the EROFS image of a layer
# holds a shared flock of it.  The kernel mount keeps it as long as the file
# system exists where the image is given to the kernel as an open file (Linux
# 7.3 and later, the feature erofs-lock); an older kernel mounts the image by
# the name of its descriptor and holds none, so the collection does not see
# the mount.  The collection asks for the lock exclusively and keeps the layer
# it cannot lock.  `flock -n -x` is that question.
image_unused () { flock -n -x "$1" true 2> /dev/null && echo unused || echo in-use; }
layer_rows () {
    python3 -I -c 'import sqlite3, sys; print(sqlite3.connect(sys.argv[1], timeout=30).execute("SELECT COUNT(*) FROM layers").fetchone()[0])' "$MNT/store/db.sqlite"
}
# what a mount of the kernel does to the lock of its image on this host: the
# answer the engine found (the marker erofs-lock-yes or erofs-lock-no)
mount_locks () {
    if [ -f "$WORKDIR/state/features/erofs-lock-yes" ]; then echo in-use; else echo unused; fi
}
# the layers no row names any more: what a crash that lost them leaves
forget_rows () {
    python3 -I - "$MNT/store/db.sqlite" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=30)
c.execute("DELETE FROM container_layers")
c.execute("DELETE FROM image_layers")
c.commit()
PY
}

@test "a mounted image is locked until its mount is gone where the kernel keeps the lock" {
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || e2e_die "pull"
    local img held
    img=$(ls "$MNT"/store/composefs/layer-*.erofs | head -1)
    held=$(mount_locks)
    check "not before" unused "$(image_unused "$img")"
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null
    check "while the container runs ($held where the kernel keeps the lock)" "$held" "$(image_unused "$img")"
    # (the engine is not the holder: it goes and the mount stays)
    kill -KILL "$(cat "$WORKDIR/daemon.pid")"
    e2e_wait_exit "$(cat "$WORKDIR/daemon.pid")" 10
    rm -f "$WORKDIR/daemon.pid"
    check "when the engine is killed" "$held" "$(image_unused "$img")"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ container rm -t 0 -f c1 > /dev/null
    check "not after" unused "$(image_unused "$img")"
}

# The number of EROFS inodes the kernel has in memory: one tree of an image
# per superblock.
erofs_inodes () {
    awk '$1 == "erofs_inode" { print $2 }' /proc/slabinfo
}
# the files of the container read, so that the kernel has their inodes
read_tree () { # container
    sh_ container exec "$1" sh -c 'find /bin /etc /lib /sbin /usr -type f | xargs cat > /dev/null 2>&1; true'
}

# Two containers of one image mount its layers with the option
# superblock_share where the kernel has it (the feature
# erofs-superblock-share, found out like the others): one superblock for both,
# whose lock stays until the last of them is gone.  Without it each has its own.
@test "containers of one image share the superblock of its layers where the kernel does" {
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || e2e_die "pull"
    local img shared=no before first second
    img=$(ls "$MNT"/store/composefs/layer-*.erofs | head -1)
    [ -f "$WORKDIR/state/features/erofs-superblock-share-yes" ] && shared=yes
    check "the answer is kept with the boot and the images" "$(cat /proc/sys/kernel/random/boot_id) $MNT/store/objects" "$(cat "$WORKDIR"/state/features/erofs-superblock-share-* | head -1)"
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null || e2e_die "run c1"
    sh_ container run -d --name c2 --network none "$IMAGE" sleep 300 > /dev/null || e2e_die "run c2"
    before=$(erofs_inodes)
    read_tree c1
    first=$(( $(erofs_inodes) - before ))
    read_tree c2
    second=$(( $(erofs_inodes) - before - first ))
    if [ "$shared" = yes ]; then
        check "the second container adds few inodes" 1 "$([ "$second" -lt $((first / 4)) ] && echo 1 || echo 0)"
        sh_ container rm -t 0 -f c1 > /dev/null
        check_match "the other reads its files" "^[0-9]+\\." "$(sh_ container exec c2 cat /etc/alpine-release 2>&1)"
        check "the layer is still locked" "$(mount_locks)" "$(image_unused "$img")"
        sh_ container rm -t 0 -f c2 > /dev/null
    else
        check "each container has its own inodes" 1 "$([ "$second" -gt $((first / 2)) ] && echo 1 || echo 0)"
        sh_ container rm -t 0 -f c1 c2 > /dev/null
    fi
    check "the layer is free after the last" unused "$(image_unused "$img")"
}

@test "a layer whose image is mounted is collected where the kernel keeps no lock, and kept where it does" {
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || e2e_die "pull"
    local img
    img=$(ls "$MNT"/store/composefs/layer-*.erofs | head -1)
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null
    forget_rows
    sh_ system gc > /dev/null 2>&1
    if [ "$(mount_locks)" = in-use ]; then
        check "the image stays" 1 "$(test -f "$img" && echo 1 || echo 0)"
        check "and the row of its layer" 1 "$(layer_rows)"
        check_match "the container reads its files" "^[0-9]+\." "$(sh_ container exec c1 cat /etc/alpine-release 2>&1)"
        sh_ container rm -t 0 -f c1 > /dev/null
        # (the layer goes in the second step of a collection, its image in the
        # first of the next)
        sh_ system gc > /dev/null 2>&1
        sh_ system gc > /dev/null 2>&1
    else
        sh_ system gc > /dev/null 2>&1
        check "no lock, the collection removes the image" 0 "$(test -f "$img" && echo 1 || echo 0)"
        sh_ container rm -t 0 -f c1 > /dev/null
    fi
    check "the image goes with the mount" 0 "$(test -f "$img" && echo 1 || echo 0)"
    check "and the row" 0 "$(layer_rows)"
    stop_daemon
}

# A kernel that keeps no lock (told so here, whatever this one does): the
# image is mounted by the name of its descriptor and nothing holds a lock, so
# only the rows keep the layer.  With the rows lost (deleted here) the
# collection removes the layer under the mount, and the mount goes on (the
# kernel has its own open file of the image: the names and directories of the
# container's root file system are still there; the objects behind the
# data-only layer are not, so an open of a file fails); a pull makes the layer
# again.
@test "a kernel that keeps no lock: mounted without one, the image removed while mounted, the mount goes on" {
    local features=$WORKDIR/state/features key
    key="$(cat /proc/sys/kernel/random/boot_id) $MNT/store/objects"
    stop_daemon
    rm -f "$features"/erofs-lock-*
    printf '%s\n' "$key" > "$features/erofs-lock-no"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    check_match "the kernel mounts the root file systems" "composefs: root file systems from the EROFS images of the layers" "$(cat "$WORKDIR/on.log")"
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || e2e_die "pull"
    local img
    img=$(ls "$MNT"/store/composefs/layer-*.erofs | head -1)
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null
    check "run" 0 $?
    check "the kernel mounts the root, no image server" 0 "$(monitor_log c1 | grep -c 'image server of the root file system')"
    check "the mount holds no lock" unused "$(image_unused "$img")"
    check_match "the container reads its files" "^[0-9]+\." "$(sh_ container exec c1 cat /etc/alpine-release 2>&1)"
    forget_rows
    sh_ system gc > /dev/null 2>&1
    sh_ system gc > /dev/null 2>&1
    check "the collection removed the image" 0 "$(test -f "$img" && echo 1 || echo 0)"
    check "and the row" 0 "$(layer_rows)"
    check "the mount goes on: the directories are there" 0 "$(sh_ container exec c1 ls /etc > /dev/null 2>&1; echo $?)"
    # (the objects of the files went with the layer)
    check "a file whose object is gone cannot be opened" 1 "$(sh_ container exec c1 cat /usr/lib/os-release > /dev/null 2>&1; echo $?)"
    sh_ container rm -t 0 -f c1 > /dev/null
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a pull makes the layer again" 1 "$(layer_rows)"
    check "and its image" 1 "$(ls "$MNT"/store/composefs/layer-*.erofs | wc -l)"
    rm -f "$features"/erofs-lock-no
    stop_daemon
}

# A kernel that keeps no lock (told so here, whatever this one does): the
# rows keep the layers of every kernel mount, the root's and an image
# mount's.  The image mounted is not removed while a container mounts it, and
# collections leave its layer and its files: a file not opened before is read.
@test "a kernel that keeps no lock: the rows of a container keep the layers of its root and of its image mounts" {
    local features=$WORKDIR/state/features key root=$E2E_REGISTRY/e2e/alpine:gzip
    key="$(cat /proc/sys/kernel/random/boot_id) $MNT/store/objects"
    stop_daemon
    rm -f "$features"/erofs-lock-*
    printf '%s\n' "$key" > "$features/erofs-lock-no"
    start_daemon on || { echo "the daemon does not start"; cat "$WORKDIR/on.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || e2e_die "pull"
    sh_ image pull --tls-verify=false "$root" > /dev/null 2>&1 || e2e_die "pull $root"
    sh_ container run -d --name c1 --network none \
        --mount "type=image,source=$IMAGE,destination=/img" "$root" sleep 300 > /dev/null
    check "run" 0 $?
    check "the kernel mounts the root, no image server" 0 "$(monitor_log c1 | grep -c 'image server of the root file system')"
    local images
    images=$(ls "$MNT"/store/composefs/layer-*.erofs | wc -l)
    check_match "the image mounted is not removed" "in use" "$(sh_ image rm "$IMAGE" 2>&1)"
    check_match "nor the image of the root" "in use" "$(sh_ image rm "$root" 2>&1)"
    sh_ system gc > /dev/null 2>&1
    sh_ system gc > /dev/null 2>&1
    check "the layers stay" "$images" "$(ls "$MNT"/store/composefs/layer-*.erofs | wc -l)"
    check_match "a file of the image mount not opened before is read" "Alpine" "$(sh_ container exec c1 cat /img/usr/lib/os-release 2>&1)"
    check_match "and one of the root" "Alpine" "$(sh_ container exec c1 cat /usr/lib/os-release 2>&1)"
    sh_ container rm -t 0 -f c1 > /dev/null
    rm -f "$features"/erofs-lock-no
    stop_daemon
}
