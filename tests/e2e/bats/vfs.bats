# SPDX-License-Identifier: Apache-2.0
# The vfs storage driver (podman's driver of that name): the root file system
# of a container is a full copy of the files of its image, made when it is
# created, with nothing mounted for the layers, so it works rootless as it is.  What
# runs on a store made with it (pull, run, exec, restart, commit, diff, cp, a
# user namespace, build), what it reports, what it refuses (fs-verity
# enforced while a container runs, lazy pulls), what an image mounted in a
# container is (a read-only copy of it, made for the container when it is
# created), and the refusal of a store made with the other driver.  Run it as an ordinary user for the
# rootless daemon, or as root (which adds a store on a file system without
# reflinks).
#
#   E2E_REGISTRY=localhost:5125 VELARX_BINDIR=target/debug bats tests/e2e/bats/vfs.bats

load helpers
load run_lib

setup_file () {
    export E2E_STORAGE_LINES='storage.driver = "vfs"'
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

store () { echo "$XDG_DATA_HOME/velarx"; }
field () { python3 -I -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(json.dumps(d) if not isinstance(d, str) else d)' "$1"; }

@test "the store records vfs, info says it and says that fs-verity is checked at pull only" {
    check "storageDriver, velarx's own" vfs "$(sh_ info --format '{{.Store.StorageDriver}}')"
    check "graphDriverName: podman's name for it" vfs "$(sh_ info --format '{{.Store.GraphDriverName}}')"
    out=$(sh_ info --format json | field store.graphStatus)
    check_match "the status says fs-verity is pull only" 'fs-verity.*checked at pull only' "$out"
    check_match "the status says there is no kernel mount" 'kernel mount.*no \(vfs mounts no layer' "$out"
    check "the driver is recorded in the store" vfs "$(sqlite3 "$(store)/db.sqlite" "SELECT value FROM store_settings WHERE key = 'driver'")"
    check "the schema is version 1" 1 "$(sqlite3 "$(store)/db.sqlite" 'PRAGMA user_version')"
    if [ -S "$SOCK" ]; then
        check "libpod info" vfs "$(curl -s --unix-socket "$SOCK" http://d/v5.0.0/libpod/info | field store.storageDriver)"
    fi
}

@test "a pull keeps the tables of contents of the layers: no directory of a layer, no image of it" {
    tocs=$(find "$(store)/vfs/tocs" -name '*.toc' | wc -l)
    [ "$tocs" -ge 1 ]
    check "no directory of a layer" 1 "$(test -e "$(store)/vfs/layers"; echo $?)"
    check "no EROFS image" 0 "$(find "$(store)" -name '*.erofs' | wc -l)"
    # the files are the objects of the store; nothing is copied for an image alone
    check "no copy for an image alone" 0 "$(find "$(store)" -path '*/bundles/*' -name root | wc -l)"
}

@test "run, exec, restart: the root file system is a directory, no kernel mount" {
    id=$(sh_ container run -d --name v1 --network none "$IMAGE" sh -c 'echo made > /root/made; sleep 1000')
    out=$(sh_ container exec v1 sh -c 'cat /root/made; grep " / " /proc/self/mountinfo')
    check_match "the file the container made" "^made$" "$out"
    ! printf '%s' "$out" | grep -Eq ' - (erofs|overlay|fuse|fuse\.[a-z-]+) '
    check "the root is not an overlay, EROFS or FUSE" 0 $?
    check "the monitor says the root is a directory" 1 "$(grep -rhs --include=monitor.log -c 'root file system: directory' "$WORKDIR" | awk '{ n += $1 } END { print (n > 0) }')"
    check "GraphDriver.Name" vfs "$(sh_ container inspect --format '{{.GraphDriver.Name}}' v1)"
    dir=$(sh_ container inspect --format '{{.GraphDriver.Data.Dir}}' v1)
    [ -f "$dir/root/made" ] || [ -f "$dir/made" ]
    check "the files of the container are in its directory" 0 $?
    # (no mount labels a directory: the copy has the container's label)
    if command -v selinuxenabled > /dev/null && selinuxenabled; then
        check_match "the copy has the label of the container's files" 'container_file_t' "$(stat -c %C "$dir/etc/os-release")"
    fi
    sh_ container stop -t 0 v1 > /dev/null
    sh_ container start v1 > /dev/null
    check "a restart keeps the copy" made "$(sh_ container exec v1 cat /root/made)"
    sh_ container rm -f -t 0 v1 > /dev/null
    check "the copy goes with the container" 1 "$(test -e "$dir"; echo $?)"
}

@test "a copy is the container's own: the image and another container do not see it" {
    sh_ container run -d --name v2 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container run -d --name v3 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container exec v2 sh -c 'echo only-v2 > /etc/own; rm /etc/os-release' > /dev/null
    check "the other container has the file of the image" 0 "$(sh_ container exec v3 test -f /etc/os-release; echo $?)"
    check "and not what v2 made" 1 "$(sh_ container exec v3 test -e /etc/own; echo $?)"
    sh_ container rm -f -t 0 v2 v3 > /dev/null
}

@test "diff, commit, cp and export of a container of a copy" {
    sh_ container run -d --name v4 --network none "$IMAGE" sh -c 'echo new > /root/new; mkdir /opt/d; echo x > /opt/d/f; rm /etc/motd; ln /root/new /root/new2; mkfifo /root/fifo; sleep 1000' > /dev/null
    sleep 1
    out=$(sh_ container diff v4)
    check_match "an added file" '^A /root/new$' "$out"
    check_match "a deleted file" '^D /etc/motd$' "$out"
    check_match "a changed directory" '^C /root$' "$out"
    check_match "a directory added with its content" '^A /opt/d/f$' "$out"
    ! printf '%s' "$out" | grep -q '/etc/hosts'
    check "the engine's files are not changes" 0 $?
    sh_ container commit v4 localhost/e2e/vfs:1 > /dev/null
    out=$(sh_ container run --rm --network none localhost/e2e/vfs:1 sh -c 'cat /root/new /opt/d/f; test -e /etc/motd || echo nomotd; stat -c %h /root/new')
    check_match "the committed layer has the files" '^new$' "$out"
    check_match "and the deletion" '^nomotd$' "$out"
    check_match "and the hard link" '^2$' "$out"
    sh_ cp v4:/root/new "$WORKDIR/new.out"
    check "cp out of a running container" new "$(cat "$WORKDIR/new.out")"
    echo "in" > "$WORKDIR/in.txt"
    sh_ cp "$WORKDIR/in.txt" v4:/root/in.txt
    check "cp into it" in "$(sh_ container exec v4 cat /root/in.txt)"
    sh_ container stop -t 0 v4 > /dev/null
    check "cp out of a stopped container" new "$(sh_ cp v4:/root/new - | tar -xO)"
    check "diff of a stopped container" 0 "$(sh_ container diff v4 | grep -c '^A /root/new$' | awk '{ print ($1 == 1) ? 0 : 1 }')"
    sh_ container export v4 | tar -t | grep -q '^root/new$'
    check "export has the file" 0 $?
    # a squashed commit
    sh_ container commit --squash v4 localhost/e2e/vfs:sq > /dev/null
    check "a squashed commit has one layer" 1 "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/vfs:sq)"
    check "and the deletion in it" nomotd "$(sh_ container run --rm --network none localhost/e2e/vfs:sq sh -c 'test -e /etc/motd || echo nomotd; test -e /root/new && echo kept' | head -1)"
    check "and the fifo the container made" fifo "$(sh_ container run --rm --network none localhost/e2e/vfs:sq sh -c 'test -p /root/fifo && echo fifo')"
    sh_ container rm -f -t 0 v4 > /dev/null
}

@test "a container with a user namespace is copied with its ids, and the image is not mapped by itself" {
    out=$(sh_ container run --rm --network none --uidmap 0:1:1000 --gidmap 0:1:1000 "$IMAGE" sh -c 'id -u; stat -c "%u:%g" /etc/passwd /root')
    check_match "root of the container" '^0$' "$out"
    check_match "the owners are the container's" '^0:0$' "$out"
    # (the owners on the host are those of the mapping, in the container's own copy)
    sh_ container run -d --name v8 --network none --uidmap 0:1:1000 --gidmap 0:1:1000 "$IMAGE" sleep 1000 > /dev/null
    dir=$(sh_ container inspect --format '{{.GraphDriver.Data.Dir}}' v8)
    if [ "$(id -u)" = 0 ]; then
        check "a file of root of the image is the host id of the container's root" 1 "$(stat -c %u "$dir/etc/passwd")"
    else
        [ "$(stat -c %u "$dir/etc/passwd")" -ge 1 ]
    fi
    sh_ container run --rm --network none --uidmap 0:2:1000 --gidmap 0:2:1000 "$IMAGE" sh -c 'stat -c "%u" /etc/passwd' > "$WORKDIR/u2"
    check "another mapping has its own copy, the same as the container sees" 0 "$(cat "$WORKDIR/u2")"
    sh_ container rm -f -t 0 v8 > /dev/null
    # nothing of a mapping is kept in the store
    check "no layer is copied per mapping" 1 "$(test -e "$(store)/vfs/mapped"; echo $?)"
    check "no directory of a layer either" 1 "$(test -e "$(store)/vfs/layers"; echo $?)"
}

@test "build: RUN, COPY and --squash on a vfs store" {
    ctx=$WORKDIR/ctx
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN echo built > /built && rm /etc/motd\nCOPY f /f\nRUN cat /f /built\n' "$IMAGE" > "$ctx/Dockerfile"
    echo hello > "$ctx/f"
    sh_ build -t localhost/e2e/vfs-b:1 "$ctx" > "$WORKDIR/build.log" 2>&1
    check "build" 0 $?
    out=$(sh_ container run --rm --network none localhost/e2e/vfs-b:1 sh -c 'cat /built /f; test -e /etc/motd || echo nomotd')
    check_match "RUN and COPY" '^built$' "$out"
    check_match "the deletion of a step" '^nomotd$' "$out"
    sh_ build --squash -t localhost/e2e/vfs-b:2 "$ctx" > "$WORKDIR/build.log" 2>&1
    check "build --squash" 0 $?
    base=$(sh_ image inspect --format '{{len .RootFS.Layers}}' "$IMAGE")
    check "the steps are one layer over the base" $((base + 1)) "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/vfs-b:2)"
    check "the squashed image runs" built "$(sh_ container run --rm --network none localhost/e2e/vfs-b:2 cat /built)"
}

@test "an image pushed from a vfs store has what a manifest of the image states" {
    sh_ image push --tls-verify=false localhost/e2e/vfs:1 "$E2E_REGISTRY/e2e/vfs:1" > "$WORKDIR/push.log" 2>&1
    check "push" 0 $?
    out=$(curl -s "http://$E2E_REGISTRY/v2/e2e/vfs/manifests/1" -H 'Accept: application/vnd.oci.image.manifest.v1+json')
    check_match "the layers state the EROFS digest of the layer" 'io.containers.composefs.digest' "$out"
    sh_ image rm -f "$E2E_REGISTRY/e2e/vfs:1" > /dev/null 2>&1 || true
}

@test "fs-verity: enforced while a container runs is an error, best effort accepts the check at pull" {
    out=$(sh_ container create --name v5 --security-opt verity=enforce --network none "$IMAGE" true 2>&1)
    check "enforced for a container is refused" 125 $?
    check_match "and says why and what to do" 'checks fs-verity only when a layer is pulled.*fsverity_best_effort = true' "$out"
    stop_daemon
    cp "$CONFIG" "$CONFIG.orig"
    # the node's setting: refused at the start of the engine
    sed -i '/^storage.driver/a storage.fsverity_require = true' "$CONFIG"
    out=$("$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check "the engine does not start with fsverity_require" 125 $?
    check_match "it says which setting" 'storage.*fsverity_require.*fsverity_best_effort = true' "$out"
    cp "$CONFIG.orig" "$CONFIG"
    sed -i '/^storage.driver/a storage.composefs_digests = "require"' "$CONFIG"
    out=$("$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check "nor with composefs_digests = require" 125 $?
    cp "$CONFIG.orig" "$CONFIG"
    # best effort: accepted
    sed -i '/^storage.driver/a storage.composefs_digests = "require"\nstorage.fsverity_best_effort = true' "$CONFIG"
    start_daemon
    out=$(sh_ container run --rm --security-opt verity=enforce --network none "$IMAGE" echo accepted 2>&1)
    check "best effort accepts the settings that enforce" accepted "$out"
    stop_daemon
    mv "$CONFIG.orig" "$CONFIG"
    start_daemon
}

@test "a lazy pull and an overlay --rootfs are refused, with the driver named" {
    out=$(sh_ image pull --lazy "$IMAGE" 2>&1)
    check "lazy" 125 $?
    check_match "lazy: the driver is named" 'storage driver vfs.*pull without --lazy' "$out"
    out=$(sh_ container create --name v7 --network none --rootfs "$WORKDIR:O" true 2>&1)
    check "--rootfs with an overlay" 125 $?
    check_match "rootfs: an overlay needs an upper directory" 'upper directory' "$out"
}

# An image mounted in a container (--mount type=image) is a copy of the mounted
# image made for the container when it is created, <bundle>/vfs/imagevol/N: owned
# by the ids of the container's user namespace as it is made, handed to the
# monitor at each start as a read-only mount, removed with the container.
@test "--mount type=image: a read-only copy, a subpath, two mounts, another image, restart, rm" {
    hostile_image
    id=$(sh_ container run -d --name im1 --network none \
        --mount "type=image,source=$IMAGE,destination=/mnt/i" \
        --mount "type=image,source=$IMAGE,destination=/mnt/etc,subpath=/etc" \
        --mount "type=image,source=$EVIL,destination=/mnt/evil" \
        "$IMAGE" sleep 1000) || e2e_die "run"
    dir=$(sh_ container inspect --format '{{.GraphDriver.Data.Dir}}' im1)
    vols=$(dirname "$dir")/imagevol
    [ -d "$vols/0" ] || vols=$dir/../imagevol
    check "a copy for each mount in the bundle" "0 1 2" "$(ls "$vols" | tr '\n' ' ' | sed 's/ $//')"
    release=$(sh_ container exec im1 cat /etc/alpine-release | head -1)
    check "the mounted image is read" "$release" "$(sh_ container exec im1 head -1 /mnt/i/etc/alpine-release)"
    check "a subpath is the directory of the image" "$release" "$(sh_ container exec im1 head -1 /mnt/etc/alpine-release)"
    check "an image of other layers than the container's" 0 "$(sh_ container exec im1 test -d /mnt/evil/evil; echo $?)"
    check "and the container's own root has not got it" 1 "$(sh_ container exec im1 test -d /evil; echo $?)"
    out=$(sh_ container exec im1 sh -c 'echo x > /mnt/i/new 2>&1; echo "write: $?"; rm /mnt/i/etc/alpine-release 2>&1; echo "rm: $?"' 2>&1)
    check_match "a write is refused as a read-only file system" "Read-only file system" "$out"
    check_match "and so is a removal" "^rm: 1$" "$out"
    out=$(sh_ container exec im1 sh -c 'for n in null zero loop0; do head -c1 /mnt/evil/evil/$n > /dev/null 2>&1 && echo "$n opens" || echo "$n refused"; done
         while read -r a b c d e f rest; do [ "$e" = /mnt/i ] && echo "mount: $f"; done < /proc/self/mountinfo')
    check "the device nodes of the mounted image are refused" "null refused
zero refused
loop0 refused" "$(printf '%s\n' "$out" | grep -E '^(null|zero|loop0) ')"
    check_match "the mount is ro and nodev" "^mount: ro.*nodev" "$out"
    # the copy is the bundle's: not shared (a change of the bundle's copy is not
    # seen by another container of the image), kept by a restart, gone with
    # the container
    sh_ container run -d --name im2 --network none --mount "type=image,source=$IMAGE,destination=/mnt/i" "$IMAGE" sleep 1000 > /dev/null
    dir2=$(sh_ container inspect --format '{{.GraphDriver.Data.Dir}}' im2)
    [ "$(stat -c %i "$vols/0")" != "$(stat -c %i "$(dirname "$dir2")/imagevol/0")" ]
    check "each container has a copy of its own" 0 $?
    ino=$(stat -c %i "$vols/0")
    sh_ container stop -t 0 im1 > /dev/null
    sh_ container start im1 > /dev/null
    check "a restart keeps the copy and mounts it again" "$release" "$(sh_ container exec im1 head -1 /mnt/i/etc/alpine-release)"
    check "and the same directory, not a new copy" "$ino" "$(stat -c %i "$vols/0")"
    sh_ container rm -f -t 0 im1 > /dev/null
    check "the copies go with the container" 1 "$(test -e "$vols"; echo $?)"
    check "another container's copy stays" "$release" "$(sh_ container exec im2 head -1 /mnt/i/etc/alpine-release)"
    sh_ container rm -f -t 0 im2 > /dev/null
}

@test "--mount type=image with SELinux: the copy of the image has the container's label, as its root does" {
    if ! command -v selinuxenabled > /dev/null || ! selinuxenabled; then
        skip "SELinux is not enabled"
    fi
    sh_ container run -d --name im3 --network none \
        --mount "type=image,source=$IMAGE,destination=/mnt/i" "$IMAGE" sleep 1000 > /dev/null
    dir=$(sh_ container inspect --format '{{.GraphDriver.Data.Dir}}' im3)
    vols=$(dirname "$dir")/imagevol
    [ -d "$vols/0" ] || vols=$dir/../imagevol
    root=$(stat -c %C "$dir/etc/os-release")
    check_match "the root's copy has the label of the container's files" 'container_file_t' "$root"
    check "the copy of the image mount has the same label" "$root" "$(stat -c %C "$vols/0/etc/os-release")"
    check "and so has its top directory" "$root" "$(stat -c %C "$vols/0")"
    # (a symlink too: it is labelled itself, not what it points to)
    link=$(find "$vols/0/etc" -maxdepth 1 -type l | head -1)
    [ -z "$link" ] || check "a link has the label" "$root" "$(stat -c %C "$link")"
    # (a confined container reads it; in enforcing mode it could not otherwise)
    release=$(sh_ container exec im3 cat /etc/alpine-release | head -1)
    check "the confined container reads the mounted image" "$release" "$(sh_ container exec im3 head -1 /mnt/i/etc/alpine-release)"
    sh_ container rm -f -t 0 im3 > /dev/null
}

@test "--mount type=image with a user namespace: the owners of the copy are the container's ids" {
    for opts in "--uidmap 0:1:1000 --gidmap 0:1:1000" "--userns auto"; do
        [ "$opts" != "--userns auto" ] || [ "$(id -u)" = 0 ] || continue
        # shellcheck disable=SC2086
        sh_ container run -d --name imu --network none $opts \
            --mount "type=image,source=$IMAGE,destination=/mnt/i" "$IMAGE" sleep 1000 > /dev/null || e2e_die "run $opts"
        check "the container sees root as the owner of the image's files ($opts)" "0:0" \
            "$(sh_ container exec imu stat -c '%u:%g' /mnt/i/etc/passwd)"
        check "it cannot write them ($opts)" 1 "$(sh_ container exec imu sh -c 'echo x > /mnt/i/etc/passwd' > /dev/null 2>&1; echo $?)"
        dir=$(sh_ container inspect --format '{{.GraphDriver.Data.Dir}}' imu)
        copy=$(dirname "$dir")/imagevol/0
        [ -d "$copy" ] || copy=$dir/../imagevol/0
        host=$(stat -c %u "$copy/etc/passwd")
        root_host=$(stat -c %u "$dir/etc/passwd")
        check "the host owner of the copy is the container root's, as the root copy's ($opts)" "$root_host" "$host"
        if [ "$(id -u)" = 0 ] && [ "$opts" != "--userns auto" ]; then
            check "and is the first id of the mapping" 1 "$host"
        fi
        check "the directory of the copies is the engine's alone" 700 "$(stat -c %a "$(dirname "$copy")")"
        sh_ container rm -f -t 0 imu > /dev/null
    done
}

@test "system check, df and gc go through the driver" {
    check "a check of the store" 0 "$(sh_ system check > /dev/null 2>&1; echo $?)"
    out=$(sh_ system df -v 2>&1)
    check_match "the rows of the driver" '^Vfs +[0-9]+|[Vv]fs' "$out"
    # damage a table of contents: the check finds it and repairs it
    d=$(find "$(store)/vfs/tocs" -name '*.toc' | head -1)
    mv "$d" "$d.moved"
    out=$(sh_ system check 2>&1 || true)
    check_match "the check finds the table is gone" 'toc_missing|table of contents' "$out"
    rm -f "$d.moved"
    sh_ system check --repair > /dev/null 2>&1
    check "repaired: the table is back" 0 "$(test -f "$d"; echo $?)"
    # an object the store lacks is named, and the image is to be pulled again
    sh_ system gc > /dev/null 2>&1
    check "gc keeps the table of an image" 0 "$(test -f "$d"; echo $?)"
}

@test "a store keeps the driver it was made with, both ways" {
    # a server has the driver of its store: the flag is not said to it
    out=$("$BIN/velarx" --socket "$ESOCK" --storage-driver composefs image list 2>&1)
    check "--storage-driver with a running engine" 125 $?
    check_match "it says the engine has its own settings" '--storage-driver: the engine has the settings of its own configuration' "$out"
    check "overlay, podman's name, chooses nothing there" 0 "$("$BIN/velarx" --socket "$ESOCK" --storage-driver overlay image list > /dev/null 2>&1; echo $?)"
    stop_daemon
    out=$("$BIN/velarx" --config "$CONFIG" --storage-driver composefs varlink 2>&1)
    check "a vfs store is not opened as composefs" 125 $?
    check_match "the error names both" 'was made with the storage driver "vfs", but composefs is asked for' "$out"
    # a composefs store is not opened as vfs
    cs=$WORKDIR/cstore
    mkdir -p "$cs"
    printf 'storage.root = "%s/root"\n[engine]\nsocket = "%s/e.sock"\n[server]\nsocket = "%s/e.sock"\nstate_dir = "%s/state"\nroot_dir = "%s/rd"\n' "$cs" "$cs" "$cs" "$cs" "$cs" > "$cs/c.toml"
    "$BIN/velarx" --config "$cs/c.toml" image list > /dev/null 2>&1
    check "a composefs store is made" composefs "$(sqlite3 "$cs/root/db.sqlite" "SELECT value FROM store_settings WHERE key = 'driver'")"
    out=$("$BIN/velarx" --config "$cs/c.toml" --storage-driver vfs image list 2>&1)
    check "a composefs store is not opened as vfs" 125 $?
    check_match "the error names both" 'was made with the storage driver "composefs", but vfs is asked for' "$out"
    # the driver of the store that is not asked for is the store's own
    out=$("$BIN/velarx" --config "$CONFIG" image list 2>&1)
    check "a vfs store is opened with its own driver" 0 $?
    start_daemon
}

@test "a store on ext4 with fs-verity, without reflinks: files are copied, the digests are checked at pull" {
    skip_unless_root
    command -v mkfs.ext4 > /dev/null || skip "no mkfs.ext4"
    img=$WORKDIR/noreflink.img
    mnt=$WORKDIR/noreflink
    truncate -s 1G "$img"
    mkfs.ext4 -q -b 4096 -O verity "$img"
    mkdir -p "$mnt"
    mount -o loop "$img" "$mnt" || skip "no loop device"
    cfg () { # extra storage lines
        cat > "$WORKDIR/nr.toml" <<EOT
storage.root = "$mnt/store"
storage.driver = "vfs"
$1
[engine]
socket = "$WORKDIR/nr.sock"
[server]
socket = "$WORKDIR/nr.sock"
state_dir = "$WORKDIR/nr-state"
root_dir = "$mnt/root"
EOT
    }
    # fsverity_require: refused without best effort, with the setting named
    cfg 'storage.fsverity_require = true'
    out=$("$BIN/velarx" --config "$WORKDIR/nr.toml" image list 2>&1)
    rc=$?
    check "fsverity_require with vfs" 125 "$rc"
    check_match "it says what to do" 'fsverity_best_effort = true' "$out"
    cfg 'storage.fsverity_require = true
storage.fsverity_best_effort = true'
    "$BIN/velarx" --config "$WORKDIR/nr.toml" image pull "$IMAGE" > "$WORKDIR/nr.log" 2>&1
    rc=$?
    out=$("$BIN/velarx" --config "$WORKDIR/nr.toml" info --format json 2>&1 | field store.graphStatus.copies)
    out2=$("$BIN/velarx" --config "$WORKDIR/nr.toml" container run --rm --network none "$IMAGE" sh -c 'echo copied' 2>&1)
    # an object replaced since the pull by a file without fs-verity: the copy
    # measures each object again, and refuses it
    obj=$(find "$mnt/store/objects" -type f -size +100k | head -1)
    cp "$obj" "$obj.new" && mv -f "$obj.new" "$obj"
    out3=$("$BIN/velarx" --config "$WORKDIR/nr.toml" container run --rm --network none "$IMAGE" true 2>&1)
    rc3=$?
    umount -l "$mnt"
    check "the pull on ext4 with fsverity_require and best effort" 0 "$rc"
    check_match "the status says there are no reflinks" 'no reflinks' "$out"
    check "the container runs on a copy" copied "$out2"
    check "a replaced object fails the copy" 125 "$rc3"
    check_match "and says it has no fs-verity" 'has no fs-verity' "$out3"
}

# The plan of the root file system (bundle/rootfs.json) is data the monitor,
# which can be privileged, reads: it names a base (`beneath`) and a way down
# (`path`), and the monitor mounts nothing that leaves the base.  A file that
# says otherwise (the first layout, without `beneath`; the host's `/`; a link
# on the way) makes the start fail with a message that names the file, and
# nothing is mounted: the container does not run.
@test "a tampered rootfs.json (no beneath, beneath=/, a link on the way) fails the start and mounts nothing" {
    id=$(sh_ container create --name tamper --network none "$IMAGE" sh -c 'echo ran > /tmp/ran; sleep 1000') || e2e_die "create"
    bundle=$XDG_DATA_HOME/velarx/bundles/$id
    plan=$bundle/rootfs.json
    [ -f "$plan" ] || e2e_die "no plan at $plan"
    cp "$plan" "$WORKDIR/plan.good"
    check "the plan names the bundle and a relative path" "directory $bundle vfs/root" \
        "$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["kind"], d["beneath"], d["path"])' "$plan")"
    ln -s vfs/root "$bundle/linkroot"
    # (the first layout; the host's /; a link as the path; a link on the way;
    # a path that leaves the base)
    for row in \
        'old|{"kind":"directory","path":"/etc"}|no `beneath`' \
        'slash|{"kind":"directory","beneath":"/","path":"etc"}|beneath is `/`' \
        'link|{"kind":"directory","beneath":"'$bundle'","path":"linkroot"}|root file system' \
        'linkway|{"kind":"directory","beneath":"'$bundle'","path":"linkroot/etc"}|root file system' \
        'dotdot|{"kind":"directory","beneath":"'$bundle'","path":"../../../etc"}|component' \
        'abs|{"kind":"directory","beneath":"'$bundle'","path":"/etc"}|not relative'; do
        name=${row%%|*}; rest=${row#*|}; json=${rest%|*}; want=${rest##*|}
        printf '%s' "$json" > "$plan"
        out=$(sh_ container start tamper 2>&1); rc=$?
        [ "$rc" -ne 0 ] || e2e_die "$name: the start succeeded: $out"
        # (a plan that is wrong in itself is refused by the name of the file;
        # one that the monitor cannot open names the directory)
        case $name in
            link*) ;;
            *) check_match "$name: the message names the file" "$bundle/rootfs.json" "$out" ;;
        esac
        check_match "$name: and says why" "$want" "$out"
        check "$name: the container did not run" 0 "$(sh_ container inspect --format '{{.State.Running}}' tamper | grep -c true)"
        [ ! -e "$bundle/rootfs/etc/passwd" ] || e2e_die "$name: a root file system was mounted"
    done
    check_match "the remedy is said for the first layout" "remove the container and create it again" "$(printf '%s' '{"kind":"directory","path":"/etc"}' > "$plan"; sh_ container start tamper 2>&1)"
    # a base its group or others can write is refused (the monitor checks the
    # descriptor it opened, whatever the plan says)
    cp "$WORKDIR/plan.good" "$plan"
    chmod g+w "$bundle"
    out=$(sh_ container start tamper 2>&1) && e2e_die "a group-writable base was taken: $out"
    check_match "group-writable base: refused" "can be written by its group or others" "$out"
    chmod g-w "$bundle"
    # the good plan again: the root file system works as before
    cp "$WORKDIR/plan.good" "$plan"
    rm -f "$bundle/linkroot"
    sh_ container start tamper > /dev/null || e2e_die "start with the good plan"
    check "the container runs on its copy" ran "$(sh_ container exec tamper cat /tmp/ran)"
    sh_ container rm -f -t 0 tamper > /dev/null
}

# A plan of the kind `mount-fd` names a detached mount that the engine passes
# to the monitor at its spawn; the engine asks the driver for it at each start.
# No driver of the product makes one (vfs makes a directory), so a bundle
# changed to say so fails closed at the start, by the name of the file or the
# driver and with the remedy (the engine asked vfs for the root at this start:
# the refusal is the engine's, not the monitor's), and a plan that names a
# descriptor by its
# number (any other file descriptor the monitor has) or an index no monitor
# gets is no plan.  Nothing is mounted and the container does not run.
@test "a mount-fd plan without a descriptor of the engine, or with a number, fails the start and mounts nothing" {
    id=$(sh_ container create --name nofd --network none "$IMAGE" sh -c 'echo ran > /tmp/ran; sleep 1000') || e2e_die "create"
    bundle=$XDG_DATA_HOME/velarx/bundles/$id
    plan=$bundle/rootfs.json
    cp "$plan" "$WORKDIR/plan.good"
    for row in \
        'noindex0|{"kind":"mount-fd","fd_index":0}|now makes another kind of plan' \
        'index99|{"kind":"mount-fd","fd_index":99}|fd_index 99' \
        'number|{"kind":"mount-fd","fd":3}|fd_index' \
        'path|{"kind":"mount-fd","path":"/"}|fd_index'; do
        name=${row%%|*}; rest=${row#*|}; json=${rest%|*}; want=${rest##*|}
        printf '%s' "$json" > "$plan"
        out=$(sh_ container start nofd 2>&1); rc=$?
        [ "$rc" -ne 0 ] || e2e_die "$name: the start succeeded: $out"
        check_match "$name: says why" "$want" "$out"
        check "$name: the container did not run" 0 "$(sh_ container inspect --format '{{.State.Running}}' nofd | grep -c true)"
        [ ! -e "$bundle/rootfs/etc/passwd" ] || e2e_die "$name: a root file system was mounted"
    done
    check_match "the remedy is said" "remove the container and create it again" "$(printf '%s' '{"kind":"mount-fd","fd_index":0}' > "$plan"; sh_ container start nofd 2>&1)"
    cp "$WORKDIR/plan.good" "$plan"
    sh_ container start nofd > /dev/null || e2e_die "start with the good plan"
    check "the container runs on its copy" ran "$(sh_ container exec nofd cat /tmp/ran)"
    sh_ container rm -f -t 0 nofd > /dev/null
}

# The bundle is the base of the plan, which must not be writable by the group
# or others: an engine whose umask is 002 (a user private group) still makes
# bundles that the monitor takes.
@test "an engine with umask 002 makes a bundle the monitor takes" {
    stop_daemon
    umask 002
    start_daemon
    umask 022
    sh_ container run -d --name um --network none "$IMAGE" sleep 1000 > /dev/null || e2e_die "run with umask 002"
    id=$(sh_ container inspect --format '{{.Id}}' um)
    check "the bundle is not writable by the group or others" 0 "$(( 0$(stat -c %a "$XDG_DATA_HOME/velarx/bundles/$id") & 022 ))"
    sh_ container rm -f -t 0 um > /dev/null
    stop_daemon
    start_daemon
}
