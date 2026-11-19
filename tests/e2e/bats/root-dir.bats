# SPDX-License-Identifier: Apache-2.0
# The root directory of a container is the root directory of the layers of its
# image: the mode, owner, time and attributes of the entry `./` of the top
# layer, with the owner as the container's user namespace shows it, whatever
# the storage driver.  As root the composefs driver mounts the root with the
# kernel, rootless the image server serves it; the vfs driver copies it.  The
# image is imported from a tar: no registry is needed.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/root-dir.bats
#   (as root too)

load helpers

setup_file () {
    command -v getfattr > /dev/null || skip "no getfattr"
    command -v crun > /dev/null || skip "crun is missing"
    e2e_setup_file
    local d
    for d in composefs vfs; do
        mkdir -p "$WORKDIR/$d"
        sed "s|^storage.root = .*|storage.root = \"$WORKDIR/$d\"|; s|^root_dir = .*|root_dir = \"$WORKDIR/$d\"|" \
            "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/$d.toml"
    done
    echo 'storage.driver = "vfs"' | cat - "$WORKDIR/vfs.toml" > "$WORKDIR/vfs.new" && mv "$WORKDIR/vfs.new" "$WORKDIR/vfs.toml"
    BINARIES="sh cat env sleep true false echo ls stat getfattr" e2e_make_rootfs
    # the files of the image, and a first entry `./` that is not a plain
    # directory: mode 01750, owner 1000:1000, a time before 1970, an attribute
    # (the second has an attribute the engine cannot set, the first a plain
    # one: user.* are the container's)
    for variant in "root-dir user.rootattr" "root-dir-refused security.ima"; do
    # shellcheck disable=SC2086
    python3 -I - "$WORKDIR/rootfs" "$WORKDIR/${variant% *}.tar" ${variant#* } << 'PY'
import os, sys, tarfile
root, out, attr = sys.argv[1:]
t = tarfile.open(out, "w", format=tarfile.PAX_FORMAT)
top = tarfile.TarInfo("./")
top.type, top.mode, top.uid, top.gid, top.mtime = tarfile.DIRTYPE, 0o1750, 1000, 1000, -2
top.pax_headers = {"SCHILY.xattr." + attr: "dg"}
t.addfile(top)
old = tarfile.TarInfo("./old")
old.mode, old.mtime = 0o644, -86400.75
t.addfile(old)
for dir, dirs, files in os.walk(root):
    for name in sorted(dirs + files):
        path = os.path.join(dir, name)
        info = t.gettarinfo(path, "./" + os.path.relpath(path, root))
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        t.addfile(info, open(path, "rb") if info.isreg() else None)
t.close()
PY
    done
    for d in composefs vfs; do
        "$BIN/velarx" --config "$WORKDIR/$d.toml" image import "$WORKDIR/root-dir.tar" localhost/root-dir:1 > /dev/null
        "$BIN/velarx" --config "$WORKDIR/$d.toml" image import "$WORKDIR/root-dir-refused.tar" localhost/root-dir:refused > /dev/null
    done
}

teardown_file () {
    e2e_teardown_file
}

# The root of a container of the image on the store of the driver $1, run
# with the options that follow.
root_of () {
    local d=$1
    shift
    "$BIN/velarx" --config "$WORKDIR/$d.toml" container run --rm --network none "$@" localhost/root-dir:1 \
        sh -c 'stat -c "%a %u:%g %Y" /; getfattr --only-values -n user.rootattr /; echo; stat -c %y /old'
}

@test "composefs: the root of the container is the root of the layer" {
    check "the root" "1750 1000:1000 -2
dg
1969-12-30 23:59:59.250000000 +0000" "$(root_of composefs)"
}

# (the runtime makes the mount points in the root of a read-only container:
# its time is the time of that)
@test "composefs: with a read-only root" {
    out=$(root_of composefs --read-only)
    check "the mode and owner" "1750 1000:1000" "$(printf '%s\n' "$out" | head -1 | cut -d' ' -f1,2)"
    check "the attribute" dg "$(printf '%s\n' "$out" | sed -n 2p)"
}

@test "composefs: with a user namespace of its own, the owner is the container's id" {
    check "the root" "1750 1000:1000 -2
dg
1969-12-30 23:59:59.250000000 +0000" "$(root_of composefs --userns auto)"
}

@test "vfs: the root of the container is the root of the layer" {
    check "the root" "1750 1000:1000 -2
dg
1969-12-30 23:59:59.250000000 +0000" "$(root_of vfs)"
}

@test "vfs: with a user namespace of its own, the owner is the container's id" {
    check "the root" "1750 1000:1000 -2
dg
1969-12-30 23:59:59.250000000 +0000" "$(root_of vfs --userns auto)"
}

# An attribute of the `./` the engine cannot set on the directory of the
# container (security.ima with a value that is no header: refused by the
# kernel, and rootless by the permission) is skipped with a warning, as the
# vfs driver does: the container runs with the mode and owner of the layer.
@test "composefs and vfs: an attribute of the root the host refuses does not stop the container" {
    local d
    for d in composefs vfs; do
        check "the root on $d" "1750 1000:1000" \
            "$("$BIN/velarx" --config "$WORKDIR/$d.toml" container run --rm --network none localhost/root-dir:refused stat -c '%a %u:%g' / 2> /dev/null)"
    done
    "$BIN/velarx" --config "$WORKDIR/composefs.toml" container run --rm --network none localhost/root-dir:refused true 2>&1 | grep -c "security.ima" | grep -qx 1 || {
        echo "FAIL: not one warning naming the attribute" >&2; exit 1; }
}

# The image a commit or a build step makes of a container keeps its root: the
# layer has the entry `./` (a layer without it has a plain root).
@test "composefs: a commit and a build step keep the root" {
    local i
    mkdir -p "$WORKDIR/ctx"
    printf 'FROM localhost/root-dir:1\nRUN true\n' > "$WORKDIR/ctx/Containerfile"
    v () { "$BIN/velarx" --config "$WORKDIR/composefs.toml" "$@"; }
    v container create --name c --network none localhost/root-dir:1 true > /dev/null || exit 1
    v container commit c localhost/root-dir:commit > /dev/null || exit 1
    v container rm c > /dev/null
    v build -q -t localhost/root-dir:built "$WORKDIR/ctx" > /dev/null || exit 1
    for i in commit built; do
        check "the root of the image of a $i" "1750 1000:1000" \
            "$(v container run --rm --network none localhost/root-dir:$i stat -c '%a %u:%g' /)"
    done
}
