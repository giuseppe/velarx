# SPDX-License-Identifier: Apache-2.0
# A directory as the root file system (--rootfs): as it is, under an overlay,
# idmapped, and the volumes made from its content.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

run_rootfs () {
    local opts=$1
    shift
    # shellcheck disable=SC2086
    sh_ container run --rm --security-opt label=disable $opts "$@" 2>&1
}

# the directory with the content of the image, made once
make_rfs () {
    rfs=$WORKDIR/rfs
    test -d "$rfs" && return
    mkdir -p "$rfs"
    cid=$(sh_ container create "$IMG" true 2> /dev/null)
    sh_ container export "$cid" | tar -xf - -C "$rfs"
    sh_ container rm "$cid" > /dev/null 2>&1
}

@test "a directory as the root file system" {
    make_rfs

    out=$(run_rootfs "" --rootfs "$rfs" echo hi)
    check "rootfs" hi "$out"
    out=$(run_rootfs "" --rootfs "$rfs:O" sh -c 'touch /not-kept; echo done')
    check "rootfs under an overlay" done "$out"
    check "the directory is not written under an overlay" false \
        "$(test -e "$rfs/not-kept" && echo true || echo false)"
    run_rootfs "" --rootfs "$rfs" sh -c 'touch /kept' > /dev/null
    check "the directory is written as it is" true \
        "$(test -e "$rfs/kept" && echo true || echo false)"
    run_rootfs "" --rootfs "$rfs" > /dev/null
    checkfail "no command" $?
    run_rootfs "" --rootfs "$rfs:idmap" true > /dev/null
    checkfail "idmap needs a user namespace" $?
}

@test "a directory as the root file system, idmapped" {
    skip_unless_root
    make_rfs
    # owned by the root of the host, as the image of podman's test
    chown -R 0:0 "$rfs"
    mkdir -p "$rfs/volume"
    chown 1000:1000 "$rfs/volume"
    touch "$rfs/testfile"
    chown 2000:2000 "$rfs/testfile"
    map="--uidmap 0:1000:10000 --gidmap 0:1000:10000"
    out=$(run_rootfs "$map" --rootfs "$rfs:idmap" stat -c %u:%g /bin)
    check "rootfs with the mapping of the container" "0:0" "$out"
    out=$(run_rootfs "$map" --rootfs "$rfs:idmap=uids=0-1001-10000;gids=0-1002-10000" stat -c %u:%g /bin)
    check "rootfs with explicit ranges" "1:2" "$out"
    out=$(run_rootfs "--uidmap 0:1000:200 --gidmap 0:1000:200" \
        --rootfs "$rfs:idmap=uids=@2000-1-1;gids=@2000-1-1" stat -c %u:%g /testfile)
    check "rootfs with ranges of the container" "1:1" "$out"
    out=$(run_rootfs "$map" --rootfs "$rfs:O,idmap" sh -c 'stat -c %u:%g /bin; touch /new; stat -c %u:%g /new')
    check "rootfs idmapped under an overlay" "0:0
0:0" "$out"
    check "nothing mounted is left" 0 "$(grep -c "$rfs" /proc/self/mountinfo)"
    # the owner of the directory of a volume is that of the directory of
    # the root file system, whatever the mapping
    sh_ volume create rfsvol > /dev/null 2>&1
    for from in 1000 2000; do
        out=$(run_rootfs "--uidmap 0:$from:10000 --gidmap 0:$from:10000" \
            -v rfsvol:/volume:idmap --rootfs "$rfs" stat -c %u:%g /volume)
        check "copy-up of an idmapped volume from the rootfs ($from)" "0:0" "$out"
    done
    sh_ volume rm rfsvol > /dev/null 2>&1
}
