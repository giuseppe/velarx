# SPDX-License-Identifier: Apache-2.0
# Image mounts (--mount type=image) and the VOLUME of the images.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

@test "image mounts" {
    out=$(runo "--mount type=image,source=$IMG,destination=/img" ls /img)
    check_match "image mount" "etc" "$out"
    out=$(runo "--mount type=image,source=$IMG,destination=/img,subpath=/etc" cat /img/alpine-release)
    check_match "image mount of a sub path" "^[0-9]" "$out"
    out=$(runo "--mount type=image,source=$IMG,destination=/img,subpath=etc" ls /img | head -1)
    check_match "image mount of a sub path without a slash" "." "$out"
    runo "--mount type=image,source=$IMG,destination=/img" sh -c 'touch /img/x' > /dev/null 2>&1
    checkfail "an image mount is read only" $?
    out=$(runo "--mount type=image,source=$IMG,destination=/img,subpath=/nonexistent" true)
    check_match "image mount of a missing sub path" "no directory" "$out"
    out=$(runo "--mount type=image,source=localhost/no-such:image,destination=/img" true)
    check_match "image mount of a missing image" "not found" "$out"
    out=$(runo "--mount type=image,source=$IMG,destination=/img,subpath=/../../etc" true)
    check_match "image mount with .. in the sub path" "invalid subpath" "$out"
    out=$(runo "--mount type=image,source=$IMG,destination=/img,rw" sh -c 'touch /img/x && echo written')
    check_match "an image mount that is read write" "written|not supported" "$out"

}

@test "image mounts under a user namespace" {
    # the owners are those of the container's user namespace
    out=$(runo "$MAPOPTS --mount type=image,source=$IMG,destination=/img" stat -c %u:%g /img/etc/shadow)
    check "image mount under a mapping" "0:42" "$out"
    out=$(runo "--userns auto --mount type=image,source=$IMG,destination=/img" stat -c %u:%g /img/etc/shadow)
    check "image mount with auto" "0:42" "$out"
}

@test "an image that is mounted is not removed" {
    # an image that is mounted cannot be removed
    id=$(bg "--mount type=image,source=$IMG,destination=/img" sleep 60)
    e2e_wait_condition "$id" running 30 || e2e_die "$id is not running"
    sh_ image rm "$IMG" > /dev/null 2>&1
    checkfail "an image in use by a mount is not removed" $?
    sh_ container rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "the VOLUME of an image: an anonymous volume each" {
    cd "$WORKDIR" || exit 1
    mkdir -p build
    printf 'FROM %s\nVOLUME /vdata\nVOLUME /etc/vconf\nRUN mkdir -p /vdata && echo in-image > /vdata/file\n' "$IMG" > build/Containerfile
    check "build" 0 "$(sh_ image build -t localhost/withvolume:1 build > "$WORKDIR/build.log" 2>&1; echo $?)"
    out=$(sh_ container run --rm localhost/withvolume:1 cat /vdata/file 2>&1)
    check "VOLUME: the content of the image is in the volume" "in-image" "$out"
    check "VOLUME: the volumes are removed with --rm" 0 "$(sh_ volume list -q | grep -cE '^[0-9a-f]{64}$')"
    id=$(sh_ container run -d localhost/withvolume:1 sleep 60 2> /dev/null)
    e2e_wait_condition "$id" running 30 || e2e_die "$id is not running"
    check "VOLUME: an anonymous volume each" 2 "$(sh_ volume list -q | grep -cE '^[0-9a-f]{64}$')"
    sh_ container rm -t 0 -f -v "$id" > /dev/null 2>&1
    check "VOLUME: the volumes are removed with rm -v" 0 "$(sh_ volume list -q | grep -cE '^[0-9a-f]{64}$')"
    out=$(sh_ container run --rm --image-volume ignore localhost/withvolume:1 sh -c 'cat /vdata/file; mount | grep -c vdata')
    check_match "--image-volume ignore" "in-image" "$out"
    out=$(sh_ container run --rm --image-volume tmpfs localhost/withvolume:1 sh -c 'mount | grep " /vdata " | cut -d" " -f5' 2>&1)
    check "--image-volume tmpfs" "tmpfs" "$out"
    out=$(sh_ container run --rm -v named:/vdata localhost/withvolume:1 cat /vdata/file 2>&1)
    check "VOLUME: a mount at the same place wins" "in-image" "$out"
    sh_ volume remove named > /dev/null 2>&1
    sh_ container run --rm --image-volume bogus localhost/withvolume:1 true > /dev/null 2>&1
    checkfail "--image-volume with a bad value" $?
    sh_ image rm localhost/withvolume:1 > /dev/null 2>&1
}
