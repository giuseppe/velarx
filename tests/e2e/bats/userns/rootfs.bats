# SPDX-License-Identifier: Apache-2.0
# Files of the image under a mapping: the owners seen inside, and on the host.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

@test "files of the image under a mapping" {
    out=$(runo "$MAPOPTS" sh -c 'stat -c %u:%g / /bin /etc/passwd /etc/shadow | tr "\n" " "')
    check "owners of the image under a mapping" "0:0 0:0 0:0 0:42 " "$out"
    out=$(runo "--userns auto" sh -c 'stat -c %u:%g / /etc/shadow | tr "\n" " "')
    check "owners of the image with auto" "0:0 0:42 " "$out"
    out=$(runo "$MAPOPTS" sh -c 'touch /new && stat -c %u:%g /new')
    check "a file made in the container" "0:0" "$out"
    out=$(runo "$MAPOPTS" sh -c 'echo x > /etc/passwd && cat /etc/passwd')
    check "a file of the image is written (copy-up)" "x" "$out"
}

@test "the upper directory of a running container on the host" {
    # on the host: the upper directory of a running container holds the
    # files with the ids of the parent namespace
    id=$(bg "$MAPOPTS" sh -c 'touch /new /etc/changed; chown 5:6 /new; echo written; sleep 60')
    # (the files are there once the command said so in its log)
    e2e_wait_line "$WORKDIR/root/logs/$id/container.log" ' stdout F written$' 30 ||
        e2e_die "the container did not write its files within 30 s"
    up=$WORKDIR/root/bundles/$id/overlay/upper
    check "the root of the container owns the upper directory" "$HOST0" "$(stat -c %u "$up" 2>&1)"
    check "a file of the container" "$HOST0:$HOST0" "$(stat -c %u:%g "$up/etc/changed" 2>&1)"
    check "a file with another owner" "$((HOST0 + 5)):$((HOST0 + 6))" "$(stat -c %u:%g "$up/new" 2>&1)"
    out=$(sh_ container exec "$id" sh -c 'cat /proc/self/uid_map' 2>&1 | squeeze)
    check "exec in a container with a mapping" "0 ${HOST0} 65536" "$(echo "$out" | sed "s/^0 [0-9]* 65536$/0 $HOST0 65536/")"
    sh_ container rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "a mapping that does not cover the owners of the image" {
    # a mapping that does not cover the owners of the image: refused, with
    # the reason, and nothing half made
    before=$(ls "$WORKDIR/root/bundles" 2>/dev/null | wc -l)
    out=$(runo "--uidmap 0:1:30 --gidmap 0:1:30" true)
    check_match "an image with owners outside the mapping" "owned by (uid|gid) [0-9]+" "$out"
    check "no bundle is left" "$before" "$(ls "$WORKDIR/root/bundles" 2>/dev/null | wc -l)"
}

@test "auto is limited to the ids of the daemon" {
    skip_if_root
    # the daemon without sub ids cannot map an image that has other owners
    out=$(runo "--userns auto:size=70000" true)
    check_match "auto is limited to the ids of the daemon" "70000" "$out"
}
