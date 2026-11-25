# SPDX-License-Identifier: Apache-2.0
# User namespaces through the podman API and the CLI: the run directory of
# a rootless daemon (0700) is out of reach of the ids of such a container.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

@test "run with --userns=auto, auto:size= and --uidmap" {
    map='awk "NR==1 {print \$1, (\$3 >= 1024)}" /proc/self/uid_map; touch /x; echo ok'
    out=$(pm run --rm --userns=auto "$IMG" sh -c "$map" 2>&1 | tr '\n' ' ')
    check "podman run --userns=auto" "0 1 ok " "$out"
    out=$(pm run --rm --userns=auto:size=2000 "$IMG" sh -c 'awk "NR==1 {print \$3}" /proc/self/uid_map' 2>&1)
    check "podman run --userns=auto:size=" "2000" "$out"
    out=$(pm run --rm --uidmap 0:1:1024 --gidmap 0:1:1024 "$IMG" sh -c 'awk "NR==1 {print \$3}" /proc/self/uid_map' 2>&1)
    check "podman run --uidmap" "1024" "$out"
    out=$(timeout 120 "$CLI" --socket "$ESOCK" container run --rm --userns=auto "$IMG" sh -c "$map" 2>&1 | tr '\n' ' ')
    check "velarx run --userns=auto" "0 1 ok " "$out"
}

@test "exec in a --userns=auto container and the public root goes with it" {
    id=$(pm run -d --userns=auto "$IMG" sleep 60)
    out=$(pm exec "$id" sh -c 'echo in > /tmp/f; cat /tmp/f')
    check "exec in a --userns=auto container" "in" "$out"
    pm rm -t 0 -f "$id" > /dev/null
    base=/tmp/velarx-rootfs-$(id -u)
    [ "$(id -u)" = 0 ] && base=/run/velarx-rootfs-0
    check "the public root is gone with the container" 0 "$(ls "$base" 2>/dev/null | grep -c "^$id")"
}
