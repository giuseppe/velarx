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

@test "libpod create: --userns nomap and ns:PATH from a podman remote client" {
    if [ "$(id -u)" = 0 ]; then
        skip "nomap is for rootless containers"
    fi
    out=$(pm run --rm --userns=nomap "$IMG" awk 'NR==1 {print $1, $2}' /proc/self/uid_map 2>&1)
    check "podman run --userns=nomap" "0 1" "$out"
    pm create --name unspath --userns=ns:/proc/$$/ns/user "$IMG" true > /dev/null 2>&1
    check "podman create --userns=ns:PATH" "ns:/proc/$$/ns/user" \
        "$(pm inspect unspath --format '{{.HostConfig.UsernsMode}}' 2>&1)"
    pm rm -f -t 0 unspath > /dev/null 2>&1
}

@test "compat create: HostConfig.UsernsMode takes the forms of --userns" {
    if [ "$(id -u)" = 0 ]; then
        skip "keep-id and nomap are for rootless containers"
    fi
    for mode in keep-id keep-id:uid=2000,gid=2000 nomap auto:size=2000 ns:/proc/$$/ns/user; do
        name=cu-${mode//[^a-z0-9]/}
        code=$(api -o "$WORKDIR/compat.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
            -d '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"UsernsMode":"'"$mode"'"}}' \
            "http://d/v1.41/containers/create?name=$name")
        check "compat create with UsernsMode $mode" "201 $mode" \
            "$code $(pm inspect "$name" --format '{{.HostConfig.UsernsMode}}' 2>&1)"
        pm rm -f -t 0 "$name" > /dev/null 2>&1
    done
    code=$(api -o "$WORKDIR/compat.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -d '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"UsernsMode":"bogus"}}' \
        http://d/v1.41/containers/create)
    check "an invalid UsernsMode is a bad request" 400 "$code"
    id=$(api -X POST -H 'Content-Type: application/json' \
        -d '{"Image":"'"$IMG"'","Cmd":["cat","/proc/self/uid_map"],"HostConfig":{"UsernsMode":"keep-id"}}' \
        http://d/v1.41/containers/create | jq -r .Id)
    check "keep-id maps the user of the daemon" "$(id -u) 0" \
        "$(pm start -a "$id" 2>&1 | awk 'NR==2 {print $1, $2}')"
    pm rm -f -t 0 "$id" > /dev/null 2>&1
}
