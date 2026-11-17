# SPDX-License-Identifier: Apache-2.0
# velarx unshare: a command in the user and mount namespaces of
# the rootless engine (the pair the daemon lives in), as podman unshare.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

un () { timeout "${E2E_TIMEOUT:-120}" "$CLI" unshare "$@"; }

@test "velarx unshare joins the namespaces of the daemon" {
    if test "$ROOTLESS" = 0; then
        out=$(un true 2>&1)
        checkfail "unshare is refused as root" $?
        check_match "and says why" "rootless" "$out"
        return
    fi
    check "unshare: root in the namespace" 0 "$(un id -u)"
    check "unshare: the daemon's id map" "$(cat "/proc/$DAEMON_PGID/uid_map")" "$(un cat /proc/self/uid_map)"
    check "unshare: the daemon's user namespace" "$(readlink "/proc/$DAEMON_PGID/ns/user")" \
        "$(un readlink /proc/self/ns/user)"
    check "unshare: the daemon's mount namespace" "$(readlink "/proc/$DAEMON_PGID/ns/mnt")" \
        "$(un readlink /proc/self/ns/mnt)"
    check "unshare: the store in the environment" "$WORKDIR/storage $WORKDIR/state" \
        "$(un sh -c 'echo $CONTAINERS_GRAPHROOT $CONTAINERS_RUNROOT')"
    check "unshare: the exit code of the command" 3 "$(un sh -c 'exit 3'; echo $?)"
    check "unshare: the working directory" "$WORKDIR" "$(cd "$WORKDIR" && un pwd)"
    out=$(SHELL=/bin/echo un)
    check "unshare: \$SHELL by default" "" "$out"
}

@test "files of the sub ids are removed in the namespace" {
    skip_if_root
    # files of the sub ids: the user cannot remove them, root of the
    # namespace can
    d=$WORKDIR/subids
    mkdir -p "$d"
    out=$(runo "$MAPOPTS -v $d:/x:U,z" sh -c 'mkdir /x/sub && touch /x/sub/f')
    check "files of sub ids made" "" "$out"
    check "they are owned by a sub id" "$HOST0" "$(stat -c %u "$d/sub/f" 2>&1)"
    rm -rf "$d" 2> /dev/null
    check "files of sub ids resist the user" 1 "$(test -e "$d/sub/f" && echo 1)"
    un rm -rf "$d"
    check "unshare rm -rf removes them" 0 "$(test -e "$d" && echo 1 || echo 0)"
}

@test "unshare --rootless-netns" {
    skip_if_root
    # --rootless-netns: the namespace of the bridge networks, once one is used
    out=$(un --rootless-netns true 2>&1)
    skip_unless_bridges
    check "network create" 0 "$(sh_ network create unsnet > /dev/null 2>&1; echo $?)"
    check "run on the network" 0 "$(sh_ container run -d --name unsc --network unsnet "$IMG" sleep 100 > /dev/null 2>&1; echo $?)"
    host=$(un readlink /proc/self/ns/net)
    rl=$(un --rootless-netns readlink /proc/self/ns/net)
    check "unshare --rootless-netns joins another network namespace" 1 \
        "$([ -n "$rl" ] && [ "$rl" != "$host" ] && echo 1)"
    check_match "the rootless netns has the bridge" "unsnet|podman|velarx|br" \
        "$(un --rootless-netns cat /proc/net/dev)"
    sh_ container rm -t 0 -f unsc > /dev/null 2>&1

    sh_ network rm unsnet > /dev/null 2>&1
}
