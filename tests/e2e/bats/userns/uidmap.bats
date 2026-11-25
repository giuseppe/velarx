# SPDX-License-Identifier: Apache-2.0
# The user namespace of a container: /proc/self/uid_map for each mode.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

# What the daemon gives a container that has no user namespace of its own.
host_map () {
    if test "$ROOTLESS" = 1; then
        printf '0 %s 1\n1 %s %s' "$ME" "$SUBSTART" "$SUBSIZE"
    else
        printf '0 0 4294967295'
    fi
}

@test "no user namespace and --userns host" {
    out=$(runo "" cat /proc/self/uid_map | squeeze)
    check "no user namespace" "$(host_map)" "$out"

    out=$(runo "--userns host" cat /proc/self/gid_map | squeeze)
    check "userns host" "$(host_map)" "$out"
}

@test "explicit uidmap and gidmap" {
    # explicit maps; rootless the host ids are ids of the daemon's namespace
    out=$(runo "--uidmap 0:1:500 --gidmap 0:2:600" sh -c 'cat /proc/self/uid_map /proc/self/gid_map' | squeeze)
    check "explicit uidmap and gidmap" "0 1 500
0 2 600" "$out"
    out=$(runo "--uidmap 0:1:500" cat /proc/self/gid_map | squeeze)
    check "uidmap implies gidmap" "0 1 500" "$out"
    out=$(runo "--gidmap 0:3:100" cat /proc/self/uid_map | squeeze)
    check "gidmap implies uidmap" "0 3 100" "$out"
    out=$(runo "--uidmap 0:1:100 --uidmap 200:300:5" cat /proc/self/uid_map | squeeze)
    check "several uidmap" "0 1 100
200 300 5" "$out"
    out=$(runo "--uidmap 0:1:100:200:300:5" cat /proc/self/uid_map | squeeze)
    check "several triples in a uidmap" "0 1 100
200 300 5" "$out"

    if test "$ROOTLESS" = 1; then
        out=$(runo "--uidmap +0:@$ME:1" cat /proc/self/uid_map | squeeze)
        check "uidmap with + and @ fills the sub ids" "0 0 1
1 1 $SUBSIZE" "$out"
        runo "--uidmap 0:1:99999999" true > /dev/null 2>&1
        checkfail "uidmap outside the ids of the daemon" $?
        runo "--uidmap 0:0:70000" true > /dev/null 2>&1
        checkfail "uidmap over the end of the sub ids" $?
    else
        out=$(runo "--uidmap 0:300000:65536 --gidmap 0:400000:65536" sh -c 'cat /proc/self/uid_map /proc/self/gid_map' | squeeze)
        check "explicit uidmap and gidmap as root" "0 300000 65536
0 400000 65536" "$out"
    fi
    runo "--userns bogus" true > /dev/null 2>&1
    checkfail "invalid userns" $?
    runo "--userns auto --uidmap 0:1:5" true > /dev/null 2>&1
    checkfail "userns and uidmap exclude each other" $?
    runo "--uidmap 0:1:5:6" true > /dev/null 2>&1
    checkfail "malformed uidmap" $?
}

@test "--userns auto and private" {
    out=$(runo "--userns auto" cat /proc/self/uid_map | squeeze)
    if test "$ROOTLESS" = 1; then
        check "auto" "0 1 1024" "$out"
    else
        check_match "auto" "^0 [0-9]+ 1024$" "$out"
    fi
    out=$(runo "--userns auto:size=300" sh -c 'cat /proc/self/uid_map; cat /proc/self/gid_map' | squeeze | tr '\n' ' ')
    check_match "auto with a size" "^0 [0-9]+ 300 0 [0-9]+ 300 $" "$out"
    runo "--userns auto:size=70000" true > /dev/null 2>&1
    checkfail "auto bigger than the maximum" $?
    runo "--userns auto:size=0" true > /dev/null 2>&1
    checkfail "auto of no ids" $?
    if test "$ROOTLESS" = 1; then
        out=$(runo "--userns private" cat /proc/self/uid_map | squeeze)
        check_match "private" "^0 1 65536$" "$out"
    fi
}

@test "containers that run at the same time have disjoint ranges" {
    a=$(bg "--userns auto" sh -c 'cat /proc/self/uid_map; sleep 60')
    b=$(bg "--userns auto:size=2000" sh -c 'cat /proc/self/uid_map; sleep 60')
    # (an exec sees the mapping once the container runs)
    for i in "$a" "$b"; do e2e_wait_condition "$i" running 30 || e2e_die "$i is not running"; done
    ma=$(sh_ container exec "$a" cat /proc/self/uid_map 2>&1 | squeeze | head -1)
    mb=$(sh_ container exec "$b" cat /proc/self/uid_map 2>&1 | squeeze | head -1)
    sa=$(echo "$ma" | cut -d' ' -f2)
    sb=$(echo "$mb" | cut -d' ' -f2)
    check "auto ranges that are in use differ" 1 "$(test "$ma" != "$mb" && echo 1)"
    if test "$sb" -gt "$sa"; then
        check "auto ranges do not overlap" 1 "$(test $((sa + 1024)) -le "$sb" && echo 1)"
    else
        check "auto ranges do not overlap" 1 "$(test $((sb + 2000)) -le "$sa" && echo 1)"
    fi
    sh_ container rm -t 0 -f "$a" > /dev/null 2>&1
    c=$(bg "--userns auto:size=100" sh -c 'cat /proc/self/uid_map; sleep 60')
    e2e_wait_condition "$c" running 30 || e2e_die "$c is not running"
    mc=$(sh_ container exec "$c" cat /proc/self/uid_map 2>&1 | squeeze | head -1)
    check "the range of a removed container is used again" "$ma" "$(echo "$mc" | sed 's/ 100$/ 1024/')"
    sh_ container rm -t 0 -f "$b" "$c" > /dev/null 2>&1
}

@test "many auto containers at once" {
    ids=
    for n in 1 2 3 4 5 6; do
        ids="$ids $(bg "--userns auto:size=500" sh -c 'cat /proc/self/uid_map; sleep 60')"
    done
    for i in $ids; do e2e_wait_condition "$i" running 30 || e2e_die "$i is not running"; done
    all=
    for i in $ids; do
        all="$all
$(sh_ container exec "$i" cat /proc/self/uid_map 2>&1 | squeeze | head -1 | cut -d' ' -f2)"
    done
    dup=$(echo "$all" | grep -v '^$' | sort | uniq -d | wc -l)
    n=$(echo "$all" | grep -v '^$' | wc -l)
    check "concurrent auto containers: all started" 6 "$n"
    check "concurrent auto containers: no range twice" 0 "$dup"
    # shellcheck disable=SC2086
    sh_ container rm -t 0 -f $ids > /dev/null 2>&1
}

@test "keep-id and nomap" {
    if test "$ROOTLESS" = 1; then
        out=$(runo "--userns keep-id" cat /proc/self/uid_map | squeeze)
        check "keep-id" "0 1 $ME
$ME 0 1
$((ME + 1)) $((ME + 1)) $((SUBSIZE - ME))" "$out"
        out=$(runo "--userns keep-id:uid=2000,gid=3000" sh -c 'cat /proc/self/uid_map; cat /proc/self/gid_map' | squeeze)
        check "keep-id with uid and gid" "0 1 2000
2000 0 1
2001 2001 $((SUBSIZE - 2000))
0 1 3000
3000 0 1
3001 3001 $((SUBSIZE - 3000))" "$out"
        out=$(runo "--userns keep-id:size=1500" cat /proc/self/uid_map | squeeze)
        check "keep-id with a size" "0 1 $ME
$ME 0 1
$((ME + 1)) $((ME + 1)) $((1499 - ME))" "$out"
        out=$(runo "--userns nomap" cat /proc/self/uid_map | squeeze)
        check "nomap" "0 1 $SUBSIZE" "$out"
    else
        runo "--userns keep-id" true > /dev/null 2>&1
        checkfail "keep-id as root is refused" $?
        runo "--userns nomap" true > /dev/null 2>&1
        checkfail "nomap as root is refused" $?
    fi
}

@test "the pid namespace of the host with a user namespace of its own" {
    # procfs is mounted only by the owner of the pid namespace: /proc is
    # the host's, also for a root daemon
    out=$(runo "--userns auto --pid host" sh -c 'test -d /proc/1 && [ "$(cat /proc/1/comm)" != sh ] && echo yes')
    check "userns auto, pid host" "yes" "$out"
}

@test "container:ID shares the namespace" {
    a=$(bg "--userns auto" sleep 60)
    e2e_wait_condition "$a" running 30 || e2e_die "$a is not running"
    out=$(runo "--userns container:$a" cat /proc/self/uid_map | squeeze)
    check_match "container: has the mapping of the other" "^0 [0-9]+ 1024$" "$out"
    same=$(sh_ container exec "$a" readlink /proc/self/ns/user 2>&1)
    other=$(sh_ container run --rm --userns "container:$a" "$IMG" readlink /proc/self/ns/user 2>&1)
    check "container: joins the user namespace" "$same" "$other"
    sh_ container rm -t 0 -f "$a" > /dev/null 2>&1
    runo "--userns container:nosuchcontainer" true > /dev/null 2>&1
    checkfail "container: of a missing container" $?
}
