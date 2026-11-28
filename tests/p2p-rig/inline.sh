#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# inline.sh: the inline threshold (`pull --inline-threshold=N`: the files of
# up to N bytes, -1: all of them, are held by the EROFS image of their layer)
# in a swarm.  p2p sends no EROFS image: a peer gives the index of a layer
# and bytes by digest, and the receiver makes its own image with its own N,
# so a layer that a peer holds in its image is served from the extent of the
# file, and two nodes with other thresholds hold other images of one layer.
# Three nodes pull one image of small and big files in turn, from the
# registry, then from the peers with the registry stopped, each with a
# threshold of its own (three rounds, the thresholds rotated).  For each pull
# the content must be what the image was made of (the root file system of a
# container, `diff -r`), the layers must have the diff ids of the registry's,
# `system check` must pass, the store must hold as objects exactly the files
# above its N, and the pull must not have asked the registry (it is down).
#
#   tests/p2p-rig/inline.sh [-s SMALL_FILES]
#
# Runs as root like the rest of the rig, and takes /var/tmp/p2p-rig.lock
# first: one rig at a time on the machine.  Needs a build with the flag.
if [ -z "${INLINE_RIG_LOCKED:-}" ]; then
    exec env INLINE_RIG_LOCKED=1 flock /var/tmp/p2p-rig.lock "$0" "$@"
fi
. "$(dirname "$0")/lib.sh"
small=200
while getopts s: o; do
    case $o in s) small=$OPTARG ;; *) exit 2 ;; esac
done
scenario_start inline 3 || exit 1
img=$REG/inline:latest
fail=0
bad () { log "FAIL: $*"; fail=1; }

# the registry again, with what it holds (`reg` starts an empty one); one
# that answers is left as it is (the first round finds the one of `reg`)
reg_again () {
    ip netns exec ${NSP}-reg curl -sf -m 1 "http://$REG/v2/" > /dev/null 2>&1 && return 0
    nsenter --net=/run/netns/${NSP}-reg setpriv --reuid="$RUSER" --regid="$RUSER" --init-groups \
        setsid "$REGISTRY_BIN" serve "$W/reg.yml" >> "$W/registry.log" 2>&1 < /dev/null &
    echo $! > "$W/registry.pid"
    disown
    for _ in $(seq 50); do ip netns exec ${NSP}-reg curl -sf "http://$REG/v2/" > /dev/null && return 0; sleep 0.2; done
    return 1
}
reg_stop () {
    kill "$(cat "$W/registry.pid")" 2> /dev/null
    for _ in $(seq 50); do ip netns exec ${NSP}-reg curl -sf -m 1 "http://$REG/v2/" > /dev/null 2>&1 || return 0; sleep 0.2; done
    return 1
}

# the image: many small files, files around a block, two big ones
ctx=$W/ctx-inline
install -d -o "$RUSER" -g "$RUSER" "$ctx/d"
build_image () {
    local s k rc
    for s in 1 100 4095 4096 4097 65536 70001 3145728 6291457; do
        head -c $s /dev/urandom > "$ctx/d/f$s"
    done
    # (101 to 500 bytes: no size of the files above, which are counted by size)
    for k in $(seq "$small"); do head -c $((RANDOM % 400 + 101)) /dev/urandom > "$ctx/d/s$k"; done
    printf 'FROM scratch\nCOPY d /d\n' > "$ctx/Containerfile"
    chown -R "$RUSER:" "$ctx"
    NOP2P=1 node b
    v b build -f "$ctx/Containerfile" -t localhost/inline:latest "$ctx" &&
        v b image push --tls-verify=false --compression-format zstd:chunked localhost/inline:latest "$img"
    rc=$?
    stop_node b
    rm -rf "$W/nodes/nb"
    return $rc
}
build_image > "$OUT/build.log" 2>&1 || { echo "the image is not built, see $OUT/build.log" >&2; exit 1; }

# verify I N REF_LAYERS [REF]: node I pulled REF (default the tag) with the
# threshold N
verify () {
    local i=$1 n=$2 st=$W/nodes/n$1/store x=$OUT/n$1-export tree=$OUT/n$1-tree s want got ref=${4:-$img}
    got=$(v "$i" image inspect --format '{{.RootFS.Layers}}' "$ref")
    [ "$got" = "$3" ] || bad "node $i (N=$n): the diff ids are $got, not $3"
    v "$i" system check > "$OUT/n$i-check.txt" 2>&1 || bad "node $i (N=$n): system check: $(head -3 "$OUT/n$i-check.txt")"
    rm -rf "$x" "$tree"
    mkdir -p "$tree"
    v "$i" container rm -f vx > /dev/null 2>&1
    v "$i" container create --name vx --network none "$ref" /nothing > /dev/null 2>&1 &&
        v "$i" container export vx -o "$x" > /dev/null 2>&1 || bad "node $i (N=$n): the container is not exported"
    v "$i" container rm -f vx > /dev/null 2>&1
    tar -xf "$x" -C "$tree" 2> /dev/null
    diff -r "$ctx/d" "$tree/d" > "$OUT/n$i-diff.txt" 2>&1 || bad "node $i (N=$n): the files are not the image's: $(head -3 "$OUT/n$i-diff.txt")"
    for s in 1 100 4095 4096 4097 65536 70001 3145728 6291457; do
        if [ "$n" -ge 0 ] && [ "$s" -gt "$n" ]; then want=1; else want=0; fi
        got=$(find "$st/objects" -type f -size "${s}c" 2> /dev/null | wc -l)
        [ "$got" = "$want" ] || bad "node $i (N=$n): $got objects of $s bytes, expected $want"
    done
    if [ "$n" = -1 ]; then
        got=$(find "$st/objects" -type f 2> /dev/null | wc -l)
        [ "$got" = 0 ] || bad "node $i (N=-1): $got objects"
    fi
    [ "$(sqlite3 "$st/db.sqlite" 'SELECT DISTINCT inline FROM layers' | tr '\n' ' ')" = "$n " ] ||
        bad "node $i: layers.inline is not $n"
    log "node $i (N=$n) verified"
}

# pull I N [REF]: the pull of REF (default the tag) with the threshold N, its
# log in OUT
pull () {
    v "$1" image pull --tls-verify=false --inline-threshold="$2" "${3:-$img}" > "$OUT/n$1-pull.log" 2>&1 ||
        bad "node $1 (N=$2): the pull fails: $(tail -2 "$OUT/n$1-pull.log")"
    log "node $1 (N=$2): $(grep -o 'Total:.*' "$OUT/n$1-pull.log")"
}

waitpeers () {
    for _ in $(seq 30); do [ "$(p "$1" peers 2> /dev/null | grep -c '"peer_id"')" -gt 0 ] && return 0; sleep 1; done
    bad "node $1 has no peer"
}

round () { # N_A N_B N_C
    local ref dig
    forget_nodes 0 1 2
    reg_again || { bad "the registry does not start"; return; }
    node 0 || return
    pull 0 "$1"
    ref=$(v 0 image inspect --format '{{.RootFS.Layers}}' "$img")
    verify 0 "$1" "$ref"
    # (the registry is gone: what follows comes from the peers, by digest:
    # a tag needs the registry)
    dig=${img%:*}@$(v 0 image inspect --format '{{.Digest}}' "$img")
    reg_stop || bad "the registry does not stop"
    node 1 || return
    waitpeers 1
    pull 1 "$2" "$dig"
    verify 1 "$2" "$ref" "$dig"
    grep -q ' [1-9][0-9.]*% registry' "$OUT/n1-pull.log" && bad "node 1 got bytes from the registry"
    BOOTN="0 1" node 2 || return
    waitpeers 2
    pull 2 "$3" "$dig"
    verify 2 "$3" "$ref" "$dig"
    grep -q ' [1-9][0-9.]*% registry' "$OUT/n2-pull.log" && bad "node 2 got bytes from the registry"
    p 0 serving > "$OUT/serving-$1.txt" 2>&1
}

round -1 0 65536
round 65536 -1 0
round 0 4096 -1
exit $fail
