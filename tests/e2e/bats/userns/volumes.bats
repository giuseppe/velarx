# SPDX-License-Identifier: Apache-2.0
# Named and anonymous volumes, bind mounts with U and idmap, image volumes.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () {
    for v in cu nc pre mapped optvol owned tmpvol expv impv a b mvol ovol spv; do
        sh_ volume remove -f "$v" > /dev/null 2>&1
    done
    userns_teardown_file
}

@test "copy-up of the image directory into a new volume" {
    VOLS=$WORKDIR/root/volumes
    # copy-up of the image directory into a new volume
    runo "-v cu:/etc" true > /dev/null
    check "copy-up" 1 "$(test -f "$VOLS/cu/_data/alpine-release" && echo 1)"
    check "copy-up keeps the content" "$(runo "" cat /etc/passwd)" "$(cat "$VOLS/cu/_data/passwd")"
    check "the volume has the owner and the mode of the directory" \
        "$(runo "" stat -c %a /etc)" "$(stat -c %a "$VOLS/cu/_data")"
    out=$(runo "-v cu:/etc" ls /etc | head -3 | wc -l)
    check "the volume is used" 3 "$out"
    runo "-v nc:/etc:nocopy" true > /dev/null
    # The mount points of /etc/hosts, hostname and resolv.conf (bind mounts
    # from the bundle) are made in a volume on /etc, as with podman.
    etc_files='^(hosts|hostname|resolv\.conf)$'
    check "nocopy" 0 "$(ls "$VOLS/nc/_data" | grep -vcE "$etc_files")"
    # a volume with data is not copied into
    sh_ volume create pre > /dev/null
    echo mine > "$VOLS/pre/_data/mine"
    runo "-v pre:/etc" true > /dev/null
    check "no copy-up into a volume that has data" "mine" "$(ls "$VOLS/pre/_data" | grep -vE "$etc_files")"
}

@test "the owners of a volume follow the mapping" {
    VOLS=$WORKDIR/root/volumes
    # the owners follow the mapping
    runo "$MAPOPTS -v mapped:/etc" true > /dev/null
    check "volume owner under a mapping" "$HOST0:$HOST0" "$(stat -c %u:%g "$VOLS/mapped/_data")"
    check "copied files have the ids of the container" "$HOST0:$((HOST0 + 42))" "$(stat -c %u:%g "$VOLS/mapped/_data/shadow")"
}

@test "anonymous volumes" {
    out=$(sh_ volume list -q | wc -l)
    runo "-v /anon" sh -c 'echo data > /anon/f; cat /anon/f' > /dev/null
    id=$(bg "-v /anon2" sleep 60)
    anon=$(sh_ volume list -q | grep -E '^[0-9a-f]{64}$')
    check "an anonymous volume" 1 "$(echo "$anon" | grep -c .)"
    sh_ container rm -t 0 -f "$id" > /dev/null
    check "an anonymous volume stays with rm" 1 "$(sh_ volume list -q | grep -cE '^[0-9a-f]{64}$')"
    id=$(bg "-v /anon3" sleep 60)
    sh_ container rm -t 0 -f -v "$id" > /dev/null
    sh_ volume prune -f > /dev/null
    check "volumes are pruned" 0 "$(sh_ volume list -q | grep -cE '^[0-9a-f]{64}$')"
    # --rm removes the anonymous volumes
    runo "-v /anon4" true > /dev/null
    check "an anonymous volume is removed with --rm" 0 "$(sh_ volume list -q | grep -cE '^[0-9a-f]{64}$')"
}

@test "volume create: options and errors" {
    VOLS=$WORKDIR/root/volumes
    # create: options and errors
    out=$(sh_ volume create --label a=b optvol)
    check "volume create" optvol "$out"
    out=$(sh_ volume create optvol 2>&1)
    check_match "volume create of an existing volume" "exists" "$out"
    check "volume create --ignore" optvol "$(sh_ volume create --ignore optvol)"
    sh_ volume create -o bogus=1 badopt > /dev/null 2>&1
    checkfail "volume create with a bad option" $?
    sh_ volume create 'bad/name' > /dev/null 2>&1
    checkfail "volume create with a bad name" $?
    rnd=$(sh_ volume create)
    check_match "volume create without a name" '^[0-9a-f]{64}$' "$rnd"
    sh_ volume remove "$rnd" > /dev/null
    sh_ volume create -o uid=1000 -o gid=1000 owned > /dev/null
    if test "$ROOTLESS" = 1; then
        want=$((SUBSTART + 999))
    else
        want=1000
    fi
    check "volume owner from the options" "$want:$want" "$(stat -c %u:%g "$VOLS/owned/_data")"
    sh_ volume create -o type=tmpfs -o device=tmpfs -o o=size=1m,mode=1777 tmpvol > /dev/null
    out=$(sh_ volume mount tmpvol)
    check "volume mount" "$VOLS/tmpvol/_data" "$out"
    # the mount is in the mount namespace of the daemon: look from a container
    check "a volume with options is mounted" tmpfs "$(runo "-v tmpvol:/t" stat -f -c %T /t)"
    sh_ volume unmount tmpvol > /dev/null
    check "volume unmount" 0 $?
}

@test "a volume in use" {
    sh_ volume create --ignore optvol > /dev/null
    id=$(bg "-v optvol:/o" sleep 60); echo "# bg [$id]"
    sh_ volume remove optvol > /dev/null 2>&1
    checkfail "a volume in use is not removed" $?
    sh_ container rm -t 0 -f "$id" > /dev/null
    sh_ volume remove optvol > /dev/null 2>&1
    check "a volume that is not in use is removed" 0 $?
}

@test "volume export and import" {
    sh_ volume create expv > /dev/null
    runo "-v expv:/d" sh -c 'mkdir /d/sub; echo exported > /d/sub/f; ln -s sub/f /d/link; chmod 600 /d/sub/f' > /dev/null
    sh_ volume export expv -o "$WORKDIR/exp.tar"
    check "volume export" "link sub/ sub/f " "$(tar -tf "$WORKDIR/exp.tar" | sort | tr '\n' ' ')"
    sh_ volume create impv > /dev/null
    sh_ volume import impv "$WORKDIR/exp.tar"
    check "volume import" "exported" "$(runo "-v impv:/d" cat /d/sub/f)"
    check "volume import keeps the link" "sub/f" "$(runo "-v impv:/d" readlink /d/link)"
    check "volume import keeps the mode" "600" "$(runo "-v impv:/d" stat -c %a /d/sub/f)"
    sh_ volume export expv | tar -tf - > /dev/null
    check "volume export to a pipe" 0 $?
    echo junk > "$WORKDIR/junk"
    sh_ volume import impv "$WORKDIR/junk" > /dev/null 2>&1
    checkfail "volume import of something that is not a tar" $?
}

@test "bind mounts with U" {
    d=$WORKDIR/bind
    mkdir -p "$d/sub"
    echo data > "$d/sub/f"
    runo "$MAPOPTS -v $d:/b" sh -c 'stat -c %u /b/sub/f' > "$WORKDIR/out" 2>&1
    check_match "a bind mount shows unmapped owners as nobody" "^(65534|nobody|4294967295)$" "$(cat "$WORKDIR/out")"
    runo "$MAPOPTS -v $d:/b:U" sh -c 'stat -c %u:%g /b /b/sub /b/sub/f | tr "\n" " "' > "$WORKDIR/out" 2>&1
    check "U: the owner inside" "0:0 0:0 0:0 " "$(cat "$WORKDIR/out")"
    check "U: the owner outside" "$HOST0:$HOST0" "$(stat -c %u:%g "$d/sub/f")"
    runo "$MAPOPTS -v $d:/b:U" sh -c 'true' > /dev/null
    # give it back (rootless: the user is root of the host mode)
    runo "-v $d:/b:z" chown -R 0:0 /b
    check "the owner is given back" "$ME" "$(stat -c %u "$d/sub/f")"
    runo "$MAPOPTS -v $d:/b:U,idmap" true > /dev/null 2>&1
    checkfail "U and idmap together" $?
    runo "$MAPOPTS -v /usr:/b:U" true > /dev/null 2>&1
    checkfail "U on a system directory" $?
    out=$(runo "--userns auto --tmpfs /t:U,mode=700" stat -c %u /t)
    check "U on a tmpfs" 0 "$out"
}

@test "idmap" {
    d=$WORKDIR/bind
    mkdir -p "$d"
    runo "-v $d:/b:idmap" true > /dev/null 2>&1
    checkfail "idmap needs a user namespace" $?
    if test "$ROOTLESS" = 0; then
        # files owned by the root of the host show as the root of the container
        mkdir -p "$WORKDIR/idm"
        echo hi > "$WORKDIR/idm/f"
        chown 0:0 "$WORKDIR/idm" "$WORKDIR/idm/f"
        chmod 777 "$WORKDIR/idm"
        # relabelled (z) as podman needs it under SELinux: a confined
        # container cannot read the files of the host otherwise
        out=$(runo "$MAPOPTS -v $WORKDIR/idm:/m:idmap,z" sh -c 'stat -c %u:%g /m/f; echo new > /m/g; stat -c %u /m/g')
        check "idmapped volume" "0:0
0" "$out"
        check "a file made in an idmapped volume" "0" "$(stat -c %u "$WORKDIR/idm/g")"
        out=$(runo "$MAPOPTS --mount type=bind,src=$WORKDIR/idm,dst=/m,idmap,relabel=shared" cat /m/f)
        check "idmapped --mount" hi "$out"
        out=$(runo "$MAPOPTS --mount type=bind,src=$WORKDIR/idm,dst=/m,idmap=uids=0-300000-1;gids=0-300000-1" stat -c %u /m/f)
        check "idmap with explicit ranges" 0 "$out"
        out=$(runo "$MAPOPTS --mount type=bind,src=$WORKDIR/idm,dst=/m,idmap=uids=0-300005-1;gids=0-300000-1" stat -c %u /m/f)
        check "idmap with another mapping shows another id" 5 "$out"
    fi
    runo "$MAPOPTS -v $d:/b:idmap=uids=bad" true > /dev/null 2>&1
    checkfail "idmap with a bad option" $?
}

@test "duplicates and other errors" {
    d=$WORKDIR/bind
    mkdir -p "$d"
    runo "-v a:/x -v b:/x" true > /dev/null 2>&1
    checkfail "two mounts at the same place" $?
    runo "-v /nonexistent-dir:/x" true > /dev/null 2>&1
    checkfail "a bind source that does not exist" $?
    runo "-v rel:x" true > /dev/null 2>&1
    checkfail "a relative destination" $?
    runo "--mount type=bind,src=$d,dst=/x,bogus=1" true > /dev/null 2>&1
    checkfail "an unknown mount option" $?
}

@test "--mount of a volume and of a tmpfs" {
    out=$(runo "--mount type=volume,src=mvol,dst=/mv" sh -c 'echo kept > /mv/f; cat /mv/f')
    check "--mount type=volume" kept "$out"
    check "--mount type=volume keeps the data" kept "$(runo "-v mvol:/mv" cat /mv/f)"
    out=$(runo "--mount type=tmpfs,dst=/tm,tmpfs-size=1m" sh -c 'grep " /tm " /proc/mounts | cut -d" " -f3')
    check "--mount type=tmpfs" tmpfs "$out"
}

@test "create takes the same flags as run, volume rm --force" {
    id=$(sh_ container create -v cvol:/cv --mount type=tmpfs,dst=/ct --tmpfs /ct2 "$IMG" \
             sh -c 'echo c > /cv/f; grep -c " /ct2* " /proc/mounts')
    out=$(sh_ container start -a "$id" 2>&1)
    check "create -v, --mount and --tmpfs" 2 "$out"
    check "create -v writes the volume" c "$(runo "-v cvol:/cv" cat /cv/f)"
    if test -n "${MAPOPTS:-}"; then
        # shellcheck disable=SC2086
        id2=$(sh_ container create $MAPOPTS "$IMG" cat /proc/self/uid_map)
        out=$(sh_ container start -a "$id2" 2>&1 | awk 'NR==1 {print $1, $3}')
        check "create with a user namespace" "0 65536" "$out"
        sh_ container rm -t 0 -f "$id2" > /dev/null 2>&1
    fi

    # volume rm --force removes the containers that use the volume
    sh_ volume remove cvol > /dev/null 2>&1
    checkfail "volume rm of a volume in use" $?
    sh_ volume remove -f cvol > /dev/null
    check "volume rm --force" 0 "$(sh_ volume list -q | grep -c '^cvol$')"
    sh_ container inspect "$id" > /dev/null 2>&1
    checkfail "volume rm --force removes its containers" $?
}

@test "overlay volumes: the source is the lower layer, never written" {
    lo=$WORKDIR/olower
    mkdir -p "$lo"
    echo orig > "$lo/f"
    out=$(runo "-v $lo:/o:O" sh -c 'echo new > /o/f && echo add > /o/g && cat /o/f /o/g')
    check "overlay volume: writable" "new
add" "$out"
    check "overlay volume: the source is unchanged" "orig no" \
        "$(cat "$lo/f") $(test -e "$lo/g" && echo yes || echo no)"
    check "overlay volume: the changes are gone at the next run" "orig" "$(runo "-v $lo:/o:O" cat /o/f)"
    out=$(runo "-v $lo:/o:O,ro" sh -c 'echo x > /o/f' 2>&1)
    check_match "overlay volume: ro" "Read-only" "$out"
    up=$WORKDIR/oupper
    wk=$WORKDIR/owork
    mkdir -p "$up" "$wk"
    runo "-v $lo:/o:O,upperdir=$up,workdir=$wk" sh -c 'echo kept > /o/k' > /dev/null
    check "overlay volume: upperdir keeps the changes" "kept no" \
        "$(cat "$up/k" 2> /dev/null) $(test -e "$lo/k" && echo yes || echo no)"
    check "overlay volume: and the next run sees them" "kept" \
        "$(runo "-v $lo:/o:O,upperdir=$up,workdir=$wk" cat /o/k)"
    runo "-v $lo:/o:O,upperdir=$up" true > /dev/null 2>&1
    checkfail "overlay volume: upperdir without workdir" $?
    runo "-v $lo:/o:O,z" true > /dev/null 2>&1
    checkfail "overlay volume: z" $?
    runo "-v $WORKDIR/nonexistent:/o:O" true > /dev/null 2>&1
    checkfail "overlay volume: a missing source" $?
    out=$(runo "$MAPOPTS -v $lo:/o:O" sh -c 'touch /o/n && stat -c %u:%g /o /o/n | tr "\n" " "')
    check "overlay volume: the root of the container owns it under a mapping" "0:0 0:0 " "$out"
    # the files of the host user are nobody's there, as with a bind mount
    out=$(runo "--userns auto -v $lo:/o:O" sh -c 'echo u > /o/new && cat /o/new /o/f')
    check "overlay volume: with --userns auto" "u
orig" "$out"
    sh_ volume create ovol > /dev/null
    runo "-v ovol:/v" sh -c 'echo base > /v/b' > /dev/null
    check "overlay of a named volume" "changed base" \
        "$( (runo "-v ovol:/v:O" sh -c 'echo changed > /v/b; cat /v/b'; runo "-v ovol:/v" cat /v/b) | tr '\n' ' ' | sed 's/ $//')"
    sh_ container run -d --name ovc -v "$lo:/o:O" "$IMG" sh -c 'echo x > /o/y; sleep 100' > /dev/null
    ovd=$(find "$WORKDIR" -type d -name ovol 2> /dev/null | head -1)
    [ -n "$ovd" ] || e2e_die "no directory of the volume ovol"
    e2e_wait_path "$ovd/0.upper/y" 30 || true
    check "overlay volume: the upper layer is in the container's bundle" 1 \
        "$(find "$WORKDIR" -path '*/ovol/0.upper/y' 2> /dev/null | wc -l)"
    sh_ container rm -t 0 -f ovc > /dev/null 2>&1
    check "overlay volume: and removed with it" 0 \
        "$(find "$WORKDIR" -path '*/ovol/0.upper' 2> /dev/null | wc -l)"
}

@test "a directory of a named volume (subpath)" {
    # a directory of a named volume, looked up inside the volume
    sh_ volume create spv > /dev/null
    runo "-v spv:/v" sh -c 'mkdir -p /v/a/b && echo inner > /v/a/b/f && echo top > /v/top &&
        ln -s / /v/root && ln -s /etc /v/hostetc && ln -s ../../../../.. /v/up' > /dev/null
    SP="type=volume,src=spv,dst=/d"
    check "volume subpath" "f inner" "$(runo "--mount $SP,subpath=a/b" sh -c 'ls /d; cat /d/f' | tr '\n' ' ' | sed 's/ $//')"
    check "volume subpath: writes go to the directory" "w" \
        "$(runo "--mount $SP,subpath=a" sh -c 'echo w > /d/new' > /dev/null; runo "-v spv:/v" cat /v/a/new)"
    check "volume subpath through a link stays in the volume" "inner" "$(runo "--mount $SP,subpath=root/a/b" cat /d/f)"
    check "volume subpath: a file" "inner" "$(runo "--mount type=volume,src=spv,dst=/f,subpath=a/b/f" cat /f)"
    runo "--mount type=volume,src=spv,dst=/f,subpath=a/b/f,U" true > /dev/null 2>&1
    checkfail "volume subpath: U needs a directory" $?
    runo "--mount $SP,subpath=nope" true > /dev/null 2>&1
    checkfail "volume subpath: a missing directory" $?
    runo "--mount $SP,subpath=hostetc" true > /dev/null 2>&1
    checkfail "volume subpath: a link to /etc is the volume's /etc (none)" $?
    runo "--mount $SP,subpath=up/etc" true > /dev/null 2>&1
    checkfail "volume subpath: .. in a link stays in the volume" $?
    # U: the directory of the sub path, not the volume
    runo "--user 1000:1000 --mount $SP,subpath=a,U" true > /dev/null 2>&1
    check "volume subpath with U: the directory is the user's" "1000:1000 1000:1000" \
        "$(runo "-v spv:/v" stat -c %u:%g /v/a /v/a/b/f | tr '\n' ' ' | sed 's/ $//')"
    check "volume subpath with U: the rest of the volume is not" "0:0 0:0" \
        "$(runo "-v spv:/v" stat -c %u:%g /v /v/top | tr '\n' ' ' | sed 's/ $//')"
    check "volume subpath with U: the user writes there" "w" \
        "$(runo "--user 1000:1000 --mount $SP,subpath=a,U" sh -c 'echo w > /d/mine && cat /d/mine')"
    # a link swapped in for the directory after the create: the start
    # looks it up again, inside the volume
    id=$(sh_ container create --mount "$SP,subpath=a/b" "$IMG" cat /d/hostname 2> /dev/null)
    runo "-v spv:/v" sh -c 'mv /v/a/b /v/a/b.old && ln -s /etc /v/a/b' > /dev/null
    out=$(sh_ container start -a "$id" 2>&1)
    check "volume subpath: a link swapped in does not lead out of the volume" 1 \
        "$(test "$out" != "$(cat /etc/hostname)" && echo 1)"
    check_match "volume subpath: the start says why" "has no a/b" "$out"
    sh_ container rm -t 0 -f "$id" > /dev/null 2>&1
    out=$(runo "$MAPOPTS --mount $SP,subpath=a/b.old" cat /d/f)
    check "volume subpath under a mapping" "inner" "$out"
}
