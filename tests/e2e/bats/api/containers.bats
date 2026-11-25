# SPDX-License-Identifier: Apache-2.0
# End to end tests of the REST API, containers: run,
# lifecycle, exec, events, cp, misc, filters (see api_helpers.bash).

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}

@test "run" {
    out=$(pm run --rm "$IMG" echo hello 2>&1)
    check "run --rm" "hello" "$out"
    pm run --rm "$IMG" sh -c 'exit 42' > /dev/null 2>&1
    check "run exit code" 42 $?
    out=$(pm run --rm "$IMG" sh -c 'echo out; echo err >&2' 2> /dev/null)
    check "run stdout" "out" "$out"
    out=$(pm run --rm "$IMG" sh -c 'echo out; echo err >&2' 2>&1 > /dev/null)
    check "run stderr" "err" "$out"
    out=$(echo from-stdin | pm run --rm -i "$IMG" cat)
    check "run stdin" "from-stdin" "$out"
    out=$(yes "$(printf '\020\021')" | head -c 1048576 | pm run --rm -i "$IMG" wc -c)
    check "run stdin of 1 MiB with the detach keys in it" 1048576 "$out"
    # a --workdir the image lacks: the container is made, its start says so
    pm run --rm --workdir /i/do/not/exist "$IMG" pwd > /dev/null 2>&1
    check "podman run of a workdir the image lacks is 126" 126 $?
    pm create --name wdnone --workdir /i/do/not/exist "$IMG" pwd > /dev/null 2>&1
    check "create with a workdir the image lacks" 0 $?
    check_match "its start says so" 'workdir "/i/do/not/exist" does not exist on container' "$(pm start wdnone 2>&1)"
    pm rm -t 0 -f wdnone > /dev/null 2>&1
    # --pod-id-file
    pm pod create --name pidpod > /dev/null 2>&1
    pm pod inspect pidpod --format '{{.ID}}' > "$WORKDIR/pod.id" 2>/dev/null
    pm run -d --pod-id-file "$WORKDIR/pod.id" --name pidc "$IMG" sleep 100 > /dev/null 2>&1
    check "run --pod-id-file (podman)" "$(cat "$WORKDIR/pod.id")" "$(pm inspect pidc --format '{{.Pod}}' 2>&1)"
    "$CLI" run -d --pod-id-file "$WORKDIR/pod.id" --name pidc2 "$IMG" sleep 100 > /dev/null 2>&1
    check "run --pod-id-file (velarx)" "$(cat "$WORKDIR/pod.id")" "$(pm inspect pidc2 --format '{{.Pod}}' 2>&1)"
    check "--pod and --pod-id-file" "Error: cannot specify both --pod and --pod-id-file" "$("$CLI" run --pod pidpod --pod-id-file "$WORKDIR/pod.id" "$IMG" true 2>&1)"
    check_match "a pod ID file that is not there" "^Error: reading pod ID file: " "$("$CLI" run --pod-id-file "$WORKDIR/nonexistent" "$IMG" true 2>&1)"
    pm pod rm -t 0 -f pidpod > /dev/null 2>&1
    # --volumes-from, through the CLI and podman's route
    pm volume create vfvol > /dev/null 2>&1
    pm run -d --name vfsrc -v vfvol:/vfv "$IMG" sleep 100 > /dev/null 2>&1
    check "run --volumes-from (podman)" "kept" "$(pm run --rm --volumes-from vfsrc "$IMG" sh -c 'echo kept > /vfv/f; cat /vfv/f' 2>&1)"
    check "run --volumes-from (velarx)" "kept" "$("$CLI" run --rm --volumes-from vfsrc "$IMG" cat /vfv/f 2>&1)"
    check "run --volumes-from :ro" "Read-only file system" "$(pm run --rm --volumes-from vfsrc:ro "$IMG" sh -c 'touch /vfv/x 2>&1' | sed 's/.*: //')"
    check "run --volumes-from of nothing" 'Error: looking up container "nosuch" for volumes-from: no container with name or ID "nosuch" found: no such container' "$("$CLI" run --rm --volumes-from nosuch "$IMG" true 2>&1)"
    check "run --volumes-from with an option podman refuses" 'Error: invalid option "Z" specified - volumes from another container can only use z,ro,rw options' "$("$CLI" run --rm --volumes-from vfsrc:Z "$IMG" true 2>&1)"
    # the files the engine binds are the new container's own, not the source's
    check "run --volumes-from keeps its own /etc/hostname (velarx)" vfnew "$("$CLI" run --rm --hostname vfnew --volumes-from vfsrc "$IMG" cat /etc/hostname 2>&1)"
    check "run --volumes-from keeps its own /etc/hostname (podman)" vfnew "$(pm run --rm --hostname vfnew --volumes-from vfsrc "$IMG" cat /etc/hostname 2>&1)"
    # a mount of the command at the same destination replaces the source's
    mkdir -p "$WORKDIR/vfbind" && echo bound > "$WORKDIR/vfbind/f"
    check "run --volumes-from and -v of its destination (velarx)" bound "$("$CLI" run --rm --volumes-from vfsrc -v "$WORKDIR/vfbind:/vfv:z" "$IMG" cat /vfv/f 2>&1)"
    check "run --volumes-from and -v of its destination (podman)" bound "$(pm run --rm --volumes-from vfsrc -v "$WORKDIR/vfbind:/vfv:z" "$IMG" cat /vfv/f 2>&1)"
    # :rw replaces the options of a read-only source mount, as podman's
    pm run -d --name vfro -v "$WORKDIR/vfbind:/ro:ro,z" "$IMG" sleep 100 > /dev/null 2>&1
    check "run --volumes-from of a read-only mount" "Read-only file system" "$(pm run --rm --volumes-from vfro "$IMG" sh -c 'touch /ro/x 2>&1' | sed 's/.*: //')"
    check "run --volumes-from :rw of it" "written" "$(pm run --rm --volumes-from vfro:rw "$IMG" sh -c 'touch /ro/x && echo written' 2>&1)"
    pm rm -f -t 0 vfro > /dev/null 2>&1
    pm rm -f -t 0 vfsrc > /dev/null 2>&1
    pm volume rm vfvol > /dev/null 2>&1
    # ps --size, --ns
    pm run -d --name psx "$IMG" sleep 100 > /dev/null 2>&1
    check_match "ps --size" '^[0-9.]+[kMG]?B \(virtual [0-9.]+[kMG]?B\)$' "$("$CLI" ps --size --format '{{.Size}}' 2>&1)"
    check_match "ps --ns" '^[0-9]+$' "$("$CLI" ps --ns --format '{{.NET}}' 2>&1)"
    check "ps --size and --ns conflict" "Error: size and namespace options conflict" "$("$CLI" ps --size --ns 2>&1)"
    check "ps -q and --size conflict" "Error: quiet conflicts with size and namespace" "$("$CLI" ps -q --size 2>&1)"
    check "ps --watch and --latest conflict" "Error: the watch and latest flags cannot be used together" "$(timeout 5 "$CLI" ps -w 1 -l 2>&1)"
    # the namespaces come from the service (podman-remote asks namespace=true)
    check_match "podman ps --ns" '^[0-9]+ [0-9]+$' "$(pm ps --ns --filter name=psx --format '{{.NET}} {{.PIDNS}}' 2>&1)"
    out=$(api 'http://d/v1.41/containers/json?size=1&filters=%7B%22name%22%3A%5B%22psx%22%5D%7D' | jq -r '.[0] | .SizeRootFs > .SizeRw')
    check "Docker's SizeRootFs has the image" true "$out"
    pm rm -f -t 0 psx > /dev/null 2>&1
    # a directory as the root file system, as it is or under an overlay
    rfs=$WORKDIR/rootfs
    mkdir -p "$rfs"
    cid=$(pm create "$IMG" true)
    pm export "$cid" | tar -xf - -C "$rfs"
    pm rm "$cid" > /dev/null
    e2e_label_for_containers "$rfs"
    check "run --rootfs" hello "$(pm run --rm --rootfs "$rfs" echo hello)"
    pm run --rm --rootfs "$rfs:O" touch /not-kept > /dev/null
    check "--rootfs PATH:O leaves the directory as it was" false "$(test -e "$rfs/not-kept" && echo true || echo false)"
    pm run --rm --rootfs "$rfs" touch /kept > /dev/null
    check "--rootfs PATH is written" true "$(test -e "$rfs/kept" && echo true || echo false)"
    pm run --rm --rootfs "$rfs" > /dev/null 2>&1
    check "--rootfs without a command" 127 $?
    out=$(pm run --name rootfsc --rootfs "$rfs:O" echo again; pm inspect rootfsc --format '[{{.ImageDigest}}]')
    check "a --rootfs container has no image digest" "again
[]" "$out"
    pm rm rootfsc > /dev/null
    want=$(head -c 3000000 /dev/zero | md5sum)
    out=$(head -c 3000000 /dev/zero | pm run --rm -i "$IMG" cat | md5sum)
    check "run large stdin" "$want" "$out"
    pm run --rm "$IMG" does-not-exist > /dev/null 2>&1
    check "run missing executable" 127 $?
    out=$(pm run --rm -e FOO=bar -w /tmp --hostname hh "$IMG" \
              sh -c 'echo $FOO $(pwd) $(hostname)')
    check "run options" "bar /tmp hh" "$out"
    note_skip "run --user" "blocked: the OCI spec of the container service always runs as root"
    out=$(pm run --rm --mount "type=image,source=$IMG,destination=/img" "$IMG" sh -c 'grep -c ^NAME= /img/etc/os-release; touch /img/x 2>/dev/null || echo ro')
    check "run --mount type=image" "1 ro" "$(echo $out)"
    want=$(pm run --rm "$IMG" cat /etc/alpine-release)
    out=$(pm run --rm --mount "type=image,source=$IMG,destination=/img,subpath=/etc" "$IMG" cat /img/alpine-release)
    check "run --mount type=image subpath" "$want" "$out"
    # the inspect tells an image mount as podman does: its type, the image by
    # the ID the API gives it as the source, the sub path
    pm create --name imgmnt --mount "type=image,source=$IMG,destination=/img,subpath=/etc" "$IMG" true > /dev/null
    imgid=$(api "http://d/v5.0.0/libpod/images/$IMG/json" | jq -r .Id)
    out=$(api "http://d/v5.0.0/libpod/containers/imgmnt/json" | jq -r '.Mounts[] | select(.Destination == "/img") | "\(.Type) \(.Source) \(.SubPath) \(.RW)"')
    check "an image mount in the inspect" "image $imgid /etc false" "$out"
    pm rm imgmnt > /dev/null
    # the mounts of the inspect are those the container was asked for (not the
    # files the engine adds: resolv.conf, hosts, hostname, .containerenv), with their propagation
    mkdir -p "$WORKDIR/mntp"
    pm create --name mntp -v "$WORKDIR/mntp:/m1:rshared" -v "$WORKDIR/mntp:/m2:ro,rslave" -v "$WORKDIR/mntp:/m3" "$IMG" true > /dev/null
    out=$(api "http://d/v5.0.0/libpod/containers/mntp/json" | jq -r '[.Mounts[] | "\(.Destination) \(.Propagation) \(.RW)"] | sort | join(",")')
    check "the mounts of the inspect are those asked for, with their propagation" "/m1 rshared true,/m2 rslave false,/m3 rprivate true" "$out"
    pm rm mntp > /dev/null
    out=$(pm ps -a -q | wc -l)
    check "run --rm removes" 0 "$out"
    out=$(python3 -I "$E2E_DIR/pty_run.py" --input 'tty; exit 3\r' -- $PODMAN_REMOTE --url "unix://$SOCK" run -it --rm "$IMG" sh)
    rc=$?
    check_match "run -it terminal" "/dev/pts/" "$out"
    check "run -it exit code" 3 "$rc"
    out=$(python3 -I "$E2E_DIR/pty_run.py" --size 20,70 --input 'stty size; exit\r' -- $PODMAN_REMOTE --url "unix://$SOCK" run -it --rm "$IMG" sh | tr -d '\r')
    check_match "run -it terminal size" "(^|[^0-9])20 70($|[^0-9])" "$out"
}

@test "a large input and its output go together" {
    # (a counter, so that a stream gone wrong shows where: cmp names the
    # first byte that differs, or the end of the short output)
    seq -f '%010g' 1 999999 > "$WORKDIR/counter.in"
    pm run -d --name streamc "$IMG" sleep 1000 > /dev/null
    local kind i bad
    for kind in run exec; do
        bad=
        for i in 1 2 3 4 5 6; do
            if [ $kind = run ]; then
                cat "$WORKDIR/counter.in" | pm run --rm -i "$IMG" cat > "$WORKDIR/counter.out"
            else
                cat "$WORKDIR/counter.in" | pm exec -i streamc cat > "$WORKDIR/counter.out"
            fi
            if ! cmp -s "$WORKDIR/counter.in" "$WORKDIR/counter.out"; then
                bad="$kind $i: $(cmp "$WORKDIR/counter.in" "$WORKDIR/counter.out" 2>&1 | head -1 | sed "s|$WORKDIR/||g")"
                break
            fi
        done
        check "11 MB through $kind -i cat, six times" "" "$bad"
    done
    pm rm -f -t 0 streamc > /dev/null
}

@test "lifecycle" {
    id=$(pm run -d --name bg -l k=v "$IMG" sh -c 'echo started; trap "echo term; exit 7" TERM; while :; do sleep 0.1; done')
    check_match "run -d" "^[0-9a-f]{64}$" "$id"
    # (its first line is in its log: the logs below have it)
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$id/container.log" ' stdout F started$' 30 ||
        fail "the first line of the container in its log"
    out=$(pm ps --format '{{.Names}} {{.State}} {{.Labels}}')
    check_match "ps" "^bg running (map\\[k:v\\]|k=v)$" "$out"
    out=$(pm inspect bg --format '{{.Id}} {{.State.Running}} {{.Config.Tty}}')
    check "inspect" "$id true false" "$out"
    out=$(pm logs bg)
    check "logs" "started" "$out"
    pm container exists bg
    check "exists" 0 $?
    pm container exists nope
    check "exists missing" 1 $?
    out=$(pm top bg | grep -c sleep)
    check_match "top" "^[0-9]+$" "$out"

    out=$(pm exec bg sh -c 'echo in-exec; exit 3')
    check "exec" "in-exec" "$out"
    pm exec bg sh -c 'exit 3' > /dev/null
    check "exec exit code" 3 $?
    out=$(echo x | pm exec -i bg cat)
    check "exec stdin" "x" "$out"
    pm exec bg /does/not/exist > /dev/null 2>&1
    check "exec missing executable" 127 $?
    pm exec bg echo still-works > /dev/null
    check "and the container still works" 0 $?
    out=$(python3 -I "$E2E_DIR/pty_run.py" -- $PODMAN_REMOTE --url "unix://$SOCK" exec -it bg sh -c 'tty; exit 4')
    rc=$?
    check_match "exec -it terminal" "/dev/pts/" "$out"
    check "exec -it exit code" 4 "$rc"
    # the detach keys of an exec session: the client leaves, the
    # command goes on (podman-remote then fails to remove the session, which
    # runs, as with podman's server)
    python3 -I "$E2E_DIR/pty_run.py" --input '\x10\x11' -- $PODMAN_REMOTE --url "unix://$SOCK" exec -it bg sleep 4646 > "$WORKDIR/execdk" 2>&1
    check_match "exec -it detach" "as it is running" "$(cat "$WORKDIR/execdk")"
    # (no wait: the command of a session is executed before its start returns)
    check "the command goes on after the detach" 1 \
        "$(pm exec bg sh -c 'for p in /proc/[0-9]*; do cat $p/cmdline 2> /dev/null | tr "\0" " "; echo; done | grep -c "[4]646"')"
    pm exec bg pkill -f 'sleep 4646'

    if have_freezer; then
        pm pause bg > /dev/null
        out=$(pm inspect bg --format '{{.State.Status}}')
        check "pause" "paused" "$out"
        pm unpause bg > /dev/null
    else
        note_skip pause "no cgroup freezer we may write here"
    fi

    # /etc/hosts, /etc/hostname and /etc/resolv.conf are mounted, not in
    # the layer of the container
    out=$(pm exec bg sh -c "grep -cE ' /etc/(hosts|hostname|resolv.conf) ' /proc/self/mountinfo")
    check "etc files are mounted" 3 "$out"
    hn=$(pm inspect bg --format '{{.Config.Hostname}}')
    check_match "hosts has the host name" "$hn" "$(pm exec bg cat /etc/hosts)"
    out=$(pm export bg | tar -xOf - etc/hosts 2>/dev/null | grep -c "$hn")
    check "export leaves the hosts of the container out" 0 "$out"

    # top with stream: the processes every delay seconds
    out=$(api -m 3 "http://d/v5.0.0/libpod/containers/bg/top?stream=true&delay=1" | jq -s 'length >= 2')
    check "top stream" true "$out"
    code=$(api -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/containers/bg/top?delay=0")
    check "top with a delay of 0" 400 "$code"
    # Docker's top is ps -ef; libpod's podman's descriptors; one ps_args
    # is split as a shell does (a docker client sends one string)
    check "compat top: ps -ef" '["UID","PID","PPID","C","STIME","TTY","TIME","CMD"]' \
        "$(api "http://d/v1.41/containers/bg/top" | jq -c .Titles)"
    check "libpod top: podman's descriptors" '["USER","PID","PPID","%CPU","ELAPSED","TTY","TIME","COMMAND"]' \
        "$(api "http://d/v5.0.0/libpod/containers/bg/top" | jq -c .Titles)"
    check "compat top with one ps_args of two words" '["PID","COMMAND"]' \
        "$(api "http://d/v1.41/containers/bg/top?ps_args=-o%20pid,comm" | jq -c .Titles)"

    # the detach keys of an attach: the client goes, the container stays
    pm run -d -i --name dtc "$IMG" cat > /dev/null
    out=$(python3 -I - "$SOCK" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b"POST /v1.41/containers/dtc/attach?stream=1&stdin=1&stdout=1&detachKeys=ctrl-a HTTP/1.1\r\n"
          b"Host: d\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
data = b""
while b"\r\n\r\n" not in data:
    data += s.recv(4096)
s.sendall(b"hello\n")
s.settimeout(5)
got = data.split(b"\r\n\r\n", 1)[1]
while b"hello" not in got:
    got += s.recv(4096)
s.sendall(b"\x01")
try:
    while s.recv(4096):
        pass
    print("closed")
except socket.timeout:
    print("still open")
PY
)
    check "attach detach keys" "closed" "$out"
    check "the container stays after a detach" running "$(pm inspect dtc --format '{{.State.Status}}')"
    pm rm -f -t 0 dtc > /dev/null

    # podman's exec kill: a signal for a running exec session
    eid=$(api -X POST -H 'Content-Type: application/json' -d '{"Cmd":["sleep","100"]}' \
          "http://d/v5.0.0/libpod/containers/bg/exec" | jq -r .Id)
    api -X POST -H 'Content-Type: application/json' -d '{"Detach":true}' "http://d/v5.0.0/libpod/exec/$eid/start" > /dev/null
    # (a poll: the state of an exec session is only read from the API, which has no event for it)
    for i in $(seq 50); do
        test "$(api "http://d/v5.0.0/libpod/exec/$eid/json" | jq -r .Running)" = true && break
        sleep 0.1
    done
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/exec/$eid/kill?signal=TERM")
    check "exec kill" 200 "$code"
    # (a poll: as above)
    for i in $(seq 50); do
        test "$(api "http://d/v5.0.0/libpod/exec/$eid/json" | jq -r .Running)" = false && break
        sleep 0.1
    done
    check "the exec session ends by the signal" 143 "$(api "http://d/v5.0.0/libpod/exec/$eid/json" | jq -r .ExitCode)"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/exec/$eid/kill?signal=TERM")
    check "exec kill of an ended session" 409 "$code"

    # podman's mount: the merged root of the running container
    mnt=$(api -X POST "http://d/v5.0.0/libpod/containers/bg/mount" | jq -r .)
    pm exec bg sh -c 'echo inside > /mounted' > /dev/null
    check "mount" "inside" "$(cat "$mnt/mounted" 2>&1)"
    out=$(api "http://d/v5.0.0/libpod/containers/showmounted" | jq -r 'keys | length')
    check "showmounted" 1 "$out"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/bg/unmount")
    check "unmount" 204 "$code"
    test -e "$mnt"
    check "unmount removes the mount point" 1 $?

    pm stop -t 5 bg > /dev/null
    check "stop" 0 $?
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/bg/mount")
    check "mount of a stopped container" 501 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/exec/$eid/resize?h=10&w=10")
    check "exec resize when the container stopped" 409 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/exec/$eid/resize?h=10&w=10&running=true")
    check "exec resize with running=true" 201 "$code"
    out=$(pm wait bg)
    check "wait" 7 "$out"
    out=$(pm logs bg | tr '\n' ' ')
    check "logs after stop" "started term " "$out"
    # the rotated files of the log, compressed or not, are in the logs
    pm run --name rotc --log-opt max-size=2k --log-opt max-file=4 --log-opt compress=true "$IMG" \
        sh -c 'i=1; while test $i -le 600; do echo $i; i=$((i+1)); test $((i % 100)) = 0 && sleep 0.1; done' > /dev/null
    out=$(pm logs rotc)
    first=$(echo "$out" | head -1)
    check "logs of rotated, compressed files" "$(seq "$first" 600 | md5sum)" "$(echo "$out" | md5sum)"
    test "$first" -gt 1 -a "$first" -lt 520
    check "logs reach into the rotated files ($first)" 0 $?
    check "logs --tail of rotated files" "$(seq 521 600 | md5sum)" "$(pm logs --tail 80 rotc | md5sum)"
    pm rm rotc > /dev/null
    pm stop bg > /dev/null
    check "stop of a stopped container" 0 $?

    pm rm bg > /dev/null
    check "rm" 0 $?
    pm rm bg > /dev/null 2>&1
    check "rm missing" 1 $?

    pm create --name c1 "$IMG" sh -c 'echo created; exit 3' > /dev/null
    out=$(pm start -a c1)
    rc=$?
    check "start -a" "created" "$out"
    check "start -a exit code" 3 "$rc"

    # init: created in the runtime, started later; a second init is refused
    # stats with all: a container that does not run too, with zeros
    pm create --name statsc "$IMG" true > /dev/null
    out=$(api "http://d/v5.0.0/libpod/containers/stats?all=true&stream=false" | jq -r '[.Stats[] | select(.Name == "statsc") | .CPUNano] | join(",")')
    check "stats with all" "0" "$out"
    out=$(api "http://d/v5.0.0/libpod/containers/stats?stream=false" | jq -r '[.Stats[] | select(.Name == "statsc")] | length')
    check "stats without all" "0" "$out"
    pm rm statsc > /dev/null

    # rm with depend: the containers that require it go first
    pm create --name dep1 "$IMG" true > /dev/null
    pm create --name dep2 --requires dep1 "$IMG" true > /dev/null
    out=$(api -X DELETE "http://d/v5.0.0/libpod/containers/dep1?depend=true" | jq -r length)
    check "rm with depend" 2 "$out"
    pm container exists dep2
    check "rm with depend removes the dependent" 1 $?
    pm create --name lnk "$IMG" true > /dev/null
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v1.41/containers/lnk?link=true")
    check "compat rm with link" 400 "$code"
    pm rm lnk > /dev/null

    pm create --name ini "$IMG" sh -c 'echo inited; exit 5' > /dev/null
    pm init ini > /dev/null
    check "init" 0 $?
    out=$(pm inspect ini --format '{{.State.Status}}')
    check "init state" "initialized" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/ini/init")
    check "init of an initialized container" "304" "$out"
    out=$(pm start -a ini)
    rc=$?
    check "start of an initialized container" "inited" "$out"
    check "its exit code" 5 "$rc"
    pm init ini > /dev/null
    pm rm ini > /dev/null
    check "rm of an initialized container" 0 $?
    pm container exists ini
    check "and it is gone" 1 $?

    pm rename c1 c2
    out=$(pm ps -a --format '{{.Names}}')
    check "rename" "c2" "$out"
    pm run -d --name c2 "$IMG" true > /dev/null 2>&1
    check "name in use" 125 $?
    pm rm -t 0 -f c2 > /dev/null
}

# The restart policy, applied by the monitor of a container the API started.
@test "restart policy" {
    id=$(pm run -d --name rpol --restart always "$IMG" sh -c 'echo run; sleep 0.5; exit 2')
    # (a line for each run: the first and two restarts)
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$id/container.log" ' stdout F run$' 30 3 ||
        fail "rpol was not restarted twice within 30 s"
    n=$(pm inspect rpol --format '{{.RestartCount}}')
    check_match "restarted by its policy" "^[2-9]|^[1-9][0-9]" "$n"
    e2e_wait_condition rpol running 30 || fail "rpol running again within 30 s"
    check "and running again" running "$(pm inspect rpol --format '{{.State.Status}}')"
    pm stop -t 1 rpol > /dev/null
    n=$(pm inspect rpol --format '{{.RestartCount}}')
    # (a window in which a restart of the policy would have come: no event
    # says that one does not come)
    sleep 1.5
    check "stop ends the restarts" "$n exited" "$(pm inspect rpol --format '{{.RestartCount}} {{.State.Status}}')"
    pm rm -t 0 -f rpol > /dev/null
    # A start while the policy restarts it is the start of a running
    # container (a second monitor found it in the runtime); the code of a
    # short run --rm is the command's (the wait came after the removal)
    pm run -d --name rpol2 --restart always "$IMG" true > /dev/null
    bad=0
    for i in $(seq 20); do
        pm start rpol2 > /dev/null 2>&1 || bad=$((bad + 1))
    done
    check "start while its policy restarts it never fails" 0 "$bad"
    pm rm -f -t 0 rpol2 > /dev/null
    bad=0
    for i in $(seq 10); do
        pm run --rm "$IMG" sh -c 'exit 3' > /dev/null 2>&1
        test $? = 3 || bad=$((bad + 1))
    done
    check "the code of a short run --rm, each time" 0 "$bad"
}

# attach and resize for a container the API did not start: its monitor.
@test "attach to containers of the CLI" {
    [ -x "$CLI" ] || skip "no velarx CLI at $CLI"
    timeout 60 "$CLI" --socket "$ESOCK" container run -d -i --name cliatt "$IMG" \
        sh -c 'while read l; do echo "got $l"; done; echo bye' > /dev/null
    # (the input comes after a second: no event says that an attach is armed)
    out=$( (sleep 1; echo hello) | timeout 20 $PODMAN_REMOTE --url "unix://$SOCK" attach cliatt 2>&1)
    check_match "attach to a CLI container with stdin" "got hello" "$out"
    check_match "and its end" "bye" "$out"
    timeout 60 "$CLI" --socket "$ESOCK" container run -d -t --name clitty "$IMG" \
        sh -c 'sleep 1.5; stty size' > /dev/null
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/clitty/resize?h=33&w=77")
    check "resize a CLI container" 200 "$code"
    pm wait clitty > /dev/null
    check_match "the terminal has the new size" "33 77" "$(pm logs clitty)"
    # and one it started
    pm run -d -i --name apiatt "$IMG" sh -c 'while read l; do echo "got $l"; done; echo bye' > /dev/null
    # (the input comes after a second: no event says that an attach is armed)
    out=$( (sleep 1; echo there) | timeout 20 $PODMAN_REMOTE --url "unix://$SOCK" attach apiatt 2>&1)
    check_match "attach to an API container with stdin" "got there" "$out"
    pm rm -t 0 -f cliatt clitty apiatt > /dev/null
    # a start the runtime fails, in podman's words: quoted ID, not with -a
    id=$(pm create "$IMG" /i/do/not/exist)
    check_match "start of a container its runtime fails" "^Error: unable to start container \"$id\": crun: " "$("$CLI" --socket "$ESOCK" start "$id" 2>&1)"
    check_match "and start -a" "^Error: unable to start container $id: crun: " "$("$CLI" --socket "$ESOCK" start -a "$id" 2>&1)"
    pm rm -t 0 -f "$id" > /dev/null
}

@test "events" {
    pm events --format '{{.Type}} {{.Status}} {{.Name}} {{.ContainerExitCode}}' > "$WORKDIR/events" 2>&1 3>&- &
    events_pid=$!
    # (the stream is there once it shows an event made after it)
    pm create --name evmark "$IMG" true > /dev/null
    e2e_wait_line "$WORKDIR/events" '^container create evmark ' 30 || fail "the events stream starts"
    pm rm evmark > /dev/null
    pm run --rm --name evc "$IMG" sh -c 'exit 3' > /dev/null 2>&1
    e2e_wait_line "$WORKDIR/events" '^container remove evc 3$' 30 || fail "the remove event of evc"
    kill $events_pid 2> /dev/null
    wait $events_pid 2> /dev/null
    out=$(grep evc "$WORKDIR/events" | tr '\n' ',')
    # the remove event has the last exit code, as podman's
    check "events stream" "container create evc 0,container init evc 0,container start evc 0,container died evc 3,container remove evc 3," "$out"
    out=$(pm events --stream=false --since 1m --filter event=died --filter container=evc --format '{{.Name}}')
    check "events history with filters" "evc" "$out"
    # every --rm run has its died event, once, before its removal
    pm events --format '{{.Status}} {{.Name}}' > "$WORKDIR/events.rm" 2>&1 3>&- &
    events_pid=$!
    pm create --name evmark "$IMG" true > /dev/null
    e2e_wait_line "$WORKDIR/events.rm" '^create evmark$' 30 || fail "the events stream starts"
    pm rm evmark > /dev/null
    for i in $(seq 10); do
        pm run --rm --name "evr$i" "$IMG" sh -c 'exit 3' > /dev/null 2>&1
    done
    e2e_wait_line "$WORKDIR/events.rm" '^remove evr10$' 30 || fail "the remove event of evr10"
    kill $events_pid 2> /dev/null
    wait $events_pid 2> /dev/null
    bad=
    for i in $(seq 10); do
        seq_of=$(grep -E "^(died|remove) evr$i\$" "$WORKDIR/events.rm" | cut -d' ' -f1 | tr '\n' ,)
        test "$seq_of" = "died,remove," || bad="$bad evr$i:$seq_of"
    done
    check "--rm runs: one died event each, then the removal" "" "$bad"
    out=$(api "http://d/v1.41/events?since=0&until=$(($(date +%s) + 1))&filters=%7B%22event%22%3A%5B%22die%22%5D%7D" |
              grep -c '"Action":"die"')
    check_match "events compat" "^[1-9]" "$out"
    # --timeout: the died event and inspect say why
    pm run --name evt --timeout 1 "$IMG" sleep 100 > /dev/null 2>&1
    # (a container killed at its time limit has no exit code: podman's run ends with 255)
    check "run --timeout" 255 $?
    out=$(api "http://d/v4.0.0/libpod/events?stream=false&since=1m&filters=%7B%22container%22%3A%5B%22evt%22%5D%2C%22event%22%3A%5B%22died%22%5D%7D")
    check_match "the died event of a timeout" '"timedOut":"true"' "$out"
    out=$(pm inspect evt --format '{{.State.Error}}')
    check_match "inspect says the time limit ended it" "time limit" "$out"
    pm rm -t 0 -f evt > /dev/null
    # a run that a rm -f kills ends with 137, whatever the record says yet
    # (start -a is the attach, start and wait of a podman-remote run)
    bad=
    for i in $(seq 10); do
        pm create --name rmf$i "$IMG" sleep 100 > /dev/null
        pm start -a rmf$i > /dev/null 2>&1 3>&- &
        run_pid=$!
        pm wait --condition=running rmf$i > /dev/null
        pm rm -t 0 -f rmf$i > /dev/null 2>&1
        wait $run_pid
        rc=$?
        test $rc = 137 || bad="$bad $rc"
    done
    check "a run killed by rm -f exits 137" "" "$bad"
    # the same for a container whose record has the code of its previous run
    pm create --name rerun "$IMG" sh -c 'if test -e /ran; then rm /ran; exec sleep 100; fi; touch /ran' > /dev/null
    bad=
    for i in $(seq 10); do
        pm start -a rerun > /dev/null 2>&1
        pm start -a rerun > /dev/null 2>&1 3>&- &
        run_pid=$!
        pm wait --condition=running rerun > /dev/null
        pm kill rerun > /dev/null 2>&1
        wait $run_pid
        rc=$?
        test $rc = 137 || bad="$bad $rc"
    done
    check "a second run killed exits 137, not the code of the first" "" "$bad"
    pm rm -t 0 -f rerun > /dev/null
}

# The actions of the velarx CLI (the native API) are events too.
@test "events of the CLI" {
    [ -x "$CLI" ] || skip "no velarx CLI at $CLI"
    sc () { timeout 60 "$CLI" --socket "$ESOCK" "$@"; }
    since=$(date +%s)
    sc container create --name cev "$IMG" sleep 1000 > /dev/null
    sc container start cev > /dev/null
    sc container kill -s USR1 cev > /dev/null
    sc container stop -t 1 cev > /dev/null
    sc container rm cev > /dev/null
    sc image tag "$IMG" localhost/cevimg:1 > /dev/null
    sc image rm localhost/cevimg:1 > /dev/null
    sc volume create cevvol > /dev/null
    sc volume remove cevvol > /dev/null
    sc network create cevnet > /dev/null
    sc network rm cevnet > /dev/null
    sc pod create --infra-image "$IMG" --infra-command "sleep 1000" cevpod > /dev/null
    sc pod rm -t 0 -f cevpod > /dev/null
    # (the events are written meanwhile: the stream shows the last one)
    timeout 30 $PODMAN_REMOTE --url "unix://$SOCK" events --since "$since" --format '{{.Type}} {{.Status}} {{.Name}}' \
        > "$WORKDIR/cev.out" 2>&1 3>&- &
    cevp=$!
    e2e_wait_line "$WORKDIR/cev.out" '^pod remove cevpod$' 30 || fail "the remove event of cevpod"
    kill "$cevp" 2> /dev/null
    wait "$cevp" 2> /dev/null
    out=$(pm events --stream=false --since "$since" --format '{{.Type}} {{.Status}} {{.Name}}' |
        grep -E 'cev(img|vol|net|pod)?( |:|$)' | tr '\n' ',')
    for want in "container create cev" "container init cev" "container start cev" "container kill cev" \
        "container died cev" "container cleanup cev" "container remove cev" "image tag" "image untag" "volume create cevvol" \
        "volume remove cevvol" "network create cevnet" "network remove cevnet" "pod create cevpod" \
        "pod remove cevpod"; do
        check_match "the CLI's event: $want" "$want" "$out"
    done
    # once each
    check "the start of a CLI container is one event" 1 "$(echo "$out" | tr ',' '\n' | grep -c '^container start cev$')"
}

# The address of the engine from VELARX_HOST (podman's and docker's variables
# name the REST API's socket, which the command line does not use), and the
# trace file.
@test "engine address variable and trace file" {
    [ -x "$CLI" ] || skip "no velarx CLI at $CLI"
    env -u VELARX_SOCKET VELARX_HOST="unix://$ESOCK" timeout 30 "$CLI" container list > /dev/null 2>&1
    check "VELARX_HOST names the engine" 0 $?
    # it is the variable that is taken (the configuration names the socket too)
    if env -u VELARX_SOCKET VELARX_HOST="unix://$WORKDIR/nosuch.sock" timeout 30 "$CLI" container list > /dev/null 2>&1; then
        fail "an engine that is not there is not reached"
    else
        ok "an engine that is not there is not reached"
    fi
    # the REST API's variables are not the engine's
    for var in CONTAINER_HOST DOCKER_HOST; do
        env -u VELARX_SOCKET $var="unix://$SOCK" timeout 30 "$CLI" container list > /dev/null 2>&1
        check "$var is not an address of the engine" 0 $?
    done
    out=$(env -u VELARX_SOCKET VELARX_HOST=tcp://127.0.0.1:1 timeout 30 "$CLI" container list 2>&1)
    check "a tcp:// address is refused" 125 $?
    check_match "and says why" "only unix://" "$out"
    : > "$WORKDIR/trace"
    VELARX_TRACE_FILE="$WORKDIR/trace" timeout 30 "$CLI" --socket "$ESOCK" container list > /dev/null
    check_match "the client writes trace points" "^[0-9]+ [0-9]+ client start$" "$(head -1 "$WORKDIR/trace")"
    check_match "and its requests" "^[0-9]+ [0-9]+ client request ContainerList$" "$(sed -n 2p "$WORKDIR/trace")"
}

@test "healthcheck, wait, export, stats, update, prune" {
    pm run -d --name hcok --health-cmd true "$IMG" sleep 100 > /dev/null
    pm healthcheck run hcok > /dev/null
    check "healthcheck run" 0 $?
    pm run -d --name nohc "$IMG" sleep 100 > /dev/null
    pm healthcheck run nohc > /dev/null 2>&1
    check "healthcheck without a healthcheck" 125 $?
    out=$(pm inspect hcok --format '{{.Config.Healthcheck.Test}}')
    check "inspect healthcheck" "[CMD-SHELL true]" "$out"
    out=$(pm wait --condition healthy hcok)
    check "wait for healthy" "-1" "$out"
    if have_freezer; then
        pm pause nohc > /dev/null
        out=$(pm wait --condition paused --condition exited nohc)
        check "wait for paused" "-1" "$out"
        pm unpause nohc > /dev/null
    else
        note_skip "wait for paused" "no cgroup freezer we may write here"
    fi
    # (podman 5.8.9's service answers 0 for a condition it cannot read, and
    # podman-remote exits 0 with it)
    pm wait --condition bogus nohc > /dev/null 2>&1
    check "wait for an unknown condition" 0 $?
    out=$(pm export hcok | tar -tf - | grep -c '^bin/sh$')
    check "export" 1 "$out"
    out=$(pm export hcok | tar -tf - | grep -c '^proc/.')
    check "export skips the mounts" 0 "$out"
    out=$(pm stats --no-stream --format '{{.Name}}' hcok)
    check "stats" "hcok" "$out"
    pm update --memory 128m --pids-limit 70 hcok > /dev/null
    check "update" 0 $?
    out=$(pm inspect hcok --format '{{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}')
    check "update applied" "134217728 70" "$out"
    pm update --cpu-shares 256 --memory-reservation 16m hcok > /dev/null
    check "update CPU shares and memory reservation" "256 16777216" \
          "$(pm inspect hcok --format '{{.HostConfig.CpuShares}} {{.HostConfig.MemoryReservation}}')"
    # the runtime refuses a cpuset the host does not have: a client error, and the
    # limits stay what they were
    pm update --cpuset-cpus 9999 hcok > /dev/null 2>&1
    check "update a cpuset the runtime refuses fails" 125 $?
    check "and the limits stay" "134217728 70" \
          "$(pm inspect hcok --format '{{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}')"
    # podman's: the health check, the restart policy, the ulimits
    pm update --health-cmd 'echo upd' --restart always hcok > /dev/null
    check "update the health check and the restart policy" "[CMD-SHELL echo upd] always" \
        "$(pm inspect hcok --format '{{.Config.Healthcheck.Test}} {{.HostConfig.RestartPolicy.Name}}')"
    # (what the run prints is the status after it, which the update reset to
    # starting: the check that ran is in the log)
    pm healthcheck run hcok > /dev/null 2>&1
    check "and the monitor runs the new check" 0 $?
    check_match "the result in the log is of the new command" "upd" \
        "$(pm inspect hcok --format '{{range .State.Health.Log}}{{.Output}}{{end}}')"
    pm update --health-startup-cmd true hcok > /dev/null
    check "update the startup check" "[CMD-SHELL true]" \
        "$(pm inspect hcok --format '{{.Config.StartupHealthCheck.Test}}')"
    pm update --no-healthcheck hcok > /dev/null
    check "update --no-healthcheck" "[NONE]" "$(pm inspect hcok --format '{{.Config.Healthcheck.Test}}')"
    check_match "a health time without a check" "healthcheck command is not set" \
        "$(pm update --health-interval 5s nohc 2>&1)"
    check_match "a device limit of what is no block device" "/dev/zero: not a block device" \
        "$(pm update --device-write-iops /dev/zero:10 hcok 2>&1)"
    pm update --ulimit nofile=1024:1024 hcok > /dev/null
    check "update --ulimit" 0 $?
    pm rm -t 0 -f hcok nohc > /dev/null
    pm create --name pruned "$IMG" true > /dev/null
    out=$(pm container prune -f | wc -l)
    check "container prune" 1 "$out"
}

@test "ps filters" {
    pm create --name flt1 -l tier=web -v fltvol:/v "$IMG" true > /dev/null
    pm run --name flt2 -l tier=db "$IMG" sh -c 'exit 3' > /dev/null 2>&1
    pm run -d --name flt3 --health-cmd true "$IMG" sleep 100 > /dev/null
    pm healthcheck run flt3 > /dev/null
    q='{{.Names}}'
    check "ps exited filter" "flt2" "$(pm ps -a --filter exited=3 --format "$q")"
    check "ps health filter" "flt3" "$(pm ps -a --filter health=healthy --format "$q")"
    check "ps volume filter" "flt1" "$(pm ps -a --filter volume=fltvol --format "$q")"
    check "ps since filter" "flt3 flt2" "$(pm ps -a --filter since=flt1 --format "$q" | sort -r | tr '\n' ' ' | sed 's/ $//')"
    check "ps before filter" "flt1" "$(pm ps -a --filter before=flt2 --format "$q" | grep flt)"
    out=$(api 'http://d/v1.41/containers/json?all=1&limit=1' | jq -r '.[0].Names[0]')
    check "list newest first with a limit" "/flt3" "$out"
    out=$(api 'http://d/v1.41/containers/json?filters=%7B%22name%22%3A%5B%22flt3%22%5D%7D' | jq -r '.[0].Status')
    check_match "docker status with the health" "^Up .* \(healthy\)$" "$out"
    pm rm -t 0 -f flt1 flt2 flt3 > /dev/null
    pm volume rm fltvol > /dev/null
}

# A forced removal stops the container with its stop signal and waits its
# stop timeout before the kill, as podman's: libpod's `timeout` overrides the
# container's, 0 kills at once; Docker's removal has no time to give.
@test "rm -f waits the stop timeout of the container, libpod's timeout overrides it" {
    stubborn='trap "" TERM; echo up; while :; do sleep 0.1; done'
    pm run -d --name rmt1 --stop-timeout 2 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/containers/rmt1?force=true")
    elapsed=$(( $(date +%s%3N) - start ))
    check "libpod rm force without timeout" 200 "$code"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 9000
    check "it took the stop timeout of the container (${elapsed}ms)" 0 $?

    pm run -d --name rmt2 --stop-timeout 60 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/containers/rmt2?force=true&timeout=0")
    elapsed=$(( $(date +%s%3N) - start ))
    check "libpod rm force with timeout 0" 200 "$code"
    test "$elapsed" -lt 9000
    check "it killed at once (${elapsed}ms)" 0 $?

    pm run -d --name rmt3 --stop-timeout 60 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/containers/rmt3?force=true&timeout=2")
    elapsed=$(( $(date +%s%3N) - start ))
    check "libpod rm force with timeout 2" 200 "$code"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 20000
    check "it took the time given (${elapsed}ms)" 0 $?

    pm run -d --name rmt4 --stop-timeout 2 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v1.41/containers/rmt4?force=1")
    elapsed=$(( $(date +%s%3N) - start ))
    check "compat rm force" 204 "$code"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 9000
    check "it took the stop timeout of the container too (${elapsed}ms)" 0 $?

    pm run -d --name rmt5 --stop-timeout 2 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    pm rm -f rmt5 > /dev/null 2>&1
    check "podman rm -f" 0 $?
    elapsed=$(( $(date +%s%3N) - start ))
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 9000
    check "it took the stop timeout of the container as well (${elapsed}ms)" 0 $?

    pm pod create --name rmtpod > /dev/null
    pm run -d --name rmt6 --pod rmtpod --stop-timeout 2 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/pods/rmtpod?force=true")
    elapsed=$(( $(date +%s%3N) - start ))
    check "libpod pod rm force" 200 "$code"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 9000
    check "the pod took the stop timeout of its container (${elapsed}ms)" 0 $?
    pm pod create --name rmtpod > /dev/null
    pm run -d --name rmt7 --pod rmtpod --stop-timeout 60 "$IMG" sh -c "$stubborn" > /dev/null
    start=$(date +%s%3N)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/pods/rmtpod?force=true&timeout=0")
    elapsed=$(( $(date +%s%3N) - start ))
    check "libpod pod rm force with timeout 0" 200 "$code"
    test "$elapsed" -lt 9000
    check "the pod killed at once (${elapsed}ms)" 0 $?
}

# the network setup of a container that cannot be read is an error of its
# inspect, not a container without ports
@test "inspect: a network setup that cannot be read is an error" {
    skip_unless_image
    pm create --name brokenspec "$IMG" true > /dev/null
    id=$(pm inspect --format '{{.Id}}' brokenspec)
    db=$XDG_DATA_HOME/velarx/db.sqlite
    spec=$(sqlite3 "$db" ".timeout 5000" "SELECT spec FROM network_containers WHERE container_id = '$id'")
    test -n "$spec" || e2e_die "the container has no network setup row"
    sqlite3 "$db" ".timeout 5000" "UPDATE network_containers SET spec = '{not json' WHERE container_id = '$id'"
    code=$(api -o "$WORKDIR/brokenspec.inspect" -w '%{http_code}' "http://d/v5.0.0/libpod/containers/brokenspec/json")
    check "inspect is an error" 500 "$code"
    check_match "and it says why" "network setup of container $id cannot be read" "$(cat "$WORKDIR/brokenspec.inspect")"
    sqlite3 "$db" ".timeout 5000" "UPDATE network_containers SET spec = '$spec' WHERE container_id = '$id'"
    pm rm -f brokenspec > /dev/null
}

# Needs a journal that takes messages from this user, and journalctl.
@test "logs --follow of a journald container: every line once, up to the end of the container" {
    if ! test -S /run/systemd/journal/socket || ! command -v journalctl > /dev/null; then
        skip "no journal"
    fi
    pm run -d --name jfl --log-driver journald --network none "$IMG" \
        sh -c 'echo first; sleep 2; echo second; sleep 1; echo third' > /dev/null 2>&1
    out=$(pm logs -f jfl 2>&1)
    rc=$?
    if test -z "$out"; then
        pm rm -f -t 0 jfl > /dev/null 2>&1
        skip "the journal cannot be read by this user"
    fi
    check "every line once, then the end" "0 first
second
third" "$rc $out"
    check "the lines of an exited container" "first
second
third" "$(pm logs jfl 2>&1)"
    pm rm -f -t 0 jfl > /dev/null 2>&1
}
