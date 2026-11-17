# SPDX-License-Identifier: Apache-2.0
# End to end tests of the REST API: checkpoint and restore
# through the libpod API, podman --remote's container checkpoint and restore,
# in place and with an archive.  The restore needs root (CRIU) (see
# api_helpers.bash).

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}

# wait_count NAME REGEX: until the counter the container NAME runs printed a
# number that matches REGEX (a line of its log file).
wait_count () {
    local id
    id=$(pm inspect "$1" --format '{{.Id}}')
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$id/container.log" " stdout F $2\$" 30 ||
        fail "the counter of $1 printed no $2 within 30 s"
}

# The engine service (org.velarx.Engine) takes the archive of a checkpoint as a
# descriptor of the caller, a file it opened itself: the engine opens no path of
# a client.  varlinkctl passes it (--push-fd).
start_engine_service () {
    ENGINE_SOCK=$ESOCK
    [ -S "$ENGINE_SOCK" ] && return 0
    E2E_SPAWN_LOG=$WORKDIR/engine.log e2e_spawn_ready ENGINE_PID setsid \
        "$DAEMON" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink || {
        echo "the engine service did not start" >&2
        cat "$WORKDIR/engine.log" >&2
        return 1; }
    echo "$ENGINE_PID" > "$WORKDIR/engine.pid"
    return 0
}

# checkpoint_call JSON-NAME [JSON-COMPRESS [LEAVE-RUNNING]]: the call with the
# descriptor 3 of the caller
checkpoint_call () {
    varlinkctl call --push-fd=3 "unix:$ENGINE_SOCK" org.velarx.Engine.ContainerCheckpoint \
        "{\"name\": \"$1\", \"archive\": 0, \"flags\": {\"leave_running\": ${3:-true}, \"create_image\": null, \"tcp_established\": false, \"file_locks\": false, \"keep\": false, \"ignore_rootfs\": false, \"ignore_volumes\": false, \"print_stats\": false, \"pre_checkpoint\": false, \"with_previous\": false, \"compress\": ${2:-null}}}" 2>&1
}

# share_archive FILE: share an archive the way `checkpoint --share` does
# (`CheckpointShare` of the engine service: the archive in a pipe, in
# frames); the CLI shares only what it exported itself.  Prints the
# reference.
share_archive () {
    python3 -I - "$ENGINE_SOCK" "$1" <<'PY'
import json, os, socket, sys, threading
path, archive = sys.argv[1:3]
up_r, up_w = os.pipe()
s = socket.socket(socket.AF_UNIX)
s.connect(path)
call = {"method": "org.velarx.Engine.CheckpointShare", "parameters": {}}
socket.send_fds(s, [json.dumps(call).encode() + b"\0"], [up_r])
os.close(up_r)
def upload():
    # (frames: a length of 4 bytes, big endian, and the bytes; 0 ends)
    with os.fdopen(up_w, "wb") as w, open(archive, "rb") as f:
        while chunk := f.read(1 << 16):
            w.write(len(chunk).to_bytes(4, "big") + chunk)
        w.write(bytes(4))
t = threading.Thread(target=upload)
t.start()
buf = b""
while not buf.endswith(b"\0"):
    chunk = s.recv(65536)
    if not chunk:
        break
    buf += chunk
t.join()
reply = json.loads(buf.rstrip(b"\0"))
if "error" in reply:
    sys.exit(json.dumps(reply))
print(reply["parameters"]["reference"])
PY
}

RESTORE_FLAGS='{"tcp_established": false, "tcp_close": false, "file_locks": false, "keep": false, "name": null, "ignore_rootfs": false, "ignore_static_ip": false, "ignore_static_mac": false, "previous": null, "pod": null, "publish": [], "print_stats": false, "verify_image": []}'

# stage_call NAME: stage the archive of the descriptor 3 of the caller in the container
stage_call () {
    varlinkctl call --push-fd=3 "unix:$ENGINE_SOCK" org.velarx.Engine.ContainerRestore \
        "{\"name\": \"$1\", \"flags\": $RESTORE_FLAGS, \"archive\": 0, \"stage\": true}" 2>&1
}

teardown_file () {
    [ ! -f "$WORKDIR/engine.pid" ] || kill -INT "$(cat "$WORKDIR/engine.pid")" 2> /dev/null
    api_teardown_file
}

@test "checkpoint over the engine service: the descriptor of the archive is checked" {
    start_engine_service
    check "the engine service starts" 0 $?
    pm create --name apicpf "$IMG" true > /dev/null
    out=$(varlinkctl call "unix:$ENGINE_SOCK" org.velarx.Engine.ContainerCheckpoint \
        '{"name": "apicpf", "archive": 0, "flags": {"leave_running": true, "create_image": null, "tcp_established": false, "file_locks": false, "keep": false, "ignore_rootfs": false, "ignore_volumes": false, "print_stats": false, "pre_checkpoint": false, "with_previous": false, "compress": null}}' 2>&1)
    check_match "without a descriptor" "descriptor" "$out"
    out=$(checkpoint_call apicpf 3< /)
    check_match "a directory is refused" "regular file" "$out"
    echo keep > "$WORKDIR/taken.tar"
    out=$(checkpoint_call apicpf 3<> "$WORKDIR/taken.tar")
    check_match "a file with something in it is refused" "not empty" "$out"
    check "and it is not touched" keep "$(cat "$WORKDIR/taken.tar")"
    : > "$WORKDIR/empty.tar"
    out=$(checkpoint_call apicpf 3< "$WORKDIR/empty.tar")
    check_match "a file open for reading is refused" "for writing" "$out"
    out=$(checkpoint_call apicpf 3>> "$WORKDIR/empty.tar")
    check_match "a file open for appending is refused" "appending" "$out"
    out=$(checkpoint_call nothere 3> "$WORKDIR/n.tar")
    check_match "a container that is not there" "no such container|not found|No such" "$out"
    # a checkpoint that fails (the container does not run) writes nothing
    out=$(checkpoint_call apicpf 3> "$WORKDIR/fresh.tar")
    check "a checkpoint that fails is an error" 1 "$(echo "$out" | grep -qi 'error\|not running\|need root' && echo 1 || echo 0)"
    check "and leaves the file empty" 0 "$(stat -c %s "$WORKDIR/fresh.tar")"
    # staging a checkpoint takes a descriptor to read, as well
    out=$(varlinkctl call "unix:$ENGINE_SOCK" org.velarx.Engine.ContainerRestore \
        "{\"name\": \"apicpf\", \"flags\": $RESTORE_FLAGS, \"archive\": 0, \"stage\": true}" 2>&1)
    check_match "a restore without a descriptor" "descriptor" "$out"
    out=$(stage_call apicpf 3> >(cat > /dev/null))
    check_match "a restore from a pipe is refused" "regular file" "$out"
    out=$(stage_call apicpf 3> "$WORKDIR/staged.tar")
    check_match "a restore from a file open for writing only is refused" "for reading" "$out"
    : > "$WORKDIR/nothing.tar"
    out=$(stage_call nothere 3< "$WORKDIR/nothing.tar")
    check_match "a restore in a container that is not there" "no such container|not found|No such" "$out"
    out=$(stage_call apicpf 3< "$WORKDIR/nothing.tar")
    check_match "a restore needs root and a real archive" "need root|the archive" "$out"
    # the REST API has no path to write at
    api -o /dev/null -X POST "http://d/v5.0.0/libpod/containers/apicpf/checkpoint?exportFile=$WORKDIR/x.tar"
    test -e "$WORKDIR/x.tar"
    check "exportFile writes no file" 1 $?
    pm rm apicpf > /dev/null
}

@test "rootless: checkpoint answers" {
    skip_if_root
    out=$(api -X POST "http://d/v5.0.0/libpod/containers/nothere/checkpoint")
    check_match "rootless: checkpoint answers" "need root|no such|not found" "$out"
}

@test "checkpoint, restore, export and share" {
    skip_unless_root
    command -v criu > /dev/null || skip "no criu"
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    pm run -d --name apicp --network none "$IMG" sh -c "$count" > /dev/null
    wait_count apicp 3
    out=$(pm container checkpoint apicp 2>&1)
    check "podman checkpoint" "apicp" "$out"
    check "it is exited" exited "$(pm inspect apicp --format '{{.State.Status}}')"
    check "inspect says it is checkpointed" true "$(pm inspect apicp --format '{{.State.Checkpointed}}')"
    last=$(pm logs apicp | tail -1)
    out=$(pm container restore apicp 2>&1)
    check "podman restore" "apicp" "$out"
    check "it runs" running "$(pm inspect apicp --format '{{.State.Status}}')"
    check "inspect says it was restored" true "$(pm inspect apicp --format '{{.State.Restored}}')"
    wait_count apicp $((last + 2))
    next=$(pm logs apicp | tail -1)
    test "$next" -gt "$last"
    check "it goes on ($last, then $next)" 0 $?

    # the engine writes the archive in the file the caller passed (the CRI's way)
    start_engine_service
    rm -f "$WORKDIR/api-cpf.tar"
    out=$(checkpoint_call apicp '"gzip"' 3> "$WORKDIR/api-cpf.tar")
    check_match "the engine service answers the container" "apicp|[0-9a-f]{64}" "$out"
    gzip -dc "$WORKDIR/api-cpf.tar" 2> /dev/null | tar -t 2> /dev/null | grep -q '^checkpoint/inventory.img$'
    check "and the archive of the descriptor has the images" 0 $?
    check "the container runs on (leaveRunning)" running "$(pm inspect apicp --format '{{.State.Status}}')"
    pm container checkpoint --export "$WORKDIR/api-cp.tar.gz" apicp > /dev/null
    check "checkpoint --export writes the archive" 0 $?
    # (zstd, podman's default; gzip when the client asks)
    list=$( (zstd -dc "$WORKDIR/api-cp.tar.gz" 2> /dev/null || gzip -dc "$WORKDIR/api-cp.tar.gz") | tar -t 2> /dev/null)
    echo "$list" | grep -q '^checkpoint/inventory.img$'
    check "it has the images" 0 $?
    pm container restore --import "$WORKDIR/api-cp.tar.gz" --name apicp2 > /dev/null
    check "restore --import" running "$(pm inspect apicp2 --format '{{.State.Status}}')"
    wait_count apicp2 '[0-9]+'
    first=$(pm logs apicp2 | head -1)
    test -n "$first" && test "$first" -gt "$next"
    check "the imported one goes on ($first)" 0 $?

    out=$(pm container checkpoint --print-stats --leave-running apicp2 2>&1)
    check_match "--print-stats is answered by the route" '"pages_written": [1-9]' "$out"
    check_match "with the durations" '"runtime_checkpoint_duration": [1-9]' "$out"
    out=$(pm container checkpoint --print-stats --export "$WORKDIR/api-st.tar" apicp2 2>&1)
    check_match "--print-stats is refused with --export by name" "printStats is not supported" "$out"
    check "and the container runs on" running "$(pm inspect apicp2 --format '{{.State.Status}}')"
    # shared with the peers: the pieces of the archive and its
    # manifest by digest; another node restores it from what the peers give
    # (here a directory of content, as a peer would serve it)
    out=$("$CLI" --socket "$ESOCK" container checkpoint --export "$WORKDIR/api-cp2.tar" --share --leave-running apicp2 2>&1)
    ref=$(echo "$out" | sed -n 's/^Shared as //p')
    check_match "checkpoint --share prints the reference" '^sha256:[0-9a-f]{64}:[0-9]+:[0-9a-f]{64}$' "$ref"
    share_root=$(find "$WORKDIR" -type d -path '*/shared/content' | head -1)
    shares=$(dirname "$share_root")/shares
    manifest=$(echo "${ref%:*}" | cut -d: -f2)
    check "the record of the share is kept" 1 "$(find "$shares" -type f -name "sha256-$manifest" | wc -l)"
    check "the shared pieces are the daemon's alone" "700 600" \
        "$(stat -c %a "$(dirname "$share_root")") $(find "$share_root" -type f -printf '%m\n' | sort -u | tr '\n' ' ' | sed 's/ $//')"
    # (encrypted: no inventory of CRIU in clear)
    check "and encrypted" 0 "$(cat "$share_root"/* | grep -c -a 'inventory' || true)"
    # (the pieces are named sha256-HEX there; the directory source of
    # content takes the bare hex)
    for f in "$share_root"/*; do cp "$f" "$WORKDIR/peers/${f##*/sha256-}"; done
    # (the reference holds the key: on the standard input, not in argv)
    out=$(echo "$ref" | "$CLI" --socket "$ESOCK" container restore --import-from-peers - --name apicp3 2>&1)
    check "restore --import-from-peers" running "$(pm inspect apicp3 --format '{{.State.Status}}' 2>&1)"
    # (by the manifest alone: no key)
    "$CLI" --socket "$ESOCK" container checkpoint --unshare "${ref%:*}" > /dev/null 2>&1
    check "checkpoint --unshare removes the record" 0 "$(find "$shares" -type f | wc -l)"
    check "and its pieces are gone" 0 "$(find "$share_root" -type f | wc -l)"

    # an archive a peer crafted (shared by a daemon as this one would): its
    # manifest and pieces check out, the archive is refused by the import as
    # one from anywhere, and nothing is written out of its place
    python3 -I - "$WORKDIR/crafted.tar" <<'PY'
import io, sys, tarfile
with tarfile.open(sys.argv[1], mode="w") as t:
    data = b"pwned\n"
    i = tarfile.TarInfo("checkpoint/../../../../crafted-escape")
    i.size = len(data)
    t.addfile(i, io.BytesIO(data))
    link = tarfile.TarInfo("checkpoint/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc"
    t.addfile(link)
PY
    ref=$(share_archive "$WORKDIR/crafted.tar")
    check_match "the crafted archive is shared like any" '^sha256:[0-9a-f]{64}:[0-9]+:[0-9a-f]{64}$' "$ref"
    # (the pieces are named sha256-HEX there; the directory source of
    # content takes the bare hex)
    for f in "$share_root"/*; do cp "$f" "$WORKDIR/peers/${f##*/sha256-}"; done
    out=$("$CLI" --socket "$ESOCK" container restore --import-from-peers "$ref" --name apicrafted 2>&1)
    check "a crafted archive from a peer is refused" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "by the import, after the fetch checked out" "the archive: " "$out"
    check "nothing escaped" "" "$(find / -xdev -name crafted-escape 2> /dev/null | head -1)"
    check "no container was made" 404 "$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/containers/apicrafted/exists)"
    "$CLI" --socket "$ESOCK" container checkpoint --unshare "$ref" > /dev/null 2>&1
    pm rm -t 0 -f apicp apicp2 apicp3 > /dev/null
}

@test "a container is checkpointed while it is paused, and a checkpoint is staged in a new container" {
    skip_unless_root
    command -v criu > /dev/null || skip "no criu"
    start_engine_service
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    pm run -d --name apipause --network none "$IMG" sh -c "$count" > /dev/null
    wait_count apipause 3
    pm pause apipause > /dev/null
    check "it is paused" paused "$(pm inspect apipause --format '{{.State.Status}}')"
    out=$(checkpoint_call apipause null false 3> "$WORKDIR/paused-refused.tar")
    check_match "a paused container is not checkpointed to be stopped" "leave-running" "$out"
    check "and nothing is written" 0 "$(stat -c %s "$WORKDIR/paused-refused.tar")"
    out=$(checkpoint_call apipause '"gzip"' 3> "$WORKDIR/paused.tar")
    check_match "a paused container is checkpointed" "apipause|[0-9a-f]{64}" "$out"
    gzip -dc "$WORKDIR/paused.tar" 2> /dev/null | tar -t 2> /dev/null | grep -q '^checkpoint/inventory.img$'
    check "its archive has the images" 0 $?
    check "and it is still paused" paused "$(pm inspect apipause --format '{{.State.Status}}')"
    pm unpause apipause > /dev/null

    # a container that was never started restores the archive when it starts
    pm create --name apistaged --network none "$IMG" sh -c "$count" > /dev/null
    out=$(stage_call apistaged 3< "$WORKDIR/paused.tar")
    check "the archive is staged" 0 "$(echo "$out" | grep -c -i error)"
    check "the container is not started by it" created "$(pm inspect apistaged --format '{{.State.Status}}')"
    out=$(stage_call apipause 3< "$WORKDIR/paused.tar")
    check_match "a container that runs takes no checkpoint" "never started|already|created" "$out"
    pm start apistaged > /dev/null
    check "starting it restores the process" running "$(pm inspect apistaged --format '{{.State.Status}}')"
    wait_count apistaged '[0-9]+'
    first=$(pm logs apistaged | head -1)
    test -n "$first" && test "$first" -gt 3
    check "it goes on from the checkpoint, not from 0 ($first)" 0 $?
    check "it was restored" true "$(pm inspect apistaged --format '{{.State.Restored}}')"
    pm rm -t 0 -f apipause apistaged > /dev/null
}
