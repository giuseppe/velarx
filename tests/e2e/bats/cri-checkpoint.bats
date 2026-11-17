# SPDX-License-Identifier: Apache-2.0
# CheckpointPod and RestorePod of velarx-cri against an engine of the test: a
# pod of two containers is checkpointed at one instant, removed, and restored
# in a new sandbox, whose containers are created and restore their processes
# when the kubelet starts them.  As root only, as the CRI is tested (docs/CRI.md).
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/cri-checkpoint.bats
#
# Skipped without root, crictl, curl, python3, criu or velarx-cri.

load helpers

cc () { crictl --timeout 120s -r "unix://$CRISOCK" -i "unix://$CRISOCK" "$@" 2> "$WORKDIR/crictl.err"; }

# grpc ARGS: CheckpointPod or RestorePod (tests/e2e/cri_grpc.py)
grpc () { python3 -I "$E2E_DIR/cri_grpc.py" "$CRISOCK" "$@" 2> "$WORKDIR/grpc.err"; }

need_state () {
    printf -v "$1" %s "$(cat "$WORKDIR/$1" 2> /dev/null)"
    if [ -z "${!1}" ]; then
        echo "FAIL no $1 of the earlier tests (one failed or did not run)" >&2
        exit 1
    fi
}

# json FILE EXPR: a value of a JSON file (python expression of `d`)
json () { python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }

setup_file () {
    [ "$(id -u)" = 0 ] || skip "the CRI is tested as root"
    for c in crictl curl python3; do command -v $c > /dev/null || skip "$c is not installed"; done
    e2e_setup_file
    test -x "$BIN/velarx-cri" || skip "$BIN/velarx-cri is not built"
    command -v criu > /dev/null || skip "no criu"
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export CRISOCK=$WORKDIR/cri.sock
    mkdir -p "$WORKDIR/logs" "$XDG_CONFIG_HOME/velarx"
    chmod 700 "$XDG_RUNTIME_DIR" "$WORKDIR"
    # (and REGISTRY_INSECURE, the registries of tests/cri/run-all.sh)
    # shellcheck disable=SC2086
    printf '%s\n' "$E2E_REGISTRY" ${REGISTRY_INSECURE:-} | sort -u | while read -r r; do
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$r"
    done > "$XDG_CONFIG_HOME/velarx/registries.conf"
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf
    # the engine of the test (root does not read $XDG_CONFIG_HOME: told), and
    # the frontend on its socket and on the checkpoint directory of the test
    e2e_start_daemon
    export CKDIR=$WORKDIR/checkpoints
    "$BIN/velarx-cri" --socket "$CRISOCK" --engine-socket "$ESOCK" \
        --checkpoint-dir "$CKDIR" > "$WORKDIR/cri.log" 2>&1 3>&- &
    CRI_PID=$!
    echo "$CRI_PID" > "$WORKDIR/cri.pid"
    # (the socket, unless the process ends first)
    e2e_wait_path_of "$CRISOCK" "$CRI_PID" 60 && test -S "$CRISOCK" && return 0
    echo "velarx-cri does not start"
    tail "$WORKDIR/cri.log"
    exit 1
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    if test -n "${CRI_PID:-}"; then
        kill -INT "$CRI_PID" 2> /dev/null
        e2e_wait_exit "$CRI_PID"
        kill -KILL "$CRI_PID" 2> /dev/null
    fi
    e2e_remove_containers "$SH" "$ESOCK"
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do kill -INT "$p" 2> /dev/null; done
    e2e_detach_mounts "$WORKDIR"
    e2e_teardown_file
}

@test "a pod of two containers, one counting" {
    cc pull "$IMAGE" > /dev/null || e2e_die "cannot pull $IMAGE"
    cat > "$WORKDIR/pod.json" <<JSON
{"metadata": {"name": "web", "namespace": "default", "uid": "u1", "attempt": 0},
 "hostname": "webhost", "log_directory": "$WORKDIR/logs",
 "labels": {"app": "web"}, "annotations": {"note": "hi"}}
JSON
    cat > "$WORKDIR/main.json" <<JSON
{"metadata": {"name": "main"}, "image": {"image": "$IMAGE"}, "log_path": "main.log",
 "command": ["sh", "-c", "trap 'exit 0' TERM; i=0; while true; do i=\$((i+1)); echo \$i > /tmp/n; sleep 0.2; done"],
 "labels": {"l": "1"}, "annotations": {"a": "1"}}
JSON
    cat > "$WORKDIR/side.json" <<JSON
{"metadata": {"name": "side"}, "image": {"image": "$IMAGE"}, "log_path": "side.log",
 "command": ["sh", "-c", "trap 'exit 0' TERM; j=1000; while true; do j=\$((j+1)); echo \$j > /tmp/m; sleep 0.2; done"]}
JSON
    pod=$(cc runp "$WORKDIR/pod.json")
    check "runp" 0 $?
    c1=$(cc create "$pod" "$WORKDIR/main.json" "$WORKDIR/pod.json")
    check "create main" 0 $?
    c2=$(cc create "$pod" "$WORKDIR/side.json" "$WORKDIR/pod.json")
    check "create side" 0 $?
    cc start "$c1" > /dev/null
    check "start main" 0 $?
    cc start "$c2" > /dev/null
    check "start side" 0 $?
    echo "$pod" > "$WORKDIR/pod"
    echo "$c1" > "$WORKDIR/c1"
    echo "$c2" > "$WORKDIR/c2"
    # (the loop runs in the container: the exec returns once the counter is there)
    cc exec -s "$c1" timeout 60 sh -c 'until [ "$(cat /tmp/n 2> /dev/null || echo 0)" -ge 5 ]; do :; done'
    n=$(cc exec -s "$c1" cat /tmp/n 2> /dev/null)
    test "${n:-0}" -ge 5
    check "main counts" 0 $?
}

@test "CheckpointPod refuses what is not a running pod of the request" {
    need_state pod
    need_state c1
    need_state c2
    mkdir -p "$CKDIR/refusals"
    grpc checkpointp "$pod" "$CKDIR/refusals" > /dev/null
    check "no container" 1 $?
    check_match "is refused" "ERROR 3 " "$(cat "$WORKDIR/grpc.err")"
    grpc checkpointp "$pod" "$CKDIR/refusals" "$c1" "$c1" > /dev/null
    check_match "a container twice" "ERROR 3 .*more than once" "$(cat "$WORKDIR/grpc.err")"
    grpc checkpointp "$pod" "$CKDIR/refusals" nosuchcontainer > /dev/null
    check_match "a container that is not there" "ERROR 5 " "$(cat "$WORKDIR/grpc.err")"
    grpc checkpointp nosuchpod "$CKDIR/refusals" "$c1" > /dev/null
    check_match "a sandbox that is not there" "ERROR 5 " "$(cat "$WORKDIR/grpc.err")"
    grpc checkpointp "$pod" "$WORKDIR" "$c1" > /dev/null
    check_match "a directory that is not one of the checkpoint directory" "ERROR 3 .*checkpoint directory" "$(cat "$WORKDIR/grpc.err")"
    grpc checkpointp "$pod" "$CKDIR/nothere" "$c1" > /dev/null
    check_match "a directory that is not there" "ERROR 5 " "$(cat "$WORKDIR/grpc.err")"
    echo x > "$CKDIR/refusals/taken"
    grpc checkpointp "$pod" "$CKDIR/refusals" "$c1" > /dev/null
    check_match "a directory with something in it" "ERROR 3 .*not empty" "$(cat "$WORKDIR/grpc.err")"
    check "no container was paused: main goes on" 1 "$(a=$(cc exec -s "$c1" cat /tmp/n); for i in $(seq 100); do b=$(cc exec -s "$c1" cat /tmp/n); test "$b" != "$a" && break; done; test "$b" != "$a" && echo 1 || echo 0)"
}

@test "CheckpointPod: the pod is checkpointed at one instant and goes on" {
    need_state pod
    need_state c1
    need_state c2
    mkdir "$CKDIR/pod1"
    grpc checkpointp "$pod" "$CKDIR/pod1" "$c1" "$c2" > /dev/null
    check "checkpointp" 0 $?
    check "the archives and the manifest" "0.tar 1.tar pod.json" "$(ls "$CKDIR/pod1" | tr '\n' ' ' | sed 's/ $//')"
    check "the files are the owner's alone" "600" "$(stat -c %a "$CKDIR/pod1/0.tar")"
    check "the manifest names the pod" "web" "$(json "$CKDIR/pod1/pod.json" 'd["sandbox"]["name"]')"
    check "its annotations" "hi" "$(json "$CKDIR/pod1/pod.json" 'd["sandbox"]["annotations"]["note"]')"
    check "its labels" "web" "$(json "$CKDIR/pod1/pod.json" 'd["labels"]["app"]')"
    check "its hostname" "webhost" "$(json "$CKDIR/pod1/pod.json" 'd["hostname"]')"
    check "its containers" "main side" "$(json "$CKDIR/pod1/pod.json" '" ".join(c["meta"]["name"] for c in d["containers"])')"
    check "the labels of a container" "1" "$(json "$CKDIR/pod1/pod.json" 'd["containers"][0]["labels"]["l"]')"
    check "both run on" 2 "$(cc ps | grep -c Running)"
    a=$(cc exec -s "$c1" cat /tmp/n)
    cc exec -s "$c1" timeout 60 sh -c "until [ \"\$(cat /tmp/n)\" != $a ]; do :; done"
    b=$(cc exec -s "$c1" cat /tmp/n)
    check "main counts again" 1 "$(test "$b" != "$a" && echo 1 || echo 0)"
    # the directory is not empty any more
    grpc checkpointp "$pod" "$CKDIR/pod1" "$c1" > /dev/null
    check_match "a second checkpoint in it is refused" "ERROR 3 .*not empty" "$(cat "$WORKDIR/grpc.err")"
    echo "$(cc exec -s "$c1" cat /tmp/n)" > "$WORKDIR/at_checkpoint"
}

@test "RestorePod refuses what is not the checkpoint, and makes nothing" {
    before=$(cc pods -q | wc -l)
    grpc restorep "$CKDIR/nothere" "$WORKDIR/pod.json" "$WORKDIR/main.json" "$WORKDIR/side.json" > /dev/null
    check_match "a directory that is not there" "ERROR 5 " "$(cat "$WORKDIR/grpc.err")"
    grpc restorep "$WORKDIR" "$WORKDIR/pod.json" "$WORKDIR/main.json" "$WORKDIR/side.json" > /dev/null
    check_match "a directory that is not the checkpoint directory's" "ERROR 3 .*checkpoint directory" "$(cat "$WORKDIR/grpc.err")"
    grpc restorep "$CKDIR/pod1" "$WORKDIR/pod.json" "$WORKDIR/main.json" > /dev/null
    check_match "a container of the checkpoint without a config" "ERROR 3 .*side" "$(cat "$WORKDIR/grpc.err")"
    sed 's/"main"/"other"/' "$WORKDIR/main.json" > "$WORKDIR/other.json"
    grpc restorep "$CKDIR/pod1" "$WORKDIR/pod.json" "$WORKDIR/other.json" "$WORKDIR/side.json" > /dev/null
    check_match "a container that is not in the checkpoint" "ERROR 3 .*other" "$(cat "$WORKDIR/grpc.err")"
    sed 's/i=0;/i=1;/' "$WORKDIR/main.json" > "$WORKDIR/changed.json"
    grpc restorep "$CKDIR/pod1" "$WORKDIR/pod.json" "$WORKDIR/changed.json" "$WORKDIR/side.json" > /dev/null
    check_match "a command that is not the one that ran" "ERROR 3 .*command" "$(cat "$WORKDIR/grpc.err")"
    check "no sandbox was made" "$before" "$(cc pods -q | wc -l)"
}

@test "RestorePod: a new sandbox, the containers created, then started by the kubelet" {
    need_state pod
    need_state c1
    need_state c2
    need_state at_checkpoint
    cc stopp "$pod" > /dev/null
    check "stopp" 0 $?
    cc rmp "$pod" > /dev/null
    check "rmp" 0 $?
    sed 's/"u1"/"u2"/' "$WORKDIR/pod.json" > "$WORKDIR/pod2.json"
    grpc restorep "$CKDIR/pod1" "$WORKDIR/pod2.json" "$WORKDIR/main.json" "$WORKDIR/side.json" > "$WORKDIR/restored.json"
    check "restorep" 0 $?
    newpod=$(json "$WORKDIR/restored.json" 'd["pod_sandbox_id"]')
    r1=$(json "$WORKDIR/restored.json" 'd["restored_containers"]["main"]')
    r2=$(json "$WORKDIR/restored.json" 'd["restored_containers"]["side"]')
    check "a new sandbox, ready" SANDBOX_READY "$(cc inspectp "$newpod" | python3 -I -c 'import sys, json; print(json.load(sys.stdin)["status"]["state"])')"
    check "with the labels of the request" "web" "$(cc inspectp "$newpod" | python3 -I -c 'import sys, json; print(json.load(sys.stdin)["status"]["labels"]["app"])')"
    check "the containers are created" 2 "$(cc ps -a | grep -c Created)"
    check "none runs" 0 "$(cc ps | grep -c Running)"
    check "main is the one of the checkpoint" "1" "$(cc inspect "$r1" | python3 -I -c 'import sys, json; print(json.load(sys.stdin)["status"]["labels"]["l"])')"
    cc start "$r1" > /dev/null
    check "start main" 0 $?
    cc start "$r2" > /dev/null
    check "start side" 0 $?
    check "both run" 2 "$(cc ps | grep -c Running)"
    # the process goes on from where it was checkpointed (not from 1), in
    # its memory and in the files of its root file system
    at=$at_checkpoint
    cc exec -s "$r1" timeout 60 sh -c "until [ \"\$(cat /tmp/n 2> /dev/null || echo 0)\" -gt $at ]; do :; done"
    n=$(cc exec -s "$r1" cat /tmp/n 2> /dev/null)
    test "${n:-0}" -gt "$at"
    check "main counts on from the checkpoint ($at, then $n)" 0 $?
    m=$(cc exec -s "$r2" cat /tmp/m)
    test "$m" -gt 1000
    check "side counts on ($m)" 0 $?
    cc stopp "$newpod" > /dev/null
    cc rmp "$newpod" > /dev/null
    check "the restored sandbox is removed" 0 "$(cc pods -q | wc -l)"
}
