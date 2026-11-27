# SPDX-License-Identifier: Apache-2.0
# velarx-cri against crictl in a scratch HOME: the engine of the test (velarx
# varlink) and velarx-cri on its socket (org.velarx.Engine; there is no
# REST API), then a sandbox, a container, its log, exec (sync and WebSocket),
# stats, stop and removal, images.
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/cri.bats
#
# As root, as the CRI is tested (docs/CRI.md); skipped without root, crictl or velarx-cri.

load helpers

cc () { crictl --timeout 120s -r "unix://$CRISOCK" -i "unix://$CRISOCK" "$@" 2> "$WORKDIR/crictl.err"; }

# need_state NAME: NAME is the value the earlier test left in $WORKDIR/NAME
need_state () {
    printf -v "$1" %s "$(cat "$WORKDIR/$1" 2> /dev/null)"
    if [ -z "${!1}" ]; then
        echo "FAIL no $1 of the earlier tests (one failed or did not run)" >&2
        exit 1
    fi
}

# pods_now: the pods of the frontend (a short timeout: it may be gone)
pods_now () { crictl --timeout 10s -r "unix://$CRISOCK" -i "unix://$CRISOCK" pods -q 2> /dev/null; }

# After a test that failed: the pods it made go, so that the next tests,
# which check that no pod is left, do not fail for it.
setup () {
    set +e
    PODS_BEFORE=" $(pods_now | tr '\n' ' ') "
}
teardown () {
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] && return 0
    local p
    for p in $(pods_now); do
        case "$PODS_BEFORE" in
        *" $p "*) ;;
        *) cc stopp "$p" > /dev/null; cc rmp "$p" > /dev/null ;;
        esac
    done
    return 0
}

setup_file () {
    # (the CRI is run and tested as root, as a kubelet runs it: docs/CRI.md)
    [ "$(id -u)" = 0 ] || skip "the CRI is tested as root"
    command -v crictl > /dev/null || skip "crictl is not installed"
    e2e_setup_file
    e2e_need_cri
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export CRISOCK=$WORKDIR/cri.sock
    mkdir -p "$WORKDIR/logs"
    chmod 700 "$XDG_RUNTIME_DIR"
    mkdir -p "$WORKDIR/cni/bin" "$WORKDIR/cni/conf"
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[runtimes]
logged = "$WORKDIR/logged-runtime"
[network.cni]
conf_dir = "$WORKDIR/cni/conf"
bin_dirs = ["$WORKDIR/cni/bin"$([ -n "${VELARX_CNI_PLUGINS:-}" ] && printf ', "%s"' "$VELARX_CNI_PLUGINS")]
cache_dir = "$WORKDIR/cni/cache"
TOML
    # a runtime handler: a script that says what it is asked, then is crun
    CRUN=$(command -v crun)
    printf '#!/bin/sh\necho "$@" >> "%s/runtime.log"\nexec %s "$@"\n' "$WORKDIR" "$CRUN" > "$WORKDIR/logged-runtime"
    chmod +x "$WORKDIR/logged-runtime"
    # the registry of the tests speaks plain HTTP (the engine has this environment)
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    # (and REGISTRY_INSECURE, the registries of tests/cri/run-all.sh)
    # shellcheck disable=SC2086
    printf '%s\n' "$E2E_REGISTRY" ${REGISTRY_INSECURE:-} | sort -u | while read -r r; do
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$r"
    done > "$XDG_CONFIG_HOME/velarx/registries.conf"
    export VELARX_REGISTRIES_CONF=${VELARX_REGISTRIES_CONF:-$XDG_CONFIG_HOME/velarx/registries.conf}
    # the engine of the test (root does not read $XDG_CONFIG_HOME: told); the
    # frontend talks to its socket and starts nothing
    e2e_start_daemon
    "$BIN/velarx-cri" --socket "$CRISOCK" --engine-socket "$ESOCK" \
        > "$WORKDIR/cri.log" 2>&1 3>&- &
    CRI_PID=$!
    echo "$CRI_PID" > "$WORKDIR/cri.pid"
    export CRI_PID
    # (the socket, unless the process ends first)
    e2e_wait_path_of "$CRISOCK" "$CRI_PID" 60 && test -S "$CRISOCK" || { echo "velarx-cri does not start"; tail "$WORKDIR/cri.log"; exit 1; }
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    if test -n "${REF_CRI_PID:-}"; then
        kill -INT "$REF_CRI_PID" 2> /dev/null
        e2e_wait_exit "$REF_CRI_PID"
        kill -KILL "$REF_CRI_PID" 2> /dev/null
    fi
    if test -n "${CNI_CRI_PID:-}"; then
        kill -INT "$CNI_CRI_PID" 2> /dev/null
        e2e_wait_exit "$CNI_CRI_PID"
        kill -KILL "$CNI_CRI_PID" 2> /dev/null
    fi
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

@test "the version of the runtime" {
    check_match "version" "RuntimeName: +velarx" "$(cc version)"
}

@test "the frontend is confined" {
    # the frontend confined itself: no new privileges, a seccomp filter, no
    # capability; every thread (those of its runtime are made after it)
    check "confined: no new privileges, seccomp filter, no capability" "CapEff: 0000000000000000 NoNewPrivs: 1 Seccomp: 2" \
        "$(for t in /proc/"$CRI_PID"/task/*; do awk '/^(NoNewPrivs|Seccomp|CapEff):/ { printf "%s%s %s", sep, $1, $2; sep = " " } END { print "" }' "$t/status"; done | sort -u)"
}

@test "another user is not served" {
    command -v setpriv > /dev/null || skip "no setpriv"
    # whatever the permissions of the socket say, only root and the user of the
    # process are served (the check needs a user to be)
    chmod 0711 "$WORKDIR"; chmod 0666 "$CRISOCK"
    out=$(setpriv --reuid=65534 --regid=65534 --clear-groups crictl --timeout 10s -r "unix://$CRISOCK" version 2>&1)
    check "another user is not served" 1 $(( $? != 0 ? 1 : 0 ))
    check_match "another user: the connection is closed" "EOF|connection|closed|Unavailable|unavailable" "$out"
    chmod 0600 "$CRISOCK"
}

@test "pull and list the image" {
    cc pull "$IMAGE" > /dev/null
    check "pull" 0 $?
    name=${IMAGE##*/}
    check_match "images" "${name%%:*}" "$(cc images)"
}

@test "run a sandbox" {
    cat > "$WORKDIR/pod.json" <<JSON
{"metadata": {"name": "web", "namespace": "default", "uid": "u1", "attempt": 0},
 "hostname": "webhost", "log_directory": "$WORKDIR/logs",
 "labels": {"app": "web"}, "annotations": {"note": "hi"},
 "linux": {"security_context": {"namespace_options": {"network": 0, "pid": 1, "ipc": 0}}}}
JSON
    cat > "$WORKDIR/ctr.json" <<JSON
{"metadata": {"name": "main"}, "image": {"image": "$IMAGE"}, "log_path": "main.log",
 "command": ["sh", "-c", "echo hello; echo oops >&2; sleep 300"],
 "envs": [{"key": "FOO", "value": "bar"}], "labels": {"l": "1"}, "annotations": {"a": "1"}}
JSON
    pod=$(cc runp "$WORKDIR/pod.json")
    check "runp" 0 $?
    check_match "pods" "web +default" "$(cc pods)"
    check "pod state" SANDBOX_READY "$(cc inspectp "$pod" | python3 -I -c 'import sys, json; print(json.load(sys.stdin)["status"]["state"])')"
    echo "$pod" > "$WORKDIR/pod"
}

@test "create and start a container, its log" {
    need_state pod
    ctr=$(cc create "$pod" "$WORKDIR/ctr.json" "$WORKDIR/pod.json")
    check "create" 0 $?
    cc start "$ctr" > /dev/null
    check "start" 0 $?
    check_match "ps" "Running +main" "$(cc ps)"
    e2e_wait_line "$WORKDIR/logs/main.log" .
    check_match "the log is in the CRI format" ' stdout F hello' "$(cat "$WORKDIR/logs/main.log")"
    check_match "logs" "hello" "$(cc logs "$ctr")"
    echo "$ctr" > "$WORKDIR/ctr"
}

@test "exec in the container, sync, WebSocket and SPDY" {
    need_state ctr
    check "exec sync" "out" "$(cc exec -s "$ctr" sh -c 'echo out')"
    cc exec -s "$ctr" sh -c 'exit 3' > /dev/null
    check "exec sync: the exit code" 1 $?
    check_match "exec sync: the exit code is reported" "exited with 3" "$(cat "$WORKDIR/crictl.err")"
    check "exec over WebSocket" "ws" "$(cc exec --transport websocket "$ctr" echo ws)"
    check "exec over SPDY (the default of crictl)" "sp" "$(cc exec "$ctr" echo sp)"
    check "env" "bar" "$(cc exec -s "$ctr" sh -c 'echo $FOO')"
}

@test "a large input and its output go together, over SPDY and WebSocket" {
    need_state ctr
    # (a counter, so that a stream gone wrong shows where: cmp names the
    # first byte that differs, or the end of the short output)
    seq -f '%010g' 1 999999 > "$WORKDIR/counter.in"
    local transport bad
    for transport in spdy websocket; do
        bad=
        cc exec --transport "$transport" -i "$ctr" cat < "$WORKDIR/counter.in" > "$WORKDIR/counter.out"
        if ! cmp -s "$WORKDIR/counter.in" "$WORKDIR/counter.out"; then
            bad=$(cmp "$WORKDIR/counter.in" "$WORKDIR/counter.out" 2>&1 | head -1 | sed "s|$WORKDIR/||g")
        fi
        check "11 MB through exec -i cat over $transport" "" "$bad"
    done
}

@test "an exec without a terminal is killed when its client goes away, over SPDY and WebSocket" {
    need_state ctr
    sleeping () { cc exec -s "$ctr" sh -c "ps | grep -c '[s]leep $1'; true"; }
    timeout -s KILL 2 crictl -r "unix://$CRISOCK" -i "unix://$CRISOCK" exec -i "$ctr" sleep 771 < /dev/null > /dev/null 2>&1 || true
    timeout -s KILL 2 crictl -r "unix://$CRISOCK" -i "unix://$CRISOCK" exec --transport websocket -i "$ctr" sleep 773 < /dev/null > /dev/null 2>&1 || true
    for n in 771 773; do
        # (the loop runs in the container: what the kill must end is only visible there)
        cc exec -s "$ctr" timeout 30 sh -c "while ps | grep -q '[s]leep $n'; do :; done" || true
        left=$(sleeping "$n")
        check "no sleep $n is left after its client was killed" 0 "$left"
    done
}

@test "stats, inspect, imagefsinfo" {
    need_state ctr
    check_match "stats" "main" "$(cc stats)"
    check_match "inspect: labels" '"l": "1"' "$(cc inspect "$ctr")"
    check_match "imagefsinfo" "usedBytes" "$(cc imagefsinfo)"
    check_match "imagefsinfo: the inodes in use" "^[1-9][0-9]*$" \
        "$(cc imagefsinfo | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["status"]["imageFilesystems"][0]["inodesUsed"]["value"])')"
    need_state pod
    check_match "the verbose status of the container: its process and sandbox" "^[1-9][0-9]* $pod$" \
        "$(cc inspect "$ctr" | python3 -I -c 'import json, sys; i = json.load(sys.stdin)["info"]; print(i["pid"], i["sandboxID"])')"
    check_match "the verbose status of the sandbox: its process and its network namespace" "^[1-9][0-9]* /proc/[0-9]+/ns/net crun$" \
        "$(cc inspectp "$pod" | python3 -I -c 'import json, sys; i = json.load(sys.stdin)["info"]; print(i["pid"], i["netnsPath"], i["runtimeType"])')"
}

@test "stop and remove the container and the sandbox" {
    need_state pod
    need_state ctr
    cc stop "$ctr" > /dev/null
    check "stop" 0 $?
    check_match "an exited container" "Exited +main" "$(cc ps -a)"
    cc rm "$ctr" > /dev/null
    check "rm" 0 $?
    cc stopp "$pod" > /dev/null
    check "stopp" 0 $?
    cc rmp "$pod" > /dev/null
    check "rmp" 0 $?
}

# free_port: a TCP port nothing listens on (the bind is released at once)
free_port () {
    python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}

# tcp_read PORT: what the server on 127.0.0.1:PORT says, first line
tcp_read () {
    python3 -I -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
print(s.makefile().readline().strip())' "$1"
}

# wait_tcp PORT: the first line the server on 127.0.0.1:PORT says, for 20 seconds at most
wait_tcp () {
    local i out
    # (a poll: a server that listens says nothing, there is no event to wait for)
    for i in $(seq 100); do
        out=$(tcp_read "$1" 2> /dev/null) && [ -n "$out" ] && { echo "$out"; return 0; }
        sleep 0.2
    done
    return 1
}

@test "a pod of two containers: host mounts, DNS, a published port, logs, stats, port-forward" {
    local hp lp
    hp=$(free_port); lp=$(free_port)
    mkdir -p "$WORKDIR/hostdir"
    echo from-host > "$WORKDIR/hostdir/f"
    cat > "$WORKDIR/pod2.json" <<JSON
{"metadata": {"name": "two", "namespace": "default", "uid": "u2", "attempt": 0},
 "hostname": "twohost", "log_directory": "$WORKDIR/logs",
 "dns_config": {"servers": ["10.1.1.1"], "searches": ["x.test"], "options": ["ndots:3"]},
 "port_mappings": [{"protocol": 0, "container_port": 8080, "host_port": $hp, "host_ip": "127.0.0.1"}]}
JSON
    cat > "$WORKDIR/srv.json" <<JSON
{"metadata": {"name": "srv"}, "image": {"image": "$IMAGE"}, "log_path": "srv.log",
 "command": ["sh", "-c", "echo up; while true; do echo served | nc -l -p 8080; done"],
 "mounts": [{"container_path": "/data", "host_path": "$WORKDIR/hostdir", "selinux_relabel": true}]}
JSON
    cat > "$WORKDIR/side.json" <<JSON
{"metadata": {"name": "side"}, "image": {"image": "$IMAGE"}, "log_path": "side.log",
 "command": ["sh", "-c", "cat /ro/f; sleep 300"],
 "mounts": [{"container_path": "/ro", "host_path": "$WORKDIR/hostdir", "readonly": true, "selinux_relabel": true}]}
JSON
    cc pull "$IMAGE" > /dev/null
    pod=$(cc runp "$WORKDIR/pod2.json")
    check "runp" 0 $?
    srv=$(cc create "$pod" "$WORKDIR/srv.json" "$WORKDIR/pod2.json")
    check "create the first container" 0 $?
    side=$(cc create "$pod" "$WORKDIR/side.json" "$WORKDIR/pod2.json")
    check "create the second container" 0 $?
    cc start "$srv" > /dev/null
    check "start the first container" 0 $?
    cc start "$side" > /dev/null
    check "start the second container" 0 $?

    check "the published port answers" served "$(wait_tcp "$hp")"
    check "the sandbox has the hostname" twohost "$(cc exec -s "$srv" hostname)"
    check "the second container shares the hostname" twohost "$(cc exec -s "$side" hostname)"
    check_match "DNS of the sandbox: server" "nameserver 10.1.1.1" "$(cc exec -s "$srv" cat /etc/resolv.conf)"
    check_match "DNS of the sandbox: search" "search x.test" "$(cc exec -s "$side" cat /etc/resolv.conf)"
    check "a writable host mount" from-host "$(cc exec -s "$srv" cat /data/f)"
    cc exec -s "$srv" sh -c 'echo written > /data/w' > /dev/null
    check "the write reached the host" written "$(cat "$WORKDIR/hostdir/w")"
    check "a read-only host mount: read" from-host "$(cc exec -s "$side" cat /ro/f)"
    cc exec -s "$side" sh -c 'echo no > /ro/x' > /dev/null
    check "a read-only host mount: write refused" 1 $(( $? != 0 ? 1 : 0 ))
    check_match "a read-only host mount: why" "Read-only file system" "$(cat "$WORKDIR/crictl.err")"

    e2e_wait_line "$WORKDIR/logs/srv.log" .
    e2e_wait_line "$WORKDIR/logs/side.log" .
    check_match "the log of the first is in the CRI format" ' stdout F up' "$(cat "$WORKDIR/logs/srv.log")"
    check_match "the log of the second" ' stdout F from-host' "$(cat "$WORKDIR/logs/side.log")"
    check_match "the containers are listed with the pod" "srv.*two|side.*two" "$(cc ps --pod "$pod" -o json | python3 -I -c 'import json, sys; print(" ".join(c["metadata"]["name"] + " two" for c in json.load(sys.stdin)["containers"]))')"
    check_match "stats of the containers" "srv" "$(cc stats -a)"
    check_match "stats of the pod" "two" "$(cc statsp)"

    # port-forward to the port of the pod: no host port needed
    cc port-forward "$pod" "$lp:8080" > "$WORKDIR/pf.out" 2>&1 3>&- &
    pf=$!
    check "port-forward" served "$(wait_tcp "$lp")"
    kill "$pf" 2> /dev/null; wait "$pf" 2> /dev/null

    cc stop "$srv" "$side" > /dev/null
    check "stop both" 0 $?
    cc rm "$srv" "$side" > /dev/null
    check "remove both" 0 $?
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
    check "the pod is removed" "" "$(cc pods -q)"
}

@test "a pod on the host network: port-forward reaches the port in the host's namespace" {
    local hn lp
    hn=$(free_port); lp=$(free_port)
    cat > "$WORKDIR/hpod.json" <<JSON
{"metadata": {"name": "hostnet", "namespace": "default", "uid": "u3", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "linux": {"security_context": {"namespace_options": {"network": 2}}}}
JSON
    cat > "$WORKDIR/hsrv.json" <<JSON
{"metadata": {"name": "hsrv"}, "image": {"image": "$IMAGE"}, "log_path": "hsrv.log",
 "command": ["sh", "-c", "while true; do echo hostnet | nc -l -p $hn; done"]}
JSON
    pod=$(cc runp "$WORKDIR/hpod.json")
    check "runp on the host network" 0 $?
    ctr=$(cc create "$pod" "$WORKDIR/hsrv.json" "$WORKDIR/hpod.json")
    cc start "$ctr" > /dev/null
    check "start" 0 $?
    check "the server is on the host's port" hostnet "$(wait_tcp "$hn")"
    cc port-forward "$pod" "$lp:$hn" > "$WORKDIR/pf2.out" 2>&1 3>&- &
    pf=$!
    check "port-forward in the host network" hostnet "$(wait_tcp "$lp")"
    kill "$pf" 2> /dev/null; wait "$pf" 2> /dev/null
    cc stop "$ctr" > /dev/null
    cc rm "$ctr" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "what the engine cannot do or the request contradicts is refused, not ignored" {
    cat > "$WORKDIR/rpod.json" <<JSON
{"metadata": {"name": "refuse", "namespace": "default", "uid": "u4", "attempt": 0},
 "log_directory": "$WORKDIR/logs"}
JSON
    pod=$(cc runp "$WORKDIR/rpod.json")
    check "runp" 0 $?
    mkdir -p "$WORKDIR/rro"
    local base="\"metadata\": {\"name\": \"r\"}, \"image\": {\"image\": \"$IMAGE\"}, \"command\": [\"sleep\", \"300\"]"
    # a recursive read-only mount that is read-write
    echo "{$base, \"mounts\": [{\"container_path\": \"/m\", \"host_path\": \"$WORKDIR/rro\", \"recursive_read_only\": true}]}" > "$WORKDIR/r1.json"
    cc create "$pod" "$WORKDIR/r1.json" "$WORKDIR/rpod.json" > /dev/null
    check "recursive read-only needs read-only" 1 $(( $? != 0 ? 1 : 0 ))
    check_match "and says so" "readonly must be set" "$(cat "$WORKDIR/crictl.err")"
    # the host network in a pod that has its own
    echo "{$base, \"linux\": {\"security_context\": {\"namespace_options\": {\"network\": 2}}}}" > "$WORKDIR/r2.json"
    cc create "$pod" "$WORKDIR/r2.json" "$WORKDIR/rpod.json" > /dev/null
    check "the host network of a container in a pod with its own" 1 $(( $? != 0 ? 1 : 0 ))
    check_match "and says so" "host's network namespace" "$(cat "$WORKDIR/crictl.err")"
    # an allowed recursive read-only mount is read-only in the container
    echo "{$base, \"mounts\": [{\"container_path\": \"/m\", \"host_path\": \"$WORKDIR/rro\", \"readonly\": true, \"recursive_read_only\": true}]}" > "$WORKDIR/r3.json"
    ctr=$(cc create "$pod" "$WORKDIR/r3.json" "$WORKDIR/rpod.json")
    check "a recursive read-only mount is created" 0 $?
    cc start "$ctr" > /dev/null
    check "and the container starts" 0 $?
    cc exec -s "$ctr" touch /m/x > /dev/null
    check "and it is read-only" 1 $(( $? != 0 ? 1 : 0 ))
    check "the runtime handlers say that they support recursive read-only mounts" true \
        "$(cc info | python3 -I -c 'import json, sys; print(str(all(h["features"]["recursive_read_only_mounts"] for h in json.load(sys.stdin)["runtimeHandlers"])).lower())')"
    cc stop "$ctr" > /dev/null
    cc rm "$ctr" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "started by a socket unit: the frontend serves the socket systemd passed" {
    command -v systemd-socket-activate > /dev/null || skip "no systemd-socket-activate"
    local act=$WORKDIR/act.sock ap child i
    systemd-socket-activate -l "$act" "$BIN/velarx-cri" --engine-socket "$ESOCK" \
        > "$WORKDIR/act.log" 2>&1 3>&- &
    ap=$!
    e2e_wait_path "$act"
    check_match "the version through the passed socket" "RuntimeName: +velarx" \
        "$(crictl --timeout 30s -r "unix://$act" version 2>&1)"
    child=$(pgrep -P "$ap")
    kill -INT $child "$ap" 2> /dev/null
    wait "$ap" 2> /dev/null
    rm -f "$act"
}

@test "the resources of a sandbox and of a container: limits and unified cgroup settings" {
    cat > "$WORKDIR/lpod.json" <<JSON
{"metadata": {"name": "limits", "namespace": "default", "uid": "u5", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "linux": {"resources": {"memory_limit_in_bytes": 134217728, "cpu_quota": 50000, "cpu_period": 100000,
                         "cpu_shares": 512, "oom_score_adj": 500, "unified": {"memory.oom.group": "1"}}}}
JSON
    cat > "$WORKDIR/lctr.json" <<JSON
{"metadata": {"name": "limited"}, "image": {"image": "$IMAGE"}, "log_path": "limited.log",
 "command": ["sleep", "300"],
 "linux": {"resources": {"memory_limit_in_bytes": 134217728, "unified": {"memory.high": "100663296", "memory.oom.group": "1"}}}}
JSON
    pod=$(cc runp "$WORKDIR/lpod.json")
    check "a sandbox with the resources the kubelet sends" 0 $?
    ctr=$(cc create "$pod" "$WORKDIR/lctr.json" "$WORKDIR/lpod.json")
    check "a container with unified cgroup settings" 0 $?
    cc start "$ctr" > /dev/null
    check "start" 0 $?
    check "memory.high of the container" 100663296 "$(cc exec -s "$ctr" cat /sys/fs/cgroup/memory.high)"
    check "memory.oom.group of the container (the kubelet's, the sandbox's accepted)" 1 \
        "$(cc exec -s "$ctr" cat /sys/fs/cgroup/memory.oom.group)"
    # the limits of the sandbox are those of the cgroup of the pod, the parent of the cgroups of
    # its infra container and its containers (not of the infra container alone): <pod> of the
    # engine's tree, or the slice of the pod where its containers are scopes (a sandbox with no
    # cgroup parent of an engine with --cgroups=scope)
    pcg=$(find /sys/fs/cgroup -maxdepth 14 -type d \( -name "$pod" -o -name "*-velarx_pod_$pod.slice" \) \
        2> /dev/null | head -1)
    if [ -z "$pcg" ]; then
        echo "FAIL the cgroup of the pod $pod is not in /sys/fs/cgroup" >&2
        exit 1
    fi
    check "memory.max of the cgroup of the pod" 134217728 "$(cat "$pcg/memory.max")"
    check "cpu.max of the cgroup of the pod" "50000 100000" "$(cat "$pcg/cpu.max")"
    # (the engine writes the weight of the pod: 512 shares are 59 in the quadratic conversion
    # of limit-core's weight_of_shares, crun's convert_shares_to_weight, where 1024 is 100)
    check "cpu.weight of the cgroup of the pod" 59 "$(cat "$pcg/cpu.weight")"
    check "the infra container and the container are below the cgroup of the pod" 2 "$(find "$pcg" -mindepth 2 -maxdepth 2 -name container | grep -c .)"
    # (the directory of a member is <id> in the engine's tree, velarx-<id>.scope in the slice)
    check "the infra container has no limit of its own" max \
        "$(cat "$(find "$pcg" -mindepth 2 -maxdepth 2 -name container ! -path "*$ctr*" | head -1)/memory.max")"
    # the update of the sandbox replaces the limits of the cgroup of the pod
    varlinkctl call "unix:$ESOCK" org.velarx.Engine.PodUpdate \
        "{\"name\": \"$pod\", \"resources\": {\"memory\": 201326592, \"cpu_quota\": 25000, \"cpu_period\": 100000}}" > /dev/null
    check "update of the pod" 0 $?
    check "memory.max after the update" 201326592 "$(cat "$pcg/memory.max")"
    check "cpu.max after the update" "25000 100000" "$(cat "$pcg/cpu.max")"
    check "cpu.weight after the update (none is the default)" 100 "$(cat "$pcg/cpu.weight")"
    # unified settings cannot be changed in a running container: refused
    cc update --memory 67108864 "$ctr" > /dev/null
    check "an update of the memory limit" 0 $?
    check "memory.max of the container after it" 67108864 "$(cc exec -s "$ctr" cat /sys/fs/cgroup/memory.max)"
    cc stop "$ctr" > /dev/null
    cc rm "$ctr" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
    check "the cgroup of the pod is removed with it" 0 "$(test -e "$pcg" && echo 1 || echo 0)"
}

@test "the security context and the OOM score of a sandbox are its infra container's" {
    cat > "$WORKDIR/spod.json" <<JSON
{"metadata": {"name": "secure", "namespace": "default", "uid": "u6", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "linux": {"resources": {"oom_score_adj": 500},
           "security_context": {"run_as_user": {"value": 1000}, "run_as_group": {"value": 2000},
                                "supplemental_groups": [3, 4], "readonly_rootfs": true,
                                "seccomp": {"profile_type": 1}}}}
JSON
    pod=$(cc runp "$WORKDIR/spod.json")
    check "a sandbox with a security context and an OOM score" 0 $?
    infra=$(cc inspectp "$pod" | python3 -I -c 'import sys, json; print(json.load(sys.stdin)["info"]["infra"])')
    check "the user of the infra container" "1000:2000" "$($SH inspect "$infra" --format '{{.Config.User}}')"
    check "its root file system is read-only" true "$($SH inspect "$infra" --format '{{.HostConfig.ReadonlyRootfs}}')"
    check_match "its seccomp profile" "seccomp=unconfined" "$($SH inspect "$infra" --format '{{.HostConfig.SecurityOpt}}')"
    local pid; pid=$($SH inspect "$infra" --format '{{.State.Pid}}')
    check "its OOM score" 500 "$(cat "/proc/$pid/oom_score_adj")"
    # the two supplemental groups are in its process, over its own group
    check "its supplemental groups" yes "$(awk '/^Groups:/ { print (NF - 1 >= 3) ? "yes" : "no" }' "/proc/$pid/status")"
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
    check "no pods left" "" "$(cc pods -q)"
}

@test "a container of a privileged sandbox keeps a level of its own" {
    command -v selinuxenabled > /dev/null && selinuxenabled || skip "SELinux is not enabled"
    cat > "$WORKDIR/ppod.json" <<JSON
{"metadata": {"name": "priv", "namespace": "default", "uid": "u7", "attempt": 0},
 "log_directory": "$WORKDIR/logs", "linux": {"security_context": {"privileged": true}}}
JSON
    cat > "$WORKDIR/pctr.json" <<JSON
{"metadata": {"name": "member"}, "image": {"image": "$IMAGE"}, "log_path": "member.log",
 "command": ["sleep", "300"], "linux": {"security_context": {}}}
JSON
    pod=$(cc runp "$WORKDIR/ppod.json")
    check "a privileged sandbox" 0 $?
    ctr=$(cc create "$pod" "$WORKDIR/pctr.json" "$WORKDIR/ppod.json")
    check "a container that is not privileged in it" 0 $?
    cc start "$ctr" > /dev/null
    local pid; pid=$($SH inspect "$ctr" --format '{{.State.Pid}}')
    # the infra container is not confined; its members are, with categories
    check_match "the label of the member" ":container_t:s0:c[0-9]+,c[0-9]+$" "$(tr -d '\0' < "/proc/$pid/attr/current")"
    cc stop "$ctr" > /dev/null
    cc rm "$ctr" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "a relabeled host mount: a file system below it is relabeled, a bind mount below it is not" {
    command -v selinuxenabled > /dev/null && selinuxenabled || skip "SELinux is not enabled"
    local h=$WORKDIR/rlhost src=$WORKDIR/rlsrc
    mkdir -p "$h/tmpfs" "$h/bound" "$src"
    : > "$h/boundf"
    echo kept > "$src/f"
    # (a directory of the same file system: the device does not tell the mount)
    chcon -t usr_t "$src" "$src/f"
    mount -t tmpfs none "$h/tmpfs"
    mount --bind "$src" "$h/bound"
    mount --bind "$src/f" "$h/boundf"
    cat > "$WORKDIR/rlpod.json" <<JSON
{"metadata": {"name": "rl", "namespace": "default", "uid": "u8", "attempt": 0},
 "log_directory": "$WORKDIR/logs"}
JSON
    cat > "$WORKDIR/rlctr.json" <<JSON
{"metadata": {"name": "rl"}, "image": {"image": "$IMAGE"}, "log_path": "rl.log",
 "command": ["sleep", "300"],
 "mounts": [{"container_path": "/h", "host_path": "$h", "selinux_relabel": true}]}
JSON
    pod=$(cc runp "$WORKDIR/rlpod.json")
    ctr=$(cc create "$pod" "$WORKDIR/rlctr.json" "$WORKDIR/rlpod.json")
    check "create a container with the relabeled mount" 0 $?
    cc start "$ctr" > /dev/null
    check "the tmpfs below the mount is writable" w "$(cc exec -s "$ctr" sh -c 'echo w > /h/tmpfs/w && cat /h/tmpfs/w')"
    check_match "the tmpfs below the mount is relabeled" ':container_file_t:' "$(stat -c %C "$h/tmpfs")"
    check "the directory bound below the mount keeps its label" "usr_t usr_t" \
        "$(stat -c %C "$src" "$src/f" | cut -d: -f3 | xargs)"
    check "a bound file is seen" kept "$(cc exec -s "$ctr" cat /h/bound/f)"
    cc stop "$ctr" > /dev/null
    cc rm "$ctr" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
    umount "$h/boundf" "$h/bound" "$h/tmpfs"
}

@test "events: created, started, stopped and deleted, of the sandbox and of its container" {
    cc events -o json > "$WORKDIR/events.json" 2> /dev/null 3>&- &
    ev=$!
    cat > "$WORKDIR/epod.json" <<JSON
{"metadata": {"name": "ev", "namespace": "default", "uid": "u6", "attempt": 0},
 "log_directory": "$WORKDIR/logs"}
JSON
    cat > "$WORKDIR/ectr.json" <<JSON
{"metadata": {"name": "evc"}, "image": {"image": "$IMAGE"}, "log_path": "evc.log", "command": ["sleep", "300"]}
JSON
    pod=$(cc runp "$WORKDIR/epod.json")
    ctr=$(cc create "$pod" "$WORKDIR/ectr.json" "$WORKDIR/epod.json")
    cc start "$ctr" > /dev/null
    cc stop "$ctr" > /dev/null
    cc rm "$ctr" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
    e2e_wait_line "$WORKDIR/events.json" CONTAINER_DELETED_EVENT 30 2
    kill "$ev" 2> /dev/null; wait "$ev" 2> /dev/null
    check "events of the sandbox: created, started, stopped, deleted" \
        "CONTAINER_CREATED_EVENT CONTAINER_STARTED_EVENT CONTAINER_STOPPED_EVENT CONTAINER_DELETED_EVENT" \
        "$(python3 -I -c '
import json, sys
print(" ".join(e["containerEventType"] for e in map(json.loads, open(sys.argv[1]).read().replace("}\n{", "}\0{").split("\0")) if e["containerId"] == sys.argv[2]))' "$WORKDIR/events.json" "$pod")"
    check "events of the container: created, started, stopped, deleted" \
        "CONTAINER_CREATED_EVENT CONTAINER_STARTED_EVENT CONTAINER_STOPPED_EVENT CONTAINER_DELETED_EVENT" \
        "$(python3 -I -c '
import json, sys
print(" ".join(e["containerEventType"] for e in map(json.loads, open(sys.argv[1]).read().replace("}\n{", "}\0{").split("\0")) if e["containerId"] == sys.argv[2]))' "$WORKDIR/events.json" "$ctr")"
}

# jq_of EXPR: EXPR (python, of `d`) of the JSON on stdin
jq_of () { python3 -I -c 'import json, sys; d = json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }

@test "a container: its groups (strict policy), ambient capabilities, user, OCI configuration and stats" {
    cc pull "$IMAGE" > /dev/null
    cat > "$WORKDIR/xpod.json" <<JSON
{"metadata": {"name": "extra", "namespace": "default", "uid": "u9", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "linux": {"resources": {"memory_limit_in_bytes": 268435456},
           "security_context": {"namespace_options": {"pid": 1}}}}
JSON
    # uid 2 is daemon, whom the image's /etc/group puts in bin and adm too
    cat > "$WORKDIR/xctr.json" <<JSON
{"metadata": {"name": "strict"}, "image": {"image": "$IMAGE"}, "log_path": "strict.log",
 "command": ["sleep", "300"],
 "linux": {"security_context": {"run_as_user": {"value": 2}, "supplemental_groups": [5000],
                                "supplemental_groups_policy": 1,
                                "capabilities": {"add_ambient_capabilities": ["NET_RAW"]}}}}
JSON
    sed 's/"strict"/"merged"/; s/strict.log/merged.log/; s/"supplemental_groups_policy": 1,//; s/, *"capabilities".*}}}}/}}}/' \
        "$WORKDIR/xctr.json" > "$WORKDIR/mctr.json"
    pod=$(cc runp "$WORKDIR/xpod.json")
    check "runp" 0 $?
    ctr=$(cc create "$pod" "$WORKDIR/xctr.json" "$WORKDIR/xpod.json")
    check "a container of the strict groups policy and an ambient capability" 0 $?
    merged=$(cc create "$pod" "$WORKDIR/mctr.json" "$WORKDIR/xpod.json")
    check "a container of the default policy" 0 $?
    cc start "$ctr" "$merged" > /dev/null
    check "start" 0 $?
    # (the process of each is 1 of its PID namespace)
    groups () { cc exec -s "$1" cat /proc/1/status | awk '/^Groups:/ { $1 = ""; print substr($0, 2) }' | xargs; }
    check "strict: the groups are the user's and the supplemental ones" "2 5000" "$(groups "$ctr")"
    check "merge: the groups of the image's /etc/group too" "1 2 4 5000" \
        "$(groups "$merged" | tr ' ' '\n' | sort -n | xargs)"
    check "the ambient capability (CAP_NET_RAW) of a user that is not root" 0000000000002000 \
        "$(cc exec -s "$ctr" cat /proc/1/status | awk '/^CapAmb:/ { print $2 }')"
    check "ContainerStatus.user: uid, gid and groups of the process" "2 2 [2, 5000]" \
        "$(cc inspect "$ctr" | jq_of '" ".join(str(x) for x in (d["status"]["user"]["linux"]["uid"], d["status"]["user"]["linux"]["gid"], [int(g) for g in d["status"]["user"]["linux"]["supplementalGroups"]]))')"
    check "the verbose status has the OCI configuration" "['sleep', '300']" \
        "$(cc inspect "$ctr" | jq_of 'd["info"]["runtimeSpec"]["process"]["args"]')"
    check_match "the stats of the container: rss" "^[0-9]+$" \
        "$(cc stats -o json --id "$ctr" | jq_of 'd["stats"][0]["memory"]["rssBytes"]["value"]')"
    check_match "the stats of the container: swap" "^[0-9]+$" \
        "$(cc stats -o json --id "$ctr" | jq_of 'd["stats"][0]["swap"]["swapUsageBytes"]["value"]')"
    check_match "the stats of the pod (its cgroup): rss and available memory" "^[0-9]+ [1-9][0-9]*$" \
        "$(cc statsp -o json --id "$pod" | jq_of 'str(d["stats"][0]["linux"]["memory"]["rssBytes"]["value"]) + " " + str(d["stats"][0]["linux"]["memory"]["availableBytes"]["value"])')"
    if [ -e /proc/pressure/io ]; then
        check_match "the pressure of the container" "^[0-9]+$" \
            "$(cc stats -o json --id "$ctr" | jq_of 'd["stats"][0]["memory"]["psi"]["Some"]["Total"]')"
        check_match "the IO of the pod is its pressure" "^[0-9]+$" \
            "$(cc statsp -o json --id "$pod" | jq_of 'd["stats"][0]["linux"]["io"]["psi"]["Full"]["Total"]')"
    fi
    cc stop "$ctr" "$merged" > /dev/null
    cc rm "$ctr" "$merged" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "masked and read-only paths: exactly the lists of the security context, empty ones mean none" {
    cc pull "$IMAGE" > /dev/null
    cat > "$WORKDIR/mpod.json" <<JSON
{"metadata": {"name": "masks", "namespace": "default", "uid": "u10", "attempt": 0},
 "log_directory": "$WORKDIR/logs"}
JSON
    cat > "$WORKDIR/mkept.json" <<JSON
{"metadata": {"name": "kept"}, "image": {"image": "$IMAGE"}, "log_path": "kept.log",
 "command": ["sleep", "300"],
 "linux": {"security_context": {"masked_paths": ["/proc/kcore"], "readonly_paths": ["/proc/sys"]}}}
JSON
    sed 's/"kept"/"open"/; s/kept.log/open.log/; s/"masked_paths": \["\/proc\/kcore"\], "readonly_paths": \["\/proc\/sys"\]/"masked_paths": [], "readonly_paths": []/' \
        "$WORKDIR/mkept.json" > "$WORKDIR/mopen.json"
    pod=$(cc runp "$WORKDIR/mpod.json")
    check "runp" 0 $?
    kept=$(cc create "$pod" "$WORKDIR/mkept.json" "$WORKDIR/mpod.json")
    open=$(cc create "$pod" "$WORKDIR/mopen.json" "$WORKDIR/mpod.json")
    cc start "$kept" "$open" > /dev/null
    check "start" 0 $?
    sys () { cc exec -s "$1" sh -c 'grep -c " /proc/sys ro[ ,]" /proc/self/mountinfo; true'; }
    check "the read-only path of the lists is read-only" 1 "$(sys "$kept")"
    check "empty lists: /proc/sys is not read-only" 0 "$(sys "$open")"
    check "the masked path of the lists is masked" 1 \
        "$(cc exec -s "$kept" sh -c 'grep -c " /proc/kcore " /proc/self/mountinfo; true')"
    check "empty lists: /proc/kcore is not masked" 0 \
        "$(cc exec -s "$open" sh -c 'grep -c " /proc/kcore " /proc/self/mountinfo; true')"
    check "the OCI configuration has no masked path" "[]" \
        "$(cc inspect "$open" | jq_of 'd["info"]["runtimeSpec"]["linux"].get("maskedPaths", [])')"
    cc stop "$kept" "$open" > /dev/null
    cc rm "$kept" "$open" > /dev/null
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "stdin_once: the input of the container is closed when the attach ends" {
    cc pull "$IMAGE" > /dev/null
    cat > "$WORKDIR/opod.json" <<JSON
{"metadata": {"name": "once", "namespace": "default", "uid": "u10", "attempt": 0},
 "log_directory": "$WORKDIR/logs"}
JSON
    for once in true false; do
        cat > "$WORKDIR/octr-$once.json" <<JSON
{"metadata": {"name": "once-$once"}, "image": {"image": "$IMAGE"}, "log_path": "once-$once.log",
 "command": ["sh", "-c", "cat; echo input closed"], "stdin": true, "stdin_once": $once}
JSON
    done
    pod=$(cc runp "$WORKDIR/opod.json")
    check "runp" 0 $?
    for once in true false; do
        c=$(cc create "$pod" "$WORKDIR/octr-$once.json" "$WORKDIR/opod.json")
        cc start "$c" > /dev/null
        echo hello | timeout -s KILL 5 crictl -r "unix://$CRISOCK" -i "unix://$CRISOCK" attach -i "$c" \
            > "$WORKDIR/attach-$once.out" 2>&1
        eval "rc_$once=$?"
        eval "c_$once=$c"
    done
    local st
    # (the wait of the engine: the container ends when its input is closed)
    e2e_wait_condition "$c_true" exited
    st=$(cc inspect "$c_true" | jq_of 'd["status"]["state"]')
    check "with stdin_once the container read the end of its input" CONTAINER_EXITED "$st"
    check_match "and what was sent" "hello" "$(cat "$WORKDIR/logs/once-true.log")"
    check "the attach ended with the container" 0 "$rc_true"
    check_match "and passed what it wrote after the end of its input" "input closed" \
        "$(cat "$WORKDIR/attach-true.out")"
    check "without, its input stays open" CONTAINER_RUNNING "$(cc inspect "$c_false" | jq_of 'd["status"]["state"]')"
    # (as CRI-O's: the attach without a terminal ends with the input of its client)
    check "and the attach ended with the input of its client" 0 "$rc_false"
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "hugepage limits: the zero limits the kubelet sends; a limit needs the hugetlb controller" {
    cc pull "$IMAGE" > /dev/null
    cat > "$WORKDIR/hgpod.json" <<JSON
{"metadata": {"name": "huge", "namespace": "default", "uid": "u11", "attempt": 0},
 "log_directory": "$WORKDIR/logs"}
JSON
    for limit in 0 2097152; do
        cat > "$WORKDIR/hctr-$limit.json" <<JSON
{"metadata": {"name": "huge-$limit"}, "image": {"image": "$IMAGE"}, "log_path": "huge-$limit.log",
 "command": ["sleep", "300"],
 "linux": {"resources": {"hugepage_limits": [{"page_size": "2MB", "limit": $limit}]}}}
JSON
    done
    pod=$(cc runp "$WORKDIR/hgpod.json")
    check "runp" 0 $?
    c=$(cc create "$pod" "$WORKDIR/hctr-0.json" "$WORKDIR/hgpod.json")
    check "a container with the zero limits of the kubelet" 0 $?
    cc start "$c" > /dev/null
    check "start" 0 $?
    # (the controllers of the engine that serves the CRI, which makes the cgroups below its
    # own: a slice of systemd delegates no hugetlb by default, while the in-process engine
    # of a local `info` reports the host's, as podman does)
    if $SH --socket "$ESOCK" info --format '{{.Host.CgroupControllers}}' | grep -qw hugetlb; then
        check "the zero limit is the container's" 0 "$(cc exec -s "$c" cat /sys/fs/cgroup/hugetlb.2MB.max)"
        c2=$(cc create "$pod" "$WORKDIR/hctr-2097152.json" "$WORKDIR/hgpod.json")
        cc start "$c2" > /dev/null
        check "a limit" 2097152 "$(cc exec -s "$c2" cat /sys/fs/cgroup/hugetlb.2MB.max)"
    else
        cc create "$pod" "$WORKDIR/hctr-2097152.json" "$WORKDIR/hgpod.json" > /dev/null
        check "a limit without the hugetlb controller is refused" 1 $(( $? != 0 ? 1 : 0 ))
        check_match "and says so" "hugetlb cgroup controller" "$(cat "$WORKDIR/crictl.err")"
    fi
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "an ID-mapped mount in a pod of its own user namespace, root only" {
    mkdir -p "$WORKDIR/idmapped"
    echo mapped > "$WORKDIR/idmapped/f"
    chown 0:0 "$WORKDIR/idmapped/f"
    cc pull "$IMAGE" > /dev/null
    cat > "$WORKDIR/upod.json" <<JSON
{"metadata": {"name": "userns", "namespace": "default", "uid": "u12", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "linux": {"security_context": {"namespace_options": {"userns_options": {"mode": 0,
   "uids": [{"container_id": 0, "host_id": 300000, "length": 65536}],
   "gids": [{"container_id": 0, "host_id": 300000, "length": 65536}]}}}}}
JSON
    cat > "$WORKDIR/uctr.json" <<JSON
{"metadata": {"name": "mapped"}, "image": {"image": "$IMAGE"}, "log_path": "mapped.log",
 "command": ["sleep", "300"],
 "mounts": [{"container_path": "/m", "host_path": "$WORKDIR/idmapped", "selinux_relabel": true,
             "uidMappings": [{"container_id": 0, "host_id": 300000, "length": 65536}],
             "gidMappings": [{"container_id": 0, "host_id": 300000, "length": 65536}]}]}
JSON
    pod=$(cc runp "$WORKDIR/upod.json")
    check "a pod with a user namespace of its own" 0 $?
    c=$(cc create "$pod" "$WORKDIR/uctr.json" "$WORKDIR/upod.json")
    check "a container with an ID-mapped mount" 0 $?
    cc start "$c" > /dev/null
    check "start" 0 $?
    check "a file of root on the host is root's in the container" "0 mapped" \
        "$(cc exec -s "$c" sh -c 'stat -c %u /m/f; cat /m/f' | xargs)"
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "the PID namespace of a container: another container's (TARGET), the host's (NODE); its stop signal" {
    cc pull "$IMAGE" > /dev/null
    cat > "$WORKDIR/ppid.json" <<JSON
{"metadata": {"name": "pids", "namespace": "default", "uid": "u13", "attempt": 0},
 "log_directory": "$WORKDIR/logs", "linux": {"security_context": {"namespace_options": {"pid": 1}}}}
JSON
    # SIGINT (10): the process says it got it and ends well
    cat > "$WORKDIR/pmain.json" <<JSON
{"metadata": {"name": "main"}, "image": {"image": "$IMAGE"}, "log_path": "pmain.log",
 "command": ["sh", "-c", "trap 'echo got-int; exit 0' INT; echo up; while :; do sleep 0.2; done"],
 "stop_signal": 10}
JSON
    pod=$(cc runp "$WORKDIR/ppid.json")
    check "runp" 0 $?
    main=$(cc create "$pod" "$WORKDIR/pmain.json" "$WORKDIR/ppid.json")
    cc start "$main" > /dev/null
    check "start" 0 $?
    cat > "$WORKDIR/ptarget.json" <<JSON
{"metadata": {"name": "debug"}, "image": {"image": "$IMAGE"}, "log_path": "ptarget.log", "command": ["sleep", "300"],
 "linux": {"security_context": {"namespace_options": {"pid": 3, "target_id": "$main"}}}}
JSON
    cat > "$WORKDIR/pnode.json" <<JSON
{"metadata": {"name": "node"}, "image": {"image": "$IMAGE"}, "log_path": "pnode.log", "command": ["sleep", "300"],
 "linux": {"security_context": {"namespace_options": {"pid": 2}}}}
JSON
    target=$(cc create "$pod" "$WORKDIR/ptarget.json" "$WORKDIR/ppid.json")
    check "a container in the PID namespace of another (an ephemeral container's)" 0 $?
    node=$(cc create "$pod" "$WORKDIR/pnode.json" "$WORKDIR/ppid.json")
    check "a container in the PID namespace of the host" 0 $?
    cc start "$target" "$node" > /dev/null
    check "start both" 0 $?
    check_match "TARGET: the processes of the other container are there" "while :" "$(cc exec -s "$target" ps -o args)"
    check "NODE: process 1 is the host's" "$(cat /proc/1/comm)" "$(cc exec -s "$node" cat /proc/1/comm)"
    check "the stop signal is in the status" SIGNAL_SIGINT "$(cc inspect "$main" | jq_of 'd["status"]["stopSignal"]')"
    cc stop -t 20 "$main" > /dev/null
    check "stop" 0 $?
    check "stopped by its signal: it ended well" 0 "$(cc inspect "$main" | jq_of 'd["status"]["exitCode"]')"
    check_match "and said so" "got-int" "$(cat "$WORKDIR/logs/pmain.log")"
    cc stopp "$pod" > /dev/null
    cc rmp "$pod" > /dev/null
}

@test "pods on a CNI network: the plugins run for the sandbox, its address is the pod IP, root only" {
    # a plugin that gives the namespace an address, and logs what it is told
    cat > "$WORKDIR/cni/bin/testplugin" <<PLUGIN
#!/bin/sh
echo "\$CNI_COMMAND \$CNI_ARGS" >> "$WORKDIR/cni/log"
cat >> "$WORKDIR/cni/log"
echo >> "$WORKDIR/cni/log"
if [ "\$CNI_COMMAND" = STATUS ]; then
    if [ -e "$WORKDIR/cni/notready" ]; then
        echo '{"cniVersion":"1.1.0","code":50,"msg":"the plugin is not ready","details":"waiting for the datastore"}'
        exit 1
    fi
fi
if [ "\$CNI_COMMAND" = ADD ]; then
    nsenter --net="\$CNI_NETNS" ip link add "\$CNI_IFNAME" type dummy || exit 1
    nsenter --net="\$CNI_NETNS" ip addr add 10.99.0.7/24 dev "\$CNI_IFNAME" || exit 1
    nsenter --net="\$CNI_NETNS" ip link set "\$CNI_IFNAME" up || exit 1
    printf '{"cniVersion":"1.0.0","interfaces":[{"name":"%s","sandbox":"%s"}],"ips":[{"address":"10.99.0.7/24","gateway":"10.99.0.1","interface":0}]}' "\$CNI_IFNAME" "\$CNI_NETNS"
fi
PLUGIN
    chmod +x "$WORKDIR/cni/bin/testplugin"
    export CNISOCK=$WORKDIR/cni-cri.sock
    "$BIN/velarx-cri" --socket "$CNISOCK" --engine-socket "$ESOCK" \
        --pod-network cni: > "$WORKDIR/cni-cri.log" 2>&1 3>&- &
    CNI_CRI_PID=$!
    export CNI_CRI_PID
    local i
    e2e_wait_path "$CNISOCK"
    cn () { crictl --timeout 120s -r "unix://$CNISOCK" -i "unix://$CNISOCK" "$@" 2> "$WORKDIR/crictl.err"; }
    ready () { cn info | python3 -I -c 'import json, sys; print([c["status"] for c in json.load(sys.stdin)["status"]["conditions"] if c["type"] == "NetworkReady"][0])'; }
    check "no CNI configuration: the network is not ready" False "$(ready)"
    echo '{"cniVersion":"1.1.0","name":"testnet","plugins":[{"type":"testplugin","capabilities":{"bandwidth":true,"ipRanges":true,"io.kubernetes.cri.pod-annotations":true}}]}' > "$WORKDIR/cni/conf/10-test.conflist"
    check "a configuration: the network is ready" True "$(ready)"
    check_match "the plugin was asked STATUS" "^STATUS " "$(cat "$WORKDIR/cni/log")"
    touch "$WORKDIR/cni/notready"
    check "the plugin says it is not ready: the network is not" False "$(ready)"
    check_match "and why" "the plugin is not ready" "$(cn info | python3 -I -c 'import json, sys; print([c["message"] for c in json.load(sys.stdin)["status"]["conditions"] if c["type"] == "NetworkReady"][0])')"
    rm "$WORKDIR/cni/notready"
    check "ready again" True "$(ready)"
    cn update-runtime-config --pod-cidr 10.99.0.0/24 > /dev/null
    check "the pod CIDR is accepted" 0 $?
    cn update-runtime-config --pod-cidr nonsense > /dev/null 2>&1
    check "a pod CIDR that is no network is refused" 1 $(( $? != 0 ? 1 : 0 ))

    cat > "$WORKDIR/cpod.json" <<JSON
{"metadata": {"name": "cnipod", "namespace": "default", "uid": "u7", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "labels": {"io.kubernetes.pod.name": "cnipod", "io.kubernetes.pod.namespace": "default", "io.kubernetes.pod.uid": "u7"},
 "annotations": {"kubernetes.io/egress-bandwidth": "10M", "example.com/note": "hello"},
 "port_mappings": [{"protocol": 0, "container_port": 80, "host_port": 18080}]}
JSON
    cat > "$WORKDIR/cctr.json" <<JSON
{"metadata": {"name": "cnictr"}, "image": {"image": "$IMAGE"}, "log_path": "cnictr.log", "command": ["sleep", "300"]}
JSON
    pod=$(cn runp "$WORKDIR/cpod.json")
    check "runp on the CNI network" 0 $?
    check "the pod IP is the address of the plugin" 10.99.0.7 \
        "$(cn inspectp "$pod" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["status"]["network"]["ip"])')"
    check_match "the plugin was told the pod" "K8S_POD_NAME=cnipod;.*K8S_POD_NAMESPACE=default|K8S_POD_NAMESPACE=default;K8S_POD_NAME=cnipod" "$(cat "$WORKDIR/cni/log")"
    check_match "the plugin got the bandwidth of the annotation" '"egressRate":10000000' "$(cat "$WORKDIR/cni/log")"
    check_match "the plugin got the pod CIDR" '"ipRanges":\[\[\{"subnet":"10.99.0.0/24"\}\]\]' "$(cat "$WORKDIR/cni/log")"
    check_match "the plugin got the annotations of the pod" '"example.com/note":"hello"' "$(cat "$WORKDIR/cni/log")"
    info=$(cn inspectp "$pod" | python3 -I -c 'import json, sys; i = json.load(sys.stdin)["info"]; print(i["pid"], i["netnsPath"], i["network"], i["runtimeType"])')
    check_match "the verbose status of the sandbox: its process, namespace, network and runtime" "^[1-9][0-9]* /proc/[0-9]+/ns/net cni:( |$)" "$info"
    ctr=$(cn create "$pod" "$WORKDIR/cctr.json" "$WORKDIR/cpod.json")
    cn start "$ctr" > /dev/null
    check "start" 0 $?
    check_match "the container has the address" "10.99.0.7/24" "$(cn exec -s "$ctr" ip -o addr)"
    cn stop "$ctr" > /dev/null
    cn rm "$ctr" > /dev/null
    cn stopp "$pod" > /dev/null
    cn rmp "$pod" > /dev/null
    check_match "the plugin was run for DEL" "^DEL " "$(cat "$WORKDIR/cni/log")"
    check "and the cache of the result is empty" "" "$(ls "$WORKDIR/cni/cache/results" 2> /dev/null)"
    kill -INT "$CNI_CRI_PID" 2> /dev/null
    wait "$CNI_CRI_PID" 2> /dev/null
    CNI_CRI_PID=
}

@test "pods on the reference CNI plugins: the pod CIDR is the range, the bandwidth is applied, root only" {
    [ -x "${VELARX_CNI_PLUGINS:-/nonexistent}/bridge" ] || skip "VELARX_CNI_PLUGINS has no containernetworking plugins"
    command -v tc > /dev/null || skip "no tc"
    # (the engine of this file has the directory of the plugins in its bin_dirs)
    rm -f "$WORKDIR/cni/conf/"*
    local bridge='{"type":"bridge","bridge":"vxcni0","isGateway":true,"ipMasq":false,"capabilities":{"ipRanges":true},"ipam":{"type":"host-local","dataDir":"'$WORKDIR'/cni/ipam"}}'
    echo '{"cniVersion":"1.1.0","name":"refnet","plugins":['"$bridge"',{"type":"bandwidth","capabilities":{"bandwidth":true}}]}' > "$WORKDIR/cni/conf/20-ref.conflist"
    export REFSOCK=$WORKDIR/ref-cri.sock
    "$BIN/velarx-cri" --socket "$REFSOCK" --engine-socket "$ESOCK" \
        --pod-network cni:refnet > "$WORKDIR/ref-cri.log" 2>&1 3>&- &
    REF_CRI_PID=$!
    export REF_CRI_PID
    local i
    e2e_wait_path "$REFSOCK"
    rf () { crictl --timeout 120s -r "unix://$REFSOCK" -i "unix://$REFSOCK" "$@" 2> "$WORKDIR/crictl.err"; }
    check "the reference plugins say the network is ready (STATUS)" True \
        "$(rf info | python3 -I -c 'import json, sys; print([c["status"] for c in json.load(sys.stdin)["status"]["conditions"] if c["type"] == "NetworkReady"][0])')"
    cat > "$WORKDIR/rpod.json" <<JSON
{"metadata": {"name": "refpod", "namespace": "default", "uid": "u8", "attempt": 0},
 "log_directory": "$WORKDIR/logs",
 "labels": {"io.kubernetes.pod.name": "refpod", "io.kubernetes.pod.namespace": "default", "io.kubernetes.pod.uid": "u8"},
 "annotations": {"kubernetes.io/egress-bandwidth": "10M"}}
JSON
    rf update-runtime-config --pod-cidr 10.88.77.0/24 > /dev/null
    pod=$(rf runp "$WORKDIR/rpod.json")
    [ -n "$pod" ] || { echo "FAIL runp with the pod CIDR of the node: $(grep -v "level=warning" "$WORKDIR/crictl.err")" >&2; exit 1; }
    check_match "the pod IP is in the pod CIDR" "^10\\.88\\.77\\." \
        "$(rf inspectp "$pod" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["status"]["network"]["ip"])')"
    check_match "the bandwidth plugin limited the pod" "tbf|ifb" "$(tc qdisc show; ip -o link)"
    rf stopp "$pod" > /dev/null
    rf rmp "$pod" > /dev/null
    # a bandwidth the plugins of the network cannot apply is refused, not ignored
    echo '{"cniVersion":"1.1.0","name":"refnet","plugins":['"$bridge"']}' > "$WORKDIR/cni/conf/20-ref.conflist"
    out=$(rf runp "$WORKDIR/rpod.json" 2>&1)
    check "a bandwidth no plugin applies: refused" 1 $(( $? != 0 ? 1 : 0 ))
    check_match "and why" "bandwidth. capability" "$(cat "$WORKDIR/crictl.err") $out"
    ip link del vxcni0 2> /dev/null
    kill -INT "$REF_CRI_PID" 2> /dev/null
    wait "$REF_CRI_PID" 2> /dev/null
    REF_CRI_PID=
}

@test "a runtime handler of the engine" {
    # a runtime handler of the engine's [runtimes]: the sandbox and its containers use it
    check "the handlers are the default one, its name and the runtimes of the engine" ",crun,logged" \
        "$(cc info | python3 -I -c 'import json, sys; print(",".join(h.get("name", "") for h in json.load(sys.stdin)["runtimeHandlers"]))')"
    pod2=$(cc runp --runtime logged "$WORKDIR/pod.json")
    check "runp with a runtime handler" 0 $?
    infra=$(cc inspectp "$pod2" | python3 -I -c 'import sys, json; print(json.load(sys.stdin)["status"]["runtimeHandler"])')
    check "the sandbox says its handler" logged "$infra"
    check "the runtime made the infra container" yes "$(grep -q 'create' "$WORKDIR/runtime.log" && echo yes)"
    cc runp --runtime nosuchhandler "$WORKDIR/pod.json" > /dev/null 2>&1
    check "an unknown handler is refused" 1 $(( $? != 0 ? 1 : 0 ))
    cc stopp "$pod2" > /dev/null
    cc rmp "$pod2" > /dev/null
    check "and it is removed" "" "$(cc pods -q)"
    check "no pods left" "" "$(cc pods -q)"
}

@test "remove the image" {
    cc rmi "$IMAGE" > /dev/null
    check "rmi" 0 $?
}

@test "the frontend ends when the engine is gone" {
    # it cannot start an engine again (it confined itself), so it ends and the
    # unit that runs it starts it again once the engine socket is back (a
    # frontend that stays answers Unavailable for ever)
    . "$E2E_DIR/cleanup.sh"
    local engine; engine=$(cat "$WORKDIR/daemon.pid")
    kill -INT "$engine" 2> /dev/null
    tail --pid="$engine" -f /dev/null
    cc pods > /dev/null 2>&1
    check "the call fails" 1 $(( $? != 0 ? 1 : 0 ))
    timeout 30 tail --pid="$CRI_PID" -f /dev/null
    check "the frontend ended" 0 $?
    check "it said why" yes "$(grep -q 'engine is gone\|can no longer be reached' "$WORKDIR/cri.log" && echo yes)"
}
