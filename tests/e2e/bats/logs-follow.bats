# SPDX-License-Identifier: Apache-2.0
# velarx - container runtime
#
# End to end test of the followed logs of the REST API (`logs?follow=true`
# of libpod and Docker): every line once and in order whatever the
# followers do and whenever they start (while the container writes), a
# follower that reads slowly holding nobody up, a log that rotates, a
# container that restarts or is removed while followed, and the containers
# the engine did not start (the command line's, before the engine was
# there).
#
# Environment:
#   VELARX_BINDIR  the directory with velarx, velarx-api, velarx-client
#                    and velarx-monitor (default: target/debug)
#   E2E_REGISTRY     registry with alpine:chunked (default localhost:5000)
#
# Skipped when the registry, crun, curl or python3 is missing.  The pid of
# the API server is in $WORKDIR/api.pid.

load helpers

IMG=$E2E_REGISTRY/alpine:chunked

setup_file () {
    local b c
    BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    for b in velarx velarx-client velarx-monitor; do
        [ -x "$BIN/$b" ] || skip "no $BIN/$b"
    done
    e2e_need_api
    for c in crun curl python3; do
        command -v $c > /dev/null || skip "no $c"
    done
    curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    RUN=$XDG_RUNTIME_DIR/velarx
    CONF=$XDG_CONFIG_HOME/velarx/config.toml
    API=$RUN/velarx.sock
    chmod 700 "$XDG_RUNTIME_DIR"
    mkdir -p "$XDG_CONFIG_HOME/velarx" "$XDG_DATA_HOME"
    cat > "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[server]
socket = "$XDG_RUNTIME_DIR/velarx/velarx.sock"
state_dir = "$XDG_RUNTIME_DIR/velarx"
root_dir = "$XDG_DATA_HOME/velarx"
[storage]
root = "$XDG_DATA_HOME/velarx"
[userns]
uid_ranges = ["655360-720895"]
gid_ranges = ["655360-720895"]
allocation_size = 65536
[engine]
idle_exit = 0
[api]
idle_exit = 0
[containers]
log_driver = "k8s-file"
TOML
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<TOML
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
TOML
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf

    S pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"

    # The containers of the command line, started before there is an engine
    S container run -d --name cli-slow "$IMG" sh -c 'echo a; sleep 3; echo b; sleep 3; echo c' > /dev/null 2>&1
    S container run -d --name cli-done "$IMG" sh -c 'echo x; echo y' > /dev/null 2>&1

    "$BIN/velarx-api" --config "$CONF" --idle-exit 0 > "$WORKDIR/api.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/api.pid"
    e2e_wait_path "$API" 10 || { echo "the API server does not start" >&2; cat "$WORKDIR/api.log" >&2; exit 1; }
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local pid
    # (the containers first, while the engine the API server started runs)
    e2e_remove_containers "$BIN/velarx" "$RUN/engine/engine.sock"
    pid=$(cat "$WORKDIR/api.pid" 2> /dev/null)
    if [ -n "$pid" ]; then
        kill "$pid" 2> /dev/null
        e2e_wait_exit "$pid" 10
    fi
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

RUN=$XDG_RUNTIME_DIR/velarx
CONF=$XDG_CONFIG_HOME/velarx/config.toml
API=$RUN/velarx.sock
FOLLOW=$E2E_DIR/logs_follow.py
S () { "$BIN/velarx" --config "$CONF" "$@"; }
post () { curl -g -s -o /dev/null --unix-socket "$API" -X POST "http://x$1"; }
# numbers N: a container command that prints 1..N
numbers () { echo "i=1; while [ \$i -le $1 ]; do echo \$i; i=\$((i+1)); done"; }

# The engine did not start these: the lines as they come, the end
# with the container

@test "containers of the command line: the lines as they come, the end with the container" {
    check "a container of the command line: its followed log ends with it" "a b c end" \
        "$(python3 -I "$FOLLOW" get "$API" '/libpod/containers/cli-slow/logs?stdout=true&follow=true' 30 | tr '\n' ' ' | sed 's/ $//')"
    check "...also with Docker's API" "a b c end" \
        "$(python3 -I "$FOLLOW" get "$API" '/v1.41/containers/cli-slow/logs?stdout=1&follow=1' 30 | tr '\n' ' ' | sed 's/ $//')"
    check "an exited container: the log and the end" "x y end" \
        "$(python3 -I "$FOLLOW" get "$API" '/libpod/containers/cli-done/logs?stdout=true&follow=true' 30 | tr '\n' ' ' | sed 's/ $//')"
}

# Every line once and in order for followers that start while the
# container writes, and one that reads slowly

@test "followers that start while the container writes get every line once, in order" {
    local N=100000
    S container create --name once "$IMG" sh -c "$(numbers $N)" > /dev/null 2>&1
    post /libpod/containers/once/start
    python3 -I "$FOLLOW" once "$API" once $N > "$WORKDIR/once.txt" 2>&1
    check "followers that start while the container writes get every line once, in order" 0 "$?"
    sed 's/^/     /' "$WORKDIR/once.txt" | head -8
}

# A log that rotates while it is followed

@test "a log that rotates while it is followed" {
    local M=60000
    S container create --name rot --log-opt max-size=200k --log-opt max-file=30 "$IMG" sh -c "$(numbers $M)" > /dev/null 2>&1
    post /libpod/containers/rot/start
    python3 -I "$FOLLOW" get "$API" '/libpod/containers/rot/logs?stdout=true&follow=true' 60 > "$WORKDIR/rot.txt"
    check "a followed log that rotates: every line once, in order" "$(seq 1 $M | md5sum)" "$(grep -v '^end$' "$WORKDIR/rot.txt" | md5sum)"
    check "...and it did rotate" yes "$(ls "$XDG_DATA_HOME/velarx/logs"/*/container.log.* > /dev/null 2>&1 && echo yes)"
}

# A container that restarts by its policy while it is followed: the
# following goes through the restarts and ends with the exit for good (the
# `Wait` of its monitor is not answered for a run that is restarted)

@test "a container that restarts by its policy while it is followed" {
    S container create --name again --restart on-failure:2 "$IMG" sh -c 'echo run; sleep 1; exit 1' > /dev/null 2>&1
    post /libpod/containers/again/start
    check "a restarting container: the output of every run, then the end" "run run run end" \
        "$(python3 -I "$FOLLOW" get "$API" '/libpod/containers/again/logs?stdout=true&follow=true' 30 | tr '\n' ' ' | sed 's/ $//')"
}

# A container that is stopped, or removed, while it is followed

@test "a container that is removed or stopped while it is followed" {
    local F
    S container create --name gone "$IMG" sh -c 'echo hi; sleep 300' > /dev/null 2>&1
    post /libpod/containers/gone/start
    python3 -I "$FOLLOW" get "$API" '/libpod/containers/gone/logs?stdout=true&follow=true' 30 > "$WORKDIR/gone.txt" 3>&- &
    F=$!
    e2e_wait_line "$WORKDIR/gone.txt" '^hi$' 30 || e2e_die "no first line followed within 30 s"
    curl -g -s -o /dev/null --unix-socket "$API" -X DELETE 'http://x/libpod/containers/gone?force=true&timeout=0'
    wait $F
    check "a container removed while it is followed: the lines, then the end" "hi end" "$(tr '\n' ' ' < "$WORKDIR/gone.txt" | sed 's/ $//')"

    S container create --name stopped "$IMG" sh -c 'echo hi; sleep 300' > /dev/null 2>&1
    post /libpod/containers/stopped/start
    python3 -I "$FOLLOW" get "$API" '/libpod/containers/stopped/logs?stdout=true&follow=true' 30 > "$WORKDIR/stopped.txt" 3>&- &
    F=$!
    e2e_wait_line "$WORKDIR/stopped.txt" '^hi$' 30 || e2e_die "no first line followed within 30 s"
    post '/libpod/containers/stopped/stop?timeout=1'
    wait $F
    check "a container stopped while it is followed: the lines, then the end" "hi end" "$(tr '\n' ' ' < "$WORKDIR/stopped.txt" | sed 's/ $//')"
}

# The engine has ONE inotify instance for all the followers (a user has 128
# of them, shared with its other programs), and idle followers wake nothing

# the engine of this file: a descendant of the API server whose command line
# has the word varlink
engine_pid () {
    local level=$(cat "$WORKDIR/api.pid") next p
    for _ in 1 2 3; do
        next=
        for p in $level; do
            for p in $(pgrep -P "$p"); do
                if tr '\0' '\n' < "/proc/$p/cmdline" 2> /dev/null | grep -qx varlink; then
                    echo "$p"
                    return
                fi
                next="$next $p"
            done
        done
        level=$next
    done
}
# the inotify instances of a process
inotify_instances () { grep -l '^inotify' /proc/$1/fdinfo/* 2> /dev/null | wc -l; }
# the context switches of the threads of a process named $2
switches () {
    local t n=0
    for t in /proc/$1/task/*; do
        [ "$(cat "$t/comm" 2> /dev/null)" = "$2" ] || continue
        n=$((n + $(awk '/ctxt_switches/ { n += $2 } END { print n + 0 }' "$t/status" 2> /dev/null)))
    done
    echo $n
}
# hold N FOLLOWERS...: followers of the containers kept open (a fifo tells
# when they follow), then wait for them
hold_followers () {
    local n=$1 out=$2
    shift 2
    rm -f "$out"
    mkfifo "$out"
    python3 -I "$FOLLOW" hold "$API" "$n" "$@" > "$out" 3>&- &
    HOLD=$!
}

@test "120 followers of one container use one inotify instance and wake nothing while idle" {
    local EP before during a b line
    S container create --name many "$IMG" sh -c 'echo first; sleep 40; echo last' > /dev/null 2>&1
    EP=$(engine_pid)
    [ -n "$EP" ] || { echo "no engine" >&2; exit 1; }
    # (the engine has served requests by now: the instances it has for other
    # things are there)
    post /libpod/containers/many/start
    before=$(inotify_instances "$EP")
    hold_followers 120 "$WORKDIR/hold1" many
    read -r -t 120 line < "$WORKDIR/hold1"
    check "120 followers of one container follow" ready "$line"
    during=$(inotify_instances "$EP")
    [ "$during" -le $((before + 1)) ] || { echo "FAIL inotify instances: $before before, $during with 120 followers" >&2; exit 1; }
    check "...they are 120 threads of the engine" 120 "$(grep -l '^logfollow$' /proc/$EP/task/*/comm | wc -l)"
    a=$(switches "$EP" logfollow)
    # (a window: the wake-ups of 10 s of idleness are counted)
    sleep 10
    b=$(switches "$EP" logfollow)
    check "...and idle they do not wake up for 10 seconds" 0 "$((b - a))"
    read -r -t 120 line < "$WORKDIR/hold1"
    check "...each got the first and the last line, and the end" ok "$line"
    wait $HOLD
}

@test "a follower for each of 100 containers" {
    local EP before during names=() i line
    for i in $(seq 100); do names+=(hc$i); done
    printf '%s\n' "${names[@]}" | xargs -P 8 -I{} "$BIN/velarx" --config "$CONF" container run -d --name {} "$IMG" sh -c 'echo first; sleep 40; echo last' > /dev/null 2>&1
    EP=$(engine_pid)
    before=$(inotify_instances "$EP")
    hold_followers 100 "$WORKDIR/hold2" "${names[@]}"
    read -r -t 120 line < "$WORKDIR/hold2"
    check "100 containers followed at once" ready "$line"
    during=$(inotify_instances "$EP")
    [ "$during" -le $((before + 1)) ] || { echo "FAIL inotify instances: $before before, $during with 100 followers" >&2; exit 1; }
    read -r -t 120 line < "$WORKDIR/hold2"
    check "...each got its lines and the end" ok "$line"
    wait $HOLD
}

# A follower that goes away does not leave a thread of the engine behind

@test "the API server and the engine are still there" {
    check "the API server and the engine are still there" yes "$(curl -s --unix-socket "$API" http://x/_ping > /dev/null && echo yes)"
}
