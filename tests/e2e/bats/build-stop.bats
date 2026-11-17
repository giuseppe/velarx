# SPDX-License-Identifier: Apache-2.0
# A build that stops in the middle of a RUN step leaves no process: the
# engine service that ends (SIGINT) while it builds, and `velarx build` in
# an engine of its own interrupted with ^C (the test after the service
# ended), end the RUN container (its
# process, its monitor, its network) and remove it.  Through the
# REST API, a build whose client leaves is stopped, as podman's: one that
# waits for its turn frees its place, one that runs ends its RUN step.
# Rootless, no
# registry: the base is an image of host binaries.

load helpers
load wait

setup_file () {
    e2e_setup_file
    e2e_start_daemon
    e2e_make_image
    export CTX=$WORKDIR/ctx
    mkdir -p "$CTX"
    printf 'FROM %s\nRUN echo running; sleep 600\n' "$IMG" > "$CTX/Containerfile"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    e2e_teardown_file
}

# wait_run_step LOG [PATTERN]: until the RUN step of the build writing LOG
# runs (its output, PATTERN, is there), and print the pid of its container.
wait_run_step () {
    local pattern=${2:-^running}
    e2e_wait_line "$1" "$pattern" 30 || true
    grep -q "$pattern" "$1" || e2e_die "the RUN step did not start: $(cat "$1")"
    "$SH" ps -a --filter label=io.velarx.build --format '{{.Pid}}'
}

@test "the engine service that ends mid-RUN stops the build: no process of it is left" {
    local log=$WORKDIR/service-build.log pid build daemon
    sc build -t localhost/stop:service "$CTX" > "$log" 2>&1 &
    build=$!
    pid=$(wait_run_step "$log")
    [ -n "$pid" ] && [ "$pid" != 0 ] || e2e_die "no RUN container: $(sc ps -a 2>&1)"
    daemon=$(cat "$WORKDIR/daemon.pid")
    kill -INT "$daemon"
    e2e_wait_exit "$daemon" 10
    wait "$build"
    check_match "the build fails" "^[1-9]" "$?"
    . "$E2E_DIR/cleanup.sh"
    e2e_check_left "$WORKDIR" || e2e_die "processes of the build are left"
    kill -0 "$pid" 2> /dev/null
    check "the RUN process is gone" 1 $?
    # (the engine of the command, from now on)
    rm -f "$WORKDIR/daemon.pid"
    check "no container is left" "" "$("$SH" ps -a --format '{{.ID}}' 2>&1)"
}

@test "velarx build in an engine of its own, interrupted: no process of it is left" {
    local log=$WORKDIR/own-build.log pid build
    # (no socket: the command is its own engine)
    VELARX_SOCKET= "$SH" build -t localhost/stop:own "$CTX" > "$log" 2>&1 &
    build=$!
    pid=$(wait_run_step "$log")
    [ -n "$pid" ] && [ "$pid" != 0 ] || e2e_die "no RUN container: $(sc ps -a 2>&1)"
    kill -INT "$build"
    wait "$build"
    check_match "the build fails" "^[1-9]" "$?"
    kill -0 "$pid" 2> /dev/null
    check "the RUN process is gone" 1 $?
    check "no container is left" "" "$("$SH" ps -a --format '{{.ID}}' 2>&1)"
}

# post_build [CURL ARGS...]: POST /build of the REST API with the context;
# only in a subshell (`&`, `$(...)`): curl takes its place, so that a kill
# of `$!` is a kill of the client
post_build () {
    exec curl -sN --unix-socket "$SOCK" -X POST -H 'Content-Type: application/x-tar' \
        --data-binary "@$WORKDIR/ctx.tar" "$@" 'http://d/v1.41/build?t=localhost/stop:rest'
}

@test "REST: a build whose client leaves is stopped, waiting or running" {
    command -v curl > /dev/null || skip "no curl"
    # (the engine of the file, if it runs, without the settings below)
    local pid
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -n "$pid" ]; then
        kill -INT "$pid"
        e2e_wait_exit "$pid" 60 || e2e_die "the engine of the file does not leave"
    fi
    printf '[build]\nmax_concurrent = 1\nmax_pending = 2\n' >> "$XDG_CONFIG_HOME/velarx/config.toml"
    e2e_start_daemon
    e2e_start_api
    tar -C "$CTX" -cf "$WORKDIR/ctx.tar" .
    local a b code i pid
    post_build > "$WORKDIR/rest-a.log" &
    a=$!
    pid=$(wait_run_step "$WORKDIR/rest-a.log" '"running')
    [ -n "$pid" ] && [ "$pid" != 0 ] || e2e_die "no RUN container: $(sc ps -a 2>&1)"
    # B waits for A's turn, then its client goes.  (Taken before the third is
    # tried: a third that came first would take B's place, B would be the one
    # refused, and each later try would be taken again once the one before
    # left.)
    post_build -D "$WORKDIR/rest-b.headers" > /dev/null &
    b=$!
    e2e_wait_line "$WORKDIR/rest-b.headers" '^HTTP/[0-9.]+ 200' 60 ||
        e2e_die "B is not taken: $(cat "$WORKDIR/rest-b.headers" 2> /dev/null)"
    # (a retry of the request: the answer is the state of the queue, no notification)
    for i in $(seq 50); do
        code=$(post_build -o /dev/null -w '%{http_code}' --max-time 1)
        [ "$code" = 503 ] && break
        sleep 0.1
    done
    check "A runs and B waits: a third build is refused" 503 "$code"
    kill "$b"
    wait "$b"
    # (a retry of the request: the place of B is freed when the server sees its client
    # go, which is not notified)
    for i in $(seq 50); do
        code=$(post_build -o /dev/null -w '%{http_code}' --max-time 1)
        [ "$code" != 503 ] && break
        sleep 0.1
    done
    check "B is dropped: another build is taken" 200 "$code"
    # (podman: the context of the request ends the build)
    kill "$a"
    wait "$a"
    e2e_wait_exit "$pid"
    check "A's client left: its RUN process is gone" gone "$(e2e_alive "$pid")"
    # (the build removes its container after the process went)
    e2e_wait_no_containers 30
    check "no container is left" "" "$("$SH" ps -a --format '{{.ID}}' 2>&1)"
}
