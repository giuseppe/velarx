# SPDX-License-Identifier: Apache-2.0
# Run podman's own REST API test suite (test/apiv2 of a podman checkout)
# against velarx-api, the REST server in front of the engine.
#
#   PODMAN_SRC=/path/to/podman bats tests/e2e/bats/podman-apiv2.bats
#   PODMAN_APIV2_GLOBS="10-images 20" PODMAN_SRC=... bats ...
#
# PODMAN_APIV2_GLOBS selects the .at files as test-apiv2 does ("10-images",
# "20"; all by default but 36-quadlets, which needs `podman quadlet install`
# and podman-remote does not have it).  The suite runs unchanged and read-only from
# PODMAN_SRC; only its plumbing is redirected, through PODMAN, a shim in place
# of the podman binary:
#
#   --root */server_root system service tcp:127.0.0.1:PORT
#       starts velarx-api (which starts the engine on its own socket) serving
#       the API on that port and on a unix socket, with a private config,
#       store and runtime dir; start_service and stop_service start and kill
#       it as they would podman
#   --root */server_root COMMAND...
#       (the podman() helper and the direct $PODMAN_BIN calls) runs
#       `podman --remote --url tcp://127.0.0.1:PORT COMMAND...`
#   --root */server_root --root DIR ...
#       (start_registry and stop_registry, a registry container in a private
#       store) runs the local podman with those arguments
#   unshare true
#       (start_service's rootless namespace warm up) does nothing
#   --root */server_root save ... (no --format), build --format=docker ...
#       save an oci-archive, build an OCI image: velarx writes no Docker format
#
# The containers.conf files that the suite names in the environment of a
# service start (the few it has) are translated to the velarx settings of the
# same meaning by tests/e2e/containers-conf-to-velarx.py: velarx reads only its
# own files.
#
# The binaries are those of VELARX_BINDIR (default: the dev build of
# CARGO_TARGET_DIR or of target/).  E2E_KEEP=1 keeps the work dir with the
# daemon log; APIV2_SUITE_LOG=FILE keeps the full log of the suite (a failure
# shows only its last lines).  The one test passes when test-apiv2 reports no
# failed check but those that podman-apiv2.skips lists, with their reasons
# (what velarx does not do on purpose, what a host decides).  Skipped when the
# suite, podman, curl or jq is missing.

load helpers

# A free port of the loopback interface.
free_port () {
    local port
    for port in $(shuf -i 20000-29999 -n 50); do
        if ! { exec 5<> /dev/tcp/127.0.0.1/$port; } 2> /dev/null; then
            echo $port
            return
        fi
        exec 5>&-
    done
    return 1
}

# The containers outlive the engine (their monitors serve their root file
# systems): a velarx-api of our own starts an engine that removes those that
# are left.
remove_leftovers () {
    local pid i
    # (the sockets of a daemon that was killed stay: the wait is for the new ones)
    rm -f "$SOCK" "$ESOCK"
    setsid "$API" --config "$XDG_CONFIG_HOME/velarx/config.toml" --log-level warn --idle-exit 0 \
        --listen "unix://$SOCK" >> "$WORKDIR/daemon.log" 2>&1 3>&- &
    pid=$!
    e2e_wait_path "$SOCK" && e2e_wait_path "$ESOCK"
    e2e_remove_containers "$CLI" "$ESOCK"
    # (the engine is of the same process group: both stop, else are killed)
    kill -INT -- "-$pid" 2> /dev/null
    e2e_wait_group "$pid" 10
    kill -KILL -- "-$pid" 2> /dev/null
}

# Kill the process of this user whose pid is in a file of the work dir.
kill_pid () {
    case "$1" in
    '' | *[!0-9]*) return 0 ;;
    esac
    if test "$(stat -c %u "/proc/$1" 2> /dev/null)" = "$(id -u)"; then
        kill "$1" 2> /dev/null
    fi
}

setup_file () {
    local top_srcdir tool
    top_srcdir=$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)
    export DAEMON=${VELARX_DAEMON:-${VELARX_BINDIR:-${CARGO_TARGET_DIR:-$top_srcdir/target}/debug}/velarx}
    export CLI=${VELARX:-$(dirname "$DAEMON")/velarx}
    export API=${VELARX_API:-$(dirname "$DAEMON")/velarx-api}
    export SUITE=${PODMAN_SRC:-}/test/apiv2/test-apiv2
    test -x "$DAEMON" || skip "cannot find the engine at $DAEMON"
    test -x "$API" || skip "cannot find velarx-api at $API"
    if test -z "${PODMAN_SRC:-}" || ! test -f "$SUITE"; then
        skip "set PODMAN_SRC to a podman checkout"
    fi
    for tool in podman curl jq; do
        command -v $tool > /dev/null || skip "$tool is missing"
    done
    export REAL_PODMAN; REAL_PODMAN=$(command -v podman)
    export PORT=${PODMAN_SERVICE_PORT:-$(free_port)}
    [ -n "$PORT" ] || { echo "no free port on 127.0.0.1" >&2; exit 1; }
    export CLOSED_PORT; CLOSED_PORT=$(free_port)
    [ -n "$CLOSED_PORT" ] && [ "$CLOSED_PORT" != "$PORT" ] || { echo "no second free port on 127.0.0.1" >&2; exit 1; }

    e2e_setup_file
    . "$E2E_DIR/cleanup.sh"
    # Every velarx command goes to the engine of the test (as --socket).
    export VELARX_SOCKET=$ESOCK
    mkdir -p "$WORKDIR/bin" "$WORKDIR/tmp"
    chmod 700 "$XDG_RUNTIME_DIR"
    # (the suite sends no token; the listener is on the loopback)
    printf '[api]\nallow_unauthenticated = true\n' >> "$XDG_CONFIG_HOME/velarx/config.toml"

    # test-apiv2 makes its work dir and log in TMPDIR
    export TMPDIR=$WORKDIR/tmp
    export PODMAN_SERVICE_PORT=$PORT
    export PODMAN=$WORKDIR/bin/podman

    cat > "$PODMAN" <<EOT
#!/bin/bash
# podman for test-apiv2: see $top_srcdir/tests/e2e/bats/podman-apiv2.bats
if test "\${1:-}" = unshare; then
    shift
    exec "\$@"
fi
if test "\${1:-}" != --root; then
    echo "podman shim: unexpected arguments: \$*" >&2
    exit 125
fi
case "\${2:-}" in
*/server_root) shift 2 ;;
*) exec "$REAL_PODMAN" "\$@" ;;
esac
if test "\${1:-}" = --root; then
    exec "$REAL_PODMAN" "\$@"
fi
if test "\${1:-}" = --syslog=true; then
    shift
fi
if test "\${1:-} \${2:-}" = "system service"; then
    for a; do
        case "\$a" in
        tcp:*) test "\$a" = "tcp:127.0.0.1:$PORT" || {
                echo "podman shim: the daemon serves tcp:127.0.0.1:$PORT, not \$a" >&2
                exit 125
            } ;;
        esac
    done
    # the suite mirrors docker.io/library to quay.io/libpod: the mirror goes
    # (docker.io/library is read from Docker Hub's mirror, as the suite's
    # docker.io prefix says); quay.io/libpod/alpine and busybox, Docker schema 2
    # images, are pulled as they are (the suite names its registries.conf in
    # podman's variable: velarx is told in its own)
    conf=\${CONTAINERS_REGISTRIES_CONF:-\${VELARX_REGISTRIES_CONF:-/nonexistent}}
    if test -r "\$conf"; then
        awk -v RS= -v ORS='\n\n' '!/quay\.io\/libpod/' "\$conf" > "$WORKDIR/registries.conf"
        # (a check pulls localhost:5000/idonotexist and expects nothing to
        # listen there, which a host may have: it goes to a port nothing
        # listens on)
        printf '[[registry]]\nprefix = "localhost:5000/idonotexist"\nlocation = "127.0.0.1:$CLOSED_PORT/idonotexist"\ninsecure = true\n' >> "$WORKDIR/registries.conf"
        export VELARX_REGISTRIES_CONF="$WORKDIR/registries.conf"
    fi
    # the containers.conf files the suite starts a service with are velarx settings
    config="$XDG_CONFIG_HOME/velarx/config.toml"
    files=()
    for f in "\${CONTAINERS_CONF:-}" "\${CONTAINERS_CONF_OVERRIDE:-}"; do
        test -n "\$f" && files+=("\$f")
    done
    if test \${#files[@]} != 0; then
        "$top_srcdir/tests/e2e/containers-conf-to-velarx.py" "\$config" "\${files[@]}" > "$WORKDIR/service.toml" || exit 125
        config="$WORKDIR/service.toml"
    fi
    exec "$API" --config "\$config" \\
        --log-level "${E2E_LOG_LEVEL:-info}" --idle-exit 0 --listen "unix://$SOCK" \\
        --listen "tcp://127.0.0.1:$PORT" >> "$WORKDIR/daemon.log" 2>&1
fi
# (velarx writes no Docker format: the docker-archive of podman's save without
# --format, and the images the suite builds in Docker's format, are OCI ones)
case "\${1:-} \${2:-}" in
"generate spec")
    # (podman-remote cannot run it: the spec of a container the suite makes a
    # container of is its image, that of a pod is empty; -c is --compact)
    shift 2
    file= name=
    while test \$# -gt 0; do
        case "\$1" in
        -f) file=\$2; shift 2 ;;
        -c | --compact) shift ;;
        *) name=\$1; shift ;;
        esac
    done
    if "$REAL_PODMAN" --remote --url "tcp://127.0.0.1:$PORT" container exists "\$name"; then
        image=\$("$REAL_PODMAN" --remote --url "tcp://127.0.0.1:$PORT" inspect --format '{{.ImageName}}' "\$name") || exit \$?
        printf '{"image":"%s"}\n' "\$image" > "\$file"
    else
        echo '{}' > "\$file"
    fi
    exit 0 ;;
"save "*)
    case " \$* " in
    *" --format"*) ;;
    *) shift; set -- save --format oci-archive "\$@" ;;
    esac ;;
"build "* | "image build")
    args=()
    for a; do
        test "\$a" = --format=docker && a=--format=oci
        args+=("\$a")
    done
    set -- "\${args[@]}" ;;
esac
exec "$REAL_PODMAN" --remote --url "tcp://127.0.0.1:$PORT" "\$@"
EOT
    chmod +x "$PODMAN"

    E2E_PROCESSES_BEFORE=$(e2e_count_processes "$WORKDIR")
    test "$E2E_PROCESSES_BEFORE" = 0 || echo "# $E2E_PROCESSES_BEFORE processes of $WORKDIR before the start" >&3
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local pause
    remove_leftovers
    e2e_detach_mounts "$WORKDIR"
    if test -n "${E2E_KEEP:-}"; then
        echo "# kept $WORKDIR" >&3
    else
        pause=$(cat "$XDG_RUNTIME_DIR/libpod/tmp/pause.pid" 2> /dev/null)
        chmod -R u+rwX "$WORKDIR" 2> /dev/null
        # the registry's store has files of its user namespace
        rm -rf "$WORKDIR" 2> /dev/null ||
            "$REAL_PODMAN" unshare rm -rf "$WORKDIR"
    fi
    # the pause process of the registry's podman
    kill_pid "${pause:-$(cat "$XDG_RUNTIME_DIR/libpod/tmp/pause.pid" 2> /dev/null)}"
    if test -z "${E2E_KEEP:-}"; then
        e2e_check_left "$WORKDIR" || return 1
    fi
}

@test "podman's test-apiv2 suite passes against velarx-api" {
    echo "# velarx-api $API on tcp:127.0.0.1:$PORT, work dir $WORKDIR" >&3
    # some tests make directories in the current one
    cd "$WORKDIR/tmp" || exit 1
    local globs=${PODMAN_APIV2_GLOBS:-}
    if test -z "$globs"; then
        globs=$(cd "$(dirname "$SUITE")" && ls *.at | grep -v '^36-quadlets' | sed 's/\.at$//')
    fi
    PODMAN_TESTS_KEEP_WORKDIR=${E2E_KEEP:-} bash "$SUITE" $globs 3>&- > "$WORKDIR/suite.log" 2>&1
    rc=$?
    if test -n "${APIV2_SUITE_LOG:-}"; then
        cp "$WORKDIR/suite.log" "$APIV2_SUITE_LOG"
    fi
    # the checks that fail on purpose are in podman-apiv2.skips: a failed
    # check it does not list, and a line of it that matches no failed check
    # of the files that ran, fail the test; the suite exits with the number
    # of the checks that failed
    local report status=0 failed
    report=$(python3 -I "$E2E_DIR/apiv2-unexpected.py" "$WORKDIR/suite.log" "$E2E_DIR/podman-apiv2.skips") || status=$?
    failed=$(grep -c '^not ok ' "$WORKDIR/suite.log")
    if [ "$status" != 0 ]; then
        printf '%s\n' "$report" >&2
        tail -n 60 "$WORKDIR/suite.log" >&2
    fi
    check "test-apiv2: no unexpected failure and no stale skip" 0 "$status"
    # (a suite that stopped before its end, or did not run)
    check "test-apiv2: the exit status is the number of failed checks" "$failed" "$rc"
}
