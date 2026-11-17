# SPDX-License-Identifier: Apache-2.0
# Run podman's system tests (test/system/*.bats of a podman checkout) in
# remote mode against velarx-api, the REST server in front of the engine.
#
#   PODMAN_SRC=/path/to/podman bats tests/e2e/bats/podman-system.bats
#   PODMAN_SYSTEM_FILES="030-run 040" PODMAN_SRC=... bats ...
#   E2E_MODE=cli PODMAN_SRC=/path/to/podman bats tests/e2e/bats/podman-system.bats
#
# E2E_MODE=cli runs the suite in its local mode with velarx's own command
# line as $PODMAN: velarx ARGS... with the private config, and a
# velarx-api of the run on a private socket for what needs one; the suite's
# prefetch pulls its images with velarx.
#
# PODMAN_SYSTEM_FILES selects .bats files by name or prefix ("030-run",
# "040"); all of them by default.  The suite runs unchanged and read-only from
# PODMAN_SRC, each file in a bats of its own, with PODMAN pointing at a
# podman-remote shim; only its plumbing is redirected:
#
#   podman-remote ARGS...
#       runs podman-remote ARGS... (podman --remote without it; the suite
#       adds the --url of its socket)
#   podman system service unix://SOCK --time=0
#       (the suite's start-suite-podman-system-service) runs velarx-api (which
#       starts the engine on its own socket) serving the API on SOCK, with a
#       private config, store and runtime dir; the suite kills it at its end
#   podman ARGS...
#       (the few local commands of the suite) runs the local podman, whose
#       store is the private one of HOME
#   skopeo copy --all oci-archive:CACHE containers-storage:NAME
#       (the suite's prefetch of its images into the store a remote podman
#       shares with the local one) pulls NAME into velarx's store
#
# The binaries are those of VELARX_BINDIR (default: the dev build of
# CARGO_TARGET_DIR or of target/).  The TAP output of each file goes to RESULTS (default: the
# work dir), with a summary line per file in RESULTS/summary.txt.
# SUMMARY_TSV=PATH appends a tab separated line per file to PATH, to compare
# runs: mode, file, pass, fail, skip, rc, seconds, commit of the daemon's
# checkout (E2E_COMMIT); the names of the failed tests go to PATH.failed
# (mode, file, test).
# E2E_KEEP=1 keeps the work dir.  The one test passes when no file of the
# suite had a failure.  Skipped when the suite, podman or bats is missing.

load helpers

# The containers outlive the engine (their monitors serve their root file
# systems): a velarx-api of our own starts an engine that removes those that
# are left.
remove_leftovers () {
    local pid i sock=$WORKDIR/cleanup.sock
    test -f "$CONFIG" || return 0
    # (the engine socket of a daemon that was killed stays: the wait is for the new one)
    rm -f "$sock" "$ESOCK"
    setsid "$API" --config "$CONFIG" --log-level warn --idle-exit 0 --listen "unix://$sock" \
        >> "$WORKDIR/daemon.log" 2>&1 3>&- &
    pid=$!
    e2e_wait_path "$sock" && e2e_wait_path "$ESOCK"
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
    local top_srcdir tool i
    top_srcdir=$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export DAEMON=${VELARX_DAEMON:-${VELARX_BINDIR:-${CARGO_TARGET_DIR:-$top_srcdir/target}/debug}/velarx}
    export CLI=${VELARX:-$(dirname "$DAEMON")/velarx}
    export API=${VELARX_API:-$(dirname "$DAEMON")/velarx-api}
    export SUITE=${PODMAN_SRC:-}/test/system
    test -x "$DAEMON" || skip "cannot find the engine at $DAEMON"
    test -x "$API" || skip "cannot find velarx-api at $API"
    if test -z "${PODMAN_SRC:-}" || ! test -f "$SUITE/helpers.bash"; then
        skip "set PODMAN_SRC to a podman checkout"
    fi
    for tool in podman bats; do
        command -v $tool > /dev/null || skip "$tool is missing"
    done
    export REAL_PODMAN; REAL_PODMAN=$(command -v podman)
    # the remote client as podman ships it, else podman --remote
    export REMOTE_CLIENT
    if command -v podman-remote > /dev/null; then
        REMOTE_CLIENT=$(command -v podman-remote)
    else
        REMOTE_CLIENT="$REAL_PODMAN --remote"
    fi
    export MODE=${E2E_MODE:-remote}
    case "$MODE" in
    remote | cli) ;;
    *) echo "E2E_MODE is remote or cli" >&2; exit 1 ;;
    esac

    # lower case: the suite matches paths of the store with [a-z0-9/.-]
    export WORKDIR=${E2E_TMPDIR:-/var/tmp}/velarx-system.$(tr -dc a-z0-9 < /dev/urandom | head -c 8)
    mkdir -m 700 "$WORKDIR" || exit 1
    export RESULTS=${RESULTS:-$WORKDIR/results}
    mkdir -p "$WORKDIR/bin" "$WORKDIR/tmp" "$RESULTS"
    . "$E2E_DIR/cleanup.sh"

    export HOME=$WORKDIR/home
    export XDG_RUNTIME_DIR=$WORKDIR/run
    export XDG_CONFIG_HOME=$HOME/.config
    export XDG_DATA_HOME=$HOME/data
    mkdir -p "$XDG_CONFIG_HOME/velarx" "$XDG_RUNTIME_DIR"
    chmod 700 "$XDG_RUNTIME_DIR"
    # (the manager of the user, whose private socket the pods' slices are made on)
    ln -s "/run/user/$(id -u)/systemd" "$XDG_RUNTIME_DIR/systemd"
    export CONFIG=$XDG_CONFIG_HOME/velarx/config.toml
    export ESOCK=$WORKDIR/engine.sock
    cat > "$CONFIG" <<EOT
storage.root = "$XDG_DATA_HOME/velarx"
[engine]
socket = "$ESOCK"
[server]
state_dir = "$XDG_RUNTIME_DIR/velarx"
root_dir = "$XDG_DATA_HOME/velarx"
shutdown_timeout_secs = 5
[userns]
uid_ranges = ["655360-720895"]
gid_ranges = ["655360-720895"]
allocation_size = 65536
EOT

    local CLI_SOCK=$WORKDIR/cli.sock
    cat > "$WORKDIR/bin/podman-cli" <<EOT
#!/bin/bash
# velarx's command line as the suite's podman (E2E_MODE=cli): see
# $top_srcdir/tests/e2e/bats/podman-system.bats
exec "$CLI" --config "$CONFIG" "\$@"
EOT
    cat > "$WORKDIR/bin/podman-remote" <<EOT
#!/bin/bash
# podman-remote for podman's system tests: see $top_srcdir/tests/e2e/bats/podman-system.bats
exec $REMOTE_CLIENT "\$@"
EOT
    cat > "$WORKDIR/bin/podman" <<EOT
#!/bin/bash
# podman for podman's system tests: see $top_srcdir/tests/e2e/bats/podman-system.bats
if test "\${1:-} \${2:-}" = "system service"; then
    sock=
    for a in "\${@:3}"; do
        case "\$a" in
        unix://*) sock=\${a#unix://} ;;
        tcp://* | --tls*)
            echo "podman shim: velarx serves the system tests on a unix socket" >&2
            exit 125 ;;
        esac
    done
    test -n "\$sock" || { echo "podman shim: no socket" >&2; exit 125; }
    exec "$API" --config "$CONFIG" --log-level "${E2E_LOG_LEVEL:-info}" --idle-exit 0 \\
        --listen "unix://\$sock" >> "$WORKDIR/daemon.log" 2>&1
fi
exec "$REAL_PODMAN" "\$@"
EOT
    REAL_SKOPEO=$(command -v skopeo || echo skopeo)
    cat > "$WORKDIR/bin/skopeo" <<EOT
#!/bin/bash
# skopeo for podman's system tests: see $top_srcdir/tests/e2e/bats/podman-system.bats
# The suite loads its cached images into the local store, which a remote
# podman shares; velarx's store is its own: the image is pulled there.
if test "\${1:-} \${2:-}" = "copy --all" && test "\${4#containers-storage:}" != "\${4:-}"; then
    name=\${4#containers-storage:}
    # (the local mode names a store first: [driver@root+runroot]NAME)
    name=\${name#\[*\]}
    if test "$MODE" = cli; then
        exec "$WORKDIR/bin/podman-cli" pull -q "\$name"
    fi
    exec $REMOTE_CLIENT --url "unix://\$REMOTESYSTEM_UNIX_SOCK" pull -q "\$name"
fi
exec "$REAL_SKOPEO" "\$@"
EOT
    chmod +x "$WORKDIR/bin/podman" "$WORKDIR/bin/podman-remote" "$WORKDIR/bin/podman-cli" "$WORKDIR/bin/skopeo"
    export PATH=$WORKDIR/bin:$PATH

    if test "$MODE" = cli; then
        export PODMAN=$WORKDIR/bin/podman-cli
        "$API" --config "$CONFIG" --log-level "${E2E_LOG_LEVEL:-info}" --idle-exit 0 \
            --listen "unix://$CLI_SOCK" >> "$WORKDIR/daemon.log" 2>&1 3>&- &
        echo $! > "$WORKDIR/cli-service.pid"
        e2e_wait_path "$CLI_SOCK" && e2e_wait_path "$ESOCK"
        test -S "$CLI_SOCK" && test -S "$ESOCK" || { echo "velarx-api did not start" >&2; exit 1; }
    else
        export PODMAN=$WORKDIR/bin/podman-remote
        export REMOTESYSTEM_TRANSPORT=unix
    fi
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local pause cli_service
    cli_service=$(cat "$WORKDIR/cli-service.pid" 2> /dev/null)
    if test -n "$cli_service"; then
        kill -INT "$cli_service" 2> /dev/null
        e2e_wait_exit "$cli_service"
        kill -KILL "$cli_service" 2> /dev/null
    fi
    remove_leftovers
    e2e_detach_mounts "$WORKDIR"
    if test -n "${E2E_KEEP:-}"; then
        echo "# kept $WORKDIR" >&3
    else
        pause=$(cat "$XDG_RUNTIME_DIR/libpod/tmp/pause.pid" 2> /dev/null)
        chmod -R u+rwX "$WORKDIR" 2> /dev/null
        rm -rf "$WORKDIR" 2> /dev/null ||
            "$REAL_PODMAN" unshare rm -rf "$WORKDIR"
    fi
    # the pause process of the local podman of the suite
    kill_pid "${pause:-$(cat "$XDG_RUNTIME_DIR/libpod/tmp/pause.pid" 2> /dev/null)}"
}

@test "podman's system tests pass against velarx-api" {
    local files=() f name start rc pass skip fail failed=0
    if test -z "${PODMAN_SYSTEM_FILES:-}"; then
        files=("$SUITE"/[0-9][0-9][0-9]-*.bats)
    else
        for f in $PODMAN_SYSTEM_FILES; do
            files+=("$SUITE"/"$f"*.bats)
        done
    fi
    export TMPDIR=$WORKDIR/tmp
    echo "# velarx-api $API ($MODE mode), work dir $WORKDIR, results in $RESULTS" >&3
    cd "$WORKDIR/tmp" || exit 1
    for f in "${files[@]}"; do
        test -f "$f" || continue
        name=$(basename "$f" .bats)
        start=$(date +%s)
        # (a bats of its own: not inside the variables of this one)
        env $(printf -- '-u %s ' $(compgen -v BATS_ | grep -v -e '^BATS_ROOT$' -e '^BATS_LIBDIR$' -e '^BATS_LIBEXEC$')) BATS_TMPDIR="$WORKDIR/tmp" \
            timeout "${E2E_FILE_TIMEOUT:-3600}" bats -T --tap "$f" > "$RESULTS/$name.tap" 2>&1 3>&-
        rc=$?
        pass=$(grep -c '^ok ' "$RESULTS/$name.tap")
        skip=$(grep -c '^ok .* # skip' "$RESULTS/$name.tap")
        fail=$(grep -c '^not ok ' "$RESULTS/$name.tap")
        printf '%-32s pass %4d fail %4d skip %4d rc %3d %5ds\n' "$name" \
            $((pass - skip)) "$fail" "$skip" "$rc" $(($(date +%s) - start)) | tee -a "$RESULTS/summary.txt" | sed 's/^/# /' >&3
        if test -n "${SUMMARY_TSV:-}"; then
            printf '%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n' "$MODE" "$name" $((pass - skip)) "$fail" "$skip" "$rc" \
                $(($(date +%s) - start)) "${E2E_COMMIT:-}" >> "$SUMMARY_TSV"
            sed -n 's/^not ok [0-9]* //p' "$RESULTS/$name.tap" | sed 's/ in [0-9]*ms$//' |
                while IFS= read -r t; do printf '%s\t%s\t%s\n' "$MODE" "$name" "$t"; done >> "$SUMMARY_TSV.failed"
        fi
        if test "$fail" != 0 || test "$rc" != 0; then
            failed=$((failed + 1))
        fi
    done
    check "files of the suite with a failure" 0 $failed
}
