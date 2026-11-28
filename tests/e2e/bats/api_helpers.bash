# SPDX-License-Identifier: Apache-2.0
# Shared setup of the end to end tests of the REST API
# (api/*.bats): velarx driven by a podman remote client (and the docker CLI
# when there is one).  Load it after helpers:
#
#   load ../helpers
#   load ../api_helpers
#   setup_file () { api_setup_file; }
#   teardown_file () { api_teardown_file; }
#
# (the default setup and teardown below make the checks soft; a file that
# needs more defines its own setup: set +e; E2E_FAILS=0; api_state_load.)
#
# PODMAN_REMOTE is the client command (default: `podman-remote` or
# `podman --remote`, any podman >= 4 works).  The containers run an image of
# the registry of the e2e tests (E2E_REGISTRY, default localhost:5000, see helpers.bash; the
# image E2E_IMAGE, default $E2E_REGISTRY/alpine:chunked).  E2E_TLS_CA is the
# CA file of a TLS registry (E2E_TLS_REGISTRY, default localhost:5001), for the checks of --cert-dir
# (skipped without it).
#
# Unlike the other end to end tests, a failed check does not end the test:
# the following checks run and the test fails at its end, as the checks of
# the old api script did (they were counted).

# api_setup_file: what the old api script did before the areas: the work
# directory with the configuration (an external source of content "peers"),
# the registries, the daemon, and the image in the local store (a failed pull fails the file).
# Skips the whole file without a podman remote client.
api_setup_file () {
    export CLI DAEMON
    DAEMON=${VELARX_DAEMON:-${BIN:-${VELARX_BINDIR:-target/debug}}/velarx}
    if [ -z "${PODMAN_REMOTE:-}" ]; then
        if command -v podman-remote > /dev/null; then
            PODMAN_REMOTE=podman-remote
        elif command -v podman > /dev/null; then
            PODMAN_REMOTE="podman --remote"
        else
            export NO_PODMAN=1
            return 0
        fi
    fi
    export PODMAN_REMOTE
    BIN=$(dirname "$(realpath "$DAEMON")")
    e2e_setup_file
    # (the files are one level down)
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/../.." && pwd)
    # Every velarx command goes to the engine of the test (as --socket):
    # none runs in an engine of its own if the engine is gone.
    export VELARX_SOCKET=$ESOCK
    mkdir -p "$XDG_CONFIG_HOME/velarx" "$WORKDIR/peers"
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<EOT
# a directory of content by digest: what peers would give
[[sources.external]]
name = "peers"
dir = "$WORKDIR/peers"
[pull]
sources = ["peers", "registry"]
EOT
    # The commands that work in the process (a build) read the configuration
    # the default way: root of the host does not look in $XDG_CONFIG_HOME.
    CLI=$SH
    # (API_REGISTRIES_HEAD: top level keys of a file that tests short names;
    # API_REGISTRIES_TAIL: more blocks)
    {
        printf '%s\n' "${API_REGISTRIES_HEAD:-}"
        cat <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
        printf '%s\n' "${API_REGISTRIES_TAIL:-}"
    } > "$XDG_CONFIG_HOME/velarx/registries.conf"
    # a root daemon reads only the system file unless it is told
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"
    export IMG=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    api_start_daemon || exit 1
    # the images are pulled once for the areas that run containers
    pm pull -q --tls-verify=false "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"
}

# velarx-api serves the REST socket and starts the engine (the socket of
# [engine] in the configuration), which stops with it.
api_start_daemon () {
    local i
    e2e_need_api
    setsid "$BIN/velarx-api" --config "$XDG_CONFIG_HOME/velarx/config.toml" --log-level "${E2E_LOG_LEVEL:-info}" --idle-exit 0 --listen "unix://$SOCK" > "$WORKDIR/daemon.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/daemon.pgid"
    e2e_wait_path "$SOCK" 10 && e2e_wait_path "$ESOCK" 10 && return 0
    echo "velarx-api did not start" >&2
    cat "$WORKDIR/daemon.log" >&2
    return 1
}

# api_teardown_file: the containers, the daemon and its processes group, the
# mounts left, the bridge slot (root), the work directory (kept when
# E2E_KEEP is set); fails when processes of the store are left.
api_teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local pgid i c
    pgid=$(cat "$WORKDIR/daemon.pgid" 2> /dev/null)
    if [ -n "$pgid" ]; then
        e2e_remove_containers "$CLI" "$ESOCK"
        kill -INT -- "-$pgid" 2> /dev/null
        e2e_wait_group "$pgid" 10
        kill -KILL -- "-$pgid" 2> /dev/null
    fi
    e2e_detach_mounts "$WORKDIR"
    e2e_bridge_release "$WORKDIR"
    if [ -n "${E2E_KEEP:-}" ]; then
        echo "# kept $WORKDIR" >&3
        return 0
    fi
    # the stores hold files of the user namespace
    chmod -R u+rwX "$WORKDIR" 2> /dev/null
    rm -rf "$WORKDIR"
    e2e_check_left "$WORKDIR"
}

# note_skip WHAT REASON: a check inside a test that does not run here (the
# rest of the test does), reported on the TAP stream.
note_skip () {
    echo "# skip $1: $2" >&3
}

# todo WHAT WHY: as note_skip, for what is blocked by a missing feature.
todo () {
    note_skip "$1" "blocked: $2"
}

# api_state_save VAR...: the variables later tests of the file read back
# (api_state_load, in setup): a test is a process of its own
api_state_save () {
    local v
    for v in "$@"; do
        printf '%s=%q\n' "$v" "${!v}" >> "$WORKDIR/state.sh"
    done
}
api_state_load () {
    [ -f "$WORKDIR/state.sh" ] && . "$WORKDIR/state.sh"
    return 0
}

pm () {
    timeout 60 $PODMAN_REMOTE --url "unix://$SOCK" "$@"
}

dk () {
    DOCKER_HOST="unix://$SOCK" timeout 60 docker "$@"
}

api () {
    curl -s --unix-socket "$SOCK" "$@"
}

# api_setup: the setup every file of the area starts from (a file with a setup
# of its own calls it first): the soft checks, and a skip without the client.
api_setup () {
    set +e
    E2E_FAILS=0
    [ -z "${NO_PODMAN:-}" ] || skip "no podman remote client (set PODMAN_REMOTE)"
}
setup () { api_setup; api_state_load; }
# The checks are soft: a failure is reported, counted, and fails the test in
# its teardown.
teardown () { [ "${E2E_FAILS:-0}" = 0 ] || exit 1; }

fail () {
    local l
    E2E_FAILS=$((E2E_FAILS + 1))
    echo "FAIL $1" >&2
    shift
    for l in "$@"; do
        echo "#   $l" >&2
    done
}

# check NAME EXPECTED ACTUAL
check () {
    if test "$2" = "$3"; then
        return 0
    fi
    fail "$1" "expected: $2" "actual:   $3"
}

# check_match NAME REGEXP ACTUAL: an extended regular expression matched line
# by line (^ and $ are those of a line of a multi line answer), as in the old api script
check_match () {
    if echo "$3" | grep -Eq -- "$2"; then
        return 0
    fi
    fail "$1" "expected to match: $2" "actual: $3"
}

ok () { :; }
