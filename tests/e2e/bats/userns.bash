# SPDX-License-Identifier: Apache-2.0
# Shared by tests/e2e/bats/userns/*.bats (and userns-tree.bats, which loads
# `helpers` and `userns` without the ../): the daemon of the user namespace
# tests, its image and the helpers the areas use.
#
#   load ../helpers
#   load ../userns
#   setup_file () { userns_setup_file; }
#   teardown_file () { userns_teardown_file; }
#
# Run as a user (a rootless daemon in its own user namespace, needs newuidmap
# and /etc/subuid) or as root (the sub ids of `containers` in /etc/subuid, or
# [userns] ranges): the checks adapt.  E2E_IMAGE is an image of a registry
# the daemon can pull from (default localhost:5000/alpine:chunked, plain HTTP
# is enabled for its host).

# The ids of the daemon: rootless, the user is 0 and the sub ids 1..N.  A
# mapping of the whole range (MAPOPTS) and what the root of the container is
# outside of the daemon's user namespace (HOST0).
userns_setup_file () {
    e2e_setup_file
    export IMG=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    local registry=${IMG%%/*}
    chmod 755 "$WORKDIR"
    # (the engine's socket is in a private directory of its own: $WORKDIR is
    # open to the ids of the containers)
    export ESOCK=$WORKDIR/engine/engine.sock
    # Every velarx command goes to the daemon of the test (as --socket):
    # none runs in an engine of its own if the daemon is gone.
    export VELARX_SOCKET=$ESOCK
    export CLI=$SH
    export ME; ME=$(id -u)
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    cat > "$XDG_CONFIG_HOME/velarx/config.toml" <<EOT
$(e2e_bridge_toml)
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
shutdown_timeout_secs = 5
[storage]
root = "$WORKDIR/storage"
[containers]
log_driver = "k8s-file"
EOT
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<EOT
[[registry]]
location = "$registry"
insecure = true
EOT
    # a root daemon reads only the system file unless it is told
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"

    setsid "$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" --log-level "${E2E_LOG_LEVEL:-info}" varlink \
        > "$WORKDIR/daemon.log" 2>&1 3>&- &
    echo "$!" > "$WORKDIR/daemon.pid"
    export DAEMON_PGID=$!
    if ! e2e_wait_path "$ESOCK" 10; then
        echo "the daemon did not start" >&2
        cat "$WORKDIR/daemon.log" >&2
        return 1
    fi

    sh_ image pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"

    if test "$ME" = 0; then
        export ROOTLESS=0
        export MAPOPTS="--uidmap 0:300000:65536 --gidmap 0:300000:65536"
        export HOST0=300000
    else
        export ROOTLESS=1
        export SUBSTART SUBSIZE
        SUBSTART=$(awk -F: -v u="$(id -un)" -v i="$ME" '$1 == u || $1 == i { print $2; exit }' /etc/subuid)
        SUBSIZE=$(awk -F: -v u="$(id -un)" -v i="$ME" '$1 == u || $1 == i { print $3; exit }' /etc/subuid)
        export MAPOPTS="--uidmap 0:1:65536 --gidmap 0:1:65536"
        export HOST0=$SUBSTART
    fi
}

userns_teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local pgid i
    pgid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if test -n "$pgid"; then
        e2e_remove_containers "$CLI" "$ESOCK"
        kill -INT -- "-$pgid" 2> /dev/null
        e2e_wait_group "$pgid" 10
        kill -KILL -- "-$pgid" 2> /dev/null
    fi
    e2e_detach_mounts "$WORKDIR"
    if test -z "${E2E_KEEP:-}"; then
        e2e_remove_workdir "$WORKDIR" "$CLI" >&3 2>&3
    fi
    e2e_teardown_file
    e2e_check_left "$WORKDIR" >&3 2>&3
}

sh_ () {
    timeout "${E2E_TIMEOUT:-120}" "$CLI" --socket "$ESOCK" "$@"
}

# checkfail NAME STATUS: the command failed
checkfail () {
    if test "$2" != 0; then return 0; fi
    echo "FAIL $1: expected a failure" >&2
    exit 1
}

# runo "OPTIONS" CMD...: a container of the image with these options (no
# spaces in the values), removed after; stdout and stderr together
runo () {
    local opts=$1
    shift
    # shellcheck disable=SC2086
    sh_ container run --rm $opts "$IMG" "$@" 2>&1
}

# the container running in the background, its logs and its removal
bg () {
    local opts=$1
    shift
    # shellcheck disable=SC2086
    sh_ container run -d $opts "$IMG" "$@" 2>/dev/null
}

# squeeze: collapse the spaces of /proc/self/uid_map
squeeze () {
    tr -s ' ' | sed 's/^ //'
}
