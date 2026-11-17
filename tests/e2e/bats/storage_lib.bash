# SPDX-License-Identifier: Apache-2.0
# Shared by the bats files of the varlink storage driver (storage-varlink.bats,
# storage-varlink-faults.bats): the reference storage service on a private
# socket, and the readings of the store it keeps for the engine of the file.
#
#   load helpers
#   load run_lib
#   load storage_lib
#
# $VDIR is the directory of the service (socket, stores, logs), made by the
# file before its work directory so that the configuration can name it.

# start_storage [SECONDS [OPTION...]]: the service on $VDIR/s.sock, with the
# idle deadline SECONDS (30), never leaving when idle (--idle-secs 0, unless an
# option says otherwise), and the options it is given more
start_storage () {
    local secs=${1:-30}
    shift
    # (not a child of the shell that runs the test or its setup: bats waits for
    # its children, and a service that a test kills is not a test that ended)
    ( setsid "$BIN/velarx-storage-server" --socket "$VDIR/s.sock" --root "$VDIR/root" \
        --timeout-secs "$secs" --idle-secs 0 "$@" >> "$VDIR/server.log" 2>&1 3>&- &
      echo $! > "$VDIR/server.pid" )
    e2e_wait_path "$VDIR/s.sock" 10
}

# stop_storage: SIGTERM and wait; a service that is gone already is not an error
stop_storage () {
    local pid
    pid=$(cat "$VDIR/server.pid" 2> /dev/null)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null
    [ -z "$pid" ] || e2e_wait_exit "$pid" 10
    rm -f "$VDIR/server.pid"
}

store () { echo "$XDG_DATA_HOME/velarx"; }
field () { python3 -I -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(json.dumps(d) if not isinstance(d, str) else d)' "$1"; }
# the directory the service keeps this store in: <root>/<uid>/<store id>
sdir () { echo "$VDIR/root/$(id -u)/$(cat "$(store)/varlink/store-id")"; }
# a configuration like the file's with other lines of the root table in place
# of its own storage driver (the lines go first: a dotted key of the root
# table must come before the first table)
config_with () { # NAME LINES...
    local name=$1
    shift
    { printf '%s\n' "$@"; grep -v '^storage\.\(driver\|varlink\)' "$CONFIG"; } > "$WORKDIR/$name.toml"
}

# two_layer_image: $E2E_REGISTRY/e2e/varlink-two:1, the image $IMAGE and one
# layer of a file more, pushed zstd:chunked from the store of an engine on the
# vfs driver of its own, which states
# the digest of the merged EROFS image in its manifest.  Made once for the
# registry.
two_layer_image () {
    curl -sf -o /dev/null -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
        "http://$E2E_REGISTRY/v2/e2e/varlink-two/manifests/1" && return 0
    local d=$VDIR/vfs pid vx
    mkdir -p "$d" && chmod 700 "$d"
    sed -e 's#^storage\.driver.*#storage.driver = "vfs"#' -e '/^storage\.varlink/d' \
        -e "s#$XDG_DATA_HOME/velarx#$d/data#g" -e "s#$ESOCK#$d/engine.sock#" -e "s#$SOCK#$d/api.sock#" \
        -e "s#$XDG_RUNTIME_DIR/velarx#$d/run#" "$CONFIG" > "$d/config.toml"
    E2E_SPAWN_LOG=$d/daemon.log e2e_spawn_ready pid setsid "$BIN/velarx" --config "$d/config.toml" varlink ||
        e2e_die "the engine for the image does not start: $(tail -3 "$d/daemon.log")"
    vx () { "$BIN/velarx" --config "$d/config.toml" --socket "$d/engine.sock" "$@" 3>&-; }
    vx image pull "$IMAGE" > /dev/null &&
        vx container run --name two --network none "$IMAGE" sh -c 'echo two > /two' > /dev/null &&
        vx container commit two localhost/e2e/varlink-two:1 > /dev/null &&
        vx image push --tls-verify=false --compression-format zstd:chunked localhost/e2e/varlink-two:1 \
            "$E2E_REGISTRY/e2e/varlink-two:1" > "$d/push.log" 2>&1
    local rc=$?
    kill "$pid" 2> /dev/null
    e2e_wait_exit "$pid" 30
    chmod -R u+rwX "$d" 2> /dev/null
    [ $rc = 0 ] || e2e_die "the image of two layers is not made: $(tail -3 "$d/push.log")"
    rm -rf "$d"
}

# lazy_image: $E2E_REGISTRY/e2e/varlink-lazy:zstd, the image $IMAGE and a
# file more squashed into one layer, pushed zstd:chunked from the store of an
# engine on the vfs driver of its own (the service does not have its layer, and
# its table of contents gives the fs-verity digest of every file, which a lazy
# pull needs); made once for the registry.
lazy_image () {
    curl -sf -o /dev/null -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
        "http://$E2E_REGISTRY/v2/e2e/varlink-lazy/manifests/zstd" && return 0
    local d=$VDIR/vfs-lazy pid vx
    mkdir -p "$d" && chmod 700 "$d"
    sed -e 's#^storage\.driver.*#storage.driver = "vfs"#' -e '/^storage\.varlink/d' \
        -e "s#$XDG_DATA_HOME/velarx#$d/data#g" -e "s#$ESOCK#$d/engine.sock#" -e "s#$SOCK#$d/api.sock#" \
        -e "s#$XDG_RUNTIME_DIR/velarx#$d/run#" "$CONFIG" > "$d/config.toml"
    E2E_SPAWN_LOG=$d/daemon.log e2e_spawn_ready pid setsid "$BIN/velarx" --config "$d/config.toml" varlink ||
        e2e_die "the engine for the image does not start: $(tail -3 "$d/daemon.log")"
    vx () { "$BIN/velarx" --config "$d/config.toml" --socket "$d/engine.sock" "$@" 3>&-; }
    # (one layer the engine writes: a layer of $IMAGE would be pushed as the
    # registry has it, whose table of contents may give no fs-verity digest)
    vx image pull "$IMAGE" > /dev/null &&
        vx container run --name lazy --network none "$IMAGE" sh -c 'echo lazy > /lazy' > /dev/null &&
        vx container commit --squash lazy localhost/e2e/varlink-lazy:zstd > /dev/null &&
        vx image push --tls-verify=false --compression-format zstd:chunked localhost/e2e/varlink-lazy:zstd \
            "$E2E_REGISTRY/e2e/varlink-lazy:zstd" > "$d/push.log" 2>&1
    local rc=$?
    kill "$pid" 2> /dev/null
    e2e_wait_exit "$pid" 30
    chmod -R u+rwX "$d" 2> /dev/null
    [ $rc = 0 ] || e2e_die "the lazy image is not made: $(tail -3 "$d/push.log")"
    rm -rf "$d"
}
