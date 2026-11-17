# SPDX-License-Identifier: Apache-2.0
# What the files of the fs-verity and sha512 e2e tests share:
#
#   load helpers
#   load verity
#
# shs (the CLI on a store of its own), e2e_verity_store (a store on a file
# system with fs-verity), need_verity (skip without one) and start_registry.

shs () { # store, arguments: the CLI on that store
    local store=$1
    shift
    "$SH" --root "$store" "$@"
}

# e2e_verity_store: sets and exports VS, a directory on a file system with
# fs-verity, empty when there is none.  Root: an ext4 image on a loop
# device (labelled as the files of containers: a file system made now has no
# labels, and a container cannot use a descriptor of a file on it); rootless:
# a directory of VELARX_VERITY_DIR.  The teardown unmounts what is below
# $WORKDIR and removes a rootless VS.
e2e_verity_store () {
    export VS=
    if [ "$(id -u)" = 0 ]; then
        if command -v mkfs.ext4 > /dev/null; then
            truncate -s 2G "$WORKDIR/verity.img"
            mkdir -p "$WORKDIR/mnt"
            local label=
            ! command -v selinuxenabled > /dev/null || ! selinuxenabled || label=,context=system_u:object_r:container_file_t:s0
            mkfs.ext4 -q -O verity "$WORKDIR/verity.img" 2> /dev/null \
                && mount -o "loop$label" "$WORKDIR/verity.img" "$WORKDIR/mnt" 2> /dev/null \
                && VS=$WORKDIR/mnt/store
        fi
    elif [ -d "${VELARX_VERITY_DIR:-}" ]; then
        VS=$(mktemp -d "$VELARX_VERITY_DIR/store.XXXXXX")
    fi
    export VS
}

need_verity () { [ -n "$VS" ] || skip "no store with fs-verity (root: mkfs.ext4 and a loop device; rootless: VELARX_VERITY_DIR)"; }

start_registry () { # mode: sets REGISTRY to host:port
    # (the server says its port and its own pid, which the teardown stops:
    # $! is not the server's, and a server left running keeps bats waiting)
    local port pid
    exec {fd}< <(exec python3 -I "$E2E_DIR/sha512_registry.py" "$1" 2> /dev/null)
    read -r port pid <&$fd
    echo "$pid" >> "$WORKDIR/registry.pids"
    REGISTRY=127.0.0.1:$port
}
