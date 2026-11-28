# SPDX-License-Identifier: Apache-2.0
# The reason of the inline threshold: an additional image store on NFS, with
# the files of its layers held by the few EROFS images and not by many
# object files.  Two machines: this host (root) fills a store with
# `pull --inline-threshold=N` and exports it read-only; the second one
# (E2E_NFS_HOST, root through ssh; a VM of 3 GB: it builds nothing, it runs
# the prebuilt binaries in E2E_NFS_BINDIR, built for its libc, default
# /var/tmp/two-hosts/bin as tests/p2p-rig/two-hosts.sh has them) mounts it and
# uses it as `[storage] additional_image_stores`, with a local store of its
# own.  What is tested: the images of the store run on the second machine
# with the content the image has, for N=-1 (nothing but images in the store)
# and N=65537 (images and objects), as root and (E2E_NFS_USER: the login of
# a user that has /etc/subuid) rootless; and a lazy pull of that image on
# the second machine fetches no layer from the registry.
#
#   E2E_NFS_HOST=192.168.125.213 VELARX_BINDIR=target/debug \
#       sudo -E bats tests/e2e/bats/inline-nfs.bats
#
# Skipped without E2E_NFS_HOST, without root, without an NFS server on this
# host (`systemctl start nfs-server`) or when the second machine does not
# answer to ssh without a password.  Not covered here (the tests of the file
# of the design for the NFS case that are not written): the second machine
# as a p2p giver of a layer that lives in the NFS store (tests/p2p-rig/
# inline.sh has the peers), and the read of a file while the mount goes away
# (EIO).
#
# The registry of the file listens on every address (the second machine
# pulls from it); it is the one of inline.bash.

load helpers
load inline

NFSDIR=/var/tmp/inline-nfs
B_BINDIR_NFS=${E2E_NFS_BINDIR:-/var/tmp/two-hosts/bin}

on_b () { ssh -o BatchMode=yes -o ConnectTimeout=10 "root@$E2E_NFS_HOST" "$@"; }

setup_file () {
    [ -n "${E2E_NFS_HOST:-}" ] || skip "no second machine: E2E_NFS_HOST is not set"
    skip_unless_root
    command -v exportfs > /dev/null || skip "no exportfs (nfs-utils)"
    systemctl is-active --quiet nfs-server || skip "the NFS server of this host does not run (systemctl start nfs-server)"
    on_b true || skip "the second machine $E2E_NFS_HOST does not answer to ssh as root without a password"
    on_b "test -x $B_BINDIR_NFS/velarx && command -v mount.nfs crun" > /dev/null ||
        skip "the second machine has no $B_BINDIR_NFS/velarx, mount.nfs or crun"
    export INLINE_REG_LISTEN=0.0.0.0
    inline_setup_file
    A_IP=$(ip -o route get "$(on_b hostname -I | awk '{print $1}')" | sed -n 's/.* src \([0-9.]*\).*/\1/p')
    echo "$A_IP" > "$WORKDIR/a_ip"
    on_b "rm -rf $NFSDIR && mkdir -p $NFSDIR/mnt $NFSDIR/store"
    scp -q "$WORKDIR/data.sums" "root@$E2E_NFS_HOST:$NFSDIR/data.sums"
    printf '[[registry]]\nlocation = "%s:%s"\ninsecure = true\n' "$A_IP" "${REG##*:}" > "$WORKDIR/b-registries.conf"
    scp -q "$WORKDIR/b-registries.conf" "root@$E2E_NFS_HOST:$NFSDIR/registries.conf"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    b_daemon_stop
    on_b "umount -l $NFSDIR/mnt 2>/dev/null; rm -rf $NFSDIR" > /dev/null 2>&1
    exportfs -u "$(on_b hostname -I | awk '{print $1}'):$WORKDIR/nfs-export" 2> /dev/null
    inline_teardown_file
}

teardown () {
    inline_teardown
}

setup () {
    set +e
    A_IP=$(cat "$WORKDIR/a_ip" 2> /dev/null)
}

# b_config STORE_LINES: the configuration of the second machine's daemon:
# a store of its own in $NFSDIR/store, the registry of this host
b_config () {
    on_b "cat > $NFSDIR/b.toml" <<EOT
[engine]
socket = "$NFSDIR/b.sock"
[server]
socket = "$NFSDIR/b.sock"
state_dir = "$NFSDIR/state"
root_dir = "$NFSDIR/root"
[storage]
root = "$NFSDIR/store"
$1
[pull]
lazy_completers = 0
EOT
}
b_daemon_start () {
    b_daemon_stop
    on_b "rm -rf $NFSDIR/store $NFSDIR/state $NFSDIR/root; cd $NFSDIR && VELARX_REGISTRIES_CONF=$NFSDIR/registries.conf setsid nohup $B_BINDIR_NFS/velarx --log-level=debug --config $NFSDIR/b.toml varlink > $NFSDIR/b.log 2>&1 < /dev/null & echo \$! > $NFSDIR/b.pid"
    on_b "for i in \$(seq 100); do test -S $NFSDIR/b.sock && exit 0; sleep 0.2; done; cat $NFSDIR/b.log; exit 1" ||
        e2e_die "the daemon of the second machine does not start"
}
b_daemon_stop () {
    on_b "kill \$(cat $NFSDIR/b.pid 2>/dev/null) 2>/dev/null; sleep 1; for c in \$($B_BINDIR_NFS/velarx --socket $NFSDIR/b.sock container list -a -q 2>/dev/null); do $B_BINDIR_NFS/velarx --socket $NFSDIR/b.sock container rm -t 0 -f \$c; done; true" > /dev/null 2>&1
}
b_sh () { on_b "VELARX_REGISTRIES_CONF=$NFSDIR/registries.conf $B_BINDIR_NFS/velarx --socket $NFSDIR/b.sock $*"; }

# export_store N: this host fills a store with the threshold N, exports it
# read-only to the second machine, which mounts it on $NFSDIR/mnt
export_store () {
    local n=$1 b_ip
    inline_fresh "nfs${n/-/m}"
    pull_n "$n" "$IMAGE" > "$WORKDIR/pull.out" 2>&1 || { cat "$WORKDIR/pull.out" >&2; e2e_die "the pull fails"; }
    inline_stop
    on_b "umount -l $NFSDIR/mnt 2>/dev/null; true"
    b_ip=$(on_b hostname -I | awk '{print $1}')
    exportfs -u "$b_ip:$WORKDIR/nfs-export" 2> /dev/null
    rm -rf "$WORKDIR/nfs-export"
    mv "$STORE" "$WORKDIR/nfs-export"
    exportfs -o ro,no_root_squash,insecure,fsid=7001 "$b_ip:$WORKDIR/nfs-export" || e2e_die "exportfs fails"
    on_b "mount -t nfs -o ro,nolock $A_IP:$WORKDIR/nfs-export $NFSDIR/mnt" || e2e_die "the second machine cannot mount the export"
}

content_on_b () { # image
    b_sh container run --rm --pull=never --network none "$1" sh -c "'cd /data && for f in \$(ls); do sha256sum \$f; done'" 2>&1
}

@test "N=-1: a store of nothing but images, exported read-only, runs on the second machine" {
    export_store -1
    check "the export has no object" 0 "$(find "$WORKDIR/nfs-export/objects" -type f 2> /dev/null | wc -l)"
    b_config "additional_image_stores = [\"$NFSDIR/mnt\"]"
    b_daemon_start
    check "the image is listed, read-only" "$IMAGE true" "$(b_sh image list --format "'{{.Repository}}:{{.Tag}} {{.ReadOnly}}'" 2>&1)"
    check "a container reads what the image was made of" "$(cat "$WORKDIR/data.sums")" "$(content_on_b "$IMAGE")"
    b_sh system check > "$WORKDIR/bcheck.out" 2>&1
    check "a check on the second machine passes" 0 $?
    check "and the local store has no object of the image" 0 "$(on_b "find $NFSDIR/store/objects -type f 2>/dev/null | wc -l")"
}

@test "N=65537: the objects and the held files of a store on NFS run on the second machine" {
    export_store 65537
    check "the export has the two files above N as objects" 1 "$(find "$WORKDIR/nfs-export/objects" -type f -size 70001c | wc -l)"
    b_config "additional_image_stores = [\"$NFSDIR/mnt\"]"
    b_daemon_start
    check "a container reads what the image was made of" "$(cat "$WORKDIR/data.sums")" "$(content_on_b "$IMAGE")"
    check "nothing was copied to the local store" 0 "$(on_b "find $NFSDIR/store/objects -type f 2>/dev/null | wc -l")"
}

@test "the second machine pulls lazily an image whose layer is in the NFS store: no layer comes from the registry" {
    export_store -1
    b_config "additional_image_stores = [\"$NFSDIR/mnt\"]"
    b_daemon_start
    before=$(grep -c '/blobs/' "$WORKDIR/registry.log" 2> /dev/null || true)
    b_sh image pull --lazy --tls-verify=false --inline-threshold=64 "$A_IP:${REG##*:}/thr/data:chunked" > "$WORKDIR/blazy.out" 2>&1
    check "the lazy pull works" 0 $?
    check "no layer was asked of the registry" "$before" "$(grep -c '/blobs/' "$WORKDIR/registry.log" 2> /dev/null || true)"
    check "the container reads the files" "$(cat "$WORKDIR/data.sums")" "$(content_on_b "$A_IP:${REG##*:}/thr/data:chunked")"
}

@test "rootless on the second machine: the image server reads the held files of the NFS store" {
    [ -n "${E2E_NFS_USER:-}" ] || skip "no user on the second machine: E2E_NFS_USER is not set"
    export_store -1
    local u=$E2E_NFS_USER
    on_b "rm -rf /var/tmp/inline-nfs-$u && install -d -o $u /var/tmp/inline-nfs-$u"
    on_b "su - $u -c 'cat > /var/tmp/inline-nfs-$u/b.toml'" <<EOT
[engine]
socket = "/var/tmp/inline-nfs-$u/b.sock"
[server]
socket = "/var/tmp/inline-nfs-$u/b.sock"
state_dir = "/var/tmp/inline-nfs-$u/state"
root_dir = "/var/tmp/inline-nfs-$u/root"
[storage]
root = "/var/tmp/inline-nfs-$u/store"
additional_image_stores = ["$NFSDIR/mnt"]
EOT
    out=$(on_b "su - $u -c '$B_BINDIR_NFS/velarx --config /var/tmp/inline-nfs-$u/b.toml container run --rm --pull=never --network none $IMAGE sh -c \"cd /data && for f in \\\$(ls); do sha256sum \\\$f; done\"'" 2>&1)
    on_b "rm -rf /var/tmp/inline-nfs-$u" > /dev/null 2>&1
    check "a rootless container reads the image of the NFS store" "$(cat "$WORKDIR/data.sums")" "$out"
}
