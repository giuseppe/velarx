# SPDX-License-Identifier: Apache-2.0
# Shared helpers of the bats end to end tests (tests/e2e/bats/*.bats).
#
#   load helpers
#   setup_file () { e2e_setup_file; e2e_start_daemon; e2e_make_image; }
#   teardown_file () { e2e_teardown_file; }
#
# BIN (default VELARX_BINDIR, else the debug build of the source tree:
# $CARGO_TARGET_DIR/debug, else target/debug of the checkout, whatever the
# current directory) is the directory of the velarx binaries.  The tests of
# a file run in order and share the work directory, the daemon and the store
# of the file.  The files have a work directory, a socket and a store of their
# own and run side by side (tests/e2e/run-all.sh), but NOT under a plain
# `bats --jobs N tests/e2e/bats`: that has no per-file timeout, no ordering,
# and starts unit.bats (the timing of its units) beside the files that
# daemon-reload the user manager (quadlet, units, engine, engine-api), and
# the file that needs a mount namespace of its own (fetcher-confine)
# skips.  Use run-all.sh, or one file at a time.
#
# In a test (and in a function called as a test step) a failure is `exit 1`:
# setup below turns errexit off and bats only sees an `exit`; a `return 1`, a
# `cmd || return 1` or a false `[ ]` as the last command report ok.  Use
# check, check_match, e2e_die.

E2E_HELPERS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$E2E_HELPERS_DIR/wait.bash"

# The registry of the images of the tests (host:port, plain HTTP; default
# localhost:5000) and the TLS one of the --cert-dir checks (default
# localhost:5001, its CA file is E2E_TLS_CA).  The tests name them through
# these variables, never by address.
export E2E_REGISTRY=${E2E_REGISTRY:-localhost:5000}
export E2E_TLS_REGISTRY=${E2E_TLS_REGISTRY:-localhost:5001}

# e2e_netns_records DB [SCOPE]: how many network namespaces the namespaces
# tables of the store's database DB record for the scopes
# like SCOPE (default every container's, `container/%`): what is left of a
# container's network after its end is a record there, never a file.
e2e_netns_records () {
    python3 -I - "$1" "${2:-container/%}" << 'EOT'
import os, sqlite3, sys
if not os.path.exists(sys.argv[1]):
    print(0)
else:
    print(sqlite3.connect(sys.argv[1]).execute(
        "select count(*) from namespaces where kind = 'net' and scope like ?",
        (sys.argv[2],)).fetchone()[0])
EOT
}

# e2e_registry_up: true when a registry answers at E2E_REGISTRY.
e2e_registry_up () {
    curl -s -m 2 "http://$E2E_REGISTRY/v2/" > /dev/null
}

# e2e_registry_lacks REF: the plain HTTP registry of REF (host:port/name:tag
# or name@digest), asked with curl and not with Velarx, says that it does not
# hold REF (404), or nothing listens at its address.  Any other answer (the
# manifest, a redirect, an error, a registry that is not plain HTTP) is not
# a lack.
e2e_registry_lacks () {
    local ref=$1 host rest name tag code rc
    host=${ref%%/*}
    rest=${ref#*/}
    # (a name without a registry host is Docker Hub's, not a test registry)
    case $host in *.* | *:* | localhost) ;; *) return 1 ;; esac
    case $rest in
    *@*) name=${rest%%@*} tag=${rest#*@} ;;
    *:*) name=${rest%:*} tag=${rest##*:} ;;
    *) name=$rest tag=latest ;;
    esac
    code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' \
        -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json' \
        "http://$host/v2/$name/manifests/$tag")
    rc=$?
    # (curl's 7: the connection was refused)
    [ "$code" = 404 ] || [ "$rc" = 7 ]
}

# e2e_pull_failed REF LOG: the pull of REF, logged to LOG, failed.  The only
# honest skip is a registry that does not hold REF, or that does not run (the
# test host was not seeded: the registry is outside what is tested); any
# other failure is a failure of the pull, and fails the test or the file with
# its log.
e2e_pull_failed () {
    local ref=$1 log=$2
    if e2e_registry_lacks "$ref"; then
        skip "$ref is not in the registry (seed it with skopeo copy)"
    fi
    echo "cannot pull $ref, which the registry holds:" >&2
    cat "$log" >&2
    exit 1
}

# skip_unless_bridges: the host can make a bridge and a veth pair in a user
# and network namespace of its own, which is all a bridge network of Velarx
# needs of it.  The probe does not run Velarx: when it passes, a failed
# network create or run on a network is a failure of Velarx.
skip_unless_bridges () {
    command -v ip > /dev/null || skip "no ip"
    unshare -rn sh -c 'ip link add e2ebr type bridge && ip link add e2eva type veth peer name e2evb' > /dev/null 2>&1 ||
        skip "no bridge and veth pair in a user and network namespace on this host"
}

# have_freezer: the cgroup of this process has a freezer it may write, which
# a container made by the engine started from here (a child of it) has too.
# The root cgroup has no freezer of its own: there, the children it may make.
have_freezer () {
    local cg
    cg=$(sed -n 's/^0:://p' /proc/self/cgroup)
    case $cg in
    /) [ -w /sys/fs/cgroup/cgroup.subtree_control ] ;;
    *) [ -w "/sys/fs/cgroup$cg/cgroup.freeze" ] ;;
    esac
}

# e2e_setup_file: the scratch work directory, HOME and XDG_* of the file, the
# configuration, $SH (the CLI on the config), sc (the CLI on the engine's socket).
# Everything it exports is visible to the tests of the file.
e2e_setup_file () {
    # tests/e2e and the source tree, from the place of this file
    export E2E_DIR; E2E_DIR=$(cd "$E2E_HELPERS_DIR/.." && pwd)
    local top_srcdir; top_srcdir=$(cd "$E2E_DIR/../.." && pwd)
    export BIN
    BIN=$(realpath "${BIN:-${VELARX_BINDIR:-${CARGO_TARGET_DIR:-$top_srcdir/target}/debug}}")
    export WORKDIR
    WORKDIR=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-$(basename "$BATS_TEST_FILENAME" .bats).XXXXXX")
    # the engine's socket (the command line, the thin client), and the REST
    # API's (velarx-api, started by the files that test it)
    export ESOCK=$WORKDIR/engine.sock SOCK=$WORKDIR/api.sock
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}
    export HOME=$WORKDIR/home XDG_RUNTIME_DIR=$WORKDIR/run
    export XDG_CONFIG_HOME=$HOME/.config XDG_DATA_HOME=$HOME/data
    mkdir -p "$XDG_CONFIG_HOME/velarx" "$XDG_RUNTIME_DIR"
    cat > "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
storage.root = "$XDG_DATA_HOME/velarx"
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$XDG_RUNTIME_DIR/velarx"
root_dir = "$XDG_DATA_HOME/velarx"
shutdown_timeout_secs = 5
[userns]
uid_ranges = ["655360-720895"]
gid_ranges = ["655360-720895"]
allocation_size = 65536
[containers]
log_driver = "k8s-file"
TOML
    # root of the host does not look for its configuration in
    # $XDG_CONFIG_HOME: the commands are told
    printf '#!/bin/sh\nexec %s --config %s "$@"\n' "$BIN/velarx" "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/velarx"
    chmod +x "$WORKDIR/velarx"
    export SH=$WORKDIR/velarx
    DAEMON_PID=
}

# sc ARGS: the CLI against the engine of the file (a function, so it is
# available in every test; bats runs each test in the file's environment).
sc () { "$SH" --socket "$ESOCK" "$@"; }

# e2e_start_daemon: start the daemon of the file and wait for it.
e2e_start_daemon () {
    # (the daemon says READY=1 when it serves: no loop of attempts)
    # (|| : the shell of bats exits at a failure, without the pid file the
    # teardown stops the daemon by)
    local ready=0
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink || ready=$?
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    [ "$ready" = 0 ] && return 0
    echo "the daemon does not start" >&2
    tail "$WORKDIR/daemon.log" >&2
    exit 1
}

# e2e_make_rootfs: $WORKDIR/rootfs, a root file system of host binaries.
# BINARIES (default: sh cat env sleep true false echo ls stat) are copied in.
e2e_make_rootfs () {
    local b p l
    local root=$WORKDIR/rootfs
    mkdir -p "$root"/{bin,lib64,usr/lib64,etc,proc,sys,dev,tmp,run}
    for b in ${BINARIES:-sh cat env sleep true false echo ls stat}; do
        p=$(type -P "$b") || continue
        cp "$p" "$root/bin/$b"
        ldd "$p" | grep -o '/[^ ]*' | while read -r l; do
            mkdir -p "$root$(dirname "$l")"
            cp -L "$l" "$root$l" 2> /dev/null
        done
    done
}

# e2e_make_image [NAME]: import an image of host binaries (no registry) as
# NAME (default localhost/e2e-base:1) and export it as $IMG.
e2e_make_image () {
    local name=${1:-localhost/e2e-base:1}
    e2e_make_rootfs
    tar -C "$WORKDIR/rootfs" -cf "$WORKDIR/rootfs.tar" .
    sc image import "$WORKDIR/rootfs.tar" "$name" > /dev/null
    export IMG=$name
}

# e2e_teardown_file: stop the daemon of the file (the pid in
# $WORKDIR/daemon.pid) and remove the work directory (kept when E2E_KEEP is
# set).  The containers are the file's business (its teardown_file).  A
# rootless podman of the file (`podman unshare`) has left its pause process,
# whose pid is in the run directory of the file ($WORKDIR/run, never the
# one of the session): it ends with it.
e2e_teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pid
    pid=$(cat "$WORKDIR/run/libpod/tmp/pause.pid" 2> /dev/null)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null
    # (the engine services a command started for its lazy pulls outlive it)
    e2e_stop_services "$WORKDIR"
    pid=$(cat "$WORKDIR/api.pid" 2> /dev/null)
    [ -z "$pid" ] || kill "$pid" 2> /dev/null
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -n "$pid" ]; then
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid" 10 || kill -KILL "$pid" 2> /dev/null
    fi
    if [ -z "${E2E_KEEP:-}" ]; then
        chmod -R u+rwX "$WORKDIR" 2> /dev/null
        rm -rf "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

# e2e_hold_completions CONFIG: the engine service of the store of CONFIG
# (which owns its lazy pulls, `velarx varlink`) completes none in the
# background: `[pull] lazy_completers = 0`, before the service starts.  A
# pull stays a pull, and a container on it stays lazy, until a command waits
# for it (`image complete`, a pull or a run without --lazy).
e2e_hold_completions () {
    python3 -I - "$1" << 'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
text = re.sub(r"(?m)^lazy_completers *=.*\n", "", text)
if re.search(r"(?m)^\[pull\][ \t]*$", text):
    text = re.sub(r"(?m)^\[pull\][ \t]*$", "[pull]\nlazy_completers = 0", text, count=1)
else:
    text += "\n[pull]\nlazy_completers = 0\n"
open(path, "w").write(text)
PY
}

# e2e_release_completions CONFIG: what e2e_hold_completions wrote goes; an
# engine service started after this completes in the background again
e2e_release_completions () { sed -i '/^lazy_completers = 0$/d' "$1"; }

# e2e_stop_services DIR: the engine and store services that listen on a
# socket under DIR stop (INT, TERM for a store service, which has the
# default actions and may have been started with INT ignored; then KILL): a
# command starts the engine service of its store for its lazy pulls, a P2P
# service the store service it serves from, and they outlive the command (a
# store service that still runs writes in its store while the work
# directory is removed).
e2e_stop_services () {
    local s pid sig
    for s in $(find "$1" -type s -name '*.sock' 2> /dev/null); do
        for pid in $(e2e_service_pid "$s"); do
            if grep -qa varlink "/proc/$pid/cmdline" 2> /dev/null; then
                sig=INT
            elif grep -qa store-service "/proc/$pid/cmdline" 2> /dev/null; then
                sig=TERM
            else
                continue
            fi
            kill -"$sig" "$pid" 2> /dev/null
            e2e_wait_exit "$pid" 10 || kill -KILL "$pid" 2> /dev/null
        done
    done
}

# e2e_service_pid SOCKET: the pid of the process that listens on SOCKET
# (empty: none).  Found by the inode of the socket: the credentials of its
# peer are those of the process that bound it, which may be the command
# that started the service and is gone.
e2e_service_pid () {
    python3 -I - "$1" << 'PY' 2> /dev/null
import os, sys
path = os.path.realpath(sys.argv[1])
inodes = set()
for line in open("/proc/net/unix").read().splitlines()[1:]:
    f = line.split()
    # (a listener: state 01 with the flag __SO_ACCEPTCON)
    if len(f) >= 8 and f[7] == path and f[3] == "00010000":
        inodes.add("socket:[%s]" % f[6])
for pid in os.listdir("/proc"):
    if not pid.isdigit():
        continue
    try:
        fds = os.listdir("/proc/%s/fd" % pid)
    except OSError:
        continue
    for fd in fds:
        try:
            if os.readlink("/proc/%s/fd/%s" % (pid, fd)) in inodes:
                print(pid)
                break
        except OSError:
            pass
PY
}

# The tests keep the semantics of the old scripts: no errexit, so
# "cmd; check what 1 $?" works.  A test that has to fail on a plain command
# says so ("cmd || exit 1"; never `return 1`, which reports ok).
setup () { set +e; }

# e2e_reap PID WHAT: wait for the background command PID, which has to end
# with status 0: a test is failed otherwise.  `setup` turns errexit off, so
# a plain `wait` never fails a test; use this for a command that must succeed.
e2e_reap () {
    local rc
    wait "$1"
    rc=$?
    [ "$rc" -eq 0 ] || e2e_die "$2 ended with status $rc"
}

# e2e_die MESSAGE...: fail the current test (or setup_file) at once.
e2e_die () {
    echo "FAIL: $*" >&2
    exit 1
}

# e2e_require_private_mounts VAR: for the files that mount over the real
# system directories (root only).  They run in a mount namespace of their own
# with private propagation, which run-all.sh makes (unshare -m --propagation
# private) and announces by setting VAR to 1.  The variable alone is not
# trusted: the mounts of the namespace must not be shared with the host
# either, or a bind mount of the test would show on the real /usr/local/bin.
# Skips the file otherwise.  Call it in setup_file, before any mount.
e2e_require_private_mounts () {
    [ -n "${!1:-}" ] || skip "needs a mount namespace of its own ($1=1 unshare -m --propagation private bats ...; tests/e2e/run-all.sh does)"
    # the optional fields of /proc/self/mountinfo (before " - ") say "shared:N"
    # for a mount that propagates to its peers
    if sed 's/ - .*//' /proc/self/mountinfo | grep -q ' shared:[0-9]'; then
        skip "$1 is set but the mounts are shared with the host (unshare -m --propagation private)"
    fi
}

# check WHAT EXPECTED ACTUAL: the assertions of the old scripts, kept so that
# a conversion is mechanical.  A failure prints the message and fails the
# test at once (bats has no soft assertions; exit ends the test, so do not
# call check in a $(...) or a pipeline).
check () {
    if [ "$2" = "$3" ]; then return 0; fi
    echo "FAIL $1: expected '$2', got '$3'" >&2
    exit 1
}
# check_match WHAT REGEXP ACTUAL: an extended regular expression matched line
# by line (^ and $ are those of a line of a multi line ACTUAL), as grep -E
# e2e_alive PID: "alive" while the process runs, else "gone" (a zombie that
# its parent did not reap yet, after e2e_wait_exit, is gone)
e2e_alive () {
    [ -d "/proc/${1:-x}" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2> /dev/null &&
        echo alive || echo gone
}
check_match () {
    if printf '%s\n' "$3" | grep -Eq -- "$2"; then return 0; fi
    echo "FAIL $1: '$3' does not match '$2'" >&2
    exit 1
}
# skip_unless_root, skip_unless_systemd_user ...: skip a test that needs what
# this machine lacks.
skip_unless_root () { [ "$(id -u)" = 0 ] || skip "needs root"; }
skip_if_root () { [ "$(id -u)" != 0 ] || skip "not as root"; }
# expected_stubs DIR: which stubs the overlay of a user namespace
# (`userxattr`) follows on this kernel, found as the engine finds it, apart
# from it: "every" (a stub of a middle layer is followed into a data-only
# layer, with `redirect_dir=followdata`) or "lowest" (the stubs of the lowest
# layer only; also a kernel without that option).  Mounts that layout (3
# layers, the stub in the middle one, `datadir+`) in `unshare -Urm` under DIR.
expected_stubs () {
    local d=$1/stubcheck out
    rm -rf "$d"
    mkdir -p "$d"/{l1,l2,l3,data,m} || { echo lowest; return; }
    echo low > "$d/l1/a"
    echo top > "$d/l3/b"
    echo content > "$d/data/blob"
    : > "$d/l2/f"
    if setfattr -n user.overlay.redirect -v /blob "$d/l2/f" 2> /dev/null \
        && setfattr -n user.overlay.metacopy -v "" "$d/l2/f" 2> /dev/null; then
        out=$(unshare -Urm sh -c "mount -t overlay overlay -o lowerdir+=$d/l3,lowerdir+=$d/l2,lowerdir+=$d/l1,datadir+=$d/data,redirect_dir=followdata,userxattr $d/m && cat $d/m/f" 2>&1)
    fi
    rm -rf "$d"
    [ "${out:-}" = content ] && echo every || echo lowest
}
# skip_unless_followdata DIR: skip a test of an image of several layers in a
# user namespace served by the kernel's overlay, which needs the mount option
# `redirect_dir=followdata` (a kernel without it serves those files by FUSE).
# Probed with a scratch overlay under DIR, never a path of the user.
skip_unless_followdata () {
    [ "$(expected_stubs "$1")" = every ] \
        || skip "this kernel lacks the overlay mount option redirect_dir=followdata"
}
# stubs_answer STATE_DIR: what the engine found (kept as a marker file in
# the run root when an image of more than one layer first needed it, as the
# feature overlay-datadir-every-layer, -yes or -no):
# every, lowest, or none
stubs_answer () {
    if [ -e "$1/features/overlay-datadir-every-layer-no" ]; then echo lowest
    elif [ -e "$1/features/overlay-datadir-every-layer-yes" ]; then echo every
    else echo none; fi
}
# skip_unless_host_changes WHAT: a test that changes a setting of the whole
# host (and puts it back in its teardown) runs only with
# VELARX_E2E_HOST_CHANGES=1
skip_unless_host_changes () {
    [ "${VELARX_E2E_HOST_CHANGES:-}" = 1 ] || skip "changes $1 of the host: set VELARX_E2E_HOST_CHANGES=1"
}
skip_unless_systemd_user () {
    # (a degraded manager, a unit of someone failed, works as well)
    case $(XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR systemctl --user is-system-running 2> /dev/null) in
    running | degraded) ;;
    *) skip "no systemd user manager" ;;
    esac
}

# e2e_need_api, e2e_need_cri: skip, saying so, without velarx-api (or
# velarx-cri) in $BIN: they are not default members of the workspace (a plain
# `cargo build` leaves them out); `make build-debug` builds them with the
# other binaries of the e2e tests.  Every test that starts one calls it first.
e2e_need_api () {
    [ -x "$BIN/velarx-api" ] || skip "velarx-api is not built: cargo build -p velarx-api-bin (make build-debug)"
}
e2e_need_cri () {
    [ -x "$BIN/velarx-cri" ] || skip "velarx-cri is not built: cargo build -p velarx-cri-bin (make build-debug)"
}

# e2e_start_api: velarx-api on $SOCK, in front of the engine that answers on
# $ESOCK (for the files that drive the REST API with curl or podman); stopped
# by e2e_teardown_file.
e2e_start_api () {
    e2e_need_api
    "$BIN/velarx-api" --config "$XDG_CONFIG_HOME/velarx/config.toml" --no-start-engine --idle-exit 0 \
        --listen "unix://$SOCK" > "$WORKDIR/api.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/api.pid"
    # (not READY=1: the API confines itself before it could tell, to the directory of the engine)
    e2e_wait_path "$SOCK" 10 && return 0
    echo "velarx-api does not start" >&2
    tail "$WORKDIR/api.log" >&2
    exit 1
}

# e2e_need_man: skip unless `make man` has written the man pages and the
# completions that `make install-files` lays out.
e2e_need_man () {
    [ -e "${top_srcdir:-$E2E_DIR/../..}/share/man/velarx.conf.5" ] ||
        skip "the generated man pages are missing: run make man first"
}

# e2e_label_for_containers DIR: where SELinux is enforcing, a host directory
# that is a root file system (--rootfs) or a mount that is no volume (CDI)
# keeps the label of where it was made and the container may not read what is
# in it: label it for the containers, as one does by hand; skip the test on a
# file system that keeps no labels, fail on any other error.
e2e_label_for_containers () {
    command -v selinuxenabled > /dev/null && selinuxenabled || return 0
    e2e_chcon -R -t container_file_t "$1"
}

# e2e_chcon ARGS...: chcon; skip the test where the file system has no
# labels of its own (a mount with context=), fail on another error.
e2e_chcon () {
    local err
    err=$(chcon "$@" 2>&1) && return 0
    case $err in
    *"Operation not supported"*) skip "the file system of the scratch directory keeps no SELinux labels" ;;
    esac
    e2e_die "chcon $*: $err"
}

# e2e_system_bin: as root where SELinux enforces, a system service may only
# run binaries labelled bin_t: the file uses a labelled copy of the binaries
# (BIN) for the units it starts.  Call it after e2e_setup_file.
e2e_system_bin () {
    [ "$(id -u)" = 0 ] || return 0
    command -v selinuxenabled > /dev/null && selinuxenabled || return 0
    mkdir -p "$WORKDIR/bin"
    cp --reflink=auto "$BIN"/velarx* "$WORKDIR/bin/" || e2e_die "copy the binaries"
    e2e_chcon -t bin_t "$WORKDIR/bin"/*
    BIN=$WORKDIR/bin
}
