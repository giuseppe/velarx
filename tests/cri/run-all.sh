#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Every test of the Kubernetes CRI frontend, in one command (make cri-tests).  The
# steps run in this order, each one can be left out or run alone:
#
#   prereq    the tools the selected steps need, and how to get the missing ones
#   build     the debug build of every binary (make build-debug)
#   unit      the mapping tests with a mock engine (make test-cri); no root
#   bats      tests/e2e/bats cri.bats and cri-checkpoint.bats: crictl against an engine
#   mirror    the images of critest, as they are, in the registry, the ones it lacks only
#   critest   the CRI validation suite of cri-tools, as root (tests/cri/critest.sh)
#   kubelet   a kubelet runs a static pod on velarx-cri, as root (tests/cri/kubelet.sh)
#   cluster   etcd, kube-apiserver, controller-manager, scheduler and a kubelet with the CNI
#             bridge plugin: Deployment, kubectl exec/attach/port-forward, QoS cgroups,
#             eviction (tests/cri/cluster.sh)
#
# The CRI is run and tested as root, as Kubernetes does.  Running it twice gives the
# same result and the second run redoes only what is needed: the build skips what is
# up to date, the mirror copies what the registry lacks, the kubelet binary is
# downloaded once.  It leaves nothing behind: its scratch directory is private and
# removed, the processes, the registry and the container it started are stopped by their
# PID or id (an interrupted run, Ctrl-C, too), and the steps run in mount namespaces of
# their own.  It never touches /var/lib/velarx, /run/velarx, /var/cache/velarx or the
# default podman store, and never installs anything.  One run at a time per cache
# directory: a second one refuses to start.
# (the steps are called by name, step_STEP)
# shellcheck disable=SC2329
set -u
set -o pipefail

TOP=$(cd "$(dirname "$0")/../.." && pwd)
STEPS="prereq build unit bats mirror critest kubelet cluster"
CACHE=${VELARX_TEST_CACHE:-${XDG_CACHE_HOME:-${HOME:?}/.cache}/velarx-tests}
LOGDIR=${CRI_TESTS_LOGS:-$CACHE/cri-tests-logs}
REGISTRY=${REGISTRY:-localhost:5000}
BINDIR=${VELARX_BINDIR:-${CARGO_TARGET_DIR:-$TOP/target}/debug}
# (shell commands, run in the source tree)
BUILD_CMD=${BUILD_CMD:-make build-debug}
UNIT_CMD=${UNIT_CMD:-make test-cri}
# the pinned versions and sha256 of the tools (the kubelet's, the registry image of
# --own-registry), shared with the workflow; the environment may change them
pin () { # NAME: its value in tests/cri/versions
    sed -n "s/^$1=//p" "$TOP/tests/cri/versions"
}
KUBELET_VERSION=${KUBELET_VERSION:-$(pin KUBELET_VERSION)}
KUBELET_SHA256=${KUBELET_SHA256:-$(pin KUBELET_SHA256)}
CRI_TOOLS_VERSION=$(pin CRI_TOOLS_VERSION)
REGISTRY_IMAGE=${REGISTRY_IMAGE:-$(pin REGISTRY_IMAGE)}
# the image of bats and of the kubelet's pod; by default alpine, copied as OCI
# into the registry by the mirror step
CRI_IMAGE=${CRI_IMAGE:-}
FOCUS=${CRITEST_FOCUS:-}
OWN_REGISTRY=0
FAIL_FAST=0
SELECTED=" $STEPS "

usage () {
    cat <<EOF
usage: tests/cri/run-all.sh [OPTIONS]   (make cri-tests)

Runs the CRI tests of velarx-cri, as root where the CRI needs it (sudo is used when
the script is not run by root).  The steps, in this order:

  prereq   the tools the selected steps need; what is missing and how to get it
  build    the debug build of every binary (make build-debug)
  unit     the mapping tests with a mock engine (make test-cri)
  bats     cri.bats and cri-checkpoint.bats: crictl against an engine
  mirror   copy the images of critest into the registry, the ones it lacks only
  critest  critest (cri-tools), as root, in a private mount namespace
  kubelet  a kubelet runs a static pod on velarx-cri, as root
  cluster  a single-node cluster (etcd, API server, controllers, kubelet, CNI) on velarx-cri, as root

Options:
  --only STEP[,STEP...]  run only these steps (repeatable)
  --skip-STEP            leave a step out (--skip-build, --skip-kubelet, ...)
  --focus REGEXP         critest: only the specs that match (ginkgo focus)
  --bindir DIR           the binaries velarx, velarx-monitor, velarx-cri (default
                         \$VELARX_BINDIR, else the debug target directory)
  --own-registry         if nothing answers at \$REGISTRY, start a throwaway registry
                         (a registry binary or podman, plain HTTP, a free port on
                         localhost) and stop it at the end; an existing one is never touched
  --keep-going           a failed step does not stop the others (the default)
  --fail-fast            stop at the first failed step
  --list                 list the steps and exit
  -h, --help             this text

Each step prints one line (ok, FAILED, skipped: reason) and the end a table with
the critest counts and the logs.  The exit status is not 0 when a step failed.

Environment:
  REGISTRY             the registry of the test images (default localhost:5000, plain HTTP)
  VELARX_BINDIR        the directory of the binaries (see --bindir)
  BUILD_CMD            the build step, a shell command run in the source tree (default:
                       make build-debug); e.g. a wrapper
  UNIT_CMD             the unit step, the same way (default: make test-cri)
  CRI_IMAGE            the image of bats and of the kubelet's pod (default
                       \$REGISTRY/ci/alpine:3.20, copied from docker.io by the mirror step)
  CRITEST_FOCUS        the same as --focus; CRITEST_ARGS: more arguments for critest
  KUBELET              the kubelet binary; without it the cached one, the one in the PATH,
                       else v$KUBELET_VERSION is downloaded once from dl.k8s.io and its sha256
                       is verified (pinned in tests/cri/versions; KUBELET_VERSION and
                       KUBELET_SHA256 change the pin)
  VELARX_TEST_CACHE    the cache (default \${XDG_CACHE_HOME:-~/.cache}/velarx-tests): the
                       kubelet binary, the data of an own registry, the logs
  CRI_TESTS_LOGS       where the logs go (default \$VELARX_TEST_CACHE/cri-tests-logs); each
                       run replaces the logs of the last
  TMPDIR               where the private scratch directory goes (default /var/tmp)
  REGISTRY_BIN         the registry binary of --own-registry (default: registry in the PATH,
                       else podman with REGISTRY_IMAGE, pinned in tests/cri/versions)

What runs as root (sudo -n, after one sudo -v, when not run by root): the bats step
(tests/e2e/run-all.sh cri cri-checkpoint), tests/cri/critest.sh run-root,
tests/cri/kubelet.sh, and the kill of the process group of an interrupted step.  They
get this PATH.
EOF
}

die () { echo "run-all.sh: $*" >&2; exit 2; }

want () { case "$SELECTED" in *" $1 "*) return 0 ;; esac; return 1; }

ONLY=
SKIP=
while [ $# -gt 0 ]; do
    case $1 in
    -h | --help) usage; exit 0 ;;
    --list) for s in $STEPS; do echo "$s"; done; exit 0 ;;
    --only) [ $# -ge 2 ] || die "--only needs a step"; ONLY="$ONLY $2"; shift ;;
    --only=*) ONLY="$ONLY ${1#--only=}" ;;
    --skip-?*) SKIP="$SKIP ${1#--skip-}" ;;
    --focus) [ $# -ge 2 ] || die "--focus needs a regexp"; FOCUS=$2; shift ;;
    --bindir) [ $# -ge 2 ] || die "--bindir needs a directory"; BINDIR=$2; shift ;;
    --own-registry) OWN_REGISTRY=1 ;;
    --keep-going) FAIL_FAST=0 ;;
    --fail-fast) FAIL_FAST=1 ;;
    *) usage | head -n 1 >&2; die "unknown option $1 (--help)" ;;
    esac
    shift
done
ONLY=${ONLY//,/ }
for s in $ONLY $SKIP; do
    case " $STEPS " in *" $s "*) ;; *) die "no step $s (--list)" ;; esac
done
if [ -n "$ONLY" ]; then
    read -ra only <<< "$ONLY"
    SELECTED=" ${only[*]} "
fi
for s in $SKIP; do SELECTED=${SELECTED/ $s / }; done
BINDIR=$(realpath -m "$BINDIR")
[ -n "$KUBELET_SHA256" ] && [ -n "$KUBELET_VERSION" ] || die "no kubelet pin in tests/cri/versions"

# the cache is private: the kubelet in it is run as root
mkdir -p "$CACHE" || die "cannot make $CACHE"
[ -O "$CACHE" ] || die "$CACHE is not owned by this user"
chmod 0700 "$CACHE" || die "cannot make $CACHE private"
# one run at a time on a cache (its logs, its registry data, the kubelet's ports)
command -v flock > /dev/null 2>&1 || die "flock is needed (util-linux)"
exec 9> "$CACHE/run-all.lock" || die "cannot open $CACHE/run-all.lock"
flock -n 9 || die "another run-all.sh is running on $CACHE"

RUN=$(mktemp -d "${TMPDIR:-/var/tmp}/velarx-cri-tests.XXXXXX") || die "cannot make a scratch directory"
[ -n "$RUN" ] && [ -d "$RUN" ] || die "cannot make a scratch directory"
STEP_PID=
REG_PID=
REG_CONTAINER=
REG_PODMAN=()

# stop what this script started, by its PID or id, and remove its scratch directory
cleanup () {
    trap - EXIT INT TERM
    if [ -n "$STEP_PID" ]; then
        # the process group of the step; its commands that run as root need root to signal
        if [ "$(id -u)" = 0 ] || ! sudo -n kill -INT -- "-$STEP_PID" 2> /dev/null; then
            kill -INT -- "-$STEP_PID" 2> /dev/null
        fi
        wait "$STEP_PID" 2> /dev/null
    fi
    if [ -n "$REG_PID" ]; then
        kill -TERM "$REG_PID" 2> /dev/null
        wait "$REG_PID" 2> /dev/null
    fi
    if [ -n "$REG_CONTAINER" ]; then
        HOME=$RUN/home "${REG_PODMAN[@]}" rm -f -t 2 "$REG_CONTAINER" > /dev/null 2>&1
    fi
    chmod -R u+rwX "$RUN" 2> /dev/null
    rm -rf --one-file-system "$RUN"
}
interrupted () {
    echo
    echo "interrupted: stopping what was started"
    cleanup
    exit 130
}
trap cleanup EXIT
trap interrupted INT TERM

MISSING=()     # "tool" per missing tool, for the report
BLOCKED=()     # step:tool
need () { # STEP TOOL...: a command of the PATH
    local t
    for t in "${@:2}"; do
        command -v "$t" > /dev/null 2>&1 && continue
        BLOCKED+=("$1:$t")
        case " ${MISSING[*]:-} " in *" $t "*) ;; *) MISSING+=("$t") ;; esac
    done
}
need_root () { # STEP: root, or sudo
    [ "$(id -u)" = 0 ] && return 0
    command -v sudo > /dev/null 2>&1 && return 0
    BLOCKED+=("$1:root-or-sudo")
    case " ${MISSING[*]:-} " in *" root-or-sudo "*) ;; *) MISSING+=(root-or-sudo) ;; esac
}

# only prereq selected: check what every step needs
needs () { want "$1" || [ "$SELECTED" = " prereq " ]; }

collect_needs () {
    needs build && { need build make; [ "$BUILD_CMD" = "make build-debug" ] && need build cargo; need build protoc; }
    needs unit && { need unit make; [ "$UNIT_CMD" = "make test-cri" ] && need unit cargo; need unit protoc; }
    needs bats && { need bats bats crictl python3 curl skopeo; need_root bats; }
    needs mirror && need mirror skopeo curl
    needs critest && { need critest critest crictl crun unshare curl; need_root critest; }
    needs kubelet && { need kubelet crun crictl unshare sha256sum curl skopeo; need_root kubelet; }
    needs cluster && { need cluster crun crictl unshare sha256sum curl skopeo openssl tar ip; need_root cluster; }
}

hint () { # TOOL: how to get it
    case $1 in
    make) echo "make: Fedora: dnf install make; Debian/Ubuntu: apt-get install make" ;;
    cargo) echo "cargo: the Rust toolchain of rust-toolchain.toml (Fedora: dnf install cargo; Debian/Ubuntu: rustup, https://rustup.rs: their cargo package is older)" ;;
    protoc) echo "protoc: Fedora: dnf install protobuf-compiler; Debian/Ubuntu: apt-get install protobuf-compiler (and build-essential pkg-config libsqlite3-dev libzstd-dev libssl-dev to build)" ;;
    bats) echo "bats: Fedora: dnf install bats; Debian/Ubuntu: apt-get install bats" ;;
    python3) echo "python3: Fedora: dnf install python3; Debian/Ubuntu: apt-get install python3" ;;
    curl) echo "curl: Fedora: dnf install curl; Debian/Ubuntu: apt-get install curl" ;;
    skopeo) echo "skopeo: Fedora: dnf install skopeo; Debian/Ubuntu: apt-get install skopeo" ;;
    crun) echo "crun: Fedora: dnf install crun; Debian/Ubuntu: apt-get install crun" ;;
    unshare | sha256sum) echo "$1: Fedora: dnf install util-linux coreutils; Debian/Ubuntu: apt-get install util-linux coreutils" ;;
    crictl) echo "crictl: Fedora: dnf install cri-tools (or the release); Debian/Ubuntu: the crictl-v$CRI_TOOLS_VERSION-linux-amd64.tar.gz of https://github.com/kubernetes-sigs/cri-tools/releases/tag/v$CRI_TOOLS_VERSION (sha256 in tests/cri/versions), crictl into the PATH" ;;
    critest) echo "critest: Fedora and Debian/Ubuntu: the critest-v$CRI_TOOLS_VERSION-linux-amd64.tar.gz of https://github.com/kubernetes-sigs/cri-tools/releases/tag/v$CRI_TOOLS_VERSION (sha256 in tests/cri/versions), critest into the PATH" ;;
    root-or-sudo) echo "root-or-sudo: run as root, or install sudo (Fedora: dnf install sudo; Debian/Ubuntu: apt-get install sudo): the CRI is tested as root" ;;
    *) echo "$1: not found in the PATH" ;;
    esac
}

# skip_step REASON: the step has nothing to do here
skip_step () { echo "$*" > "$RUN/skip"; exit 77; }

as_root () { # COMMAND...: as root, with this PATH
    if [ "$(id -u)" = 0 ]; then env PATH="$PATH" "$@"; else sudo -n env PATH="$PATH" "$@"; fi
}

registry_up () { curl -sf -m 5 "http://$1/v2/" > /dev/null 2>&1; }

step_build () {
    cd "$TOP" || exit 1
    bash -c "$BUILD_CMD" || exit 1
    local b
    for b in velarx velarx-monitor velarx-cri; do
        [ -x "$BINDIR/$b" ] || { echo "$BINDIR/$b was not built" >&2; exit 1; }
    done
}

have_binaries () {
    local b
    for b in velarx velarx-monitor velarx-cri; do
        [ -x "$BINDIR/$b" ] || { echo "$BINDIR/$b is not built (the build step, or --bindir)" >&2; return 1; }
    done
}

step_unit () {
    cd "$TOP" || exit 1
    bash -c "$UNIT_CMD" || exit 1
}

step_bats () {
    have_binaries || exit 1
    ensure_image || exit 1
    mkdir -p "$LOGDIR/bats"
    cd "$TOP" || exit 1
    as_root env VELARX_BINDIR="$BINDIR" IMAGE="$CRI_IMAGE" REGISTRY_INSECURE="$REGISTRY" E2E_LOGDIR="$LOGDIR/bats" \
        tests/e2e/run-all.sh cri cri-checkpoint || exit 1
}

# ensure_image: the image of bats and of the kubelet's pod, as OCI; the default one
# is copied from docker.io when the registry lacks it, one from CRI_IMAGE is the caller's
ensure_image () {
    [ "$CRI_IMAGE" = "$REGISTRY/ci/alpine:3.20" ] || return 0
    if skopeo inspect --raw --tls-verify=false "docker://$CRI_IMAGE" > /dev/null 2>&1; then
        echo "$CRI_IMAGE is in the registry"
    else
        skopeo copy --format oci --override-os linux --override-arch amd64 --dest-tls-verify=false \
            docker://docker.io/library/alpine:3.20 "docker://$CRI_IMAGE" > /dev/null ||
            { echo "cannot copy docker.io/library/alpine:3.20 to $CRI_IMAGE" >&2; return 1; }
        echo "copied docker.io/library/alpine:3.20 to $CRI_IMAGE"
    fi
}

step_mirror () {
    cd "$TOP" || exit 1
    tests/cri/critest.sh mirror "$REGISTRY" || exit 1
    ensure_image || exit 1
}

step_critest () {
    have_binaries || exit 1
    cd "$TOP" || exit 1
    as_root env REGISTRY="$REGISTRY" CRITEST_OUT="$LOGDIR/critest.out" \
        CRITEST_KNOWN_FAILURES="$TOP/tests/cri/critest-known-failures-root.txt" \
        ${CRITEST_ARGS:+CRITEST_ARGS="$CRITEST_ARGS"} \
        tests/cri/critest.sh run-root "$BINDIR" "$FOCUS" || exit 1
}

sha256_of () { sha256sum "$1" | cut -d' ' -f1; }

# the kubelet binary: KUBELET, the cached one, the one in the PATH, else downloaded once.
# The cached one is run from a copy in the private scratch directory, verified there:
# nothing can change it between the check and the run.
kubelet_binary () {
    if [ -n "${KUBELET:-}" ]; then
        [ -x "$KUBELET" ] || { echo "KUBELET=$KUBELET is not an executable" >&2; return 1; }
        echo "$KUBELET"
        return 0
    fi
    local dir=$CACHE/kubelet-v$KUBELET_VERSION run=$RUN/kubelet
    if [ -f "$dir/kubelet" ]; then
        cp "$dir/kubelet" "$run" && chmod 0755 "$run" || return 1
        if [ "$(sha256_of "$run")" = "$KUBELET_SHA256" ]; then
            echo "$run"
            return 0
        fi
        echo "$dir/kubelet is not the pinned one: downloaded again" >&2
        rm -f "$run" "$dir/kubelet"
    fi
    if command -v kubelet > /dev/null 2>&1; then
        command -v kubelet
        return 0
    fi
    local url=https://dl.k8s.io/release/v$KUBELET_VERSION/bin/linux/amd64/kubelet sum published rc
    # (to the private scratch directory: a partial download is never in the cache)
    curl -fsSL --proto =https --proto-redir =https -m 600 -o "$run" "$url" 2> "$RUN/curl.err"
    rc=$?
    if [ "$rc" != 0 ]; then
        rm -f "$run"
        echo "cannot download $url ($(tail -n 1 "$RUN/curl.err"))" >&2
        # no network (cannot resolve, connect, a timeout, TLS connect): skipped; anything else fails
        case $rc in 5 | 6 | 7 | 28 | 35 | 56) return 2 ;; esac
        return 1
    fi
    sum=$(sha256_of "$run")
    published=$(curl -fsSL --proto =https --proto-redir =https -m 30 "$url.sha256" 2> /dev/null | cut -d' ' -f1)
    if [ "$sum" != "$KUBELET_SHA256" ] || [ "$sum" != "$published" ]; then
        rm -f "$run"
        echo "the sha256 of $url is $sum, not the pinned $KUBELET_SHA256 and the published ${published:-(none)}" >&2
        return 1
    fi
    chmod 0755 "$run"
    # into the cache under a temporary name, then renamed: never a partial file there
    local tmp
    if ! { mkdir -p "$dir" && chmod 0700 "$dir" && tmp=$(mktemp "$dir/kubelet.XXXXXX") &&
        cp "$run" "$tmp" && chmod 0755 "$tmp" && mv -f "$tmp" "$dir/kubelet"; }; then
        rm -f "${tmp:-}"
        echo "cannot keep the kubelet in $dir" >&2
    fi
    echo "downloaded $url (sha256 verified)" >&2
    echo "$run"
}

step_kubelet () {
    have_binaries || exit 1
    local k rc
    k=$(kubelet_binary)
    rc=$?
    [ "$rc" = 2 ] && skip_step "no kubelet and none can be downloaded (no network): KUBELET=path, or kubelet in the PATH"
    [ "$rc" = 0 ] || exit 1
    ensure_image || exit 1
    mkdir -p "$LOGDIR/kubelet"
    cd "$TOP" || exit 1
    as_root env KUBELET="$k" IMAGE="$CRI_IMAGE" REGISTRY_INSECURE="$REGISTRY" KUBELET_LOGS="$LOGDIR/kubelet" \
        tests/cri/kubelet.sh "$BINDIR" || exit 1
    # (kubelet.sh ends with 0 and SKIP: when something is missing)
}

# pinned_file URL SHA256 NAME: the file of URL in $RUN/NAME, as the pinned sha256 says; kept in
# the cache by its hash (verified again on every use).  Returns 2 when there is no network.
pinned_file () {
    local url=$1 sum=$2 out=$RUN/$3 rc cached=$CACHE/pinned/$2
    if [ -f "$cached" ]; then
        cp "$cached" "$out" || return 1
        [ "$(sha256_of "$out")" = "$sum" ] && return 0
        rm -f "$cached" "$out"
    fi
    curl -fsSL --proto =https --proto-redir =https -m 600 -o "$out" "$url" 2> "$RUN/curl.err"
    rc=$?
    if [ "$rc" != 0 ]; then
        rm -f "$out"
        echo "cannot download $url ($(tail -n 1 "$RUN/curl.err"))" >&2
        case $rc in 5 | 6 | 7 | 28 | 35 | 56) return 2 ;; esac
        return 1
    fi
    if [ "$(sha256_of "$out")" != "$sum" ]; then
        echo "the sha256 of $url is $(sha256_of "$out"), not the pinned $sum" >&2
        rm -f "$out"
        return 1
    fi
    mkdir -p "$CACHE/pinned" && cp "$out" "$cached.tmp" && mv -f "$cached.tmp" "$cached"
    echo "downloaded $url (sha256 verified)" >&2
}

# the tools of the cluster step in $RUN/cluster-tools (and the CNI plugins in $RUN/cni): the
# kubelet as kubelet_binary says, the rest of the pins of tests/cri/versions
cluster_tools () {
    local t=$RUN/cluster-tools rel=https://dl.k8s.io/release/v$KUBELET_VERSION/bin/linux/amd64 rc n var k
    mkdir -p "$t" "$RUN/cni" "$RUN/etcd" || return 1
    k=$(kubelet_binary)
    rc=$?
    [ "$rc" = 0 ] || return "$rc"
    ln -sf "$k" "$t/kubelet"
    for n in kube-apiserver kube-controller-manager kube-scheduler kubectl; do
        var=$(echo "$n" | tr a-z- A-Z_)_SHA256
        pinned_file "$rel/$n" "$(pin "$var")" "$n" || return $?
        chmod 0755 "$RUN/$n" && mv "$RUN/$n" "$t/$n" || return 1
    done
    local v
    v=$(pin ETCD_VERSION)
    pinned_file "https://github.com/etcd-io/etcd/releases/download/v$v/etcd-v$v-linux-amd64.tar.gz" "$(pin ETCD_SHA256)" etcd.tar.gz || return $?
    tar -xzf "$RUN/etcd.tar.gz" -C "$RUN/etcd" --strip-components=1 "etcd-v$v-linux-amd64/etcd" && ln -sf "$RUN/etcd/etcd" "$t/etcd" || return 1
    v=$(pin CNI_PLUGINS_VERSION)
    pinned_file "https://github.com/containernetworking/plugins/releases/download/v$v/cni-plugins-linux-amd64-v$v.tgz" "$(pin CNI_PLUGINS_SHA256)" cni.tgz || return $?
    tar -xzf "$RUN/cni.tgz" -C "$RUN/cni" ./bridge ./host-local || return 1
}

step_cluster () {
    have_binaries || exit 1
    local rc
    cluster_tools
    rc=$?
    [ "$rc" = 2 ] && skip_step "the tools of the cluster cannot be downloaded (no network): KUBELET=path does not give the others"
    [ "$rc" = 0 ] || exit 1
    ensure_image || exit 1
    mkdir -p "$LOGDIR/cluster"
    cd "$TOP" || exit 1
    as_root env IMAGE="$CRI_IMAGE" REGISTRY_INSECURE="$REGISTRY" CLUSTER_LOGS="$LOGDIR/cluster" \
        tests/cri/cluster.sh "$BINDIR" "$RUN/cluster-tools" "$RUN/cni" || exit 1
}

REG_STATE=       # existing, own, none
registry_resolve () {
    [ -z "$REG_STATE" ] || return 0
    if registry_up "$REGISTRY"; then
        REG_STATE=existing
        return 0
    fi
    REG_STATE=none
    [ "$OWN_REGISTRY" = 1 ] || return 0
    local port data=$CACHE/registry-data
    port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])') || return 0
    mkdir -p "$data" "$RUN/home"
    local bin=${REGISTRY_BIN:-$(command -v registry || true)}
    if [ -n "$bin" ]; then
        cat > "$RUN/registry.yml" <<YAML
version: 0.1
storage:
  filesystem:
    rootdirectory: $data
http:
  addr: 127.0.0.1:$port
YAML
        "$bin" serve "$RUN/registry.yml" > "$LOGDIR/registry.log" 2>&1 &
        REG_PID=$!
    elif command -v podman > /dev/null 2>&1; then
        # a scratch podman store under the cache: the default store is not touched
        mkdir -p "$CACHE/registry-podman/root" "$CACHE/registry-podman/run"
        REG_PODMAN=(podman --root "$CACHE/registry-podman/root" --runroot "$CACHE/registry-podman/run")
        REG_CONTAINER=$(HOME=$RUN/home "${REG_PODMAN[@]}" run -d --rm -p "127.0.0.1:$port:5000" \
            -v "$data:/var/lib/registry:Z" "$REGISTRY_IMAGE" 2> "$LOGDIR/registry.log") || REG_CONTAINER=
        [ -n "$REG_CONTAINER" ] || return 0
    else
        echo "--own-registry needs a registry binary or podman" > "$LOGDIR/registry.log"
        return 0
    fi
    # (a poll: a registry that listens says nothing; the port is the only trace)
    for _ in $(seq 150); do
        registry_up "localhost:$port" && { REG_STATE=own; REGISTRY=localhost:$port; return 0; }
        sleep 0.2
    done
}

declare -A RESULT DETAIL
FAILED=0
CRITEST_COUNTS=

report () { # STEP RESULT DETAIL
    RESULT[$1]=$2
    DETAIL[$1]=$3
    case $2 in
    ok) printf '%-9s ok%s\n' "$1" "${3:+ ($3)}" ;;
    FAILED) printf '%-9s FAILED%s\n' "$1" "${3:+: $3}"; FAILED=1 ;;
    *) printf '%-9s skipped: %s\n' "$1" "$3" ;;
    esac
}

blocked_by () { # STEP: the missing tools of it
    local b out=
    for b in "${BLOCKED[@]:-}"; do
        [ "${b%%:*}" = "$1" ] && out="$out ${b#*:}"
    done
    echo "${out# }"
}

run_step () {
    local s=$1 log=$LOGDIR/$1.log rc missing
    want "$s" || return 0
    [ "$FAIL_FAST" = 1 ] && [ "$FAILED" = 1 ] && { report "$s" skipped "an earlier step failed (--fail-fast)"; return 0; }
    missing=$(blocked_by "$s")
    if [ -n "$missing" ]; then
        if want prereq; then
            report "$s" skipped "missing: $missing (see prereq)"
        else
            report "$s" FAILED "missing: $missing (run the prereq step)"
        fi
        return 0
    fi
    case $s in
    mirror | critest | kubelet | cluster | bats)
        registry_resolve
        if [ "$REG_STATE" = none ]; then
            report "$s" FAILED "no registry answers at $REGISTRY (start one, or --own-registry)"
            return 0
        fi
        [ -n "$CRI_IMAGE" ] || CRI_IMAGE=$REGISTRY/ci/alpine:3.20
        ;;
    esac
    rm -f "$RUN/skip"
    set -m
    ( step_"$s" ) < /dev/null > "$log" 2>&1 &
    STEP_PID=$!
    wait "$STEP_PID"
    rc=$?
    STEP_PID=
    set +m
    if [ "$rc" = 77 ] && [ -f "$RUN/skip" ]; then
        report "$s" skipped "$(cat "$RUN/skip")"
    elif [ "$rc" = 0 ]; then
        case $s in
        kubelet | cluster)
            if grep -q '^SKIP:' "$log"; then report "$s" skipped "$(grep -m1 '^SKIP:' "$log" | sed 's/^SKIP: //')"
            elif grep -q '^PASS' "$log"; then report "$s" ok ""
            else report "$s" FAILED "no PASS in $log"; fi ;;
        critest)
            counts "$LOGDIR/critest.out"
            report "$s" ok "$CRITEST_COUNTS" ;;
        unit)
            report "$s" ok "$(awk '/^test result: ok/ { n += $4 } END { print n + 0 " tests" }' "$log")" ;;
        *) report "$s" ok "" ;;
        esac
    else
        if [ "$s" = critest ]; then counts "$LOGDIR/critest.out"; else CRITEST_COUNTS=; fi
        report "$s" FAILED "see $log${CRITEST_COUNTS:+ ($CRITEST_COUNTS)}"
        tail -n 8 "$log" | sed 's/^/    | /'
    fi
}

# counts FILE: the numbers of a critest run
CT_RUN=-; CT_PASSED=-; CT_FAILED=-; CT_SKIPPED=-
counts () {
    [ -f "$1" ] || return 0
    local line
    line=$(grep -m1 -E '[0-9]+ Passed \| [0-9]+ Failed' "$1") || return 0
    CT_PASSED=$(echo "$line" | sed -n 's/.* \([0-9]*\) Passed.*/\1/p')
    CT_FAILED=$(echo "$line" | sed -n 's/.*| \([0-9]*\) Failed.*/\1/p')
    CT_SKIPPED=$(echo "$line" | sed -n 's/.*| \([0-9]*\) Skipped.*/\1/p')
    CT_RUN=$(sed -n 's/^Ran \([0-9]*\) of.*/\1/p' "$1" | head -n 1)
    CRITEST_COUNTS="run $CT_RUN, passed $CT_PASSED, failed $CT_FAILED, skipped $CT_SKIPPED"
}

mkdir -p "$LOGDIR" || die "cannot make $LOGDIR"
# this run replaces the logs of the last
rm -rf "$LOGDIR/bats" "$LOGDIR/kubelet" "$LOGDIR/cluster" "$LOGDIR/registry.log" "$LOGDIR/critest.out"
for s in $STEPS; do rm -f "$LOGDIR/$s.log"; done

collect_needs

# prereq: reported here, in the foreground
if want prereq; then
    if [ ${#MISSING[@]} -eq 0 ]; then
        report prereq ok ""
    else
        report prereq FAILED "missing: ${MISSING[*]}"
        {
            echo "  how to get what is missing (nothing is installed by this script):"
            for t in "${MISSING[@]}"; do echo "    $(hint "$t")"; done
        } | tee "$LOGDIR/prereq.log"
    fi
fi

# root: the sudo password is asked here, in the foreground, not in a step
if [ "$(id -u)" != 0 ] && { want bats || want critest || want kubelet || want cluster; } && command -v sudo > /dev/null 2>&1; then
    sudo -v || die "sudo is needed for the steps that run as root"
fi

for s in build unit bats mirror critest kubelet cluster; do
    run_step "$s"
done

echo
echo "step      result"
for s in $STEPS; do
    want "$s" || continue
    printf '%-9s %s%s\n' "$s" "${RESULT[$s]:-?}" "${DETAIL[$s]:+  ${DETAIL[$s]}}"
done
if want critest && [ "$CT_RUN" != - ]; then
    echo
    echo "critest   run $CT_RUN  passed $CT_PASSED  failed $CT_FAILED  skipped $CT_SKIPPED"
fi
echo
echo "logs: $LOGDIR"
[ "$FAILED" = 0 ] || echo "FAILED"
exit "$FAILED"
