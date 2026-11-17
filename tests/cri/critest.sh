#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# critest (cri-tools, the CRI validation suite) against velarx-cri.
#
#   tests/cri/critest.sh mirror [REGISTRY]            # once: the test images, as they are, in a registry
#   sudo tests/cri/critest.sh run-root BINDIR [FOCUS] # as root, in a private mount namespace
#   sudo CRITEST_BENCHMARK=1 tests/cri/critest.sh run-root BINDIR   # the benchmarks, not the specs
#
# tests/cri/run-all.sh runs this among the other CRI tests (make cri-tests).
# The CRI is run and tested as root only, as a kubelet does.
#
# BINDIR has velarx, velarx-monitor and velarx-cri (the engine is `velarx varlink`;
# velarx-cri talks to its socket and starts nothing).  The results (the failed specs, the
# counts) are printed, the whole output is in $CRITEST_OUT (default
# /var/tmp/velarx-critest.out).  critest and crictl have to be installed.
#
# The images of critest are Docker schema 2 images, which the engine reads as the
# registry serves them.  `mirror` copies them with skopeo as they are
# (linux/amd64 of a list; the image that critest pulls by its digest with that
# digest) into the registry (default localhost:5000, plain HTTP, under
# critest/) and `run-root` maps their registries to the copies with a registries.conf
# mirror, so the specs do not depend on the network.  The specs that need a pod
# IP the node can reach, and the ones that mount on the host, need root.
#
# CRITEST_BENCHMARK=1: runs the benchmarks of critest (`-benchmark`, which the specs skip),
# a few rounds each, with the mirrored images (no network); the numbers are in the output.
#
# CRITEST_KNOWN_FAILURES=FILE: the exit status is 0 when critest ran and
# every spec that failed is named in FILE (a string of the spec's line per
# line of FILE, # for comments): tests/cri/critest-known-failures-root.txt
# (`make critest-root`).  Without it the status is critest's.
set -u
# the waits of the end to end tests (READY=1, inotify, pidfd)
. "$(dirname "$(realpath "$0")")/../e2e/bats/wait.bash"
REGISTRY=${REGISTRY:-localhost:5000}
OUT=${CRITEST_OUT:-/var/tmp/velarx-critest.out}

# mirror [REGISTRY]: copies what the registry does not have yet (skopeo inspect of the
# destination first), so a second run copies nothing
mirror () {
    local reg=${1:-$REGISTRY} g=gcr.io/k8s-staging-cri-tools t copied=0 present=0
    command -v skopeo > /dev/null || { echo "skopeo is needed" >&2; exit 1; }
    have () { skopeo inspect --raw --tls-verify=false "docker://$1" > /dev/null 2>&1; }
    cp1 () { # SOURCE DESTINATION
        if have "$reg/critest/$2"; then present=$((present + 1)); return 0; fi
        skopeo copy --override-os linux --override-arch amd64 --dest-tls-verify=false \
            "docker://$1" "docker://$reg/critest/$2" > /dev/null || { echo "cannot copy $1" >&2; exit 1; }
        copied=$((copied + 1))
    }
    # (the manifest as it is, so the registry has it by the digest critest pulls it by)
    t=sha256:9700f9a2f5bf2c45f2f605a0bd3bce7cf37420ec9d3ed50ac2758413308766bf
    if have "$reg/critest/gcr/test-image-digest:digest"; then
        present=$((present + 1))
    else
        skopeo copy --preserve-digests --dest-tls-verify=false \
            "docker://$g/test-image-digest@$t" "docker://$reg/critest/gcr/test-image-digest:digest" > /dev/null ||
            { echo "cannot copy test-image-digest" >&2; exit 1; }
        copied=$((copied + 1))
    fi
    for t in hostnet-nginx-amd64:latest test-image-1:latest test-image-2:latest test-image-3:latest \
        test-image-latest:latest test-image-tag:test test-image-tag:all test-image-tags:1 test-image-tags:2 \
        test-image-tags:3 test-image-user-uid:latest test-image-predefined-group:latest \
        test-image-user-username:latest test-image-user-uid-group:latest test-image-user-username-group:latest; do
        cp1 "$g/$t" "gcr/$t"
    done
    for t in busybox:1.29-2 httpd:2.4.39-4 nginx:1.14-2 nonewprivs:1.3; do
        cp1 "registry.k8s.io/e2e-test-images/$t" "rk8s/e2e-test-images/$t"
    done
    cp1 registry.k8s.io/pause:3.9 rk8s/pause:3.9
    cp1 registry.k8s.io/pause:3.9 k8sgcr/pause:3.9
    echo "mirror: $copied copied, $present already in $reg"
}

# registries_conf FILE: the mirrors of the registries of critest
registries_conf () {
    cat > "$1" <<TOML
[[registry]]
prefix = "gcr.io/k8s-staging-cri-tools"
location = "gcr.io/k8s-staging-cri-tools"
[[registry.mirror]]
location = "$REGISTRY/critest/gcr"
insecure = true
[[registry]]
prefix = "registry.k8s.io"
location = "registry.k8s.io"
[[registry.mirror]]
location = "$REGISTRY/critest/rk8s"
insecure = true
[[registry]]
prefix = "k8s.gcr.io"
location = "k8s.gcr.io"
[[registry.mirror]]
location = "$REGISTRY/critest/k8sgcr"
insecure = true
[[registry]]
location = "$REGISTRY"
insecure = true
TOML
}

# serve BINDIR W: the config of the engine under W (its socket W/engine.sock), the
# command that runs it as W/velarx (the caller's environment says where HOME and XDG_* are).
# BIN is where the binaries are run from: with SELinux, copies in W/bin labelled as
# podman's and conmon's are (`velarx` the runtime's executable, `velarx-monitor`
# conmon's, which runs at the level s0): the pipes of the output of a container
# are the monitor's, and a container (`container_t` of its own categories) may
# open them again (`/dev/stderr`, as nginx does) only when they are of the level s0.
serve () {
    local bin=$1 w=$2
    mkdir -p "$w/run" "$w/data" "$w/etc"
    BIN=$bin
    if command -v selinuxenabled > /dev/null && selinuxenabled; then
        BIN=$w/bin
        mkdir -p "$BIN"
        cp "$bin/velarx" "$bin/velarx-monitor" "$bin/velarx-cri" "$BIN/"
        chcon -t container_runtime_exec_t "$BIN/velarx" "$BIN/velarx-cri" &&
            chcon -t conmon_exec_t "$BIN/velarx-monitor" || return 1
    fi
    cat > "$w/etc/config.toml" <<TOML
storage.root = "$w/data"
[engine]
socket = "$w/engine.sock"
[server]
state_dir = "$w/run"
root_dir = "$w/data"
shutdown_timeout_secs = 5
[userns]
uid_ranges = ["655360-720895"]
gid_ranges = ["655360-720895"]
allocation_size = 65536
TOML
    registries_conf "$w/etc/registries.conf"
    export VELARX_REGISTRIES_CONF=$w/etc/registries.conf
    printf '#!/bin/sh\nexec %s --config %s "$@"\n' "$BIN/velarx" "$w/etc/config.toml" > "$w/velarx"
    chmod +x "$w/velarx"
}

# engine W: start the engine of the files of W (as the caller's children: run
# it under the given command, if any) and wait until it says READY=1
engine () {
    local w=$1; shift
    # (in a session of its own, as velarx-cri: a Ctrl-C of the caller's process group
    # does not stop them before finish removed the pods through them)
    E2E_SPAWN_LOG=$w/engine.log e2e_spawn_ready ENGINE_PID "$@" setsid "$w/velarx" varlink && return 0
    echo "the engine does not start" >&2
    tail "$w/engine.log" >&2
    return 1
}

finish () { # W PID: stop the frontend and whatever runs under W
    local w=$1 pid=$2 p
    # the pods an interrupted critest left (their monitors do not run from W)
    if [ -S "$w/cri.sock" ] && command -v crictl > /dev/null; then
        crictl -r "unix://$w/cri.sock" -i "unix://$w/cri.sock" rmp -fa > /dev/null 2>&1
        crictl -r "unix://$w/cri.sock" -i "unix://$w/cri.sock" rm -fa > /dev/null 2>&1
    fi
    if [ "${pid:-0}" -gt 0 ] 2> /dev/null; then
        kill -INT "$pid" 2> /dev/null
        wait "$pid" 2> /dev/null
    fi
    # (the processes that run from W, a directory of mktemp: none of another run)
    # shellcheck disable=SC2009
    local left
    left=$(ps -eo pid,args | grep -F "$w" | grep -v grep | awk '{ print $1 }')
    for p in $left; do kill -INT "$p" 2> /dev/null; done
    for p in $left; do e2e_wait_exit "$p" 20 2> /dev/null; done
    chmod -R u+rwX "$w" 2> /dev/null
    rm -rf "$w"
}

summary () { # STATUS: critest's
    grep -E "^\s*\[FAIL\]|^Ran |Passed" "$OUT" | sort -u
    # (the benchmarks print no "Ran" line)
    grep -qE "^Ran " "$OUT" || grep -oE "(SUCCESS|FAIL)! .*" "$OUT"
    [ -n "${CRITEST_KNOWN_FAILURES:-}" ] || return "${1:-1}"
    grep -qE "^Ran |SUCCESS!" "$OUT" || { echo "critest did not run the specs" >&2; return 1; }
    grep -qE "^(FAIL!|Ran 0 of)" "$OUT" && ! grep -qE "^\s*\[FAIL\]" "$OUT" &&
        { echo "critest failed without a failed spec" >&2; return 1; }
    local unexpected
    unexpected=$(grep -E "^\s*\[FAIL\]" "$OUT" | sort -u | grep -vFf <(grep -v -e '^#' -e '^[[:space:]]*$' "$CRITEST_KNOWN_FAILURES"))
    [ -z "$unexpected" ] || { echo "specs that fail and are not known to:" >&2; echo "$unexpected" >&2; return 1; }
}

run_root () {
    [ "$(id -u)" = 0 ] || { echo "run-root needs root" >&2; exit 1; }
    local bin; bin=$(realpath "$1"); local focus=${2:-}
    # a mount namespace of its own: the mounts of the specs do not reach the host
    exec unshare -m --propagation private "$0" in-namespace "$bin" "$focus"
}

in_namespace () {
    local bin=$1 focus=${2:-}
    local w; w=$(mktemp -d /var/tmp/velarx-critest.XXXXXX)
    serve "$bin" "$w" || { rm -rf "$w"; return 1; }
    # (an interrupted run stops what it started, so it can be run again)
    trap 'finish "$w" "${ENGINE_PID:-0}"; exit 130' INT TERM
    engine "$w" || { finish "$w" "${ENGINE_PID:-0}"; return 1; }
    setsid "$BIN/velarx-cri" --socket "$w/cri.sock" --engine-socket "$w/engine.sock" --checkpoint-dir "$w/checkpoints" > "$w/cri.log" 2>&1 &
    local pid=$!
    trap 'finish "$w" "$pid"; exit 130' INT TERM
    e2e_wait_path_of "$w/cri.sock" "$pid" 60 || { echo "velarx-cri does not listen" >&2; tail "$w/cri.log" >&2; finish "$w" "$pid"; return 1; }
    local bench=
    if [ -n "${CRITEST_BENCHMARK:-}" ]; then
        # (the benchmarks that have no number of rounds skip themselves)
        cat > "$w/bench-params.yml" <<YAML
containersNumber: 6
containersNumberParallel: 2
podsNumber: 6
podsNumberParallel: 2
imagesNumber: 4
imagesNumberParallel: 2
imagePullingBenchmarkImage: registry.k8s.io/e2e-test-images/busybox:1.29-2
imageListingBenchmarkImages:
  - registry.k8s.io/e2e-test-images/busybox:1.29-2
  - registry.k8s.io/e2e-test-images/httpd:2.4.39-4
YAML
        cat > "$w/bench-images.yml" <<YAML
defaultTestContainerImage: registry.k8s.io/e2e-test-images/busybox:1.29-2
webServerTestImage: registry.k8s.io/e2e-test-images/nginx:1.14-2
YAML
        bench="-benchmark --benchmarking-params-file=$w/bench-params.yml --test-images-file=$w/bench-images.yml"
    fi
    # (CRITEST_ARGS: words)
    # shellcheck disable=SC2086
    critest --runtime-endpoint "unix://$w/cri.sock" --image-endpoint "unix://$w/cri.sock" \
        ${focus:+--ginkgo.focus="$focus"} --ginkgo.no-color $bench ${CRITEST_ARGS:-} > "$OUT" 2>&1
    local rc=$?
    finish "$w" "$pid"
    summary "$rc"
}

case ${1:-} in
mirror) shift; mirror "$@" ;;
run-root) shift; run_root "$@" ;;
in-namespace) shift; in_namespace "$@" ;;
*) sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//; /^set -u/d' >&2; exit 2 ;;
esac
