# SPDX-License-Identifier: Apache-2.0
# Stats and metrics of a pod and its container, against a rootless daemon in
# a scratch HOME: the working set, the files the container wrote (bytes and
# inodes) in the stats, and the metrics in the names of cAdvisor.
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/metrics.bats
#
# Skipped without python3, curl or the image.

load helpers

sh_ () { "$BIN/velarx" --config "$CONF" --socket "$ESOCK" "$@"; }
api () { curl -sf --unix-socket "$SOCK" "http://d/v5.0.0/libpod$1"; }
py () { python3 -I -c "$@"; }
# the stats of the container, asked until the kernel has added the page
# faults and the file pages of its cgroup to memory.stat (every 2 s)
fetch_stats () {
    local i
    # (a poll: the kernel updates the counters every 2 s and tells nothing)
    for i in $(seq 100); do
        stats=$(api "/containers/stats?stream=false&size=true&containers=mc")
        echo "$stats" | py 'import json, sys; sys.exit(json.load(sys.stdin)["Stats"][0]["PageFaults"] == 0)' && break
        sleep 0.1
    done
}

setup_file () {
    command -v curl > /dev/null && command -v python3 > /dev/null || skip "needs curl and python3"
    # the cgroup of a container (its stats) needs a delegated one: the daemon asks
    # the service manager for a scope
    local RUNDIR=/run/user/$(id -u) i
    test "$(id -u)" != 0 && ! test -S "$RUNDIR/systemd/private" && skip "no user manager"
    e2e_setup_file
    export IMG=${IMAGE:-${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}}
    export CONF=$XDG_CONFIG_HOME/velarx/config.toml
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    if [ "$(id -u)" != 0 ]; then
        export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$RUNDIR/bus}
        chmod 700 "$XDG_RUNTIME_DIR"
        ln -s "$RUNDIR/systemd" "$XDG_RUNTIME_DIR/systemd"
    fi
    cat > "$CONF" <<EOT
$(e2e_bridge_toml)
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/run/velarx"
root_dir = "$WORKDIR/root"
shutdown_timeout_secs = 5
cgroup_manager = "systemd"
[storage]
root = "$WORKDIR/storage"
EOT
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"
    e2e_start_daemon
    e2e_start_api
    sh_ image pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"

    sh_ pod create --name mp > /dev/null
    sh_ run -d --pod mp --name mc "$IMG" sh -c 'mkdir -p /var/w && for i in 1 2 3 4 5 6 7 8 9 10; do echo hi > /var/w/f$i; done; sleep 300' > /dev/null
    sh_ exec mc timeout 30 sh -c 'until test -e /var/w/f10; do :; done'
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    sh_ pod rm -t 0 -f mp > /dev/null 2>&1
    e2e_remove_containers "$BIN/velarx" "$ESOCK"
    e2e_teardown_file
}

@test "stats: the files the container wrote, inodes" {
    fetch_stats
    check "stats: the files the container wrote, inodes" "ok" "$(echo "$stats" | py '
import json, sys
s = json.load(sys.stdin)["Stats"][0]
print("ok" if s["RwInodes"] >= 11 and s["RwBytes"] >= 4096 * 10 else s)')"
}

@test "stats: the working set is at most the usage" {
    fetch_stats
    check "stats: the working set is at most the usage" "ok" "$(echo "$stats" | py '
import json, sys
s = json.load(sys.stdin)["Stats"][0]
print("ok" if 0 < s["MemWorkingSet"] <= s["MemUsage"] and s["PageFaults"] > 0 else s)')"
}

@test "stats without size: no writable layer" {
    check "stats without size: no writable layer" "null" "$(api "/containers/stats?stream=false&containers=mc" | py '
import json, sys
print(json.dumps(json.load(sys.stdin)["Stats"][0]["RwBytes"]))')"
}

@test "metrics descriptors: help and the labels id, image, name" {
    descriptors=$(api "/metrics/descriptors")
    check "descriptors: every one has help and the labels id, image, name" "ok" "$(echo "$descriptors" | py '
import json, sys
d = json.load(sys.stdin)
bad = [x["name"] for x in d if not x["help"] or x["labels"][:3] != ["id", "image", "name"]]
print("ok" if len(d) > 50 and not bad else bad)')"
}

@test "pod metrics: the samples have the labels of their descriptors" {
    api "/metrics/descriptors" > "$WORKDIR/descriptors.json"
    api "/pods/mp/metrics" > "$WORKDIR/metrics.json"
    check "metrics: the samples have the labels of their descriptors" "ok" "$(py '
import json, sys
w = sys.argv[1]
d = {x["name"]: x for x in json.load(open(w + "/descriptors.json"))}
pods = json.load(open(w + "/metrics.json"))
assert len(pods) == 1, pods
p = pods[0]
samples = p["samples"] + [s for c in p["containers"] for s in c["samples"]]
bad = [s["name"] for s in samples if s["name"] not in d or len(s["labels"]) != len(d[s["name"]]["labels"])]
print("ok" if samples and not bad else bad)' "$WORKDIR")"
}

@test "pod metrics: the container, not the infra container, is listed" {
    api "/pods/mp/metrics" > "$WORKDIR/metrics.json"
    check "metrics: the container, not the infra container, is listed" "mc" "$(py '
import json, sys
p = json.load(open(sys.argv[1] + "/metrics.json"))[0]
print(",".join(c["name"] for c in p["containers"]))' "$WORKDIR")"
}

@test "pod metrics: what a kubelet reads is there" {
    api "/pods/mp/metrics" > "$WORKDIR/metrics.json"
    check "metrics: what a kubelet reads is there" "ok" "$(py '
import json, sys
w = sys.argv[1]
p = json.load(open(w + "/metrics.json"))[0]
have = {s["name"]: s["value"] for s in p["samples"] + p["containers"][0]["samples"]}
want = ["container_cpu_usage_seconds_total", "container_memory_working_set_bytes", "container_memory_usage_bytes",
        "container_memory_rss", "container_fs_usage_bytes", "container_fs_inodes_total", "container_fs_limit_bytes",
        "container_network_receive_bytes_total", "container_network_transmit_bytes_total", "container_processes",
        "container_threads", "container_file_descriptors", "container_sockets", "container_start_time_seconds",
        "container_last_seen", "container_spec_cpu_period", "container_spec_cpu_shares", "container_oom_events_total"]
missing = [n for n in want if n not in have]
ok = not missing and have["container_memory_working_set_bytes"] <= have["container_memory_usage_bytes"] \
    and have["container_fs_usage_bytes"] > 0 and have["container_processes"] >= 1
print("ok" if ok else (missing, have))' "$WORKDIR")"
}

@test "metrics of all the running pods and of a missing pod" {
    check "metrics: all the running pods" "1" "$(api "/pods/metrics" | py 'import json, sys; print(len(json.load(sys.stdin)))')"
    api "/pods/nosuchpod/metrics" > /dev/null 2>&1
    check "metrics of a missing pod fail" 22 $?
}

# --cgroups=disabled: the cgroup it is in is not its own, no numbers
@test "stats of a container with no cgroup of its own fail" {
    sh_ run -d --name nocg --cgroups=disabled "$IMG" sleep 300 > /dev/null
    api "/containers/stats?stream=false&containers=nocg" > /dev/null 2>&1
    rc=$?
    sh_ rm -f -t 0 nocg > /dev/null
    check "stats of a container with no cgroup of its own fail" 22 $rc
}
