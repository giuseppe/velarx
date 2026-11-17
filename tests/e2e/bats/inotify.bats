# SPDX-License-Identifier: Apache-2.0
# The inotify instances of a user are few (fs.inotify.max_user_instances, 128
# by default; root shares them with udev and the service manager), so a
# container must not cost one: a monitor holds none (it polls the file of its
# cgroup for the out of memory events), and any other process holds one at
# most, for all its waits.  As root 150 containers run with the default limit
# (E2E_INOTIFY_CONTAINERS changes the number).  Run it as an ordinary user or
# as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# The inotify instances a process holds.
instances_of () {
    local n=0 f
    for f in /proc/"$1"/fd/*; do
        case "$(readlink "$f" 2> /dev/null)" in *'anon_inode:inotify') n=$((n + 1)) ;; esac
    done
    echo "$n"
}

# The instances of all the processes of this user.
instances_of_user () {
    local n=0 p
    for p in $(ps -u "$(id -u)" -o pid=); do
        n=$((n + $(instances_of "$p")))
    done
    echo "$n"
}

# monitor_instances: the instances all the monitors of the file hold.
monitor_instances () {
    local n=0 p
    for p in $(e2e_monitors "$WORKDIR"); do
        n=$((n + $(instances_of "$p")))
    done
    echo "$n"
}

@test "a monitor holds no inotify instance" {
    for i in 1 2 3; do
        sh_ container run -d --name in$i --network none "$IMAGE" sleep 1000 > /dev/null
    done
    check_match "three monitors" "^3$" "$(e2e_monitors "$WORKDIR" | wc -l)"
    check_match "inotify instances of the monitors" "^0$" "$(monitor_instances)"
    for i in 1 2 3; do
        sh_ container rm -f -t 0 in$i > /dev/null
    done
}

@test "as root 150 containers run with the default limit of inotify instances" {
    skip_unless_root
    local before after i n=${E2E_INOTIFY_CONTAINERS:-150}
    before=$(instances_of_user)
    for i in $(seq $n); do
        sh_ container run -d --name many$i --network none "$IMAGE" sleep 1000 > /dev/null 2> "$WORKDIR/many.err" ||
            { echo "container $i" >&2; cat "$WORKDIR/many.err" >&2; exit 1; }
    done
    after=$(instances_of_user)
    echo "# instances of the user: $before before, $after after $n containers" >&3
    check_match "inotify instances of the monitors" "^0$" "$(monitor_instances)"
    # (the other programs of the user make and close instances meanwhile)
    check "growth of the instances of the user below 10" 1 "$((after - before < 10))"
    for i in $(seq $n); do
        sh_ container rm -f -t 0 many$i > /dev/null
    done
}

# The engine starts many containers at once: each start waits for the cgroup
# of its scope, and the waits share the one instance of the engine.
@test "100 starts at once: the engine holds one inotify instance at most" {
    local i max=0 n engine
    engine=$(cat "$WORKDIR/daemon.pid")
    : > "$WORKDIR/burst.sampling"
    # (the most the engine holds while the starts run, looked at all along:
    # a wait holds its watch for milliseconds)
    python3 -I -c '
import os, sys
pid, flag, n = sys.argv[1], sys.argv[2], 0
while os.path.exists(flag):
    m = 0
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            m += os.readlink(f"/proc/{pid}/fd/{fd}") == "anon_inode:inotify"
        except OSError:
            pass
    n = max(n, m)
print(n)' "$engine" "$WORKDIR/burst.sampling" > "$WORKDIR/burst.max" 3>&- &
    local sampler=$!
    for i in $(seq 100); do
        sc container run -d --name burst$i --network none "$IMAGE" sleep 1000 \
            > /dev/null 2> "$WORKDIR/burst.$i.err" 3>&- &
    done
    wait $(jobs -p | grep -v "^$sampler$")
    rm -f "$WORKDIR/burst.sampling"
    wait "$sampler"
    max=$(cat "$WORKDIR/burst.max")
    echo "# inotify instances of the engine during 100 starts: $max at most" >&3
    check "starts that failed" "" "$(cat "$WORKDIR"/burst.*.err)"
    check "running containers" 100 "$(sh_ container list | grep -c "burst[0-9]")"
    check_match "inotify instances of the engine" "^[01]$" "$max"
    for i in $(seq 100); do
        sh_ container rm -f -t 0 burst$i > /dev/null &
    done
    wait
}
