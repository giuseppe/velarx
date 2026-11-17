# SPDX-License-Identifier: Apache-2.0
# The user-namespace tree of a rootless user (userns::tree): every rootless
# process of a store joins the one user and mount namespace pair that a
# process lives in, and makes a new pair when none does; nothing holds the
# pair but the processes that live in it (no keeper, no waiter).
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/userns-tree.bats   # as a user (skipped as root)
#
# IMAGE is any image with a shell (default localhost:5000/alpine:chunked,
# pulled over plain HTTP).  The store, the runtime directory and the daemon
# are in a work directory of its own.
#
# The tests share the namespaces of the tree, the containers and the daemon,
# and run in order: what crosses tests (UNS, CREATOR, DAEMON_PID, ...) is in
# $WORKDIR/tree.env.

load helpers

. "$BATS_TEST_DIRNAME/../cleanup.sh"

# save VAR...: keep the variables for the next tests; restore: read them
save () { local v; for v; do printf '%s=%q\n' "$v" "${!v}" >> "$WORKDIR/tree.env"; done; }
restore () {
    . "$WORKDIR/tree.env"
    if [ -z "${UNS:-}" ]; then
        echo "no user namespace recorded: the first test failed or did not run" >&2
        exit 1
    fi
}

# differ WHAT A B: both are set and differ
differ () {
    if [ -n "$2" ] && [ -n "$3" ] && [ "$2" != "$3" ]; then return 0; fi
    echo "FAIL $1: both: $2 / $3" >&2
    exit 1
}
sh_ () { timeout "${E2E_TIMEOUT:-120}" "$SH" "$@"; }
# the user namespace of a process
userns_of () { readlink "/proc/$1/ns/user" 2> /dev/null; }
# the pid of the container NAME, and of its monitor
cpid () { sh_ container inspect --format '{{.State.Pid}}' "$1" 2> /dev/null; }
monitor_of () {
    pgrep -f "^velarx-monitor: $(sh_ container inspect --format '{{.Id}}' "$1" 2> /dev/null | cut -c1-12) "
}
# what a command sees of the namespaces
un_user () { sh_ unshare readlink /proc/self/ns/user; }
# change the records of the namespaces in their database (in the store's database)
dbx () {
    python3 -I - "$WORKDIR/storage/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.executescript(sys.argv[2])
c.close()
EOT
}
# the records of the namespaces in their database
dbq () {
    python3 -I - "$WORKDIR/storage/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
for row in sqlite3.connect(sys.argv[1]).execute(sys.argv[2]):
    print(*row)
EOT
}
# the velarx processes of the store (monitors included), and their names
velarx_processes () { e2e_store_processes "$WORKDIR" | awk '{ print $2 }' | sort | tr '\n' ' '; }
# Keep the user namespace of PID alive, by an open descriptor (of a process
# that lives until the end of the file): the inode number of a namespace that
# is gone goes to the next one, and a test that compares inodes must not be
# fooled by it.
pin_userns () {
    ( exec 9< "/proc/$1/ns/user"; exec sleep 1000 ) 3>&- > /dev/null 2>&1 &
    echo $! >> "$WORKDIR/pins"
}

# Run a shell command line as root of the host (the mounts of the host are
# made in the initial mount namespace): E2E_AS_ROOT is a command that runs
# its argument as root (a wrapper around su), or sudo without a password;
# 77 when neither.  Its output is not for tests (a pty wrapper adds to it),
# its status is.
as_root () {
    if [ -n "${E2E_AS_ROOT:-}" ]; then
        "$E2E_AS_ROOT" "$*" > /dev/null 2>&1
    elif sudo -n true > /dev/null 2>&1; then
        sudo -n sh -c "$*" > /dev/null 2>&1
    else
        return 77
    fi
}

# the holder of the rootless network namespace and the namespace it made
# (device, inode, handle), as the namespaces tables have them
holder_pid () { dbq "select pid from holders where scope = 'rootless-netns' and role = 'netns'" 2> /dev/null; }
holder_file () { dbq "select dev, ino, hex(handle) from namespaces where scope = 'rootless-netns'" 2> /dev/null; }
netns_of () { readlink "/proc/$1/ns/net" 2> /dev/null; }
ip_of () { sh_ container inspect --format "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1" 2> /dev/null; }
wait_gone () { e2e_wait_exit "$1"; }
setup_file () {
    skip_if_root
    e2e_setup_file
    export IMAGE=${IMAGE:-${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}}
    export CONF=$XDG_CONFIG_HOME/velarx/config.toml
    export NETNS_DIR=$WORKDIR/state/netns
    export NETNS_PASTA=$WORKDIR/state/networks/rootless-netns.pasta.pid
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    chmod 700 "$XDG_RUNTIME_DIR"
    : > "$WORKDIR/tree.env"
    cat > "$CONF" << EOT
[engine]
socket = "$SOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
shutdown_timeout_secs = 5
[storage]
root = "$WORKDIR/storage"
EOT
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" << EOT
[[registry]]
location = "${IMAGE%%/*}"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"
    sh_ image pull "$IMAGE" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMAGE" "$WORKDIR/pull.log"
}

# a failing check must not leave the processes the test started
teardown () {
    set +e
    [ -n "${BOOT_HOLDER:-}" ] && kill "$BOOT_HOLDER" 2> /dev/null
    [ -n "${CLIENT:-}" ] && kill "$CLIENT" 2> /dev/null
    return 0
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    [ -f "$WORKDIR/tree.env" ] && . "$WORKDIR/tree.env"
    [ -n "${HOSTMNT:-}" ] && as_root "umount '$HOSTMNT'; rmdir '$HOSTMNT'"
    [ -n "${LEAK:-}" ] && rmdir "$LEAK" 2> /dev/null
    [ -n "${BOOT_HOLDER:-}" ] && kill -9 "$BOOT_HOLDER" 2> /dev/null
    if [ -n "${DAEMON_PID:-}" ]; then
        e2e_remove_containers "$SH" "$SOCK"
        kill -INT "$DAEMON_PID" 2> /dev/null
        e2e_wait_exit "$DAEMON_PID"
    fi
    local c p
    for c in $(sh_ container list -a 2> /dev/null | awk 'NR > 1 { print $1 }'); do
        sh_ container rm -t 0 -f "$c" > /dev/null 2>&1
    done
    for p in $(cat "$WORKDIR/pins" 2> /dev/null); do kill -9 "$p" 2> /dev/null; done
    [ "$(cat "/proc/${CREATOR:-0}/comm" 2> /dev/null)" = sleep ] && kill -9 "$CREATOR" 2> /dev/null
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do kill -9 "$p" 2> /dev/null; done
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR" "$SH" >&3 2>&3
    fi
    e2e_teardown_file
}

# --- the first command makes the namespaces; the next joins them

@test "the first command makes the namespaces; the next joins them" {
    # A process of the first command lives in the namespaces until it is
    # killed: the creator of the pair.
    "$SH" unshare sh -c 'echo up; exec sleep 300' 3>&- > "$WORKDIR/creator.out" 2>&1 &
    CREATOR=$!
    e2e_wait_line "$WORKDIR/creator.out" '^up$' 30 || e2e_die "the first command did not start within 30 s"
    UNS=$(userns_of "$CREATOR")
    save CREATOR UNS
    differ "the first command lives in a user namespace of its own" "$UNS" "$(userns_of $$)"
    check "the pair is recorded: user and mount" "mnt user" \
        "$(dbq 'select kind from namespaces order by kind' | tr '\n' ' ' | sed 's/ $//')"
    check "and the boot it is for" "$(cat /proc/sys/kernel/random/boot_id)" \
        "$(dbq 'select distinct boot_id from namespaces')"
    check "the creator is the holder" "$CREATOR" "$(dbq "select pid from holders where scope = 'tree'")"
    check "the next command joins the user namespace" "$UNS" "$(un_user)"
    check "and the mount namespace" "$(readlink /proc/$CREATOR/ns/mnt)" \
        "$(sh_ unshare readlink /proc/self/ns/mnt)"
}

# --- the mounts of the host reach the namespace; its mounts do not reach the host

@test "the mounts of the host reach the namespace; its mounts do not reach the host" {
    restore
    # (the mount namespace is a slave of the host's, it is not a snapshot of the
    # mounts of the day it was made)
    as_root true || skip "needs root (E2E_AS_ROOT or sudo)"
    HOSTMNT=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-hostmnt.XXXXXX")
    save HOSTMNT
    as_root "mount -t tmpfs tmpfs '$HOSTMNT' && echo from-the-host > '$HOSTMNT/f' && chmod 755 '$HOSTMNT' && chmod 644 '$HOSTMNT/f'"
    check "the host has the mount" 1 "$(grep -c " $HOSTMNT " /proc/self/mountinfo)"
    check "a mount made on the host after the pair exists is seen by the next command" from-the-host \
        "$(sh_ unshare cat "$HOSTMNT/f" 2> /dev/null)"
    check "and by a container with a bind mount of it" from-the-host \
        "$(sh_ container run --rm -v "$HOSTMNT:/data:ro" "$IMAGE" cat /data/f 2> /dev/null)"
    LEAK=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-leak.XXXXXX")
    save LEAK
    check "a mount made in the namespace is there" 1 \
        "$(sh_ unshare sh -c 'mount -t tmpfs tmpfs "$1" && grep -c " $1 " /proc/self/mountinfo' sh "$LEAK" 2> /dev/null)"
    check "and not on the host" 0 "$(grep -c " $LEAK " /proc/self/mountinfo)"
    check "the container's volume mount does not reach the host either" 0 \
        "$(sh_ container run --rm -v "$LEAK:/data" --mount type=tmpfs,destination=/scratch "$IMAGE" true > /dev/null 2>&1; grep -c scratch /proc/self/mountinfo)"
    rmdir "$LEAK"
    LEAK=
    save LEAK
    # a container that runs with the directory does not keep the host from
    # unmounting it, and the unmount reaches the namespace (a process of the
    # namespace with a file open or its working directory in a host mount
    # does: umount says busy, as it does for any process, until it leaves)
    sh_ container run -d --name hm -v "$HOSTMNT:/data:ro" "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a running container reads it" from-the-host "$(sh_ container exec hm cat /data/f 2> /dev/null)"
    as_root "umount '$HOSTMNT'"
    check "the host unmounts it" 0 "$(grep -c " $HOSTMNT " /proc/self/mountinfo)"
    check "and it is unmounted in the namespace" 0 \
        "$(sh_ unshare sh -c 'grep -c " $1 " /proc/self/mountinfo' sh "$HOSTMNT" 2> /dev/null)"
    sh_ container rm -t 0 -f hm > /dev/null 2>&1
    as_root "rmdir '$HOSTMNT'"
    HOSTMNT=
    save HOSTMNT
}

# --- a container: nothing but the client, the monitor, the container and
# pasta

@test "a container: nothing but the client, the monitor, the container and pasta" {
    restore
    sh_ container run -d --name t1 "$IMAGE" sleep 300 > /dev/null
    check "the container is in the namespace" "$UNS" "$(userns_of "$(cpid t1)")"
    check "so is its monitor" "$UNS" "$(userns_of "$(monitor_of t1)")"
    check "the monitor is the only velarx process (the creator runs sleep)" \
        "velarx-monitor " "$(velarx_processes)"
    check "the monitor is the container's parent" "$(monitor_of t1)" "$(ps -o ppid= -p "$(cpid t1)" | tr -d ' ')"
    check "and has a readable command line" "velarx-monitor: $(sh_ container inspect --format '{{.Id}}' t1 | cut -c1-12) t1 $IMAGE" \
        "$(tr '\0' ' ' < "/proc/$(monitor_of t1)/cmdline" | sed 's/ *$//')"
}

@test "the namespaces outlive the command that made them" {
    restore
    # The creator is killed: the container keeps the namespaces
    kill -9 "$CREATOR"
    wait_gone "$CREATOR"
    check "the namespaces outlive the command that made them" "$UNS" "$(un_user)"
    check "exec reaches the container" "$UNS" "$(sh_ container exec t1 readlink /proc/self/ns/user)"
    echo hello > "$WORKDIR/hello"
    sh_ container cp "$WORKDIR/hello" t1:/tmp/hello > /dev/null 2>&1
    check "cp into the container" hello "$(sh_ container exec t1 cat /tmp/hello 2> /dev/null)"
    check "--pid container:" 1 "$(sh_ container run --rm --pid container:t1 "$IMAGE" sh -c 'ps' 2> /dev/null | grep -c 'sleep 300')"
    check "--ipc container:" 0 "$(sh_ container run --rm --ipc container:t1 "$IMAGE" true > /dev/null 2>&1; echo $?)"
    check "--uts container:" 0 "$(sh_ container run --rm --uts container:t1 "$IMAGE" true > /dev/null 2>&1; echo $?)"
}

# --- run, the process count: the client is the engine; no waiter

@test "run: the client is the engine, no waiter" {
    restore
    "$SH" container run --rm --name t2 "$IMAGE" sh -c 'echo up; exec sleep 20' 3>&- > "$WORKDIR/t2.out" 2>&1 &
    CLIENT=$!
    e2e_wait_line "$WORKDIR/t2.out" '^up$' 30 || e2e_die "the container did not start within 30 s"
    mon=$(monitor_of t2)
    check "run: the client joined the namespaces in place" "$UNS" "$(userns_of "$CLIENT")"
    check "run: the client has no child but the monitor" "$mon" "$(pgrep -P "$CLIENT" | tr '\n' ' ' | sed 's/ $//')"
    check "run: the velarx processes are the client and the monitors" \
        "velarx velarx-monitor velarx-monitor " "$(velarx_processes)"
    # (the jobs of the monitor are threads of it)
    check "run: the container is the child of the monitor" 1 \
        "$(ps -o comm= --ppid "$mon" | grep -vcx velarx)"
    kill "$CLIENT" 2> /dev/null
    wait "$CLIENT" 2> /dev/null
}

# --- a monitor that dies does not break the others

@test "a monitor that dies does not break the others" {
    restore
    sh_ container run -d --name t3 "$IMAGE" sleep 300 > /dev/null
    mon=$(monitor_of t3)
    kill -9 "$mon"
    e2e_wait_exit "$mon"
    check "kill -9 of a monitor: the other container is served" "$UNS" "$(sh_ container exec t1 readlink /proc/self/ns/user)"
    check "and a new command is in the same tree" "$UNS" "$(un_user)"
    sh_ container rm -t 0 -f t3 > /dev/null 2>&1
}

# --- the daemon is in the tree; so are the modes that need it

@test "the daemon is in the tree; so are the modes that need it" {
    restore
    setsid "$SH" varlink > "$WORKDIR/daemon.log" 2>&1 3>&- &
    DAEMON_PID=$!
    save DAEMON_PID
    e2e_wait_path "$SOCK"
    check "the daemon is in the same user namespace" "$UNS" "$(userns_of "$DAEMON_PID")"
    check "its only process is the daemon (no waiter)" "1" "$(pgrep -fc -- "--config $CONF varlink")"
    check "the pair has the daemon as a holder" 1 \
        "$(dbq "select count(*) from holders where role = 'daemon'")"
    check "--network container: through the daemon" 0 \
        "$(sh_ container run --rm --network container:t1 "$IMAGE" true > /dev/null 2>&1; echo $?)"
}

@test "a bridge network between two containers" {
    skip_unless_bridges
    restore
    check "network create" 0 "$(sh_ network create treenet > /dev/null 2>&1; echo $?)"
    check "run n1 on the network" 0 "$(sh_ container run -d --name n1 --network treenet "$IMAGE" sleep 300 > /dev/null 2>&1; echo $?)"
    check "run n2 on the network" 0 "$(sh_ container run -d --name n2 --network treenet "$IMAGE" sleep 300 > /dev/null 2>&1; echo $?)"
    ip2=$(sh_ container inspect --format '{{(index .NetworkSettings.Networks "treenet").IPAddress}}' n2 2> /dev/null)
    check_match "n2 has an address on the network" "^[0-9.]+$" "$ip2"
    check "a bridge network between two containers" 0 \
        "$(sh_ container exec n1 ping -c1 -W3 "$ip2" > /dev/null 2>&1; echo $?)"
    n1ns=$(netns_of "$(cpid n1)")
    n1id=$(sh_ container inspect --format '{{.Id}}' n1 2> /dev/null)
    check "the monitor of the container holds its network namespace by a descriptor" "$n1ns" \
        "$(for f in /proc/$(monitor_of n1)/fd/*; do readlink "$f" 2> /dev/null; done | grep -Fx "$n1ns" | head -1)"
    check "the namespace of the container is recorded, with the monitor as a holder" "1 1" \
        "$(dbq "select count(*) from namespaces where scope = 'container/$n1id' and kind = 'net'") $(dbq "select count(*) from holders where scope = 'container/$n1id' and role = 'monitor' and pid = $(monitor_of n1)")"
    holder=$(holder_pid)
    check "the rootless network namespace is held by one process" "velarx-netns" "$(cat "/proc/${holder:-0}/comm" 2> /dev/null)"
    check "and that process is in the tree" "$UNS" "$(userns_of "${holder:-0}")"
    check "the unshare command reaches the bridges" 0 \
        "$(sh_ unshare --rootless-netns ip link show > /dev/null 2>&1; echo $?)"
    sh_ container rm -t 0 -f n1 n2 > /dev/null 2>&1
    sh_ network rm treenet > /dev/null 2>&1
    e2e_wait_exit "$holder"
    check "the namespace of a container is forgotten with it" 0 \
        "$(dbq "select count(*) from namespaces where scope = 'container/$n1id'")"
    check "the holder of the network namespace goes with the last bridge" "" "$(holder_file)"
    check "nothing is pinned for the namespaces of the containers or the bridges" "" \
        "$(ls "$NETNS_DIR" 2> /dev/null)"
}

# --- the holder of the network namespace dies while containers use it

@test "the holder of the network namespace dies while containers use it" {
    skip_unless_bridges
    restore
    sh_ network create recnet > /dev/null 2>&1
    sh_ container run -d --name r1 --network recnet "$IMAGE" sleep 300 > /dev/null 2>&1
    sh_ container run -d --name r2 --network recnet "$IMAGE" sleep 300 > /dev/null 2>&1
    H1=$(holder_pid)
    check "a holder of the network namespace" 1 "$([ -n "$H1" ] && echo 1)"
    check_match "r2 has an address on the network" "^[0-9.]+$" "$(ip_of r2 recnet)"
    NS1=$(netns_of "$H1")
    check "the database records the namespace: device, inode and handle" 1 \
        "$(holder_file | awk '$2 == "'"${NS1//[^0-9]/}"'" { print 1 }' | head -1)"
    check "the DNS server of the network is in the namespace and a holder" 1 \
        "$(dbq "select count(*) from holders where role = 'dns-server'")"
    PASTA1=$(cat "$NETNS_PASTA" 2> /dev/null)
    check "pasta runs on the holder" 1 "$(pgrep -fc -- "--netns /proc/$H1/ns/net")"
    kill -9 "$H1"
    wait_gone "$H1"
    # (the pasta does not watch the holder: it goes on, and the containers
    # with it, until the next holder takes its place)
    check "the pasta of a killed holder goes on" alive "$(e2e_alive "$PASTA1")"
    sh_ container run -d --name r3 --network recnet "$IMAGE" sleep 300 > /dev/null 2>&1
    H2=$(holder_pid)
    differ "after kill -9 of the holder a new holder is started" "$H1" "$H2"
    wait_gone "$PASTA1"
    check "the next holder stopped the pasta of the holder before it" gone "$(e2e_alive "$PASTA1")"
    check "in the namespace the containers have their links in" "$NS1" "$(netns_of "${H2:-0}")"
    PASTA2=$(cat "$NETNS_PASTA" 2> /dev/null)
    differ "and a new pasta, on the new holder" "$PASTA1" "$PASTA2"
    check "the new pasta is on the new holder" 1 "$(pgrep -fc -- "--netns /proc/$H2/ns/net")"
    check "the new holder is a holder of the tree" 1 \
        "$(dbq "select count(*) from holders where scope = 'tree' and role = 'netns' and pid = ${H2:-0}")"
    check "and the holder of the namespace" 1 \
        "$(dbq "select count(*) from holders where scope = 'rootless-netns' and pid = ${H2:-0}")"
    check "the new container reaches the first" 0 \
        "$(sh_ container exec r3 ping -c1 -W3 "$(ip_of r1 recnet)" > /dev/null 2>&1; echo $?)"
    check "and the second, by name" 0 \
        "$(sh_ container exec r3 ping -c1 -W3 r2 > /dev/null 2>&1; echo $?)"
    check "and the first reaches the new one" 0 \
        "$(sh_ container exec r1 ping -c1 -W3 "$(ip_of r3 recnet)" > /dev/null 2>&1; echo $?)"
    sh_ container rm -t 0 -f r1 r2 r3 > /dev/null 2>&1
    sh_ network rm recnet > /dev/null 2>&1
    wait_gone "$H2"
    check "the holder goes with the last bridge" "" "$(holder_file)"
    wait_gone "$PASTA2"
    check "and its pasta" gone "$(e2e_alive "$PASTA2")"
}

# a holder that is asked to end (not killed) stops the pasta of its namespace
@test "a holder that ends stops its pasta" {
    skip_unless_bridges
    restore
    sh_ network create --disable-dns termnet > /dev/null 2>&1
    sh_ container run -d --name t2 --network termnet "$IMAGE" sleep 300 > /dev/null 2>&1
    HT=$(holder_pid)
    PT=$(cat "$NETNS_PASTA" 2> /dev/null)
    check "a holder and a pasta" 1 "$([ -n "$HT" ] && [ -n "$PT" ] && echo 1)"
    kill "$HT"
    wait_gone "$HT"
    wait_gone "$PT"
    check "the pasta went with the holder" gone "$(e2e_alive "$PT")"
    sh_ container rm -t 0 -f t2 > /dev/null 2>&1
    sh_ network rm termnet > /dev/null 2>&1
}

# the engine that starts stops the pasta of a holder that was killed, when
# nothing else keeps the namespace (the ports it published are free): the
# monitors of the containers keep it, so the holder and the monitor of the
# only container are killed
@test "the start of the engine stops the pasta of a killed holder" {
    skip_unless_bridges
    restore
    sh_ network create --disable-dns sweepnet > /dev/null 2>&1
    sh_ container run -d --name s1 --network sweepnet "$IMAGE" sleep 300 > /dev/null 2>&1
    HS=$(holder_pid)
    PS=$(cat "$NETNS_PASTA" 2> /dev/null)
    check "a holder and a pasta" 1 "$([ -n "$HS" ] && [ -n "$PS" ] && echo 1)"
    MS=$(monitor_of s1)
    kill -9 "$HS"
    wait_gone "$HS"
    check "the pasta goes on, the namespace is the monitor's too" alive "$(e2e_alive "$PS")"
    kill -9 "$MS"
    wait_gone "$MS"
    check "the pasta goes on with the monitor gone" alive "$(e2e_alive "$PS")"
    kill -INT "$DAEMON_PID" 2> /dev/null
    wait_gone "$DAEMON_PID"
    setsid "$SH" varlink > "$WORKDIR/daemon.log" 2>&1 3>&- &
    DAEMON_PID=$!
    save DAEMON_PID
    e2e_wait_path "$SOCK"
    wait_gone "$PS"
    check "the engine that started stopped it" gone "$(e2e_alive "$PS")"
    sh_ container rm -t 0 -f s1 > /dev/null 2>&1
    sh_ network rm sweepnet > /dev/null 2>&1
}

# a network without DNS and without published ports: no process but the
# holder and its pasta is in the namespace, and nothing pins it but the
# descriptor of the monitor of the container: when the holder is killed the
# pasta goes on (it does not watch the holder) until the next container gets
# a holder, which joins the namespace the monitor holds, stops the pasta,
# starts its own and makes a network that works
@test "a namespace with the holder alone" {
    skip_unless_bridges
    restore
    sh_ network create --disable-dns barenet > /dev/null 2>&1
    sh_ container run -d --name b1 --network barenet "$IMAGE" sleep 300 > /dev/null 2>&1
    H3=$(holder_pid)
    check "a holder of the network namespace" 1 "$([ -n "$H3" ] && echo 1)"
    sh_ container run -d --name m1 --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    PASTA3=$(cat "$NETNS_PASTA" 2> /dev/null)
    GW=$(ip route show default 2> /dev/null | awk '{ print $3; exit }')
    check "no file and no mount holds the namespace" "" "$(ls "$NETNS_DIR" 2> /dev/null)"
    check "no mount of the namespace is in the mount namespace of the tree" 0 \
        "$(sh_ unshare sh -c "grep -c ' $NETNS_DIR' /proc/self/mountinfo")"
    kill -9 "$H3"
    wait_gone "$H3"
    check "the pasta of a killed holder goes on" alive "$(e2e_alive "$PASTA3")"
    sh_ container run -d --name b2 --network barenet "$IMAGE" sleep 300 > /dev/null 2>&1
    H4=$(holder_pid)
    differ "a new holder" "$H3" "$H4"
    wait_gone "$PASTA3"
    check "the old pasta is gone before the new one" gone "$(e2e_alive "$PASTA3")"
    PASTA4=$(cat "$NETNS_PASTA" 2> /dev/null)
    check "with a new pasta" 1 "$(pgrep -fc -- "--netns /proc/$H4/ns/net")"
    if [ -n "$GW" ]; then
        check "the new container reaches the host through pasta" 0 \
            "$(sh_ container exec b2 ping -c1 -W3 "$GW" > /dev/null 2>&1; echo $?)"
    fi
    sh_ container rm -t 0 -f b1 b2 > /dev/null 2>&1
    wait_gone "$H4"
    check "released: no holder record" "" "$(holder_file)"
    check "no holder process" 1 "$(wait_gone "$H4" && echo 1)"
    check "and no pasta of the namespace" 1 "$(wait_gone "${PASTA4:-0}" && echo 1)"
    check "the container that is not on a bridge runs on" running \
        "$(sh_ container inspect --format '{{.State.Status}}' m1 2> /dev/null)"
    sh_ container rm -t 0 -f m1 > /dev/null 2>&1
    sh_ network rm barenet > /dev/null 2>&1
}

# --- the boot is part of the key

@test "the boot is part of the key" {
    restore
    pin_userns "$(cpid t1)"
    dbx "update namespaces set boot_id = 'another-boot'; update holders set boot_id = 'another-boot'"
    "$SH" unshare sh -c 'echo up; exec sleep 300' 3>&- > "$WORKDIR/boot.out" 2>&1 &
    BOOT_HOLDER=$!
    save BOOT_HOLDER
    e2e_wait_line "$WORKDIR/boot.out" '^up$' 30 || e2e_die "the command did not start within 30 s"
    BOOT_NS=$(userns_of "$BOOT_HOLDER")
    differ "the record of another boot is of no use: a new pair" "$UNS" "$BOOT_NS"
    check "the records of the old boot are gone" 1 "$(dbq 'select count(distinct boot_id) from namespaces')"
    check "and the new ones are for this boot" "$(cat /proc/sys/kernel/random/boot_id)" \
        "$(dbq 'select distinct boot_id from namespaces')"
    check "the next command joins the new pair" "$BOOT_NS" "$(un_user)"
    kill "$BOOT_HOLDER"
    wait "$BOOT_HOLDER" 2> /dev/null
    BOOT_HOLDER=
    save BOOT_HOLDER
}

# --- everything stops: the next command makes a new pair

@test "everything stops: the next command makes a new pair" {
    restore
    sh_ container rm -t 0 -f t1 > /dev/null 2>&1
    procs=$(e2e_store_processes "$WORKDIR" | awk '{ print $1 }')
    kill -INT "$DAEMON_PID" 2> /dev/null
    wait_gone "$DAEMON_PID"
    DAEMON_PID=
    save DAEMON_PID
    for p in $procs; do e2e_wait_exit "$p"; done
    check "nothing of the store is left" "" "$(e2e_store_processes "$WORKDIR" | awk '{ print $2 }' | tr '\n' ' ')"
    AFTER=$(un_user)
    differ "no process lived in the namespaces: a new pair" "$UNS" "$AFTER"
}

# --- two commands that start together share one pair

@test "two commands that start together share one pair" {
    restore
    for n in 1 2 3; do
        ( "$SH" unshare sh -c 'readlink /proc/self/ns/user; sleep 1' > "$WORKDIR/race$n.out" 2>&1 ) 3>&- &
    done
    wait
    check "the first commands of a new boot: one user namespace" 1 \
        "$(cat "$WORKDIR"/race?.out | sort -u | wc -l)"
}

# Containers started together from nothing share the user namespace of one
# creator (the pair is made under the lock of the database); each monitor
# has a mount namespace of its own (its FUSE and overlay mounts are its
# own), a later command joins the user namespace and does not see them.
@test "containers that start together from nothing share one user namespace" {
    restore
    # (the commands of the test before leave their processes behind them: each is waited for)
    local p
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do e2e_wait_exit "$p"; done
    check "nothing of the store is left" "" "$(e2e_store_processes "$WORKDIR" | awk '{ print $2 }' | tr '\n' ' ')"
    for n in 1 2 3 4; do
        ( sh_ container run -d --name par$n "$IMAGE" sleep 300 > /dev/null 2>&1 ) 3>&- &
    done
    wait
    local ns= n m
    for n in 1 2 3 4; do
        m=$(monitor_of par$n)
        [ -n "$m" ] || { echo "FAIL: no monitor for par$n" >&2; exit 1; }
        ns="$ns$(userns_of "$m")
$(userns_of "$(cpid par$n)")
"
    done
    check "four containers and their monitors: one user namespace" 1 "$(echo "$ns" | sed '/^$/d' | sort -u | wc -l)"
    check "a third command is in it" "$(echo "$ns" | sed -n 1p)" "$(un_user)"
    sh_ container rm -t 0 -f par1 par2 par3 par4 > /dev/null 2>&1
}

# everything is killed, the namespaces are gone: the record left behind is
# compared with what the next start finds, and replaced
@test "a record left behind by a crash" {
    skip_unless_bridges
    restore
    sh_ network create --disable-dns crashnet > /dev/null 2>&1
    sh_ container run -d --name k1 --network crashnet "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a holder of the network namespace" 1 "$([ -n "$(holder_pid)" ] && echo 1)"
    KNS=$(holder_file)
    # (everything of the store: the container, its monitor, pasta, the holder;
    # the monitors first, else one could see its container end and release
    # the namespace as it should)
    KILL="$(cpid k1) $(cat "$NETNS_PASTA" 2> /dev/null) $(holder_pid)"
    MONS=$(e2e_store_processes "$WORKDIR" | awk '{ print $1 }' | tr '\n' ' ')
    for p in $MONS; do kill -9 "$p" 2> /dev/null; done
    for p in $MONS; do wait_gone "$p"; done
    for p in $KILL; do kill -9 "$p" 2> /dev/null; done
    for p in $KILL; do wait_gone "$p"; done
    check "after kill -9 of everything the record stays" "$KNS" "$(holder_file)"
    check "and nothing is pinned" "" "$(ls "$NETNS_DIR" 2> /dev/null)"
    sh_ container rm -t 0 -f k1 > /dev/null 2>&1
    sh_ container run -d --name k2 --network crashnet "$IMAGE" sleep 300 > /dev/null 2>&1
    differ "the next container gets a new namespace" "$KNS" "$(holder_file)"
    check "on its own gateway" 0 \
        "$(sh_ container exec k2 ping -c1 -W3 "$(sh_ network inspect --format '{{(index .Subnets 0).Gateway}}' crashnet 2> /dev/null)" > /dev/null 2>&1; echo $?)"
    # the cleanup of the last container never ran: the holder is idle
    K2H=$(holder_pid)
    sh_ unshare --rootless-netns sh -c 'for b in $(ip -o link show type bridge | cut -d: -f2); do ip link del $b; done' > /dev/null 2>&1
    sh_ system prune -f > /dev/null 2>&1
    check "system prune stops the holder when no bridge is in use" "" "$(holder_file)"
    check "and the process is gone" 1 "$(wait_gone "${K2H:-0}" && echo 1)"
    sh_ container rm -t 0 -f k2 > /dev/null 2>&1
    sh_ container rm -t 0 -f k1 k2 > /dev/null 2>&1
    sh_ network rm crashnet > /dev/null 2>&1
}
