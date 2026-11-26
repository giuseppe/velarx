# SPDX-License-Identifier: Apache-2.0
# End to end tests of pasta for rootless containers: the default network,
# published ports, the restart of a pasta that dies, the teardown.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/pasta.bats   (as a user with subordinate ids)
#
# The daemon is the one in VELARX_BINDIR, or VELARX_DAEMON; the image
# E2E_IMAGE (default localhost:5000/alpine:chunked).  Skipped as root or
# without pasta.

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

# (--socket: the test's daemon, never an engine of the command's own)
sh_ () {
    "$CLI" --config "$CONF" --socket "$ESOCK" "$@"
}
fetch () {
    python3 -I -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
s.settimeout(3)
print(s.recv(4096).decode().strip())
' "$1" 2>&1
}
# a connection to a port of the namespace of a container or of a pod, made
# by the daemon inside it: the status line and what the port says
dial () {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(sys.argv[1])
s.sendall(("POST /v5.0.0/libpod/%s/connect?port=%s HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n" % (sys.argv[2], sys.argv[3])).encode())
data = b""
while b"\r\n\r\n" not in data:
    data += s.recv(4096)
head, _, rest = data.partition(b"\r\n\r\n")
print(head.split(b"\r\n")[0].decode())
if b" 101 " in head.split(b"\r\n")[0]:
    s.sendall(b"\n")
    while not rest.endswith(b"\n"):
        rest += s.recv(4096)
    print(rest.decode().strip())
else:
    print(rest.decode())
' "$SOCK" "$1" "$2" 2>&1
}

# the monitor of container $1, and the arguments of the pasta of its network
monitor_of () {
    pgrep -f "^velarx-monitor: $(sh_ container inspect --format '{{.Id}}' "$1" 2> /dev/null | cut -c1-12) "
}
pasta_args () {
    local id pid
    id=$(sh_ container inspect --format '{{.Id}}' "$1" 2> /dev/null)
    pid=$(cat "$WORKDIR/run/velarx/networks/pasta/$id.pid" 2> /dev/null)
    tr '\0' ' ' < "/proc/${pid:-0}/cmdline" 2> /dev/null
}

setup_file () {
    if test "$(id -u)" = 0 || ! command -v pasta > /dev/null; then
        skip "pasta.bats runs rootless and needs pasta"
    fi
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export DAEMON=${VELARX_DAEMON:-$BIN/velarx}
    export CLI=${VELARX:-$(dirname "$DAEMON")/velarx}
    export IMG=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export PORT=${E2E_PORT:-18213}
    export WORKDIR; WORKDIR=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-pasta.XXXXXX")
    export SOCK=$WORKDIR/api.sock
    export ESOCK=$WORKDIR/engine.sock
    export CONF=$WORKDIR/config.toml
    export HOME=$WORKDIR/home XDG_CONFIG_HOME=$WORKDIR/home/.config XDG_DATA_HOME=$WORKDIR/home/data
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    cat > "$CONF" <<EOT
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/run/velarx"
root_dir = "$WORKDIR/root"
shutdown_timeout_secs = 5
[storage]
root = "$WORKDIR/storage"
EOT
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"

    # (the daemon says READY=1 when it serves)
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready daemon_pid "$DAEMON" --config "$CONF" varlink
    ready=$?
    echo "$daemon_pid" > "$WORKDIR/daemon.pid"
    if [ "$ready" != 0 ]; then
        cat "$WORKDIR/daemon.log" >&2
        echo "the daemon does not start" >&2
        exit 1
    fi
    # the REST API in front of it (the connect to a port)
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --idle-exit 0 --listen "unix://$SOCK" \
        > "$WORKDIR/api.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/api.pid"
    e2e_wait_path "$SOCK" 10
    sh_ image pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"
}

# the host service of the bridge test ends with a test that failed; the
# engine a test killed is started again (none when setup_file skipped)
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    [ -z "${hostsvc:-}" ] || kill "$hostsvc" 2> /dev/null
    kill -0 "$(cat "$WORKDIR/daemon.pid")" 2> /dev/null || restart_engine
    return 0
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    if [ -S "$ESOCK" ]; then
        e2e_remove_containers "$CLI" "$ESOCK"
        sh_ pod rm -t 0 -f dp > /dev/null 2>&1
        sh_ network rm rlnet > /dev/null 2>&1
    fi
    e2e_teardown_file
}

@test "pasta is the default network: nameserver, host, route" {
    out=$(sh_ container run --rm "$IMG" sh -c 'grep -m1 nameserver /etc/resolv.conf; grep -c host.containers.internal /etc/hosts; ip route | grep -c default')
    check "pasta by default: nameserver, host, route" "nameserver 169.254.1.1
1
1" "$out"
}

@test "a published port and the address inspect shows" {
    sh_ container run -d --name p1 -p "$PORT:80" "$IMG" nc -lk -p 80 -e echo from-p1 > /dev/null
    e2e_wait_listening p1
    check "published port" "from-p1" "$(fetch "$PORT")"
    # the address pasta gave the container (the host's) is the one inspect shows,
    # on the network `pasta`, with the gateway
    inside=$(sh_ exec p1 ip -4 -o addr show scope global | awk '{ split($4, a, "/"); print a[1] }' | head -1)
    check "inspect: the address of the container on pasta" "$inside" "$(sh_ inspect --format '{{.NetworkSettings.IPAddress}}' p1 2>&1)"
    check "inspect: the same address on the network pasta" "$inside" "$(sh_ inspect --format '{{(index .NetworkSettings.Networks "pasta").IPAddress}}' p1 2>&1)"
    check "inspect: the gateway" "$(sh_ exec p1 ip route | awk '/^default/ { print $3 }')" "$(sh_ inspect --format '{{.NetworkSettings.Gateway}}' p1 2>&1)"
}

@test "a pasta that dies is restarted and the published port still works" {
    pidfile=$(ls "$WORKDIR"/run/velarx/networks/pasta/*.pid)
    pid=$(cat "$pidfile")
    [ -n "$pid" ] || { echo "needs the container p1 of the test 'a published port and the address inspect shows'" >&2; exit 1; }
    kill "$pid"
    e2e_wait_content "$pidfile" "^(?!$pid\$)[0-9]+\$" 30 || e2e_die "pasta was not restarted within 30 s"
    check "pasta restarted" "yes" "$(test "$(cat "$pidfile" 2> /dev/null)" != "$pid" && echo yes)"
    check "published port after the restart" "from-p1" "$(fetch "$PORT")"
    out=$(sh_ container run --rm --network container:p1 "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80' 2>&1)
    check "network container: rootless" "from-p1" "$out"
}

@test "the daemon connects to a port of a container" {
    check "connect to a port of a container (not published)" "HTTP/1.1 101 Switching Protocols
from-p1" "$(dial containers/p1 80)"
    check "connect to a closed port" "HTTP/1.1 502 Bad Gateway" "$(dial containers/p1 81 | head -1)"
    check "connect without a port" "HTTP/1.1 400 Bad Request" "$(dial containers/p1 0 | head -1)"
    check "connect to a container that is not there" "HTTP/1.1 404 Not Found" "$(dial containers/nonesuch 80 | head -1)"
}

@test "the daemon connects to a port of a pod" {
    sh_ pod create --name dp > /dev/null
    sh_ run -d --pod dp --name dpc "$IMG" nc -lk -p 8080 -e echo from-pod > /dev/null
    e2e_wait_listening dpc 8080
    out=$(dial pods/dp 8080)
    check "connect to a port of a pod" "HTTP/1.1 101 Switching Protocols
from-pod" "$out"
    sh_ pod stop dp > /dev/null
    check "connect to a pod that is stopped" "HTTP/1.1 409 Conflict" "$(dial pods/dp 8080 | head -1)"
    sh_ pod rm -t 0 -f dp > /dev/null
}

@test "pasta goes with the container and nothing of its namespace stays" {
    pidfile=$(ls "$WORKDIR"/run/velarx/networks/pasta/*.pid)
    newpid=$(cat "$pidfile")
    [ -n "$newpid" ] || { echo "needs the pasta of the container p1" >&2; exit 1; }
    id=$(sh_ container inspect --format '{{.Id}}' p1)
    check "the namespace of the container is recorded" 1 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    sh_ container rm -t 0 -f p1 > /dev/null
    e2e_wait_exit "$newpid"
    check "pasta stopped with the container" "gone" "$(e2e_alive "$newpid")"
    check "no file of its pasta" "" "$(ls "$WORKDIR"/run/velarx/networks/pasta 2> /dev/null)"
    check "and no record of its namespace" 0 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
}

# the runtime makes the network namespace of a container with a user
# namespace of its own; its monitor holds it, and pasta runs on the monitor's
# descriptor, not on the first process, so a restart of the policy keeps the
# published port
@test "a container with a user namespace of its own keeps pasta across its restarts" {
    port=$((PORT + 9))
    sh_ container run -d --name ur --uidmap 0:1:1000 --gidmap 0:1:1000 --restart always \
        -p "$port:80" "$IMG" sh -c 'echo run; nc -lk -p 80 -e echo from-ur' > /dev/null
    e2e_wait_listening ur
    check "published port of the first run" "from-ur" "$(fetch "$port")"
    check_match "its pasta runs on a descriptor of the monitor" "--netns /proc/$(monitor_of ur)/fd/[0-9]+ " "$(pasta_args ur)"
    log=$WORKDIR/ur.events
    sh_ events --filter container=ur --filter event=restart --format '{{.Status}}' > "$log" 2>&1 3>&- &
    follow=$!
    # (the end of nc is the end of the container: the policy starts it again)
    sh_ container exec ur pkill nc > /dev/null 2>&1
    e2e_wait_line "$log" '^restart$' 30 || e2e_die "ur was not restarted: $(sh_ container inspect --format '{{.State.Status}} {{.RestartCount}}' ur 2>&1)"
    kill "$follow" 2> /dev/null
    wait "$follow" 2> /dev/null || true
    timeout 30 "$CLI" --config "$CONF" --socket "$ESOCK" container wait --condition running ur > /dev/null ||
        e2e_die "ur does not run again"
    e2e_wait_listening ur
    check "published port after a restart of the policy" "from-ur" "$(fetch "$port")"
    check_match "the same pasta, on the monitor" "--netns /proc/$(monitor_of ur)/fd/[0-9]+ " "$(pasta_args ur)"
    sh_ container rm -t 0 -f ur > /dev/null
}

# under a service manager the monitor leaves its parent (a child of its own,
# the unit's main process): pasta runs on a descriptor of that process, not
# of the one that was started and exited
@test "the pasta of a container under a service manager runs on its monitor" {
    port=$((PORT + 10))
    sock=$WORKDIR/pn-notify.sock
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.bind(sys.argv[1]); s.settimeout(30)
s.recv(4096)
' "$sock" > /dev/null 2>&1 3>&- &
    reader=$!
    e2e_wait_path "$sock"
    NOTIFY_SOCKET=$sock "$CLI" --config "$CONF" container run -d --sdnotify conmon --name pn -p "$port:80" "$IMG" \
        nc -lk -p 80 -e echo from-pn > "$WORKDIR/pn.out" 2>&1
    check "run under a service manager" "0 $(cat "$WORKDIR/pn.out")" "$? $(cat "$WORKDIR/pn.out")"
    wait "$reader" || true
    check_match "its pasta runs on a descriptor of the monitor" "--netns /proc/$(monitor_of pn)/fd/[0-9]+ " "$(pasta_args pn)"
    e2e_wait_listening pn
    check "published port" "from-pn" "$(fetch "$port")"
    sh_ container rm -t 0 -f pn > /dev/null
}

# a monitor killed while its container runs: the process of the container
# keeps the namespace (and its published port); when it ends too, the engine
# that follows it takes the network down: its pasta goes, its record too
@test "a killed monitor: the network namespace goes with the container" {
    port=$((PORT + 11))
    sh_ container run -d --name mk -p "$port:80" "$IMG" nc -lk -p 80 -e echo from-mk > /dev/null
    e2e_wait_listening mk
    id=$(sh_ container inspect --format '{{.Id}}' mk)
    pid=$(sh_ container inspect --format '{{.State.Pid}}' mk)
    mon=$(monitor_of mk)
    pasta=$(cat "$WORKDIR/run/velarx/networks/pasta/$id.pid")
    check_match "its monitor" "^[0-9]+$" "$mon"
    check "its namespace is recorded" 1 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    kill -9 "$mon"
    e2e_wait_exit "$mon"
    check "the container runs on, its published port too" "from-mk" "$(fetch "$port")"
    check "its namespace is still recorded" 1 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    kill -9 "$pid"
    timeout 30 "$CLI" --config "$CONF" --socket "$ESOCK" container wait mk > /dev/null ||
        e2e_die "the end of mk is not recorded"
    e2e_wait_exit "$pasta" || e2e_die "the pasta of mk outlived it"
    check "its pasta is gone" "gone" "$(e2e_alive "$pasta")"
    check "and the record of its namespace" 0 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    sh_ container rm mk > /dev/null
}

@test "-p takes an IPv4 host address in brackets, an empty -p publishes nothing" {
    # podman's -p: an IPv4 host address in brackets; an empty -p publishes
    # nothing (a port of its own: the bridge checks below take PORT + 1, + 2)
    sh_ run -d --name p2 -p "[127.0.0.1]:$((PORT + 7)):80" -p "" "$IMG" nc -lk -p 80 -e echo from-p2 > /dev/null
    e2e_wait_listening p2
    check "-p [127.0.0.1]:HOST:CTR" '{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"'$((PORT + 7))'"}]}' \
        "$(sh_ inspect --format '{{json .HostConfig.PortBindings}}' p2 2>&1)"
    check "-p [127.0.0.1]:HOST:CTR publishes" "from-p2" "$(fetch "$((PORT + 7))")"
    sh_ rm -f -t0 p2 > /dev/null
    out=$(sh_ create -p "[127.0.0.1;x]:1:1" "$IMG" true 2>&1)
    check "-p with an odd host address" 125 $?
}

# nothing asked for is the default network (pasta rootless, never a bridge
# named by the engine); pasta and a bridge asked for are those
@test "rootless: no --network, --network pasta and --network bridge all run" {
    out=$(sh_ container run --rm "$IMG" sh -c 'grep -m1 nameserver /etc/resolv.conf' 2>&1)
    check "no --network: pasta" "nameserver 169.254.1.1" "$out"
    out=$(sh_ container run --rm --network pasta "$IMG" sh -c 'grep -m1 nameserver /etc/resolv.conf' 2>&1)
    check "--network pasta" "nameserver 169.254.1.1" "$out"
    sh_ container run --rm --network bridge "$IMG" true > "$WORKDIR/bridge.out" 2>&1
    check "--network bridge" "0 " "$? $(cat "$WORKDIR/bridge.out")"
}

# pasta does not end by itself with the monitor that holds its namespace:
# the engine that follows the container stops it, an engine that comes back
# finds it running
@test "a pasta stays across a restart of the engine and goes with the container" {
    port=$((PORT + 12))
    sh_ container run -d --name er -p "$port:80" "$IMG" nc -lk -p 80 -e echo from-er > /dev/null
    e2e_wait_listening er
    id=$(sh_ container inspect --format '{{.Id}}' er)
    pasta=$(cat "$WORKDIR/run/velarx/networks/pasta/$id.pid")
    kill "$(cat "$WORKDIR/daemon.pid")"
    e2e_wait_exit "$(cat "$WORKDIR/daemon.pid")" 30
    check "the pasta runs without the engine" "alive" "$(e2e_alive "$pasta")"
    check "its published port works" "from-er" "$(fetch "$port")"
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready daemon_pid "$DAEMON" --config "$CONF" varlink
    echo "$daemon_pid" > "$WORKDIR/daemon.pid"
    sh_ container rm -t 0 -f er > /dev/null
    e2e_wait_exit "$pasta" 30
    check "pasta stopped with the container" "gone" "$(e2e_alive "$pasta")"
}

# the row of the container NAME as the store has it, read with no velarx
# command (a command would reconcile the store first): its state and exit
# code, or "gone"
store_row () {
    python3 -I - "$WORKDIR/storage/db.sqlite" "$1" << 'EOT'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
r = c.execute("select state, exit_code from containers where name = ?", (sys.argv[2],)).fetchone()
print("gone" if r is None else "%s %s" % r)
EOT
}
# whether the port $1 of the host can be bound: nothing listens on it (what
# the connections of the test left in TIME_WAIT does not count)
port_free () {
    python3 -I -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen()
print("free")
' "$1" 2>&1 | tail -1
}
restart_engine () {
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready daemon_pid "$DAEMON" --config "$CONF" varlink
    echo "$daemon_pid" > "$WORKDIR/daemon.pid"
}

# the engine is killed while a container with a published port runs: when the
# container ends, its monitor stops its pasta, which frees the port, forgets
# its namespace and removes it (--rm), with no engine and before any other
# command runs
@test "the engine is killed: the monitor of the container stops its pasta and frees its port" {
    port=$((PORT + 13))
    sh_ container run -d --rm --name ek -p "$port:80" "$IMG" sh -c 'nc -lk -p 80 -e echo from-ek & sleep 6' > /dev/null
    e2e_wait_listening ek
    check "its published port" "from-ek" "$(fetch "$port")"
    id=$(sh_ container inspect --format '{{.Id}}' ek)
    pid=$(sh_ container inspect --format '{{.State.Pid}}' ek)
    mon=$(monitor_of ek)
    pasta=$(cat "$WORKDIR/run/velarx/networks/pasta/$id.pid")
    daemon=$(cat "$WORKDIR/daemon.pid")
    kill -9 "$daemon"
    e2e_wait_exit "$daemon" 30
    e2e_wait_exit "$pid" 30 || e2e_die "ek did not end"
    e2e_wait_exit "$mon" 30 || e2e_die "the monitor of ek did not end"
    check "its pasta is gone" "gone" "$(e2e_alive "$pasta")"
    check "no file of its pasta" "" "$(ls "$WORKDIR/run/velarx/networks/pasta/$id".* 2> /dev/null)"
    check "its port is free" "free" "$(port_free "$port")"
    check "no record of its namespace" 0 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    check "its row is gone" "gone" "$(store_row ek)"
}

# the monitor is killed in the middle of the release of the network: its
# pasta is stopped, the record of its namespace is not forgotten yet (the
# store's database is held from the stop of the pasta on, so the monitor
# waits to forget it) and its exit is not in the store; the engine finds the
# monitor gone and does the rest, with the same steps
@test "the monitor is killed while it releases the network: the engine finishes the release" {
    port=$((PORT + 14))
    sh_ container run -d --rm --name mh -p "$port:80" "$IMG" sh -c 'nc -lk -p 80 -e echo from-mh & sleep 5' > /dev/null
    e2e_wait_listening mh
    id=$(sh_ container inspect --format '{{.Id}}' mh)
    pid=$(sh_ container inspect --format '{{.State.Pid}}' mh)
    mon=$(monitor_of mh)
    pidfile=$WORKDIR/run/velarx/networks/pasta/$id.pid
    pasta=$(cat "$pidfile")
    # (the pasta does not end until it is let go: the monitor, which removes
    # its pid file once what comes before the release is in the store, waits
    # for it while the database is taken)
    kill -STOP "$pasta"
    go=$WORKDIR/mh.go
    release=$WORKDIR/mh.release
    rm -f "$go" "$release"
    mkfifo "$go" "$release"
    python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], isolation_level=None, timeout=30)
open(sys.argv[2]).read()
c.execute("BEGIN IMMEDIATE")
print("held", flush=True)
open(sys.argv[3]).read()
c.execute("ROLLBACK")
' "$WORKDIR/storage/db.sqlite" "$go" "$release" > "$WORKDIR/mh.held" 2>&1 3>&- &
    holder=$!
    e2e_wait_exit "$pid" 30 || e2e_die "mh did not end"
    e2e_wait_gone "$pidfile" 30 || e2e_die "the monitor did not stop the pasta of mh"
    echo > "$go"
    e2e_wait_line "$WORKDIR/mh.held" '^held$' 10 || e2e_die "the store database is not held"
    kill -CONT "$pasta"
    e2e_wait_exit "$pasta" 30 || e2e_die "the pasta of mh did not end"
    kill -9 "$mon"
    e2e_wait_exit "$mon" 10
    check "its port is free" "free" "$(port_free "$port")"
    check "the record of its namespace stays" 1 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    check_match "its exit is not in the store" "^running" "$(store_row mh)"
    echo > "$release"
    wait "$holder"
    rm -f "$go" "$release"
    # (its files go first, the monitor directory last, then its row)
    e2e_wait_gone "$WORKDIR/run/velarx/mon/${id:0:12}" 30 || e2e_die "the engine did not remove mh"
    for _ in $(seq 50); do [ "$(store_row mh)" = gone ] && break; sleep 0.1; done
    check "its row is gone" "gone" "$(store_row mh)"
    check "and the record of its namespace" 0 "$(e2e_netns_records "$WORKDIR/storage/db.sqlite" "container/$id")"
    check "no file of its pasta" "" "$(ls "$WORKDIR/run/velarx/networks/pasta/$id".* 2> /dev/null)"
}

@test "rootless bridge networks: names, addresses, the host, published ports" {
    # Rootless bridge networks: in the rootless network namespace, connected
    # to the host by pasta, the ports through a forwarder.
    command -v nft > /dev/null || test -x /usr/sbin/nft || skip "no nft"
    sh_ network create --subnet 10.213.60.0/24 rlnet > /dev/null
    check "rootless network create" 0 $?
    sh_ container run -d --name rb1 --network rlnet "$IMG" nc -lk -p 80 -e echo from-rb1 > /dev/null
    check "rootless run on a bridge" 0 $?
    e2e_wait_listening rb1
    out=$(sh_ container run --rm --network rlnet "$IMG" sh -c 'echo | nc -w 2 rb1 80' 2>&1)
    check "rootless bridge: a container by name" from-rb1 "$out"
    # (rb1 has .2, the client above had .3: the next address is the one after
    # the last given, as podman's IPAM does)
    out=$(sh_ container run --rm --network rlnet "$IMG" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}"' 2>&1)
    check "rootless bridge: the address" 10.213.60.4/24 "$out"
    # (a service of the host on every address: the host's loopback is not
    # reachable through host.containers.internal, and the registry may be on it)
    python3 -I -c 'import socket, sys; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(); print("listening", flush=True)
while True:
    c, _ = s.accept(); c.sendall(b"from-host\n"); c.close()' "$((PORT + 25))" > "$WORKDIR/hostbr.out" 3>&- &
    hostbr=$!
    e2e_wait_line "$WORKDIR/hostbr.out" '^listening$' 30 || e2e_die "the host service does not start"
    out=$(sh_ container run --rm --network rlnet "$IMG" sh -c "nc -w 2 host.containers.internal $((PORT + 25)) </dev/null" 2>&1)
    kill $hostbr 2> /dev/null
    check "rootless bridge: the host through pasta" from-host "$out"
    port2=$((PORT + 1))
    sh_ container run -d --name rb2 --network rlnet -p "$port2:80" "$IMG" nc -lk -p 80 -e echo from-rb2 > /dev/null
    e2e_wait_listening rb2
    check "rootless bridge: a published port" from-rb2 "$(fetch "$port2")"
    sh_ container run --rm --network rlnet -p "$port2:80" "$IMG" true > /dev/null 2>&1
    check "rootless bridge: a port published twice fails" 1 "$(test $? != 0 && echo 1)"
    python3 -I -c 'import socket, sys; s = socket.socket(); s.bind(("0.0.0.0", int(sys.argv[1]))); s.listen(); print("listening", flush=True); __import__("time").sleep(20)' "$((port2 + 1))" > "$WORKDIR/hostsvc.out" 3>&- &
    hostsvc=$!
    e2e_wait_line "$WORKDIR/hostsvc.out" '^listening$' 30 || e2e_die "the host service does not start"
    out=$(sh_ container run --rm --network rlnet -p "$((port2 + 1)):80" "$IMG" true 2>&1)
    check "rootless bridge: a port of a host service is not taken" 1 "$(echo "$out" | grep -c 'in use')"
    kill $hostsvc 2> /dev/null
    check "rootless bridge: one forwarder" 1 "$(ls "$WORKDIR"/run/velarx/networks/portfwd/ 2> /dev/null | grep -c '\.pid$')"
    fwds=$(cat "$WORKDIR"/run/velarx/networks/portfwd/*.pid 2> /dev/null)
    sh_ container rm -t 0 -f rb1 rb2 > /dev/null
    for fwd in $fwds; do e2e_wait_exit "$fwd" 30; done
    check "rootless bridge: the forwarder goes" 0 "$(ls "$WORKDIR"/run/velarx/networks/portfwd/ 2> /dev/null | grep -c '\.pid$')"
    check "rootless bridge: no record left" "" "$(ls "$WORKDIR"/run/velarx/networks/dns/ 2> /dev/null | grep -v -e server.lock -e control.sock -e upstream -e server.log)"
    sh_ network rm rlnet > /dev/null
    check "rootless network rm" 0 $?
    check "rootless network rm releases the rootless namespace" "" \
        "$(ps -eo args | grep "[p]asta.*$WORKDIR/run/velarx/netns/rootless-netns")"
}

@test "the host's loopback is not reachable through host.containers.internal, its own address is" {
    # podman's pasta arguments: 169.254.1.2 is the address of the container's
    # namespace on the host (--map-guest-addr), a service bound to 127.0.0.1
    # is not reachable unless --map-host-loopback asks
    srv="import socket, sys, threading
def serve(addr, port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port)); s.listen()
    def loop():
        while True:
            c, _ = s.accept(); c.sendall(b'hello\n'); c.close()
    threading.Thread(target=loop, daemon=True).start()
serve('127.0.0.1', int(sys.argv[1])); serve('0.0.0.0', int(sys.argv[2]))
print('listening', flush=True)
threading.Event().wait(60)"
    lo=$((PORT + 20)); all=$((PORT + 21))
    python3 -I -c "$srv" "$lo" "$all" > "$WORKDIR/loop.out" 3>&- &
    pid=$!
    e2e_wait_line "$WORKDIR/loop.out" '^listening$' 30 || e2e_die "the host service does not start"
    probe () { sh_ container run --rm "${@:2}" "$IMG" sh -c "nc -w 2 $1 </dev/null 2>&1 | head -1" ; }
    check "the address of the host answers" hello "$(probe "169.254.1.2 $all")"
    check "host.containers.internal too" hello "$(probe "host.containers.internal $all")"
    check "the loopback of the host does not" "" "$(probe "169.254.1.2 $lo")"
    check "--map-host-loopback opens it" hello "$(probe "169.254.1.3 $lo" --network pasta:--map-host-loopback,169.254.1.3)"
    check "--map-gw is podman's, not pasta's" ok "$(sh_ container run --rm --network pasta:--map-gw "$IMG" echo ok 2>&1)"
    # the options of the user are what /etc/hosts and resolv.conf say
    check "a --map-guest-addr of the user is host.containers.internal" "169.254.9.9 hello" \
        "$(sh_ container run --rm --network pasta:--map-guest-addr,169.254.9.9 "$IMG" \
            sh -c "awk '/host.containers.internal/ { printf \"%s \", \$1 }' /etc/hosts; nc -w 2 host.containers.internal $all </dev/null" 2>&1)"
    # (the first one: the host's follow, as podman's)
    check "a --dns-forward of the user is the name server" "nameserver 169.254.7.7" \
        "$(sh_ container run --rm --network pasta:--dns-forward,169.254.7.7 "$IMG" grep -m1 nameserver /etc/resolv.conf 2>&1)"
    kill $pid 2> /dev/null
}

@test "rootless bridge: the short id and the hostname are names, a published port is on IPv6 too, an alias needs a bridge" {
    command -v nft > /dev/null || test -x /usr/sbin/nft || skip "no nft"
    sh_ network create --subnet 10.213.61.0/24 rlnet2 > /dev/null
    sh_ container run -d --name hn1 --hostname myhost --network rlnet2 -p "$((PORT + 30)):80" "$IMG" nc -lk -p 80 -e echo from-hn1 > /dev/null
    check "run with a hostname on a bridge" 0 $?
    e2e_wait_listening hn1
    id=$(sh_ container inspect -f '{{.Id}}' hn1)
    out=$(sh_ container run --rm --network rlnet2 "$IMG" sh -c "getent hosts myhost | awk '{print \$1}'; getent hosts ${id:0:12} | awk '{print \$1}'; getent hosts hn1 | awk '{print \$1}'" 2>&1)
    check "the hostname, the short id and the name are one address" 1 "$(echo "$out" | sort -u | wc -l)"
    check_match "and it is the container's" "^10\.213\.61\." "$out"
    check "IPv4 reaches the published port" from-hn1 "$(python3 -I -c 'import socket,sys; s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),5); s.sendall(b"x\n"); print(s.recv(64).decode().strip())' "$((PORT + 30))")"
    check "IPv6 too" from-hn1 "$(python3 -I -c 'import socket,sys; s=socket.create_connection(("::1",int(sys.argv[1])),5); s.sendall(b"x\n"); print(s.recv(64).decode().strip())' "$((PORT + 30))" 2>&1)"
    sh_ container rm -t 0 -f hn1 > /dev/null
    out=$(sh_ container run --rm --network-alias x "$IMG" true 2>&1)
    check "--network-alias without a bridge network" 125 $?
    check_match "says why" "can only be used with Bridge mode networking" "$out"
    sh_ network rm rlnet2 > /dev/null
}
