# SPDX-License-Identifier: Apache-2.0
# End to end tests of the bridge networks, as root, with a daemon in a
# network namespace of its own: nothing touches the network of the host.
#
#   sudo VELARX_BINDIR=target/debug bats tests/e2e/bats/network.bats
#
# The image (E2E_IMAGE, default localhost:5000/alpine:chunked) is pulled
# first by a daemon in the namespace of the host (the registry is there),
# then the daemon runs in a network namespace of its own ($E2E_NETNS, a file
# bound to it) and so does every command of the tests that looks at the
# network (nse).  Skipped when not root, without nft or unshare, or when the
# image cannot be pulled.

load helpers

# (the grep of the script: basic regular expressions, a line at a time)
check_match () {
    if echo "$3" | grep -q -- "$2"; then return 0; fi
    echo "FAIL $1: expected to match '$2', got '$3'" >&2
    exit 1
}
ok () { :; }
fail () {
    echo "FAIL $1: ${*:2}" >&2
    exit 1
}

# nse CMD...: CMD in the network namespace of the tests (in the one of the
# host while the image is pulled)
nse () { $NSE "$@"; }
ip () { nse ip "$@"; }
nft () { nse nft "$@"; }

start_daemon () {
    # (the daemon says READY=1 when it serves)
    E2E_SPAWN_LOG=$WORKDIR/daemon-$1.log e2e_spawn_ready DAEMON_PID $NSE "$BIN/velarx" --config "$CONF" varlink ||
        e2e_die "the daemon did not start"
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
}

stop_daemon () {
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid")
    kill -INT "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID" 10
    kill -KILL "$DAEMON_PID" 2> /dev/null || :
    wait "$DAEMON_PID" 2> /dev/null || :
    rm -f "$SOCK"
}

# (--socket: the test's daemon, never an engine of the command's own)
sh_ () {
    "$BIN/velarx" --config "$CONF" --socket "$SOCK" "$@"
}

# What a daemon left mounted below the work directory.
umount_all () {
    grep " $WORKDIR" /proc/self/mounts | awk '{print $2}' | sort -r | while read -r m; do
        umount -l "$m" 2> /dev/null
    done
}
fetch () {
    # The answer of the server on 127.0.0.1:$1.
    nse python3 -I -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
s.settimeout(3)
out = b""
while True:
    try:
        b = s.recv(4096)
    except OSError:
        break
    if not b:
        break
    out += b
sys.stdout.write(out.decode().strip())
' "$1" 2>&1
}
run_ctr () {
    sh_ container run --rm "$@" 2>&1
}

# need_brnet: the network and the containers of the earlier tests
need_brnet () {
    if ! sh_ network inspect brnet > /dev/null 2>&1; then
        echo "FAIL no network brnet: the test 'network create, an overlapping subnet' failed or did not run" >&2
        exit 1
    fi
}

setup_file () {
    local t
    skip_unless_root
    for t in nft unshare; do
        command -v $t > /dev/null || skip "needs $t"
    done
    e2e_setup_file
    export IMG=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export CONF=$WORKDIR/config.toml
    export NSE=
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    cat > "$CONF" <<EOT
[engine]
socket = "$SOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/run/velarx"
root_dir = "$WORKDIR/root"
shutdown_timeout_secs = 5
[storage]
root = "$WORKDIR/storage"
[network.bridge]
default_bridge = "shbr0"
subnet = "10.213.0.0/24"
gateway = "10.213.0.1"
EOT
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"
    local rc=0
    start_daemon pull
    sh_ image pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || rc=$?
    stop_daemon
    umount_all
    test $rc = 0 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"
    export E2E_NETNS=$WORKDIR/netns
    touch "$E2E_NETNS"
    unshare --net="$E2E_NETNS" true
    export NSE="nsenter --net=$E2E_NETNS"
    ip link set lo up
    start_daemon net
    test -S "$SOCK" || { echo "the daemon does not start" >&2; cat "$WORKDIR/daemon-net.log" >&2; exit 1; }
}

# a failing check must not leave the host service that holds a port
teardown () {
    if [ -n "${hostsvc:-}" ]; then
        kill "$hostsvc" 2> /dev/null
        wait "$hostsvc" 2> /dev/null
        hostsvc=
    fi
    # (the dummy link of the macvlan test)
    if [ -n "${NSE:-}" ] && [ "$BATS_TEST_DESCRIPTION" = macvlan ]; then
        sh_ container rm -t 0 -f mv1 > /dev/null 2>&1
        sh_ network rm -t 0 -f mvnet > /dev/null 2>&1
        ip link del shmv0 > /dev/null 2>&1
    fi
    return 0
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    local p
    . "$E2E_DIR/cleanup.sh"
    e2e_remove_containers "$SH" "$SOCK"
    [ ! -s "$WORKDIR/daemon.pid" ] || stop_daemon
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do kill -INT "$p" 2> /dev/null; done
    umount_all
    e2e_teardown_file
}

@test "the default network is podman's" {
    # The default network: the address, the route, host.containers.internal.
    out=$(run_ctr "$IMG" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}"; ip route | grep default; grep host.containers.internal /etc/hosts')
    check_match "default network address" "^10.213.0.2/24" "$out"
    check_match "default network route" "default via 10.213.0.1" "$out"
    check_match "default network host.containers.internal" "10.213.0.1" "$out"
    # podman's name and id; the bridge keeps the name of the configuration,
    # which is not a name of the network (podman's `podman0` is not either).
    out=$(sh_ network ls | grep -c "^2f259bab93aa[0-9a-f]* *podman ")
    check "the default network is podman" 1 "$out"
    out=$(sh_ network inspect podman | tr -d ' \n')
    check_match "the default network has podman's id" '"id":"2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9"' "$out"
    check_match "the default network has a bridge of its own" '"network_interface":"shbr0"' "$out"
    run_ctr --network shbr0 "$IMG" true > /dev/null 2>&1
    check_match "the name of the bridge is not a name of the network" "[1-9]" "$?"
}

@test "network create, an overlapping subnet" {
    sh_ network create --subnet 10.213.4.0/24 brnet > /dev/null
    check "network create" 0 $?
    sh_ network create --subnet 10.213.4.0/25 brnet2 > /dev/null 2>&1
    check "network create of an overlapping subnet fails" 125 $?
    out=$(sh_ network inspect brnet | tr -d ' \n')
    check_match "network inspect" '"gateway":"10.213.4.1"' "$out"
}

@test "container to container by address and by name, /etc/hosts and DNS" {
    need_brnet
    sh_ container run -d --name b1 --network brnet --ip 10.213.4.50 "$IMG" nc -lk -p 80 -e echo from-b1 > /dev/null
    e2e_wait_listening b1
    out=$(run_ctr --network brnet "$IMG" sh -c 'echo | nc -w 2 10.213.4.50 80')
    check "container to container by address" "from-b1" "$out"
    out=$(run_ctr --network brnet "$IMG" sh -c 'echo | nc -w 2 b1 80')
    check "container to container by name" "from-b1" "$out"
    out=$(run_ctr --name hn1 --hostname web1 --network brnet --ip 10.213.4.77 "$IMG" sh -c 'grep -w web1 /etc/hosts; grep -c "127.0.0.1.*web1" /etc/hosts')
    check "the container's address in /etc/hosts" "10.213.4.77	web1 hn1
0" "$out"
    out=$(run_ctr --network brnet "$IMG" sh -c 'grep -c "search dns.podman" /etc/resolv.conf; grep nameserver /etc/resolv.conf')
    check "DNS search domain and nameserver" "1
nameserver 10.213.4.1" "$out"
    out=$(sh_ network inspect brnet | tr -d ' \n')
    check_match "network inspect shows the container" '"ipnet":"10.213.4.50/24"' "$out"
}

@test "published ports: from the host, hairpin, twice, held, pasta options" {
    need_brnet
    sh_ container run -d --name b2 --network brnet --network-alias web -p 18099:80 "$IMG" nc -lk -p 80 -e echo from-b2 > /dev/null
    e2e_wait_listening b2
    check "published port from the host" "from-b2" "$(fetch 18099)"
    out=$(run_ctr --network brnet "$IMG" sh -c 'echo | nc -w 2 web 80')
    check "network alias" "from-b2" "$out"
    out=$(run_ctr --network brnet "$IMG" sh -c 'echo | nc -w 2 10.213.4.1 18099')
    check "published port hairpin" "from-b2" "$out"
    run_ctr --network brnet -p 18099:80 "$IMG" true > /dev/null 2>&1
    check_match "a port published twice fails" "[1-9]" "$?"
    out=$(nse python3 -I -c 'import socket; s = socket.socket(); s.bind(("0.0.0.0", 18099)); print("bound")' 2>&1 | tail -1)
    check_match "a published port is held from the host" "Address already in use" "$out"
    $NSE python3 -I -c 'import socket, time; s = socket.socket(); s.bind(("0.0.0.0", 18097)); s.listen(); print("listening", flush=True); time.sleep(20)' > "$WORKDIR/hostsvc.out" 3>&- &
    hostsvc=$!
    e2e_wait_line "$WORKDIR/hostsvc.out" '^listening$' 30 || e2e_die "the host service does not start"
    out=$(run_ctr --network brnet -p 18097:80 "$IMG" true 2>&1)
    check_match "a port of a host service is not taken" "in use" "$out"
    kill $hostsvc 2> /dev/null
    wait $hostsvc 2> /dev/null
    hostsvc=
    run_ctr --network pasta:--pcap,/tmp/pcap "$IMG" true > /dev/null 2>&1
    check_match "pasta options that write files are refused" "[1-9]" "$?"
}

# The engine is killed while a container runs: when it ends, its monitor
# releases its network itself (the port, the firewall elements, the veth, the
# DNS record); the row of the attachment stays until `rm`.
@test "the engine is killed before the container ends: the monitor releases the network" {
    need_brnet
    sh_ container run -d --name b9 --network brnet --ip 10.213.4.90 -p 18098:80 "$IMG" sh -c 'sleep 4; exit 0' > /dev/null
    pid=$(sh_ container inspect --format '{{.State.Pid}}' b9)
    id=$(sh_ container inspect --format '{{.Id}}' b9)
    check_match "the address is in the firewall" '^[1-9]' "$(nft list ruleset | grep -c '10\.213\.4\.90')"
    check "the container has a DNS record" 1 "$(ls "$WORKDIR/run/velarx/networks/dns/"*/"$id" 2> /dev/null | wc -l)"
    mon=$(cat "$WORKDIR/run/velarx/mon/${id:0:12}/monitor.pid")
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid")
    kill -9 "$DAEMON_PID"
    wait "$DAEMON_PID" 2> /dev/null || :
    rm -f "$SOCK"
    e2e_wait_exit "$pid" 30 || e2e_die "the container did not end within 30 s"
    # (the monitor settles it after the container, and ends: no command runs
    # before the checks)
    e2e_wait_exit "$mon" 30 || e2e_die "the monitor did not end within 30 s"
    check "no firewall element of its address" 0 "$(nft list ruleset | grep -c '10\.213\.4\.90')"
    check "no DNS record of it" 0 "$(ls "$WORKDIR/run/velarx/networks/dns/"*/"$id" 2> /dev/null | wc -l)"
    check "no port of the bridge is its veth" "" "$(ip -o link show master "$(sh_ network inspect --format '{{.Bridge}}' brnet 2> /dev/null)" 2> /dev/null)"
    out=$(nse python3 -I -c 'import socket; s = socket.socket(); s.bind(("0.0.0.0", 18098)); print("bound")' 2>&1 | tail -1)
    check "its published port is free" bound "$out"
    start_daemon 9
    sh_ container rm -f b9 > /dev/null
}

@test "MAC addresses and ports without a network" {
    need_brnet
    out=$(run_ctr --network brnet --ip 10.213.4.60 "$IMG" cat /sys/class/net/eth0/address)
    check "MAC address derived from the address" "02:42:0a:d5:04:3c" "$out"
    out=$(run_ctr --network brnet --mac-address 12:34:56:78:9a:bc "$IMG" cat /sys/class/net/eth0/address)
    check "static MAC address" "12:34:56:78:9a:bc" "$out"
    out=$(run_ctr --network brnet --mac-address 01:00:00:00:00:01 "$IMG" true 2>&1)
    check_match "multicast MAC address refused" "invalid MAC address" "$out"
    # as podman: the ports are dropped, with a warning
    out=$(run_ctr --network none -p 8080:80 "$IMG" true 2>&1)
    check_match "port mapping without a network is dropped" "Port mappings have been discarded" "$out"
}

@test "the options of each network: --network NAME:ip=,mac=,alias=,interface_name=" {
    sh_ network create --subnet 10.213.60.0/24 optnet1 > /dev/null
    sh_ network create --subnet 10.213.61.0/24 optnet2 > /dev/null
    sh_ network create --subnet 10.213.62.0/24 optnet3 > /dev/null
    # (the second network gets the first free ethN: eth0)
    out=$(run_ctr --network optnet1:ip=10.213.60.20,mac=02:42:ac:11:00:98,interface_name=foo0 \
        --network optnet2:ip=10.213.61.30,alias=second "$IMG" sh -c \
        'cat /sys/class/net/foo0/address; ip -o -4 addr show foo0; ip -o -4 addr show eth0' | awk 'NF == 1 {print; next} {print $2, $3, $4}')
    check "an address, a MAC address and an interface name for each network" \
        "$(printf '02:42:ac:11:00:98\nfoo0 inet 10.213.60.20/24\neth0 inet 10.213.61.30/24')" "$out"
    sh_ container run -d --name optc --network optnet1:alias=first,interface_name=eth1 \
        --network optnet2:alias=second "$IMG" top > /dev/null
    out=$(sh_ container inspect --format '{{range .NetworkSettings.Networks}}{{.Aliases}} {{end}}' optc | tr -d ' ' | grep -o 'first\|second' | sort | tr '\n' ' ')
    check "the aliases of each network" "first second " "$out"
    out=$(sh_ container inspect --format '{{.NetworkSettings.Networks.optnet1.Aliases}}' optc)
    case "$out" in *second*) fail "the alias of the other network" "$out" ;; esac
    out=$(sh_ container inspect --format '{{.HostConfig.NetworkMode}}' optc)
    check "the network mode names the network, not its options" "optnet1" "$out"
    out=$(sh_ container ps --filter network=optnet1 --format '{{.Names}}')
    check "ps finds the container by the name of its network" "optc" "$out"
    # the interface asked for, the free eth0 for the other, and eth2 for the
    # one connected (eth1 is taken)
    sh_ network connect optnet3 optc
    out=$(sh_ container exec optc sh -c 'for i in eth0 eth1 eth2; do ip -o -4 addr show $i; done' | awk '{print $2, $4}' | cut -d. -f1-3)
    check "the interfaces of the networks" "$(printf 'eth0 10.213.61\neth1 10.213.60\neth2 10.213.62')" "$out"
    sh_ container rm -t 0 -f optc > /dev/null
    # one address of the command line cannot be on two networks
    out=$(run_ctr --network optnet1 --network optnet2 --ip 10.213.60.21 "$IMG" true)
    check_match "--ip with two networks" "can only be set for a single network" "$out"
    out=$(run_ctr --network optnet1 --network optnet2 --mac-address 02:42:ac:11:00:99 "$IMG" true)
    check_match "--mac-address with two networks" "can only be set for a single network" "$out"
    out=$(run_ctr --network optnet1:ip=10.213.61.5 "$IMG" true)
    check_match "an address outside the network" "not in any subnet" "$out"
    out=$(run_ctr --network optnet1:colour=red "$IMG" true)
    check_match "an unknown option" "invalid network option" "$out"
    out=$(run_ctr --network optnet1:alias= "$IMG" true)
    check_match "an empty alias" "invalid network option .alias=" "$out"
    out=$(run_ctr --network :ip=10.213.60.22 "$IMG" true)
    check_match "no network name" "invalid network mode" "$out"
    out=$(run_ctr --network optnet1:interface_name=foo0 --network optnet2:interface_name=foo0 "$IMG" true)
    check_match "an interface name of two networks" "more than one network" "$out"
    out=$(run_ctr --network optnet1:ip=10.213.60.20 --ip 10.213.60.21 "$IMG" true)
    check_match "an address twice" "given more than once" "$out"
    out=$(run_ctr --network optnet1:ip=10.213.60.20 --network optnet1:ip=10.213.60.21 "$IMG" true)
    check_match "a network twice with options" "given more than once" "$out"
    sh_ network rm optnet1 optnet2 optnet3 > /dev/null
}

@test "a free host port and -P" {
    need_brnet
    # A free host port.
    sh_ container run -d --name b3 --network brnet -p 80 "$IMG" nc -lk -p 80 -e echo from-b3 > /dev/null
    e2e_wait_listening b3
    port=$(nft list map ip velarx dnat_tcp | grep -o '[0-9]* : 10.213.4.[0-9]* . 80' | grep -v '^18099' | awk '{print $1}' | head -1)
    check "connect to a free host port" "from-b3" "$(fetch "${port:-0}")"
    check "container port says which" "0.0.0.0:${port:-none}" "$(sh_ container port b3 80/tcp 2>&1)"
    sh_ container rm -t 0 -f b3 > /dev/null
    # -P: the exposed ports, each on a free host port
    sh_ container run -d --name b4 --network brnet --expose 81 -P "$IMG" nc -lk -p 81 -e echo from-b4 > /dev/null
    e2e_wait_listening b4 81
    port=$(sh_ container port b4 81/tcp 2>&1 | sed 's/.*://')
    check_match "-P publishes an exposed port" "^[0-9][0-9]*$" "$port"
    check "connect to it" "from-b4" "$(fetch "${port:-0}")"
    sh_ container rm -t 0 -f b4 > /dev/null
}

@test "network IP range, MTU, unsupported option" {
    sh_ network create --subnet 10.213.5.0/24 --ip-range 10.213.5.100-10.213.5.110 rangenet > /dev/null
    out=$(run_ctr --network rangenet "$IMG" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}"')
    check "network IP range" "10.213.5.100/24" "$out"
    sh_ network rm rangenet > /dev/null
    sh_ network create --subnet 10.213.6.0/24 --opt mtu=1400 mtunet > /dev/null
    check "network MTU" "1400" "$(run_ctr --network mtunet "$IMG" cat /sys/class/net/eth0/mtu)"
    sh_ network rm mtunet > /dev/null
    sh_ network create --opt vlan=3 badopt > /dev/null 2>&1
    check_match "unsupported network option" "[1-9]" "$?"
}

@test "an internal network" {
    sh_ network create --subnet 10.213.7.0/24 --internal intnet > /dev/null
    sh_ container run -d --name i1 --network intnet "$IMG" nc -lk -p 80 -e echo from-i1 > /dev/null
    e2e_wait_listening i1
    out=$(run_ctr --network intnet "$IMG" sh -c 'echo | nc -w 2 i1 80; ip route | grep -c default')
    check "internal network: containers only" "from-i1
0" "$out"
    sh_ container rm -t 0 -f i1 > /dev/null
    sh_ network rm intnet > /dev/null
}

@test "two bridge networks do not reach each other: --opt isolate" {
    sh_ network create --subnet 10.213.8.0/24 --opt isolate=true isonet1 > /dev/null
    check "isolate=true" 0 $?
    sh_ network create --subnet 10.213.9.0/24 isonet2 > /dev/null
    sh_ network create --subnet 10.213.10.0/24 --opt isolate=strict isonet3 > /dev/null
    check "isolate=strict" 0 $?
    out=$(sh_ network create --opt isolate=false isonet4 2>&1)
    check_match "isolate=false is refused" "never forward traffic to each other" "$out"
    sh_ network create --opt isolate=maybe isonet4 > /dev/null 2>&1
    check_match "an unknown value" "[1-9]" "$?"
    for n in 1 2 3; do
        sh_ container run -d --name iso$n --network isonet$n --ip 10.213.$((7 + n)).50 "$IMG" nc -lk -p 80 -e echo from-iso$n > /dev/null
        e2e_wait_listening iso$n
    done
    for n in 1 2 3; do
        out=$(run_ctr --network isonet$n "$IMG" sh -c "echo | nc -w 2 10.213.$((7 + n)).50 80")
        check "isonet$n: its own containers" "from-iso$n" "$out"
    done
    # (whatever the option: no bridge forwards to another, either way)
    for pair in "1 2" "2 1" "2 3" "3 2" "1 3"; do
        set -- $pair
        out=$(run_ctr --network isonet$1 "$IMG" sh -c "echo | nc -w 2 10.213.$((7 + $2)).50 80; echo rc=\$?")
        check_match "isonet$1 does not reach isonet$2" "^rc=[1-9]" "$out"
    done
    sh_ container rm -t 0 -f iso1 iso2 iso3 > /dev/null
    sh_ network rm isonet1 isonet2 isonet3 > /dev/null
}

@test "dual stack: IPv6 subnets, names, a published port" {
    # Dual stack: an IPv6 subnet picked or given, the addresses, the default
    # route, the names (AAAA), a static IPv6 address, a port published on IPv6.
    sh_ network create --ipv6 --subnet 10.213.13.0/24 v6auto > /dev/null
    check "network create --ipv6" 0 $?
    out=$(sh_ network inspect v6auto | tr -d ' \n')
    check_match "network create --ipv6 picks a ULA /64" '"subnet":"fd[0-9a-f:]*::/64"' "$out"
    sh_ network rm v6auto > /dev/null
    sh_ network create --subnet 10.213.14.0/24 --subnet fd00:213:14::/64 v6net > /dev/null
    check "network create with an IPv6 subnet" 0 $?
    sh_ container run -d --name s6 --network v6net -p 18097:80 "$IMG" nc -lk -p 80 -e echo from-s6 > /dev/null
    e2e_wait_listening s6
    out=$(run_ctr --network v6net "$IMG" sh -c 'ip -6 -o addr show eth0 scope global | awk "{print \$4}"; ip -6 route show default; nslookup -type=AAAA s6 2>&1 | grep -c "fd00:213:14::2"; echo | nc -w 2 fd00:213:14::2 80')
    check_match "dual stack: the IPv6 address" "^fd00:213:14::3/64" "$out"
    check_match "dual stack: the IPv6 default route" "default via fd00:213:14::1 dev eth0" "$out"
    check_match "dual stack: AAAA of a container name" "^1$" "$out"
    check_match "dual stack: containers reach each other over IPv6" "from-s6" "$out"
    out=$(run_ctr --network v6net --ip6 fd00:213:14::99 "$IMG" ip -6 -o addr show eth0 scope global)
    check_match "dual stack: --ip6" "fd00:213:14::99/64" "$out"
    out=$(run_ctr --network v6net --name h6 "$IMG" sh -c 'grep -w h6 /etc/hosts | awk "{print \$1}"')
    check_match "dual stack: /etc/hosts has the IPv4 address" "^10\.213\.14\." "$out"
    check_match "dual stack: /etc/hosts has the IPv6 address" "^fd00:213:14::" "$out"
    out=$(nse python3 -I -c '
import socket
s = socket.create_connection(("fd00:213:14::1", 18097), timeout=3)
s.settimeout(3)
print(s.recv(4096).decode().strip())' 2>&1)
    check "dual stack: a port published on IPv6" "from-s6" "$out"
    out=$(nse python3 -I -c '
import socket
s = socket.create_connection(("::1", 18097), timeout=3)
s.settimeout(3)
print(s.recv(4096).decode().strip())' 2>&1)
    check "dual stack: a published port on ::1" "from-s6" "$out"
    check "dual stack: the IPv6 table" 0 "$(nft list table ip6 velarx > /dev/null 2>&1; echo $?)"
    sh_ container rm -t 0 -f s6 > /dev/null
    sh_ network rm v6net > /dev/null
    check "dual stack: the ::1 forwarder goes with the container" 0 "$(ls "$WORKDIR/run/velarx/networks/portfwd" 2> /dev/null | grep -c pid)"
    sh_ network create --subnet fd00:213:15::/64 v6only > /dev/null
    out=$(sh_ network inspect v6only | tr -d ' \n')
    check_match "an IPv6 subnet alone: dual stack" '"subnet":"10\..*"subnet":"fd00:213:15::/64"' "$out"
    sh_ network rm v6only > /dev/null
}

@test "macvlan" {
    # macvlan: the containers on the LAN of a parent (a dummy here), no
    # bridge, no firewall rule.
    ip link add shmv0 type dummy && ip link set shmv0 up
    sh_ network create -d macvlan --subnet 10.213.16.0/24 --opt parent=shmv0 mvnet > /dev/null
    check "network create -d macvlan" 0 $?
    out=$(sh_ network inspect mvnet | tr -d ' \n')
    check_match "a macvlan network" '"driver":"macvlan"' "$out"
    sh_ container run -d --name mv1 --network mvnet "$IMG" nc -lk -p 80 -e echo from-mv1 > /dev/null
    e2e_wait_listening mv1
    mvpid=$(sh_ container inspect mv1 | tr -d ' \n' | grep -o '"[Pp]id":[0-9]*' | head -1 | cut -d: -f2)
    check_match "macvlan: the link" "macvlan mode bridge" "$(nsenter --net=/proc/$mvpid/ns/net ip -d -o link show eth0 2>&1)"
    out=$(run_ctr --network mvnet "$IMG" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}"; ip route | grep default; echo | nc -w 2 10.213.16.2 80')
    check_match "macvlan: the address" "^10.213.16.3/24" "$out"
    check_match "macvlan: the default route" "default via 10.213.16.1" "$out"
    check_match "macvlan: containers reach each other" "from-mv1" "$out"
    check "macvlan: no firewall rule" "" "$(nft list ruleset 2> /dev/null | grep 10.213.16)"
    # a running container connected, then disconnected: its link goes
    sh_ container run -d --name mv2 "$IMG" sleep 1000 > /dev/null
    sh_ network connect mvnet mv2 > /dev/null
    check "network connect to a macvlan network" 0 $?
    mv2pid=$(sh_ container inspect mv2 | tr -d ' \n' | grep -o '"[Pp]id":[0-9]*' | head -1 | cut -d: -f2)
    links () { nsenter --net=/proc/$mv2pid/ns/net ip -d -o link show | grep -c 'macvlan mode bridge'; }
    check "macvlan: the link of the connect" 1 "$(links)"
    sh_ network disconnect mvnet mv2 > /dev/null
    check "network disconnect from a macvlan network" 0 $?
    check "macvlan: the link went with the disconnect" 0 "$(links)"
    sh_ container rm -f -t0 mv2 > /dev/null
    sh_ container rm -t 0 -f mv1 > /dev/null
    sh_ network rm mvnet > /dev/null
    check "macvlan network rm" 0 $?
    check "macvlan: the parent stays" 0 "$(ip link show shmv0 > /dev/null; echo $?)"
    ip link del shmv0
}

@test "connect and disconnect of a running container" {
    need_brnet
    # connect and disconnect of a running container.
    sh_ network create --subnet 10.213.8.0/24 hotnet > /dev/null
    sh_ container run -d --name hot1 --network hotnet "$IMG" nc -lk -p 80 -e echo from-hot1 > /dev/null
    sh_ network connect --alias hotalias --ip 10.213.8.40 hotnet b2 > /dev/null
    check "network connect of a running container" 0 $?
    out=$(sh_ container exec b2 sh -c 'ip -4 -o addr show eth1 | awk "{print \$4}"; ip route | grep -c default; echo | nc -w 2 10.213.8.2 80')
    check "connected interface" "10.213.8.40/24
1
from-hot1" "$out"
    out=$(run_ctr --network hotnet "$IMG" sh -c 'echo | nc -w 2 hotalias 80')
    check "DNS of a connected container" "from-b2" "$out"
    sh_ network disconnect hotnet b2 > /dev/null
    check "network disconnect of a running container" 0 $?
    sh_ network disconnect brnet b2 > /dev/null 2>&1
    check_match "the network of the published ports stays while it runs" "[1-9]" "$?"
    out=$(sh_ container exec b2 sh -c 'test -e /sys/class/net/eth1 && echo present || echo gone')
    check "disconnected interface" "gone" "$out"
    check "published port after disconnect" "from-b2" "$(fetch 18099)"
    sh_ container rm -t 0 -f hot1 > /dev/null
    sh_ network rm hotnet > /dev/null
}

@test "network create --route, connect --ip6 and --mac-address, network reload" {
    sh_ network create --subnet 10.213.50.0/24 --subnet fd00:213:50::/64 --route 10.99.0.0/24,10.213.50.77 --route 10.98.0.0/24,10.213.50.77,200 rtnet > /dev/null
    check "network create --route" 0 $?
    sh_ network create --subnet 10.213.51.0/24 --subnet fd00:213:51::/64 cnet > /dev/null
    sh_ container run -d --name rt1 --network rtnet "$IMG" sleep 300 > /dev/null
    out=$(sh_ container exec rt1 ip route)
    check_match "the route in the container" "10\.99\.0\.0/24 via 10\.213\.50\.77 dev eth0" "$out"
    check_match "the route with a metric" "10\.98\.0\.0/24 via 10\.213\.50\.77 dev eth0 .*metric 200" "$out"
    sh_ network connect --ip6 fd00:213:51::50 --mac-address 0a:00:00:00:51:01 cnet rt1 > /dev/null
    check "network connect --ip6 --mac-address" 0 $?
    out=$(sh_ container exec rt1 sh -c 'ip -o link show eth1; ip -6 -o addr show eth1 scope global')
    check_match "the MAC address" "link/ether 0a:00:00:00:51:01" "$out"
    check_match "the IPv6 address" "fd00:213:51::50/64" "$out"
    sh_ network create --subnet 10.213.52.0/24 --subnet fd00:213:52::/64 cnet2 > /dev/null
    out=$(sh_ network connect --ip6 fd00:213:99::5 cnet2 rt1 2>&1)
    check_match "an address outside the subnet is refused" "requested static ip fd00:213:99::5 not in any subnet on network cnet2" "$out"
    sh_ network rm cnet2 > /dev/null
    # the rules a flush took away are made again
    nft delete table ip velarx
    check "the table is gone" 1 "$(nft list table ip velarx > /dev/null 2>&1; echo $?)"
    id=$(sh_ container inspect --format '{{.Id}}' rt1)
    check "network reload prints the ID" "$id" "$(sh_ network reload rt1)"
    check "the table is back" 0 "$(nft list table ip velarx > /dev/null 2>&1; echo $?)"
    check "network reload --all: its ID among those of the running containers" "$id" \
        "$(sh_ network reload -a | grep -x "$id")"
    sh_ network disconnect cnet rt1 > /dev/null
    sh_ container rm -f -t 0 rt1 > /dev/null
    sh_ network rm rtnet cnet > /dev/null
}

@test "network container: and ns: join the namespace of a target" {
    need_brnet
    # container: and ns: join the namespace of a target, also after a restart
    # of the daemon and of the target.
    sh_ container run -d --name tgt --network brnet "$IMG" nc -lk -p 80 -e echo from-tgt > /dev/null
    e2e_wait_listening tgt
    out=$(run_ctr --network container:tgt "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80')
    check "network container:" "from-tgt" "$out"
    tgtpid=$(sh_ container inspect --format '{{.State.Pid}}' tgt)
    out=$(run_ctr --network "ns:/proc/$tgtpid/ns/net" "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80')
    check "network ns:" "from-tgt" "$out"
    sh_ container run -d --name dep --network container:tgt "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80' > /dev/null
    sh_ container wait dep > /dev/null
    stop_daemon
    start_daemon net
    out=$(run_ctr --network container:tgt "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80')
    check "network container: after a restart of the daemon" "from-tgt" "$out"
    sh_ container start dep > /dev/null
    sh_ container wait dep > /dev/null
    check "a dependent created before the restart" "2" "$(sh_ container logs dep 2>&1 | grep -c from-tgt)"
    sh_ container restart tgt > /dev/null
    e2e_wait_listening tgt
    out=$(run_ctr --network container:tgt "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80')
    check "network container: after a restart of the target" "from-tgt" "$out"
    sh_ container rm -t 0 -f dep tgt > /dev/null
}

@test "a container stopped and started again by the same daemon has its network" {
    # (the exit is recorded, and the network released, by the command the
    # monitor runs: the daemon sets the network up again at the next start)
    sh_ container run -d --name again "$IMG" sleep 1000 > /dev/null
    addr="ip -4 -o addr show eth0 | awk '{print \$4}'; ip route | grep -c default"
    first=$(sh_ container exec again sh -c "$addr")
    check_match "the first start" "^10.213.0.[0-9]*/24" "$first"
    sh_ container stop -t 0 again > /dev/null
    sh_ container start again > /dev/null
    check "a start after a stop" "$first" "$(sh_ container exec again sh -c "$addr" 2>&1)"
    sh_ container restart -t 0 again > /dev/null
    check "a restart" "$first" "$(sh_ container exec again sh -c "$addr" 2>&1)"
    sh_ container rm -t 0 -f again > /dev/null
}

# The namespace of a container that another one joined outlives it: its
# interface is taken down with its end, so that its start does not put the
# same address on a second port of the bridge.
@test "a container that another joined stopped and started again has one port" {
    ports () { ip -o link show master shbr0 | wc -l; }
    n=$(ports)
    sh_ container run -d --name jna "$IMG" sleep 1000 > /dev/null
    sh_ container run -d --name jnb --network container:jna "$IMG" sleep 1000 > /dev/null
    check "the two share a port" $((n + 1)) "$(ports)"
    sh_ container stop -t 0 jna > /dev/null
    check "no port stays" "$n" "$(ports)"
    check "the namespace that is left has no interface" "" \
        "$(sh_ container exec jnb sh -c 'ls /sys/class/net | grep -v "^lo$"')"
    sh_ container start jna > /dev/null
    check "the start of the container makes one port" $((n + 1)) "$(ports)"
    sh_ container rm -t 0 -f jnb > /dev/null
    sh_ container rm -t 0 -f jna > /dev/null
}

@test "network rm of a used network" {
    need_brnet
    sh_ network rm brnet > /dev/null 2>&1
    check_match "network rm of a used network fails" "[1-9]" "$?"
    sh_ network rm -t 0 -f brnet > /dev/null
    check "network rm -f" 0 $?
}

@test "DNS servers of a network, update" {
    sh_ network create --subnet 10.213.9.0/24 --dns 10.213.9.53 dnssrv > /dev/null
    out=$(sh_ network inspect dnssrv | tr -d ' \n')
    check_match "network create --dns" '"network_dns_servers":\["10.213.9.53"\]' "$out"
    sh_ network update --dns-drop 10.213.9.53 --dns-add 10.0.0.53 dnssrv > /dev/null
    out=$(sh_ network inspect dnssrv | tr -d ' \n')
    check_match "network update" '"network_dns_servers":\["10.0.0.53"\]' "$out"
    sh_ network update --dns-drop 192.0.2.99 dnssrv > /dev/null 2>&1
    check_match "network update of a server not set" "[1-9]" "$?"
    sh_ network create --dns bogus dnsbad > /dev/null 2>&1
    check_match "network create --dns of an invalid address" "[1-9]" "$?"
    sh_ network create --subnet 10.213.10.0/24 --disable-dns nodnsnet > /dev/null
    out=$(sh_ network inspect nodnsnet | tr -d ' \n')
    check_match "network create --disable-dns" '"dns_enabled":false' "$out"
    sh_ network rm dnssrv nodnsnet > /dev/null
}

@test "a container none, connected, or disconnected from its last network" {
    # `--network none` then `network connect`: the network is the container's
    # for the run, and nothing of it stays after the stop.
    sh_ network create --subnet 10.213.12.0/24 nonenet > /dev/null
    sh_ container create --name nc1 --network none "$IMG" sleep 600 > /dev/null
    sh_ network connect nonenet nc1 > /dev/null
    sh_ container start nc1 > /dev/null
    out=$(sh_ container exec nc1 sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}"')
    check_match "a none container connected has its interface" "^10.213.12." "$out"
    sh_ container stop -t 0 nc1 > /dev/null
    sh_ network create --subnet 10.213.13.0/24 nonenet2 > /dev/null
    sh_ network connect nonenet2 nc1 > /dev/null
    check "network connect of the stopped container: only the record" 0 $?
    sh_ container start nc1 > /dev/null
    out=$(sh_ container exec nc1 sh -c 'ip -4 -o addr show | grep -c " eth"')
    check "both networks after the next start" "2" "$out"
    sh_ container rm -t 0 -f nc1 > /dev/null
    # the last network goes: the container starts with the loopback only
    sh_ container create --name nc3 --network nonenet "$IMG" sh -c 'ls /sys/class/net' > /dev/null
    sh_ network disconnect nonenet nc3 > /dev/null
    check "disconnect of the only network" 0 $?
    sh_ container start -a nc3 > "$WORKDIR/nc3.out" 2>&1
    check "a container without a network starts" 0 $?
    check "the loopback only" "lo" "$(cat "$WORKDIR/nc3.out")"
    sh_ container rm -t 0 -f nc3 > /dev/null
    sh_ network rm nonenet nonenet2 > /dev/null
}

@test "network update of the DNS servers on a network with routes" {
    sh_ network create --subnet 10.213.14.0/24 --route 10.99.0.0/24,10.213.14.77 rtnet > /dev/null
    sh_ network update --dns-add 10.0.0.53 rtnet > /dev/null
    check "network update on a network created with --route" 0 $?
    out=$(sh_ network inspect rtnet | tr -d ' \n')
    check_match "the server is set" '"network_dns_servers":\["10.0.0.53"\]' "$out"
    sh_ network rm rtnet > /dev/null
}

@test "a name of two containers, a long range of ports" {
    sh_ network create --subnet 10.213.15.0/24 aliasnet > /dev/null
    for n in 1 2; do
        sh_ container run -d --name al$n --network aliasnet --network-alias web "$IMG" sleep 600 > /dev/null
    done
    out=$(run_ctr --network aliasnet "$IMG" sh -c 'nslookup web | grep -c "^Address: *10.213.15."')
    check "the name of two containers answers both addresses" "2" "$out"
    # a range of ports (the unit test of the firewall has the one that is
    # more than a netlink message: each port is a socket the monitor holds)
    sh_ container run -d --name rtp1 --network aliasnet -p 20000-20299:20000-20299/udp "$IMG" sleep 600 > /dev/null
    check "a container with 300 ports starts" 0 $?
    sh_ container rm -t 0 -f rtp1 > /dev/null
    check "and goes" 0 $?
    sh_ container run -d --name rtp2 --network aliasnet -p 20000-20299:20000-20299/udp "$IMG" sleep 600 > /dev/null
    check "the next one takes the same ports" 0 $?
    sh_ container rm -t 0 -f rtp2 al1 al2 > /dev/null
    sh_ network rm aliasnet > /dev/null
}

@test "the DNS server forwards the queries of a TCP client over TCP, more than one per connection" {
    # An upstream that has a short answer over UDP (TC set) and the whole one
    # over TCP, for as many queries as a connection brings.
    nse python3 -I -c '
import socket, struct, threading
def reply(q, tc):
    r = bytearray(q); r[2] |= 0x80
    if tc:
        r[2] |= 0x02
        return bytes(r)
    r[7] = 1
    return bytes(r) + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\xc0\x00\x02\x07"
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.2", 53))
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.2", 53)); t.listen(8)
def udp():
    while True:
        q, a = u.recvfrom(512); u.sendto(reply(q, True), a)
def serve(c):
    while True:
        h = c.recv(2)
        if len(h) < 2: return
        n = struct.unpack(">H", h)[0]; q = b""
        while len(q) < n: q += c.recv(n - len(q))
        r = reply(q, False); c.sendall(struct.pack(">H", len(r)) + r)
threading.Thread(target=udp, daemon=True).start()
while True:
    c, _ = t.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
' > /dev/null 2>&1 3>&- &
    hostsvc=$!
    sleep 1
    sh_ network create --subnet 10.213.16.0/24 --dns 127.0.0.2 tcpdns > /dev/null
    q='\x00\x1a\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03tcp\x04test\x00\x00\x01\x00\x01'
    out=$(run_ctr --network tcpdns "$IMG" sh -c "printf '$q$q' | nc -w 2 10.213.16.1 53 | wc -c")
    check "two queries over one TCP connection: two whole answers" "88" "$out"
    sh_ network rm tcpdns > /dev/null
}

@test "shareable network namespaces" {
    show_netns='echo $(readlink /proc/self/ns/net) $(ip -4 -o addr show eth0 | awk "{print \$4}")'
    SHARE=--annotation=io.velarx.shareableNetworkNamespace=true
    sh_ network create --disable-dns --subnet 10.213.11.0/24 shnet > /dev/null
    a=$(run_ctr $SHARE --network shnet "$IMG" sh -c "$show_netns")
    b=$(run_ctr $SHARE --network shnet "$IMG" sh -c "$show_netns")
    check_match "shareable netns" "^net:" "$a"
    check "shareable netns reused" "$a" "$b"
    # The pooled namespace comes with its address: /etc/hosts has it.
    out=$(run_ctr $SHARE --network shnet "$IMG" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}" | cut -d/ -f1; grep -w "$(hostname)" /etc/hosts | grep -v "^127\." | awk "{print \$1}"')
    check "a pooled namespace: its address in /etc/hosts" "$(echo "$out" | head -1)" "$(echo "$out" | tail -n +2)"
    c=$(run_ctr --network shnet "$IMG" sh -c "$show_netns")
    if test "${c%% *}" != "${a%% *}"; then
        ok "a plain container has its own netns"
    else
        fail "a plain container has its own netns" "pooled: $a" "plain: $c"
    fi
    run_ctr $SHARE --network shnet -p 18098:80 "$IMG" true > /dev/null 2>&1
    check_match "shareable netns with ports refused" "[1-9]" "$?"
    sh_ network rm shnet > /dev/null
    check "network rm drains the pool" "0" "$(ls "$WORKDIR/run/velarx/netns-pool" 2> /dev/null | grep -c netns)"
}

@test "subnet_pools of the configuration" {
    # `[network] subnet_pools`: the subnets of new networks, and the compat
    # info.
    { cat "$CONF"; cat <<'EOT'
[[network.subnet_pools]]
base = "10.213.32.0/24"
size = 26
[[network.subnet_pools]]
base = "10.213.33.0/24"
size = 25
EOT
    } > "$WORKDIR/pools.toml"
    stop_daemon
    CONF=$WORKDIR/pools.toml start_daemon pools
    sh_ network create poolnet1 > /dev/null
    sh_ network create poolnet2 > /dev/null
    out=$(for n in poolnet1 poolnet2; do sh_ network inspect $n | grep -o '"subnet": *"[0-9./]*"' | tr -d ' "'; done | tr '\n' ' ')
    check "subnets from the configuration's pools" "subnet:10.213.32.0/26 subnet:10.213.32.64/26 " "$out"
    # (the compat info is velarx-api's, in front of the engine of $SOCK)
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --idle-exit 0 \
        --listen "unix://$WORKDIR/compat.sock" > "$WORKDIR/api-pools.log" 2>&1 3>&- &
    local api=$!
    e2e_wait_path "$WORKDIR/compat.sock" 10
    out=$(curl -s --max-time 30 --unix-socket "$WORKDIR/compat.sock" http://d/v1.41/info | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["DefaultAddressPools"])')
    kill "$api" 2> /dev/null
    wait "$api" 2> /dev/null
    check "compat info: the pools" "[{'Base': '10.213.32.0/24', 'Size': 26}, {'Base': '10.213.33.0/24', 'Size': 25}]" "$out"
    sh_ network rm poolnet1 poolnet2 > /dev/null
    stop_daemon
    start_daemon net
}

@test "concurrent runs" {
    # Concurrent runs: no address or name collision, nothing left.
    N=${E2E_CONCURRENT:-50}
    sh_ network create --subnet 10.213.12.0/24 concnet > /dev/null
    pids=
    for i in $(seq "$N"); do
        run_ctr --name "c$i" --network concnet "$IMG" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}"' > "$WORKDIR/conc.$i" 2>&1 3>&- &
        pids="$pids $!"
    done
    # Not a plain `wait`: the daemon is a job too.
    wait $pids
    out=$(cat "$WORKDIR"/conc.* | grep -c '^10\.213\.12\.')
    check "$N concurrent runs got an address" "$N" "$out"
    out=$(cat "$WORKDIR"/conc.* | grep '^10\.213\.12\.' | sort | uniq -d)
    check "$N concurrent runs: distinct addresses" "" "$out"
    rm -f "$WORKDIR"/conc.*
    sh_ network rm concnet > /dev/null
    check "network rm after concurrent runs" 0 $?
}

# (checkpoint and restore: root and CRIU)
skip_unless_criu () {
    command -v criu > /dev/null || skip "no criu"
}

# cr_state NAME: the state of the container
cr_state () {
    sh_ container inspect "$1" 2> /dev/null |
        python3 -I -c 'import json, sys; print(json.load(sys.stdin)["state"])' 2> /dev/null
}

# cr_server NAME [RUN-OPTIONS...]: a container that counts in /tmp/n and
# answers the number to whoever connects to its port 80
cr_server () {
    local name=$1
    shift
    sh_ container run -d --name "$name" "$@" "$IMG" sh -c \
        'i=0; nc -lk -p 80 -e cat /tmp/n & while :; do echo $i > /tmp/n.tmp; mv /tmp/n.tmp /tmp/n; i=$((i+1)); sleep 0.1; done' > /dev/null
    sh_ container exec "$name" timeout 30 sh -c 'until test -s /tmp/n; do :; done' 3>&- && return 0
    echo "FAIL the server $name did not start" >&2
    exit 1
}

# cr_ip NAME: the address of the container on its first network
cr_ip () {
    sh_ container exec "$1" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}" | cut -d/ -f1'
}

# cr_count NAME: the number the container serves, through its address
cr_count () {
    nse python3 -I -c '
import socket, sys
s = socket.create_connection((sys.argv[1], 80), timeout=3)
s.settimeout(3)
sys.stdout.write(s.recv(100).decode().strip())
' "$(cr_ip "$1")" 2>&1
}

# cr_counts_on NAME BEFORE: the container serves a number past BEFORE
cr_counts_on () {
    # (the counter is read in the container: the exec returns once it is past)
    sh_ container exec "$1" timeout 30 sh -c "until [ \"\$(cat /tmp/n)\" -gt $2 ]; do :; done" 3>&- && return 0
    echo "FAIL $1 does not count on from $2 (got '$(cr_count "$1")')" >&2
    exit 1
}

# cr_veths: the number of veth interfaces of the host
cr_veths () {
    ip -o link show | awk -F': ' '$2 ~ /^veth/ { print $2 }' | wc -l
}
# cr_veths_settled N: the number, once it is N or 10 s passed (polled: the
# kernel takes down the veth of a namespace that went on its own time)
cr_veths_settled () {
    local deadline=$(( $(date +%s) + 10 )) n
    until n=$(cr_veths); [ "$n" = "$1" ] || [ "$(date +%s)" -ge "$deadline" ]; do sleep 0.05; done
    echo "$n"
}

@test "checkpoint and restore on the default bridge network: the counter and the listening socket go on" {
    skip_unless_criu
    cr_server cpb -p 18110:80
    before=$(cr_count cpb)
    ip_before=$(cr_ip cpb)
    sh_ container checkpoint cpb > /dev/null
    check "checkpoint" 0 $?
    check "the veth of the stopped container is gone" 0 "$(cr_veths_settled 0)"
    out=$(sh_ container restore cpb 2>&1)
    check "restore" cpb "$out"
    check "the address is the one of the container" "$ip_before" "$(cr_ip cpb)"
    check_match "eth0 is on the bridge of the default network" "^1$" "$(cr_veths_settled 1)"
    cr_counts_on cpb "$before"
    n=$(fetch 18110)
    test "$n" -gt "$before"
    check "the published port reaches the restored listening socket ($before, then $n)" 0 $?
    out=$(nse python3 -I -c 'import socket; s = socket.socket(); s.bind(("0.0.0.0", 18110)); print("bound")' 2>&1 | tail -1)
    check_match "and it is held again" "Address already in use" "$out"
    out=$(sh_ container exec cpb sh -c 'echo | nc -w 2 10.213.0.1 18110 2>&1; ip route | grep default')
    check_match "the route out is the gateway of the network" "default via 10.213.0.1" "$out"
    # the restored container stops, starts and leaves nothing behind
    sh_ container stop -t 1 cpb > /dev/null
    check "stop of the restored container" exited "$(cr_state cpb)"
    check "its veth is gone" 0 "$(cr_veths_settled 0)"
    sh_ container start cpb > /dev/null
    check "and it starts again from the beginning" running "$(cr_state cpb)"
    check "with its own network namespace again" 1 "$(cr_veths_settled 1)"
    sh_ container rm -t 0 -f cpb > /dev/null
    check "removed: no veth" 0 "$(cr_veths_settled 0)"
}

@test "checkpoint and restore on a network of its own: static address, published port, --keep" {
    skip_unless_criu
    # (a network of the test: the earlier tests removed brnet)
    sh_ network create --subnet 10.213.40.0/24 cpnet > /dev/null
    cr_server cpn --network cpnet --ip 10.213.40.77 --mac-address 02:42:0a:d5:28:4d --network-alias cpweb -p 18111:80
    before=$(cr_count cpn)
    sh_ container checkpoint cpn > /dev/null
    check "checkpoint" 0 $?
    sh_ container restore --keep cpn > /dev/null
    check "restore --keep" 0 $?
    check "the static address" 10.213.40.77 "$(cr_ip cpn)"
    check "the static MAC address" 02:42:0a:d5:28:4d "$(sh_ container exec cpn cat /sys/class/net/eth0/address)"
    cr_counts_on cpn "$before"
    n=$(fetch 18111)
    test "$n" -gt "$before"
    check "the published port ($before, then $n)" 0 $?
    out=$(run_ctr --network cpnet "$IMG" sh -c 'echo | nc -w 2 cpweb 80')
    test "$out" -gt "$before"
    check "the name of the container is still resolved by the network ($out)" 0 $?
    sh_ network inspect cpnet | tr -d ' \n' | grep -q '"ipnet":"10.213.40.77/24"'
    check "the network knows the address" 0 $?
    # a second checkpoint of the restored container, from where it is
    sh_ container checkpoint cpn > /dev/null
    sh_ container restore cpn > /dev/null
    check "a second round" 10.213.40.77 "$(cr_ip cpn)"
    cr_counts_on cpn "$n"
    sh_ container rm -t 0 -f cpn > /dev/null
    sh_ network rm cpnet > /dev/null
    check "network rm after the restored container is removed" 0 $?
}

@test "checkpoint and restore of a container of a pod: the network of the pod stays" {
    skip_unless_criu
    sh_ pod create --name cpp -p 18113:80 > /dev/null
    cr_server cpm --pod cpp
    before=$(cr_count cpm)
    ip_before=$(cr_ip cpm)
    sh_ container checkpoint cpm > /dev/null
    check "checkpoint" 0 $?
    check "the pod keeps its interface" 1 "$(cr_veths_settled 1)"
    sh_ container restore cpm > /dev/null
    check "restore" 0 $?
    check "the address of the pod" "$ip_before" "$(cr_ip cpm)"
    cr_counts_on cpm "$before"
    n=$(fetch 18113)
    test "$n" -gt "$before"
    check "the port of the pod reaches it ($before, then $n)" 0 $?
    sh_ pod rm -t 0 -f cpp > /dev/null
    check "no veth is left" 0 "$(cr_veths_settled 0)"
}

@test "checkpoint --export and restore --import on a bridge network, --name, --ignore-static-ip" {
    skip_unless_criu
    cr_server cpx --ip 10.213.0.77 -p 18112:80
    before=$(cr_count cpx)
    sh_ container checkpoint --export "$WORKDIR/cpx.tar" --compress none cpx > /dev/null
    check "export" 0 $?
    check "the veth is released" 0 "$(cr_veths_settled 0)"
    # the container is still there with its address: the import takes
    # another, or the same when it is not the original's
    sh_ container restore --import "$WORKDIR/cpx.tar" --name cpy --ignore-static-ip > /dev/null 2>&1
    check "an import beside the original with --ignore-static-ip" 0 $?
    test "$(cr_ip cpy)" != 10.213.0.77
    check "it has another address ($(cr_ip cpy))" 0 $?
    cr_counts_on cpy "$before"
    sh_ container rm -t 0 -f cpy > /dev/null
    sh_ container rm -t 0 -f cpx > /dev/null
    check "no veth is left" 0 "$(cr_veths_settled 0)"
    sh_ container restore --import "$WORKDIR/cpx.tar" --name cpz > /dev/null
    check "the import of the archive once the original is gone" 0 $?
    check "with the static address of the archive" 10.213.0.77 "$(cr_ip cpz)"
    cr_counts_on cpz "$before"
    n=$(fetch 18112)
    test "$n" -gt "$before"
    check "and its published port ($before, then $n)" 0 $?
    sh_ container rm -t 0 -f cpz > /dev/null
    check "no veth is left" 0 "$(cr_veths_settled 0)"
}

@test "remove the containers and prune the networks" {
    sh_ container rm -t 0 -f b1 b2 > /dev/null 2>&1
    sh_ network prune -f > /dev/null
}

@test "nothing is left behind but the default network" {
    stop_daemon
    out=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | grep -v '^shbr0$')
    check "no link left" "" "$out"
    out=$(nft list table ip velarx 2> /dev/null | grep -E '10\.213\.|br-|: jump' | grep -v -e shbr0 -e '10.213.0.0/24' -e '{ 10.213.0.1 }')
    check "no firewall element left" "" "$out"
    # (a bridge and the table live until their network goes: the last
    # container leaving removes neither, and no port of it stays)
    check "the default bridge stays" 0 "$(ip link show shbr0 > /dev/null 2>&1; echo $?)"
    check "without a port" "" "$(ip -o link show master shbr0)"
    check "and the table" 0 "$(nft list table ip velarx > /dev/null 2>&1; echo $?)"
    out=$(ls "$WORKDIR/run/velarx/networks/dns" 2> /dev/null | grep -v -e server.lock -e control.sock -e server.log)
    check "no DNS record left" "" "$out"
    out=$(ls "$WORKDIR/run/velarx/netns" 2> /dev/null)
    check "no pinned namespace left" "" "$out"
}
