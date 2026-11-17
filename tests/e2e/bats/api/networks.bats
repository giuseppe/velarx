# SPDX-License-Identifier: Apache-2.0
# Networks through the podman API and the CLI.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

@test "network create, inspect, ls, update" {
    skip_unless_bridges
    pm network create --subnet 10.151.0.0/24 apinet > /dev/null
    check "network create" 0 $?
    out=$(pm network inspect apinet --format '{{range .Subnets}}{{.Subnet}}{{end}}')
    check "network inspect" "10.151.0.0/24" "$out"
    out=$(pm network ls --format '{{.Name}}' | grep -c '^apinet$')
    check "network ls" 1 "$out"
    # (podman 5.8.9's libpod route has no ignore: a missing network is a 404)
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/networks/nosuchnet?ignore=true")
    check "network rm ignore=true of a missing network" 404 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/networks/nosuchnet")
    check "network rm of a missing network" 404 "$code"
    out=$(api -o /dev/null -w '%{http_code}' -X POST -d '{"adddnsservers": ["10.0.0.53"]}' \
              http://d/v5.0.0/libpod/networks/apinet/update)
    check "network update" 204 "$out"
    out=$(api http://d/v5.0.0/libpod/networks/apinet | jq -r '.network_dns_servers[0]')
    check "network DNS servers" "10.0.0.53" "$out"
    api -o /dev/null -X POST -d '{"removednsservers": ["10.0.0.53"]}' http://d/v5.0.0/libpod/networks/apinet/update
    out=$(api http://d/v5.0.0/libpod/networks/apinet | jq -r '.network_dns_servers | length')
    check "network DNS servers removed" 0 "$out"
    out=$(api http://d/v1.41/networks/apinet | jq -r '.Name + " " + .Driver + " " + .IPAM.Config[0].Subnet')
    check "compat network inspect" "apinet bridge 10.151.0.0/24" "$out"
}

@test "containers on a network" {
    skip_unless_bridges
    # Rootless too: the bridges live in the rootless network namespace.
    pm run -d --name netsrv --network apinet "$IMG" nc -lk -p 80 -e echo from-netsrv > /dev/null
    out=$(pm run --rm --network apinet "$IMG" sh -c 'sleep 0.5; echo | nc -w 2 netsrv 80' 2>&1)
    check "containers on a network reach each other by name" from-netsrv "$out"
    out=$(api http://d/v1.41/containers/netsrv/json | jq -r '.NetworkSettings.Networks.apinet.IPAddress')
    check_match "the address in the Docker inspect" "^10\.151\.0\." "$out"
    pm rm -t 0 -f netsrv > /dev/null 2>&1
    # podman's 20-containers.at: no gateway shown on an internal network
    # without DNS, the IPv6 address of a dual-stack one.
    pm network create apinet6 --ipv6 --internal --disable-dns > /dev/null
    pm run --name apicon6 --network apinet6 -d "$IMG" top > /dev/null
    out=$(api http://d/v1.41/containers/apicon6/json | jq -r '.NetworkSettings.Networks.apinet6 |
                  [.Gateway, .IPAddress, .IPPrefixLen, .IPv6Gateway, .GlobalIPv6Address, .GlobalIPv6PrefixLen] | @tsv')
    check_match "an internal dual-stack network in the Docker inspect" \
        "$(printf '^\t10\\.[0-9.]*\t24\t\tfd[0-9a-f:]*\t64$')" "$out"
    pm rm -f -t0 apicon6 > /dev/null 2>&1
    pm network rm apinet6 > /dev/null
}

@test "network exists" {
    skip_unless_bridges
    pm network exists apinet
    check "network exists" 0 $?
}

@test "compat inspect: the containers of a network" {
    skip_unless_bridges
    # The compat inspect of a network: its containers, their addresses.
    pm network create --subnet 10.152.253.0/24 --gateway 10.152.253.1 apinet5 > /dev/null
    pm run --network apinet5 --name apimynet --ip 10.152.253.2 --mac-address 0a:01:73:78:43:18 -td "$IMG" top > /dev/null
    cid=$(pm inspect --format '{{.Id}}' apimynet)
    nid=$(pm network inspect --format '{{.ID}}' apinet5)
    out=$(api http://d/v1.41/networks/$nid | jq -r --arg c "$cid" '.Containers[$c] | [.Name, .MacAddress, .IPv4Address] | @tsv')
    check "compat inspect: the containers of a network" "$(printf 'apimynet\t0a:01:73:78:43:18\t10.152.253.2/24')" "$out"
    pm network rm -t 0 -f apinet5 > /dev/null
    pm rm -f -t0 apimynet > /dev/null 2>&1
}

@test "compat connect of a container" {
    skip_unless_bridges
    # Connect a container that is already connected: fine unless it runs.
    pm network create apinetcon > /dev/null
    pm create --network bridge --name apic1 "$IMG" top > /dev/null
    code () { api -o /dev/null -w '%{http_code}' -X POST -d '{"Container":"apic1"}' http://d/v1.41/networks/apinetcon/connect; }
    check "compat connect of a created container" 200 "$(code)"
    check "compat connect again" 200 "$(code)"
    pm start apic1 > /dev/null
    out=$(api -X POST -d '{"Container":"apic1"}' http://d/v1.41/networks/apinetcon/connect)
    check "compat connect of a running container already connected" "403 network is already connected" "$(code) $(echo "$out" | jq -r .cause)"
    pm stop -t0 apic1 > /dev/null
    check "compat connect of a stopped container" 200 "$(code)"
    # podman's answer: the text OK
    check "and its answer" OK "$(api -X POST -d '{"Container":"apic1"}' http://d/v1.41/networks/apinetcon/connect)"
    pm network rm -t 0 -f apinetcon > /dev/null
    pm rm -f -t0 apic1 > /dev/null 2>&1
}

@test "libpod list refuses external by name, takes sync" {
    out=$(api -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/containers/json?external=true")
    check "libpod list ?external=true is refused" 501 "$out"
    check_match "and names it" "the parameter \`external\` is not supported" "$(api "http://d/v5.0.0/libpod/containers/json?external=true")"
    check "?external=false is fine" 200 "$(api -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/containers/json?external=false")"
    # (podman's remote client sends it for the containers it acts on)
    check "?sync=true is taken" 200 "$(api -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/containers/json?all=true&sync=true")"
    pm ps --external > /dev/null 2>&1
    check "podman --remote ps --external is refused" 125 $?
}

@test "connect to a host network is refused by name" {
    api -o /dev/null -X POST -d '{"name":"apihost","driver":"host"}' http://d/v5.0.0/libpod/networks/create
    pm create --name apic2 "$IMG" true > /dev/null
    for p in v1.41/networks/apihost/connect:Container v5.0.0/libpod/networks/apihost/connect:container \
        v1.41/networks/apihost/disconnect:Container v5.0.0/libpod/networks/apihost/disconnect:Container; do
        out=$(api -X POST -d "{\"${p##*:}\":\"apic2\"}" "http://d/${p%:*}" | jq -r '"\(.response) \(.message)"')
        check_match "${p%:*} is refused" "^400 .*the network \`apihost\`: the host driver puts no interface in a container" "$out"
    done
    pm rm -f -t0 apic2 > /dev/null 2>&1
    pm network rm apihost > /dev/null
}

@test "network connectivity: a published port and container:" {
    local port=$((18300 + $$ % 500))
    pm run -d --name netpub -p "$port:80" "$IMG" nc -lk -p 80 -e echo from-api > /dev/null
    pm exec netpub timeout 30 sh -c 'until nc -z 127.0.0.1 80; do :; done'
    out=$(python3 -I -c '
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2)
s.settimeout(2)
print(s.recv(4096).decode().strip())
' "$port" 2> /dev/null)
    check "a port published through the API" from-api "$out"
    out=$(api http://d/v1.41/containers/netpub/json | jq -r '.NetworkSettings.Ports["80/tcp"][0].HostPort')
    check "the published port in the Docker inspect" "$port" "$out"
    out=$(pm run --rm --network container:netpub "$IMG" sh -c 'echo | nc -w 2 127.0.0.1 80' 2>&1)
    check "network container: through the API" from-api "$out"
    pm rm -t 0 -f netpub > /dev/null 2>&1
}

@test "network rm" {
    skip_unless_bridges
    pm network rm apinet > /dev/null
    check "network rm" 0 $?
    pm network exists apinet
    check "network rm removes" 1 $?
}

@test "network inspect of a missing network" {
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/networks/nope/json)
    check "network inspect of a missing network" 404 "$out"
    out=$(api http://d/v5.0.0/libpod/networks/nope/json | jq -r .cause)
    check "network not found cause" "network not found" "$out"
}

@test "IPv6 networks" {
    out=$(api -X POST -d '{"name":"v6","ipv6_enabled":true}' http://d/v5.0.0/libpod/networks/create |
              jq -r '[.ipv6_enabled, (.subnets | length), (.subnets[1].subnet | test("^fd[0-9a-f:]*::/64$"))] | @tsv')
    check "IPv6 networks are created" "$(printf 'true\t2\ttrue')" "$out"
    out=$(api http://d/v1.41/networks/v6 | jq -r '[.EnableIPv6, (.IPAM.Config | length)] | @tsv')
    check "compat inspect of an IPv6 network" "$(printf 'true\t2')" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v5.0.0/libpod/networks/v6)
    check "IPv6 network rm" 200 "$out"
}

@test "the Docker bridge name option" {
    api -o /dev/null -X POST -d '{"Name":"dkbr","Options":{"com.docker.network.bridge.name":"shdk0"}}' http://d/v1.41/networks/create
    out=$(api http://d/v5.0.0/libpod/networks/dkbr/json | jq -r .network_interface)
    check "the Docker bridge name option" shdk0 "$out"
    api -o /dev/null -X DELETE http://d/v1.41/networks/dkbr
}

@test "internal networks" {
    out=$(api -X POST -d '{"name":"internal","internal":true}' http://d/v5.0.0/libpod/networks/create | jq -r .internal)
    check "internal networks are created" true "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v5.0.0/libpod/networks/internal)
    check "internal network rm" 200 "$out"
}

@test "the default network" {
    out=$(pm network ls --format '{{.Name}}' | wc -l)
    check_match "the default network is listed" "^[1-9]" "$out"
    out=$(api http://d/v5.0.0/libpod/networks/podman/json | jq -r '.name + " " + .id')
    check "the default network is podman's" "podman 2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9" "$out"
    out=$(api http://d/v1.41/networks | jq -r '[.[].Name] | map(select(test("bridge"))) | length')
    check "compat list: the default network is bridge" 1 "$out"
    out=$(api http://d/v1.41/networks/bridge | jq -r .Name)
    check "compat inspect of bridge" bridge "$out"
    out=$(api http://d/v1.41/networks/podman | jq -r .Name)
    check "compat inspect of podman" podman "$out"
}

@test "macvlan networks" {
    out=$(api -X POST -d '{"name":"apimacvlan","driver":"macvlan","subnets":[{"subnet":"10.152.135.0/24"}]}' http://d/v5.0.0/libpod/networks/create | jq -r '.name + " " + .driver')
    check "a macvlan network" "apimacvlan macvlan" "$out"
    out=$(api http://d/v1.41/networks/apimacvlan | jq -r '.Name + " " + .Driver')
    check "compat inspect of a macvlan network" "apimacvlan macvlan" "$out"
    out=$(api -X DELETE http://d/v5.0.0/libpod/networks/apimacvlan | jq -r '.[0].Name')
    check "macvlan network rm" apimacvlan "$out"
}

@test "compat network list and rm of a missing network" {
    out=$(api http://d/v1.41/networks | jq -r '.[0].Driver')
    check "compat network list" "bridge" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v5.0.0/libpod/networks/nope)
    check "network rm of a missing network" 404 "$out"
}

# a record of the database that cannot be read is an error of the list, not
# a network that is left out
@test "network ls: a network record that cannot be read is an error" {
    db=$XDG_DATA_HOME/velarx/db.sqlite
    sqlite3 "$db" ".timeout 5000" "INSERT INTO networks (id, name, driver, options, created_at) VALUES ('0badbad0badbad0badbad0badbad0badbad0badbad0badbad0badbad0badbad00', 'brokennet', 'bridge', '{not json', '2026-01-01T00:00:00Z')"
    code=$(api -o "$WORKDIR/netls.out" -w '%{http_code}' http://d/v5.0.0/libpod/networks/json)
    sqlite3 "$db" ".timeout 5000" "DELETE FROM networks WHERE name = 'brokennet'"
    check "the list is an error" 500 "$code"
    check_match "and it names the network" "brokennet.*unreadable options" "$(cat "$WORKDIR/netls.out")"
    code=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/networks/json)
    check "the list is back without the record" 200 "$code"
}
