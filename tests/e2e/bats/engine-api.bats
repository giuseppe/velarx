# SPDX-License-Identifier: Apache-2.0
# The REST API as a frontend of the engine (velarx-api and the engine
# service, org.velarx.Engine):
#
# * started by hand, with no service manager: velarx-api starts the engine
#   with the socket it binds, the engine stops with it;
# * started by the socket units: a request to the API socket starts
#   velarx-api, whose first call connects to the engine's socket and starts
#   the engine; both leave when idle and the next request starts them again;
# * the frontend is confined (no new privileges, seccomp, no capability);
# * with a registry at E2E_REGISTRY (default localhost:5000; E2E_IMAGE, default
#   $E2E_REGISTRY/alpine:chunked): the limits of the frontend (the size of a
#   pod spec, of the labels, of an exec request), a client that leaves an
#   idle attach.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/engine-api.bats
#                                              # user units (rootless), or as
#                                              # root the system units
#
# The activation test links copies of velarx-engine.* and velarx-api.*,
# renamed shi-<pid>-*, with the paths of $WORKDIR, into the runtime unit
# directory; they are stopped and unlinked at the end.
# E2E_NO_UNITS=1 skips the activation test (it links units into the service
# manager of the machine; as root run the rest in a private mount namespace).
# Skipped without velarx-api or curl.

load helpers

setup_file () {
    command -v curl > /dev/null || skip "no curl"
    e2e_setup_file
    e2e_need_api
    export IMG=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export U=shi-$$
    chmod 700 "$XDG_RUNTIME_DIR"
    local run=$XDG_RUNTIME_DIR/velarx
    cat > "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[server]
socket = "$run/velarx.sock"
state_dir = "$run"
root_dir = "$XDG_DATA_HOME/velarx"
[storage]
root = "$XDG_DATA_HOME/velarx"
[userns]
uid_ranges = ["655360-720895"]
gid_ranges = ["655360-720895"]
allocation_size = 65536
[engine]
idle_exit = 2
[api]
idle_exit = 2
TOML
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<TOML
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
TOML
    # (root of the host does not look in $XDG_CONFIG_HOME)
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf
}

# the containers (their monitors outlive the servers), the servers and the
# engine of this file, the units, the work directory
teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local c p i
    kill $(cat "$WORKDIR/pids" 2> /dev/null) 2> /dev/null
    for c in $(timeout 30 "$SH" container list -a 2> /dev/null | awk 'NR > 1 { print $1 }'); do
        timeout 30 "$SH" container rm -t 0 -f "$c" > /dev/null 2>&1
    done
    procs=$(e2e_store_processes "$WORKDIR" | awk '{ print $1 }')
    for p in $procs; do
        kill "$p" 2> /dev/null
    done
    if [ -e "$WORKDIR/units-linked" ]; then
        units_env
        "${SCTL[@]}" stop $UNITS 2> /dev/null
        "${SCTL[@]}" disable --runtime $UNITS > /dev/null 2>&1
        "${SCTL[@]}" reset-failed $UNITS 2> /dev/null
        "${SCTL[@]}" daemon-reload
    fi
    for p in $procs; do
        e2e_wait_exit "$p" 5
    done
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do
        kill -KILL "$p" 2> /dev/null
    done
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

# what the sections share: the paths of the work directory
setup () {
    set +e
    top_srcdir=$(cd "$E2E_DIR/../.." && pwd)
    RUN=$XDG_RUNTIME_DIR/velarx
    CONF=$XDG_CONFIG_HOME/velarx/config.toml
    API=$RUN/velarx.sock
    ENGINE_SOCK=$RUN/engine/engine.sock
    HC=$E2E_DIR/hijack_client.py
    S="$BIN/velarx --config $CONF"
    units_env
}

# the service manager of the machine: the system one as root, else the user's
units_env () {
    UNITS="$U-engine.socket $U-engine.service $U-api.socket $U-api.service"
    if [ "$(id -u)" = 0 ]; then
        MODE=system
        SCTL=(systemctl)
    else
        MODE=user
        REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR_REAL:-/run/user/$(id -u)}
        SCTL=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemctl --user)
    fi
}

units_gate () {
    if [ -n "${E2E_NO_UNITS:-}" ]; then
        skip "E2E_NO_UNITS: the activation test is skipped"
    fi
    if ! "${SCTL[@]}" is-system-running > /dev/null 2>&1 && [ "$("${SCTL[@]}" is-system-running 2>&1)" != degraded ]; then
        skip "no service manager: the activation test is skipped"
    fi
}

# the frontends a section starts by hand: gone at the end of it, also when it
# fails
track () { echo "$@" >> "$WORKDIR/frontends"; }

# the containers and volumes a section makes are removed at its end, also when
# a check fails (ct_later NAME..., vol_later NAME...)
ct_later () { echo "$@" >> "$WORKDIR/ctrs"; }
vol_later () { echo "$@" >> "$WORKDIR/vols"; }

teardown () {
    local p
    for p in $(cat "$WORKDIR/frontends" 2> /dev/null); do
        kill -9 "$p" 2> /dev/null
    done
    : > "$WORKDIR/frontends"
    if [ -s "$WORKDIR/ctrs" ]; then
        "$BIN/velarx" --config "$CONF" container rm -f -t 0 $(cat "$WORKDIR/ctrs") > /dev/null 2>&1
        : > "$WORKDIR/ctrs"
    fi
    if [ -s "$WORKDIR/vols" ]; then
        "$BIN/velarx" --config "$CONF" volume rm $(cat "$WORKDIR/vols") > /dev/null 2>&1
        : > "$WORKDIR/vols"
    fi
}

# the tests with a store need the frontend the test before them started
need_servers () {
    [ -S "$API" ] && return 0
    echo "velarx-api is not up (see the test 'velarx-api and a store')" >&2
    exit 1
}

get () { curl -s --max-time 60 --unix-socket "$API" "$@"; }

engine_pid () { # the engine a frontend of this file started: a descendant of a
    # pid the test started, whose command line has the word varlink (its name
    # changes when it joins its namespaces); never a process found by name
    local level=$(cat "$WORKDIR/frontends" "$WORKDIR/pids" 2> /dev/null) next p
    level="$level $PIDS"
    for _ in 1 2 3; do
        next=
        for p in $level; do
            for p in $(pgrep -P "$p"); do
                if tr '\0' '\n' < "/proc/$p/cmdline" 2> /dev/null | grep -qx varlink; then
                    echo "$p"
                    return
                fi
                next="$next $p"
            done
        done
        level=$next
    done
}

active () { "${SCTL[@]}" show -P ActiveState "$1"; }

# (the answers without their date, whose length may differ)

answer () { # socket method path [body]
    local x="-X $2"
    [ "$2" = HEAD ] && x=-I
    if [ $# -gt 3 ]; then
        curl -g -s -i $x --unix-socket "$1" -H 'Content-Type: application/json' --data-binary "$4" "http://x$3" | grep -a -v -i -E '^(date):' | sed 's/\r$//'
    else
        curl -g -s -i $x --unix-socket "$1" "http://x$3" | grep -a -v -i -E '^(date):' | sed 's/\r$//'
    fi
}

@test "by hand: no service manager" {
    # 1. By hand: no service manager
    "$BIN/velarx-api" --config "$CONF" --idle-exit 0 > "$WORKDIR/api.log" 2>&1 3>&- &
    PIDS=$!
    track $PIDS
    e2e_wait_path "$API"
    check "by hand: the API answers a ping (and starts the engine)" OK "$(get http://x/_ping)"
    check "by hand: images" "[]" "$(get http://x/libpod/images/json)"
    check "by hand: containers" "[]" "$(get "http://x/v1.41/containers/json?all=1")"
    check "by hand: head" "200" "$(curl -s -I -o /dev/null -w '%{http_code}' --unix-socket "$API" http://x/_ping)"
    check "by hand: no route" "404" "$(get -o /dev/null -w '%{http_code}' http://x/nothing)"
    check "by hand: a bad filter is podman's error" "500" \
        "$(get -o /dev/null -w '%{http_code}' 'http://x/libpod/images/json?filters=%7B%22nonsense%22%3A%5B%22x%22%5D%7D')"
    # (every thread: those of its runtime are made after the confinement)
    tasks () { sed -n "s/^$1:\t//p" /proc/"$PIDS"/task/*/status | sort -u; }
    check "the frontend: no new privileges" 1 "$(tasks NoNewPrivs)"
    check "the frontend: a seccomp filter" 2 "$(tasks Seccomp)"
    check "the frontend: no capability" 0000000000000000 "$(tasks CapEff)"
    check "the frontend: the engine's socket is there" yes "$([ -S "$ENGINE_SOCK" ] && echo yes)"
    # the engine stops with the frontend, also when the frontend is killed
    ENGINE_PID=$(engine_pid)
    check_match "the engine of the frontend" "^[0-9]+$" "$ENGINE_PID"
    kill -9 "$PIDS"
    PIDS=
    e2e_wait_exit "$ENGINE_PID"
    check "the engine stops with the frontend that started it" gone "$(e2e_alive "$ENGINE_PID")"
    rm -f "$API" "$ENGINE_SOCK"
}

@test "a socket that is not the user's is not served, a TCP address that is not loopback needs a token" {
    # 2. A socket that is not the user's is not served; TCP asks for a token
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --listen tcp://0.0.0.0:0 > "$WORKDIR/tcp.log" 2>&1
    check "a TCP address that is not loopback has no token: refused" 1 $?
    check "...and the error says what to set" yes "$(grep -q 'token_file' "$WORKDIR/tcp.log" && echo yes)"
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --listen tcp://:0 --tls-cert /x > "$WORKDIR/tcp.log" 2>&1
    check "a TLS certificate without its key is refused" "1 yes" "$? $(grep -q 'both the certificate and the key' "$WORKDIR/tcp.log" && echo yes)"
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --listen tcp://:0 > "$WORKDIR/tcp.log" 2>&1
    check "TCP with no token and no explicit choice is refused" 1 $?
    check "...and the error says what to set" yes "$(grep -q 'token_file' "$WORKDIR/tcp.log" && echo yes)"
    (umask 077 && echo 0123456789abcdefghijklmnopqrstuv > "$WORKDIR/api-token")
    sed "s|^\[api\]|[api]\ntoken_file = \"$WORKDIR/api-token\"|" "$CONF" > "$WORKDIR/api-tcp.toml"
    "$BIN/velarx-api" --config "$WORKDIR/api-tcp.toml" --listen tcp://:0 --listen unix://$WORKDIR/tcp.sock --idle-exit 0 > "$WORKDIR/tcp.log" 2>&1 3>&- &
    PIDS=$!
    track $PIDS
    e2e_wait_path "$WORKDIR/tcp.sock"
    check "TCP on loopback and a unix socket are served" yes "$([ -S "$WORKDIR/tcp.sock" ] && echo yes)"
    kill "$PIDS" 2> /dev/null
    e2e_wait_exit "$PIDS"
    PIDS=
    rm -f "$ENGINE_SOCK" "$WORKDIR/tcp.sock"
    # (a free port: velarx-api is not dumpable, ss cannot tell its sockets)
    local port
    port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("0.0.0.0", 0)); print(s.getsockname()[1])')
    "$BIN/velarx-api" --config "$WORKDIR/api-tcp.toml" --no-start-engine --listen "tcp://0.0.0.0:$port" --listen unix://$WORKDIR/tcp.sock --idle-exit 0 > "$WORKDIR/tcp.log" 2>&1 3>&- &
    PIDS=$!
    track $PIDS
    e2e_wait_path "$WORKDIR/tcp.sock"
    # (IPv4 only: another process may hold the port number on [::])
    check "an address that is not loopback is bound" "0.0.0.0:$port" "$(ss -4Htln "sport = :$port" | awk '{ print $4 }')"
    check "...and served, with the token" yes "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer 0123456789abcdefghijklmnopqrstuv' "http://127.0.0.1:$port/_ping" | grep -qv 401 && echo yes)"
    check "...not without it" 401 "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/_ping")"
    check "...and the warning is podman's" yes "$(grep -q 'Using the velarx API service with TCP sockets without TLS is not recommended' "$WORKDIR/tcp.log" && echo yes)"
    kill "$PIDS" 2> /dev/null
    e2e_wait_exit "$PIDS"
    PIDS=
}

@test "TLS and client certificates on the TCP listener, with curl and the podman client" {
    command -v openssl > /dev/null || skip "no openssl"
    local d=$WORKDIR/tls port n
    mkdir -p "$d"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$d/ca.key" -out "$d/ca.crt" -subj /CN=ca -days 2 2> /dev/null
    for n in server:serverAuth client:clientAuth; do
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$d/${n%%:*}.key" -out "$d/${n%%:*}.csr" -subj "/CN=${n%%:*}" 2> /dev/null
        printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=%s\n' "${n##*:}" > "$d/${n%%:*}.ext"
        openssl x509 -req -in "$d/${n%%:*}.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial -out "$d/${n%%:*}.crt" -days 2 -extfile "$d/${n%%:*}.ext" 2> /dev/null
    done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$d/other.key" -out "$d/other.crt" -subj /CN=other -days 2 2> /dev/null
    port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    rm -f "$API" "$ENGINE_SOCK"
    # (no token: the client certificate is what authenticates)
    "$BIN/velarx-api" --config "$CONF" --listen "tcp://127.0.0.1:$port" --listen unix://$WORKDIR/tls.sock --idle-exit 0 \
        --tls-cert "$d/server.crt" --tls-key "$d/server.key" --tls-client-ca "$d/ca.crt" > "$WORKDIR/tls.log" 2>&1 3>&- &
    PIDS=$!
    track $PIDS
    e2e_wait_path "$WORKDIR/tls.sock"
    check "no warning about TCP without TLS" "" "$(grep 'without TLS' "$WORKDIR/tls.log")"
    check "a client with a certificate of the CA is served" 200 "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$d/ca.crt" --cert "$d/client.crt" --key "$d/client.key" "https://localhost:$port/_ping")"
    check "a client with no certificate is refused" 000 "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$d/ca.crt" "https://localhost:$port/_ping")"
    check "a certificate of another CA is refused" 000 "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$d/ca.crt" --cert "$d/other.crt" --key "$d/other.key" "https://localhost:$port/_ping")"
    check "TLS 1.2 is refused" 000 "$(curl -s -o /dev/null -w '%{http_code}' --tls-max 1.2 --cacert "$d/ca.crt" --cert "$d/client.crt" --key "$d/client.key" "https://localhost:$port/_ping")"
    check "plain HTTP is refused" 000 "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$port/_ping")"
    if [ -z "${NO_PODMAN:-}" ] && command -v podman > /dev/null; then
        podman --remote --url "tcp://localhost:$port" --tls-ca "$d/ca.crt" --tls-cert "$d/client.crt" --tls-key "$d/client.key" ps > /dev/null 2>&1
        check "the podman client with --tls-ca --tls-cert --tls-key" 0 $?
        podman --remote --url "tcp://localhost:$port" --tls-ca "$d/ca.crt" ps > /dev/null 2>&1
        check "...and not without its certificate" 125 $?
    fi
    kill "$PIDS" 2> /dev/null
    e2e_wait_exit "$PIDS"
    PIDS=
    "$BIN/velarx-api" --config "$CONF" --no-start-engine --listen tcp://127.0.0.1:0 --tls-cert "$d/server.crt" --tls-key "$d/server.key" > "$WORKDIR/tls.log" 2>&1
    check "TLS alone is no authentication: refused" "1 yes" "$? $(grep -q 'tls_client_ca' "$WORKDIR/tls.log" && echo yes)"
}

@test "velarx varlink and velarx-api started together, in either order" {
    # the instant start of the quick start: one engine serves, both processes
    # stay up and say nothing
    local order first second pids p i
    for order in "varlink api" "api varlink"; do
        rm -f "$API" "$ENGINE_SOCK"
        pids=
        for first in $order; do
            if [ "$first" = varlink ]; then
                "$BIN/velarx" --config "$CONF" varlink --time 0 > "$WORKDIR/together-varlink.log" 2>&1 3>&- &
            else
                "$BIN/velarx-api" --config "$CONF" --idle-exit 0 > "$WORKDIR/together-api.log" 2>&1 3>&- &
            fi
            pids="$pids $!"
            track $!
        done
        e2e_wait_path "$API"
        e2e_wait_path "$ENGINE_SOCK"
        check "$order: the API answers" OK "$(get http://x/_ping)"
        check "$order: the engine answers" "[]" "$(get http://x/libpod/images/json)"
        # (a window: none of them may have left by now)
        sleep 1
        for p in $pids; do
            check "$order: process $p is up" yes "$(kill -0 "$p" 2> /dev/null && echo yes)"
        done
        if command -v ss > /dev/null; then
            check "$order: one process serves the engine's socket" 1 \
                "$(ss -H -xlpn "src $ENGINE_SOCK" | grep -o 'pid=[0-9]*' | sort -u | wc -l)"
        fi
        check "$order: neither says anything" "" "$(cat "$WORKDIR/together-varlink.log" "$WORKDIR/together-api.log")"
        # the engine goes with the last that holds it
        for p in $pids; do kill -INT "$p" 2> /dev/null; done
        for p in $pids; do e2e_wait_exit "$p" || e2e_die "$order: process $p did not end within 30 s"; done
        for p in $pids; do
            check "$order: process $p ended" gone "$(e2e_alive "$p")"
        done
        # (the engine removes its socket when it ends)
        e2e_wait_gone "$ENGINE_SOCK"
        check "$order: the engine ended with them" no "$([ -S "$ENGINE_SOCK" ] && echo yes || echo no)"
        rm -f "$API"
    done
}

@test "a second frontend holds the engine the first one started" {
    # 2b. A second frontend with no service manager holds the engine the first
    # one started: the engine does not go with the first
    rm -f "$API" "$ENGINE_SOCK"
    "$BIN/velarx-api" --config "$CONF" --idle-exit 0 --listen "unix://$WORKDIR/a.sock" > "$WORKDIR/a.log" 2>&1 3>&- &
    FIRST=$!
    PIDS=$FIRST
    track $FIRST
    e2e_wait_path "$WORKDIR/a.sock"
    "$BIN/velarx-api" --config "$CONF" --idle-exit 0 --listen "unix://$WORKDIR/b.sock" > "$WORKDIR/b.log" 2>&1 3>&- &
    SECOND=$!
    PIDS="$FIRST $SECOND"
    track $SECOND
    e2e_wait_path "$WORKDIR/b.sock"
    ENGINE_PID=$(engine_pid)
    check_match "two frontends: the engine" "^[0-9]+$" "$ENGINE_PID"
    check "two frontends: the second answers" OK "$(curl -s --max-time 60 --unix-socket "$WORKDIR/b.sock" http://x/_ping)"
    # a restart of the engine (SIGHUP) keeps the hold of the second frontend
    kill -HUP "$ENGINE_PID"
    # (it says so before it executes itself, on the output of the frontend
    # that started it: the socket stays open, the request waits for the next engine)
    e2e_wait_line "$WORKDIR/a.log" '^Restarting' 30 || e2e_die "the engine did not restart within 30 s"
    check "...and after a restart of the engine" OK "$(curl -s --max-time 60 --unix-socket "$WORKDIR/b.sock" http://x/_ping)"
    kill -9 "$FIRST"
    wait "$FIRST" 2> /dev/null
    # (a window: the engine must not leave now that the first frontend is gone)
    sleep 1
    check "...and still does when the first is gone" OK "$(curl -s --max-time 60 --unix-socket "$WORKDIR/b.sock" http://x/_ping)"
    check "...the engine of the first is still there" alive "$(e2e_alive "$ENGINE_PID")"
    kill -9 "$SECOND"
    wait "$SECOND" 2> /dev/null
    e2e_wait_exit "$ENGINE_PID"
    check "...and it goes with the last" gone "$(e2e_alive "$ENGINE_PID")"
    PIDS=
    rm -f "$API" "$ENGINE_SOCK" "$WORKDIR/a.sock" "$WORKDIR/b.sock"
}

# 3. A store: the limits of the frontend

@test "the image for the tests with a store is pulled" {
    e2e_registry_up || skip "no registry on $E2E_REGISTRY: the tests with a store are skipped"
    "$BIN/velarx" --config "$CONF" pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"
    : > "$WORKDIR/pulled"
}

@test "velarx-api and a store" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    for i in 1 2 3; do
        "$BIN/velarx" --config "$CONF" container create --name c$i --label k=v$((i % 2)) "$IMG" sleep 1 > /dev/null
    done
    "$BIN/velarx-api" --config "$CONF" --idle-exit 0 > "$WORKDIR/api.log" 2>&1 3>&- &
    PIDS=$!
    echo "$PIDS" > "$WORKDIR/pids"
    e2e_wait_path "$API"
    need_servers
}

@test "a pod spec over 1 MiB is refused" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # (a spec over 1 MiB is refused with the words of a body over the limit)
    printf '{"name":"e2e-pod-huge","labels":{"k":"%s"}}' "$(head -c 1100000 /dev/zero | tr '\0' x)" > "$WORKDIR/pod-huge.json"
    check "a pod spec over 1 MiB is refused" '400 "read the request body: length limit exceeded"' \
        "$(curl -s --unix-socket "$API" -o "$WORKDIR/huge.out" -w '%{http_code}' --data-binary "@$WORKDIR/pod-huge.json" http://x/libpod/pods/create) $(grep -o '"message":"[^"]*"' "$WORKDIR/huge.out" | cut -d: -f2-)"
}

@test "40 kB of labels: velarx-api answers 413" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # (the arguments of a call to the engine are at most 32 kB of JSON: more
    # labels than that are a 413)
    printf '{"Name":"e2e-vol-big","Label":{"k":"%s"}}' "$(head -c 40000 /dev/zero | tr '\0' x)" > "$WORKDIR/vol-big.json"
    check "40 kB of labels are a 413" "413" \
        "$(curl -s --unix-socket "$API" -o "$WORKDIR/vol-big.out" -w '%{http_code}' --data-binary "@$WORKDIR/vol-big.json" http://x/libpod/volumes/create)"
    check "...and says why" yes "$(grep -q 'are larger than 32768 bytes' "$WORKDIR/vol-big.out" && echo yes)"
}

@test "podman remote attach" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # podman's own client: the input of `run -i` reaches the container and its
    # end ends it (it hangs if the server keeps the input open)
    if command -v podman > /dev/null; then
        ct_later hx-pr
        $S container run -d -i --name hx-pr "$IMG" cat > /dev/null 2>&1
        check "podman --remote: echo hi | run -i cat ends with hi" hi \
            "$(echo hi | timeout 20 podman --url "unix://$API" attach hx-pr 2>&1 | tail -3)"
    fi
}

@test "a passthrough container has no logs and no attach, in podman's words" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    ct_later hx-pt
    # (the command line runs it: the engine service cannot write to its
    # caller's output)
    "$BIN/velarx" --config "$CONF" container run -d --name hx-pt --log-driver passthrough "$IMG" sleep 300 > /dev/null 2>&1
    for p in /libpod/containers/hx-pt/logs?stdout=true /v1.44/containers/hx-pt/logs?stdout=true; do
        check "GET $p: podman's answer" \
            '500 {"cause":"this container is not logging output","message":"failed to obtain logs for Container '"'hx-pt'"': this container is using the '"'passthrough'"' log driver, cannot read logs: this container is not logging output","response":500}' \
            "$(curl -s --unix-socket "$API" -w '%{http_code} ' -o "$WORKDIR/pt.out" "http://x$p")$(cat "$WORKDIR/pt.out")"
    done
    check "an attach: 500 and why" "500 yes" \
        "$(curl -s --max-time 5 --unix-socket "$API" -X POST -w '%{http_code}' -o "$WORKDIR/pt.out" "http://x/v1.44/containers/hx-pt/attach?stream=1&stdout=1") $(grep -q "using the 'passthrough' log driver, cannot attach" "$WORKDIR/pt.out" && echo yes)"
}

@test "abandoned idle attaches leave no descriptor" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # a client that leaves an idle attach (at once, or after it closed its
    # output: a half close first): the engine lets go of the monitor
    # connection and the socket at once, not when the container outputs
    ep=$(engine_pid)
    ct_later hx-idle
    "$BIN/velarx" --config "$CONF" container run -d -i --name hx-idle "$IMG" sleep 300 > /dev/null 2>&1
    fds () { ls "/proc/$1/fd" 2> /dev/null | wc -l; }
    leave () { python3 "$HC" "$1" POST "/v1.44/containers/hx-idle/attach?stream=1&stdin=1&stdout=1" --input 'x\n@0.2' "${@:2}" --read 1 > /dev/null 2>&1; }
    for p in "$API $ep engine"; do
        set -- $p
        sock=$1 pid=$2
        shift 2
        before=$(fds $pid)
        for _ in $(seq 10); do leave $sock --close-after 0.3; leave $sock --eof --close-after 0.6; done
        after=$(fds $pid)
        # (polled: the descriptors of a process notify nobody)
        for _ in $(seq 30); do [ "$after" -le "$before" ] && break; sleep 0.1; after=$(fds $pid); done
        check "abandoned idle attaches (half closed first or not) leave no descriptor in the $*" 0 "$([ "$before" -eq 0 ] && echo "no /proc/$pid/fd" || { [ "$after" -gt "$before" ] && echo "$((after - before)) more" || echo 0; })"
    done
    check "...and the engine is the one that was measured" "$ep" "$(engine_pid)"
}

@test "the bytes of an attach and of an exec do not pass through the engine" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # 100 MiB through `cat` by the REST API: all comes back in order, and the
    # engine neither holds more descriptors while they flow nor uses CPU for
    # them (the frontend copies; a relay in the engine used 10 to 60 ticks)
    ep=$(engine_pid)
    ct_later hx-bulk hx-bulkx
    "$BIN/velarx" --config "$CONF" container run -d --name hx-bulkx "$IMG" sleep 300 > /dev/null 2>&1
    for kind in attach exec; do
        name=hx-bulkx
        if [ $kind = attach ]; then
            name=hx-bulk
            # (no log: 100 MiB in the journal of the user would hit its rate
            # limit, which drops what other tests write there for a while)
            "$BIN/velarx" --config "$CONF" container run -d -i --log-driver none --name $name "$IMG" cat > /dev/null 2>&1
        fi
        out=$(timeout 120 python3 -I "$E2E_DIR/stream_bytes.py" "$API" $kind $name "$ep" 100)
        echo "# $kind: $out" >&3
        check "$kind: 100 MiB come back in order" true "$(echo "$out" | jq -r .ok)"
        check "$kind: the engine holds no more descriptors while they flow" true \
            "$(echo "$out" | jq -r '.during[0] == .during[1] and .during[0] <= .before + 4')"
        check "$kind: the engine used little CPU (ticks: $(echo "$out" | jq -r .ticks))" true \
            "$(echo "$out" | jq -r '.ticks < 5')"
    done
    check "...and the engine is the one that was measured" "$ep" "$(engine_pid)"
}

@test "the command of an exec whose client leaves goes on, as podman's" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # podman 5: the command of a REST client that leaves (idle or writing, at
    # once or after a half close, even before the 101) goes on; a `cat` whose
    # client sent its input and closed reads its end and exits 0
    ct_later hx-exl
    "$BIN/velarx" --config "$CONF" container run -d --name hx-exl "$IMG" sleep 300 > /dev/null 2>&1
    inspect () { curl -s --unix-socket "$API" "http://x/v1.44/exec/$1/json"; }
    create () { curl -s --unix-socket "$API" -X POST -H 'Content-Type: application/json' \
        -d "{\"Cmd\":$1,\"AttachStdout\":true,\"AttachStdin\":true}" \
        "http://x/v1.44/containers/hx-exl/exec" | jq -r .Id; }
    start () { python3 "$HC" "$API" POST "/v1.44/exec/$1/start" --body '{"Detach":false}' "${@:2}" > /dev/null 2>&1; }
    gone_early () { python3 - "$API" "/v1.44/exec/$1/start" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
b = b'{"Detach":false}'
s.sendall(("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
           "Connection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n" % (sys.argv[2], len(b))).encode() + b)
s.close()
PY
    }
    e1=$(create '["sleep","4747"]'); start $e1 --close-after 0.5 --read 1
    e2=$(create '["sleep","4748"]'); start $e2 --eof --close-after 0.8 --read 1
    e3=$(create '["sh","-c","while :; do echo x; sleep 0.1; done"]'); start $e3 --close-after 0.5 --read 1
    e4=$(create '["sleep","4749"]'); gone_early $e4
    e5=$(create '["cat"]'); start $e5 --input 'x\n' --close-after 0.8 --read 1
    # (a window: a command killed when its client leaves would be gone by
    # then)
    sleep 2
    for e in "$e1 idle, it left" "$e2 idle, a half close then it left" "$e3 writing, it left" "$e4 it left before the 101"; do
        set -- $e
        check "an exec whose client left goes on ($(echo ${@:2}))" "true" "$(inspect $1 | jq -r .Running)"
    done
    # (a poll: the end of an exec has no event, and its inspect has no pid)
    for _ in $(seq 50); do
        [ "$(inspect $e5 | jq -r .Running)" = false ] && break
        sleep 0.1
    done
    check "a cat whose client sent its input and left ends with it" "false 0" \
        "$(inspect $e5 | jq -r '"\(.Running) \(.ExitCode)"')"
}

@test "an exec request over 1 MiB is refused" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    need_servers
    # an exec request body is at most 1 MiB here (MAX_EXEC_BODY: it crosses
    # to the engine in a pipe)
    ct_later hx-new
    python3 -c 'import json,sys; sys.stdout.write(json.dumps({"Cmd":["true"],"Env":["X="+"a"*(1<<20)]}))' > "$WORKDIR/big-exec.json"
    check "an exec request over 1 MiB is a 400" "400" \
        "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$API" -H 'Content-Type: application/json' --data-binary @"$WORKDIR/big-exec.json" "http://x/v1.41/containers/hx-new/exec")"
}

@test "velarx-api stops" {
    [ -e "$WORKDIR/pulled" ] || skip "no registry on $E2E_REGISTRY or no image from it: the tests with a store are skipped"
    stopping=$(cat "$WORKDIR/pids")
    kill $stopping 2> /dev/null
    for p in $stopping; do e2e_wait_exit "$p"; done
    : > "$WORKDIR/pids"
    PIDS=
    rm -f "$API" "$ENGINE_SOCK"
}

# 4. Socket activation: the units

@test "socket activation: the units are installed and linked" {
    units_gate
    : > "$WORKDIR/units-linked"
    MAKE=(make -s -C "$top_srcdir" TARGETDIR="$BIN")
    P=$WORKDIR/pfx
    e2e_need_man
    "${MAKE[@]}" install-files PREFIX="$P"
    check "install into a PREFIX" 0 $?
    mkdir -p "$WORKDIR/units"
    if [ "$MODE" = system ] && command -v selinuxenabled > /dev/null && selinuxenabled; then
        chcon -t bin_t "$P"/bin/* || exit 1
    fi
    if [ "$MODE" = user ]; then
        # the engine reaches the user manager through its runtime directory
        ln -sfn "$REAL_RUNTIME_DIR/systemd" "$XDG_RUNTIME_DIR/systemd"
    fi
    unit () { # name: the installed unit, with the paths of this test
        sed -e "s|^ListenStream=.*|ListenStream=$RUN/$2|" \
            -e "s|^ExecStart=\(.*velarx[a-z-]*\)\(.*\)$|ExecStart=\1 --config $CONF\2|" \
            -e "s|velarx-engine.socket|$U-engine.socket|g; s|velarx-api.socket|$U-api.socket|g" \
            -e "/^\[Service\]/a Environment=HOME=$HOME XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" \
            -e '/^RuntimeDirectory=/d' -e '/^StateDirectory=/d' -e '/^PrivateTmp=/d' \
            -e '/^ProtectSystem=/d' -e '/^ProtectHome=/d' \
            "$P/lib/systemd/$MODE/$1"
    }
    unit velarx-engine.socket engine/engine.sock > "$WORKDIR/units/$U-engine.socket"
    unit velarx-engine.service engine/engine.sock > "$WORKDIR/units/$U-engine.service"
    unit velarx-api.socket velarx.sock > "$WORKDIR/units/$U-api.socket"
    unit velarx-api.service velarx.sock > "$WORKDIR/units/$U-api.service"
    # (the units were verified by units.bats: the engine's idle time is the one of
    # the configuration)
    "${SCTL[@]}" link --runtime "$WORKDIR"/units/$U-* > /dev/null
    check "the units are linked" 0 $?
    : > "$WORKDIR/units-ready"
}

# units_linked: skip unless the test that installs the units linked them
units_linked () {
    units_gate
    [ -e "$WORKDIR/units-ready" ] || skip "the units are not installed (see the test that installs them)"
}

@test "socket activation: a request starts the API and the engine" {
    units_linked
    "${SCTL[@]}" start "$U-engine.socket" "$U-api.socket"
    check "the sockets listen" "active active" "$(active $U-engine.socket) $(active $U-api.socket)"
    check "nothing runs before a request" "inactive inactive" "$(active $U-engine.service) $(active $U-api.service)"
    out=$(get http://x/_ping)
    check "a request starts the API" OK "$out"
    check "...and its first call the engine" "active active" "$(active $U-api.service) $(active $U-engine.service)"
    check "the engine answers through the API" "[" "$(get http://x/libpod/containers/json?all=true | cut -c1)"
}

@test "socket activation: idle, both leave and the next request starts them again" {
    units_linked
    # idle: both leave (2 seconds), the sockets stay: their processes end by
    # themselves (a pidfd each), then the manager says the units are inactive
    local u mainpid
    for u in api engine; do
        mainpid=$("${SCTL[@]}" show -P MainPID "$U-$u.service")
        [ "${mainpid:-0}" -le 0 ] || e2e_wait_exit "$mainpid" 30
    done
    e2e_wait_unit_state "$U-api.service" inactive 20
    e2e_wait_unit_state "$U-engine.service" inactive 20
    check "idle: both leave" "inactive inactive" "$(active $U-api.service) $(active $U-engine.service)"
    check "...cleanly" "success success" \
        "$("${SCTL[@]}" show -P Result "$U-api.service") $("${SCTL[@]}" show -P Result "$U-engine.service")"
    check "...and the sockets stay" "active active" "$(active $U-engine.socket) $(active $U-api.socket)"
    check "the next request starts them again" OK "$(get http://x/_ping)"
    check "...both" "active active" "$(active $U-api.service) $(active $U-engine.service)"
}
