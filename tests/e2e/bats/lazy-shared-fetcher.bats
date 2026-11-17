# SPDX-License-Identifier: Apache-2.0
# A lazy pull is the engine service's of the store (`velarx varlink`), which
# the command that pulls finds or starts on the engine's socket: every command
# runs in its own process (no daemon), and the containers of three commands
# are served by that one service through the one socket of the store
# (`services/image-fetch/engine`, longer than a socket address holds), which
# no monitor and no command binds; it serves them after the commands ended,
# keeps serving the others when a container is killed, completes the pull
# with no command waiting, and leaves when it has nothing to do (no pull to
# complete, no container to follow).  A service killed under the containers
# is replaced by the one the next command starts, which binds the same
# socket, and the image servers ask it.  Rootless.
#
#   VELARX_BINDIR=target/debug E2E_IMAGE=image bats tests/e2e/bats/lazy-shared-fetcher.bats
#
# (LAZY_IMAGE_SEALED=1: the image has the fs-verity digests in its TOCs
# already, as velarx writes them, and is used as it is; else it is pushed
# again to $E2E_PUSH_REGISTRY, which the test stops a moment)

load helpers

E2E_PUSH_REGISTRY=${E2E_PUSH_REGISTRY:-$E2E_REGISTRY}

setup_file () {
    command -v curl > /dev/null || skip "no curl"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n[[registry]]\nlocation = "%s"\ninsecure = true\n' \
        "$E2E_REGISTRY" "$E2E_PUSH_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # (the engine's socket in a directory of 85 bytes: it fits in a socket
    # address, the fetcher's below it, in services/, does not)
    export SOCKDIR=$WORKDIR/s
    while [ ${#SOCKDIR} -lt 85 ]; do SOCKDIR=${SOCKDIR}x; done
    mkdir -m 0700 "$SOCKDIR"
    cat > "$WORKDIR/sh.toml" <<EOF
[engine]
socket = "$SOCKDIR/sh.sock"
[server]
socket = "$SOCKDIR/sh.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$WORKDIR/store"
[pull]
EOF
    # (the service leaves soon when it has nothing to do)
    sed -i 's/^\[engine\]$/[engine]\nidle_exit = 2/' "$WORKDIR/sh.toml"
    export IMAGE=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    # Only the layers whose TOCs give the fs-verity digests of their files
    # stay lazy: the image is pushed again by velarx (gzip, and back as
    # zstd:chunked), then the store starts empty.
    if [ -z "${LAZY_IMAGE_SEALED:-}" ]; then
        local sealed=$E2E_PUSH_REGISTRY/velarx-e2e/lazy-shared-$$
        { vx image pull --tls-verify=false "$IMAGE" &&
          vx image push --tls-verify=false --compression-format gzip "$IMAGE" "$sealed:gzip" &&
          vx image pull --tls-verify=false "$sealed:gzip" &&
          vx image push --tls-verify=false --compression-format zstd:chunked "$sealed:gzip" "$sealed:zstd"
        } > "$WORKDIR/seal.log" 2>&1 || { echo "cannot make the image"; cat "$WORKDIR/seal.log"; exit 1; }
        IMAGE=$sealed:zstd
        rm -rf "$WORKDIR/store" "$WORKDIR/root" "$WORKDIR/state"
    fi
    echo "IMAGE=$IMAGE" > "$WORKDIR/vars"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local c p
    for c in $(vx container list -a -q 2> /dev/null); do
        vx container rm -t 0 -f "$c" > /dev/null 2>&1
    done
    if [ -f "$WORKDIR/d.toml" ]; then
        for c in $("$BIN/velarx" --config "$WORKDIR/d.toml" container list -a -q 2> /dev/null); do
            "$BIN/velarx" --config "$WORKDIR/d.toml" container rm -t 0 -f "$c" > /dev/null 2>&1
        done
    fi
    [ -z "${E2E_PUSH_REGISTRY_PID:-}" ] || kill -CONT "$E2E_PUSH_REGISTRY_PID" 2> /dev/null
    for p in $(fetchers); do kill -KILL "$p" 2> /dev/null; done
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    e2e_teardown_file
}

setup () {
    set +e
    if [ -f "$WORKDIR/vars" ]; then . "$WORKDIR/vars"; fi
}

# every command in a process of its own
vx () { "$BIN/velarx" --config "$WORKDIR/sh.toml" "$@"; }

# the fetchers of this store: their sockets are in its services
# directory (no other process is looked at); the front only, not the
# runner of its credential helpers, a child with its command line
fetchers () {
    local d all p
    for d in /proc/[0-9]*; do
        tr '\0' ' ' 2> /dev/null < "$d/cmdline" | grep -qF -- "--shared $SOCKDIR/services/registry-" &&
            all="$all ${d#/proc/}"
    done
    for p in $all; do
        case " $all " in *" $(ppid_of "$p") "*) ;; *) echo "$p" ;; esac
    done
}
monitors () {
    local f
    for f in $(find "$WORKDIR/state" -name monitor.pid 2> /dev/null); do
        cat "$f"; echo
    done
}
# the engine service of the store, if one runs
service () { e2e_service_pid "$SOCKDIR/sh.sock"; }
# the one socket the containers of the store ask
PROXY_DIR=image-fetch
ppid_of () { awk '/^PPid:/ {print $2}' "/proc/$1/status" 2> /dev/null; }
sockets_of () { ls -l "/proc/$1/fd" 2> /dev/null | grep -c 'socket:'; }

@test "a lazy pull is the service's: it outlives the command, completes the pull alone, and leaves" {
    local p id svc
    check "no service runs" "" "$(service)"
    vx image pull --lazy --tls-verify=false "$IMAGE" > "$WORKDIR/pull.log" 2>&1
    rc=$?
    [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/pull.log"
    check "a lazy pull" 0 $rc
    svc=$(service)
    check_match "the command started the engine service" "^[0-9]+$" "$svc"
    id=$(ls "$WORKDIR/store/staging/pulls" 2> /dev/null | grep -v '^\.' | head -1)
    # the service finishes alone (no command waits for it): 120 s at most
    if [ -n "$id" ]; then
        e2e_wait_gone "$WORKDIR/store/staging/pulls/$id" 120
    fi
    check "the pull is complete" "" "$(ls "$WORKDIR/store/staging/pulls" 2> /dev/null | grep -v '^\.')"
    # (with nothing to do it leaves: 2 s idle, 60 s at most)
    e2e_wait_exit "$svc" 60
    check "the service left" gone "$(e2e_alive "$svc")"
    check "the image is in the store" 1 "$(vx image list -q | grep -c .)"
    for p in $(fetchers); do e2e_wait_exit "$p" 60; done
    check "no fetcher once the pull is complete" "" "$(fetchers)"
}

@test "three containers of three commands are served by the one engine service, which no monitor starts" {
    local i p m out svc
    # a store with nothing in it, the pull held where it is
    rm -rf "$WORKDIR/store" "$WORKDIR/root" "$WORKDIR/state"
    e2e_hold_completions "$WORKDIR/sh.toml"
    # (in a command substitution: nothing that outlives the command holds
    # its descriptors, so the substitution ends with it, though the service
    # it started lives on; 60 s is an upper bound)
    out=$(timeout 60 "$BIN/velarx" --config "$WORKDIR/sh.toml" container run -d --lazy --network none --name lz1 "$IMAGE" sleep 600 2>&1)
    check "container lz1 runs, the substitution ends" 0 $?
    svc=$(service)
    check_match "the command started the engine service" "^[0-9]+$" "$svc"
    for i in 2 3; do
        vx container run -d --lazy --network none --name "lz$i" "$IMAGE" sleep 600 > /dev/null 2>&1
        check "container lz$i runs" 0 $?
    done
    check "one service for the three" "$svc" "$(service)"
    for i in 1 2 3; do
        check_match "lz$i reads a file of the image" "^[0-9]+\.[0-9]+" "$(vx container exec "lz$i" cat /etc/alpine-release 2>&1)"
    done
    m=$(monitors)
    check "three monitors" 3 "$(echo "$m" | grep -c .)"
    for p in /proc/[0-9]*; do
        echo "$m" | grep -qx "$(ppid_of "${p#/proc/}")" || continue
        ! tr '\0' ' ' < "$p/cmdline" 2> /dev/null | grep -q 'fetcher' ||
            { echo "FAIL monitor $(ppid_of "${p#/proc/}") started a fetcher" >&2; exit 1; }
    done
    # the one socket of the store, longer than a socket address holds
    check "the socket of the store" socket "$([ -S "$SOCKDIR/services/$PROXY_DIR/engine" ] && echo socket)"
    check "and no other" "engine" "$(ls "$SOCKDIR/services/$PROXY_DIR" | grep -v '\.lock$')"
    check "the service holds the pull" held "$(flock -n "$WORKDIR/store/staging/pulls/$(vx image pulls -q --no-trunc)/lease" true && echo free || echo held)"
}

@test "a container killed with its monitor goes, the others are served" {
    local m id c
    id=$(vx container inspect --format '{{.Id}}' lz1 2> /dev/null)
    m=$(cat "$(find "$WORKDIR/state" -path "*${id:0:12}*" -name monitor.pid | head -1)" 2> /dev/null)
    c=$(vx container inspect --format '{{.State.Pid}}' lz1 2> /dev/null)
    [ -n "$id" ] && [ -n "$m" ] && [ -n "$c" ] || { echo "FAIL no monitor of lz1" >&2; exit 1; }
    kill -KILL "$m" "$c"
    e2e_wait_exit "$m" 10
    check_match "lz2 reads files" "^[0-9a-f]{64}" "$(vx container exec lz2 sh -c 'find /bin /lib /usr -type f | head -50 | xargs sha256sum' 2>&1)"
    check_match "lz3 reads files" "^[0-9a-f]{64}" "$(vx container exec lz3 sh -c 'find /bin /lib /usr -type f | head -50 | xargs sha256sum' 2>&1)"
}

@test "the engine service killed: the next command starts one that binds the same socket, and the image servers ask it" {
    local svc next log served
    svc=$(service)
    [ -n "$svc" ] || { echo "FAIL no engine service" >&2; exit 1; }
    log=$SOCKDIR/service.log
    served=$(grep -c "lazy pulls are served on" "$log")
    kill -KILL "$svc"
    e2e_wait_exit "$svc" 10
    # (any command of the store starts another one for the pull, which
    # binds the same path and says so; 30 s is an upper bound)
    vx image pulls -q > /dev/null 2>&1
    e2e_wait_line "$log" "lazy pulls are served on" 30 $((served + 1))
    check "a new service binds the same socket" 0 $?
    next=$(service)
    check_match "another service" "^[0-9]+$" "$([ "$next" != "$svc" ] && echo "$next")"
    check_match "lz2 reads more files" "^[0-9a-f]{64}" "$(vx container exec lz2 sh -c 'find /usr /lib /bin -type f | tail -50 | xargs sha256sum' 2>&1)"
}

@test "the containers end and the pull completes; the service leaves with its socket" {
    local i p svc
    svc=$(service)
    for i in 1 2 3; do vx container rm -t 0 -f "lz$i" > /dev/null 2>&1; done
    vx image complete "$IMAGE" > /dev/null 2>&1
    check "the pull is complete" "" "$(vx image pulls -q)"
    [ -z "$svc" ] || e2e_wait_exit "$svc" 60
    check "the service left" "" "$(service)"
    for p in $(fetchers); do e2e_wait_exit "$p" 60; done
    check "no fetcher once the pull is complete" "" "$(fetchers)"
    check "no socket is left" "" "$(ls "$SOCKDIR/services/$PROXY_DIR" 2> /dev/null | grep -v '\.lock$')"
}

# The registry stops a moment: the first read of the container (its
# program) waits for the fetcher, which is killed meanwhile.  A store of
# its own, where the image is lazy again.

@test "a container whose engine's fetcher was killed gets EIO at once, a new container is served" {
    local dl out p started run id
    case "$IMAGE" in
    "$E2E_PUSH_REGISTRY"/*) [ -n "${E2E_PUSH_REGISTRY_PID:-}" ] || skip "E2E_PUSH_REGISTRY_PID: the registry to stop" ;;
    *) skip "an image of a registry the test may stop" ;;
    esac
    mkdir -m 0700 "$SOCKDIR/d"
    sed "s#$WORKDIR/\(state\|root\|store\)\"#$WORKDIR/d-\1\"#; s#$SOCKDIR/sh.sock#$SOCKDIR/d/sh.sock#g" "$WORKDIR/sh.toml" > "$WORKDIR/d.toml"
    vd () { "$BIN/velarx" --config "$WORKDIR/d.toml" "$@"; }
    mkdir -p "$WORKDIR/d-store"
    vd image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a lazy pull in a new store" 0 $?
    for p in $(fetchers); do e2e_wait_exit "$p" 10; done
    # (made while the registry serves: the engine reads files of the image
    # for it)
    vd container create --lazy --network none --name lzd "$IMAGE" cat /etc/alpine-release > /dev/null 2>&1
    check "the container is made" 0 $?
    kill -STOP "$E2E_PUSH_REGISTRY_PID"
    started=$(date +%s)
    timeout 120 "$BIN/velarx" --config "$WORKDIR/d.toml" container start -a lzd > "$WORKDIR/lzd.out" 2>&1 &
    run=$!
    # (once the monitor runs it holds its connection, which it got as it
    # started; its reads wait for the registry.  10 s at most)
    id=$(vd container inspect --format '{{.Id}}' lzd)
    e2e_wait_path "$WORKDIR/d-state/mon/${id:0:12}/monitor.pid" 10 || e2e_die "the monitor of lzd does not start"
    dl=$(fetchers)
    kill -KILL $dl 2> /dev/null
    for p in $dl; do e2e_wait_exit "$p" 10; done
    kill -CONT "$E2E_PUSH_REGISTRY_PID"
    wait "$run"
    check "one fetcher was killed" 1 "$(echo "$dl" | grep -c .)"
    out=$(cat "$WORKDIR/lzd.out")
    check "no hang: the reads failed at once" 1 "$([ $(( $(date +%s) - started )) -lt 60 ] && echo 1)"
    check_match "the read fails with EIO" "I/O error|Input/output error" "$out"
    ! echo "$out" | grep -qE '^[0-9]+\.[0-9]+$'
    check "it did not read the file" 0 $?
    vd container rm -t 0 -f lzd > /dev/null 2>&1
    out=$(vd container run --rm --lazy --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "a new container reads its files (the engine started a new fetcher)" "^[0-9]+\.[0-9]+" "$out"
    # the service finishes the pull with a fetcher of its own, which
    # leaves with it
    vd image complete "$IMAGE" > /dev/null 2>&1
    check "the pull is complete" "" "$(vd image pulls -q)"
    for p in $(fetchers); do e2e_wait_exit "$p" 60; done
    check "no fetcher once the pull is complete" "" "$(fetchers)"
}
