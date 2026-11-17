# SPDX-License-Identifier: Apache-2.0
# An image of the most layers the overlay takes, with the soft limit of open
# files that a shell or a unit gives (1024): the engine raises its own limit
# for the descriptors of the layers it mounts (a kernel mount of an eager
# image: one for each layer; the image server of a lazy one: three), and the
# containers keep the limits they would have had: the limit of their spec
# (podman's default, or --ulimit) for the container and its exec, the one the
# engine's user gave for the OCI runtime that starts them.  An image the
# overlay cannot take (its layers and the data-only layers of the stores, for
# a lazy image also one for the files fetched for each layer, are more than
# 500) is refused when it is pulled, and a hard limit too low for
# the layers is an error that names it, not a mount that falls back.  Without
# a daemon (the commands are the engine) and with one.  Rootless and root.
#
#   VELARX_BINDIR=target/debug E2E_IMAGE=image bats tests/e2e/bats/many-layers.bats
#
# The layers are made by tests/e2e/many_layers.py on the layers of E2E_IMAGE
# (a few of its own at most): an eager image of 499 layers (the store's
# objects are the 500th layer of the overlay), a lazy one of 249 (with the
# directory of the files fetched for each layer and the objects, 499) and
# one of 250 that a lazy pull does not take, and one of 500 that no pull
# takes.

load helpers

# the soft limit of open files the engine of a command gets
SOFT=1024

setup_file () {
    # (the soft limit a shell gives; the hard limit stays)
    [ "$(ulimit -Hn)" = unlimited ] || [ "$(ulimit -Hn)" -gt $SOFT ] || skip "the hard limit of open files is $SOFT or less"
    ulimit -Sn $SOFT
    command -v curl > /dev/null || skip "no curl"
    command -v crun > /dev/null || skip "no crun"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # (no completion in the background: a lazy pull stays one while it is looked at)
    e2e_hold_completions "$XDG_CONFIG_HOME/velarx/config.toml"
    # an OCI runtime that says the soft limit it has, then is crun
    cat > "$WORKDIR/limit-runtime" <<EOT
#!/bin/sh
echo "\$(ulimit -Sn) \$*" >> "$WORKDIR/runtime-limits"
exec $(command -v crun) "\$@"
EOT
    chmod +x "$WORKDIR/limit-runtime"
    printf '\n[runtimes]\nlimited = "%s"\n' "$WORKDIR/limit-runtime" >> "$XDG_CONFIG_HOME/velarx/config.toml"
    local base=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    local repo=$E2E_REGISTRY/velarx-e2e/many-$$
    {
        "$SH" image pull --tls-verify=false "$base" &&
        "$SH" image save -o "$WORKDIR/base.tar" "$base" &&
        make_images "$repo"
    } > "$WORKDIR/make.log" 2>&1 || { echo "cannot make the images"; cat "$WORKDIR/make.log"; exit 1; }
    { echo "BASE=$base"; echo "REPO=$repo"; } > "$WORKDIR/vars"
}

# the engine of the command, in its process (no daemon: nothing listens on
# the socket of the file's configuration), with the soft limit of a shell
vx () { "$SH" "$@"; }
# the engine service of the daemon of the file
dx () { "$SH" --socket "$ESOCK" "$@"; }
# hard N COMMAND...: the command with N as both limits of open files
hard () { local n=$1; shift; ( ulimit -Sn "$n" && ulimit -Hn "$n" && "$@" ); }

# the soft limits the OCI runtime had when the monitor started it (create,
# start, delete: the calls of the engine, `features` and `state`, are the
# engine's own)
runtime_limits () {
    grep -E ' (create|start|delete) ' "$WORKDIR/runtime-limits" | cut -d' ' -f1 | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# make_images REPO: the images of 499 (eager), 249 and 250 (lazy) and 500
# layers; the layers they add to the base's are in the file extra-N
make_images () {
    local repo=$1 n id
    for n in 499 249 250 500; do
        python3 -I "$E2E_DIR/many_layers.py" "$WORKDIR/base.tar" "$WORKDIR/many$n.tar" $n > "$WORKDIR/extra-$n" || return 1
    done
    for n in 499 249 250; do
        # (gzip layers, which a push writes with their digests, and back as
        # zstd:chunked: the tables of contents of a lazy pull give fs-verity)
        id=$("$SH" image pull "oci-archive:$WORKDIR/many$n.tar") || return 1
        "$SH" image push --tls-verify=false --compression-format gzip "$id" "$repo:g$n" &&
        "$SH" image rm -f "$id" || return 1
        [ $n = 499 ] && continue
        "$SH" image pull --tls-verify=false "$repo:g$n" &&
        "$SH" image push --tls-verify=false --compression-format zstd:chunked "$repo:g$n" "$repo:z$n" &&
        "$SH" image rm -f "$repo:g$n" || return 1
    done
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    . "$E2E_DIR/cleanup.sh"
    e2e_remove_containers "$BIN/velarx" "$ESOCK"
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    e2e_teardown_file
}

setup () {
    set +e
    ulimit -Sn $SOFT
    . "$WORKDIR/vars"
}

# a failing check must not leave a container
teardown () {
    set +e
    vx container rm -t 0 -f many > /dev/null 2>&1
    return 0
}

@test "a container of the most layers an eager pull takes runs with 1024 open files" {
    local out
    out=$(vx image pull --tls-verify=false "$REPO:g499" 2>&1)
    check "the pull" 0 $?
    out=$(vx run --rm --network none "$REPO:g499" ls /many 2>&1)
    check "the run" 0 $?
    check "the layers on top of the base are there" "$(cat "$WORKDIR/extra-499")" "$(echo "$out" | wc -l)"
}

@test "the limit of a container is its spec's: the same for an image of 499 layers as for one of a few" {
    local many few
    few=$(vx run --rm --network none "$BASE" sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')
    many=$(vx run --rm --network none "$REPO:g499" sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')
    check "the limits of the container" "$few" "$many"
    # an exec has the container's
    vx run -d --name many --network none "$REPO:g499" sleep 300 > /dev/null
    check "the run" 0 $?
    check "an exec's limits" "$many" "$(vx exec many sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')"
}

@test "a container with --ulimit nofile keeps it, and so does its exec" {
    local out
    out=$(vx run --rm --network none --ulimit nofile=512:1024 "$REPO:g499" sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')
    check "the run" "512 1024 " "$out"
    vx run -d --name many --network none --ulimit nofile=512:1024 "$REPO:g499" sleep 300 > /dev/null
    check "the run -d" 0 $?
    check "the exec" "512 1024 " "$(vx exec many sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')"
}

@test "the OCI runtime has the soft limit the user gave, not the raised one of the engine" {
    rm -f "$WORKDIR/runtime-limits"
    vx run --rm --network none --runtime "$WORKDIR/limit-runtime" "$BASE" true > /dev/null 2>&1
    check "the run" 0 $?
    check "the runtime ran" yes "$([ -s "$WORKDIR/runtime-limits" ] && echo yes)"
    check "it always had the limit of the user" "$SOFT" "$(runtime_limits)"
}

@test "a lazy image of 249 layers is mounted with 1024 open files" {
    local out
    out=$(vx image pull --lazy --tls-verify=false "$REPO:z249" 2>&1)
    check "the lazy pull" 0 $?
    out=$(vx run --rm --lazy --network none "$REPO:z249" ls /many 2>&1)
    check "the run" 0 $?
    check "the layers are there" "$(cat "$WORKDIR/extra-249")" "$(echo "$out" | wc -l)"
    check_match "and it is still a pull" "^queued$" "$(vx image pulls --format '{{.State}}' 2>&1)"
}

@test "an image of 500 layers is refused when it is pulled, naming it and the limit" {
    local out images
    images=$(vx image list -q 2>&1 | wc -l)
    out=$(vx image pull "oci-archive:$WORKDIR/many500.tar" 2>&1)
    check "the pull of 500 layers is refused" 125 $?
    check_match "it says what the image is" "image sha256:[0-9a-f]+ has 500 layers" "$out"
    check_match "and what the limit is" "more than the 499 that can be mounted" "$out"
    check_match "and why" "takes 500 layers altogether, 1 of them for the objects of the stores\)" "$out"
    check "nothing of it is in the store" "$images" "$(vx image list -q 2>&1 | wc -l)"
}

@test "a lazy image of 250 layers is refused: the files fetched for each layer are a layer of the overlay" {
    local out pulls
    pulls=$(vx image pulls -q 2>&1)
    out=$(vx image pull --lazy --tls-verify=false "$REPO:z250" 2>&1)
    check "the lazy pull of 250 layers is refused" 125 $?
    check_match "it says what the image is" "image $REPO:z250 has 250 layers" "$out"
    check_match "and the limit" "more than the 249 that a lazy pull can mount" "$out"
    check_match "and why" "two for each of its layers.*pull it without --lazy" "$out"
    check "nothing of it is a pull" "$pulls" "$(vx image pulls -q 2>&1)"
    check "the same image is pulled whole" 0 "$(vx image pull --tls-verify=false "$REPO:z250" > /dev/null 2>&1; echo $?)"
    vx image rm -f "$REPO:z250" > /dev/null 2>&1
}

# the soft limit of open files of the process $1 (an engine, alive)
soft_of () { awk '/^Max open files/ { print $4 }' "/proc/$1/limits"; }

# engine_limit ARGS...: the soft limit of open files the engine of
# `velarx run --rm ARGS... sh -c ...` has while its container runs: the
# container says it is up through a file and waits for the test on a fifo
engine_limit () {
    local pid out
    rm -rf "$WORKDIR/sync" && mkdir "$WORKDIR/sync" && mkfifo "$WORKDIR/sync/go"
    "$SH" run --rm --network none -v "$WORKDIR/sync:/sync:z" "$@" sh -c 'touch /sync/up; read x < /sync/go' > "$WORKDIR/engine.log" 2>&1 &
    pid=$!
    e2e_wait_path_of "$WORKDIR/sync/up" $pid || { cat "$WORKDIR/engine.log"; kill $pid; return 1; }
    out=$(soft_of $pid)
    echo go > "$WORKDIR/sync/go"
    wait $pid
    echo "$out"
}

@test "an engine that mounts no big image keeps the soft limit it was given" {
    check "a plain run" "$SOFT" "$(engine_limit "$BASE")"
}

@test "the engine raises its soft limit to 3 for each layer and the base, for the image it mounts only" {
    vx image pull --tls-verify=false "$REPO:g499" > /dev/null 2>&1
    # (499 layers of the image, 3 for each, and the 64 of the engine)
    check "the engine of an image of 499 layers" 1561 "$(engine_limit "$REPO:g499")"
    check "and the next command has the limit of its shell" "$SOFT" "$(engine_limit "$BASE")"
    vx image pull --lazy --tls-verify=false "$REPO:z249" > /dev/null 2>&1
    # (a lazy image of 249 layers needs 811, below what the shell gave: not lowered)
    check "a lazy image of 249 layers" "$SOFT" "$(engine_limit --lazy "$REPO:z249")"
}

@test "a hard limit below the need refuses the pull before anything is fetched, naming the image and the limits" {
    local out images
    vx image rm -f "$REPO:g499" > /dev/null 2>&1
    images=$(vx image list -q 2>&1 | wc -l)
    out=$(hard 1200 vx image pull "oci-archive:$WORKDIR/many499.tar" 2>&1)
    check "the pull is refused" 125 $?
    check_match "it says what the image is and what it needs" "image sha256:[0-9a-f]+: mounting it needs 1561 open files \\(3 for each of its 499 layers and 64 for the engine\\)" "$out"
    check_match "and the hard limit" "more than the hard limit of 1200" "$out"
    check "nothing of it is in the store" "$images" "$(vx image list -q 2>&1 | wc -l)"
    out=$(hard 1560 vx image pull --tls-verify=false "$REPO:g499" 2>&1)
    check "one open file short is refused too" 125 $?
    check_match "naming the image" "image $REPO:g499: mounting it needs 1561 open files" "$out"
    check "nothing of it is in the store" "$images" "$(vx image list -q 2>&1 | wc -l)"
    hard 1561 vx image pull --tls-verify=false "$REPO:g499" > /dev/null 2>&1
    check "the exact need is pulled" 0 $?
    out=$(hard 1561 vx run --rm --network none "$REPO:g499" ls /many 2>&1)
    check "and mounted" 0 $?
}

@test "a hard limit too low for the layers is an error that names it, not a mount by another way" {
    local out
    vx image pull --tls-verify=false "$REPO:g499" > /dev/null 2>&1
    out=$(hard 520 vx run --rm --network none "$REPO:g499" true 2>&1)
    check "the run fails" "1" "$(echo "$out" | grep -c 'mounting it needs 1561 open files')"
    check_match "it says the limits" "soft limit 520, hard limit 520" "$out"
    out=$(hard 1200 vx run --rm --network none "$REPO:g499" true 2>&1)
    check_match "a hard limit of 1200 as well" "mounting it needs 1561 open files.*soft limit 1200, hard limit 1200" "$out"
    vx image pull --lazy --tls-verify=false "$REPO:z249" > /dev/null 2>&1
    out=$(hard 600 vx run --rm --lazy --network none "$REPO:z249" true 2>&1)
    check_match "a lazy image too" "mounting it needs 811 open files.*hard limit 600" "$out"
    check_match "and it is a pull still" "^queued$" "$(vx image pulls --format '{{.State}}' 2>&1)"
}

@test "with a daemon: the same limits, the same mount" {
    # (the engine service a command started for a lazy pull is the store's:
    # the daemon is the service now)
    e2e_stop_services "$WORKDIR"
    # (its default OCI runtime is the one that says its limit)
    sed "s|^\[server\]\$|[server]\nruntime = \"$WORKDIR/limit-runtime\"|" "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/daemon.toml"
    E2E_SPAWN_LOG=$WORKDIR/daemon.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --config "$WORKDIR/daemon.toml" varlink || {
        echo "the daemon does not start"; cat "$WORKDIR/daemon.log"; exit 1; }
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    local out few
    few=$(dx run --rm --network none "$BASE" sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')
    out=$(dx run --rm --network none "$REPO:g499" sh -c 'ulimit -Sn; ulimit -Hn; ls /many | wc -l' 2>&1 | tr '\n' ' ')
    check "the limits of the container, with its layers" "$few$(cat "$WORKDIR/extra-499") " "$out"
    out=$(dx run --rm --lazy --network none "$REPO:z249" ls /many 2>&1)
    check "the lazy image" 0 $?
    check "its layers" "$(cat "$WORKDIR/extra-249")" "$(echo "$out" | wc -l)"
    out=$(dx run --rm --network none --ulimit nofile=512:1024 "$REPO:g499" sh -c 'ulimit -Sn; ulimit -Hn' 2>&1 | tr '\n' ' ')
    check "--ulimit" "512 1024 " "$out"
    rm -f "$WORKDIR/runtime-limits"
    dx run --rm --network none "$BASE" true > /dev/null 2>&1
    check "the runtime had the limit of the user" "$SOFT" "$(runtime_limits)"
    kill -INT "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID" 10 || kill -KILL "$DAEMON_PID"
    rm -f "$WORKDIR/daemon.pid"
}
