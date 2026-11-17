# SPDX-License-Identifier: Apache-2.0
# OCI artifacts: add, ls, inspect, rm, extract, through a rootless
# server and through the engine of the command (no server); pull and push
# against the registry of the e2e (E2E_REGISTRY, default localhost:5000)
# when it answers.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/artifact.bats

load helpers


setup_file () {
    e2e_setup_file
    chmod 700 "$XDG_RUNTIME_DIR"
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<EOF
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOF
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf
    export F=$WORKDIR/files
    mkdir -p "$F"
    echo "first file" > "$F/one.txt"
    printf '\x00\x01\x02binary' > "$F/two.bin"
    echo "third" > "$F/three.txt"
    # (the repositories of the pushes are of this run only)
    export RUNID=$$
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    local pid
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -n "$pid" ]; then
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid" 10
        kill -KILL "$pid" 2> /dev/null
        rm -f "$WORKDIR/daemon.pid"
    fi
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

sh_ () { "$SH" --config "$XDG_CONFIG_HOME/velarx/config.toml" "$@"; }
skip_unless_registry () {
    curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
}

local_commands () { # where
    local w=$1
    out=$(sh_ artifact add --type application/x-e2e --annotation k=v localhost/e2e/a "$F/one.txt" "$F/two.bin" 2>&1)
    check_match "$w: add prints the digest" '^[0-9a-f]{64}$' "$out"
    digest=$out
    check "$w: inspect, the type" "application/x-e2e" \
        "$(sh_ artifact inspect --format '{{.Manifest.ArtifactType}}' localhost/e2e/a 2>&1)"
    check "$w: inspect, the files" "one.txt two.bin" \
        "$(sh_ artifact inspect --format '{{range .Manifest.Layers}}{{index .Annotations "org.opencontainers.image.title"}} {{end}}' localhost/e2e/a 2>&1 | sed 's/ $//')"
    check "$w: inspect, the media types" "text/plain; charset=utf-8|application/octet-stream" \
        "$(sh_ artifact inspect --format '{{(index .Manifest.Layers 0).MediaType}}|{{(index .Manifest.Layers 1).MediaType}}' localhost/e2e/a 2>&1)"
    check "$w: inspect, an annotation of the files" "v" \
        "$(sh_ artifact inspect --format '{{index (index .Manifest.Layers 0).Annotations "k"}}' localhost/e2e/a 2>&1)"
    check "$w: inspect by digest" "localhost/e2e/a:latest" \
        "$(sh_ artifact inspect --format '{{.Name}}' "${digest:0:12}" 2>&1)"
    check_match "$w: ls" "^localhost/e2e/a +latest +${digest:0:12} " "$(sh_ artifact ls --noheading 2>&1)"
    check "$w: ls -q" "${digest:0:12}" "$(sh_ artifact ls -q 2>&1)"
    sh_ artifact add localhost/e2e/a "$F/three.txt" > /dev/null 2>&1
    check "$w: add of a name that is there fails" 125 $?
    sh_ artifact add --append localhost/e2e/a "$F/three.txt" > /dev/null
    check "$w: add --append" 3 "$(sh_ artifact inspect --format '{{len .Manifest.Layers}}' localhost/e2e/a 2>&1)"
    out=$(sh_ artifact add --append --replace localhost/e2e/a "$F/three.txt" 2>&1)
    check "$w: --append with --replace is refused" 125 $?
    check_match "$w: and says so" "--append and --replace options cannot be used together" "$out"

    rm -rf "$WORKDIR/out" && mkdir "$WORKDIR/out"
    sh_ artifact extract localhost/e2e/a "$WORKDIR/out"
    check "$w: extract into a directory" "one.txt three.txt two.bin" "$(ls "$WORKDIR/out" | tr '\n' ' ' | sed 's/ $//')"
    check "$w: the files are the same" "first file" "$(cat "$WORKDIR/out/one.txt")"
    sh_ artifact extract --title three.txt localhost/e2e/a "$WORKDIR/single"
    check "$w: extract --title into a file" "third" "$(cat "$WORKDIR/single")"
    sh_ artifact extract localhost/e2e/a "$WORKDIR/notadir" > /dev/null 2>&1
    check "$w: several files are not one file" 125 $?
    ln -sf "$WORKDIR/elsewhere" "$WORKDIR/link"
    sh_ artifact extract --title three.txt localhost/e2e/a "$WORKDIR/link" > /dev/null 2>&1
    check "$w: extract does not follow a symbolic link" "125 no" "$? $(test -e "$WORKDIR/elsewhere" && echo yes || echo no)"
    rm -f "$WORKDIR/link" "$WORKDIR/single"

    sh_ artifact add --replace localhost/e2e/a "$F/three.txt" > /dev/null
    check "$w: add --replace" 1 "$(sh_ artifact inspect --format '{{len .Manifest.Layers}}' localhost/e2e/a 2>&1)"
    sh_ artifact add localhost/e2e/b "$F/one.txt" > /dev/null
    sh_ artifact rm localhost/e2e/a > /dev/null
    check "$w: rm" "localhost/e2e/b" "$(sh_ artifact ls --format '{{.Repository}}' 2>&1)"
    sh_ artifact rm localhost/e2e/nosuch > /dev/null 2>&1
    check "$w: rm of nothing fails" 125 $?
    sh_ artifact rm -i localhost/e2e/nosuch > /dev/null 2>&1
    check "$w: rm -i of nothing" 0 $?
    sh_ artifact rm -a > /dev/null
    check "$w: rm -a" "" "$(sh_ artifact ls -q 2>&1)"
    check "$w: the blobs went with them" 0 \
        "$(find "$XDG_DATA_HOME" -path '*/artifacts/blobs/sha256/*' -type f | wc -l)"
}

registry_commands () { # where
    local w=$1 ref digest out
    ref=$E2E_REGISTRY/e2e-artifact/$w-$RUNID:v1
    sh_ artifact add --type application/x-e2e "$ref" "$F/one.txt" "$F/two.bin" > /dev/null
    digest=$(sh_ artifact inspect --format '{{.Digest}}' "$ref")
    sh_ artifact push --tls-verify=false --digestfile "$WORKDIR/pushed" "$ref" 2> "$WORKDIR/push.err"
    check "$w: push" 0 $?
    check "$w: push --digestfile" "$digest" "$(cat "$WORKDIR/pushed" 2>&1)"
    sh_ artifact rm "$ref" > /dev/null
    out=$(sh_ artifact pull --tls-verify=false "$ref" 2> /dev/null)
    check "$w: pull" "${digest#sha256:}" "$out"
    rm -rf "$WORKDIR/pulled" && mkdir "$WORKDIR/pulled"
    sh_ artifact extract "$ref" "$WORKDIR/pulled"
    check "$w: the files pulled" "first file" "$(cat "$WORKDIR/pulled/one.txt" 2>&1)"
    check "$w: the type pulled" "application/x-e2e" "$(sh_ artifact inspect --format '{{.Manifest.ArtifactType}}' "$ref" 2>&1)"
    sh_ artifact pull --tls-verify=false --retry 0 "$E2E_REGISTRY/e2e-artifact/nosuch:v1" > /dev/null 2>&1
    check "$w: pull of nothing fails" 125 $?
    sh_ artifact push --tls-verify=false localhost/e2e/nosuch > /dev/null 2>&1
    check "$w: push of nothing fails" 125 $?
    sh_ artifact rm "$ref" > /dev/null
}

mount_commands () { # where
    local w=$1 out
    local run=(sh_ run --rm --network none)
    sh_ artifact add localhost/e2e/single "$F/one.txt" > /dev/null
    sh_ artifact add localhost/e2e/multi "$F/one.txt" "$F/three.txt" > /dev/null
    check "$w: a file not in the image" "first file" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/single,dst=/test "$IMAGE" cat /test 2>&1)"
    check "$w: a directory of the image" "first file" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/single,dst=/tmp "$IMAGE" cat /tmp/one.txt 2>&1)"
    check "$w: a file of the image, through its link" "first file" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/single,dst=/etc/os-release "$IMAGE" cat /etc/os-release 2>&1)"
    check "$w: several files" "first file third" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/multi,dst=/data "$IMAGE" sh -c 'cat /data/one.txt /data/three.txt' 2>&1 | tr '\n' ' ' | sed 's/ $//')"
    check "$w: title" "third" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/multi,dst=/tmp,title=three.txt "$IMAGE" cat /tmp/three.txt 2>&1)"
    check "$w: name" "first file" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/single,dst=/tmp,name=abcd "$IMAGE" cat /tmp/abcd 2>&1)"
    check "$w: name of several files" "first file third" \
        "$("${run[@]}" --mount type=artifact,src=localhost/e2e/multi,dst=/x,name=f "$IMAGE" sh -c 'cat /x/f-0 /x/f-1' 2>&1 | tr '\n' ' ' | sed 's/ $//')"
    "${run[@]}" --mount type=artifact,src=localhost/e2e/single,dst=/test "$IMAGE" sh -c 'echo x > /test' > /dev/null 2>&1
    check "$w: read-only" 1 $?
    out=$("${run[@]}" --mount type=artifact,src=localhost/e2e/multi,dst=/etc/os-release "$IMAGE" true 2>&1)
    check "$w: several files on a file are refused" 125 $?
    check_match "$w: and it says so" "contains more than one blob" "$out"
    "${run[@]}" --mount type=artifact,src=localhost/e2e/nosuch,dst=/x "$IMAGE" true > /dev/null 2>&1
    check "$w: an artifact that is not there" 125 $?
    sh_ artifact rm -a > /dev/null
}

IMAGE=$E2E_REGISTRY/alpine:chunked

# no server: the engine of the command ----------------------------------

@test "engine: add, inspect, ls, extract and rm without a server" {
    local_commands engine
}

@test "engine: push and pull against the registry" {
    skip_unless_registry
    registry_commands engine
}

@test "engine: artifact mounts in a container" {
    skip_unless_registry
    sh_ pull -q "$IMAGE" > /dev/null
    mount_commands engine
}

# a server ---------------------------------------------------------------

@test "server: add, inspect, ls, extract and rm" {
    e2e_start_daemon
    e2e_start_api
    local_commands server
}

@test "server: push and pull against the registry" {
    skip_unless_registry
    registry_commands server
}

@test "server: artifact mounts in a container" {
    skip_unless_registry
    mount_commands server
}

# podman's remote client against the server ------------------------------

@test "podman --remote against the server" {
    command -v podman > /dev/null || skip "no podman"
    local out
    sh_ artifact add localhost/e2e/remote "$F/one.txt" > /dev/null
    out=$(podman --remote --url "unix://$SOCK" artifact ls --format '{{.Repository}}:{{.Tag}}' 2>&1)
    check "podman --remote artifact ls" "localhost/e2e/remote:latest" "$out"
    out=$(podman --remote --url "unix://$SOCK" artifact inspect --format '{{len .Manifest.Layers}}' localhost/e2e/remote 2>&1)
    check "podman --remote artifact inspect" 1 "$out"
    podman --remote --url "unix://$SOCK" artifact add localhost/e2e/remote2 "$F/three.txt" > /dev/null 2>&1
    check "podman --remote artifact add" "third" \
        "$(sh_ artifact extract localhost/e2e/remote2 "$WORKDIR/r2" && cat "$WORKDIR/r2")"
    if curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null; then
        out=$(podman --remote --url "unix://$SOCK" run --rm --network none \
            --mount type=artifact,src=localhost/e2e/remote,dst=/test "$IMAGE" cat /test 2>&1)
        check "podman --remote run --mount type=artifact" "first file" "$out"
    fi
    podman --remote --url "unix://$SOCK" artifact rm localhost/e2e/remote localhost/e2e/remote2 > /dev/null 2>&1
    check "podman --remote artifact rm" "" "$(sh_ artifact ls -q 2>&1)"
}
