# SPDX-License-Identifier: Apache-2.0
# A content source that is a `command` (examples/dircache.rs): the engine
# starts it for the pull with the connection to it as its descriptor 3, the
# layers of the pull come from it (the registry, behind a proxy that logs
# what it served, is asked for the manifest only), and the process is gone
# when the command that pulled ends.  Rootless, against E2E_REGISTRY, no
# daemon (the engine of each command).
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/fetcher-command.bats
#
# What the test waits for is the end of the process, never a time: the
# command of the source is a script that runs dircache as its child and then
# writes to a fifo the test reads, so the read returns when dircache has
# ended (and does not return while it runs).

load helpers

# (no daemon: the engine of each command)
sc () { "$SH" "$@"; }

setup_file () {
    e2e_setup_file
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    [ -x "$BIN/examples/dircache" ] || skip "no $BIN/examples/dircache (cargo build --example dircache)"
    chmod 700 "$XDG_RUNTIME_DIR"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$XDG_CONFIG_HOME/velarx/registries.conf"
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf
    export REPO=e2e-command-$$
    # an image of two files of random bytes (they do not compress) as a layer
    # of zstd:chunked: dircache serves the chunks of such a layer, named by
    # their digests, which its table of contents lists.  The files are in
    # the tar in an order that is not the canonical one, so the layer has no
    # binary table, which dircache does not read.
    mkdir -p "$WORKDIR/files" "$WORKDIR/cache"
    head -c 1000000 /dev/urandom > "$WORKDIR/files/z"
    head -c 1000000 /dev/urandom > "$WORKDIR/files/a"
    tar -C "$WORKDIR/files" -cf "$WORKDIR/files.tar" z a
    sc image import "$WORKDIR/files.tar" localhost/e2e-files:1 > /dev/null
    sc push --compression-format zstd:chunked localhost/e2e-files:1 "$E2E_REGISTRY/$REPO:v1" > /dev/null
    local base=http://$E2E_REGISTRY/v2/$REPO position
    curl -sf -H 'Accept: application/vnd.oci.image.manifest.v1+json' "$base/manifests/v1" > "$WORKDIR/manifest.json"
    position=$(jq -r '.layers[0].annotations["io.github.containers.zstd-chunked.manifest-position"]' "$WORKDIR/manifest.json")
    curl -sf -r "${position%%:*}-$(( ${position%%:*} + $(cut -d: -f2 <<< "$position") - 1 ))" \
        "$base/blobs/$(jq -r '.layers[0].digest' "$WORKDIR/manifest.json")" | zstd -dc > "$WORKDIR/toc.json"
    local name offset size digest
    while IFS=$'\t' read -r name offset size digest; do
        dd if="$WORKDIR/files/${name#./}" of="$WORKDIR/cache/${digest#sha256:}" bs=1M iflag=skip_bytes,count_bytes \
            skip="$offset" count="$size" status=none
    done < <(jq -r '.entries[] | select(.chunkDigest) | [.name, (.chunkOffset // 0), .chunkSize, .chunkDigest] | @tsv' "$WORKDIR/toc.json")
    # the pull goes through a registry that logs what it served
    ( setsid python3 -I "$E2E_DIR/registry_log.py" "$E2E_REGISTRY" "$WORKDIR/registry.log" > "$WORKDIR/registry.port" 2> /dev/null 3>&- &
      echo $! > "$WORKDIR/registry.pid" )
    e2e_wait_content "$WORKDIR/registry.port" '[0-9]' 10
    printf '[[registry]]\nlocation = "127.0.0.1:%s"\ninsecure = true\n' "$(cat "$WORKDIR/registry.port")" > "$WORKDIR/proxy.conf"
    mkfifo "$WORKDIR/gone"
    cat > "$WORKDIR/once" <<'SCRIPT'
#!/bin/sh
# once DIRCACHE CACHE WORKDIR: a use of the source, and its end
echo started >> "$3/starts"
"$1" "$2"
echo gone > "$3/gone"
SCRIPT
    chmod +x "$WORKDIR/once"
    # a store of its own: it has nothing
    cat > "$WORKDIR/command.toml" <<TOML
storage.root = "$WORKDIR/store"
[engine]
socket = "$WORKDIR/command.sock"
[server]
socket = "$WORKDIR/command.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[[sources.external]]
name = "dircache"
command = ["$WORKDIR/once", "$BIN/examples/dircache", "$WORKDIR/cache", "$WORKDIR"]
[pull]
sources = ["dircache", "registry"]
TOML
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    [ ! -f "$WORKDIR/registry.pid" ] || kill "$(cat "$WORKDIR/registry.pid")" 2> /dev/null
    # (a source that ended and waits to say so, after a test that failed)
    [ ! -p "$WORKDIR/gone" ] || : <> "$WORKDIR/gone"
    . "$E2E_DIR/cleanup.sh"
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

@test "a source that is a command serves a pull and is gone afterwards" {
    # (to a file: the source of a pull that ended may still be there, with
    # its standard error, and a pipe of `run` would wait for it)
    local ref=127.0.0.1:$(cat "$WORKDIR/registry.port")/$REPO:v1
    VELARX_REGISTRIES_CONF=$WORKDIR/proxy.conf "$BIN/velarx" --config "$WORKDIR/command.toml" pull "$ref" > "$WORKDIR/pull.out" 2>&1 ||
        { cat "$WORKDIR/pull.out"; e2e_die "the pull failed"; }
    run "$BIN/velarx" --config "$WORKDIR/command.toml" image exists "$ref"
    check "the image is in the store" 0 "$status"
    # the registry gave the manifest, and of the layer no more than its
    # table of contents: the files are the cache's
    check_match "the registry was asked for the manifest" 'manifests' "$(cat "$WORKDIR/registry.log")"
    local layer size served
    layer=$(jq -r '.layers[0].digest' "$WORKDIR/manifest.json")
    size=$(jq -r '.layers[0].size' "$WORKDIR/manifest.json")
    served=$(awk -v l="$layer" '$2 ~ l { n += $4 } END { print n + 0 }' "$WORKDIR/registry.log")
    [ $((served * 4)) -lt "$size" ] || e2e_die "the registry served $served of the $size bytes of the layer"
    local started i
    started=$(wc -l < "$WORKDIR/starts")
    [ "$started" -ge 1 ] || e2e_die "the command was not started"
    # one end for each start: each read returns when that process ended
    for i in $(seq "$started"); do
        check "a started process ended" "gone" "$(timeout 60 head -n 1 "$WORKDIR/gone")"
    done
}

@test "a config with a socket and a command for a source is refused" {
    printf '[[sources.external]]\nname = "x"\nsocket = "/s"\ncommand = ["/bin/true"]\n' > "$WORKDIR/both.toml"
    run "$BIN/velarx" --config "$WORKDIR/both.toml" image list
    [ "$status" -ne 0 ] || e2e_die "a source with both was accepted"
    check_match "and says why" 'one of them' "$output"
}
