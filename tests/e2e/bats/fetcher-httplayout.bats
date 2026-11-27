# SPDX-License-Identifier: Apache-2.0
# An OCI image layout published as static files over HTTP is an origin of
# pulls by `oci+http://` (examples/httplayout.rs, the `command` of a
# [[transports]] entry): a layout pushed with `oci:` and served by a plain
# web server is pulled into a store of its own, by the tag of its entry.
# Rootless, no registry, no daemon (the engine of each command).
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/fetcher-httplayout.bats

load helpers

setup_file () {
    e2e_setup_file
    [ -x "$BIN/examples/httplayout" ] || skip "no $BIN/examples/httplayout (cargo build --example httplayout)"
    chmod 700 "$XDG_RUNTIME_DIR"
    mkdir -p "$WORKDIR/files" "$WORKDIR/srv"
    head -c 100000 /dev/urandom > "$WORKDIR/files/a"
    tar -C "$WORKDIR/files" -cf "$WORKDIR/files.tar" a
    "$SH" image import "$WORKDIR/files.tar" localhost/e2e-layout:1 > /dev/null
    "$SH" image push --compression-format gzip localhost/e2e-layout:1 "oci:$WORKDIR/srv/layout:v1" > /dev/null
    "$SH" image inspect --format '{{.Id}}' localhost/e2e-layout:1 > "$WORKDIR/id"
    ( setsid python3 -I -u -m http.server --bind 127.0.0.1 --directory "$WORKDIR/srv" 0 \
          < /dev/null > "$WORKDIR/http.out" 2> /dev/null 3>&- &
      echo $! > "$WORKDIR/http.pid" )
    e2e_wait_content "$WORKDIR/http.out" 'port [0-9]+' 10
    sed -E 's/.* port ([0-9]+) .*/\1/' "$WORKDIR/http.out" > "$WORKDIR/http.port"
    # a store of its own: it has nothing
    cat > "$WORKDIR/layout.toml" <<TOML
storage.root = "$WORKDIR/store"
[engine]
socket = "$WORKDIR/layout.sock"
[server]
socket = "$WORKDIR/layout.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[[transports]]
scheme = "oci+http"
command = ["$BIN/examples/httplayout"]
TOML
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    [ ! -f "$WORKDIR/http.pid" ] || kill "$(cat "$WORKDIR/http.pid")" 2> /dev/null
    . "$E2E_DIR/cleanup.sh"
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

@test "a layout served over HTTP is pulled by the tag of its entry" {
    local url=oci+http://127.0.0.1:$(cat "$WORKDIR/http.port")/layout
    run "$BIN/velarx" --config "$WORKDIR/layout.toml" pull "$url:v1"
    check "the pull" 0 "$status"
    check "it is the image that was pushed" "$(cat "$WORKDIR/id")" "${lines[-1]}"
    run "$BIN/velarx" --config "$WORKDIR/layout.toml" image exists "${lines[-1]}"
    check "the image is in the store" 0 "$status"
}

@test "a tag the layout does not have fails the pull" {
    local url=oci+http://127.0.0.1:$(cat "$WORKDIR/http.port")/layout
    run "$BIN/velarx" --config "$WORKDIR/layout.toml" pull "$url:nope"
    [ "$status" -ne 0 ] || e2e_die "a tag the layout lacks was pulled"
    check_match "and says why" '0 images' "$output"
}
