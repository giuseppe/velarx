# SPDX-License-Identifier: Apache-2.0
# push, tags, search, login and the remote inspection through the registry
# fetcher, with the engine of the command (no server): the commands do what
# they did, and the process of the command opens no connection to the
# registry.  Against the registry of the e2e (E2E_REGISTRY, default
# localhost:5000, which takes pushes); the login tests need a registry that
# wants credentials (E2E_AUTH_REGISTRY, with E2E_AUTH_USER and E2E_AUTH_PASSWORD).
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/fetcher-remote.bats

load helpers


# (no daemon: the engine of each command)
sc () { "$SH" "$@"; }

setup_file () {
    e2e_setup_file
    chmod 700 "$XDG_RUNTIME_DIR"
    {
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY"
        [ -z "${E2E_AUTH_REGISTRY:-}" ] || printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_AUTH_REGISTRY"
    } > "$XDG_CONFIG_HOME/velarx/registries.conf"
    export VELARX_REGISTRIES_CONF=$XDG_CONFIG_HOME/velarx/registries.conf
    # (the repositories of the pushes are of this run only)
    export REPO=e2e183-$$
    curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null || return 0
    e2e_make_image localhost/e2e-base:1
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    stop_dirsink
    . "$E2E_DIR/cleanup.sh"
    if [ -z "${E2E_KEEP:-}" ]; then
        e2e_remove_workdir "$WORKDIR"
    else
        echo "# kept $WORKDIR" >&3
    fi
}

# (no daemon: the engine of each command)
sh_ () { "$SH" "$@"; }
skip_unless_registry () {
    curl -s --max-time 2 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
}
skip_unless_auth_registry () {
    [ -n "${E2E_AUTH_REGISTRY:-}" ] || skip "no registry with credentials (E2E_AUTH_REGISTRY)"
}

@test "push goes through the fetcher and the image is pulled back" {
    skip_unless_registry
    out=$(sh_ push localhost/e2e-base:1 "$E2E_REGISTRY/$REPO:v1" 2>&1)
    check_match "push: the digest of the manifest" 'sha256:[0-9a-f]{64}' "$out"
    run sh_ pull "$E2E_REGISTRY/$REPO:v1"
    check "pull back" 0 "$status"
    run sh_ image exists "$E2E_REGISTRY/$REPO:v1"
    check "the image is in the store" 0 "$status"
}

@test "a push to a repository mounts or finds the blobs it has" {
    skip_unless_registry
    sh_ push localhost/e2e-base:1 "$E2E_REGISTRY/$REPO:v2" > /dev/null 2>&1
    out=$(sh_ push localhost/e2e-base:1 "$E2E_REGISTRY/$REPO-copy:v1" 2>&1)
    check_match "second push, other repository" 'sha256:[0-9a-f]{64}' "$out"
}

# An external pusher (examples/dirsink.rs) and a configuration that names it;
# its pid is in $WORKDIR/dirsink.pid, and it has said READY=1 when this returns.
start_dirsink () {
    local bin=$BIN/examples/dirsink
    [ -x "$bin" ] || skip "no $bin (cargo build --example dirsink)"
    mkdir -p "$WORKDIR/sinkdir" "$WORKDIR/sinksock"
    chmod 700 "$WORKDIR/sinksock"
    python3 -I - "$bin" "$WORKDIR/sinksock/sink.sock" "$WORKDIR/sinkdir" "$WORKDIR/dirsink.pid" "$WORKDIR/notify.sock" <<'PY'
import os, socket, subprocess, sys
exe, sock, directory, pidfile, notify = sys.argv[1:]
ready = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
ready.bind(notify)
child = subprocess.Popen([exe, sock, directory], env={**os.environ, "NOTIFY_SOCKET": notify}, start_new_session=True)
if ready.recv(64) != b"READY=1":
    sys.exit("dirsink did not say READY=1")
open(pidfile, "w").write(str(child.pid))
PY
    cp "$XDG_CONFIG_HOME/velarx/config.toml" "$WORKDIR/sinks.toml"
    printf '\n[[sinks.external]]\nname = "dirsink"\nsocket = "%s"\n' "$WORKDIR/sinksock/sink.sock" >> "$WORKDIR/sinks.toml"
}

stop_dirsink () {
    [ -f "$WORKDIR/dirsink.pid" ] || return 0
    kill -TERM "$(cat "$WORKDIR/dirsink.pid")" 2> /dev/null
    e2e_wait_exit "$(cat "$WORKDIR/dirsink.pid")"
    rm -f "$WORKDIR/dirsink.pid"
}

@test "push --sinks and manifest push --sinks: a helper sink is asked first, the destination's own pusher places" {
    skip_unless_registry
    start_dirsink
    local sh="$BIN/velarx --config $WORKDIR/sinks.toml" tar=$WORKDIR/sinkimg.tar
    # (an image whose blobs no repository has: the sink is asked for them)
    mkdir -p "$WORKDIR/sinkroot"
    echo "sink $$ $RANDOM $(date +%s%N)" > "$WORKDIR/sinkroot/unique"
    tar -C "$WORKDIR/sinkroot" -cf "$tar" .
    $sh image import "$tar" localhost/e2e-sink:1 > /dev/null
    out=$($sh push --sinks dirsink localhost/e2e-sink:1 "$E2E_REGISTRY/$REPO-sink:1" 2>&1)
    check_match "the push says the digest" 'sha256:[0-9a-f]{64}' "$out"
    local digest
    digest=$(sed -n 's/.*\(sha256:[0-9a-f]\{64\}\).*/\1/p' <<< "$out" | head -n 1)
    run sh_ pull "$E2E_REGISTRY/$REPO-sink:1"
    check "the registry has the image" 0 "$status"
    check_match "the sink was told of the commit, by the manifest's digest" "\"digest\":\"$digest\"" "$(cat "$WORKDIR/sinkdir/${digest/:/-}.json")"
    # the same sink, a second destination: another repository of the
    # registry, and a path (the sink places nothing, so nothing it said can
    # be false at another destination)
    run $sh push --sinks dirsink localhost/e2e-sink:1 "$E2E_REGISTRY/$REPO-sink2:1"
    check "a second push to another repository" 0 "$status"
    mkdir -p "$WORKDIR/sinklayout"
    run $sh push --sinks dirsink localhost/e2e-sink:1 "oci:$WORKDIR/sinklayout:one"
    check "a push to a layout" 0 "$status"
    check_match "the layout has the image" 'one' "$(cat "$WORKDIR/sinklayout/index.json")"
    # (the config's own list, a path, and no --sinks)
    printf '\n[push]\nsinks = ["dirsink"]\n' >> "$WORKDIR/sinks.toml"
    mkdir -p "$WORKDIR/sinklayout2"
    run $sh push localhost/e2e-sink:1 "oci:$WORKDIR/sinklayout2:one"
    check "[push] sinks serves a path" 0 "$status"
    run $sh push localhost/e2e-sink:1 "$E2E_REGISTRY/$REPO-sink3:1"
    check "and a registry" 0 "$status"
    run $sh push --sinks registry localhost/e2e-sink:1 "$E2E_REGISTRY/$REPO-sink:2"
    check "the destination's own pusher is not a sink" 125 "$status"
    check_match "and the engine says so" "destination's own pusher" "$output"
    run $sh push --sinks nosuch localhost/e2e-sink:1 "$E2E_REGISTRY/$REPO-sink:2"
    check "an undefined sink is refused" 125 "$status"
    check_match "and named" "nosuch" "$output"
    $sh manifest create "$REPO-list" > /dev/null
    $sh manifest add --tls-verify=false "$REPO-list" "$E2E_REGISTRY/$REPO-sink:1" > /dev/null
    run $sh manifest push --sinks dirsink "$REPO-list" "$E2E_REGISTRY/$REPO-list-sink:v1"
    check "the list is pushed" 0 "$status"
    $sh manifest rm "$REPO-list" > /dev/null
    stop_dirsink
}

@test "search lists the repositories and --list-tags the tags" {
    skip_unless_registry
    out=$(sh_ search --list-tags "$E2E_REGISTRY/$REPO" 2>&1)
    check_match "the tags" "$REPO +v1" "$out"
    check_match "the other tag" "$REPO +v2" "$out"
    out=$(sh_ search --limit 100 --format '{{.Name}}' "$E2E_REGISTRY/$REPO" 2>&1) || true
    check_match "the repository" "$E2E_REGISTRY/$REPO" "$out"
}

@test "the manifest of the remote image is inspected" {
    skip_unless_registry
    out=$(sh_ manifest inspect "$E2E_REGISTRY/$REPO:v1" 2>&1)
    check_match "a manifest" '"schemaVersion": *2' "$out"
}

@test "a refused repository is an error, in the words of the registry" {
    skip_unless_registry
    run sh_ search --list-tags "$E2E_REGISTRY/$REPO-nosuch"
    check "no such repository" 125 "$status"
}

@test "login checks the credentials at the registry and the CLI writes the auth file" {
    skip_unless_auth_registry
    export REGISTRY_AUTH_FILE=$WORKDIR/auth.json
    run sh_ login --username "$E2E_AUTH_USER" --password-stdin "$E2E_AUTH_REGISTRY" <<< "wrong-$E2E_AUTH_PASSWORD"
    check "a wrong password is refused" 125 "$status"
    check_match "in podman's words" 'invalid username/password' "$output"
    [ ! -e "$REGISTRY_AUTH_FILE" ] || e2e_die "an auth file after a refused login"
    run sh_ login --username "$E2E_AUTH_USER" --password-stdin "$E2E_AUTH_REGISTRY" <<< "$E2E_AUTH_PASSWORD"
    check "login" 0 "$status"
    check "login prints" "Login Succeeded!" "$output"
    check_match "the CLI wrote the auth file" '"auths"' "$(cat "$REGISTRY_AUTH_FILE")"
    # the stored credentials are the fetcher's to use
    out=$(sh_ push localhost/e2e-base:1 "$E2E_AUTH_REGISTRY/$REPO:v1" 2>&1)
    check_match "push with the stored credentials" 'sha256:[0-9a-f]{64}' "$out"
    out=$(sh_ search --list-tags "$E2E_AUTH_REGISTRY/$REPO" 2>&1)
    check_match "tags with the stored credentials" "$REPO +v1" "$out"
    run sh_ logout "$E2E_AUTH_REGISTRY"
    check "logout" 0 "$status"
    run sh_ search --list-tags "$E2E_AUTH_REGISTRY/$REPO"
    check "without the credentials" 125 "$status"
    # credentials of the command itself
    out=$(sh_ search --list-tags --creds "$E2E_AUTH_USER:$E2E_AUTH_PASSWORD" "$E2E_AUTH_REGISTRY/$REPO" 2>&1)
    check_match "tags with --creds" "$REPO +v1" "$out"
    # a pull with credentials of the command is made by the fetcher too
    run sh_ pull --creds "$E2E_AUTH_USER:wrong-$E2E_AUTH_PASSWORD" "$E2E_AUTH_REGISTRY/$REPO:v1"
    check "a pull with a wrong password" 125 "$status"
    run sh_ pull --creds "$E2E_AUTH_USER:$E2E_AUTH_PASSWORD" "$E2E_AUTH_REGISTRY/$REPO:v1"
    check "a pull with --creds" 0 "$status"
    run sh_ image exists "$E2E_AUTH_REGISTRY/$REPO:v1"
    check "the image is in the store" 0 "$status"
}
