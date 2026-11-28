# SPDX-License-Identifier: Apache-2.0
# The storage driver of a store: what `info` and `inspect` say of it (the
# name podman and Docker report, velarx's own, the data the driver gives), the
# choice by --storage-driver and [storage] driver (composefs, the only
# one), and the refusal of a store that was made with another driver.
# Rootless.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/storage-driver.bats

load helpers

sh_ () { "$BIN/velarx" --socket "$ESOCK" "$@"; }
# libpod: /v5.0.0/libpod/..., Docker: /v1.44/...
api () { curl -s --unix-socket "$SOCK" "http://d$1"; }
# the field of a JSON document, by the path of keys
field () { python3 -I -c 'import json,sys; d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k]
print(json.dumps(d) if not isinstance(d, str) else d)' "$1"; }
config_with () { # extra lines of [storage]
    cat > "$XDG_CONFIG_HOME/velarx/config.toml" <<EOT
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$WORKDIR/store"
check_leftover_age_secs = 0
$1
[pull]
EOT
}
stop_daemon () {
    local pid
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if test -n "$pid"; then
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid" 10
        kill -KILL "$pid" 2> /dev/null || true
        rm -f "$WORKDIR/daemon.pid"
    fi
}
# velarx on the private configuration, as an engine in this process
sh_cfg () { "$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" "$@"; }

setup_file () {
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    config_with ""
    e2e_start_daemon
    e2e_make_image
    e2e_start_api
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    sh_ container rm -f -t 0 c1 > /dev/null 2>&1
    e2e_teardown_file
}

@test "info: the graph driver as podman reports it, the driver by its own name" {
    out=$(sh_ info --format '{{.Store.GraphDriverName}}')
    check "graphDriverName" overlay "$out"
    out=$(sh_ info --format '{{.Store.StorageDriver}}')
    check "storageDriver, velarx's own" composefs "$out"
    out=$(sh_ info --format json | field store.graphStatus.composefs)
    check "the status is the driver's" yes "$out"
    # (nothing about the driver is said where nothing was asked)
    out=$(sh_ image list 2>&1 | grep -ci "driver")
    check "image list does not mention the driver" 0 "$out"
}

@test "the REST APIs: libpod and Docker info" {
    check "libpod info: graphDriverName" overlay "$(api /v5.0.0/libpod/info | field store.graphDriverName)"
    check "libpod info: storageDriver" composefs "$(api /v5.0.0/libpod/info | field store.storageDriver)"
    check "Docker info: Driver" overlay "$(api /v1.44/info | field Driver)"
    check_match "Docker info: DriverStatus is the driver's" '"composefs", "yes"' "$(api /v1.44/info | field DriverStatus)"
}

@test "inspect: GraphDriver comes from the driver" {
    sh_ container create --name c1 --network none "$IMG" sleep 100 > /dev/null
    check "container: name" overlay "$(sh_ container inspect --format '{{.GraphDriver.Name}}' c1)"
    out=$(api /v5.0.0/libpod/containers/c1/json)
    check "libpod container: Driver" overlay "$(printf '%s' "$out" | field Driver)"
    check "libpod container: GraphDriver.Name" overlay "$(printf '%s' "$out" | field GraphDriver.Name)"
    for key in UpperDir WorkDir MergedDir; do
        check_match "libpod container: $key" "^$WORKDIR/root/bundles/.*" "$(printf '%s' "$out" | field GraphDriver.Data.$key)"
    done
    check_match "the upper directory is the overlay's" "/overlay/upper$" "$(printf '%s' "$out" | field GraphDriver.Data.UpperDir)"
    check "Docker container: GraphDriver.Name" overlay "$(api /v1.44/containers/c1/json | field GraphDriver.Name)"
    check "image: name" overlay "$(sh_ image inspect --format '{{.GraphDriver.Name}}' "$IMG")"
    check "libpod image: name" overlay "$(api "/v5.0.0/libpod/images/$IMG/json" | field GraphDriver.Name)"
    check "Docker image: name" overlay "$(api "/v1.44/images/$IMG/json" | field GraphDriver.Name)"
    sh_ container rm -f -t 0 c1 > /dev/null
}

@test "system df -v names the driver's rows, system check and gc go through it" {
    out=$(sh_ system df -v)
    check_match "the rows of the store" "^Composefs +[0-9]+" "$out"
    check "a check of the store" 0 "$(sh_ system check > /dev/null 2>&1; echo $?)"
    check "a collection" 0 "$(sh_ system gc > /dev/null 2>&1; echo $?)"
    # a leftover of the driver is found by the check and removed by its repair
    mkdir -p "$WORKDIR/store/composefs"
    : > "$WORKDIR/store/composefs/.tmp-leftover"
    out=$(sh_ system check 2>&1 || true)
    check_match "the leftover is a problem" "stale_temp|temporary file of the composefs" "$out"
}

@test "--storage-driver: composefs is the driver, any other name is an error that says which one there is" {
    sh_cfg --storage-driver composefs image list > /dev/null 2>&1
    check "composefs" 0 $?
    local name
    for name in zfs vfs varlink overlay; do
        out=$(sh_cfg --storage-driver "$name" image list 2>&1)
        check "$name: refused" 125 $?
        check_match "$name: the one there is is named" "the storage driver \"$name\" is not available: this velarx has only \"composefs\"" "$out"
    done
}

@test "a [storage] driver other than composefs is refused at start, with the one there is" {
    stop_daemon
    local name
    for name in zfs vfs varlink; do
        config_with "driver = \"$name\""
        out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink 2>&1)
        check "$name: the daemon does not start" 125 $?
        check_match "$name: it says which one there is" "the storage driver \"$name\" is not available: this velarx has only \"composefs\" \\(\\[storage\\] driver" "$out"
    done
    config_with 'driver = "composefs"'
    e2e_start_daemon
    check "composefs starts" composefs "$(sh_ info --format '{{.Store.StorageDriver}}')"
}

@test "a store made with another driver is not opened" {
    stop_daemon
    local name
    for name in vfs zfs; do
        # a scratch store: its recorded driver is set by hand
        rm -rf "$WORKDIR/other"
        mkdir -p "$WORKDIR/other"
        cp "$WORKDIR/store/db.sqlite" "$WORKDIR/other/db.sqlite"
        sqlite3 "$WORKDIR/other/db.sqlite" "UPDATE store_settings SET value = '$name' WHERE key = 'driver'"
        config_with ""
        sed -i "s|^root = .*|root = \"$WORKDIR/other\"|" "$XDG_CONFIG_HOME/velarx/config.toml"
        out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink 2>&1)
        check "$name: the daemon does not open it" 125 $?
        check_match "$name: the error names the driver and the store" "the store $WORKDIR/other was made with the storage driver \"$name\", and this velarx has only \"composefs\"" "$out"
        check_match "$name: and says what to do" "use the velarx that made it, or remove the store" "$out"
        out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" image list 2>&1)
        check "$name: a command that serves the engine itself does not open it" 125 $?
        check_match "$name: with the same error" "was made with the storage driver \"$name\"" "$out"
    done
    # the database of the store of the file is as it was
    config_with ""
    e2e_start_daemon
    check "the store opens with its own driver" composefs "$(sh_ info --format '{{.Store.StorageDriver}}')"
    check "the driver is recorded in the store" composefs "$(sqlite3 "$WORKDIR/store/db.sqlite" "SELECT value FROM store_settings WHERE key = 'driver'")"
}

@test "a store of another shape: image ls, inspect and df fail with the message, not with wrong sizes" {
    stop_daemon
    cp "$WORKDIR/store/db.sqlite" "$WORKDIR/db.sqlite.good"
    # a store whose layers lack a column (a build of another shape)
    sqlite3 "$WORKDIR/store/db.sqlite" "ALTER TABLE layers DROP COLUMN diff_id_other"
    e2e_start_daemon
    for cmd in "image ls" "image inspect $IMG" "system df"; do
        rc=0
        out=$(sh_ $cmd 2>&1) || rc=$?
        check "$cmd: fails" 1 $((rc == 0 ? 0 : 1))
        check_match "$cmd: the operation and the SQL error" 'no such column: .*diff_id_other' "$out"
        check_match "$cmd: the remedy" 'the store was made by another build: remove it' "$out"
    done
    # the REST APIs: a 500 with the message
    code=$(curl -s -o "$WORKDIR/body" -w '%{http_code}' --unix-socket "$SOCK" "http://d/v5.0.0/libpod/images/json")
    check "libpod images/json: 500" 500 "$code"
    check_match "libpod: the message" 'the store was made by another build: remove it' "$(cat "$WORKDIR/body")"
    code=$(curl -s -o "$WORKDIR/body" -w '%{http_code}' --unix-socket "$SOCK" "http://d/v1.44/system/df")
    check "docker system/df: 500" 500 "$code"
    stop_daemon
    cp "$WORKDIR/db.sqlite.good" "$WORKDIR/store/db.sqlite"
    e2e_start_daemon
    out=$(sh_ image ls 2>&1)
    check "the store as it was lists" 0 $?
}
