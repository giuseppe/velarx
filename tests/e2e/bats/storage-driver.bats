# SPDX-License-Identifier: Apache-2.0
# The storage driver of a store: what `info` and `inspect` say of it (the
# name podman and Docker report, velarx's own, the data the driver gives), the
# choice by --storage-driver and [storage] driver, and the refusal of a
# store that was made with another driver.  Rootless.
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

@test "--storage-driver: composefs is the driver, an unknown name is an error that lists the known ones" {
    sh_cfg --storage-driver composefs image list > /dev/null 2>&1
    check "composefs" 0 $?
    out=$(sh_cfg --storage-driver zfs image list 2>&1)
    check "zfs: refused" 125 $?
    check_match "the known ones are listed" 'storage driver of this velarx \(known: composefs, vfs\)' "$out"
    out=$("$BIN/velarx" --storage-driver "" --socket "$ESOCK" image list 2>&1)
    check "the empty name chooses nothing" 0 $?
    out=$("$BIN/velarx" --storage-driver overlay --socket "$ESOCK" image list 2>&1)
    check "overlay, podman's name, chooses nothing" 0 $?
}

@test "an unknown [storage] driver is refused at start, with the known ones" {
    stop_daemon
    config_with 'driver = "zfs"'
    out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink 2>&1)
    check "the daemon does not start" 125 $?
    check_match "it says which key" '\[storage\] driver = "zfs" is not a storage driver of this velarx \(known: composefs, vfs\)' "$out"
}

@test "a store keeps the driver it was made with" {
    stop_daemon
    # the store was made above with composefs: another driver in its database
    config_with 'driver = "composefs"'
    sqlite3 "$WORKDIR/store/db.sqlite" "UPDATE store_settings SET value = 'zfs' WHERE key = 'driver'"
    out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink 2>&1)
    check "the daemon does not open it" 125 $?
    check_match "the error names both drivers" 'was made with the storage driver "zfs", but composefs is asked for' "$out"
    check_match "and says what to do" 'ask for "zfs", or remove the store' "$out"
    check_match "and which store" "$WORKDIR/store" "$out"
    # with nothing asked for, the store's own is wanted, and this build lacks it
    sqlite3 "$WORKDIR/store/db.sqlite" "UPDATE store_settings SET value = 'zfs' WHERE key = 'driver'"
    config_with ""
    out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" varlink 2>&1)
    check "the daemon does not open it either" 125 $?
    check_match "the store's driver is not one of the build's" 'was made with the storage driver "zfs", which this velarx does not have \(known: composefs, vfs\): use the velarx that made it, or remove the store' "$out"
    out=$("$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" --storage-driver composefs varlink 2>&1)
    check "--storage-driver is the same" 125 $?
    check_match "--storage-driver: the mismatch" 'was made with the storage driver "zfs", but composefs is asked for' "$out"
    # the database is as it was: the store opens again with its driver
    sqlite3 "$WORKDIR/store/db.sqlite" "UPDATE store_settings SET value = 'composefs' WHERE key = 'driver'"
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
