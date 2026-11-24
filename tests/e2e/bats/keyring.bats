# SPDX-License-Identifier: Apache-2.0
# `[containers] keyring` (podman's `keyring`): by default the OCI runtime gives
# every container a session keyring of its own, which counts against the keys
# of the user (kernel.keys.maxkeys, 200 for a user: about 190 containers);
# `keyring = false` creates them with --no-new-keyring, they keep the session
# keyring of their monitor and take no key.  Checked with the arguments of the
# runtime (a log of its calls: the keys of a user are shared by all its
# containers on the host) for run, create + start, exec, restart, a restart
# policy, pods and their infra containers and the REST API; and the
# refusal of a runtime without the option.  As root a last test fills the key quota of a spare user and runs
# more containers than it leaves.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/keyring.bats   # as a user, or as root
#
# Skipped without crun, curl or the registry.

load helpers
load wait
load run_lib

# keyring_config VALUE|- [RUNTIME]: the configuration with [containers]
# keyring = VALUE (- for none) and the runtime, the daemon restarted on it
keyring_config () {
    stop_daemon
    cp "$CONFIG.keyring-base" "$CONFIG"
    [ -z "${2:-}" ] || sed -i "s|^\[server\]\$|&\nruntime = \"$2\"|" "$CONFIG"
    [ "$1" = - ] || printf '[containers]\nkeyring = %s\n' "$1" >> "$CONFIG"
    start_daemon
}
create_calls () { grep ' create ' "$WORKDIR/runtime.log" | grep -c -- '--bundle'; }
create_calls_with_flag () { grep ' create ' "$WORKDIR/runtime.log" | grep -- '--bundle' | grep -c -- '--no-new-keyring'; }

setup_file () {
    run_setup_file
    cp "$CONFIG" "$CONFIG.keyring-base"
    # a runtime that logs its calls, then is crun
    cat > "$WORKDIR/logged-runtime" <<EOT
#!/bin/sh
echo "\$@" >> "$WORKDIR/runtime.log"
exec $(command -v crun) "\$@"
EOT
    chmod +x "$WORKDIR/logged-runtime"
}

teardown_file () {
    spare_cleanup
    run_teardown_file
}

# (a test that failed puts the configuration back before the daemon starts,
# and the spare user's containers, daemon and keys go first: the daemon is a
# job of the test, which the teardown of a failed test kills)
teardown () {
    spare_cleanup
    [ -n "${BATS_TEST_COMPLETED:-}${BATS_TEST_SKIPPED:-}" ] || cp "$CONFIG.keyring-base" "$CONFIG"
    run_test_teardown
}

# The keys a user owns (/proc/key-users) are shared by every container of
# the user on the host, so they are no measure for a test that runs beside
# other work: what each container is created with is read from the calls to
# the runtime instead, and the quota itself is tested as root with a spare uid.
# runtime_creates: the creations the runtime was asked for, and those that
# asked for no new session keyring
runtime_creates () { echo "$(create_calls) $(create_calls_with_flag)"; }

@test "by default every container gets a session keyring of its own" {
    keyring_config - "$WORKDIR/logged-runtime"
    : > "$WORKDIR/runtime.log"
    sh_ container run -d --name kr1 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container create --name kr2 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container start kr2 > /dev/null
    check "running" running "$(state_of kr2)"
    check "two creations, none without a keyring of its own" "2 0" "$(runtime_creates)"
    check "exec" yes "$(sh_ container exec kr1 echo yes)"
    sh_ container rm -f -t 0 kr1 kr2 > /dev/null
}

@test "keyring = false: run, create and start, exec and restart take no key" {
    keyring_config false "$WORKDIR/logged-runtime"
    : > "$WORKDIR/runtime.log"
    sh_ container run -d --name kr1 --network none "$IMAGE" sleep 1000 > /dev/null
    check "run" running "$(state_of kr1)"
    sh_ container create --name kr2 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container start kr2 > /dev/null
    check "create and start" running "$(state_of kr2)"
    check "no keyring for two containers" "2 2" "$(runtime_creates)"
    check "exec" yes "$(sh_ container exec kr1 echo yes)"
    sh_ container restart -t 0 kr1 > /dev/null
    check "restart" running "$(state_of kr1)"
    check "no keyring for a restart" "3 3" "$(runtime_creates)"
    sh_ container rm -f -t 0 kr1 kr2 > /dev/null
}

@test "keyring = false: the restart policy, pods and their infra take no key" {
    keyring_config false "$WORKDIR/logged-runtime"
    : > "$WORKDIR/runtime.log"
    sh_ container run -d --name kr3 --network none --restart always "$IMAGE" sh -c 'sleep 0.3' > /dev/null
    wait_restarts kr3 2 || e2e_die "kr3 was not restarted twice"
    check_match "the policy started it again, twice" '^[2-9]$' "$(sh_ container inspect --format '{{.RestartCount}}' kr3)"
    sh_ container stop -t 0 kr3 > /dev/null
    sh_ pod create --network none --name krpod > /dev/null
    sh_ container run -d --pod krpod --name kr4 "$IMAGE" sleep 1000 > /dev/null
    check "a member of a pod" running "$(state_of kr4)"
    read -r calls flagged <<< "$(runtime_creates)"
    check_match "the policy's starts, the members and the infra containers were created" '^([5-9]|[1-9][0-9]+)$' "$calls"
    check "none without --no-new-keyring, the infra containers included" "$calls" "$flagged"
    sh_ pod rm -f -t 0 krpod > /dev/null
    sh_ container rm -f -t 0 kr3 > /dev/null
}

@test "keyring = false: the REST API takes no key" {
    e2e_need_api
    keyring_config false "$WORKDIR/logged-runtime"
    : > "$WORKDIR/runtime.log"
    id=$(curl -s --unix-socket "$SOCK" -X POST -H 'Content-Type: application/json' \
        -d '{"image":"'"$IMAGE"'","name":"kr5","command":["sleep","1000"],"netns":{"nsmode":"none"}}' \
        http://d/v5.0.0/libpod/containers/create | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["Id"])')
    check "a container is made" 64 ${#id}
    curl -s --unix-socket "$SOCK" -X POST "http://d/v5.0.0/libpod/containers/kr5/start" > /dev/null
    check "and runs" running "$(state_of kr5)"
    check "no keyring of its own" "1 1" "$(runtime_creates)"
    sh_ container rm -f -t 0 kr5 > /dev/null
}

# (the RUN steps of a build do not read `keyring`: as buildah's, a rootless
# one always has --no-new-keyring and a root one never)
@test "the RUN steps of a build: --no-new-keyring when rootless, never as root, whatever keyring says" {
    local ctx=$WORKDIR/kr-build want=1
    [ "$(id -u)" != 0 ] || want=0
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN true\n' "$IMAGE" > "$ctx/Containerfile"
    for v in true false; do
        keyring_config "$v" "$WORKDIR/logged-runtime"
        : > "$WORKDIR/runtime.log"
        sh_ image build -q --no-cache -t localhost/kr-build:1 "$ctx" > /dev/null
        check "one RUN container (keyring = $v)" 1 "$(create_calls)"
        check "its --no-new-keyring (keyring = $v)" "$want" "$(create_calls_with_flag)"
    done
    sh_ image rm -f localhost/kr-build:1 > /dev/null 2>&1 || true
}

@test "the runtime gets --no-new-keyring in create when the option is off, and never otherwise" {
    for v in - true false; do
        keyring_config "$v" "$WORKDIR/logged-runtime"
        : > "$WORKDIR/runtime.log"
        sh_ container run -d --name kr6 --network none "$IMAGE" sleep 1000 > /dev/null
        sh_ container rm -f -t 0 kr6 > /dev/null
        check "create calls ($v)" 1 "$(create_calls)"
        if [ "$v" = false ]; then
            check "the flag with false" 1 "$(create_calls_with_flag)"
        else
            check "no flag ($v)" 0 "$(create_calls_with_flag)"
        fi
    done
}

@test "keyring = false is refused by name for a runtime without the option" {
    # (a runtime whose features do not list the run.oci. annotations and
    # whose `create --help` has no --no-new-keyring: it is crun otherwise)
    cat > "$WORKDIR/youki" <<EOT
#!/bin/sh
case "\$*" in
features) echo '{"potentiallyUnsafeConfigAnnotations":["bundle"]}' ;;
"create --help") echo "usage: create [--bundle DIR]" ;;
*) exec $(command -v crun) "\$@" ;;
esac
EOT
    chmod +x "$WORKDIR/youki"
    keyring_config true "$WORKDIR/youki"
    sh_ container run --rm --network none "$IMAGE" true && rc=0 || rc=$?
    check "with the default the runtime is used" 0 "$rc"
    keyring_config false "$WORKDIR/youki"
    out=$(sh_ container run --rm --network none "$IMAGE" true 2>&1) && rc=0 || rc=$?
    check "with false it is refused" 125 "$rc"
    check_match "and the option and the runtime are named" 'keyring = false.*--no-new-keyring.*youki' "$out"
    # (the RUN steps of a rootless build ask for no option: such a runtime
    # makes them a keyring, it does not refuse them)
    local ctx=$WORKDIR/kr-youki
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN true\n' "$IMAGE" > "$ctx/Containerfile"
    keyring_config - "$WORKDIR/youki"
    sh_ image build -q --no-cache -t localhost/kr-youki:1 "$ctx" > /dev/null \
        || e2e_die "a RUN step under a runtime without --no-new-keyring"
    sh_ image rm -f localhost/kr-youki:1 > /dev/null
}

# runc has `create --no-new-keyring` as crun does, without crun's other
# options: keyring = false is not refused for it
@test "keyring = false works with runc" {
    command -v runc > /dev/null || skip "no runc"
    cat > "$WORKDIR/logged-runc" <<EOT
#!/bin/sh
echo "\$@" >> "$WORKDIR/runtime.log"
exec $(command -v runc) "\$@"
EOT
    chmod +x "$WORKDIR/logged-runc"
    keyring_config false "$WORKDIR/logged-runc"
    : > "$WORKDIR/runtime.log"
    sh_ container run -d --name kr7 --network none "$IMAGE" sleep 1000 > /dev/null || e2e_die "run under runc with keyring = false"
    check "runc runs it" running "$(state_of kr7)"
    check "created with --no-new-keyring" "1 1" "$(runtime_creates)"
    sh_ container restart -t 0 kr7 > /dev/null
    check "and again after a restart" running "$(state_of kr7)"
    check "with it" "2 2" "$(runtime_creates)"
    sh_ container rm -f -t 0 kr7 > /dev/null
}

# A spare user (E2E_SPARE_UID: no account, no process, at most the two keyrings
# the kernel keeps for a uid once used) whose key quota is nearly used up by
# keys of its own: the containers of the default run out of it, those of
# keyring = false do not.  root only: the user has no subuid range, its
# containers map one id.  Its files are in a directory of their own (SPARE_DIR,
# not below WORKDIR, which must stay accessible to root only), removed with
# its containers, its daemon and its keys after the test, failed or not.
SPARE_UID=${E2E_SPARE_UID:-61001}
SPARE_QUOTA_LEFT=8
SPARE_DIR_FILE_NAME=spare-dir
# SPARE: the command prefix that runs a command as the spare user
spare_prefix () {
    local w=$SPARE_DIR
    SPARE=(setpriv --reuid "$SPARE_UID" --regid "$SPARE_UID" --clear-groups
        env HOME="$w/home" XDG_RUNTIME_DIR="$w/run" XDG_CONFIG_HOME="$w/home/.config"
        XDG_DATA_HOME="$w/home/data" VELARX_REGISTRIES_CONF="$HOME/.config/velarx/registries.conf")
}
spare () { spare_prefix; "${SPARE[@]}" "$@" 3>&-; }
spare_velarx () { spare "$BIN/velarx" --config "$SPARE_DIR/config.toml" --socket "$SPARE_DIR/run/e.sock" "$@"; }
spare_daemon () { # keyring
    local w=$SPARE_DIR
    spare_daemon_stop
    cat > "$w/config.toml" <<EOT
storage.root = "$w/store"
[engine]
socket = "$w/run/e.sock"
[server]
socket = "$w/run/a.sock"
state_dir = "$w/run/velarx"
root_dir = "$w/store"
[containers]
keyring = $1
EOT
    chown "$SPARE_UID" "$w/config.toml"
    spare_prefix
    rm -f "$w/run/e.sock"
    setsid "${SPARE[@]}" "$BIN/velarx" --config "$w/config.toml" varlink >> "$w/daemon.log" 2>&1 3>&- &
    echo $! > "$w/daemon.pid"
    # (the socket of the engine, which was removed above, unless the daemon ends first)
    e2e_wait_path_of "$w/run/e.sock" "$(cat "$w/daemon.pid")" 30 && spare_velarx image list > /dev/null 2>&1 && return 0
    cat "$w/daemon.log" >&2
    exit 1
}
spare_daemon_stop () {
    local pid
    pid=$(cat "$SPARE_DIR/daemon.pid" 2> /dev/null)
    [ -n "$pid" ] || return 0
    kill -INT "$pid" 2> /dev/null
    # (it ends after its shutdown timeout at the latest, 30 s by default)
    e2e_wait_exit "$pid" 120 || e2e_die "the engine of the spare user did not end"
    rm -f "$SPARE_DIR/daemon.pid"
}
spare_keyring_drop () {
    [ -z "$SPARE_DIR" ] || {
        # (a test that ended half way left keys of the user: all of them go, it is a spare uid)
        spare keyctl clear @u > /dev/null 2>&1
        rm -f "$SPARE_DIR/ring"
    }
}
# spare_cleanup: the containers, daemon, keys and files of the spare user, if any
spare_cleanup () {
    local c
    SPARE_DIR=$(cat "$WORKDIR/$SPARE_DIR_FILE_NAME" 2> /dev/null)
    [ -n "$SPARE_DIR" ] || return 0
    for c in $(spare_velarx container list -a -q 2> /dev/null); do
        spare_velarx container rm -f -t 0 "$c" > /dev/null 2>&1
    done
    spare_daemon_stop
    spare_keyring_drop
    e2e_detach_mounts "$SPARE_DIR"
    rm -rf "$SPARE_DIR" "$WORKDIR/$SPARE_DIR_FILE_NAME"
    SPARE_DIR=
    return 0
}
spare_keys () { awk -v u="$SPARE_UID:" '$1 == u { split($4, a, "/"); print a[1] }' /proc/key-users; }

@test "as root: with keyring = false more containers run than the key quota of a user leaves" {
    skip_unless_root
    command -v setpriv > /dev/null && command -v keyctl > /dev/null || skip "needs setpriv and keyctl"
    # never a real user: no account, no process, no key but the kernel's two keyrings
    ! getent passwd "$SPARE_UID" > /dev/null || skip "uid $SPARE_UID has an account: set E2E_SPARE_UID to a spare one"
    [ -z "$(ps -u "$SPARE_UID" -o pid= 2> /dev/null)" ] || skip "uid $SPARE_UID runs processes: set E2E_SPARE_UID"
    [ "$(spare_keys)" -le 2 ] 2> /dev/null || [ -z "$(spare_keys)" ] || skip "uid $SPARE_UID owns keys: set E2E_SPARE_UID"
    SPARE_DIR=$(mktemp -d /var/tmp/velarx-e2e-keyring-spare.XXXXXX)
    echo "$SPARE_DIR" > "$WORKDIR/$SPARE_DIR_FILE_NAME"
    w=$SPARE_DIR
    mkdir -p "$w/home" "$w/run" "$w/store"
    chown -R "$SPARE_UID" "$w"
    chmod 700 "$w/run"
    # an image of root's files: the user maps one id
    e2e_make_image keyring-spare > /dev/null
    spare_daemon true
    install -o "$SPARE_UID" -m 600 "$WORKDIR/rootfs.tar" "$w/rootfs.tar"
    spare_velarx image import "$w/rootfs.tar" keyring-spare > /dev/null || e2e_die "image import"
    # the quota of keys, nearly used up by keys that are not the containers'
    max=$(cat /proc/sys/kernel/keys/maxkeys)
    # (in a session of its own; the keyring of the keys, one more key, is linked to the user keyring and stays)
    spare keyctl session - sh -c '
        r=$(keyctl newring fill @s) || exit 1
        i=0
        while [ "$i" -lt '"$((max - $(spare_keys) - SPARE_QUOTA_LEFT - 2))"' ]; do
            keyctl add user "f$i" x "$r" > /dev/null || exit 1
            i=$((i + 1))
        done
        keyctl link "$r" @u && echo "$r" > '"$w"'/ring' > /dev/null || e2e_die "the keys of the user"
    left=$((max - $(spare_keys)))
    check_match "the quota leaves a few keys" '^[1-9]$|^1[0-2]$' "$left"
    n=$((left + 4))
    ok=0
    for i in $(seq $n); do
        out=$(spare_velarx container run -d --name "q$i" --network none keyring-spare sleep 1000 2>&1) && ok=$((ok + 1))
    done
    check "by default the quota stops the containers" 1 "$(test "$ok" -lt "$n" && echo 1)"
    check_match "and says why" 'Disk quota exceeded' "$out"
    for i in $(seq $n); do spare_velarx container rm -f -t 0 "q$i" > /dev/null 2>&1; done
    spare_daemon false
    held=$(spare_keys)
    ok=0
    for i in $(seq $n); do
        spare_velarx container run -d --name "q$i" --network none keyring-spare sleep 1000 > /dev/null 2>&1 && ok=$((ok + 1))
    done
    check "with keyring = false all of them run" "$n" "$ok"
    check "and they took no key" 1 "$(test "$(spare_keys)" -le "$held" && echo 1)"
    spare_cleanup
}
