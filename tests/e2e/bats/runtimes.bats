# SPDX-License-Identifier: Apache-2.0
# The OCI runtime of a container: a name of [runtimes] (here a script that logs
# its calls and runs crun), asked for by `oci_runtime` of the libpod create, used for
# the whole life of the container (create, start, kill, state, delete) and for the
# members of a pod; the default one for the others.  Rootless, in a scratch HOME.
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/runtimes.bats
#
# Skipped without crun, curl or python3, or without the image.

load helpers

sh_ () { "$BIN/velarx" --config "$CONF" --socket "$ESOCK" "$@"; }
api () { curl -s --unix-socket "$SOCK" "$@"; }
create () { # body: the id of the container made, or the answer
    api -X POST -H 'Content-Type: application/json' -d "$1" http://d/v5.0.0/libpod/containers/create |
        python3 -I -c 'import json, sys; d = json.load(sys.stdin); print(d.get("Id") or d.get("message"))'
}
calls () { grep -c "$1" "$LOG" 2> /dev/null; }

setup_file () {
    local CRUN
    CRUN=$(command -v crun) || skip "no crun"
    command -v curl > /dev/null && command -v python3 > /dev/null || skip "needs curl and python3"
    e2e_setup_file
    export IMG=${IMAGE:-${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}}
    export CONF=$XDG_CONFIG_HOME/velarx/config.toml
    export LOG=$WORKDIR/runtime.log
    mkdir -p "$XDG_CONFIG_HOME/velarx"
    # a runtime of its own: it says what it is asked, then is crun
    cat > "$WORKDIR/logged-runtime" <<EOT
#!/bin/sh
echo "\$@" >> "$LOG"
exec $CRUN "\$@"
EOT
    chmod +x "$WORKDIR/logged-runtime"
    # and one that has options of its own ([runtimes.flagged] args)
    cat > "$WORKDIR/flagged-runtime" <<EOT
#!/bin/sh
echo "flagged \$@" >> "$LOG"
exec $CRUN "\$@"
EOT
    chmod +x "$WORKDIR/flagged-runtime"
    cat > "$CONF" <<EOT
$(e2e_bridge_toml)
[engine]
socket = "$ESOCK"
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/run/velarx"
root_dir = "$WORKDIR/root"
shutdown_timeout_secs = 5
[storage]
root = "$WORKDIR/storage"
[containers]
log_driver = "k8s-file"
[runtimes]
logged = "$WORKDIR/logged-runtime"
[runtimes.flagged]
path = "$WORKDIR/flagged-runtime"
args = ["--debug"]
EOT
    cat > "$XDG_CONFIG_HOME/velarx/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF="$XDG_CONFIG_HOME/velarx/registries.conf"
    e2e_start_daemon
    e2e_start_api
    sh_ image pull "$IMG" > "$WORKDIR/pull.log" 2>&1 || e2e_pull_failed "$IMG" "$WORKDIR/pull.log"
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    # (the runtime may be moved away by a test that failed)
    mv "$WORKDIR/logged-runtime.gone" "$WORKDIR/logged-runtime" 2> /dev/null
    e2e_remove_containers "$BIN/velarx" "$ESOCK"
    e2e_teardown_file
}

# what a test made is gone at its end, also when a check failed (the next one
# looks for "nothing" in the list)
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    mv "$WORKDIR/logged-runtime.gone" "$WORKDIR/logged-runtime" 2> /dev/null
    sh_ pod rm -f -t 0 rtpod > /dev/null 2>&1
    sh_ rm -f -t 0 rt1 rt2 rt3 rt4 rt5 rt6 rt7 rtm > /dev/null 2>&1
    return 0
}

@test "the runtimes of the engine are told, in libpod's and Docker's info" {
    check "the runtimes of the engine are told" '["flagged", "logged"]' "$(api http://d/v5.0.0/libpod/info | python3 -I -c 'import json, sys; print(json.dumps(json.load(sys.stdin)["host"]["ociRuntimes"]))')"
    check "and Docker's info lists them" 'crun flagged logged' "$(api http://d/v1.44/info | python3 -I -c 'import json, sys; print(" ".join(sorted(json.load(sys.stdin)["Runtimes"])))')"
}

# a container of the runtime of [runtimes]
@test "a container of a runtime of [runtimes] goes through it for its whole life" {
    id=$(create '{"image":"'"$IMG"'","name":"rt1","command":["sleep","300"],"oci_runtime":"logged"}')
    check "a container is made with a runtime of [runtimes]" 64 ${#id}
    sh_ start rt1 > /dev/null
    check "it runs" running "$(sh_ inspect rt1 --format '{{.State.Status}}')"
    check "its inspect says which" logged "$(sh_ inspect rt1 --format '{{.HostConfig.Runtime}}')"
    check "the runtime made it" 1 "$(test "$(grep -c "create.* $id\$" "$LOG")" -ge 1 && echo 1)"
    check "and started it" 1 "$(test "$(grep -c "start.* $id\$" "$LOG")" -ge 1 && echo 1)"
    sh_ kill -s USR1 rt1 > /dev/null
    sh_ stop -t 1 rt1 > /dev/null
    check "a stop too" exited "$(sh_ inspect rt1 --format '{{.State.Status}}')"
    sh_ rm rt1 > /dev/null
    check "the removal deletes it with the runtime" 1 "$(test "$(grep -c "delete.* $id\$" "$LOG")" -ge 1 && echo 1)"
}

# the options of one runtime are not those of the others
@test "[runtimes.NAME] args go to that runtime only" {
    id=$(create '{"image":"'"$IMG"'","name":"rt2","command":["sleep","300"],"oci_runtime":"flagged"}')
    check "a container is made with the runtime that has options" 64 ${#id}
    sh_ start rt2 > /dev/null
    check "it runs" running "$(sh_ inspect rt2 --format '{{.State.Status}}')"
    check "its runtime got its options before the command" 1 "$(test "$(grep -c "^flagged --debug .*create.* $id\$" "$LOG")" -ge 1 && echo 1)"
    other=$(create '{"image":"'"$IMG"'","name":"rt3","command":["sleep","300"],"oci_runtime":"logged"}')
    sh_ start rt3 > /dev/null
    check "another runtime got none of them" 0 "$(grep -c -e "--debug.* $other\$" "$LOG")"
}

@test "a container made with --runtime keeps it for the later commands" {
    "$BIN/velarx" --config "$CONF" run --runtime "$WORKDIR/logged-runtime" -d --name rt5 --network none "$IMG" sleep 300 > /dev/null
    id=$("$BIN/velarx" --config "$CONF" inspect rt5 --format '{{.Id}}')
    check "the runtime made it" 1 "$(test "$(grep -c "create.* $id\$" "$LOG")" -ge 1 && echo 1)"
    "$BIN/velarx" --config "$CONF" kill -s USR1 rt5 > /dev/null
    "$BIN/velarx" --config "$CONF" rm -f -t 0 rt5 > /dev/null
    check "so does the removal" 1 "$(test "$(grep -c "delete.* $id\$" "$LOG")" -ge 1 && echo 1)"
}

# the default runtime: not that one
@test "the default runtime: a container with no runtime asked is not made by the logged one" {
    id2=$(create '{"image":"'"$IMG"'","name":"rt2","command":["true"]}')
    sh_ start rt2 > /dev/null 2>&1
    sh_ wait rt2 > /dev/null 2>&1
    check "a container with no runtime asked is not made by it" 0 "$(calls "$id2")"
    check "its inspect says oci" oci "$(sh_ inspect rt2 --format '{{.HostConfig.Runtime}}')"
    sh_ rm rt2 > /dev/null
}

# a runtime that is none: the create fails and says so
@test "an unknown runtime is refused, by name, and nothing is made" {
    out=$(create '{"image":"'"$IMG"'","name":"rt3","oci_runtime":"nosuchruntime"}')
    check_match "an unknown runtime is refused, by name" "nosuchruntime" "$out"
    check "and nothing is made" "" "$(sh_ ps -a -q)"
}

# a client names a runtime of the engine, never a binary of its choice
@test "a client names a runtime of the engine, never a binary of its choice" {
    for r in "$WORKDIR/logged-runtime" /bin/sh sh; do
        out=$(create '{"image":"'"$IMG"'","name":"rt4","oci_runtime":"'"$r"'"}')
        check_match "oci_runtime $r is refused" "unknown OCI runtime" "$out"
    done
    code=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -d '{"Image":"'"$IMG"'","HostConfig":{"Runtime":"/bin/sh"}}' http://d/v1.41/containers/create)
    check "and so is HostConfig.Runtime /bin/sh" 1 "$(test "$code" -ge 400 && echo 1)"
    check "nothing is made" "" "$(sh_ ps -a -q)"
}

# a pod: its infra container and its members
@test "a pod: its infra container and its members use the runtime of the pod" {
    api -X POST -H 'Content-Type: application/json' -d '{"name":"rtpod","oci_runtime":"logged"}' http://d/v5.0.0/libpod/pods/create > /dev/null
    sh_ run -d --pod rtpod --name rtm "$IMG" sleep 300 > /dev/null
    infra=$(sh_ pod inspect rtpod --format '{{.InfraContainerID}}')
    member=$(sh_ inspect rtm --format '{{.Id}}')
    check "the infra container of the pod is made by its runtime" 1 "$(test "$(grep -c "create.* $infra\$" "$LOG")" -ge 1 && echo 1)"
    check "and so is a member" 1 "$(test "$(grep -c "create.* $member\$" "$LOG")" -ge 1 && echo 1)"
    check "its inspect says which" logged "$(sh_ inspect rtm --format '{{.HostConfig.Runtime}}')"
    sh_ pod rm -f -t 0 rtpod > /dev/null
}

# a runtime that is gone: the container says which, its removal still works
@test "a runtime that is gone: the start names it, the removal still works" {
    id5=$(create '{"image":"'"$IMG"'","name":"rt5","command":["sleep","300"],"oci_runtime":"logged"}')
    mv "$WORKDIR/logged-runtime" "$WORKDIR/logged-runtime.gone"
    out=$(sh_ start rt5 2>&1)
    check_match "a start with a runtime that is gone names it" "logged-runtime" "$out"
    sh_ rm -t 0 -f rt5 > /dev/null 2>&1
    check "and the container is removed" "" "$(sh_ ps -a -q)"
    mv "$WORKDIR/logged-runtime.gone" "$WORKDIR/logged-runtime"
}

# runc exits with 255 when it cannot start a command and logs why
# (`time=... level=error msg=...`): podman's 127 and 126, in runc's name
@test "runc: a command it cannot start is 127 or 126, said in runc's name" {
    command -v runc > /dev/null || skip "no runc"
    vx () { "$BIN/velarx" --config "$CONF" "$@"; }
    vx run --runtime runc -d --name rt6 --network none "$IMG" sleep 300 > /dev/null || e2e_die "run -d under runc"
    out=$(vx exec rt6 nosuchcmd 2>&1)
    check "exec of a command that is not there: 127" 127 $?
    check "runc's message, in its name, podman's cause" \
        'Error: runc: exec failed: unable to start container process: exec: "nosuchcmd": executable file not found in $PATH: OCI runtime attempted to invoke a command that was not found' "$out"
    out=$(sh_ exec rt6 nosuchcmd 2>&1)
    check "the same through the engine" "127 runc" "$? ${out:7:4}"
    vx exec rt6 /etc/hostname > /dev/null 2>&1
    check "exec of a file that is not executable: 126" 126 $?
    vx exec rt6 sh -c 'exit 3'
    check "the command's own code stays" 3 $?
    out=$(vx run --rm --runtime runc --network none "$IMG" nosuchcmd 2>&1)
    check "run of a command that is not there: 127" 127 $?
    check_match "said in runc's name" '^Error: runc: runc create failed: .*nosuchcmd.*OCI runtime attempted to invoke a command that was not found$' "$out"
    vx rm -f -t 0 rt6 > /dev/null
}

# a restart joins the namespaces the container keeps through a spec of its
# own: crun takes it with `create --config`, runc (which has no such option)
# in a bundle of its own
@test "runc: a container of a restart policy is started again" {
    command -v runc > /dev/null || skip "no runc"
    vx () { "$BIN/velarx" --config "$CONF" "$@"; }
    vx run --runtime runc -d --name rt7 --restart on-failure:1 --network none "$IMG" \
        sh -c 'echo run; exit 3' > /dev/null || e2e_die "run -d under runc"
    log=$WORKDIR/root/logs/$(vx inspect --format '{{.Id}}' rt7)/container.log
    e2e_wait_line "$log" ' stdout F run$' 30 2 || e2e_die "no second run: $(tail -2 "$WORKDIR"/run/velarx/mon/*/monitor.log)"
    check "it was started again once" 1 "$(vx inspect --format '{{.RestartCount}}' rt7)"
    vx rm -f -t 0 rt7 > /dev/null
}

# crun's own options (the global --cgroup-manager, create --config, create
# --no-new-keyring) are there when the runtime's `features` allow the
# run.oci. annotations: crun and krun do, runc does not (its features list
# no run.oci. prefix), whatever the file is called
@test "--cgroups=disabled is refused for runc and runs under a crun that is not called crun" {
    vx () { "$BIN/velarx" --config "$CONF" "$@"; }
    out=$(vx run --rm --runtime "$WORKDIR/logged-runtime" --network none --cgroups=disabled "$IMG" echo disabled 2>&1)
    check "a wrapper of crun (named logged-runtime) takes --cgroups=disabled" "disabled" "$out"
    command -v runc > /dev/null || skip "no runc"
    out=$(vx run --rm --runtime runc --network none --cgroups=disabled "$IMG" true 2>&1) && rc=0 || rc=$?
    check "runc is refused" 125 "$rc"
    check_match "and the option is named" '^Error: .*cgroups=disabled.*--cgroup-manager=disabled.*runc' "$out"
    vx run --rm --runtime runc --network none "$IMG" true || e2e_die "runc without the option"
    # (what crun's run.oci. annotations give is refused too: runc ignores them)
    out=$(vx run --rm --runtime runc --network none --group-add keep-groups "$IMG" true 2>&1) && rc=0 || rc=$?
    check "runc is refused keep-groups" 125 "$rc"
    check_match "and the option is named" '^Error: .*keep-groups.*run\.oci\..*runc' "$out"
}

# krun (crun built with libkrun: a microVM per container) runs a container;
# it has no exec
@test "krun runs a container (a microVM; no exec)" {
    command -v krun > /dev/null && [ -w /dev/kvm ] || skip "no krun or no /dev/kvm"
    vx () { "$BIN/velarx" --config "$CONF" "$@"; }
    out=$(vx run --rm --runtime krun --network none "$IMG" sh -c 'echo hello; uname -r' 2>&1)
    check_match "krun runs the command" '^hello' "$out"
    vx run -d --name rt1 --runtime krun --network none "$IMG" sleep 300 > /dev/null
    check "it runs" running "$(vx inspect rt1 --format '{{.State.Status}}')"
    out=$(vx exec rt1 true 2>&1) && rc=0 || rc=$?
    check_match "exec says krun has none" 'does not support exec' "$out"
    vx rm -f -t 0 rt1 > /dev/null
}

# gVisor's runsc runs a container, with no SELinux label (it refuses one)
@test "runsc runs a container with --security-opt label=disable" {
    command -v runsc > /dev/null || skip "no runsc"
    skip_unless_root
    vx () { "$BIN/velarx" --config "$CONF" "$@"; }
    out=$(vx run --rm --runtime runsc --security-opt label=disable --network none "$IMG" echo hello 2>&1)
    check "runsc runs the command" hello "$out"
}
