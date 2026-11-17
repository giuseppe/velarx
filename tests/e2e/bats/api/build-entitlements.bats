# SPDX-License-Identifier: Apache-2.0
# End to end tests of the entitlements of a build (network.host,
# security.insecure; the two gates: [build] insecure_entitlements of the
# configuration and `build --allow` of the request): refused by default
# before the first step and with every missing entitlement named; the
# request alone and the configuration alone are not enough; both together
# let a step see the network namespace of the host (and a privileged step
# have no seccomp filter); the REST routes have no `allow`, the
# configuration alone decides.  Rootless.

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
    [ -z "${NO_PODMAN:-}" ] || return 0
    cp "$XDG_CONFIG_HOME/velarx/config.toml" "$WORKDIR/base-config.toml"
    mkdir "$WORKDIR/ctx"
}

teardown_file () {
    api_teardown_file
}

teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pp=$XDG_RUNTIME_DIR/libpod/tmp/pause.pid
    [ ! -f "$pp" ] || kill "$(cat "$pp")" 2> /dev/null
    [ "$E2E_FAILS" = 0 ] || exit 1
}

# with_entitlements LIST: restart the daemon with `insecure_entitlements =
# [LIST]` (the names quoted, as in the file)
with_entitlements () {
    local pgid i
    pgid=$(cat "$WORKDIR/daemon.pgid")
    kill -INT -- "-$pgid" 2> /dev/null || true
    e2e_wait_group "$pgid"
    # (the engine has a process group of its own and leaves after the API)
    e2e_wait_gone "$ESOCK"
    kill -KILL -- "-$pgid" 2> /dev/null || true
    rm -f "$SOCK" "$ESOCK"
    cp "$WORKDIR/base-config.toml" "$XDG_CONFIG_HOME/velarx/config.toml"
    if [ -n "$1" ]; then
        printf '[build]\ninsecure_entitlements = [%s]\n' "$1" >> "$XDG_CONFIG_HOME/velarx/config.toml"
    fi
    api_start_daemon
}

two_stages () {
    printf 'FROM %s AS first\nRUN echo first > /first\nFROM %s\nRUN --network=host true\nRUN --security=insecure true\n' "$IMG" "$IMG" > "$WORKDIR/ctx/Containerfile.two"
}

@test "refused by default, before the first step, naming every entitlement" {
    with_entitlements ''
    check "the daemon is up" 0 $?
    two_stages
    out=$("$CLI" image build --tls-verify=false -f "$WORKDIR/ctx/Containerfile.two" "$WORKDIR/ctx" 2>&1)
    check "build refused, as podman's errors" 125 $?
    check_match "network.host" 'network.host is not allowed \(line 4: RUN --network=host\): start the build with --allow network.host and enable it in the engine configuration \(\[build\] insecure_entitlements = \["network.host"\]\)' "$out"
    check_match "security.insecure" 'security.insecure is not allowed \(line 5: RUN --security=insecure\): start the build with --allow security.insecure and enable it' "$out"
    check "no step ran" 0 "$(printf '%s\n' "$out" | grep -c 'STEP')"

    # the whole build on the host network, from the command line and REST
    printf 'FROM %s\nRUN true\n' "$IMG" > "$WORKDIR/ctx/Containerfile.plain"
    out=$("$CLI" image build --tls-verify=false --network host -f "$WORKDIR/ctx/Containerfile.plain" "$WORKDIR/ctx" 2>&1)
    check "build --network=host refused" 1 "$(( $? != 0 ))"
    check_match "build --network=host: message" 'network.host is not allowed \(build --network=host\): start the build with --allow network.host and enable it' "$out"
    out=$(pm build --tls-verify=false --network=host -f "$WORKDIR/ctx/Containerfile.plain" "$WORKDIR/ctx" 2>&1)
    check "REST networkmode=host refused" 1 "$(( $? != 0 ))"
    check_match "REST: message" 'network.host is not allowed \(build --network=host\): enable it in the engine configuration \(\[build\] insecure_entitlements = \["network.host"\]\)' "$out"
    out=$(pm build --tls-verify=false -f "$WORKDIR/ctx/Containerfile.two" "$WORKDIR/ctx" 2>&1)
    check "REST: a RUN --network=host refused" 1 "$(( $? != 0 ))"
    check_match "REST: a RUN --network=host: message" 'network.host is not allowed \(line 4: RUN --network=host\)' "$out"

    # --allow without the configuration
    out=$("$CLI" image build --tls-verify=false --allow network.host -f "$WORKDIR/ctx/Containerfile.plain" "$WORKDIR/ctx" 2>&1)
    check "--allow alone refused" 1 "$(( $? != 0 ))"
    check_match "--allow alone: message" '--allow network.host: network.host is not enabled in the engine configuration \(\[build\] insecure_entitlements\)' "$out"

    # the names
    for bad in bogus network network.none "network.host,bogus"; do
        out=$("$CLI" image build --tls-verify=false --allow "$bad" -f "$WORKDIR/ctx/Containerfile.plain" "$WORKDIR/ctx" 2>&1)
        check "--allow $bad refused" 125 $?
        check_match "--allow $bad: message" 'unknown entitlement' "$out"
    done
    # a build that needs nothing is not affected
    "$CLI" image build --tls-verify=false -t localhost/ent:plain -f "$WORKDIR/ctx/Containerfile.plain" "$WORKDIR/ctx" > /dev/null 2>&1
    check "a plain build" 0 $?
    # an unused stage is not counted
    printf 'FROM %s AS debug\nRUN --network=host true\nFROM %s\nRUN true\n' "$IMG" "$IMG" > "$WORKDIR/ctx/Containerfile.unused"
    "$CLI" image build --tls-verify=false -f "$WORKDIR/ctx/Containerfile.unused" "$WORKDIR/ctx" > /dev/null 2>&1
    check "an unused stage needs nothing" 0 $?
    # the ONBUILD trigger of a base image is checked when it runs
    printf 'FROM %s\nONBUILD RUN --network=host true\n' "$IMG" > "$WORKDIR/ctx/Containerfile.onbuild"
    "$CLI" image build --tls-verify=false -t localhost/ent:onbuild -f "$WORKDIR/ctx/Containerfile.onbuild" "$WORKDIR/ctx" > /dev/null 2>&1
    check "a base image with an ONBUILD trigger" 0 $?
    printf 'FROM localhost/ent:onbuild\nRUN true\n' > "$WORKDIR/ctx/Containerfile.child"
    out=$("$CLI" image build --tls-verify=false -f "$WORKDIR/ctx/Containerfile.child" "$WORKDIR/ctx" 2>&1)
    check "the trigger refused" 1 "$(( $? != 0 ))"
    check_match "the trigger: message" 'network.host is not allowed \(line 1: RUN --network=host\)' "$out"
    out=$(pm build --tls-verify=false -f "$WORKDIR/ctx/Containerfile.child" "$WORKDIR/ctx" 2>&1)
    check "REST: the trigger refused" 1 "$(( $? != 0 ))"
    check_match "REST: the trigger: message" 'network.host is not allowed \(line 1: RUN --network=host\)' "$out"
    "$CLI" image rm -f localhost/ent:plain localhost/ent:onbuild > /dev/null 2>&1
}

@test "enabled by the configuration, not allowed by the request" {
    with_entitlements '"network.host", "security.insecure"'
    check "the daemon is up" 0 $?
    two_stages
    out=$("$CLI" image build --tls-verify=false -f "$WORKDIR/ctx/Containerfile.two" "$WORKDIR/ctx" 2>&1)
    check "build refused" 1 "$(( $? != 0 ))"
    check_match "network.host" 'network.host is not allowed \(line 4: RUN --network=host\): start the build with --allow network.host(;|$)' "$out"
    check_match "security.insecure" 'security.insecure is not allowed \(line 5: RUN --security=insecure\): start the build with --allow security.insecure(;|$)' "$out"
    # one of the two allowed: the other is still named
    out=$("$CLI" image build --tls-verify=false --allow network.host -f "$WORKDIR/ctx/Containerfile.two" "$WORKDIR/ctx" 2>&1)
    check "one allowed: refused" 1 "$(( $? != 0 ))"
    check "one allowed: only the other named" 0 "$(printf '%s\n' "$out" | grep -c 'network.host is not allowed')"
    check_match "one allowed: the other" 'security.insecure is not allowed' "$out"
    out=$("$CLI" image build --tls-verify=false --network host -f "$WORKDIR/ctx/Containerfile.plain" "$WORKDIR/ctx" 2>&1)
    check "build --network=host without --allow refused" 1 "$(( $? != 0 ))"
    check_match "build --network=host: message" 'start the build with --allow network.host(;|$)' "$out"
}

@test "allowed by both: the step is on the host network" {
    with_entitlements '"network.host", "security.insecure"'
    check "the daemon is up" 0 $?
    local host; host=$(readlink /proc/self/ns/net)
    printf 'FROM %s\nRUN readlink /proc/self/ns/net > /netns; grep -E "^Seccomp:" /proc/self/status > /seccomp\n' "$IMG" > "$WORKDIR/ctx/Containerfile.private"
    printf 'FROM %s\nRUN --network=host readlink /proc/self/ns/net > /netns\nRUN --security=insecure grep -E "^Seccomp:" /proc/self/status > /seccomp\nRUN grep -E "^Seccomp:" /proc/self/status > /after\n' "$IMG" > "$WORKDIR/ctx/Containerfile.open"
    "$CLI" image build --tls-verify=false -t localhost/ent:private -f "$WORKDIR/ctx/Containerfile.private" "$WORKDIR/ctx" > /dev/null 2>&1
    check "default build" 0 $?
    private=$("$CLI" run --rm --network none localhost/ent:private cat /netns /seccomp 2>&1)
    check "a default step has a namespace of its own" 0 "$(printf '%s\n' "$private" | head -1 | grep -c -F "$host")"
    check_match "and a seccomp filter" '^Seccomp:\s+2$' "$private"

    out=$("$CLI" image build --tls-verify=false --allow network.host,security.insecure -t localhost/ent:open -f "$WORKDIR/ctx/Containerfile.open" "$WORKDIR/ctx" 2>&1)
    rc=$?
    [ $rc = 0 ] || echo "$out" >&2
    check "both gates open" 0 $rc
    open=$("$CLI" run --rm --network none localhost/ent:open cat /netns /seccomp 2>&1)
    check "RUN --network=host: the namespace of the host" "$host" "$(printf '%s\n' "$open" | head -1)"
    check_match "RUN --security=insecure: no seccomp filter" '^Seccomp:\s+0$' "$open"
    after=$("$CLI" run --rm --network none localhost/ent:open cat /after 2>&1)
    check_match "the next step is confined again" '^Seccomp:\s+2$' "$after"

    # the repeated and the comma forms are the same
    out=$("$CLI" image build --tls-verify=false --allow network.host --allow security.insecure --no-cache -t localhost/ent:open2 -f "$WORKDIR/ctx/Containerfile.open" "$WORKDIR/ctx" 2>&1)
    rc=$?
    [ $rc = 0 ] || echo "$out" >&2
    check "--allow repeated" 0 $rc

    # the whole build
    printf 'FROM %s\nRUN readlink /proc/self/ns/net > /netns\n' "$IMG" > "$WORKDIR/ctx/Containerfile.whole"
    "$CLI" image build --tls-verify=false --network host --allow network.host -t localhost/ent:whole -f "$WORKDIR/ctx/Containerfile.whole" "$WORKDIR/ctx" > /dev/null 2>&1
    check "build --network=host --allow network.host" 0 $?
    check "the whole build: the namespace of the host" "$host" "$("$CLI" run --rm --network none localhost/ent:whole cat /netns 2>&1)"

    # REST: the configuration is the opt-in
    pm build --tls-verify=false --network=host --no-cache -t localhost/ent:rest -f "$WORKDIR/ctx/Containerfile.whole" "$WORKDIR/ctx" > /dev/null 2>&1
    check "REST networkmode=host" 0 $?
    check "REST: the namespace of the host" "$host" "$("$CLI" run --rm --network none localhost/ent:rest cat /netns 2>&1)"
    pm build --tls-verify=false --no-cache -t localhost/ent:rest2 -f "$WORKDIR/ctx/Containerfile.open" "$WORKDIR/ctx" > /dev/null 2>&1
    check "REST: RUN --network=host and --security=insecure" 0 $?
    check "REST: the namespace of the host (RUN)" "$host" "$("$CLI" run --rm --network none localhost/ent:rest2 cat /netns 2>&1)"
    "$CLI" image rm -f localhost/ent:private localhost/ent:open localhost/ent:open2 localhost/ent:whole localhost/ent:rest localhost/ent:rest2 > /dev/null 2>&1
}

@test "an unknown entitlement in the configuration is an error" {
    printf '[build]\ninsecure_entitlements = ["network.hosts"]\n' > "$WORKDIR/bad.toml"
    cat "$WORKDIR/base-config.toml" "$WORKDIR/bad.toml" > "$WORKDIR/bad-config.toml"
    out=$("$BIN/velarx" --config "$WORKDIR/bad-config.toml" varlink 2>&1 < /dev/null)
    check "the engine refuses to start" 1 "$(( $? != 0 ))"
    check_match "and says why" 'network.hosts' "$out"
}
