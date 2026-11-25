# SPDX-License-Identifier: Apache-2.0
# Velarx supports cgroup v2 only: the engine service, the engine of a command
# and the monitor leave at once, with one error and no fallback, when
# /sys/fs/cgroup is not a cgroup2 mount.  A tmpfs over /sys/fs/cgroup, in a
# user and mount namespace of the test (nothing of the host changes), is
# what cgroup v1 and the hybrid layout look like at that path.  What needs no
# cgroup keeps working there: --help, version, a client of an engine that
# is named.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/cgroup-v2-only.bats   # as root, or as a user
#
# No registry, no image and no daemon are needed.

load helpers

setup_file () {
    e2e_setup_file
    unshare -rm true 2> /dev/null || skip "no user and mount namespaces"
}
teardown_file () { e2e_teardown_file; }

# without_cgroup2 CMD...: CMD with a tmpfs over /sys/fs/cgroup
without_cgroup2 () {
    unshare -rm sh -c 'mount -t tmpfs none /sys/fs/cgroup && exec "$@"' sh "$@"
}

refusal='velarx needs cgroup v2 and /sys/fs/cgroup is not a cgroup2 mount'

@test "the engine service refuses to start without cgroup v2" {
    out=$(without_cgroup2 "$BIN/velarx" varlink --time 1 2>&1)
    check "exit status" 125 $?
    check_match "the error" "^Error: $refusal" "$out"
    check "one line" 1 "$(printf '%s\n' "$out" | wc -l)"
}

@test "the engine of a command refuses to start without cgroup v2" {
    for cmd in "container ps" "container run --rm img true" "info"; do
        # shellcheck disable=SC2086
        out=$(without_cgroup2 "$BIN/velarx" $cmd 2>&1)
        check "$cmd: exit status" 125 $?
        check_match "$cmd: the error" "$refusal" "$out"
    done
}

@test "the monitor refuses to start without cgroup v2" {
    out=$(without_cgroup2 "$BIN/velarx-monitor" --varlink-fd 3 "$WORKDIR" 2>&1)
    check "exit status" 1 $?
    check_match "the error" "monitor failed: $refusal" "$out"
}

@test "a cgroup2 mount of a cgroup namespace (a nested container) is cgroup v2" {
    unshare -rmC true 2> /dev/null || skip "no cgroup namespaces"
    # (the monitor checks first, then fails on the run directory that is not one)
    out=$(unshare -rmC sh -c 'mount -t cgroup2 none /sys/fs/cgroup && exec "$@"' sh \
        "$BIN/velarx-monitor" --varlink-fd 3 "$WORKDIR/no-such-run-dir" 2>&1)
    check "the monitor fails, not on the cgroups" 1 $?
    case "$out" in
        *"needs cgroup v2"*) echo "FAIL a cgroup2 mount of a cgroup namespace is refused: $out" >&2; return 1 ;;
    esac
    check_match "but on its run directory" "monitor failed" "$out"
}

@test "what needs no cgroup works without cgroup v2" {
    out=$(without_cgroup2 "$BIN/velarx" --help 2>&1)
    check "--help" 0 $?
    out=$(without_cgroup2 "$BIN/velarx" container run --help 2>&1)
    check "run --help" 0 $?
    out=$(without_cgroup2 "$BIN/velarx" version 2>&1)
    check "version" 0 $?
    check_match "and says its version" "ersion" "$out"
    out=$(without_cgroup2 "$BIN/velarx-client" --socket "$WORKDIR/none.sock" container ps 2>&1)
    check "a client with no engine fails as ever" 125 $?
    check_match "and says why, not the cgroups" "socket not found" "$out"
    out=$(without_cgroup2 "$BIN/velarx" --socket "$WORKDIR/none.sock" container ps 2>&1)
    check "velarx with a named engine fails as ever" 125 $?
    check_match "and says why, not the cgroups" "socket not found" "$out"
    out=$(without_cgroup2 "$BIN/velarx" completion bash 2>&1)
    check "completion" 0 $?
}

@test "the options only cgroup v1 has are unknown" {
    for flag in --memory-swappiness=30 --cpu-rt-period=1000 --cpu-rt-runtime=1000; do
        out=$("$BIN/velarx" container run --rm "$flag" img true 2>&1)
        check "run $flag" 125 $?
        check_match "unknown flag" "unknown flag: ${flag%%=*}" "$out"
    done
}
