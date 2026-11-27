# SPDX-License-Identifier: Apache-2.0
# Commands run side by side, each with the engine of its own process (no
# daemon), on what they share: the pause image of a store that has none,
# and the rootless network namespace the removals of networks release.
# Run it as an ordinary user for the rootless one, or as root.

load helpers
load run_lib

setup_file () {
    export E2E_NO_DAEMON=1
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

@test "parallel pod create build the pause image once" {
    command -v catatonit > /dev/null || [ -x /usr/libexec/podman/catatonit ] ||
        skip "no static catatonit to build the pause image from"
    seq 1 20 | xargs -P 20 -I{} "$SH" pod create --name pp{} > /dev/null
    check "pods" 20 "$(sh_ pod ls -q | wc -l)"
    # (the image of the pull and the pause image: no untagged copy)
    check "untagged images" 0 "$(sh_ images -a | grep -c '<none>' || true)"
    check "the pause image" 1 "$(sh_ images | grep -c velarx-pause)"
}

# (a stress test: whether a removal finds the namespace released by
# another depends on the timing; most runs of four rounds catch it)
@test "parallel network rm of networks with containers all succeed" {
    local round bad=0
    for round in 1 2 3 4; do
        seq 1 10 | xargs -P 10 -I{} "$SH" network create pn{} > /dev/null
        seq 1 10 | xargs -P 10 -I{} "$SH" run --rm --network pn{} "$IMAGE" true
        seq 1 10 | xargs -P 10 -I{} sh -c '"$0" network rm pn{} > /dev/null || echo FAIL pn{}' "$SH" > "$WORKDIR/rm.$round" 2>&1
        if [ -s "$WORKDIR/rm.$round" ]; then
            cat "$WORKDIR/rm.$round" >&3
            bad=$((bad + 1))
        fi
        check "networks left" 1 "$(sh_ network ls -q | wc -l)"
    done
    check "rounds with a failed removal" 0 "$bad"
}
