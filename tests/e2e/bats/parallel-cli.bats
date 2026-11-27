# SPDX-License-Identifier: Apache-2.0
# Commands run side by side, each with the engine of its own process (no
# daemon), on what they share: the pause image of a store that has none.
# Run it as an ordinary user or as root.

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
