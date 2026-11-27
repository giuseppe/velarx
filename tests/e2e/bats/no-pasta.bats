# SPDX-License-Identifier: Apache-2.0
# A rootless engine without pasta does not fall back to a container without a
# network: the default network, `--network pasta`, a pod and the REST API
# fail with the error that names pasta, and start nothing; so does a pasta
# older than the release needed, a rootless bridge network and the start of
# a container made while pasta was there; `--network none` and `host` run.
# The daemon (and the engine of a command with no daemon) has a $PATH that has
# every tool of the host except pasta.  The image is made here from host
# binaries (no registry):
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/no-pasta.bats   (as a user with subordinate ids)

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

setup_file () {
    if test "$(id -u)" = 0; then
        skip "no-pasta.bats runs rootless (a rootful engine has bridges, not pasta)"
    fi
    e2e_setup_file
    e2e_need_api
    # every executable of $PATH but pasta (and its package's other programs)
    export NOPASTA=$WORKDIR/nopasta
    mkdir -p "$NOPASTA"
    local d f
    while IFS= read -r d; do
        for f in "$d"/*; do
            [ -x "$f" ] && [ -f "$f" ] || continue
            case ${f##*/} in pasta | pasta.avx2 | passt | passt.avx2 | passt-repair) continue ;; esac
            ln -sf "$f" "$NOPASTA/${f##*/}" 2> /dev/null
        done
    done < <(printf '%s\n' "$PATH" | tr : '\n')
    [ ! -e "$NOPASTA/pasta" ] || { echo "pasta is in $NOPASTA" >&2; exit 1; }
    PATH=$NOPASTA e2e_start_daemon
    BINARIES="sh true cat" e2e_make_image
    "$BIN/velarx-api" --config "$XDG_CONFIG_HOME/velarx/config.toml" --no-start-engine --idle-exit 0 \
        --listen "unix://$SOCK" > "$WORKDIR/api.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/api.pid"
    e2e_wait_path "$SOCK" 10
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    e2e_remove_containers "$SH" "$ESOCK"
    e2e_teardown_file
}

# no container, no pod and no network left behind
none_left () {
    check "$1: no container" "" "$(sc container list -a --format '{{.ID}}')"
    check "$1: no pod" "" "$(sc pod list --format '{{.ID}}')"
}

@test "the default network needs pasta: run and create fail, nothing starts" {
    rc=0
    out=$(sc container run --rm --name np1 "$IMG" true 2>&1) || rc=$?
    # (an error of the engine, not of the container: 125)
    check "the exit status of a run without pasta" 125 "$rc"
    [[ $out == *'cannot find `pasta`'* ]] || e2e_die "the error does not say pasta is missing: $out"
    [[ $out == *"$NOPASTA"* ]] || e2e_die "the error does not name what was searched: $out"
    [[ $out == *2026_10_02* ]] || e2e_die "the error does not name the release: $out"
    ! sc container create --name np2 "$IMG" true > /dev/null 2>&1 || e2e_die "create without pasta succeeded"
    none_left "default"
}

@test "--network pasta needs pasta too" {
    ! sc container run --rm --network pasta "$IMG" true > /dev/null 2>&1 || e2e_die "run --network pasta without pasta succeeded"
    ! sc container run --rm --network pasta:--ipv4-only "$IMG" true > /dev/null 2>&1 || e2e_die "run with pasta options and no pasta succeeded"
    none_left "pasta"
}

@test "a pod needs pasta for its network: nothing is left" {
    ! sc pod create --name npod > /dev/null 2>&1 || e2e_die "pod create without pasta succeeded"
    none_left "pod"
}

@test "the REST API says it the same way and starts nothing" {
    code=$(curl -s -o "$WORKDIR/api.out" -w '%{http_code}' --unix-socket "$SOCK" -X POST \
        -H 'Content-Type: application/json' -d '{"image":"'"$IMG"'","name":"np3","command":["true"]}' \
        http://d/v5.0.0/libpod/containers/create)
    check "libpod create without pasta" 500 "$code"
    grep -q 'cannot find `pasta`' "$WORKDIR/api.out" || e2e_die "the REST error does not say pasta: $(cat "$WORKDIR/api.out")"
    none_left "api"
}

@test "an engine of a command with no daemon refuses it the same way" {
    out=$(PATH=$NOPASTA "$SH" container run --rm --name np4 "$IMG" true 2>&1) && e2e_die "a run with no daemon and no pasta succeeded"
    [[ $out == *'cannot find `pasta`'* ]] || e2e_die "the error does not say pasta is missing: $out"
}

@test "a pasta older than the release needed is refused with what it says" {
    mkdir -p "$WORKDIR/oldpasta"
    printf '#!/bin/sh\necho "pasta 2025_01_21.4f2c8e7"\n' > "$WORKDIR/oldpasta/pasta"
    chmod 755 "$WORKDIR/oldpasta/pasta"
    out=$(PATH=$WORKDIR/oldpasta:$NOPASTA "$SH" container run --rm --name np5 "$IMG" true 2>&1) &&
        e2e_die "a run with an old pasta succeeded"
    [[ $out == *"$WORKDIR/oldpasta/pasta"*'is not pasta 2026_10_02 or later'* ]] || e2e_die "the error does not name the pasta and the release: $out"
    [[ $out == *2025_01_21* ]] || e2e_die "the error does not say what pasta said: $out"
    none_left "old"
}

@test "a rootless bridge network needs pasta: refused the same way, and removed" {
    sc network create npnet > /dev/null
    out=$(sc container run --rm --network npnet "$IMG" true 2>&1) && e2e_die "a run on a bridge without pasta succeeded"
    [[ $out == *'cannot find `pasta`'* ]] || e2e_die "the error does not say pasta is missing: $out"
    none_left "bridge"
    sc network rm npnet > /dev/null
}

@test "a container made with pasta, started without it: refused, nothing left, starts again with pasta" {
    "$SH" container create --name np6 "$IMG" sh -c 'echo ran' > /dev/null
    id=$("$SH" container inspect --format '{{.Id}}' np6)
    out=$(PATH=$NOPASTA "$SH" container start -a np6 2>&1) && e2e_die "a start without pasta succeeded"
    [[ $out == *'cannot find `pasta`'* ]] || e2e_die "the error does not say pasta is missing: $out"
    check "state after the refused start" created "$("$SH" container inspect --format '{{.State.Status}}' np6)"
    check "no namespace recorded" 0 "$(e2e_netns_records "$XDG_DATA_HOME/velarx/db.sqlite" "container/$id")"
    check "start with pasta" ran "$("$SH" container start -a np6)"
    "$SH" container rm np6 > /dev/null
    none_left "restart"
}

@test "--network none and host need no pasta" {
    check "none" ok "$(sc container run --rm --network none "$IMG" sh -c 'echo ok')"
    check "host" ok "$(sc container run --rm --network host "$IMG" sh -c 'echo ok')"
    none_left "none"
}
