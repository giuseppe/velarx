# SPDX-License-Identifier: Apache-2.0
# `system check`: a whole store passes, damage is found (quick and full),
# a repair makes the composefs image again, removes leftovers and removes
# the images that cannot be repaired without a pull, but not one a
# container uses.  Rootless.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/system-check.bats
#   (IMAGE=... for another image than $E2E_REGISTRY/alpine:chunked)

load helpers

sh_ () { "$BIN/velarx" --socket "$ESOCK" "$@"; }
images () { sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1; }
biggest () { find "$WORKDIR/store/objects" -type f -printf '%s %p\n' | sort -n | tail -1 | cut -d' ' -f2; }

setup_file () {
    export IMAGE=${IMAGE:-${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}}
    command -v curl > /dev/null || skip "no curl"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
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
[pull]
EOT
    e2e_start_daemon
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    . "$E2E_DIR/cleanup.sh"
    e2e_remove_containers "$BIN/velarx" "$ESOCK"
    if test -z "${E2E_KEEP:-}"; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    e2e_teardown_file
}

# (a test that fails must not leave its container to the next)
teardown () {
    sh_ container rm -f -t 0 user > /dev/null 2>&1
    return 0
}

@test "a pull; a whole store passes, silently, and the flags are podman's" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a pull" 0 $?

    out=$(sh_ system check 2>&1); rc=$?
    check "a whole store passes" 0 $rc
    check "and prints nothing, as podman" "" "$out"
    sh_ system check --quick > /dev/null 2>&1
    check "so does a quick check" 0 $?
    out=$(sh_ system check --max 1h --timeout 1h --format json)
    check "the json report is podman's" "false null" "$(echo "$out" | jq -r '"\(.Errors) \(.Layers)"')"
    out=$(sh_ system check --max nonsense 2>&1); rc=$?
    check "--max takes a duration" 125 $rc
    check_match "and says which" 'invalid argument "nonsense" for "-m, --max" flag: time: invalid duration "nonsense"' "$out"
    sh_ system check --timeout nonsense > /dev/null 2>&1
    check "--timeout takes a duration" 125 $?
    sh_ system check -q -m 24h0m0s --timeout 0 > /dev/null 2>&1
    check "podman's flags and Go durations" 0 $?
}

# a bit flipped in a file: only the full check reads it
@test "a bit flipped in a file: only the full check finds it" {
    obj=$(biggest)
    [ -n "$obj" ] || { echo "no object in the store (the pull of the first test?)" >&2; exit 1; }
    chmod u+w "$obj"
    printf '\xff' | dd of="$obj" bs=1 seek=100 conv=notrunc 2> /dev/null
    sh_ system check --quick > /dev/null 2>&1
    check "a quick check does not read the files" 0 $?
    out=$(sh_ system check 2>&1); rc=$?
    check "a flipped bit fails the check" 125 $rc
    check_match "as podman does" "Error: damage detected in local storage" "$out"
    check_match "it names the image" "Damaged image [0-9a-f]{12,64}:" "$out"
    check_match "it counts the errors" "^[0-9]+ errors? occurred:" "$out"
    check_match "it lists the mismatch" "^"$'\t'"\* verity_mismatch" "$out"
    check_match "and the problem" "verity_mismatch" "$out"
    check_match "and the path" "$WORKDIR/store/objects/" "$out"
}

# a container keeps its image
@test "a container keeps its image, --repair --force removes both" {
    sh_ container create --name user --network none "$IMAGE" true > /dev/null 2>&1
    out=$(sh_ system check --repair 2>&1); rc=$?
    check "an image a container uses is not removed" 125 $rc
    check_match "it says so, as podman" "Error: damage in local storage still present after repair attempt" "$out"
    check_match "and why" "image not removed: used by the container" "$out"
    check "and stays" "$IMAGE" "$(images)"
    sh_ system check --force > /dev/null 2>&1
    check "--force repairs nothing without --repair, as podman" 125 $?
    check "the container stays" "user" "$(sh_ container ls -a --format '{{.Names}}')"
    out=$(sh_ system check --repair --force 2>&1); rc=$?
    check "--repair --force removes the container and the image" 0 $rc
    check_match "it says which container" "Deleted damaged container: [0-9a-f]{64}" "$out"
    check_match "and which image" "Deleted damaged image: [0-9a-f]{12,64}" "$out"
    check "the container is gone" "" "$(sh_ container ls -a --format '{{.Names}}')"
    check "the image is gone" "" "$(images)"
    sh_ system check > /dev/null 2>&1
    check "the store is whole after --force" 0 $?
}

@test "a repair removes a damaged image nothing uses, and its files" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    obj=$(biggest)
    [ -n "$obj" ] || { echo "no object in the store (the pull of the first test?)" >&2; exit 1; }
    chmod u+w "$obj"
    printf '\xff' | dd of="$obj" bs=1 seek=100 conv=notrunc 2> /dev/null
    sh_ container create --name user --network none "$IMAGE" true > /dev/null 2>&1
    sh_ container rm user > /dev/null 2>&1

    out=$(sh_ system check --repair 2>&1); rc=$?
    check "a repair succeeds" 0 $rc
    check_match "it removes the image" "Deleted damaged image: [0-9a-f]{12,64}" "$out"
    check "the image is gone" "" "$(images)"
    check "and its files" 0 "$(find "$WORKDIR/store/objects" -type f | wc -l)"
    sh_ system check > /dev/null 2>&1
    check "the store is whole" 0 $?
}

# pulled again, the composefs image made again
@test "a missing composefs image is made again by a repair" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    erofs=$(ls "$WORKDIR"/store/composefs/layer-*.erofs | head -1)
    rm -f "$erofs"
    out=$(sh_ system check 2>&1); rc=$?
    check "a missing composefs image fails the check" 125 $rc
    check_match "it says which" "artifact_missing" "$out"
    sh_ system check --repair > /dev/null 2>&1
    check "the repair makes it again" 0 $?
    check "it is there" 1 "$(ls "$erofs" | wc -l)"
    check "read-only" "r--r--r--" "$(stat -c %A "$erofs" | cut -c2-)"
    check "the image stays" "$IMAGE" "$(images)"
    sh_ system check > /dev/null 2>&1
    check "and passes" 0 $?
}

# a start does not make it again: the layer is incomplete, a pull makes it
@test "a missing composefs image: the start fails, a pull makes it again" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    erofs=$(ls "$WORKDIR"/store/composefs/layer-*.erofs | head -1)
    rm -f "$erofs"
    out=$(sh_ container run --rm --network none "$IMAGE" true 2>&1); rc=$?
    check "the start fails" 125 $rc
    check_match "it says the image is damaged" "the image $IMAGE is damaged \\(layer (toc:)?sha256:[0-9a-f]{64} has no EROFS image\\): pull it again" "$out"
    check "the image stays" "$IMAGE" "$(images)"
    test ! -e "$erofs"
    check "and nothing made it again" 0 $?
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "the pull succeeds" 0 $?
    check "it made the image again" 1 "$(ls "$erofs" | wc -l)"
    out=$(sh_ container run --rm --network none "$IMAGE" echo back 2>&1)
    check "the container runs" "back" "$out"
    # (a container made before the image went: its start says the same)
    sh_ container create --name made --network none "$IMAGE" true > /dev/null
    rm -f "$erofs"
    out=$(sh_ container start made 2>&1); rc=$?
    check "the start of a container made before fails" 125 $rc
    check_match "it says the image is damaged" "the image $IMAGE is damaged \\(layer (toc:)?sha256:[0-9a-f]{64} has no EROFS image\\): pull it again" "$out"
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ container start made > /dev/null 2>&1
    check "and it starts after a pull" 0 $?
    sh_ container rm -f -t 0 made > /dev/null 2>&1
    sh_ system check > /dev/null 2>&1
    check "and the store passes" 0 $?
}

@test "leftovers: a temporary file and a stale staging directory" {
    mkdir -p "$WORKDIR/store/objects/ab"
    echo partial > "$WORKDIR/store/objects/ab/.tmpleft"
    out=$(sh_ system check --max 1h 2>&1); rc=$?
    check "--max: a temporary file younger than that is no leftover" 0 $rc
    out=$(sh_ system check --max 0s 2>&1); rc=$?
    check "--max 0s: any is" 125 $rc
    mkdir -p "$WORKDIR/store/staging/pull-0123abcd/files"
    out=$(sh_ system check 2>&1); rc=$?
    check "a stale staging directory fails the check" 125 $rc
    check_match "it is listed" "Damaged layer .*staging.*:" "$out"
    sh_ system check --repair > /dev/null 2>&1
    check "they are repaired" 0 $?
    # (the staging root keeps `incoming` where the fetchers write files with
    # no name, `layers`, `meta` and the `boot` of its lazy pulls: only the
    # stale pull directory goes)
    check "the staging directory is gone" 0 "$(ls "$WORKDIR/store/staging" | grep -cv '^\(incoming\|layers\|meta\|boot\)$')"
    check "and the temporary file" 0 "$(ls -A "$WORKDIR/store/objects/ab" | grep -c tmpleft)"
}
