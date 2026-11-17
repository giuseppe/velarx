# SPDX-License-Identifier: Apache-2.0
# `system df` and `system prune`: what the store holds is counted (images,
# containers, volumes, the objects and the composefs images), a prune removes
# what is unused and what nothing references any more, and keeps the rest.
# Rootless.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/system-prune.bats
#   (IMAGE=... for another image than $E2E_REGISTRY/alpine:chunked)

load helpers

sh_ () { "$BIN/velarx" --socket "$ESOCK" "$@"; }
images () { sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1; }
objects () { find "$WORKDIR/store/objects" -type f | wc -l; }
# TOTAL and ACTIVE of a row of `system df` (podman's), the COUNT of a row
# of the store table of `system df -v`
df_row () {
    case $1 in
    Objects | Composefs) sh_ system df -v | awk -v t="$1" '$1 == t {print $2}' ;;
    Volumes) sh_ system df | awk '$1 == "Local" && $2 == "Volumes" {print $3, $4}' ;;
    *) sh_ system df | awk -v t="$1" '$1 == t {print $2, $3}' ;;
    esac
}

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

# (a test that fails must not leave its container, volume and pods to the
# next)
teardown () {
    sh_ container rm -f -t 0 vt > /dev/null 2>&1
    sh_ volume rm -t 0 -f vt > /dev/null 2>&1
    # (the holder of the lock of a pod lets it go, if it still holds it)
    if [ -p "$WORKDIR/go" ]; then
        exec 9<> "$WORKDIR/go"
        echo >&9
        exec 9>&-
    fi
    rm -f "$WORKDIR/held" "$WORKDIR/go"
    sh_ pod rm -f -t 0 pruned kept > /dev/null 2>&1
    return 0
}

@test "df of an empty store" {
    out=$(sh_ system df 2>&1)
    check_match "df of an empty store" "Images +0 +0 +0B" "$out"
    check "no object" "0" "$(df_row Objects)"
}

@test "df counts a pulled image, its objects and the composefs images" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a pull" 0 $?
    check "df counts the image" "1 0" "$(df_row Images)"
    n=$(objects)
    echo "$n" > "$WORKDIR/objects"
    check "and its objects" "$n" "$(df_row Objects)"
    check_match "with their size" "Objects +[1-9][0-9]* +[1-9][0-9.]*[kMG]?B" "$(sh_ system df -v)"
    check_match "and the composefs images" "Composefs +[1-9][0-9]* " "$(sh_ system df -v)"
    check_match "an image no container uses is reclaimable (podman's)" "Images +1 +0 +[1-9][0-9.]*[kMG]?B +[1-9][0-9.]*[kMG]?B \(100%\)" "$(sh_ system df)"
}

@test "df counts a container that uses the image" {
    sh_ container run --name user --network none "$IMAGE" true > /dev/null 2>&1
    check "a container uses it" "1 1" "$(df_row Images)"
    check "df counts the container" "1 0" "$(df_row Containers)"
    check_match "df -v lists it" "user" "$(sh_ system df -v)"
    repo=${IMAGE%:*}
    check_match "and the image" "${repo//./\\.} +${IMAGE##*:} " "$(sh_ system df -v)"
}

@test "df counts a volume" {
    sh_ volume create keep > /dev/null 2>&1
    check "df counts the volume" "1 0" "$(df_row Volumes)"
}

# an object nothing records is garbage
@test "a prune removes the stopped container and the orphan object, keeps the rest" {
    [ -s "$WORKDIR/objects" ] || { echo "needs the test 'df counts a pulled image, its objects and the composefs images'" >&2; exit 1; }
    n=$(cat "$WORKDIR/objects")
    mkdir -p "$WORKDIR/store/objects/ab"
    orphan="$WORKDIR/store/objects/ab/$(printf 'c%.0s' $(seq 62))"
    echo garbage > "$orphan"
    out=$(sh_ system prune -f 2>&1)
    check_match "a prune removes the stopped container" "Deleted Containers" "$out"
    check "and df counts none" "0 0" "$(df_row Containers)"
    check "the orphan object is collected" 0 "$([ -e "$orphan" ] && echo 1 || echo 0)"
    check "the image stays (it is tagged)" "$IMAGE" "$(images)"
    check "its objects stay" "$n" "$(objects)"
    check "so does the volume without --volumes" "1 0" "$(df_row Volumes)"
}

@test "prune -a removes the image and its objects, --volumes the volume" {
    out=$(sh_ system prune -a -f 2>&1)
    check_match "prune -a reports the image" "Deleted Images" "$out"
    check_match "and the reclaimed space" "Total reclaimed space: [1-9]" "$out"
    check "the image is gone" "" "$(images)"
    check "its objects are gone" 0 "$(objects)"
    check "df says so" "0" "$(df_row Objects)"
    check "the volume stays" "1 0" "$(df_row Volumes)"
    sh_ system prune -f --volumes > /dev/null 2>&1
    check "--volumes removes it" "0 0" "$(df_row Volumes)"
}

# what a prune says it reclaimed is what it freed, as the API says it
# (`ReclaimedSpace`): the bytes of the volumes it removed
@test "system prune --volumes reclaims the bytes of the volume" {
    sh_ volume create sized > /dev/null 2>&1
    head -c 8388608 /dev/zero > "$(sh_ volume inspect sized --format '{{.Mountpoint}}')/f"
    out=$(sh_ system prune -f --volumes 2>&1)
    check_match "the volume is reclaimed" "Total reclaimed space: 8\\.[0-9] MB" "$out"
}

# ... the writable layer of a container it removed, and of an image it
# removed what the store no longer has: not the layer the image shares with
# an image left (podman counts the image whole)
@test "system prune reclaims what it freed, not the layer an image left shares" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ container run --name vt --network none "$IMAGE" sh -c 'head -c 2097152 /dev/zero > /f' > /dev/null 2>&1
    check "a container writes 2 MiB" 0 $?
    sh_ container commit vt > /dev/null 2>&1
    check "an image without a name is made of it" 0 $?
    out=$(sh_ system prune -f 2>&1)
    check_match "the prune removes the container" "Deleted Containers" "$out"
    check_match "and the image" "Deleted Images" "$out"
    check_match "it reclaims the 2 MiB of each, not the layer of $IMAGE" "Total reclaimed space: 4\\.[0-9] MB" "$out"
    check "the image it shares that layer with stays" "$IMAGE" "$(images)"
}

# what an image prune reclaims is what the removal freed: the layer the image
# has of its own (2 MiB here), not the layers it shares with an image that
# stays, and its objects are gone with it
@test "image prune reclaims the layer of the image, not the shared ones" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ container run --name vt --network none "$IMAGE" sh -c 'head -c 2097152 /dev/zero > /f' > /dev/null 2>&1
    sh_ container commit vt > /dev/null 2>&1
    check "an image without a name is made of the container" 0 $?
    sh_ container rm vt > /dev/null 2>&1
    out=$(sh_ image prune -f 2>&1)
    check_match "the image is deleted" "Deleted: " "$out"
    check_match "and its 2 MiB reclaimed once" "Total reclaimed space: 2\\.[0-9] MB" "$out"
    check "the image it shares a layer with stays" "$IMAGE" "$(images)"
    out=$(sh_ system gc 2>&1)
    check_match "nothing is left for the collector, the removal freed it" "Bytes freed: +0 B" "$out"
}

# the garbage collector counts the bytes an object took once
@test "system gc says how many bytes the objects it removed took" {
    mkdir -p "$WORKDIR/store/objects/ab"
    orphan="$WORKDIR/store/objects/ab/$(printf 'c%.0s' $(seq 62))"
    head -c 2097152 /dev/zero > "$orphan"
    out=$(sh_ system gc 2>&1)
    check_match "the orphan is counted once" "Bytes freed: +2\\.0 MB" "$out"
    check "and gone" 0 "$([ -e "$orphan" ] && echo 1 || echo 0)"
}

# volume rm --time: the containers that use it get that long to stop
@test "volume rm --time: the containers that use it get that long to stop" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ volume create vt > /dev/null 2>&1
    sh_ container run -d --name vt -v vt:/data --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a container uses the volume" 0 $?
    start=$SECONDS
    sh_ volume rm -f --time 1 vt > /dev/null 2>&1
    check "volume rm -f --time removes it" 0 $?
    check "in the time it was given" 1 "$([ $((SECONDS - start)) -lt 8 ] && echo 1 || echo 0)"
    check "and the container" "" "$(sh_ container list -a --format '{{.Names}}' 2>&1)"
    sh_ system check > /dev/null 2>&1
    check "the store is whole" 0 $?
}

# A pod is pruned by what its containers are, under its operation lock (as
# `pod prune`), not by the state it recorded: a start whose containers run
# has not recorded it yet while it waits for the state lock of the pod
# (held here), and the prune leaves the pod to it.
@test "a prune keeps a pod a start runs, removes one where none runs" {
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ pod create --infra=false --name pruned > /dev/null 2>&1
    check "an empty pod" 0 $?
    sh_ pod create --infra=false --name kept > /dev/null 2>&1
    sh_ container create --pod kept --name kept-c --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a container in the other one" 0 $?
    id=$(sh_ pod inspect --format '{{.ID}}' kept)
    rm -f "$WORKDIR/held" "$WORKDIR/go"
    mkfifo "$WORKDIR/held" "$WORKDIR/go"
    flock "$WORKDIR/root/pods/.$id.lock" sh -c 'echo > "$1"; read -r x < "$2"' _ "$WORKDIR/held" "$WORKDIR/go" &
    holder=$!
    read -r _ < "$WORKDIR/held"
    sh_ pod start kept > /dev/null 2>&1 &
    starting=$!
    timeout 60 "$BIN/velarx" --socket "$ESOCK" wait --condition running kept-c > /dev/null 2>&1
    check "its container runs" 0 $?
    timeout 60 "$BIN/velarx" --socket "$ESOCK" system prune -f > /dev/null 2>&1
    check "a prune while the start has not recorded it" 0 $?
    echo > "$WORKDIR/go"
    wait "$holder"
    wait "$starting"
    check "the start" 0 $?
    check "the empty pod is gone" 1 "$(sh_ pod exists pruned; echo $?)"
    check "the pod the start runs stays" 0 "$(sh_ pod exists kept; echo $?)"
    check "and its container runs" "running" "$(sh_ container inspect --format '{{.State.Status}}' kept-c 2>&1)"
}
