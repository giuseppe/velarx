# SPDX-License-Identifier: Apache-2.0
# The options of `container checkpoint` and `container restore` that need
# CRIU: --tcp-close, --latest, a restore of several containers that looks
# them all up first, --pre-checkpoint and --with-previous with --export,
# restore --import-previous, --print-stats with --export, --pod and
# --publish of an import, checkpoint images (--create-image, restore IMAGE).
# As root only (skipped otherwise, and without criu).
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/api/checkpoint-options.bats

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}

vx () { "$CLI" --socket "$ESOCK" "$@"; }

# wait_count NAME REGEX: until the counter the container NAME runs printed a
# number that matches REGEX (a line of its log file).
wait_count () {
    local id
    id=$(pm inspect "$1" --format '{{.Id}}')
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$id/container.log" " stdout F $2\$" 30 ||
        fail "the counter of $1 printed no $2 within 30 s"
}

COUNT='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'

need_criu () {
    skip_unless_root
    command -v criu > /dev/null || skip "no criu"
}

@test "checkpoint and restore look every container up first, --latest takes the newest" {
    need_criu
    pm run -d --name cpl1 --network none "$IMG" sh -c "$COUNT" > /dev/null
    pm run -d --name cpl2 --network none "$IMG" sh -c "$COUNT" > /dev/null
    wait_count cpl1 3
    wait_count cpl2 3
    out=$(vx container checkpoint cpl1 nothere 2>&1)
    check "a name that is not there fails the command" 125 $?
    check_match "by its name" 'no container with name or ID "nothere" found' "$out"
    check "and nothing was checkpointed" running "$(pm inspect cpl1 --format '{{.State.Status}}')"
    out=$(vx container checkpoint --latest 2>&1)
    check "--latest checkpoints one" 1 "$(echo "$out" | wc -l)"
    check "the newest" exited "$(pm inspect cpl2 --format '{{.State.Status}}')"
    check "and not the other" running "$(pm inspect cpl1 --format '{{.State.Status}}')"
    out=$(vx container checkpoint --latest cpl1 2>&1)
    check_match "--latest and names" "cannot be used together" "$out"
    out=$(vx container restore cpl2 nothere 2>&1)
    check_match "a restore looks them up too" 'no such container or image: nothere' "$out"
    check "and restores none" exited "$(pm inspect cpl2 --format '{{.State.Status}}')"
    vx container restore --latest > /dev/null
    check "restore --latest" running "$(pm inspect cpl2 --format '{{.State.Status}}')"
    pm rm -t 0 -f cpl1 cpl2 > /dev/null
}

# the number of established TCP connections in the network namespace of a
# container (state 01 of /proc/net/tcp)
established () {
    pm exec "$1" sh -c "grep -c ' 01 ' /proc/net/tcp || true"
}

@test "restore --tcp-close restores the container with its connections closed" {
    need_criu
    pm run -d --name cptc --network none "$IMG" sh -c \
        "nc -ll -p 9000 -e /bin/cat > /dev/null & sleep 1; (while :; do echo x; sleep 0.2; done | nc 127.0.0.1 9000 > /dev/null) & $COUNT" > /dev/null
    for _ in $(seq 20); do [ "$(established cptc)" -ge 1 ] && break; sleep 0.5; done
    test "$(established cptc)" -ge 1
    check "the container has connections" 0 $?
    vx container checkpoint --tcp-established cptc > /dev/null
    last=$(pm logs cptc | tail -1)
    vx container restore --tcp-close cptc > /dev/null
    check "restore --tcp-close" running "$(pm inspect cptc --format '{{.State.Status}}')"
    wait_count cptc $((last + 2))
    check "its connections are closed" 0 "$(established cptc)"
    # (both: CRIU is given the pair)
    vx container checkpoint --tcp-established cptc > /dev/null
    vx container restore --tcp-established --tcp-close cptc > /dev/null
    check "restore --tcp-established --tcp-close" running "$(pm inspect cptc --format '{{.State.Status}}')"
    pm rm -t 0 -f cptc > /dev/null
}

# archive_list FILE: the names in an archive of a checkpoint (zstd, gzip or plain)
archive_list () {
    (zstd -dc "$1" 2> /dev/null || gzip -dc "$1" 2> /dev/null || cat "$1") | tar -t 2> /dev/null
}

@test "a pre-checkpoint is exported and the checkpoint on top of it imported with it" {
    need_criu
    pm run -d --name cpp --network none "$IMG" sh -c "$COUNT" > /dev/null
    wait_count cpp 3
    out=$(vx container checkpoint --pre-checkpoint --export "$WORKDIR/pre.tar" cpp 2>&1) ||
        { echo "$out" | grep -qi "memory tracking" && skip "no memory tracking"; }
    check "the container goes on after the pre-checkpoint" running "$(pm inspect cpp --format '{{.State.Status}}')"
    archive_list "$WORKDIR/pre.tar" | grep -q '^pre-checkpoint/inventory.img$'
    check "the archive has the images of the pre-checkpoint" 0 $?
    check "and not those of a checkpoint" 0 "$(archive_list "$WORKDIR/pre.tar" | grep -c '^checkpoint/')"
    wait_count cpp 8
    out=$(vx container checkpoint --with-previous --print-stats --export "$WORKDIR/main.tar" cpp 2>&1)
    check_match "--print-stats goes with --export" '"pages_written": [0-9]+' "$out"
    check_match "and the duration of the command" '"podman_checkpoint_duration": [1-9]' "$out"
    last=$(pm logs cpp | tail -1)
    archive_list "$WORKDIR/main.tar" | grep -q '^checkpoint/inventory.img$'
    check "the checkpoint on top of it is exported" 0 $?
    if vx container restore --import "$WORKDIR/main.tar" --name cpp2 > /dev/null 2>&1; then
        fail "the archive of a checkpoint on a pre-checkpoint was restored alone"
    fi
    check "and no container is left" 404 "$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/containers/cpp2/exists)"
    out=$(vx container restore --import "$WORKDIR/main.tar" --import-previous "$WORKDIR/pre.tar" --name cpp2 2>&1)
    check "restore --import --import-previous" running "$(pm inspect cpp2 --format '{{.State.Status}}')"
    wait_count cpp2 $((last + 2))
    out=$(vx container restore --import-previous "$WORKDIR/pre.tar" cpp 2>&1)
    check_match "--import-previous goes with --import" "--import-previous can only be used with --import" "$out"
    pm rm -t 0 -f cpp cpp2 > /dev/null
}

# podman's: the container of a pod is restored into a pod (the namespaces of
# that pod are its), and only it
@test "restore --import --pod and --publish" {
    need_criu
    pm run -d --name cpq --network none "$IMG" sh -c "$COUNT" > /dev/null
    wait_count cpq 3
    vx container checkpoint --export "$WORKDIR/q.tar" cpq > /dev/null
    out=$(vx container restore --pod nopod cpq 2>&1) || true
    check_match "--pod goes with --import" "go with --import" "$out"
    out=$(vx container restore --publish 8080:80 cpq 2>&1) || true
    check_match "--publish goes with --import" "go with --import" "$out"
    pm pod create --name cppod > /dev/null
    pm pod start cppod > /dev/null
    out=$(vx container restore --import "$WORKDIR/q.tar" --name cpq2 --pod cppod 2>&1) || true
    check_match "a container of no pod is not restored into one" "cannot restore non pod container into pod" "$out"
    check "and no container is left" 404 "$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/containers/cpq2/exists)"
    pm run -d --pod cppod --name cpq4 "$IMG" sh -c "$COUNT" > /dev/null
    wait_count cpq4 3
    vx container checkpoint --export "$WORKDIR/q4.tar" cpq4 > /dev/null
    out=$(vx container restore --import "$WORKDIR/q4.tar" --name cpq5 2>&1) || true
    check_match "a container of a pod is restored into a pod" "cannot restore pod container without --pod" "$out"
    out=$(vx container restore --import "$WORKDIR/q4.tar" --name cpq5 --pod nopod 2>&1) || true
    check_match "a pod that is not there" "nopod" "$out"
    check "and no container is left" 404 "$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/containers/cpq5/exists)"
    pm pod create --name cppod2 > /dev/null
    pm pod start cppod2 > /dev/null
    last=$(pm logs cpq4 | tail -1)
    vx container restore --import "$WORKDIR/q4.tar" --name cpq3 --pod cppod2 > /dev/null
    check "the container is restored" running "$(pm inspect cpq3 --format '{{.State.Status}}')"
    check "in the pod" "$(pm pod inspect cppod2 --format '{{.ID}}')" "$(pm inspect cpq3 --format '{{.Pod}}')"
    ns='for n in uts ipc net; do readlink /proc/1/ns/$n; done'
    check "in the namespaces of the pod" "$(pm run --rm --pod cppod2 "$IMG" sh -c "$ns")" "$(pm exec cpq3 sh -c "$ns")"
    wait_count cpq3 $((last + 2))
    pm rm -t 0 -f cpq cpq3 cpq4 > /dev/null
    pm pod rm -f cppod cppod2 > /dev/null
}

@test "restore --import --publish publishes the ports it is given instead of the archive's" {
    need_criu
    pm run -d --name cpr -p 18081:81 "$IMG" sh -c "$COUNT" > /dev/null
    wait_count cpr 3
    vx container checkpoint --export "$WORKDIR/r.tar" cpr > /dev/null
    vx container restore --import "$WORKDIR/r.tar" --name cpr2 --publish 18082:82 > /dev/null
    check "the container is restored" running "$(pm inspect cpr2 --format '{{.State.Status}}')"
    out=$(pm port cpr2)
    check_match "with the port it was given" "82/tcp -> .*:18082" "$out"
    check "and not the one of the archive" 0 "$(echo "$out" | grep -c 18081)"
    pm rm -t 0 -f cpr cpr2 > /dev/null
}

@test "a checkpoint image is made by --create-image and restored by its name" {
    need_criu
    pm run -d --name cpi --network none "$IMG" sh -c "$COUNT" > /dev/null
    wait_count cpi 3
    out=$(vx container checkpoint --create-image localhost/cpimage:1 --export "$WORKDIR/x.tar" cpi 2>&1) || true
    check_match "--create-image and --export" "can not be used with --export" "$out"
    vx container checkpoint --create-image localhost/cpimage:1 cpi > /dev/null
    check "the container is checkpointed" exited "$(pm inspect cpi --format '{{.State.Status}}')"
    out=$(pm image inspect localhost/cpimage:1 --format '{{index .Annotations "io.podman.annotations.checkpoint.name"}}')
    check "the image has the annotations of podman's checkpoint images" cpi "$out"
    last=$(pm logs cpi | tail -1)
    out=$(vx container restore --name cpi2 localhost/cpimage:1 2>&1)
    check "restore IMAGE prints the name it was given" localhost/cpimage:1 "$out"
    check "the container is restored" running "$(pm inspect cpi2 --format '{{.State.Status}}')"
    wait_count cpi2 $((last + 2))
    out=$(vx container restore --name cpi3 "$IMG" 2>&1) || true
    check_match "an image that is no checkpoint" "image is not a checkpoint" "$out"
    out=$(vx container restore --name cpi3 localhost/nosuch:1 2>&1) || true
    check_match "a name that is neither" "no such container or image: localhost/nosuch:1" "$out"
    pm rm -t 0 -f cpi cpi2 > /dev/null
    pm rmi localhost/cpimage:1 > /dev/null
}
