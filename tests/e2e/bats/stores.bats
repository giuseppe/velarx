# SPDX-License-Identifier: Apache-2.0
# Additional image stores: a store filled by another velarx is
# read-only under the store of a daemon, whose images are found and run
# without a pull, and that nothing writes or collects.  Rootless or as root
# (then the containers run on composefs where they can).
#
#   E2E_TMPDIR=/var/tmp VELARX_BINDIR=target/debug bats tests/e2e/bats/stores.bats

load helpers

stop_daemon () {
    local pid
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if test -n "$pid"; then
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid" 10
        kill -KILL "$pid" 2> /dev/null || true
        rm -f "$WORKDIR/daemon.pid"
    fi
}

config () { # name, store root, extra lines of [storage]
    cat > "$WORKDIR/$1.toml" <<EOT
[engine]
socket = "$WORKDIR/$1.sock"
[server]
socket = "$WORKDIR/$1.sock"
state_dir = "$WORKDIR/$1-state"
root_dir = "$WORKDIR/$1-root"
[storage]
root = "$2"
$3
[pull]
EOT
}

start_daemon () { # name
    # (one daemon at a time; every pid is kept for the teardown)
    stop_daemon
    SOCK=$WORKDIR/$1.sock
    E2E_SPAWN_LOG=$WORKDIR/$1.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --config "$WORKDIR/$1.toml" varlink || return 1
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    return 0
}
sh_ () { "$BIN/velarx" --socket "$SOCK" "$@"; }
# need_main: the daemon on the other store (the second test) runs
need_main () {
    SOCK=$WORKDIR/main.sock
    if ! sh_ image inspect "$IMAGE" > /dev/null 2>&1; then
        echo "the daemon with the additional store is not there: the test 'the image of the other store is listed and runs without a pull' failed or did not run" >&2
        exit 1
    fi
}
# the state of every file of a tree: its type, size, mode, owner, links,
# times of change (a new name of a file changes its link count and ctime)
# and the content of the regular files
tree_sum () { # dir, where the listing goes
    { find "$1" -printf '%P %y %s %m %u %n %T@ %C@\n'
      find "$1" -type f -exec sha256sum {} +; } | sort > "$2"
    sha256sum < "$2" | cut -d' ' -f1
}
# the commands that read the images of the other store (or try to change
# them): the root of a user namespace passes the permissions of the store,
# so only the engine keeps it as it is
read_everything () {
    sh_ image list > /dev/null 2>&1
    sh_ image inspect "$IMAGE" > /dev/null 2>&1
    sh_ image history "$IMAGE" > /dev/null 2>&1
    sh_ image save -o "$WORKDIR/saved.tar" "$IMAGE" > /dev/null 2>&1
    check "an image of it is saved" 0 $?
    rm -f "$WORKDIR/saved.tar"
    sh_ container run --rm --pull=never --network none "$IMAGE" true > /dev/null 2>&1
    check "a container of it runs" 0 $?
    sh_ image exists "$IMAGE"
    sh_ image tree "$IMAGE" > /dev/null 2>&1
    sh_ image complete "$IMAGE" > /dev/null 2>&1
    sh_ system check > /dev/null 2>&1
    check "a check of a store with the other one is clean" 0 $?
    sh_ system check --repair > /dev/null 2>&1
    sh_ system df > /dev/null 2>&1
    sh_ image rm "$IMAGE" > /dev/null 2>&1
    sh_ image rm -f "$IMAGE" > /dev/null 2>&1
    # a build from it and a commit of a container of it are images of
    # this store
    mkdir -p "$WORKDIR/ctx"
    printf 'FROM %s\nRUN echo built > /built\n' "$IMAGE" > "$WORKDIR/ctx/Containerfile"
    sh_ image build -q --network none -t localhost/derived:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "an image is built from it" 0 $?
    sh_ container run -d --name c2 --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    sh_ container exec c2 sh -c 'echo x > /written' > /dev/null 2>&1
    sh_ container commit c2 localhost/committed:1 > /dev/null 2>&1
    check "a container of it is committed" 0 $?
    sh_ container rm -t 0 -f c2 > /dev/null 2>&1
    sh_ image rm localhost/derived:1 localhost/committed:1 > /dev/null 2>&1
    sh_ image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
    sh_ system gc > /dev/null 2>&1
}

setup_file () {
    local t
    for t in crun curl; do
        command -v $t > /dev/null || skip "no $t"
    done
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    export IMAGE=$E2E_REGISTRY/alpine:chunked
    mkdir -p "$XDG_DATA_HOME"
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
}

# a failing check must not leak the container
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then
        sh_ container rm -t 0 -f c1 > /dev/null 2>&1
    fi
    return 0
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    stop_daemon
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m" 2> /dev/null; done
    chmod -R u+w "$WORKDIR/ro" "$WORKDIR/unclean" 2> /dev/null
    if test -z "${E2E_KEEP:-}" && [ "$(id -u)" != 0 ]; then
        # the files of user namespaces of containers (velarx's own unshare:
        # podman's would start its pause process, which outlives the test)
        "$BIN/velarx" unshare rm -rf "$WORKDIR" 2> /dev/null
    fi
    e2e_teardown_file
}

# the files SQLite keeps next to the database of a store while it is used
# (the `-changes` file is velarx's own and stays)
db_side_files () { # store root
    find "$1" -maxdepth 1 -name 'db.sqlite-*' ! -name '*-changes'
}

@test "the other store pulls" {
    # the store of another instance, with the image, filled by a command
    # without a daemon
    config filler "$WORKDIR/ro" ""
    "$BIN/velarx" --config "$WORKDIR/filler.toml" image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "the other store pulls" 0 $?
    # (the command closed the database: no log, no shared memory file)
    check "the store is closed cleanly" "" "$(db_side_files "$WORKDIR/ro")"
    # the user's alone and not writable (which the root of a user
    # namespace passes)
    chmod -R a-w,go-rwx "$WORKDIR/ro"
    before=$(tree_sum "$WORKDIR/ro" "$WORKDIR/ro.before")
    echo "$before" > "$WORKDIR/ro.sum"
}

@test "commands that read, write or fail leave their store closed" {
    config closed "$WORKDIR/closed" ""
    V="$BIN/velarx --config $WORKDIR/closed.toml"
    $V image pull --tls-verify=false "$E2E_REGISTRY/nonexistent:nothing" > /dev/null 2>&1
    check "a pull of a missing image fails" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check "and leaves no log" "" "$(db_side_files "$WORKDIR/closed")"
    $V image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a pull works" 0 $?
    check "and leaves no log" "" "$(db_side_files "$WORKDIR/closed")"
    before=$(stat -c '%s %.9Y' "$WORKDIR/closed/db.sqlite"; sha256sum < "$WORKDIR/closed/db.sqlite")
    $V image list > /dev/null 2>&1
    check "a command that reads works" 0 $?
    check "and leaves no log" "" "$(db_side_files "$WORKDIR/closed")"
    # (a command that only reads records nothing of the namespaces it joins)
    check "and writes nothing to the database" "$before" "$(stat -c '%s %.9Y' "$WORKDIR/closed/db.sqlite"; sha256sum < "$WORKDIR/closed/db.sqlite")"
    $V image rm "$IMAGE" > /dev/null 2>&1
    check "an image is removed" 0 $?
    check "and the store has no log" "" "$(db_side_files "$WORKDIR/closed")"
}

@test "the image of the other store is listed and runs without a pull" {
    config main "$WORKDIR/main" "additional_image_stores = [\"$WORKDIR/ro\"]"
    start_daemon main || { echo "the daemon does not start"; cat "$WORKDIR/main.log"; exit 1; }
    check "its image is listed, read-only" "$IMAGE true" \
        "$(sh_ image list --format '{{.Repository}}:{{.Tag}} {{.ReadOnly}}' 2>&1)"
    out=$(sh_ container run --rm --pull=never --network none "$IMAGE" cat /etc/alpine-release 2>&1)
    check_match "a container of it runs without a pull" "^[0-9]+\.[0-9]+" "$out"
    check "nothing was pulled" 0 "$(grep -c 'Pulling image' "$WORKDIR/main.log")"
    check_match "it is inspected" "^sha256:" "$(sh_ image inspect --format '{{.Digest}}' "$IMAGE" 2>&1)"
}

@test "the image of the other store cannot be removed" {
    need_main
    out=$(sh_ image rm "$IMAGE" 2>&1)
    check "it cannot be removed" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "and says why" "read-only image store" "$out"
    out=$(sh_ image untag "$IMAGE" 2>&1)
    check "its name cannot be removed" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "and says why" "read-only image store" "$out"
}

@test "the image takes a name of this store" {
    need_main
    sh_ image tag "$IMAGE" localhost/mine:1 > /dev/null 2>&1
    check "it takes a name of this store" 0 $?
    check "with its own" "$IMAGE localhost/mine:1" \
        "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1 | sort | tr '\n' ' ' | sed 's/ $//')"
    sh_ image untag "$IMAGE" localhost/mine:1 > /dev/null 2>&1
    check "the name of this store is removed" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
}

@test "a detached container of the image runs" {
    need_main
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a detached container of it runs" 0 $?
    check_match "it reads the image" "^[0-9]+\.[0-9]+" "$(sh_ container exec c1 cat /etc/alpine-release 2>&1)"
    if [ "$(id -u)" = 0 ]; then
        id=$(sh_ container inspect --format '{{.Id}}' c1)
        log=$(find "$WORKDIR/main-state" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat)
        check_match "on composefs, with the files of the other store" "root file system: mount descriptor 0 of the storage driver" "$log"
    fi
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
}

@test "an image of the other store is pushed, saved, committed and built on" {
    need_main
    local repo=$E2E_REGISTRY/stores-rule/alpine
    sh_ image push --tls-verify=false "$IMAGE" "$repo:pushed" > "$WORKDIR/push.out" 2>&1
    check "it is pushed" 0 $?
    layers=$(skopeo inspect --tls-verify=false --raw "docker://$repo:pushed" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)["layers"]))')
    check "with its layers" "$(sh_ image inspect "$IMAGE" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)[0]["RootFS"]["Layers"]))')" "$layers"
    sh_ image save -o "$WORKDIR/saved.tar" "$IMAGE" > /dev/null 2>&1
    check "it is saved" 0 $?
    check "as an archive of its layers" "$layers" \
        "$(skopeo inspect --raw "oci-archive:$WORKDIR/saved.tar" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)["layers"]))')"
    rm -f "$WORKDIR/saved.tar"
    mkdir -p "$WORKDIR/ctx"
    printf 'FROM %s\nRUN echo built > /built\n' "$IMAGE" > "$WORKDIR/ctx/Containerfile"
    sh_ image build -q --network none -t localhost/derived:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "an image is built from it" 0 $?
    check "which runs, with the file it made" "built" \
        "$(sh_ container run --rm --pull=never --network none localhost/derived:1 cat /built 2>&1)"
    check_match "and has the layers of the other store" "^[0-9]+\.[0-9]+" \
        "$(sh_ container run --rm --pull=never --network none localhost/derived:1 cat /etc/alpine-release 2>&1)"
    sh_ container run -d --name c2 --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    sh_ container exec c2 sh -c 'echo x > /written' > /dev/null 2>&1
    sh_ container commit c2 localhost/committed:1 > /dev/null 2>&1
    check "a container of it is committed" 0 $?
    sh_ container rm -t 0 -f c2 > /dev/null 2>&1
    check "the commit has the file" "x" \
        "$(sh_ container run --rm --pull=never --network none localhost/committed:1 cat /written 2>&1)"
    check "and the other layers" "$layers" \
        "$(sh_ image inspect localhost/committed:1 | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)[0]["RootFS"]["Layers"]) - 1)')"
    sh_ image rm localhost/derived:1 localhost/committed:1 > /dev/null 2>&1
    skopeo delete --tls-verify=false "docker://$repo:pushed" > /dev/null 2>&1 || true
}

@test "a rootless container of the other store is served by the image server" {
    [ "$(id -u)" != 0 ] || skip "rootless only"
    need_main
    sh_ container run -d --name c1 --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    id=$(sh_ container inspect --format '{{.Id}}' c1)
    log=$(find "$WORKDIR/main-state" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat)
    check_match "its root is the image server's mount" "image server of the root file system: pid" "$log"
    sh_ container rm -t 0 -f c1 > /dev/null 2>&1
}

@test "prune and pull leave the other store as it is" {
    need_main
    before=$(cat "$WORKDIR/ro.sum" 2> /dev/null)
    [ -n "$before" ] || { echo "no sum of the other store: the test 'the other store pulls' failed or did not run" >&2; exit 1; }
    read_everything
    sh_ image prune -a -f > /dev/null 2>&1
    check "a prune leaves it" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    out=$(sh_ system prune -a -f 2>&1)
    check_match "a system prune says it removed nothing" "Total reclaimed space: 0 B" "$out"
    check "so does a system prune" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    check_match "df counts the image of the other store" "Images +1 " "$(sh_ system df 2>&1)"
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "a pull of it takes its records" 0 $?
    check "and runs it from there" "$IMAGE true" \
        "$(sh_ image list --format '{{.Repository}}:{{.Tag}} {{.ReadOnly}}' 2>&1)"
    stop_daemon
    after=$(tree_sum "$WORKDIR/ro" "$WORKDIR/ro.after")
    diff "$WORKDIR/ro.before" "$WORKDIR/ro.after" | sed 's/^/# /'
    check "nothing in the other store changed" "$before" "$after"
    check "no file of it was copied" 0 "$(find "$WORKDIR/main/objects" -type f 2> /dev/null | wc -l)"
}

@test "a store on a read-only mount is used and left as it is" {
    [ "$(id -u)" = 0 ] || skip "a bind mount needs root"
    before=$(cat "$WORKDIR/ro.sum" 2> /dev/null)
    [ -n "$before" ] || { echo "no sum of the other store: the test 'the other store pulls' failed or did not run" >&2; exit 1; }
    mkdir -p "$WORKDIR/romnt"
    mount --bind "$WORKDIR/ro" "$WORKDIR/romnt" && mount -o remount,bind,ro "$WORKDIR/romnt"
    check "the store is mounted read-only" 0 $?
    config onmount "$WORKDIR/onmount" "additional_image_stores = [\"$WORKDIR/romnt\"]"
    start_daemon onmount || { echo "the daemon does not start"; cat "$WORKDIR/onmount.log"; exit 1; }
    check "its image is listed, read-only" "$IMAGE true" \
        "$(sh_ image list --format '{{.Repository}}:{{.Tag}} {{.ReadOnly}}' 2>&1)"
    read_everything
    sh_ image prune -a -f > /dev/null 2>&1
    sh_ system prune -a -f > /dev/null 2>&1
    check "a prune leaves it" "$IMAGE" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    stop_daemon
    umount "$WORKDIR/romnt"
    check "nothing in the other store changed" "$before" "$(tree_sum "$WORKDIR/ro" "$WORKDIR/ro.after")"
}

@test "a store whose owner was killed is skipped with a warning" {
    # a daemon that is killed leaves the log of its database
    config owner "$WORKDIR/unclean" ""
    start_daemon owner || { echo "the daemon does not start"; cat "$WORKDIR/owner.log"; exit 1; }
    sh_ image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "the owner pulls" 0 $?
    kill -KILL "$DAEMON_PID"
    e2e_wait_exit "$DAEMON_PID" 10
    rm -f "$WORKDIR/daemon.pid"
    [ -s "$WORKDIR/unclean/db.sqlite-wal" ] || skip "the owner left no log"
    chmod -R a-w,go-rwx "$WORKDIR/unclean"
    before=$(tree_sum "$WORKDIR/unclean" "$WORKDIR/unclean.before")
    config reader "$WORKDIR/reader" "additional_image_stores = [\"$WORKDIR/unclean\"]"
    start_daemon reader || { echo "the daemon does not start"; cat "$WORKDIR/reader.log"; exit 1; }
    check_match "the log names the store, says why and what to do" \
        "additional image store .*unclean is not used: it has a write-ahead log.*its owner runs a command that writes nothing" "$(cat "$WORKDIR/reader.log")"
    check "its images are not listed" "" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    stop_daemon
    check "nothing in it changed" "$before" "$(tree_sum "$WORKDIR/unclean" "$WORKDIR/unclean.after")"
    # any command of the owner recovers the log and closes the store
    chmod -R u+w "$WORKDIR/unclean"
    "$BIN/velarx" --config "$WORKDIR/owner.toml" image list > /dev/null 2>&1
    check "a command of the owner recovers the store" 0 $?
    check "which is closed" "" "$(db_side_files "$WORKDIR/unclean")"
}

@test "a store that is not one fails the start" {
    config bad "$WORKDIR/bad" "additional_image_stores = [\"$WORKDIR/nowhere\"]"
    ! start_daemon bad || e2e_die "the daemon starts"
    check_match "the error names it and how to start without it" \
        "additional image store .*nowhere: .*remove it from \[storage\] additional_image_stores" "$(cat "$WORKDIR/bad.log")"
    out=$("$BIN/velarx" --config "$WORKDIR/bad.toml" image list 2>&1)
    check "a command without a daemon fails" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    check_match "with the same error" "additional image store .*nowhere: " "$out"
}

@test "a store of another schema version fails the start" {
    mkdir -p "$WORKDIR/future"
    sqlite3 "$WORKDIR/future/db.sqlite" 'PRAGMA user_version = 99; CREATE TABLE t (a);'
    config future "$WORKDIR/futuremain" "additional_image_stores = [\"$WORKDIR/future\"]"
    ! start_daemon future || e2e_die "the daemon starts"
    check_match "the error names it and the version" "additional image store .*future: .*schema version 99" "$(cat "$WORKDIR/future.log")"
}

@test "a store made with another storage driver fails the start" {
    # (the row of a copy of the database says so: it is all the check reads)
    mkdir -p "$WORKDIR/vfsstore"
    cp "$WORKDIR/ro/db.sqlite" "$WORKDIR/vfsstore/db.sqlite"
    chmod u+w "$WORKDIR/vfsstore/db.sqlite"
    sqlite3 "$WORKDIR/vfsstore/db.sqlite" "INSERT OR REPLACE INTO store_settings (key, value) VALUES ('driver', 'vfs')"
    config vfsmain "$WORKDIR/vfsmain" "additional_image_stores = [\"$WORKDIR/vfsstore\"]"
    ! start_daemon vfsmain || e2e_die "the daemon starts"
    check_match "the error names the store and its driver" \
        "additional image store .*vfsstore: .*storage driver \"vfs\".*composefs" "$(cat "$WORKDIR/vfsmain.log")"
}
