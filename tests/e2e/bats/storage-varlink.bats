# SPDX-License-Identifier: Apache-2.0
# The varlink storage driver: the storage is kept by a program of its own that
# serves org.velarx.Storage on a unix socket (here the reference server,
# velarx-storage-server, on a private socket), selected by `[storage] driver =
# "varlink"` and `[storage.varlink]`.  What runs on a store made with it (pull,
# run, exec, restart, commit, diff, cp, a user namespace, build, import, an image
# mounted in a container, rm, image rm, gc, prune), what `info` says of it, what
# it refuses (fs-verity enforced while a container runs, an image whose tables
# of contents have no fs-verity digests, `alpine-plain:chunked`), lazy images (staged and run by the
# engine, completed into the service),
# the service stopped, a service of another version, the settings that are
# wrong, and the store the service drops when everything is removed.  Run it
# as an ordinary user for the rootless daemon, or as root (which adds the image
# mount, that the server has only for root).
#
#   E2E_REGISTRY=localhost:5360 VELARX_BINDIR=target/debug bats tests/e2e/bats/storage-varlink.bats

load helpers
load run_lib
load storage_lib

# the storage service: its directory (socket, stores, the files of the tests)
# is made before the work directory, so that the configuration can name it
before_daemon () {
    [ -x "$BIN/velarx-storage-server" ] || skip "cannot find $BIN/velarx-storage-server"
    start_storage
}

setup_file () {
    export VDIR
    VDIR=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-e2e-varlink.XXXXXX")
    export E2E_STORAGE_LINES="storage.driver = \"varlink\"
storage.varlink.socket = \"$VDIR/s.sock\"
storage.varlink.name = \"velarx-storage-ref\"
pull.lazy_completers = 0"
    export E2E_BEFORE_DAEMON=before_daemon
    run_setup_file
}

teardown_file () {
    set +e
    run_teardown_file
    stop_storage
    [ -z "${VDIR:-}" ] || { chmod -R u+rwX "$VDIR" 2> /dev/null; rm -rf "$VDIR"; }
}

@test "the store records varlink, info says it, the service and its capabilities" {
    check "storageDriver, velarx's own" varlink "$(sh_ info --format '{{.Store.StorageDriver}}')"
    check "graphDriverName" varlink "$(sh_ info --format '{{.Store.GraphDriverName}}')"
    out=$(sh_ info --format json | field store.graphStatus)
    check_match "the socket" "$VDIR/s.sock" "$out"
    check_match "the service and its version" 'velarx-storage-ref [0-9]' "$out"
    check_match "the store id" '"store": "[0-9a-f]{32}"' "$out"
    check_match "the capabilities (lazy is the engine's)" 'lazy yes, rootless yes, fs-verity at pull only' "$out"
    check "the driver is recorded in the store" varlink "$(sqlite3 "$(store)/db.sqlite" "SELECT value FROM store_settings WHERE key = 'driver'")"
    check "the schema is version 1" 1 "$(sqlite3 "$(store)/db.sqlite" 'PRAGMA user_version')"
    id=$(cat "$(store)/varlink/store-id")
    check_match "the id of the store is a file of the graph root" '^[0-9a-f]{32}$' "$id"
    check "and is not in the database" 0 "$(sqlite3 "$(store)/db.sqlite" "SELECT count(*) FROM store_settings WHERE value = '$id'")"
    check "the service keeps the store under it" 1 "$(test -d "$(sdir)"; echo $((1 - $? )))"
    if [ -S "$SOCK" ]; then
        check "libpod info" varlink "$(curl -s --unix-socket "$SOCK" http://d/v5.0.0/libpod/info | field store.storageDriver)"
    fi
}

@test "a pull is the service's: the engine keeps the index of the layers, no object, no EROFS image" {
    [ "$(sh_ image list | grep -c alpine)" -ge 1 ]
    check "no object of the store is the engine's" 0 "$(find "$(store)/objects" -type f 2> /dev/null | wc -l)"
    check "no EROFS image" 0 "$(find "$(store)" -name '*.erofs' | wc -l)"
    [ "$(find "$(sdir)" -type f | wc -l)" -ge 1 ]
    check "the service has the files" 0 $?
    # a second pull finds every layer in the service (HasLayers): nothing is fetched
    : > "$WORKDIR/registry-gets"
    out=$(sh_ image pull "$IMAGE" 2>&1)
    check "pull again" 0 $?
    sh_ image inspect "$IMAGE" > /dev/null
    check "the image is there" 0 $?
}

@test "an image of two layers whose manifest states the merged EROFS digest: pulled, run, each layer in the service" {
    two_layer_image
    two=$E2E_REGISTRY/e2e/varlink-two:1
    out=$(sh_ image pull "$two" 2>&1)
    check "the pull ($out)" 0 $?
    check "the layers of the image are in the service" 1 "$([ "$(sqlite3 "$(sdir)/db" 'SELECT count(*) FROM layers')" -ge 2 ]; echo $((1 - $?)))"
    check "a file of the second layer, and one of the first" two:ok "$(sh_ container run --rm --network none "$two" sh -c 'cat /two; test -e /etc/os-release && echo ok' | tr '\n' ':' | sed 's/:$//')"
    sh_ image rm -f "$two" > /dev/null
}

@test "run, exec, restart: the root file system is a directory the service made, no kernel mount" {
    id=$(sh_ container run -d --name v1 --network none "$IMAGE" sh -c 'echo made > /root/made; sleep 1000')
    out=$(sh_ container exec v1 sh -c 'cat /root/made; grep " / " /proc/self/mountinfo')
    check_match "the file the container made" "^made$" "$out"
    ! printf '%s' "$out" | grep -Eq ' - (erofs|overlay|fuse|fuse\.[a-z-]+) '
    check "the root is not an overlay, EROFS or FUSE" 0 $?
    check "the monitor says the root is a directory" 1 "$(grep -rhs --include=monitor.log -c 'root file system: directory' "$WORKDIR" | awk '{ n += $1 } END { print (n > 0) }')"
    plan=$(find "$(store)/bundles" -name rootfs.json | head -1)
    check_match "the plan is a directory beneath the work directory of the store" "\"beneath\": ?\"$(store)/varlink/work\"" "$(cat "$plan")"
    check "that directory is the engine's alone" 700 "$(stat -c %a "$(store)/varlink/work")"
    sh_ container stop -t 0 v1 > /dev/null
    sh_ container start v1 > /dev/null
    check "a restart keeps the root" made "$(sh_ container exec v1 cat /root/made)"
    sh_ container rm -f -t 0 v1 > /dev/null
    check "no plan is left" 0 "$(find "$(store)/bundles" -name rootfs.json | wc -l)"
}

@test "a root is the container's own: the image and another container do not see its changes" {
    sh_ container run -d --name v2 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container run -d --name v3 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container exec v2 sh -c 'echo only-v2 > /etc/own; rm /etc/os-release' > /dev/null
    check "the other container has the file of the image" 0 "$(sh_ container exec v3 test -f /etc/os-release; echo $?)"
    check "and not what v2 made" 1 "$(sh_ container exec v3 test -e /etc/own; echo $?)"
    sh_ container rm -f -t 0 v2 v3 > /dev/null
}

@test "--user, --workdir and --tz: read from a mount of the image, the entries written into the container's own layer" {
    out=$(sh_ container run --rm --network none --user daemon "$IMAGE" id)
    check_match "a user of the image's /etc/passwd" 'uid=2\(daemon\)' "$out"
    out=$(sh_ container run --rm --network none --user daemon:adm "$IMAGE" id)
    check_match "and a group of its /etc/group" 'gid=4\(adm\)' "$out"
    sh_ container run -d --name u1 --network none --user 4242:4243 "$IMAGE" sleep 1000 > /dev/null || e2e_die "run"
    check "a user the image lacks runs with its ids" 4242:4243 "$(sh_ container exec u1 id -u):$(sh_ container exec u1 id -g)"
    check_match "and has its entry in /etc/passwd" '^4242:' "$(sh_ container exec u1 cat /etc/passwd)"
    out=$(sh_ container diff u1)
    check_match "the entry is in the container's own layer: /etc" '^C /etc$' "$out"
    check_match "and /etc/passwd" '^C /etc/passwd$' "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'grep -c "^4242:" /etc/passwd || true')
    check "the image and the other containers do not have it" 0 "$out"
    out=$(sh_ container exec --user 5151 u1 id -u)
    check "exec as a user the image lacks" 5151 "$out"
    sh_ container rm -f -t 0 u1 > /dev/null
    check "a working directory of the image" /etc "$(sh_ container run --rm --network none --workdir /etc "$IMAGE" pwd)"
    out=$(sh_ container run --rm --network none --workdir /no/such/dir "$IMAGE" pwd 2>&1)
    check_match "one it lacks is podman's error" 'workdir "/no/such/dir" does not exist on container' "$out"
    out=$(sh_ container run --rm --network none --workdir /etc/passwd "$IMAGE" pwd 2>&1)
    check_match "and a file is not a directory" 'exists on container .*, but is not a directory' "$out"
    check "--tz makes /etc/localtime" TZif "$(sh_ container run --rm --network none --tz Europe/Berlin "$IMAGE" sh -c 'head -c 4 /etc/localtime')"
}

@test "diff, commit, cp and export of a container of the service: the layer is read whole and the service gets the files it lacks" {
    sh_ container run -d --name v4 --network none "$IMAGE" sh -c 'echo new > /root/new; mkdir /opt/d; echo x > /opt/d/f; rm /etc/motd; ln /root/new /root/new2; mkfifo /root/fifo; echo ready; sleep 1000' > /dev/null
    e2e_wait_log v4 '^ready$' || e2e_die "v4 does not run its command"
    out=$(sh_ container diff v4)
    check_match "an added file" '^A /root/new$' "$out"
    check_match "a deleted file" '^D /etc/motd$' "$out"
    check_match "a directory added with its content" '^A /opt/d/f$' "$out"
    sh_ cp v4:/root/new "$WORKDIR/new.out"
    check "cp out of a running container" new "$(cat "$WORKDIR/new.out")"
    echo "in" > "$WORKDIR/in.txt"
    sh_ cp "$WORKDIR/in.txt" v4:/root/in.txt
    check "cp into it" in "$(sh_ container exec v4 cat /root/in.txt)"
    out=$(sh_ container commit v4 localhost/e2e/varlink:1 2>&1)
    check "commit ($out)" 0 $?
    out=$(sh_ container run --rm --network none localhost/e2e/varlink:1 sh -c 'cat /root/new /opt/d/f; test -e /etc/motd || echo nomotd; stat -c %h /root/new')
    check_match "the committed layer has the files" '^new$' "$out"
    check_match "and the deletion" '^nomotd$' "$out"
    check_match "and the hard link" '^2$' "$out"
    check "the committed image has one layer more than its base" $(( $(sh_ image inspect --format '{{len .RootFS.Layers}}' "$IMAGE") + 1 )) "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/varlink:1)"
    check "the layer is in the service, the engine has no object of it" 0 "$(find "$(store)/objects" -type f 2> /dev/null | wc -l)"
    check "the container is as it was" new "$(sh_ container exec v4 cat /root/new)"
    sh_ container stop -t 0 v4 > /dev/null
    check "cp out of a stopped container" new "$(sh_ cp v4:/root/new - | tar -xO)"
    check "diff of a stopped container" 1 "$(sh_ container diff v4 | grep -c '^A /root/new$')"
    sh_ container export v4 | tar -t | grep -q '^root/new$'
    check "export has the file" 0 $?
    # a squashed commit
    out=$(sh_ container commit --squash v4 localhost/e2e/varlink:sq 2>&1)
    check "a squashed commit ($out)" 0 $?
    check "it has one layer" 1 "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/varlink:sq)"
    check "and the deletion in it" nomotd "$(sh_ container run --rm --network none localhost/e2e/varlink:sq sh -c 'test -e /etc/motd || echo nomotd; test -e /root/new && echo kept' | head -1)"
    check "and the fifo the container made" fifo "$(sh_ container run --rm --network none localhost/e2e/varlink:sq sh -c 'test -p /root/fifo && echo fifo')"
    # a commit again of the same changes: every layer is there, nothing is written
    out=$(sh_ container commit v4 localhost/e2e/varlink:again 2>&1)
    check "a commit again ($out)" 0 $?
    sh_ container rm -f -t 0 v4 > /dev/null
    sh_ image rm -f localhost/e2e/varlink:1 localhost/e2e/varlink:sq localhost/e2e/varlink:again > /dev/null
}

@test "a container with a user namespace: its ids as root, refused up front for a service that cannot give them" {
    out=$(sh_ container run --rm --network none --uidmap 0:1:1000 --gidmap 0:1:1000 "$IMAGE" sh -c 'id -u; stat -c "%u:%g" /etc/passwd /root' 2>&1)
    rc=$?
    if [ "$(id -u)" != 0 ]; then
        check "an unprivileged service cannot give the ids of a mapping" 125 "$rc"
        check_match "refused before anything is made, naming the driver" 'storage driver velarx-storage-ref cannot show the ids of a container with a user namespace of its own.*--userns=host' "$out"
        return 0
    fi
    check "run" 0 "$rc"
    check_match "root of the container" '^0$' "$out"
    check_match "the owners are the container's" '^0:0$' "$out"
}

@test "build: RUN, COPY and --squash, and import, make layers the service stores" {
    ctx=$WORKDIR/ctx
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN echo built > /built && rm /etc/motd\nCOPY f /f\nRUN cat /f /built\n' "$IMAGE" > "$ctx/Dockerfile"
    echo hello > "$ctx/f"
    sh_ build -t localhost/e2e/varlink-b:1 "$ctx" > "$WORKDIR/build.log" 2>&1
    check "build ($(tail -3 "$WORKDIR/build.log"))" 0 $?
    out=$(sh_ container run --rm --network none localhost/e2e/varlink-b:1 sh -c 'cat /built /f; test -e /etc/motd || echo nomotd')
    check_match "RUN and COPY" '^built$' "$out"
    check_match "the file of COPY" '^hello$' "$out"
    check_match "the deletion of a step" '^nomotd$' "$out"
    base=$(sh_ image inspect --format '{{len .RootFS.Layers}}' "$IMAGE")
    [ "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/varlink-b:1)" -ge $((base + 2)) ]
    check "a layer for the steps that change files" 0 $?
    # a build again finds every step in the cache
    sh_ build -t localhost/e2e/varlink-b:again "$ctx" > "$WORKDIR/build.log" 2>&1
    check "build again" 0 $?
    check "the same image" "$(sh_ image inspect --format '{{.Id}}' localhost/e2e/varlink-b:1)" "$(sh_ image inspect --format '{{.Id}}' localhost/e2e/varlink-b:again)"
    sh_ build --squash -t localhost/e2e/varlink-b:2 "$ctx" > "$WORKDIR/build.log" 2>&1
    check "build --squash ($(tail -3 "$WORKDIR/build.log"))" 0 $?
    check "the steps are one layer over the base" $((base + 1)) "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/varlink-b:2)"
    check "the squashed image runs" built "$(sh_ container run --rm --network none localhost/e2e/varlink-b:2 cat /built)"
    sh_ build --squash-all -t localhost/e2e/varlink-b:3 "$ctx" > "$WORKDIR/build.log" 2>&1
    check "build --squash-all ($(tail -3 "$WORKDIR/build.log"))" 0 $?
    check "one layer" 1 "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/varlink-b:3)"
    check "that has the base and the steps" ok "$(sh_ container run --rm --network none localhost/e2e/varlink-b:3 sh -c 'test -e /etc/os-release && test -e /built && echo ok')"
    # an import makes a layer from a tar
    mkdir -p "$WORKDIR/imp"
    echo hi > "$WORKDIR/imp/hi"
    ln "$WORKDIR/imp/hi" "$WORKDIR/imp/hi2"
    tar -C "$WORKDIR/imp" -cf "$WORKDIR/imp.tar" hi hi2
    out=$(sh_ image import "$WORKDIR/imp.tar" localhost/e2e/varlink-i:1 2>&1)
    check "import ($out)" 0 $?
    check "one layer" 1 "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/e2e/varlink-i:1)"
    out=$(sh_ container create --name imp --network none localhost/e2e/varlink-i:1 /hi 2>&1)
    check "a container of it ($out)" 0 $?
    check "its file" hi "$(sh_ cp imp:/hi - | tar -xO)"
    sh_ container rm -f -t 0 imp > /dev/null
    sh_ image rm -f localhost/e2e/varlink-b:1 localhost/e2e/varlink-b:again localhost/e2e/varlink-b:2 localhost/e2e/varlink-b:3 localhost/e2e/varlink-i:1 > /dev/null
    sh_ image prune -f > /dev/null
    check "the images of the steps are gone" 0 "$(sh_ image list -a | grep -c '<none>')"
    check "the base is still there" 0 "$(sh_ image inspect "$IMAGE" > /dev/null 2>&1; echo $?)"
}

@test "an image pushed from the store of the service is read back from it, a pull of it is the same image" {
    sh_ image tag "$IMAGE" localhost/e2e/varlink:1
    sh_ image push --tls-verify=false localhost/e2e/varlink:1 "$E2E_REGISTRY/e2e/varlink:1" > "$WORKDIR/push.log" 2>&1
    check "push" 0 $?
    out=$(curl -s "http://$E2E_REGISTRY/v2/e2e/varlink/manifests/1" -H 'Accept: application/vnd.oci.image.manifest.v1+json')
    check_match "the manifest is the image's own" "$(sh_ image inspect --format '{{.Id}}' "$IMAGE")" "$out"
    sh_ image save -o "$WORKDIR/saved.tar" localhost/e2e/varlink:1
    check "save" 0 $?
    tar -tf "$WORKDIR/saved.tar" | grep -Eq '(^|/)(manifest|index)\.json$'
    check "the archive has the image" 0 $?
    sh_ image rm -f localhost/e2e/varlink:1 > /dev/null
    sh_ image pull "$E2E_REGISTRY/e2e/varlink:1" > /dev/null
    check "pull of the pushed image" 0 $?
    check "the same image" "$(sh_ image inspect --format '{{.Id}}' "$IMAGE")" "$(sh_ image inspect --format '{{.Id}}' "$E2E_REGISTRY/e2e/varlink:1")"
    sh_ image rm -f "$E2E_REGISTRY/e2e/varlink:1" > /dev/null 2>&1 || true
}

@test "an option the service does not have is refused up front, naming the driver" {
    out=$(sh_ container create --name v7 --network none --security-opt verity=enforce "$IMAGE" true 2>&1)
    check "enforced digests for a container" 125 $?
    check_match "and says why and what to do" 'checks fs-verity only when a layer is pulled.*fsverity_best_effort = true' "$out"
    stop_daemon
    cp "$CONFIG" "$CONFIG.orig"
    sed -i '/^storage.driver/a storage.fsverity_require = true' "$CONFIG"
    out=$("$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check "the engine does not start with fsverity_require" 125 $?
    check_match "it says which setting" 'storage.*fsverity_require.*fsverity_best_effort = true' "$out"
    cp "$CONFIG.orig" "$CONFIG"
    sed -i '/^storage.driver/a storage.additional_image_stores = ["/nonexistent"]' "$CONFIG"
    out=$("$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check "nor with read-only image stores" 125 $?
    check_match "it says which setting" 'additional_image_stores' "$out"
    mv "$CONFIG.orig" "$CONFIG"
    start_daemon
}

# the monitor log of the container NAME (the root of a lazy container is the
# engine's image server)
monitor_log () {
    local id
    id=$(sh_ container inspect "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    find "$WORKDIR" -path "*/${id:0:12}*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat
}

@test "an image whose tables of contents have no fs-verity digests is refused, lazily or not, before anything is staged, naming the layer" {
    local plain=$E2E_REGISTRY/alpine-plain:chunked
    curl -sf -m 5 -o /dev/null -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
        "http://$E2E_REGISTRY/v2/alpine-plain/manifests/chunked" || skip "no $plain"
    for lazy in --lazy ""; do
        # shellcheck disable=SC2086
        out=$(sh_ image pull $lazy --tls-verify=false "$plain" 2>&1)
        check "the pull ($lazy) is refused" 125 $?
        check_match "the layer is named" 'layer sha256:[0-9a-f]{64}' "$out"
        check_match "and the missing digest" 'its table of contents has no fs-verity digest for' "$out"
        check "no pull is in progress" "" "$(sh_ image pulls -q)"
        check "nothing is staged" 0 "$(find "$(store)/staging/meta" -name layer.json 2> /dev/null | wc -l)"
        check "no image is made" 0 "$(sh_ image list | grep -c alpine-plain)"
    done
    out=$(sh_ container run -d --lazy --network none --name nolazy "$plain" true 2>&1)
    check "a container with --lazy is refused the same way" 125 $?
    check_match "and no container is made" '^$' "$(sh_ container list -a -q)"
}

# what the engine keeps of a lazy image: its objects, the EROFS images of its
# layers, and the pins of the containers whose root it serves
engine_objects () { find "$(store)/objects" -type f 2> /dev/null | wc -l; }
engine_images () { find "$(store)/composefs" -type f -name 'layer-*' 2> /dev/null | wc -l; }
engine_pins () { find "$(store)/lazy-pins" -type f 2> /dev/null | wc -l; }
engine_copy_gone () {
    check "$1: no object of the engine's copy" 0 "$(engine_objects)"
    check "$1: no EROFS image of the engine's copy" 0 "$(engine_images)"
    check "$1: no pin" 0 "$(engine_pins)"
}

@test "a lazy image: staged by the engine, run from the engine's files, completed into the service" {
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    out=$(sh_ image pull --lazy --tls-verify=false "$LAZY" 2>&1)
    check "the lazy pull ($out)" 0 $?
    check_match "it says it goes on in the background" 'Pulled \(lazy\)' "$out"
    check_match "the pull is in progress" '^queued$' "$(sh_ image pulls --format '{{.State}}')"
    check "the image is not in the list" 0 "$(sh_ image list -q | grep -c varlink-lazy)"
    sh_ container run -d --lazy --network none --name lz1 "$LAZY" sleep 600 > /dev/null
    check "a container runs on the pull" 0 $?
    check_match "it reads a file of the image" '^[0-9]+\.[0-9]+' "$(sh_ container exec lz1 cat /etc/alpine-release 2>&1)"
    check_match "the root is served by the engine's image server" 'image server of the root file system: pid' "$(monitor_log lz1)"
    check_match "the file is in the staging of its layer" '^[1-9][0-9]*$' "$(find "$(store)/staging/layers" -path "*/files/*" -type f | wc -l)"
    check "the service made no root for it" 0 "$(find "$(store)/varlink/work" -mindepth 1 | wc -l)"
    sh_ container exec lz1 sh -c 'echo lazy-made > /root/made'
    check_match "its writable layer is the engine's: in its bundle" 'lazy-made' "$(cat "$(store)"/bundles/*/overlay/upper/root/made 2>&1)"
    sh_ image complete "$LAZY" > "$WORKDIR/complete.log" 2>&1
    check "the pull completes ($(tail -3 "$WORKDIR/complete.log"))" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check "the image is in the list" 1 "$(sh_ image list --format '{{.Repository}}' | grep -c varlink-lazy)"
    check_match "the service has its layers" '^toc:sha256:' "$(sqlite3 "$(sdir)/db" 'SELECT id FROM layers')"
    check_match "the engine keeps the files for the container made on the pull" '^[1-9][0-9]*$' "$(find "$(store)/objects" -type f 2> /dev/null | wc -l)"
    check "no file is staged" 0 "$(find "$(store)/staging/layers" -path "*/files/*" -type f 2> /dev/null | wc -l)"
    check_match "the container goes on" 'lazy-made' "$(sh_ container exec lz1 cat /root/made 2>&1)"
    sh_ container stop -t 0 lz1 > /dev/null
    sh_ container start lz1 > /dev/null
    check "it starts again" 0 $?
    check_match "with its own layer" 'lazy-made' "$(sh_ container exec lz1 cat /root/made 2>&1)"
    out=$(sh_ container run --rm --network none "$LAZY" sh -c 'cat /etc/alpine-release; grep " / " /proc/self/mountinfo')
    check_match "a new container is the service's" '^[0-9]+\.[0-9]+' "$out"
    ! printf '%s' "$out" | grep -Eq ' - (erofs|overlay|fuse|fuse\.[a-z-]+) '
    check "its root is not the image server's" 0 $?
    check "the container made on the pull is pinned" 1 "$(engine_pins)"
    sh_ container rm -f -t 0 lz1 > /dev/null
    engine_copy_gone "the last container made on the pull is removed"
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    out=$(sh_ system check 2>&1)
    check "system check ($out)" 0 $?
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "a lazy image no container was made on: the engine's copy is dropped when the completion ends, and the image runs from the service" {
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    sh_ image rm -f "$LAZY" > /dev/null 2>&1
    sh_ image pull --lazy --tls-verify=false "$LAZY" > /dev/null 2>&1
    check "the lazy pull" 0 $?
    sh_ image complete "$LAZY" > "$WORKDIR/complete3.log" 2>&1
    check "the pull completes ($(tail -3 "$WORKDIR/complete3.log"))" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check_match "the service has the layer" '^toc:sha256:' "$(sqlite3 "$(sdir)/db" 'SELECT id FROM layers')"
    engine_copy_gone "no container was made on the pull"
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    out=$(sh_ system check 2>&1)
    check "system check ($out)" 0 $?
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "two containers made on a lazy pull: the engine's copy stays until the last is removed, a stopped one starts again, and a container made later is the service's" {
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    sh_ image rm -f "$LAZY" > /dev/null 2>&1
    sh_ image pull --lazy --tls-verify=false "$LAZY" > /dev/null 2>&1
    sh_ container run -d --lazy --network none --name lza "$LAZY" sleep 600 > /dev/null
    check "a container runs on the pull" 0 $?
    sh_ container run -d --lazy --network none --name lzb "$LAZY" sleep 600 > /dev/null
    check "another one" 0 $?
    check "both are pinned" 2 "$(engine_pins)"
    sh_ image complete "$LAZY" > "$WORKDIR/complete4.log" 2>&1
    check "the pull completes ($(tail -3 "$WORKDIR/complete4.log"))" 0 $?
    check_match "the engine keeps the files" '^[1-9][0-9]*$' "$(engine_objects)"
    sh_ container stop -t 0 lza > /dev/null
    sh_ container rm -f -t 0 lza > /dev/null
    check_match "one is removed: the other holds the files" '^[1-9][0-9]*$' "$(engine_objects)"
    check_match "and the images of the layers" '^[1-9][0-9]*$' "$(engine_images)"
    check "one pin is left" 1 "$(engine_pins)"
    sh_ container stop -t 0 lzb > /dev/null
    sh_ container start lzb > /dev/null
    check "the other one starts again" 0 $?
    check_match "from the engine's files" '^[0-9]+\.[0-9]+' "$(sh_ container exec lzb cat /etc/alpine-release 2>&1)"
    check "a container made after the completion is the service's" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    sh_ container rm -f -t 0 lzb > /dev/null
    engine_copy_gone "the last one is removed"
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "a container made on a lazy pull without a pin (an engine built before the pins): its start says that its root is gone and to create it again" {
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    sh_ image rm -f "$LAZY" > /dev/null 2>&1
    sh_ image pull --lazy --tls-verify=false "$LAZY" > /dev/null 2>&1
    sh_ container run -d --lazy --network none --name nopin "$LAZY" sleep 600 > /dev/null
    check "a container runs on the pull" 0 $?
    # (stopped: while its image server runs, the container holds the lock of
    # the images of the engine's copy, and the copy stays)
    sh_ container stop -t 0 nopin > /dev/null
    rm -f "$(store)"/lazy-pins/*
    sh_ image complete "$LAZY" > "$WORKDIR/complete-nopin.log" 2>&1
    check "the pull completes ($(tail -3 "$WORKDIR/complete-nopin.log"))" 0 $?
    check "nothing held the copy" 0 "$(engine_images)"
    out=$(sh_ container start nopin 2>&1)
    check_match "the start fails ($out)" '^[1-9]' "$?"
    check_match "it says why and what to do" 'nothing held.*remove the container and create it again' "$out"
    sh_ container rm -f -t 0 nopin > /dev/null
    check "the image runs from the service" ok "$(sh_ container run --rm --network none "$LAZY" echo ok)"
    sh_ image rm -f "$LAZY" > /dev/null
}

@test "a lazy image with a layer the service holds already: the engine keeps that layer too, and the container made on the pull starts again after the completion" {
    lazy_image
    LAZY=$E2E_REGISTRY/e2e/varlink-lazy:zstd
    sh_ image rm -f "$LAZY" > /dev/null 2>&1
    # another image over the same layer, pulled whole: the service holds the layer
    python3 -I "$E2E_DIR/registry_images.py" variant "$E2E_REGISTRY" e2e/varlink-lazy zstd other > /dev/null ||
        e2e_die "the variant of the lazy image"
    sh_ image pull --tls-verify=false "$E2E_REGISTRY/e2e/varlink-lazy:other" > /dev/null
    check "the other image pulls whole" 0 $?
    sh_ image pull --lazy --tls-verify=false "$LAZY" > /dev/null 2>&1
    check "the lazy pull" 0 $?
    sh_ container run -d --lazy --network none --name lz2 "$LAZY" sleep 600 > /dev/null
    check "a container runs on the pull" 0 $?
    sh_ container exec lz2 sh -c 'echo held > /root/made'
    sh_ image complete "$LAZY" > "$WORKDIR/complete2.log" 2>&1
    check "the pull completes ($(tail -3 "$WORKDIR/complete2.log"))" 0 $?
    check "no pull is left" "" "$(sh_ image pulls -q)"
    check_match "the container goes on" '^[0-9]+\.[0-9]+' "$(sh_ container exec lz2 cat /etc/alpine-release 2>&1)"
    sh_ container stop -t 0 lz2 > /dev/null
    sh_ container start lz2 > /dev/null
    check "it starts again" 0 $?
    check_match "it reads every file of the image" '^[0-9]+$' "$(sh_ container exec lz2 sh -c 'cat $(find / -xdev -type f 2> /dev/null) > /dev/null && echo $?' 2>&1)"
    check_match "with its own layer" 'held' "$(sh_ container exec lz2 cat /root/made 2>&1)"
    sh_ container rm -f -t 0 lz2 > /dev/null
    sh_ image rm -f "$LAZY" "$E2E_REGISTRY/e2e/varlink-lazy:other" > /dev/null
    sh_ system gc > /dev/null 2>&1
    check "the EROFS images of the engine's copy go with the images" 0 "$(find "$(store)/composefs" -type f 2> /dev/null | wc -l)"
    # (the files the image of the file setup names stay: their rows name them)
    [ "$(find "$(store)/objects" -type f 2> /dev/null | wc -l)" -le "$(sqlite3 "$(store)/db.sqlite" 'SELECT COUNT(*) FROM file_refs')" ]
    check "and the objects no layer names" 0 $?
}

@test "--mount type=image: a read-only copy as root, refused up front for an unprivileged engine" {
    if [ "$(id -u)" != 0 ]; then
        out=$(sh_ container create --name im0 --network none --mount "type=image,source=$IMAGE,destination=/mnt/i" "$IMAGE" true 2>&1)
        check "rootless: refused" 125 $?
        check_match "and says the service has no image mounts" 'image' "$out"
        return 0
    fi
    sh_ container run -d --name im1 --network none \
        --mount "type=image,source=$IMAGE,destination=/mnt/i" \
        --mount "type=image,source=$IMAGE,destination=/mnt/etc,subpath=/etc" \
        "$IMAGE" sleep 1000 > /dev/null || e2e_die "run"
    release=$(sh_ container exec im1 cat /etc/alpine-release | head -1)
    check "the mounted image is read" "$release" "$(sh_ container exec im1 head -1 /mnt/i/etc/alpine-release)"
    check "a subpath is the directory of the image" "$release" "$(sh_ container exec im1 head -1 /mnt/etc/alpine-release)"
    out=$(sh_ container exec im1 sh -c 'echo x > /mnt/i/new 2>&1; echo "write: $?"; rm /mnt/i/etc/alpine-release 2>&1; echo "rm: $?"' 2>&1)
    check_match "a write is refused as a read-only file system" "Read-only file system" "$out"
    check_match "and so is a removal" "^rm: 1$" "$out"
    sh_ container stop -t 0 im1 > /dev/null
    sh_ container start im1 > /dev/null
    check "a restart mounts it again" "$release" "$(sh_ container exec im1 head -1 /mnt/i/etc/alpine-release)"
    sh_ container rm -f -t 0 im1 > /dev/null
}

@test "--mount type=image: a sub path the image lacks, or that is a file, is refused naming it" {
    [ "$(id -u)" = 0 ] || skip "an image mount is made by a service that is root"
    out=$(sh_ container create --name im3 --network none --mount "type=image,source=$IMAGE,destination=/mnt/i,subpath=/no/such" "$IMAGE" true 2>&1)
    check "a missing sub path: refused" 125 $?
    check_match "and named" 'the image has no directory /no/such' "$out"
    out=$(sh_ container create --name im4 --network none --mount "type=image,source=$IMAGE,destination=/mnt/i,subpath=/etc/passwd" "$IMAGE" true 2>&1)
    check "a file as the sub path: refused" 125 $?
    check_match "and named" 'the image has no directory /etc/passwd' "$out"
}

@test "system check, df and gc go through the service" {
    check "a check of the store" 0 "$(sh_ system check > /dev/null 2>&1; echo $?)"
    out=$(sh_ system df -v 2>&1)
    check_match "df names the driver" '[Vv]elarx-storage-ref' "$out"
    check "gc" 0 "$(sh_ system gc > /dev/null 2>&1; echo $?)"
    check "the image is still there after a collection" 0 "$(sh_ image inspect "$IMAGE" > /dev/null 2>&1; echo $?)"
}

@test "image rm and a collection give the layers back to the service" {
    layers () { sqlite3 "$(sdir)/db" 'SELECT count(*) FROM layers'; }
    sh_ container rm -f -t 0 -a > /dev/null 2>&1
    [ "$(layers)" -ge 1 ]
    check "the service has the layers of the image" 0 $?
    sh_ image rm -f "$IMAGE" > /dev/null
    check "the image is gone" 125 "$(sh_ image inspect "$IMAGE" > /dev/null 2>&1; echo $?)"
    sh_ system gc > /dev/null
    check "the service forgot the layers ($(sqlite3 "$(sdir)/db" "SELECT id FROM layers"))" 0 "$(layers)"
    sh_ image pull "$IMAGE" > /dev/null
    check "and a pull again works" 0 $?
    check "with the layers in the service again" 1 "$([ "$(layers)" -ge 1 ]; echo $((1 - $?)))"
}

@test "the engine and the service restart: the images and the roots are there" {
    sh_ container run -d --name v5 --network none "$IMAGE" sh -c 'echo kept > /root/kept; sleep 1000' > /dev/null
    sh_ container stop -t 0 v5 > /dev/null
    stop_daemon
    stop_storage
    start_storage
    start_daemon
    check "the image" 0 "$(sh_ image inspect "$IMAGE" > /dev/null 2>&1; echo $?)"
    sh_ container start v5 > /dev/null
    check "the root of a container is the service's, kept" kept "$(sh_ container exec v5 cat /root/kept)"
    sh_ container rm -f -t 0 v5 > /dev/null
    check "the store id is the same" 1 "$(test -d "$(sdir)"; echo $((1 - $?)))"
}

@test "the service stopped: the engine says to start it, does not hang, and recovers" {
    sh_ container run -d --name v6 --network none "$IMAGE" sleep 1000 > /dev/null
    stop_storage
    started=$(date +%s)
    out=$(timeout 60 "$SH" --socket "$ESOCK" container run --rm --network none "$IMAGE" true 2>&1)
    check "a run with the service stopped fails" 125 $?
    check_match "it says to start the service" "start the storage service" "$out"
    check_match "and names the socket" "$VDIR/s.sock" "$out"
    out=$(timeout 60 "$SH" --socket "$ESOCK" image pull "$IMAGE" 2>&1)
    check_match "a pull too" "start the storage service" "$out"
    out=$(timeout 60 "$SH" --socket "$ESOCK" info --format json | field store.graphStatus)
    check_match "info says it instead of failing" "start the storage service" "$out"
    [ $(($(date +%s) - started)) -lt 30 ]
    check "none of it waited for the timeout" 0 $?
    # an engine does not start without it
    stop_daemon
    out=$(timeout 60 "$BIN/velarx" --config "$CONFIG" varlink 2>&1)
    check "the engine does not start" 125 $?
    check_match "it names the key" 'storage\] driver = "varlink"' "$out"
    check_match "and says to start the service" "start the storage service" "$out"
    start_storage
    start_daemon
    sh_ container rm -f -t 0 v6 > /dev/null
    check "the engine works again" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

# act_start COMMAND...: the socket of the service made by an activator (not
# the service), which starts the service with it; the pids of the starts are in
# $VDIR/starts
act_start () {
    stop_storage
    rm -f "$VDIR/s.sock" "$VDIR/starts"
    ( setsid "$@" >> "$VDIR/activate.log" 2>&1 3>&- &
      echo $! > "$VDIR/activate.pid" )
    e2e_wait_path "$VDIR/s.sock" 10
    check "nothing runs before the first call" 0 "$(cat "$VDIR/starts" 2> /dev/null | wc -l)"
}
act_stop () {
    local pid
    pid=$(cat "$VDIR/activate.pid" 2> /dev/null)
    if [ -n "$pid" ]; then
        kill "$pid" 2> /dev/null || true
        e2e_wait_exit "$pid" 10
    fi
    pid=$(tail -1 "$VDIR/starts" 2> /dev/null)
    if [ -n "$pid" ]; then
        kill "$pid" 2> /dev/null || true
        e2e_wait_exit "$pid" 10
    fi
    rm -f "$VDIR/s.sock" "$VDIR/activate.pid"
}
# the service the activators start: it records its pid, then leaves 3 s after it is idle
act_service () { # the arguments of sh -c: $0 is VDIR, $1 the server
    echo 'echo $$ >> "$0/starts"; exec "$1" --root "$0/root" --idle-secs 3'
}

@test "the service leaves when idle (socket activated): a connection keeps it, the next call starts it again" {
    command -v systemd-socket-activate > /dev/null || skip "no systemd-socket-activate"
    act_start systemd-socket-activate -l "$VDIR/s.sock" sh -c "$(act_service)" "$VDIR" "$BIN/velarx-storage-server"
    out=$(sh_ image pull "$IMAGE" 2>&1)
    check "a pull starts the service ($out)" 0 $?
    check "started once" 1 "$(wc -l < "$VDIR/starts")"
    first=$(head -1 "$VDIR/starts")
    # a connection that is held keeps it past the idle time
    python3 -I -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
time.sleep(6)' "$VDIR/s.sock" 3>&- &
    sleep 5
    kill -0 "$first"
    check "the service stays while a connection is open" 0 $?
    e2e_wait_exit "$first" 20
    check "and leaves when idle" 0 $?
    act_stop
    # the socket stays and starts it again on the next call (the activator
    # of systemd-socket-activate ends with its first child: the one of the
    # test does not)
    act_start python3 -I "$E2E_DIR/storage-activate.py" "$VDIR/s.sock" sh -c "$(act_service)" "$VDIR" "$BIN/velarx-storage-server"
    sh_ image pull "$IMAGE" > /dev/null
    check "started" 1 "$(wc -l < "$VDIR/starts")"
    e2e_wait_exit "$(head -1 "$VDIR/starts")" 20
    check "left" 0 $?
    check "the socket stays" 0 "$([ -S "$VDIR/s.sock" ]; echo $?)"
    check "the next call is served by a new start" again "$(sh_ container run --rm --network none "$IMAGE" echo again)"
    check "two starts" 2 "$(wc -l < "$VDIR/starts")"
    act_stop
    start_storage
}

@test "a service that bound its own socket leaves when idle and removes it: the engine is told to start it, without a wait" {
    stop_storage
    start_storage 30 --idle-secs 2
    pid=$(cat "$VDIR/server.pid")
    e2e_wait_exit "$pid" 20
    check "the service leaves when idle" 0 $?
    check "and removes its socket" 1 "$([ -e "$VDIR/s.sock" ]; echo $?)"
    started=$(date +%s)
    out=$(timeout 60 "$SH" --socket "$ESOCK" container run --rm --network none "$IMAGE" true 2>&1)
    check "a run fails" 125 $?
    check_match "and says to start the service" "start the storage service" "$out"
    check_match "naming the socket" "$VDIR/s.sock" "$out"
    [ $(($(date +%s) - started)) -lt 30 ]
    check "without waiting" 0 $?
    start_storage
    check "the engine works again" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
}

@test "a service of another version is refused with both versions named" {
    python3 -I "$E2E_DIR/storage-fake.py" "$VDIR/fake.sock" 99 3>&- &
    fake=$!
    e2e_wait_path "$VDIR/fake.sock" 10
    config_with fake 'storage.driver = "varlink"' "storage.varlink.socket = \"$VDIR/fake.sock\""
    stop_daemon
    out=$(timeout 60 "$BIN/velarx" --config "$WORKDIR/fake.toml" varlink 2>&1)
    rc=$?
    kill "$fake"
    start_daemon
    check "the engine does not start" 125 "$rc"
    check_match "it names both versions" 'speaks org.velarx.Storage.99 and velarx org.velarx.Storage.1' "$out"
    check_match "and what to do" 'upgrade the driver or velarx' "$out"
    check_match "and the key" 'storage\] driver = "varlink"' "$out"
}

@test "a service that is not the one named, and the settings that are wrong, are refused naming the key" {
    stop_daemon
    run_engine () { timeout 60 "$BIN/velarx" --config "$WORKDIR/$1.toml" varlink 2>&1; }
    config_with name 'storage.driver = "varlink"' "storage.varlink.socket = \"$VDIR/s.sock\"" 'storage.varlink.name = "other"'
    out=$(run_engine name)
    check "a service with another name" 125 $?
    check_match "it says what it calls itself and the key" 'calls itself "velarx-storage-ref".*name = "other"' "$out"
    config_with nosock 'storage.driver = "varlink"'
    out=$(run_engine nosock)
    check "no [storage.varlink]" 125 $?
    check_match "it says what is needed" 'needs \[storage.varlink\].*socket' "$out"
    config_with rel 'storage.driver = "varlink"' 'storage.varlink.socket = "s.sock"'
    out=$(run_engine rel)
    check "a relative socket" 125 $?
    check_match "it names the key" '\[storage.varlink\] socket.*not an absolute path' "$out"
    config_with tmo 'storage.driver = "varlink"' "storage.varlink.socket = \"$VDIR/s.sock\"" 'storage.varlink.timeout_secs = 0'
    out=$(run_engine tmo)
    check "timeout_secs = 0" 125 $?
    check_match "it names the key" '\[storage.varlink\] timeout_secs' "$out"
    config_with other 'storage.driver = "vfs"' "storage.varlink.socket = \"$VDIR/s.sock\""
    out=$(run_engine other)
    check "the table with another driver" 125 $?
    check_match "it says it is for varlink" '\[storage.varlink\] is set' "$out"
    # a store of the service is not opened as another driver, and the other way
    out=$("$BIN/velarx" --config "$CONFIG" --storage-driver composefs varlink 2>&1)
    check "a varlink store is not opened as composefs" 125 $?
    check_match "the error names both" 'was made with the storage driver "varlink", but composefs is asked for|\[storage.varlink\] is set' "$out"
    start_daemon
}

@test "system prune --all --volumes drops the store of the service" {
    sh_ container rm -f -t 0 -a > /dev/null 2>&1
    d=$(sdir)
    [ -d "$d" ]
    check "the service has the store" 0 $?
    out=$(sh_ system prune --all --volumes --force 2>&1)
    check "prune" 0 $?
    check "the service dropped the store" 1 "$(test -e "$d"; echo $?)"
    check "no image is left" 0 "$(sh_ image list -q | wc -l)"
    # the store is made again by the next pull
    sh_ image pull "$IMAGE" > /dev/null
    check "a pull makes it again" 0 $?
    check "same id, same place" 0 "$(test -d "$(sdir)"; echo $?)"
    check "an image run" ok "$(sh_ container run --rm --network none "$IMAGE" echo ok)"
    # (a container is left: the store stays)
    sh_ container run -d --name keep --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ system prune --all --volumes --force > /dev/null 2>&1
    check "a container is left, the store stays" 0 "$(test -d "$(sdir)"; echo $?)"
    sh_ container rm -f -t 0 keep > /dev/null
    # (a filter selects: the store stays)
    sh_ system prune --all --volumes --force --filter until=1 > /dev/null 2>&1
    check "a filter is given, the store stays" 0 "$(test -d "$(sdir)"; echo $?)"
}
