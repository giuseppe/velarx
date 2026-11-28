# SPDX-License-Identifier: Apache-2.0
# The image server (`velarx-monitor --image-server`): the process that serves
# the EROFS images of the layers of a container's image by FUSE where the
# kernel does not mount them, and hands the overlay over as a mount
# descriptor.  As a user (rootless: the kernel never mounts the images) and
# as root (`composefs = "off"`: no kernel mount either).
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/image-server.bats
#   sudo VELARX_BINDIR=target/debug unshare -m --propagation private bats tests/e2e/bats/image-server.bats

load helpers

# the log of the monitor of the container `name`
monitor_log () {
    local id
    id=$(sc container inspect "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    find "$WORKDIR" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat
}
# the pid of the image server the monitor log (stdin) names
server_pid () {
    sed -n 's/.*image server of the root file system: pid \([0-9]*\),.*/\1/p' | head -1
}
server_pids () { # log: the pids of every image server it names
    sed -n 's/.*image server of the [a-z ]*[^:]*: pid \([0-9]*\),.*/\1/p'
}
# gone PID: ended, or never there
gone () { e2e_wait_exit "$1" 20; test "$(e2e_alive "$1")" = gone; }

setup_file () {
    command -v curl > /dev/null || skip "no curl"
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    export IMAGE=$E2E_REGISTRY/alpine:chunked
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$E2E_REGISTRY"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # no kernel mount as root either
    sed -i '1a storage.composefs = "off"' "$XDG_CONFIG_HOME/velarx/config.toml"
    # (a descriptor the caller of the engine left open: no image server keeps it)
    e2e_start_daemon 8> "$WORKDIR/held-by-the-caller"
    sc image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1 || { echo "pull failed" >&2; exit 1; }
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    sc container rm -t 0 -f -a > /dev/null 2>&1
    e2e_teardown_file
}

@test "the layers are served by an image server of the monitor's cgroup" {
    sc container run -d --name s1 --network none "$IMAGE" sleep 300 > /dev/null
    log=$(monitor_log s1)
    check_match "the monitor attaches the mount of the driver" "root file system: mount descriptor 0 of the storage driver" "$log"
    srv=$(printf '%s\n' "$log" | server_pid)
    test -n "$srv" || e2e_die "the monitor does not name an image server"
    check_match "the process is the image server" "image server" "$(tr '\0' ' ' < /proc/$srv/cmdline)"
    mon=$(sc container inspect --format '{{.State.ConmonPid}}' s1 2> /dev/null)
    if [ -n "$mon" ] && [ "$mon" != 0 ] && grep -q '^0::' /proc/$mon/cgroup; then
        check "it is in the cgroup of the monitor" "$(cat /proc/$mon/cgroup)" "$(cat /proc/$srv/cgroup)"
    fi
    # it is nobody's child: its parent is init or a subreaper, not the engine
    check "the engine has nothing to reap" 0 "$(ps -o ppid= -p "$srv" | grep -c "^ *$(cat "$WORKDIR/daemon.pid")$")"
    check_match "the files are read" "^[0-9]+\.[0-9]+" "$(sc container exec s1 cat /etc/alpine-release 2>&1)"
    # every thread of the server is confined once it answered (the main
    # thread too: the requests of the container reach the process)
    local t bare=
    for t in /proc/"$srv"/task/*; do
        grep -q '^Seccomp:[[:space:]]*2$' "$t/status" && grep -q '^NoNewPrivs:[[:space:]]*1$' "$t/status" ||
            bare="$bare $(cat "$t/comm")"
    done
    check "no thread of the server is unconfined" "" "$bare"
    # it holds its socket, /dev/null, its FUSE device, its log (the file the
    # engine opened for it: its standard error) and the EROFS images of the
    # layers (the files they hold are read from them), nothing it inherited
    local fds
    fds=$(for t in /proc/"$srv"/fd/*; do readlink "$t"; done | sed 's/^socket:.*/socket/' | sort -u | tr '\n' ' ')
    check_match "the descriptors of the server" "^/dev/fuse /dev/null socket [^ ]*/bundles/[0-9a-f]{64}/image-server.log ([^ ]*/composefs/layer-[^ ]*\\.erofs )*$" "$fds"
    sc container exec s1 sh -c 'echo w > /etc/written && cat /etc/written' > "$WORKDIR/written" 2>&1
    check "the container writes in its upper layer" w "$(cat "$WORKDIR/written")"
    echo "$srv" > "$WORKDIR/server.pid"
}

@test "the server ends with the container, and nobody tells it to stop" {
    srv=$(cat "$WORKDIR/server.pid")
    check "the server is there while the container is" alive "$(e2e_alive "$srv")"
    sc container rm -t 0 -f s1 > /dev/null
    gone "$srv" || e2e_die "the server of a removed container is still there"
}

@test "the container goes on when the engine is killed: the server serves" {
    sc container run -d --name s2 --network none "$IMAGE" sleep 300 > /dev/null
    srv=$(monitor_log s2 | server_pid)
    test -n "$srv" || e2e_die "no image server"
    kill -KILL "$(cat "$WORKDIR/daemon.pid")"
    e2e_wait_exit "$(cat "$WORKDIR/daemon.pid")" 10
    check "the server is not the engine's" alive "$(e2e_alive "$srv")"
    e2e_start_daemon
    check_match "the container still reads its files" "^[0-9]+\.[0-9]+" "$(sc container exec s2 cat /etc/alpine-release 2>&1)"
    sc container rm -t 0 -f s2 > /dev/null
    gone "$srv" || e2e_die "the server of a removed container is still there"
}

@test "stop and start: a server for each start, none left behind" {
    sc container run -d --name s3 --network none "$IMAGE" sleep 300 > /dev/null
    first=$(monitor_log s3 | server_pid)
    sc container stop -t 0 s3 > /dev/null
    gone "$first" || e2e_die "the server of a stopped container is still there"
    sc container start s3 > /dev/null
    all=$(monitor_log s3 | server_pids | sort -u | wc -l)
    check "a new server" 2 "$all"
    check_match "the files are read" "^[0-9]+\.[0-9]+" "$(sc container exec s3 cat /etc/alpine-release 2>&1)"
    sc container rm -t 0 -f s3 > /dev/null
    for p in $(monitor_log s3 2> /dev/null | server_pids); do gone "$p" || e2e_die "server $p is still there"; done
}

@test "image mounts and a user namespace" {
    sc container run -d --name s4 --userns auto --network none \
        --mount "type=image,source=$IMAGE,destination=/img" "$IMAGE" sleep 300 > /dev/null 2>&1
    check "a container with an image mount runs" 0 $?
    log=$(monitor_log s4)
    check "a server for the root and one for the image mount" 2 "$(printf '%s\n' "$log" | server_pids | sort -u | wc -l)"
    check "the image mount reads the image" "0 0" "$(sc container exec s4 stat -c '%u %g' /img/etc/alpine-release 2>&1)"
    sc container exec s4 sh -c 'echo x > /img/new' > /dev/null 2>&1
    check "an image mount is read-only" 1 "$([ $? != 0 ] && echo 1 || echo 0)"
    pids=$(printf '%s\n' "$log" | server_pids)
    sc container rm -t 0 -f s4 > /dev/null
    for p in $pids; do gone "$p" || e2e_die "server $p is still there"; done
}

@test "owners outside the ids of a rootless engine: the create refuses, no user namespace of its own" {
    [ "$(id -u)" != 0 ] || skip "as root every id is the engine's"
    # (a file owned by an id the user namespace of the engine does not have)
    python3 -I - "$WORKDIR/owners.tar" <<'PY'
import io, sys, tarfile
out = tarfile.open(sys.argv[1], "w")
for name, uid in (("ok", 0), ("far", 4000000)):
    t = tarfile.TarInfo(name)
    t.size, t.uid, t.gid, t.mode = 1, uid, uid, 0o644
    out.addfile(t, io.BytesIO(b"x"))
out.close()
PY
    sc image import "$WORKDIR/owners.tar" e2e-far-owner > /dev/null 2>&1 || skip "no image with such an owner here"
    local out
    out=$(sc container create --name far --network none e2e-far-owner /ok 2>&1)
    check "no container is made" 0 "$(sc container ls -a --format '{{.Names}}' | grep -cx far)"
    check_match "the create says why" "image has files owned by (uid|gid) 4000000, which is not mapped in the user namespace" "$out"
    sc image rm e2e-far-owner > /dev/null 2>&1
}

@test "a monitor killed with its container: the next start serves again" {
    sc container run -d --name s5 --network none "$IMAGE" sleep 300 > /dev/null
    mon=$(sc container inspect --format '{{.State.ConmonPid}}' s5)
    cpid=$(sc container inspect --format '{{.State.Pid}}' s5)
    kill -KILL "$mon" "$cpid" 2> /dev/null
    e2e_wait_exit "$mon" 10
    sc container stop -t 0 s5 > /dev/null 2>&1
    sc container start s5 > /dev/null 2>&1
    check "it starts again" 0 $?
    check_match "and serves its files" "^[0-9]+\.[0-9]+" "$(sc container exec s5 cat /etc/alpine-release 2>&1)"
    sc container rm -t 0 -f s5 > /dev/null
}

# The lock of an image: whoever serves or mounts the EROFS image of a layer
# holds a shared flock of it (the image server for as long as it runs; the
# collection asks for it exclusively and keeps what it cannot lock).  `flock
# -n -x` is that question.
layer_image () { ls "$XDG_DATA_HOME"/velarx/composefs/layer-*.erofs | head -1; }
layer_rows () {
    python3 -I -c 'import sqlite3, sys; print(sqlite3.connect(sys.argv[1], timeout=30).execute("SELECT COUNT(*) FROM layers").fetchone()[0])' "$XDG_DATA_HOME/velarx/db.sqlite"
}
image_unused () { flock -n -x "$1" true 2> /dev/null && echo unused || echo in-use; }

@test "an image is in use while its image server runs, and not after" {
    img=$(layer_image)
    test -n "$img" || e2e_die "no image of a layer in the store"
    check "no one uses it before" unused "$(image_unused "$img")"
    sc container run -d --name l1 --network none "$IMAGE" sleep 300 > /dev/null
    srv=$(monitor_log l1 | server_pid)
    test -n "$srv" || e2e_die "no image server"
    check "the image server holds it" in-use "$(image_unused "$img")"
    sc container rm -t 0 -f l1 > /dev/null
    gone "$srv" || e2e_die "the server of a removed container is still there"
    check "no one uses it after" unused "$(image_unused "$img")"
}

@test "kill -9 of the image server releases the image" {
    img=$(layer_image)
    sc container run -d --name l2 --network none "$IMAGE" sleep 300 > /dev/null
    srv=$(monitor_log l2 | server_pid)
    test -n "$srv" || e2e_die "no image server"
    check "in use" in-use "$(image_unused "$img")"
    kill -KILL "$srv"
    gone "$srv" || e2e_die "the server is still there"
    check "the kernel closed its image" unused "$(image_unused "$img")"
    sc container rm -t 0 -f l2 > /dev/null
}

@test "a layer whose image a server holds is not collected, and is when it is not held" {
    img=$(layer_image)
    sc container run -d --name l3 --network none "$IMAGE" sleep 300 > /dev/null
    srv=$(monitor_log l3 | server_pid)
    test -n "$srv" || e2e_die "no image server"
    # (what no row says any more: a crash that lost them, or a layer of an
    # image removed while another engine's server still serves it)
    python3 -I - "$XDG_DATA_HOME/velarx/db.sqlite" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=30)
c.execute("DELETE FROM container_layers")
c.execute("DELETE FROM image_layers")
c.commit()
PY
    sc system gc > /dev/null 2>&1
    check "the collection keeps the image" 1 "$(test -f "$img" && echo 1 || echo 0)"
    check "and its row" 1 "$(layer_rows)"
    check_match "the files are still read" "^[0-9]+\.[0-9]+" "$(sc container exec l3 cat /etc/alpine-release 2>&1)"
    sc container rm -t 0 -f l3 > /dev/null
    gone "$srv" || e2e_die "the server of a removed container is still there"
    # (the layer goes in the second step of a collection, its image in the
    # first of the next)
    sc system gc > /dev/null 2>&1
    sc system gc > /dev/null 2>&1
    check "once nothing holds it, the collection removes the image" 0 "$(test -f "$img" && echo 1 || echo 0)"
    check "and the row" 0 "$(layer_rows)"
}
