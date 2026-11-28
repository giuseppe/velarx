# SPDX-License-Identifier: Apache-2.0
# What the files of the inline threshold tests share (inline-threshold.bats,
# inline-nfs.bats):
#
#   load helpers
#   load inline
#
# The threshold N (`pull --inline-threshold=N`, `[storage] inline_threshold`)
# puts every regular file of 1..N bytes (-1: every file) into the EROFS image
# of its layer; the bigger ones stay objects of the store.  This file makes
# the image of the tests, a registry of their own (so that a test can stop it
# once a pull is made), and the questions the tests ask of a store: which
# objects it holds, which rows `layers.inline` and `inlined_files` say, and
# what a container reads.
#
# The image has one layer: the binaries of the host and /data, files of
# the sizes in DATA_SIZES made of random bytes (f<SIZE>), a hard link (hl) and
# a symlink (sl); $WORKDIR/data.sums are their sha256sum, as the container
# prints them.

DATA_SIZES="1 50 100 4095 4096 4097 65537 70001 3145745"

# inline_setup_file: skips without what the files need, makes the work
# directory, the registry and the image (as zstd:chunked and as gzip) in it,
# and exports REG (host:port of the registry) and IMAGE, IMAGE_GZIP.
inline_setup_file () {
    local t
    for t in curl registry sqlite3 sha256sum python3; do
        command -v $t > /dev/null || skip "no $t"
    done
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    export REGISTRY_BIN
    REGISTRY_BIN=$(command -v registry)
    inline_registry_start
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$REG" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    export IMAGE=$REG/thr/data:chunked IMAGE_GZIP=$REG/thr/data:gzip
    inline_make_image
}

# inline_registry_start: the registry of the file on a port of its own (a new
# one the first time, the same after), its data in $WORKDIR/regdata, which a
# stop keeps.  Sets REG.
inline_registry_start () {
    if [ ! -s "$WORKDIR/regport" ]; then
        python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])' > "$WORKDIR/regport"
    fi
    export REG=127.0.0.1:$(cat "$WORKDIR/regport")
    cat > "$WORKDIR/reg.yml" <<EOT
version: 0.1
log:
  level: info
  accesslog:
    disabled: false
storage:
  filesystem:
    rootdirectory: $WORKDIR/regdata
  delete:
    enabled: true
http:
  addr: ${INLINE_REG_LISTEN:-127.0.0.1}:${REG##*:}
EOT
    "$REGISTRY_BIN" serve "$WORKDIR/reg.yml" >> "$WORKDIR/registry.log" 2>&1 3>&- &
    echo $! > "$WORKDIR/registry.pid"
    curl -sf -m 5 --retry 30 --retry-connrefused --retry-delay 1 "http://$REG/v2/" > /dev/null ||
        e2e_die "the registry does not start: $(cat "$WORKDIR/registry.log")"
}

# inline_registry_stop: the registry ends, its data stay.  A request now is a
# refused connection.
inline_registry_stop () {
    local pid
    pid=$(cat "$WORKDIR/registry.pid" 2> /dev/null || :)
    [ -n "$pid" ] || return 0
    kill "$pid" 2> /dev/null
    e2e_wait_exit "$pid" 10 || kill -KILL "$pid" 2> /dev/null
    rm -f "$WORKDIR/registry.pid"
}

# inline_make_image: the files of the image, its store (`src`), and the
# image pushed to the registry as zstd:chunked and as gzip.
inline_make_image () {
    local s d
    BINARIES="sh cat env sleep true false echo ls stat sha256sum cp" e2e_make_rootfs
    d=$WORKDIR/rootfs/data
    mkdir -p "$d"
    for s in 0 $DATA_SIZES; do
        head -c "$s" /dev/urandom > "$d/f$s"
        # (a size of its own: the objects of the store are found by it)
        if find "$WORKDIR/rootfs" -type f -size "${s}c" -not -path "$d/*" | grep -q . && [ "$s" != 0 ]; then
            e2e_die "a file of the host has $s bytes, the sizes of the test are not its own"
        fi
    done
    ln "$d/f100" "$d/hl"
    ln -s f4096 "$d/sl"
    (cd "$d" && for f in $(ls | LC_ALL=C sort); do sha256sum "$f"; done) > "$WORKDIR/data.sums"
    tar -C "$WORKDIR/rootfs" -cf "$WORKDIR/rootfs.tar" .
    inline_use src
    sh_ image import "$WORKDIR/rootfs.tar" localhost/inline-src:1 > "$WORKDIR/make.log" 2>&1 &&
        sh_ image push --tls-verify=false --compression-format zstd:chunked localhost/inline-src:1 "$IMAGE" >> "$WORKDIR/make.log" 2>&1 &&
        sh_ image push --tls-verify=false --compression-format gzip localhost/inline-src:1 "$IMAGE_GZIP" >> "$WORKDIR/make.log" 2>&1 ||
        { cat "$WORKDIR/make.log" >&2; e2e_die "cannot make the image"; }
}

# inline_teardown_file: everything a file started goes: containers, daemons,
# mounts, the registry, the work directory
inline_teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    . "$E2E_DIR/cleanup.sh"
    local s
    for s in "$WORKDIR"/*.sock; do e2e_remove_containers "$BIN/velarx" "$s"; done
    inline_stop
    inline_registry_stop
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m" 2> /dev/null; done
        chmod -R u+rwX "$WORKDIR" 2> /dev/null
        if [ "$(id -u)" != 0 ]; then
            # (the files of user namespaces of containers)
            "$BIN/velarx" unshare rm -rf "$WORKDIR" 2> /dev/null
        fi
    fi
    e2e_teardown_file
}

# a failing test must not leave its container to the next
inline_teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then
        sh_ container rm -t 0 -f c1 > /dev/null 2>&1
    fi
    # (a test that failed while the registry was down)
    [ -s "$WORKDIR/registry.pid" ] || inline_registry_start
    return 0
}

# inline_stop: the daemon of the last inline_use ends
inline_stop () {
    local pid
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null || :)
    [ -n "$pid" ] || return 0
    kill -INT "$pid" 2> /dev/null
    e2e_wait_exit "$pid" 10 || kill -KILL "$pid" 2> /dev/null
    rm -f "$WORKDIR/daemon.pid"
}

# inline_config NAME [STORAGE_LINES [PULL_LINES]]: $WORKDIR/NAME.toml, a
# store of its own at $WORKDIR/NAME-store; the lines are those of [storage]
# and of [pull] (a lazy pull is completed by a command that waits for it
# only: `lazy_completers = 0` is added)
inline_config () {
    cat > "$WORKDIR/$1.toml" <<EOT
[engine]
socket = "$WORKDIR/$1.sock"
[server]
socket = "$WORKDIR/$1.sock"
state_dir = "$WORKDIR/$1-state"
root_dir = "$WORKDIR/$1-root"
[storage]
root = "${INLINE_ROOT:-$WORKDIR}/$1-store"
${2:-}
[pull]
lazy_completers = 0
${3:-}
EOT
}

# inline_use NAME [STORAGE_LINES [PULL_LINES]]: the daemon of the store NAME
# (its configuration made as inline_config does, if there is none) runs,
# the one of the last call ended; sh_ speaks to it.  The daemon logs at the
# level debug to $WORKDIR/NAME.log.
inline_use () {
    inline_stop
    [ -e "$WORKDIR/$1.toml" ] || inline_config "$@"
    SOCK=$WORKDIR/$1.sock
    STORE=${INLINE_ROOT:-$WORKDIR}/$1-store
    NAME=$1
    E2E_SPAWN_LOG=$WORKDIR/$1.log e2e_spawn_ready DAEMON_PID \
        "$BIN/velarx" --log-level=debug --config "$WORKDIR/$1.toml" varlink ||
        e2e_die "the daemon of $1 does not start: $(tail "$WORKDIR/$1.log")"
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
}
# inline_fresh NAME [STORAGE_LINES [PULL_LINES]]: a store with nothing in it
inline_fresh () {
    inline_stop
    rm -rf "$WORKDIR/$1.toml" "${INLINE_ROOT:-$WORKDIR}/$1-store" "$WORKDIR/$1-root" "$WORKDIR/$1-state"
    inline_use "$@"
}
sh_ () { "$BIN/velarx" --socket "$SOCK" "$@"; }

# pull_n N IMAGE [ARGS...]: pull IMAGE with the threshold N
pull_n () {
    local n=$1 img=$2
    shift 2
    sh_ image pull --tls-verify=false --inline-threshold="$n" "$@" "$img"
}

# objects STORE: how many files of the store are objects, and how many of
# them have SIZE bytes
objects () { find "$1/objects" -type f 2> /dev/null | wc -l; }
objects_of_size () { find "$1/objects" -type f -size "${2}c" 2> /dev/null | wc -l; }

# expect_objects STORE N: of the files of /data, the ones above N bytes are
# objects of the store, the others are not (N = -1: no file of the store is)
expect_objects () {
    local store=$1 n=$2 s want
    for s in $DATA_SIZES; do
        if [ "$n" -ge 0 ] && [ "$s" -gt "$n" ]; then want=1; else want=0; fi
        check "objects of $s bytes with N=$n" "$want" "$(objects_of_size "$store" "$s")"
    done
    if [ "$n" = -1 ]; then check "objects with N=-1" 0 "$(objects "$store")"; fi
}

# db STORE SQL: a query of the database of the store
db () { sqlite3 "$1/db.sqlite" "$2"; }
# layer_inlines STORE: the thresholds the layers of the store were made with
layer_inlines () { db "$1" 'SELECT DISTINCT inline FROM layers ORDER BY 1' | tr '\n' ' ' | sed 's/ $//'; }
# inlined_sizes STORE: the sizes of the files the layers hold, sorted
inlined_sizes () { db "$1" 'SELECT size FROM inlined_files ORDER BY size' | tr '\n' ' ' | sed 's/ $//'; }

# expect_inlined STORE N: the rows of inlined_files are the files of /data
# that N holds (and no file above N, whatever else the image has)
expect_inlined () {
    local store=$1 n=$2 s sizes=
    check "the layer's threshold is recorded" "$n" "$(layer_inlines "$store")"
    for s in $DATA_SIZES; do
        if [ "$n" = -1 ] || [ "$s" -le "$n" ]; then
            check "a row for the $s bytes file (N=$n)" 1 \
                "$(db "$store" "SELECT count(*) FROM inlined_files WHERE size = $s")"
        else
            check "no row for the $s bytes file (N=$n)" 0 \
                "$(db "$store" "SELECT count(*) FROM inlined_files WHERE size = $s")"
        fi
    done
    if [ "$n" -ge 0 ]; then
        check "no row above N" 0 "$(db "$store" "SELECT count(*) FROM inlined_files WHERE size > $n")"
    fi
    # (every extent lies inside the image of its layer)
    check "no extent outside of its image" 0 "$(db "$store" "SELECT count(*) FROM inlined_files WHERE offset < 0 OR size <= 0")"
}

# content_of IMAGE [ARGS...]: what a container of IMAGE says of /data, the
# sha256sum of each file (ARGS: more arguments of `container run`)
content_of () {
    local img=$1
    shift
    sh_ container run --rm --pull=never --network none "$@" "$img" \
        sh -c 'cd /data && for f in $(ls); do sha256sum "$f"; done' 2>&1
}
# content_ok IMAGE [ARGS...]: the files are what was made
content_ok () {
    local out
    out=$(content_of "$@")
    if [ "$out" != "$(cat "$WORKDIR/data.sums")" ]; then
        echo "FAIL the content of /data in a container of $1:" >&2
        diff <(echo "$out") "$WORKDIR/data.sums" >&2
        exit 1
    fi
}

# rss_kb PID FIELD: VmHWM or VmRSS of the process, in kB
rss_kb () { awk -v f="$2:" '$1 == f { print $2 }' "/proc/$1/status"; }

# monitor_log CONTAINER: what the monitor of the container said (of the
# daemon of the last inline_use)
monitor_log () {
    local id
    id=$(sh_ container inspect "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    find "$WORKDIR/$NAME-state" -path "*/${id:0:12}/*" -name monitor.log 2> /dev/null | head -1 | xargs -r cat
}
# server_pid: the pid of the image server the monitor log (stdin) names
server_pid () {
    sed -n 's/.*image server of the root file system: pid \([0-9]*\),.*/\1/p' | head -1
}

# registry_requests: how many requests the registry has answered (its
# access log), to show that a command asked it for nothing
registry_requests () { grep -c 'http.request.method' "$WORKDIR/registry.log" 2> /dev/null || true; }
