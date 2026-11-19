# SPDX-License-Identifier: Apache-2.0
# The whole loop of an image velarx builds: `velarx build` of a
# Containerfile (RUN, COPY, ADD, ENV, CMD, ENTRYPOINT, USER, LABEL, WORKDIR,
# two stages) with small files, a file of many chunks and a sparse file,
# pushed to a plain HTTP registry in each compression, pulled back eagerly
# and lazily into fresh stores, run.  Checked: the content and the holes of
# the files (st_blocks), the TOC gives the fs-verity digest of every file,
# the manifest states the digest of the merged EROFS and the pull checks it
# (an image whose manifest states another is refused), the id of the image
# pulled back is the digest of the manifest pushed, a push of what the
# registry has uploads nothing, a pushed image that was pulled, and
# `system check`.  The base is $BASE pushed again by velarx.  An image of
# containers/storage (`alpine-plain:chunked`), whose TOCs give no
# fs-verity digests, is refused, lazily or not, before anything is stored; a
# lazy pull of the images pushed with gzip or uncompressed is refused.  skopeo (the
# containers image library, no store) reads the images too.  Rootless.
#
# The tests share one daemon at a time, on the store the last `use_store`
# made (its name is in $WORKDIR/store, the daemon's pid in
# $WORKDIR/daemon.pid), and what the build tests compute is in files of
# $WORKDIR.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/build-loop.bats

load helpers

BASE=${BASE:-$E2E_REGISTRY/alpine:chunked}
SEAL=composefs.merged.erofs.v1.fsverity-sha256-12

setup_file () {
    local t
    for t in curl zstd python3 sqlite3; do
        command -v $t > /dev/null || skip "no $t"
    done
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    e2e_setup_file
    mkdir -p "$XDG_DATA_HOME"
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "$E2E_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    export REPO=$E2E_REGISTRY/velarx-e2e/build-loop-$$
    export CTX=$WORKDIR/ctx
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    stop_daemon
    rm -f "$WORKDIR/daemon.pid"
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    e2e_teardown_file
}

setup () {
    set +e
    STORE=$(cat "$WORKDIR/store" 2> /dev/null)
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
}

stop_daemon () {
    [ -n "$DAEMON_PID" ] || return 0
    kill -INT "$DAEMON_PID" 2> /dev/null
    e2e_wait_exit "$DAEMON_PID"
    kill -KILL "$DAEMON_PID" 2> /dev/null
    DAEMON_PID=
    rm -f "$WORKDIR/daemon.pid"
}

# a daemon on a store of its own: `use_store NAME`
use_store () {
    stop_daemon
    STORE=$WORKDIR/$1
    echo "$STORE" > "$WORKDIR/store"
    mkdir -p "$STORE"
    chmod 700 "$STORE"
    cat > "$STORE/sh.toml" <<EOF
[engine]
socket = "$STORE/sh.sock"
[server]
socket = "$STORE/sh.sock"
state_dir = "$STORE/state"
root_dir = "$STORE/root"
[storage]
root = "$STORE/store"
[pull]
# the gzip layer of the sparse file inflates 1000 times (the bound of a
# stream counts its zeros)
inflate_floor_mib = 256
# (no background completion: a lazy pull stays a pull, its containers run
# on it, until a command waits for it)
lazy_completers = 0
EOF
    # (the daemon says READY=1 when it serves)
    E2E_SPAWN_LOG=$STORE/sh.log e2e_spawn_ready DAEMON_PID "$BIN/velarx" --config "$STORE/sh.toml" varlink
    ready=$?
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    [ "$ready" = 0 ] && return 0
    echo "the daemon does not start"; cat "$STORE/sh.log"; exit 1
}
sh_ () { "$BIN/velarx" --socket "$STORE/sh.sock" "$@"; }

manifest () { # reference: the manifest in the registry
    local r=${1#*/} tag=${1##*:}
    curl -sf -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$E2E_REGISTRY/v2/${r%:*}/manifests/$tag"
}
# the TOC of the top layer of the manifest on stdin, from the registry
top_toc () {
    python3 -I -c '
import json, subprocess, sys
repo, m = sys.argv[1], json.load(sys.stdin)
l = m["layers"][-1]
pos = l.get("annotations", {}).get("io.github.containers.zstd-chunked.manifest-position")
if not pos:
    sys.exit("no TOC")
off, size = map(int, pos.split(":")[:2])
url = "http://%s/v2/%s/blobs/%s" % (sys.argv[2], repo, l["digest"])
z = subprocess.run(["curl", "-sf", "-r", "%d-%d" % (off, off + size - 1), url],
    capture_output=True, check=True).stdout
print(subprocess.run(["zstd", "-dc"], input=z, capture_output=True, check=True).stdout.decode())
' "${REPO#*/}" "$E2E_REGISTRY"
}

sums_of () { # container image options: sums and blocks of the files
    sh_ container run --rm --network none "$@" 'cd /data && sha256sum small big sparse copied added/added added/sub/blob from-base hard empty link && stat -c "%n %s %b" sparse' 2>&1
}
# the directories of an image, as the layers give them (the merge of the
# tars of an `image save`) and as a container sees them: the empty ones too
layer_dirs () { # archive
    python3 -I -c '
import io, json, sys, tarfile
def layers(t):
    blob = lambda d: t.extractfile("blobs/sha256/" + d.split(":")[1]).read()
    index = json.load(t.extractfile("index.json"))
    manifest = json.loads(blob(index["manifests"][0]["digest"]))
    return ["blobs/sha256/" + l["digest"].split(":")[1] for l in manifest["layers"]]
t = tarfile.open(sys.argv[1])
tree = {}
for l in layers(t):
    for m in tarfile.open(fileobj=io.BytesIO(t.extractfile(l).read())):
        n = "/" + "/".join(p for p in m.name.split("/") if p not in ("", "."))
        d, base = n.rsplit("/", 1)
        if base == ".wh..wh..opq":
            tree = {k: v for k, v in tree.items() if not k.startswith(d + "/")}
        elif base.startswith(".wh."):
            w = d + "/" + base[4:]
            tree = {k: v for k, v in tree.items() if k != w and not k.startswith(w + "/")}
        else:
            tree[n] = m
for n, m in sorted(tree.items()):
    if m.isdir() and not n.startswith(("/proc", "/sys", "/dev", "/run")):
        print("%o %s" % (m.mode & 0o7777, n))' "$1" | sort -k2
}
container_dirs () { # container image options
    sh_ container run --rm --network none --user 0 "$@" \
        "find / -xdev -type d -exec stat -c '%a %n' {} +" 2>&1 \
        | grep -v -E ' /(proc|sys|dev|run)?$| /(proc|sys|dev|run)/' | sort -k2
}

# what the build test computed: the digest of the image, its files and
# directories
load_built () {
    built_id=$(cat "$WORKDIR/built_id")
    built_sums=$(cat "$WORKDIR/built_sums")
    built_dirs=$(cat "$WORKDIR/built_dirs")
}

# push_pull COMPRESSION: push in the compression, pull back in fresh stores
push_pull () {
    local comp=$1 tag out pushed m toc regs mode lazy
    load_built
    tag=${comp%%:*}
    use_store build
    out=$(sh_ image push --tls-verify=false --compression-format "$comp" localhost/build-loop:1 "$REPO:$tag" 2>&1)
    check_match "push $comp" "Digest: sha256:[0-9a-f]{64}" "$out"
    pushed=$(echo "$out" | grep -o 'sha256:[0-9a-f]\{64\}' | tail -1)
    m=$(manifest "$REPO:$tag")
    check_match "$comp: the pushed manifest states the merged EROFS" "\"$SEAL\": *\"[0-9a-f]{64}\"" "$m"
    if [ "$comp" = zstd:chunked ]; then
        check "zstd:chunked: the manifest pushed has the configuration the image id is the digest of" "$built_id" \
            "$(echo "$m" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["config"]["digest"].split(":")[1])')"
        out=$(sh_ image push --tls-verify=false localhost/build-loop:1 "$REPO:$tag" 2>&1)
        check_match "a push of what the registry has uploads nothing" " 0 uploaded" "$out"
        toc=$(echo "$m" | top_toc)
        regs=$(echo "$toc" | python3 -I -c '
import json, re, sys
e = [x for x in json.load(sys.stdin)["entries"] if x["type"] == "reg" and x.get("size", 0) > 0]
ok = all(re.fullmatch("sha256-12:[0-9a-f]{64}", x.get("fsverity", "")) for x in e)
print(len(e) > 0 and ok)')
        check "the TOC gives the fs-verity digest of every file" "True" "$regs"
    fi
    for mode in eager lazy; do
        use_store "pull-$tag-$mode"
        if [ $mode = lazy ] && [ "$comp" != zstd:chunked ]; then
            # (a layer with no table of contents cannot be lazy: the pull
            # is refused before anything is in the store)
            sh_ image pull --lazy --tls-verify=false "$REPO:$tag" > "$WORKDIR/pull.out" 2>&1
            check "$comp lazy: refused" "125 1" "$? $(grep -c 'cannot be pulled lazily: layer 1 (sha256:[0-9a-f]*): .* has no table of contents' "$WORKDIR/pull.out")"
            check "$comp lazy: nothing in the store" "0 0  0" \
                "$(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM images") $(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM layers") $(sh_ image pulls -q) $(find "$STORE/store/staging" -name layer.json 2>/dev/null | wc -l)"
            continue
        fi
        if [ $mode = lazy ]; then
            # (no background completion: the containers below run on the
            # pull in progress, their files fetched as they read them)
            sh_ image pull --lazy --tls-verify=false "$REPO:$tag" > "$WORKDIR/pull.out" 2>&1
        else
            sh_ image pull --tls-verify=false "$REPO:$tag" > "$WORKDIR/pull.out" 2>&1
        fi
        check "$comp $mode: pull" "0 " "$? $(grep -i error "$WORKDIR/pull.out")"
        lazy=
        if [ $mode = lazy ] && [ "$comp" = zstd:chunked ]; then lazy=--lazy; fi
        if [ -n "$lazy" ]; then
            # a pull in progress, not an image of the store until it is
            # complete: its id is the manifest pushed
            check "$comp lazy: the pull is the manifest pushed" "${pushed#sha256:}" \
                "$(sh_ image pulls -q --no-trunc 2>&1)"
            check "$comp lazy: no image of the store yet" "0 " \
                "$(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM images") $(sh_ image list -q)"
        else
            check "$comp $mode: the image is the manifest pushed" "$pushed" \
                "$(sh_ image inspect --format '{{.Digest}}' "$REPO:$tag" 2>&1)"
        fi
        check "$comp $mode: the files" "$built_sums" "$(sums_of $lazy "$REPO:$tag")"
        check "$comp $mode: the directories, the empty ones too" "$built_dirs" \
            "$(container_dirs $lazy "$REPO:$tag")"
        if [ -n "$lazy" ]; then
            check "$comp lazy: still a pull while no command waits for it" 0 \
                "$(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM images")"
            # the pull is completed (only if its merged EROFS is the one
            # stated): the image is one of the store
            sh_ image complete "$REPO:$tag" > /dev/null 2>&1
            check "$comp lazy: completed" "" "$(sh_ image pulls -q)"
            check "$comp lazy: in the store" 1 "$(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM images")"
            check "$comp lazy: the image is the manifest pushed" "$pushed" \
                "$(sh_ image inspect --format '{{.Digest}}' "$REPO:$tag" 2>&1)"
            check "$comp lazy: the files after the completion" "$built_sums" "$(sums_of "$REPO:$tag")"
        fi
        sh_ system check > "$WORKDIR/check.out" 2>&1
        check "$comp $mode: system check" "0 " "$? $(cat "$WORKDIR/check.out")"
    done
}

# the base ------------------------------------------------------------------
# a pulled image (its TOCs give the fs-verity digests of the layer writer),
# pushed again with another compression (it states its merged EROFS) and back
# as zstd:chunked, which the layer writer makes: the base of the build

@test "base: TOCs without fs-verity digests are refused, lazily or not" {
    local plain=$E2E_REGISTRY/alpine-plain:chunked
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/alpine-plain/manifests/chunked" -o /dev/null -H 'Accept: application/vnd.oci.image.manifest.v1+json' || skip "no $plain"
    use_store plain
    for lazy in --lazy ""; do
        sh_ image pull $lazy --tls-verify=false "$plain" > "$WORKDIR/pull.out" 2>&1
        check "a pull ($lazy) of TOCs without fs-verity digests is refused" "125 1" \
            "$? $(grep -c 'layer sha256:[0-9a-f]*: its table of contents has no fs-verity digest for' "$WORKDIR/pull.out")"
        check "before anything is in the store" "0 0 " \
            "$(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM images") $(sqlite3 "file:$STORE/store/db.sqlite?mode=ro" "SELECT count(*) FROM layers") $(sh_ image pulls -q)"
    done
}

@test "base: pushed again with another compression and back as zstd:chunked" {
    use_store pushed-base
    sh_ image pull --tls-verify=false "$BASE" > /dev/null 2>&1
    out=$(sh_ image push --tls-verify=false --compression-format gzip "$BASE" "$REPO:base-gzip" 2>&1)
    check_match "push of a pulled image" "Digest: sha256:[0-9a-f]{64}" "$out"
    check_match "it states its merged EROFS" "\"$SEAL\"" "$(manifest "$REPO:base-gzip")"
    use_store pull-base
    sh_ image pull --tls-verify=false "$REPO:base-gzip" > /dev/null 2>&1
    check "it pulls back" 0 $?
    check_match "and runs" "^[0-9]+\.[0-9]+" "$(sh_ container run --rm --network none "$REPO:base-gzip" cat /etc/alpine-release 2>&1)"
    out=$(sh_ image push --tls-verify=false --compression-format zstd:chunked "$REPO:base-gzip" "$REPO:base" 2>&1)
    check_match "and pushed as zstd:chunked" "Digest: sha256:[0-9a-f]{64}" "$out"
}

# a RUN writes files of its base: the copy-up of a stub of the image of a
# layer (the overlay opens the stub through FUSE for its attributes)

@test "a RUN writes the files of its base" {
    use_store copy-up
    mkdir -p "$WORKDIR/copy-up"
    printf 'FROM %s\nRUN printf x >> /etc/services && chmod 600 /lib/apk/db/installed\n' "$REPO:base" \
        > "$WORKDIR/copy-up/Containerfile"
    sh_ image build -q -t localhost/copy-up:1 "$WORKDIR/copy-up" > "$WORKDIR/build.out" 2>&1
    check "a RUN writes the files of its base" "0 " "$? $(grep -i error "$WORKDIR/build.out")"
    check "and keeps their bytes" \
        "$(sh_ container run --rm --network none "$REPO:base" sh -c 'cat /etc/services; printf x' | sha256sum)" \
        "$(sh_ container run --rm --network none localhost/copy-up:1 cat /etc/services | sha256sum)"
    check "and their modes" "600" \
        "$(sh_ container run --rm --network none localhost/copy-up:1 stat -c %a /lib/apk/db/installed 2>&1)"
}

# the build -------------------------------------------------------------------

@test "build: velarx build and build --squash-all" {
    use_store build
    mkdir -p "$CTX/tree/sub"
    echo "copied" > "$CTX/copied"
    head -c 100000 /dev/urandom > "$CTX/tree/sub/blob"
    echo "added" > "$CTX/tree/added"
    cat > "$CTX/Containerfile" <<EOF
FROM $REPO:base AS base
RUN mkdir -p /data && echo hello > /data/small && : > /data/empty \\
 && head -c 3000000 /dev/urandom > /data/big && ln /data/small /data/hard \\
 && ln -s small /data/link \\
 && test -d /var/log && touch /var/log/x && test "\$(stat -c %a /tmp)\$(stat -c %a /var/tmp)" = 17771777
FROM base
# 64 MiB with 4 KiB of data in the middle and at the end
RUN truncate -s 64M /data/sparse \\
 && printf middle | dd of=/data/sparse bs=1 seek=33554432 conv=notrunc 2> /dev/null \\
 && printf end | dd of=/data/sparse bs=1 seek=67108861 conv=notrunc 2> /dev/null
COPY copied /data/copied
ADD tree/ /data/added/
COPY --from=base /data/small /data/from-base
ENV A=1 B="two words"
LABEL org.example.l=v
USER 1000
WORKDIR /data
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["cat /data/small"]
EOF
    sh_ image build -q -t localhost/build-loop:1 "$CTX" > "$WORKDIR/build.out" 2>&1
    rc=$?
    [ $rc = 0 ] || cat "$WORKDIR/build.out"
    check "velarx build" 0 $rc
    sh_ image build -q --squash-all -t localhost/build-loop:squashed "$CTX" > "$WORKDIR/squash.out" 2>&1
    check "build --squash-all" 0 $?
    check "squash-all: one layer" 1 "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/build-loop:squashed)"
    check "squash-all: the same content" \
        "$(sh_ container run --rm --network none localhost/build-loop:1 'cd /data && sha256sum small big sparse copied added/added added/sub/blob from-base hard empty link && stat -c "%n %s %b" sparse' 2>&1)" \
        "$(sh_ container run --rm --network none localhost/build-loop:squashed 'cd /data && sha256sum small big sparse copied added/added added/sub/blob from-base hard empty link && stat -c "%n %s %b" sparse' 2>&1)"
    check "squash-all: the same configuration" \
        "$(sh_ image inspect --format '{{.Config.Env}} {{.Config.Cmd}} {{.Config.Entrypoint}} {{.Config.User}} {{.Config.WorkingDir}}' localhost/build-loop:1)" \
        "$(sh_ image inspect --format '{{.Config.Env}} {{.Config.Cmd}} {{.Config.Entrypoint}} {{.Config.User}} {{.Config.WorkingDir}}' localhost/build-loop:squashed)"
}

@test "build: the built image runs, its files and directories, system check" {
    local built_id built_sums built_dirs sparse_blocks
    use_store build
    sh_ image inspect localhost/build-loop:1 > "$WORKDIR/inspect.json"
    built_id=$(sh_ image inspect --format '{{.Id}}' localhost/build-loop:1)
    check_match "the built image runs" "^hello$" "$(sh_ container run --rm --network none localhost/build-loop:1 2>&1)"
    check_match "its configuration" "1000 /data A=1 two words v" \
        "$(sh_ container run --rm --network none localhost/build-loop:1 'echo $(id -u) $PWD A=$A $B' 2>&1) $(sh_ image inspect --format '{{index .Labels "org.example.l"}}' localhost/build-loop:1)"
    built_sums=$(sums_of localhost/build-loop:1)
    sh_ image save -q -o "$WORKDIR/dirs.tar" localhost/build-loop:1
    built_dirs=$(layer_dirs "$WORKDIR/dirs.tar")
    rm -f "$WORKDIR/dirs.tar"
    echo "$built_id" > "$WORKDIR/built_id"
    echo "$built_sums" > "$WORKDIR/built_sums"
    echo "$built_dirs" > "$WORKDIR/built_dirs"
    check_match "the layers of the built image have /var/log and /tmp" "^.*(1777 /tmp).*(755 /var/log)" "$(echo "$built_dirs" | tr '\n' ' ')"
    check "the directories of a container are those of the layers, the empty ones too" "$built_dirs" \
        "$(container_dirs localhost/build-loop:1)"
    check_match "the files of the built image" "small" "$built_sums"
    sparse_blocks=$(echo "$built_sums" | awk '$1 == "sparse" {print $3}')
    check_match "the sparse file of the built image has holes" "^[0-9]{1,3}$" "$sparse_blocks"
    sh_ system check > "$WORKDIR/check.out" 2>&1
    check "system check of the build store" "0 " "$? $(cat "$WORKDIR/check.out")"
}

# the progress of build, commit and push on a run that is not a terminal:
# lines on the standard error, no escape codes or carriage returns, none with
# --quiet

@test "progress: a quiet build says nothing of its blobs, a build shows its layers" {
    use_store build
    check "a quiet build says nothing of its blobs" "" "$(grep -c 'new layer' "$WORKDIR/build.out" | grep -v '^0$')"
    mkdir -p "$CTX/progress"
    printf 'FROM %s\nRUN head -c 1000000 /dev/urandom > /p\n' "$REPO:base" > "$CTX/progress/Containerfile"
    sh_ image build -t localhost/progress:1 "$CTX/progress" > "$WORKDIR/progress.out" 2> "$WORKDIR/progress.err"
    check "a build with its progress" 0 $?
    check_match "the build shows the layer it writes" "new layer streaming.*new layer complete [0-9.]+ [KM]B" \
        "$(tr '\n' ' ' < "$WORKDIR/progress.err")"
    check_match "and the image it merges" "Merging the layers" "$(cat "$WORKDIR/progress.err")"
    check "the progress has no escape codes or carriage returns" "" "$(grep -c -P '\x1b|\r' "$WORKDIR/progress.err" | grep -v '^0$')"
    check_match "the steps stay on the standard output" "STEP 2/2: RUN" "$(cat "$WORKDIR/progress.out")"
}

@test "progress: a commit shows its layer, commit --squash" {
    local out
    use_store build
    sh_ container run --network none --user 0 --name progress-c localhost/build-loop:1 'echo changed > /data/changed' > /dev/null 2>&1
    out=$(sh_ image commit progress-c localhost/progress-commit:1 2>&1 > /dev/null)
    check_match "a commit shows its layer" "new layer streaming.*new layer complete" "$(echo "$out" | tr '\n' ' ')"
    check_match "and the layer in the store" "[0-9a-f]{12} complete [0-9.]+ [KB]+" "$out"
    out=$(sh_ image commit -q progress-c localhost/progress-commit:2 2>&1 > /dev/null)
    check "a quiet commit says nothing" "" "$out"
    sh_ image commit --squash progress-c localhost/progress-commit:sq > /dev/null 2>&1
    check "commit --squash" 0 $?
    check "commit --squash: one layer" 1 "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/progress-commit:sq)"
    check "commit --squash: the same content" \
        "$(sh_ container run --rm --network none localhost/progress-commit:1 'cd /data && sha256sum small big sparse copied added/added added/sub/blob from-base hard empty link changed' 2>&1)" \
        "$(sh_ container run --rm --network none localhost/progress-commit:sq 'cd /data && sha256sum small big sparse copied added/added added/sub/blob from-base hard empty link changed' 2>&1)"
    check "commit --squash: the same configuration" \
        "$(sh_ image inspect --format '{{.Config.Env}} {{.Config.Cmd}} {{.Config.Entrypoint}} {{.Config.User}} {{.Config.WorkingDir}}' localhost/progress-commit:1)" \
        "$(sh_ image inspect --format '{{.Config.Env}} {{.Config.Cmd}} {{.Config.Entrypoint}} {{.Config.User}} {{.Config.WorkingDir}}' localhost/progress-commit:sq)"
    out=$(sh_ image commit -q --squash progress-c 2>&1 > /dev/null)
    check "a quiet squashed commit says nothing" "" "$out"
    sh_ container rm progress-c > /dev/null 2>&1
}

@test "progress: a push and a load" {
    local out
    use_store build
    out=$(sh_ image push --tls-verify=false --compression-format gzip localhost/build-loop:1 "$REPO:progress" 2>&1 > /dev/null)
    check_match "a push shows the layers it compresses and uploads" "[0-9a-f]{12} complete [0-9.]+ [KM]B" "$out"
    check_match "and the manifest" "Pushing the manifest" "$out"
    check "the push has no escape codes or carriage returns" "" "$(echo "$out" | grep -c -P '\x1b|\r' | grep -v '^0$')"
    out=$(sh_ image push --tls-verify=false --compression-format gzip localhost/build-loop:1 "$REPO:progress" 2>&1 > /dev/null)
    check_match "a push of what the registry has shows it" "[0-9a-f]{12} already exists" "$out"
    sh_ image save -o "$WORKDIR/progress.tar" localhost/progress:1 > "$WORKDIR/save.out" 2>&1
    check "a save writes the archive and says nothing" "" "$(cat "$WORKDIR/save.out")"
    sh_ image load -i "$WORKDIR/progress.tar" > "$WORKDIR/load.out" 2>&1
    check_match "a load shows its layers, as a pull does" "[0-9a-f]{12} complete [0-9.]+ [KM]B.*Loaded image" "$(tr '\n' ' ' < "$WORKDIR/load.out")"
    sh_ image load -q -i "$WORKDIR/progress.tar" > "$WORKDIR/load.out" 2>&1
    check_match "a quiet load shows nothing but the id" "^[0-9a-f]{12}$" "$(cat "$WORKDIR/load.out")"
    rm -f "$WORKDIR/progress.tar"
}

# push in each compression, pull back in fresh stores ----------------------

@test "push zstd:chunked, pull it back eagerly and lazily" {
    push_pull zstd:chunked
}

@test "push gzip, pull it back eagerly and lazily" {
    push_pull gzip
}

@test "push uncompressed, pull it back eagerly and lazily" {
    push_pull none
}

# the pull of the base of a build, in a store that has none of it: bars
# on a terminal (a pty of 120 columns), lines on the standard error elsewhere

@test "the pull of the base of a build on a terminal" {
    local layers tty_out l
    use_store pty-build
    mkdir -p "$CTX/pty"
    printf 'FROM %s\nUSER root\nRUN test -d /var/log && touch /var/log/x\n' "$REPO:zstd" > "$CTX/pty/Containerfile"
    layers=$(manifest "$REPO:zstd" | python3 -I -c "
import json, sys
print(' '.join(l['digest'].split(':')[1][:12] for l in json.load(sys.stdin)['layers']))")
    check_match "the base has layers" "^[0-9a-f]{12}" "$layers"
    echo "$layers" > "$WORKDIR/layers"
    python3 -I -c '
import fcntl, os, pty, struct, sys, termios
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[2], sys.argv[2:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
with open(sys.argv[1], "wb") as out:
    while True:
        try:
            b = os.read(fd, 65536)
        except OSError:
            break
        if not b:
            break
        out.write(b)
sys.exit(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))' \
        "$WORKDIR/pty.out" "$BIN/velarx" --socket "$STORE/sh.sock" image build --tls-verify=false -t localhost/pty:1 "$CTX/pty"
    check "a build on a terminal" 0 $?
    tty_out=$(sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' "$WORKDIR/pty.out" | tr '\r' '\n')
    check_match "says it pulls the base" "STEP 1/3: FROM .*Pulling " "$(echo "$tty_out" | tr '\n' ' ')"
    for l in $layers; do
        check_match "a bar for the layer $l of the base" "$l \[#+\] 100% Complete \(" "$tty_out"
    done
    check_match "and the build goes on" "STEP 3/3: RUN" "$tty_out"
}

@test "the pull of the base of a build, not on a terminal" {
    local layers l
    layers=$(cat "$WORKDIR/layers")
    use_store plain-build
    sh_ image build --tls-verify=false -t localhost/pty:1 "$CTX/pty" > "$WORKDIR/plain.out" 2> "$WORKDIR/plain.err"
    check "a build with its base pulled, not on a terminal" 0 $?
    for l in $layers; do
        check_match "a line for the layer $l of the base" "^$l (downloading|complete)" "$(cat "$WORKDIR/plain.err")"
    done
    check "the lines have no escape codes or carriage returns" "" "$(grep -c -P '\x1b|\r' "$WORKDIR/plain.err" | grep -v '^0$')"
    check_match "the steps stay on the standard output" "STEP 1/3: FROM .*STEP 3/3: RUN" "$(tr '\n' ' ' < "$WORKDIR/plain.out")"
    check_match "the pull of the base on the standard error, as buildah's" "Pulling " "$(cat "$WORKDIR/plain.err")"
}

# an image whose manifest states another merged EROFS is refused

@test "an image whose manifest states another merged EROFS is refused" {
    local m out
    use_store build
    m=$(manifest "$REPO:zstd" | python3 -I -c "
import json, sys
m = json.load(sys.stdin); m['annotations']['$SEAL'] = 'ab' * 32
sys.stdout.write(json.dumps(m))")
    curl -sf -X PUT -H 'Content-Type: application/vnd.oci.image.manifest.v1+json' --data-binary "$m" \
        "http://$E2E_REGISTRY/v2/${REPO#*/}/manifests/forged" > /dev/null
    use_store pull-forged
    out=$(sh_ image pull --tls-verify=false "$REPO:forged" 2>&1)
    check_match "a pull of a manifest that states another merged EROFS fails" "$SEAL" "$out"
    check "and records no image" "" "$(sh_ image list -q 2>&1)"
    stop_daemon
}

# other tools read what velarx pushed

@test "skopeo reads what velarx pushed" {
    command -v skopeo > /dev/null || skip "no skopeo"
    local tag out
    for tag in zstd gzip none; do
        out=$(skopeo inspect --tls-verify=false "docker://$REPO:$tag" 2>&1)
        check "skopeo inspect $tag" "0 " "$? $(echo "$out" | grep -i error)"
        skopeo copy -q --src-tls-verify=false "docker://$REPO:$tag" "oci:$WORKDIR/oci:$tag" > "$WORKDIR/skopeo.out" 2>&1
        check "skopeo copy $tag" "0 " "$? $(cat "$WORKDIR/skopeo.out")"
    done
}

# What velarx pushed is read by the containers image library, the one podman
# pulls with: skopeo copies each image into an OCI layout (every blob checked
# against its digest, no store, no podman process, no pause process), and
# the files of its layers, unpacked in order, are those that were built.
@test "the containers image library reads what velarx pushed" {
    command -v skopeo > /dev/null || skip "no skopeo"
    local tag out layout layer root manifest
    load_built
    for tag in zstd gzip; do
        layout="$WORKDIR/oci-$tag"
        rm -rf "$layout"
        skopeo copy -q --src-tls-verify=false "docker://$REPO:$tag" "oci:$layout:x" > "$WORKDIR/skopeo.out" 2>&1
        check "skopeo reads $tag" "0 " "$? $(grep -i error "$WORKDIR/skopeo.out")"
    done
    layout="$WORKDIR/oci-zstd"
    root="$WORKDIR/oci-root"
    rm -rf "$root" && mkdir -p "$root"
    manifest=$(jq -r '.manifests[0].digest' "$layout/index.json")
    for layer in $(jq -r '.layers[].digest' "$layout/blobs/${manifest%%:*}/${manifest#*:}"); do
        zstd -dcq "$layout/blobs/${layer%%:*}/${layer#*:}" | tar -x --no-same-owner -C "$root"
    done
    out=$(cd "$root/data" && sha256sum big sparse)
    check "its layers have the files that were built" "$(echo "$built_sums" | grep -E ' (big|sparse)$')" "$out"
    rm -rf "$WORKDIR"/oci-zstd "$WORKDIR"/oci-gzip "$root"
}
