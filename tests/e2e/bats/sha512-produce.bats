# SPDX-License-Identifier: Apache-2.0
# Images that velarx makes with sha512 digests: `--digest sha512` (and
# `[build] digest`) on build, commit, import, `manifest create` and
# `artifact add`; every digest of the image is then a sha512 (the layers, the
# diff ids, the configuration, the manifest, the TOC and the merged EROFS
# statement of its annotations), its id has 128 hex digits, a build on a
# sha256 base is a mixed image (the base's layers and diff ids stay what they
# are), `commit` follows the image of its container, `push` says once that a
# registry may refuse it, `save` writes it as an OCI archive and refuses the
# docker-archive, and the images pull back from a registry that takes sha512
# manifests by `NAME:TAG@sha512:D`.
#
# The registries are tests/e2e/sha512_registry.py (one that addresses
# manifests by sha256 only, as registry:2 and registry:3 do, and one that
# takes the sha512 too, as zot does), and the real registry:3 and zot when
# VELARX_E2E_REGISTRY3 and VELARX_E2E_ZOT name their binaries (the `registry`
# of the registry:3 image and `zot-linux-amd64` of zot's).
#
# The tests that enforce the digests need a store on a file system with
# fs-verity, as sha512-digests.bats (root: a loop device of the work directory,
# in a mount namespace of its own; rootless: VELARX_VERITY_DIR); the others
# skip.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/sha512-produce.bats

load helpers
load verity

# the diff ids of an image of the daemon's store (RootFS.Layers), one a line
slayers () { sc image inspect "$1" | python3 -I -c "import sys, json; print('\n'.join(json.load(sys.stdin)[0]['RootFS']['Layers']))"; }

free_port () { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }

start_real_registry () { # kind (registry3 or zot), binary: sets REGISTRY
    local port; port=$(free_port)
    mkdir -p "$WORKDIR/$1-data"
    if [ "$1" = zot ]; then
        printf '{"storage":{"rootDirectory":"%s"},"http":{"address":"127.0.0.1","port":"%s"},"log":{"level":"warn"}}\n' \
            "$WORKDIR/zot-data" "$port" > "$WORKDIR/zot.json"
        "$2" serve "$WORKDIR/zot.json" > "$WORKDIR/zot.log" 2>&1 &
    else
        printf 'version: 0.1\nlog:\n  level: warn\nstorage:\n  filesystem:\n    rootdirectory: %s\nhttp:\n  addr: 127.0.0.1:%s\n' \
            "$WORKDIR/registry3-data" "$port" > "$WORKDIR/registry3.yml"
        "$2" serve "$WORKDIR/registry3.yml" > "$WORKDIR/registry3.log" 2>&1 &
    fi
    echo $! >> "$WORKDIR/registry.pids"
    REGISTRY=127.0.0.1:$port
    local i
    for i in $(seq 1 100); do
        curl -sf -m 1 "http://$REGISTRY/v2/" > /dev/null && return 0
        sleep 0.1
    done
    e2e_die "no registry at $REGISTRY"
}

setup_file () {
    command -v python3 > /dev/null || skip "no python3"
    command -v curl > /dev/null || skip "no curl"
    e2e_setup_file
    start_registry distribution
    export DIST=$REGISTRY
    start_registry zot
    export ZOT=$REGISTRY
    # the registries that take sha512 manifests by their digest, and those
    # that do not
    export TAKES="$ZOT"
    export REFUSES="$DIST"
    if [ -n "${VELARX_E2E_ZOT:-}" ] && [ -x "$VELARX_E2E_ZOT" ]; then
        start_real_registry zot "$VELARX_E2E_ZOT"
        export REAL_ZOT=$REGISTRY
        TAKES="$TAKES $REGISTRY"
    fi
    if [ -n "${VELARX_E2E_REGISTRY3:-}" ] && [ -x "$VELARX_E2E_REGISTRY3" ]; then
        start_real_registry registry3 "$VELARX_E2E_REGISTRY3"
        export REAL_R3=$REGISTRY
        REFUSES="$REFUSES $REGISTRY"
    fi
    export ALLREGS="$DIST $ZOT ${REAL_ZOT:-} ${REAL_R3:-}"
    : > "$WORKDIR/registries.conf"
    local reg
    for reg in $ALLREGS; do
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n\n' "$reg" >> "$WORKDIR/registries.conf"
    done
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    e2e_start_daemon
    e2e_make_image localhost/e2e-base:1
    # the base is pulled by its sha256 (the mixed case of a build)
    sc image push --tls-verify=false --compression-format gzip localhost/e2e-base:1 "$DIST/e2e/base:1" > /dev/null 2>&1 || e2e_die "push of the base"
    sc image rm localhost/e2e-base:1 > /dev/null 2>&1
    sc image pull --tls-verify=false "$DIST/e2e/base:1" > /dev/null 2>&1 || e2e_die "pull of the base"
    export BASE_DIGEST; BASE_DIGEST=$(sc image inspect --format '{{.Digest}}' "$DIST/e2e/base:1")
    check_match "the base is a sha256 image" '^sha256:[0-9a-f]{64}$' "$BASE_DIGEST"
    export BASE=$DIST/e2e/base@$BASE_DIGEST
    mkdir -p "$WORKDIR/ctx"
    echo hello > "$WORKDIR/ctx/file"
    printf 'FROM %s\nCOPY file /file\nRUN echo made > /made\n' "$BASE" > "$WORKDIR/ctx/Containerfile"
    printf 'FROM scratch\nCOPY file /file\n' > "$WORKDIR/ctx/Scratchfile"
    # a store on a file system with fs-verity, where there is one
    e2e_verity_store
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -z "${VS:-}" ] || [ "$(id -u)" = 0 ] || rm -rf "$VS"
    local pid
    for pid in $(cat "$WORKDIR/registry.pids" 2> /dev/null); do kill "$pid" 2> /dev/null; done
    e2e_teardown_file
}

# pushed_digest IMAGE: the digest of the manifest a push of the image writes
# (the layers are compressed by the push: the manifest of the store is not it)
pushed_digest () {
    sc image push --quiet --digestfile "$WORKDIR/pushed-digest" --tls-verify=false "$1" "${ALLREGS%% *}/produce/learn:1" > /dev/null 2>&1 || return 1
    cat "$WORKDIR/pushed-digest"
}

@test "build --digest sha512 on a sha256 base makes a mixed image: the base's links stay sha256, the new ones are sha512" {
    out=$(sc build --digest sha512 -t localhost/mixed:1 "$WORKDIR/ctx" 2>&1)
    check "build" 0 $?
    check_match "the id of the image has 128 hex digits" '^[0-9a-f]{128}$' "$(printf '%s\n' "$out" | tail -1)"
    d=$(sc image inspect --format '{{.Digest}}' localhost/mixed:1)
    check_match "the manifest is a sha512" '^sha512:[0-9a-f]{128}$' "$d"
    check_match "the id has 128 hex digits" '^[0-9a-f]{128}$' "$(sc image inspect --format '{{.Id}}' localhost/mixed:1)"
    layers=$(slayers localhost/mixed:1)
    check "three layers" 3 "$(printf '%s\n' "$layers" | wc -l)"
    check_match "the base layer is as it was" '^sha256:[0-9a-f]{64}$' "$(printf '%s\n' "$layers" | sed -n 1p)"
    check_match "COPY is a sha512 diff id" '^sha512:[0-9a-f]{128}$' "$(printf '%s\n' "$layers" | sed -n 2p)"
    check_match "RUN is a sha512 diff id" '^sha512:[0-9a-f]{128}$' "$(printf '%s\n' "$layers" | sed -n 3p)"
    # no statement of the merged EROFS: the layers have two algorithms
    check "no merged-tree annotation" 0 "$(sc image inspect --format '{{json .Annotations}}' localhost/mixed:1 | grep -c 'composefs.merged')"
    out=$(sc run --rm --network none localhost/mixed:1 cat /file /made 2>&1)
    check "run" 0 $?
    check_match "ran" "hello" "$out"
    check_match "and the RUN step's file" "made" "$out"
    sc system check > /dev/null 2>&1
    check "system check" 0 $?
}

@test "a build from scratch with --digest sha512 has only sha512 digests and states the merged EROFS with SHA-512" {
    sc build --digest sha512 -f "$WORKDIR/ctx/Scratchfile" -t localhost/own512:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build" 0 $?
    check_match "the id has 128 hex digits" '^[0-9a-f]{128}$' "$(sc image inspect --format '{{.Id}}' localhost/own512:1)"
    layers=$(slayers localhost/own512:1)
    check_match "its layer's diff id" '^sha512:[0-9a-f]{128}$' "$layers"
    check_match "the merged EROFS is stated with SHA-512" 'composefs.merged.erofs.v1.fsverity-sha512-12' "$(sc image inspect --format '{{json .Annotations}}' localhost/own512:1)"
    check "none with SHA-256" 0 "$(sc image inspect --format '{{json .Annotations}}' localhost/own512:1 | grep -c 'fsverity-sha256-12')"
    sc image save --format oci-archive -o "$WORKDIR/own512.tar" localhost/own512:1 > /dev/null 2>&1
    check "save" 0 $?
    # (the archive has no sha256 blob but the ones of the image: none)
    check "all the blobs are sha512" 0 "$(tar tf "$WORKDIR/own512.tar" | grep -c '^blobs/sha256/.')"
    sc system check > /dev/null 2>&1
    check "system check" 0 $?
}

@test "a build without --digest is sha256, [build] digest sets the default, and --digest overrides it" {
    store=$WORKDIR/cfg
    # (the configuration of the file, and the default of the digests)
    { cat "$XDG_CONFIG_HOME/velarx/config.toml"; printf '[build]\ndigest = "sha512"\n'; } > "$WORKDIR/sha512.toml"
    "$SH" --config "$WORKDIR/sha512.toml" --root "$store" build -f "$WORKDIR/ctx/Scratchfile" -t localhost/cfg:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build with the configured default" 0 $?
    check_match "sha512" '^sha512:' "$(shs "$store" image inspect --format '{{.Digest}}' localhost/cfg:1)"
    "$SH" --config "$WORKDIR/sha512.toml" --root "$store" build --digest sha256 -f "$WORKDIR/ctx/Scratchfile" -t localhost/cfg:2 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build with the flag" 0 $?
    check_match "the flag wins" '^sha256:' "$(shs "$store" image inspect --format '{{.Digest}}' localhost/cfg:2)"
    shs "$store" build -f "$WORKDIR/ctx/Scratchfile" -t localhost/cfg:3 "$WORKDIR/ctx" > /dev/null 2>&1
    check_match "none: sha256" '^sha256:' "$(shs "$store" image inspect --format '{{.Digest}}' localhost/cfg:3)"
    # (a pull is never changed by it)
    "$SH" --config "$WORKDIR/sha512.toml" --root "$store" image pull --tls-verify=false "$DIST/e2e/base:1" > /dev/null 2>&1
    check_match "a pulled image has its own digests" '^sha256:' "$("$SH" --config "$WORKDIR/sha512.toml" --root "$store" image inspect --format '{{.Digest}}' "$DIST/e2e/base:1")"
    { cat "$XDG_CONFIG_HOME/velarx/config.toml"; printf '[build]\ndigest = "md5"\n'; } > "$WORKDIR/bad.toml"
    out=$("$SH" --config "$WORKDIR/bad.toml" --root "$WORKDIR/badcfg" image ls 2>&1)
    check "a bad value is refused" 125 $?
    check_match "named" '\[build\] digest = "md5": sha256 or sha512' "$out"
}

@test "an unknown --digest is refused by name by every command that makes images" {
    : > "$WORKDIR/empty.tar"
    c=$(sc create --network none localhost/own512:1 true) || exit 1
    for args in \
        "build --digest md5 -t localhost/x:1 $WORKDIR/ctx" \
        "commit --digest md5 $c localhost/x:2" \
        "import --digest md5 $WORKDIR/rootfs.tar localhost/x:3" \
        "manifest create --digest md5 localhost/xlist" \
        "artifact add --digest md5 localhost/xart $WORKDIR/ctx/file"; do
        # shellcheck disable=SC2086
        out=$(sc $args 2>&1)
        check "refused: $args" 125 $?
        check_match "named: $args" 'unknown digest algorithm `md5`' "$out"
    done
    sc rm -f "$c" > /dev/null 2>&1
    check "nothing was made" "" "$(sc image ls -q --filter reference='localhost/x:*')"
    out=$(sc build --digest SHA512 -t localhost/x:1 "$WORKDIR/ctx" 2>&1)
    check_match "case matters" 'unknown digest algorithm `SHA512`' "$out"
}

@test "commit follows the image of its container, and --digest sets the algorithm" {
    c=$(sc create --network none localhost/own512:1 true) || exit 1
    sc commit "$c" localhost/follow:1 > /dev/null 2>&1
    check "commit" 0 $?
    check_match "a sha512 image commits to a sha512 image" '^sha512:[0-9a-f]{128}$' "$(sc image inspect --format '{{.Digest}}' localhost/follow:1)"
    check_match "its id has 128 hex digits" '^[0-9a-f]{128}$' "$(sc image inspect --format '{{.Id}}' localhost/follow:1)"
    sc commit --digest sha256 "$c" localhost/down:1 > /dev/null 2>&1
    check "commit --digest sha256" 0 $?
    check_match "sha256 on a sha512 image" '^sha256:[0-9a-f]{64}$' "$(sc image inspect --format '{{.Digest}}' localhost/down:1)"
    sc rm -f "$c" > /dev/null 2>&1
    c=$(sc create --network none localhost/mixed:1 true) || exit 1
    sc commit "$c" localhost/follow-mixed:1 > /dev/null 2>&1
    check "commit of a mixed image" 0 $?
    check_match "follows its manifest" '^sha512:' "$(sc image inspect --format '{{.Digest}}' localhost/follow-mixed:1)"
    sc rm -f "$c" > /dev/null 2>&1
    c=$(sc create --network none "$BASE" true) || exit 1
    sc commit --digest sha512 "$c" localhost/up:1 > /dev/null 2>&1
    check "commit --digest sha512 on a sha256 image" 0 $?
    check_match "a mixed image" '^sha512:' "$(sc image inspect --format '{{.Digest}}' localhost/up:1)"
    check_match "over the base's layer" '^sha256:' "$(slayers localhost/up:1 | head -1)"
    sc rm -f "$c" > /dev/null 2>&1
    sc system check > /dev/null 2>&1
    check "system check" 0 $?
}

@test "import --digest sha512 makes a sha512 image and tells its id with its algorithm" {
    out=$(sc image import --digest sha512 "$WORKDIR/rootfs.tar" localhost/imp512:1 2> /dev/null)
    check "import" 0 $?
    check_match "the id has its algorithm and 128 digits" '^sha512:[0-9a-f]{128}$' "$out"
    check "the digest is the id" "$out" "sha512:$(sc image inspect --format '{{.Id}}' localhost/imp512:1)"
    check_match "the layer's diff id" '^sha512:' "$(slayers localhost/imp512:1 | head -1)"
    out=$(sc image import "$WORKDIR/rootfs.tar" localhost/imp256:1 2> /dev/null)
    check_match "by default sha256" '^sha256:[0-9a-f]{64}$' "$out"
    out=$(sc run --rm --network none localhost/imp512:1 echo imported 2>&1)
    check_match "it runs" "imported" "$out"
    sc system check > /dev/null 2>&1
    check "system check" 0 $?
}

@test "manifest create --digest sha512 makes a list with a sha512 digest for images and artifacts" {
    id=$(sc manifest create --digest sha512 localhost/list512) || exit 1
    sc manifest add localhost/list512 containers-storage:localhost/own512:1 > /dev/null 2>&1
    check "add an image" 0 $?
    sc manifest add --artifact localhost/list512 "$WORKDIR/ctx/file" > /dev/null 2>&1
    check "add an artifact" 0 $?
    doc=$(sc manifest inspect localhost/list512)
    check "two instances" 2 "$(printf '%s' "$doc" | python3 -I -c "import sys, json; print(len(json.load(sys.stdin)['manifests']))")"
    check "both are sha512" 2 "$(printf '%s' "$doc" | python3 -I -c "import sys, json; print(sum(m['digest'].startswith('sha512:') for m in json.load(sys.stdin)['manifests']))")"
    # (the artifact's own manifest, config and file are sha512 too: they are
    # pushed with the list)
    out=$(sc manifest create --digest sha256 localhost/list512 2>&1 --amend)
    check "another algorithm for the list that is there is refused" 125 $?
    check_match "named" "has sha512 digests, not sha256" "$out"
    sc manifest create localhost/list256 > /dev/null 2>&1
    check "a list is sha256 by default" 0 $?
    # pushed to a registry that takes the sha512 children: the index and the instances
    sc manifest push --tls-verify=false --all localhost/list512 "$ZOT/lists/l512:1" > /dev/null 2>&1
    check "push of the list" 0 $?
    code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$ZOT/v2/lists/l512/manifests/1")
    check "the registry has it" 200 "$code"
    if [ -n "${REAL_R3:-}" ]; then
        # (registry:3 takes a manifest by its sha256 only: said, not rewritten)
        out=$(sc manifest push --tls-verify=false --all localhost/list512 "$REAL_R3/lists/l512:1" 2>&1)
        check "a registry that addresses manifests by sha256 only refuses the list" 125 $?
        check_match "naming the digest" "may not take a manifest by its sha512 digest" "$out"
        check_match "with the answer of the registry" "DIGEST_INVALID" "$out"
    fi
    if [ -n "${REAL_ZOT:-}" ]; then
        # (zot takes the sha512 instances by their digest)
        sc manifest push --tls-verify=false --all localhost/list512 "$REAL_ZOT/lists/l512:1" > /dev/null 2>&1
        check "zot takes the list" 0 $?
        shs "$WORKDIR/zotlist" image pull --tls-verify=false "$REAL_ZOT/lists/l512:1" > /dev/null 2>&1
        check "a pull of the list from zot" 0 $?
        check "finds its sha512 instance" "$(sc image inspect --format '{{.Id}}' localhost/own512:1)" \
            "$(shs "$WORKDIR/zotlist" image inspect --format '{{.Id}}' "$REAL_ZOT/lists/l512:1")"
    fi
}

@test "artifact add --digest sha512 makes an artifact with sha512 digests, kept when appended to" {
    d=$(sc artifact add --digest sha512 localhost/art512 "$WORKDIR/ctx/file") || exit 1
    check_match "its digest" '^[0-9a-f]{128}$' "$d"
    doc=$(sc artifact inspect localhost/art512)
    check "the manifest digest" "sha512:$d" "$(printf '%s' "$doc" | python3 -I -c "import sys, json; print(json.load(sys.stdin)['Digest'])")"
    check "the config and the file are sha512" 2 "$(printf '%s' "$doc" | python3 -I -c "
import sys, json
m = json.load(sys.stdin)['Manifest']
print(sum(x['digest'].startswith('sha512:') for x in [m['config']] + m['layers']))")"
    echo more > "$WORKDIR/more.txt"
    sc artifact add --append localhost/art512 "$WORKDIR/more.txt" > /dev/null 2>&1
    check "append" 0 $?
    check "still sha512" 2 "$(sc artifact inspect localhost/art512 | python3 -I -c "
import sys, json
m = json.load(sys.stdin)['Manifest']
print(sum(x['digest'].startswith('sha512:') for x in m['layers']))")"
    out=$(sc artifact add --append --digest sha256 localhost/art512 "$WORKDIR/ctx/Containerfile" 2>&1)
    check "another algorithm for an artifact that is appended to is refused" 125 $?
    check_match "named" "has sha512 digests, not sha256" "$out"
    d=$(sc artifact add localhost/art256 "$WORKDIR/ctx/file") || exit 1
    check_match "sha256 by default" '^[0-9a-f]{64}$' "$d"
}

@test "a sha512 image pushes with one warning and pulls back by NAME:TAG@sha512:D, whichever the registry" {
    for reg in $ALLREGS; do
        err=$(sc image push --tls-verify=false localhost/mixed:1 "$reg/produce/mixed:1" 2>&1 > /dev/null)
        check "push to $reg" 0 $?
        check "one warning about sha512 on $reg" 1 "$(printf '%s\n' "$err" | grep -c '^Warning: the image has sha512')"
        d=$(pushed_digest localhost/mixed:1)
        store=$WORKDIR/back-${reg##*:}
        shs "$store" image pull --tls-verify=false "$reg/produce/mixed:1@$d" > /dev/null 2>&1
        check "pull back from $reg" 0 $?
        check "the digest" "$d" "$(shs "$store" image inspect --format '{{.Digest}}' "$reg/produce/mixed:1@$d")"
        check_match "the id has 128 hex digits" '^[0-9a-f]{128}$' "$(shs "$store" image inspect --format '{{.Id}}' "$reg/produce/mixed:1@$d")"
        out=$(shs "$store" run --rm --network none "$reg/produce/mixed:1@$d" cat /file /made 2>&1)
        check_match "it runs from $reg" "hello" "$out"
        shs "$store" system check > /dev/null 2>&1
        check "system check" 0 $?
        # the bare digest: pulled where the registry addresses manifests by
        # sha512 (the mock of zot), told by name where it does not (registry:3,
        # and zot's release, which has the manifest by the sha256 of its bytes)
        out=$(shs "$WORKDIR/bare-${reg##*:}" image pull --tls-verify=false "$reg/produce/mixed@$d" 2>&1)
        rc=$?
        case " $TAKES " in
        *" $reg "*) check "the bare digest on $reg" 0 $rc ;;
        *)
            check "the bare digest on $reg" 125 $rc
            check_match "named" "name the tag as well" "$out"
            ;;
        esac
    done
    # sha256 images push without a word about it
    err=$(sc image push --tls-verify=false "$BASE" "$ZOT/produce/base:1" 2>&1 > /dev/null)
    check "no warning for a sha256 image" 0 "$(printf '%s\n' "$err" | grep -c 'Warning')"
    # nor does a push to a directory
    err=$(sc image push localhost/mixed:1 "dir:$WORKDIR/mixed-dir" 2>&1 > /dev/null)
    check "no warning for a dir: destination" 0 "$(printf '%s\n' "$err" | grep -c 'Warning')"
}

@test "a sha512 image pushed by a tag is put by its digest too: the registry that takes it knows NAME@sha512:D, the one that refuses it is told in one warning" {
    d=$(pushed_digest localhost/mixed:1)
    for reg in $ALLREGS; do
        err=$(sc image push --tls-verify=false localhost/mixed:1 "$reg/produce/bydigest:1" 2>&1 > /dev/null)
        check "push to $reg" 0 $?
        check_match "the name by the tag" "^Pushed: $reg/produce/bydigest:1\$" "$err"
        status=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/produce/bydigest/manifests/$d")
        case " $TAKES " in
        *" $reg "*)
            check "the manifest is known by $d on $reg" 200 "$status"
            check_match "the name by the digest is said" "^Pushed: $reg/produce/bydigest@$d\$" "$err"
            check "no refusal on $reg" 0 "$(printf '%s\n' "$err" | grep -c 'will not resolve')"
            ;;
        *)
            check "the manifest is not known by $d on $reg" 404 "$status"
            check "one warning that the digest does not resolve on $reg" 1 "$(printf '%s\n' "$err" | grep -c '^Warning: the destination refused .*@sha512:[0-9a-f]*: ..*')"
            check "the name by the digest is not said on $reg" 0 "$(printf '%s\n' "$err" | grep -c "^Pushed: $reg/produce/bydigest@")"
            ;;
        esac
        # a push by the digest keeps failing by name where it is refused
        case " $REFUSES " in
        *" $reg "*)
            out=$(sc image push --tls-verify=false localhost/mixed:1 "$reg/produce/bydigest@$d" 2>&1)
            check "the push by the digest on $reg" 125 $?
            check_match "named" "may not take a manifest by its sha512 digest" "$out"
            ;;
        esac
    done
    # --all-tags says it for each tag, --quiet too, --digestfile names the
    # sha512; `artifact push` says it the same way
    sc tag localhost/mixed:1 localhost/alltags:a localhost/alltags:b
    sc manifest create --digest sha512 localhost/mlhost > /dev/null 2>&1
    sc manifest add localhost/mlhost containers-storage:localhost/mixed:1 > /dev/null 2>&1
    check "a list of the image" 0 $?
    for reg in $ALLREGS; do
        # (`manifest push --all=false`: the instance of this host, by the tag)
        merr=$(sc manifest push --quiet --all=false --tls-verify=false localhost/mlhost "$reg/produce/ml:1" 2>&1 > /dev/null)
        check "manifest push --all=false to $reg" 0 $?
        mn=$(printf '%s\n' "$merr" | grep -c "^Warning: the destination refused $reg/produce/ml@$d: ..*\$")
        err=$(sc image push --quiet --all-tags --tls-verify=false localhost/alltags "$reg/produce/alltags" 2>&1 > /dev/null)
        check "push --all-tags to $reg" 0 $?
        n=$(printf '%s\n' "$err" | grep -c "^Warning: the destination refused $reg/produce/alltags@$d: ..*\$")
        sc image push --quiet --digestfile "$WORKDIR/digestfile" --tls-verify=false localhost/mixed:1 "$reg/produce/df:1" > /dev/null 2>&1
        check "--digestfile names the sha512 on $reg" "$d" "$(cat "$WORKDIR/digestfile")"
        # (a type of the file zot's schema takes: not `text/plain; charset=utf-8`)
        sc artifact add --digest sha512 --file-type application/octet-stream "$reg/produce/art512:1" "$WORKDIR/ctx/file" > /dev/null 2>&1
        a=$(sc artifact inspect "$reg/produce/art512:1" | python3 -I -c "import sys, json; print(json.load(sys.stdin)['Digest'])")
        aerr=$(sc artifact push --quiet --tls-verify=false "$reg/produce/art512:1" 2>&1 > /dev/null)
        check "artifact push to $reg" 0 $?
        an=$(printf '%s\n' "$aerr" | grep -c "^Warning: the destination refused $reg/produce/art512@$a: ..*\$")
        case " $REFUSES " in
        *" $reg "*)
            check "a warning for each tag on $reg" 2 "$n"
            check "a warning for the artifact on $reg" 1 "$an"
            check "a warning for the instance of the list on $reg" 1 "$mn"
            ;;
        *)
            check "no refusal of a tag on $reg" 0 "$n"
            check "no refusal of the artifact on $reg" 0 "$an"
            check "no refusal of the instance of the list on $reg" 0 "$mn"
            check "the artifact is known by $a on $reg" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/produce/art512/manifests/$a")"
            ;;
        esac
    done
    # a sha512 list pushed whole by its tag is put by its digest too
    sc manifest push --all --digestfile "$WORKDIR/listdigest" --tls-verify=false localhost/mlhost "$ZOT/produce/mlall:1" > /dev/null 2>&1
    check "manifest push --all" 0 $?
    ld=$(cat "$WORKDIR/listdigest")
    check_match "the list is sha512" '^sha512:' "$ld"
    check "the list is known by its digest" 200 "$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$ZOT/v2/produce/mlall/manifests/$ld")"
    # a sha256 image says nothing more, and a quiet push says nothing
    err=$(sc image push --tls-verify=false "$BASE" "$ZOT/produce/base:2" 2>&1 > /dev/null)
    check "no digest line for a sha256 image" 0 "$(printf '%s\n' "$err" | grep -c '^Pushed: .*@')"
}

@test "a build without --digest on a sha512 base is sha256 on top of the base's sha512 layers, and its push warns" {
    printf 'FROM localhost/imp512:1\nCOPY file /again\n' > "$WORKDIR/ctx/On512file"
    sc build -f "$WORKDIR/ctx/On512file" -t localhost/on512:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build" 0 $?
    check_match "the default is sha256" '^sha256:[0-9a-f]{64}$' "$(sc image inspect --format '{{.Digest}}' localhost/on512:1)"
    layers=$(slayers localhost/on512:1)
    check_match "the base layer stays sha512" '^sha512:[0-9a-f]{128}$' "$(printf '%s\n' "$layers" | sed -n 1p)"
    check_match "the new one is sha256" '^sha256:[0-9a-f]{64}$' "$(printf '%s\n' "$layers" | sed -n 2p)"
    out=$(sc run --rm --network none localhost/on512:1 cat /again 2>&1)
    check_match "it runs" "hello" "$out"
    # (its blobs of the base are sha512: a registry may refuse them)
    err=$(sc image push --tls-verify=false localhost/on512:1 "$ZOT/produce/on512:1" 2>&1 > /dev/null)
    check "push" 0 $?
    check "one warning" 1 "$(printf '%s\n' "$err" | grep -c '^Warning: .*sha512')"
}

@test "a sha512 image is saved as an OCI archive and loaded, and the docker-archive is refused by name" {
    sc image save --format oci-archive -o "$WORKDIR/mixed.tar" localhost/mixed:1 > /dev/null 2>&1
    check "save" 0 $?
    shs "$WORKDIR/loaded" image load -i "$WORKDIR/mixed.tar" > /dev/null 2>&1
    check "load" 0 $?
    id=$(shs "$WORKDIR/loaded" image ls -q | head -1)
    out=$(shs "$WORKDIR/loaded" run --rm --network none "$id" cat /file 2>&1)
    check_match "the loaded image runs" "hello" "$out"
    out=$(sc image save --format docker-archive -o "$WORKDIR/mixed-docker.tar" localhost/mixed:1 2>&1)
    check "docker-archive" 125 $?
    check_match "refused by name" "docker-archive" "$out"
    [ ! -s "$WORKDIR/mixed-docker.tar" ]
    check "nothing written" 0 $?
}

@test "an enforced run of a sha512 image built on a store with fs-verity verifies every link and names its algorithm" {
    need_verity
    store=$VS/built
    shs "$store" image pull --tls-verify=false "$BASE" > /dev/null 2>&1 || exit 1
    shs "$store" build --digest sha512 -t localhost/vmixed:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build on a store with fs-verity" 0 $?
    # (an image of sha512 layers only: an import, and a build on it)
    shs "$store" image import --digest sha512 "$WORKDIR/rootfs.tar" localhost/vbase:1 > /dev/null 2>&1
    check "import" 0 $?
    printf 'FROM localhost/vbase:1\nCOPY file /file\n' > "$WORKDIR/ctx/Ownfile"
    shs "$store" build --digest sha512 -f "$WORKDIR/ctx/Ownfile" -t localhost/vown:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build on it" 0 $?
    check_match "the objects of 126 digits" '.' "$(find "$store/objects" -type f -name "$(printf '%126s' '' | tr ' ' '?')" | head -1)"
    for img in localhost/vmixed:1 localhost/vown:1; do
        out=$(shs "$store" --log-level=debug run --rm --network none --security-opt verity=enforce "$img" cat /file 2>&1)
        rc=$?
        [ "$rc" = 0 ] || printf '%s\n' "$out" | tail -15 >&2
        check "enforced run of $img" 0 $rc
        d=$(shs "$store" image inspect --format '{{.Digest}}' "$img")
        chain=$(printf '%s\n' "$out" | sed -n 's/^.*verity chain: //p')
        check_match "the root is the sha512 of $img" "^root [A-Za-z]+ ${d}" "$chain"
        check_match "its layer is linked by sha512 digests" "$d manifest -> sha512:[0-9a-f]{128} layer [0-9] blob -> sha512:" "$chain"
        printf '%s\n' "$chain" | sed 's/^/verity chain: /' | python3 -I "$E2E_DIR/verity_chain.py" --expect complete > /dev/null
        check "the chain of $img is well formed" 0 $?
    done
    out=$(shs "$store" --log-level=debug run --rm --network none --security-opt verity=enforce localhost/vmixed:1 true 2>&1)
    check_match "the base layer is checked with its sha256" "manifest -> sha256:[0-9a-f]{64} layer 1 blob" "$(printf '%s\n' "$out" | sed -n 's/^.*verity chain: //p')"
    check_match "and the new ones with their sha512" "manifest -> sha512:[0-9a-f]{128} layer 2 blob" "$(printf '%s\n' "$out" | sed -n 's/^.*verity chain: //p')"
    shs "$store" image push --tls-verify=false localhost/vmixed:1 "$ZOT/produce/vmixed:1" > /dev/null 2>&1
    check "push" 0 $?
    shs "$store" system check > /dev/null 2>&1
    check "system check" 0 $?
}

# A file system that takes fs-verity but not the hash of SHA-512 (an
# LD_PRELOAD of the test makes the ioctl say so: this kernel has the hash): a
# build asking for sha512 fails by name before it makes anything, a build of
# sha256 goes on.
@test "--digest sha512 on a store whose fs-verity lacks SHA-512 fails by name and makes nothing" {
    need_verity
    command -v cc > /dev/null || skip "no C compiler"
    cat > "$WORKDIR/nosha512.c" <<'C'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <linux/fsverity.h>
int ioctl(int fd, unsigned long request, ...)
{
    static int (*real)(int, unsigned long, ...);
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (!real)
        real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    if (request == FS_IOC_ENABLE_VERITY && arg != NULL
        && ((struct fsverity_enable_arg *) arg)->hash_algorithm == FS_VERITY_HASH_ALG_SHA512) {
        errno = ENOPKG;
        return -1;
    }
    return real(fd, request, arg);
}
C
    cc -shared -fPIC -o "$WORKDIR/nosha512.so" "$WORKDIR/nosha512.c" -ldl || skip "cannot build the preload library"
    store=$VS/nosha512
    LD_PRELOAD=$WORKDIR/nosha512.so shs "$store" build -f "$WORKDIR/ctx/Scratchfile" -t localhost/p256:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "a sha256 build goes on" 0 $?
    out=$(LD_PRELOAD=$WORKDIR/nosha512.so shs "$store" build --digest sha512 -f "$WORKDIR/ctx/Scratchfile" -t localhost/p512:1 "$WORKDIR/ctx" 2>&1)
    check "the sha512 build is refused" 125 $?
    check_match "naming the algorithm and the store" "cannot take sha512 images" "$out"
    check_match "and the hash" "fs-verity with SHA-512 is not available here" "$out"
    shs "$store" image exists localhost/p512:1 2> /dev/null
    check "no image of it" 1 $?
    out=$(LD_PRELOAD=$WORKDIR/nosha512.so shs "$store" image import --digest sha512 "$WORKDIR/rootfs.tar" localhost/i512:1 2>&1)
    check "the import is refused" 125 $?
    check_match "by name" "cannot take sha512 images" "$out"
    c=$(shs "$store" create --network none localhost/p256:1 true) || exit 1
    out=$(LD_PRELOAD=$WORKDIR/nosha512.so shs "$store" commit --digest sha512 "$c" localhost/c512:1 2>&1)
    check "the commit is refused" 125 $?
    check_match "by name" "cannot take sha512 images" "$out"
    shs "$store" rm -f "$c" > /dev/null 2>&1
    check "no object of 126 digits was made" "" "$(find "$store/objects" -type f -name "$(printf '%126s' '' | tr ' ' '?')" | head -1)"
}
