# SPDX-License-Identifier: Apache-2.0
# An image named by a digest (`NAME@sha256:D`) is the root of a chain of trust
# at every start that enforces the digests (`--security-opt verity=enforce`,
# `[storage] composefs_digests = "require"`): the manifest (or the index it
# was chosen from) hashes to D, the configuration to the digest in the
# manifest, the layers' EROFS digests come from that manifest, and what the
# container took from the configuration of the image is held against it.  The
# repository is the file's own (velarx-e2e/verity-digest-PID) in the local
# registry; the images made of bytes are made by registry_images.py.
#
# The tests that enforce the digests need a store on a file system with
# fs-verity, as verity-start.bats (root: a loop device of the work directory,
# in a mount namespace of its own: `unshare -m --propagation private bats ...`;
# rootless: VELARX_VERITY_DIR); the others skip.
#
#   VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/verity-digest.bats

load helpers
load verity

run_in () { # store, image, arguments of run (before the image)...
    local store=$1 image=$2
    shift 2
    shs "$store" run --rm --network none "$@" "$image" cat /etc/alpine-release 2>&1
}

go () { # store, digest, container: start it, giving the digest on the command
    shs "$1" start -a --verify-image "$2" "$3" 2>&1 < /dev/null
}

reg () { python3 -I "$E2E_DIR/registry_images.py" "$@"; }

sql () { # store, statements
    python3 -I -c '
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.executescript(sys.argv[2])
c.commit()' "$1/db.sqlite" "$2"
}

one () { # store, query: the first column of the first row
    python3 -I -c '
import sqlite3, sys
print(sqlite3.connect(sys.argv[1]).execute(sys.argv[2]).fetchone()[0])' "$1/db.sqlite" "$2"
}

edit_config () { # store, container id, python statements on the record c (a dict)
    python3 -I -c '
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
(text,) = db.execute("SELECT config FROM containers WHERE id = ?", (sys.argv[2],)).fetchone()
c = json.loads(text)
exec(sys.argv[3])
db.execute("UPDATE containers SET config = ? WHERE id = ?", (json.dumps(c), sys.argv[2]))
db.commit()' "$1/db.sqlite" "$2" "$3"
}

# what an image without the annotation is refused with (the option follows)
unstated="layer 1 of [0-9]+ \(sha256:[0-9a-f]{64}\) states no EROFS digest \(io.containers.composefs.digest\)"

setup_file () {
    export REG=$E2E_REGISTRY
    command -v curl > /dev/null || skip "no curl"
    command -v python3 > /dev/null || skip "no python3"
    command -v crun > /dev/null || skip "no crun"
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    export IMG=$REG/alpine:chunked
    export NAME=velarx-e2e/verity-digest-$$
    export REPO=$REG/$NAME
    cat > "$WORKDIR/registries.conf" <<EOT
[[registry]]
location = "$REG"
insecure = true
EOT
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    # an image velarx made: its layers state the digests of their EROFS images
    shs "$WORKDIR/seal" image pull --tls-verify=false "$IMG" > /dev/null || e2e_die "pull"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format gzip "$IMG" "$REPO:gz" > /dev/null || e2e_die "push"
    shs "$WORKDIR/seal" image pull --tls-verify=false "$REPO:gz" > /dev/null || e2e_die "pull again"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format zstd:chunked "$REPO:gz" "$REPO:zstd" > /dev/null || e2e_die "push zstd"
    # its manifest digest, another manifest over the same layers (another
    # configuration), and an index of the first
    export D; D=$(reg digest "$REG" "$NAME" zstd) || e2e_die "digest"
    export B; B=$(reg variant "$REG" "$NAME" zstd variant) || e2e_die "variant"
    export X; X=$(reg index "$REG" "$NAME" zstd index) || e2e_die "index"
    # an index that lists the variant first, then the image, for one platform
    export X2; X2=$(reg index "$REG" "$NAME" variant index2 zstd) || e2e_die "index2"
    # an image of another writer, copied as it is: no layer states a digest;
    # an index of it, and an index that lists it before the image above
    export U; U=$(reg copy "$REG" alpine chunked "$NAME" plain) || e2e_die "copy"
    export UX; UX=$(reg index "$REG" "$NAME" plain plainindex) || e2e_die "plain index"
    export UM; UM=$(reg index "$REG" "$NAME" plain mixedindex zstd) || e2e_die "mixed index"
    # an image of two layers that state theirs (both written by velarx, with
    # the fs-verity digest of every file: it can be pulled lazily), and the
    # same with the annotation of a layer taken off, or not a list of digests
    shs "$WORKDIR/seal" run --name two --network none "$REPO:gz" sh -c 'echo second > /second' > /dev/null 2>&1 || e2e_die "run"
    shs "$WORKDIR/seal" commit two localhost/verity-digest-two:1 > /dev/null 2>&1 || e2e_die "commit"
    shs "$WORKDIR/seal" image push --tls-verify=false --compression-format zstd:chunked localhost/verity-digest-two:1 "$REPO:two" > /dev/null 2>&1 || e2e_die "push two"
    export T2; T2=$(reg digest "$REG" "$NAME" two) || e2e_die "digest two"
    export P1; P1=$(reg annotate "$REG" "$NAME" two first-bare 1) || e2e_die "annotate"
    export P2; P2=$(reg annotate "$REG" "$NAME" two second-bare 2) || e2e_die "annotate"
    # a store on a file system with fs-verity, where there is one
    e2e_verity_store
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    set +e
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    [ -z "${VS:-}" ] || [ "$(id -u)" = 0 ] || rm -rf "$VS"
    e2e_teardown_file
}

# a store with the image pulled by its digest, and the variant (another
# manifest, the same layers) pulled by a tag
pulled () { # store
    shs "$1" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$1" image pull --tls-verify=false "$REPO:variant" > /dev/null || exit 1
}

# make the name (and a container) resolve to the variant, as a writer of the
# store would
swap_to_variant () { # store, container id...
    local store=$1 bid c
    shift
    bid=$(one "$store" "SELECT id FROM images WHERE manifest_digest = '$B'")
    sql "$store" "UPDATE image_digest_names SET image_id = '$bid' WHERE digest = '$D';
                  UPDATE image_tags SET image_id = '$bid' WHERE tag = 'zstd';"
    for c in "$@"; do
        sql "$store" "UPDATE containers SET image_id = '$bid' WHERE id = '$c';"
    done
}

@test "a digest that is not in the store is not the latest of the name" {
    store=$WORKDIR/notag
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    shs "$store" tag "$REPO:zstd" "$REPO:latest" || exit 1
    out=$(shs "$store" run --rm --pull=never --network none "$REPO@sha256:$(printf '%064d' 7)" true 2>&1)
    check "refused" 125 $?
    check_match "the image is not known" "$REPO@sha256:0+7: image not known" "$out"
}

@test "an enforced run by digest runs, and every start verifies the chain" {
    need_verity
    store=$VS/chain
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    out=$(run_in "$store" "$REPO@$D" --security-opt verity=enforce)
    check_match "run" '^[0-9]+\.[0-9]+' "$out"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    for n in 1 2; do
        out=$(go "$store" "$D" "$id")
        check_match "start $n" '^[0-9]+\.[0-9]+' "$out"
    done
    # the volume of an image by its digest: the same chain
    out=$(shs "$store" run --rm --network none --security-opt verity=enforce \
        --mount "type=image,source=$REPO@$D,destination=/img" "$REPO@$D" cat /img/etc/alpine-release 2>&1)
    check_match "an image mount" '^[0-9]+\.[0-9]+' "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "a manifest replaced by another one of the same name is refused at the next start" {
    need_verity
    store=$VS/swapped
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    check_match "it starts" '^[0-9]+\.[0-9]+' "$(go "$store" "$D" "$id")"
    # (the variant is a whole image, consistent with its own id and layers:
    # the check against its id passes, the one against the digest typed fails)
    swap_to_variant "$store" "$id"
    out=$(go "$store" "$D" "$id")
    check_match "refused, both digests named" "$REPO@$D: image [0-9a-f]{12}: the stored manifest hashes to $B, not $D[, ].*--security-opt verity=enforce" "$out"
    # the record of the container edited to the digest of the variant too: the
    # digest typed on the command decides, the record is not believed
    edit_config "$store" "$id" "c['pinned']['digest'] = '$B'"
    out=$(go "$store" "$D" "$id")
    check_match "the typed digest wins over the record" "the stored manifest hashes to $B, not $D[, ].*the container was made from $B, which the command does not give" "$out"
    # and a command that gives none is refused for a container made from a digest
    out=$(shs "$store" start -a "$id" 2>&1 < /dev/null)
    check_match "no digest, no start" "the container was made from the digest $B, and the command gives none .*pass --verify-image $B" "$out"
    # a new container of the name resolves to the variant: refused when created
    out=$(run_in "$store" "$REPO@$D" --security-opt verity=enforce)
    check_match "refused at create" "the stored manifest hashes to $B, not $D" "$out"
    # the same swap of a container that is not enforced runs, as before
    id2=$(shs "$store" create --network none "$REPO@$D" cat /etc/alpine-release) || exit 1
    check_match "not enforced" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a "$id2" 2>&1 < /dev/null)"
    shs "$store" rm -t 0 -f "$id" "$id2" > /dev/null 2>&1
}

@test "the node's require holds an image named by digest too" {
    need_verity
    store=$VS/require
    sed '1i storage.composefs_digests = "require"' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require.toml"
    node () { "$BIN/velarx" --config "$WORKDIR/require.toml" --root "$store" "$@"; }
    node image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    node image pull --tls-verify=false "$REPO:variant" > /dev/null || exit 1
    id=$(node create --network none "$REPO@$D" cat /etc/alpine-release) || exit 1
    check_match "it starts" '^[0-9]+\.[0-9]+' "$(node start -a --verify-image "$D" "$id" 2>&1 < /dev/null)"
    swap_to_variant "$store" "$id"
    out=$(node start -a --verify-image "$D" "$id" 2>&1 < /dev/null)
    check_match "refused" "the stored manifest hashes to $B, not $D[, ].*composefs_digests is \"require\"" "$out"
    node rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "an image mount by digest is held to its digest" {
    need_verity
    store=$VS/mount
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce \
        --mount "type=image,source=$REPO@$D,destination=/img" "$REPO@$D" cat /img/etc/alpine-release) || exit 1
    check_match "it starts" '^[0-9]+\.[0-9]+' "$(go "$store" "$D" "$id")"
    bid=$(one "$store" "SELECT id FROM images WHERE manifest_digest = '$B'")
    edit_config "$store" "$id" "
for m in c['mounts']:
    if m.get('image'):
        m['image']['image'] = '$bid'"
    out=$(go "$store" "$D" "$id")
    check_match "refused, the mount named" "--mount type=image,source=@$D: image [0-9a-f]{12}: the stored manifest hashes to $B, not $D" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "the settings the image decided are taken from its configuration, hashed" {
    need_verity
    store=$VS/settings
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    mk () { shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" "$@"; }
    # (no command: the image's, /bin/sh, which ends with its empty input)
    id=$(mk) || exit 1
    go "$store" "$D" "$id" > /dev/null
    check "it starts" 0 $?
    # the command of the container edited in its row
    edit_config "$store" "$id" "c['command'] = ['cat', '/etc/passwd']"
    out=$(go "$store" "$D" "$id")
    check_match "the command" 'command: the configuration of the image .*gives \["/bin/sh"\], the container has \["cat", "/etc/passwd"\]' "$out"
    # (the same edit of a container that is not enforced is not looked at)
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # an environment entry of the image removed
    id=$(mk) || exit 1
    edit_config "$store" "$id" "c['env'] = [e for e in c['env'] if not e.startswith('PATH=')]"
    out=$(go "$store" "$D" "$id")
    check_match "the environment" 'env: .*the container has no such entry' "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the record of what was taken, edited together with the command: the
    # configuration of the image is the judge
    id=$(mk) || exit 1
    edit_config "$store" "$id" "
c['command'] = ['sh', '-c', 'echo evil']
c['pinned']['taken']['cmd'] = ['sh', '-c', 'echo evil']"
    out=$(go "$store" "$D" "$id")
    check_match "the record" 'command: the configuration of the image .*gives \["/bin/sh"\]' "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the spec the runtime reads
    id=$(mk) || exit 1
    python3 -I -c '
import json, sys
p = sys.argv[1]
s = json.load(open(p))
s["process"]["args"] = ["sh", "-c", "echo evil"]
json.dump(s, open(p, "w"))' "$store/bundles/$id/config.json" || exit 1
    out=$(go "$store" "$D" "$id")
    check_match "the spec" "the arguments of the bundle's spec is " "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # a request that gives its own command is not held to the image's
    id=$(mk cat /etc/alpine-release) || exit 1
    check_match "an own command" '^[0-9]+\.[0-9]+' "$(go "$store" "$D" "$id")"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the configuration stored for the image, edited
    id=$(mk) || exit 1
    sql "$store" "UPDATE images SET config = config || ' ';"
    out=$(go "$store" "$D" "$id")
    check_match "the configuration" "the stored configuration hashes to sha256:[0-9a-f]{64} \([0-9]+ bytes\), the manifest says" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "the digest of an index is a root" {
    need_verity
    store=$VS/index
    shs "$store" image pull --tls-verify=false "$REPO@$X" > /dev/null || exit 1
    out=$(run_in "$store" "$REPO@$X" --security-opt verity=enforce)
    check_match "run by the index" '^[0-9]+\.[0-9]+' "$out"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$X" cat /etc/alpine-release) || exit 1
    check_match "start" '^[0-9]+\.[0-9]+' "$(go "$store" "$X" "$id")"
    # the index edited in the store
    kept=$(one "$store" "SELECT value FROM store_settings WHERE key = 'index:$X'")
    sql "$store" "UPDATE store_settings SET value = value || ' ' WHERE key = 'index:$X';"
    out=$(go "$store" "$X" "$id")
    check_match "the index is not the one the digest names" "the stored index $X hashes to sha256:[0-9a-f]{64}" "$out"
    # no index at all
    sql "$store" "DELETE FROM store_settings WHERE key = 'index:$X';"
    out=$(go "$store" "$X" "$id")
    check_match "no index" "not $X, the digest of the reference \(and the store has no index $X\)" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    [ -n "$kept" ] || exit 1
}

@test "a tag is as before: it resolves in the store" {
    need_verity
    store=$VS/tag
    pulled "$store"
    out=$(run_in "$store" "$REPO:zstd" --security-opt verity=enforce)
    check_match "run by the tag" '^[0-9]+\.[0-9]+' "$out"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO:zstd" cat /etc/alpine-release) || exit 1
    swap_to_variant "$store" "$id"
    out=$(shs "$store" start -a "$id" 2>&1 < /dev/null)
    check_match "the other image of the name runs" '^[0-9]+\.[0-9]+' "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "the REST API verifies a digest in the create the same way" {
    need_verity
    store=$VS/rest
    api () { curl -s --unix-socket "$SOCK" "$@"; }
    sed -i "s|^storage.root = .*|storage.root = \"$store\"|; s|^root_dir = .*|root_dir = \"$store\"|" "$XDG_CONFIG_HOME/velarx/config.toml"
    e2e_start_daemon
    e2e_start_api
    sc image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    sc image pull --tls-verify=false "$REPO:variant" > /dev/null || exit 1
    body=$(printf '{"image":"%s@%s","command":["cat","/etc/alpine-release"],"netns":{"nsmode":"none"},"verity_enforce":true}' "$REPO" "$D")
    id=$(api -X POST -H 'Content-Type: application/json' -d "$body" "http://d/v5.0.0/libpod/containers/create" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["Id"])')
    [ -n "$id" ] || exit 1
    out=$(api -X POST "http://d/v5.0.0/libpod/containers/$id/start?verify_image=$D" -w '%{http_code}')
    check "started" 204 "$out"
    # the unit of generate systemd gives the digest on its command line
    out=$(api "http://d/v5.0.0/libpod/generate/$id/systemd")
    check_match "the unit" "--verify-image $D $id" "$out"
    api -X POST "http://d/v5.0.0/libpod/containers/$id/wait" > /dev/null
    swap_to_variant "$store" "$id"
    out=$(api -X POST "http://d/v5.0.0/libpod/containers/$id/start?verify_image=$D")
    check_match "refused" "the stored manifest hashes to $B, not $D" "$out"
    # an image without the annotation: refused by the create (the daemon of
    # the file is this one)
    sc image pull --tls-verify=false "$REPO@$U" > /dev/null || exit 1
    sc image pull --tls-verify=false "$REPO:plain" > /dev/null || exit 1
    # the libpod create
    body=$(printf '{"image":"%s@%s","command":["cat","/etc/alpine-release"],"netns":{"nsmode":"none"},"verity_enforce":true}' "$REPO" "$U")
    out=$(api -X POST -H 'Content-Type: application/json' -d "$body" "http://d/v5.0.0/libpod/containers/create" -w '%{http_code}')
    check_match "libpod: refused, the layer and the option" "$unstated, and --security-opt verity=enforce" "$out"
    # the Docker create, by its tag
    body=$(printf '{"Image":"%s:plain","Cmd":["cat","/etc/alpine-release"],"NetworkDisabled":true,"HostConfig":{"SecurityOpt":["verity=enforce"]}}' "$REPO")
    out=$(api -X POST -H 'Content-Type: application/json' -d "$body" "http://d/v1.41/containers/create" -w '%{http_code}')
    check_match "docker: refused, the layer and the option" "$unstated, and --security-opt verity=enforce" "$out"
    # A Docker client cannot give the digest a start of a container made from
    # a digest is held to (it has no --verify-image): such a container is
    # refused by the create, whatever its image states.
    for digest in "$U" "$D"; do
        body=$(printf '{"Image":"%s@%s","Cmd":["cat","/etc/alpine-release"],"NetworkDisabled":true,"HostConfig":{"SecurityOpt":["verity=enforce"]}}' "$REPO" "$digest")
        out=$(api -X POST -H 'Content-Type: application/json' -d "$body" "http://d/v1.41/containers/create" -w '%{http_code}')
        check_match "docker: $digest refused by name" "$REPO@$digest: --security-opt verity=enforce: .*which a Docker client cannot give.*\"response\":400" "$out"
    done
    # (an annotated image by its tag is created and started by a Docker client)
    sc image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    body=$(printf '{"Image":"%s:zstd","Cmd":["cat","/etc/alpine-release"],"NetworkDisabled":true,"HostConfig":{"SecurityOpt":["verity=enforce"]}}' "$REPO")
    did=$(api -X POST -H 'Content-Type: application/json' -d "$body" "http://d/v1.41/containers/create" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["Id"])')
    [ -n "$did" ] || exit 1
    check "docker: the tag starts" 204 "$(api -X POST "http://d/v1.41/containers/$did/start" -o /dev/null -w '%{http_code}')"
}

@test "a writer of the row who erases the digest: a start that gives it is refused" {
    need_verity
    store=$VS/erased
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    edit_config "$store" "$id" "del c['pinned']"
    swap_to_variant "$store" "$id"
    out=$(go "$store" "$D" "$id")
    check_match "the digest typed holds no image" "container .*: --verify-image $D: no image of the container is held to it \(it was made from no digest\)" "$out"
    # (a start that gives none: what this record says is a tag, nothing is
    # verified against the digest: the limit of the record)
    check_match "the limit of the record" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a "$id" 2>&1 < /dev/null)"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "--verify-image is refused when it cannot be honoured" {
    need_verity
    store=$VS/option
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    upper=sha256:$(printf '%s' "${D#sha256:}" | tr a-f A-F)
    out=$(go "$store" "$upper" "$id")
    check_match "upper case" ": --verify-image $upper: not a digest \(sha256:<64 lowercase hex digits> or sha512:<128 lowercase hex digits>\)" "$out"
    out=$(go "$store" "${D%?}" "$id")
    check_match "too short" ": --verify-image ${D%?}: not a digest" "$out"
    out=$(go "$store" "sha512:$(printf '%0128d' 1)" "$id")
    check_match "sha512 of an image named by a sha256" "the image is named by $D, not by a sha512 digest: pass that digest" "$out"
    out=$(go "$store" "sha512:$(printf '%0127d' 1)" "$id")
    check_match "a sha512 of 127 digits" ": --verify-image sha512:0+1: not a digest \(sha256:<64 lowercase hex digits> or sha512:<128 lowercase hex digits>\)" "$out"
    # (a second digest, of no image of the container)
    out=$(go "$store" "$D" "$id" 2>&1)
    check_match "the one digest" '^[0-9]+\.[0-9]+' "$out"
    out=$(shs "$store" start -a --verify-image "$D" --verify-image "$B" "$id" 2>&1 < /dev/null)
    check_match "two digests for one image" "container .*: --verify-image $B: no image of the container is held to it \(it was made from $D\)" "$out"
    # restart takes it the same way
    shs "$store" restart --verify-image "$D" "$id" > /dev/null || exit 1
    out=$(shs "$store" restart --verify-image "$B" "$id" 2>&1)
    check_match "restart, another digest" "the stored manifest hashes to $D, not $B.*the container was made from $D, which the command does not give" "$out"
    # a container that does not enforce the digests: refused by name
    id2=$(shs "$store" create --network none "$REPO@$D" cat /etc/alpine-release) || exit 1
    out=$(go "$store" "$D" "$id2")
    check_match "not enforced" "container .*: --verify-image: the digests of its images are not enforced" "$out"
    mkdir -p "$WORKDIR/rootfs"
    id3=$(shs "$store" create --network none --rootfs "$WORKDIR/rootfs" true) || exit 1
    out=$(go "$store" "$D" "$id3")
    check_match "--rootfs" "container .*: --verify-image: the digests of its images are not enforced" "$out"
    # a digest in a reference: as typed, refused the same
    out=$(run_in "$store" "$REPO@$upper" --security-opt verity=enforce --pull=never)
    check "upper case reference" 125 $?
    out=$(run_in "$store" "$REPO@sha512:$(printf '%0128d' 1)" --security-opt verity=enforce --pull=never)
    check "sha512 reference" 125 $?
    # the service manager at boot goes by the record
    check_match "start --service" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a --service "$id" 2>&1 < /dev/null)"
    out=$(shs "$store" start --service --verify-image "$D" "$id" 2>&1)
    check_match "--service with a digest" "cannot be used with" "$out"
    shs "$store" rm -t 0 -f "$id" "$id2" "$id3" > /dev/null 2>&1
}

@test "--verify-image is refused for a start that checks nothing: initialized, or running" {
    need_verity
    store=$VS/unchecked
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    # `container init` mounts the file systems by the digest of the record:
    # the start that follows mounts nothing, a digest typed on it would be
    # compared with nothing
    shs "$store" container init "$id" > /dev/null || exit 1
    out=$(go "$store" "$B" "$id")
    check_match "another digest, after init" "container .*: --verify-image $B: it was initialized .*nothing would be checked now; stop it, then start it with --verify-image" "$out"
    out=$(go "$store" "sha512:$(printf '%0128d' 1)" "$id")
    check_match "a sha512 digest, after init" "not a digest|nothing would be checked now" "$out"
    shs "$store" stop "$id" > /dev/null || exit 1
    check_match "stopped, it starts with its digest" '^[0-9]+\.[0-9]+' "$(go "$store" "$D" "$id")"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # a container that runs: a start is nothing to it (podman's), with a
    # digest it is refused
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" sleep 60) || exit 1
    shs "$store" start --verify-image "$D" "$id" > /dev/null || exit 1
    shs "$store" start "$id" > /dev/null
    check "a start of a running container, no digest" 0 $?
    out=$(shs "$store" start --verify-image "$D" "$id" 2>&1)
    check_match "with a digest" "container .*: --verify-image $D: it runs, on the file systems its monitor mounted when it started: nothing would be checked now" "$out"
    shs "$store" restart --verify-image "$D" "$id" > /dev/null
    check "restart checks it again" 0 $?
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "a bundle that names other layers than the manifest of the image changes nothing: the driver measures the manifest's" {
    need_verity
    store=$VS/relabel
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    # (the plan of the root is a mount of the storage driver, which measures
    # the images of the layers of the manifest itself: the plan names no
    # layer, and a layer written in it is not read)
    check "the plan names no layer" mount-fd \
        "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["kind"])' "$store/bundles/$id/rootfs.json")"
    python3 -I -c '
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["layers"] = [{"layer": "sha256:" + "0" * 63 + "5", "image": "/etc/passwd"}]
json.dump(m, open(p, "w"))' "$store/bundles/$id/rootfs.json" || exit 1
    out=$(go "$store" "$D" "$id")
    check_match "the start measures the layers of the manifest" '^[0-9]+\.[0-9]+' "$out"
    check "and the plan is the driver's again" mount-fd \
        "$(python3 -I -c 'import json,sys; d = json.load(open(sys.argv[1])); print(d["kind"] if "layers" not in d else "layers")' "$store/bundles/$id/rootfs.json")"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "the stored bytes swapped for others of the same size, or an index edited, are refused" {
    need_verity
    store=$VS/bytes
    shs "$store" image pull --tls-verify=false "$REPO@$X2" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    # (the index lists the variant first: the pull took it)
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$X2" cat /etc/alpine-release) || exit 1
    check_match "start" '^[0-9]+\.[0-9]+' "$(go "$store" "$X2" "$id")"
    # the image of the container swapped for the one the index lists second,
    # for the same platform: not what a pull of that platform takes
    did=$(one "$store" "SELECT id FROM images WHERE manifest_digest = '$D'")
    bid=$(one "$store" "SELECT image_id FROM containers WHERE id = '$id'")
    sql "$store" "UPDATE containers SET image_id = '$did' WHERE id = '$id';"
    out=$(go "$store" "$X2" "$id")
    check_match "the second entry of a platform" "the index $X2 lists $B first for the platform of the stored manifest $D" "$out"
    sql "$store" "UPDATE containers SET image_id = '$bid' WHERE id = '$id';"
    # the entry of the index edited to name the other manifest
    sql "$store" "UPDATE store_settings SET value = replace(value, '$B', '$D') WHERE key = 'index:$X2';"
    out=$(go "$store" "$X2" "$id")
    check_match "an index entry edited" "the stored index $X2 hashes to sha256:[0-9a-f]{64}" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the configuration replaced by other bytes of the same size
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    sql "$store" "UPDATE images SET config = replace(config, '\"os\":\"linux\"', '\"os\":\"linuz\"') WHERE manifest_digest = '$D';"
    [ "$(one "$store" "SELECT instr(config, 'linuz') > 0 FROM images WHERE manifest_digest = '$D'")" = 1 ] || exit 1
    out=$(go "$store" "$D" "$id")
    check_match "same size, other bytes" "the stored configuration hashes to sha256:[0-9a-f]{64} \(([0-9]+) bytes\), the manifest says sha256:[0-9a-f]{64} \(\1 bytes\)" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

# An image whose layers state no digest of their EROFS image cannot be held to
# any: whenever a digest is asked for (--security-opt verity=enforce, a start
# with --verify-image, [storage] composefs_digests = "require") it is refused,
# naming the layer and the option, and never checked less: by the create, and
# again by every start (the record of the container or the node's setting may
# have changed since).  The same image named by a digest, and run without any
# of them, is a plain pinned pull.

# a container made without the option, that a writer of its row has made
# enforce: what every start checks again
enforce_later () { # store, container id
    edit_config "$1" "$2" "c['security_opt']['verity_enforce'] = True"
}

@test "an image without the annotation, named by its digest, is refused when verity is enforced" {
    need_verity
    store=$VS/plain
    shs "$store" image pull --tls-verify=false "$REPO@$U" > /dev/null || exit 1
    check_match "run without any option: a pinned pull" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$REPO@$U")"
    out=$(run_in "$store" "$REPO@$U" --security-opt verity=enforce)
    check_match "run: the layer and the option named" "$unstated, and --security-opt verity=enforce" "$out"
    out=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$U" cat /etc/alpine-release 2>&1)
    check "create: refused" 125 $?
    check_match "create: the layer and the option named" "$unstated, and --security-opt verity=enforce" "$out"
    check "nothing created" 0 "$(shs "$store" ps -aq | grep -c .)"
    # (enforced after the create: refused by the start, by the command that
    # gives the digest or by none)
    id=$(shs "$store" create --network none "$REPO@$U" cat /etc/alpine-release) || exit 1
    enforce_later "$store" "$id"
    out=$(go "$store" "$U" "$id")
    check_match "start --verify-image" "$unstated, and --security-opt verity=enforce" "$out"
    out=$(shs "$store" start -a "$id" 2>&1 < /dev/null)
    check_match "start without the digest" "the container was made from the digest $U, and the command gives none" "$out"
    out=$(shs "$store" restart --verify-image "$U" "$id" 2>&1)
    check_match "restart --verify-image" "$unstated, and --security-opt verity=enforce" "$out"
    # the same container without the option starts, as a plain pinned pull
    id2=$(shs "$store" create --network none "$REPO@$U" cat /etc/alpine-release) || exit 1
    check_match "not enforced" '^[0-9]+\.[0-9]+' "$(shs "$store" start -a "$id2" 2>&1 < /dev/null)"
    shs "$store" rm -t 0 -f "$id" "$id2" > /dev/null 2>&1
}

@test "an image mount without the annotation is refused, in either place" {
    need_verity
    store=$VS/mountplain
    pulled "$store"
    shs "$store" image pull --tls-verify=false "$REPO@$U" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO:plain" > /dev/null || exit 1
    # the mounted image lacks it: by its digest, by its tag
    for source in "$REPO@$U" "$REPO:plain"; do
        out=$(shs "$store" create --network none --security-opt verity=enforce \
            --mount "type=image,source=$source,destination=/img" "$REPO@$D" cat /etc/alpine-release 2>&1)
        check_match "create: the mount $source, the layer and the option named" "--mount type=image,source=(@$U|[0-9a-f]{12}): .*$unstated, and --security-opt verity=enforce" "$out"
    done
    # the image of the container lacks it
    out=$(shs "$store" create --network none --security-opt verity=enforce \
        --mount "type=image,source=$REPO@$D,destination=/img" "$REPO@$U" cat /etc/alpine-release 2>&1)
    check_match "create: the image of the container" "$unstated, and --security-opt verity=enforce" "$out"
    check "nothing created" 0 "$(shs "$store" ps -aq | grep -c .)"
    # enforced after the create: refused by the start
    id=$(shs "$store" create --network none \
        --mount "type=image,source=$REPO@$U,destination=/img" "$REPO@$D" cat /etc/alpine-release) || exit 1
    enforce_later "$store" "$id"
    out=$(shs "$store" start -a --verify-image "$D" --verify-image "$U" "$id" 2>&1 < /dev/null)
    check_match "start: the mount, the layer and the option named" "--mount type=image,source=@$U: .*$unstated, and --security-opt verity=enforce" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    id=$(shs "$store" create --network none \
        --mount "type=image,source=$REPO:plain,destination=/img" "$REPO@$D" cat /etc/alpine-release) || exit 1
    enforce_later "$store" "$id"
    out=$(shs "$store" start -a --verify-image "$D" "$id" 2>&1 < /dev/null)
    check_match "start: the mount by its tag" "--mount type=image,source=[0-9a-f]{12}: .*$unstated, and --security-opt verity=enforce" "$out"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # (without the option the mount of the same image is a plain pinned pull)
    out=$(shs "$store" run --rm --network none \
        --mount "type=image,source=$REPO@$U,destination=/img" "$REPO@$D" cat /img/etc/alpine-release 2>&1)
    check_match "not enforced" '^[0-9]+\.[0-9]+' "$out"
}

@test "an index whose platform manifest lacks the annotation is refused" {
    need_verity
    store=$VS/indexplain
    for root in $UX $UM; do
        shs "$store" image pull --tls-verify=false "$REPO@$root" > /dev/null || exit 1
        check_match "$root: a pinned pull runs" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$REPO@$root")"
        out=$(run_in "$store" "$REPO@$root" --security-opt verity=enforce)
        check_match "$root: refused" "$unstated, and --security-opt verity=enforce" "$out"
        id=$(shs "$store" create --network none "$REPO@$root" cat /etc/alpine-release) || exit 1
        enforce_later "$store" "$id"
        out=$(go "$store" "$root" "$id")
        check_match "$root: start --verify-image" "$unstated, and --security-opt verity=enforce" "$out"
        shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    done
    # (the index that lists the annotated image after the plain one: the pull
    # took the first for the platform, which the digests are not stated by)
    [ "$(one "$store" "SELECT count(*) FROM images")" = 1 ] || exit 1
}

@test "an image with one layer annotated and one not is refused, naming the layer" {
    need_verity
    store=$VS/partial
    shs "$store" image pull --tls-verify=false "$REPO@$T2" > /dev/null || exit 1
    out=$(run_in "$store" "$REPO@$T2" --security-opt verity=enforce)
    check_match "both stated: it runs" '^[0-9]+\.[0-9]+' "$out"
    for n in 1 2; do
        bare=$(reg digest "$REG" "$NAME" $([ $n = 1 ] && echo first-bare || echo second-bare)) || exit 1
        shs "$store" image pull --tls-verify=false "$REPO@$bare" > /dev/null || exit 1
        check_match "layer $n bare, not enforced" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$REPO@$bare")"
        out=$(run_in "$store" "$REPO@$bare" --security-opt verity=enforce)
        check_match "layer $n bare, enforced" "layer $n of 2 \(sha256:[0-9a-f]{64}\) states no EROFS digest \(io.containers.composefs.digest\), and --security-opt verity=enforce" "$out"
        id=$(shs "$store" create --network none "$REPO@$bare" cat /etc/alpine-release) || exit 1
        enforce_later "$store" "$id"
        out=$(go "$store" "$bare" "$id")
        check_match "layer $n bare, start --verify-image" "layer $n of 2 .*states no EROFS digest .*--security-opt verity=enforce" "$out"
        shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    done
    # (the layers are stored once, for the image that states their digests
    # and the ones that do not: what decides is the manifest of each image)
    check "the layers stored once" 2 "$(one "$store" "SELECT count(*) FROM layers")"
}

@test "a lazy image is refused when verity is enforced" {
    need_verity
    store=$VS/lazy
    # (nothing fetches the rest of a pull in the background until the end of
    # the test, so that the pulls stay lazy: a completion that wins the race
    # makes the image complete before the run, and the refusal is not the one
    # looked for)
    e2e_hold_completions "$XDG_CONFIG_HOME/velarx/config.toml"
    # without the annotation: refused for that by the create (fetching its
    # files would not make it state one).  (The image of velarx without it:
    # one of another writer has no fs-verity digest in its tables of
    # contents, and no lazy pull takes it.)
    bare=$(reg annotate "$REG" "$NAME" zstd lazy-bare 1) || exit 1
    shs "$store" image pull --lazy --tls-verify=false "$REPO@$bare" > /dev/null || exit 1
    out=$(run_in "$store" "$REPO@$bare" --lazy --security-opt verity=enforce)
    check_match "unannotated" "$unstated, and --security-opt verity=enforce" "$out"
    # with it: refused by the start until it is all in the store
    shs "$store" image pull --lazy --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    # (a pull in progress is not an image of the store: it is listed as a pull)
    check_match "the pull is in progress" "." "$(shs "$store" image pulls -q)"
    out=$(run_in "$store" "$REPO@$D" --lazy --security-opt verity=enforce)
    check_match "annotated, lazy" "is not all in the store \(a lazy pull\) and --security-opt verity=enforce" "$out"
    e2e_release_completions "$XDG_CONFIG_HOME/velarx/config.toml"
}

# the values of the annotation that are not the digest of the EROFS image
# velarx makes (another writer's: empty entries, other algorithms, words, a
# sha256 value of another image or of a damaged one) are ignored; an image
# with no value of its own is held to its record like an unannotated one
foreign_values () { # prints the values, one a line
    local d; d=$(printf '%064d' 5)
    printf '%s\n' "" "notadigest" "sha512:$d" "sha256:$(printf '%s' "$d" | tr 0-9 a-f | tr a-f A-F)" \
        "sha256:$d," "sha256:$d,,sha256:$d" "sha256:$d,sha256:ab" "sha256:zz" "x-1:$d,sha512:$d"
}

@test "foreign values in the annotation are ignored at the pull, and the image runs when nothing is enforced" {
    n=0
    while IFS= read -r bad; do
        n=$((n + 1))
        m=$(reg annotate "$REG" "$NAME" two "bad$n" 2 "$bad") || exit 1
        for mode in "--lazy" ""; do
            # (a store of its own for each pull: the engine service of a store
            # stays a while after its last command)
            out=$(shs "$WORKDIR/foreign-$n${mode:+-lazy}" image pull --tls-verify=false $mode "$REPO@$m" 2>&1)
            check "[$bad] is pulled ($mode)" 0 $?
        done
        out=$(run_in "$WORKDIR/foreign-$n" "$REPO@$m")
        check_match "[$bad] runs" '^[0-9]+\.[0-9]+' "$out"
    done < <(foreign_values)
}

@test "a list with the digest of velarx among foreign values is accepted, a damaged one that is the only value is foreign" {
    d=$(printf '%064d' 5)
    own=$(python3 -I -c '
import json, sys, urllib.request
req = urllib.request.Request(f"http://{sys.argv[1]}/v2/{sys.argv[2]}/manifests/two", headers={"Accept": "application/vnd.oci.image.manifest.v1+json"})
print(json.load(urllib.request.urlopen(req))["layers"][1]["annotations"]["io.containers.composefs.digest"])' "$REG" "$NAME") || exit 1
    m=$(reg annotate "$REG" "$NAME" two mixed 2 ",sha512:$d, $own ,sha256:$d,") || exit 1
    shs "$WORKDIR/mixed" image pull --tls-verify=false "$REPO@$m" > /dev/null 2>&1
    check "ours among foreign values" 0 $?
    check_match "it runs" '^[0-9]+\.[0-9]+' "$(run_in "$WORKDIR/mixed" "$REPO@$m")"
    # the only sha256 value is not the digest of the image made here: foreign
    # (nothing says it was meant to be ours), pulled in the default mode
    m=$(reg annotate "$REG" "$NAME" two damaged 2 "sha256:$d") || exit 1
    shs "$WORKDIR/damaged" image pull --tls-verify=false "$REPO@$m" > /dev/null 2>&1
    check "the damaged digest as the only value is pulled" 0 $?
    check_match "and runs" '^[0-9]+\.[0-9]+' "$(run_in "$WORKDIR/damaged" "$REPO@$m")"
}

@test "foreign values are refused when the digests are required, at the pull, naming the layer" {
    sed '1i storage.composefs_digests = "require"' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require.toml"
    node () { "$BIN/velarx" --config "$WORKDIR/require.toml" --root "$WORKDIR/foreignrequire" "$@"; }
    n=0
    while IFS= read -r bad; do
        n=$((n + 1))
        m=$(reg annotate "$REG" "$NAME" two "bad$n" 2 "$bad") || exit 1
        out=$(node image pull --tls-verify=false "$REPO@$m" 2>&1)
        check "[$bad] is refused" 125 $?
        check_match "[$bad]: the layer and the option named" "layer 2 of 2 \(sha256:[0-9a-f]{64}\)[: ].*composefs_digests is \"require\"" "$out"
    done < <(foreign_values)
    check "nothing pulled" 0 "$(node image ls --format '{{.ID}}' 2>&1 | grep -c .)"
}

@test "foreign values are refused when verity is enforced, naming the layer" {
    need_verity
    store=$VS/foreignenforced
    n=0
    while IFS= read -r bad; do
        n=$((n + 1))
        m=$(reg annotate "$REG" "$NAME" two "bad$n" 2 "$bad") || exit 1
        shs "$store" image pull --tls-verify=false "$REPO@$m" > /dev/null || exit 1
        out=$(run_in "$store" "$REPO@$m" --security-opt verity=enforce)
        check_match "[$bad]: the layer and the option named" "layer 2 of 2 \(sha256:[0-9a-f]{64}\).*(states no sha256:<hex> or sha512:<hex> EROFS digest|is recorded with the fs-verity digest sha256:[0-9a-f]{64}, the manifest says).*--security-opt verity=enforce" "$out"
        check_match "[$bad]: not enforced it runs" '^[0-9]+\.[0-9]+' "$(run_in "$store" "$REPO@$m")"
    done < <(foreign_values)
}

@test "the node's require refuses an image without the annotation, named by its digest" {
    sed '1i storage.composefs_digests = "require"' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require.toml"
    node () { "$BIN/velarx" --config "$WORKDIR/require.toml" --root "$store" "$@"; }
    store=$WORKDIR/requireplain
    out=$(node image pull --tls-verify=false "$REPO@$U" 2>&1)
    check "not pulled" 125 $?
    check_match "the layer and the option" "$unstated, and \[storage\] composefs_digests is \"require\"" "$out"
    out=$(node image pull --tls-verify=false "$REPO@$UX" 2>&1)
    check_match "an index: its platform manifest" "states no EROFS digest .*composefs_digests is \"require\"" "$out"
    out=$(node run --rm --network none "$REPO@$U" true 2>&1)
    check_match "run pulls and refuses" "states no EROFS digest .*composefs_digests is \"require\"" "$out"
    need_verity
    # an image stored before require was set
    store=$VS/requirestored
    shs "$store" image pull --tls-verify=false "$REPO@$U" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO@$UX" > /dev/null || exit 1
    for root in $U $UX; do
        out=$(node run --rm --pull=never --network none "$REPO@$root" true 2>&1)
        check_match "$root: run, refused at the start" "$unstated, and \[storage\] composefs_digests is \"require\"" "$out"
    done
    id=$(shs "$store" create --network none "$REPO@$U" cat /etc/alpine-release) || exit 1
    out=$(node start -a --verify-image "$U" "$id" 2>&1 < /dev/null)
    check_match "start --verify-image" "$unstated, and \[storage\] composefs_digests is \"require\"" "$out"
    out=$(node start -a "$id" 2>&1 < /dev/null)
    check_match "a start without the digest" "composefs_digests is \"require\"" "$out"
    node rm -t 0 -f "$id" > /dev/null 2>&1
}

# --log-level=debug shows the chain of trust of an enforced start as a chain
# of digests, a line per link, in the log of the engine (the monitor, which
# checks the last links and writes them to its own log, is repeated there
# after the mount); verity_chain.py checks that the digests connect

dbg () { # store, arguments: the CLI at debug level; the lines of the chain only
    local store=$1
    shift
    "$SH" --root "$store" --log-level=debug "$@" 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p'
}

in_order () { # lines, regular expressions: each is on a line after the one before
    local text=$1 re at=0 n
    shift
    for re; do
        n=$(printf '%s\n' "$text" | tail -n "+$((at + 1))" | grep -anE -m1 -- "$re" | cut -d: -f1)
        [ -n "$n" ] || { echo "# not in order after line $at: $re"; printf '%s\n' "$text"; return 1; }
        at=$((at + n))
    done
}

connected () { # lines of the chain, [broken]: the digests connect, each chain COMPLETE (or the last BROKEN)
    printf '%s\n' "$1" | sed 's/^/verity chain: /' | python3 -I "$E2E_DIR/verity_chain.py" --expect "${2:-complete}" > /dev/null \
        || { printf '%s\n' "$1"; return 1; }
}

h='sha256:[0-9a-f]{64}'

# every line is digests and the names of what they are, never an explanation
only_digests () { # lines of the chain
    local other
    other=$(printf '%s\n' "$1" | sed -E 's/^image mount [^ ]+: //' | grep -avE "^(root (typed|RECORDED|NONE) $h|$h .* -> .*|settings -> spec process|layer [0-9]+ annotation $h == erofs fd $h|erofs fd $h(,$h)* -> overlay verity=require( \(files of layer 1\), fuse verity=require \(files of layers? 2(-[0-9]+)?\))?|COMPLETE .*|BROKEN .* expected .* found .*|OFF|signature .*)$")
    [ -z "$other" ] || { echo "# not a line of digests: $other"; return 1; }
}

@test "verity_chain.py: the samples of STORAGE.md connect, a digest changed in a link does not" {
    # (the first block of the log that starts with a root: the sample of a run)
    ok=$(awk '/^```text$/ { inb = 1; n = 0; next } /^```$/ { if (inb && ok) exit; inb = 0; next }
              inb { if (n++ == 0) ok = /^verity chain: root /; if (ok) print }' "$E2E_DIR/../../docs/STORAGE.md")
    [ -n "$ok" ] || { echo "# no sample"; exit 1; }
    printf '%s\n' "$ok" | python3 -I "$E2E_DIR/verity_chain.py" > /dev/null || exit 1
    e1=$(printf '%s\n' "$ok" | sed -En "s/^verity chain: layer 1 annotation ($h) == .*/\1/p")
    e2=$(printf '%s\n' "$ok" | sed -En "s/^verity chain: layer 2 annotation ($h) == .*/\1/p")
    [ -n "$e1" ] && [ -n "$e2" ] || exit 1
    ! printf '%s\n' "$ok" | sed "s/^\(verity chain: layer 1 annotation\) $e1 == erofs fd $e1/\1 $e2 == erofs fd $e2/" | python3 -I "$E2E_DIR/verity_chain.py" > /dev/null 2>&1 || { echo "# a measure of another layer's digest passes"; exit 1; }
    ! printf '%s\n' "$ok" | grep -v ' -> overlay ' | python3 -I "$E2E_DIR/verity_chain.py" > /dev/null 2>&1 || { echo "# a chain without its overlay passes"; exit 1; }
    ! printf '%s\n' "$ok" | grep -v '^verity chain: COMPLETE' | python3 -I "$E2E_DIR/verity_chain.py" > /dev/null 2>&1 || { echo "# a chain without COMPLETE passes"; exit 1; }
    printf '%s\n' "$ok" | grep -v '^verity chain: COMPLETE' | sed '$a verity chain: BROKEN layer 1 erofs fd expected x found none' | python3 -I "$E2E_DIR/verity_chain.py" --expect broken > /dev/null || exit 1
}

@test "debug shows the chain of digests of an enforced run of two layers, from the digest to each EROFS image" {
    need_verity
    store=$VS/dbg2
    shs "$store" image pull --tls-verify=false "$REPO@$T2" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none --security-opt verity=enforce "$REPO@$T2" cat /etc/alpine-release)
    in_order "$out" \
        "^root typed $T2$" \
        "^$T2 manifest -> $h config$" \
        "^$h config -> settings$" \
        '^settings -> spec process$' \
        "^$T2 manifest -> $h layer 1 blob -> $h annotation$" \
        "^$T2 manifest -> $h layer 2 blob -> $h annotation$" || exit 1
    only_digests "$out" || exit 1
    for l in 1 2; do
        a=$(printf '%s\n' "$out" | sed -En "s/^$T2 manifest -> $h layer $l blob -> ($h) annotation$/\1/p")
        check "layer $l measured as its annotation" 1 "$(printf '%s\n' "$out" | grep -acE "^layer $l annotation $a == erofs fd $a$")"
    done
    # (rootless on a kernel that follows the stubs of the lowest layer only,
    # the file system of FUSE checks the files of the layer above it)
    link="^erofs fd $h,$h -> overlay verity=require$"
    if [ "$(id -u)" != 0 ] && [ "$(expected_stubs "$WORKDIR")" = lowest ]; then
        link="^erofs fd $h,$h -> overlay verity=require \(files of layer 1\), fuse verity=require \(files of layer 2\)$"
    fi
    in_order "$out" "$link" "^COMPLETE $T2 -> $h ; $h -> $h ; $h -> $h$" || exit 1
    connected "$out" || exit 1
}

@test "debug shows the chain of an image mount labelled with its destination, and of an index" {
    need_verity
    store=$VS/dbgmount
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO@$X" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none --security-opt verity=enforce \
        --mount "type=image,source=$REPO@$D,destination=/img" "$REPO@$D" cat /img/etc/alpine-release)
    in_order "$out" \
        "^root typed $D$" \
        "^image mount /img: root typed $D$" \
        "^image mount /img: $D manifest -> $h config$" \
        "^image mount /img: $D manifest -> $h layer 1 blob -> $h annotation$" \
        "^image mount /img: layer 1 annotation ($h) == erofs fd \1$" \
        "^image mount /img: erofs fd $h -> overlay verity=require$" \
        "^image mount /img: COMPLETE $D -> $h ; $h -> $h$" || exit 1
    printf '%s\n' "$out" | grep -aqE "^COMPLETE $D -> " || { echo "# no closing line for the root file system"; exit 1; }
    connected "$out" || exit 1
    only_digests "$out" || exit 1
    # an index: hashed, the manifest it lists, then the manifest
    out=$(dbg "$store" run --rm --network none --security-opt verity=enforce "$REPO@$X" cat /etc/alpine-release)
    in_order "$out" \
        "^root typed $X$" \
        "^$X index -> $D manifest$" \
        "^$D manifest -> $h config$" \
        "^COMPLETE $X -> $D -> $h ; $h -> $h$" || exit 1
    connected "$out" || exit 1
}

@test "debug shows the chain at a start with --verify-image and at a restart" {
    need_verity
    store=$VS/dbgstart
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" sleep 60) || exit 1
    out=$(dbg "$store" start --verify-image "$D" "$id")
    in_order "$out" "^root typed $D$" "^$D manifest -> $h config$" "^COMPLETE $D -> " || exit 1
    connected "$out" || exit 1
    out=$(dbg "$store" restart --verify-image "$D" "$id")
    in_order "$out" "^root typed $D$" "^COMPLETE $D -> " || exit 1
    connected "$out" || exit 1
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

# the link that fails is the BROKEN one, after the links that held, and
# nothing says COMPLETE
broken_at () { # lines, regular expression of what follows BROKEN
    in_order "$1" "^BROKEN $2$" || return 1
    ! printf '%s\n' "$1" | grep -aq 'COMPLETE' || { echo "# COMPLETE after a broken link"; return 1; }
    connected "$1" broken
}

@test "debug names the broken link, after the ones that held, and never says COMPLETE" {
    need_verity
    store=$VS/dbgfail
    pulled "$store"
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    # the manifest the name resolves to is another one: the first link after the root
    swap_to_variant "$store" "$id"
    out=$(dbg "$store" start -a --verify-image "$D" "$id")
    in_order "$out" "^root typed $D$" || exit 1
    broken_at "$out" "manifest expected $D found $B" || exit 1
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the annotation of a layer is not the digest the record of the layer has
    store=$VS/dbgannotation
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    sql "$store" "UPDATE layers SET erofs = 'sha256:$(printf '%064d' 3)'"
    out=$(dbg "$store" start -a --verify-image "$D" "$id")
    in_order "$out" '^settings -> spec process$' || exit 1
    broken_at "$out" "layer 1 annotation expected $h found sha256:0+3" || exit 1
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "debug names the layer image that does not measure as its annotation, and never says COMPLETE" {
    need_verity
    store=$VS/dbgimage
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release) || exit 1
    # the image of the layer is replaced by a copy of its bytes, which has no
    # fs-verity (a file that has it cannot change, but can be replaced)
    image=$(ls "$store"/composefs/layer-*.erofs)
    cp "$image" "$image.new" && mv -f "$image.new" "$image" || skip "the layer image cannot be replaced"
    out=$(dbg "$store" start -a --verify-image "$D" "$id")
    in_order "$out" "^$D manifest -> $h layer 1 blob -> $h annotation$" || exit 1
    broken_at "$out" "layer 1 erofs fd expected $h found none" || exit 1
    # (the FUSE file system would check the same image: not tried, one BROKEN)
    check "one BROKEN line" 1 "$(printf '%s\n' "$out" | grep -ac 'BROKEN')"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "debug says the digests are not enforced and shows no chain; the default level shows nothing" {
    need_verity
    store=$VS/dbgplain
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    out=$(dbg "$store" run --rm --network none "$REPO@$D" true)
    check "one line" "OFF" "$out"
    out=$(shs "$store" run --rm --network none --security-opt verity=enforce "$REPO@$D" cat /etc/alpine-release)
    check_match "default level: the command's output only" '^[0-9]+\.[0-9]+(\.[0-9]+)?$' "$out"
    check "nothing of the chain at the default level" 0 "$(printf '%s\n' "$out" | grep -ac 'verity chain')"
}

@test "debug says the root of trust is weaker when no digest was typed: the node's require, and the engine's starts" {
    need_verity
    sed '1i storage.composefs_digests = "require"' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require-dbg.toml"
    store=$VS/dbgrequire
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    out=$("$BIN/velarx" --config "$WORKDIR/require-dbg.toml" --root "$store" --log-level=debug run --rm --pull=never --network none "$REPO:zstd" cat /etc/alpine-release 2>&1 | sed -n 's/^.*verity chain: //p')
    in_order "$out" \
        "^root NONE $D$" \
        "^$D manifest -> $h layer 1 blob -> $h annotation$" \
        "^COMPLETE $D ; $h -> $h$" || exit 1
    connected "$out" || exit 1
    # a start by the engine: the digest of the record, said to be the record's
    store=$VS/dbgengine
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    id=$(shs "$store" create --network none --security-opt verity=enforce "$REPO@$D" sleep 60) || exit 1
    out=$("$SH" --root "$store" --log-level=debug container start --service "$id" 2>&1 < /dev/null | sed -n 's/^.*verity chain: //p')
    in_order "$out" "^root RECORDED $D$" "^COMPLETE $D -> $h ; " || exit 1
    connected "$out" || exit 1
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

# the debug log and the error of a start, apart
dbg_err () { # store, arguments: sets $out (the lines of the chain) and $err (the rest)
    local store=$1 full
    shift
    full=$("$SH" --root "$store" --log-level=debug "$@" 2>&1 < /dev/null)
    out=$(printf '%s\n' "$full" | sed -n 's/^.*verity chain: //p')
    err=$(printf '%s\n' "$full" | grep -av 'verity chain: ')
}

@test "debug: each input tampered with breaks the chain at its own link, the error as without debug" {
    need_verity
    store=$VS/dbgtamper
    shs "$store" image pull --tls-verify=false "$REPO@$X" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO@$T2" > /dev/null || exit 1
    mk () { shs "$store" create --network none --security-opt verity=enforce "$@"; }
    # the bytes of the configuration
    id=$(mk "$REPO@$D" cat /etc/alpine-release) || exit 1
    sql "$store" "UPDATE images SET config = config || ' ' WHERE manifest_digest = '$D';"
    dbg_err "$store" start -a --verify-image "$D" "$id"
    broken_at "$out" "config expected ($h) found $h" || exit 1
    check_match "the error" "the stored configuration hashes to $h \([0-9]+ bytes\), the manifest says" "$err"
    sql "$store" "UPDATE images SET config = substr(config, 1, length(config) - 1) WHERE manifest_digest = '$D';"
    # an annotation in the bytes of the manifest
    sql "$store" "UPDATE images SET manifest = replace(manifest, 'io.containers.composefs.digest', 'io.containers.composefs.digesT') WHERE manifest_digest = '$D';"
    dbg_err "$store" start -a --verify-image "$D" "$id"
    broken_at "$out" "manifest expected $D found $h" || exit 1
    check_match "the error" "the stored manifest hashes to $h, not $D" "$err"
    sql "$store" "UPDATE images SET manifest = replace(manifest, 'io.containers.composefs.digesT', 'io.containers.composefs.digest') WHERE manifest_digest = '$D';"
    check_match "it starts again" '^[0-9]+\.[0-9]+' "$(go "$store" "$D" "$id")"
    # the process line of the bundle's spec
    python3 -I -c '
import json, sys
p = sys.argv[1]
s = json.load(open(p))
s["process"]["args"] = ["sh", "-c", "echo evil"]
json.dump(s, open(p, "w"))' "$store/bundles/$id/config.json" || exit 1
    dbg_err "$store" start -a --verify-image "$D" "$id"
    broken_at "$out" 'spec process arguments expected \["cat", "/etc/alpine-release"\] found \["sh", "-c", "echo evil"\]' || exit 1
    check_match "the error" "the arguments of the bundle's spec is " "$err"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # a setting the container took from the image
    id=$(mk "$REPO@$D") || exit 1
    edit_config "$store" "$id" "c['command'] = ['cat', '/etc/passwd']"
    dbg_err "$store" start -a --verify-image "$D" "$id"
    broken_at "$out" 'settings command expected \["/bin/sh"\] found \["cat", "/etc/passwd"\]' || exit 1
    check_match "the error" 'command: the configuration of the image .*gives \["/bin/sh"\]' "$err"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # an entry of the index
    id=$(mk "$REPO@$X" cat /etc/alpine-release) || exit 1
    sql "$store" "UPDATE store_settings SET value = value || ' ' WHERE key = 'index:$X';"
    dbg_err "$store" start -a --verify-image "$X" "$id"
    broken_at "$out" "index expected $X found $h" || exit 1
    check_match "the error" "the stored index $X hashes to $h" "$err"
    sql "$store" "UPDATE store_settings SET value = substr(value, 1, length(value) - 1) WHERE key = 'index:$X';"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
    # the image of the layer replaced by another file with fs-verity: the
    # image of the top layer of the image of two (another tree than the
    # layer below it, which may be the same as this one), moved there (its
    # fs-verity goes with it)
    id=$(mk "$REPO@$D" cat /etc/alpine-release) || exit 1
    # (the image of a layer is named by its key: `toc:sha256:<hex>` makes
    # `layer-toc-sha256-<hex>`, `sha256:<hex>` makes `layer-sha256-<hex>`)
    image=$(one "$store" "SELECT replace(replace(layer_id, 'toc:', 'toc-'), ':', '-') FROM image_layers WHERE image_id = (SELECT id FROM images WHERE manifest_digest = '$D')") || exit 1
    top=$(one "$store" "SELECT replace(replace(layer_id, 'toc:', 'toc-'), ':', '-') FROM image_layers WHERE image_id = (SELECT id FROM images WHERE manifest_digest = '$T2') ORDER BY layer_index DESC LIMIT 1") || exit 1
    [ "$top" != "$image" ] || exit 1
    mv -f "$(ls "$store"/composefs/layer-"$top".*erofs)" "$(ls "$store"/composefs/layer-"$image".*erofs)" || exit 1
    dbg_err "$store" start -a --verify-image "$D" "$id"
    broken_at "$out" "layer 1 erofs fd expected ($h) found $h" || exit 1
    a=$(printf '%s\n' "$out" | sed -En "s/^BROKEN layer 1 erofs fd expected ($h) found ($h)$/\1 \2/p")
    [ "${a% *}" != "${a#* }" ] || { echo "# expected and found are the same: $a"; exit 1; }
    check_match "the error" "has the fs-verity digest ${a#* }, expected ${a% *}" "$err"
    check "one BROKEN line" 1 "$(printf '%s\n' "$out" | grep -ac 'BROKEN')"
    shs "$store" rm -t 0 -f "$id" > /dev/null 2>&1
}

# The starts that are not `start` or `run` take the digests typed on their
# command as well: pod start and restart (--verify-image, for all the members),
# kube play (the digests of the YAML), container clone --run and container
# restore (--verify-image).

podm () { # store, pod, member name, image, [options]: a member that sleeps
    local store=$1 pod=$2 name=$3 image=$4
    shift 4
    shs "$store" create --pod "$pod" --name "$name" --network none --security-opt verity=enforce "$@" "$image" sleep 300 > /dev/null || exit 1
}

running () { # store: the names of the running containers, one line
    shs "$1" ps --format '{{.Names}}' | sort | tr '\n' ' '
}

@test "pod start and restart hold every member to the digest typed for its image" {
    need_verity
    store=$VS/podstart
    zero=sha256:$(printf '%064d' 7)
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO@$B" > /dev/null || exit 1
    shs "$store" pod create --infra=false --name pv > /dev/null || exit 1
    podm "$store" pv m1 "$REPO@$D"
    podm "$store" pv m2 "$REPO@$B"
    # none, or one of the two: refused naming the member, and nothing starts
    out=$(shs "$store" pod start pv 2>&1)
    check_match "no digest" "container m1: $REPO@$D: the container was made from the digest $D, and the command gives none to hold its image to: pass --verify-image $D" "$out"
    out=$(shs "$store" pod start --verify-image "$D" pv 2>&1)
    check_match "one missing" "container m2: $REPO@$B: .*pass --verify-image $B" "$out"
    out=$(shs "$store" pod restart --verify-image "$B" pv 2>&1)
    check_match "restart, one missing" "container m1: .*pass --verify-image $D" "$out"
    check "nothing started" "" "$(running "$store")"
    # a digest that names no image of the members
    out=$(shs "$store" pod start --verify-image "$D" --verify-image "$B" --verify-image "$zero" pv 2>&1)
    check_match "no image" "--verify-image $zero: no image of the containers that start is held to it" "$out"
    out=$(shs "$store" pod start --verify-image "${D%?}" pv 2>&1)
    check_match "not a digest" "--verify-image ${D%?}: not a digest" "$out"
    check "nothing started" "" "$(running "$store")"
    # both: the pod starts, restarts, and a pod that runs refuses the digests
    shs "$store" pod start --verify-image "$D" --verify-image "$B" pv > /dev/null || exit 1
    check "both run" "m1 m2 " "$(running "$store")"
    out=$(shs "$store" pod start --verify-image "$D" --verify-image "$B" pv 2>&1)
    check_match "a pod that runs" "it runs, on the file systems .* nothing would be checked now" "$out"
    shs "$store" pod restart --verify-image "$D" --verify-image "$B" pv > /dev/null || exit 1
    check "both run again" "m1 m2 " "$(running "$store")"
    shs "$store" pod stop -t 1 pv > /dev/null || exit 1
    # the record of a member edited to another digest: the digests typed are
    # the user's, so the start is refused (and a typed digest of the record's
    # is hashed against the stored image)
    id1=$(shs "$store" inspect --format '{{.Id}}' m1)
    edit_config "$store" "$id1" "c['pinned']['digest'] = '$zero'"
    out=$(shs "$store" pod start --verify-image "$D" --verify-image "$B" pv 2>&1)
    check_match "record edited, typed right" "container m1: .*the container was made from the digest $zero, and the command gives none" "$out"
    out=$(shs "$store" pod start --verify-image "$zero" --verify-image "$B" pv 2>&1)
    check_match "record edited, typed as edited" "the stored manifest hashes to $D, not $zero" "$out"
    # (a member that fails to start does not keep the others from it, as before)
    check "m1 does not run" "m2 " "$(running "$store")"
    shs "$store" pod rm -t 0 -f pv > /dev/null 2>&1
}

@test "pod start: members of one image take its digest, a member of a tag starts on the tag rules" {
    need_verity
    store=$VS/podshare
    pulled "$store"
    shs "$store" pod create --infra=false --name ps > /dev/null || exit 1
    podm "$store" ps a1 "$REPO@$D"
    podm "$store" ps a2 "$REPO@$D" --mount "type=image,source=$REPO@$D,destination=/img"
    podm "$store" ps t1 "$REPO:variant"
    # one digest for the two members and the image mount; the member of a
    # tag goes from the image id of the store
    out=$(dbg "$store" pod start --verify-image "$D" ps)
    check "all run" "a1 a2 t1 " "$(running "$store")"
    check "the roots typed" 2 "$(printf '%s\n' "$out" | grep -acE "^root typed $D$")"
    check "the image mount's root typed" 1 "$(printf '%s\n' "$out" | grep -acE "^image mount /img: root typed $D$")"
    check "the tag's root" 1 "$(printf '%s\n' "$out" | grep -acE "^root NONE $h$")"
    connected "$out" || exit 1
    check "nothing RECORDED" 0 "$(printf '%s\n' "$out" | grep -ac 'RECORDED')"
    shs "$store" pod stop -t 1 ps > /dev/null || exit 1
    # the digest of the image of the member of a tag is held by no member
    out=$(shs "$store" pod start --verify-image "$D" --verify-image "$B" ps 2>&1)
    check_match "a digest of a tag's image" "--verify-image $B: no image of the containers that start is held to it" "$out"
    # the same digest twice is the digest once
    shs "$store" pod start --verify-image "$D" --verify-image "$D" ps > /dev/null || exit 1
    check "all run again" "a1 a2 t1 " "$(running "$store")"
    shs "$store" pod rm -t 0 -f ps > /dev/null 2>&1
}

@test "--verify-image is for one pod, and one container to restore" {
    store=$WORKDIR/onepod
    for c in start restart; do
        out=$(shs "$store" pod $c --all --verify-image "$D" 2>&1)
        check_match "pod $c --all" "--verify-image: the digests are of the images of the containers of one pod" "$out"
    done
    shs "$store" pod create --infra=false --name o1 > /dev/null || exit 1
    shs "$store" pod create --infra=false --name o2 > /dev/null || exit 1
    out=$(shs "$store" pod start --verify-image "$D" o1 o2 2>&1)
    check_match "two pods" "--verify-image: the digests are of the images of the containers of one pod" "$out"
    out=$(shs "$store" container restore --all --verify-image "$D" 2>&1)
    check_match "restore --all" "--verify-image: the digests are of the images of one container" "$out"
    shs "$store" pod rm -t 0 -f o1 o2 > /dev/null 2>&1
}

@test "pod start: the chain says the digest was typed, and breaks at the link that does not hold" {
    need_verity
    store=$VS/poddbg
    pulled "$store"
    shs "$store" pod create --infra=false --name pd > /dev/null || exit 1
    podm "$store" pd m1 "$REPO@$D"
    out=$(dbg "$store" pod start --verify-image "$D" pd)
    in_order "$out" "^root typed $D$" "^COMPLETE $D -> " || exit 1
    connected "$out" || exit 1
    shs "$store" pod stop -t 1 pd > /dev/null || exit 1
    swap_to_variant "$store" "$(shs "$store" inspect --format '{{.Id}}' m1)"
    dbg_err "$store" pod start --verify-image "$D" pd
    broken_at "$out" "manifest expected $D found $B" || exit 1
    check_match "the error" "the stored manifest hashes to $B, not $D" "$err"
    shs "$store" pod rm -t 0 -f pd > /dev/null 2>&1
}

@test "pod start refuses digests where nothing is enforced, and starts members that are not" {
    need_verity
    store=$VS/podplain
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    shs "$store" pod create --infra=false --name pp > /dev/null || exit 1
    shs "$store" create --pod pp --name plain --network none "$REPO@$D" sleep 300 > /dev/null || exit 1
    out=$(shs "$store" pod start --verify-image "$D" pp 2>&1)
    check_match "not enforced" "--verify-image: the digests of the images of the containers that start are not enforced" "$out"
    shs "$store" pod start pp > /dev/null || exit 1
    check "it runs" "plain " "$(running "$store")"
    shs "$store" pod rm -t 0 -f pp > /dev/null 2>&1
}

# the engine service of STORE (the configuration that requires the digests,
# debug log): velarx-kube plays through it, so the log of the play is its
# log.  $KSOCK is its socket, $KLOG its log.
kube_service () { # store
    local store=$1
    kube_service_stop
    KSOCK=$WORKDIR/kube-engine.sock
    KLOG=$WORKDIR/kube-engine.log
    # (the store by its configuration, not by --root: a service of --root has
    # a socket of its own beneath the state directory; its run root is the
    # one the store was made with)
    local run
    run=$(shs "$store" info --format '{{.Store.RunRoot}}') || return 1
    awk -v s="$KSOCK" -v store="$store" -v run="$run" '
        /^\[engine\]/ { e = 1; print; next }
        e && /^socket/ { print "socket = \"" s "\""; e = 0; next }
        /^storage.root/ { print "storage.root = \"" store "\""; next }
        /^root_dir/ { print "root_dir = \"" store "\""; next }
        /^state_dir/ { print "state_dir = \"" run "\""; next }
        { print }' "$WORKDIR/require.toml" > "$WORKDIR/kube-service.toml"
    E2E_SPAWN_LOG=$KLOG e2e_spawn_ready KPID "$BIN/velarx" --config "$WORKDIR/kube-service.toml" \
        --log-level=debug varlink
}

kube_service_stop () {
    [ -z "${KPID:-}" ] || kill -INT "$KPID" 2> /dev/null
    KPID=
}

# kc ARGS: velarx-kube against that service
kc () { "$BIN/velarx-kube" --engine-socket "$KSOCK" --no-start-engine "$@"; }

# kchain ARGS: velarx-kube against that service, the chain of the verity
# checks the service logged for it in $out, what it printed in $err
kchain () {
    local mark
    mark=$(wc -c < "$KLOG")
    err=$(kc "$@" 2>&1 < /dev/null)
    # (the service logs as the play goes: its log is complete when the
    # command returned)
    out=$(tail -c +$((mark + 1)) "$KLOG" | sed -n 's/^.*verity chain: //p')
}

@test "kube play takes the digest of the image in the YAML, and pod start the option" {
    need_verity
    store=$VS/kube
    sed '1i storage.composefs_digests = "require"' "$XDG_CONFIG_HOME/velarx/config.toml" > "$WORKDIR/require.toml"
    node () { "$BIN/velarx" --config "$WORKDIR/kube-service.toml" --socket "$KSOCK" "$@"; }
    pulled "$store"
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    kube_service "$store" || exit 1
    yaml () { # image, pod name
        cat > "$WORKDIR/$2.yaml" <<EOT
apiVersion: v1
kind: Pod
metadata:
  name: $2
spec:
  containers:
  - name: c
    image: $1
    imagePullPolicy: Never
    command: ["sleep", "300"]
EOT
    }
    # the digest in the YAML is the one typed: it plays and starts
    yaml "$REPO@$D" kd
    kc play "$WORKDIR/kd.yaml" > /dev/null || exit 1
    kc down "$WORKDIR/kd.yaml" > /dev/null 2>&1
    kchain play "$WORKDIR/kd.yaml"
    in_order "$out" "^root typed $D$" "^COMPLETE $D -> " || exit 1
    connected "$out" || exit 1
    # a later start of the pod needs the option
    node pod stop -t 1 kd > /dev/null || exit 1
    out=$(node pod start kd 2>&1)
    check_match "pod start, no digest" "the container was made from the digest $D, and the command gives none .*pass --verify-image $D" "$out"
    node pod start --verify-image "$D" kd > /dev/null || exit 1
    kc down "$WORKDIR/kd.yaml" > /dev/null 2>&1
    # the store swapped for another manifest of the name: the play is refused
    swap_to_variant "$store"
    out=$(kc play "$WORKDIR/kd.yaml" 2>&1)
    check_match "refused" "the stored manifest hashes to $B, not $D" "$out"
    kc down "$WORKDIR/kd.yaml" > /dev/null 2>&1
    node pod rm -t 0 -f kd > /dev/null 2>&1
    # an image named by a tag: the tag rules, as for a run
    yaml "$REPO:zstd" kt
    kc play "$WORKDIR/kt.yaml" > /dev/null || exit 1
    kc down "$WORKDIR/kt.yaml" > /dev/null 2>&1
    # an init container, and the image twice: by its digest and by a tag
    cat > "$WORKDIR/km.yaml" <<EOT
apiVersion: v1
kind: Pod
metadata:
  name: km
spec:
  initContainers:
  - name: i
    image: $REPO@$D
    imagePullPolicy: Never
    command: ["true"]
  containers:
  - name: d
    image: $REPO@$D
    imagePullPolicy: Never
    command: ["sleep", "300"]
  - name: t
    image: $REPO:zstd
    imagePullPolicy: Never
    command: ["sleep", "300"]
EOT
    swap_to_variant "$store"
    out=$(kc play "$WORKDIR/km.yaml" 2>&1)
    check_match "the init container refused" "the stored manifest hashes to $B, not $D" "$out"
    kc down "$WORKDIR/km.yaml" > /dev/null 2>&1
    node pod rm -t 0 -f km > /dev/null 2>&1
    store=$VS/kube2
    pulled "$store"
    shs "$store" image pull --tls-verify=false "$REPO:zstd" > /dev/null || exit 1
    kube_service "$store" || exit 1
    kchain play "$WORKDIR/km.yaml"
    check "the roots typed: the init container and d" 2 "$(printf '%s\n' "$out" | grep -acE "^root typed $D$")"
    check "the roots of t and of the infra container" 2 "$(printf '%s\n' "$out" | grep -acE "^root NONE $h$")"
    connected "$out" || exit 1
    check "nothing RECORDED" 0 "$(printf '%s\n' "$out" | grep -ac 'RECORDED')"
    check "d and t run" "km-d km-t " "$(running "$store" | sed 's/[^ ]*-infra //')"
    kc down "$WORKDIR/km.yaml" > /dev/null 2>&1
    kube_service_stop
}

@test "container clone --run holds the new container to the digest typed" {
    need_verity
    store=$VS/clone
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    id=$(shs "$store" create --name orig --network none --security-opt verity=enforce "$REPO@$D" sleep 300) || exit 1
    out=$(shs "$store" container clone --run orig c1 2>&1)
    check_match "no digest" "the container was made from the digest $D, and the command gives none .*pass --verify-image $D" "$out"
    out=$(shs "$store" container clone --run --verify-image "$B" orig c2 2>&1)
    check_match "another digest" "--verify-image $B: no image of the container is held to it|which the command does not give" "$out"
    out=$(shs "$store" container clone --run --verify-image "$D" orig c3 2>&1)
    check "right digest" 0 $?
    check "it runs" "c3 " "$(running "$store")"
    out=$(shs "$store" container clone --verify-image "$D" orig c4 2>&1)
    check_match "without --run" "--verify-image" "$out"
    shs "$store" rm -t 0 -f c1 c2 c3 orig > /dev/null 2>&1
}

@test "container restore holds the container to the digest typed" {
    need_verity
    [ "$(id -u)" = 0 ] || skip "a checkpoint is made by root"
    command -v criu > /dev/null || skip "no criu"
    store=$VS/restore
    shs "$store" image pull --tls-verify=false "$REPO@$D" > /dev/null || exit 1
    # (a loop of short sleeps: busybox's sleep ends at a restore, its
    # interrupted call done)
    id=$(shs "$store" create --name rs --network none --security-opt verity=enforce "$REPO@$D" sh -c 'while :; do sleep 0.1; done') || exit 1
    shs "$store" start --verify-image "$D" rs > /dev/null || exit 1
    out=$(shs "$store" container checkpoint rs 2>&1) || { echo "# criu: $out"; skip "checkpoint does not work here"; }
    out=$(shs "$store" container restore rs 2>&1)
    check_match "no digest" "the container was made from the digest $D, and the command gives none .*pass --verify-image $D" "$out"
    out=$(shs "$store" container restore --verify-image "$B" rs 2>&1)
    check_match "another digest" "--verify-image $B: no image of the container is held to it|which the command does not give" "$out"
    check "not running" "" "$(running "$store")"
    out=$(shs "$store" container restore --verify-image "$D" rs 2>&1)
    check "right digest" 0 $?
    check "restored" "rs " "$(running "$store")"
    # an archive: the digest its image reference names must be typed
    shs "$store" container checkpoint --export "$WORKDIR/rs.tar" --compress none rs > /dev/null || exit 1
    shs "$store" rm -t 0 -f rs > /dev/null 2>&1
    out=$(shs "$store" container restore --import "$WORKDIR/rs.tar" 2>&1)
    check_match "import, no digest" "the container was made from the digest $D, and the command gives none .*pass --verify-image $D" "$out"
    check "nothing left" "" "$(shs "$store" ps -a --format '{{.Names}}')"
    out=$(shs "$store" container restore --import "$WORKDIR/rs.tar" --verify-image "$B" 2>&1)
    check_match "import, another digest" "--verify-image $B: no image of the container is held to it|which the command does not give" "$out"
    out=$(dbg "$store" container restore --import "$WORKDIR/rs.tar" --verify-image "$D")
    in_order "$out" "^root typed $D$" "^COMPLETE $D -> " || exit 1
    connected "$out" || exit 1
    check "imported" "rs " "$(running "$store")"
    shs "$store" rm -t 0 -f rs > /dev/null 2>&1
    # the archive edited to name the variant, by its digest or by a tag: the
    # digest typed holds
    shs "$store" image pull --tls-verify=false "$REPO@$B" > /dev/null || exit 1
    shs "$store" image pull --tls-verify=false "$REPO:variant" > /dev/null || exit 1
    for ref in "$REPO@$B" "$REPO:variant"; do
        python3 -I -c '
import io, json, sys, tarfile
src, dst, ref = sys.argv[1:]
with tarfile.open(src) as t, tarfile.open(dst, "w") as o:
    for m in t.getmembers():
        data = t.extractfile(m).read() if m.isfile() else None
        if m.name.lstrip("./") == "config.dump":
            d = json.loads(data)
            d["request"]["image"] = ref
            data = json.dumps(d).encode()
            m.size = len(data)
        o.addfile(m, io.BytesIO(data) if data is not None else None)' "$WORKDIR/rs.tar" "$WORKDIR/edited.tar" "$ref" || exit 1
        out=$(shs "$store" container restore --import "$WORKDIR/edited.tar" --verify-image "$D" 2>&1)
        check_match "archive of $ref refused" "the stored manifest hashes to $B, not $D|--verify-image $D: no image of the container is held to it \(it was made from no digest\)" "$out"
        check "nothing left ($ref)" "" "$(shs "$store" ps -a --format '{{.Names}}')"
    done
}
