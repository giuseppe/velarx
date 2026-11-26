# SPDX-License-Identifier: Apache-2.0
# End to end checks of the image commands against a daemon of the file's own
# and a plain HTTP registry that has $E2E_REGISTRY/alpine:chunked:
#
#   VELARX_BINDIR=target/debug E2E_REGISTRY=localhost:5000 bats tests/e2e/bats/images.bats
#
# (the old script needed a daemon that was already running; the file starts
# its own, so it needs only the registry)
#
# podman, if there is one, is used to check the archives; its storage is
# put in $WORKDIR so that nothing of the system is touched.

load helpers

setup_file () {
    export REG=$E2E_REGISTRY
    command -v curl > /dev/null || skip "no curl"
    command -v python3 > /dev/null || skip "no python3"
    curl -sf -m 5 "http://$REG/v2/" > /dev/null || skip "no registry at $REG"
    e2e_setup_file
    export PODMAN="podman --root $WORKDIR/podman/root --runroot $WORKDIR/podman/run --storage-driver vfs"
    cat >> "$XDG_CONFIG_HOME/velarx/config.toml" <<TOML
[pull]
TOML
    e2e_start_daemon
    export IMG=$REG/alpine:chunked
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pause
    # the storage of podman has files of its user namespace
    if [ -d "$WORKDIR/podman" ]; then
        pause=$(cat "$XDG_RUNTIME_DIR/libpod/tmp/pause.pid" 2> /dev/null)
        $PODMAN unshare rm -rf "$WORKDIR/podman" > /dev/null 2>&1 3>&-
        pause=${pause:-$(cat "$XDG_RUNTIME_DIR/libpod/tmp/pause.pid" 2> /dev/null)}
        case "$pause" in
        '' | *[!0-9]*) ;;
        *) kill "$pause" 2> /dev/null ;;
        esac
    fi
    e2e_teardown_file
}

@test "pull" {
    $SH image pull --tls-verify=false "$IMG" > /dev/null
    check "pull" 0 $?
}

# A pull of an image the store has prints the id the pull answered with (the
# client does not inspect the image again for it) and writes nothing to the
# store: the file of the write-ahead log is as it was.
@test "pull of an image the store has asks for no inspect and writes nothing" {
    local wal=$XDG_DATA_HOME/velarx/store/db.sqlite-wal id out before
    $SH image pull -q --tls-verify=false "$IMG" > /dev/null
    id=$($SH image inspect --format '{{.Id}}' "$IMG")
    before=$(stat -c '%s %y' "$wal")
    : > "$WORKDIR/trace"
    out=$(VELARX_TRACE_FILE="$WORKDIR/trace" $SH image pull -q --tls-verify=false "$IMG")
    check "pull of a present image" 0 $?
    check "it prints the id of the image" "$id" "$out"
    check "the client asked for no inspect" 0 "$(grep -c ' client request ImageInspect$' "$WORKDIR/trace")"
    check "and for the pull" 1 "$(grep -c ' client request ImagePull$' "$WORKDIR/trace")"
    check "nothing was written" "$before" "$(stat -c '%s %y' "$wal")"
}

@test "pull --all-tags pulls every tag of the repository" {
    local tags
    tags=$(curl -sf "http://$REG/v2/alpine/tags/list" | python3 -I -c 'import json,sys; print(" ".join(json.load(sys.stdin)["tags"]))')
    out=$($SH image pull -q --all-tags --tls-verify=false "$REG/alpine" 2>&1)
    check "pull --all-tags" 0 $?
    check "one ID for each tag" "$(echo "$tags" | wc -w)" "$(echo "$out" | wc -l)"
    for t in $tags; do
        check "the tag $t is there" 0 "$($SH image exists "$REG/alpine:$t"; echo $?)"
    done
    out=$($SH image pull --all-tags "$REG/alpine@sha256:$(printf '0%.0s' $(seq 64))" 2>&1)
    check "a digest" 125 $?
    check_match "is refused as podman does" "tag can't be used with --all-tags" "$out"
}

# Docker schema 2 is read, as the registry serves it: the image has the
# registry's digest, runs, is written back as OCI and --format v2s2 stays
# refused.
@test "pull and run an image the registry has in the Docker schema 2 format" {
    command -v skopeo > /dev/null || skip "no skopeo"
    skopeo copy -q --src-tls-verify=false --dest-tls-verify=false --format v2s2 --dest-compress-format gzip --dest-force-compress-format \
        "docker://$IMG" "docker://$REG/e2e/dockerfmt:v1" > /dev/null 2>&1
    check "skopeo copy --format v2s2" 0 $?
    remote=$(skopeo inspect --raw --tls-verify=false "docker://$REG/e2e/dockerfmt:v1")
    check_match "the registry serves schema 2" "distribution.manifest.v2\+json" "$remote"
    want=sha256:$(printf '%s' "$remote" | sha256sum | cut -d' ' -f1)
    out=$($SH image pull --tls-verify=false "$REG/e2e/dockerfmt:v1" 2>&1)
    check "pull" 0 $?
    check "the digest is the registry's" "$want" "$($SH image inspect --format '{{.Digest}}' "$REG/e2e/dockerfmt:v1")"
    out=$($SH image pull --tls-verify=false "$REG/e2e/dockerfmt@$want" 2>&1)
    check "pull by that digest" 0 $?
    check "run" "hi" "$($SH container run --rm --network none "$REG/e2e/dockerfmt:v1" echo hi 2>&1)"
    $SH image remove --force "$REG/e2e/dockerfmt:v1" > /dev/null 2>&1
    # (a gzip layer cannot be lazy: the lazy pull is refused, nothing made)
    out=$($SH image pull --lazy --tls-verify=false "$REG/e2e/dockerfmt:v1" 2>&1)
    check "lazy pull refused" 125 $?
    check_match "...saying why" "cannot be pulled lazily: layer 1 .*has no table of contents" "$out"
    check "...and no pull is left" "" "$($SH image pulls -q)"
    $SH image pull --tls-verify=false "$REG/e2e/dockerfmt:v1" > /dev/null 2>&1
    check "pull again" 0 $?
    $SH image push --tls-verify=false "$REG/e2e/dockerfmt:v1" "$REG/e2e/dockerfmt:oci" > /dev/null 2>&1
    check "push" 0 $?
    pushed=$(skopeo inspect --raw --tls-verify=false "docker://$REG/e2e/dockerfmt:oci")
    check_match "what is written is OCI" "vnd.oci.image.manifest.v1\+json" "$pushed"
    check "...with no Docker type" 0 "$(printf '%s' "$pushed" | grep -c 'vnd.docker')"
    out=$($SH image push --tls-verify=false --format v2s2 "$REG/e2e/dockerfmt:v1" "$REG/e2e/dockerfmt:again" 2>&1)
    check_match "--format v2s2 is still refused" "Docker image formats are not supported" "$out"
}

# A pull by digest names the image repository@digest, as podman does: the
# repository shows with no tag, RepoDigests has it, a prune keeps it, and
# no other repository finds the image.
@test "pull by digest: the image is named repository@digest" {
    d=sha256:$(skopeo inspect --raw --tls-verify=false "docker://$IMG" | sha256sum | cut -d' ' -f1)
    for id in $($SH image list -q); do $SH image remove --force "$id" > /dev/null 2>&1; done
    $SH image pull --tls-verify=false "$REG/alpine@$d" > /dev/null 2>&1
    check "pull by digest" 0 $?
    check "images: the repository and no tag" "$REG/alpine <none>" \
        "$($SH image list --format '{{.Repository}} {{.Tag}}')"
    check "RepoDigests" "$REG/alpine@$d" "$($SH image inspect --format '{{index .RepoDigests 0}}' "$REG/alpine@$d")"
    check "NamesHistory" "$REG/alpine@$d" "$($SH image inspect --format '{{index .NamesHistory 0}}' "$REG/alpine@$d")"
    $SH image prune -f > /dev/null 2>&1
    check "a prune keeps it" 1 "$($SH image list -q | wc -l)"
    $SH image inspect "$REG/other@$d" > /dev/null 2>&1
    check "another repository does not find it" 125 $?
    $SH image remove "$REG/alpine@$d" > /dev/null 2>&1
    check "rmi of the name removes the image" 0 "$($SH image list -q | wc -l)"
    # (the tests after this one use $IMG)
    $SH image pull --tls-verify=false "$IMG" > /dev/null 2>&1
    check "pull $IMG again" 0 $?
}

# Push: mounts when the registry has the blobs, the same manifest.
@test "push: the digest, the blobs mounted, quiet, another compression" {
    out=$($SH image push --tls-verify=false "$IMG" "$REG/e2e/alpine:pushed" 2> "$WORKDIR/push.err")
    check_match "push" "Digest: sha256:[0-9a-f]{64}" "$(cat "$WORKDIR/push.err")"
    check "push: nothing on the standard output" "" "$out"
    check_match "push mounts the blobs" "[0-9]+ mounted" "$(cat "$WORKDIR/push.err")"
    out=$($SH image push -q --tls-verify=false "$IMG" "$REG/e2e/alpine:pushed" 2>&1)
    check "push -q: nothing at all" "" "$out"
    out=$($SH image push --tls-verify=false --compression-format gzip "$IMG" "$REG/e2e/alpine:gzip" 2>&1)
    check_match "push regenerates with another compression" "[0-9]+ uploaded, [0-9]+ mounted, [0-9]+ already" "$out"
}

# --all-tags: every tag of the repository; a manifest list with its
# instances
@test "push --all-tags and a manifest list" {
    tag=e2e-$$
    $SH image tag "$IMG" "localhost/e2e-alltags:a-$tag" > /dev/null
    $SH image tag "$IMG" "localhost/e2e-alltags:b-$tag" > /dev/null
    out=$($SH image push --tls-verify=false --all-tags localhost/e2e-alltags "$REG/e2e/alltags" 2>&1)
    check "push --all-tags" 0 $?
    tags=$(curl -s "http://$REG/v2/e2e/alltags/tags/list")
    check_match "both tags are in the registry" "a-$tag.*b-$tag|b-$tag.*a-$tag" "$tags"
    $SH image rm "localhost/e2e-alltags:a-$tag" "localhost/e2e-alltags:b-$tag" > /dev/null
    $SH manifest create "localhost/e2e-list:$tag" > /dev/null
    # (an index of its own content: a registry that answered the same bytes
    # earlier may know the digest without having the data)
    $SH manifest annotate --index --annotation "e2e.run=$tag" "localhost/e2e-list:$tag" > /dev/null
    $SH manifest add --tls-verify=false "localhost/e2e-list:$tag" "$IMG" > /dev/null
    out=$($SH image push --tls-verify=false "localhost/e2e-list:$tag" "$REG/e2e/list:$tag" 2>&1)
    check_match "push of a manifest list" "Digest: sha256:[0-9a-f]{64}" "$out"
    mt=$(curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' \
        "http://$REG/v2/e2e/list/manifests/$tag" | python3 -I -c 'import json, sys; d = json.load(sys.stdin); print(d.get("mediaType"), len(d["manifests"]))')
    check_match "the registry has the index and its instance" "index.* 1$|list.* 1$" "$mt"
    $SH manifest rm "localhost/e2e-list:$tag" > /dev/null 2>&1
}

# The manifest digests of an OCI archive or layout, as `index.json` lists
# them (the layers of a save are uncompressed, as the store has them).
index_digests () { # TARFILE or DIR
    if [ -d "$1" ]; then cat "$1/index.json"; else tar -xOf "$1" index.json; fi |
        python3 -I -c 'import json, sys; print(" ".join(sorted(m["digest"] for m in json.load(sys.stdin)["manifests"])))'
}

@test "save is a push to an oci-archive: the digests survive a load, several images share one archive, a pipe is written" {
    $SH image tag "$IMG" localhost/e2e-rt:a
    $SH image tag "$IMG" localhost/e2e-rt:b
    $SH image save -o "$WORKDIR/rt1.tar" localhost/e2e-rt:a
    check "save" 0 $?
    first=$(index_digests "$WORKDIR/rt1.tar")
    $SH image remove localhost/e2e-rt:a localhost/e2e-rt:b > /dev/null
    $SH image load -q -i "$WORKDIR/rt1.tar" > /dev/null
    check "load" 0 $?
    $SH image save -o "$WORKDIR/rt2.tar" localhost/e2e-rt:a
    check "a saved and loaded image saves with the same manifest digest" "$first" "$(index_digests "$WORKDIR/rt2.tar")"
    # the same through a layout directory, and a pipe
    $SH image save --format oci-dir -o "$WORKDIR/rt-dir" localhost/e2e-rt:a
    check "the layout has the same manifest digest" "$first" "$(index_digests "$WORKDIR/rt-dir")"
    $SH image save localhost/e2e-rt:a | cat > "$WORKDIR/rt-pipe.tar"
    check "an archive written to a pipe has the same manifest digest" "$first" "$(index_digests "$WORKDIR/rt-pipe.tar")"
    # two names of an image and a second image: one archive, one index
    $SH image tag "$IMG" localhost/e2e-rt:b
    $SH image save -o "$WORKDIR/rt-two.tar" localhost/e2e-rt:a localhost/e2e-rt:b
    check "two names of one image: two entries of the index" 2 "$(tar -xOf "$WORKDIR/rt-two.tar" index.json | python3 -I -c 'import json, sys; print(len(json.load(sys.stdin)["manifests"]))')"
    check "the blobs are in the archive once" "" "$(tar -tf "$WORKDIR/rt-two.tar" | sort | uniq -d)"
    # a save that fails leaves the file that was there
    echo keep > "$WORKDIR/rt-keep.tar"
    $SH image save -o "$WORKDIR/rt-keep.tar" localhost/no-such-image:1 > /dev/null 2>&1
    check "a save of an image that is not there fails" 125 $?
    check "and leaves the archive that was there" keep "$(cat "$WORKDIR/rt-keep.tar")"
    $SH image remove localhost/e2e-rt:a localhost/e2e-rt:b > /dev/null
    rm -rf "$WORKDIR"/rt*.tar "$WORKDIR/rt-dir"
}

@test "save and load" {
    $SH image tag "$IMG" localhost/e2e-saved:v1
    $SH image save -o "$WORKDIR/saved.tar" localhost/e2e-saved:v1
    check "save" 0 $?
    check "save writes the OCI archive by default" "oci-layout" "$(tar -tf "$WORKDIR/saved.tar" | grep '^oci-layout$')"
    check "save writes the requested name" 'localhost/e2e-saved:v1' \
          "$(tar -xOf "$WORKDIR/saved.tar" index.json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["manifests"][0]["annotations"]["io.containerd.image.name"])')"
    out=$($SH image save --format docker-archive localhost/e2e-saved:v1 2>&1 > /dev/null; echo "rc=$?")
    check "save --format docker-archive is refused" "Error: the format docker-archive: Docker image formats are not supported: only OCI images (application/vnd.oci.image.*)
rc=125" "$out"
    $SH image save --format oci-archive localhost/e2e-saved:v1 > "$WORKDIR/saved-oci.tar"
    check_match "save oci-archive to stdout" "oci-layout" "$(tar -tf "$WORKDIR/saved-oci.tar")"
    $SH image save --format oci-dir -o "$WORKDIR/ocidir" localhost/e2e-saved:v1
    check "save oci-dir" 0 $?
    for src in "-i $WORKDIR/saved.tar" "-i $WORKDIR/ocidir"; do
        $SH image remove localhost/e2e-saved:v1 > /dev/null
        check "load $src" "Loaded image: localhost/e2e-saved:v1" "$($SH image load $src)"
    done
    $SH image remove localhost/e2e-saved:v1 > /dev/null
    check "load oci-archive from stdin" "Loaded image: localhost/e2e-saved:v1" "$($SH image load < "$WORKDIR/saved-oci.tar")"
    printf junk > "$WORKDIR/random.tar"
    $SH image load -i "$WORKDIR/random.tar" > /dev/null 2>&1
    check "load of an invalid archive fails" 125 $?
    # a docker save tarball (manifest.json, the configuration, the layers) is read
    python3 -I "$E2E_DIR/docker_archive.py" "$WORKDIR/saved.tar" "$WORKDIR/docker.tar" localhost/e2e-docker:v1
    id=$($SH image inspect --format '{{.Id}}' "$IMG")
    check "load of a docker-archive" "Loaded image: localhost/e2e-docker:v1" "$($SH image load -i "$WORKDIR/docker.tar")"
    check "the image id of the docker-archive is the configuration's" "$id" \
        "$($SH image inspect --format '{{.Id}}' localhost/e2e-docker:v1)"
    check "the stored manifest is OCI" "application/vnd.oci.image.manifest.v1+json" \
        "$($SH image inspect --format '{{.ManifestType}}' localhost/e2e-docker:v1)"
    $SH image remove localhost/e2e-docker:v1 > /dev/null
    check_match "load of a docker-archive from stdin" "Loaded image: localhost/e2e-docker:v1" "$($SH image load < "$WORKDIR/docker.tar")"
    $SH run --rm --network none localhost/e2e-docker:v1 true
    check "the docker-archive image runs" 0 $?
    $SH image remove localhost/e2e-docker:v1 > /dev/null
    # a layer of the archive that was changed is refused, nothing is loaded
    python3 -I - "$WORKDIR/docker.tar" "$WORKDIR/docker-bad.tar" <<'PY'
import io, sys, tarfile
src = tarfile.open(sys.argv[1])
out = tarfile.open(sys.argv[2], "w")
for m in src.getmembers():
    data = src.extractfile(m).read()
    if m.name.endswith("layer.tar"):
        data = data[:len(data) // 2] + bytes([data[len(data) // 2] ^ 0xff]) + data[len(data) // 2 + 1:]
    out.addfile(m, io.BytesIO(data))
out.close()
PY
    $SH image load -i "$WORKDIR/docker-bad.tar" > /dev/null 2>&1
    check "load of a docker-archive with a changed layer fails" 125 $?
    $SH image exists localhost/e2e-docker:v1
    check "nothing of it was loaded" 1 $?
}

# (podman starts a pause process that would keep bats's fd 3: 3>&-)
@test "podman interoperability: our archive loads in podman and theirs in velarx" {
    [ -s "$WORKDIR/saved.tar" ] || { echo "needs the archive of the test 'save and load'" >&2; exit 1; }
    $PODMAN load -i "$WORKDIR/saved.tar" > /dev/null 2>&1 3>&- || skip "podman load failed"
    $PODMAN image exists localhost/e2e-saved:v1 3>&-
    check "podman loads our archive" 0 $?
    $PODMAN save --format oci-archive -o "$WORKDIR/podman.tar" localhost/e2e-saved:v1 2> /dev/null 3>&-
    $SH image remove localhost/e2e-saved:v1 > /dev/null
    check "load a podman archive" "Loaded image: localhost/e2e-saved:v1" "$($SH image load -i "$WORKDIR/podman.tar")"
    # (podman's default is the docker-archive; the second image of a multi-image
    # archive is the same configuration under another name)
    $PODMAN tag localhost/e2e-saved:v1 localhost/e2e-saved:v2 3>&-
    $PODMAN save -o "$WORKDIR/podman-docker.tar" localhost/e2e-saved:v1 2> /dev/null 3>&-
    $PODMAN save -m -o "$WORKDIR/podman-multi.tar" localhost/e2e-saved:v1 localhost/e2e-saved:v2 2> /dev/null 3>&-
    id=$($PODMAN image inspect --format '{{.Id}}' localhost/e2e-saved:v1 3>&-)
    $SH image remove localhost/e2e-saved:v1 > /dev/null
    check "a docker-archive of podman is loaded" "Loaded image: localhost/e2e-saved:v1" \
        "$($SH image load -i "$WORKDIR/podman-docker.tar")"
    check "...with the image id podman has" "$id" "$($SH image inspect --format '{{.Id}}' localhost/e2e-saved:v1)"
    $SH run --rm --network none localhost/e2e-saved:v1 true
    check "...and runs" 0 $?
    $SH image remove localhost/e2e-saved:v1 > /dev/null
    out=$($SH image load < "$WORKDIR/podman-multi.tar")
    check_match "a multi-image docker-archive of podman is loaded" "localhost/e2e-saved:v1" "$out"
    check "...with both names" "$id $id" "$($SH image inspect --format '{{.Id}}' localhost/e2e-saved:v1 localhost/e2e-saved:v2 | xargs)"
}

@test "import" {
    c=$($PODMAN create "$(cut -d: -f1 <<< localhost/e2e-saved):v1" true 2> /dev/null 3>&-) && $PODMAN export "$c" > "$WORKDIR/rootfs.tar" 2> /dev/null 3>&-
    [ -s "$WORKDIR/rootfs.tar" ] || skip "no root file system from podman"
    out=$($SH image import -c 'ENV IMPORTED=yes' -m 'e2e' "$WORKDIR/rootfs.tar" e2e-imported)
    check_match "import" "^sha256:[0-9a-f]{64}$" "$out"
    out=$(gzip -c "$WORKDIR/rootfs.tar" | $SH image import - e2e-imported:gz)
    check_match "import a compressed tar from stdin" "^sha256:[0-9a-f]{64}$" "$out"
    printf junk | $SH image import - e2e-imported:bad > /dev/null 2>&1
    check "import of an invalid tar fails" 125 $?
}

# a file with holes in the tar of an import (GNU tar --sparse, in each of its
# formats) is a regular file of the layer, as with podman
@test "import of a tar with sparse files" {
    d=$WORKDIR/sparse-rootfs
    mkdir -p "$d"
    head -c 4096 /dev/urandom > "$d/f"
    truncate -s 8M "$d/f"
    printf end >> "$d/f"
    want="$(sha256sum < "$d/f" | cut -d' ' -f1) $(stat -c %s "$d/f")"
    n=0
    for fmt in gnu "posix --sparse-version=0.0" "posix --sparse-version=0.1" "posix --sparse-version=1.0" gzip; do
        n=$((n + 1))
        if [ "$fmt" = gzip ]; then
            tar -C "$d" --sparse --format=posix -czf "$WORKDIR/sparse$n.tar" f
        else
            # shellcheck disable=SC2086
            tar -C "$d" --sparse --format=$fmt -cf "$WORKDIR/sparse$n.tar" f
        fi
        out=$($SH image import "$WORKDIR/sparse$n.tar" "e2e-sparse:$n" 2>&1)
        check_match "import of a tar with a sparse file ($fmt)" "^sha256:[0-9a-f]{64}$" "$out"
        c=$($SH create "localhost/e2e-sparse:$n" true 2>&1)
        got="$($SH cp "$c:/f" - | tar -xOf - f | sha256sum | cut -d' ' -f1) $($SH cp "$c:/f" - | tar -tvf - | awk '{print $3}')"
        check "the file of the import ($fmt): content and size" "$want" "$got"
        $SH rm "$c" > /dev/null
        $SH image remove "localhost/e2e-sparse:$n" > /dev/null
    done
}

# a hole of 1 GiB in a tar of a few KiB: the zeros are written nowhere, the
# disk of the store stays small and the file reads back whole
@test "import of a tar with a huge hole takes the disk of its data" {
    d=$WORKDIR/hole-rootfs
    mkdir -p "$d"
    printf start > "$d/f"
    truncate -s 1G "$d/f"
    printf end >> "$d/f"
    tar -C "$d" --sparse --format=gnu -cf "$WORKDIR/hole.tar" f
    [ "$(stat -c %s "$WORKDIR/hole.tar")" -lt 65536 ]
    if [ "$(du -sk "$d/f" | cut -f1)" -gt 1024 ]; then
        skip "no holes in the file system of the test directory"
    fi
    out=$($SH image import "$WORKDIR/hole.tar" e2e-hole:1 2>&1)
    check_match "import of a tar with a 1 GiB hole" "^sha256:[0-9a-f]{64}$" "$out"
    used=$(du -sk "$XDG_DATA_HOME/velarx" | cut -f1)
    check "the disk of the store with a 1 GiB hole (KiB, under 64 MiB)" "yes" "$([ "$used" -lt 65536 ] && echo yes || echo "no: $used")"
    c=$($SH create localhost/e2e-hole:1 true 2>&1)
    size=$($SH cp "$c:/f" - | tar -tvf - | awk '{print $3}')
    check "the file of the import: size" "$(stat -c %s "$d/f")" "$size"
    $SH rm "$c" > /dev/null
    $SH image remove localhost/e2e-hole:1 > /dev/null
}

# a file with a hole of 1 GiB copied into a container and out of it, and
# through a volume: each archive holds its data, each copy has its holes
@test "cp and volume export keep the holes of a file" {
    d=$WORKDIR/holes
    mkdir -p "$d"
    printf start > "$d/f"
    truncate -s 1G "$d/f"
    printf end >> "$d/f"
    if [ "$(du -sk "$d/f" | cut -f1)" -gt 1024 ]; then
        skip "no holes in the file system of the test directory"
    fi
    small () { [ "$(du -sk "$1" | cut -f1)" -lt 1024 ] && echo yes || echo "no: $(du -sk "$1")"; }
    c=$($SH create "$IMG" true 2>&1)
    $SH cp "$d/f" "$c:/f"
    check "the archive of cp out (bytes, under 64 KiB)" yes "$([ "$($SH cp "$c:/f" - | wc -c)" -lt 65536 ] && echo yes || echo no)"
    $SH cp "$c:/f" "$d/back"
    check "cp in and out: size" "$(stat -c %s "$d/f")" "$(stat -c %s "$d/back")"
    check "cp in and out: the hole" yes "$(small "$d/back")"
    cmp "$d/f" "$d/back"
    $SH rm "$c" > /dev/null
    $SH volume create e2e-holes > /dev/null
    tar -C "$d" --sparse --format=gnu -cf "$d/in.tar" f
    $SH volume import e2e-holes "$d/in.tar"
    $SH volume export e2e-holes -o "$d/vol.tar"
    check "the archive of a volume (bytes, under 64 KiB)" yes "$([ "$(stat -c %s "$d/vol.tar")" -lt 65536 ] && echo yes || echo no)"
    mkdir "$d/x"
    tar -C "$d/x" -xf "$d/vol.tar"
    check "volume import and export: the hole" yes "$(small "$d/x/f")"
    cmp "$d/f" "$d/x/f"
    $SH volume rm e2e-holes > /dev/null
}

@test "an image of a table of contents without fs-verity digests is refused, lazily or not, and nothing is made" {
    local plain=$REG/alpine-plain:chunked
    curl -sf -m 5 "http://$REG/v2/alpine-plain/manifests/chunked" -o /dev/null -H 'Accept: application/vnd.oci.image.manifest.v1+json' || skip "no $plain"
    for id in $($SH image list -q); do $SH image remove --force "$id" > /dev/null 2>&1; done
    # (the zstd:chunked layers of containers/storage give no fs-verity
    # digest of their files: a layer with a table is pulled by it or not at
    # all; no pull in progress, no image)
    for lazy in --lazy ""; do
        out=$($SH image pull $lazy --tls-verify=false "$plain" 2>&1)
        check "pull ($lazy) refused" 125 $?
        check_match "...saying why" "layer sha256:[0-9a-f]+: its table of contents has no fs-verity digest for" "$out"
        check "no pull is left" "" "$($SH image pulls -q)"
        check "no image" "" "$($SH image list -q)"
    done
}

@test "a single image of another platform is taken with podman's warning" {
    out=$($SH image pull -q --platform linux/s390x --tls-verify=false "$IMG" 2>&1)
    check "a platform the image is not for is pulled" 0 $?
    check_match "with podman's warning" \
        "image platform \\(linux/amd64\\) does not match the expected platform \\(linux/s390x\\)" "$out"
}

# The transports of the image names: docker:// (a registry), oci:, oci-archive:
# and dir: (written by push, read by pull and run, and by skopeo),
# docker-archive: (read only), the
# refusals by name.
@test "transports: docker://, oci:, oci-archive:, dir:" {
    t=$WORKDIR/transports
    mkdir -p "$t"
    $SH image pull --tls-verify=false "docker://$IMG" > /dev/null 2>&1
    check "pull docker://" 0 $?
    id=$($SH image inspect --format '{{.Id}}' "$IMG")
    $SH image push --tls-verify=false "$IMG" "docker://$REG/e2e/transport:docker" > /dev/null 2>&1
    check "push to docker://" 0 $?
    out=$($SH container run --rm --tls-verify=false "docker://$IMG" echo via-docker-transport 2>&1)
    check "run docker://" "via-docker-transport" "$out"

    # a zstd:chunked layer is pulled by its table of contents or not at all,
    # and an archive, a layout or a directory gives none: refused, and no
    # image is named after it
    names=$($SH image list --format '{{.Repository}}:{{.Tag}}' 2>&1)
    $SH image push "$IMG" "oci-archive:$t/chunked.tar:chunked" > /dev/null 2>&1
    check "push the chunked image to oci-archive:" 0 $?
    $SH image push "$IMG" "oci:$t/chunked:chunked" > /dev/null 2>&1
    check "push the chunked image to oci:" 0 $?
    $SH image push "$IMG" "dir:$t/chunked-dir" > /dev/null 2>&1
    check "push the chunked image to dir:" 0 $?
    for ref in "oci-archive:$t/chunked.tar:chunked" "oci:$t/chunked:chunked" "dir:$t/chunked-dir"; do
        out=$($SH image pull "$ref" 2>&1)
        check "pull $ref of a zstd:chunked layer" 125 $?
        check_match "...saying why" "layer sha256:[0-9a-f]{64}: it is zstd:chunked, which is pulled by its table of contents or not at all, and the source gives none" "$out"
    done
    check "no image is named after them" "$names" "$($SH image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"

    # the gzip layers of the same image are pulled from them
    $SH image push --compression-format gzip "$IMG" "oci-archive:$t/a.tar:v1" > /dev/null 2>&1
    check "push to oci-archive:" 0 $?
    $SH image push --compression-format gzip "$IMG" "oci:$t/layout:v1" > /dev/null 2>&1
    check "push to oci:" 0 $?
    $SH image push --compression-format gzip "$IMG" "oci:$t/layout:v2" > /dev/null 2>&1
    check "push a second tag to the layout" 0 $?
    $SH image push --compress "$IMG" "dir:$t/dir" > /dev/null 2>&1
    check "push to dir:" 0 $?
    check_match "dir: has a manifest and a version" "manifest.json" "$(ls "$t/dir")"
    check "the layout has two entries" 2 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["manifests"]))' "$t/layout/index.json")"

    $SH image push --compression-format gzip "$IMG" "oci:$t/layout:v1" > /dev/null 2>&1
    check "the same tag again replaces its entry" 2 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["manifests"]))' "$t/layout/index.json")"

    for ref in "oci-archive:$t/a.tar:v1" "oci:$t/layout:v2" "dir:$t/dir"; do
        out=$($SH image pull "$ref" 2>&1)
        check "pull $ref" "$(printf '%s' "$id")" "$out"
        out=$($SH container run --rm "$ref" echo "ran-$$" 2>&1)
        check "run $ref" "ran-$$" "$out"
    done
    names=$($SH image list --format '{{.Repository}}:{{.Tag}}' 2>&1)
    check_match "oci:PATH:TAG names the image after the tag, as podman" "library/v2:latest" "$names"
    check_match "oci-archive: names it after its ref.name, local like podman load" "localhost/v1:latest" "$names"
    $SH image push --compression-format gzip "$IMG" "oci:$t/single:only" > /dev/null 2>&1
    check "oci:PATH: with an empty tag is the only image, as skopeo has it" "$id" "$($SH image pull "oci:$t/single:" 2>&1)"
    check "the tag of the layout is not a name of the image pulled without it" 0 "$($SH image list --format '{{.Repository}}:{{.Tag}}' 2>&1 | grep -c 'only')"
    out=$($SH image pull "oci:$t/layout" 2>&1)
    check "a layout of two images and no tag" 125 $?
    check_match "...says what it has" "2 images" "$out"
    $SH image pull "oci-archive:$t/a.tar:nope" > /dev/null 2>&1
    check "a tag the archive lacks" 125 $?

    # an archive that cannot be read twice (a pipe given as a path, a FIFO)
    # is copied first, as podman does
    check "pull oci-archive: from /dev/fd/N" "$id" "$($SH image pull "oci-archive:/dev/fd/3:v1" 3< <(cat "$t/a.tar") 2>&1)"
    mkfifo "$t/fifo"
    cat "$t/a.tar" > "$t/fifo" &
    fifo_writer=$!
    check "pull oci-archive: from a FIFO" "$id" "$($SH image pull "oci-archive:$t/fifo:v1" 2>&1)"
    e2e_reap "$fifo_writer" "the writer of the FIFO"
    python3 -I "$E2E_DIR/docker_archive.py" "$t/a.tar" "$t/docker.tar" localhost/e2e-docker-fifo:v1
    check_match "pull docker-archive: from /dev/fd/N" "$id" "$($SH image pull "docker-archive:/dev/fd/3" 3< <(cat "$t/docker.tar") 2>&1)"
    cat "$t/docker.tar" > "$t/fifo" &
    fifo_writer=$!
    check_match "pull docker-archive: from a FIFO" "$id" "$($SH image pull "docker-archive:$t/fifo" 2>&1)"
    e2e_reap "$fifo_writer" "the writer of the FIFO"

    if command -v skopeo > /dev/null; then
        skopeo inspect --raw "oci-archive:$t/a.tar:v1" > /dev/null 2>&1
        check "skopeo reads our oci-archive" 0 $?
        skopeo inspect --raw "oci:$t/layout:v2" > /dev/null 2>&1
        check "skopeo reads our layout" 0 $?
        skopeo inspect --raw "dir:$t/dir" > /dev/null 2>&1
        check "skopeo reads our dir" 0 $?
        skopeo copy --src-tls-verify=false --dest-compress --dest-compress-format gzip --dest-force-compress-format "docker://$IMG" "dir:$t/skdir" > /dev/null 2>&1
        skopeo copy --src-tls-verify=false --dest-compress --dest-compress-format gzip --dest-force-compress-format "docker://$IMG" "oci:$t/sklayout:sk" > /dev/null 2>&1
        skopeo copy --src-tls-verify=false --dest-compress --dest-compress-format gzip --dest-force-compress-format "docker://$IMG" "oci-archive:$t/sk.tar:sk" > /dev/null 2>&1
        check "pull a dir: of skopeo" "$id" "$($SH image pull "dir:$t/skdir" 2>&1)"
        check "pull an oci: of skopeo" "$id" "$($SH image pull "oci:$t/sklayout:sk" 2>&1)"
        check "pull an oci-archive: of skopeo" "$id" "$($SH image pull "oci-archive:$t/sk.tar:sk" 2>&1)"
    fi

    check "containers-storage: is the store" "$id" "$($SH image pull "containers-storage:$IMG" 2>&1)"
    $SH image pull "containers-storage:localhost/e2e-not-there:1" > /dev/null 2>&1
    check "containers-storage: of an image that is not there" 125 $?

    for ref in docker-daemon:alpine rootfs:$t; do
        out=$($SH image push "$IMG" "$ref" 2>&1)
        check "push to $ref is refused" 125 $?
        check_match "...a source, not a destination" "is a source of a pull" "$out"
    done
    out=$($SH image pull "registry://x/y" 2>&1)
    check "an unknown transport" 125 $?
    check_match "...is a scheme no [[transports]] has" "no transport is configured for registry://" "$out"
    out=$($SH image push "$IMG" "docker-archive:$t/x.tar" 2>&1)
    check "push to docker-archive:" 125 $?
    check_match "...refused by the rule" "Docker image formats are not supported" "$out"
    # the selector is checked as podman checks it, before the file is read
    for sel in ":" ":@-1" ":@x" ":Upper"; do
        $SH image pull "docker-archive:$t/none.tar$sel" > /dev/null 2>&1
        check "docker-archive:FILE$sel is an invalid name" 125 $?
    done

    # the docker-archive: a `podman save` archive is read as `load` reads
    # it, with podman's selector (`:REF`, `:@N`, none = the one image)
    command -v podman > /dev/null || skip "no podman for a docker-archive"
    $PODMAN pull -q --tls-verify=false "docker://$IMG" > /dev/null 2>&1 3>&- || skip "podman pull failed"
    $PODMAN save -o "$t/da.tar" "$IMG" > /dev/null 2>&1 3>&-
    check "podman save wrote the docker-archive" 0 $?
    $SH image remove "$IMG" > /dev/null 2>&1
    out=$($SH image pull "docker-archive:$t/da.tar" 2>&1)
    check "pull a podman save archive" "$id" "$out"
    check "...named after its RepoTags" "$id" \
        "$($SH image inspect --format '{{.Id}}' "$IMG")"
    out=$($SH container run --rm "docker-archive:$t/da.tar" echo ran-docker-archive 2>&1)
    check "run of the docker-archive transport" "ran-docker-archive" "$out"
    # a multi-image archive (-m): the selector picks one, none is an error.
    # (the second image is made here, from a file; two names of one image
    # are one manifest entry of `podman save -m`)
    $PODMAN tag "$IMG" localhost/e2e-da:v2 2>/dev/null 3>&-
    mkdir -p "$t/other" && echo other > "$t/other/file"
    tar -C "$t/other" -cf "$t/other.tar" file
    $PODMAN import -q "$t/other.tar" localhost/e2e-da:other > /dev/null 2>&1 3>&-
    check "podman made the second image" 0 $?
    $PODMAN save -m -o "$t/da-multi.tar" localhost/e2e-da:v2 \
        localhost/e2e-da:other > /dev/null 2>&1 3>&-
    entries=$(tar -xOf "$t/da-multi.tar" manifest.json | python3 -I -c 'import json, sys; print(len(json.load(sys.stdin)))')
    check_match "the multi-image archive has two images" "^2$" "$entries"
    out=$($SH image pull "docker-archive:$t/da-multi.tar" 2>&1)
    check "a multi-image archive without a selector" 125 $?
    check_match "...says what it has and how to name one" "expected 1 image in manifest.json, got 2.*docker-archive:FILE:REF or docker-archive:FILE:@N" "$out"
    out=$($SH image pull "docker-archive:$t/da-multi.tar:localhost/e2e-da:v2" 2>&1)
    check "...:REF selects the image whose RepoTags has it" "$id" "$out"
    other=$($PODMAN image inspect --format '{{.Id}}' localhost/e2e-da:other 2>/dev/null 3>&-)
    out=$($SH image pull "docker-archive:$t/da-multi.tar:localhost/e2e-da:other" 2>&1)
    check "...the other reference selects the other image" "${other#sha256:}" "$out"
    out=$($SH image pull "docker-archive:$t/da-multi.tar:@1" 2>&1)
    check "...@1 is the second entry" "${other#sha256:}" "$out"
    out=$($SH image pull "docker-archive:$t/da-multi.tar:@2" 2>&1)
    check "...@2 is past the end" 125 $?
    check_match "...and says how many there are" "only 2 manifest items available" "$out"
    out=$($SH image pull "docker-archive:$t/da-multi.tar:localhost/nope:1" 2>&1)
    check "...a reference no image has" 125 $?
    check_match "...says the names it has" "no image named .localhost/nope:1." "$out"
    $SH image remove localhost/e2e-da:v2 localhost/e2e-da:other > /dev/null 2>&1
    # (the name of $IMG is the archive's image: the registry's again for the
    # tests that follow)
    $SH image remove "$IMG" > /dev/null 2>&1
    $SH image pull --tls-verify=false "$IMG" > /dev/null 2>&1
    check "the image of the registry is back" "$id" "$($SH image inspect --format '{{.Id}}' "$IMG")"
}

# podman's options of push: the digest file, the level of a compression, the
# retries, the no-ops of podman; signing and encryption refused by name
@test "push: --digestfile, --compression-level, --retry, the refusals" {
    $SH image push --tls-verify=false --digestfile "$WORKDIR/digest" --retry 2 --retry-delay 1s \
        --remove-signatures --disable-content-trust "$IMG" "$REG/e2e/alpine:digestfile" > /dev/null 2>&1
    check "push --digestfile" 0 $?
    check_match "the digest file has the digest" "^sha256:[0-9a-f]{64}$" "$(cat "$WORKDIR/digest")"
    remote=$(curl -s -o /dev/null -w '%header{docker-content-digest}' \
        -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$REG/v2/e2e/alpine/manifests/digestfile")
    check "...the one the registry has" "$remote" "$(cat "$WORKDIR/digest")"
    $SH image push --tls-verify=false --compression-format gzip --compression-level 1 \
        --force-compression "$IMG" "$REG/e2e/alpine:level1" > /dev/null 2>&1
    check "push --compression-level" 0 $?
    out=$($SH image push --tls-verify=false --compression-format gzip --compression-level 12 "$IMG" "$REG/e2e/alpine:x" 2>&1)
    check "a level gzip has not" 125 $?
    check_match "...says why" "invalid compression level 12 for gzip" "$out"
    out=$($SH image push --tls-verify=false --compression-level 3 "$IMG" "$REG/e2e/alpine:x" 2>&1)
    check_match "a level without a compression format" "needs a compression format" "$out"
    for opt in --sign-by-sigstore=/p --sign-by-sq-fingerprint=f; do
        out=$($SH image push --tls-verify=false "$opt" "$IMG" "$REG/e2e/alpine:x" 2>&1)
        check "push $opt is refused" 125 $?
        check_match "push $opt: by name" "^Error: ${opt%%=*} is not supported for push: " "$out"
    done
    # (signing with a sigstore key is signing.bats's)
    out=$($SH image push --tls-verify=false --sign-passphrase-file=/p "$IMG" "$REG/e2e/alpine:x" 2>&1)
    check "push --sign-passphrase-file alone is refused" 125 $?
    check_match "...says why" "requires --sign-by-sigstore-private-key" "$out"
    out=$($SH image push --tls-verify=false --sign-by-sigstore-private-key=/nonexistent "$IMG" "$REG/e2e/alpine:x" 2>&1)
    check "push with a missing key is refused" 125 $?
    check_match "...says why" "reading the signing key /nonexistent" "$out"
    out=$($SH image push --encryption-key jwe:/k "$IMG" "$REG/e2e/alpine:x" 2>&1)
    check_match "push --encryption-key is refused" "velarx pushes no encrypted image" "$out"
    out=$($SH image push --compress "$IMG" "$REG/e2e/alpine:x" 2>&1)
    check_match "push --compress is for dir:" "dir: transport" "$out"
}

@test "push --compress to dir: writes gzip layers that pull back to the same image" {
    id=$($SH image inspect --format '{{.Id}}' "$IMG")
    $SH image push --compress "$IMG" "dir:$WORKDIR/gzdir" > /dev/null 2>&1
    check "push --compress dir:" 0 $?
    types=$(python3 -I -c 'import json,sys; print(" ".join(sorted({l["mediaType"] for l in json.load(open(sys.argv[1]))["layers"]})))' "$WORKDIR/gzdir/manifest.json")
    check "the layers are gzip" "application/vnd.oci.image.layer.v1.tar+gzip" "$types"
    check "pull it back" "$id" "$($SH image pull "dir:$WORKDIR/gzdir" 2>&1)"
}

@test "manifest push: --add-compression, --compression-level, --format, rm --ignore" {
    tag=e2e-ac-$$
    $SH manifest create "localhost/e2e-ac:$tag" > /dev/null
    $SH manifest annotate --index --annotation "e2e.run=$tag" "localhost/e2e-ac:$tag" > /dev/null
    $SH manifest add --tls-verify=false "localhost/e2e-ac:$tag" "$IMG" > /dev/null
    $SH manifest push -q --tls-verify=false --compression-format gzip --compression-level 9 \
        --add-compression zstd --digestfile "$WORKDIR/list.digest" \
        "localhost/e2e-ac:$tag" "$REG/e2e/ac:$tag" > /dev/null 2>&1
    check "manifest push --add-compression" 0 $?
    index=$(curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$REG/v2/e2e/ac/manifests/$tag")
    out=$(python3 -I -c 'import json,sys; d=json.loads(sys.argv[1]); print(len(d["manifests"]), sum(1 for m in d["manifests"] if m.get("annotations",{}).get("io.github.containers.compression.zstd")=="true"))' "$index")
    check "the gzip instance and its zstd variant" "2 1" "$out"
    out=$($SH manifest push --tls-verify=false --format v2s2 "localhost/e2e-ac:$tag" "$REG/e2e/ac:$tag" 2>&1)
    check_match "manifest push --format v2s2 is refused" "Docker image formats are not supported" "$out"
    out=$($SH manifest push --tls-verify=false --sign-by k "localhost/e2e-ac:$tag" "$REG/e2e/ac:$tag" 2>&1)
    check_match "manifest push --sign-by is refused" "^Error: --sign-by is not supported for manifest push: " "$out"
    $SH manifest rm "localhost/e2e-ac:$tag" > /dev/null
    $SH manifest rm "localhost/e2e-ac:$tag" > /dev/null 2>&1
    check "manifest rm of a list that is not there" 1 "$(( $? != 0 ))"
    out=$($SH manifest rm --ignore "localhost/e2e-ac:$tag" 2>&1)
    check "manifest rm --ignore" "0 " "$? $out"
}

@test "import --arch --os --variant, save --uncompressed, pull --disable-content-trust" {
    printf 'x' > "$WORKDIR/f" && tar -cf "$WORKDIR/one.tar" -C "$WORKDIR" f
    $SH image import -q --arch arm64 --variant v8 "$WORKDIR/one.tar" e2e-arm > /dev/null
    check "import --arch" "linux/arm64" "$($SH image inspect --format '{{.Os}}/{{.Architecture}}' e2e-arm)"
    $SH image save -o "$WORKDIR/arm.tar" e2e-arm
    variant=$(python3 -I - "$WORKDIR/arm.tar" <<'PY'
import json, sys, tarfile
t = tarfile.open(sys.argv[1])
blob = lambda d: json.load(t.extractfile("blobs/sha256/" + d.split(":")[1]))
m = blob(json.load(t.extractfile("index.json"))["manifests"][0]["digest"])
print(blob(m["config"]["digest"]).get("variant"))
PY
)
    check "import --variant" "v8" "$variant"
    $SH image import -q --os freebsd "$WORKDIR/one.tar" e2e-bsd > /dev/null
    check_match "import --os, the host's architecture" "^freebsd/" "$($SH image inspect --format '{{.Os}}/{{.Architecture}}' e2e-bsd)"
    $SH image rm e2e-arm e2e-bsd > /dev/null
    $SH image save --uncompressed -o "$WORKDIR/unc.tar" "$IMG"
    check "save --uncompressed" 0 $?
    out=$($SH image save --compress -o "$WORKDIR/c.tar" "$IMG" 2>&1)
    check "save --compress is podman's error" "Error: --compress can only be set when --format is 'docker-dir'" "$out"
    $SH image pull --disable-content-trust --tls-verify=false "$IMG" > /dev/null 2>&1
    check "pull --disable-content-trust" 0 $?
}

@test "image prune --external, system prune --external" {
    $SH image prune -f --external > /dev/null
    check "image prune --external" 0 $?
    out=$($SH system prune --external 2>&1)
    check "system prune --external: no prompt, nothing printed" "0 " "$? $out"
    out=$($SH system prune --external --all 2>&1)
    check "system prune --external with another option" "Error: system prune --external cannot be combined with other options" "$out"
}

@test "search and image tree" {
    out=$($SH search --tls-verify=false "$REG/alpine")
    check_match "search: the header" "^NAME +DESCRIPTION$" "$out"
    check_match "search: the repository of the catalog" "^$REG/alpine" "$out"
    out=$($SH image search --tls-verify=false --list-tags --limit 50 "$REG/alpine")
    check_match "search --list-tags" "^$REG/alpine +chunked$" "$out"
    out=$($SH search --tls-verify=false --list-tags --format json "$REG/alpine")
    check "search --list-tags --format json" "chunked" "$(python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(t for t in d[0]["Tags"] if t=="chunked"))' <<< "$out")"
    out=$($SH search --tls-verify=false --format '{{.Name}}|{{.Official}}' "$REG/alpine")
    check_match "search --format" "^$REG/alpine\|$" "$out"
    out=$($SH search --list-tags --filter stars=1 "$REG/alpine" 2>&1)
    check "search --list-tags --filter" "Error: filters are not applicable to list tags result" "$out"
    out=$($SH image tree "$IMG")
    check_match "image tree" "^Image Layers$" "$out"
    check_match "image tree: the layers" "ID: [0-9a-f]{12} Size:" "$out"
    out=$($SH image tree --whatrequires "$IMG")
    check_match "image tree --whatrequires" "^Images built on it$" "$out"
    out=$($SH image mount "$IMG" 2>&1)
    check "image mount is refused" 125 $?
    check_match "...by name" "podman's command \`image mount\` is not supported" "$out"
}

@test "auto-update --authfile, artifact push signing" {
    out=$($SH auto-update --authfile "$WORKDIR/none.json" 2>&1)
    check_match "auto-update --authfile of a file that is not there" "credential file is not accessible" "$out"
    echo '{"auths": {}}' > "$WORKDIR/auth.json"
    $SH auto-update --dry-run --authfile "$WORKDIR/auth.json" > /dev/null
    check "auto-update --authfile" 0 $?
    out=$($SH artifact push --sign-by-sigstore /p localhost/a:1 2>&1)
    check_match "artifact push --sign-by-sigstore" "^Error: --sign-by-sigstore is not supported: velarx signs no artifact" "$out"
}
