# SPDX-License-Identifier: Apache-2.0
# End to end tests of the REST API, the build cache: the
# intermediate images kept by a build (--layers, the default) and taken by
# the next one for the same steps on the same image; --no-cache,
# --layers=false, the listing and the prune of the cache (see
# api_helpers.bash).

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}

@test "build cache" {
    local ctx=$WORKDIR/cache-context
    mkdir -p "$ctx"
    printf 'one\n' > "$ctx/f"
    cat > "$ctx/Containerfile" <<EOT
FROM $IMG
ARG V=1
ENV E=e
RUN echo run-\$V > /v
COPY f /app/
LABEL x=y
EOT
    cbuild () { "$CLI" image build --tls-verify=false "$@" "$ctx" 2>&1; }
    hits () { printf '%s\n' "$1" | grep -c "Using cache"; }

    out=$(cbuild -t cache:1)
    check "first build" 0 "$(hits "$out")"
    id1=$(pm image inspect localhost/cache:1 --format '{{.Id}}')
    out=$(cbuild -t cache:2)
    check "the same build: RUN, COPY and the configuration from the cache" 3 "$(hits "$out")"
    check "the same image" "$id1" "$(pm image inspect localhost/cache:2 --format '{{.Id}}')"
    check "its content" "run-1 one" "$(pm run --rm localhost/cache:2 sh -c 'echo $(cat /v /app/f)' 2>&1)"

    out=$(cbuild --build-arg V=2 -t cache:arg)
    check "another build argument runs the RUN again" 0 "$(hits "$out")"
    check "and its content" "run-2" "$(pm run --rm localhost/cache:arg cat /v 2>&1)"

    printf 'two\n' > "$ctx/f"
    out=$(cbuild -t cache:file)
    check "another file: the RUN only from the cache" 1 "$(hits "$out")"
    check "the new file" "two" "$(pm run --rm localhost/cache:file cat /app/f 2>&1)"
    printf 'one\n' > "$ctx/f"
    out=$(cbuild -t cache:back)
    check "the file as it was: all from the cache" 3 "$(hits "$out")"
    check "the first image" "$id1" "$(pm image inspect localhost/cache:back --format '{{.Id}}')"
    # The files of the context are checked before they are copied: their
    # times are not, their modes are.
    touch -d '2001-01-01' "$ctx/f"
    out=$(cbuild -t cache:touched)
    check "a file of other times: all from the cache" 3 "$(hits "$out")"
    chmod 600 "$ctx/f"
    out=$(cbuild -t cache:mode)
    check "a file of another mode: the RUN only from the cache" 1 "$(hits "$out")"
    chmod 644 "$ctx/f"

    # COPY --from a stage or an image: the cache is asked before the files
    # are read, by the image's manifest.
    local multi=$WORKDIR/cache-multi
    mkdir -p "$multi"
    cat > "$multi/Containerfile" <<EOT
FROM $IMG AS builder
RUN echo built > /out
FROM $IMG
COPY --from=builder /out /app/out
COPY --from=$IMG /etc/os-release /app/
EOT
    mbuild () { "$CLI" image build --tls-verify=false "$@" "$multi" 2>&1; }
    out=$(mbuild -t cache:multi1)
    check "a build with COPY --from" "built" "$(pm run --rm localhost/cache:multi1 cat /app/out 2>&1)"
    out=$(mbuild -t cache:multi2)
    check "COPY --from a stage and an image from the cache" 3 "$(hits "$out")"
    check "the same content" "built" "$(pm run --rm localhost/cache:multi2 cat /app/out 2>&1)"
    sed -i 's/echo built/echo rebuilt/' "$multi/Containerfile"
    out=$(mbuild -t cache:multi3)
    check "another stage: COPY --from it again, the image's from the cache" "rebuilt" \
          "$(pm run --rm localhost/cache:multi3 cat /app/out 2>&1)"
    pm rmi localhost/cache:multi1 localhost/cache:multi2 localhost/cache:multi3 > /dev/null 2>&1

    out=$(cbuild --no-cache -t cache:nocache)
    check "--no-cache" 0 "$(hits "$out")"
    test "$(pm image inspect localhost/cache:nocache --format '{{.Id}}')" != "$id1"
    check "--no-cache makes a new image" 0 $?

    all_before=$(pm images -a -q | sort -u | wc -l)
    out=$(cbuild --layers=false --build-arg V=3 -t cache:nolayers)
    check "--layers=false does not use the cache" 0 "$(hits "$out")"
    check "--layers=false keeps no intermediate image" "$((all_before + 1))" "$(pm images -a -q | sort -u | wc -l)"
    out=$(cbuild --build-arg V=3 -t cache:nolayers2)
    check "nor records it" 0 "$(hits "$out")"

    # podman --remote: the API keeps the layers too.
    out=$(pm build --tls-verify=false -t localhost/cache:remote "$ctx" 2>&1)
    check "podman build takes the cache" 3 "$(hits "$out")"
    # podman build --layers=false sends no `layers`: nothing is kept but
    # the image (podman's import test checks no image is left).
    all_before=$(pm images -a -q | sort -u | wc -l)
    dangling_before=$(pm images -q --filter dangling=true | sort -u)
    out=$(pm build --tls-verify=false --layers=false --build-arg V=4 -t localhost/cache:remote-nolayers "$ctx" 2>&1)
    check "podman build --layers=false does not use the cache" 0 "$(hits "$out")"
    check "podman build --layers=false keeps no intermediate image" "$((all_before + 1))" \
          "$(pm images -a -q | sort -u | wc -l)"
    check "nor a dangling one" "$dangling_before" "$(pm images -q --filter dangling=true | sort -u)"

    # Listing: the intermediate images with all only, with their parent.
    shown=$(pm images -q | sort -u | wc -l)
    all=$(pm images -a -q | sort -u | wc -l)
    test "$all" -gt "$shown"
    check "intermediate images shown with --all" 0 $?
    short=$(printf %.12s "$id1")
    parent=$(api "http://d/v5.0.0/libpod/images/json?all=true" | jq -r ".[] | select(.Id == \"$id1\") | .ParentId")
    check_match "the parent of a built image" '^[0-9a-f]{64}$' "$parent"
    check "an intermediate image is not dangling" false \
          "$(api "http://d/v5.0.0/libpod/images/json?all=true" | jq -r ".[] | select(.Id == \"$parent\") | .Dangling")"

    # A prune leaves the cache of named images.
    pm image prune -f > /dev/null 2>&1
    out=$(cbuild -t cache:afterprune)
    check "the cache after an image prune" 3 "$(hits "$out")"

    # Without the names, builder prune removes it all.
    pm rmi localhost/cache:1 localhost/cache:2 localhost/cache:arg localhost/cache:file localhost/cache:back \
       localhost/cache:touched localhost/cache:mode localhost/cache:nocache localhost/cache:nolayers localhost/cache:nolayers2 localhost/cache:remote localhost/cache:remote-nolayers \
       localhost/cache:afterprune > /dev/null 2>&1
    n=$(api -X POST http://d/v1.41/build/prune | jq '.CachesDeleted | length')
    test "$n" -ge 4
    check "builder prune" 0 $?
    test "$(pm images -a -q | grep -c "^$short")" = 0
    check "the built images are gone" 0 $?
    out=$(cbuild -t cache:1)
    check "no cache after builder prune" 0 "$(hits "$out")"
    pm rmi localhost/cache:1 > /dev/null 2>&1
    api -X POST http://d/v1.41/build/prune > /dev/null
}
