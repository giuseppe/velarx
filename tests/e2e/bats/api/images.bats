# SPDX-License-Identifier: Apache-2.0
# End to end tests of the REST API, images: pull, inspect,
# filters, remove, search, save and load, import, push, untag, build (see
# api_helpers.bash).

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}

# The credentials and certificates of a pull: --cert-dir, --creds and
# --authfile of the CLI, X-Registry-Auth of podman.
@test "registry access: --cert-dir, --creds, --authfile, X-Registry-Auth" {
    sh_cli () {
        timeout 120 "$CLI" --socket "$ESOCK" "$@"
    }
    ca=${E2E_TLS_CA:-}
    tlsimg=$E2E_TLS_REGISTRY/alpine:chunked
    if ! test -r "$ca" || ! curl -s -m 2 --cacert "$ca" https://$E2E_TLS_REGISTRY/v2/ > /dev/null; then
        skip "no TLS registry on $E2E_TLS_REGISTRY (E2E_TLS_CA is its CA file)"
    fi
    mkdir -p "$WORKDIR/certs"
    cp "$ca" "$WORKDIR/certs/ca.crt"
    if curl -s -m 2 https://$E2E_TLS_REGISTRY/v2/ > /dev/null; then
        note_skip "pull without --cert-dir fails" "the CA is trusted by the system"
    else
        sh_cli image pull "$tlsimg" > /dev/null 2>&1
        check "pull without --cert-dir fails" 125 $?
    fi
    sh_cli image pull --cert-dir "$WORKDIR/certs" "$tlsimg" > /dev/null 2>&1
    check "pull with --cert-dir" 0 $?
    sh_cli image pull --cert-dir "$WORKDIR/nope" "$tlsimg" > /dev/null 2>&1
    check "pull with a missing --cert-dir" 125 $?
    # the registries need no credentials: they must only be accepted
    sh_cli image pull --tls-verify=false --creds u:p "$IMG" > /dev/null 2>&1
    check "pull with --creds" 0 $?
    sh_cli image pull --tls-verify=false --creds ":p" "$IMG" > /dev/null 2>&1
    check "pull with invalid --creds" 125 $?
    echo '{"auths": {"'"$E2E_REGISTRY"'": {"auth": "dTpw"}}}' > "$WORKDIR/auth.json"
    sh_cli image pull --tls-verify=false --authfile "$WORKDIR/auth.json" "$IMG" > /dev/null 2>&1
    check "pull with --authfile" 0 $?
    echo '{broken' > "$WORKDIR/bad.json"
    sh_cli image pull --tls-verify=false --authfile "$WORKDIR/bad.json" "$IMG" > /dev/null 2>&1
    check "pull with a broken --authfile" 125 $?
    pm pull --tls-verify=false --creds u:p "$IMG" > /dev/null 2>&1
    check "podman pull with X-Registry-Auth" 0 $?
    out=$(api -o /dev/null -w '%{http_code}' -X POST -H 'X-Registry-Auth: %%%' "http://d/v5.0.0/libpod/images/pull?reference=$IMG&tlsVerify=false")
    check "an invalid X-Registry-Auth" 400 "$out"
}

@test "pull, inspect, tag, filters, remove" {
    e2e_registry_up || skip "no registry on $E2E_REGISTRY"
    out=$(pm pull --tls-verify=false "$IMG" 2>&1 | tail -1)
    check_match "pull prints the id" "^[0-9a-f]{64}$" "$out"
    out=$(pm images --format '{{.Repository}}:{{.Tag}}' | grep -c "^${IMG%:*}:${IMG##*:}$")
    check "images lists the pulled image" 1 "$out"
    id=$(pm image inspect "$IMG" --format '{{.Id}}')
    check_match "image inspect id" "^[0-9a-f]{64}$" "$id"
    out=$(pm image inspect "$IMG" --format '{{.Os}} {{.Architecture}}')
    check_match "image inspect" "^linux " "$out"
    out=$(pm image inspect "$(echo "$id" | cut -c1-12)" --format '{{.Id}}')
    check "inspect by id prefix" "$id" "$out"
    pm image exists "$IMG"
    check "image exists" 0 $?
    pm image exists $E2E_REGISTRY/nosuch:tag
    check "image exists of a missing image" 1 $?
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/images/nosuch:tag/json)
    check "inspect of a missing image" 404 "$out"
    out=$(api http://d/v5.0.0/libpod/images/nosuch:tag/json | jq -r .cause)
    check "missing image cause" "image not known" "$out"
    out=$(pm pull --tls-verify=false $E2E_REGISTRY/nosuch:tag 2>&1 >/dev/null; echo $?)
    check_match "pull of a missing image fails" "[1-9]$" "$out"

    pm tag "$IMG" localhost/fltimg:v1
    check "tag" 0 $?
    out=$(pm images --filter reference='fltim*' --format '{{.Repository}}:{{.Tag}}' | grep -x localhost/fltimg:v1)
    check "images reference filter" "localhost/fltimg:v1" "$out"
    out=$(pm images --filter label=nolabel -q | wc -l)
    check "images label filter" 0 "$out"
    out=$(api 'http://d/v1.41/images/json?filters=%7B%22dangling%22%3A%5B%22true%22%5D%7D' | jq '[.[] | select(.RepoTags != null and (.RepoTags | length) > 0 and .RepoTags[0] != "<none>:<none>")] | length')
    check "images dangling filter" 0 "$out"
    out=$(api -o /dev/null -w '%{http_code}' 'http://d/v1.41/images/json?filters=%7B%22before%22%3A%5B%22nonexistent%22%5D%7D')
    check "images before filter of a missing image" 404 "$out"
    out=$(pm images --filter reference=localhost/fltimg -q | wc -l)
    check "images reference filter without a tag" 1 "$out"
    out=$(api 'http://d/v1.41/images/json' | jq -r '.[0].Id')
    check_match "compat image id" "^sha256:[0-9a-f]{64}$" "$out"
    out=$(pm history --format '{{.CreatedBy}}' "$IMG" | wc -l)
    check_match "history" "^[1-9]" "$out"
    pm untag localhost/fltimg:v1 localhost/fltimg:v1
    check "untag" 0 $?
    out=$(pm images --filter reference='fltim*' -q | wc -l)
    check "untag removes the name" 0 "$out"
    pm tag "$IMG" localhost/rmtest:a
    pm tag "$IMG" localhost/rmtest:b
    out=$(pm rmi localhost/rmtest:a | tr '\n' ' ')
    check "rmi of one of two names" "Untagged: localhost/rmtest:a " "$out"
    pm image exists "$IMG"
    check "rmi of a name keeps the image" 0 $?
    pm rmi localhost/rmtest:b > /dev/null
    pm rmi -i localhost/nosuch:x > /dev/null 2>&1
    check "rmi --ignore of a missing image" 0 $?
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v5.0.0/libpod/images/localhost%2Fnosuch:x?ignore=true")
    check "image remove with ignore" 200 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v1.41/images/localhost%2Fnosuch:x?ignore=true")
    check "compat image remove with ignore" 200 "$code"
    # a removed image is downloaded again: its layers went with it
    other=$E2E_REGISTRY/e2e/alpine:gzip
    pm pull -q --tls-verify=false "$other" > /dev/null 2>&1
    pm rmi "$other" > /dev/null
    out=$(api -X POST "http://d/v1.41/images/create?fromImage=$other" 2>&1)
    check "a removed image is pulled again" 0 "$(echo "$out" | grep -c 'Already exists')"
    check_match "and its layers downloaded" "Pull complete|Download complete" "$out"
    pm rmi "$other" > /dev/null 2>&1
}

# The removal of an image never takes the files of a container that uses
# another one: the release of the layers keeps the container's.
@test "remove of an image does not take the files of a container of another" {
    a=$E2E_REGISTRY/e2e/alpine:gzip
    b=$E2E_REGISTRY/sh-store/alpine:fmt
    pm pull -q --tls-verify=false "$a" > /dev/null 2>&1
    pm pull -q --tls-verify=false "$b" > /dev/null 2>&1
    pm create --name rmistop "$a" cat /etc/alpine-release > /dev/null
    pm run -d --name rmirun "$a" sleep 1000 > /dev/null
    pm rmi "$b" > /dev/null
    out=$(pm start -a rmistop 2>&1)
    check_match "a stopped container keeps its files when another image goes" "^[0-9.]+$" "$out"
    out=$(pm exec rmirun cat /etc/alpine-release 2>&1)
    check_match "a running one too" "^[0-9.]+$" "$out"
    pm rm -t 0 -f rmistop rmirun > /dev/null
    pm rmi "$a" > /dev/null 2>&1
}

# velarx image rm: podman's semantics
@test "velarx image rm" {
    [ -x "$CLI" ] || skip "no velarx CLI at $CLI"
    sc () { timeout 60 "$CLI" --socket "$ESOCK" "$@"; }
    pm tag "$IMG" localhost/clirm:a
    pm tag "$IMG" localhost/clirm:b
    out=$(sc image rm localhost/clirm:a)
    check "image rm of one of its names untags it" "Untagged: localhost/clirm:a" "$out"
    check "and keeps the image" 0 "$(pm image exists localhost/clirm:b; echo $?)"
    dig=$(pm image inspect --format '{{.Digest}}' localhost/clirm:b)
    check "images --filter reference=REPO@DIGEST lists the image" 1 "$(sc images -q --filter "reference=localhost/clirm@$dig" | sort -u | wc -l)"
    out=$(sc image rm "localhost/clirm@$dig" 2>&1)
    check "image rm of NAME@DIGEST untags the reference" "Untagged: localhost/clirm@$dig" "$out"
    check "and keeps the image" 0 "$(pm image exists localhost/clirm:b; echo $?)"
    check "tag prints nothing" "" "$(sc tag localhost/clirm:b clirm2:x localhost/clirm3:y 2>&1)"
    check "tag names a short name as localhost" "localhost/clirm2:x localhost/clirm3:y" \
        "$(sc images --format '{{.Repository}}:{{.Tag}}' localhost/clirm2 | grep -x localhost/clirm2:x) $(sc images --format '{{.Repository}}:{{.Tag}}' localhost/clirm3 | grep -x localhost/clirm3:y)"
    check "images REPO lists every name of the image" "localhost/clirm2:x localhost/clirm3:y localhost/clirm:b $E2E_REGISTRY/alpine:chunked" \
        "$(sc images --format '{{.Repository}}:{{.Tag}}' localhost/clirm | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
    check "images REPO:TAG lists that name only" "localhost/clirm:b" \
        "$(sc images --format '{{.Repository}}:{{.Tag}}' localhost/clirm:b | tr '\n' ' ' | sed 's/ $//')"
    check "the reference filter REPO:TAG through the API too" "localhost/clirm:b" \
        "$(pm images --format '{{.Repository}}:{{.Tag}}' --filter reference=localhost/clirm:b | tr '\n' ' ' | sed 's/ $//')"
    cid=$(pm image inspect localhost/clirm:b --format '{{.Id}}')
    check "rmi by the ID of an image with several names is refused" "125" "$(sc rmi "$cid" > /dev/null 2>&1; echo $?)"
    out=$(pm rmi "$cid" 2>&1)
    check_match "and through the API (podman-remote)" "125 .*by ID with more than one tag .*please force removal" "$? $out"
    check "images --sort tag" "b chunked x y" "$(sc images --sort tag --format '{{.Tag}}' --filter 'reference=localhost/clirm*' | tr '\n' ' ' | sed 's/ $//')"
    sc rmi localhost/clirm2:x localhost/clirm3:y > /dev/null 2>&1
    # The gzip variant of the image is the same image as IMG (one
    # configuration, two manifests: podman's one image), so it has all the
    # names of both and `rm` by its ID is refused.
    same=$E2E_REGISTRY/e2e/alpine:gzip
    pm pull -q --tls-verify=false "$same" > /dev/null 2>&1
    sc image rm "$(pm image inspect "$same" --format '{{.Id}}')" > /dev/null 2>&1
    check "image rm by ID of the variants of one image with several names fails with 125" "125 0" "$?$(pm image exists "$same"; echo " $?")"
    pm rmi "$same" > /dev/null 2>&1
    # an image of its own (another configuration), with two names
    other=localhost/clirm-used:1
    pm create --name clirmx "$IMG" true > /dev/null
    pm export -o "$WORKDIR/clirm-used.tar" clirmx > /dev/null 2>&1
    pm rm clirmx > /dev/null 2>&1
    pm import -q "$WORKDIR/clirm-used.tar" "$other" > /dev/null 2>&1
    pm tag "$other" localhost/clirm:c
    id=$(pm image inspect "$other" --format '{{.Id}}')
    pm create --name clirmc "$other" true > /dev/null
    sc image rm "$id" > /dev/null 2>&1
    check "image rm by ID of an image with two names fails with 125" "125 0" "$?$(pm image exists "$other"; echo " $?")"
    sc image rm localhost/clirm:c > /dev/null 2>&1
    sc image rm "$id" > /dev/null 2>&1
    check "image rm of an image in use fails with 2" "2 0" "$?$(pm image exists "$other"; echo " $?")"
    out=$(sc image rm -f "$id" 2>&1)
    check_match "image rm -f by id removes its names and its containers" \
        "Untagged: .*Deleted: " "$(echo $out)"
    check "the names, the image and the container are gone" "1 1 1" \
        "$(pm image exists "$other"; echo -n "$? "; pm image exists localhost/clirm:c; echo -n "$? "; pm container exists clirmc; echo $?)"
    sc image rm localhost/nosuch:x > /dev/null 2>&1
    check "image rm of a missing image fails" 1 $?
    check "image rm needs an image" "Error: image name or ID must be specified 125" "$(echo $(sc image rm 2>&1; echo $?))"
    out=$(sc image rm -f localhost/nosuch:x 2>&1)
    check "image rm -f of a missing image is silent" "0:" "$?:$out"
    pm rmi localhost/clirm:b > /dev/null 2>&1
}

# Image ids as podman resolves them (libimage LookupImage): a full id is an
# id and nothing else, any other reference is a name first and then an id or
# its unique prefix; sha256: wants the whole digest; capitals are no id.
@test "image ids" {
    sh_cli () {
        timeout 120 "$CLI" --socket "$ESOCK" "$@"
    }
    second=$E2E_REGISTRY/e2e/alpine:gzip
    pm pull -q --tls-verify=false "$IMG" > /dev/null 2>&1
    pm pull -q --tls-verify=false "$second" > /dev/null 2>&1
    id=$(api "http://d/v5.0.0/libpod/images/$IMG/json" | jq -r .Id)
    other_id=$(api "http://d/v5.0.0/libpod/images/$second/json" | jq -r .Id)
    check_match "libpod Id is the whole id" "^[0-9a-f]{64}$" "$id"
    check "compat Id has sha256:" "sha256:$id" "$(api "http://d/v1.41/images/$IMG/json" | jq -r .Id)"
    for ref in "${id:0:12}" "${id:0:20}" "$id" "sha256:$id"; do
        check "libpod json of $ref" "$id" "$(api "http://d/v5.0.0/libpod/images/$ref/json" | jq -r .Id)"
        check "compat json of $ref" "sha256:$id" "$(api "http://d/v1.41/images/$ref/json" | jq -r .Id)"
        pm image exists "$ref"
        check "exists $ref" 0 $?
    done
    check "inspect by the short id" "$id" "$(sh_cli image inspect --format '{{.Id}}' "${id:0:12}")"
    check_match "the list shows 12 digits" "^${id:0:12}\$" "$(sh_cli image list --format '{{.ID}}' | grep "^${id:0:12}")"
    
    out=$(api "http://d/v5.0.0/libpod/images/sha256:${id:0:12}/json")
    check "sha256: with a short id" "404 sha256:${id:0:12}: invalid format: no 64-byte hexadecimal value" \
        "$(echo "$out" | jq -r '"\(.response) \(.cause)"')"
    out=$(api "http://d/v5.0.0/libpod/images/${id:0:12}x/json")
    check "a prefix that is none" "404 image not known" "$(echo "$out" | jq -r '"\(.response) \(.cause)"')"
    up=$(echo "${id:0:12}" | tr a-f A-F)
    case $up in *[A-F]*)
        out=$(api "http://d/v5.0.0/libpod/images/$up/json")
        check "capitals" "404 repository name must be lowercase" "$(echo "$out" | jq -r '"\(.response) \(.cause)"')"
        out=$(sh_cli image inspect "$up" 2>&1)
        check "capitals: the CLI" "Error: parsing reference \"$up\": repository name must be lowercase 125" "$out $?"
        ;;
    esac
    out=$(sh_cli image inspect "sha256:${id:0:12}" 2>&1)
    check "sha256: with a short id: the CLI" "Error: sha256:${id:0:12}: invalid format: no 64-byte hexadecimal value" "$out"

    out=$(sh_cli image rm "sha256:${id:0:12}" 2>&1)
    check "rm of sha256: with a short id" "Error: sha256:${id:0:12}: invalid format: no 64-byte hexadecimal value 125" "$out $?"
    out=$(sh_cli image rm nosuch1 nosuch2 2>&1)
    rc=$?
    check "rm of two missing images is go-multierror's" "Error: 2 errors occurred:|	* nosuch1: image not known|	* nosuch2: image not known|1" "$(echo "$out" | grep . | tr '\n' '|')$rc"
    out=$(sh_cli image tag "sha256:${id:0:12}" localhost/idtag:1 2>&1)
    check "tag of sha256: with a short id" "Error: sha256:${id:0:12}: invalid format: no 64-byte hexadecimal value 125" "$out $?"
    out=$(sh_cli run --rm "sha256:${id:0:12}" true 2>&1)
    check "run of sha256: with a short id is not a pull" "Error: sha256:${id:0:12}: invalid format: no 64-byte hexadecimal value 125" "$out $?"
    check "run by the short id" "$(sh_cli run --rm --network none "${id:0:12}" echo hi 2>&1)" "hi"
    check "list --no-trunc shows sha256: and the 64 digits" "sha256:$id" "$(sh_cli image list --no-trunc --format '{{.ID}}' | grep "${id:0:12}" | head -1)"
    check "list -q --no-trunc too" "sha256:$id" "$(sh_cli image list -q --no-trunc | grep "${id:0:12}" | head -1)"

    # a name wins over an id prefix
    sh_cli image tag "$second" "${id:0:12}" > /dev/null 2>&1
    check "a name that is an id prefix is the name" "$other_id" "$(sh_cli image inspect --format '{{.Id}}' "${id:0:12}")"
    check "while the whole id is the id" "$id" "$(sh_cli image inspect --format '{{.Id}}' "$id")"
    sh_cli image untag "$second" "localhost/${id:0:12}:latest" > /dev/null 2>&1
    pm rmi "$second" > /dev/null 2>&1
}

# the size an image prune reports is what the removal freed: the layer of the
# image, 2 MiB here, not the whole image (podman's) with the layers of the
# image it is made on
@test "image prune reports what it freed, libpod's Size and Docker's SpaceReclaimed" {
    e2e_registry_up || skip "no registry on $E2E_REGISTRY"
    pm pull --tls-verify=false "$IMG" > /dev/null 2>&1
    pm image prune -f > /dev/null 2>&1
    for n in 1 2; do
        pm run --name prunec$n "$IMG" sh -c "head -c 2097152 /dev/urandom > /f$n" > /dev/null 2>&1
        "$CLI" image commit -q prunec$n > /dev/null
        pm rm prunec$n > /dev/null 2>&1
    done
    out=$(api -X POST http://d/v5.0.0/libpod/images/prune | jq -c '[.[].Size | . >= 2097152 and . < 3145728]')
    check "libpod prune: the size of each is its own layer" "[true,true]" "$out"
    pm run --name prunec3 "$IMG" sh -c "head -c 2097152 /dev/urandom > /f3" > /dev/null 2>&1
    "$CLI" image commit -q prunec3 > /dev/null
    pm rm prunec3 > /dev/null 2>&1
    out=$(api -X POST http://d/v1.41/images/prune | jq -c '[(.ImagesDeleted | length), (.SpaceReclaimed >= 2097152 and .SpaceReclaimed < 3145728)]')
    check "Docker prune: the space is what it freed" "[1,true]" "$out"
    out=$(api -X POST http://d/v1.41/images/prune | jq -c '.SpaceReclaimed')
    check "and nothing the second time" "0" "$out"
}

@test "image prune, resolve, search" {
    pm rmi localhost/nosuch:x > /dev/null 2>&1
    check "rmi of a missing image" 1 $?
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v1.41/images/localhost/nosuch:x)
    check "compat image delete of a missing image" 404 "$out"
    pm image prune -f > /dev/null
    check "image prune" 0 $?

    out=$(api http://d/v5.6.0/libpod/images/$E2E_REGISTRY%2Falpine%3Achunked/resolve | jq -r '.Names[0]')
    check "image resolve" "$E2E_REGISTRY/alpine:chunked" "$out"
    out=$(pm search --tls-verify=false --format '{{.Name}}' $E2E_REGISTRY/alpine | grep -x $E2E_REGISTRY/alpine)
    check "search" "$E2E_REGISTRY/alpine" "$out"
    out=$(api 'http://d/v1.41/images/search?term='"$E2E_REGISTRY"'/alpine&tlsVerify=false' | jq -r '[.[].name | select(. == "'"$E2E_REGISTRY"'/alpine")][0]')
    check "compat search (podman's names)" "$E2E_REGISTRY/alpine" "$out"
    check "compat search of nothing" 404 \
          "$(api -o /dev/null -w '%{http_code}' 'http://d/v1.41/images/search?term='"$E2E_REGISTRY"'/no-such-thing&tlsVerify=false')"
    out=$(pm search --tls-verify=false --list-tags --format '{{.Name}} {{.Tag}}' $E2E_REGISTRY/alpine)
    check "search --list-tags" "$E2E_REGISTRY/alpine chunked" "$out"
    out=$(pm search --tls-verify=false --list-tags $E2E_REGISTRY/alpine:chunked 2>&1)
    check_match "search --list-tags of a tag" "takes no tag" "$out"
    check "search --limit" 1 "$(pm search --tls-verify=false --limit 1 --format '{{.Name}}' $E2E_REGISTRY/alpine | wc -l)"
    check "search --filter" "" "$(pm search --tls-verify=false --filter is-official --format '{{.Name}}' $E2E_REGISTRY/alpine)"
    out=$(api 'http://d/v5.0.0/libpod/images/search?term='"$E2E_REGISTRY"'/alpine&filters=%7B%22label%22%3A%5B%22x%22%5D%7D&tlsVerify=false' | jq -r .cause)
    check_match "search with an unknown filter" "invalid filter" "$out"
    if curl -s -m 5 -o /dev/null https://index.docker.io/v1/search?q=alpine; then
        out=$(pm search --limit 3 --filter is-official --format '{{.Name}} {{.Official}}' docker.io/alpine)
        check "search docker.io" "docker.io/library/alpine [OK]" "$out"
    else
        note_skip "search docker.io" "no network"
    fi

}

@test "compat pull, distribution, save, load, export, import" {
    out=$(api -X POST 'http://d/v1.41/images/create?fromImage='"$E2E_REGISTRY"'/alpine&tag=chunked' | tail -1 | jq -r .status)
    # podman's CompatPull ends with the short id of the image
    check "compat pull" "Download complete" "$out"

    # What the registry has for a name (manifest lists: manifests.bats).
    want=$(curl -s -I -H 'Accept: application/vnd.oci.image.manifest.v1+json' http://$E2E_REGISTRY/v2/alpine/manifests/chunked \
           | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
    check "distribution" "$want" \
          "$(api http://d/v1.41/distribution/$E2E_REGISTRY/alpine:chunked/json | jq -r .Descriptor.digest)"
    pm tag "$IMG" localhost/apisaved:v1
    # podman's default format is the docker-archive: refused
    out=$(pm save -o "$WORKDIR/apisaved-docker.tar" localhost/apisaved:v1 2>&1; echo "rc=$?")
    check_match "save (docker-archive) is refused" "Docker image formats are not supported: only OCI images \(application/vnd.oci.image.\*\)" "$out"
    check_match "save (docker-archive): an error" "rc=[1-9]" "$out"
    out=$(api -s -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/images/localhost%2Fapisaved:v1/get?format=docker-archive")
    check "libpod images/get format=docker-archive" 501 "$out"
    out=$(api -s -o /dev/null -w '%{http_code}' "http://d/v1.41/images/localhost%2Fapisaved:v1/get?format=docker-archive")
    check_match "docker images/get format=docker-archive" "^(501|500)$" "$out"
    pm save --format oci-archive -o "$WORKDIR/apisaved.tar" localhost/apisaved:v1 > /dev/null 2>&1
    check "save" 0 $?
    check_match "save oci-archive" "oci-layout" "$(tar -tf "$WORKDIR/apisaved.tar")"
    check "save writes the requested name" 'localhost/apisaved:v1' \
          "$(tar -xOf "$WORKDIR/apisaved.tar" index.json | jq -r '.manifests[0].annotations["io.containerd.image.name"]')"
    # the docker save of the Docker client (the compat route, no format): an OCI archive
    api -s -o "$WORKDIR/apisaved-compat.tar" "http://d/v1.41/images/localhost%2Fapisaved:v1/get"
    check_match "docker save: the OCI archive" "oci-layout" "$(tar -tf "$WORKDIR/apisaved-compat.tar")"
    pm rmi localhost/apisaved:v1 > /dev/null 2>&1
    out=$(pm load -i "$WORKDIR/apisaved.tar" 2>&1)
    check_match "load" "Loaded image: localhost/apisaved:v1" "$out"
    pm rmi localhost/apisaved:v1 > /dev/null 2>&1
    out=$(pm load -i "$WORKDIR/apisaved-compat.tar" 2>&1)
    check_match "load oci-archive" "Loaded image: localhost/apisaved:v1" "$out"
    # a docker save tarball (manifest.json, the configuration, the layers) is
    # read by both loads
    python3 -I "$E2E_DIR/docker_archive.py" "$WORKDIR/apisaved.tar" "$WORKDIR/apisaved-docker.tar" localhost/apisaved:v1
    pm rmi localhost/apisaved:v1 > /dev/null 2>&1
    out=$(api -s -w '\n%{http_code}' -X POST --data-binary @"$WORKDIR/apisaved-docker.tar" http://d/v5.0.0/libpod/images/load)
    check_match "load of a docker-archive" "localhost/apisaved:v1" "$out"
    check_match "load of a docker-archive: 200" "^200$" "$out"
    pm rmi localhost/apisaved:v1 > /dev/null 2>&1
    out=$(api -s -w '\n%{http_code}' -X POST --data-binary @"$WORKDIR/apisaved-docker.tar" http://d/v1.41/images/load)
    check_match "docker load of a docker-archive" "localhost/apisaved:v1" "$out"
    check_match "docker load of a docker-archive: 200" "^200$" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST --data-binary 'not an archive' http://d/v5.0.0/libpod/images/load)
    check "load of an invalid archive fails" 500 "$out"
    pm rmi localhost/apisaved:v1 > /dev/null 2>&1
    # podman's local API: a file of the host that the engine opens and pulls
    # from like any origin
    out=$(api -s -w '\n%{http_code}' -X POST "http://d/v5.0.0/libpod/local/images/load?path=$WORKDIR/apisaved.tar")
    check_match "local load names the image" "localhost/apisaved:v1" "$out"
    check_match "local load: 200" "^200$" "$out"
    pm rmi localhost/apisaved:v1 > /dev/null 2>&1
    out=$(api -s -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/local/images/load?path=$WORKDIR/none.tar")
    check "local load of a file that is not there" 404 "$out"
    out=$(api -s -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/local/images/load?path=apisaved.tar")
    check "local load of a path that is not absolute" 400 "$out"
    out=$(api -s -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/local/images/load?path=$WORKDIR")
    check "local load of a directory" 400 "$out"
    # the docker-archive: transport of a name is the command line's and the
    # engine's, not the REST API's: both pull routes take docker:// only,
    # as podman's do
    out=$(api -s -w '\n%{http_code}' -X POST 'http://d/v1.41/images/create?fromImage=docker-archive%3A%2Ftmp%2Fx.tar')
    check_match "docker create of the docker-archive: transport is refused" "[45][0-9][0-9]$" "$out"
    pm create --name apiexport "$IMG" true > /dev/null 2>&1
    pm export -o "$WORKDIR/apirootfs.tar" apiexport > /dev/null
    check "export" 0 $?
    check "the exported archive is not empty" 1 "$(test -s "$WORKDIR/apirootfs.tar" && echo 1)"
    out=$(pm import -c 'ENV IMPORTED=yes' "$WORKDIR/apirootfs.tar" localhost/apiimported:v1 2>&1)
    check_match "import" "^sha256:[0-9a-f]{64}$" "$out"
    check "import changes" "yes" \
          "$(pm image inspect localhost/apiimported:v1 --format '{{range .Config.Env}}{{.}} {{end}}' | tr ' ' '\n' | sed -n 's/^IMPORTED=//p')"
    pm import -q --arch arm64 --variant v8 "$WORKDIR/apirootfs.tar" localhost/apiimported:arm > /dev/null 2>&1
    check "import for a platform" "arm64" \
          "$(pm image inspect localhost/apiimported:arm --format '{{.Architecture}}' 2>&1)"
    pm rmi localhost/apiimported:arm > /dev/null 2>&1
    pm rmi localhost/apiimported:v1 > /dev/null 2>&1
    # From a URL: the daemon downloads it.
    port=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    python3 -I -u -m http.server --bind 127.0.0.1 --directory "$WORKDIR" "$port" > "$WORKDIR/web.out" 2>&1 3>&- &
    web=$!
    e2e_wait_line "$WORKDIR/web.out" '^Serving HTTP' 30 || fail "the web server does not start"
    # (podman --remote cannot: its bindings refuse a URL with a nil file)
    out=$(api -X POST "http://d/v5.0.0/libpod/images/import?url=http://127.0.0.1:$port/apirootfs.tar&reference=localhost/apiurl:v1" | jq -r .Id)
    check_match "import from a URL" "^sha256:[0-9a-f]{64}$" "$out"
    check "the imported files" "ok" "$(pm run --rm localhost/apiurl:v1 sh -c 'test -x /bin/sh && echo ok' 2>&1)"
    out=$(api -X POST "http://d/v1.41/images/create?fromSrc=http://127.0.0.1:$port/apirootfs.tar&repo=localhost/apicompat&tag=v1")
    check "compat import from a URL" "$(pm image inspect localhost/apicompat:v1 --format '{{.Id}}' 2>&1)" \
          "$(printf '%s' "$out" | jq -r .id | sed 's/^sha256://')"
    out=$(api -X POST --data-binary "@$WORKDIR/apirootfs.tar" "http://d/v1.41/images/create?fromSrc=-&repo=localhost/apicompat&tag=v2" | jq -r .status)
    check_match "compat import of the body" "^sha256:[0-9a-f]{64}$" "$out"
    check "compat import of a missing file" 500 \
          "$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/images/import?url=http://127.0.0.1:$port/nothing.tar")"
    check "import of a file URL" 500 \
          "$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/images/import?url=file:///etc/passwd")"
    kill "$web"
    wait "$web" 2> /dev/null
    pm rmi localhost/apiurl:v1 localhost/apicompat:v1 localhost/apicompat:v2 > /dev/null 2>&1
    pm rm apiexport > /dev/null 2>&1
}

@test "image diff, tree, push, pull --all-tags" {
    pm run --name apidiff "$IMG" sh -c 'echo x > /apidiff' > /dev/null 2>&1
    pm commit -q apidiff localhost/apidiff:v1 > /dev/null 2>&1
    pm rm apidiff > /dev/null 2>&1
    check "image diff" "A /apidiff" "$(pm image diff localhost/apidiff:v1 2>&1)"
    check "image diff of two images" "A /apidiff" "$(pm image diff localhost/apidiff:v1 "$IMG" 2>&1)"
    check "image diff the other way" "D /apidiff" "$(pm image diff "$IMG" localhost/apidiff:v1 2>&1)"
    code=$(api -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/images/localhost%2Fapidiff:v1/changes?diffType=container")
    check "diffType container of an image" 404 "$code"
    check_match "image tree" "Top Layer of: \[localhost/apidiff:v1\]" "$(pm image tree localhost/apidiff:v1 2>&1)"
    reg=${IMG%%/*}
    if curl -s -m 2 "http://$reg/v2/" > /dev/null; then
        pm push -q --tls-verify=false localhost/apidiff:v1 "$reg/velarx-e2e/apidiff:v1" > /dev/null 2>&1
        check "push of a committed image" 0 $?
        check "the registry has it" 200 \
              "$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/apidiff/manifests/v1")"
        # compressionFormat: the layers are written with it
        code=$(api -o /dev/null -w '%{http_code}' -X POST \
               "http://d/v5.0.0/libpod/images/localhost%2Fapidiff:v1/push?destination=$reg/velarx-e2e/apidiff:zstd&tlsVerify=false&compressionFormat=zstd")
        check "push with a compression" 200 "$code"
        out=$(curl -s -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/apidiff/manifests/zstd" \
              | jq -r '[.layers[].mediaType | endswith("+zstd")] | all')
        check "the layers of a push with a compression" true "$out"
        # retry: a push and a pull that fail on the way are tried again
        t0=$(date +%s)
        api -o /dev/null -X POST "http://d/v5.0.0/libpod/images/localhost%2Fapidiff:v1/push?destination=127.0.0.1:9/x/y:z&tlsVerify=false&retry=2&retryDelay=1s"
        api -o /dev/null -X POST "http://d/v5.0.0/libpod/images/pull?reference=127.0.0.1:9/x/y:z&tlsVerify=false&retry=2&retrydelay=1s"
        check "push and pull with retry wait between the attempts" true "$(test $(( $(date +%s) - t0 )) -ge 4 && echo true)"
        code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/images/pull?reference=127.0.0.1:9/x/y:z&retry=x")
        check "pull with a bad retry" 400 "$code"
        # podman push --format v2s2 (the Docker manifest) is refused, and nothing is pushed
        out=$(pm push --tls-verify=false --format v2s2 localhost/apidiff:v1 "$reg/velarx-e2e/apidiff:docker$$" 2>&1)
        check_match "push --format v2s2 is refused" "Docker image formats are not supported: only OCI images \(application/vnd.oci.image.\*\)" "$out"
        check "no manifest of the refused push" 404 \
              "$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/apidiff/manifests/docker$$")"
        out=$(api -s -X POST "http://d/v5.0.0/libpod/images/localhost%2Fapidiff:v1/push?destination=$reg/velarx-e2e/apidiff:docker$$&tlsVerify=false&format=docker" -w '\n%{http_code}')
        check_match "libpod push format=docker is refused" "Docker image formats are not supported" "$out"
        check_match "libpod push format=docker is refused: 501" "^501$" "$out"
        # podman pull --all-tags: every tag of the repository
        for t in a b; do
            pm push -q --tls-verify=false localhost/apidiff:v1 "$reg/velarx-e2e/alltags:$t" > /dev/null 2>&1
        done
        pm pull -q --tls-verify=false --all-tags "$reg/velarx-e2e/alltags" > /dev/null 2>&1
        check "pull --all-tags" 0 $?
        # (images REPO lists every name of a matching image, as podman:
        # localhost/apidiff:v1 too)
        out=$(pm images --format '{{.Repository}} {{.Tag}}' "$reg/velarx-e2e/alltags" | sed -n "s|^$reg/velarx-e2e/alltags ||p" | sort | tr '\n' ' ')
        check "pull --all-tags pulls each tag" "a b " "$out"
        code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/images/pull?reference=$reg/velarx-e2e/alltags:a&allTags=true&tlsVerify=false")
        check "pull --all-tags of a tag" 400 "$code"
        pm rmi "$reg/velarx-e2e/alltags:a" "$reg/velarx-e2e/alltags:b" > /dev/null 2>&1
    else
        note_skip "push of a committed image" "no registry"
    fi
    pm rmi localhost/apidiff:v1 > /dev/null 2>&1

}

@test "image untag" {
    # velarx image untag: names of an image, or all of them.
    mkdir -p "$WORKDIR/untag/d" && echo x > "$WORKDIR/untag/d/f"
    tar -cf "$WORKDIR/untag/t.tar" -C "$WORKDIR/untag/d" f
    uid=$(pm import -q "$WORKDIR/untag/t.tar" localhost/untag:a 2>&1 | sed 's/^sha256://')
    pm tag localhost/untag:a localhost/untag:b localhost/other:c > /dev/null
    check "velarx image untag prints nothing" "" "$("$CLI" image untag localhost/untag:a untag:b 2>&1)"
    pm image exists localhost/untag:a
    check "the other names stay" 0 $?
    pm image exists localhost/untag:b
    check "the name is gone" 1 $?
    check "untag of NAME@DIGEST of the image is no error" 0 "$("$CLI" image untag localhost/untag:a "localhost/untag@$(pm image inspect --format '{{.Digest}}' localhost/untag:a)" > /dev/null 2>&1; echo $?)"
    check "untag of NAME@DIGEST of another repository" "Error: localhost/nope@$(pm image inspect --format '{{.Digest}}' localhost/untag:a): tag not known 125" \
        "$(echo $("$CLI" image untag localhost/untag:a "nope@$(pm image inspect --format '{{.Digest}}' localhost/untag:a)" 2>&1; echo $?))"
    check "untag of a name the image lacks" "Error: localhost/untag:nope: tag not known 125" \
        "$(echo $("$CLI" image untag localhost/untag:a untag:nope 2>&1; echo $?))"
    check "untag of all the names prints nothing" "" "$("$CLI" image untag localhost/untag:a 2>&1)"
    check "untag of all the names" "" "$(pm image inspect --format '{{.RepoTags}}' "$uid" | tr -d '[]')"
    check "the image stays" "$uid" "$(pm image inspect --format '{{.Id}}' "$uid" 2>&1)"
    pm rmi "$uid" > /dev/null 2>&1
}

@test "build, push --format, create --platform, build prune" {
    mkdir -p "$WORKDIR/bctx"
    printf 'FROM %s\nLABEL built=yes\nCOPY hello.txt /hello.txt\nCMD ["cat", "/hello.txt"]\n' "$IMG" > "$WORKDIR/bctx/Containerfile"
    echo hi > "$WORKDIR/bctx/hello.txt"
    (cd "$WORKDIR/bctx" && pm build -q -t localhost/apibuilt:v1 . > /dev/null 2>&1)
    check "build" 0 $?
    out=$(pm image inspect localhost/apibuilt:v1 --format '{{.Labels.built}}' 2>&1)
    check "build result" "yes" "$out"
    printf 'FROM %s\nRUN false\n' "$IMG" > "$WORKDIR/bctx/Bad"
    (cd "$WORKDIR/bctx" && pm build -f Bad . > /dev/null 2>&1)
    check_match "build failure" "^[1-9]" "$?"
    pm rmi localhost/apibuilt:v1 > /dev/null 2>&1
    # push --format: the type of the manifest in the registry
    pm pull -q --tls-verify=false $E2E_REGISTRY/e2e/alpine:gzip > /dev/null 2>&1
    "$CLI" push -q --tls-verify=false --format oci $E2E_REGISTRY/e2e/alpine:gzip "$E2E_REGISTRY/velarx-e2e/pushfmt:oci$$" > /dev/null 2>&1
    check "push --format oci" "application/vnd.oci.image.manifest.v1+json" \
        "$(curl -s -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$E2E_REGISTRY/v2/velarx-e2e/pushfmt/manifests/oci$$" | jq -r .mediaType)"
    for f in v2s2 docker v2s1; do
        out=$("$CLI" push --tls-verify=false --format "$f" $E2E_REGISTRY/e2e/alpine:gzip "$E2E_REGISTRY/velarx-e2e/pushfmt:$f$$" 2>&1; echo "rc=$?")
        check "push --format $f is refused" "Error: the format $f: Docker image formats are not supported: only OCI images (application/vnd.oci.image.*)
rc=125" "$out"
    done
    check "push --format of another type" "Error: unknown format \"zip\". Choose on of the supported formats: 'oci'" \
        "$("$CLI" push --tls-verify=false --format zip $E2E_REGISTRY/e2e/alpine:gzip $E2E_REGISTRY/velarx-e2e/pushfmt:zip 2>&1)"
    # run/create --platform, --arch: the image of the store is taken when it
    # is for that platform, else the platform is pulled
    out=$("$CLI" container create --tls-verify=false --platform linux/amd64 "$IMG" true 2>&1)
    check_match "create --platform of the platform of the image" "^[0-9a-f]{64}$" "$out"
    pm rm -t 0 -f "$out" > /dev/null 2>&1
    # (what the pull of a platform the registry does not have gives is the
    # pull's: podman takes a single image of another platform with a warning)
    check_match "create --platform of another platform pulls it" "^Trying to pull" \
        "$("$CLI" container create --tls-verify=false --platform linux/s390x "$IMG" true 2>&1 | head -1)"
    check_match "create --arch of another platform pulls it" "^Trying to pull" \
        "$("$CLI" container create --tls-verify=false --arch arm64 "$IMG" true 2>&1 | head -1)"
    out=$("$CLI" container create --pull=never --arch arm64 "$IMG" true 2>&1)
    check "create --pull=never --arch of another platform" "Error: $IMG: image not known 125" "$out $?"
    out=$("$CLI" container create --platform linux/amd64 --arch arm64 "$IMG" true 2>&1)
    check "--platform with --arch (podman's)" "Error: --platform option can not be specified with --arch or --os 125" "$out $?"
    # The images the build kept as its cache, unused once its image is gone.
    out=$(api -X POST http://d/v1.41/build/prune | jq -r '(.CachesDeleted | length) > 0 and .SpaceReclaimed > 0')
    check "build prune" true "$out"
}

# Docker's daemon treats the registries of the loopback as insecure and
# libpod's routes do not, whatever compatMode says.
@test "the loopback registries are insecure on Docker's routes only" {
    e2e_registry_up || skip "no registry on $E2E_REGISTRY"
    case $E2E_REGISTRY in
        localhost:*|127.0.0.1:*) ;;
        *) skip "$E2E_REGISTRY is not on the loopback" ;;
    esac
    # (an address registries.conf does not mark insecure)
    ref=127.0.0.1:${E2E_REGISTRY##*:}/alpine:chunked
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/images/pull?reference=$ref&compatMode=true")
    check "libpod pull with compatMode verifies" 500 "$out"
    out=$(api -X POST "http://d/v1.44/images/create?fromImage=${ref%:*}&tag=chunked" | jq -rs 'map(.error // empty) | length')
    check "Docker's pull does not" 0 "$out"
    # (pushed to a name of the test, not over the image the tests share)
    dst=127.0.0.1:${E2E_REGISTRY##*:}/velarx-e2e/loopback-$$:1
    pm tag "$ref" "$dst" > /dev/null
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v1.44/images/$dst/push")
    check "Docker's push does not" 200 "$out"
    out=$(api -X POST "http://d/v5.0.0/libpod/images/$dst/push" | jq -rs 'map(.error // empty) | length > 0')
    check "libpod's push verifies" true "$out"
    out=$(api "http://d/v1.44/distribution/$ref/json" | jq -r '.Descriptor.digest | startswith("sha256:")')
    check "Docker's distribution does not" true "$out"
    pm rmi -f "$ref" "$dst" > /dev/null 2>&1
}
