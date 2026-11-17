# SPDX-License-Identifier: Apache-2.0
# End to end tests of the short names of the REST API:
# libpod's routes try the unqualified search registries in order (one that is
# down, or lacks the image, is skipped), Docker's routes mean Docker Hub
# (compat_api_enforce_docker_hub), as the command line resolves like libpod.
# The search list has a registry nobody listens on first; Docker Hub is
# rewritten to the registry of the tests.

load ../helpers
load ../api_helpers

setup_file () {
    export API_REGISTRIES_HEAD='unqualified-search-registries = ["127.0.0.1:1", "'"$E2E_REGISTRY"'"]'
    export API_REGISTRIES_TAIL='[[registry]]
prefix = "docker.io"
location = "'"$E2E_REGISTRY"'"
insecure = true'
    api_setup_file
    # the short names are repositories of the registry
    $SH image push --tls-verify=false "$IMG" "$E2E_REGISTRY/shortlib:latest" > /dev/null
    $SH image push --tls-verify=false "$IMG" "$E2E_REGISTRY/library/shortcompat:latest" > /dev/null
}

teardown_file () {
    api_teardown_file
}

@test "libpod pull of a short name: the registry that is down is skipped" {
    code=$(api -X POST -o "$WORKDIR/pull.out" -w '%{http_code}' "http://d/libpod/images/pull?reference=shortlib&quiet=true")
    check "libpod pull of a short name" 200 "$code"
    check "the image is known by the registry that had it" 204 \
        "$(api -o /dev/null -w '%{http_code}' "http://d/libpod/images/$E2E_REGISTRY/shortlib:latest/exists")"
}

@test "libpod pull of a short name nobody has: every candidate is named" {
    api -X POST -o "$WORKDIR/pull.out" "http://d/libpod/images/pull?reference=nobodyhasthis&quiet=true" > /dev/null
    check_match "the first candidate" "127.0.0.1:1/nobodyhasthis" "$(cat "$WORKDIR/pull.out")"
    check_match "the second candidate" "$E2E_REGISTRY/nobodyhasthis" "$(cat "$WORKDIR/pull.out")"
}

@test "Docker's pull of a short name is Docker Hub's, not the search list's" {
    code=$(api -X POST -o "$WORKDIR/pull.out" -w '%{http_code}' "http://d/images/create?fromImage=shortcompat")
    check "images/create of a short name" 200 "$code"
    check "the image is docker.io/library/shortcompat" 204 \
        "$(api -o /dev/null -w '%{http_code}' "http://d/libpod/images/docker.io/library/shortcompat:latest/exists")"
    code=$(api -X POST -o "$WORKDIR/pull.out" -w '%{http_code}' "http://d/images/create?fromImage=shortcompat&tag=latest")
    check "images/create with a tag" 200 "$code"
}

@test "the command line resolves a short name as libpod does" {
    $SH --socket "$ESOCK" image pull --tls-verify=false shortlib > /dev/null 2>&1
    check "pull of a short name through a registry that is down" 0 $?
}
