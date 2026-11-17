# SPDX-License-Identifier: Apache-2.0
# Routes and parameters that podman's apiv2 suite does not cover:
# generate systemd, swagger, artifacts/local/add, image rm lookupManifest.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () {
    kill "$(cat "$WORKDIR/k8s.pid" 2> /dev/null)" 2> /dev/null
    api_teardown_file
}

setup () { api_setup; }

@test "swagger" {
    # swagger: podman's spec, in velarx's directory; a 500 without it
    code=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/swagger)
    if test -f /usr/share/velarx/swagger.yaml; then
        check "swagger serves podman's spec" 200 "$code"
    else
        check "swagger without the spec: podman's 500" 500 "$code"
        check_match "and why" "does not exist" "$(api http://d/v5.0.0/libpod/swagger | jq -r .message)"
    fi
}

@test "generate systemd of a container and of a pod" {
    pm create --name gsys "$IMG" sleep 1000 > /dev/null
    out=$(api 'http://d/v5.0.0/libpod/generate/gsys/systemd?useName=true&restartSec=3&wants=a.service&additionalEnvVariables=X%3D1')
    # (continued lines joined, as systemd reads them)
    unit=$(echo "$out" | jq -r '."container-gsys"' | sed -e ':a' -e '/\\$/N; s/ \\\n\t/ /; ta')
    for line in "^ExecStart=.*velarx.* start gsys$" "^PIDFile=/.*/monitor.pid$" "^Type=forking$" \
        "^Environment=PODMAN_SYSTEMD_UNIT=%n$" "^Environment=X=1$" "^RestartSec=3$" "^Wants=a.service$" \
        "^TimeoutStopSec=70$" "^RequiresMountsFor=/"; do
        echo "$unit" | grep -qE "$line"
        check "generate systemd: $line" 0 $?
    done
    out=$(api 'http://d/v5.0.0/libpod/generate/gsys/systemd?noHeader=true&containerPrefix=ctr&separator=_' | jq -r 'keys[0]')
    check "the prefix and separator name the unit" "ctr_$(pm inspect gsys --format '{{.Id}}')" "$out"
    out=$(api 'http://d/v5.0.0/libpod/generate/gsys/systemd?new=true' | jq -r .message)
    check_match "--new is refused, with why" "new is not supported" "$out"
    out=$(api 'http://d/v5.0.0/libpod/generate/gsys/systemd?restartPolicy=sometimes' | jq -r .message)
    check "a bad restart policy" "sometimes is not a valid restart policy" "$out"
    pm rm gsys > /dev/null
    pm pod create --name gpod > /dev/null
    pm create --pod gpod --name gpodc "$IMG" sleep 1000 > /dev/null
    out=$(api 'http://d/v5.0.0/libpod/generate/gpod/systemd?useName=true')
    check "a pod: its unit and its containers'" "container-gpodc pod-gpod" "$(echo "$out" | jq -r 'keys | join(" ")')"
    check_match "the pod's unit wants its containers" "Wants=container-gpodc.service" "$(echo "$out" | jq -r '."pod-gpod"')"
    check_match "a container is bound to its pod" "BindsTo=pod-gpod.service" "$(echo "$out" | jq -r '."container-gpodc"')"
    check_match "the pod starts with pod start" "ExecStart=.* pod start gpod" \
        "$(echo "$out" | jq -r '."pod-gpod"' | sed -e ':a' -e '/\\$/N; s/ \\\n\t/ /; ta')"
    pm pod rm -t 0 -f gpod > /dev/null
}

@test "generate systemd of nothing" {
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/generate/nothere/systemd)
    check "generate systemd of nothing" 404 "$out"
}

@test "artifacts/local/add" {
    # artifacts/local/add: a file of the server
    echo local-content > "$WORKDIR/local-artifact.txt"
    out=$(api -X POST "http://d/v5.0.0/libpod/artifacts/local/add?name=localhost/e2e/local:1&fileName=a.txt&path=$WORKDIR/local-artifact.txt" | jq -r .ArtifactDigest)
    check_match "artifacts/local/add" "^sha256:" "$out"
    out=$(api "http://d/v5.0.0/libpod/artifacts/localhost%2Fe2e%2Flocal:1/json" | jq -r '.Manifest.layers[0].annotations["org.opencontainers.image.title"]')
    check "the file is its layer" a.txt "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/artifacts/local/add?name=localhost/e2e/local:2&fileName=a&path=relative/x")
    check "a relative path is a 400" 400 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/artifacts/local/add?name=localhost/e2e/local:2&fileName=a&path=$WORKDIR/nothere")
    check "a missing file is a 404" 404 "$out"
    api -X DELETE "http://d/v5.0.0/libpod/artifacts/localhost%2Fe2e%2Flocal:1" > /dev/null
}

@test "image rm lookupManifest" {
    pm manifest create lmlist > /dev/null
    out=$(api -X DELETE "http://d/v5.0.0/libpod/images/$IMG?lookupManifest=true" | jq -r .message)
    check_match "lookupManifest refuses an image" "not a manifest list" "$out"
    check "and the image stays" 0 "$(pm image exists "$IMG"; echo $?)"
    out=$(api -X DELETE "http://d/v5.0.0/libpod/images/lmlist?lookupManifest=true" | jq -r '.Deleted | length')
    check "lookupManifest removes the list" 1 "$out"
    out=$(api -X DELETE "http://d/v5.0.0/libpod/images/remove?images=$IMG&lookupManifest=true" | jq -r '.Errors | length')
    check "the batch removal too" 1 "$out"
}

