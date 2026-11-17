# SPDX-License-Identifier: Apache-2.0
# Manifest lists: the libpod /manifests routes (the checks of podman's
# test/apiv2/15-manifest.at over the unix socket), podman --remote manifest,
# lists among the images, and the push of a list and of one instance.
# Artifacts in lists: the multipart modify of podman's 15-manifest.at
# (test_artifacts), pushed and read back from the registry.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; api_state_load; reg=${IMG%%/*}; j=$WORKDIR/manifest.json; }

# jq of the body of the last request
body () { jq -r "$1" "$j"; }
req () { # METHOD PATH [JSON] -> status, body in $j
    if test $# -ge 3; then
        api -o "$j" -w '%{http_code}' -X "$1" -H 'Content-Type: application/json' -d "$3" "http://d$2"
    else
        api -o "$j" -w '%{http_code}' -X "$1" "http://d$2"
    fi
}

test_manifest_artifact () { # REQUEST-JSON-FIELDS EXPECTED...
    local fields=$1 reg=$2 tag=$3
    req POST /v6.0.0/libpod/manifests/artifacts > /dev/null
    local aid
    aid=$(body .Id)
    api -o "$j" -w '%{http_code}' -X PUT "http://d/v6.0.0/libpod/manifests/$aid" \
        --form "request.json={\"operation\":\"update\"$fields}" \
        --form "listed.txt=oh yeah $$ $(date +%s%N)" --form "zeroes=@$WORKDIR/zeroes" > "$WORKDIR/artifact.status"
    if test "$(cat "$WORKDIR/artifact.status")" != 200; then
        echo "status $(cat "$WORKDIR/artifact.status"): $(cat "$j")"
        return
    fi
    req POST "/v6.0.0/libpod/manifests/artifacts:latest/registry/$reg%2Fvelarx-e2e%2Fartifacts:$tag?tlsVerify=false&all=true" > /dev/null
    local index digest artifact
    index=$(curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/velarx-e2e/artifacts/manifests/$tag")
    digest=$(printf '%s' "$index" | jq -r '.manifests[0].digest')
    artifact=$(curl -s -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/artifacts/manifests/$digest")
    # artifactType (manifest, index) foo config.size config.mediaType
    # layer types, layer titles, the blobs in the registry
    printf '%s\n' "$artifact" | jq -r --argjson index "$index" \
        '[.artifactType, $index.manifests[0].artifactType, .annotations.foo, .config.size, .config.mediaType,
          .layers[0].mediaType, .layers[1].mediaType,
          .layers[0].annotations["org.opencontainers.image.title"], .layers[1].annotations["org.opencontainers.image.title"]]
         | map(tostring) | join(" ")'
    for d in $(printf '%s' "$artifact" | jq -r '.config.digest, .layers[].digest'); do
        curl -s -o /dev/null -w '%{http_code} ' -I "http://$reg/v2/velarx-e2e/artifacts/blobs/$d"
    done
    req DELETE "/v6.0.0/libpod/manifests/$aid" > /dev/null
}

@test "two images: the test image and a commit of it" {
    pm run --name mfc "$IMG" sh -c 'echo x > /x' > /dev/null 2>&1
    id1=$(pm image inspect "$IMG" --format '{{.Id}}')
    id2=$(pm commit -q mfc localhost/mf2:latest)
    pm rm -t 0 -f mfc > /dev/null 2>&1
    api_state_save id1 id2
}

@test "manifest create, exists and amend" {
    check "create (3.x)" 200 "$(req POST '/v3.4.0/libpod/manifests/create?name=abc')"
    id_abc=$(body .Id)
    check_match "create gives an id" '^[0-9a-f]{64}$' "$id_abc"
    check "create (4.x)" 201 "$(req POST /v4.0.0/libpod/manifests/xyz)"
    id_xyz=$(body .Id)
    check "exists (3.x)" 204 "$(req GET /v3.4.0/libpod/manifests/$id_abc/exists)"
    check "exists (4.x)" 204 "$(req GET /v4.0.0/libpod/manifests/$id_xyz/exists)"
    check "create of an existing name" 409 "$(req POST /v4.0.0/libpod/manifests/xyz)"
    check "create with amend" 201 "$(req POST '/v4.0.0/libpod/manifests/xyz?amend=true')"
    check "amend gives the list" "$id_xyz" "$(body .Id)"
    api_state_save id_abc id_xyz
}

@test "manifest create with images, delete" {
    check "create with an image" 201 "$(req POST "/v4.0.0/libpod/manifests/withimage?images=containers-storage:$id1")"
    id_w=$(body .Id)
    req GET /v4.0.0/libpod/manifests/$id_w/json > /dev/null
    check "its instance" 1 "$(body '.manifests | length')"
    check_match "the instance digest" '^sha256:[0-9a-f]{64}$' "$(body '.manifests[0].digest')"
    check "create with images" 201 "$(req POST "/v4.0.0/libpod/manifests/withimages?images=containers-storage:$id1&images=containers-storage:$id2")"
    id_ws=$(body .Id)
    req GET /v4.0.0/libpod/manifests/$id_ws/json > /dev/null
    check "its instances" 2 "$(body '.manifests | length')"
    check "delete (4.x)" 200 "$(req DELETE /v4.0.0/libpod/manifests/$id_w)"
    check "delete report" "$id_w" "$(body '.Deleted[0]')"
    req DELETE /v4.0.0/libpod/manifests/$id_ws > /dev/null
}

@test "manifest add, update, annotate" {
    check "add (3.x)" 200 "$(req POST /v3.4.0/libpod/manifests/$id_abc/add "{\"images\":[\"containers-storage:$id1\"]}")"
    check "update with both annotation forms" 400 \
          "$(req PUT /v4.0.0/libpod/manifests/$id_xyz "{\"operation\":\"update\",\"images\":[\"containers-storage:$id2\"],\"annotations\":{\"foo\":\"bar\"},\"annotation\":[\"hoge=fuga\"]}")"
    check "its cause" "can not set both Annotation and Annotations" "$(body .cause)"
    check "update" 200 "$(req PUT /v4.0.0/libpod/manifests/$id_xyz "{\"operation\":\"update\",\"images\":[\"containers-storage:$id2\"],\"annotations\":{\"foo\":\"bar\"}}")"
    req GET /v4.0.0/libpod/manifests/$id_xyz/json > /dev/null
    check "instance annotation" bar "$(body '.manifests[0].annotations.foo')"
    digest=$(body '.manifests[0].digest')
    check "annotate" 200 "$(req PUT /v4.0.0/libpod/manifests/$id_xyz "{\"operation\":\"annotate\",\"images\":[\"$digest\"],\"annotation\":[\"hoge2=fuga2\"],\"arch\":\"arm64\"}")"
    req GET /v4.0.0/libpod/manifests/$id_xyz/json > /dev/null
    check "annotated" "fuga2 arm64" "$(body '.manifests[0].annotations.hoge2 + " " + .manifests[0].platform.architecture')"
    check "annotate the index" 200 "$(req PUT /v4.0.0/libpod/manifests/$id_xyz '{"operation":"annotate","index_annotations":{"top":"level"}}')"
    req GET /v4.0.0/libpod/manifests/$id_xyz/json > /dev/null
    check "index annotation" level "$(body '.annotations.top')"
    check "an unknown operation" 400 "$(req PUT /v4.0.0/libpod/manifests/$id_xyz '{"operation":"frob"}')"
}

@test "manifest push to a registry" {
    curl -s -m 2 "http://$reg/v2/" > /dev/null || skip "no registry"
    check "push (3.x)" 200 "$(req POST "/v3.4.0/libpod/manifests/abc:latest/push?destination=$reg%2Fvelarx-e2e%2Fabc:latest&tlsVerify=false&all=true")"
    check_match "pushed index digest" '^sha256:' "$(body .Id)"
    check "push (4.x)" 200 "$(req POST "/v4.0.0/libpod/manifests/xyz:latest/registry/$reg%2Fvelarx-e2e%2Fxyz:latest?tlsVerify=false&all=true")"
    out=$(curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/velarx-e2e/xyz/manifests/latest" | jq -r '.manifests[0].platform.architecture + " " + .annotations.top')
    check "the registry has the index" "arm64 level" "$out"
    d=$(curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/velarx-e2e/xyz/manifests/latest" | jq -r '.manifests[0].digest')
    check "and its instance" 200 "$(curl -s -o /dev/null -w '%{http_code}' -I -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/xyz/manifests/$d")"
}

@test "manifest remove an instance, delete" {
    check "remove an instance (3.x)" 200 "$(req DELETE "/v3.4.0/libpod/manifests/$id_abc?digest=$(pm image inspect $id1 --format '{{.Digest}}')")"
    req GET /v4.0.0/libpod/manifests/$id_abc/json > /dev/null
    check "the instance is gone" 0 "$(body '.manifests | length')"
    check "delete" 200 "$(req DELETE /v4.0.0/libpod/manifests/$id_abc)"
    check "delete" 200 "$(req DELETE /v4.0.0/libpod/manifests/$id_xyz)"
    check "exists of a deleted list" 404 "$(req GET /v4.0.0/libpod/manifests/$id_xyz/exists)"
    check "delete of a missing list" 404 "$(req DELETE /v4.0.0/libpod/manifests/$id_xyz)"
    check "delete ?ignore" 200 "$(req DELETE "/v4.0.0/libpod/manifests/$id_xyz?ignore=true")"
}

@test "podman manifest, lists among the images" {
    # podman --remote, the lists among the images.
    before=$(api http://d/v1.41/images/json | jq length)
    pm manifest create mlist > /dev/null
    check "manifest create" 0 $?
    check "a list is not a Docker image" "$before" "$(api http://d/v1.41/images/json | jq length)"
    out=$(api http://d/v5.0.0/libpod/images/json | jq -r '.[] | select(.IsManifestList) | .Names[0] + " " + (.Arch // "null")')
    check "a list is a libpod image" "localhost/mlist:latest null" "$out"
    pm manifest add mlist containers-storage:$id1 > /dev/null
    check "manifest add" 0 $?
    pm manifest add --arch arm64 mlist containers-storage:$id2 > /dev/null
    check "manifest add --arch" 0 $?
    out=$(pm manifest inspect mlist | jq -r '[.manifests[].platform.architecture] | join(" ")')
    check_match "manifest inspect" "arm64" "$out"
    pm manifest exists mlist
    check "manifest exists" 0 $?
    if curl -s -m 2 "http://$reg/v2/" > /dev/null; then
        pm manifest push --all --tls-verify=false mlist "$reg/velarx-e2e/mlist:e2e" > /dev/null 2>&1
        check "manifest push --all" 0 $?
        # The pull of a list takes the instance of this host.
        "$CLI" image pull --tls-verify=false "$reg/velarx-e2e/mlist:e2e" > /dev/null 2>&1
        check "pull of a list" "$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')" \
              "$(pm image inspect "$reg/velarx-e2e/mlist:e2e" --format '{{.Architecture}}' 2>&1)"
        # The push of a list as an image: one instance by its platform.
        check "tag a list" 201 "$(req POST "/v5.0.0/libpod/images/mlist/tag?repo=$reg/velarx-e2e/mtest&tag=latest")"
        check "push an instance by its platform" 200 \
              "$(req POST "/v5.0.0/libpod/images/$reg/velarx-e2e/mtest:latest/push?tlsVerify=false&os=linux&arch=arm64")"
        out=$(curl -s -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/mtest/manifests/latest" | jq -r .mediaType)
        check "the registry has an image, not a list" "application/vnd.oci.image.manifest.v1+json" "$out"
        check "push for a platform the list does not have" 400 \
              "$(req POST "/v5.0.0/libpod/images/$reg/velarx-e2e/mtest:latest/push?tlsVerify=false&os=linux&arch=s390x")"
        pm rmi "$reg/velarx-e2e/mlist:e2e" > /dev/null 2>&1
    fi
    pm manifest rm mlist > /dev/null
}

@test "velarx manifest with podman's flags" {
    cid=$("$CLI" manifest create clist 2>&1)
    check_match "velarx manifest create" '^[0-9a-f]{64}$' "$cid"
    "$CLI" manifest exists clist
    check "velarx manifest exists" 0 $?
    check_match "create of an existing list" "exists already" "$("$CLI" manifest create clist 2>&1)"
    check "create --amend" "$cid" "$("$CLI" manifest create --amend clist 2>&1)"
    # (by name: an image loaded from a saved archive has the id of $IMG too)
    check "velarx manifest add" "$cid" \
          "$("$CLI" manifest add --arch arm64 --variant v8 --annotation k=v clist containers-storage:$IMG 2>&1)"
    out=$("$CLI" manifest inspect clist | jq -r '.manifests[0] | "\(.platform.architecture) \(.platform.variant) \(.annotations.k)"')
    check "velarx manifest inspect" "arm64 v8 v" "$out"
    d1=$("$CLI" manifest inspect clist | jq -r '.manifests[0].digest')
    "$CLI" manifest annotate --os-version 1.0 --features sse4 clist "$d1" > /dev/null
    check "velarx manifest annotate" "1.0 sse4" \
          "$("$CLI" manifest inspect clist | jq -r '.manifests[0].platform | "\(."os.version") \(.features[0])"')"
    "$CLI" manifest annotate --index --annotation top=x clist > /dev/null
    check "annotate --index" "x" "$("$CLI" manifest inspect clist | jq -r .annotations.top)"
    check_match "annotate without an instance" "--index" "$("$CLI" manifest annotate clist 2>&1)"
    "$CLI" manifest add clist containers-storage:$id2 > /dev/null
    if curl -s -m 2 "http://$reg/v2/" > /dev/null; then
        "$CLI" manifest add --tls-verify=false clist "docker://$IMG" > /dev/null
        # The registry's image is the first instance: replaced, not added.
        check "add of an image of a registry" "2 none" \
              "$("$CLI" manifest inspect clist | jq -r "[(.manifests | length), (.manifests[] | select(.digest == \"$d1\") | (.annotations.k // \"none\"))] | join(\" \")")"
        out=$("$CLI" manifest inspect --tls-verify=false "$IMG" | jq -r .schemaVersion)
        check "inspect of a registry's manifest" 2 "$out"
        "$CLI" manifest push -q --tls-verify=false --digestfile "$WORKDIR/clist.digest" clist "$reg/velarx-e2e/clist:$$"
        check "velarx manifest push" 0 $?
        want=$(curl -s -I -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/velarx-e2e/clist/manifests/$$" \
               | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')
        check "push --digestfile" "$want" "$(cat "$WORKDIR/clist.digest")"
    else
        note_skip "velarx manifest push" "no registry"
    fi
    "$CLI" manifest remove clist "$d1" > /dev/null
    check "velarx manifest remove" "" \
          "$("$CLI" manifest inspect clist | jq -r ".manifests[] | select(.digest == \"$d1\") | .digest")"
    out=$("$CLI" manifest rm clist 2>&1)
    check "velarx manifest rm" "Untagged: localhost/clist:latest
Deleted: $cid" "$out"
    "$CLI" manifest exists clist
    check "the list is gone" 1 $?
    check_match "rm of a missing list" "no such manifest list" "$("$CLI" manifest rm clist 2>&1)"
    check "manifest rm" 0 $?
    pm manifest exists mlist
    check "the list is gone" 1 $?
    pm image exists "$id2"
    check "its instances stay" 0 $?
}

@test "build --manifest" {
    # build --manifest: an image a platform (its configuration saying so),
    # added to the list, which is created.
    local mctx=$WORKDIR/manifest-context
    mkdir -p "$mctx"
    printf 'm\n' > "$mctx/f"
    printf 'FROM scratch\nCOPY f /f\n' > "$mctx/Containerfile"
    out=$(pm build --platform linux/amd64,linux/arm64/v8 --manifest localhost/built-list "$mctx" 2>&1)
    check "build --manifest" 0 $?
    list_id=$(api http://d/v5.0.0/libpod/images/json | jq -r '.[] | select(.Names[0] == "localhost/built-list:latest") | .Id')
    check "the build gives the id of the list" "$list_id" "$(printf '%s\n' "$out" | tail -1)"
    check "the instances of the platforms" "amd64 linux null|arm64 linux v8" \
          "$(pm manifest inspect localhost/built-list | jq -r '[.manifests[].platform | "\(.architecture) \(.os) \(.variant)"] | join("|")')"
    for d in $(pm manifest inspect localhost/built-list | jq -r '.manifests[].digest'); do
        printf '%s ' "$(pm image inspect --format '{{.Architecture}}' "$d" 2>&1)"
    done > "$WORKDIR/arches"
    check "the configurations of the instances" "amd64 arm64 " "$(cat "$WORKDIR/arches")"
    out=$("$CLI" image build --platform linux/arm64/v8 --manifest built-list "$mctx" 2>&1)
    check "velarx build --manifest" 0 $?
    check "the same image again replaces its instance" 2 \
          "$(pm manifest inspect localhost/built-list | jq '.manifests | length')"
    out=$("$CLI" image build --manifest localhost/mf2:latest "$mctx" 2>&1)
    check_match "build --manifest of an image name" "is an image, not a manifest list" "$out"
}

@test "build --all-platforms" {
    curl -s -m 2 "http://$reg/v2/" > /dev/null || skip "no registry"
    mctx=$WORKDIR/manifest-context
    local two=$reg/velarx-e2e/allp-two:$$ one=$reg/velarx-e2e/allp-one:$$
    pm manifest push --all --tls-verify=false localhost/built-list "$two" > /dev/null 2>&1
    check "push a base list" 0 $?
    pm build -q --platform linux/amd64 --manifest localhost/one-list "$mctx" > /dev/null 2>&1
    pm manifest push --all --tls-verify=false localhost/one-list "$one" > /dev/null 2>&1
    printf 'FROM %s\nCOPY f /g\n' "$two" > "$mctx/Containerfile.all"
    out=$("$CLI" image build --tls-verify=false --all-platforms --manifest all-list -f "$mctx/Containerfile.all" "$mctx" 2>&1)
    # arm64/v8 is arm64, as buildah normalizes it.
    check_match "build --all-platforms" "Building for linux/amd64, linux/arm64$" "$out"
    check "its instances" "amd64 linux null|arm64 linux null" \
          "$(pm manifest inspect localhost/all-list | jq -r '[.manifests[].platform | "\(.architecture) \(.os) \(.variant)"] | join("|")')"
    printf 'FROM %s AS a\nFROM %s\nCOPY --from=a /f /g\n' "$two" "$one" > "$mctx/Containerfile.all"
    out=$(pm build --tls-verify=false --all-platforms --manifest localhost/common-list -f "$mctx/Containerfile.all" "$mctx" 2>&1)
    check "the platforms in common" "amd64" \
          "$(pm manifest inspect localhost/common-list | jq -r '[.manifests[].platform.architecture] | join(" ")')"
    printf 'FROM %s\n' "$IMG" > "$mctx/Containerfile.all"
    check_match "--all-platforms on an image that is not a list" "not a manifest list" \
                "$("$CLI" image build --tls-verify=false --all-platforms -f "$mctx/Containerfile.all" "$mctx" 2>&1)"
    for l in all-list common-list one-list; do
        pm manifest rm localhost/$l > /dev/null 2>&1
    done
}

@test "create from a list" {
    pm create --name mfl localhost/built-list /f > /dev/null 2>&1
    check "create from a list takes the instance of the host" 0 $?
    pm rm -t 0 -f mfl > /dev/null 2>&1
    pm manifest rm localhost/built-list > /dev/null 2>&1
    pm rmi -f localhost/mf2:latest > /dev/null 2>&1
}

@test "manifest artifacts: the variants of the modify" {
    curl -s -m 2 "http://$reg/v2/" > /dev/null || skip "no registry"
    truncate -s 20M "$WORKDIR/zeroes"
    echo "$$ $(date +%s%N)" >> "$WORKDIR/zeroes"
    local u=application/vnd.unknown.artifact.v1 e=application/vnd.oci.empty.v1+json c=application/vnd.oci.image.config.v1+json
    local blobs="200 200 200 "
    t=$$
    check "artifact" "$u $u null 2 $e text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact '' "$reg" "$t")"
    check "artifact_annotations" "$u $u bar 2 $e text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_annotations":{"foo":"bar"}' "$reg" "$t")"
    check "artifact_config empty" "$u $u null 2 $e text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_config":""' "$reg" "$t")"
    check "artifact_config" "$u $u null 2 $c text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_config":"{}"' "$reg" "$t")"
    check "artifact_config_type" "$u $u null 2 text/plain text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_config_type":"text/plain"' "$reg" "$t")"
    check "artifact_config and its type" "$u $u null 2 text/plain text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_config":"{}","artifact_config_type":"text/plain"' "$reg" "$t")"
    check "artifact_exclude_titles" "$u $u null 2 $e text/plain application/octet-stream null null
$blobs" "$(test_manifest_artifact ',"artifact_exclude_titles":true' "$reg" "$t")"
    check "artifact_layer_type" "$u $u null 2 $e application/octet-stream application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_layer_type":"application/octet-stream"' "$reg" "$t")"
    check "artifact_type empty" "null null null 2 $e text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_type":""' "$reg" "$t")"
    check "artifact_type" "text/plain text/plain null 2 $e text/plain application/octet-stream listed.txt zeroes
$blobs" "$(test_manifest_artifact ',"artifact_type":"text/plain"' "$reg" "$t")"
}

@test "manifest artifact report, instance and a body without parts" {
    curl -s -m 2 "http://$reg/v2/" > /dev/null || skip "no registry"
    # The list and its files go together.
    req POST /v6.0.0/libpod/manifests/artifacts > /dev/null
    aid=$(body .Id)
    api -o "$j" -X PUT "http://d/v6.0.0/libpod/manifests/$aid" \
        --form 'request.json={"operation":"update","arch":"arm64"}' --form 'a.json={}' > /dev/null
    check "an artifact's report" '["a.json"]' "$(jq -c .files "$j")"
    req GET "/v6.0.0/libpod/manifests/$aid/json" > /dev/null
    check "its instance" "arm64 application/vnd.unknown.artifact.v1" \
          "$(body '.manifests[0] | "\(.platform.architecture) \(.artifactType)"')"
    check "a body without parts" 400 \
          "$(api -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: multipart/form-data; boundary=x' --data-binary 'nothing' "http://d/v6.0.0/libpod/manifests/$aid")"
    req DELETE "/v6.0.0/libpod/manifests/$aid" > /dev/null
}

@test "velarx manifest add --artifact" {
    curl -s -m 2 "http://$reg/v2/" > /dev/null || skip "no registry"
    t=$$
    # velarx manifest add --artifact.
    "$CLI" manifest create cart > /dev/null
    printf 'notes\n' > "$WORKDIR/notes.txt"
    printf '{"a":1}' > "$WORKDIR/acfg.json"
    "$CLI" manifest add --artifact --artifact-type application/x-notes --artifact-config "$WORKDIR/acfg.json" \
        --annotation k=v --os linux --arch amd64 cart "$WORKDIR/notes.txt" "$WORKDIR/zeroes" > /dev/null
    check "velarx manifest add --artifact" 0 $?
    check "the artifact instance" "application/x-notes v amd64" \
          "$("$CLI" manifest inspect cart | jq -r '.manifests[0] | "\(.artifactType) \(.annotations.k) \(.platform.architecture)"')"
    "$CLI" manifest push -q --tls-verify=false cart "$reg/velarx-e2e/cart:$t"
    d=$(curl -s -H 'Accept: application/vnd.oci.image.index.v1+json' "http://$reg/v2/velarx-e2e/cart/manifests/$t" | jq -r '.manifests[0].digest')
    out=$(curl -s -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$reg/v2/velarx-e2e/cart/manifests/$d" \
          | jq -r '[.config.mediaType, (.config.size | tostring), .layers[0].annotations["org.opencontainers.image.title"], .layers[1].mediaType] | join(" ")')
    check "the pushed artifact" "application/vnd.oci.image.config.v1+json 7 notes.txt application/octet-stream" "$out"
    check_match "artifact flags without --artifact" "requires --artifact" \
                "$("$CLI" manifest add --artifact-type x cart "$IMG" 2>&1)"
    "$CLI" manifest rm cart > /dev/null
    rm -f "$WORKDIR/zeroes"
}
