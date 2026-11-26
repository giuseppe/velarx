# SPDX-License-Identifier: Apache-2.0
# What the API does not have is refused, not ignored: a filter that is not
# one (even with nothing to filter), a parameter or a body field that asks
# for what velarx lacks (501 naming it), and what podman's and Docker's
# clients send by default stays accepted.

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
    [ -z "${NO_PODMAN:-}" ] || return 0
    mkdir -p "$WORKDIR/ctx"
    printf 'FROM scratch\nLABEL a=b\n' > "$WORKDIR/ctx/Containerfile"
    tar -C "$WORKDIR/ctx" -cf "$WORKDIR/ctx.tar" Containerfile
}

teardown_file () { api_teardown_file; }

setup () { api_setup; }

BOGUS='filters=%7B%22bogus%22%3A%5B%221%22%5D%7D'

# req METHOD URL [BODY [CONTENT-TYPE]]: the status code (the answer in $WORKDIR/out)
req () {
    local m=$1 u=$2 d=${3:-} t=${4:-application/json}
    if [ -n "$d" ] && [ "${d#@}" != "$d" ]; then
        api -g -o "$WORKDIR/out" -w '%{http_code}' -X "$m" -H "Content-Type: $t" --data-binary "$d" "http://d$u"
    elif [ -n "$d" ]; then
        api -g -o "$WORKDIR/out" -w '%{http_code}' -X "$m" -H "Content-Type: $t" -d "$d" "http://d$u"
    else
        api -g -o "$WORKDIR/out" -w '%{http_code}' -X "$m" "http://d$u"
    fi
}

# every filter parser answers for a filter that is not one, with no object
@test "an unknown filter is an error even with nothing to filter" {
    L=/v5.0.0/libpod
    while IFS='|' read -r method url code why; do
        [ -n "$method" ] || continue
        check "$method $url" "$code" "$(req "$method" "$url")"
        check_match "$method $url: why" "$why" "$(cat "$WORKDIR/out")"
    done <<EOT
GET|$L/volumes/json?$BOGUS|500|invalid volume filter
POST|$L/volumes/prune?$BOGUS|500|invalid volume filter
GET|$L/pods/json?$BOGUS|400|invalid filter
GET|$L/pods/json?filters={"status":["bogus"]}|400|not a valid pod status
GET|$L/pods/json?filters={"ctr-status":["bogus"]}|400|not a valid status
POST|$L/images/prune?$BOGUS|500|invalid filter
POST|$L/system/prune?$BOGUS|500|invalid filter
GET|$L/events?stream=false&until=1&$BOGUS|400|invalid filter
GET|$L/containers/json?$BOGUS|500|invalid filter
POST|$L/containers/prune?$BOGUS|500|invalid filter
GET|$L/networks/json?$BOGUS|500|invalid filter
POST|$L/networks/prune?$BOGUS|500|invalid filter
GET|$L/secrets/json?$BOGUS|500|invalid filter
GET|$L/images/json?$BOGUS|500|invalid image filter
EOT
}

@test "a volume prune with dryrun removes nothing" {
    L=/v5.0.0/libpod
    check "create" 201 "$(req POST $L/volumes/create '{"Name":"unsup-dry"}')"
    check "dry run" 200 "$(req POST "$L/volumes/prune?dryrun=true")"
    check_match "the volume it would remove" unsup-dry "$(cat "$WORKDIR/out")"
    check "the volume is there" 204 "$(req GET $L/volumes/unsup-dry/exists)"
    check "prune" 200 "$(req POST $L/volumes/prune)"
    check "the volume is gone" 404 "$(req GET $L/volumes/unsup-dry/exists)"
}

@test "a pod filter on the containers and the network selects" {
    L=/v5.0.0/libpod
    check "create" 201 "$(req POST $L/pods/create '{"name":"unsup-pod"}')"
    check "ctr-number 1 (the infra container)" unsup-pod \
        "$(req GET "$L/pods/json?filters={\"ctr-number\":[\"1\"]}" > /dev/null; jq -r '.[0].Name' "$WORKDIR/out")"
    check "ctr-number 7" "[]" \
        "$(req GET "$L/pods/json?filters={\"ctr-number\":[\"7\"]}" > /dev/null; jq -c . "$WORKDIR/out")"
    check "label!" unsup-pod \
        "$(req GET "$L/pods/json?filters={\"label!\":[\"nope\"]}" > /dev/null; jq -r '.[0].Name' "$WORKDIR/out")"
    req DELETE "$L/pods/unsup-pod?force=true&timeout=0" > /dev/null
}

@test "build parameters that ask for what the build lacks are refused" {
    for q in save-stages=true stage-labels=true isolation=2 cppflags=-DX \
        ignore=true \
        rusage=true rusagelogfile=x securityopt=x sourcePolicy=x \
        "idmappingoptions=%7B%22AutoUserNs%22%3Atrue%2C%22AutoUserNsOpts%22%3A%7B%22InitialSize%22%3A1024%7D%7D"; do
        check "build?$q" 501 "$(req POST "/v5.0.0/libpod/build?$q" "@$WORKDIR/ctx.tar" application/x-tar)"
        check_match "build?$q: names it" "not supported" "$(cat "$WORKDIR/out")"
    done
}

@test "build parameters that velarx has: outputs writes the files of the image on this host" {
    local out=$WORKDIR/build-out
    check "outputs=type=local" 200 "$(req POST "/v5.0.0/libpod/build?outputs=type%3Dlocal%2Cdest%3D$out" "@$WORKDIR/ctx.tar" application/x-tar)"
    check "the directory is made" 0 "$(test -d "$out"; echo $?)"
    check "outputs=type=tar" 200 "$(req POST "/v5.0.0/libpod/build?outputs=type%3Dtar%2Cdest%3D$WORKDIR/build-out.tar" "@$WORKDIR/ctx.tar" application/x-tar)"
    check "a tar" 0 "$(tar -tf "$WORKDIR/build-out.tar" > /dev/null 2>&1; echo $?)"
    check "a relative path is refused" 400 "$(req POST "/v5.0.0/libpod/build?outputs=type%3Dlocal%2Cdest%3Drel" "@$WORKDIR/ctx.tar" application/x-tar)"
    check "the standard output is not a place" 400 "$(req POST "/v5.0.0/libpod/build?outputs=-" "@$WORKDIR/ctx.tar" application/x-tar)"
    check "a type velarx has not" 400 "$(req POST "/v5.0.0/libpod/build?outputs=type%3Doci%2Cdest%3D$out" "@$WORKDIR/ctx.tar" application/x-tar)"
    check_match "...says so as podman does" "invalid type" "$(cat "$WORKDIR/out")"
}

@test "build parameters that podman and Docker send by default are accepted" {
    for q in createdannotation=1 inheritlabels=1 inheritannotations=1 identitylabel=1 omithistory=0 \
        rewritetimestamp=0 compatvolumes=0 isolation=0 memory=0 memswap=0 cpushares=0 cachefrom=null \
        rm=1 rm=0 forcerm=1 jobs=1 httpproxy=1 retry=3 retry-delay=2s isolation=1 isolation=3 \
        cachettl=1h inheritlabels=0 omithistory=true nohosts=true skipunusedstages=0 \
        memory=67108864 memswap=-1 cpushares=2 cpusetcpus=0 sourcedateepoch=5 timestamp=5 \
        groupadd=wheel \
        "idmappingoptions=%7B%22HostUIDMapping%22%3Atrue%2C%22HostGIDMapping%22%3Atrue%2C%22UIDMap%22%3A%5B%5D%2C%22GIDMap%22%3A%5B%5D%2C%22AutoUserNs%22%3Afalse%7D" \
        "nsoptions=%5B%7B%22Name%22%3A%22user%22%2C%22Host%22%3Atrue%2C%22Path%22%3A%22%22%7D%5D" \
        "nsoptions=%5B%7B%22Name%22%3A%22pid%22%2C%22Host%22%3Afalse%7D%5D"; do
        check "build?$q" 200 "$(req POST "/v5.0.0/libpod/build?$q" "@$WORKDIR/ctx.tar" application/x-tar)"
    done
}

@test "build: compressionFormat, compressionLevel and forceCompressionFormat are checked and change nothing" {
    for q in compressionFormat= compressionFormat=gzip compressionFormat=zstd \
        compressionFormat=zstd:chunked compressionFormat=zstd\&compressionLevel=3 \
        forceCompressionFormat=0 forceCompressionFormat=1; do
        check "build?$q" 200 "$(req POST "/v5.0.0/libpod/build?$q" "@$WORKDIR/ctx.tar" application/x-tar)"
    done
    check "an unknown format" 400 "$(req POST "/v5.0.0/libpod/build?compressionFormat=lz4" "@$WORKDIR/ctx.tar" application/x-tar)"
    check_match "...names it" "invalid compression" "$(cat "$WORKDIR/out")"
    check "a level that is no number" 400 "$(req POST "/v5.0.0/libpod/build?compressionLevel=x" "@$WORKDIR/ctx.tar" application/x-tar)"
}

@test "parameters of other routes that ask for what is not there are refused" {
    L=/v5.0.0/libpod
    while IFS='|' read -r method url body; do
        [ -n "$method" ] || continue
        check "$method $url" 501 "$(req "$method" "$url" "$body")"
        check_match "$method $url: names it" "not supported" "$(cat "$WORKDIR/out")"
    done <<EOT
POST|$L/manifests/x/registry/y?addCompression=zstd|
POST|/v1.41/build/prune?min-free-space=5|
POST|/v1.41/build/prune?filters=%7B%22until%22%3A%5B%221h%22%5D%7D|
EOT
}

@test "bodies that ask for what is not there are refused" {
    L=/v5.0.0/libpod
    while IFS='|' read -r method url body; do
        [ -n "$method" ] || continue
        check "$method $url $body" 501 "$(req "$method" "$url" "$body")"
        check_match "$method $url: names it" "not supported" "$(cat "$WORKDIR/out")"
    done <<EOT
POST|$L/pods/create|{"name":"unsup-p","no_manage_resolv_conf":true}
POST|$L/networks/create|{"name":"unsup-n","ipam_options":{"driver":"dhcp"}}
POST|$L/networks/unsup-n/connect|{"container":"c","interface_name":"eth9"}
POST|$L/networks/unsup-n/connect|{"container":"c","static_ips":["10.1.0.2","10.1.0.3"]}
POST|/v1.41/networks/create|{"Name":"unsup-d","Attachable":true}
POST|/v1.41/networks/create|{"Name":"unsup-d","IPAM":{"Driver":"weave"}}
POST|/v1.41/networks/create|{"Name":"unsup-d","IPAM":{"Options":{"a":"b"}}}
POST|/v1.41/volumes/create|{"Name":"unsup-v","ClusterVolumeSpec":{"Group":"g"}}
EOT
}

@test "what the clients send by default is accepted" {
    check "network create, Docker's defaults" 201 \
        "$(req POST /v1.41/networks/create '{"Name":"unsup-ok","Attachable":false,"Ingress":false,"ConfigOnly":false,"IPAM":{"Driver":"default","Options":{},"Config":[]},"Options":{},"Labels":{}}')"
    check "network create, podman's host-local" 200 \
        "$(req POST /v5.0.0/libpod/networks/create '{"name":"unsup-ok2","ipam_options":{"driver":"host-local"}}')"
    req DELETE /v5.0.0/libpod/networks/unsup-ok > /dev/null
    req DELETE /v5.0.0/libpod/networks/unsup-ok2 > /dev/null
}

@test "image parameters that podman reads and velarx has nothing to do for are accepted" {
    check "images/json manifests, identity (podman's compat list has neither)" 200 \
        "$(req GET '/v1.45/images/json?manifests=true&identity=true')"
    check "images/export ociAcceptUncompressedLayers (the archive is uncompressed)" 200 \
        "$(req GET "/v5.0.0/libpod/images/export?references=$IMG&ociAcceptUncompressedLayers=true")"
    req POST "/v5.0.0/libpod/images/x/push?forceCompressionFormat=true" > /dev/null
    check_match "push forceCompressionFormat (no other variant of a layer exists)" "image not known|no such image" "$(cat "$WORKDIR/out")"
}

@test "the query parameters of a few routes do what podman's do" {
    L=/v5.0.0/libpod
    # (podman never reads the scope of a network inspect)
    check "network inspect, scope local" 200 "$(req GET '/v1.44/networks/bridge?scope=local')"
    check "network inspect, scope swarm" 200 "$(req GET '/v1.44/networks/bridge?scope=swarm')"
    sc create --name unsup-all --network none "$IMG" true > /dev/null
    check "restart all" 501 "$(req POST '/v1.44/containers/unsup-all/restart?all=true')"
    check_match "restart all names the parameter" '`all`' "$(cat "$WORKDIR/out")"
    sc rm unsup-all > /dev/null
    # showsecret on Docker's route too
    check "secret create" 200 "$(req POST "$L/secrets/create?name=unsup-sec" 'sesame' application/octet-stream)"
    check "compat secret inspect" 200 "$(req GET /v1.44/secrets/unsup-sec)"
    check "no data unless asked" null "$(jq -c .SecretData "$WORKDIR/out")"
    check "compat secret inspect, showsecret" 200 "$(req GET '/v1.44/secrets/unsup-sec?showsecret=true')"
    check "the data" '"sesame"' "$(jq -c .SecretData "$WORKDIR/out")"
    req DELETE /v1.44/secrets/unsup-sec > /dev/null
    # the annotations of a manifest list as a JSON object, and as KEY=VALUE
    check "manifest create" 201 "$(req POST "$L/manifests/unsup-list?annotations=%7B%22a%22%3A%22b%22%7D&annotation=c=d")"
    check "manifest inspect" 200 "$(req GET "$L/manifests/unsup-list/json")"
    check "its annotations" '{"a":"b","c":"d"}' "$(jq -c .annotations "$WORKDIR/out")"
    req DELETE "$L/manifests/unsup-list" > /dev/null
}
