# SPDX-License-Identifier: Apache-2.0
# The Docker compatible routes, driven with curl (the docker CLI is used
# when there is one).

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; api_state_load; }

@test "compat ping and version" {
    out=$(api -i http://d/_ping | tr -d '\r')
    check_match "compat _ping" "^Api-Version: 1\." "$(echo "$out" | sed 's/^api-version/Api-Version/I')"
    out=$(api http://d/v1.41/version | jq -r .ApiVersion)
    check_match "compat version" "^1\." "$out"
}

@test "compat create and inspect" {
    id=$(api -X POST -H 'Content-Type: application/json' \
         -d '{"Image":"'"$IMG"'","Cmd":["sh","-c","echo out; echo err >&2; exit 5"],"Labels":{"k":"v"}}' \
         'http://d/v1.41/containers/create?name=dkc' | jq -r .Id)
    check_match "compat create" "^[0-9a-f]{64}$" "$id"
    code=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
           -d '{"Image":"'"$IMG"'"}' 'http://d/v1.41/containers/create?name=dkc')
    check "compat create name in use" 409 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
           -d '{"Image":"'"$E2E_REGISTRY"'/nosuch:tag"}' 'http://d/v1.41/containers/create')
    check "compat create of a missing image" 404 "$code"
    out=$(api "http://d/v1.41/containers/$id/json" | jq -r '"\(.Name) \(.State.Status) \(.Config.Labels.k)"')
    check "compat inspect" "/dkc created v" "$out"
    api_state_save id
}

@test "compat create for a platform" {
    # the platform of a create: the image must be for it
    arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
    code=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
           -d '{"Image":"'"$IMG"'"}' "http://d/v1.41/containers/create?name=dkplat&platform=linux/$arch")
    check "compat create for the image's platform" 201 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
           -d '{"Image":"'"$IMG"'"}' "http://d/v1.41/containers/create?platform=linux/s390x")
    check "compat create for another platform" 404 "$code"
    api -o /dev/null -X DELETE "http://d/v1.41/containers/dkplat"
}

@test "compat start, wait, logs, list, exec and remove of a container" {
    # Docker's default network is podman's default bridge, rootless too
    out=$(api "http://d/v1.41/containers/$id/json" | jq -r '"\(.HostConfig.NetworkMode) \(.NetworkSettings.Networks | keys | join(","))"')
    check "compat default network" "bridge podman" "$out"
    # wait first, as the docker CLI: the head comes once the wait is armed,
    # and the container starts after it (the head is read whole)
    mkfifo "$WORKDIR/wait.head"
    api -D "$WORKDIR/wait.head" -X POST "http://d/v1.41/containers/$id/wait?condition=next-exit" > "$WORKDIR/wait.out" 3>&- &
    wait_pid=$!
    while IFS= read -r line; do
        [ "$line" = $'\r' ] && break
    done < "$WORKDIR/wait.head"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v1.41/containers/$id/start")
    check "compat start" 204 "$code"
    wait $wait_pid
    check "compat wait" 5 "$(jq -r .StatusCode "$WORKDIR/wait.out")"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v1.41/containers/$id/start")
    check "compat restart of an exited container" 204 "$code"
    api -X POST "http://d/v1.41/containers/$id/wait" > /dev/null
    api "http://d/v1.41/containers/$id/logs?stdout=1&stderr=1" > "$WORKDIR/logs.bin"
    # frames: stream type, 3 zero bytes, big endian length
    out=$(python3 -I -c '
import sys
d = open(sys.argv[1], "rb").read()
i = 0
out = []
while i + 8 <= len(d):
    n = int.from_bytes(d[i + 4:i + 8], "big")
    out.append((d[i], d[i + 8:i + 8 + n].decode().strip()))
    i += 8 + n
print(sorted(set(out)))' "$WORKDIR/logs.bin")
    check "compat logs are multiplexed" "[(1, 'out'), (2, 'err')]" "$out"
    out=$(api 'http://d/v1.41/containers/json?all=1' | jq -r '.[] | select(.Names[0] == "/dkc") | "\(.State) \(.Status | split(" ")[0])"')
    check "compat list" "exited Exited" "$out"
    out=$(api -X POST -H 'Content-Type: application/json' -d '{"Cmd":["echo","hi"],"AttachStdout":true}' \
          "http://d/v1.41/containers/$id/exec")
    check_match "compat exec on a stopped container" "container state improper" "$out"
    code=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"Cmd":["id"],"User":1000}' \
          "http://d/v1.41/containers/$id/exec")
    check "compat exec with a user that is no string" 400 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v1.41/containers/$id")
    check "compat remove" 204 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X DELETE "http://d/v1.41/containers/$id")
    check "compat remove of a missing container" 404 "$code"
}

@test "compat attach before the start" {
    # attach before the start, over a hijacked connection
    id=$(api -X POST -H 'Content-Type: application/json' \
         -d '{"Image":"'"$IMG"'","Cmd":["echo","attached"]}' 'http://d/v1.41/containers/create' | jq -r .Id)
    api --http1.1 -m 20 -X POST -H 'Connection: Upgrade' -H 'Upgrade: tcp' \
        "http://d/v1.41/containers/$id/attach?stream=1&stdout=1&stderr=1" > "$WORKDIR/attach.bin" 3>&- &
    attach_pid=$!
    # (no event says that an attach is armed)
    sleep 1
    api -X POST "http://d/v1.41/containers/$id/start" > /dev/null
    wait $attach_pid
    check_match "compat attach before the start" "attached" "$(tr -d '\000-\010' < "$WORKDIR/attach.bin")"
    api -X DELETE "http://d/v1.41/containers/$id?force=1" > /dev/null
}

@test "compat exec session, stats, changes, stop and prune" {
    # an exec session
    id=$(api -X POST -H 'Content-Type: application/json' \
         -d '{"Image":"'"$IMG"'","Cmd":["sleep","100"]}' 'http://d/v1.41/containers/create?name=dkx' | jq -r .Id)
    api -X POST "http://d/v1.41/containers/$id/start" > /dev/null
    eid=$(api -X POST -H 'Content-Type: application/json' \
          -d '{"Cmd":["sh","-c","echo in; exit 4"],"AttachStdout":true,"AttachStderr":true}' \
          "http://d/v1.41/containers/$id/exec" | jq -r .Id)
    api --http1.1 -m 20 -X POST -H 'Connection: Upgrade' -H 'Upgrade: tcp' -H 'Content-Type: application/json' \
        -d '{"Detach":false,"Tty":false}' "http://d/v1.41/exec/$eid/start" > "$WORKDIR/exec.bin"
    check_match "compat exec start" "in" "$(tr -d '\000-\010' < "$WORKDIR/exec.bin")"
    out=$(api "http://d/v1.41/exec/$eid/json" | jq -r '"\(.Running) \(.ExitCode)"')
    check "compat exec inspect" "false 4" "$out"
    out=$(api 'http://d/v1.41/containers/'"$id"'/stats?stream=false&one-shot=true' | jq -r .name)
    check "compat stats" "/dkx" "$out"
    out=$(api "http://d/v1.41/containers/$id/changes" | jq -r 'length')
    check_match "compat changes" "^[0-9]+$" "$out"
    api -X POST "http://d/v1.41/containers/$id/stop?t=1" > /dev/null
    out=$(api "http://d/v1.41/containers/$id/json" | jq -r .State.Status)
    check "compat stop" exited "$out"
    api -X DELETE "http://d/v1.41/containers/$id" > /dev/null
    out=$(api http://d/v1.41/images/json | jq -r '[.[] | select(.RepoTags | index("'"$IMG"'"))] | length')
    check "compat images" 1 "$out"
    out=$(api -X POST 'http://d/v1.41/containers/prune' | jq -r 'has("ContainersDeleted")')
    check "compat container prune" true "$out"
}

@test "docker CLI" {
    command -v docker > /dev/null || skip "no docker client"
    out=$(dk run --rm "$IMG" echo hello)
    check "docker run" "hello" "$out"
    dk run --rm "$IMG" sh -c 'exit 7'
    check "docker run exit code" 7 $?
    dk run -d --name dkc2 "$IMG" sleep 100 > /dev/null
    out=$(dk ps --format '{{.Names}} {{.Command}}')
    check "docker ps" 'dkc2 "sleep 100"' "$out"
    out=$(dk exec dkc2 echo in-exec)
    check "docker exec" "in-exec" "$out"
    dk rm -f dkc2 > /dev/null
    check "docker rm" 0 $?
}
