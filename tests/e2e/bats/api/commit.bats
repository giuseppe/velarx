# SPDX-License-Identifier: Apache-2.0
# End to end tests of the REST API, commit and diff, with
# the velarx CLI and podman --remote, checked against what a local podman
# (in a store of its own) makes of the same container (see api_helpers.bash).

# The changes the containers commit1 make, and the diff they give.

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}
commit_vars () {
    changes='echo hi > /hello; rm /etc/motd; mkdir -p /app/sub; ln -s /hello /app/l; chown 1000:1000 /app/sub; echo x >> /etc/passwd'
    expected_diff='A /app
A /app/l
A /app/sub
C /etc
D /etc/motd
C /etc/passwd
A /hello'
}

@test "container diff and commit with the CLI" {
    commit_vars
    pm run --name commit1 "$IMG" sh -c "$changes" > /dev/null 2>&1
    check "container diff" "$expected_diff" "$("$CLI" container diff commit1)"
    check "podman diff" "$expected_diff" "$(pm diff commit1)"

    out=$("$CLI" image commit -q -c 'ENV FOO=bar' -c 'LABEL l=v' -a me commit1 committed:v1)
    check_match "commit prints the id" "^[0-9a-f]{64}$" "$out"
    check "image diff" "$expected_diff" "$("$CLI" image diff committed:v1)"
    out=$(pm run --rm localhost/committed:v1 sh -c 'cat /hello; stat -c %u:%g /app/sub; test -e /etc/motd || echo gone; echo $FOO; tail -1 /etc/passwd' 2>&1)
    check "committed content" "hi
1000:1000
gone
bar
x" "$out"
    out=$(pm image inspect localhost/committed:v1 --format '{{.Author}} {{.Config.Labels}} {{index .Config.Cmd 0}}')
    check "committed configuration" "me map[l:v] sh" "$out"
    out=$(pm image inspect localhost/committed:v1 --format '{{len .RootFS.Layers}}')
    base=$(pm image inspect "$IMG" --format '{{len .RootFS.Layers}}')
    check "one layer more" "$((base + 1))" "$out"
    out=$("$CLI" image commit -m msg commit1 committed:msg 2>&1; echo "rc=$?")
    check "commit -m is refused as podman's is" "Error: messages are only compatible with the docker image format (-f docker)
rc=125" "$out"
    out=$("$CLI" image commit -f docker commit1 committed:docker 2>&1; echo "rc=$?")
    check "commit -f docker is refused" "Error: the format docker: Docker image formats are not supported: only OCI images (application/vnd.oci.image.*)
rc=125" "$out"
    check "no image was made" "" "$(pm images -q localhost/committed:docker)"

    out=$(pm image tree localhost/committed:v1 2>&1)
    check_match "image tree" "Top Layer of: \[localhost/committed:v1\]" "$out"
    out=$(pm image tree --whatrequires "$IMG" 2>&1)
    check_match "image tree --whatrequires" "localhost/committed:v1" "$out"
    out=$(api -s "http://d/v1.41/distribution/$IMG/json?tlsVerify=false" | jq -r '.Descriptor.digest + " " + .Platforms[0].os')
    check_match "distribution" "^sha256:[0-9a-f]{64} linux$" "$out"
}

@test "podman commit and the compat commit" {
    commit_vars
    out=$(pm commit -q -c 'ENV FROM_PODMAN=1' commit1 localhost/committed:remote)
    check_match "podman commit" "^[0-9a-f]{64}$" "$out"
    check "podman image diff" "$expected_diff" "$(pm image diff localhost/committed:remote)"
    out=$(pm run --rm localhost/committed:remote sh -c 'echo $FROM_PODMAN; cat /hello')
    check "podman commit content" "1
hi" "$out"
    out=$(api -s -X POST 'http://d/v1.41/commit?container=commit1&repo=compat/committed&tag=t&comment=c' | jq -r .Id)
    # podman's compat API: the id alone, a Docker image with the comment.
    check_match "compat commit" "^[0-9a-f]{64}$" "$out"
    check "compat commit: its comment is the history's" "c" \
          "$(pm history --format '{{.Comment}}' "$out" | head -1)"
    check "compat commit: an OCI manifest" "application/vnd.oci.image.manifest.v1+json" \
          "$(api "http://d/v5.0.0/libpod/images/$out/json" | jq -r .ManifestType)"
    out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commit1&repo=localhost/committed&tag=docker&format=docker&comment=d&author=a' -w '\n%{http_code}')
    check_match "libpod commit format=docker is refused" "Docker image formats are not supported: only OCI images \(application/vnd.oci.image.\*\)" "$out"
    check_match "libpod commit format=docker: 501" "501$" "$out"
    out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commit1&repo=localhost/committed&tag=docker&format=oci&comment=d&author=a' -w '\n%{http_code}')
    check_match "libpod commit -f oci takes no message, as podman's" "messages are only compatible with the docker image format \(-f docker\)" "$out"
    check_match "libpod commit -f oci with a message: 500" "^500$" "$out"
    out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commit1&repo=localhost/committed&tag=docker&format=oci&author=a' | jq -r .Id)
    check "libpod commit -f oci" "a" "$(api "http://d/v5.0.0/libpod/images/$out/json" | jq -r .Author)"
    check "its content" "hi" "$(pm run --rm localhost/committed:docker cat /hello 2>&1)"
    pm rmi localhost/committed:docker > /dev/null 2>&1
    # On a base of gzip layers: an OCI manifest, and the Docker one is refused.
    reg=${IMG%%/*}
    if curl -s -m 2 "http://$reg/v2/" > /dev/null; then
        gz=$reg/velarx-e2e/gzbase:$$
        "$CLI" push -q --tls-verify=false --compression-format gzip "$IMG" "$gz" > /dev/null 2>&1
        "$CLI" image pull --tls-verify=false "$gz" > /dev/null 2>&1
        pm run --name commitgz "$gz" sh -c 'echo gz > /gz' > /dev/null 2>&1
        out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commitgz&repo=localhost/committed&tag=v2s2&format=docker&comment=g' -w '\n%{http_code}')
        check_match "a Docker image on gzip layers is refused" "Docker image formats are not supported" "$out"
        check_match "a Docker image on gzip layers is refused: 501" "^501$" "$out"
        out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commitgz&repo=localhost/committed&tag=v2s2' | jq -r .Id)
        check "an OCI image on gzip layers" "application/vnd.oci.image.manifest.v1+json" \
              "$(api "http://d/v5.0.0/libpod/images/$out/json" | jq -r .ManifestType)"
        check "its content" "gz" "$(pm run --rm localhost/committed:v2s2 cat /gz 2>&1)"
        pm rm -t 0 -f commitgz > /dev/null 2>&1
        pm rmi localhost/committed:v2s2 "$gz" > /dev/null 2>&1
    fi
}

@test "commit with a stream, with a configuration" {
    commit_vars
    out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commit1&repo=localhost/committed&tag=stream&stream=true' | jq -r .stream)
    check_match "commit with stream" "^[0-9a-f]{64}$" "$out"
    out=$(api -s -X POST 'http://d/v5.0.0/libpod/commit?container=commit1&repo=localhost/committed&tag=bad&stream=true&changes=BOGUS%20x' | jq -r '.error.message // empty')
    check_match "commit with stream reports the error" "." "$out"
    pm rmi localhost/committed:stream > /dev/null 2>&1
    # the body of a commit: settings of the new configuration
    api -s -X POST -H 'Content-Type: application/json' -d '{"Entrypoint":["/bin/crash"],"Cmd":["and","burn"],"Labels":{"for":"ever"}}' \
        'http://d/v5.0.0/libpod/commit?container=commit1&repo=localhost/committed&tag=body' > /dev/null
    out=$(pm image inspect localhost/committed:body --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{index .Config.Labels "for"}}')
    check "commit with a configuration" '["/bin/crash"] ["and","burn"] ever' "$out"
    pm rmi localhost/committed:body > /dev/null 2>&1

    "$CLI" image commit -q -c 'NOSUCH x' commit1 bad:2 > /dev/null 2>&1
    check "commit with a bad change fails" 125 $?
    pm image exists localhost/bad:2
    check "a failed commit leaves no image" 1 $?
}

@test "commit of a running container" {
    commit_vars
    # The files the engine writes are not changes, and a running
    # container is committed with --pause.
    id=$(pm run -d --name commit2 "$IMG" sh -c 'echo run > /running; echo ready; sleep 60')
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$id/container.log" ' stdout F ready$' 30 || fail "commit2 did not write its file within 30 s"
    # --pause needs a cgroup to freeze, which a rootless container may not
    # have.
    pause=
    if pm pause commit2 > /dev/null 2>&1; then
        pm unpause commit2 > /dev/null 2>&1
        pause=--pause
    fi
    out=$("$CLI" image commit -q $pause commit2 committed:running)
    check_match "commit of a running container" "^[0-9a-f]{64}$" "$out"
    check "engine files left out" "A /running" "$("$CLI" image diff committed:running)"
    check "the container runs after the commit" "running" "$(pm inspect commit2 --format '{{.State.Status}}')"
    pm rm -t 0 -f commit2 > /dev/null 2>&1
}

@test "commit of a container in a user namespace" {
    commit_vars
    # A user namespace: the ids of the container in the image.
    pm run --name commit3 --userns auto "$IMG" sh -c 'mkdir /u; chown 1000:1000 /u; echo a > /u/f' > /dev/null 2>&1
    if "$CLI" image commit -q commit3 committed:userns > /dev/null 2>&1; then
        out=$(pm run --rm localhost/committed:userns stat -c '%u:%g %n' /u /u/f)
        check "ids of a user namespace" "1000:1000 /u
0:0 /u/f" "$out"
    else
        fail "commit of a container in a user namespace"
    fi
    pm rm -t 0 -f commit3 > /dev/null 2>&1
}

@test "the same changes in podman" {
    commit_vars
    # The same changes in podman: the same diff and configuration.
    if command -v podman > /dev/null; then
        local_pm="podman --root $WORKDIR/podman/root --runroot $WORKDIR/podman/run"
        if $local_pm pull -q --tls-verify=false "$IMG" > /dev/null 2>&1; then
            $local_pm run --net=none --name commit1 "$IMG" sh -c "$changes" > /dev/null 2>&1
            $local_pm commit -q -c 'ENV FOO=bar' -c 'LABEL l=v' -a me commit1 localhost/committed:v1 > /dev/null
            check "diff as podman" "$($local_pm image diff localhost/committed:v1)" "$("$CLI" image diff committed:v1)"
            fmt='{{.Author}} {{.Config.Labels}} {{json .Config.Cmd}} {{.Config.WorkingDir}}'
            check "configuration as podman" "$($local_pm image inspect --format "$fmt" localhost/committed:v1)" \
                  "$(pm image inspect --format "$fmt" localhost/committed:v1)"
            $local_pm rm -f commit1 > /dev/null 2>&1
            $local_pm unshare rm -rf "$WORKDIR/podman" 2> /dev/null
        else
            note_skip "commit as podman" "the local podman cannot pull $IMG"
        fi
    fi
    pm rm -t 0 -f commit1 > /dev/null 2>&1
    pm rmi -f localhost/committed:v1 localhost/committed:remote \
       localhost/committed:running localhost/committed:userns compat/committed:t > /dev/null 2>&1
}
