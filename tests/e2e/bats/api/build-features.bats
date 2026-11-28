# SPDX-License-Identifier: Apache-2.0
# End to end tests of the Containerfile features and the build options of
# buildah, through the velarx CLI and podman --remote: RUN
# --mount of each type (bind of the context and of a stage, cache kept
# between builds and pruned, tmpfs, secret, ssh with a test agent),
# here-documents of RUN and COPY, build --secret (not in the layers, the
# history, the cache key or the trace logs), --build-context (a directory,
# an image), --from, the stages the target does not use, --output, the
# times of reproducible builds, --omit-history, --inherit-labels, the
# resources and groups of the RUN containers, the annotations of the
# manifest, --http-proxy, build --runtime-flag, a Containerfile outside of
# the context (podman), system prune --build.
# Rootless.

load ../helpers
load ../api_helpers

setup_file () {
    # (velarx-api logs everything: the secrets must not be in it)
    export E2E_LOG_LEVEL=trace
    api_setup_file
}

teardown_file () {
    # (the cache directories hold files of the user namespace)
    [ -n "${WORKDIR:-}" ] && "$CLI" image prune -f --build-cache > /dev/null 2>&1
    api_teardown_file
}

teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pp=$XDG_RUNTIME_DIR/libpod/tmp/pause.pid
    [ ! -f "$pp" ] || kill "$(cat "$pp")" 2> /dev/null
    [ "$E2E_FAILS" = 0 ] || exit 1
}


@test "RUN --mount: bind, cache, tmpfs; here-documents" {
    local c=$WORKDIR/mounts
    mkdir -p "$c/sub"
    printf 'from the context\n' > "$c/sub/f.txt"
    cat > "$c/Containerfile" <<EOT
FROM $IMG AS builder
RUN mkdir -p /out && echo built > /out/artifact
FROM $IMG
ARG NAME=world
RUN --mount=type=bind,target=/ctx cat /ctx/sub/f.txt > /from-ctx
RUN --mount=type=bind,source=sub,target=/w,rw echo x > /w/new && test -e /w/f.txt
RUN --mount=type=bind,from=builder,source=/out,target=/b cat /b/artifact > /from-stage
RUN --mount=type=bind,from=builder,source=/out/artifact,target=/one.txt cat /one.txt > /from-file
RUN --mount=type=cache,target=/cache,id=bm,uid=1000,mode=0750 echo run >> /cache/log && wc -l < /cache/log > /cache-count && stat -c '%u %a' /cache > /cache-owner
RUN --mount=type=tmpfs,target=/t,size=1m df -k /t | tail -1 | awk '{print \$2}' > /tmpfs && touch /t/x
RUN <<EOF
echo "hello \$NAME" > /heredoc
EOF
RUN <<EOF
#!/bin/sh
echo shebang > /shebang
EOF
RUN cat > /tabs <<-X
	tabbed
	X
COPY <<A <<"B" /docs/
a \$NAME
A
b \$NAME
B
EOT
    out=$("$CLI" image build --tls-verify=false -t localhost/bm:mounts "$c" 2>&1)
    check "build" 0 $?
    [ $? = 0 ] || echo "$out" >&2
    check "contents" "from the context
built
built
1
1000 750
1024
hello world
shebang
tabbed
a world
b \$NAME" "$("$CLI" run --rm --network none localhost/bm:mounts cat /from-ctx /from-stage /from-file /cache-count /cache-owner /tmpfs /heredoc /shebang /tabs /docs/A /docs/B 2>&1)"
    check "no mount point in the layers" "" "$("$CLI" run --rm --network none localhost/bm:mounts sh -c 'ls -d /ctx /w /b /one.txt /cache /t /dev/pipes 2> /dev/null')"
    check "rw of the context is not written back" "f.txt" "$(ls "$c/sub")"
    # the cache directory stays: a build without the layer cache sees it
    "$CLI" image build --tls-verify=false --no-cache -t localhost/bm:mounts2 "$c" > /dev/null 2>&1
    check "the cache is kept between builds" 2 "$("$CLI" run --rm --network none localhost/bm:mounts2 cat /cache-count 2>&1)"
    # a step the cache has is not run again
    out=$("$CLI" image build --tls-verify=false -t localhost/bm:mounts3 "$c" 2>&1)
    check "the layer cache with mounts" 11 "$(printf '%s\n' "$out" | grep -c 'Using cache')"
    "$CLI" image prune -f --build-cache > /dev/null 2>&1
    check "image prune --build-cache" 0 $?
    "$CLI" image build --tls-verify=false --no-cache -t localhost/bm:mounts4 "$c" > /dev/null 2>&1
    check "the cache is gone after the prune" 1 "$("$CLI" run --rm --network none localhost/bm:mounts4 cat /cache-count 2>&1)"
    # the same through podman's route
    out=$(pm build --tls-verify=false --no-cache -t localhost/bm:remote "$c" 2>&1)
    check_match "podman build with mounts and here-documents" "[0-9a-f]{64}$" "$out"
    check "podman: contents" "from the context
hello world
2" "$(pm run --rm localhost/bm:remote cat /from-ctx /heredoc /cache-count 2>&1)"

    printf 'FROM %s\nRUN --mount=type=bind,source=../../etc,target=/x cat /x/passwd > /p\n' "$IMG" > "$WORKDIR/up.Containerfile"
    mkdir -p "$WORKDIR/upctx/etc"
    printf 'inside\n' > "$WORKDIR/upctx/etc/passwd"
    "$CLI" image build --tls-verify=false -f "$WORKDIR/up.Containerfile" -t localhost/bm:up "$WORKDIR/upctx" > /dev/null 2>&1
    check "a source stays in the context" inside "$("$CLI" run --rm --network none localhost/bm:up cat /p 2>&1)"
    for bad in "type=nfs,target=/x" "type=bind" "type=cache,target=/x,sharing=sometimes" "type=secret,id=a,required"; do
        printf 'FROM %s\nRUN --mount=%s true\n' "$IMG" "$bad" > "$c/Containerfile.bad"
        "$CLI" image build --tls-verify=false -f "$c/Containerfile.bad" "$c" > /dev/null 2>&1
        check "refused: --mount=$bad" 1 "$(( $? != 0 ))"
    done
    printf 'FROM %s\nRUN --security=insecure true\n' "$IMG" > "$c/Containerfile.bad"
    out=$("$CLI" image build --tls-verify=false -f "$c/Containerfile.bad" "$c" 2>&1)
    check_match "RUN --security=insecure needs its entitlement" "security.insecure is not allowed \(line 2: RUN --security=insecure\)" "$out"
    printf 'FROM %s\nRUN --network=none cat /etc/resolv.conf > /dev/null; ip -o link 2> /dev/null | grep -vc lo > /links || true\n' "$IMG" > "$c/Containerfile.net"
    "$CLI" image build --tls-verify=false -f "$c/Containerfile.net" -t localhost/bm:net "$c" > /dev/null 2>&1
    check "RUN --network=none" 0 $?
    pm rmi -f localhost/bm:mounts localhost/bm:mounts2 localhost/bm:mounts3 localhost/bm:mounts4 localhost/bm:remote localhost/bm:up localhost/bm:net > /dev/null 2>&1
}

@test "build --secret: in the step only" {
    local c=$WORKDIR/secrets mark=SECRETMARK$$x
    mkdir -p "$c"
    printf '%s' "$mark" > "$WORKDIR/secret.txt"
    cat > "$c/Containerfile" <<EOT
FROM $IMG
RUN --mount=type=secret,id=tok sha256sum < /run/secrets/tok | cut -c1-16 > /mode && stat -c '%a %u' /run/secrets/tok >> /mode
RUN --mount=type=secret,id=tok,target=/etc/tok,uid=1000,mode=0440 stat -c '%a %u' /etc/tok >> /mode
RUN --mount=type=secret,id=tok,env=TOK printf %s "\$TOK" | sha256sum | cut -c1-16 >> /mode
RUN --mount=type=secret,id=fromenv cat /run/secrets/fromenv | wc -c >> /mode
RUN --mount=type=secret,id=missing ls /run/secrets 2> /dev/null | wc -l >> /mode
COPY . /ctxcopy
EOT
    out=$(SECRET_ENV=$mark "$CLI" --log-level trace image build --tls-verify=false --secret id=tok,src="$WORKDIR/secret.txt" \
        --secret id=fromenv,env=SECRET_ENV -t localhost/bm:secret "$c" 2>&1)
    check "build with secrets" 0 $?
    local sum
    sum=$(printf %s "$mark" | sha256sum | cut -c1-16)
    check "secret files, a variable" "$sum
400 0
440 1000
$sum
${#mark}
0" "$("$CLI" run --rm --network none localhost/bm:secret cat /mode 2>&1)"
    check "not in the image" "" "$("$CLI" run --rm --network none localhost/bm:secret sh -c 'ls -A /run/secrets /etc/tok 2> /dev/null')"
    "$CLI" image save -o "$WORKDIR/secret-image.tar" localhost/bm:secret > /dev/null 2>&1
    mkdir -p "$WORKDIR/secret-image"
    tar -C "$WORKDIR/secret-image" -xf "$WORKDIR/secret-image.tar"
    local hits=0 b
    for b in "$WORKDIR"/secret-image/blobs/sha256/*; do
        if { zstd -dcq "$b" 2> /dev/null || gzip -dc "$b" 2> /dev/null || cat "$b"; } | grep -aq "$mark"; then
            hits=$((hits + 1))
        fi
    done
    check "not in the layers, the config or the manifest" 0 "$hits"
    check "not in the history" 0 "$("$CLI" image history --no-trunc localhost/bm:secret 2>&1 | grep -c "$mark")"
    check "not in the output of the build (trace)" 0 "$(printf '%s\n' "$out" | grep -c "$mark")"
    # the engine of the command, in its process, logs to its standard error
    local t=$WORKDIR/tracestore
    mkdir -p "$t"
    cat > "$t/config.toml" <<EOT
storage.root = "$t/store"
$(e2e_bridge_toml)
[engine]
socket = "$t/engine.sock"
[server]
socket = "$t/engine.sock"
state_dir = "$t/state"
root_dir = "$t/root"
EOT
    out=$(VELARX_SOCKET= SECRET_ENV=$mark "$BIN/velarx" --config "$t/config.toml" --log-level trace image build --tls-verify=false \
        --secret id=tok,src="$WORKDIR/secret.txt" --secret id=fromenv,env=SECRET_ENV -t localhost/bm:secret-trace "$c" 2>&1)
    check "a build in the engine of the command" 0 $?
    check "the engine of the command logs at trace" 1 "$(printf '%s\n' "$out" | grep -c -m1 TRACE)"
    check "not in the logs of the engine (trace)" 0 "$(printf '%s\n' "$out" | grep -c "$mark")"
    # (the RUN containers' records: the variable of TOK is the spec's only)
    check "not in the database" 0 "$(find "$t" -name 'db.sqlite*' -exec cat {} + 2> /dev/null | grep -ac "$mark")"
    # (the store holds files of the user namespace)
    VELARX_SOCKET= "$BIN/velarx" --config "$t/config.toml" unshare rm -rf "$t" > /dev/null 2>&1
    check "no secret file is left in the state directory" "" "$(find "$XDG_RUNTIME_DIR/velarx/build" -type f 2> /dev/null)"
    # the same through podman's route
    out=$(SECRET_ENV=$mark pm build --tls-verify=false --secret id=tok,src="$WORKDIR/secret.txt" --secret id=fromenv,env=SECRET_ENV -t localhost/bm:secret-remote "$c" 2>&1)
    check_match "podman build --secret" "[0-9a-f]{64}$" "$out"
    check "podman: secret files, a variable" "$sum
400 0
440 1000
$sum
${#mark}
0" "$(pm run --rm localhost/bm:secret-remote cat /mode 2>&1)"
    check "podman: not in the history" 0 "$(pm image history --no-trunc localhost/bm:secret-remote 2>&1 | grep -c "$mark")"
    check "podman: not in the context" "Containerfile" "$(pm run --rm localhost/bm:secret-remote ls /ctxcopy 2>&1)"
    check "podman: not in the logs of velarx-api (trace)" 0 "$(grep -c "$mark" "$WORKDIR/daemon.log")"
    printf 'FROM %s\nRUN --mount=type=secret,id=nope,required true\n' "$IMG" > "$c/Containerfile"
    out=$("$CLI" image build --tls-verify=false "$c" 2>&1)
    check_match "a required secret that is missing" "secret required but no secret with id \"nope\" found" "$out"
    out=$("$CLI" image build --tls-verify=false --secret id=x,src="$WORKDIR/nosuchfile" "$c" 2>&1)
    check_match "a secret file that is not there" "could not parse secrets" "$out"
    pm rmi -f localhost/bm:secret localhost/bm:secret-remote > /dev/null 2>&1
}

@test "build --mount: transient mounts of every RUN step" {
    local c=$WORKDIR/transient out
    mkdir -p "$c"
    printf 'tokvalue' > "$WORKDIR/transient-secret.txt"
    cat > "$c/Containerfile" <<EOT
FROM $IMG
RUN cat /run/secrets/tok > /seen
RUN echo one > /c/a
RUN cat /c/a > /cached
RUN grep ' /t ' /proc/mounts | grep -o 'size=[0-9]*k' > /sizes
RUN --mount=type=tmpfs,target=/t,size=2m grep ' /t ' /proc/mounts | grep -o 'size=[0-9]*k' >> /sizes
EOT
    out=$("$CLI" image build --tls-verify=false --layers --secret id=tok,src="$WORKDIR/transient-secret.txt" \
        --mount type=secret,id=tok --mount type=cache,target=/c,id=transient$$ --mount type=tmpfs,target=/t,size=1m \
        -t localhost/bm:transient "$c" 2>&1)
    check "build --mount" 0 $?
    check "a secret in every step, not in the image" "tokvalue" \
        "$("$CLI" run --rm --network none localhost/bm:transient cat /seen 2>&1)"
    check "the cache is shared by the steps, not in the image" "one" \
        "$("$CLI" run --rm --network none localhost/bm:transient sh -c 'cat /cached; ls -A /c /run/secrets 2> /dev/null' 2>&1)"
    check "the step's own mount wins on a target" "size=2048k" \
        "$("$CLI" run --rm --network none localhost/bm:transient tail -n1 /sizes 2>&1)"
    # a different mount is not served by the cache of the first build
    out=$("$CLI" image build --tls-verify=false --layers --secret id=tok,src="$WORKDIR/transient-secret.txt" \
        --mount type=secret,id=tok --mount type=cache,target=/c,id=transient$$ --mount type=tmpfs,target=/t,size=3m \
        -t localhost/bm:transient2 "$c" 2>&1)
    check "build with another mount" 0 $?
    check "...runs the step again" "size=3072k" \
        "$("$CLI" run --rm --network none localhost/bm:transient2 sh -c 'head -n1 /sizes' 2>&1)"
    out=$("$CLI" image build --tls-verify=false --mount type=nfs,target=/x -t localhost/bm:transient3 "$c" 2>&1)
    check "a bad mount" 125 $?
    out=$("$CLI" image build --tls-verify=false --mount type=tmpfs,target=/x --mount type=cache,target=/x \
        -t localhost/bm:transient3 "$c" 2>&1)
    check "two mounts of the build on one target" 125 $?
    check_match "...name it" "/x: duplicate mount destination" "$out"
    # the same through podman's route
    out=$(pm build --tls-verify=false --secret id=tok,src="$WORKDIR/transient-secret.txt" \
        --mount type=secret,id=tok --mount type=cache,target=/c,id=transient$$ --mount type=tmpfs,target=/t,size=1m \
        -t localhost/bm:transient-remote "$c" 2>&1)
    check "podman build --mount" 0 $?
    check "podman: a secret in every step, not in the image" "tokvalue" \
        "$(pm run --rm localhost/bm:transient-remote cat /seen 2>&1)"
    "$CLI" rmi -f localhost/bm:transient localhost/bm:transient2 > /dev/null 2>&1
    pm rmi -f localhost/bm:transient-remote > /dev/null 2>&1
}

@test "podman build --save-stages and --stage-labels" {
    local c=$WORKDIR/stages out
    mkdir -p "$c"
    printf 'FROM %s AS first\nLABEL a=1\nFROM first\nLABEL b=2\n' "$IMG" > "$c/Containerfile"
    out=$(pm build --tls-verify=false --layers=false --save-stages --stage-labels -t localhost/bm:stages "$c" 2>&1)
    check "podman build --save-stages --stage-labels" 0 $?
    check "the built image has the labels of its stage" "1" \
        "$(pm image inspect --format '{{index .Config.Labels "io.buildah.stage.name"}}' localhost/bm:stages)"
    check "the image of the first stage stays" "first" \
        "$(pm images -a --filter label=io.buildah.stage.name=first --format '{{index .Labels "io.buildah.stage.name"}}')"
    pm rmi -f localhost/bm:stages > /dev/null 2>&1
}

@test "Docker build: securityopt takes label, apparmor and seccomp" {
    local c=$WORKDIR/secopt code
    mkdir -p "$c"
    printf 'FROM %s\nRUN grep -E "^Seccomp:" /proc/self/status > /seccomp\n' "$IMG" > "$c/Containerfile"
    tar -C "$c" -cf "$WORKDIR/secopt.tar" Containerfile
    code=$(api -g -o "$WORKDIR/out" -w '%{http_code}' -X POST -H "Content-Type: application/x-tar" --data-binary "@$WORKDIR/secopt.tar" \
        "http://d/v5.0.0/build?t=localhost/bm:secopt&nocache=1&securityopt=%5B%22seccomp%3Dunconfined%22%5D")
    check "build?securityopt=seccomp=unconfined" 200 "$code"
    check_match "the steps have no seccomp filter" '^Seccomp:\s+0$' \
        "$("$CLI" run --rm --network none localhost/bm:secopt cat /seccomp 2>&1)"
    for opt in no-new-privileges "no-new-privileges%3Dtrue" bogus "bogus%3D1"; do
        code=$(api -g -o "$WORKDIR/out" -w '%{http_code}' -X POST -H "Content-Type: application/x-tar" --data-binary "@$WORKDIR/secopt.tar" \
            "http://d/v5.0.0/build?securityopt=%5B%22$opt%22%5D")
        check "securityopt $opt" 400 "$code"
    done
    "$CLI" rmi -f localhost/bm:secopt > /dev/null 2>&1
}

@test "podman build --source-policy-file" {
    local c=$WORKDIR/policy
    mkdir -p "$c"
    printf 'FROM %s\nLABEL policy=yes\n' "$IMG" > "$c/Containerfile"
    printf '{"rules": [{"action": "DENY", "selector": {"identifier": "docker-image://*"}}]}\n' > "$WORKDIR/deny.json"
    out=$(pm build --tls-verify=false --source-policy-file "$WORKDIR/deny.json" -t localhost/bm:policy "$c" 2>&1)
    check "a base image the policy denies" 125 $?
    check_match "...is refused" "denied by the source policy" "$out"
    printf '{"rules": [{"action": "ALLOW", "selector": {"identifier": "docker-image://*"}}]}\n' > "$WORKDIR/allow.json"
    pm build --tls-verify=false --source-policy-file "$WORKDIR/allow.json" -t localhost/bm:policy "$c" > /dev/null 2>&1
    check "a base image it allows" 0 $?
    pm rmi -f localhost/bm:policy > /dev/null 2>&1
}

@test "podman build --ignorefile: in the context or out of it, over .dockerignore" {
    local c=$WORKDIR/ignf f out
    mkdir -p "$c"
    echo x > "$c/kept-file"
    echo kept-file > "$c/.dockerignore"
    printf 'FROM %s\nCOPY . /d/\nRUN ls /d\n' "$IMG" > "$c/Containerfile"
    touch "$c/.empty" "$WORKDIR/outside-ignore"
    for f in "$c/.empty" "$WORKDIR/outside-ignore"; do
        out=$(pm build --tls-verify=false --no-cache --ignorefile "$f" "$c" 2>&1)
        check "podman build --ignorefile $f" 0 $?
        check_match "...the file .dockerignore names is copied" "kept-file" "$out"
    done
}

@test "build --build-context: a directory, an image; COPY --from and RUN --mount from=" {
    local c=$WORKDIR/named
    mkdir -p "$c" "$WORKDIR/extra/sub"
    printf 'extra file\n' > "$WORKDIR/extra/sub/e.txt"
    cat > "$c/Containerfile" <<EOT
FROM $IMG
COPY --from=extra sub/e.txt /copied
RUN --mount=type=bind,from=extra,source=sub,target=/e cat /e/e.txt > /bound
COPY --from=base /etc/os-release /os-release
EOT
    "$CLI" image build --tls-verify=false --build-context extra="$WORKDIR/extra" --build-context base=docker-image://"$IMG" -t localhost/bm:named "$c" > "$WORKDIR/named.out" 2>&1
    check "build with named contexts" 0 $?
    check "contents" "extra file
extra file
1" "$("$CLI" run --rm --network none localhost/bm:named sh -c 'cat /copied /bound; grep -c ^ID= /os-release' 2>&1)"
    out=$(pm build --tls-verify=false --build-context extra="$WORKDIR/extra" --build-context base=docker-image://"$IMG" -t localhost/bm:named-remote "$c" 2>&1)
    check_match "podman build --build-context (a multipart body)" "[0-9a-f]{64}$" "$out"
    check "podman: contents" "extra file
extra file" "$(pm run --rm localhost/bm:named-remote cat /copied /bound 2>&1)"
    out=$("$CLI" image build --tls-verify=false --build-context bad "$c" 2>&1)
    check_match "a build context without a value" "NAME=VALUE" "$out"
    pm rmi -f localhost/bm:named localhost/bm:named-remote > /dev/null 2>&1
}

@test "build --ssh: RUN --mount=type=ssh reaches the agent of the client" {
    command -v ssh-agent > /dev/null && command -v ssh-add > /dev/null || skip "no ssh-agent"
    local c=$WORKDIR/ssh img=$IMG
    mkdir -p "$c"
    # an image with the ssh-add of the host
    BINARIES="sh cat stat ssh-add wc ls" e2e_make_image localhost/bm-ssh:1
    local sshimg=$IMG
    IMG=$img
    ssh-keygen -q -t ed25519 -N '' -C bm-test-key -f "$WORKDIR/key" > /dev/null
    eval "$(ssh-agent -s)" > /dev/null
    ssh-add -q "$WORKDIR/key" 2> /dev/null
    cat > "$c/Containerfile" <<EOT
FROM $sshimg
RUN --mount=type=ssh ssh-add -l > /keys; ssh-add -l >> /keys; echo \$SSH_AUTH_SOCK >> /keys
RUN --mount=type=ssh,id=other,target=/agent,uid=1000,mode=0660 stat -c '%u %a' /agent >> /keys; SSH_AUTH_SOCK=/agent ssh-add -l | wc -l >> /keys
RUN --mount=type=ssh,id=nope ls /run/buildkit 2> /dev/null | wc -l >> /keys
EOT
    out=$("$CLI" image build --tls-verify=false --ssh default --ssh other="$SSH_AUTH_SOCK" -t localhost/bm:ssh "$c" 2>&1)
    local rc=$?
    check "build with agents" 0 $rc
    [ $rc = 0 ] || echo "$out" | tail -5 >&2
    local fp
    fp=$(ssh-add -l)
    check "the agent was reached, twice, and the second id" "$fp
$fp
/run/buildkit/ssh_agent.0
1000 660
1
0" "$("$CLI" run --rm --network none localhost/bm:ssh cat /keys 2>&1)"
    printf 'FROM %s\nRUN --mount=type=ssh,required=true true\n' "$sshimg" > "$c/Containerfile"
    out=$("$CLI" image build --tls-verify=false "$c" 2>&1)
    check_match "a required agent that is missing" "ssh required but no ssh with id default found" "$out"
    out=$("$CLI" image build --tls-verify=false --ssh k="$WORKDIR/key" "$c" 2>&1)
    check_match "a key file is refused" "ssh-add" "$out"
    kill "$SSH_AGENT_PID"
    pm rmi -f localhost/bm:ssh localhost/bm-ssh:1 > /dev/null 2>&1
}

@test "build options: --from, unused stages, --output, the times, --omit-history, labels, RUN resources" {
    local c=$WORKDIR/options
    mkdir -p "$c"
    cat > "$c/Containerfile" <<EOT
FROM $IMG AS unused
RUN exit 1
FROM $IMG AS used
RUN echo used > /used
FROM scratch
COPY --from=used /used /used
EOT
    out=$("$CLI" image build --tls-verify=false -t localhost/bm:stages "$c" 2>&1)
    check "the stages the target does not use are not built" 0 $?
    out=$("$CLI" image build --tls-verify=false --skip-unused-stages=false "$c" 2>&1)
    check_match "--skip-unused-stages=false builds them" "exit code 1" "$out"
    "$CLI" image build --tls-verify=false -q -o "$WORKDIR/out-dir" "$c" > /dev/null 2>&1
    check "--output DIR" used "$(cat "$WORKDIR/out-dir/used" 2>&1)"
    "$CLI" image build --tls-verify=false -q -o type=tar,dest="$WORKDIR/out.tar" "$c" > /dev/null 2>&1
    check "--output type=tar" used "$(tar -xOf "$WORKDIR/out.tar" used 2>&1)"
    out=$("$CLI" image build --tls-verify=false -o type=registry,dest=x "$c" 2>&1)
    check_match "--output type=registry is refused as podman does" "invalid type \"registry\" selected for build output options" "$out"

    cat > "$c/Containerfile.t" <<EOT
FROM nothing-of-this-name
ARG SOURCE_DATE_EPOCH
COPY Containerfile /copied
RUN echo "\$SOURCE_DATE_EPOCH" > /sde; id -G > /groups; cat /sys/fs/cgroup/memory.max > /mem
EOT
    out=$("$CLI" image build --tls-verify=false -q --from "$IMG" --source-date-epoch 1700000000 --rewrite-timestamp \
        --group-add 1234 --memory 64m -f "$c/Containerfile.t" -t localhost/bm:sde "$c" 2>&1)
    check "--from, --source-date-epoch, --group-add, --memory" 0 $?
    check "the RUN step" "1700000000 1234 67108864" \
        "$("$CLI" run --rm --network none localhost/bm:sde sh -c 'echo $(cat /sde) $(grep -o 1234 /groups) $(cat /mem)' 2>&1)"
    check "the time of the image" 2023-11-14T22:13:20Z "$("$CLI" image inspect --format '{{.Created}}' localhost/bm:sde 2>&1)"
    local a b
    a=$("$CLI" image build --tls-verify=false -q --from "$IMG" --timestamp 1600000000 --omit-history -f "$c/Containerfile.t" "$c" 2>&1)
    b=$("$CLI" image build --tls-verify=false -q --no-cache --from "$IMG" --timestamp 1600000000 --omit-history -f "$c/Containerfile.t" "$c" 2>&1)
    check "--timestamp: the same image again" "$a" "$b"
    check "--omit-history" 0 "$("$CLI" image inspect --format '{{len .History}}' "$a" 2>&1)"
    pm rmi -f "$a" > /dev/null 2>&1
    a=$("$CLI" image build --tls-verify=false -q --no-cache --from "$IMG" --source-date-epoch 1700000000 --rewrite-timestamp -f "$c/Containerfile.t" "$c" 2>&1)
    touch "$c/Containerfile"
    b=$("$CLI" image build --tls-verify=false -q --no-cache --from "$IMG" --source-date-epoch 1700000000 --rewrite-timestamp -f "$c/Containerfile.t" "$c" 2>&1)
    check "--source-date-epoch --rewrite-timestamp: the same image again" "$a" "$b"
    out=$("$CLI" image build --tls-verify=false --timestamp 1 --source-date-epoch 1 "$c" 2>&1)
    check_match "--timestamp with --source-date-epoch" "cannot be used together" "$out"
    out=$("$CLI" image build --tls-verify=false --isolation chroot "$c" 2>&1)
    check_match "--isolation chroot" "not supported by velarx" "$out"

    printf 'FROM %s\nLABEL mine=1\n' "$IMG" > "$c/Containerfile.l"
    "$CLI" image build --tls-verify=false -q -f "$c/Containerfile.l" -t localhost/bm:labels "$c" > /dev/null 2>&1
    printf 'FROM localhost/bm:labels\nLABEL other=2\n' > "$c/Containerfile.l2"
    "$CLI" image build --tls-verify=false -q --inherit-labels=false -f "$c/Containerfile.l2" -t localhost/bm:nolabels "$c" > /dev/null 2>&1
    check "--inherit-labels=false" '{"other":"2"}' \
        "$("$CLI" image inspect --format '{{json .Config.Labels}}' localhost/bm:nolabels 2>&1 | jq -c 'del(.["io.velarx.version"])')"

    # the same through podman's route
    out=$(pm build --tls-verify=false --from "$IMG" --timestamp 1600000000 -f "$c/Containerfile.t" -t localhost/bm:remote-time "$c" 2>&1)
    check_match "podman build --from --timestamp" "[0-9a-f]{64}$" "$out"
    check "podman: the time of the image" 2020-09-13T12:26:40Z "$(pm image inspect --format '{{.Created.UTC.Format "2006-01-02T15:04:05Z07:00"}}' localhost/bm:remote-time 2>&1)"
    pm rmi -f localhost/bm:stages localhost/bm:sde localhost/bm:labels localhost/bm:nolabels localhost/bm:remote-time "$a" > /dev/null 2>&1
}

@test "build ARG: a stage ARG sees the stage's ARGs before it, a global one again the global value" {
    local c=$WORKDIR/args
    mkdir -p "$c"
    # (buildah: b=1 c=g1)
    printf 'ARG G=g1\nFROM scratch\nARG A=1\nARG B=$A\nARG G\nARG C=$G\nLABEL b=$B c=$C\n' > "$c/Containerfile"
    "$CLI" image build -q -t localhost/bm:args "$c" > /dev/null 2>&1
    check "build" 0 $?
    check "the values of the ARGs" '{"b":"1","c":"g1"}' \
        "$("$CLI" image inspect --format '{{json .Config.Labels}}' localhost/bm:args 2>&1 | jq -c 'del(.["io.velarx.version"])')"
    "$CLI" image rm -f localhost/bm:args > /dev/null 2>&1
}

@test "build options: annotations, --http-proxy, --runtime-flag, -f outside of the context" {
    local c=$WORKDIR/annotations out
    mkdir -p "$c"
    printf 'FROM %s\nRUN echo "${http_proxy:-none}" > /proxy\n' "$IMG" > "$c/Containerfile"
    "$CLI" image build --tls-verify=false -q --annotation a=b --annotation c=d --unsetannotation c \
        -t localhost/bm:annotated "$c" > /dev/null 2>&1
    check "--annotation, --unsetannotation" 'b null true' \
        "$("$CLI" image inspect --format '{{json .Annotations}}' localhost/bm:annotated 2>&1 |
            jq -r '"\(.a) \(.c) \(has("org.opencontainers.image.created"))"')"
    check "the base is named" "$IMG" \
        "$("$CLI" image inspect --format '{{json .Annotations}}' localhost/bm:annotated 2>&1 | jq -r '.["org.opencontainers.image.base.name"]')"
    "$CLI" image build --tls-verify=false -q --inherit-annotations=false --created-annotation=false \
        -t localhost/bm:plain "$c" > /dev/null 2>&1
    check "--inherit-annotations=false --created-annotation=false" '{}' \
        "$("$CLI" image inspect --format '{{json .Annotations}}' localhost/bm:plain 2>&1 | jq -c 'del(.["composefs.merged.erofs.v1.fsverity-sha256-12"])')"

    http_proxy=http://proxy.invalid:3128 "$CLI" image build --tls-verify=false -q --no-cache -t localhost/bm:proxy "$c" > /dev/null 2>&1
    check "--http-proxy (the default): the RUN steps have the proxy" "http://proxy.invalid:3128" \
        "$("$CLI" run --rm --network none localhost/bm:proxy cat /proxy 2>&1)"
    check "not the image" "" "$("$CLI" image inspect --format '{{.Config.Env}}' localhost/bm:proxy 2>&1 | grep -o proxy.invalid)"
    http_proxy=http://proxy.invalid:3128 "$CLI" image build --tls-verify=false -q --no-cache --http-proxy=false -t localhost/bm:proxy "$c" > /dev/null 2>&1
    check "--http-proxy=false" "none" "$("$CLI" run --rm --network none localhost/bm:proxy cat /proxy 2>&1)"

    # (an engine of the command's own: the service has its own settings)
    out=$(VELARX_SOCKET= "$CLI" image build --tls-verify=false -q --no-cache --runtime-flag=debug "$c" 2>&1)
    check_match "--runtime-flag" "^[0-9a-f]{64}$" "$out"
    out=$("$CLI" image build --tls-verify=false --runtime-flag=debug "$c" 2>&1)
    check_match "--runtime-flag with the engine service" "settings of its own configuration" "$out"

    # podman: the annotations, and a Containerfile outside of the context
    mkdir -p "$WORKDIR/elsewhere"
    printf 'FROM %s\nRUN echo outside > /outside\n' "$IMG" > "$WORKDIR/elsewhere/Containerfile"
    out=$(pm build --tls-verify=false --annotation e=f --os-version 1.2 -f "$WORKDIR/elsewhere/Containerfile" -t localhost/bm:outside "$c" 2>&1)
    check_match "podman build -f of a Containerfile outside of the context" "[0-9a-f]{64}$" "$out"
    check "podman: the step" outside "$("$CLI" run --rm --network none localhost/bm:outside cat /outside 2>&1)"
    check "podman: --annotation" f \
        "$("$CLI" image inspect --format '{{json .Annotations}}' localhost/bm:outside 2>&1 | jq -r .e)"
    pm rmi -f localhost/bm:annotated localhost/bm:plain localhost/bm:proxy localhost/bm:outside > /dev/null 2>&1
}

@test "build --network: none, a named network, pasta; RUN --network" {
    local c=$WORKDIR/netmodes out
    mkdir -p "$c"
    # the interfaces the RUN step sees
    printf 'FROM %s\nRUN sed 1,2d /proc/net/dev | cut -d: -f1 | tr -d " " | sort | tr "\\n" " " > /ifs\n' "$IMG" > "$c/Containerfile"
    ifs() { "$CLI" run --rm --network none "$1" cat /ifs 2>&1; }
    "$CLI" network create bnet > /dev/null 2>&1
    check "network create" 0 $?

    "$CLI" image build --tls-verify=false -q --no-cache --network=none -t localhost/bm:net-none "$c" > /dev/null 2>&1
    check "--network=none: only lo" "lo " "$(ifs localhost/bm:net-none)"
    "$CLI" image build --tls-verify=false -q --no-cache --network=bnet -t localhost/bm:net-named "$c" > /dev/null 2>&1
    check_match "--network NAME: an interface of the network" "eth0" "$(ifs localhost/bm:net-named)"
    # (pasta is the network of a rootless engine, as in pasta.bats)
    if [ "$(id -u)" != 0 ]; then
        "$CLI" image build --tls-verify=false -q --no-cache --network=pasta -t localhost/bm:net-pasta "$c" > /dev/null 2>&1
        check_match "--network=pasta: an interface of pasta" "^[a-z][a-z0-9]* lo $" "$(ifs localhost/bm:net-pasta)"
        "$CLI" image build --tls-verify=false -q --no-cache --network=pasta:--no-map-gw -t localhost/bm:net-pasta-opts "$c" > /dev/null 2>&1
        check_match "--network=pasta:OPTIONS" "^[a-z][a-z0-9]* lo $" "$(ifs localhost/bm:net-pasta-opts)"
    fi
    # a RUN step's own network: default is the build's
    printf 'FROM %s\nRUN --network=default sed 1,2d /proc/net/dev | cut -d: -f1 | tr -d " " | sort | tr "\\n" " " > /ifs\n' "$IMG" > "$c/Containerfile.default"
    "$CLI" image build --tls-verify=false -q --no-cache --network=none -f "$c/Containerfile.default" -t localhost/bm:net-default "$c" > /dev/null 2>&1
    check "RUN --network=default: the network of the build" "lo " "$(ifs localhost/bm:net-default)"
    for bad in bnet pasta private bridge ns:/proc/self/ns/net container:x; do
        printf 'FROM %s\nRUN --network=%s true\n' "$IMG" "$bad" > "$c/Containerfile.bad"
        out=$("$CLI" image build --tls-verify=false -q --no-cache -f "$c/Containerfile.bad" "$c" 2>&1)
        check "RUN --network=$bad refused" 1 "$(( $? != 0 ))"
        check_match "RUN --network=$bad: message" "invalid --network \`$bad\`: default, none or host" "$out"
    done
    out=$("$CLI" image build --tls-verify=false -q --no-cache --network=container:x "$c" 2>&1)
    check_match "--network=container:ID refused" "unsupported network \`container:x\` for a build" "$out"

    "$CLI" rmi -f localhost/bm:net-none localhost/bm:net-named localhost/bm:net-pasta localhost/bm:net-pasta-opts localhost/bm:net-default > /dev/null 2>&1
    "$CLI" network rm bnet > /dev/null 2>&1
}

@test "podman --remote build: the network and the namespaces of the RUN steps" {
    local c=$WORKDIR/netmodes
    mkdir -p "$c"
    printf 'FROM %s\nRUN sed 1,2d /proc/net/dev | cut -d: -f1 | tr -d " " | sort | tr "\\n" " " > /ifs\n' "$IMG" > "$c/Containerfile"
    ifs() { "$CLI" run --rm --network none "$1" cat /ifs 2>&1; }
    "$CLI" network create bnet > /dev/null 2>&1
    check "network create" 0 $?
    pm build --tls-verify=false --no-cache --network=none -t localhost/bm:net-none-r "$c" > /dev/null 2>&1
    check "podman --remote build --network=none: only lo" "lo " "$(ifs localhost/bm:net-none-r)"
    pm build --tls-verify=false --no-cache --network=bnet -t localhost/bm:net-named-r "$c" > /dev/null 2>&1
    check_match "podman --remote build --network NAME" "eth0" "$(ifs localhost/bm:net-named-r)"
    if [ "$(id -u)" != 0 ]; then
        pm build --tls-verify=false --no-cache --network=pasta -t localhost/bm:net-pasta-r "$c" > /dev/null 2>&1
        check_match "podman --remote build --network=pasta" "^[a-z][a-z0-9]* lo $" "$(ifs localhost/bm:net-pasta-r)"
    fi
    # Docker's networkmode
    tar -C "$c" -cf "$WORKDIR/netctx.tar" Containerfile
    check "Docker's networkmode=none" 200 "$(api -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/x-tar' \
        --data-binary "@$WORKDIR/netctx.tar" 'http://d/v1.41/build?networkmode=none&t=localhost/bm:net-docker')"
    check "Docker: only lo" "lo " "$(ifs localhost/bm:net-docker)"

    # the other namespaces of podman --remote
    pm build --tls-verify=false --no-cache --ipc=host --pid=private --uts=private --userns=private \
        -t localhost/bm:ns-r "$c" > /dev/null 2>&1
    check "podman --remote build --ipc --pid --uts --userns" 0 $?

    "$CLI" rmi -f localhost/bm:net-none-r localhost/bm:net-named-r localhost/bm:net-pasta-r localhost/bm:net-docker localhost/bm:ns-r > /dev/null 2>&1
    "$CLI" network rm bnet > /dev/null 2>&1
}

@test "build: VOLUME as buildah (--compat-volumes as Docker), the identity label" {
    local c=$WORKDIR/volumes out
    mkdir -p "$c"
    cat > "$c/Containerfile" <<EOT
FROM $IMG
VOLUME /v /deep/er
RUN echo kept > /v/f && ls -d /deep/er > /dirs
RUN cat /v/f > /seen
EOT
    out=$("$CLI" image build --tls-verify=false -q --no-cache -t localhost/bm:vol "$c" 2>&1)
    check "VOLUME: the RUN steps keep what they write" 0 $?
    check "the file is in the image" "kept /deep/er" \
        "$("$CLI" run --rm --network none localhost/bm:vol sh -c 'echo $(cat /seen) $(cat /dirs)' 2>&1)"
    check "the volumes are in the configuration" '{"/deep/er":{},"/v":{}}' \
        "$("$CLI" image inspect --format '{{json .Config.Volumes}}' localhost/bm:vol 2>&1)"
    out=$("$CLI" image build --tls-verify=false -q --no-cache --compat-volumes -t localhost/bm:compat "$c" 2>&1)
    check "--compat-volumes: what a RUN step writes in a volume is discarded" 125 $?
    check_match "...as the next step finds" "cat /v/f" "$out"
    out=$(pm build --tls-verify=false --compat-volumes --no-cache -t localhost/bm:compat "$c" 2>&1)
    check "podman build --compat-volumes: the same" 125 $?
    out=$(pm build --tls-verify=false --no-cache -t localhost/bm:vol2 "$c" 2>&1)
    check "podman build: the default keeps it" 0 $?
    # a VOLUME on a directory a step made: no layer of its own
    printf 'FROM %s\nRUN mkdir /w && echo base > /w/f\nVOLUME /w\nRUN echo new > /w/g\nRUN ls /w > /wl\n' "$IMG" > "$c/Containerfile"
    "$CLI" image build --tls-verify=false -q --no-cache --compat-volumes -t localhost/bm:compat2 "$c" > /dev/null 2>&1
    check "--compat-volumes on a directory of the image" "f" "$("$CLI" run --rm --network none localhost/bm:compat2 cat /wl 2>&1)"
    "$CLI" image build --tls-verify=false -q --no-cache -t localhost/bm:compat3 "$c" > /dev/null 2>&1
    check "...and without" "f g" "$("$CLI" run --rm --network none localhost/bm:compat3 sh -c 'echo $(cat /wl)' 2>&1)"

    printf 'FROM %s\nRUN true\n' "$IMG" > "$c/Containerfile"
    idlabel () { "$CLI" image inspect --format '{{json .Config.Labels}}' "$1" 2>&1 | jq -r '.["io.velarx.version"] // ""'; }
    out=$("$CLI" image build --tls-verify=false -q --no-cache -t localhost/bm:id "$c" 2>&1)
    check_match "the label that names the builder" "^[0-9]+[.][0-9]+" "$(idlabel localhost/bm:id)"
    for opts in "--timestamp 5" "--source-date-epoch 5" "--identity-label=false"; do
        "$CLI" image build --tls-verify=false -q --no-cache $opts -t localhost/bm:id "$c" > /dev/null 2>&1
        check "no label with $opts" "" "$(idlabel localhost/bm:id)"
    done
    "$CLI" image build --tls-verify=false -q --no-cache --timestamp 5 --identity-label -t localhost/bm:id "$c" > /dev/null 2>&1
    check_match "--identity-label with --timestamp" "^[0-9]+[.][0-9]+" "$(idlabel localhost/bm:id)"
    printf 'FROM %s\nLABEL io.velarx.version=mine\n' "$IMG" > "$c/Containerfile"
    "$CLI" image build --tls-verify=false -q --no-cache -t localhost/bm:id "$c" > /dev/null 2>&1
    check_match "the identity label wins over a LABEL of the Containerfile" "^[0-9]+[.][0-9]+" "$(idlabel localhost/bm:id)"
    "$CLI" image build --tls-verify=false -q --no-cache --identity-label=false -t localhost/bm:id "$c" > /dev/null 2>&1
    check "...and without it the LABEL stays" "mine" "$(idlabel localhost/bm:id)"
    "$CLI" image build --tls-verify=false -q --no-cache --label io.velarx.version=cli -t localhost/bm:id "$c" > /dev/null 2>&1
    check_match "...it wins over --label too" "^[0-9]+[.][0-9]+" "$(idlabel localhost/bm:id)"
    "$CLI" image build --tls-verify=false -q --no-cache --label io.velarx.version=cli --unsetlabel io.velarx.version -t localhost/bm:id "$c" > /dev/null 2>&1
    check "...and --unsetlabel over both" "" "$(idlabel localhost/bm:id)"
    pm rmi -f localhost/bm:vol localhost/bm:vol2 localhost/bm:compat2 localhost/bm:compat3 localhost/bm:id > /dev/null 2>&1
}

@test "build --cache-to and --cache-from: the images of the steps in a repository" {
    local c=$WORKDIR/cache out repo=${CACHE_REGISTRY:-$E2E_REGISTRY}/e2e/cache-$$
    mkdir -p "$c"
    printf 'FROM %s\nRUN echo one > /one\nCOPY Containerfile /c\nRUN echo two > /two\n' "$IMG" > "$c/Containerfile"
    local first second
    first=$("$CLI" image build --tls-verify=false -q --cache-to "$repo" -t localhost/bm:cache1 "$c" 2>&1)
    check_match "--cache-to" "^[0-9a-f]{64}$" "$first"
    check "a tag for each step" 3 "$(curl -s "http://${repo%%/*}/v2/${repo#*/}/tags/list" | jq '.tags | length')"
    "$CLI" image prune -f --build-cache > /dev/null 2>&1
    pm rmi -f localhost/bm:cache1 > /dev/null 2>&1
    out=$("$CLI" image build --tls-verify=false --cache-from "$repo" -t localhost/bm:cache2 "$c" 2>&1)
    check "--cache-from" 0 $?
    check "...the steps come from the repository" 3 "$(grep -c -- '--> Using cache' <<< "$out")"
    second=$(pm image inspect --format '{{.Id}}' localhost/bm:cache2 2>&1)
    check "the same image" "$first" "$second"
    pm rmi -f localhost/bm:cache2 > /dev/null 2>&1
    "$CLI" image prune -f --build-cache > /dev/null 2>&1
    out=$("$CLI" image build --tls-verify=false --no-cache --cache-from "$repo" -t localhost/bm:cache3 "$c" 2>&1)
    check "--no-cache ignores the repository" 0 "$(grep -c -- '--> Using cache' <<< "$out")"
    out=$("$CLI" image build --tls-verify=false --cache-from localhost:1/none -t localhost/bm:cache4 "$c" 2>&1)
    check "a repository that cannot be reached is no cache" 0 $?
    pm rmi -f localhost/bm:cache3 localhost/bm:cache4 > /dev/null 2>&1
}

@test "COPY --parents and COPY/ADD --exclude, as buildah" {
    local c=$WORKDIR/parents out
    mkdir -p "$c/sub/deep"
    for f in a.txt a.log sub/b.txt sub/b.log sub/deep/c.txt sub/deep/c.log; do echo "$f" > "$c/$f"; done
    cat > "$c/Containerfile" <<EOT
FROM $IMG AS s
COPY . /src/
FROM $IMG
COPY --exclude=*.log . /t1/
COPY --exclude=sub/*.log sub /t2/
COPY --exclude=**/*.log sub /t3/
ADD --exclude=sub/deep sub /t4/
COPY --parents sub/deep/c.txt /p1/
COPY --parents sub/./deep/c.txt /p2/
COPY --parents --exclude=**/*.log sub/ /p3/
COPY --parents a.* sub/b.* /p4/
COPY --from=s --parents /src/sub/./deep/c.txt /p5/
COPY --from=s --exclude=src/sub/*.log /src/sub /p6
COPY --parents --chown=1:2 sub/./deep/c.txt /p7/x/
RUN stat -c %u:%g /p7 /p7/x /p7/x/deep > /owners && cd / && find t1 t2 t3 t4 p1 p2 p3 p4 p5 p6 -type f | sort > /found
EOT
    out=$("$CLI" image build --tls-verify=false -q -t localhost/bm:parents "$c" 2>&1)
    check "build" 0 $?
    check "--chown: the directories the copy makes too, as buildah" "1:2 1:2 1:2" \
        "$("$CLI" run --rm --network none localhost/bm:parents sh -c 'echo $(cat /owners)' 2>&1)"
    check "the files" "p1/sub/deep/c.txt
p2/deep/c.txt
p3/sub/b.txt
p3/sub/deep/c.txt
p4/a.log
p4/a.txt
p4/sub/b.log
p4/sub/b.txt
p5/deep/c.txt
p6/b.txt
p6/deep/c.log
p6/deep/c.txt
t1/Containerfile
t1/a.txt
t1/sub/b.log
t1/sub/b.txt
t1/sub/deep/c.log
t1/sub/deep/c.txt
t2/b.txt
t2/deep/c.log
t2/deep/c.txt
t3/b.txt
t3/deep/c.txt
t4/b.log
t4/b.txt" "$("$CLI" run --rm --network none localhost/bm:parents cat /found 2>&1)"
    printf 'FROM %s\nADD --parents a.txt /x/\n' "$IMG" > "$c/Containerfile"
    out=$("$CLI" image build --tls-verify=false "$c" 2>&1)
    check_match "ADD --parents is refused as buildah does" "ADD only supports the --chmod" "$out"
    printf 'FROM %s\nRUN echo x > /file\nCOPY --parents a.txt /file\n' "$IMG" > "$c/Containerfile"
    out=$("$CLI" image build --tls-verify=false "$c" 2>&1)
    check_match "--parents onto a file fails as buildah" "already exists but is not a directory" "$out"
    pm rmi -f localhost/bm:parents > /dev/null 2>&1
}

@test "build --layer-label and --cpp-flag" {
    local c=$WORKDIR/layers out
    mkdir -p "$c"
    printf 'FROM %s\nRUN echo 1 > /a\nLABEL keep=user\nRUN echo 2 > /b\nENV X=1\n' "$IMG" > "$c/Containerfile"
    out=$("$CLI" image build --tls-verify=false --no-cache --layer-label step=mid --layer-label bare --layer-label keep=layer -t localhost/bm:layers "$c" 2>&1)
    check "the last image has no layer label, the labels of the stage stay" '{"keep":"user"}' \
        "$("$CLI" image inspect --format '{{json .Config.Labels}}' localhost/bm:layers 2>&1 | jq -c 'del(.["io.velarx.version"])')"
    local mid
    mid=$(grep -o -- '--> [0-9a-f]*' <<< "$out" | sed -n 1p | cut -c5-)
    check "an intermediate image has them" 'mid||layer' \
        "$("$CLI" image inspect --format '{{json .Config.Labels}}' "$mid" 2>&1 | jq -r '(.step|tostring) + "|" + .bare + "|" + .keep')"
    mid=$(grep -o -- '--> [0-9a-f]*' <<< "$out" | sed -n 2p | cut -c5-)
    check "...but a label of the stage wins, as buildah" 'mid|user' \
        "$("$CLI" image inspect --format '{{json .Config.Labels}}' "$mid" 2>&1 | jq -r '(.step|tostring) + "|" + .keep')"
    printf 'FROM %s\n#ifdef EXTRA\nRUN echo extra > /e\n#endif\nRUN echo VERSION_STR > /v\nRUN echo linux http://x//y > /w\n' "$IMG" > "$c/Containerfile.in"
    "$CLI" image build --tls-verify=false -q --cpp-flag=-DEXTRA --cpp-flag=-DVERSION_STR=7 -f "$c/Containerfile.in" -t localhost/bm:cpp "$c" > /dev/null 2>&1
    check "--cpp-flag" "extra 7" "$("$CLI" run --rm --network none localhost/bm:cpp sh -c 'echo $(cat /e) $(cat /v)' 2>&1)"
    "$CLI" image build --tls-verify=false -q -f "$c/Containerfile.in" -t localhost/bm:cpp2 "$c" > /dev/null 2>&1
    check "a Containerfile *.in is preprocessed without flags too" "VERSION_STR" "$("$CLI" run --rm --network none localhost/bm:cpp2 cat /v 2>&1)"
    check "...as buildah: no macro predefined, // is no comment" "linux http://x//y" "$("$CLI" run --rm --network none localhost/bm:cpp2 cat /w 2>&1)"
    out=$(pm build --tls-verify=false -f "$c/Containerfile.in" "$c" 2>&1)
    check_match "the build routes refuse a Containerfile *.in" "named [*][.]in is not supported" "$out"
    pm rmi -f localhost/bm:layers localhost/bm:cpp localhost/bm:cpp2 > /dev/null 2>&1
}

@test "build --sbom-*: a scanner image runs on the root of the image and the context" {
    local c=$WORKDIR/sbom out
    mkdir -p "$c"
    printf 'FROM %s\nRUN echo hi > /hi\n' "$IMG" > "$c/Containerfile"
    cat > "$c/one.sh" <<'EOT'
test -f /.rootfs/hi || exit 1
echo '{"components":[{"name":"rootfs","version":"1","purl":"pkg:r@1"}]}' > "$1"
EOT
    cat > "$c/two.sh" <<'EOT'
test -f /.context0/Containerfile || exit 1
echo '{"components":[{"name":"ctx","version":"1","purl":"pkg:c@1"},{"name":"rootfs","version":"1"}]}' > "$1"
EOT
    local one="sh {CONTEXT}/one.sh {OUTPUT}" two="sh {CONTEXT}/two.sh {OUTPUT}"
    out=$("$CLI" image build --tls-verify=false -q --no-cache --sbom-scanner-image "$IMG" \
        --sbom-scanner-command "$one" --sbom-scanner-command "$two" \
        --sbom-merge-strategy merge-cyclonedx-by-component-name-and-version \
        --sbom-output "$WORKDIR/sbom.json" --sbom-purl-output "$WORKDIR/purls" \
        --sbom-image-output /sbom/bom.json --sbom-image-purl-output /sbom/purls -t localhost/bm:sbom "$c" 2>&1)
    check "build" 0 $?
    check "the merged document" "rootfs ctx" "$(jq -r '[.components[].name] | join(" ")' "$WORKDIR/sbom.json")"
    check "the package URLs, as buildah writes them" '{"image_contents":{"dependencies":["pkg:c@1","pkg:r@1"]}}' "$(cat "$WORKDIR/purls")"
    check "in the image" "rootfs ctx pkg:c@1" \
        "$("$CLI" run --rm --network none localhost/bm:sbom sh -c 'cat /sbom/bom.json' 2>&1 | jq -r '[.components[].name] | join(" ")') $(
            "$CLI" run --rm --network none localhost/bm:sbom cat /sbom/purls 2>&1 | jq -r '.image_contents.dependencies[0]')"
    out=$("$CLI" image build --tls-verify=false --sbom syft "$c" 2>&1)
    check_match "an SBOM without an output" "missing one or more of [(]\"--sbom-output\"" "$out"
    out=$("$CLI" image build --tls-verify=false --sbom nope --sbom-output "$WORKDIR/x" "$c" 2>&1)
    check_match "a preset that is none" "unrecognized preset name" "$out"
    out=$("$CLI" image build --tls-verify=false --sbom-scanner-image "$IMG" --sbom-scanner-command "$one" --sbom-output "$WORKDIR/x" "$c" 2>&1)
    check_match "a command needs a merge strategy, as buildah" "unrecognized merge strategy" "$out"
    out=$("$CLI" image build --tls-verify=false --sign-by me "$c" 2>&1)
    check_match "--sign-by is refused with its reason" "not supported by velarx's build yet: --sign-by [(]a build does not sign: sign what it made with \`push --sign-by\` or \`image sign --sign-by\`, or with \`push --sign-by-sigstore-private-key\`[)]" "$out"
    out=$("$CLI" image build --tls-verify=false --log-rusage --rusage-logfile=x "$c" 2>&1)
    check_match "--log-rusage and --rusage-logfile are refused" "not supported by velarx's build yet: --log-rusage [(]the resource usage of the steps is not logged[)], --rusage-logfile" "$out"
    out=$("$CLI" image build --tls-verify=false --log-rusage=false -t localhost/bm:sbom "$c" 2>&1)
    check "--log-rusage=false is no ask" 0 $?
    pm rmi -f localhost/bm:sbom > /dev/null 2>&1
}

@test "system prune --build: the containers of builds that are gone" {
    # (the label names the process of the build: one that ended, this one)
    local gone
    sh -c 'exit 0' &
    gone=$!
    wait "$gone"
    "$CLI" run -d --name bm-left --label io.velarx.build="$gone" "$IMG" sleep 600 > /dev/null 2>&1
    "$CLI" run -d --name bm-live --label io.velarx.build=$$ "$IMG" sleep 600 > /dev/null 2>&1
    "$CLI" system prune -f > /dev/null 2>&1
    check "system prune leaves a running build container" "bm-left bm-live" \
        "$(echo $("$CLI" ps -a --format '{{.Names}}' --filter name=bm- 2>&1 | sort))"
    out=$("$CLI" system prune -f --build 2>&1)
    check "system prune --build" 0 $?
    check "the container of a build that is gone goes, running or not" "bm-live" \
        "$(echo $("$CLI" ps -a --format '{{.Names}}' --filter name=bm- 2>&1 | sort))"
    "$CLI" run -d --name bm-left2 --label io.velarx.build="$gone" "$IMG" sleep 600 > /dev/null 2>&1
    pm system prune -f --build > /dev/null 2>&1
    check "podman system prune --build" "bm-live" \
        "$(echo $("$CLI" ps -a --format '{{.Names}}' --filter name=bm- 2>&1 | sort))"
    "$CLI" rm -f -t 0 bm-live > /dev/null 2>&1
}
