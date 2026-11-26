# SPDX-License-Identifier: Apache-2.0
# End to end tests of the REST API, builds: the multistage
# image of tests/fixtures/build, --target, --squash, the confinement of COPY,
# a push pulled by podman fully and partially.  Through the velarx CLI
# and podman --remote (see api_helpers.bash).

load ../helpers
load ../api_helpers

setup_file () {
    api_setup_file
}

teardown_file () {
    api_teardown_file
}

# podman on a store of its own (rootless) leaves a pause process that holds
# bats's fd 3: the commands close it, the test stops the process.
teardown () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pp=$XDG_RUNTIME_DIR/libpod/tmp/pause.pid
    [ ! -f "$pp" ] || kill "$(cat "$pp")" 2> /dev/null
    [ "$E2E_FAILS" = 0 ] || exit 1
}

# The output of the last step of a build's standard output (the progress of
# the commit is on the standard error, as podman's).
last_step () {
    awk '/STEP [0-9]+\/[0-9]+: /{buf=""; grab=1; next} grab && /^(-->|COMMIT)/{grab=0} grab{buf=buf $0 "\n"} END{printf "%s", buf}'
}

# The variables of the builds and the context (made once), the content checks
# run in the built image.
build_prep () {
    bw=$WORKDIR/build
    ctx=$bw/context
    base="--build-arg BASE=$IMG"
    if [ ! -d "$ctx" ]; then
        mkdir -p "$ctx" "$bw/arch"
        cp -a "$E2E_DIR/../fixtures/build/." "$ctx/"
        printf 'inner\n' > "$bw/arch/inner.txt"
        tar -czf "$ctx/archive.tar.gz" -C "$bw/arch" inner.txt
    fi
    checks='
test "$(cat /app/greeting.txt)" = "hello from /app" || echo "greeting"
test "$(cat /app/built.txt)" = "built e2e" || echo "build-arg"
test "$(cat /app/artifact)" = artifact || echo "copy --from directory"
test "$(cat /app/exec)" = exec-form || echo "exec form"
test "$(cat /app/asset.txt)" = asset || echo "copy --from scratch stage"
test -f /app/files/a.txt -a -f /app/files/sub/b.txt -a -f /app/files/keep.tmp || echo "copy directory"
test ! -e /app/files/secret.txt -a ! -e /app/files/x.tmp || echo "containerignore"
test "$(stat -c %u:%g:%a /app/owned.txt)" = 1000:1000:640 || echo "chown chmod"
test "$(cat /app/extracted/inner.txt)" = inner || echo "add archive"
test "$(cat /app/added.txt)" = hello || echo "add file"
test ! -e /etc/motd || echo "whiteout"
test "$(stat -c %a /tmp)" = 1777 -a -e /tmp/x || echo "parent directory attributes"
test "$GREETING" = hello -a "$LEGACY" = "legacy value" || echo "env"
echo done
'
}

@test "multistage build, tags and history" {
    build_prep
    local before
    before=$(pm images -q --filter dangling=false | sort -u | wc -l)
    out=$("$CLI" image build --tls-verify=false $base --build-arg MSG=e2e -t built:e2e -t built:second "$ctx" 2>&1)
    if test $? -eq 0; then
        ok "build"
    else
        fail "build" "$out"
        return
    fi
    check_match "build steps (of the last stage, as buildah numbers them)" "\[3/3\] STEP 20/20: CMD" "$out"
    check "run the default command" "hello from /app" "$(pm run --rm localhost/built:e2e 2>&1)"
    check "image content" "done" "$(pm run --rm localhost/built:e2e "$checks" 2>&1)"
    out=$(pm image inspect localhost/built:e2e --format '{{json .Config.Labels}} {{json .Config.ExposedPorts}} {{json .Config.Volumes}} {{.Config.StopSignal}} {{.Config.User}} {{.Config.WorkingDir}}')
    check_match "labels" '"org.example.test":"yes"' "$out"
    check_match "exposed ports" '"9090/udp"' "$out"
    check_match "volumes" '"/data"' "$out"
    check_match "stop signal, user, workdir" 'SIGINT 1000 /app$' "$out"
    check "a second tag" "$(pm image inspect localhost/built:e2e --format '{{.Id}}')" \
          "$(pm image inspect localhost/built:second --format '{{.Id}}')"
    # The intermediate images are kept as the build cache, not shown (the
    # earlier stages are, without a name).
    check "no intermediate image shown" "$((before + 1))" "$(pm images -q --filter dangling=false | sort -u | wc -l)"
    out=$(pm history --no-trunc --format '{{.CreatedBy}}' localhost/built:e2e | head -5 | tr '\n' '|')
    check_match "history of the steps, as buildah's" '[|]/bin/sh -c test "[$]LEGACY" = "legacy value"[|]' "$out"
    check_match "...a step that is not RUN" '[|]/bin/sh -c #[(]nop[)] ADD hello.txt /app/added.txt[|]' "$out"
}

@test "--target, --squash and --squash-all" {
    build_prep
    out=$("$CLI" image build -q --tls-verify=false $base --target BUILDER -t built:builder "$ctx" 2> /dev/null | tail -n 1)
    check_match "build --target (case insensitive)" "^[0-9a-f]{64}$" "$out"
    check "target stage content" "built default" "$(pm run --rm localhost/built:builder cat /built.txt 2>&1)"

    out=$("$CLI" image build -q --squash --tls-verify=false $base --build-arg MSG=e2e -t built:squash "$ctx" 2> /dev/null | tail -n 1)
    check_match "build --squash" "^[0-9a-f]{64}$" "$out"
    base_layers=$(pm image inspect "$IMG" --format '{{len .RootFS.Layers}}')
    check "squash: base layers plus one" "$((base_layers + 1))" \
          "$(pm image inspect localhost/built:squash --format '{{len .RootFS.Layers}}')"
    check "squashed image content" "done" "$(pm run --rm localhost/built:squash "$checks" 2>&1)"
    out=$("$CLI" image build -q --squash-all --tls-verify=false $base --build-arg MSG=e2e -t built:squashall "$ctx" 2> /dev/null | tail -n 1)
    check_match "build --squash-all" "^[0-9a-f]{64}$" "$out"
    check "squash-all: one layer" "1" "$(pm image inspect localhost/built:squashall --format '{{len .RootFS.Layers}}')"
    check "squash-all image content" "done" "$(pm run --rm localhost/built:squashall "$checks" 2>&1)"
    # podman --remote --squash-all sends libpod's squash=1 (buildah's squash)
    pm build -q --squash-all --tls-verify=false $base --build-arg MSG=e2e -t localhost/built:squashremote "$ctx" > /dev/null 2>&1
    check "podman build --squash-all: one layer" "1" \
          "$(pm image inspect localhost/built:squashremote --format '{{len .RootFS.Layers}}' 2>&1)"
}

# The auth file stays in the client: the build asks for the entries of the
# registries of the images it pulls.
@test "build --authfile answers the questions of the build" {
    mkdir -p "$WORKDIR/authbuild"
    printf 'FROM %s\nLABEL authfile=yes\n' "$IMG" > "$WORKDIR/authbuild/Containerfile"
    echo '{"auths": {"'"$E2E_REGISTRY"'": {"auth": "dTpw"}, "other.example": {"auth": "eDp5"}}}' > "$WORKDIR/authbuild.json"
    out=$("$CLI" image build -q --tls-verify=false --pull=always --authfile "$WORKDIR/authbuild.json" -t built:authfile "$WORKDIR/authbuild" 2>&1 | tail -n 1)
    check_match "build with --authfile pulls its base" "^[0-9a-f]{64}$" "$out"
    echo '{broken' > "$WORKDIR/bad.json"
    "$CLI" image build -q --tls-verify=false --authfile "$WORKDIR/bad.json" -t built:badauth "$WORKDIR/authbuild" > /dev/null 2>&1
    check "build with a broken --authfile fails before the build" 125 $?
}

# The credentials of the auth file reach a registry that asks for them: the
# build asks the command for those of its registry (a pipe of
# `ImageBuildAnswer`), and pulls its base with them.
@test "build --authfile pulls from a registry that asks for credentials" {
    local dir=$WORKDIR/authreg
    mkdir -p "$dir/ctx"
    mkfifo "$dir/port"
    python3 -I "$E2E_DIR/auth_registry.py" "${IMG%%/*}" e2e:secret > "$dir/port" 2> /dev/null &
    local proxy=$! port good bad none
    read -r port < "$dir/port"
    printf 'FROM localhost:%s/%s\nLABEL authreg=yes\n' "$port" "${IMG#*/}" > "$dir/ctx/Containerfile"
    printf '{"auths": {"localhost:%s": {"auth": "%s"}}}' "$port" "$(printf e2e:secret | base64)" > "$dir/good.json"
    printf '{"auths": {"localhost:%s": {"auth": "%s"}}}' "$port" "$(printf e2e:wrong | base64)" > "$dir/bad.json"
    echo '{"auths": {}}' > "$dir/none.json"
    for creds in good bad none; do
        out=$("$CLI" image build -q --tls-verify=false --pull=always --authfile "$dir/$creds.json" -t "built:authreg-$creds" "$dir/ctx" 2>&1)
        printf -v "$creds" '%s %s' "$?" "$(printf '%s' "$out" | tail -n 1)"
    done
    kill "$proxy"
    wait "$proxy" 2> /dev/null
    check_match "build pulls its base with the credentials of the auth file" "^0 [0-9a-f]{64}$" "$good"
    check_match "wrong credentials are refused by the registry" "^[1-9][0-9]* .*(401 Unauthorized|requires credentials)" "$bad"
    check_match "no credentials are refused by the registry" "^[1-9][0-9]* .*(401 Unauthorized|requires credentials)" "$none"
}

@test "podman build sends the context itself" {
    build_prep
    # podman --remote sends the context itself.
    out=$(pm build --tls-verify=false $base --build-arg MSG=e2e -t localhost/built:remote "$ctx" 2>&1)
    check_match "podman build" "\[3/3\] STEP 20/20" "$out"
    check "podman build content" "done" "$(pm run --rm localhost/built:remote "$checks" 2>&1)"
}

@test "podman's local build: the engine reads a directory of the host" {
    local d=$WORKDIR/localbuild out
    mkdir -p "$d"
    printf 'FROM %s\nCOPY hello /hello\n' "$IMG" > "$d/Dockerfile"
    printf 'from the host\n' > "$d/hello"
    out=$(api -s -w '\n%{http_code}' -X POST "http://d/v5.0.0/libpod/local/build?localcontextdir=$d&t=localhost/localbuild:1")
    check_match "the build answers 200" "^200$" "$out"
    check_match "the progress ends with the image" "localhost/localbuild|Successfully" "$out"
    check "the file of the directory is in the image" "from the host" "$(pm run --rm localhost/localbuild:1 cat /hello 2> /dev/null)"
    out=$(api -s -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/local/build?localcontextdir=$WORKDIR/none&t=localhost/localbuild:2")
    check_match "a directory that is not there is refused" "^(400|404)$" "$out"
    pm rmi localhost/localbuild:1 > /dev/null 2>&1
}

@test "symlinks and archives cannot lead COPY out of the context or the image" {
    build_prep
    # Symlinks cannot lead COPY out of the context or of a --from image,
    # nor make it write outside of the image.
    local esc=$bw/esc
    mkdir -p "$esc/a" "$esc/b/etc" "$bw/target"
    printf 'SECRET\n' > "$bw/hostsecret"
    ln -s "$bw" "$esc/link"
    ln -s "$bw/target" "$esc/a/etc"
    printf 'victim\n' > "$esc/b/etc/victim"
    cat > "$esc/Containerfile" <<EOT
FROM $IMG AS links
RUN ln -s / /hostroot
FROM $IMG
COPY a/ b/ /dst/
COPY --from=links /hostroot$bw/hostsecret /fromleak
EOT
    "$CLI" image build -q --tls-verify=false -t built:esc "$esc" > "$bw/esc.out" 2>&1
    test ! -e "$bw/target/victim"
    check "COPY does not write through symlinks" 0 $?
    check_match "COPY --from resolves symlinks in the image" "not found|[Nn]o such file" "$(cat "$bw/esc.out")"
    cat > "$esc/Containerfile" <<EOT
FROM $IMG
COPY link/hostsecret /leak
EOT
    out=$("$CLI" image build -q --tls-verify=false -t built:esc2 "$esc" 2>&1)
    check_match "COPY resolves symlinks in the context" "not found|[Nn]o such file" "$out"
    cat > "$esc/Containerfile" <<EOT
FROM $IMG
COPY a/ b/ /dst/
EOT
    out=$("$CLI" image build -q --tls-verify=false -t built:esc3 "$esc" 2>&1)
    check_match "COPY of several directories" "^[0-9a-f]{64}$" "$out"
    out=$(pm run --rm localhost/built:esc3 sh -c 'cat /dst/etc/victim; test -d /dst/etc -a ! -L /dst/etc && echo dir' 2>&1)
    check "COPY replaces the copied symlink with a directory" "victim
dir" "$out"
    test ! -e "$bw/target/victim"
    check "COPY of several directories stays in the image" 0 $?
    cat > "$esc/Containerfile" <<EOT
FROM $IMG
COPY ../../etc/passwd /x
EOT
    out=$("$CLI" image build -q --tls-verify=false -t built:esc4 "$esc" 2>&1)
    check_match "COPY of a path above the context" "outside of the build context" "$out"
    # A context archive that writes through a link it carries.
    printf 'FROM %s\n' "$IMG" > "$bw/Containerfile.tar"
    python3 -I - "$bw" <<'PY'
import io, sys, tarfile
d = sys.argv[1]
with tarfile.open(d + "/evil.tar", "w") as t:
    i = tarfile.TarInfo("Containerfile"); data = open(d + "/Containerfile.tar", "rb").read(); i.size = len(data); t.addfile(i, io.BytesIO(data))
    i = tarfile.TarInfo("l"); i.type = tarfile.SYMTYPE; i.linkname = d + "/target"; t.addfile(i)
    i = tarfile.TarInfo("l/planted"); i.size = 1; t.addfile(i, io.BytesIO(b"x"))
PY
    api -o /dev/null -X POST -H 'Content-Type: application/x-tar' --data-binary "@$bw/evil.tar" \
        "http://d/v5.0.0/libpod/build?t=localhost/built:evil"
    test ! -e "$bw/target/planted"
    check "a context archive cannot write through its links" 0 $?

    out=$(api -s -o /dev/null -w '%{http_code}' -X POST -H 'X-Registry-Config: !!!' \
        -H 'Content-Type: application/x-tar' --data-binary "@$bw/evil.tar" "http://d/v1.41/build")
    check "the registry credentials of a build are read" 400 "$out"
    out=$("$CLI" image build -q --network container:x --tls-verify=false -f "$bw/Containerfile.tar" "$bw/arch" 2>&1)
    check_match "a build network that is not a mode" "unsupported network" "$out"
}

@test "failing builds" {
    build_prep
    out=$("$CLI" image build --tls-verify=false "$bw/arch" 2>&1)
    check_match "missing Containerfile" "Containerfile|Dockerfile" "$out"
    printf 'FROM %s\nRUN exit 3\n' "$IMG" > "$bw/Containerfile.fail"
    out=$("$CLI" image build -q --tls-verify=false -f "$bw/Containerfile.fail" "$bw/arch" 2>&1)
    check_match "a failing RUN fails the build" "exit code 3" "$out"

    printf 'FROM '"$E2E_REGISTRY"'/velarx-e2e/nosuch:image\n' > "$bw/Containerfile.never"
    out=$("$CLI" image build -q --pull=never --tls-verify=false -f "$bw/Containerfile.never" "$bw/arch" 2>&1)
    check_match "--pull never with a missing base" "creating build container: .*: image not known" "$out"
}

@test "directory destinations of COPY and the containerignore" {
    build_prep
    # Destinations: `.` and an existing directory are directories, links
    # of the image on the way are followed, not replaced.
    local dst=$bw/dst
    mkdir -p "$dst/sub/keep"
    printf '{}' > "$dst/package.json"
    printf 'x' > "$dst/x"
    printf 's' > "$dst/secret"
    printf 'k' > "$dst/sub/keep/k"
    printf 'o' > "$dst/sub/other"
    printf 'secret\nsub\n!sub/keep\n' > "$dst/.containerignore"
    cat > "$bw/Containerfile.dst" <<EOT
FROM $IMG
RUN mkdir -p /usr/real /app && ln -s usr/real /lnk
WORKDIR /app
COPY package.json .
COPY x /app
COPY x /lnk/foo
COPY . /all
EOT
    out=$("$CLI" image build -q --tls-verify=false -f "$bw/Containerfile.dst" -t built:dst "$dst" 2>&1)
    check_match "build with directory destinations" "^[0-9a-f]{64}$" "$out"
    out=$(pm run --rm localhost/built:dst sh -c 'test -f /app/package.json && test -d /app && test -f /app/x && echo dirs; test -L /lnk && test -f /usr/real/foo && echo link; ls -A /all | tr "\n" " "' 2>&1)
    check "COPY into . and an existing directory, through an image link" "dirs
link
.containerignore package.json sub x " "$out"
    out=$(pm run --rm localhost/built:dst find /all/sub 2>&1 | sort | tr '\n' ' ')
    check "a ! pattern takes back a file of an ignored directory" "/all/sub /all/sub/keep /all/sub/keep/k " "$out"
    printf 'FROM %s\nCOPY secret /s\n' "$IMG" > "$bw/Containerfile.ign"
    out=$("$CLI" image build -q --tls-verify=false -f "$bw/Containerfile.ign" "$dst" 2>&1)
    check_match "an ignored source is not found" "[Nn]o such file" "$out"

    mkdir -p "$bw/stub"
    printf 'FROM %s\nRUN echo x > /newfile && rm -f /etc/motd\n' "$IMG" > "$bw/stub/Containerfile"
    "$CLI" image build -q --tls-verify=false -t built:stub "$bw/stub" > /dev/null 2>&1
    out=$("$CLI" image diff built:stub)
    check_match "image diff" "A /newfile" "$out"
    check "the engine files are not in the layer" "" "$(echo "$out" | grep -E 'resolv.conf|/etc/hosts|/etc/hostname')"
}

@test "the image pushed is pulled by podman fully and partially" {
    build_prep
    # Pushed, the image is pulled by podman fully and partially
    # (zstd:chunked, the TOC checked against the tar-split).
    local reg=${IMG%%/*}
    if command -v podman > /dev/null && curl -s -m 2 "http://$reg/v2/" > /dev/null; then
        local compat=$bw/compat
        mkdir -p "$compat/ctx" "$compat/conf"
        {
            head -c 1500000 /dev/urandom
            head -c 70000 /dev/zero
            head -c 3000 /dev/urandom
            head -c 1100 /dev/zero
            printf 'tail'
        } > "$compat/ctx/mixed.bin"
        cat > "$compat/ctx/Containerfile" <<EOT
FROM $IMG
COPY mixed.bin /data/mixed.bin
RUN mkdir -p /data/sub && : > /data/empty && ln -s mixed.bin /data/sym && ln /data/mixed.bin /data/sub/hard && \\
    printf 'x' > /data/one && chmod 4750 /data/one && chown 1000:1001 /data/empty && \\
    touch -d '2001-02-03 04:05:06' /data/one && rm -f /etc/motd
EOT
        # A tag of this run: other runs push to the same registry.  The
        # sizes and link counts of directories are the file system's.
        local cimg=$reg/velarx-e2e/build-compat:e2e-$$
        local cchecks='cd /data && for f in $(find . | sort); do if test -d "$f"; then stat -c "%n %F %a %u:%g" "$f"; else stat -c "%n %F %a %u:%g %s %h" "$f"; fi; test -L "$f" && readlink "$f"; done; md5sum mixed.bin one && test ! -e /etc/motd && echo gone'
        out=$("$CLI" image build -q --tls-verify=false -t built:compat "$compat/ctx" 2>&1)
        check_match "build for podman" "^[0-9a-f]{64}$" "$out"
        "$CLI" image push --tls-verify=false built:compat "$cimg" > /dev/null 2>&1
        check "push for podman" 0 $?
        expected=$(pm run --rm localhost/built:compat sh -c "$cchecks" 2>&1)
        check_match "compat content in velarx" "gone$" "$expected"
        check_match "the files listed" "./one regular file 4750 0:0 1 1" "$expected"
        diff_ids=$(pm image inspect localhost/built:compat --format '{{json .RootFS.Layers}}')
        for mode in full partial; do
            local partial=false
            test $mode = partial && partial=true
            cat > "$compat/conf/$mode.conf" <<EOT
[storage]
driver = "overlay"
graphroot = "$compat/$mode/root"
runroot = "$compat/$mode/run"
[storage.options]
pull_options = {enable_partial_images = "$partial", use_hard_links = "false"}
EOT
            lp="podman --root $compat/$mode/root --runroot $compat/$mode/run"
            CONTAINERS_STORAGE_CONF=$compat/conf/$mode.conf $lp pull -q --tls-verify=false "$cimg" > /dev/null 2>&1 3>&-
            check "podman $mode pull" 0 $?
            check "podman $mode diff ids" "$diff_ids" \
                  "$(CONTAINERS_STORAGE_CONF=$compat/conf/$mode.conf $lp image inspect --format '{{json .RootFS.Layers}}' "$cimg" 2>&1 3>&-)"
            check "podman $mode content" "$expected" \
                  "$(CONTAINERS_STORAGE_CONF=$compat/conf/$mode.conf $lp run --rm --net=none "$cimg" sh -c "$cchecks" 2>&1 3>&-)"
            CONTAINERS_STORAGE_CONF=$compat/conf/$mode.conf $lp unshare rm -rf "$compat/$mode" 2> /dev/null 3>&-
        done
    else
        note_skip "podman pull of a built image" "no podman or registry"
    fi
}

@test "RUN as the USER before it" {
    build_prep
    # RUN as the USER before it: a name, a uid:gid, a user:group of the
    # image as built so far, without passwd entries made for them.
    local uctx=$bw/user
    mkdir -p "$uctx"
    cat > "$uctx/Containerfile" <<EOT
FROM $IMG
RUN adduser -D -u 4321 builder
USER builder
RUN id -u > /tmp/builder; touch /tmp/owned
USER 1234:2345
RUN id > /tmp/num
USER bin:daemon
RUN id -u > /tmp/bin; id -g >> /tmp/bin
USER root
RUN cat /tmp/builder /tmp/num /tmp/bin; stat -c %u /tmp/owned; grep -c :1234: /etc/passwd || true
EOT
    out=$("$CLI" image build --tls-verify=false -t built:user "$uctx" 2> "$bw/build.err")
    check "build with USER" 0 $?
    check "RUN as the users of USER" "4321
uid=1234 gid=2345 groups=2345
1
2
4321
0" "$(printf '%s\n' "$out" | last_step)"
    printf 'FROM %s\nUSER nosuchuser\nRUN true\n' "$IMG" > "$uctx/Containerfile"
    out=$("$CLI" image build --tls-verify=false -t built:nouser "$uctx" 2>&1)
    check_match "RUN as a user the image lacks" "nosuchuser" "$out"

    pm rmi -f localhost/built:user > /dev/null 2>&1
}

@test "the streams of a build" {
    build_prep
    # The streams as buildah's: the steps and what a RUN writes on its
    # standard output, then the image id, on the standard output; what it
    # writes on its standard error on the standard error; with -q only the
    # RUN's streams and the id; with --iidfile the id in the file only.
    local uctx=$bw/user
    mkdir -p "$uctx"
    printf 'FROM %s\nRUN echo to-out; echo to-err >&2\n' "$IMG" > "$uctx/Containerfile"
    out=$("$CLI" image build --tls-verify=false -t built:streams "$uctx" 2> "$bw/streams.err")
    check "build with both streams" 0 $?
    check "a RUN's standard output on the standard output" "to-out" "$(printf '%s\n' "$out" | last_step)"
    check_match "and the image id last" "^[0-9a-f]{64}$" "$(printf '%s\n' "$out" | tail -n 1)"
    check "a RUN's standard error on the standard error" "to-err" "$(grep '^to-' "$bw/streams.err")"
    out=$(pm build --tls-verify=false -t built:streams "$uctx" 2>&1)
    check "podman build: COMMIT and the first name as given" "COMMIT built:streams" "$(printf '%s\n' "$out" | grep '^COMMIT')"
    out=$("$CLI" image build -q --no-cache --tls-verify=false -t built:streams "$uctx" 2> "$bw/streams.err")
    check "build -q: the RUN's output" "to-out" "$(printf '%s\n' "$out" | head -n 1)"
    check_match "and the full id" "^[0-9a-f]{64}$" "$(printf '%s\n' "$out" | sed 1d)"
    check "build -q: the RUN's standard error" "to-err" "$(cat "$bw/streams.err")"
    out=$("$CLI" image build -q --no-cache --iidfile "$bw/iid" --tls-verify=false -t built:streams "$uctx" 2> /dev/null)
    check "build --iidfile: no id on the standard output" "to-out" "$out"
    check_match "the id in the file" "^sha256:[0-9a-f]{64}$" "$(cat "$bw/iid")"
    pm rmi -f localhost/built:streams > /dev/null 2>&1
}

@test "ONBUILD" {
    build_prep
    # ONBUILD: recorded in the image, run by the builds on it, not kept.
    local octx=$bw/onbuild
    mkdir -p "$octx"
    printf 'context\n' > "$octx/f"
    printf 'FROM %s\nONBUILD RUN echo triggered > /triggered\nONBUILD COPY f /from-context\n' "$IMG" > "$octx/Containerfile"
    "$CLI" image build -q --tls-verify=false -t built:onbuild-base "$octx" > /dev/null 2>&1
    check "ONBUILD recorded" '["RUN echo triggered > /triggered","COPY f /from-context"]' \
          "$(api http://d/v1.41/images/localhost/built:onbuild-base/json | jq -c .Config.OnBuild)"
    printf 'FROM localhost/built:onbuild-base\nRUN cat /triggered /from-context > /seen\n' > "$octx/Containerfile"
    out=$(pm build -t localhost/built:onbuild "$octx" 2>&1)
    check_match "the triggers run" "Executing 2 build triggers" "$out"
    check "with the context of the build on the image" "triggered
context" "$(pm run --rm localhost/built:onbuild cat /seen 2>&1)"
    check "the triggers are not kept" "null" \
          "$(api http://d/v1.41/images/localhost/built:onbuild/json | jq -c .Config.OnBuild)"
    printf 'FROM %s\nONBUILD FROM scratch\n' "$IMG" > "$octx/Containerfile"
    check_match "ONBUILD FROM refused" "not allowed as an ONBUILD trigger" \
                "$("$CLI" image build --tls-verify=false "$octx" 2>&1)"
    pm rmi -f localhost/built:onbuild localhost/built:onbuild-base > /dev/null 2>&1
}

@test "ADD of a URL" {
    build_prep
    # ADD of a URL: downloaded by a confined pull worker, not extracted, 0600 and the
    # time of Last-Modified unless --chmod and --chown say otherwise.
    local web=$bw/web uctx2=$bw/addurl
    mkdir -p "$web" "$uctx2"
    printf 'downloaded\n' > "$web/file.txt"
    touch -d @1600000000 "$web/file.txt"
    tar -czf "$web/a.tar.gz" -C "$web" file.txt
    sum=sha256:$(sha256sum "$web/file.txt" | cut -d' ' -f1)
    port=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    python3 -I -u -m http.server --bind 127.0.0.1 --directory "$web" "$port" > "$WORKDIR/web.out" 2>&1 3>&- &
    webpid=$!
    e2e_wait_line "$WORKDIR/web.out" '^Serving HTTP' 30 || fail "the web server does not start"
    u=http://127.0.0.1:$port
    cat > "$uctx2/Containerfile" <<EOT
FROM $IMG
ADD $u/file.txt /dl/
ADD --checksum=$sum $u/file.txt /named
ADD --chown=1:2 --chmod=644 $u/file.txt /owned
ADD $u/a.tar.gz /arch/
RUN cat /dl/file.txt /named; stat -c '%a %Y' /dl/file.txt; stat -c '%u:%g %a' /owned; ls /arch
EOT
    out=$("$CLI" image build --tls-verify=false -t built:addurl "$uctx2" 2> "$bw/build.err")
    check "ADD of URLs" 0 $?
    check "the downloaded files" "downloaded
downloaded
600 1600000000
1:2 644
a.tar.gz" "$(printf '%s\n' "$out" | last_step)"
    printf 'FROM %s\nADD --checksum=sha256:%064d %s/file.txt /x\n' "$IMG" 0 "$u" > "$uctx2/Containerfile"
    check_match "ADD with a wrong checksum" "checksum sha256:[0-9a-f]+ is not" "$("$CLI" image build --tls-verify=false "$uctx2" 2>&1)"
    printf 'FROM %s\nADD %s/missing /x\n' "$IMG" "$u" > "$uctx2/Containerfile"
    check_match "ADD of a missing URL" "404" "$("$CLI" image build --tls-verify=false "$uctx2" 2>&1)"
    printf 'FROM %s\nCOPY %s/file.txt /x\n' "$IMG" "$u" > "$uctx2/Containerfile"
    check_match "COPY of a URL" "use ADD" "$("$CLI" image build --tls-verify=false "$uctx2" 2>&1)"
    kill "$webpid"
    wait "$webpid" 2> /dev/null
    pm rmi -f localhost/built:addurl > /dev/null 2>&1
}

@test "COPY --from with globs" {
    build_prep
    # COPY --from with globs, matched in the image of the stage.
    local gctx=$bw/fromglob
    mkdir -p "$gctx"
    cat > "$gctx/Containerfile" <<EOT
FROM $IMG AS files
RUN mkdir -p /out/sub && echo a > /out/a.txt && echo b > /out/b.txt && echo c > /out/c.log && echo d > /out/sub/d.txt
FROM $IMG
COPY --from=files /out/*.txt /txt/
COPY --from=files /out/?.log /one.log
COPY --from=files /o*/s*/*.txt /deep/
RUN ls /txt /deep; cat /one.log
EOT
    out=$("$CLI" image build --tls-verify=false -t built:fromglob "$gctx" 2> "$bw/build.err")
    check "COPY --from with globs" 0 $?
    check "the files the globs match" "/deep:
d.txt

/txt:
a.txt
b.txt
c" "$(printf '%s\n' "$out" | last_step)"
    printf 'FROM %s AS files\nFROM %s\nCOPY --from=files /nothing/*.x /x/\n' "$IMG" "$IMG" > "$gctx/Containerfile"
    check_match "COPY --from of a glob that matches nothing" "no such file" \
                "$("$CLI" image build --tls-verify=false "$gctx" 2>&1)"
    pm rmi -f localhost/built:fromglob > /dev/null 2>&1
}

@test "fifos and user xattrs" {
    build_prep
    # Fifos and user xattrs: of the context, of another stage.
    local fctx=$bw/fifo
    mkdir -p "$fctx"
    mkfifo -m 640 "$fctx/pipe"
    printf 'x\n' > "$fctx/attr"
    python3 -I -c 'import os, sys; os.setxattr(sys.argv[1], "user.velarx", b"kept")' "$fctx/attr"
    cat > "$fctx/Containerfile" <<EOT
FROM $IMG AS stage
RUN mkfifo -m 600 /made
FROM $IMG
COPY pipe attr /ctx/
COPY --from=stage /made /made
RUN stat -c '%n %F %a' /ctx/pipe /made
EOT
    out=$("$CLI" image build --tls-verify=false -t built:fifo "$fctx" 2> "$bw/build.err")
    check "fifos copied" "/ctx/pipe fifo 640
/made fifo 600" "$(printf '%s\n' "$out" | last_step)"
    # The xattr of the image, through podman cp.
    mkdir -p "$fctx/out"
    pm create --name fifoc localhost/built:fifo true > /dev/null 2>&1
    pm cp fifoc:/ctx/attr - | tar --xattrs --xattrs-include='user.*' -x -C "$fctx/out"
    check "the xattr of a copied file" "kept" \
          "$(python3 -I -c 'import os, sys; print(os.getxattr(sys.argv[1], "user.velarx").decode())' "$fctx/out/attr" 2>&1)"
    pm rm fifoc > /dev/null 2>&1
    # podman's client sends the regular files of the context only.
    rm "$fctx/pipe"
    sed -i 's,COPY pipe attr /ctx/,COPY attr /ctx/,; s,/ctx/pipe ,,' "$fctx/Containerfile"
    out=$(pm build --no-cache -t localhost/built:fifo2 "$fctx" 2>&1)
    check "podman build: a fifo of a stage" "/made fifo 600" \
          "$(printf '%s\n' "$out" | last_step)"
    pm rmi -f localhost/built:fifo localhost/built:fifo2 > /dev/null 2>&1
}

# GNU tar --sparse sends a file with holes as a sparse entry (old GNU, or the
# pax formats): the file is in the context whole
@test "a tar context with sparse files" {
    build_prep
    local sctx=$bw/sparse
    mkdir -p "$sctx"
    truncate -s 4M "$sctx/hole"
    head -c 4096 /dev/urandom > "$sctx/mixed"
    truncate -s 32M "$sctx/mixed"
    printf end | dd of="$sctx/mixed" bs=1 seek=16777216 conv=notrunc 2> /dev/null
    printf 'FROM %s\nCOPY hole mixed /d/\n' "$IMG" > "$sctx/Containerfile"
    want=$(cd "$sctx" && sha256sum hole mixed)
    local fmt n=0
    for fmt in gnu "posix --sparse-version=0.1" "posix --sparse-version=1.0"; do
        n=$((n + 1))
        # shellcheck disable=SC2086
        tar -C "$sctx" --sparse --format=$fmt -cf "$bw/sparse$n.tar" Containerfile hole mixed
        out=$(curl -s --unix-socket "$SOCK" -X POST -H 'Content-Type: application/x-tar' --data-binary @"$bw/sparse$n.tar" \
            "http://d/v5.0.0/libpod/build?t=localhost/built:sparse$n&layers=false&dockerfile=Containerfile" 2>&1)
        check_match "libpod build of a tar with sparse files ($fmt)" "[0-9a-f]{64}" "$out"
        check "the sparse files of the tar ($fmt) in the build" "$want
4194304
33554432" "$(pm run --rm localhost/built:sparse$n sh -c 'cd /d && sha256sum hole mixed && stat -c %s hole mixed' 2>&1)"
        pm rmi -f localhost/built:sparse$n > /dev/null 2>&1
    done
}

@test "ADD of a git repository" {
    build_prep
    # ADD of a git repository, served over smart HTTP here: cloned by the
    # confined helper, a tag, a subdirectory, .git kept on demand.
    if command -v git > /dev/null && test -x /usr/libexec/git-core/git-http-backend; then
        local gw=$bw/git gctx2=$bw/gitctx
        mkdir -p "$gw/work" "$gctx2"
        (
            cd "$gw/work" && git init -q -b main . && git config user.email t@e && git config user.name t &&
            mkdir docs && echo one > top.txt && echo doc1 > docs/d.txt && git add -A && git commit -qm 1 &&
            git tag v1 && echo two > top.txt && echo doc2 > docs/d.txt && git commit -qam 2
        )
        git clone -q --bare "$gw/work" "$gw/srv/repo.git"
        python3 -I "$E2E_DIR/git_http.py" "$gw/srv" "$gw/port" > /dev/null 2>&1 3>&- &
        gitpid=$!
        # (the server writes its port when it listens; the file is read again at each change)
        e2e_wait_content "$gw/port" '^[0-9]+$' 10 || true
        local gu="http://127.0.0.1:$(cat "$gw/port")/repo.git"
        cat > "$gctx2/Containerfile" <<EOT
FROM $IMG
ADD $gu /head/
ADD $gu#v1 /v1/
ADD $gu#main:docs /docs/
ADD --keep-git-dir=true $gu#v1 /kept/
RUN cat /head/top.txt /v1/top.txt /docs/d.txt; ls -a /head | tr '\n' ' '; echo; test -d /kept/.git && echo kept
EOT
        out=$("$CLI" image build --tls-verify=false -t built:git "$gctx2" 2> "$bw/build.err")
        check "ADD of a git repository" 0 $?
        check "the files of the refs and subdirectory" "two
one
doc2
. .. docs top.txt 
kept" "$(printf '%s\n' "$out" | last_step)"
        out=$(pm build -t localhost/built:git2 "$gctx2" 2>&1)
        check_match "podman build too" "doc2" "$out"
        printf 'FROM %s\nADD %s#nosuch /x/\n' "$IMG" "$gu" > "$gctx2/Containerfile"
        check_match "a missing ref" "git fetch failed" "$("$CLI" image build --tls-verify=false "$gctx2" 2>&1)"
        printf 'FROM %s\nADD %s#v1:../.. /x/\n' "$IMG" "$gu" > "$gctx2/Containerfile"
        check_match "a subdirectory that goes up" "goes up" "$("$CLI" image build --tls-verify=false "$gctx2" 2>&1)"
        printf 'FROM %s\nCOPY %s /x/\n' "$IMG" "$gu" > "$gctx2/Containerfile"
        check_match "COPY of a git repository" "use ADD" "$("$CLI" image build --tls-verify=false "$gctx2" 2>&1)"
        kill "$gitpid"
        wait "$gitpid" 2> /dev/null
        pm rmi -f localhost/built:git localhost/built:git2 > /dev/null 2>&1
    else
        note_skip "ADD of a git repository" "no git"
    fi
}

@test "libpod build of a remote context: a git repository, a tar, a Containerfile" {
    build_prep
    if command -v git > /dev/null && test -x /usr/libexec/git-core/git-http-backend; then
        local rw=$bw/rgit
        mkdir -p "$rw/work" "$rw/static"
        (
            cd "$rw/work" && git init -q -b main . && git config user.email t@e && git config user.name t &&
            printf 'FROM %s\nCOPY top.txt /top.txt\n' "$IMG" > Containerfile && echo remote > top.txt &&
            git add -A && git commit -qm 1
        )
        git clone -q --bare "$rw/work" "$rw/srv/repo.git"
        python3 -I "$E2E_DIR/git_http.py" "$rw/srv" "$rw/port" > /dev/null 2>&1 3>&- &
        local rpid=$!
        e2e_wait_content "$rw/port" '^[0-9]+$' 10 || true
        local ru="http://127.0.0.1:$(cat "$rw/port")/repo.git"
        out=$(curl -s --unix-socket "$SOCK" -X POST "http://d/v5.0.0/libpod/build?t=localhost/built:rgit&layers=false&remote=$ru%23main" 2>&1)
        check_match "libpod build of a git repository" "[0-9a-f]{64}" "$out"
        check "its file" remote "$(pm run --rm localhost/built:rgit cat /top.txt 2>&1)"
        tar -C "$rw/work" -czf "$rw/static/ctx.tgz" Containerfile top.txt
        python3 -I -c '
import functools, http.server, os, sys
class Q(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Q, directory=sys.argv[1]))
open(sys.argv[2] + ".tmp", "w").write(str(s.server_port)); os.rename(sys.argv[2] + ".tmp", sys.argv[2])
s.serve_forever()' "$rw/static" "$rw/sport" > /dev/null 2>&1 3>&- &
        local spid=$!
        e2e_wait_content "$rw/sport" '^[0-9]+$' 10 || true
        out=$(curl -s --unix-socket "$SOCK" -X POST "http://d/v5.0.0/libpod/build?t=localhost/built:rtar&layers=false&remote=http://127.0.0.1:$(cat "$rw/sport")/ctx.tgz" 2>&1)
        check_match "libpod build of a tar of a URL" "[0-9a-f]{64}" "$out"
        check "its file" remote "$(pm run --rm localhost/built:rtar cat /top.txt 2>&1)"
        printf 'FROM %s\nLABEL from=url\n' "$IMG" > "$rw/static/Alt"
        out=$(curl -s --unix-socket "$SOCK" -X POST "http://d/v5.0.0/libpod/build?t=localhost/built:rurl&layers=false&dockerfile=http://127.0.0.1:$(cat "$rw/sport")/Alt&remote=http://127.0.0.1:$(cat "$rw/sport")/ctx.tgz" 2>&1)
        check_match "libpod build with a Containerfile URL" "[0-9a-f]{64}" "$out"
        check "the Containerfile of the URL" url "$(pm image inspect localhost/built:rurl --format '{{index .Labels "from"}}' 2>&1)"
        out=$(curl -s -w '%{http_code}' --unix-socket "$SOCK" -X POST "http://d/v5.0.0/libpod/build?t=localhost/built:rnot&remote=file:///etc" 2>&1)
        check_match "a file URL is no context" "unsupported remote context" "$out"
        check_match "with status 400" "^400$" "$out"
        out=$(curl -s -w '%{http_code}' --unix-socket "$SOCK" -X POST "http://d/v5.0.0/libpod/build?t=localhost/built:rnot&remote=http://u:hunter2@127.0.0.1:1/x.tar" 2>&1)
        check "the password is not in the answer" 0 "$(printf '%s' "$out" | grep -c hunter2)"
        kill "$rpid" "$spid"
        wait "$rpid" "$spid" 2> /dev/null || true
        pm rmi -f localhost/built:rgit localhost/built:rtar localhost/built:rurl > /dev/null 2>&1
    else
        note_skip "libpod build of a remote context" "no git"
    fi
}

@test "options of the RUN containers through podman" {
    build_prep
    # the options of the RUN containers and of the image through podman's
    # route, as the command line has them
    local octx2=$bw/runopts
    mkdir -p "$octx2/vol"
    printf 'volume\n' > "$octx2/vol/f"
    # (z: under SELinux a directory of the host is the containers' only
    # once relabeled, as with podman)
    printf 'FROM '"$E2E_REGISTRY"'/e2e/alpine:gzip\nENV FOO=1\nRUN cat /vol/f > /vf && ulimit -n > /ul && echo "$OPTRUN" > /optrun\n' > "$octx2/Containerfile"
    out=$(pm build --tls-verify=false -v "$octx2/vol:/vol:ro,z" --ulimit nofile=77:77 --env OPTENV=fromflag --unsetenv FOO --format oci -t localhost/built:runopts "$octx2" 2>&1)
    check_match "podman build with -v, --ulimit, --env, --unsetenv, --format" "[0-9a-f]{64}$" "$out"
    check "the volume and the ulimit were in the RUN" "volume 77" "$(pm run --rm localhost/built:runopts sh -c 'echo $(cat /vf) $(cat /ul)' 2>&1)"
    check "--env is in the image, --unsetenv is not" "fromflag unset" "$(pm run --rm localhost/built:runopts sh -c 'echo $OPTENV ${FOO-unset}' 2>&1)"
    check "--format oci" "application/vnd.oci.image.manifest.v1+json" "$(pm image inspect --format '{{.ManifestType}}' localhost/built:runopts 2>&1)"
    # the Docker format is refused: nothing is built
    out=$(pm build --tls-verify=false --format docker -t localhost/built:docker "$octx2" 2>&1)
    check_match "podman build --format docker is refused" "Docker image formats are not supported: only OCI images \\(application/vnd.oci.image.\\*\\)" "$out"
    pm image exists localhost/built:docker
    check "no image of the refused build" 1 $?
    tar -C "$octx2" -cf "$bw/runopts.tar" Containerfile
    check "libpod build outputformat=docker is 501" 501 \
        "$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" -X POST -H 'Content-Type: application/x-tar' --data-binary @"$bw/runopts.tar" "http://d/v5.0.0/libpod/build?t=localhost/built:docker&outputformat=application%2Fvnd.docker.distribution.manifest.v2%2Bjson")"
    pm rmi -f localhost/built:runopts > /dev/null 2>&1
    # what a Docker client sends for none: ulimits=null, shmsize=0
    mkdir -p "$bw/dknone"
    printf 'FROM '"$E2E_REGISTRY"'/e2e/alpine:gzip\nRUN true\n' > "$bw/dknone/Dockerfile"
    tar -C "$bw/dknone" -cf "$bw/dknone.tar" Dockerfile
    out=$(curl -s --unix-socket "$SOCK" -X POST -H 'Content-Type: application/x-tar' --data-binary @"$bw/dknone.tar" \
        "http://d/v1.41/build?t=localhost/built:dknone&q=1&ulimits=null&shmsize=0" 2>&1)
    check_match "a Docker build with ulimits=null and shmsize=0" '"stream":"(sha256:)?[0-9a-f]{64}' "$out"
    # (q=1: the bare ID, as podman streams it)
    check "a quiet Docker build streams the ID" 1 "$(printf '%s\n' "$out" | grep -cE '^\{"stream":"[0-9a-f]{64}\\n"\}$')"
    pm rmi -f localhost/built:dknone > /dev/null 2>&1
    pm rmi -f localhost/built:e2e localhost/built:second localhost/built:builder localhost/built:squash localhost/built:squashall localhost/built:squashremote \
       localhost/built:remote localhost/built:esc3 localhost/built:stub localhost/built:compat \
       localhost/built:dst > /dev/null 2>&1
}
