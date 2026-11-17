# SPDX-License-Identifier: Apache-2.0
# `velarx build URL`: a git repository (https://HOST/REPO.git#REF:SUBDIR), a
# tar (plain, gzip, zstd) or a lone Containerfile of an http URL as the
# build context, and `-f URL`, as buildah's TempDirForURL.  The repository is
# served over smart HTTP by git http-backend (tests/e2e/git_http.py), the
# tars by a static server, both on 127.0.0.1.  Rootless, no registry: the
# base is an image of host binaries.

load helpers
load wait

setup_file () {
    e2e_setup_file
    e2e_start_daemon
    e2e_make_image
    command -v git > /dev/null && test -x /usr/libexec/git-core/git-http-backend || return 0
    local w=$WORKDIR/srvdata
    mkdir -p "$w/work/docs" "$w/static/tree"
    (
        cd "$w/work" && git init -q -b main . && git config user.email t@e && git config user.name t &&
        printf 'FROM %s\nCOPY top.txt /top.txt\nRUN cat /top.txt\n' "$IMG" > Containerfile &&
        printf 'FROM %s\nCOPY d.txt /d.txt\nRUN cat /d.txt\n' "$IMG" > docs/Containerfile &&
        printf 'FROM %s\nCOPY top.txt /alt.txt\nRUN cat /alt.txt\n' "$IMG" > Containerfile.alt &&
        echo one > top.txt && echo doc1 > docs/d.txt && git add -A && git commit -qm 1 &&
        git tag v1 && echo two > top.txt && echo doc2 > docs/d.txt && git commit -qam 2
    )
    git clone -q --bare "$w/work" "$w/srv/repo.git"
    # a small pack whose tree names one blob of 100 MiB 700 times: 70 GiB,
    # more than a copy may write
    git init -q --bare "$w/srv/bomb.git"
    local blob tree
    blob=$(head -c 100M /dev/zero | git -C "$w/srv/bomb.git" hash-object -w --stdin)
    tree=$(for i in $(seq 700); do printf '100644 blob %s\tf%s\n' "$blob" "$i"; done |
        git -C "$w/srv/bomb.git" mktree)
    git -C "$w/srv/bomb.git" update-ref refs/heads/main \
        "$(git -C "$w/srv/bomb.git" -c user.name=t -c user.email=t@e commit-tree -m bomb "$tree")"
    git -C "$w/srv/bomb.git" symbolic-ref HEAD refs/heads/main
    python3 -I "$E2E_DIR/git_http.py" "$w/srv" "$w/port" > /dev/null 2>&1 3>&- &
    echo $! > "$WORKDIR/git.pid"
    e2e_wait_content "$w/port" '^[0-9]+$' 10 || true
    # the tars and the Containerfile
    cp "$w/work/Containerfile" "$w/work/top.txt" "$w/static/tree/"
    tar -C "$w/static/tree" -cf "$w/static/ctx.tar" .
    gzip -c "$w/static/ctx.tar" > "$w/static/ctx.tgz"
    ! command -v zstd > /dev/null || zstd -q "$w/static/ctx.tar" -o "$w/static/ctx.tar.zst"
    printf 'FROM %s\nRUN echo from-url\n' "$IMG" > "$w/static/Dockerfile"
    # a tar that goes out of its directory
    python3 -I - "$w/static/evil.tar" "$IMG" << 'PY'
import io, sys, tarfile
t = tarfile.open(sys.argv[1], "w")
def add(name, data=b"", **kw):
    i = tarfile.TarInfo(name); i.size = len(data)
    for k, v in kw.items(): setattr(i, k, v)
    t.addfile(i, io.BytesIO(data))
add("Containerfile", ("FROM %s\nCOPY ok.txt /ok.txt\n" % sys.argv[2]).encode())
add("ok.txt", b"ok\n")
add("../escaped", b"x")
add("/tmp/escaped-abs", b"x")
t.close()
PY
    python3 -I -c '
import functools, http.server, os, sys
class Q(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Q, directory=sys.argv[1]))
open(sys.argv[2] + ".tmp", "w").write(str(s.server_port)); os.rename(sys.argv[2] + ".tmp", sys.argv[2])
s.serve_forever()' "$w/static" "$w/sport" > /dev/null 2>&1 3>&- &
    echo $! > "$WORKDIR/static.pid"
    e2e_wait_content "$w/sport" '^[0-9]+$' 10 || true
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    kill "$(cat "$WORKDIR/git.pid" 2> /dev/null)" "$(cat "$WORKDIR/static.pid" 2> /dev/null)" 2> /dev/null
    e2e_teardown_file
}

setup () {
    command -v git > /dev/null && test -x /usr/libexec/git-core/git-http-backend || skip "no git"
    w=$WORKDIR/srvdata
    gu=http://127.0.0.1:$(cat "$w/port")/repo.git
    su=http://127.0.0.1:$(cat "$w/sport")
}

# content NAME FILE: the content of FILE of the image NAME, as a container
# of it prints it
content () {
    sc run --rm "$1" cat "$2" 2>&1
}

@test "a git repository as the context: HEAD, a tag, a subdirectory" {
    out=$(sc build --tls-verify=false -t localhost/rc:head "$gu" 2>&1)
    check "build of the repository" 0 $?
    check "the head of the repository" "two" "$(content localhost/rc:head /top.txt)"
    check_match "the output of its RUN" "^two$" "$out"
    sc build --tls-verify=false -t localhost/rc:v1 "$gu#v1" > /dev/null 2>&1
    check "the tag" "one" "$(content localhost/rc:v1 /top.txt)"
    sc build --tls-verify=false -t localhost/rc:sub "$gu#main:docs" > /dev/null 2>&1
    check "the subdirectory of a branch" "doc2" "$(content localhost/rc:sub /d.txt)"
    sc build --tls-verify=false -t localhost/rc:alt -f Containerfile.alt "$gu#v1" > /dev/null 2>&1
    check "-f names a file of the repository" "one" "$(content localhost/rc:alt /alt.txt)"
    sc rmi -f localhost/rc:head localhost/rc:v1 localhost/rc:sub localhost/rc:alt > /dev/null 2>&1
}

@test "a git repository as the context: what fails" {
    out=$(sc build --tls-verify=false "$gu#nosuch" 2>&1) || true
    check_match "a missing ref" "git fetch failed" "$out"
    out=$(sc build --tls-verify=false "$gu#v1:../.." 2>&1) || true
    check_match "a subdirectory that goes up" "goes up" "$out"
    out=$(sc build --tls-verify=false "$gu#main:top.txt" 2>&1) || true
    check_match "a subdirectory that is a file" "not a directory" "$out"
    out=$(sc build --tls-verify=false "http://u:hunter2@127.0.0.1:1/r.git" 2>&1) || true
    check_match "an unreachable repository" "127.0.0.1:1" "$out"
    check "the password is not shown" 0 "$(printf '%s' "$out" | grep -c hunter2)"
    out=$(sc build --tls-verify=false "$gu" --ignorefile "$w/work/top.txt" 2>&1) || true
    check_match "--ignorefile is refused" "ignorefile" "$out"
    out=$(sc build --tls-verify=false -f - "$gu" 2>&1 < /dev/null) || true
    check_match "-f - is refused" "takes one -f file" "$out"
    out=$(sc build "file://$w/srv/repo.git" 2>&1) || true
    check_match "a file URL is no context" "file://" "$out"
    check "no git directory of the host was read" 0 "$(sc images 2>&1 | grep -c file)"
}

@test "a repository whose tree is larger than the limit is not written" {
    out=$(sc build --tls-verify=false "${gu%/repo.git}/bomb.git" 2>&1) || true
    check_match "refused" "the tree is larger than a copy may write" "$out"
}

@test "a tar as the context: plain, gzip, zstd" {
    sc build -t localhost/rc:tar "$su/ctx.tar" > /dev/null 2>&1
    check "plain tar" "two" "$(content localhost/rc:tar /top.txt)"
    sc build -t localhost/rc:tgz "$su/ctx.tgz" > /dev/null 2>&1
    check "gzip tar" "two" "$(content localhost/rc:tgz /top.txt)"
    if [ -f "$w/static/ctx.tar.zst" ]; then
        sc build -t localhost/rc:zst "$su/ctx.tar.zst" > /dev/null 2>&1
        check "zstd tar" "two" "$(content localhost/rc:zst /top.txt)"
    fi
    out=$(sc build "$su/missing.tar" 2>&1) || true
    check_match "a 404" "404" "$out"
    sc rmi -f localhost/rc:tar localhost/rc:tgz localhost/rc:zst > /dev/null 2>&1
}

@test "a tar that goes out of its directory stays in it" {
    out=$(sc build -t localhost/rc:evil "$su/evil.tar" 2>&1) || true
    [ ! -e "$w/static/../escaped" ] && [ ! -e "$w/escaped" ] && [ ! -e /tmp/escaped-abs ]
    check "nothing outside of the context" 0 $?
    sc rmi -f localhost/rc:evil > /dev/null 2>&1 || true
}

@test "a lone Containerfile as the context, and as -f" {
    out=$(sc build -t localhost/rc:lone "$su/Dockerfile" 2>&1)
    check "a Containerfile URL is the context" 0 $?
    check_match "its RUN ran" "^from-url$" "$out"
    mkdir -p "$WORKDIR/localctx"
    echo local > "$WORKDIR/localctx/f"
    out=$(sc build --no-cache -t localhost/rc:minusf -f "$su/Dockerfile" "$WORKDIR/localctx" 2>&1)
    check "-f URL with a directory" 0 $?
    check_match "its RUN ran" "^from-url$" "$out"
    out=$(sc build -f "$su/Dockerfile" -f x "$WORKDIR/localctx" 2>&1) || true
    check_match "a URL is the only -f" "only -f" "$out"
    out=$(sc build -f "$su/nosuch" "$WORKDIR/localctx" 2>&1) || true
    check_match "a missing Containerfile URL" "404" "$out"
    sc rmi -f localhost/rc:lone localhost/rc:minusf > /dev/null 2>&1
}

@test "a named context may be a git repository" {
    d=$WORKDIR/named
    mkdir -p "$d"
    printf 'FROM %s\nCOPY --from=repo /top.txt /named.txt\nRUN cat /named.txt\n' "$IMG" > "$d/Containerfile"
    sc build --tls-verify=false -t localhost/rc:named --build-context "repo=$gu#v1" "$d" > /dev/null 2>&1
    check "the file of the repository" "one" "$(content localhost/rc:named /named.txt)"
    sc rmi -f localhost/rc:named > /dev/null 2>&1
}
