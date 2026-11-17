# SPDX-License-Identifier: Apache-2.0
# podman cp / docker cp, export, diff and the size of the changes.
# velarx cp: the host side done by the client, the container side by the
# archive endpoints.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

sh_cli () {
    timeout 60 "$CLI" --socket "$ESOCK" "$@"
}

@test "podman cp of files and directories into and out of a container" {
    src=$WORKDIR/cpsrc
    mkdir -p "$src/sub"
    echo hello > "$src/f"
    echo nested > "$src/sub/g"
    ln -s f "$src/l"
    pm run -d --name cpc "$IMG" sleep 100 > /dev/null
    pm cp "$src/f" cpc:/tmp/
    check "cp file to container" "hello" "$(pm exec cpc cat /tmp/f)"
    pm cp "$src" cpc:/tmp/dir
    out=$(pm exec cpc sh -c 'cat /tmp/dir/sub/g; readlink /tmp/dir/l' | tr '\n' ' ')
    check "cp directory to container" "nested f " "$out"
    pm cp "$src/f" cpc:/tmp/renamed
    check "cp file to a new name" "hello" "$(pm exec cpc cat /tmp/renamed)"
    pm cp cpc:/tmp/dir "$WORKDIR/cpout"
    check "cp directory from container" "nested" "$(cat "$WORKDIR/cpout/sub/g")"
    out=$(pm cp cpc:/tmp/f - | tar -tf -)
    check "cp to stdout" "f" "$out"
    pm cp cpc:/nope "$WORKDIR/x" > /dev/null 2>&1
    check "cp of a missing path" 125 $?
    out=$(api -o /dev/null -w '%{http_code}' -I "http://d/v1.41/containers/cpc/archive?path=/tmp/f")
    check "archive HEAD" 200 "$out"
}

@test "podman cp does not follow a link out of the container" {
    pm exec cpc sh -c 'ln -s /etc /tmp/evil'
    echo bad > "$WORKDIR/bad"
    pm cp "$WORKDIR/bad" cpc:/tmp/evil/escape > /dev/null 2>&1
    check "cp does not follow a link out of the container" 1 "$(test -e /etc/escape; echo $?)"
    pm exec cpc test -f /etc/escape
    check "cp follows the link in the container" 0 $?
}

@test "podman export skips the mounts, diff lists the changes" {
    out=$(pm export cpc | tar -tf - | grep -c '^tmp/dir/sub/g$')
    check "export" 1 "$out"
    out=$(pm export cpc | tar -tf - | grep -c '^proc/.')
    check "export skips the mounts" 0 "$out"
    out=$(pm diff cpc | tr '\n' ',')
    check_match "diff" "A /tmp/dir" "$out"
    pm rm -t 0 -f cpc > /dev/null
}

@test "velarx cp leaves out dev, proc and sys of the root of a container" {
    pm run -d --name cproot "$IMG" sleep 100 > /dev/null
    # (as podman's copier does: Excludes dev, proc and sys, relative to the
    # root of the container, whatever path is copied)
    check "a running container" 0 "$(sh_cli container cp cproot:/ - | tar -tf - | grep -cE '^([^/]*/)?(dev|proc|sys)(/|$)')"
    check "a running container: the rest is there" 1 "$(sh_cli container cp cproot:/ - | tar -tf - | grep -cE '(^|/)etc/os-release$')"
    sh_cli container cp cproot:/proc - > "$WORKDIR/proc.tar"
    check "a directory of them: an empty archive" "" "$(tar -tf "$WORKDIR/proc.tar")"
    check "a file below them: not copied" 125 "$(sh_cli container cp cproot:/dev/null - > /dev/null 2> "$WORKDIR/null.err"; echo $?)"
    check "a file below them: why" 1 "$(grep -c 'left out of a copy' "$WORKDIR/null.err")"
    pm stop -t 0 cproot > /dev/null
    check "a stopped container" 0 "$(sh_cli container cp cproot:/ - | tar -tf - | grep -cE '^([^/]*/)?(dev|proc|sys)(/|$)')"
    check "a stopped container: the rest is there" 1 "$(sh_cli container cp cproot:/ - | tar -tf - | grep -cE '(^|/)etc/os-release$')"
    pm rm -t 0 -f cproot > /dev/null
}

@test "velarx cp archives a device as a header, out of a running and a stopped container" {
    [ "$(id -u)" = 0 ] || skip "needs root (mknod)"
    pm run -d --privileged --name cpdev "$IMG" sleep 100 > /dev/null
    pm exec cpdev sh -c 'mknod /tmp/cdev c 1 7; mknod /tmp/bdev b 7 1; echo x > /tmp/f' > /dev/null
    # (podman's tar.FileInfoHeader: the entry with its numbers, no content)
    running=$(sh_cli container cp cpdev:/tmp - | tar -tvf - | awk '$1 ~ /^[cb]/ {print substr($1,1,1), $3, $NF}')
    check "a running container: the devices are entries" "b 7,1 tmp/bdev
c 1,7 tmp/cdev" "$(echo "$running" | sort)"
    pm stop -t 0 cpdev > /dev/null
    stopped=$(sh_cli container cp cpdev:/tmp - | tar -tvf - | awk '$1 ~ /^[cb]/ {print substr($1,1,1), $3, $NF}')
    check "a stopped container: the same entries" "$running" "$stopped"
    pm rm -t 0 -f cpdev > /dev/null
}

@test "podman cp into a created container and out of a stopped one" {
    src=$WORKDIR/cpsrc
    pm create --name cpcreated "$IMG" cat /tmp/f > /dev/null
    pm cp "$src/f" cpcreated:/tmp/
    out=$(pm start -a cpcreated)
    check "cp into a created container" "hello" "$out"
    out=$(pm cp cpcreated:/etc/os-release - | tar -xOf - | grep -c '^NAME=')
    check "cp from a stopped container" 1 "$out"
    pm rm -t 0 -f cpcreated > /dev/null
}

@test "velarx cp into a container" {
    src=$WORKDIR/clisrc
    mkdir -p "$src/sub" "$WORKDIR/cliout"
    echo hello > "$src/f"
    echo nested > "$src/sub/g"
    ln -s f "$src/l"
    echo "host secret" > "$WORKDIR/hostsecret"
    pm volume create clivol > /dev/null
    pm run -d --name clic -v clivol:/vol --user 1000:1001 "$IMG" sleep 100 > /dev/null
    sh_cli container cp "$src/f" clic:/tmp/
    check "cli: file into a directory" "hello" "$(pm exec clic cat /tmp/f)"
    check "cli: owned by the user of the container" "1000:1001" "$(pm exec clic stat -c %u:%g /tmp/f)"
    sh_cli container cp "$src/f" clic:/tmp/renamed
    check "cli: file to a new name" "hello" "$(pm exec clic cat /tmp/renamed)"
    sh_cli container cp "$src" clic:/tmp/dir
    out=$(pm exec clic sh -c 'cat /tmp/dir/sub/g; readlink /tmp/dir/l' | tr '\n' ' ')
    check "cli: directory to a new name" "nested f " "$out"
    sh_cli container cp "$src" clic:/tmp/dir
    check "cli: directory into a directory" "nested" "$(pm exec clic cat /tmp/dir/clisrc/sub/g)"
    sh_cli container cp "$src/." clic:/tmp/
    check "cli: contents of a directory" "nested" "$(pm exec clic cat /tmp/sub/g)"
    sh_cli container cp "$src" clic:/tmp/f > /dev/null 2>&1
    check "cli: directory onto a file fails" 125 $?
    sh_cli container cp "$src/f" clic:/nonexistent/x > /dev/null 2>&1
    check "cli: missing parent fails" 125 $?
    sh_cli container cp "$src/f" clic:/vol/
    check "cli: into a volume of a running container" "hello" "$(pm run --rm -v clivol:/v "$IMG" cat /v/f)"
    pm exec clic mkdir /tmp/fromstdin
    tar -C "$src" -cf - sub | sh_cli container cp - clic:/tmp/fromstdin
    check "cli: a tar from the standard input" "nested" "$(pm exec clic cat /tmp/fromstdin/sub/g)"
    tar -C "$src" -cf - sub | sh_cli container cp - clic:/tmp/nodir > /dev/null 2>&1
    check "cli: a tar to a missing directory fails" 125 $?
}

@test "velarx cp out of a container" {
    sh_cli container cp clic:/tmp/dir "$WORKDIR/cliout/d"
    check "cli: directory out to a new name" "nested" "$(cat "$WORKDIR/cliout/d/sub/g")"
    sh_cli container cp clic:/tmp/dir "$WORKDIR/cliout"
    check "cli: directory out into a directory" "nested" "$(cat "$WORKDIR/cliout/dir/sub/g")"
    sh_cli container cp clic:/tmp/dir/. "$WORKDIR/cliout/contents"
    check "cli: contents out" "nested" "$(cat "$WORKDIR/cliout/contents/sub/g")"
    sh_cli container cp clic:/tmp/f "$WORKDIR/cliout/file"
    check "cli: file out" "hello" "$(cat "$WORKDIR/cliout/file")"
    out=$(sh_cli container cp clic:/tmp/f - | tar -tf -)
    check "cli: to the standard output" "f" "$out"
    sh_cli container cp clic:/nope "$WORKDIR/cliout/x" > /dev/null 2>&1
    check "cli: missing source fails" 125 $?
}

@test "velarx cp resolves links in the root of the container" {
    # links in the container are resolved in its root (made by the user of
    # the container, not in the sticky /tmp: protected_symlinks would keep
    # the engine from following them)
    pm exec clic sh -c "mkdir /tmp/links; ln -s /etc /tmp/links/evil; ln -s /etc/hostname /tmp/links/hn; ln -s $WORKDIR/hostsecret /tmp/links/hs; ln -s ../../../../../../../../etc /tmp/links/up"
    sh_cli container cp "$WORKDIR/hostsecret" clic:/tmp/links/evil/cliescape > /dev/null 2>&1
    check "cli: no write through a link out of the container" 1 "$(test -e /etc/cliescape; echo $?)"
    check "cli: the link is followed in the container" 0 "$(pm exec clic test -f /etc/cliescape; echo $?)"
    sh_cli container cp "$WORKDIR/hostsecret" clic:/tmp/links/up/cliescape2 > /dev/null 2>&1
    check "cli: no write through .. out of the container" 1 "$(test -e /etc/cliescape2; echo $?)"
    sh_cli container cp clic:/tmp/links/hn "$WORKDIR/cliout/hn"
    check "cli: a link out is the container's file" "$(pm exec clic cat /etc/hostname)" "$(cat "$WORKDIR/cliout/hn")"
    sh_cli container cp clic:/tmp/links/hs "$WORKDIR/cliout/hs" > /dev/null 2>&1
    check "cli: a link to a host file is not followed" 1 "$(test -e "$WORKDIR/cliout/hs"; echo $?)"
    # the links the user (1000) of the container made in the sticky /tmp:
    # protected_symlinks would keep the kernel from following them
    pm exec clic sh -c "ln -s /etc /tmp/stickyetc; ln -s /etc/hostname /tmp/stickyhn"
    sh_cli container cp "$WORKDIR/hostsecret" clic:/tmp/stickyetc/clisticky
    check "cli: into a link of the user in a sticky directory" 0 "$(pm exec clic test -f /etc/clisticky; echo $?)"
    check "cli: and not the host's" 1 "$(test -e /etc/clisticky; echo $?)"
    sh_cli container cp clic:/tmp/stickyhn "$WORKDIR/cliout/stickyhn"
    check "cli: out of a link of the user in a sticky directory" "$(pm exec clic cat /etc/hostname)" \
        "$(cat "$WORKDIR/cliout/stickyhn" 2>&1)"
    sh_cli container cp "clic:/../../../../$WORKDIR/hostsecret" "$WORKDIR/cliout/dd" > /dev/null 2>&1
    check "cli: .. does not leave the container" 1 "$(test -e "$WORKDIR/cliout/dd"; echo $?)"
    # a tar from the container with a link and a file below it
    pm exec clic sh -c "mkdir -p /tmp/t && ln -s $WORKDIR/cliout /tmp/t/l"
    sh_cli container cp clic:/tmp/t "$WORKDIR/cliout/t"
    check "cli: a link from the container is copied as a link" "$WORKDIR/cliout" "$(readlink "$WORKDIR/cliout/t/l")"
}

@test "velarx cp of a stopped container" {
    # a container that does not run: its changes over its image
    pm run --name clist "$IMG" sh -c 'rm /etc/motd; mkdir /tmp/made; echo in > /tmp/made/f; ln -s /etc /tmp/etclink' > /dev/null
    out=$(sh_cli container cp clist:/etc - | tar -tf - | grep -c 'motd')
    check "cli: a file deleted in a stopped container is not copied" 0 "$out"
    sh_cli container cp clist:/tmp/made/f "$WORKDIR/cliout/stopped"
    check "cli: a file written by a stopped container" "in" "$(cat "$WORKDIR/cliout/stopped")"
    sh_cli container cp "$WORKDIR/hostsecret" clist:/tmp/etclink/viaclink > /dev/null 2>&1
    check "cli: a stopped container's link stays in its root" 1 "$(test -e /etc/viaclink; echo $?)"
    # nothing is mounted for it: the changes come from the table of contents
    out=$(pm diff clist | sort | tr '\n' ',')
    check_match "diff of a stopped container" "A /tmp/made,A /tmp/made/f,.*D /etc/motd" "$out"
    pm rm -t 0 -f clist > /dev/null
}

@test "velarx cp owner in a user namespace and a fifo" {
    src=$WORKDIR/clisrc
    pm create --userns=auto --name cliuns "$IMG" stat -c %u:%g /tmp/f > /dev/null
    sh_cli container cp "$src/f" cliuns:/tmp/
    check "cli: owner in a user namespace" "0:0" "$(pm start -a cliuns)"
    pm rm -t 0 -f cliuns > /dev/null
    pm exec clic mkfifo /tmp/fifo
    out=$(sh_cli container cp clic:/tmp - | tar -tf - | grep -c fifo)
    # (as the copy out of a stopped container: the entry, never opened)
    check "cli: a fifo is archived, not read" 1 "$out"
    pm rm -t 0 -f clic > /dev/null
    pm volume rm clivol > /dev/null
}
