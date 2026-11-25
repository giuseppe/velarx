# SPDX-License-Identifier: Apache-2.0
# What the OCI spec of a container gives the process (user, groups,
# security defaults, create options), against a rootless daemon in a scratch
# HOME.  The expected values are podman's; with E2E_PODMAN=1 the same flags
# are also run with podman (in a scratch store) and the outputs compared.
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/spec.bats

load helpers
. "$BATS_TEST_DIRNAME/../cleanup.sh"

pm () { podman --root "$WORKDIR/podman/root" --runroot "$WORKDIR/podman/runroot" --storage-driver vfs "$@"; }

# run_ctr WHAT EXPECTED [FLAGS...] -- CMD...: the output of CMD in a container,
# compared with EXPECTED and, with E2E_PODMAN=1, with podman's.
run_ctr () {
    local what=$1 expected=$2 flags=() out
    shift 2
    while [ $# -gt 0 ] && [ "$1" != -- ]; do flags+=("$1"); shift; done
    shift
    out=$(sc container run --rm "${flags[@]}" "$IMAGE" "$@" 2>&1)
    check "$what" "$expected" "$out"
    if [ -n "${E2E_PODMAN:-}" ]; then
        check "$what (podman)" "$(pm run --rm "${flags[@]}" "$IMAGE" "$@" 2>&1)" "$out"
    fi
}
# fails WHAT REGEXP [FLAGS...] -- CMD...: the create is refused.
fails () {
    local what=$1 re=$2 flags=() out
    shift 2
    while [ $# -gt 0 ] && [ "$1" != -- ]; do flags+=("$1"); shift; done
    shift
    out=$(sc container run --rm "${flags[@]}" "$IMAGE" "$@" 2>&1)
    check "$what fails" 1 $(( $? != 0 ))
    check_match "$what: message" "$re" "$out"
}

# update of a container (the libpod API): the limits of a running
# container change, those of a stopped one apply at its next start, block IO
# and device rules are taken
api_update () { # ID BODY: the HTTP status
    curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" -XPOST \
        -H 'Content-Type: application/json' -d "$2" "http://d/v4.0.0/libpod/containers/$1/update"
}

setup_file () {
    e2e_setup_file
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    e2e_start_daemon
    e2e_start_api
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    local p
    e2e_remove_containers "$SH" "$ESOCK"
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do kill -INT "$p" 2> /dev/null; done
    if test -z "${E2E_KEEP:-}"; then
        # the store of podman has files of the sub ids
        test -d "$WORKDIR/podman" && podman unshare rm -rf "$WORKDIR/podman"
    fi
    e2e_detach_mounts "$WORKDIR"
    e2e_teardown_file
}

@test "pull the image" {
    sc image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
    check "pull $IMAGE" 0 $?
    if [ -n "${E2E_PODMAN:-}" ]; then
        pm pull -q --tls-verify=false "$IMAGE" > /dev/null || exit 1
    fi
}

@test "the user, groups, umask and timezone" {
    ID='id; echo HOME=$HOME'
    run_ctr "root by default" "uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
HOME=/root" -- sh -c "$ID"
    run_ctr "user by name" "uid=1(bin) gid=1(bin) groups=1(bin),2(daemon),3(sys)
HOME=/bin" --user bin -- sh -c "$ID"
    run_ctr "user by id" "uid=1(bin) gid=1(bin) groups=1(bin),2(daemon),3(sys)" --user 1 -- id
    run_ctr "user and group name" "uid=1(bin) gid=18(audio) groups=18(audio)" --user bin:audio -- id
    run_ctr "user and group id" "uid=1(bin) gid=1(bin) groups=1(bin)" --user 1:1 -- id
    run_ctr "group-add" "uid=1(bin) gid=1(bin) groups=1(bin),2(daemon),3(sys),9(kmem),10(wheel)" \
        --user 1 --group-add 10 --group-add kmem -- id
    run_ctr "unknown uid" "uid=4242(4242) gid=0(root) groups=0(root)
HOME=/tmp
4242:*:4242:0:container user:/tmp:/bin/sh" --user 4242 -w /tmp -- sh -c "$ID; tail -1 /etc/passwd"
    run_ctr "unknown uid and gid" "uid=4242(4242) gid=4243(4243) groups=4243(4243)
4243:x:4243:4242" --user 4242:4243 -- sh -c 'id; tail -1 /etc/group'
    run_ctr "root with an unknown gid" "uid=0(root) gid=4242(4242) groups=4242(4242)" --user 0:4242 -- id
    run_ctr "passwd-entry" '4242:x:4242:0:custom:/:/bin/ash' \
        --user 4242 --passwd-entry '$USERNAME:x:$UID:$GID:custom:$HOME:/bin/ash' -- tail -1 /etc/passwd
    run_ctr "passwd=false" 'uid=4242 gid=0(root) groups=0(root)' --user 4242 --passwd=false -- id
    run_ctr "umask" "0077" --umask 0077 -- sh -c umask
    run_ctr "default umask" "0022" -- sh -c umask
    run_ctr "tz" "JST" --tz Asia/Tokyo -- date +%Z
    if [ "$(id -u)" != 0 ]; then
        run_ctr "keep-id" "uid=$(id -u)($(id -un)) gid=$(id -g)($(id -gn)) groups=$(id -g)($(id -gn))
HOME=/
$(id -un):*:$(id -u):$(id -g)::/:/bin/sh
$(id -gn):x:$(id -g):$(id -un)" --userns=keep-id -- sh -c "$ID; tail -1 /etc/passwd; tail -1 /etc/group"
        # (--user root: the user of the host has its entry all the same)
        run_ctr "keep-id with --user" "root
$(id -un):*:$(id -u):$(id -g)::/:/bin/sh
$(id -gn):x:$(id -g):$(id -un)" --userns=keep-id --user root -- sh -c "id -un; tail -1 /etc/passwd; tail -1 /etc/group"
    fi
}

@test "an unknown user, group, umask or timezone is refused" {
    fails "unknown user" "unable to find user nosuch" --user nosuch -- true
    fails "unknown group" "unable to find group nosuch" --group-add nosuch -- true
    fails "keep-groups with groups" "keep-groups" --group-add keep-groups --group-add 10 -- true
    fails "bad umask" "invalid umask" --umask 999 -- true
    fails "bad tz" "invalid timezone" --tz ../../etc/passwd -- true
}

@test "the User of the image, --user overrides it" {
    # The User of the image, and exec as a name of the container.
    mkdir -p "$WORKDIR/ctx"
    printf 'FROM %s\nUSER bin\n' "$IMAGE" > "$WORKDIR/ctx/Containerfile"
    sc image build -q -t localhost/e2e-user:1 "$WORKDIR/ctx" > /dev/null 2>&1
    check "build an image with USER" 0 $?
    check "the user of the image" "uid=1(bin) gid=1(bin) groups=1(bin),2(daemon),3(sys)" \
        "$(sc container run --rm localhost/e2e-user:1 id 2>&1)"
    check "--user overrides the image" "0" "$(sc container run --rm --user 0 localhost/e2e-user:1 id -u 2>&1)"
}

@test "capabilities and no-new-privileges" {
    CAPS='grep -E "^(Cap|NoNewPrivs|Seccomp:)" /proc/self/status'
    run_ctr "default capabilities" "CapInh:	0000000000000000
CapPrm:	00000000800405fb
CapEff:	00000000800405fb
CapBnd:	00000000800405fb
CapAmb:	0000000000000000
NoNewPrivs:	0
Seccomp:	2" -- sh -c "$CAPS"
    run_ctr "a user has no capabilities" "CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	00000000800405fb
CapAmb:	0000000000000000" --user 1000 -- sh -c 'grep ^Cap /proc/self/status'
    run_ctr "a user gets the added ones" "CapInh:	0000000000002000
CapPrm:	0000000000002000
CapEff:	0000000000002000
CapBnd:	00000000800425fb
CapAmb:	0000000000002000" --user 1000 --cap-add net_raw -- sh -c 'grep ^Cap /proc/self/status'
    run_ctr "cap-add and cap-drop" "CapEff:	00000000a00c05f9" --cap-add CAP_SYS_PTRACE,audit_write --cap-drop dac_override -- \
        sh -c 'grep ^CapEff /proc/self/status'
    run_ctr "cap-drop all" "CapEff:	0000000000000020" --cap-drop all --cap-add kill -- sh -c 'grep ^CapEff /proc/self/status'
    run_ctr "no-new-privileges" "NoNewPrivs:	1" --security-opt no-new-privileges -- sh -c 'grep ^NoNewPrivs /proc/self/status'
    run_ctr "no-new-privileges=false" "NoNewPrivs:	0" --security-opt no-new-privileges=false -- sh -c 'grep ^NoNewPrivs /proc/self/status'
}

@test "seccomp, privileged, masked paths and sysctls" {
    run_ctr "seccomp=unconfined" "Seccomp:	0" --security-opt seccomp=unconfined -- sh -c 'grep ^Seccomp: /proc/self/status'
    run_ctr "privileged" "Seccomp:	0
rw" --privileged -- sh -c 'grep ^Seccomp: /proc/self/status; grep " /sys " /proc/self/mounts | cut -d" " -f4 | cut -d, -f1'
    run_ctr "sysfs is read-only" "ro" -- sh -c 'grep " /sys " /proc/self/mounts | cut -d" " -f4 | cut -d, -f1'
    run_ctr "masked paths" "0
0" -- sh -c 'wc -c < /proc/kcore; wc -c < /proc/keys'
    run_ctr "mask and unmask" "masked
unmasked" --security-opt mask=/proc/version --security-opt unmask=/proc/kcore -- \
        sh -c 'test -s /proc/version && echo visible || echo masked; test -r /proc/kcore && [ "$(stat -c %s /proc/kcore)" != 0 ] && echo unmasked || echo still'
    run_ctr "sysctl" "1" --sysctl net.ipv4.ip_forward=1 -- cat /proc/sys/net/ipv4/ip_forward
    run_ctr "ping without NET_RAW" "0	0" -- sh -c 'cat /proc/sys/net/ipv4/ping_group_range'
    fails "unknown capability" "unknown capability" --cap-add CAP_NOPE -- true
    fails "unknown security option" "unsupported security option" --security-opt bogus=1 -- true
    fails "a sysctl of the host" "not namespaced" --sysctl kernel.panic=1 -- true
    fails "a net sysctl with the host network" "network namespace the container does not own" --network host --sysctl net.ipv4.ip_forward=1 -- true
    echo '{"defaultAction": "SCMP_ACT_NOPE"}' > "$WORKDIR/bad-seccomp.json"
    fails "an invalid seccomp profile" "seccomp" --security-opt "seccomp=$WORKDIR/bad-seccomp.json" -- true
    fails "a missing seccomp profile" "seccomp profile" --security-opt "seccomp=$WORKDIR/nosuch.json" -- true
    cat > "$WORKDIR/seccomp.json" <<'JSON'
{"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [{"names": ["mkdir", "mkdirat"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]}
JSON
    run_ctr "a custom seccomp profile" "denied" --security-opt "seccomp=$WORKDIR/seccomp.json" -- \
        sh -c 'mkdir /tmp/x 2>/dev/null && echo made || echo denied'
}

@test "environment, entrypoint and hostname" {
    run_ctr "environment" "A=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
container=@ENGINE@" --hostname h1 -e A=1 -- sh -c 'env | grep -v -e ^HOME= -e ^HOSTNAME= -e ^PWD= -e ^SHLVL= | sed "s/container=.*/container=@ENGINE@/" | sort'
    run_ctr "HOSTNAME" "HOSTNAME=h1" --hostname h1 -- sh -c 'env | grep ^HOSTNAME'
    run_ctr "unsetenv" "" --unsetenv container --unsetenv PATH -- /bin/sh -c 'env | grep -e ^container= -e ^PATH='
    run_ctr "unsetenv-all keeps HOSTNAME" "HOSTNAME=h1" --hostname h1 --unsetenv-all -- /bin/sh -c 'env | grep -v -e ^PWD= -e ^SHLVL= -e ^HOME='
    run_ctr "env-merge" "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/x" --env-merge 'PATH=${PATH}:/x' -- sh -c 'env | grep ^PATH='
    E2E_INHERIT=inherited run_ctr "-e KEY takes the value of the caller" "inherited" -e E2E_INHERIT -- sh -c 'echo $E2E_INHERIT'
    run_ctr "--entrypoint drops the command of the image" "" --entrypoint echo --
    run_ctr "--entrypoint as JSON" "a b" --entrypoint '["echo","a"]' -- b
    run_ctr "--entrypoint ''" "x" --entrypoint "" -- echo x
    run_ctr "hostname file" "h1
h1" --hostname h1 -- sh -c 'hostname; cat /etc/hostname'
}

@test "ulimit, oom score, shm, read-only, host namespaces, personality and devices" {
    run_ctr "ulimit" "100
200" --ulimit nofile=100:200 -- sh -c 'ulimit -n; ulimit -Hn'
    run_ctr "oom-score-adj" "200" --oom-score-adj 200 -- cat /proc/self/oom_score_adj
    run_ctr "shm-size" "1.0M" --shm-size 1m -- sh -c "df -h /dev/shm | tail -1 | awk '{print \$2}'"
    run_ctr "read-only rootfs with tmpfs" "tmpfs
tmpfs
tmpfs" --read-only -- sh -c 'for d in /tmp /var/tmp /run; do grep " $d " /proc/self/mounts | cut -d" " -f3; done'
    run_ctr "read-only-tmpfs=false" "ro" --read-only --read-only-tmpfs=false -- sh -c 'touch /tmp/x 2>/dev/null && echo rw || echo ro'
    run_ctr "pid host" "yes" --pid host -- sh -c 'test -d /proc/1 && [ "$(cat /proc/1/comm)" != sh ] && echo yes'
    run_ctr "uts host" "$(hostname)" --uts host -- hostname
    run_ctr "personality" "i686" --personality LINUX32 -- uname -m
    run_ctr "device" "c 1, 3" --device /dev/null:/dev/mynull -- sh -c "ls -l /dev/mynull | awk '{print substr(\$1, 1, 1), \$5, \$6}'"
}

@test "create options that are refused" {
    fails "bad ulimit" "ulimit" --ulimit bogus=1 -- true
    fails "bad personality" "personality" --personality BSD -- true
    fails "bad device" "device" --device /etc/passwd -- true
    fails "bad oom score" "oom" --oom-score-adj 5000 -- true
}

@test "a compiled seccomp filter" {
    printf '\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x02\x00\x02\x01\x00\x00\x15\x00\x01\x00\x53\x00\x00\x00\x06\x00\x00\x00\x00\x00\xff\x7f\x06\x00\x00\x00\x01\x00\x05\x00' > "$WORKDIR/nomkdir.bpf"
    if [ "$(uname -m)" = x86_64 ]; then
        check "seccomp-bpf" "denied" "$(sc container run --rm --security-opt "seccomp-bpf=$WORKDIR/nomkdir.bpf" "$IMAGE" \
            sh -c 'mkdir /tmp/x 2>/dev/null && echo made || echo denied')"
    fi
    head -c 5 /etc/passwd > "$WORKDIR/bad.bpf"
    fails "a file that is not a BPF program" "not a BPF program" --security-opt "seccomp-bpf=$WORKDIR/bad.bpf" -- true
}

@test "SELinux labels" {
    [ -e /sys/fs/selinux/enforce ] || skip "no SELinux"
    LABEL='cat /proc/self/attr/current | tr -d "\0"'
    check_match "a confined process" '^system_u:system_r:container_t:s0:c[0-9]+,c[0-9]+$' \
        "$(sc container run --rm "$IMAGE" sh -c "$LABEL")"
    a=$(sc container run --rm "$IMAGE" sh -c "$LABEL")
    b=$(sc container run --rm "$IMAGE" sh -c "$LABEL")
    check "each container has its level" yes "$([ "$a" != "$b" ] && echo yes)"
    check "label=level" "system_u:system_r:container_t:s0:c1,c2" \
        "$(sc container run --rm --security-opt label=level:s0:c1,c2 "$IMAGE" sh -c "$LABEL")"
    check_match "label=disable" '^[^:]*:[^:]*:(spc_t|unconfined_t):' \
        "$(sc container run --rm --security-opt label=disable "$IMAGE" sh -c "$LABEL")"
    check_match "privileged" '^[^:]*:[^:]*:(spc_t|unconfined_t):' \
        "$(sc container run --rm --privileged "$IMAGE" sh -c "$LABEL")"
    check "the root file system is writable" "ok" \
        "$(sc container run --rm --user 4242 "$IMAGE" sh -c 'touch /tmp/x && id -un >/dev/null && echo ok')"
    mkdir -p "$WORKDIR/vol"
    echo data > "$WORKDIR/vol/f"
    # (a permissive policy denies nothing)
    if [ "$(cat /sys/fs/selinux/enforce)" = 1 ]; then
        check "an unlabeled bind mount is denied" "denied" \
            "$(sc container run --rm -v "$WORKDIR/vol:/v" "$IMAGE" sh -c 'cat /v/f 2>/dev/null || echo denied')"
    fi
    check ":Z relabels for the container" "data" "$(sc container run --rm -v "$WORKDIR/vol:/v:Z" "$IMAGE" cat /v/f)"
    check_match ":Z gives the level of the container" 'container_file_t:s0:c[0-9]+,c[0-9]+$' "$(stat -c %C "$WORKDIR/vol/f")"
    check ":z relabels for all" "data" "$(sc container run --rm -v "$WORKDIR/vol:/v:z" "$IMAGE" cat /v/f)"
    check_match ":z gives the shared level" 'container_file_t:s0$' "$(stat -c %C "$WORKDIR/vol/f")"
    check "a named volume" "x" "$(sc container run --rm -v e2e-selinux:/n "$IMAGE" sh -c 'echo x > /n/f && cat /n/f')"
    # podman's rule: a few exact paths are refused, a directory below them is relabeled
    fails "relabel /etc" "SELinux relabeling of /etc is not allowed" -v /etc:/x:Z -- true
    fails "relabel /usr" "SELinux relabeling of /usr is not allowed" -v /usr:/x:Z -- true
    fails "relabel /usr/" "SELinux relabeling of /usr is not allowed" -v /usr/:/x:Z -- true
    for base in /dev/shm /tmp; do
        d=$(mktemp -d "$base/e2e-relabel.XXXXXX")
        echo data > "$d/f"
        out=$(sc container run --rm -v "$d:/v:Z" "$IMAGE" cat /v/f)
        rm -rf "$d"
        check ":Z on a subdirectory of $base" "data" "$out"
    done
    fails "an invalid label option" "SELinux" --security-opt label=type:a:b -- true
    fails "a level without the colon before its categories" "SELinux level" --security-opt label=level:s0,c1,c2 -- true
    fails "and with --privileged too" "SELinux level" --privileged --security-opt label=level:s0,c1,c2 -- true
    # label=files: a privileged container is spc_t, its files are labelled as those of
    # the others (what the CRI asks for)
    check "label=files: the process of a privileged container" "system_u:system_r:spc_t:s0" \
        "$(sc container run --rm --privileged --security-opt label=files "$IMAGE" sh -c "$LABEL")"
    check_match "label=files: its files have a level of their own" 'context="system_u:object_r:container_file_t:s0:c[0-9]+,c[0-9]+"' \
        "$(sc container run --rm --privileged --security-opt label=files "$IMAGE" cat /proc/1/mountinfo)"
}

@test "an AppArmor profile without AppArmor" {
    if [ -e /sys/module/apparmor/parameters/enabled ] && [ "$(cat /sys/module/apparmor/parameters/enabled)" = Y ]; then
        skip "AppArmor is enabled"
    fi
    fails "an AppArmor profile without AppArmor" "AppArmor" --security-opt apparmor=myprofile -- true
    run_ctr "apparmor=unconfined without AppArmor" "ok" --security-opt apparmor=unconfined -- echo ok
}

@test "cgroup limits and stats, rootless too" {
    # the daemon delegates a scope to itself
    run_ctr "memory limit" "67108864" --memory 64m -- cat /sys/fs/cgroup/memory.max
    run_ctr "pids limit" "50" --pids-limit 50 -- cat /sys/fs/cgroup/pids.max
    run_ctr "cpu limit" "50000 100000" --cpus 0.5 -- cat /sys/fs/cgroup/cpu.max
    id=$(sc container run -d --memory 32m "$IMAGE" sleep 60)
    check_match "stats" "33.55MB" "$(sc stats --no-stream "$id" 2>&1)"
    sc container rm -t 0 -f "$id" > /dev/null
}

@test "namespaces of another container are resolved at each start" {
    sc container run -d --name nsa "$IMAGE" sleep 301 > /dev/null
    check_match "--pid container: sees the target" "sleep 301" \
        "$(sc container run --rm --pid container:nsa "$IMAGE" ps -o args)"
    sc container run -d --name nsb --pid container:nsa "$IMAGE" sleep 302 > /dev/null
    sc container stop -t 1 nsa > /dev/null; sc container start nsa > /dev/null
    sc container stop -t 1 nsb > /dev/null; sc container start nsb > /dev/null
    check_match "a restarted target: the joiner follows it" "sleep 301" "$(sc container exec nsb ps -o args)"
    sc container stop -t 1 nsb > /dev/null; sc container stop -t 1 nsa > /dev/null
    out=$(sc container start nsb 2>&1)
    check "the target does not run: the start fails" 1 $(( $? != 0 ))
    check_match "the target does not run: message" "nsa|joins" "$out"
    # A restart policy with a joined namespace is allowed: the monitor keeps
    # the joined namespaces open for its restarts.
    sc container start nsa > /dev/null
    sc container run -d --name nsr --restart always --pid container:nsa "$IMAGE" sleep 302 > /dev/null
    check "a restart policy with a joined namespace" running "$(sc container inspect --format '{{.State.Status}}' nsr)"
    sc container rm -t 0 -f nsr > /dev/null
    sc container stop -t 1 nsa > /dev/null
    if [ "$(id -u)" != 0 ]; then
        fails "its own user namespace and the pid namespace of another" "user namespace" \
            --userns keep-id --pid container:nsa -- true
        out=$(sc container run --rm --oom-score-adj=-100 "$IMAGE" cat /proc/self/oom_score_adj 2>/dev/null)
        check "a lower oom score rootless is raised to the current one" "$(cat /proc/self/oom_score_adj)" "$out"
    fi
    sc container rm -t 0 -f nsb nsa > /dev/null 2>&1
    run_ctr "privileged: the cgroup file system is writable" "rw" --privileged -- \
        sh -c 'grep " /sys/fs/cgroup " /proc/self/mounts | cut -d" " -f4 | cut -d, -f1'
    fails "a sysctl in another container's network" "network namespace" \
        --network container:nosuch --sysctl net.ipv4.ip_forward=1 -- true
}

# The spec carries the destinations of the bind mounts as given: the runtime
# resolves them in the root at every start, so a container that replaces the
# link /etc -> /var/etc of its image by a directory gets /etc/hosts there
# after a restart.
@test "the destinations of the bind mounts are resolved at each start" {
    sc container create --name lnk "$IMAGE" true > /dev/null
    mkdir "$WORKDIR/lnkroot"
    sc container export lnk | tar -C "$WORKDIR/lnkroot" -xf - 2> /dev/null
    sc container rm lnk > /dev/null
    mkdir -p "$WORKDIR/lnkroot/var"
    mv "$WORKDIR/lnkroot/etc" "$WORKDIR/lnkroot/var/etc"
    ln -s /var/etc "$WORKDIR/lnkroot/etc"
    tar -C "$WORKDIR/lnkroot" -cf "$WORKDIR/lnk.tar" .
    sc image import "$WORKDIR/lnk.tar" localhost/e2e-etclink:1 > /dev/null
    check "the image is imported" 0 $?
    sc container run -d --name lnk --network none localhost/e2e-etclink:1 sleep 303 > /dev/null
    hosts () { sc container exec lnk sh -c 'grep -E " /(var/)?etc/hosts " /proc/self/mountinfo | cut -d" " -f5'; }
    check "first start: /etc/hosts below the link" /var/etc/hosts "$(hosts)"
    sc container exec lnk sh -c 'rm /etc && mkdir /etc'
    sc container stop -t 0 lnk > /dev/null; sc container start lnk > /dev/null
    check "after a restart: in the directory that replaced the link" /etc/hosts "$(hosts)"
    sc container rm -t 0 -f lnk > /dev/null
    sc image rm -f localhost/e2e-etclink:1 > /dev/null
}

@test "the daemon keeps the limits of where it was started" {
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid")
    mine=$(lim "$(sed -n 's/^0:://p' /proc/self/cgroup)")
    theirs=$(lim "$(sed -n 's/^0:://p' "/proc/$DAEMON_PID/cgroup")")
    if [ "$mine" != max ]; then
        check "the daemon has the memory limit of its caller" "$mine" "$theirs"
    fi
}

@test "--requires" {
    sc container create --name dep1 "$IMAGE" sleep 303 > /dev/null
    sc container run -d --name dep2 --requires dep1 "$IMAGE" sleep 304 > /dev/null
    check_match "--requires starts the dependency" "sleep 303" "$(sc container exec dep1 ps -o args 2>&1)"
    out=$(sc container rm -t 0 -f dep1 2>&1)
    check "a dependency cannot be removed" 1 $(( $? != 0 ))
    check_match "a dependency cannot be removed: message" "dependent containers" "$out"
    sc container rm -t 0 -f dep2 > /dev/null
    sc container rm -t 0 -f dep1 > /dev/null
    sc container inspect dep1 > /dev/null 2>&1
    check "then it can" 1 $(( $? != 0 ))
    fails "--requires of a missing container" "not a valid container" --requires nosuch -- true
}

@test "host.containers.internal, with and without a network" {
    check_match "host.containers.internal" "host.containers.internal host.docker.internal" \
        "$(sc container run --rm "$IMAGE" grep host.containers.internal /etc/hosts)"
    check_match "host.containers.internal without a network" "host.containers.internal host.docker.internal" \
        "$(sc container run --rm --network none "$IMAGE" grep host.containers.internal /etc/hosts)"
}

@test "hugepage limits" {
    skip_unless_root
    [ -d /sys/kernel/mm/hugepages/hugepages-2048kB ] || skip "no 2 MB hugepages"
    body="{\"image\": \"$IMAGE\", \"command\": [\"sleep\", \"60\"], \"resource_limits\": {\"hugepageLimits\": [{\"pageSize\": \"2MB\", \"limit\": 4194304}]}}"
    id=$(curl -s --unix-socket "$SOCK" -XPOST -H 'Content-Type: application/json' -d "$body" \
        http://d/v4.0.0/libpod/containers/create | sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p')
    curl -s --unix-socket "$SOCK" -XPOST "http://d/v4.0.0/libpod/containers/$id/start" > /dev/null
    check "hugepage limit" "4194304" "$(sc container exec "$id" cat /sys/fs/cgroup/hugetlb.2MB.max 2>&1)"
    sc container rm -t 0 -f "$id" > /dev/null
}

@test "update of a container" {
    id=$(sc container run -d "$IMAGE" sleep 305)
    check "update a running container" 201 "$(api_update "$id" '{"memory": {"limit": 41943040}}')"
    check "its memory limit changed" "41943040" "$(sc container exec "$id" cat /sys/fs/cgroup/memory.max)"
    sc container stop -t 1 "$id" > /dev/null
    check "update a stopped container" 201 "$(api_update "$id" '{"memory": {"limit": 52428800}, "pids": {"limit": 77}}')"
    sc container start "$id" > /dev/null
    check "the next start has it" "52428800 77" \
        "$(sc container exec "$id" sh -c 'echo $(cat /sys/fs/cgroup/memory.max) $(cat /sys/fs/cgroup/pids.max)')"
    check "device rules" 201 \
        "$(api_update "$id" '{"devices": [{"allow": true, "type": "c", "major": 10, "minor": 229, "access": "rw"}]}')"
    # the io controller is delegated to root only
    if [ "$(id -u)" = 0 ]; then
        check "block IO" 201 "$(api_update "$id" '{"blockIO": {"weight": 300}}')"
        check_match "its weight" "default (300|2930)" "$(sc container exec "$id" sh -c "cat /sys/fs/cgroup/io.bfq.weight 2>/dev/null || cat /sys/fs/cgroup/io.weight" 2>&1)"
    else
        check "block IO without the io controller" 400 "$(api_update "$id" '{"blockIO": {"weight": 300}}')"
        # what the runtime refuses is not recorded: neither the memory limit
        # that came with it
        check "a refused update" 400 \
            "$(api_update "$id" '{"memory": {"limit": 62914560}, "blockIO": {"weight": 300}}')"
        check "the record keeps the limit the cgroup has" "52428800 52428800" \
            "$(sc container inspect --format '{{.HostConfig.Memory}}' "$id") $(sc container exec "$id" cat /sys/fs/cgroup/memory.max)"
    fi
    check "an invalid block IO weight" 400 "$(api_update "$id" '{"blockIO": {"weight": 5}}')"
    check "a deny rule" 501 "$(api_update "$id" '{"devices": [{"allow": false, "access": "rwm"}]}')"
    sc container rm -t 0 -f "$id" > /dev/null
}

@test "SELinux of image mounts and of the containers of a pod" {
    [ -e /sys/fs/selinux/enforce ] || skip "no SELinux"
    check_match "an image mount has the label of the container" \
        'overlay none ro,context="system_u:object_r:container_file_t:s0:c[0-9]+,c[0-9]+"' \
        "$(sc container run --rm --mount "type=image,source=$IMAGE,target=/img" "$IMAGE" grep ' /img ' /proc/self/mountinfo)"
    check "an image mount is readable" "$(sc container run --rm "$IMAGE" cat /etc/alpine-release)" \
        "$(sc container run --rm --mount "type=image,source=$IMAGE,target=/img" "$IMAGE" cat /img/etc/alpine-release)"
    api () { curl -s --unix-socket "$SOCK" -XPOST -H 'Content-Type: application/json' -d "$2" "http://d/v4.0.0/libpod/$1"; }
    api pods/create "{\"name\": \"selpod\", \"infra_image\": \"$IMAGE\", \"infra_command\": [\"sleep\", \"1000\"]}" > /dev/null
    for n in 1 2; do
        id=$(api containers/create "{\"image\": \"$IMAGE\", \"command\": [\"sleep\", \"60\"], \"pod\": \"selpod\"}" \
            | sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p')
        api "containers/$id/start" '' > /dev/null
        eval "label$n=\$(sc container exec $id cat /proc/self/attr/current | tr -d '\\0')"
    done
    check_match "a container of a pod is confined" ':container_t:s0:c[0-9]+,c[0-9]+$' "$label1"
    check "the containers of a pod share the label" "$label1" "$label2"
    curl -s --unix-socket "$SOCK" -XDELETE "http://d/v4.0.0/libpod/pods/selpod?force=true&timeout=0" > /dev/null
}

@test "container= and /run/.containerenv for every container" {
    run_ctr "container= in the environment" "podman" -- sh -c 'echo $container'
    run_ctr "the image's container= wins" "oci" --env container=oci -- sh -c 'echo $container'
    run_ctr "/run/.containerenv is empty" "0" -- sh -c 'wc -c < /run/.containerenv'
    out=$(sc container run --rm --privileged --name ce "$IMAGE" cat /run/.containerenv 2>&1)
    check_match "/run/.containerenv of a privileged container" \
        '^engine="velarx-[0-9.]+"
name="ce"
id="[0-9a-f]{64}"
image="[^"]+"
imageid="[0-9a-f]{64}"
rootless=[01]$' "$out"
    check "a user /run/.containerenv is kept" "mine" \
        "$(echo mine > "$WORKDIR/ce"; sc container run --rm -v "$WORKDIR/ce:/run/.containerenv:z" "$IMAGE" cat /run/.containerenv 2>&1)"
}

@test "systemd mode" {
    MI='awk -v d=$d '"'"'$5 == d {for (i = 7; $i != "-"; i++); split($6, o, ","); print $5, o[1], $(i + 1)}'"'"' /proc/self/mountinfo'
    SDMOUNTS='for d in /run /run/lock /tmp /var/log/journal /sys/fs/cgroup; do '"$MI"'; done; echo uuid=${#container_uuid}'
    run_ctr "--systemd=always" "/run rw tmpfs
/run/lock rw tmpfs
/tmp rw tmpfs
/var/log/journal rw tmpfs
/sys/fs/cgroup rw cgroup2
uuid=32" --systemd=always -- sh -c "$SDMOUNTS"
    run_ctr "--systemd=always keeps a /tmp of the user" "/tmp ro tmpfs" \
        --systemd=always --tmpfs /tmp:ro -- sh -c "d=/tmp; $MI"
    run_ctr "--systemd=false" "/sys/fs/cgroup ro cgroup2
uuid=0" --systemd=false -- sh -c "$SDMOUNTS"
    fails "--systemd=bogus" "true, false or always" --systemd=bogus -- true
    sc container run -d --name sdi --systemd=always "$IMAGE" sleep 60 > /dev/null 2>&1
    check "systemd mode: stop signal and inspect" "37 true" \
        "$(curl -s --unix-socket "$SOCK" "http://d/v4.0.0/libpod/containers/sdi/json" | python3 -c 'import json,sys; c=json.load(sys.stdin)["Config"]; print(c["StopSignal"], str(c["SystemdMode"]).lower())')"
    sc container rm -t 0 -f sdi > /dev/null 2>&1
}

@test "a real systemd boots and stops on SIGRTMIN+3" {
    [ -n "${SYSTEMD_IMAGE:-}" ] || skip "no SYSTEMD_IMAGE"
    sc image pull --tls-verify=false "$SYSTEMD_IMAGE" > /dev/null 2>&1
    sc container run -d --name sd "$SYSTEMD_IMAGE" /sbin/init > /dev/null
    # (`is-system-running --wait` ends when the boot has: the loop in the container
    # is for the first seconds, while systemd does not answer yet)
    st=$(sc container exec sd timeout 60 sh -c 'until s=$(systemctl is-system-running --wait 2> /dev/null) || [ "$s" = degraded ]; do :; done; echo "$s"')
    check_match "systemd boots" '^(running|degraded)$' "$st"
    check "systemd: no unit but logind failed (as podman)" "" \
        "$(sc container exec sd systemctl --failed --plain --no-legend | grep -v -E '^systemd-logind' | cut -d' ' -f1)"
    sc container stop sd > /dev/null
    check "systemd shuts down cleanly on stop" 0 \
        "$(curl -s --unix-socket "$SOCK" http://d/v4.0.0/libpod/containers/sd/json | python3 -c 'import json,sys; print(json.load(sys.stdin)["State"]["ExitCode"])')"
    sc container rm -t 0 -f sd > /dev/null 2>&1
}

@test "overlay volumes through the podman API" {
    mkdir -p "$WORKDIR/olow"
    echo orig > "$WORKDIR/olow/f"
    id=$(curl -s --unix-socket "$SOCK" -H 'Content-Type: application/json' \
        -d "{\"image\": \"$IMAGE\", \"command\": [\"sh\", \"-c\", \"echo w > /o/f; cat /o/f\"],
        \"overlay_volumes\": [{\"source\": \"$WORKDIR/olow\", \"destination\": \"/o\", \"options\": []}]}" \
        http://d/v4.0.0/libpod/containers/create | sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p')
    curl -s --unix-socket "$SOCK" -XPOST "http://d/v4.0.0/libpod/containers/$id/start" > /dev/null
    curl -s --unix-socket "$SOCK" -XPOST "http://d/v4.0.0/libpod/containers/$id/wait" > /dev/null
    check "overlay_volumes: the container writes" "w" "$(sc container logs "$id" 2>&1)"
    check "overlay_volumes: the source is unchanged" "orig" "$(cat "$WORKDIR/olow/f")"
    sc container rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "a directory of a named volume through the docker and podman APIs" {
    sc volume create spapi > /dev/null
    sc container run --rm -v spapi:/v "$IMAGE" sh -c 'mkdir -p /v/a && echo in > /v/a/f' > /dev/null
    apirun () { # PATH BODY: create, start, wait; the logs
        local id
        id=$(curl -s --unix-socket "$SOCK" -H 'Content-Type: application/json' -d "$2" "http://d/$1" \
            | sed -n 's/.*"Id":"\([0-9a-f]*\)".*/\1/p')
        curl -s --unix-socket "$SOCK" -XPOST "http://d/v4.0.0/libpod/containers/$id/start" > /dev/null
        curl -s --unix-socket "$SOCK" -XPOST "http://d/v4.0.0/libpod/containers/$id/wait" > /dev/null
        sc container logs "$id" 2>&1
        sc container rm -t 0 -f "$id" > /dev/null 2>&1
    }
    check "docker API VolumeOptions.Subpath" "in" "$(apirun v1.41/containers/create \
        "{\"Image\": \"$IMAGE\", \"Cmd\": [\"cat\", \"/d/f\"], \"HostConfig\": {\"Mounts\": [{\"Type\": \"volume\",
      \"Source\": \"spapi\", \"Target\": \"/d\", \"VolumeOptions\": {\"Subpath\": \"a\"}}]}}")"
    check "podman API volume SubPath" "in" "$(apirun v4.0.0/libpod/containers/create \
        "{\"image\": \"$IMAGE\", \"command\": [\"cat\", \"/d/f\"],
      \"volumes\": [{\"Name\": \"spapi\", \"Dest\": \"/d\", \"SubPath\": \"a\"}]}")"
    sc volume remove -f spapi > /dev/null 2>&1
}

@test "the mounts of a monitor are its own" {
    engine_mountinfo () {
        if [ "$(id -u)" = 0 ]; then cat /proc/self/mountinfo; else "$SH" unshare cat /proc/self/mountinfo; fi
    }
    sc container run -d --name privm "$IMAGE" sleep 100 > /dev/null
    check "the container runs from its root file system" 0 \
        "$(sc container exec privm test -f /etc/alpine-release; echo $?)"
    check "its root file system is not mounted where the engine is" "" \
        "$(engine_mountinfo | grep "/bundles/$(sc container inspect privm --format '{{.Id}}' 2> /dev/null)/rootfs ")"
    sc container rm -t 0 -f privm > /dev/null 2>&1
}

@test "rshared volumes reach the host" {
    skip_unless_root
    # (a test run in a private mount namespace has no host to reach)
    findmnt -n -o PROPAGATION --target "$WORKDIR" | grep -q shared ||
        skip "the mounts of this mount namespace are private: they do not reach the host"
    mkdir -p "$WORKDIR/shared/x" "$WORKDIR/private/x"
    sc container run --rm --privileged -v "$WORKDIR/shared:/m:rshared" "$IMAGE" mount -t tmpfs t /m/x > /dev/null 2>&1
    check "a mount below an rshared volume reaches the host" tmpfs "$(stat -f -c %T "$WORKDIR/shared/x")"
    umount "$WORKDIR/shared/x" 2> /dev/null
    sc container run --rm --privileged -v "$WORKDIR/private:/m" "$IMAGE" mount -t tmpfs t /m/x > /dev/null 2>&1
    check "and not below a private one" 0 "$(grep -c " $WORKDIR/private/x " /proc/self/mountinfo)"
    # a monitor in the host's namespace (rshared) that dies: its mounts are
    # detached once the engine notices
    id=$(sc container run -d --conmon-pidfile "$WORKDIR/mon.pid" -v "$WORKDIR/shared:/m:rshared" "$IMAGE" sleep 100)
    check "the root of an rshared container is in the host's namespace" 1 \
        "$(grep -c "/bundles/$id/rootfs " /proc/self/mountinfo)"
    mon=$(cat "$WORKDIR/mon.pid")
    kill -9 "$mon"
    e2e_wait_exit "$mon"
    # its container runs on, followed by the server, from its root
    check "a monitor that died: its container runs on" running \
        "$(sc container inspect "$id" --format '{{.State.Status}}' 2> /dev/null)"
    check "from its root file system" 1 "$(grep -c "/bundles/$id/rootfs " /proc/self/mountinfo)"
    sc container stop -t 1 "$id" > /dev/null 2>&1
    # (the kernel signals a change of the mount table: POLLPRI on mountinfo)
    python3 -I -c '
import select, sys, time
f = open("/proc/self/mountinfo")
p = select.poll()
p.register(f, select.POLLERR | select.POLLPRI)
end = time.monotonic() + 10
while True:
    f.seek(0)
    if not any("/bundles/" + sys.argv[1] + "/" in l for l in f):
        break
    left = end - time.monotonic()
    if left <= 0:
        break
    p.poll(left * 1000)' "$id"
    check "once it ends, nothing is left mounted" 0 "$(grep -c "/bundles/$id/" /proc/self/mountinfo)"
    sc container rm -t 0 -f "$id" > /dev/null 2>&1
}

@test "--init: catatonit of the host bound at /run/podman-init" {
    [ -x /usr/libexec/podman/catatonit ] || [ -x /usr/libexec/catatonit/catatonit ] || [ -x /usr/bin/catatonit ] || skip "no catatonit"
    run_ctr "--init: an init is PID 1, the command its child" "podman-init
2" --init -- sh -c 'cat /proc/1/comm; echo $$'
    run_ctr "--init with --read-only" "podman-init" --init --read-only -- cat /proc/1/comm
}

@test "--init with an init binary that is not there is refused at create, as podman's" {
    out=$(sc container create --init --init-path /nonexistent/init "$IMAGE" true 2>&1)
    check "refused" 125 $?
    check_match "in podman's words" "container-init binary not found on the host: /nonexistent/init" "$out"
}

@test "--read-only keeps /run/.containerenv" {
    run_ctr "--read-only keeps /run/.containerenv" "0" --read-only -- sh -c 'wc -c < /run/.containerenv'
}

@test "an exec gets the rlimits of the container" {
    sc container run -d --name ulim --ulimit nofile=1024:2048 "$IMAGE" sleep 100 > /dev/null
    check "exec gets the container's rlimits" "1024 2048" "$(sc container exec ulim sh -c 'echo $(ulimit -Sn) $(ulimit -Hn)' 2>&1)"
    sc container rm -t 0 -f ulim > /dev/null 2>&1
    if [ -n "${E2E_PODMAN:-}" ]; then
        pm run -d --name ulim --ulimit nofile=1024:2048 "$IMAGE" sleep 100 > /dev/null
        check "exec gets the container's rlimits (podman)" "1024 2048" "$(pm exec ulim sh -c 'echo $(ulimit -Sn) $(ulimit -Hn)' 2>&1)"
        pm rm -f -t0 ulim > /dev/null 2>&1
    fi
}
