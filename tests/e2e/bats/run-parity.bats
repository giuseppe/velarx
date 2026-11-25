# SPDX-License-Identifier: Apache-2.0
# The options of run, create, exec, update, logs and stats that podman has and
# velarx got for parity: each has its effect in the container (or the
# refusal podman's runtime gives), through a daemon of its own.  Run it as an
# ordinary user for the rootless daemon, or as root (the cgroup tests need it).

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

teardown () {
    # (the scheduler a test changed for the whole host, back even when it
    # failed)
    if [ -n "${SCHED_RESTORE:-}" ]; then
        echo "$SCHED_RESTORE" > /sys/block/nullb0/queue/scheduler
    fi
    run_test_teardown
}

# ID of a container
id_of () { sh_ container inspect -f '{{.Id}}' "$1"; }
# a field of the OCI spec of the bundle of a container
spec_of () {
    python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$XDG_DATA_HOME/velarx/bundles/$(id_of "$1")/config.json" "$2"
}

@test "-h is the hostname, --help is the help" {
    check "run -h" "myhost" "$(sh_ container run --rm -h myhost "$IMAGE" hostname 2>&1)"
    check "run -hNAME" "glued" "$(sh_ container run --rm -hglued "$IMAGE" hostname 2>&1)"
    out=$(sh_ container run --help 2>&1)
    check "run --help" 0 $?
    check_match "run --help is the help" "^Usage:" "$out"
    check_match "and shows -h" "-h, --hostname" "$out"
    check_match "create --help is the help" "^Usage:" "$(sh_ container create --help 2>&1)"
    sh_ container create --name hn -h created "$IMAGE" hostname > /dev/null
    check "create -h" "created" "$(sh_ container inspect -f '{{.Config.Hostname}}' hn)"
    sh_ container rm hn > /dev/null
    sh_ pod create --name hp -h podhost > /dev/null
    check "pod create -h" "podhost" "$(sh_ container run --rm --pod hp "$IMAGE" hostname 2>&1)"
    check_match "pod create --help" "^Usage:" "$(sh_ pod create --help 2>&1)"
    sh_ pod rm -t 0 -f hp > /dev/null
}

@test "-f is --filter of start, stop, restart, pause, unpause" {
    for n in a1 a2 b1; do
        sh_ container run -d --name "f$n" -l "grp=${n%[0-9]}" --network none "$IMAGE" sleep 300 > /dev/null
    done
    out=$(sh_ container stop -t 0 -f label=grp=a 2>&1)
    check "stop -f prints the two" 2 "$(echo "$out" | wc -l)"
    check "the match stopped" exited "$(state_of fa1)"
    check "the others did not" running "$(state_of fb1)"
    out=$(sh_ container start --all -f label=grp=a 2>&1)
    check "start -f prints the two" 2 "$(echo "$out" | wc -l)"
    check "and started them" running "$(state_of fa1)"
    sh_ container restart -t 0 -f label=grp=b > /dev/null 2>&1
    check "restart -f" 0 $?
    sh_ container pause -f label=grp=a > /dev/null 2>&1
    check "pause -f" paused "$(state_of fa2)"
    check "pause -f leaves the others" running "$(state_of fb1)"
    sh_ container unpause -f label=grp=a > /dev/null 2>&1
    check "unpause -f" running "$(state_of fa2)"
    sh_ container rm -f -t 0 fa1 fa2 fb1 > /dev/null
}

@test "--hosts-file" {
    printf '10.9.8.7 base.test\n' > "$WORKDIR/hosts.base"
    out=$(sh_ container run --rm --hosts-file "$WORKDIR/hosts.base" "$IMAGE" cat /etc/hosts 2>&1)
    check_match "a base file" "^10.9.8.7[[:space:]]+base.test" "$out"
    check_match "the container's own entry is there too" "^127.0.0.1[[:space:]]+localhost" "$out"
    out=$(sh_ container run --rm --hosts-file none "$IMAGE" cat /etc/hosts 2>&1)
    check "none: no base entry" 0 "$(echo "$out" | grep -c base.test)"
    # the hosts file of the image is the base
    printf '10.1.2.3 inimage.test\n' > "$WORKDIR/ctx.hosts"
    mkdir -p "$WORKDIR/hctx"
    cp "$WORKDIR/ctx.hosts" "$WORKDIR/hctx/hosts"
    printf 'FROM %s\nCOPY hosts /etc/hosts\n' "$IMAGE" > "$WORKDIR/hctx/Containerfile"
    sh_ image build -q -t localhost/e2e-hosts:1 "$WORKDIR/hctx" > /dev/null 2>&1
    check "build the image with an /etc/hosts" 0 $?
    out=$(sh_ container run --rm --hosts-file image localhost/e2e-hosts:1 cat /etc/hosts 2>&1)
    check_match "image: the hosts file of the image" "^10.1.2.3[[:space:]]+inimage.test" "$out"
    out=$(sh_ container run --rm localhost/e2e-hosts:1 cat /etc/hosts 2>&1)
    check "the default is not the image's" 0 "$(echo "$out" | grep -c inimage.test)"
    sh_ rmi localhost/e2e-hosts:1 > /dev/null 2>&1
    out=$(cd "$WORKDIR" && sh_ container run --rm --hosts-file hosts.base "$IMAGE" cat /etc/hosts 2>&1)
    check_match "a relative path is the caller's, as podman's" "^10.9.8.7[[:space:]]+base.test" "$out"
    out=$(sh_ container run --rm --hosts-file "$WORKDIR/nosuch" "$IMAGE" true 2>&1)
    check_match "a file that is not there" "not a file" "$out"

}

@test "--hostuser" {
    # a user of the host that the image does not know (root's own entry is
    # the image's)
    sh_ container run --rm "$IMAGE" cat /etc/passwd > "$WORKDIR/image.passwd"
    me=$(awk -F: 'NR == FNR { known[$1] = 1; next } !($1 in known) && $3 > 0 && $3 < 60000 { print $1; exit }' \
        "$WORKDIR/image.passwd" /etc/passwd)
    [ -n "$me" ] || skip "every user of the host is known to the image"
    uid=$(id -u "$me"); gid=$(id -g "$me")
    out=$(sh_ container run --rm --hostuser "$me" "$IMAGE" sh -c "grep '^$me:' /etc/passwd" 2>&1)
    check_match "--hostuser: the entry of the host's user" "^$me:\\*:$uid:$gid:" "$out"
    out=$(sh_ container run --rm --hostuser "$uid" --user "$me" "$IMAGE" id -u 2>&1)
    check "--user is a host user" "$uid" "$out"
    out=$(sh_ container run --rm --hostuser nosuchuser9 "$IMAGE" true 2>&1)
    check "an unknown host user" 126 $?
    check_match "is named" "nosuchuser9" "$out"
}

@test "--chrootdirs" {
    out=$(sh_ container run --rm --chrootdirs /chroot,/other "$IMAGE" sh -c 'cat /chroot/etc/hostname /other/etc/hosts | wc -l; test "$(cat /chroot/etc/hostname)" = "$(hostname)" && echo same; ls /chroot/etc' 2>&1)
    check_match "--chrootdirs: the files are below the directories" "same" "$out"
    check_match "and resolv.conf" "resolv.conf" "$out"
    out=$(sh_ container run --rm --chrootdirs ../x "$IMAGE" true 2>&1)
    check "a relative directory is refused" 125 $?
}

@test "-a attaches some of the streams" {
    out=$(sh_ container run --rm -a stdout "$IMAGE" sh -c 'echo out; echo err >&2' 2> /dev/null)
    check "-a stdout shows the output" "out" "$out"
    out=$(sh_ container run --rm -a stdout "$IMAGE" sh -c 'echo out; echo err >&2' 2>&1 > /dev/null)
    check "-a stdout does not show the errors" "" "$out"
    out=$(sh_ container run --rm -a stderr "$IMAGE" sh -c 'echo out; echo err >&2' 2>&1)
    check "-a stderr shows the errors only" "err" "$out"
    out=$(sh_ container run --rm -a STDOUT -a stderr "$IMAGE" sh -c 'echo out; echo err >&2' 2>&1 | sort)
    check "both" "err
out" "$out"
    sh_ container run --rm -a stdout "$IMAGE" sh -c 'exit 7' > /dev/null 2>&1
    check "the exit status" 7 $?
    out=$(sh_ container run --rm -a bogus "$IMAGE" true 2>&1)
    check "an unknown stream" 125 $?
    check_match "is named as podman does" 'invalid stream "bogus" for --attach - must be one of stdin, stdout, or stderr' "$out"
    out=$(sh_ container create -a stdout "$IMAGE" true 2>&1)
    check "create -a is refused" 125 $?
    check_match "and says what to do" "start --attach" "$out"
}

@test "exec: --preserve-fds, --preserve-fd, --cidfile, --no-session" {
    sh_ container run -d --name px --network none "$IMAGE" sleep 300 > /dev/null
    echo from-three > "$WORKDIR/fd3"
    echo from-five > "$WORKDIR/fd5"
    out=$("$SH" container exec --preserve-fds 1 px sh -c 'cat <&3' 3< "$WORKDIR/fd3" 2>&1)
    check "--preserve-fds 1: the descriptor 3" "from-three" "$out"
    out=$("$SH" container exec --preserve-fds 3 px sh -c 'cat <&3; cat <&5' 3< "$WORKDIR/fd3" 4< /dev/null 5< "$WORKDIR/fd5" 2>&1)
    check "--preserve-fds 3: the numbers are kept" "from-three
from-five" "$out"
    out=$("$SH" container exec --preserve-fd 5 px sh -c 'cat <&5; test -e /proc/self/fd/4 && echo four; test -e /proc/self/fd/3' 5< "$WORKDIR/fd5" 3< "$WORKDIR/fd3" 2>&1)
    check_match "--preserve-fd 5: the descriptor" "^from-five" "$out"
    check "the hole stays closed" 0 "$(echo "$out" | grep -c four)"
    out=$("$SH" container exec --preserve-fd 3,5 px sh -c 'cat <&3; cat <&5' 3< "$WORKDIR/fd3" 5< "$WORKDIR/fd5" 2>&1)
    check "a list" "from-three
from-five" "$out"
    out=$("$SH" container exec px sh -c 'test -e /proc/self/fd/3 && echo open' 3< "$WORKDIR/fd3" 2>&1)
    check "no option: the descriptor does not pass" "" "$out"
    out=$(sh_ container exec --preserve-fds 1 px true 2>&1 3<&-)
    check "a descriptor that is not open" 125 $?
    check_match "is refused as podman does" "file descriptor 3 is not available - the preserve-fds option requires that file descriptors must be passed" "$out"
    out=$("$SH" container exec --preserve-fds 3 px true 2>&1 3< /dev/null 4<&- 5<&-)
    check_match "none of velarx's own descriptors stands in for the caller's" "file descriptor 4 is not available" "$out"
    out=$("$SH" container exec --preserve-fds 1 --preserve-fd 3 px true 2>&1 3< /dev/null)
    check_match "both options" "cannot specify both --preserve-fds and --preserve-fd" "$out"
    out=$("$SH" container exec -d --preserve-fds 1 px true 2>&1 3< /dev/null)
    check "a detached command" 125 $?
    "$SH" container exec --preserve-fds 1 px sh -c 'exit 9' 3< /dev/null
    check "the exit status" 9 $?

    id_of px > "$WORKDIR/px.cid"
    out=$(sh_ container exec --cidfile "$WORKDIR/px.cid" echo by-cidfile 2>&1)
    check "--cidfile names the container, the arguments are the command" "by-cidfile" "$out"
    out=$(sh_ container exec --cidfile "$WORKDIR/nosuch.cid" echo x 2>&1)
    check "a cidfile that is not there" 125 $?
    check_match "says podman's words" "reading CIDFile" "$out"

    out=$(sh_ container exec --no-session px sh -c 'echo out; echo err >&2; exit 4' 2>&1)
    check "--no-session: the exit status" 4 $?
    check "--no-session: the output" "out
err" "$(echo "$out" | sort -r)"
    check "no exec session was kept" "" "$(sh_ container inspect -f '{{.ExecIDs}}' px | tr -d '[]')"
    sh_ container rm -f -t 0 px > /dev/null
}

@test "update: --env, --unsetenv, and the flags that are gone with cgroup v1" {
    sh_ container run -d --name ux -e KEEP=1 -e DROP=2 -e CHANGE=old --network none "$IMAGE" sleep 300 > /dev/null
    out=$(sh_ container update --env CHANGE=new --env ADDED=3 --unsetenv DROP ux 2>&1)
    check "update prints the ID" "$(id_of ux)" "$out"
    env_now=$(sh_ container inspect -f '{{range .Config.Env}}{{.}}
{{end}}' ux)
    check_match "inspect shows the new variable" "^ADDED=3$" "$env_now"
    check_match "and the changed one" "^CHANGE=new$" "$env_now"
    check "and not the unset one" 0 "$(echo "$env_now" | grep -c '^DROP=')"
    check "the running process keeps its environment" "old" "$(sh_ container exec ux sh -c 'echo $CHANGE')"
    sh_ container restart -t 0 ux > /dev/null
    check "the next start has the new environment" "KEEP=1 CHANGE=new ADDED=3 DROP=" \
        "$(sh_ container exec ux sh -c 'echo KEEP=$KEEP CHANGE=$CHANGE ADDED=$ADDED DROP=$DROP')"
    for flag in "--memory-swappiness 30" "--cpu-rt-runtime 1000" "--cpu-rt-period 1000"; do
        # shellcheck disable=SC2086
        out=$(sh_ container update $flag ux 2>&1)
        check "update ${flag%% *} is an unknown flag" 125 $?
        check_match "and says so" "(unknown flag: |unexpected argument ')${flag%% *}" "$out"
    done
    sh_ container rm -f -t 0 ux > /dev/null
}

@test "--memory-swappiness and --cpu-rt-* are gone, --blkio-weight-device, --rdt-class" {
    for flag in --memory-swappiness=30 --memory-swappiness=-1 --cpu-rt-period=10000 --cpu-rt-runtime=1000; do
        out=$(sh_ container run --rm "$flag" "$IMAGE" true 2>&1)
        check "run $flag is an unknown flag" 125 $?
        check_match "and says so" "(unknown flag: |unexpected argument ')${flag%%=*}" "$out"
    done

    out=$(sh_ container run --rm --blkio-weight-device /dev/null:100 "$IMAGE" true 2>&1)
    check "a device that is no block device" 125 $?
    check_match "is named" "/dev/null: not a block device" "$out"
    out=$(sh_ container run --rm --blkio-weight-device /dev/sda "$IMAGE" true 2>&1)
    check_match "no weight" "invalid weight device" "$out"

    sh_ container create --name rdt --rdt-class gold "$IMAGE" true > /dev/null
    check "--rdt-class: the class of service is in the spec" "{'closID': 'gold'}" "$(spec_of rdt "d['linux']['intelRdt']")"
    sh_ container rm rdt > /dev/null
    sh_ container create --name rdt "$IMAGE" true > /dev/null
    check "and only there" "None" "$(spec_of rdt "d['linux'].get('intelRdt')")"
    sh_ container rm rdt > /dev/null
}

@test "--seccomp-policy" {
    python3 -I - "$WORKDIR" "$IMAGE" << 'EOT'
import json, os, sys
work, image = sys.argv[1:3]
profile = {"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
    {"names": ["mkdir", "mkdirat"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]}
os.makedirs(work + "/sctx", exist_ok=True)
open(work + "/sctx/Containerfile", "w").write(
    "FROM %s\nLABEL io.containers.seccomp.profile='%s'\n" % (image, json.dumps(profile, separators=(",", ":"))))
EOT
    sh_ image build -q -t localhost/e2e-seccomp:1 "$WORKDIR/sctx" > /dev/null 2>&1
    check "build an image with a seccomp profile" 0 $?
    out=$(sh_ container run --rm --seccomp-policy image localhost/e2e-seccomp:1 mkdir /made 2>&1)
    check "image: the profile of the label forbids mkdir" 1 $?
    check_match "with the profile's errno" "Operation not permitted" "$out"
    sh_ container run --rm --seccomp-policy default localhost/e2e-seccomp:1 mkdir /made > /dev/null 2>&1
    check "default: the label is not used" 0 $?
    sh_ container run --rm localhost/e2e-seccomp:1 mkdir /made > /dev/null 2>&1
    check "and neither without the option" 0 $?
    out=$(sh_ container run --rm --seccomp-policy image "$IMAGE" true 2>&1)
    check "image: an image without the label" 125 $?
    check_match "is refused as podman does" "no seccomp policy defined by image" "$out"
    out=$(sh_ container run --rm --seccomp-policy bogus "$IMAGE" true 2>&1)
    check_match "a policy that does not exist" 'invalid seccomp policy "bogus"' "$out"
    sh_ rmi localhost/e2e-seccomp:1 > /dev/null 2>&1
    # the label is the profile itself: not a file of the engine, not unconfined
    for label in unconfined /etc/passwd; do
        printf 'FROM %s\nLABEL io.containers.seccomp.profile=%s\n' "$IMAGE" "$label" > "$WORKDIR/sctx/Containerfile"
        sh_ image build -q -t localhost/e2e-seccomp:2 "$WORKDIR/sctx" > /dev/null 2>&1
        out=$(sh_ container run --rm --seccomp-policy image localhost/e2e-seccomp:2 true 2>&1)
        check "image: the label $label" 125 $?
        check_match "is not a profile" "not a JSON profile" "$out"
    done
    sh_ rmi localhost/e2e-seccomp:2 > /dev/null 2>&1
}

@test "logs --color, stats --interval --no-reset --no-trunc" {
    sh_ container run -d --name lc1 --network none "$IMAGE" sh -c 'echo one; echo two' > /dev/null
    sh_ container run -d --name lc2 --network none "$IMAGE" sh -c 'echo three' > /dev/null
    sh_ container wait lc1 lc2 > /dev/null
    esc=$(printf '\033')
    out=$(sh_ container logs --color lc1)
    check "one container is in the first color" "${esc}[37mone${esc}[0m
${esc}[37mtwo${esc}[0m" "$out"
    out=$(sh_ container logs --color -n lc1 lc2 | sort)
    check "each container has a color of its own, with its name" "${esc}[31mlc2 three${esc}[0m
${esc}[37mlc1 one${esc}[0m
${esc}[37mlc1 two${esc}[0m" "$out"
    check "without --color there is none" "one
two" "$(sh_ container logs lc1)"
    sh_ container rm -t 0 -f lc1 lc2 > /dev/null

    sh_ container run -d --name st --network none "$IMAGE" sleep 300 > /dev/null
    full=$(id_of st)
    out=$(sh_ container stats --no-stream --no-trunc st 2>&1)
    check_match "--no-trunc: the whole ID" "$full" "$out"
    out=$(sh_ container stats --no-stream st 2>&1)
    check "the ID is cut by default" 0 "$(echo "$out" | grep -c "$full")"
    out=$(timeout 4 "$SH" container stats --interval 1 st 2>&1)
    check_match "streaming: the screen is cleared" "${esc}\\[2J" "$out"
    out=$(timeout 5 "$SH" container stats --interval 1 --no-reset st 2>&1)
    check "--no-reset: it is not" 0 "$(echo "$out" | grep -c "${esc}\\[2J")"
    check_match "and the reports go on" "MEM USAGE / LIMIT" "$out"
    check "every second, not every five: several reports" 1 "$(( $(echo "$out" | grep -c "MEM USAGE / LIMIT") >= 2 ))"
    sh_ container rm -f -t 0 st > /dev/null
}

@test "--format: podman's fields of stats, ps, inspect --size, images, networks, volumes, secrets" {
    sh_ container run -d --name ff --label a=b --expose 9000-9002 --network none "$IMAGE" sleep 300 > /dev/null
    full=$(id_of ff)
    out=$(sh_ stats --no-stream --format '{{.Name}} {{.ContainerID}} {{.CPUPerc}} {{.PIDS}} {{.ContainerStats.Name}}' ff)
    check_match "stats: podman's fields" "^ff $full [0-9.]+% [0-9]+ ff$" "$out"
    out=$(sh_ stats --no-stream --format '{{.MemUsage}}|{{.MemUsageBytes}}|{{.NetIO}}|{{.BlockIO}}|{{.UpTime}}|{{.AVGCPU}}' ff)
    check_match "stats: the sizes, the CPU time and the average" "^[0-9.]+[kMG]?B / [0-9.]+[kMG]?B\|[0-9.]+[KMG]?i?B / [0-9.]+[KMG]?iB\|[^|]+ / [^|]+\|[^|]+ / [^|]+\|[0-9.]+(ns|µs|ms|s)\|[0-9.]+%$" "$out"
    out=$(sh_ stats --no-stream --format json ff)
    check "stats --format json: podman's keys" "avg_cpu block_io cpu_percent cpu_time id mem_percent mem_usage name net_io pids" \
        "$(echo "$out" | python3 -I -c 'import json, sys; print(" ".join(sorted(json.load(sys.stdin)[0])))')"
    check "ps: the labels are a map" "b map[a:b]" "$(sh_ ps --filter name=ff --format '{{index .Labels "a"}} {{.Labels}}')"
    check "ps: the exposed ports" "9000-9002/tcp map[9000:[tcp] 9001:[tcp] 9002:[tcp]]" \
        "$(sh_ ps --filter name=ff --format '{{.Ports}} {{.ExposedPorts}}')"
    check_match "ps --size: .Size" "^[0-9.]+[kMG]?B \(virtual [0-9.]+[kMG]?B\)$" "$(sh_ ps --size --filter name=ff --format '{{.Size}}')"
    check "inspect: no sizes without --size" "<nil> 0" "$(sh_ container inspect --format '{{.SizeRw}} {{.SizeRootFs}}' ff)"
    out=$(sh_ container inspect --size --format '{{.SizeRw}} {{.SizeRootFs}}' ff)
    check_match "inspect --size: the sizes, the image's in SizeRootFs" "^[0-9]+ [1-9][0-9]+$" "$out"
    check_match "inspect: the command line that made it" "run -d --name ff" "$(sh_ inspect --format '{{.Config.CreateCommand}}' ff)"
    check "inspect: podman's HostConfig keys" "0 0 false []" \
        "$(sh_ inspect --format '{{.HostConfig.CpuPeriod}} {{.HostConfig.MemorySwappiness}} {{.HostConfig.OomKillDisable}} {{.HostConfig.Devices}}' ff)"
    check "images: podman's fields" "false false" "$(sh_ images --format '{{.IsDangling}} {{.IsReadOnly}}' "$IMAGE")"
    check_match "images: .CreatedTime" "^[0-9-]+ [0-9:]+ \+0000 UTC$" "$(sh_ images --format '{{.CreatedTime}}' "$IMAGE")"
    check "image inspect: no check is a nil pointer" "<nil>" "$(sh_ image inspect --format '{{.HealthCheck}}' "$IMAGE")"
    sh_ network create ffn > /dev/null
    check "network ls: podman's fields" "true false []" \
        "$(sh_ network ls --filter name=ffn --format '{{.DNSEnabled}} {{.IPv6Enabled}} {{.Routes}}')"
    check "network inspect: .Network" "ffn" "$(sh_ network inspect --format '{{.Network.Name}}' ffn)"
    sh_ volume create ffv > /dev/null
    check "volume ls: podman's fields" "map[] 0 ffv" \
        "$(sh_ volume ls --filter name=ffv --format '{{.Status}} {{.Timeout}} {{.InspectVolumeData.Name}}')"
    printf x | sh_ secret create ffs - > /dev/null
    out=$(sh_ secret inspect --pretty ffs)
    check_match "secret inspect --pretty" "^ID: +[0-9a-f]+
Name: +ffs
Driver: +file
Created at: +[0-9-]+ [0-9:.]+ [+-][0-9]{4} " "$out"
    check "template functions of Go" "[ ff ] f true 1 2 a+b" \
        "$(sh_ ps --filter name=ff --format '[{{pad .Names 1 1}}] {{slice .Names 0 1}} {{lt 1 2}} {{print 1 2}} {{urlquery "a b"}}')"
    run "$SH" image diff --format yaml "$IMAGE"
    check "image diff --format: json only" "125 Error: only supported value for '--format' is 'json'" "$status $output"
    check_match "image diff --format json" '"added"' "$(sh_ image diff --format json "$IMAGE")"
    sh_ secret rm ffs > /dev/null
    sh_ volume rm ffv > /dev/null
    sh_ network rm ffn > /dev/null
    sh_ container rm -f -t 0 ff > /dev/null
}

@test "options taken for podman's sake: --disable-content-trust, exists --external; --decryption-key is refused" {
    out=$(sh_ container run --rm --disable-content-trust "$IMAGE" echo ok 2>&1)
    check "--disable-content-trust has no effect" "ok" "$out"
    out=$(sh_ container run --rm --decryption-key key.pem "$IMAGE" true 2>&1)
    check "--decryption-key is refused" 125 $?
    check_match "and says why" "velarx pulls no encrypted image" "$out"
    out=$(sh_ container create --init-ctr once "$IMAGE" true 2>&1)
    check "--init-ctr needs a pod" 125 $?
    check_match "and says so" "must specify pod value with init-ctr" "$out"
    sh_ container create --name ex "$IMAGE" true > /dev/null
    sh_ container exists --external ex
    check "exists --external" 0 $?
    sh_ container exists --external nosuch
    check "exists --external of nothing" 1 $?
    sh_ container rm ex > /dev/null
}

@test "root: --blkio-weight-device sets the weight of the device" {
    skip_unless_root
    # (the weights of the devices are the bfq scheduler's: the null_blk test
    # device gets it for the test, and its own back in the teardown)
    dev=/dev/nullb0
    [ -b "$dev" ] || skip "no $dev"
    skip_unless_host_changes "the I/O scheduler of $dev"
    old=$(sed -n 's/.*\[\(.*\)\].*/\1/p' /sys/block/nullb0/queue/scheduler)
    SCHED_RESTORE=${old:-none}
    echo bfq > /sys/block/nullb0/queue/scheduler 2> /dev/null || skip "no bfq scheduler"
    sh_ container run -d --name bw --blkio-weight-device "$dev:300" --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    rc=$?
    cg=$(awk -F: '{ print $3 }' "/proc/$(inspect_of bw pid)/cgroup" 2> /dev/null)
    w=$(cat "/sys/fs/cgroup$cg/io.bfq.weight" 2> /dev/null)
    sh_ container rm -f -t 0 bw > /dev/null 2>&1
    check "run with a weight for $dev" 0 $rc
    mm=$(stat -c '%t %T' "$dev" | awk '{ printf "%d:%d", strtonum("0x" $1), strtonum("0x" $2) }')
    check_match "the cgroup has the weight of the device" "^$mm 300$" "$w"
}

@test "named and anonymous volumes are mounted nosuid and nodev, as podman's" {
    sh_ volume create hv > /dev/null
    opts () { sh_ container run --rm "$@" "$IMAGE" sh -c 'while read -r _ _ _ _ mp o _; do [ "$mp" = /data ] && echo "$o"; done < /proc/self/mountinfo' 2>&1; }
    check_match "-v NAME:/data" "nosuid" "$(opts -v hv:/data)"
    check_match "-v NAME:/data: nodev" "nodev" "$(opts -v hv:/data)"
    check_match "--mount type=volume" "nosuid,nodev|nodev,nosuid|nosuid.*nodev" "$(opts --mount type=volume,source=hv,destination=/data)"
    check_match "anonymous volume" "nosuid.*nodev|nodev.*nosuid" "$(opts -v /data)"
    out=$(opts -v hv:/data:suid,dev)
    check "suid,dev ask for them" 0 "$(echo "$out" | grep -c 'nosuid\|nodev')"
    mkdir -p "$WORKDIR/bindsrc"
    check "a bind mount keeps what its host file system has" 0 "$(opts -v "$WORKDIR/bindsrc:/data" | grep -c nodev)"
    sh_ volume rm hv > /dev/null
}

@test "rootless --network host: /sys/kernel is masked; --privileged binds no ptmx and no console" {
    skip_if_root
    # (what the runtime masks with is empty or cannot be read: either way nothing is listed)
    check "nothing is listed in /sys/kernel" 0 "$(sh_ container run --rm --network host "$IMAGE" sh -c 'ls -A /sys/kernel 2> /dev/null | wc -l' 2>&1)"
    check "unmask does not put it back" 0 "$(sh_ container run --rm --network host --security-opt unmask=/sys/kernel "$IMAGE" sh -c 'ls -A /sys/kernel 2> /dev/null | wc -l' 2>&1)"
    check "a privileged one has it" "yes" "$(sh_ container run --rm --network host --privileged "$IMAGE" sh -c 'test -n "$(ls -A /sys/kernel)" && echo yes' 2>&1)"
    check "a privileged one gets the host's /sys, writable" "rw" "$(sh_ container run --rm --network host --privileged "$IMAGE" sh -c 'awk "\$5 == \"/sys\" { split(\$6, o, \",\"); print o[1] }" /proc/self/mountinfo' 2>&1)"
    check "the host ptmx is not bound" "pts/ptmx" "$(sh_ container run --rm --privileged "$IMAGE" readlink /dev/ptmx 2>&1)"
    check "no virtual console" 0 "$(sh_ container run --rm --privileged "$IMAGE" sh -c 'ls /dev/tty[0-9]* 2> /dev/null | wc -l' 2>&1)"
}

@test "--security-opt label=nested and --network slirp4netns are refused by name" {
    out=$(sh_ container run --rm --security-opt label=nested "$IMAGE" true 2>&1)
    check "label=nested" 125 $?
    check_match "label=nested says what" "label=nested is not supported" "$out"
    for mode in slirp4netns slirp4netns:allow_host_loopback=true; do
        out=$(sh_ container run --rm --network "$mode" "$IMAGE" true 2>&1)
        check "--network $mode" 125 $?
        check_match "and says to use pasta" "slirp4netns is not supported: use pasta" "$out"
    done
}

@test "--restart is checked, --mount type=devpts works, export prints nothing, top shows the host ids and Go's times" {
    for bad in foo alwasy unless_stopped always:3 on-failure:abc on-failure:-1; do
        sh_ container create --restart "$bad" "$IMAGE" true > /dev/null 2>&1
        check "--restart $bad is refused" 125 $?
    done
    out=$(sh_ container create --name rs --restart on-failure:3 "$IMAGE" true 2>&1)
    check "on-failure:3" 0 $?
    check "recorded" "on-failure 3" "$(sh_ container inspect -f '{{.HostConfig.RestartPolicy.Name}} {{.HostConfig.RestartPolicy.MaximumRetryCount}}' rs)"
    sh_ container rm rs > /dev/null
    check "--restart never is no" "no" "$(sh_ container create --name rn --restart never "$IMAGE" true > /dev/null; sh_ container inspect -f '{{.HostConfig.RestartPolicy.Name}}' rn; sh_ container rm rn > /dev/null)"
    out=$(sh_ container run --rm --mount type=devpts,destination=/dev/pts2,ptmxmode=666 "$IMAGE" sh -c 'grep -c " /dev/pts2 .* - devpts " /proc/self/mountinfo' 2>&1)
    check "a devpts mount" 1 "$out"
    out=$(sh_ container run --rm "$IMAGE" sh -c 'm=$(awk "\$1 <= 5 && 5 < \$1 + \$3 { print \"mapped\" }" /proc/self/gid_map); o=$(grep " /dev/pts .* - devpts " /proc/self/mountinfo); case "$o" in *,gid=*) echo "gid5-$m" ;; *) echo "nogid5-$m" ;; esac' 2>&1)
    case "$out" in
    gid5-mapped | nogid5-) ;;
    *) echo "FAIL /dev/pts has gid=5 where the namespace maps it, and only there: $out" >&2; exit 1 ;;
    esac
    sh_ container run -d --name ex1 "$IMAGE" sleep 300 > /dev/null
    sh_ container export ex1 > "$WORKDIR/ex1.tar" 2> "$WORKDIR/ex1.err"
    check "export: the archive" 0 $?
    check "export: nothing on stderr" "" "$(cat "$WORKDIR/ex1.err")"
    check_match "export: a tar" "bin/" "$(tar tf "$WORKDIR/ex1.tar" | head -50)"
    sh_ container export -o "$WORKDIR/ex2.tar" ex1 2> "$WORKDIR/ex2.err"
    check "export -o: nothing on stderr" "" "$(cat "$WORKDIR/ex2.err")"
    out=$(sh_ container top ex1 user huser group hgroup etime time 2>&1)
    check_match "top: titles" "^USER[[:space:]]+HUSER[[:space:]]+GROUP[[:space:]]+HGROUP[[:space:]]+ELAPSED[[:space:]]+TIME" "$out"
    row=$(echo "$out" | sed -n 2p)
    # (psgo names the host id by the passwd file of the container: the
    # user of a rootless engine has no name there, root has)
    if [ "$(id -u)" = 0 ]; then want=root; else want=$(id -u); fi
    check "top: the host user of root is the user of the engine" "$want" "$(echo "$row" | awk '{print $2}')"
    check_match "top: Go's elapsed time" "[0-9]+(\.[0-9]+)?(ms|s|m[0-9.]+s)" "$(echo "$row" | awk '{print $5}')"
    sh_ container rm -f -t 0 ex1 > /dev/null
}

@test "logs --since and --until take podman's date forms" {
    sh_ container run --name lg "$IMAGE" echo logged > /dev/null
    check "--since a date" "logged" "$(sh_ container logs --since 2020-01-01 lg)"
    check "--since a date and time" "logged" "$(sh_ container logs --since 2020-01-01T10:00:00 lg)"
    check "--since a date with a zone" "logged" "$(sh_ container logs --since 2020-01-01+01:00 lg)"
    check "--until a date in the future" "logged" "$(sh_ container logs --until 2200-01-01 lg)"
    check "--until a date in the past" "" "$(sh_ container logs --until 2020-01-01 lg)"
    sh_ container rm lg > /dev/null
}

@test "--memory alone allows as much swap as memory, the default pids limit is 2048" {
    out=$(sh_ container run --rm --memory 3m "$IMAGE" cat /sys/fs/cgroup/memory.swap.max 2>&1)
    [ "$out" != "max" ] || {
        echo "FAIL --memory alone leaves swap unlimited: $out" >&2
        exit 1
    }
    case "$out" in *"No such file"*) skip "no memory controller for this user" ;; esac
    check "swap = memory (podman's)" 3145728 "$out"
    check "--memory-swap still wins" 6291456 "$(sh_ container run --rm --memory 3m --memory-swap 9m "$IMAGE" cat /sys/fs/cgroup/memory.swap.max 2>&1)"
    out=$(sh_ container run --rm "$IMAGE" cat /sys/fs/cgroup/pids.max 2>&1)
    case "$out" in *"No such file"*) skip "no pids controller for this user" ;; esac
    check "the default pids limit" 2048 "$out"
    check "--pids-limit=-1 is unlimited" max "$(sh_ container run --rm --pids-limit=-1 "$IMAGE" cat /sys/fs/cgroup/pids.max 2>&1)"
    check "--pids-limit=77" 77 "$(sh_ container run --rm --pids-limit=77 "$IMAGE" cat /sys/fs/cgroup/pids.max 2>&1)"
    sh_ container create --name pl "$IMAGE" true > /dev/null
    check "inspect shows the default" 2048 "$(sh_ container inspect -f '{{.HostConfig.PidsLimit}}' pl)"
    sh_ container rm pl > /dev/null
    out=$(sh_ container run --rm --cgroups=disabled "$IMAGE" true 2>&1)
    check "--cgroups=disabled has no default limit to refuse" 0 $?
}

@test "inspect: capabilities, labels, ulimits, annotations and the cgroup manager of what runs" {
    sh_ container create --name ins --rm --init "$IMAGE" sleep 300 > /dev/null
    check_match "EffectiveCaps" "CAP_CHOWN" "$(sh_ container inspect -f '{{.EffectiveCaps}}' ins)"
    check_match "BoundingCaps" "CAP_KILL" "$(sh_ container inspect -f '{{.BoundingCaps}}' ins)"
    caps=$(sh_ container inspect -f '{{json .EffectiveCaps}}' ins)
    check "the capabilities are sorted, as podman's" "$caps" "$(echo "$caps" | python3 -I -c 'import json, sys; print(json.dumps(sorted(json.load(sys.stdin)), separators=(",", ":")))')"
    check_match "Ulimits" "RLIMIT_NOFILE" "$(sh_ container inspect -f '{{json .HostConfig.Ulimits}}' ins)"
    check_match "the annotations podman records" '"io.podman.annotations.autoremove":"TRUE"' \
        "$(sh_ container inspect -f '{{json .Config.Annotations}}' ins)"
    check_match "and init" '"io.podman.annotations.init":"TRUE"' "$(sh_ container inspect -f '{{json .Config.Annotations}}' ins)"
    sh_ container rm -f -t 0 ins > /dev/null
    sh_ container create --name ins2 --cap-drop ALL --security-opt label=disable "$IMAGE" true > /dev/null
    check "no capability: EffectiveCaps" "[]" "$(sh_ container inspect -f '{{.EffectiveCaps}}' ins2)"
    check "SecurityOpt shows the label option (podman's)" "[label=disable]" "$(sh_ container inspect -f '{{.HostConfig.SecurityOpt}}' ins2)"
    check_match "and the annotation" '"io.podman.annotations.label":"disable"' "$(sh_ container inspect -f '{{json .Config.Annotations}}' ins2)"
    sh_ container rm ins2 > /dev/null
    sh_ container run -d --name ins3 "$IMAGE" sleep 300 > /dev/null
    cg=$(cat "/proc/$(inspect_of ins3 pid)/cgroup")
    mgr=$(sh_ container inspect -f '{{.HostConfig.CgroupManager}}' ins3)
    case "$cg" in
    *.scope*) check "in a systemd scope: the cgroup manager" systemd "$mgr" ;;
    *) check "not in a scope: the cgroup manager" cgroupfs "$mgr" ;;
    esac
    if command -v selinuxenabled > /dev/null && selinuxenabled; then
        want=$(sh_ container exec ins3 cat /proc/1/attr/current | tr -d '\0')
        check "ProcessLabel is the label of the process" "$want" "$(sh_ container inspect -f '{{.ProcessLabel}}' ins3)"
        check_match "MountLabel" "container_file_t" "$(sh_ container inspect -f '{{.MountLabel}}' ins3)"
    fi
    sh_ container rm -f -t 0 ins3 > /dev/null
}

@test "--cidfile goes with the container" {
    f=$WORKDIR/cid1
    sh_ container create --name cid --cidfile "$f" "$IMAGE" true > /dev/null
    check "the cidfile has the id" "$(id_of cid)" "$(cat "$f")"
    check_match "the annotation of podman" "io.podman.annotations.cid-file" "$(sh_ container inspect -f '{{json .Config.Annotations}}' cid)"
    check "inspect: ContainerIDFile" "$f" "$(sh_ container inspect -f '{{.HostConfig.ContainerIDFile}}' cid)"
    sh_ container rm cid > /dev/null
    check "rm removes the cidfile" "no" "$([ -e "$f" ] && echo yes || echo no)"
    sh_ container run --rm --cidfile "$f" "$IMAGE" true > /dev/null
    check "--rm removes it too" "no" "$([ -e "$f" ] && echo yes || echo no)"
    sh_ container create --name cid2 --cidfile "$f" "$IMAGE" true > /dev/null
    echo other > "$f"
    sh_ container rm cid2 > /dev/null
    check "rm removes it when it changed, as podman's" "no" "$([ -e "$f" ] && echo yes || echo no)"
    sh_ container create --cidfile "$f" "$WORKDIR/no/such/image" true > /dev/null 2>&1
    check "a failed create writes none" "no" "$([ -e "$f" ] && echo yes || echo no)"
}

@test "--add-host: host-gateway, several names, values are checked, it overrides the generated entries" {
    out=$(sh_ container run --rm --network none --add-host 'a;b:10.0.0.3' --add-host gw:host-gateway \
        --add-host host.containers.internal:10.1.1.1 "$IMAGE" cat /etc/hosts 2>&1)
    check_match "several names on one line" "^10\.0\.0\.3[[:space:]]+a b$" "$out"
    check_match "host-gateway is the address of the host" "^[0-9a-f.:]+[[:space:]]+gw$" "$out"
    check "host-gateway is not written as a word" 0 "$(echo "$out" | grep -c host-gateway)"
    first=$(echo "$out" | awk '$2 == "host.containers.internal" { print $1; exit }')
    check "an entry before the generated one wins" 10.1.1.1 "$first"
    out=$(sh_ container run --rm --network none --hostname hh --add-host hh:10.0.0.9 "$IMAGE" cat /etc/hosts 2>&1)
    check "a name given by --add-host is not on the loopback too" 0 "$(echo "$out" | grep -c '^127\.0\.0\.1.*hh')"
    for bad in bad:notanip baz=10.0.0.2 :1.1.1.1 x:; do
        out=$(sh_ container run --rm --network none --add-host "$bad" "$IMAGE" true 2>&1)
        check "--add-host $bad is refused" 125 $?
    done
    check_match "and says what" "invalid IP address in add-host" \
        "$(sh_ container run --rm --network none --add-host bad:notanip "$IMAGE" true 2>&1)"
}

@test "/etc/hosts: the host's /etc/hosts is the base, a pasta container has its own address and name" {
    hostline=$(grep -v '^[[:space:]]*#' /etc/hosts | grep -v '^[[:space:]]*$' | awk 'NF > 1 && $1 != "::1" { print; exit }')
    first=$(echo "$hostline" | awk '{ print $1 "\t" $2 }')
    out=$(sh_ container run --rm --network none "$IMAGE" cat /etc/hosts 2>&1)
    check "the first host entry is the first line" "$first" "$(echo "$out" | head -1 | awk '{ print $1 "\t" $2 }')"
    sh_ container run --rm --network none --read-only "$IMAGE" sh -c 'echo x >> /etc/hosts' > /dev/null 2>&1
    check "--read-only: /etc/hosts is read-only too (podman's)" 1 $?
    out=$(sh_ container run --rm --network none --name hnn --hostname hh "$IMAGE" cat /etc/hosts 2>&1)
    check_match "no network: the host name and the name on the loopback" "^127\.0\.0\.1[[:space:]]+(localhost )?.*hh hnn$|^127\.0\.0\.1[[:space:]]+hh hnn$" "$out"
    [ "$(id -u)" != 0 ] || return 0
    command -v pasta > /dev/null || return 0
    out=$(sh_ container run --rm --network pasta --name hnp --hostname hp "$IMAGE" cat /etc/hosts 2>&1)
    check_match "pasta: the name on the address of the container, not the loopback" "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+hp hnp$" "$out"
    check "and not on the loopback" 0 "$(echo "$out" | grep -c '^127\.0\.0\.1.*hnp')"
}

@test "--network host: the hostname of the host, host.containers.internal, --dns and --dns-search" {
    check "the host's hostname" "$(cat /proc/sys/kernel/hostname)" "$(sh_ container run --rm --network host "$IMAGE" hostname 2>&1)"
    check "an explicit --hostname wins" "mine" "$(sh_ container run --rm --network host --hostname mine "$IMAGE" hostname 2>&1)"
    check_match "host.containers.internal is in /etc/hosts" "host.containers.internal" \
        "$(sh_ container run --rm --network host "$IMAGE" cat /etc/hosts 2>&1)"
    out=$(sh_ container run --rm --network host --dns 192.0.2.53 --dns-search corp.test --dns-option ndots:2 "$IMAGE" cat /etc/resolv.conf 2>&1)
    check "--dns reaches a host network container" "search corp.test
nameserver 192.0.2.53
options ndots:2" "$out"
    out=$(sh_ container run --rm --network host "$IMAGE" cat /etc/resolv.conf 2>&1)
    check "the host's resolv.conf is rebuilt, its comments are not copied (podman's)" 0 "$(echo "$out" | grep -c '^#')"
    check "with the host's servers" "$(grep -E '^[[:space:]]*nameserver' /etc/resolv.conf | awk '{ print $1, $2 }')" \
        "$(echo "$out" | grep '^nameserver')"
    out=$(sh_ container run --rm --network host --dns 192.0.2.53 "$IMAGE" cat /etc/resolv.conf 2>&1)
    check "the host's options stay" "$(grep -E '^options' /etc/resolv.conf)" "$(echo "$out" | grep -E '^options')"
    check_match "and the server is the given one" "^nameserver 192.0.2.53$" "$out"
}

@test "resolv.conf: --dns-search . is no search, a pasta container keeps the host's servers, search and options" {
    out=$(sh_ container run --rm --dns 192.0.2.53 --dns-search . "$IMAGE" cat /etc/resolv.conf 2>&1)
    check "--dns-search . writes no search line" 0 "$(echo "$out" | grep -c '^search')"
    command -v pasta > /dev/null || return 0
    [ "$(id -u)" != 0 ] || return 0
    out=$(sh_ container run --rm --network pasta "$IMAGE" cat /etc/resolv.conf 2>&1)
    check "pasta: the forwarder is first" "nameserver 169.254.1.1" "$(echo "$out" | grep -m1 '^nameserver')"
    hostsearch=$(sed -n 's/^search//p' /etc/resolv.conf | tail -1 | tr ' ' '\n' | grep -v '^\.\?$' | tr '\n' ' ')
    check "pasta: the host's search domains" "$hostsearch" "$(echo "$out" | sed -n 's/^search//p' | tr ' ' '\n' | grep -v '^\.\?$' | tr '\n' ' ')"
    check_match "pasta: and a server after the forwarder" "^nameserver [0-9a-f.:]+$" "$(echo "$out" | grep '^nameserver' | sed -n 2p)"
}
