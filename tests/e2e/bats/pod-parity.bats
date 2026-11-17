# SPDX-License-Identifier: Apache-2.0
# The options, fields and commands of `pod` that podman has and velarx got for
# parity: each has its effect on the pods and their containers.  Run it
# as an ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

teardown () {
    sh_ pod rm -t 0 -af > /dev/null 2>&1
    run_test_teardown
}

# pod_state NAME: the state podman's inspect gives
pod_state () { sh_ pod inspect --format '{{.State}}' "$1"; }

# running_pod NAME...: pods with a member that sleeps, started
running_pod () {
    local p
    for p in "$@"; do
        sh_ pod create --network none --name "$p" > /dev/null || e2e_die "pod create $p"
        sh_ container run -d --pod "$p" --name "$p-c" "$IMAGE" sleep 300 > /dev/null || e2e_die "run in $p"
    done
}

@test "the lifecycle commands of pods take --all" {
    running_pod pa pb
    out=$(sh_ pod stop -t 0 --all 2>&1)
    check "stop --all prints the two ids" 2 "$(echo "$out" | wc -l)"
    check "stopped the first" Exited "$(pod_state pa)"
    check "and the second" Exited "$(pod_state pb)"
    sh_ pod start -a > /dev/null 2>&1
    check "start --all" Running "$(pod_state pa)"
    check "starts the second too" Running "$(pod_state pb)"
    sh_ pod pause --all > /dev/null 2>&1
    check "pause --all" Paused "$(pod_state pa)"
    check "pause --all, the second" Paused "$(pod_state pb)"
    sh_ pod unpause -a > /dev/null 2>&1
    check "unpause --all" Running "$(pod_state pb)"
    before=$(sh_ container inspect -f '{{.State.StartedAt}}' pa-c)
    sh_ pod restart --all > /dev/null 2>&1
    check "restart --all" 0 $?
    [ "$before" != "$(sh_ container inspect -f '{{.State.StartedAt}}' pa-c)" ]
    check "restart --all started the containers again" 0 $?
    sh_ pod kill --all > /dev/null 2>&1
    check "kill --all" Exited "$(pod_state pa)"
    check "kill --all, the second" Exited "$(pod_state pb)"
    out=$(sh_ pod rm --all 2>&1)
    check "rm --all prints the two ids" 2 "$(echo "$out" | wc -l)"
    check "rm --all removed them" "" "$(sh_ pod ps -q)"
    sh_ pod start --all > /dev/null 2>&1
    check "--all with no pod is no error" 0 $?
}

@test "--latest acts on the pod made last" {
    running_pod la lb
    sh_ pod stop -t 0 --latest > /dev/null 2>&1
    check "stop --latest stopped the last pod" Exited "$(pod_state lb)"
    check "and not the first" Running "$(pod_state la)"
    sh_ pod start -l > /dev/null 2>&1
    check "start --latest" Running "$(pod_state lb)"
    sh_ pod pause -l > /dev/null 2>&1
    check "pause --latest" Paused "$(pod_state lb)"
    check "pause --latest leaves the first" Running "$(pod_state la)"
    sh_ pod unpause -l > /dev/null 2>&1
    check "unpause --latest" Running "$(pod_state lb)"
    sh_ pod kill -l > /dev/null 2>&1
    check "kill --latest" Exited "$(pod_state lb)"
    sh_ pod restart -l > /dev/null 2>&1
    check "restart --latest" Running "$(pod_state lb)"
    check "inspect --latest" "lb" "$(sh_ pod inspect -l --format '{{.Name}}')"
    check_match "top --latest lists the processes" "sleep 300" "$(sh_ pod top -l 2>&1)"
    sh_ pod rm -t 0 -f -l > /dev/null 2>&1
    check "rm --latest removed the last pod" "la" "$(sh_ pod ps --format '{{.Name}}')"
    out=$(sh_ pod start -a -l 2>&1)
    check "--all and --latest conflict" 125 $?
    check_match "and say so" "--all and --latest cannot be used together" "$out"
    out=$(sh_ pod start -l la 2>&1)
    check "--latest and a name conflict" 125 $?
    sh_ pod rm -t 0 -af > /dev/null 2>&1
    out=$(sh_ pod stop -l 2>&1)
    check "no pod, --latest" 125 $?
    check_match "says no such pod" "no such pod" "$out"
    sh_ pod rm -l > /dev/null 2>&1
    check "rm --latest of no pod is 1" 1 $?
}

@test "--pod-id-file of pod start, stop and rm" {
    running_pod ia ib
    sh_ pod inspect --format '{{.Id}}' ia > "$WORKDIR/ia.id"
    sh_ pod stop -t 0 --pod-id-file "$WORKDIR/ia.id" > /dev/null 2>&1
    check "stop --pod-id-file" Exited "$(pod_state ia)"
    check "and not the other pod" Running "$(pod_state ib)"
    sh_ pod start --pod-id-file "$WORKDIR/ia.id" > /dev/null 2>&1
    check "start --pod-id-file" Running "$(pod_state ia)"
    out=$(sh_ pod start --pod-id-file "$WORKDIR/nosuch" 2>&1)
    check "a missing file" 125 $?
    check_match "is said as podman does" "reading pod ID file: open .*nosuch: no such file or directory" "$out"
    sh_ pod rm -t 0 -f --pod-id-file "$WORKDIR/ia.id" > /dev/null 2>&1
    check "rm --pod-id-file" 0 $?
    check "removed the pod" 1 "$(sh_ pod exists ia; echo $?)"
    check "and the file" 1 "$([ -e "$WORKDIR/ia.id" ]; echo $?)"
    check "the other pod stays" Running "$(pod_state ib)"
    out=$(sh_ pod rm -t 3 ib 2>&1)
    check "--time needs --force" 125 $?
    check_match "and says so" "--force option must be specified to use the --time option" "$out"
    out=$(sh_ pod rm ib 2>&1)
    check "rm of a pod whose member runs, without --force" 125 $?
    check_match "says why, as podman" "cannot remove container [0-9a-f]+ as it is running" "$out"
    check "and leaves the pod" Running "$(pod_state ib)"
    check "and its member" running "$(sh_ container inspect --format '{{.State.Status}}' ib-c)"
    id=$(sh_ pod inspect --format '{{.Id}}' ib)
    check "a prefix of the ID names the pod" ib "$(sh_ pod inspect --format '{{.Name}}' "${id:0:12}")"
    check "pod ps -q has the whole IDs" "$id" "$(sh_ pod ps -q --filter name=ib)"
    check "kill prints the ID, as podman" "$id" "$(sh_ pod kill ib)"
    check "rm -f of a prefix of the ID prints the ID" "$id" "$(sh_ pod rm -t 0 -f "${id:0:12}")"
    check "and removes the pod" 1 "$(sh_ pod exists ib; echo $?)"
}

@test "pod ps: --sort, --ctr-ids, --ctr-names, --ctr-status, --ns, --latest and the container fields" {
    sh_ pod create --network none --name sa > /dev/null
    sh_ pod create --network none --name sb > /dev/null
    sh_ container create --pod sb --name sb1 "$IMAGE" sleep 300 > /dev/null
    sh_ container create --pod sb --name sb2 "$IMAGE" sleep 300 > /dev/null
    check "default: the newest first" "sb sa" "$(sh_ pod ps --format '{{.Name}}' | tr '\n' ' ' | sed 's/ $//')"
    check "--sort created" "sb sa" "$(sh_ pod ps --sort created --format '{{.Name}}' | tr '\n' ' ' | sed 's/ $//')"
    check "--sort name" "sa sb" "$(sh_ pod ps --sort name --format '{{.Name}}' | tr '\n' ' ' | sed 's/ $//')"
    check "--sort number" "sa sb" "$(sh_ pod ps --sort number --format '{{.Name}}' | tr '\n' ' ' | sed 's/ $//')"
    check "--sort id" "$(sh_ pod ps --format '{{.Id}}' | sort | tr '\n' ' ')" "$(sh_ pod ps --sort id --format '{{.Id}}' | tr '\n' ' ')"
    out=$(sh_ pod ps --sort bogus 2>&1)
    check "--sort of nothing" 125 $?
    check_match "says the choices" "invalid option for --sort, options are: created, id, name, number, or status" "$out"
    check "--latest" "sb" "$(sh_ pod ps --latest --format '{{.Name}}')"
    out=$(sh_ pod ps --ctr-names)
    check_match "--ctr-names has the column" "NAMES" "$out"
    sbid=$(sh_ pod inspect --format '{{.Id}}' sb)
    check_match "and the names" "${sbid:0:12}-infra,sb1,sb2" "$out"
    out=$(sh_ pod ps --ctr-ids --ctr-status --no-trunc)
    check_match "--ctr-ids has the column" "IDS" "$out"
    check_match "--ctr-status has the column" "STATUS" "$out"
    check_match "and the states" "created,created,created" "$out"
    infra=$(sh_ pod inspect --format '{{.InfraContainerID}}' sb)
    check_match "--no-trunc gives the whole ids" "$infra," "$(sh_ pod ps --ctr-ids --no-trunc)"
    check_match "--ns has the columns" "CGROUP +NAMESPACES" "$(sh_ pod ps --ns)"
    check "the fields" "sb1,sb2" "$(sh_ pod ps --filter name=sb --format '{{.ContainerNames}}' | sed 's/^[^,]*,//')"
    check "the statuses" "created,created,created" "$(sh_ pod ps --filter name=sb --format '{{.ContainerStatuses}}')"
    check "the ids are short" 12 "$(sh_ pod ps --filter name=sb --format '{{.ContainerIds}}' | cut -d, -f1 | wc -c | awk '{print $1 - 1}')"
    check "the restarts" 0 "$(sh_ pod ps --filter name=sb --format '{{.Restarts}}')"
    out=$(sh_ pod ps -q --format '{{.Name}}' 2>&1)
    check "--quiet and --format conflict" 125 $?
    check_match "and say so" "quiet and format cannot be used together" "$out"
    out=$(sh_ pod ps --filter name 2>&1)
    check "a filter without a value" 125 $?
    check_match "is said" "filter input must be in the form of filter=value: name is invalid" "$out"
}

@test "pod stats: --format, --no-stream, --latest, --all" {
    running_pod sta stb
    out=$(sh_ pod stats --no-stream)
    check_match "the header" "^POD +CID +NAME +CPU % +MEM USAGE/ LIMIT +MEM % +NET IO +BLOCK IO +PIDS" "$out"
    check_match "a row for the member" "sta-c" "$out"
    check_match "and for the other pod" "stb-c" "$out"
    staid=$(sh_ pod inspect --format '{{.Id}}' sta)
    stbid=$(sh_ pod inspect --format '{{.Id}}' stb)
    check_match "and the infra container" "${staid:0:12}-infra" "$out"
    check "--format" "${staid:0:12}-infra sta-c" "$(sh_ pod stats --no-stream --format '{{.Name}}' sta | tr '\n' ' ' | sed 's/ $//')"
    check_match "--format table has a header" "^NAME +CPU %" "$(sh_ pod stats --no-stream --format 'table {{.Name}}\t{{.CPU}}' sta)"
    pod=$(sh_ pod inspect --format '{{.Id}}' sta)
    check "the pod field is the short id" "${pod:0:12}" "$(sh_ pod stats --no-stream --format '{{.Pod}}' sta | sort -u)"
    check "the fields" "yes" "$(sh_ pod stats --no-stream --format '{{.CID}} {{.CPU}} {{.MemUsage}} {{.MemUsageBytes}} {{.Mem}} {{.NetIO}} {{.BlockIO}} {{.PIDS}}' sta | head -1 | grep -q 'no value' && echo no || echo yes)"
    check "json" "2" "$(sh_ pod stats --no-stream --format json sta | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(len(d)); assert d[0]["Pod"] and d[0]["CID"] and d[0]["Name"]')"
    check "--latest" "${stbid:0:12}-infra stb-c" "$(sh_ pod stats --no-stream --latest --format '{{.Name}}' | tr '\n' ' ' | sed 's/ $//')"
    check "--all" "4" "$(sh_ pod stats --no-stream -a --format '{{.Name}}' | wc -l)"
    out=$(sh_ pod stats -a -l 2>&1)
    check "--all and --latest conflict" 125 $?
    check_match "and say so" "--all, --latest and arguments cannot be used together" "$out"
    out=$(sh_ pod stats --no-stream nosuch 2>&1)
    check "a missing pod" 125 $?
    check_match "is said" "unable to get list of pods: no pod with name or ID nosuch found: no such pod" "$out"
    sh_ pod rm -t 0 -af > /dev/null
    out=$(sh_ pod stats --no-stream)
    check_match "no pods: a row of dashes" "^-- +-- +-- " "$out"
}

@test "pod top: the processes of the containers, descriptors" {
    running_pod tpa
    out=$(sh_ pod top tpa)
    check_match "the title row" "^USER +PID +PPID" "$out"
    check_match "the infra process" "pause|catatonit" "$out"
    check_match "and the member's" "sleep 300" "$out"
    out=$(sh_ pod top tpa pid comm)
    check_match "descriptors" "^PID +COMMAND" "$out"
    check_match "of the member" " sleep" "$out"
    out=$(sh_ pod top nosuch 2>&1)
    check "a missing pod" 125 $?
    check_match "is said" "no pod with name or ID nosuch found: no such pod" "$out"
    out=$(sh_ pod top 2>&1)
    check "no pod" 125 $?
    check_match "is said" "you must provide the name or id of a running pod" "$out"
    sh_ pod create --network none --name tpb > /dev/null
    check "a pod that does not run: nothing, as podman" "" "$(sh_ pod top tpb)"
}

@test "pod inspect without --format is podman's document" {
    sh_ pod create --network none --name ipa > /dev/null
    out=$(sh_ pod inspect ipa)
    check "an array" 1 "$(echo "$out" | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(len(d))')"
    check "its name" ipa "$(echo "$out" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["Name"])')"
    out=$(sh_ pod inspect ipa nosuch 2>&1)
    check "a missing pod fails" 125 $?
    check_match "and is said" "Error: no such pod nosuch" "$out"
    out=$(sh_ pod inspect 2>&1)
    check "no pod" 125 $?
    check "and says it as podman" "Error: no names or ids specified" "$out"
    out=$(sh_ pod inspect --latest ipa 2>&1)
    check "--latest and a pod" "Error: --latest and arguments cannot be used together" "$out"
    check "podman's nil lists and no empty labels" "None None None False False" \
        "$(sh_ pod inspect ipa | python3 -I -c 'import json,sys; d=json.load(sys.stdin)[0]; i=d["InfraConfig"]; print(i["DNSServer"], i["DNSSearch"], i["HostAdd"], "Labels" in d, "Namespace" in d)')"
    check "a template sees Go's zero values" "map[] [] []" \
        "$(sh_ pod inspect ipa --format '{{.Labels}} {{.InfraConfig.DNSServer}} {{.InfraConfig.HostAdd}}')"
    sh_ pod create --network none -l a=b --name ipb > /dev/null
    check "pod ps: the labels are a map" "map[a:b]" "$(sh_ pod ps --filter name=ipb --format '{{.Labels}}')"
    out=$(sh_ pod start nosuch 2>&1)
    check "a missing pod: podman's words" "Error: no pod with name or ID nosuch found: no such pod" "$out"
}

@test "pod create --device, --gpus: the infra container and the members have them" {
    # (no CDI device: a host with a spec of nvidia.com/gpu in /etc/cdi has them)
    mkdir -p "$WORKDIR/cdi"
    events_daemon "[containers]
cdi_spec_dirs = [\"$WORKDIR/cdi\"]"
    sh_ pod create --network none --device /dev/null:/dev/podnull --name dev1 > /dev/null
    check "pod create --device" 0 $?
    check "a member has the device" "1, 3" "$(sh_ container run --rm --pod dev1 "$IMAGE" sh -c 'ls -l /dev/podnull' | awk '{print $5 $6}' | sed 's/,/, /')"
    check "inspect has the device" "/dev/podnull" "$(sh_ pod inspect dev1 --format '{{range .Devices}}{{.path}}{{end}}')"
    out=$(sh_ pod create --network none --gpus all gpupod 2>&1)
    check "--gpus asks the CDI devices" 125 $?
    check_match "and says which" "nvidia.com/gpu=all" "$out"
    out=$(sh_ pod create --network none --device /dev/nosuch nodev 2>&1)
    check "a device that is not there" 125 $?
    events_daemon ""
}

@test "pod create --volumes-from, --volume: the members have the volumes" {
    sh_ volume create pvol > /dev/null
    sh_ container run -d --name vsrc --log-driver k8s-file -v pvol:/data "$IMAGE" sh -c 'echo shared > /data/f; echo ready; sleep 300' > /dev/null
    wait_log vsrc ready || e2e_die "vsrc did not write its file"
    sh_ pod create --network none --volumes-from vsrc:ro --name vf > /dev/null
    check "pod create --volumes-from" 0 $?
    check "a member sees the file" "shared" "$(sh_ container run --rm --pod vf "$IMAGE" cat /data/f)"
    sh_ container run --rm --pod vf "$IMAGE" sh -c 'echo x > /data/g' > /dev/null 2>&1
    check "and :ro is there" 1 $?
    check "inspect has the source container" "vsrc:ro" "$(sh_ pod inspect vf --format '{{.VolumesFrom}}' | tr -d '[]')"
    out=$(sh_ pod create --network none --volumes-from nosuchctr x 2>&1)
    check "a missing container" 125 $?
    check_match "is said" "looking up container \"nosuchctr\" for volumes-from" "$out"
    sh_ pod rm -t 0 -f vf > /dev/null
    sh_ container rm -t 0 -f vsrc > /dev/null
    sh_ volume rm pvol > /dev/null
}

@test "pod create --hosts-file, --no-hosts, --no-hostname, --label-file, --pod-id-file" {
    printf '10.9.8.7 base.test\n' > "$WORKDIR/hosts.base"
    sh_ pod create --network none --hosts-file "$WORKDIR/hosts.base" --name hf > /dev/null
    check_match "the base file is in the members' /etc/hosts" "^10.9.8.7[[:space:]]+base.test" \
        "$(sh_ container run --rm --pod hf "$IMAGE" cat /etc/hosts)"
    check "inspect has it" "$WORKDIR/hosts.base" "$(sh_ pod inspect hf --format '{{.InfraConfig.HostsFile}}')"
    sh_ pod create --network none --no-hosts --name nh > /dev/null
    check "--no-hosts: the image's /etc/hosts" 0 "$(sh_ container run --rm --pod nh "$IMAGE" grep -c host.containers.internal /etc/hosts)"
    check "inspect has it" true "$(sh_ pod inspect nh --format '{{.InfraConfig.NoManageHosts}}')"
    check "the others get the pod's names" 1 "$(sh_ container run --rm --pod hf "$IMAGE" grep -c host.containers.internal /etc/hosts)"
    out=$(sh_ pod create --network none --no-hosts --add-host a:1.2.3.4 bad 2>&1)
    check "--no-hosts with --add-host" 125 $?
    check_match "is said" "--no-hosts and --add-host cannot be set together" "$out"
    sh_ pod create --network none --no-hostname --name nhn > /dev/null
    [ "$(sh_ container run --rm --pod hf "$IMAGE" cat /etc/hostname)" = "hf" ]
    check "a pod writes the /etc/hostname of the members" 0 $?
    check "--no-hostname: the /etc/hostname of the image stays" "localhost" "$(sh_ container run --rm --pod nhn "$IMAGE" cat /etc/hostname)"
    check "inspect has it" true "$(sh_ pod inspect nhn --format '{{.InfraConfig.NoManageHostname}}')"
    printf '# a comment\n\nfrom=file\nboth=file\nbare\n' > "$WORKDIR/labels"
    BARE=envvalue sh_ pod create --network none --label-file "$WORKDIR/labels" -l both=cli -l emptyone --name lf --pod-id-file "$WORKDIR/lf.id" > /dev/null
    check "--label-file" "file" "$(sh_ pod inspect lf --format '{{.Labels.from}}')"
    check "--label wins" "cli" "$(sh_ pod inspect lf --format '{{.Labels.both}}')"
    check "a label without a value" "" "$(sh_ pod inspect lf --format '{{.Labels.emptyone}}')"
    check "--pod-id-file" "$(sh_ pod inspect lf --format '{{.Id}}')" "$(cat "$WORKDIR/lf.id")"
    out=$(sh_ pod create --network none --label-file "$WORKDIR/nosuch" x 2>&1)
    check "a missing label file" 125 $?
    check_match "is said" "unable to process labels: open .*nosuch: no such file or directory" "$out"
    out=$(sh_ pod create --network none --pod-id-file /nonexistent/dir/id x 2>&1)
    check "a pod ID file that cannot be written" 125 $?
    check "leaves no pod" 1 "$(sh_ pod exists x; echo $?)"
    echo keep > "$WORKDIR/kept.id"
    out=$(sh_ pod create --network none --name lf --pod-id-file "$WORKDIR/kept.id" 2>&1)
    check "a pod that is not made" 125 $?
    check "says it as podman" 'Error: adding pod to state: name "lf" is in use: pod already exists' "$out"
    check "leaves the file that was there" keep "$(cat "$WORKDIR/kept.id")"
    sh_ pod create --network none --name lf2 --pod-id-file "$WORKDIR/kept.id" > /dev/null
    check "a made pod replaces what the file had" "$(sh_ pod inspect lf2 --format '{{.Id}}')" "$(cat "$WORKDIR/kept.id")"
    sh_ pod create --network none --pod-id-file "$WORKDIR/gone.id" --name lf > /dev/null 2>&1
    check "a file it made goes when the pod is not made" 1 "$([ -e "$WORKDIR/gone.id" ]; echo $?)"
}

@test "pod create --pid host, --uts host, --mac-address, --share-parent, --shm-size-systemd, --subuidname" {
    sh_ pod create --network none --pid host --uts host --name hostns > /dev/null
    check "--pid host: the members are in the PID namespace of the host" "$(readlink /proc/self/ns/pid)" \
        "$(sh_ container run --rm --pod hostns "$IMAGE" readlink /proc/self/ns/pid)"
    check "--uts host: and in the UTS namespace" "$(readlink /proc/self/ns/uts)" \
        "$(sh_ container run --rm --pod hostns "$IMAGE" readlink /proc/self/ns/uts)"
    check "with the name of the host" "$(hostname)" "$(sh_ container run --rm --pod hostns "$IMAGE" hostname)"
    check "inspect says pid host" host "$(sh_ pod inspect hostns --format '{{.InfraConfig.PidNS}}')"
    check "and uts host" host "$(sh_ pod inspect hostns --format '{{.InfraConfig.UtsNS}}')"
    sh_ pod create --network none --pid private --uts private --name privns > /dev/null
    [ "$(readlink /proc/self/ns/uts)" != "$(sh_ container run --rm --pod privns "$IMAGE" readlink /proc/self/ns/uts)" ]
    check "private: a namespace of its own" 0 $?
    out=$(sh_ pod create --network none --pid ns:/proc/1/ns/pid x 2>&1)
    check "--pid ns:" 125 $?
    check_match "is refused with the reason" "the pid namespace mode .ns:/proc/1/ns/pid. is not supported for pods" "$out"
    out=$(sh_ pod create --network none --uts host --hostname h x 2>&1)
    check "--uts host with a hostname" 125 $?
    check_match "is refused, in podman's words" "invalid config provided: cannot set hostname when running in the host UTS namespace: invalid configuration" "$out"
    out=$(sh_ pod create --mac-address zz x 2>&1)
    check "a bad --mac-address" 125 $?
    check_match "is said" "address zz: invalid MAC address" "$out"
    sh_ pod create --mac-address 02:42:ac:11:00:99 --name macpod > /dev/null
    check "--mac-address is in the pod" "02:42:ac:11:00:99" "$(sh_ pod inspect macpod --format '{{.InfraConfig.StaticMAC}}')"
    out=$(sh_ pod create --share-parent=false --share cgroup,net x 2>&1)
    check "--share-parent=false with --share cgroup" 125 $?
    check_match "conflicts as in podman" "cannot define the pod as the cgroup parent at the same time as joining the infra container's cgroupNS" "$out"
    sh_ pod create --network none --shm-size-systemd 20m --name ssd > /dev/null
    check "--shm-size-systemd" 0 $?
    out=$(sh_ pod create --shm-size-systemd lots x 2>&1)
    check "a bad --shm-size-systemd" 125 $?
    if [ "$(id -u)" != 0 ]; then
        out=$(sh_ pod create --subuidname nosuchuser x 2>&1)
        check "--subuidname as a user" 125 $?
        check_match "is for root" "--subuidname and --subgidname are for containers run by root" "$out"
    fi
    out=$(sh_ pod create --userns private --subuidname u x 2>&1)
    check "--userns with --subuidname" 125 $?
    check_match "conflict" "mutually exclusive" "$out"
}

@test "pod clone: the spec of the pod with a name, --destroy, --start" {
    sh_ pod create --network none --name co -l a=b --hostname chost --add-host x:1.2.3.4 > /dev/null
    sh_ pod clone co cc > /dev/null
    check "pod clone" 0 $?
    check "the copy has the settings" "chost map[a:b] [x:1.2.3.4]" \
        "$(sh_ pod inspect cc --format '{{.Hostname}} {{.Labels}} {{.InfraConfig.HostAdd}}')"
    check "the original stays" 0 "$(sh_ pod exists co; echo $?)"
    sh_ pod clone --destroy --start -l c=d -h other co cd > /dev/null
    check "--destroy removes the original" 1 "$(sh_ pod exists co; echo $?)"
    check "--start starts the copy" Running "$(pod_state cd)"
    check "-h and -l change it" "other map[a:b c:d]" "$(sh_ pod inspect cd --format '{{.Hostname}} {{.Labels}}')"
    sh_ container run -d --pod cd --name cdc "$IMAGE" sleep 300 > /dev/null
    sh_ container create --pod cd --name cdd "$IMAGE" sleep 300 > /dev/null
    id=$(sh_ pod clone cd y)
    check "a pod with containers is cloned with them" "cdc-clone cdd-clone" \
        "$(sh_ ps -a --filter pod=y --format '{{.Names}}' | grep -v infra | sort | tr '\n' ' ' | sed 's/ $//')"
    check "the copy is stopped" Created "$(pod_state y)"
    check "the infra container is named after the original's" "$(sh_ ps -a --filter pod=cd --format '{{.Names}}' | grep infra)-clone" \
        "$(sh_ ps -a --filter pod=y --format '{{.Names}}' | grep infra)"
    check "the original is untouched" "cdc cdd" "$(sh_ ps -a --filter pod=cd --format '{{.Names}}' | grep -v infra | sort | tr '\n' ' ' | sed 's/ $//')"
    out=$(sh_ pod clone nosuch z 2>&1)
    check "a missing pod" 125 $?
    sh_ pod create --network none --name cn > /dev/null
    sh_ pod clone cn > /dev/null
    sh_ pod clone cn > /dev/null
    check "the names of copies are podman's" "cn-clone1 cn-clone cn" \
        "$(sh_ pod ps --filter name=cn --format '{{.Name}}' | tr '\n' ' ' | sed 's/ $//')"
    out=$(sh_ pod clone --destroy cn cn-clone 2>&1)
    check "a copy that cannot be made" 125 $?
    check "leaves the pod with --destroy" 0 "$(sh_ pod exists cn; echo $?)"
}

@test "pod clone: the options of pod create change the copy" {
    sh_ pod create --network none --name cl1 --sysctl kernel.msgmax=7777 --security-opt label=disable --volume "$WORKDIR:/vo1:ro" > /dev/null
    sh_ pod clone --pid host --uts host --device /dev/null:/dev/clnull --volume "$WORKDIR:/vo2" --sysctl kernel.msgmnb=9999 \
        --shm-size 33m --restart on-failure:2 --cgroup-parent clgroup.slice --security-opt seccomp=unconfined \
        --memory 200m --cpu-shares 300 cl1 cl2 > /dev/null
    check "pod clone with options" 0 $?
    check "--pid host" host "$(sh_ pod inspect cl2 --format '{{.InfraConfig.PidNS}}')"
    check "--uts host" host "$(sh_ pod inspect cl2 --format '{{.InfraConfig.UtsNS}}')"
    check "the original keeps its namespaces" "private private" "$(sh_ pod inspect cl1 --format '{{.InfraConfig.PidNS}} {{.InfraConfig.UtsNS}}')"
    check "--device" "/dev/clnull" "$(sh_ pod inspect cl2 --format '{{range .Devices}}{{.path}}{{end}}')"
    check "the volumes replace the pod's" "/vo2" \
        "$(sh_ container run --rm --pod cl2 "$IMAGE" sh -c 'echo; ls -d /vo1 /vo2 2> /dev/null | tr "\n" " "' | tail -1 | sed 's/ $//')"
    check "the original keeps its volume" "/vo1" \
        "$(sh_ container run --rm --pod cl1 "$IMAGE" sh -c 'echo; ls -d /vo1 /vo2 2> /dev/null | tr "\n" " "' | tail -1 | sed 's/ $//')"
    check "the sysctls replace the pod's" "8192 9999" \
        "$(sh_ container run --rm --pod cl2 "$IMAGE" sh -c 'echo $(cat /proc/sys/kernel/msgmax) $(cat /proc/sys/kernel/msgmnb)')"
    check "--shm-size" "34603008" "$(sh_ container run --rm --pod cl2 "$IMAGE" stat -f -c '%b*%S' /dev/shm | awk -F'*' '{print $1*$2}')"
    check "--restart" "on-failure:2" "$(sh_ container run -d --pod cl2 --name cl2c "$IMAGE" true >/dev/null; sh_ container inspect cl2c --format '{{.HostConfig.RestartPolicy.Name}}:{{.HostConfig.RestartPolicy.MaximumRetryCount}}')"
    sh_ pod clone --infra-command "/pause 99" --infra-conmon-pidfile "$WORKDIR/cl3.pid" cl1 cl3 > /dev/null
    check "--infra-command" "/pause 99" "$(sh_ ps -a --filter pod=cl3 --format '{{.Command}}')"
    out=$(sh_ pod clone --uidmap 0:1:1 --subuidname u cl1 x 2>&1)
    check "options that conflict" 125 $?
    check_match "are refused" "mutually exclusive" "$out"
    out=$(sh_ pod clone --shm-size lots cl1 x 2>&1)
    check "a bad value" 125 $?
    check "makes no pod" 1 "$(sh_ pod exists x; echo $?)"
}

@test "create --init-ctr: init containers run to their end before the others when the pod starts" {
    sh_ pod create --network none --name ip > /dev/null
    sh_ container create --pod ip --name once1 --init-ctr once "$IMAGE" true > /dev/null
    check "create --init-ctr once" 0 $?
    sh_ container create --pod ip --name always1 --init-ctr always "$IMAGE" sh -c 'echo ran >> /dev/null' > /dev/null
    # the main container needs the file the init container makes in a volume
    sh_ volume create initvol > /dev/null
    sh_ container create --pod ip --name seed --init-ctr once -v initvol:/v "$IMAGE" sh -c 'echo seeded > /v/f' > /dev/null
    sh_ container create --pod ip --name main1 -v initvol:/v "$IMAGE" sh -c 'cat /v/f; sleep 300' > /dev/null
    out=$(sh_ pod start ip 2>&1)
    check "pod start" 0 $?
    check "a once container is removed after it ran" 1 "$(sh_ container exists once1; echo $?)"
    check "the one that seeds the volume too" 1 "$(sh_ container exists seed; echo $?)"
    check "an always container stays, exited" exited "$(state_of always1)"
    check "the main container ran after the init containers" "seeded" "$(sh_ container logs main1 2>&1)"
    check "the pod runs" Running "$(pod_state ip)"
    check "pod ps counts the init container" 3 "$(sh_ pod ps --format '{{.NumberOfContainers}}')"
    started=$(sh_ container inspect -f '{{.State.StartedAt}}' always1)
    sh_ pod stop -t 0 ip > /dev/null
    sh_ pod start ip > /dev/null
    [ "$started" != "$(sh_ container inspect -f '{{.State.StartedAt}}' always1)" ]
    check "an always container runs at each start" 0 $?
    sh_ pod restart ip > /dev/null
    check "pod restart" 0 $?
    sh_ pod pause ip > /dev/null
    check "pause skips the exited init container" Paused "$(pod_state ip)"
    sh_ pod unpause ip > /dev/null
    out=$(sh_ container create --init-ctr once "$IMAGE" true 2>&1)
    check "--init-ctr without a pod" 125 $?
    check_match "is said" "must specify pod value with init-ctr" "$out"
    out=$(sh_ container create --pod ip --init-ctr sometimes "$IMAGE" true 2>&1)
    check "a bad type" 125 $?
    check_match "is said" "init-ctr value must be 'always' or 'once'" "$out"
    sh_ pod rm -t 0 -f ip > /dev/null
    sh_ volume rm initvol > /dev/null
    sh_ pod create --network none --name fp > /dev/null
    sh_ container create --pod fp --name failinit --init-ctr once "$IMAGE" sh -c 'exit 3' > /dev/null
    sh_ container create --pod fp --name failmain "$IMAGE" sleep 300 > /dev/null
    out=$(sh_ pod start fp 2>&1)
    check "a failing init container fails the start" 125 $?
    check_match "and its code is said" "init container .* exited with code 3" "$out"
    check "the other containers did not start" created "$(state_of failmain)"
}

@test "the members of a pod share the /dev/shm of the infra container" {
    sh_ pod create --network none --name shp > /dev/null || e2e_die "pod create"
    sh_ container run --rm --pod shp "$IMAGE" touch /dev/shm/test1 || e2e_die "touch"
    out=$(sh_ container run --rm --pod shp "$IMAGE" ls /dev/shm/test1 2>&1)
    check "a member finds the file another one made" /dev/shm/test1 "$out"
    sh_ container run -d --pod shp --name shp-a "$IMAGE" sleep 300 > /dev/null || e2e_die "run a"
    check "a running member sees it too" /dev/shm/test1 "$(sh_ container exec shp-a ls /dev/shm/test1 2>&1)"
    # the file is the infra's, gone when the pod stops
    sh_ pod stop -t 0 shp > /dev/null 2>&1
    sh_ pod start shp > /dev/null 2>&1
    check "a restarted pod has an empty /dev/shm" "" "$(sh_ container exec shp-a ls /dev/shm 2>&1)"
    # a container of another pod does not
    sh_ pod create --network none --name shq > /dev/null || e2e_die "pod create"
    sh_ container run --rm --pod shq "$IMAGE" sh -c 'ls /dev/shm | wc -l' > "$WORKDIR/shq" 2>&1
    check "another pod has its own" 0 "$(cat "$WORKDIR/shq")"
}

@test "--ipc container:ID of a shareable container shares its /dev/shm" {
    sh_ container run -d --ipc shareable --name shc "$IMAGE" sleep 300 > /dev/null || e2e_die "run"
    sh_ container run --rm --ipc container:shc "$IMAGE" touch /dev/shm/f1 || e2e_die "touch"
    check "the target sees the file" /dev/shm/f1 "$(sh_ container exec shc ls /dev/shm/f1 2>&1)"
    # a private target cannot be joined, as podman says
    sh_ container run -d --ipc private --name shd "$IMAGE" sleep 300 > /dev/null || e2e_die "run d"
    out=$(sh_ container run --rm --ipc container:shd "$IMAGE" touch /dev/shm/f2 2>&1)
    check "a private target cannot be joined" 125 $?
    check_match "in podman's words" "non-shareable IPC" "$out"
    sh_ container rm -t 0 -f shc shd > /dev/null 2>&1
}

@test "pod create --blkio-weight: the inspect, the refusals of the device limits" {
    out=$(sh_ pod create --blkio-weight 50 --name bw1 2>&1) || e2e_die "pod create: $out"
    check "the weight is in the inspect" 50 "$(sh_ pod inspect --format '{{.BlkioWeight}}' bw1 2>&1 | head -1)"
    out=$(sh_ pod create --device-read-bps /dev/null:1mb 2>&1)
    check "a device that is no block device is refused" "Error: /dev/null: not a block device" "$out"
    out=$(sh_ pod create --device-write-bps sda:1mb 2>&1)
    check "a path outside /dev" "Error: bad format for device path: sda:1mb" "$out"
    out=$(sh_ pod create --blkio-weight-device /dev/nosuch:50 2>&1)
    check "a device that is not there" "Error: bad --blkio-weight-device: could not parse device /dev/nosuch: no such file or directory" "$out"
    out=$(sh_ pod create --blkio-weight abc 2>&1)
    [[ "$out" == "Error: invalid value for blkio-weight: "* ]]
    check "a weight that is no number" 0 $?
    out=$(sh_ pod create --cgroups disabled --blkio-weight 50 2>&1)
    [[ "$out" == *"without cgroups"* ]]
    check "--cgroups=disabled refuses the limit" 0 $?
}
