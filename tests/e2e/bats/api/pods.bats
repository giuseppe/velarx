# SPDX-License-Identifier: Apache-2.0
# Pods through the podman API and the CLI.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; api_state_load; }

need_catatonit () {
    if ! test -x /usr/libexec/podman/catatonit && ! test -x /usr/libexec/catatonit/catatonit &&
        ! command -v catatonit > /dev/null; then
        skip "no catatonit"
    fi
}

ns () {
    pm exec "$1" sh -c 'echo $(hostname) $(readlink /proc/self/ns/net) $(readlink /proc/self/ns/ipc) $(readlink /proc/self/ns/uts)'
}

mkpod () {
    pm pod create --infra-image "$IMG" --infra-command "sleep 1000" "$@"
}

# A pod with no infra image: the local pause image, built once, no pull.

@test "a pod with no infra image uses the pause image" {
    need_catatonit
    pm pod create --name pausepod > /dev/null
    check "pod create without an infra image" 0 $?
    pm pod start pausepod > /dev/null
    check "and start" "Running" "$(pm pod inspect pausepod --format '{{.State}}')"
    # podman pod stats --remote: a report per container of the pod
    out=$(pm pod stats --no-stream --format '{{.Name}} {{.PIDS}}' pausepod 2>&1 | tail -1)
    pausepod=$(pm pod inspect pausepod --format '{{.Id}}')
    check_match "pod stats" "^${pausepod:0:12}-infra [0-9]+$" "$out"
    out=$(api "http://d/v5.0.0/libpod/pods/stats?namesOrIDs=nopod" | jq -r .message)
    check "pod stats of a missing pod" "unable to get list of pods: no pod with name or ID nopod found: no such pod" "$out"
    out=$(pm ps --pod --filter pod=pausepod --format '{{.Image}} {{.Command}}')
    check_match "its infra container runs the pause image" "^localhost/velarx-pause:[^ ]+ /catatonit -P" "$out"
    pm pod create --name pausepod2 > /dev/null
    check "a second pod" 0 $?
    check "uses the same image" 1 "$(pm images --format '{{.Repository}}' | grep -c velarx-pause)"
    pm pod rm -t 0 -f pausepod pausepod2 > /dev/null
}

@test "an infra image that is not in the store is pulled" {
    need_catatonit
    # an infra image that is not in the store is pulled
    other=$E2E_REGISTRY/e2e/alpine:gzip
    pm rmi -f "$other" > /dev/null 2>&1
    pm pod create --name pullpod --infra-image "$other" --infra-command "sleep 1000" > /dev/null
    check "a missing infra image is pulled" 0 $?
    pm pod rm -t 0 -f pullpod > /dev/null
    pm rmi -f "$other" > /dev/null 2>&1
}

# The containers of a pod join the namespaces of its infra container that
# the pod shares.

@test "the members of a pod share its namespaces" {
    pm pod create --name nspod --infra-image "$IMG" --infra-command "sleep 1000" > /dev/null
    pm run -d --pod nspod --name nsm1 "$IMG" sleep 1000 > /dev/null
    check "a member of a pod" 0 $?
    pm run -d --pod nspod --name nsm2 "$IMG" sleep 1000 > /dev/null
    ns () {
        pm exec "$1" sh -c 'echo $(hostname) $(readlink /proc/self/ns/net) $(readlink /proc/self/ns/ipc) $(readlink /proc/self/ns/uts)'
    }
    one=$(ns nsm1)
    check_match "a member has the pod's hostname" "^nspod net:" "$one"
    check "two members share the hostname, network, IPC and UTS" "$one" "$(ns nsm2)"
    pid1=$(pm exec nsm1 readlink /proc/self/ns/pid)
    test "$pid1" != "$(pm exec nsm2 readlink /proc/self/ns/pid)"
    check "but not the PID namespace by default" 0 $?
    api_state_save one
}

@test "a message queue of a member is seen by the others" {
    # a message queue of one is seen by the other: the mqueue file system
    # is that of the IPC namespace
    pm exec nsm1 sh -c ': > /dev/mqueue/q1'
    check "a message queue is seen by both" "q1" "$(pm exec nsm2 ls /dev/mqueue 2>&1)"
}

@test "the velarx CLI joins the pod too" {
    timeout 60 "$CLI" --socket "$ESOCK" container run -d --pod nspod --name nsm3 "$IMG" sleep 1000 > /dev/null
    check "the velarx CLI joins the pod too" "$one" "$(ns nsm3)"
}

@test "a member restarted by its policy stays in the pod" {
    # a restart by the policy joins the same namespaces
    pm run -d --pod nspod --restart on-failure:1 --name nsr "$IMG" \
        sh -c 'readlink /proc/self/ns/ipc; sleep 0.3; exit 1' > /dev/null
    # (a line for each of the two runs, then it stays exited)
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$(pm inspect nsr --format '{{.Id}}')/container.log" ' stdout F ' 30 2 ||
        fail "nsr did not run twice within 30 s"
    e2e_wait_condition nsr exited 30 || fail "nsr did not stay exited within 30 s"
    ipc=$(pm exec nsm1 readlink /proc/self/ns/ipc)
    check "a member restarted by its policy stays in the pod" "$ipc $ipc" "$(pm logs nsr | tr '\n' ' ' | sed 's/ $//')"
}

@test "a member cannot have a hostname or a network of its own" {
    out=$(pm run --rm --pod nspod --hostname other "$IMG" true 2>&1)
    check_match "a hostname of its own is refused" "UTS namespace" "$out"
    out=$(pm run --rm --pod nspod --network none "$IMG" true 2>&1)
    check_match "a network of its own too" "network namespace" "$out"
}

@test "--share pid shares the PID namespace" {
    pm pod create --name nspod2 --share pid,ipc --infra-image "$IMG" --infra-command "sleep 1000" > /dev/null
    pm run -d --pod nspod2 --name nsp1 "$IMG" sleep 1000 > /dev/null
    pm run -d --pod nspod2 --name nsp2 "$IMG" sleep 1000 > /dev/null
    check "--share pid shares the PID namespace" "$(pm exec nsp1 readlink /proc/self/ns/pid)" \
        "$(pm exec nsp2 readlink /proc/self/ns/pid)"
    out=$(pm exec nsp1 ps -o comm 2>&1 | grep -c sleep)
    check "where the processes of the others are seen" 3 "$out"
    test "$(pm exec nsp1 readlink /proc/self/ns/net)" != "$(pm exec nsp2 readlink /proc/self/ns/net)"
    check "and nothing else" 0 $?
}

@test "a pod in the host's PID and IPC namespaces" {
    # a pod in the PID and IPC namespaces of the host (the CRI's hostPID and
    # hostIPC): there is none to join, its members use the host's like the
    # infra container
    api -o /dev/null -X POST -H 'Content-Type: application/json' \
        -d '{"name":"hostns","pidns":{"nsmode":"host"},"ipcns":{"nsmode":"host"},"infra_image":"'"$IMG"'","infra_command":["sleep","1000"]}' \
        http://d/v5.0.0/libpod/pods/create
    pm run -d --pod hostns --name hn1 "$IMG" sleep 1000 > /dev/null
    check "a member of a pod in the host's PID and IPC namespaces" 0 $?
    hostnsi=$(pm pod inspect hostns --format '{{.InfraContainerID}}')
    hostns="$(readlink /proc/self/ns/pid) $(readlink /proc/self/ns/ipc)"
    check "is in them" "$hostns" "$(pm exec hn1 sh -c 'echo $(readlink /proc/self/ns/pid) $(readlink /proc/self/ns/ipc)')"
    check "and so is the infra container" "$hostns" \
        "$(pm exec "$hostnsi" sh -c 'echo $(readlink /proc/self/ns/pid) $(readlink /proc/self/ns/ipc)')"
    check "its inspect says so" "host host" "$(pm inspect "$hostnsi" --format '{{.HostConfig.PidMode}} {{.HostConfig.IpcMode}}')"
    out=$(pm run --rm --pod hostns --pid "container:$hostnsi" "$IMG" true 2>&1)
    check_match "another PID namespace is refused" "pid namespace" "$out"
    pm pod rm -t 0 -f hostns > /dev/null
    pm pod rm -t 0 -f nspod nspod2 > /dev/null
}

# pod create options, the exit policy and the user namespace of a pod

@test "pod create with options" {
    mkdir -p "$WORKDIR/podvol"
    echo inpodvol > "$WORKDIR/podvol/f"
    pm pod create --name optpod --sysctl net.ipv4.ip_unprivileged_port_start=81 \
        --shm-size 32m -v "$WORKDIR/podvol:/pv:z" --restart on-failure:1 > /dev/null
    check "pod create with options" 0 $?
    out=$(pm run --rm --pod optpod "$IMG" sh -c 'cat /proc/sys/net/ipv4/ip_unprivileged_port_start /pv/f; df -k /dev/shm | tail -1' 2>&1)
    check_match "the sysctl of the pod" "^81" "$out"
    check_match "its volume" "inpodvol" "$out"
    check_match "its /dev/shm size" " 32768 " "$out"
    pm run -d --pod optpod --name optr "$IMG" sh -c 'sleep 0.2; exit 1' > /dev/null
    # (the exit of the run of its policy: one restart, then exited)
    e2e_wait_condition optr stopped 30 || fail "optr exited within 30 s"
    check "its restart policy" "1 exited" "$(pm inspect optr --format '{{.RestartCount}} {{.State.Status}}')"
    pm pod rm -t 0 -f optpod > /dev/null
}

@test "the exit policy of a pod" {
    pm pod create --name stoppod --exit-policy stop > /dev/null
    # (each container ends when the test writes to the FIFO it reads)
    local c
    for c in stop1 stop2; do
        mkfifo "$WORKDIR/$c.fifo"
        pm run -d --pod stoppod --name $c -v "$WORKDIR/$c.fifo:/fifo:z" "$IMG" sh -c 'read l < /fifo' > /dev/null
    done
    timeout 30 sh -c 'echo end > "$1"' sh "$WORKDIR/stop1.fifo" || fail "stop1 reads its FIFO"
    pm wait stop1 > /dev/null
    check_match "exit policy stop: running while a container runs" "Running|Degraded" \
        "$(pm pod inspect stoppod --format '{{.State}}')"
    timeout 30 sh -c 'echo end > "$1"' sh "$WORKDIR/stop2.fifo" || fail "stop2 reads its FIFO"
    pm wait stop2 > /dev/null
    # (the engine stops the pod after the exit, its infra container last:
    # the record of the pod says when it is done)
    e2e_wait_content "$XDG_DATA_HOME/velarx/pods/$(pm pod inspect stoppod --format '{{.Id}}').json" \
        '"state": *"(exited|stopped)"' 30 || fail "stoppod was not stopped within 30 s"
    check_match "and stopped once they all exited" "Exited|Stopped" "$(pm pod inspect stoppod --format '{{.State}}')"
    pm pod rm -t 0 -f stoppod > /dev/null
}

@test "the user namespace of a pod" {
    pm pod create --name unspod --userns auto > /dev/null
    check "pod create --userns auto" 0 $?
    pm run -d --pod unspod --name uns1 "$IMG" sleep 1000 > /dev/null
    pm run -d --pod unspod --name uns2 "$IMG" sleep 1000 > /dev/null
    m1=$(pm exec uns1 sh -c 'readlink /proc/self/ns/user; cat /proc/self/uid_map' 2>&1)
    check "the members of a pod share its user namespace" "$m1" \
        "$(pm exec uns2 sh -c 'readlink /proc/self/ns/user; cat /proc/self/uid_map' 2>&1)"
    test "$m1" != "$(sh -c 'readlink /proc/self/ns/user; cat /proc/self/uid_map')"
    check "which is not the daemon's" 0 $?
    out=$(pm run --rm --pod unspod --userns host "$IMG" true 2>&1)
    pm pod rm -t 0 -f unspod > /dev/null
}

@test "velarx pod create with options" {
    sc () { timeout 60 "$CLI" --socket "$ESOCK" "$@"; }
    sc pod create --share +pid --sysctl net.ipv4.ip_unprivileged_port_start=82 \
        --infra-command "sleep 1000" --infra-image "$IMG" clipod > /dev/null
    check "velarx pod create with options" 0 $?
    sc container run -d --pod clipod --name clim "$IMG" sleep 1000 > /dev/null
    out=$(pm exec clim sh -c 'cat /proc/sys/net/ipv4/ip_unprivileged_port_start; ps -o comm | grep -c sleep')
    check "its sysctl and --share +pid" "82 2" "$(echo $out)"
    sc pod create --share bogus clibad > /dev/null 2>&1
    check "an unknown namespace for --share is refused" 1 "$(sc pod exists clibad > /dev/null 2>&1; echo $?)"
    pm pod rm -t 0 -f clipod > /dev/null
}

@test "an option a pod cannot have is refused" {
    out=$(pm pod create --name badpod --uts container:x 2>&1)
    check_match "an option a pod cannot have is refused" "not supported" "$out"
    pm pod rm -t 0 -f badpod > /dev/null 2>&1
}

# The answers podman's REST API test suite (test/apiv2/40-pods) expects.

@test "pod answers: filters, duplicates and start" {
    pm pod create --name ansp > /dev/null
    out=$(api 'http://d/v5.0.0/libpod/pods/json?filters=%7B%22until%22%3A%5B%22500000%22%5D%7D' | jq length)
    check "until before the pod" 0 "$out"
    out=$(api 'http://d/v5.0.0/libpod/pods/json?filters=%7B%22until%22%3A%5B%225000000000%22%5D%7D' | jq '[.[] | select(.Name == "ansp")] | length')
    check "until after it" 1 "$out"
    out=$(api -X POST -d '{"name":"ansp"}' http://d/v5.0.0/libpod/pods/create | jq -r .cause)
    check "a duplicate pod: its cause" "pod already exists" "$out"
    out=$(api -X POST http://d/v5.0.0/libpod/pods/ansp/start | jq -c .Errs)
    check "a start reports no errors as null" null "$out"
}

@test "pod answers: unpause, removal, top and stop" {
    pm run -d --pod ansp --name ansc "$IMG" sleep 1000 > /dev/null
    out=$(api -o /dev/null -w '%{http_code}' -X POST http://d/v5.0.0/libpod/pods/ansp/unpause)
    check "an unpause of a pod that is not paused" 200 "$out"
    out=$(api -X DELETE 'http://d/v5.0.0/libpod/pods/ansp?force=false' | jq -r .cause)
    check "a removal without force of a pod with a running container" "removing pod containers" "$out"
    out=$(api 'http://d/v5.0.0/libpod/pods/ansp/top?ps_args=args,pid' | jq -c '[.Titles, .Processes[0]]')
    check "top with podman's descriptors" '[["COMMAND","PID"],["/catatonit -P","1"]]' "$out"
    out=$(api 'http://d/v5.0.0/libpod/pods/ansp/top' | jq -r '.Titles[-1]')
    check "top's default titles" COMMAND "$out"
    # stream: a report every delay seconds
    out=$(api -m 3 'http://d/v5.0.0/libpod/pods/ansp/top?stream=true&delay=1' | jq -s 'length >= 2')
    check "top stream sends a report every delay" true "$out"
    out=$(api 'http://d/v5.0.0/libpod/pods/ansp/top?stream=true&delay=0' | jq -r .message)
    check_match "a delay below 1 is refused" "delay.*< 1" "$out"
    api -X POST "http://d/v5.0.0/libpod/pods/ansp/stop?t=1" > /dev/null
    out=$(api -o /dev/null -w '%{http_code}' -X POST http://d/v5.0.0/libpod/pods/ansp/stop)
    check "the stop of a stopped pod" 304 "$out"
    pm rm -t 0 -f ansc > /dev/null
    api -X POST http://d/v5.0.0/libpod/pods/ansp/start > /dev/null
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v5.0.0/libpod/pods/ansp)
    check "a pod whose infra alone runs is removed without force" 200 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v5.0.0/libpod/pods/ansp)
    check "and then is gone" 404 "$out"
}

@test "pod create, ls, inspect and exists" {
    out=$(mkpod --name apipod --label k=v 2>&1)
    rc=$?
    echo "# $out"
    check "pod create" 0 $rc
    out=$(pm pod ls --format '{{.Name}} {{.Status}} {{.Labels}}')
    check_match "pod ls" "^apipod Created (map\\[k:v\\]|k=v)$" "$out"
    out=$(pm pod inspect apipod --format '{{.State}} {{.NumContainers}} {{.SharedNamespaces}}')
    check "pod inspect" "Created 1 [ipc net uts]" "$out"
    pm pod exists apipod
    check "pod exists" 0 $?
    pm pod exists nope
    check "pod exists of a missing pod" 1 $?
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/pods/nope/json)
    check "pod inspect of a missing pod" 404 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST -d '{"name":"apipod"}' http://d/v5.0.0/libpod/pods/create)
    check "pod create conflict" 409 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST -d '{"name":"noinfra","no_infra":true}' http://d/v5.0.0/libpod/pods/create)
    check "a pod without an infra container is made" 201 "$out"
    check "and has none" "" "$(pm pod inspect noinfra --format '{{.InfraContainerID}}' 2>&1)"
    check "it is there" noinfra "$(pm pod inspect noinfra --format '{{.Name}}' 2>&1)"
    pm pod rm noinfra > /dev/null
}

@test "pod start" {
    pm pod start apipod > /dev/null
    check "pod start" 0 $?
    out=$(pm pod inspect apipod --format '{{.State}}')
    check "pod started" "Running" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST http://d/v5.0.0/libpod/pods/apipod/start)
    check "pod start of a running pod" 304 "$out"
}

@test "a container in a pod: ps and top" {
    pm run -d --pod apipod --name podc "$IMG" sleep 100 > /dev/null
    check "run in a pod" 0 $?
    apipod=$(pm pod inspect apipod --format '{{.Id}}')
    out=$(pm ps --pod --format '{{.Names}} {{.PodName}} {{.IsInfra}}' | sort | tr '\n' ',')
    check "ps --pod" "${apipod:0:12}-infra apipod true,podc apipod false," "$out"
    if test "$(pm top podc | wc -l)" -gt 1; then
        out=$(pm pod top apipod | grep -c "sleep")
        check_match "pod top" "^[1-9]" "$out"
    else
        todo "pod top" "container top finds no processes (the cgroup of the container)"
    fi
}

@test "pod pause and unpause" {
    pm pod pause apipod > /dev/null 2>&1
    rc=$?
    if have_freezer; then
        check "pod pause" 0 $rc
        check "pod paused" "Paused" "$(pm pod inspect apipod --format '{{.State}}')"
        pm pod unpause apipod > /dev/null
        check "pod unpaused" "Running" "$(pm pod inspect apipod --format '{{.State}}')"
    else
        note_skip "pod pause" "no cgroup freezer we may write here"
        # A pause that fails leaves every container as it was.
        out=$(pm ps -a --filter pod=apipod --format '{{.State}}' | sort -u | tr '\n' ' ')
        check "a failed pod pause leaves the containers running" "running " "$out"
        check "a failed pod pause leaves the pod running" "Running" "$(pm pod inspect apipod --format '{{.State}}')"
    fi
}

@test "pod stop, restart, kill and rm" {
    pm pod stop -t 1 apipod > /dev/null
    check "pod stop" 0 $?
    out=$(pm pod inspect apipod --format '{{.State}}')
    check "pod stopped" "Exited" "$out"
    pm pod start apipod > /dev/null
    out=$(pm pod inspect apipod --format '{{.State}}')
    check "pod restarted" "Running" "$out"
    out=$(api -o $WORKDIR/restart.body -w '%{http_code}' -X POST 'http://d/v5.0.0/libpod/pods/apipod/restart?t=1'); cat $WORKDIR/restart.body >&2
    check "pod restart" 200 "$out"
    check "pod restarted state" "Running" "$(pm pod inspect apipod --format '{{.State}}')"
    pm pod kill apipod > /dev/null
    check "pod kill" 0 $?
    out=$(api -X POST -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/pods/nope/stop)
    check "pod stop of a missing pod" 404 "$out"
    pm pod rm -t 0 -f apipod > /dev/null
    check "pod rm" 0 $?
    pm pod exists apipod
    check "pod rm removes" 1 $?
    out=$(pm ps -a -q | wc -l)
    check "pod rm removes the containers" 0 "$out"
}

@test "pod prune" {
    mkpod --name pruned > /dev/null
    out=$(pm pod prune -f)
    check_match "pod prune" "^[0-9a-f]{64}$" "$out"
    pm pod exists pruned
    check "pod prune removes" 1 $?
}

@test "init containers run before the others when the pod starts" {
    need_catatonit
    pm pod create --name initpod > /dev/null
    pm create --pod initpod --name once1 --init-ctr once "$IMG" true > /dev/null
    check "create --init-ctr once" 0 $?
    pm create --pod initpod --name always1 --init-ctr always "$IMG" true > /dev/null
    pm create --pod initpod --name main1 "$IMG" sleep 300 > /dev/null
    out=$(pm create --pod initpod --init-ctr sometimes "$IMG" true 2>&1)
    check_match "a bad type" "init-ctr value must be 'always' or 'once'" "$out"
    pm pod start initpod > /dev/null
    check "the pod runs" Running "$(pm pod inspect initpod --format '{{.State}}')"
    check "a once container is removed after it succeeded" 1 "$(pm container exists once1; echo $?)"
    check "an always container is kept, exited" exited "$(pm inspect --format '{{.State.Status}}' always1)"
    check "the main container runs" running "$(pm inspect --format '{{.State.Status}}' main1)"
    started=$(pm inspect --format '{{.State.StartedAt}}' always1)
    pm pod stop -t 0 initpod > /dev/null
    pm pod start initpod > /dev/null
    check "an always container runs at each start" 0 "$([ "$started" != "$(pm inspect --format '{{.State.StartedAt}}' always1)" ]; echo $?)"
    check "the pod is running with an exited init container" Running "$(pm pod inspect initpod --format '{{.State}}')"
    pm pod pause initpod > /dev/null
    check "pause skips the exited init container" Paused "$(pm pod inspect initpod --format '{{.State}}')"
    pm pod unpause initpod > /dev/null
    pm pod rm -t 0 -f initpod > /dev/null
    pm pod create --name failpod > /dev/null
    pm create --pod failpod --name failinit --init-ctr once "$IMG" sh -c 'exit 3' > /dev/null
    pm create --pod failpod --name failmain "$IMG" sleep 300 > /dev/null
    out=$(pm pod start failpod 2>&1)
    check "a failing init container fails the start" 125 $?
    check_match "and says so" "init container .* exited with code 3" "$out"
    check "the other containers did not start" created "$(pm inspect --format '{{.State.Status}}' failmain)"
    pm pod rm -t 0 -f failpod > /dev/null
}

@test "the pod create options of podman reach the pod through the REST API" {
    need_catatonit
    printf '10.9.8.7 base.test\n' > "$WORKDIR/hosts.api"
    pm pod create --name optpod --hosts-file "$WORKDIR/hosts.api" --no-hostname --device /dev/null:/dev/apinull \
        --uts private --share-parent=false --shm-size-systemd 10m > /dev/null
    check "pod create with the options" 0 $?
    check "hosts file" "$WORKDIR/hosts.api" "$(pm pod inspect optpod --format '{{.InfraConfig.HostsFile}}')"
    check "no hostname" true "$(pm pod inspect optpod --format '{{.InfraConfig.NoManageHostname}}')"
    check_match "a member has the device and the base hosts" "^10.9.8.7" \
        "$(pm run --rm --pod optpod "$IMG" sh -c 'test -c /dev/apinull && cat /etc/hosts')"
    pm pod rm -t 0 -f optpod > /dev/null
}
