# SPDX-License-Identifier: Apache-2.0
# End to end tests of the command layout, options and
# output (what podman's Quadlet generator and podman's users write),
# --preserve-fds, build's options, run --rmi and cp, through a daemon of its
# own.  Run it as an ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    E2E_BEFORE_DAEMON=events_in_a_file run_setup_file
}

teardown_file () {
    run_teardown_file
}

# podman's command layout and options: what podman's Quadlet
# generator and podman's users write.
@test "podman's command layout and options" {
    check "run" "hi" "$(sh_ run --rm --network none "$IMAGE" echo hi 2>&1)"
    sh_ run -d --name pl1 --network none "$IMAGE" sleep 100 > /dev/null
    check_match "ps" "pl1" "$(sh_ ps 2>&1)"
    check "exec" "in" "$(sh_ exec pl1 echo in 2>&1)"
    check "exec, the options of the command" "-i -t" "$(sh_ exec pl1 echo -i -t 2>&1)"
    check_match "images" "alpine" "$(sh_ images 2>&1)"
    sh_ rm -t 0 -v -f -i pl1 nosuch > /dev/null
    check "rm -v -f -i, one of them missing" 0 $?
    check "the native layout still works" "hi" "$(sh_ container run --rm --network none "$IMAGE" echo hi 2>&1)"
    # run's pull, the one after an "image not found" too, with --authfile;
    # an auth file that is not there is refused first
    echo '{"auths": {}}' > "$WORKDIR/auth.json"
    other=$E2E_REGISTRY/e2e/alpine:gzip
    # (the test pushes the image it pulls: the shared registry may have been
    # pruned; the registry deletes nothing, images.bats pushes the same one)
    sh_ image push --tls-verify=false --compression-format gzip "$IMAGE" "$other" > /dev/null 2>&1
    sh_ rmi -i "$other" > /dev/null 2>&1
    check "run --authfile -q pulls the image it does not have" "pulled" \
        "$(sh_ run --rm --network none --authfile "$WORKDIR/auth.json" -q "$other" echo pulled 2>&1)"
    sh_ rmi -i "$other" > /dev/null 2>&1
    out=$(sh_ run --rm --network none --authfile "$WORKDIR/nosuch.json" "$other" true 2>&1)
    check "run --authfile of nothing" 125 $?
    check_match "says podman's words" "credential file is not accessible" "$out"
    # what follows the image is the container's, even what looks like an
    # option of run (-t, -c, -v), as podman takes it
    check "the command after the image keeps its options" "-t -v" \
        "$(sh_ run --rm --network none "$IMAGE" sh -c 'echo "$1 $2"' -- -t -v 2>&1)"
    check "-c after the image is the container's" "c" \
        "$(sh_ run --rm --network none -e X=c "$IMAGE" sh -c 'echo $X' 2>&1)"
    out=$(sh_ --storage-opt x=y ps 2>&1)
    check "podman's --storage-opt is refused" 125 $?
    check_match "and says why" "global option --storage-opt is not supported" "$out"

}

@test "podman's command layout: the environment of the caller" {
    out=$(http_proxy=http://proxy:3128 FOO=bar sh_ run --rm --network none "$IMAGE" sh -c 'echo "$http_proxy/$FOO"')
    check "--http-proxy is the default" "http://proxy:3128/" "$out"
    out=$(http_proxy=http://proxy:3128 sh_ run --rm --network none --http-proxy=false "$IMAGE" sh -c 'echo "[$http_proxy]"')
    check "--http-proxy=false" "[]" "$out"
    # (the PATH of the caller too: the shell by its path)
    out=$(FOO=bar sh_ run --rm --network none --env-host -e FOO=mine "$IMAGE" /bin/sh -c 'echo "$FOO"')
    check "--env-host, -e over it" "mine" "$out"
    out=$(FOO=bar sh_ run --rm --network none --env-host "$IMAGE" /bin/sh -c 'echo "$FOO"')
    check "--env-host" "bar" "$out"

}

# the base of /etc/hosts of the configuration, read by the engine of the
# command
@test "podman's command layout: base_hosts_file of the configuration" {
    echo "10.9.8.7 modhost" > "$WORKDIR/mod.hosts"
    { cat "$CONFIG"; printf '[containers]\nbase_hosts_file = "%s"\n' "$WORKDIR/mod.hosts"; } > "$WORKDIR/hosts.toml"
    out=$(sh_ --config "$WORKDIR/hosts.toml" run --no-monitor --rm "$IMAGE" cat /etc/hosts 2>&1)
    check_match "[containers] base_hosts_file" "modhost" "$out"
    out=$(sh_ --module e2e.conf ps 2>&1)
    check "--module is refused" 125 $?
}

@test "podman's command layout: pull and pod create" {
    out=$(sh_ pull --policy missing "$IMAGE" 2>&1)
    check "pull --policy missing of an image that is there prints its id" "$(sh_ inspect --format '{{.ID}}' "$IMAGE")" "$out"
    out=$(sh_ pull --policy never localhost/e2e-nosuch:1 2>&1)
    check_match "pull --policy never of one that is not" "image not known" "$out"
    out=$(sh_ pull --all-tags "$IMAGE" 2>&1)
    check_match "pull --all-tags pulls the tags of the repository" "Trying to pull" "$out"

    # pod create --name
    sh_ pod create --name plpod > /dev/null
    check "pod create --name" 0 $?
    check_match "the pod" "plpod" "$(sh_ pod list -a 2>&1)"
    sh_ pod rm -t 0 -f plpod > /dev/null
}

# podman's network options: --route is taken, and --ip6 and --mac-address of
# connect go to the lookup of the network, which is not there
@test "podman's network options: route, ip6 and mac-address" {
    out=$(sh_ network create --route 10.1.0.0/16,10.0.0.1 e2e-route 2>&1)
    check "network create --route" 0 $?
    check_match "and the route is in the network" '"destination": "10.1.0.0/16"' "$(sh_ network inspect e2e-route 2>&1)"
    sh_ network rm e2e-route > /dev/null 2>&1
    out=$(sh_ network connect --ip6 fd00::5 e2e-nonet e2e-noctr 2>&1)
    check "network connect --ip6" 125 $?
    check_match "network connect --ip6 looks the network up" "unable to find network" "$out"
    out=$(sh_ network connect --mac-address 02:00:00:00:00:05 e2e-nonet e2e-noctr 2>&1)
    check "network connect --mac-address" 125 $?
    check_match "network connect --mac-address looks the network up" "unable to find network" "$out"
}

# podman's output: --format templates, the list options, inspect, exists,
# port, history, version, and the commands refused.
@test "podman's output: --format, list options, inspect, exists" {
    sh_ run -d --name po1 --network none -l k=v "$IMAGE" sleep 100 > /dev/null
    check "ps --format, --filter" "po1 running" "$(sh_ ps --format '{{.Names}} {{.State}}' --filter name=po1 2>&1)"
    check "ps -q --no-trunc" 64 "$(sh_ ps -q --no-trunc --filter name=po1 | tr -d '\n' | wc -c)"
    check_match "ps, a table" "^CONTAINER ID +IMAGE +COMMAND" "$(sh_ ps --format 'table {{.ID}}\t{{.Image}}\t{{.Command}}' | head -1)"
    check "ps --noheading" "" "$(sh_ ps --noheading --format 'table {{.ID}}' --filter name=nosuch 2>&1)"
    check "ps --format json" po1 "$(sh_ ps --format json --filter name=po1 | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["Names"][0])')"
    check "container ls, podman's alias" po1 "$(sh_ container ps --format '{{.Names}}' --filter name=po1 2>&1)"
    check "inspect --format" "running" "$(sh_ inspect --format '{{.State.Status}}' po1 2>&1)"
    check "container inspect --format, index" "v" "$(sh_ container inspect --format '{{index .Config.Labels "k"}}' po1 2>&1)"
    check "inspect --type image" "$IMAGE" "$(sh_ inspect --type image --format '{{index .RepoTags 0}}' "$IMAGE" 2>&1)"
    check_match "inspect, a range with variables" "(^|;)k=v;" "$(sh_ inspect --format '{{range $k, $v := .Config.Labels}}{{$k}}={{$v}};{{end}}' po1 2>&1)"
    out=$(sh_ inspect nosuch 2>&1)
    check "inspect of nothing" 125 $?
    check_match "says so" "no such object" "$out"
    check_match "inspect is podman's array" '^\[' "$(sh_ inspect po1 2>&1)"
    check_match "images --format" "alpine:chunked" "$(sh_ images --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    sh_ container exists po1
    check "container exists" 0 $?
    sh_ container exists nosuch
    check "container exists, not there" 1 $?
    sh_ image exists "$IMAGE"
    check "image exists" 0 $?
    sh_ image exists localhost/nosuch
    check "image exists, not there" 1 $?
    sh_ volume create pov > /dev/null
    sh_ volume exists pov
    check "volume exists" 0 $?
    sh_ run -d --name pov1 --network none -v pov:/v "$IMAGE" sleep 100 > /dev/null
    out=$(sh_ volume rm pov 2>&1)
    rc=$?
    check "volume rm of a volume in use: podman's words and 2" \
        "Error: volume pov is being used by the following container(s): $(sh_ inspect --format '{{.Id}}' pov1): volume is being used 2" "$out $rc"
    sh_ rm -f -t 0 pov1 > /dev/null
    out=$(sh_ volume rm nosuchvol 2>&1)
    check "volume rm of a missing volume: podman's words and 1" 'Error: no volume with name "nosuchvol" found: no such volume 1' "$out $?"
    out=$(sh_ volume rm -t 0 -f nosuchvol 2>&1)
    check "volume rm -f of a missing volume is silent" "0:" "$?:$out"
    sh_ volume create povp > /dev/null
    out=$(sh_ volume prune < /dev/null 2>&1)
    check "volume prune asks, and the end of the input is no" "WARNING! This will remove all volumes not used by at least one container. The following volumes will be removed:
pov
povp
Are you sure you want to continue? [y/N] Error: EOF 125" "$out $?"
    check "volume prune n keeps them" "pov povp" "$(echo n | sh_ volume prune > /dev/null 2>&1; sh_ volume ls -q --filter name=pov | sort | tr '\n' ' ' | sed 's/ $//')"
    check "volume prune lists the names" "pov
povp" "$(sh_ volume prune -f 2>&1 | sort)"
    sh_ volume create pov > /dev/null
    check "volume rm -t -1 --force" "pov" "$(sh_ volume rm -t -1 --force pov 2>&1)"
    sh_ volume create pov > /dev/null
    check "df: podman's rows" "Images Containers Local Volumes" \
        "$(sh_ system df --format '{{.Type}}' 2>&1 | tr '\n' ' ' | sed 's/ $//')"
    check_match "df, a table" "^TYPE +TOTAL +ACTIVE +SIZE +RECLAIMABLE" "$(sh_ system df 2>&1 | head -1)"
    check_match "df --format json" '"Type":"Local Volumes","Total":1,' "$(sh_ system df --format json 2>&1)"
    check_match "df -v" "Local Volumes space usage:" "$(sh_ system df -v 2>&1)"
    sh_ system df --format '{{.Type}}' -v > /dev/null 2>&1
    check "df: --format and --verbose do not go together" 125 $?
    sh_ network exists podman
    check "network exists" 0 $?
    check "network create says its name" ponet "$(sh_ network create ponet 2>&1)"
    out=$(sh_ network rm ponet nosuchnet 2>&1)
    check "network rm: the removed and the missing" "ponet
Error: unable to find network with name or ID nosuchnet: network not found 1" "$out $?"
    out=$(sh_ network rm -t 0 -f nosuchnet 2>&1)
    check "network rm -f of a missing network is silent" "0:" "$?:$out"
    sh_ network create ponet2 > /dev/null
    sh_ create --name ponetc --network ponet2 "$IMAGE" true > /dev/null
    out=$(sh_ network rm ponet2 2>&1)
    check "network rm of a network in use: podman's words and 2" "Error: \"ponet2\" has associated containers with it. Use -f to forcibly delete containers and pods: network is being used 2" "$out $?"
    check "network prune asks" "WARNING! This will remove all networks not used by at least one container.
Are you sure you want to continue? [y/N] ponet2" "$(echo n | sh_ network prune 2>&1; sh_ network ls -q --filter name=ponet2)"
    check "network rm -f removes the network and its containers" "ponet2 1" "$(echo $(sh_ network rm -t 0 -f ponet2 2>&1; sh_ container exists ponetc; echo $?))"
    events=$(sh_ events --filter type=network --since 5m --stream=false 2>&1)
    check_match "the network create event has its ID and type" "network create [0-9a-f]{64} \(name=ponet, type=bridge\)" "$events"
    check_match "the network remove event too" "network remove [0-9a-f]{64} \(name=ponet, type=bridge\)" "$events"
    check "volume ls --format, --filter" "pov" "$(sh_ volume ls --format '{{.Name}}' --filter name=pov 2>&1)"
    check_match "network ls --format" "podman bridge" "$(sh_ network ls --format '{{.Name}} {{.Driver}}' 2>&1)"
    check_match "info --format" "^[0-9]+$" "$(sh_ info --format '{{.Host.Cpus}}' 2>&1)"
    check_match "version" "^Client:" "$(sh_ version 2>&1)"
    check_match "version --format" "^[0-9]+\.[0-9]+" "$(sh_ version --format '{{.Client.Version}}' 2>&1)"
    check_match "history" "CREATED BY" "$(sh_ history "$IMAGE" 2>&1)"
    check_match "history --format" "^(<missing>|[0-9a-f]{12})$" "$(sh_ history --format '{{.ID}}' "$IMAGE" 2>&1 | head -1)"

    check_match "images --format {{.Created}} is the duration" "(ago|Less than a second|seconds?)" "$(sh_ images --format '{{.Created}}' "$IMAGE" 2>&1 | head -1)"
    sh_ run -d --name po2 -p 127.0.0.1:18089:80 "$IMAGE" sleep 100 > /dev/null
    check "port" "80/tcp -> 127.0.0.1:18089" "$(sh_ port po2 2>&1)"
    check "port of one" "127.0.0.1:18089" "$(sh_ port po2 80 2>&1)"
    sh_ port po2 81 > /dev/null 2>&1
    check "port of one not published" 125 $?
    sh_ volume create dupv > /dev/null 2>&1
    check "the same volume twice, the first options win" "ok" "$(sh_ run --rm --network none -v dupv:/x -v dupv:/x:ro "$IMAGE" sh -c 'touch /x/f && echo ok' 2>&1)"
    sh_ volume rm dupv > /dev/null 2>&1
    mkdir -p "$WORKDIR/dupb"
    out=$(sh_ run --rm --network none -v "$WORKDIR/dupb:/x" -v "$WORKDIR/dupb:/x:ro" "$IMAGE" true 2>&1)
    check "a bind twice with other options is refused" 125 $?
    check_match "a bind twice with other options, podman's words" "/x: duplicate mount destination" "$out"
    out=$(sh_ create --network none --dns-opt ndots:2 "$IMAGE" true 2>&1)
    check "--dns-opt with --network none" 125 $?
    check_match "--dns-opt with --network none, podman's words" "conflicting options: dns and the network mode: none" "$out"
    out=$(sh_ create --network container:po1 --dns 10.1.1.1 "$IMAGE" true 2>&1)
    check "--dns with --network container:" 125 $?
    check_match "--dns with --network container:, podman's words" "conflicting options: dns and the network mode: container" "$out"
    out=$(sh_ run --rm -p 18098:80/sctp "$IMAGE" true 2>&1)
    check "run -p /sctp fails at run time" 126 $?
    check_match "run -p /sctp, podman's words" "can't forward protocol: sctp" "$out"

    sh_ create --name po3 --network none -e PO=3 --restart on-failure:2 "$IMAGE" true > /dev/null
    check "create takes the options of run" "PO=3 on-failure" \
        "$(sh_ inspect --format '{{range .Config.Env}}{{if eq . "PO=3"}}{{.}}{{end}}{{end}} {{.HostConfig.RestartPolicy.Name}}' po3 2>&1)"
    check "init" po3 "$(sh_ init po3 2>&1)"
    sh_ pod create --name pop > /dev/null
    sh_ pod start pop > /dev/null
    check "pod restart prints the ID, as podman" "$(sh_ pod inspect --format '{{.Id}}' pop)" "$(sh_ pod restart pop 2>&1)"
    check_match "pod ps --format" "^pop " "$(sh_ pod ps --format '{{.Name}} {{.Status}}' 2>&1)"

    out=$(sh_ machine list 2>&1)
    check "machine is refused" 125 $?
    check_match "and says why" "command .machine. is not supported" "$out"
    out=$(sh_ generate systemd po1 2>&1)
    check "generate systemd is refused" 125 $?
    sh_ rm -t 0 -f po1 po2 po3 > /dev/null 2>&1
    sh_ pod rm -t 0 -f pop > /dev/null 2>&1
    sh_ volume rm pov > /dev/null 2>&1
}

# podman's ways to choose the containers of a command (--latest,
# --cidfile, --filter, --all), rm --depend/--time, wait --condition,
# update, export, mount, exec --env-file, ps --last/--sort/--pod.
@test "podman's ways to choose containers, rm --depend, update, export" {
    sh_ run -d --name pla --network none "$IMAGE" sleep 100 > /dev/null
    sh_ run -d --name plb --network none -l grp=pl "$IMAGE" sleep 100 > /dev/null
    ida=$(sh_ inspect --format '{{.Id}}' pla)
    idb=$(sh_ inspect --format '{{.Id}}' plb)
    check "ps --last" plb "$(sh_ ps --last 1 --format '{{.Names}}' 2>&1)"
    check "ps --sort names" "pla plb" "$(sh_ ps --sort names --filter name=pl --format '{{.Names}}' 2>&1 | tr '\n' ' ' | sed 's/ $//')"
    check_match "ps Status of a running container" "^Up " "$(sh_ ps --filter name=pla --format '{{.Status}}' 2>&1)"
    check_match "ps --pod" "POD ID +PODNAME" "$(sh_ ps --pod 2>&1 | head -1)"
    # (what is chosen, not named, is said by its ID, as podman)
    check "stop --latest" "$idb" "$(sh_ stop -t 0 --latest 2>&1)"
    check_match "ps Status of an exited container" "^Exited \([0-9]+\) " "$(sh_ ps -a --filter name=plb --format '{{.Status}}' 2>&1)"
    sh_ stop --latest pla > /dev/null 2>&1
    check "names and --latest together are refused" 125 $?
    check "pause --filter" "$ida" "$(sh_ pause --filter name=pla 2>&1)"
    check "unpause --filter" "$ida" "$(sh_ unpause --filter name=pla 2>&1)"
    check "restart --filter" "$idb" "$(sh_ restart --filter label=grp=pl 2>&1)"
    check "kill --filter" "$idb" "$(sh_ kill --filter label=grp=pl 2>&1)"
    check "a container by a prefix of its ID" pla "$(sh_ container inspect --format '{{.Name}}' "${ida:0:8}" 2>&1)"
    check "stop by a prefix of its ID" "${ida:0:8}" "$(sh_ stop -t 0 "${ida:0:8}" 2>&1)"
    sh_ start "${ida:0:8}" > /dev/null
    check "wait --condition" 137 "$(sh_ wait --condition stopped plb 2>&1)"
    check "wait --ignore" -1 "$(sh_ wait --ignore nosuch 2>&1)"

    sh_ create --name plc --cidfile "$WORKDIR/plc.cid" --network none "$IMAGE" true > /dev/null
    check "rm --cidfile" "$(cat "$WORKDIR/plc.cid")" "$(sh_ rm --cidfile "$WORKDIR/plc.cid" 2>&1)"
    sh_ rm --ignore --cidfile "$WORKDIR/nosuch.cid" > /dev/null 2>&1
    check "rm --ignore of a cidfile that is not there" 0 $?

    sh_ run -d --name pll --network none --log-driver k8s-file "$IMAGE" sh -c 'echo logline; exec sleep 100' > /dev/null
    wait_log pll logline
    check "ps --latest" pll "$(sh_ ps --latest --format '{{.Names}}' 2>&1)"
    check "inspect --latest" pll "$(sh_ inspect -l --format '{{.Name}}' 2>&1)"
    check "logs --latest" logline "$(sh_ logs --latest 2>&1)"
    check "exec --latest: its first argument is the command" pll-works "$(sh_ exec -l sh -c 'touch /pll-file; echo pll-works' 2>&1)"
    check_match "top: podman's descriptors" "^USER +PID +PPID +%CPU +ELAPSED +TTY +TIME +COMMAND" "$(sh_ top pll 2>&1 | head -1)"
    check_match "top --latest, the ps options after it" "^PID +COMMAND" "$(sh_ top -l -eo pid,comm 2>&1 | head -1)"
    check_match "top: the descriptors of a list" "^root +1 +0 +0.000" "$(sh_ top pll user,pid,ppid,pcpu 2>&1 | tail -n +2 | head -1)"
    check_match "diff --latest" "^A /pll-file$" "$(sh_ diff -l 2>&1 | grep pll-file)"
    sh_ logs --latest pla > /dev/null 2>&1
    check "logs: names and --latest together are refused" 125 $?
    sh_ rm -f -t 0 pll > /dev/null 2>&1

    echo PLE=fromfile > "$WORKDIR/pl.env"
    check "exec --env-file" fromfile "$(sh_ exec --env-file "$WORKDIR/pl.env" pla sh -c 'echo $PLE' 2>&1)"
    plaid=$(sh_ inspect --format '{{.Id}}' pla 2>&1)
    check "update prints the full ID" "$plaid" "$(sh_ update --pids-limit 50 --restart always pla 2>&1)"
    check "update changed them" "50 always" "$(sh_ inspect --format '{{.HostConfig.PidsLimit}} {{.HostConfig.RestartPolicy.Name}}' pla 2>&1)"
    sh_ update --restart no pla > /dev/null
    check "update --health-*" "$plaid" "$(sh_ update --health-cmd 'echo ok' --health-interval 7s --health-retries 4 --health-on-failure kill pla 2>&1)"
    check "update changed the health check" "[CMD-SHELL echo ok] 7s 4" \
        "$(sh_ inspect --format '{{.Config.Healthcheck.Test}} {{.Config.Healthcheck.Interval}} {{.Config.Healthcheck.Retries}}' pla 2>&1)"
    check "json of a duration: the nanoseconds" "7000000000" "$(sh_ inspect --format '{{json .Config.Healthcheck.Interval}}' pla 2>&1)"
    check "update --no-healthcheck" "[NONE]" "$(sh_ update --no-healthcheck pla > /dev/null 2>&1; sh_ inspect --format '{{.Config.Healthcheck.Test}}' pla 2>&1)"
    check "update --ulimit" "$plaid" "$(sh_ update --ulimit nofile=1000:2000 pla 2>&1)"
    check "update --ulimit host" "$plaid" "$(sh_ update --ulimit host pla 2>&1)"
    # (the io controller is delegated to root only: what the runtime
    # refuses for the running container is not recorded)
    sh_ update --blkio-weight 300 pla > /dev/null 2>&1
    if [ "$(id -u)" = 0 ]; then
        check "update --blkio-weight is shown" 300 "$(sh_ inspect --format '{{.HostConfig.BlkioWeight}}' pla 2>&1)"
    else
        check "a refused update --blkio-weight is not shown" 0 "$(sh_ inspect --format '{{.HostConfig.BlkioWeight}}' pla 2>&1)"
    fi
    check "run --ulimit host" "ok" "$(sh_ run --rm --network none --ulimit host "$IMAGE" echo ok 2>&1)"
    sh_ create --name plc -p 18097:80 "$IMAGE" true > /dev/null 2>&1
    check "port of a created container lists nothing" "" "$(sh_ port plc 2>&1)"
    sh_ start plc > /dev/null 2>&1
    sh_ wait plc > /dev/null 2>&1
    check "port of an exited container lists nothing" "" "$(sh_ port plc 2>&1)"
    sh_ rm -t 0 -f plc > /dev/null 2>&1
    check_match "update --ulimit, podman's words" "failed to be parsed: invalid ulimit argument" "$(sh_ update --ulimit nofile:1 pla 2>&1)"
    out=$(sh_ update --device-read-bps nosuchdev:1mb pla 2>&1)
    check "update --device-read-bps of no device" 125 $?
    sh_ update -l --restart no > /dev/null 2>&1
    check "update --latest" 0 $?
    sh_ export -o "$WORKDIR/pl.tar" pla
    check "export" 0 $?
    check_match "export has the root file system" "etc/passwd" "$(tar tf "$WORKDIR/pl.tar" 2>&1)"
    rm -f "$WORKDIR/pl.tar"
    if [ "$(id -u)" = 0 ]; then
        dir=$(sh_ mount pla 2>&1)
        check "mount" yes "$(test -f "$dir/etc/passwd" && echo yes)"
        check "unmount" pla "$(sh_ unmount pla 2>&1)"
    fi

    sh_ create --name pld --requires pla --network none "$IMAGE" true > /dev/null
    out=$(sh_ rm -f -t 0 --depend pla 2>&1)
    check "rm --depend removes the dependents first" "2 pla" "$(echo "$out" | wc -l) $(echo "$out" | tail -1)"
    sh_ container exists pld
    check "the dependent is gone" 1 $?
    sh_ rm -f -t 0 plb > /dev/null 2>&1
    check "rm -t" 0 $?
}

# --preserve-fds N and --preserve-fd FD[,FD]: podman's checks and messages,
# the descriptors under the same numbers, holes left closed.
# (not through sh_, which closes 3, and with 4 closed: bats keeps it open)
@test "--preserve-fds and --preserve-fd" {
    out=$("$SH" 4>&- run --rm --network none --preserve-fds 5 "$IMAGE" true 2>&1 3< /dev/null)
    check "--preserve-fds: a missing descriptor" "Error: file descriptor 4 is not available - the preserve-fds option requires that file descriptors must be passed 125" "$out $?"
    out=$("$SH" 4>&- run --rm --network none --preserve-fd 7 "$IMAGE" true 2>&1)
    check "--preserve-fd: a missing descriptor" "Error: file descriptor 7 is not available - the preserve-fd option requires that file descriptors must be passed" "$out"
    "$SH" 4>&- run --rm --network none --preserve-fds 1 --preserve-fd 3 "$IMAGE" true 3< /dev/null > /dev/null 2>&1
    check "both options" 125 $?
    "$SH" 4>&- run --rm --network none --preserve-fd 1 "$IMAGE" true > /dev/null 2>&1
    check "--preserve-fd 1" 126 $?
    out=$("$SH" 4>&- run --rm --network none --preserve-fds 2 "$IMAGE" sh -c 'cat <&3; cat <&4' 3<<< one 4<<< two 2>&1)
    check "--preserve-fds: the container reads 3 and 4" "one two" "$(echo $out)"
    out=$("$SH" 4>&- run --rm --network none --preserve-fd 3,5 "$IMAGE" sh -c 'cat <&3; cat <&5; test -e /proc/self/fd/4 && echo open || echo closed' 3<<< one 5<<< five 2>&1)
    check "--preserve-fd: the numbers are kept, the hole is closed" "one five closed" "$(echo $out)"
    out=$(LISTEN_FDS=1 LISTEN_PID=$$ "$SH" 4>&- run --rm --network none --preserve-fds 1 "$IMAGE" sh -c 'env | grep -c LISTEN; cat <&3' 3<<< one 2>&1)
    check_match "LISTEN_FDS is ignored with a warning" "Ignoring LISTEN_FDS to preserve custom user-specified FDs" "$out"
    check_match "the container gets its descriptor, no LISTEN_*" "0 one|^0$" "$(echo "$out" | tail -2 | tr '\n' ' ')"
    "$SH" 4>&- --socket "$WORKDIR/x.sock" run --rm --preserve-fds 1 "$IMAGE" true 3< /dev/null > /dev/null 2>&1
    check "--preserve-fds does not go through a named socket" 125 $?
}

# build's options as podman's: the RUN containers, the image, the Containerfile
# on the standard input or beside the context, the messages.
@test "build's options as podman's" {
    ctx=$WORKDIR/bf
    mkdir -p "$ctx/vol"
    echo volfile > "$ctx/vol/f"
    # (z: under SELinux a directory of the host is the containers' only
    # once relabeled, as with podman)
    printf '# a comment\nX=fromfile\n' > "$ctx/args"
    printf 'FROM %s\nARG X=default\nRUN echo "x=$X" > /x.txt && ulimit -n > /n.txt && cat /etc/hosts > /h.txt && cat /etc/resolv.conf > /r.txt && cat /vol/f > /f.txt && echo "e3=$E3" > /e.txt\nENV E1=one E2=two\n' "$IMAGE" > "$ctx/Containerfile"
    sh_ build -q -t localhost/bf:1 --build-arg-file "$ctx/args" --ulimit nofile=101:102 --add-host bfhost:1.2.3.4 \
        --dns-search bf.search -v "$ctx/vol:/vol:ro,z" --env E3=three --unsetenv E1 --jobs 2 "$ctx" > /dev/null 2>&1
    check "build with the options of podman's" 0 $?
    check "build-arg-file" "x=fromfile" "$(sh_ run --rm --network none localhost/bf:1 cat /x.txt 2>&1)"
    check "--ulimit" 101 "$(sh_ run --rm --network none localhost/bf:1 cat /n.txt 2>&1)"
    check_match "--add-host" "1.2.3.4[[:space:]]+bfhost" "$(sh_ run --rm --network none localhost/bf:1 cat /h.txt 2>&1)"
    check_match "--dns-search" "search bf.search" "$(sh_ run --rm --network none localhost/bf:1 cat /r.txt 2>&1)"
    check "--volume" volfile "$(sh_ run --rm --network none localhost/bf:1 cat /f.txt 2>&1)"
    env=$(sh_ run --rm --network none localhost/bf:1 env 2>&1)
    check_match "--env" "E3=three" "$env"
    check "--env reaches the RUN steps" "e3=three" "$(sh_ run --rm --network none localhost/bf:1 cat /e.txt 2>&1)"
    check "--unsetenv" 0 "$(echo "$env" | grep -c '^E1=')"
    out=$(sh_ build -q --format oci -v "$ctx/vol:/vol:ro,z" -t localhost/bf:2 "$ctx" 2>&1)
    check "build --format oci" 0 $?
    out=$(sh_ build -q --format docker -t localhost/bf:docker "$ctx" 2>&1; echo "rc=$?")
    check "build --format docker is refused" "Error: the format docker: Docker image formats are not supported: only OCI images (application/vnd.oci.image.*)
rc=125" "$out"
    sh_ image exists localhost/bf:docker
    check "no image of the refused build" 1 $?
    out=$(sh_ build --format zip "$ctx" 2>&1)
    check_match "--format that is none" "unrecognized image type" "$out"
    out=$(sh_ build --squash --squash-all "$ctx" 2>&1)
    check "--squash and --squash-all" "Error: cannot specify --squash-all with --squash" "$out"
    out=$(sh_ build --sign-by me "$ctx" 2>&1)
    check_match "an option that velarx's build has not" "not supported by velarx's build yet: --sign-by" "$out"
    mkdir "$ctx/in"
    printf 'FROM scratch\n' > "$ctx/in/Containerfile"
    echo '*' > "$ctx/in/.dockerignore"
    sh_ build -q -t localhost/bf:3 "$ctx/in" > /dev/null 2>&1
    check "an ignore file of everything keeps the Containerfile" 0 $?
    printf 'FROM %s\nRUN echo stdin\n' "$IMAGE" | sh_ build -q -t localhost/bf:4 -f - "$ctx/in" > /dev/null 2>&1
    check "-f - reads the Containerfile on the standard input" 0 $?
    mv "$ctx/in/Containerfile" "$ctx/in/foofile"
    out=$(sh_ build "$ctx/in" 2>&1)
    check "no Containerfile in the context" "Error: no Containerfile or Dockerfile specified or found in context directory, $ctx/in: no such file or directory" "$out"
    out=$(cd "$ctx" && sh_ build -f Containerfile2 "$ctx" 2>&1)
    check_match "-f that is not there" "Containerfile2: no such file or directory" "$out"
    (cd "$ctx/in" && sh_ build -q -t localhost/bf:5 -f foofile . > /dev/null 2>&1)
    check "-f relative to the context" 0 $?
    printf 'FROM %s\nCOPY nosuchdir ./\n' "$IMAGE" > "$ctx/Containerfile"
    out=$(sh_ build "$ctx" 2>&1)
    check_match "a failed step says building at STEP" 'Error: building at STEP "COPY nosuchdir ./"' "$out"
    sh_ build --logfile "$WORKDIR/bf.log" -t localhost/bf:6 -f "$ctx/in/foofile" "$ctx/in" > /dev/null 2>&1
    check_match "--logfile gets the output" "STEP 1/" "$(cat "$WORKDIR/bf.log" 2>&1)"
    sh_ rmi -f localhost/bf:1 localhost/bf:2 localhost/bf:3 localhost/bf:4 localhost/bf:5 localhost/bf:6 > /dev/null 2>&1
    sh_ run --name bfc --network none "$IMAGE" true > /dev/null 2>&1
    out=$(sh_ commit -q -m msg bfc localhost/bfc:1 2>&1; echo "rc=$?")
    check "commit with a message is podman's error" "Error: messages are only compatible with the docker image format (-f docker)
rc=125" "$out"
    sh_ commit -q bfc localhost/bfc:1 > /dev/null 2>&1
    check "commit" 0 $?
    out=$(sh_ commit -q -f docker bfc localhost/bfc:2 2>&1; echo "rc=$?")
    check "commit --format docker is refused" "Error: the format docker: Docker image formats are not supported: only OCI images (application/vnd.oci.image.*)
rc=125" "$out"
    sh_ rm -f -t 0 bfc > /dev/null 2>&1
    sh_ rmi -f localhost/bfc:1 > /dev/null 2>&1
}

# run --rmi: the image goes with the container unless another container uses it
@test "run --rmi" {
    sh_ container run --name rmi-base --network none "$IMAGE" true > /dev/null 2>&1
    sh_ commit -c 'LABEL n=1' rmi-base localhost/rmi-img:1 > /dev/null 2>&1
    sh_ commit -c 'LABEL n=2' rmi-base localhost/rmi-img:2 > /dev/null 2>&1
    sh_ container rm rmi-base > /dev/null 2>&1
    sh_ container run --name rmi-keep --network none localhost/rmi-img:1 true > /dev/null 2>&1
    sh_ container run --rmi --network none localhost/rmi-img:1 true > /dev/null 2>&1
    check "run --rmi of an image another container uses: no error" 0 $?
    sh_ image exists localhost/rmi-img:1
    check "the image stays" 0 $?
    sh_ container rm rmi-keep > /dev/null 2>&1
    sh_ container run --rmi --network none localhost/rmi-img:1 true > /dev/null 2>&1
    sh_ image exists localhost/rmi-img:1
    check "run --rmi removes the image before it ends" 1 $?
    out=$(sh_ container run --rmi --rm=false --network none localhost/rmi-img:2 true 2>&1)
    check "--rmi with --rm=false is refused" 125 $?
    check "and says why" "Error: the --rmi option does not work without --rm" "$out"
    sh_ tag localhost/rmi-img:2 localhost/rmi-img:3 > /dev/null 2>&1
    sh_ container run --rmi --network none localhost/rmi-img:3 true > /dev/null 2>&1
    check "run --rmi of a name of an image with others: the name goes" 1 "$(sh_ image exists localhost/rmi-img:3; echo $?)"
    check "the image stays with its other names" 0 "$(sh_ image exists localhost/rmi-img:2; echo $?)"
    check "the image of the others stays" 0 "$(sh_ image exists "$IMAGE"; echo $?)"
    # (the events are kept in a file: the monitor writes the ones of the
    # image it removes there, and tells them to the daemon, which streams
    # them; the stream starts from now, whenever it is ready)
    "$SH" events --stream --since "$(date +%s.%N)" > "$WORKDIR/rmi.ev" 2>&1 3>&- &
    local ev=$!
    sh_ container run -d --name rmi-d --rmi --network none localhost/rmi-img:2 sleep 100 > /dev/null 2>&1
    e2e_wait_line "$WORKDIR/rmi.ev" 'container create .*name=rmi-d' 30 || e2e_die "the events stream does not start"
    check "inspect says AutoRemoveImage" "true true" "$(sh_ inspect --format '{{.HostConfig.AutoRemoveImage}} {{.HostConfig.AutoRemove}}' rmi-d 2>&1)"
    sh_ container stop -t 0 rmi-d > /dev/null 2>&1
    e2e_wait_line "$XDG_DATA_HOME/velarx/events/events.log" '"Status":"untag".*rmi-img:2'
    check "a detached run --rmi of the last name writes the untag event" 0 $?
    e2e_wait_line "$XDG_DATA_HOME/velarx/events/events.log" '"Status":"remove".*rmi-img:2'
    check "and the remove event of the image" 0 $?
    e2e_wait_line "$WORKDIR/rmi.ev" 'image untag .*rmi-img:2' 30
    check "the stream of the daemon has the untag event" 0 $?
    e2e_wait_line "$WORKDIR/rmi.ev" 'image remove .*rmi-img:2' 30
    check "and the remove event" 0 $?
    kill "$ev"
    wait "$ev"
    sh_ image exists localhost/rmi-img:2
    check "a detached run --rmi removes the image at its end" 1 $?
}

# cp as podman's: --overwrite, -a=false, the standard input, and no write
# through a link of the archive or the destination
@test "cp" {
    sh_ run -d --name cpc --network none "$IMAGE" sh -c 'mkdir -p /t/f /e; echo z > /t/d; sleep 1000' > /dev/null
    local h=$WORKDIR/cp
    rm -rf "$h"
    mkdir -p "$h/src/d" "$h/out" "$h/victim"
    echo f > "$h/src/f"
    echo dd > "$h/src/d/x"
    sh_ exec cpc timeout 30 sh -c 'until test -d /e; do :; done'
    out=$(sh_ cp "$h/src/f" cpc:/t/ 2>&1)
    check "cp: a file does not replace a directory" 125 $?
    check_match "in podman's words" 'error creating "/t/f": cannot overwrite directory with a file: file exists' "$out"
    sh_ cp --overwrite "$h/src/f" cpc:/t/ > /dev/null 2>&1
    check "cp --overwrite: it does" "f" "$(sh_ exec cpc cat /t/f 2>&1)"
    sh_ cp -a=false "$h/src/f" cpc:/tmp/own > /dev/null 2>&1
    check "cp -a=false" 0 $?
    out=$(echo hi | sh_ cp - cpc:/tmp 2>&1)
    check "cp - of no tar" "Error: source must be a (compressed) tar archive when copying from stdin" "$out"
    out=$(tar cf - -C "$h/src" f | sh_ cp - cpc:/t/d 2>&1)
    check "cp - to a file" "Error: destination must be a directory when copying from stdin" "$out"
    out=$(sh_ cp cpc:/etc/hostname /dev/null 2>&1)
    check "cp to a device" 'Error: invalid destination: "/dev/null" must be a directory or a regular file' "$out"
    # an archive with a link out of the container and a file through it
    python3 -I - "$h/evil.tar" "$h/victim" <<'PY'
import io, sys, tarfile
t = tarfile.open(sys.argv[1], "w")
ln = tarfile.TarInfo("lnk"); ln.type = tarfile.SYMTYPE; ln.linkname = sys.argv[2]; t.addfile(ln)
f = tarfile.TarInfo("lnk/ESCAPE"); f.size = 1; t.addfile(f, io.BytesIO(b"x"))
t.close()
PY
    sh_ cp - cpc:/e < "$h/evil.tar" > /dev/null 2>&1
    check "cp - writes nothing through a link of the archive" "" "$(ls "$h/victim")"
    # a link of the destination is replaced, not followed
    ln -s "$h/victim" "$h/out/d"
    sh_ exec cpc sh -c 'mkdir -p /o/d && echo pwn > /o/d/new'
    sh_ cp cpc:/o/. "$h/out" > /dev/null 2>&1
    check "cp out: no file through a link of the host" "" "$(ls "$h/victim")"
    sh_ cp --overwrite cpc:/o/. "$h/out" > /dev/null 2>&1
    check "cp out --overwrite: the link replaced" "pwn" "$(test -L "$h/out/d" || cat "$h/out/d/new"; ls "$h/victim")"
    sh_ rm -f -t 0 cpc > /dev/null 2>&1
    rm -rf "$h"
}
