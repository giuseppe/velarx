# SPDX-License-Identifier: Apache-2.0
# Small differences of the command line from podman's: the words, the exit
# statuses and the options of podman 5 that velarx takes as podman does,
# through a daemon of its own.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

teardown () {
    run_test_teardown
}

@test "exec: the session ID of -d, podman's words" {
    sh_ container run -d --name ex --network none "$IMAGE" sleep 300 > /dev/null
    out=$(sh_ container exec -d ex true 2>&1)
    check "exec -d" 0 $?
    check_match "prints the ID of the exec session" "^[0-9a-f]{64}$" "$out"
    out=$(sh_ container exec ex 2>&1)
    check "exec without a command" 125 $?
    check "in podman's words" "Error: must provide a non-empty command to start an exec session" "$out"
    for opt in "" -d -i; do
        out=$(sh_ container exec $opt nosuch true 2>&1)
        check "exec $opt of no container" 125 $?
        check "exec $opt: podman's words" 'Error: no container with name or ID "nosuch" found: no such container' "$out"
    done
    sh_ container rm -f -t 0 ex > /dev/null
}

@test "rm and pod rm of a name that is not there: podman's words" {
    out=$(sh_ container rm nosuch 2>&1)
    check "rm" 1 $?
    check "rm: ID or name" 'Error: no container with ID or name "nosuch" found: no such container' "$out"
    out=$(sh_ container stop nosuch 2>&1)
    check "stop: name or ID" 'Error: no container with name or ID "nosuch" found: no such container' "$out"
    out=$(sh_ pod rm nosuch 2>&1)
    check "pod rm: no quotes" 'Error: no pod with name or ID nosuch found: no such pod' "$out"
}

@test "two --mount on one destination are refused, -v and --mount are merged" {
    out=$(sh_ container create --mount type=volume,src=dupv,dst=/x --mount type=volume,src=dupv,dst=/x,ro "$IMAGE" true 2>&1)
    check "--mount twice" 125 $?
    check "in podman's words" "Error: /x: duplicate mount destination" "$out"
    out=$(sh_ container create --mount type=tmpfs,dst=/t --mount type=tmpfs,dst=/t "$IMAGE" true 2>&1)
    check "the same tmpfs twice too" 125 $?
    id=$(sh_ container create -v dupv:/x --mount type=volume,src=dupv,dst=/x "$IMAGE" true 2>&1)
    check_match "-v and --mount of one volume" "^[0-9a-f]{64}$" "$id"
    sh_ container rm "$id" > /dev/null
}

@test "--health-interval=disable: no timer, healthcheck run checks" {
    sh_ container run -d --name hd --health-cmd true --health-interval=disable --network none "$IMAGE" sleep 300 > /dev/null
    check "created" 0 $?
    # (with a timer of 0 the checks would run at once and without end)
    check "no check ran: podman's health of one that has not run" "starting 0" \
        "$(sh_ container inspect --format '{{.State.Health.Status}} {{len .State.Health.Log}}' hd)"
    sh_ healthcheck run hd > /dev/null
    check "healthcheck run" 0 $?
    check "one check ran" "healthy 1" "$(sh_ container inspect --format '{{.State.Health.Status}} {{len .State.Health.Log}}' hd)"
    sh_ container rm -f -t 0 hd > /dev/null
}

@test "prune --filter of containers, volumes and networks" {
    sh_ container create --name pk --label prune=yes "$IMAGE" true > /dev/null
    sh_ container create --name pn "$IMAGE" true > /dev/null
    # (a filter that would select everything is refused before anything goes)
    for f in until=garbage label "until=1h --filter until=2h"; do
        # shellcheck disable=SC2086
        out=$(sh_ container prune -f --filter $f 2>&1)
        check "container prune --filter $f" 125 $?
        check "nothing went ($f)" "pk pn" "$(sh_ container ps -a --format '{{.Names}}' | grep -E '^(pk|pn)$' | sort | xargs)"
    done
    check "in podman's words" 'Error: specify exactly one timestamp for until' "$out"
    out=$(sh_ system prune -f --filter until=garbage 2>&1)
    check "system prune --filter until=garbage" 'Error: failed to parse value as time or duration: "garbage" 125' "$out $?"
    out=$(sh_ volume prune -f --filter label 2>&1)
    check "volume prune --filter without a value" 'Error: filter input must be in the form of filter=value: label is invalid 125' "$out $?"
    out=$(sh_ container prune -f --filter label=prune=yes 2>&1)
    check_match "container prune --filter prints the IDs only" "^[0-9a-f]{64}$" "$out"
    check "the other stays" "pn" "$(sh_ container ps -a --format '{{.Names}}' | grep -x pn)"
    sh_ container rm pn > /dev/null
    sh_ volume create --label prune=yes pv1 > /dev/null
    sh_ volume create pv2 > /dev/null
    check "volume prune --filter" "pv1" "$(sh_ volume prune -f --filter label=prune=yes 2>&1)"
    check "the other volume stays" "pv2" "$(sh_ volume ls -q | grep -x pv2)"
    sh_ volume rm pv2 > /dev/null
    sh_ network create --label prune=yes pnet1 > /dev/null
    sh_ network create pnet2 > /dev/null
    check "network prune --filter" "pnet1" "$(sh_ network prune -f --filter label=prune=yes 2>&1)"
    check "the other network stays" "pnet2" "$(sh_ network ls --format '{{.Name}}' | grep -x pnet2)"
    sh_ network rm pnet2 > /dev/null
    out=$(sh_ volume prune -f --filter bogus=1 2>&1)
    check "a filter podman does not know" 125 $?
    check "in podman's words" 'Error: "bogus" is an invalid volume filter' "$out"
}

@test "mount: the list, --all, --latest, --format json, --no-trunc; unmount --all" {
    sh_ container run -d --name mt --network none "$IMAGE" sleep 300 > /dev/null
    id=$(sh_ container inspect --format '{{.Id}}' mt)
    path=$(sh_ container mount mt)
    check "mount prints where" 0 $?
    check "mount lists the mounted containers" "${id:0:12}	$path" "$(sh_ container mount)"
    check "--no-trunc" "$id	$path" "$(sh_ container mount --no-trunc)"
    check "--format json" "$id mt $path" \
        "$(sh_ container mount --format json | jq -r '.[] | "\(.id) \(.Names[0]) \(.mountpoint)"')"
    out=$(sh_ container mount --format '{{.ID}}' 2>&1)
    check "another format" 'Error: unknown --format argument: "{{.ID}}"' "$out"
    check "--latest" "$path" "$(sh_ container mount -l)"
    out=$(sh_ container mount -a mt 2>&1)
    check "--all with a name" "Error: no arguments are needed with --all" "$out"
    out=$(sh_ container unmount 2>&1)
    check "unmount of nothing" "Error: you must provide at least one name or id" "$out"
    check "unmount --all prints the IDs" "$id" "$(sh_ container unmount --all)"
    check "nothing is mounted" "" "$(sh_ container mount)"
    sh_ container rm -f -t 0 mt > /dev/null
}

@test "inspect --size, volume inspect --all, secret inspect --pretty" {
    sh_ container create --name sz "$IMAGE" true > /dev/null
    check_match "container inspect --size" "^[0-9]+ [1-9][0-9]*$" \
        "$(sh_ container inspect --size --format '{{.SizeRw}} {{.SizeRootFs}}' sz)"
    check_match "inspect -s" "^[0-9]+ [1-9][0-9]*$" \
        "$(sh_ inspect -s --format '{{.SizeRw}} {{.SizeRootFs}}' sz)"
    sh_ container rm sz > /dev/null
    sh_ volume create via > /dev/null
    check "volume inspect --all" "via" "$(sh_ volume inspect --all --format '{{.Name}}' | grep -x via)"
    out=$(sh_ volume inspect --all via 2>&1)
    check "--all with a name" "Error: provide one or more volume names or use --all" "$out"
    sh_ volume rm via > /dev/null
    printf data | sh_ secret create --label k=v sp - > /dev/null
    out=$(sh_ secret inspect --pretty sp)
    check_match "secret inspect --pretty" "^ID: +[0-9a-f]+
Name: +sp
Labels:
 - k=v
Driver: +file
Created at: " "$out"
    sh_ secret rm sp > /dev/null
}

@test "podman's global options after the command" {
    out=$(sh_ container run --rm --runtime "$(command -v crun)" --network none "$IMAGE" echo ran 2>&1)
    check "run --runtime" "ran" "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" echo --runtime x 2>&1)
    check "the command's own arguments stay" "--runtime x" "$out"
    out=$(sh_ container run --rm --runtime "$(command -v crun)" --network none "$IMAGE" echo --runtime 2>&1)
    check "with the option given too" "--runtime" "$out"
    out=$(sh_ container run --rm --syslog "$IMAGE" true 2>&1)
    check "a global option velarx has not" 125 $?
    check_match "is refused by name" "global option --syslog is not supported" "$out"
}

@test "ps and system df -v: the oldest first, podman's states, Go's CreatedAt" {
    sh_ container create --name old1 "$IMAGE" true > /dev/null
    sh_ container run --name new1 --network none "$IMAGE" true > /dev/null
    check "ps -a lists the oldest first" "old1 new1" "$(sh_ container ps -a --format '{{.Names}}' | grep -E '^(old1|new1)$' | xargs)"
    check "ps --last 1 the newest" "new1" "$(sh_ container ps -a --last 1 --format '{{.Names}}')"
    check_match "{{.CreatedAt}} is Go's time" "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ [-+][0-9]{4} " \
        "$(sh_ container ps -a --format '{{.CreatedAt}}' | head -1)"
    check_match "the JSON has the time since" " ago$" \
        "$(sh_ container ps -a --format json | jq -r '.[0].CreatedAt')"
    out=$(sh_ system df -v | sed -n '/^Containers space usage/,/^Local Volumes/p' | awk '$NF ~ /^(old1|new1)$/ { print $(NF-1), $NF }' | xargs)
    check "system df -v: the oldest first, exited not stopped" "created old1 exited new1" "$out"
    sh_ container rm old1 new1 > /dev/null
}

@test "images: .History and --history, the names an image had" {
    sh_ image tag "$IMAGE" hist1:latest
    sh_ image tag "$IMAGE" hist2:latest
    out=$(sh_ image list --format '{{.History}}' localhost/hist2:latest)
    check_match "the last name given first" "^localhost/hist2:latest, localhost/hist1:latest, .*$IMAGE" "$out"
    check_match "image inspect .NamesHistory" "^\\[localhost/hist2:latest localhost/hist1:latest " \
        "$(sh_ image inspect --format '{{.NamesHistory}}' localhost/hist2:latest)"
    check_match "--history adds the column" "HISTORY$" "$(sh_ image list --history | head -1)"
    sh_ image untag "$IMAGE" hist1:latest hist2:latest
    check_match "a name that went stays in the history" "localhost/hist2:latest" \
        "$(sh_ image list --format '{{.History}}' "$IMAGE")"
}

@test "a store used with another run root is refused, in podman's words" {
    local s=$WORKDIR/runroot-store
    "$SH" --root "$s/root" --runroot "$s/run1" image list -q > /dev/null
    check "the first run root" 0 $?
    "$SH" --root "$s/root" --runroot "$s/run1" image list -q > /dev/null
    check "the same run root again" 0 $?
    out=$("$SH" --root "$s/root" --runroot "$s/run2" image list -q 2>&1)
    check "another run root" 125 $?
    check "podman's words" "Error: database run root \"$s/run1\" does not match our run root \"$s/run2\": database configuration mismatch" "$out"
}

@test "podman's bats: options that exclude each other, --env PREFIX*, /NAME, stop's warning" {
    for pair in "--cpu-period=1 --cpus=2|--cpu-period and --cpus" \
                "--cpus=2 --cpu-quota=1|--cpu-quota and --cpus" \
                "--no-hosts --add-host=foo:1.1.1.1|--no-hosts and --add-host"; do
        # shellcheck disable=SC2086
        out=$(sh_ container create ${pair%%|*} "$IMAGE" 2>&1)
        check "create ${pair%%|*}" "Error: ${pair#*|} cannot be set together 125" "$out $?"
    done
    out=$(ENVGLOB_a=1 ENVGLOB_b=2 ENVGLOB=3 sh_ container run --rm --env 'ENVGLOB*' --env 'NOT*SET' \
        --network none "$IMAGE" sh -c 'env | grep -E "^(ENVGLOB|NOT)" | sort | xargs')
    check "--env PREFIX* passes the caller's variables of that prefix" "ENVGLOB=3 ENVGLOB_a=1 ENVGLOB_b=2" "$out"
    sh_ container create --name /slashed "$IMAGE" true > /dev/null
    check "/NAME is the name" "slashed" "$(sh_ container inspect --format '{{.Name}}' /slashed)"
    check "rm /NAME" "/slashed" "$(sh_ container rm /slashed 2>&1)"
    sh_ container run -d --rm --name sw --network none "$IMAGE" sleep 100 > /dev/null
    out=$(sh_ container stop -t 1 sw 2>&1)
    check_match "stop of a --rm container that SIGTERM did not stop: podman's warning" \
        "StopSignal SIGTERM failed to stop container sw in 1 seconds, resorting to SIGKILL" "$out"
}

@test "podman's bats: exec --preserve-fd of a high descriptor, the runtime as given, df {{json .}}" {
    sh_ container run -d --name hf --network none "$IMAGE" sleep 300 > /dev/null
    echo far > "$WORKDIR/fd40"
    # (the holes are no descriptors of the call: 9 and 40 pass)
    out=$("$SH" container exec --preserve-fd=9,40 hf sh -c 'ls /proc/self/fd | xargs; cat <&9; cat <&40' \
        9<<<"fd9" 10< /dev/null 40< "$WORKDIR/fd40" 2>&1)
    check "--preserve-fd=9,40" "0 1 2 3 40 9
fd9
far" "$out"
    sh_ container rm -f -t 0 hf > /dev/null
    cp --preserve "$(command -v crun)" "$WORKDIR/myruntime"
    id=$(sh_ container run -d --runtime "$WORKDIR/myruntime" --network none "$IMAGE" sleep 300)
    check "inspect shows the runtime as given" "$WORKDIR/myruntime" "$(sh_ container inspect --format '{{.OCIRuntime}}' "$id")"
    sh_ container rm -f -t 0 "$id" > /dev/null
    check_match "df {{json .}}: Type first, as podman" '^\{"Type":"Local Volumes","Total":' \
        "$(sh_ system df --format '{{json .}}' | tail -1)"
}

@test "network create --route: podman's checks, the routes in inspect" {
    for r in bad 10.0.0.0/24 x,10.89.5.5 10.0.0.1/24,10.89.5.5 10.0.0.0/24,x 10.0.0.0/24,10.89.5.5,x; do
        out=$(sh_ network create --route "$r" rt0 2>&1)
        check "route $r" 125 $?
        check_match "route $r: podman's words" "^Error: (invalid route|route destination invalid)" "$out"
    done
    check "no network was made" "" "$(sh_ network ls --format '{{.Name}}' | grep -x rt0)"
    sh_ network create --subnet 10.213.45.0/24 --route 10.0.0.0/24,10.213.45.5 --route 10.1.0.0/16,10.213.45.6,100 rt1 > /dev/null
    check "network create --route" 0 $?
    check "the routes in inspect" "10.0.0.0/24 10.213.45.5 null
10.1.0.0/16 10.213.45.6 100" \
        "$(sh_ network inspect rt1 | jq -r '.[0].routes[] | "\(.destination) \(.gateway) \(.metric)"')"
    out=$(sh_ network create -d host --route 10.0.0.0/24,10.213.45.5 rt2 2>&1)
    check "a route needs a bridge network" 125 $?
    sh_ network rm rt1 > /dev/null
}

@test "network reload: podman's checks and words" {
    out=$(sh_ network reload 2>&1)
    check "reload of nothing" "Error: you must provide at least one name or id 125" "$out $?"
    out=$(sh_ network reload -a -l 2>&1)
    check "--all and --latest" "Error: --all and --latest cannot be used together 125" "$out $?"
    out=$(sh_ network reload -a rl1 2>&1)
    check "--all with a name" "Error: no arguments are needed with --all 125" "$out $?"
    out=$(sh_ network reload -l rl1 2>&1)
    check "--latest with a name" "Error: --latest and containers cannot be used together 125" "$out $?"
    out=$(sh_ network reload nosuch 2>&1)
    check "a container that is not there" 'Error: no container with name or ID "nosuch" found: no such container 125' "$out $?"
    sh_ container create --name rl1 --network none "$IMAGE" true > /dev/null
    out=$(sh_ network reload rl1 2>&1)
    check "a container that never ran" \
        "Error: cannot reload network unless container network has been configured: container state improper 125" "$out $?"
    check "--all skips it" "" "$(sh_ network reload -a 2>&1)"
    sh_ container run -d --name rl2 --network none "$IMAGE" sleep 300 > /dev/null
    id=$(sh_ container inspect --format '{{.Id}}' rl2)
    out=$(sh_ network reload rl2 2>&1)
    check "a container without a bridge network" \
        "Error: container $id network is not configured, refusing to reload: container state improper 125" "$out $?"
    check "--all skips it too" "" "$(sh_ network reload -a 2>&1)"
    sh_ container rm -f -t 0 rl1 rl2 > /dev/null
}

@test "container clone: the request again, a name, an image, the limits, --destroy, --run" {
    sh_ container create --name cl1 -e A=b -l k=v --annotation an=1 --init --hostname clh --memory 64m \
        --restart on-failure:3 --network none "$IMAGE" sleep 300 > /dev/null
    id=$(sh_ container clone cl1)
    check "clone" 0 $?
    check_match "prints the ID" "^[0-9a-f]{64}$" "$id"
    check "NAME-clone by default" "cl1-clone created" "$(sh_ container inspect --format '{{.Name}} {{.State.Status}}' "$id")"
    check "the configuration is the original's" "v 1 true 67108864 on-failure 3" \
        "$(sh_ container inspect --format '{{.Config.Labels.k}} {{.Config.Annotations.an}} {{.HostConfig.Init}} {{.HostConfig.Memory}} {{.HostConfig.RestartPolicy.Name}} {{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$id")"
    check "as podman, a hostname of its own" "${id:0:12}" "$(sh_ container inspect --format '{{.Config.Hostname}}' "$id")"
    check "the environment too" "A=b" "$(sh_ container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$id" | grep -x A=b)"
    id=$(sh_ container clone cl1)
    check "as podman, NAME-clone1 when NAME-clone is taken" "cl1-clone1" "$(sh_ container inspect --format '{{.Name}}' "$id")"
    id=$(sh_ container clone cl1-clone)
    check "as podman, the clone of a clone" "cl1-clone2" "$(sh_ container inspect --format '{{.Name}}' "$id")"
    sh_ container update --memory 48m cl1 > /dev/null
    id=$(sh_ container clone --name cl2 cl1)
    check "what update changed" "50331648" "$(sh_ container inspect --format '{{.HostConfig.Memory}}' "$id")"
    id=$(sh_ container clone --memory 32m cl1 cl2b)
    check "--memory" "33554432" "$(sh_ container inspect --format '{{.HostConfig.Memory}}' "$id")"
    id=$(sh_ container clone --name ignored cl1 cl3)
    check "the argument wins over --name" "cl3" "$(sh_ container inspect --format '{{.Name}}' "$id")"
    out=$(sh_ container clone -f cl1 clf 2>&1)
    check "--force without --destroy" "Error: cannot set --force without --destroy: invalid argument 125" "$out $?"
    id=$(sh_ container clone --run cl1 cl4)
    check "--run starts it" "running" "$(sh_ container inspect --format '{{.State.Status}}' "$id")"
    out=$(sh_ container clone --destroy cl4 cl5 2>&1)
    check "--destroy of a running container" 125 $?
    check_match "needs --force" "running or paused containers cannot be removed without force" "$out"
    id=$(sh_ container clone --destroy --force cl4 cl6)
    check "--destroy --force" 0 $?
    check "the original is gone" "" "$(sh_ container ps -a --format '{{.Names}}' | grep -x cl4)"
    out=$(sh_ container clone nosuch 2>&1)
    check "no such container" 'Error: no container with name or ID "nosuch" found: no such container 125' "$out $?"
    sh_ container clone cl1 a b c > /dev/null 2>&1
    check_match "too many arguments" "[1-9]" "$?"
    sh_ container rm -f -t 0 cl1 cl1-clone cl1-clone1 cl1-clone2 cl2 cl2b cl3 cl5 cl6 > /dev/null 2>&1
}

@test "container clone: volumes, secrets, addresses and ports, pods" {
    sh_ volume create clv > /dev/null
    sh_ container create --name cv1 -v clv:/named -v /anon --network none "$IMAGE" true > /dev/null
    id=$(sh_ container clone cv1)
    check "as podman, the same volumes, the anonymous one too" \
        "$(sh_ container inspect --format '{{range .Mounts}}{{.Name}}:{{.Destination}} {{end}}' cv1)" \
        "$(sh_ container inspect --format '{{range .Mounts}}{{.Name}}:{{.Destination}} {{end}}' "$id")"
    printf s3cr3t | sh_ secret create cls - > /dev/null
    sh_ container create --name cs1 --secret cls --secret cls,type=env,target=CLS --network none "$IMAGE" \
        sh -c 'echo $CLS $(cat /run/secrets/cls)' > /dev/null
    check "the values of the secrets are in no record" "" \
        "$(grep -rl s3cr3t "$XDG_DATA_HOME/velarx/podman-api" 2>/dev/null)"
    id=$(sh_ container clone cs1)
    check "a container with secrets is cloned" 0 $?
    check "the secrets by name" "s3cr3t s3cr3t" "$(sh_ container start -a "$id" 2>&1)"
    # (a subnet the engine picks: free of the networks and routes of the host,
    # which may have bridges of other runs)
    sh_ network create cln > /dev/null
    subnet=$(sh_ network inspect --format '{{(index .Subnets 0).Subnet}}' cln)
    check_match "the subnet of the network" '^[0-9]+\.[0-9]+\.[0-9]+\.0/24$' "$subnet"
    ip=${subnet%.0/24}.50
    sh_ container run -d --name cn1 --network cln --ip "$ip" --mac-address 0a:00:00:00:49:50 \
        -p 127.0.0.1::8080 "$IMAGE" sleep 300 > /dev/null
    id=$(sh_ container clone --run cn1)
    check "a clone of a container with a static address and a port runs beside it" "running" \
        "$(sh_ container inspect --format '{{.State.Status}}' "$id")"
    check "with addresses of its own and no published port" "true true map[]" \
        "$(sh_ container inspect --format '{{ne .NetworkSettings.Networks.cln.IPAddress "'"$ip"'"}} {{ne .NetworkSettings.Networks.cln.MacAddress "0a:00:00:00:49:50"}} {{.HostConfig.PortBindings}}' "$id")"
    sh_ pod create --name clp1 > /dev/null
    sh_ pod create --name clp2 > /dev/null
    sh_ container create --pod clp1 --name cp1 "$IMAGE" sleep 300 > /dev/null
    id=$(sh_ container clone cp1)
    check "the clone of a member is in the pod" "$(sh_ pod inspect --format '{{.Id}}' clp1)" \
        "$(sh_ container inspect --format '{{.Pod}}' "$id")"
    id=$(sh_ container clone --pod clp2 cp1 cp2)
    check "--pod: in the other pod" "$(sh_ pod inspect --format '{{.Id}}' clp2)" \
        "$(sh_ container inspect --format '{{.Pod}}' "$id")"
    id=$(sh_ container clone --pod clp2 cn1 cp3)
    check "--pod: the networks are the pod's" "$(sh_ pod inspect --format '{{.Id}}' clp2)" \
        "$(sh_ container inspect --format '{{.Pod}}' "$id")"
    out=$(sh_ container clone --pod nosuch cv1 2>&1)
    check "--pod of no pod" 125 $?
    sh_ pod rm -f -t 0 clp1 clp2 > /dev/null
    sh_ container rm -f -t 0 cv1 cv1-clone cs1 cs1-clone cn1 cn1-clone > /dev/null
    sh_ network rm cln > /dev/null
    sh_ volume rm clv > /dev/null
    sh_ secret rm cls > /dev/null
}

@test "container runlabel: refused by name" {
    out=$(sh_ container runlabel run "$IMAGE" 2>&1)
    check "exit status" 125 $?
    check_match "the refusal" "^Error: podman's command .container runlabel. is not supported by velarx" "$out"
}

@test "volume reload: nothing to do without volume plugins" {
    sh_ volume reload
    check "volume reload" 0 $?
    check "prints nothing" "" "$(sh_ volume reload 2>&1)"
    sh_ volume reload extra > /dev/null 2>&1
    check_match "no arguments" "[1-9]" "$?"
}

@test "network connect: --ip6 and --mac-address are checked as podman does" {
    sh_ network create --subnet 10.213.46.0/24 cn1 > /dev/null
    sh_ network create --ipv6 --subnet 10.213.47.0/24 cn6 > /dev/null
    sh_ container create --name cc1 --network cn1 "$IMAGE" true > /dev/null
    out=$(sh_ network connect --ip6 notip cn6 cc1 2>&1)
    check "--ip6 of no address" 'Error: invalid argument "notip" for "--ip6" flag: failed to parse IP: "notip" 125' "$out $?"
    out=$(sh_ network connect --mac-address zz cn6 cc1 2>&1)
    check "--mac-address of no address" "Error: address zz: invalid MAC address 125" "$out $?"
    out=$(sh_ network connect --ip6 fd00::5 cn6 cc1 2>&1)
    check "--ip6 outside the subnet" 125 $?
    check_match "podman's words" "requested static ip fd00::5 not in any subnet on network cn6" "$out"
    sh_ network create --subnet 10.213.48.0/24 cn4 > /dev/null
    out=$(sh_ network connect --ip6 fd00::5 cn4 cc1 2>&1)
    check "--ip6 on a network without IPv6" 125 $?
    check_match "podman's words there too" "requested static ip fd00::5 not in any subnet on network cn4" "$out"
    sh_ network connect --mac-address 0a:00:00:00:00:01 cn6 cc1
    check "--mac-address" 0 $?
    sh_ network disconnect cn6 cc1
    check "disconnect" 0 $?
    sh_ container rm -f -t 0 cc1 > /dev/null
    sh_ network rm cn1 cn4 cn6 > /dev/null
}

@test "a flag takes a glued true or false, as in Go: ps --all=true, inspect --size=false" {
    sh_ container create --name bv --network none "$IMAGE" true > /dev/null
    check "--all=true lists the container" 1 "$(sh_ ps --all=true -q | wc -l)"
    check "--all=false does not" 0 "$(sh_ ps --all=false -q | wc -l)"
    check "--size=true" bv "$(sh_ container inspect --size=true --format '{{.Name}}' bv)"
    out=$(sh_ ps --all=maybe 2>&1)
    check "another value is still refused" 125 $?
}

@test "events: the IDs are whole, templates read the attributes, words of the errors" {
    sh_ container run --rm --name evl --label evk=evv --network none "$IMAGE" sh -c 'exit 3' > /dev/null
    check_match "the ID is not truncated" "container died [0-9a-f]{64} " "$(sh_ events --since 1m --stream=false --filter container=evl --filter event=died)"
    check_match "--no-trunc=false cuts it" "container died [0-9a-f]{12} " "$(sh_ events --since 1m --stream=false --no-trunc=false --filter container=evl --filter event=died)"
    check "an attribute of the template" "evv 3" "$(sh_ events --since 1m --stream=false --filter container=evl --filter event=died --format '{{.Attributes.evk}} {{.ContainerExitCode}}')"
    # (podman's ParseInputTime: a date alone, a time without a zone, and a
    # duration of --until that goes forward from now)
    check "since a date alone" 1 "$(sh_ events --since 2000-01-01 --stream=false --filter container=evl --filter event=died | wc -l)"
    check "since a time without a zone" 1 "$(sh_ events --since 2000-01-01T00:00:00 --stream=false --filter container=evl --filter event=died | wc -l)"
    check "until 5m is five minutes from now" 1 "$(sh_ events --since 1m --until 5m --stream=false --filter container=evl --filter event=died | wc -l)"
    check "until -5m is five minutes ago" 0 "$(sh_ events --since 1h --until -5m --stream=false --filter container=evl --filter event=died | wc -l)"
    out=$(sh_ events --since "the dawn of time" --stream=false 2>&1)
    check "a time that is none" 125 $?
    check_match "says it as podman" "failed to parse event filters" "$out"
    out=$(sh_ --events-backend none events --stream=false 2>&1)
    check "the none backend" 125 $?
    check "cannot be read" 'Error: cannot read events with the "none" backend' "$out"
}

@test "pod create: podman's words for a bad namespace, exit policy and network" {
    out=$(sh_ pod create --share bogus 2>&1)
    check "--share" 125 $?
    check_match "bad namespace" "invalid kernel namespace to share: bogus. Options are: cgroup, ipc, net, pid, uts or none" "$out"
    out=$(sh_ pod create --exit-policy invalid 2>&1)
    check "--exit-policy" 125 $?
    check_match "bad policy" 'running pod create option: invalid pod exit policy: "invalid"' "$out"
    out=$(sh_ pod create --network nonet 2>&1)
    check "--network" 125 $?
    check_match "missing network" "unable to find network with name or ID nonet: network not found" "$out"
}

@test "the infra container of a pod is removed with its pod, and --pod new: is not left when the container is not made" {
    sh_ container create --pod new:ip1 --name ipm "$IMAGE" true > /dev/null
    infra=$(sh_ pod inspect --format '{{.InfraContainerID}}' ip1)
    ip1=$(sh_ pod inspect --format '{{.Id}}' ip1)
    for opt in "" -f; do
        out=$(sh_ container rm $opt "$infra" 2>&1)
        check "rm $opt of the infra container" 125 $?
        check_match "says why" "is the infra container of pod $ip1 and cannot be removed without removing the pod" "$out"
    done
    member=$(sh_ container inspect --format '{{.Id}}' ipm)
    out=$(sh_ container rm --depend "${infra:0:12}")
    check "with --depend the member, then the infra container as it was named" \
        "$member ${infra:0:12}" "$(echo $out)"
    check "the pod is gone" 1 "$(sh_ pod exists ip1; echo $?)"
    sh_ container create --name ipdup --network none "$IMAGE" true > /dev/null
    out=$(sh_ container run --pod new:ip2 --name ipdup "$IMAGE" true 2>&1)
    check "a name in use" 125 $?
    check "the new pod is not kept" 1 "$(sh_ pod exists ip2; echo $?)"
    sh_ container create --pod new:ip3 --hostname ip3.example --name ip3c "$IMAGE" hostname > /dev/null
    check "--hostname is the pod's" ip3.example "$(sh_ pod inspect --format '{{.Hostname}}' ip3)"
    check "the infra command is the entrypoint" "[/pause]" "$(sh_ pod create --name ip4 --infra-command /pause > /dev/null; sh_ container inspect --format '{{.Config.Entrypoint}}' "$(sh_ pod inspect --format '{{.InfraContainerID}}' ip4)")"
    sh_ rm -t 0 -af > /dev/null
    check "rm -a removes the pods with their infra containers" 0 "$(sh_ pod ls -q | wc -l)"
}

@test "run -a stdin prints the ID and a ulimit of -1 under a hard limit has podman's words" {
    out=$(sh_ container run --rm --name as1 -a stdin --network none "$IMAGE" echo hi)
    check_match "the ID" "^[0-9a-f]{64}$" "$out"
    out=$(sh_ container run --ulimit core=-1:1000 "$IMAGE" true 2>&1)
    check_match "ulimit" 'soft: -1 \(unlimited\), hard: 1000' "$out"
}

@test "a pod's operations and the removal of its members wait for each other" {
    sh_ pod create --name lk --network none > /dev/null
    for i in 1 2 3; do
        sh_ container run -d --pod lk --name lk$i "$IMAGE" sleep 300 > /dev/null
    done
    sh_ pod stop -t 1 lk > /dev/null 2>&1 &
    sh_ pod start lk > "$WORKDIR/lk-start" 2>&1 &
    sh_ container rm -f -t 0 lk2 > /dev/null 2>&1 &
    sh_ pod restart lk > "$WORKDIR/lk-restart" 2>&1 &
    wait
    check "no operation met a member that went meanwhile" "" "$(cat "$WORKDIR/lk-start" "$WORKDIR/lk-restart" | grep -i 'not found')"
    sh_ pod rm -f -t 0 lk > /dev/null &
    sh_ container rm -f -t 0 lk3 > /dev/null 2>&1 &
    wait
    check "the pod is gone" 1 "$(sh_ pod exists lk; echo $?)"
    check "with its lock files" "" "$(ls -A "$(sh_ info --format '{{.Store.GraphRoot}}')/pods" 2>/dev/null | grep -v '^.lock$')"
}

@test "cp reaches the volumes and bind mounts of a container that does not run, and follows a link" {
    mkdir -p "$WORKDIR/cpb"
    echo content > "$WORKDIR/cpf"
    sh_ volume create cpv1 > /dev/null
    sh_ volume create cpv2 > /dev/null
    sh_ container create --name cpc --network none -v cpv1:/tmp/volume -v cpv2:/tmp/volume/sub \
        -v "$WORKDIR/cpb:/tmp/volume/mount" "$IMAGE" true > /dev/null
    sh_ container cp "$WORKDIR/cpf" cpc:/tmp/volume/sub
    check "into the deepest volume" content "$(cat "$(sh_ volume inspect --format '{{.Mountpoint}}' cpv2)/cpf")"
    check "not the one above" "" "$(ls "$(sh_ volume inspect --format '{{.Mountpoint}}' cpv1)")"
    sh_ container cp "$WORKDIR/cpf" cpc:/tmp/volume/mount
    check "into the bind mount" content "$(cat "$WORKDIR/cpb/cpf")"
    sh_ container cp cpc:/tmp/volume/mount/cpf "$WORKDIR/cpout"
    check "and out of it" content "$(cat "$WORKDIR/cpout")"
    sh_ container run -d --name cpl --log-driver k8s-file --network none "$IMAGE" sh -c 'mkdir /tmp/d; ln -s /tmp/nowhere /tmp/d/x; echo linked; sleep 300' > /dev/null
    wait_log cpl linked
    sh_ container cp "$WORKDIR/cpf" cpl:/tmp/d/x
    check "a copy onto a link makes what it points to" content "$(sh_ container exec cpl cat /tmp/nowhere)"
    sh_ container rm -f -t 0 cpc cpl > /dev/null
    sh_ volume rm cpv1 cpv2 > /dev/null
}

@test "a tmpfs starts with what the image has there, and the root has podman's /etc/mtab" {
    echo content > "$WORKDIR/tmf"
    sh_ container create --name tmc --network none --tmpfs /tmp "$IMAGE" sleep 300 > /dev/null
    sh_ container cp "$WORKDIR/tmf" tmc:/tmp
    sh_ container start tmc > /dev/null
    check "the file copied before the start" content "$(sh_ container exec tmc cat /tmp/tmf)"
    check_match "no noexec" "nosuid,nodev" "$(sh_ container exec tmc grep ' /tmp ' /proc/self/mountinfo)"
    check "notmpcopyup" "" "$(sh_ container run --rm --network none --tmpfs /var:notmpcopyup "$IMAGE" ls /var)"
    sh_ container rm -f -t 0 tmc > /dev/null
    printf 'FROM %s\nRUN rm -f /etc/mtab\n' "$IMAGE" > "$WORKDIR/Containerfile.mtab"
    sh_ image build -q -t localhost/nomtab -f "$WORKDIR/Containerfile.mtab" "$WORKDIR" > /dev/null
    check "/etc/mtab" "'/etc/mtab' -> '/proc/mounts'" "$(sh_ container run --rm --network none localhost/nomtab stat -c %N /etc/mtab)"
    sh_ container run --name mtd --network none localhost/nomtab true
    check "is no change of the container" "" "$(sh_ container diff mtd)"
    sh_ container rm mtd > /dev/null
    printf 'FROM %s\nRUN umount /etc/hostname; rm /etc/hostname\n' "$IMAGE" > "$WORKDIR/Containerfile.nohost"
    sh_ image build -q --cap-add SYS_ADMIN -t localhost/nohost -f "$WORKDIR/Containerfile.nohost" "$WORKDIR" > /dev/null
    check "the removal of /etc/hostname is kept" 1 "$(sh_ container run --rm --no-hostname --network none localhost/nohost test -e /etc/hostname; echo $?)"
    sh_ image rm localhost/nomtab localhost/nohost > /dev/null
}

@test "podman's words for a flag without its value, an unknown flag, and a field an event has not" {
    out=$(sh_ run -h 2>&1)
    check "run -h" 125 $?
    check "says it as podman" "Error: flag needs an argument: 'h' in -h
See 'velarx run --help'" "$out"
    out=$(sh_ ps --nosuch 2>&1)
    check "an unknown flag" 125 $?
    check "says it as podman" "Error: unknown flag: --nosuch
See 'velarx ps --help'" "$out"
    sh_ container run --rm --name evn --network none "$IMAGE" true
    out=$(sh_ events --since 1m --stream=false --filter container=evn --format '{{.Nope}}' 2>&1)
    check "an unknown field" 125 $?
    check_match "says it as podman" "can't evaluate field Nope in type system.Event" "$out"
}

@test "a pod without an infra container: no namespace is shared, its cgroup comes and goes with it" {
    out=$(sh_ pod create --infra=false --share net nsh 2>&1)
    check "--infra=false with --share" 125 $?
    check "says it as podman" "Error: cannot set share(net) namespaces without an infra container" "$out"
    out=$(sh_ pod create --infra=false -p 8080:80 nsh 2>&1)
    check "no port without an infra container" "Error: you must have an infra container to publish port bindings to the host" "$out"
    out=$(sh_ pod create --infra=false --no-hosts nsh 2>&1)
    check "nor --no-hosts" "Error: cannot specify --no-hosts without an infra container" "$out"
    out=$(sh_ pod create --infra=false --network none nsh 2>&1)
    check "nor a network" "Error: NoInfra and network modes cannot be used together" "$out"
    sh_ pod create --share none --name noshare > /dev/null
    check "a pod that shares nothing has no infra container, as podman's" "" "$(sh_ pod inspect --format '{{.InfraContainerID}}' noshare)"
    out=$(sh_ pod start noshare 2>&1)
    check_match "an empty pod without infra does not start" "^Error: no containers in pod [0-9a-f]* have no dependencies, cannot start pod: no such container" "$out"
    sh_ pod rm noshare > /dev/null
    sh_ pod create --infra=false --name noinf --memory 256M > /dev/null
    check "created" 0 $?
    check "no infra container" "" "$(sh_ pod inspect --format '{{.InfraContainerID}}' noinf)"
    sh_ container run -d --pod noinf --name noinf-a --network none "$IMAGE" sleep 300 > /dev/null
    check "a member runs" 0 $?
    sh_ container run -d --pod noinf --name noinf-b --network none "$IMAGE" sleep 300 > /dev/null
    check "and another" 0 $?
    check "the processes are not in one pid namespace" 2 \
        "$(for c in noinf-a noinf-b; do sh_ container exec $c readlink /proc/self/ns/pid; done | sort -u | wc -l)"
    check_match "pod ps shows two containers and no infra" "noinf .*2" "$(sh_ pod ps --format '{{.Name}} {{.InfraID}} {{.NumberOfContainers}}')"
    if [ "$(id -u)" = 0 ] || [ -d "$XDG_RUNTIME_DIR/systemd" ]; then
        cg=$(sh_ pod inspect --format '{{.CgroupPath}}' noinf)
        check_match "the cgroup path" "^/" "$cg"
        check "the cgroup is there" 0 "$(test -e "/sys/fs/cgroup$cg"; echo $?)"
        check "with the limit of the pod" 268435456 "$(cat "/sys/fs/cgroup$cg/memory.max")"
        sh_ pod stop -t 0 noinf > /dev/null
        check "the cgroup goes with the stop" 1 "$(test -e "/sys/fs/cgroup$cg"; echo $?)"
        sh_ pod start noinf > /dev/null
        check "and comes back with the start" 0 "$(test -e "/sys/fs/cgroup$cg"; echo $?)"
        check "with its limit" 268435456 "$(cat "/sys/fs/cgroup$cg/memory.max")"
        sh_ pod rm -f -t 0 noinf > /dev/null
        check "and is gone with the pod" 1 "$(test -e "/sys/fs/cgroup$cg"; echo $?)"
    fi
    sh_ pod rm -f -t 0 noinf > /dev/null 2>&1
}

@test "--mount type=glob and type=ramfs, a limit of 0 is none, log-opt max-size has podman's units" {
    mkdir -p "$WORKDIR/gl"
    touch "$WORKDIR/gl/v1a" "$WORKDIR/gl/v1b" "$WORKDIR/gl/v2"
    check "glob mounts each path at its own place" "v1a
v1b" "$(sh_ container run --rm --network none --mount "type=glob,src=$WORKDIR/gl/v1*,ro" "$IMAGE" ls "$WORKDIR/gl")"
    check "or below the destination" "v1a
v1b" "$(sh_ container run --rm --network none --mount "type=glob,src=$WORKDIR/gl/v1*,destination=/non/existing,ro" "$IMAGE" ls /non/existing)"
    out=$(sh_ container run --rm --network none --mount "type=glob,src=$WORKDIR/gl/v3*" "$IMAGE" true 2>&1)
    check "a glob that matches nothing" 125 $?
    check_match "says it as podman" "no file paths matching glob \"$WORKDIR/gl/v3\*\"" "$out"
    out=$(sh_ container run --rm --network none --mount "type=glob,src=$WORKDIR/gl/v*,destination=/tmp" "$IMAGE" ls /tmp 2>&1)
    check "the paths of one destination" "v1a
v1b
v2" "$out"
    out=$(sh_ container run --rm --network none --mount "type=glob,src=$WORKDIR/gl/v2*,ro" "$IMAGE" touch "$WORKDIR/gl/v2" 2>&1)
    check_match "ro is read only" "Read-only file system" "$out"
    check "ramfs" ramfs "$(sh_ container run --rm --network none --mount type=ramfs,destination=/mnt "$IMAGE" stat -f -c %T /mnt)"
    out=$(sh_ container run --rm --network none --mount type=ramfs,destination=/mnt,tmpfs-size=1m "$IMAGE" true 2>&1)
    check "ramfs has no size" 125 $?
    check "--memory=0 is no limit" hello "$(sh_ container run --rm --network none --memory=0 "$IMAGE" echo hello 2>&1)"
    sh_ container run -d --rm --network none --name lgs --log-opt max-size=7.069m "$IMAGE" sleep 300 > /dev/null
    check "max-size is in powers of 1000" 7.069MB "$(sh_ container inspect --format '{{.HostConfig.LogConfig.Size}}' lgs)"
    sh_ container rm -f -t 0 lgs > /dev/null
    sh_ container run --name lgj --network none --log-driver json-file "$IMAGE" true
    check "json-file stays what it was called" json-file "$(sh_ container inspect --format '{{.HostConfig.LogConfig.Type}}' lgj)"
    sh_ container rm lgj > /dev/null
}

@test "health checks: the action without a check is refused, a stopped container is stopped, the event has the status" {
    out=$(sh_ container create --health-on-failure=kill "$IMAGE" 2>&1)
    check "--health-on-failure without a check" 125 $?
    check "says it as podman" "Error: cannot set on-failure action to kill without a health check" "$out"
    sh_ container run -d --name hcs --network none --health-cmd 'touch /tmp/abc; sleep 20; echo msg' --health-interval=disable "$IMAGE" sleep 300 > /dev/null
    sh_ healthcheck run hcs > "$WORKDIR/hcs.out" 2>&1 &
    pid=$!
    # (a poll: the check says nothing before its end; its first command leaves a file in the container)
    wait_for 10 sh_ container exec hcs cat /tmp/abc
    sh_ container stop -t 0 hcs > /dev/null
    wait $pid
    check "the check that the stop ended" 1 $?
    check "says it is stopped" stopped "$(cat "$WORKDIR/hcs.out")"
    check "the status is kept" "exited--stopped--0" "$(sh_ container inspect --format '{{.State.Status}}--{{.State.Health.Status}}--{{.State.Health.FailingStreak}}' hcs)"
    sh_ container rm -f -t 0 hcs > /dev/null
    sh_ container run -d --name hce --network none --health-cmd true --health-interval=disable "$IMAGE" sleep 300 > /dev/null
    sh_ healthcheck run hce
    check "healthcheck run" 0 $?
    check "health_status is a field of the event" healthy "$(sh_ events --since 1m --stream=false --filter container=hce --filter event=health_status --format '{{.HealthStatus}}')"
    sh_ container rm -f -t 0 hce > /dev/null
}

@test "a user or group the image has not: podman's words and status 126; commit --config merges a configuration" {
    out=$(sh_ container run --rm --network none --user nosuch "$IMAGE" id 2>&1)
    check "unknown user" 126 $?
    check "says it as podman" "Error: unable to find user nosuch: no matching entries in passwd file" "$out"
    out=$(sh_ container run --rm --network none --user root:nosuch "$IMAGE" id 2>&1)
    check "unknown group" 126 $?
    check "in podman's words" "Error: unable to find group nosuch: no matching entries in group file" "$out"
    sh_ container create --name cmc --network none "$IMAGE" sleep 300 > /dev/null
    printf '{"Env":["FROM_CONFIG=1"],"WorkingDir":"/srv","Labels":{"cfg":"yes"},"ExposedPorts":{"81/tcp":{}},"Cmd":["sleep","1"]}' > "$WORKDIR/commit.json"
    sh_ container commit --config "$WORKDIR/commit.json" --change 'ENV EXTRA=2' cmc localhost/commit-config > /dev/null
    check "commit --config" 0 $?
    check "the working directory" /srv "$(sh_ image inspect --format '{{.Config.WorkingDir}}' localhost/commit-config)"
    check "the label" yes "$(sh_ image inspect --format '{{index .Config.Labels "cfg"}}' localhost/commit-config)"
    check_match "the variables of the file and of --change" "FROM_CONFIG=1.*EXTRA=2" "$(sh_ image inspect --format '{{.Config.Env}}' localhost/commit-config)"
    check "the command" "[sleep 1]" "$(sh_ image inspect --format '{{.Config.Cmd}}' localhost/commit-config)"
    out=$(sh_ container commit --config "$WORKDIR/nosuch.json" cmc 2>&1)
    check "a file that is not there" 125 $?
    sh_ image rm localhost/commit-config > /dev/null
    sh_ container rm -f -t 0 cmc > /dev/null
}

@test "a plain container shares its /dev/shm by default; a user the image has not is found by the start" {
    sh_ container run -d --name shd --network none "$IMAGE" sleep 300 > /dev/null
    check "the default is shareable" shareable "$(sh_ container inspect --format '{{.HostConfig.IpcMode}}' shd)"
    sh_ container exec shd sh -c 'echo hi > /dev/shm/f'
    out=$(sh_ container run --rm --network none --ipc container:shd "$IMAGE" cat /dev/shm/f 2>&1)
    check "another container joins it" hi "$out"
    out=$(sh_ container run --rm --network none --ipc container:shd "$IMAGE" sh -c 'ls /dev/shm' 2>&1)
    check_match "and sees the file" "^f" "$out"
    sh_ container run -d --name shj --network none --ipc container:shd "$IMAGE" sleep 300 > /dev/null
    out=$(sh_ container run --rm --network none --ipc container:shj "$IMAGE" cat /dev/shm/f 2>&1)
    check "one that joins a container that joined it has its /dev/shm too" hi "$out"
    sh_ container run -d --name shp --network none --ipc private "$IMAGE" sleep 300 > /dev/null
    out=$(sh_ container create --network none --ipc container:shp "$IMAGE" true 2>&1)
    check "a private one cannot be joined" 125 $?
    check_match "in podman's words" "joining IPC of container [0-9a-f]{64} is not allowed: non-shareable IPC" "$out"
    out=$(sh_ container run --rm --network none --ipc none "$IMAGE" sh -c 'test -e /dev/shm; echo $?' 2>&1)
    check "--ipc none has no /dev/shm" 1 "$out"
    # the tmpfs of the engine goes with its container (the ones that joined
    # it keep theirs), in the namespace of the engine where it was mounted
    shd=$(sh_ container inspect --format '{{.ID}}' shd)
    shm_mounts () {
        if [ "$(id -u)" = 0 ]; then
            grep -c "/mon/${shd:0:12}/shm " /proc/self/mountinfo
        else
            sh_ unshare grep -c "/mon/${shd:0:12}/shm " /proc/self/mountinfo
        fi
    }
    check "the /dev/shm of the engine is mounted" 1 "$(shm_mounts)"
    sh_ container stop -t 0 shd > /dev/null
    check "and goes when its container exits" 0 "$(shm_mounts)"
    check "the containers that joined it keep it" hi "$(sh_ container exec shj cat /dev/shm/f 2>&1)"
    sh_ container start shd > /dev/null
    check "a start mounts it again" 1 "$(shm_mounts)"
    # (the containers of one rm are removed at once: the one that joined shd
    # goes first, in a command of its own)
    sh_ container rm -f -t 0 shj shp > /dev/null
    sh_ container rm -f -t 0 shd > /dev/null
    check "and a removal takes it" 0 "$(shm_mounts)"
    # the mounts of the user keep their place
    out=$(sh_ container run --rm --network none --tmpfs /dev/shm:rw,size=1m "$IMAGE" df -k /dev/shm 2>&1 | tail -1 | awk '{print $2}')
    check "--tmpfs /dev/shm" 1024 "$out"
    out=$(sh_ container run --rm --network none --shm-size 2m "$IMAGE" df -k /dev/shm 2>&1 | tail -1 | awk '{print $2}')
    check "--shm-size" 2048 "$out"
    out=$(sh_ container run --rm --network none "$IMAGE" df -k /dev/shm 2>&1 | tail -1 | awk '{print $2}')
    check "the default size is podman's 64m" 65536 "$out"
    # a user the image has not: the container is made, the start says so
    id=$(sh_ container create --network none --user nosuch "$IMAGE" id)
    check "create" 0 $?
    check "it is created" created "$(sh_ container inspect --format '{{.State.Status}}' "$id")"
    out=$(sh_ container start "$id" 2>&1)
    check "start" 125 $?
    check_match "says it as podman" "unable to find user nosuch: no matching entries in passwd file" "$out"
    sh_ container rm -f -t 0 "$id" > /dev/null
    out=$(sh_ container create --network none --group-add nosuch "$IMAGE" id 2>&1)
    check "a group is found at the start too" 0 $?
    sh_ container rm -f -t 0 "$(echo "$out" | tail -1)" > /dev/null
    out=$(sh_ container run -d --network none --user nosuch "$IMAGE" id 2>&1)
    check "run -d" 126 $?
    sh_ container rm -f -t 0 -a > /dev/null
}

@test "pod create --infra=false ignores the options of the infra container; exec forwards no signal" {
    sh_ pod create --infra=false --infra-image "$IMAGE" --infra-command /x --name noi > /dev/null
    check "--infra-image and --infra-command are ignored" 0 $?
    check "no infra container" "" "$(sh_ pod inspect --format '{{.InfraContainerID}}' noi 2>&1)"
    out=$(sh_ pod create --infra=false --infra-name n x 2>&1)
    check "--infra-name is still refused" 125 $?
    sh_ pod rm -t 0 -f noi > /dev/null
    out=$(sh_ container exec --sig-proxy=false x true 2>&1)
    check_match "exec has no --sig-proxy" "unknown flag: --sig-proxy" "$out"
    # the command of an exec goes on when its client gets INT or TERM
    mkdir -p "$WORKDIR/exs"
    sh_ container run -d --name exs --network none -v "$WORKDIR/exs:/x:z" "$IMAGE" sleep 300 > /dev/null
    for sig in INT TERM; do
        env --default-signal=INT "$SH" container exec exs sh -c "echo \$\$ > /x/$sig.pid; sleep 60" > /dev/null 2>&1 &
        client=$!
        e2e_wait_path "$WORKDIR/exs/$sig.pid"
        kill -$sig $client
        wait $client
        got=$?
        check "the client ends at $sig" $((128 + $(kill -l $sig))) $got
        sh_ container exec exs sh -c "kill -0 \$(cat /x/$sig.pid)"
        check "the command survives $sig sent to the client" 0 $?
    done
    sh_ container rm -f -t 0 exs > /dev/null
}

@test "every health check is an event, and the events file stays bounded by its rotation" {
    sed -i '/^\[server\]/a events_logger = "file"\nevents_logfile_max_size = "4k"' "$CONFIG"
    sh_ container run -d --name hev --network none --health-cmd true --health-interval=disable "$IMAGE" sleep 300 > /dev/null
    for _ in $(seq 40); do sh_ healthcheck run hev > /dev/null; done
    log=$XDG_DATA_HOME/velarx/events/events.log
    check "the file is rotated" 0 "$(test -e "$log.1"; echo $?)"
    [ "$(stat -c %s "$log")" -le 4096 ]
    check "the file is within its limit" 0 $?
    [ "$(stat -c %s "$log.1")" -le 4096 ]
    check "so is the rotated one" 0 $?
    n=$(cat "$log" "$log.1" | grep -c '"health_status"')
    [ "$n" -ge 8 ]
    check "the checks are in it, one each" 0 $?
    sh_ container rm -f -t 0 hev > /dev/null
}

@test "the image digest of a container, --tz as a link, top huser, id filters of pod ps are regular expressions, the log records carry the local offset" {
    sh_ container create --name idg --network none "$IMAGE" true > /dev/null
    digest=$(sh_ container inspect --format '{{.ImageDigest}}' idg)
    check_match "ImageDigest is one of the RepoDigests" "$digest" "$(sh_ image inspect --format '{{json .RepoDigests}}' "$IMAGE")"
    sh_ container rm idg > /dev/null
    sh_ container run -d --name tzl --network none --tz Europe/Berlin "$IMAGE" sleep 300 > /dev/null
    # (a link where the image has the zone file, else the host's file)
    out=$(sh_ container exec tzl sh -c 'if [ -e /usr/share/zoneinfo/Europe/Berlin ]; then readlink /etc/localtime; else test -L /etc/localtime || head -c 4 /etc/localtime; fi')
    case $out in
    TZif) ;;
    *) check "/etc/localtime links to the zone file" ../usr/share/zoneinfo/Europe/Berlin "$out" ;;
    esac
    out=$(sh_ container top tzl huser,user,hpid 2>&1)
    check_match "top has the host user" "^HUSER +USER +HPID" "$out"
    sh_ container rm -f -t 0 tzl > /dev/null
    sh_ pod create --infra=false --name rp1 > /dev/null
    id=$(sh_ pod inspect --format '{{.ID}}' rp1)
    out=$(sh_ pod ps --filter "id=^${id:0:3}" --format '{{.Name}}')
    check "id is a regular expression" rp1 "$out"
    out=$(sh_ pod ps --filter "id=^[^${id:0:1}]" --format '{{.Name}}')
    check "and so is its negation" "" "$out"
    sh_ pod rm -t 0 -f rp1 > /dev/null
    sh_ container run --name ltz --log-driver k8s-file --network none "$IMAGE" echo hello > /dev/null
    check_match "the log record has the offset of the local time" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}\.[0-9]{9}[+-][0-9]{2}:[0-9]{2} stdout F hello$' "$(cat "$XDG_DATA_HOME/velarx/logs/$(sh_ container inspect --format '{{.ID}}' ltz)/container.log")"
    sh_ container rm ltz > /dev/null
}

@test "--follow of a journald container needs the journald events backend" {
    sh_ container run -d --name jf --network none --log-driver journald "$IMAGE" sleep 300 > /dev/null || skip "no journald log driver"
    out=$(sh_ --events-backend=file container logs --follow jf 2>&1)
    check "refused" 125 $?
    check "in podman's words" "Error: using --follow with the journald --log-driver but without the journald --events-backend (file) is not supported" "$out"
    sh_ container rm -f -t 0 jf > /dev/null
}

@test "build --logsplit: the output for each platform is in a file of its own" {
    printf 'FROM scratch\nCOPY f /f\n' > "$WORKDIR/Containerfile.split"
    echo x > "$WORKDIR/f"
    sh_ image build --platform linux/amd64,linux/arm64 --logfile "$WORKDIR/split.log" --logsplit \
        -f "$WORKDIR/Containerfile.split" "$WORKDIR" > /dev/null
    check "the build" 0 $?
    for p in amd64 arm64; do
        check_match "the log of $p" "COPY f /f" "$(cat "$WORKDIR/split.log_linux_$p")"
    done
    check "the file itself is there" 0 "$(test -e "$WORKDIR/split.log"; echo $?)"
    sh_ image build --platform linux/arm64 --logfile "$WORKDIR/one.log" --logsplit=true \
        -f "$WORKDIR/Containerfile.split" "$WORKDIR" > /dev/null
    check_match "one platform: its own file too" "COPY f /f" "$(cat "$WORKDIR/one.log_linux_arm64")"
    out=$(sh_ image build --logsplit -f "$WORKDIR/Containerfile.split" "$WORKDIR" 2>&1)
    check "--logsplit needs --logfile, as buildah's" "Error: cannot use --logsplit without --logfile" "$out"
}

@test ":U gives the source to the user again at every start, podman's" {
    [ "$(id -u)" != 0 ] || skip "rootless: unshare chown"
    dir=$WORKDIR/uvol; mkdir -p "$dir"
    touch "$dir/test1"
    sh_ container run --name ureown --user 1000:2000 -v "$dir:/data:U" --network none "$IMAGE" stat -c %u:%g /data > /dev/null
    check "first run" 0 $?
    sh_ unshare chown -R 100:200 "$dir"
    out=$(sh_ container start --attach ureown 2>&1)
    check "the directory is the user's again" "1000:2000" "$out"
    out=$(sh_ unshare stat -c %u:%g "$dir/test1")
    check "and what is inside" "1000:2000" "$out"
    # the owner of the directory is right: nothing below it changes
    sh_ unshare chown 100:200 "$dir/test1"
    sh_ container start --attach ureown > /dev/null 2>&1
    out=$(sh_ unshare stat -c %u:%g "$dir/test1")
    check "a changed file below an unchanged directory stays" "100:200" "$out"
    sh_ container rm ureown > /dev/null
    sh_ unshare rm -rf "$dir"
}

@test "--userns=keep-id: the passwd file is the container's own and can be renamed over" {
    [ "$(id -u)" != 0 ] || skip "keep-id is rootless"
    id=$(sh_ container run -d --userns=keep-id --cap-add=dac_override --network none "$IMAGE" sleep 300)
    out=$(sh_ container exec --user root "$id" sh -c 'mv /etc/passwd /etc/passwd.x && mv /etc/passwd.x /etc/passwd && echo renamed' 2>&1)
    check_match "renamed" "renamed" "$out"
    out=$(sh_ container exec "$id" sh -c 'grep -c "^$(id -un):" /etc/passwd; grep -c "^$(id -gn):" /etc/group')
    check "the entries" "1
1" "$out"
    out=$(sh_ container exec "$id" sh -c 'grep -c " /etc/passwd " /proc/self/mountinfo')
    check "no mount at /etc/passwd" "0" "$out"
    out=$(sh_ container diff "$id")
    check_match "diff shows it" "^C /etc/passwd$" "$out"
    sh_ container stop -t 0 "$id" > /dev/null
    sh_ container start "$id" > /dev/null
    out=$(sh_ container exec "$id" sh -c 'grep -c "^$(id -un):" /etc/passwd')
    check "after a restart" "1" "$out"
    sh_ container rm -f -t 0 "$id" > /dev/null
    # a read-only root file system keeps the mounted file
    out=$(sh_ container run --rm --userns=keep-id --read-only --network none "$IMAGE" sh -c 'grep -c "^$(id -un):" /etc/passwd; grep -c " /etc/passwd " /proc/self/mountinfo')
    check "read-only" "1
1" "$out"
}

@test "build --stdin: the standard input of the command is the one of the RUN steps" {
    ctx=$WORKDIR/stdin
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN cat > /in.txt\n' "$IMAGE" > "$ctx/Containerfile"
    printf 'hello\nfrom stdin\n' | sh_ build -q --stdin -t localhost/bs:1 "$ctx" > /dev/null 2>&1
    check "build --stdin" 0 $?
    out=$(sh_ run --rm --network none localhost/bs:1 cat /in.txt 2>&1)
    check "the step read it" "hello
from stdin" "$out"
    # without it the step has an empty input
    printf 'lost\n' | sh_ build -q --no-cache -t localhost/bs:2 "$ctx" > /dev/null 2>&1
    out=$(sh_ run --rm --network none localhost/bs:2 sh -c 'wc -c < /in.txt' 2>&1)
    check "no --stdin" "0" "$out"
    # (and to the engine of a socket: the call carries the descriptor)
    printf 'over the socket\n' | sc build -q --stdin --no-cache -t localhost/bs:3 "$ctx" > /dev/null 2>&1
    check "build --stdin through the socket" 0 $?
    out=$(sh_ run --rm --network none localhost/bs:3 cat /in.txt 2>&1)
    check "the step read it too" "over the socket" "$out"
    out=$(sh_ build --isolation chroot "$ctx" 2>&1)
    check_match "chroot is refused" "isolation chroot is not supported" "$out"
}

@test "a negative number after an option is its value (pflag), --pull takes its value after a space" {
    out=$(sh_ run --rm --network none --pids-limit -1 --memory-swap -1 --cpu-quota -1 --oom-score-adj 5 "$IMAGE" echo ok 2>&1)
    check "negative values as separate arguments" "ok" "$(printf '%s\n' "$out" | tail -1)"
    # (--pull never IMAGE: "never" is the policy, not the image)
    out=$(sh_ run --pull never --rm --network none "$IMAGE" echo never-ok 2>&1)
    check "--pull never IMAGE" "never-ok" "$out"
    out=$(sh_ run --pull never --rm --network none localhost/nosuchimage:1 true 2>&1)
    check "--pull never of a missing image" 125 $?
    check "in podman's words" "Error: localhost/nosuchimage:1: image not known" "$out"
    out=$(sh_ run --pull sometimes --rm "$IMAGE" true 2>&1)
    check "an unknown policy" 125 $?
    check "in podman's words (unsupported pull policy)" 'Error: unsupported pull policy "sometimes"' "$out"
    # --sig-proxy is a boolean: bare, and false with an equals sign
    out=$(sh_ run --sig-proxy --rm --network none "$IMAGE" echo sp 2>&1)
    check "--sig-proxy bare" "sp" "$out"
    out=$(sh_ run --sig-proxy=false --rm --network none "$IMAGE" echo sp 2>&1)
    check "--sig-proxy=false" "sp" "$out"
}

@test "build --pull: false is never, true is always" {
    ctx=$WORKDIR/pullpol
    mkdir -p "$ctx"
    printf 'FROM localhost/nosuchbase:1\n' > "$ctx/Containerfile"
    out=$(sh_ build --pull=false "$ctx" 2>&1)
    check "--pull=false of a base that is not there" 125 $?
    check_match "it is not pulled: image not known" "image not known" "$out"
    printf 'FROM %s\nRUN true\n' "$IMAGE" > "$ctx/Containerfile"
    sh_ build -q --pull=false -t localhost/pullpol:1 "$ctx" > /dev/null 2>&1
    check "--pull=false of a base that is there" 0 $?
    sh_ rmi localhost/pullpol:1 > /dev/null
    sh_ build -q --pull never "$ctx" > /dev/null 2>&1
    check "--pull never is a value after a space for build too: the context is not 'never'" 125 $?
}

@test "podman's exit status and words of the commands that need an argument" {
    for c in "start" "network rm" "volume rm" "secret inspect" "container checkpoint" "rm" "stop" "tag" "image push" "volume exists"; do
        # shellcheck disable=SC2086
        sh_ $c > /dev/null 2>&1
        check "$c without an argument" 125 $?
    done
    check "start" "Error: start requires at least one argument" "$(sh_ start 2>&1)"
    check "rm" "Error: you must provide at least one name or id" "$(sh_ rm 2>&1)"
    check "network rm" "Error: requires at least 1 arg(s), only received 0" "$(sh_ network rm 2>&1)"
    check "tag" "Error: requires at least 2 arg(s), only received 1" "$(sh_ tag x 2>&1)"
    check "volume exists" "Error: accepts 1 arg(s), received 2" "$(sh_ volume exists a b 2>&1)"
    check "image push" "Error: accepts between 1 and 2 arg(s), received 3" "$(sh_ image push a b c 2>&1)"
    check "images" "Error: accepts at most 1 arg(s), received 2" "$(sh_ images a b 2>&1)"
    check "version" "Error: \`velarx version\` takes no arguments" "$(sh_ version x 2>&1)"
    check "events" "Error: \`velarx events\` takes no arguments" "$(sh_ events --stream false 2>&1)"
    check "volume rm" "Error: choose either one or more volumes or all" "$(sh_ volume rm 2>&1)"
    check "an option that is not a number" 'Error: invalid argument "abc" for "--pids-limit" flag: strconv.ParseInt: parsing "abc": invalid syntax' "$(sh_ run --pids-limit abc "$IMAGE" 2>&1)"
    check "a negative number for an unsigned option" 'Error: invalid argument "-1" for "--retry" flag: strconv.ParseUint: parsing "-1": invalid syntax' "$(sh_ build --retry -1 . 2>&1)"
    check "memory" "Error: invalid value for memory: invalid suffix: 'x'" "$(sh_ run -m 1x "$IMAGE" true 2>&1)"
    check "host port" "Error: parsing host port: port numbers must be between 1 and 65535 (inclusive), got 99999" "$(sh_ run -p 99999:80 "$IMAGE" true 2>&1)"
    check "network inspect" "Error: network nosuchnet: unable to find network with name or ID nosuchnet: network not found" "$(sh_ network inspect nosuchnet 2>&1 | tail -1)"
}

@test "pull takes several images, and restore --tcp-close is refused by name" {
    sh_ tag "$IMAGE" localhost/pull-two:1
    out=$(sh_ pull -q "$IMAGE" "$IMAGE" 2>&1)
    check "pull of two images" 0 $?
    check "each id" 2 "$(printf '%s\n' "$out" | grep -c '^[0-9a-f]\{64\}$')"
    sh_ rmi localhost/pull-two:1 > /dev/null
    # (podman: a failure is said and the next image is pulled; the status
    # is that of the failure)
    out=$(sh_ pull -q localhost:1/nosuch:1 "$IMAGE" 2>&1)
    check "pull of a missing image and one that is there" 125 $?
    check "the second is pulled" 1 "$(printf '%s\n' "$out" | grep -c '^[0-9a-f]\{64\}$')"
    check_match "the first is said" "^Error: .*localhost:1" "$out"
    out=$(sh_ container restore --tcp-close nosuch 2>&1)
    check "restore --tcp-close" 125 $?
    check_match "refused by name, not unknown" "--tcp-close is not supported" "$out"
}

@test "tools/parity-report/cli.py counts an option velarx does not know as unknown" {
    tool="$BATS_TEST_DIRNAME/../../../tools/parity-report"
    [ -f "$tool/cli.py" ] || skip "no tools/parity-report in this tree"
    out=$(cd "$tool" && python3 -I -B - "$BIN/velarx" << 'PY'
# (-B: no __pycache__ in the source tree)
import importlib.util, sys
spec = importlib.util.spec_from_file_location("cli", "cli.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
v = sys.argv[1]
print("unknown" if not m.probe(v, ["container", "restore"], "--nosuchoption") else "known")
print("known" if m.probe(v, ["pull"], "--decryption-key") else "unknown")
PY
)
    check "the probe" "unknown
known" "$out"
}

@test "ps: the health of a container after its state" {
    sh_ run -d --name psh --network none --health-cmd true --health-interval 1s "$IMAGE" sleep 300 > /dev/null
    check_match "starting or healthy at once" "^Up .* \((starting|healthy)\)$" "$(sh_ ps --filter name=psh --format '{{.Status}}')"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ "$(sh_ ps --filter name=psh --format '{{.Status}}' | grep -c '(healthy)')" = 1 ] && break
        sleep 1
    done
    check_match "healthy" "^Up .* \(healthy\)$" "$(sh_ ps --filter name=psh --format '{{.Status}}')"
    # (podman's ps --format json: the state with the health, as the column;
    # the REST list's own Status is the health alone)
    check_match "the JSON field" "^Up .* \(healthy\)$" "$(sh_ ps --filter name=psh --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["Status"])')"
    sh_ run -d --name psn --network none "$IMAGE" sleep 300 > /dev/null
    check_match "no check, no suffix" "^Up [^(]*$" "$(sh_ ps --filter name=psn --format '{{.Status}}')"
    sh_ rm -f -t 0 psh psn > /dev/null
}

@test "images --filter: every key of libimage, until with a duration, negation" {
    for f in containers=true digest=sha256:9999 readonly=true manifest=true; do
        check "$f selects none" "" "$(sh_ images --filter $f -q 2>&1)"
    done
    # (the image of the registry was made long ago; the others of the file
    # are new)
    id=$(sh_ image inspect --format '{{.ID}}' "$IMAGE")
    id=${id:0:12}
    check "containers=false" 1 "$(sh_ images --filter containers=false -q | grep -c "$id")"
    check "readonly=false" 1 "$(sh_ images --filter readonly=false -q | grep -c "$id")"
    check "until=1h: the image made long ago" 1 "$(sh_ images --filter until=1h -q | grep -c "$id")"
    check "until=100000h: none" 0 "$(sh_ images --filter until=100000h -q | grep -c "$id")"
    check "reference!= of the name" 0 "$(sh_ images --filter "reference!=*alpine*" -q | grep -c "$id")"
    check "reference of the name" 1 "$(sh_ images --filter "reference=*alpine*" -q | grep -c "$id")"
    check "digest=sha256: of the manifest digest selects it" "$id" "$(sh_ images --filter "digest=$(sh_ image inspect --format '{{.Digest}}' "$IMAGE")" -q | head -1)"
    out=$(sh_ images --filter dangling=x 2>&1)
    check "a boolean that is none" 125 $?
    check "in libimage's words" 'Error: non-boolean value "dangling" for x filter: strconv.ParseBool: parsing "x": invalid syntax' "$out"
    out=$(sh_ images --filter digest=abc 2>&1)
    check "digest without sha256:" 'Error: invalid value "abc" for digest filter' "$out"
}

@test "tag: docker.io names are normalised, a digest is refused, rmi by ID of an image with several names" {
    sh_ tag "$IMAGE" docker.io/tagnorm:1
    check "docker.io/tagnorm:1 is docker.io/library/tagnorm:1" 0 "$(sh_ image exists docker.io/library/tagnorm:1; echo $?)"
    check "listed so" "docker.io/library/tagnorm" "$(sh_ images --format '{{.Repository}}' | grep tagnorm)"
    out=$(sh_ tag "$IMAGE" "localhost/z@sha256:$(printf '0%.0s' $(seq 64))" 2>&1)
    check "tag by digest" 125 $?
    check_match "in podman's words" "tag by digest not supported$" "$out"
    check "and no :latest was made" "" "$(sh_ images --format '{{.Repository}}:{{.Tag}}' | grep '^localhost/z:')"
    out=$(sh_ tag "$IMAGE" sha256:abc 2>&1)
    check "tag sha256:abc" 125 $?
    id=$(sh_ image inspect --format '{{.ID}}' "$IMAGE")
    out=$(sh_ rmi "$id" 2>&1)
    check "rmi by ID of an image with several names" 125 $?
    check_match "podman's refusal" "by ID with more than one tag .*: please force removal" "$out"
    sh_ rmi docker.io/library/tagnorm:1 > /dev/null
    check "the other name stays" 0 "$(sh_ image exists "$IMAGE"; echo $?)"
}

@test "image prune --filter until judges the creation time of the image, not the pull" {
    sh_ tag "$IMAGE" localhost/prune-until:1
    # (the image was made long ago and pulled now: it is older than a day)
    out=$(sh_ image prune -a -f --filter until=24h 2>&1)
    check "prune until=24h" 0 $?
    check "the image made long ago is gone" "" "$(sh_ images --filter 'reference=*alpine*' -q)"
    sh_ pull -q "$IMAGE" > /dev/null
}

@test "PODMAN_USERNS is the default of --userns outside a pod, an unknown value is refused, the flag wins" {
    [ "$(id -u)" != 0 ] || skip "keep-id is for a rootless user"
    out=$(PODMAN_USERNS=keep-id sh_ container run --rm --network none "$IMAGE" id -u 2>&1)
    check "the user of the host" "$(id -u)" "$out"
    out=$(PODMAN_USERNS=keep-id sh_ container run --rm --userns=host --network none "$IMAGE" id -u 2>&1)
    check "--userns wins" "0" "$out"
    out=$(PODMAN_USERNS=nonsense sh_ container run --rm --network none "$IMAGE" id -u 2>&1)
    check "an invalid value" 125 $?
    sh_ pod create --network none upod > /dev/null
    out=$(PODMAN_USERNS=nonsense sh_ container run --rm --pod upod "$IMAGE" id -u 2>&1)
    check "in a pod it is not read" "0" "$out"
    sh_ pod rm -f upod > /dev/null
}

@test "build: continuation lines keep their white space, a BOM and empty continuation lines are no problem, shell-style expansions and --chown=\${UID}" {
    ctx=$WORKDIR/parse
    mkdir -p "$ctx"
    printf 'x\n' > "$ctx/data"
    printf '\xef\xbb\xbfFROM %s\nARG UID=1234\nARG V=hello.tar.gz\nENV STRIP=${V%%.tar.gz} BASE=${V##*.}\nRUN echo hello\\\n   world > /a.txt\nRUN echo one > /b.txt \\\n\n  && echo two >> /b.txt\nCOPY --chown=${UID}:${UID} --chmod=${UID:+750} data /data\nRUN echo "$STRIP $BASE" > /c.txt\n' "$IMAGE" > "$ctx/Containerfile"
    sh_ build -q -t localhost/bp:1 "$ctx" > /dev/null 2>&1
    check "build" 0 $?
    out=$(sh_ run --rm --network none localhost/bp:1 sh -c 'cat /a.txt /b.txt /c.txt; stat -c "%u %g %a" /data')
    check "what was built" "hello world
one
two
hello gz
1234 1234 750" "$out"
    printf 'FROM %s\nSTOPSIGNAL SIGFOO\n' "$IMAGE" > "$ctx/Containerfile.sig"
    out=$(sh_ build -q -f "$ctx/Containerfile.sig" "$ctx" 2>&1)
    check "a signal that is none" 125 $?
    check_match "named" "invalid signal .SIGFOO." "$out"
    printf 'FROM %s\nENV X=${V:-ok}${V%%}\n' "$IMAGE" > "$ctx/Containerfile.bad"
    out=$(sh_ build -q -f "$ctx/Containerfile.bad" "$ctx" 2>&1)
    check "a substitution that is none" 125 $?
    check_match "named" "no suffix to remove" "$out"
    sh_ image rm localhost/bp:1 > /dev/null
}

@test "build: -f given several times joins the files, <Containerfile>.dockerignore is read" {
    ctx=$WORKDIR/multi
    mkdir -p "$ctx"
    printf 'FROM %s\n' "$IMAGE" > "$ctx/base"
    printf 'RUN echo extra > /e.txt\nCOPY . /ctx\n' > "$ctx/extra"
    echo keep > "$ctx/keep.txt"
    echo skip > "$ctx/skip.txt"
    printf 'skip.txt\n' > "$ctx/extra.dockerignore"
    sh_ build -q -f "$ctx/base" -f "$ctx/extra" -t localhost/bm:1 "$ctx" > /dev/null 2>&1
    check "build with two files" 0 $?
    out=$(sh_ run --rm --network none localhost/bm:1 sh -c 'cat /e.txt; ls /ctx')
    check_match "the second file ran after the first" "^extra" "$out"
    check_match "the file the ignore file of ... does not name is there" "keep.txt" "$out"
    check "the one it names is not" 0 "$(printf '%s' "$out" | grep -c skip.txt)"
    # in a context the same ignore file goes with the one -f
    mkdir -p "$ctx/c2"
    printf 'FROM %s\nCOPY . /ctx\n' "$IMAGE" > "$ctx/c2/Containerfile"
    echo a > "$ctx/c2/a.txt"; echo b > "$ctx/c2/b.txt"
    printf 'a.txt\n' > "$ctx/c2/Containerfile.containerignore"
    printf 'b.txt\n' > "$ctx/c2/.dockerignore"
    sh_ build -q -t localhost/bm:2 "$ctx/c2" > /dev/null 2>&1
    check "build with its own ignore file" 0 $?
    out=$(sh_ run --rm --network none localhost/bm:2 ls /ctx)
    check_match "the file of the Containerfile wins over the context's" "b.txt" "$out"
    check "a.txt is not there" 0 "$(printf '%s' "$out" | grep -c a.txt)"
    sh_ image rm localhost/bm:1 localhost/bm:2 > /dev/null
}

@test "build: COPY sees what the ignore file the command applies leaves (--ignorefile, -f outside, the Containerfile used)" {
    ctx=$WORKDIR/ignwho
    mkdir -p "$ctx/c" "$ctx/out"
    printf 'FROM %s\nCOPY . /ctx\n' "$IMAGE" > "$ctx/c/Containerfile"
    for f in secret other keep; do echo $f > "$ctx/c/$f"; done
    printf 'secret\n' > "$ctx/c/.dockerignore"
    printf 'other\n' > "$ctx/ign"
    sh_ build -q --ignorefile "$ctx/ign" -t localhost/ign:1 "$ctx/c" > /dev/null 2>&1
    check "build --ignorefile" 0 $?
    check "--ignorefile, not the context's" "Containerfile keep secret" "$(sh_ run --rm --network none localhost/ign:1 ls /ctx | tr '\n' ' ' | sed 's/ $//')"
    cp "$ctx/c/Containerfile" "$ctx/out/Cf"
    printf 'other\n' > "$ctx/out/Cf.dockerignore"
    sh_ build -q -f "$ctx/out/Cf" -t localhost/ign:2 "$ctx/c" > /dev/null 2>&1
    check "build -f outside" 0 $?
    check "that of the Containerfile outside" "Containerfile keep secret" "$(sh_ run --rm --network none localhost/ign:2 ls /ctx | grep -v dockerignore | tr '\n' ' ' | sed 's/ $//')"
    # (with no -f the Containerfile is used: the ignore file of the
    # Dockerfile is not its)
    cp "$ctx/c/Containerfile" "$ctx/c/Dockerfile"
    printf 'other\n' > "$ctx/c/Dockerfile.dockerignore"
    sh_ build -q -t localhost/ign:3 "$ctx/c" > /dev/null 2>&1
    check "build with both files" 0 $?
    check "the context's" "Containerfile Dockerfile Dockerfile.dockerignore keep other" "$(sh_ run --rm --network none localhost/ign:3 ls /ctx | tr '\n' ' ' | sed 's/ $//')"
    sh_ image rm localhost/ign:1 localhost/ign:2 localhost/ign:3 > /dev/null
}

@test "build: COPY --from keeps the owners of the files of the other stage, a directory copied leaves the one it goes to as the image has it" {
    ctx=$WORKDIR/fromown
    mkdir -p "$ctx/sub"
    echo s > "$ctx/sub/s"
    chmod 700 "$ctx/sub"
    printf 'FROM %s AS b\nRUN mkdir /d && echo x > /d/x && chown -R 1001:1002 /d\nFROM %s\nCOPY --from=b /d /d\nCOPY --from=b --chown=7:8 /d/x /y\nCOPY sub /etc\nCOPY sub /new\n' "$IMAGE" "$IMAGE" > "$ctx/Containerfile"
    sh_ build -q -t localhost/fromown:1 "$ctx" > /dev/null 2>&1
    check "build" 0 $?
    # (/d is where the content of /d goes: as buildah's, root's)
    check "the owners" "0:0 1001:1002 7:8" "$(sh_ run --rm --network none localhost/fromown:1 stat -c %u:%g /d /d/x /y | tr '\n' ' ' | sed 's/ $//')"
    check "/etc keeps its mode, /new is made 0755, as podman's" "755 755 644" "$(sh_ run --rm --network none localhost/fromown:1 stat -c %a /etc /new /etc/s | tr '\n' ' ' | sed 's/ $//')"
    sh_ image rm localhost/fromown:1 > /dev/null
}

@test "a short name that is no alias is refused when no registry is listed, podman's words" {
    out=$(sh_ pull nonexistentxyzq:1 2>&1)
    check "pull of a short name" 125 $?
    check_match "named" 'short-name "nonexistentxyzq:1" did not resolve to an alias and no unqualified-search registries are defined' "$out"
    out=$(sh_ run --rm --network none nonexistentxyzq 2>&1)
    check "run of a short name" 125 $?
    check_match "named by run too" 'short-name "nonexistentxyzq" did not resolve to an alias' "$out"
    printf 'FROM nonexistentxyzq\n' > "$WORKDIR/Containerfile.short"
    out=$(sh_ image build -q -f "$WORKDIR/Containerfile.short" "$WORKDIR" 2>&1)
    check_match "and by build" 'short-name "nonexistentxyzq" did not resolve to an alias' "$out"
}
