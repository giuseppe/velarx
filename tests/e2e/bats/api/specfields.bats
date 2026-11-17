# SPDX-License-Identifier: Apache-2.0
# The fields of a create (libpod's SpecGenerator, Docker's Config and
# HostConfig) that are applied, and those refused with the reason.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; api_state_load; }

# status code of a libpod create of the spec $1

libpod_create_code () {
    api -o "$WORKDIR/specfields.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -d "$1" http://d/v5.0.0/libpod/containers/create
}

docker_create_code () { # spec, name
    api -o "$WORKDIR/specfields.out" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
        -d "$1" "http://d/v1.41/containers/create?name=$2"
}

@test "libpod create: the fields it applies" {
    # applied
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sf1","command":["sleep","100"],
        "sdnotifyMode":"ignore","manage_password":false,"use_image_hostname":true,
        "image_volume_mode":"anonymous","publish_image_ports":true,"expose":{"8080":"tcp"},
        "oci_runtime":"crun","seccomp_policy":"default",
        "healthconfig":{"Test":["CMD","true"],"Interval":30000000000},
        "health_check_on_failure_action":2,
        "containerCreateCommand":["podman","run"],"raw_image_name":"'"$IMG"'","volatile":true}')
    check "libpod create with the fields it applies" 201 "$code"
    check "-P (publish_image_ports)" true "$(pm container inspect --format '{{.HostConfig.PublishAllPorts}}' sf1 2>&1)"
    check "the on-failure action of the health check" kill \
        "$(api http://d/v5.0.0/libpod/containers/sf1/json | jq -r .Config.HealthcheckOnFailureAction)"
    pm start sf1 > /dev/null 2>&1
    port=$(api http://d/v5.0.0/libpod/containers/sf1/json | jq -r '.NetworkSettings.Ports["8080/tcp"][0].HostPort // empty')
    check_match "the exposed port is published on a free port" '^[0-9]+$' "$port"
    out=$(pm exec sf1 sh -c 'grep -c " /etc/hostname " /proc/self/mountinfo' 2>&1)
    check "use_image_hostname: the /etc/hostname of the image" 0 "$out"
    pm rm -f -t 0 sf1 > /dev/null 2>&1
}

@test "libpod create: a health check is kept as given, Docker's gets the defaults" {
    # libpod: an interval of 0 is no timer (the checks of healthcheck run
    # only), 0 retries is unhealthy after the first failure and a timeout
    # of 0 is none; inspect shows them as given
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"hz1","command":["sleep","100"],
        "healthconfig":{"Test":["CMD","false"],"Interval":0,"Retries":0,"Timeout":0}}')
    check "libpod create with a health check of zero times" 201 "$code"
    check "inspect: the times as given" "0 0 0" \
        "$(api http://d/v5.0.0/libpod/containers/hz1/json | jq -r '.Config.Healthcheck | "\(.Interval) \(.Timeout) \(.Retries)"')"
    pm start hz1 > /dev/null 2>&1
    pm healthcheck run hz1 > /dev/null 2>&1
    inspect=$(api http://d/v5.0.0/libpod/containers/hz1/json)
    check "one failure of 0 retries is unhealthy" "unhealthy 1 1" \
        "$(echo "$inspect" | jq -r '.State.Health | "\(.Status) \(.FailingStreak) \(.Log | length)"')"
    pm rm -f -t 0 hz1 > /dev/null 2>&1
    # Docker: 0 retries is the default of 3
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["sleep","100"],
        "Healthcheck":{"Test":["CMD","false"],"Interval":0,"Retries":0}}' hz2)
    check "docker create with a health check of zero times" 201 "$code"
    check "inspect: the defaults" "30000000000 30000000000 3" \
        "$(api http://d/v5.0.0/libpod/containers/hz2/json | jq -r '.Config.Healthcheck | "\(.Interval) \(.Timeout) \(.Retries)"')"
    pm start hz2 > /dev/null 2>&1
    pm healthcheck run hz2 > /dev/null 2>&1
    check "one failure of the default retries is not unhealthy" starting \
        "$(api http://d/v5.0.0/libpod/containers/hz2/json | jq -r .State.Health.Status)"
    pm rm -f -t 0 hz2 > /dev/null 2>&1
}

@test "libpod create: hostusers, chroot_directories, base_hosts_file, seccomp_policy, intelRdt" {
    # a user of the host that the image does not know
    pm run --rm "$IMG" cat /etc/passwd > "$WORKDIR/image.passwd" 2>&1
    me=$(awk -F: 'NR == FNR { known[$1] = 1; next } !($1 in known) && $3 > 0 && $3 < 60000 { print $1; exit }' \
        "$WORKDIR/image.passwd" /etc/passwd)
    [ -n "$me" ] || skip "every user of the host is known to the image"
    printf '10.9.8.7 base.test\n' > "$WORKDIR/hosts.base"
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfopts","command":["sleep","100"],
        "hostusers":["'"$me"'"],"chroot_directories":["/chr"],"base_hosts_file":"'"$WORKDIR"'/hosts.base"}')
    check "libpod create with hostusers, chroot_directories and base_hosts_file" 201 "$code"
    pm start sfopts > /dev/null 2>&1
    check_match "hostusers: the entry of the host's user" "^$me:\\*:$(id -u "$me"):" "$(pm exec sfopts grep "^$me:" /etc/passwd 2>&1)"
    check_match "base_hosts_file" "base.test" "$(pm exec sfopts cat /etc/hosts 2>&1)"
    check_match "chroot_directories" "hosts" "$(pm exec sfopts ls /chr/etc 2>&1)"
    pm rm -f -t 0 sfopts > /dev/null 2>&1
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfimg","command":["true"],"seccomp_policy":"image"}')
    check "seccomp_policy image of an image without the label" 400 "$code"
    check_match "is refused as podman does" "no seccomp policy defined by image" "$(cat "$WORKDIR/specfields.out")"
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfrdt","command":["true"],"intelRdt":{"closID":"gold"}}')
    check "intelRdt closID" 201 "$code"
    check "is in the spec" "{'closID': 'gold'}" "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["linux"]["intelRdt"])' \
        "$XDG_DATA_HOME/velarx/bundles/$(api http://d/v5.0.0/libpod/containers/sfrdt/json | jq -r .Id)/config.json")"
    pm rm -t 0 -f sfrdt > /dev/null 2>&1
}

@test "libpod create: mask, r_o_paths and unmask ALL" {
    # the lists of masked and read-only paths with unmask ALL are exactly those
    # (what the CRI sends); without unmask the read-only ones add to the defaults
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfpaths","command":["sleep","100"],
        "unmask":["ALL"],"mask":["/etc/os-release"],"r_o_paths":["/tmp"]}')
    check "libpod create with mask, r_o_paths and unmask ALL" 201 "$code"
    pm start sfpaths > /dev/null 2>&1
    check "a read-only path is read-only" "touch: /tmp/x: Read-only file system" \
        "$(pm exec sfpaths touch /tmp/x 2>&1)"
    check "a masked path is masked" "0" "$(pm exec sfpaths sh -c 'wc -c < /etc/os-release' 2>&1)"
    check "the default masked paths are not" "open" \
        "$(pm exec sfpaths sh -c 'test "$(wc -c < /proc/interrupts)" != 0 && echo open || echo masked' 2>&1)"
    check "the default read-only paths are not" "writable" \
        "$(pm exec sfpaths sh -c 'grep -q " /proc/sys ro[ ,]" /proc/self/mountinfo && echo readonly || echo writable' 2>&1)"
    pm rm -f -t 0 sfpaths > /dev/null 2>&1
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfpaths2","command":["sleep","100"],"r_o_paths":["/tmp"]}')
    pm start sfpaths2 > /dev/null 2>&1
    check "r_o_paths without unmask add to the defaults" "touch: /tmp/x: Read-only file system|readonly" \
        "$(pm exec sfpaths2 touch /tmp/x 2>&1)|$(pm exec sfpaths2 sh -c 'grep -q " /proc/sys ro[ ,]" /proc/self/mountinfo && echo readonly || echo writable' 2>&1)"
    pm rm -f -t 0 sfpaths2 > /dev/null 2>&1
}

@test "libpod create: env_host" {
    # (the server's PATH too, as podman's server does: not started)
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfenv","env_host":true}')
    check "env_host gives the server's environment" "201 1" \
        "$code $(api http://d/v5.0.0/libpod/containers/sfenv/json | jq '[.Config.Env[] | select(startswith("HOME="))] | length')"
    pm rm -t 0 -f sfenv > /dev/null 2>&1
}

@test "libpod create: pasta's network options" {
    # (where pasta runs at all)
    libpod_create_code '{"image":"'"$IMG"'","name":"sfpasta0","command":["true"],"netns":{"nsmode":"pasta"}}' > /dev/null
    if pm start sfpasta0 > /dev/null 2>&1; then
        code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfpasta","command":["true"],
            "netns":{"nsmode":"pasta"},"network_options":{"pasta":["--ipv4-only"]}}')
        check "pasta's network options" 201 "$code"
        pm start sfpasta > "$WORKDIR/specfields.start" 2>&1
        check "are given to pasta" "0" "$(pm wait sfpasta 2>&1)$(grep -v sfpasta "$WORKDIR/specfields.start")"
        pm rm -t 0 -f sfpasta > /dev/null 2>&1
    else
        note_skip "pasta's network options" "pasta does not run here"
    fi
    pm rm -t 0 -f sfpasta0 > /dev/null 2>&1
}

@test "libpod create: an image of another architecture" {
    code=$(libpod_create_code '{"image":"'"$IMG"'","image_arch":"s390x"}')
    check "an image of another architecture is refused" 400 "$code"
    check_match "and says why" "architecture" "$(cat "$WORKDIR/specfields.out")"
}

@test "libpod create: the fields refused with the reason" {
    for f in '"gpus":["all"]' \
             '"label_nested":true' '"use_image_resolve_conf":true' \
             '"network_options":{"bridge":["mtu=1400"]}' '"intelRdt":{"l3CacheSchema":"L3:0=f"}' \
             '"storage_opts":{"size":"10G"}' '"devices_from":["c"]'; do
        code=$(libpod_create_code '{"image":"'"$IMG"'",'"$f"'}')
        msg=$(jq -r '.message // .cause // empty' "$WORKDIR/specfields.out" 2> /dev/null)
        check "libpod $f is refused" 501 "$code"
        check_match "and says why ($f)" "not supported" "$msg"
    done
}

@test "libpod create: an init container needs a pod" {
    code=$(libpod_create_code '{"image":"'"$IMG"'","init_container_type":"always"}')
    check "an init container without a pod is refused" 400 "$code"
    check_match "and says why" "must specify pod value with init-ctr" "$(cat "$WORKDIR/specfields.out")"
}

@test "Docker create: the fields it applies" {
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["sleep","100"],"ExposedPorts":{"8081/tcp":{}},
        "HostConfig":{"PublishAllPorts":true,"LogConfig":{"Type":"none","Config":{}},"Umask":"0077",
        "MaskedPaths":[],"ReadonlyPaths":[]},"AttachStdout":true,"StdinOnce":false}' sf2)
    check "Docker create with the fields it applies" 201 "$code"
    check "PublishAllPorts" true "$(api http://d/v1.41/containers/sf2/json | jq -r .HostConfig.PublishAllPorts)"
    check "LogConfig" none "$(api http://d/v1.41/containers/sf2/json | jq -r .HostConfig.LogConfig.Type)"
    check "Umask" 0077 "$(api http://d/v5.0.0/libpod/containers/sf2/json | jq -r .Config.Umask)"
    pm start sf2 > /dev/null 2>&1
    port=$(api http://d/v1.41/containers/sf2/json | jq -r '.NetworkSettings.Ports["8081/tcp"][0].HostPort // empty')
    check_match "the exposed port is published" '^[0-9]+$' "$port"
    out=$(pm exec sf2 sh -c 'cat /proc/kcore > /dev/null 2>&1 & sleep 0.2; kill $! 2> /dev/null; test -c /proc/kcore && echo masked || echo open' 2>&1)
    check "empty MaskedPaths and ReadonlyPaths unmask" open "$out"
    pm rm -f -t 0 sf2 > /dev/null 2>&1
}

@test "Docker create: BlkioWeightDevice, CpuRealtime*, MemorySwappiness, DeviceRequests" {
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"CpuRealtimeRuntime":1000,"CpuRealtimePeriod":10000}}' sf3)
    check "CpuRealtime* are refused" 501 "$code"
    check_match "and named" "CpuRealtime(Runtime|Period) is not supported" "$(cat "$WORKDIR/specfields.out")"
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"CpuRealtimeRuntime":0,"CpuRealtimePeriod":0}}' sf3)
    check "CpuRealtime* of 0 are not set" 201 "$code"
    pm rm -t 0 -f sf3 > /dev/null 2>&1
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"MemorySwappiness":30}}' sf4)
    check "MemorySwappiness is refused" 501 "$code"
    check_match "and named" "MemorySwappiness is not supported" "$(cat "$WORKDIR/specfields.out")"
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"MemorySwappiness":-1}}' sf4)
    check "MemorySwappiness -1 is not set" 201 "$code"
    pm rm -t 0 -f sf4 > /dev/null 2>&1
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"BlkioWeightDevice":[{"Path":"/dev/null","Weight":100}]}}' sf5)
    check "BlkioWeightDevice goes to the engine, which wants a block device" 400 "$code"
    check_match "and says so" "/dev/null: not a block device" "$(cat "$WORKDIR/specfields.out")"
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"DeviceRequests":[{"Driver":"cdi","DeviceIDs":["nosuch.vendor.com/dev=0"]}]}}' sf6)
    check "a cdi device request is a CDI device" 400 "$code"
    check_match "the engine looks it up" "nosuch.vendor.com/dev=0" "$(cat "$WORKDIR/specfields.out")"
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"DeviceRequests":[{"Driver":"nvidia","Count":-1,"Capabilities":[["gpu"]]}]}}' sf7)
    check "another driver is refused" 501 "$code"
    pm rm -t 0 -f sf5 sf6 sf7 > /dev/null 2>&1
}

@test "Docker create: NetworkDisabled" {
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"NetworkDisabled":true}' sf3)
    check "NetworkDisabled" "201 none" "$code $(api http://d/v1.41/containers/sf3/json | jq -r .HostConfig.NetworkMode)"
    pm rm -t 0 -f sf3 > /dev/null 2>&1
}

@test "Docker create: the endpoint fields podman drops" {
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"NetworkingConfig":{"EndpointsConfig":{"podman":{"Links":["x:y"],"DriverOpts":{"a":"b"},"GwPriority":2}}}}' sfep)
    check "Links, DriverOpts and GwPriority of an endpoint are ignored" 201 "$code"
    pm rm -t 0 -f sfep > /dev/null 2>&1
}

@test "Docker create: the fields refused with the reason" {
    for f in '"Domainname":"example.com"' \
             '"HostConfig":{"CpuCount":2}' '"HostConfig":{"MaskedPaths":["/proc/x"]}'; do
        code=$(docker_create_code '{"Image":"'"$IMG"'",'"$f"'}' "")
        check "Docker $f is refused" 501 "$code"
        check_match "and says why ($f)" "not supported" "$(jq -r '.message // empty' "$WORKDIR/specfields.out" 2> /dev/null)"
    done
}

@test "create: a memory limit alone allows as much swap (podman's handlers)" {
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfswap","command":["true"],"resource_limits":{"memory":{"limit":3145728}}}')
    check "libpod create with a memory limit" 201 "$code"
    check "libpod: memory + swap is twice the limit" 6291456 \
        "$(api http://d/v5.0.0/libpod/containers/sfswap/json | jq -r .HostConfig.MemorySwap)"
    pm rm sfswap > /dev/null 2>&1
    code=$(libpod_create_code '{"image":"'"$IMG"'","name":"sfswap0","command":["true"],"resource_limits":{"memory":{"limit":3145728,"swap":0}}}')
    check "libpod create with swap 0" 201 "$code"
    check "libpod: swap 0 is no swap (memory + swap = memory)" 0 \
        "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["linux"]["resources"]["memory"]["swap"])' \
            "$XDG_DATA_HOME/velarx/bundles/$(api http://d/v5.0.0/libpod/containers/sfswap0/json | jq -r .Id)/config.json")"
    pm rm sfswap0 > /dev/null 2>&1
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"Memory":3145728}}' dkswap)
    check "docker create with a memory limit" 201 "$code"
    check "docker: memory + swap is twice the limit" 6291456 \
        "$(api http://d/v1.41/containers/dkswap/json | jq -r .HostConfig.MemorySwap)"
    pm rm dkswap > /dev/null 2>&1
    code=$(docker_create_code '{"Image":"'"$IMG"'","Cmd":["true"],"HostConfig":{"Memory":3145728,"MemorySwap":-1}}' dkswapu)
    check "docker create with MemorySwap -1" 201 "$code"
    check "docker: -1 stays unlimited" -1 \
        "$(api http://d/v1.41/containers/dkswapu/json | jq -r .HostConfig.MemorySwap)"
    pm rm dkswapu > /dev/null 2>&1
}
