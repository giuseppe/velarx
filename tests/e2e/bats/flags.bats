# SPDX-License-Identifier: Apache-2.0
# The flags that systemd units (Quadlet) need, against a rootless daemon in a
# scratch HOME.  The image is made here from host binaries (no registry):
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/flags.bats

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

# The manager that auto-update restarts a unit through: the user manager of
# the caller, the system manager as root (as podman does).
au_systemctl () {
    if [ "$(id -u)" = 0 ]; then systemctl "$@"; else XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR systemctl --user "$@"; fi
}
au_systemd_run () {
    if [ "$(id -u)" = 0 ]; then systemd-run "$@"; else XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR systemd-run --user "$@"; fi
}

showsecret () { sc secret inspect --showsecret "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["SecretData"])'; }

setup_file () {
    e2e_setup_file
    e2e_system_bin
    # the unit of the auto-update checks, of this run only (runs in parallel
    # must not share it)
    export AU_UNIT=sh-e2e-au-$$
    export ROOT=$WORKDIR/rootfs
    e2e_start_daemon
    e2e_make_image
}

# a gpg-agent of the pass test does not outlive a test that failed
teardown () {
    [ -z "${GNUPGHOME_E2E:-}" ] || gpgconf --homedir "$GNUPGHOME_E2E" --kill all 2> /dev/null
    return 0
}

teardown_file () {
    set +e
    local u
    for u in $AU_UNIT; do
        au_systemctl stop "$u.service" 2> /dev/null
        au_systemctl reset-failed "$u.service" 2> /dev/null
    done
    e2e_remove_containers "$BIN/velarx" "$ESOCK"
    # a container of a failed test keeps the mounts of its network namespace
    [ -z "${WORKDIR:-}" ] || e2e_detach_mounts "$WORKDIR"
    e2e_teardown_file
}

@test "the test image is imported" {
    sc image exists "$IMG"
    check "import the test image" 0 $?
}

@test "podman's global options" {
    check "-v" "$("$BIN/velarx" --version)" "$("$SH" -v)"
    G="--storage-driver overlay --root $WORKDIR/groot --runroot $WORKDIR/grun --tmpdir $WORKDIR/gtmp"
    # shellcheck disable=SC2086
    "$SH" $G image import "$WORKDIR/rootfs.tar" localhost/e2e-other:1 > /dev/null
    check "--root: an image in another store" 0 $?
    # shellcheck disable=SC2086
    check "--root: the store is that one" "localhost/e2e-other:1" "$("$SH" $G images --format '{{.Repository}}:{{.Tag}}')"
    check "--root: the default store is not" "" "$(sc images --format '{{.Repository}}:{{.Tag}}' | grep e2e-other)"
    # shellcheck disable=SC2086
    out=$("$SH" $G run --rm --network none localhost/e2e-other:1 echo isolated 2>&1)
    check "--runroot: a run in the other store" "isolated" "$out"
    [ -d "$WORKDIR/gtmp" ]
    check "--tmpdir: the directory is made" 0 $?
    out=$("$SH" --storage-driver zfs images 2>&1)
    check "--storage-driver that is none of velarx's" 125 $?
    # (vfs is not podman's spelling of nothing: the driver of its own, and
    # a store made with composefs is not opened with it)
    out=$("$SH" --storage-driver vfs images 2>&1)
    check "--storage-driver vfs on a composefs store" 125 $?
    check_match "--storage-driver vfs says which store it is" 'made with the storage driver "composefs", but vfs is asked for' "$out"
    out=$("$SH" --runtime nosuchruntime $G run --rm --network none localhost/e2e-other:1 true 2>&1)
    check "--runtime that is not there" 125 $?
    check_match "--runtime says so" "nosuchruntime.*not found" "$out"
    check "--root alone: not the store of the server that runs" "" \
        "$("$SH" --root "$WORKDIR/groot-alone" images --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    out=$("$SH" --runtime nosuchruntime run --rm --network none "$IMG" true 2>&1)
    check "--runtime with a server that runs: not that server's runtime" 125 $?
    check_match "--runtime with a server that runs says so" "nosuchruntime.*not found" "$out"
    out=$(sc --runtime-flag debug images 2>&1)
    check "--runtime-flag with --socket is refused" 125 $?
    out=$("$SH" --cgroup-manager bogus images 2>&1)
    check "--cgroup-manager that is none" 125 $?
    # podman's files are not velarx's: never read, not even named
    printf '[storage]\ngraphrot = "/x"\n' > "$WORKDIR/storage-typo.conf"
    printf '[engine]\nruntim = "crun"\n' > "$WORKDIR/containers-typo.conf"
    out=$(CONTAINERS_STORAGE_CONF=$WORKDIR/storage-typo.conf CONTAINERS_CONF=$WORKDIR/containers-typo.conf \
        "$SH" --root "$WORKDIR/groot-cc" images -q 2>&1)
    check "storage.conf and containers.conf are not read" "0 " "$? $out"
    out=$("$SH" --module e2e images 2>&1)
    check "--module is refused" 125 $?
    check_match "--module names velarx's file" "reads no containers.conf.*config.toml" "$out"
    check "--url and --remote ask the server" "localhost/e2e-base:1" \
        "$("$SH" --remote --url "unix://$ESOCK" images --format '{{.Repository}}:{{.Tag}}')"
    out=$("$SH" --url "tcp://127.0.0.1:1" images 2>&1)
    check "--url that is not a unix socket" 125 $?
    out=$("$SH" --connection x images 2>&1)
    check "--connection is refused" 125 $?
    out=$(CONTAINER_CONNECTION=x "$SH" images 2>&1)
    check "CONTAINER_CONNECTION is refused" 125 $?
}

@test "--ignore of rm, stop and create" {
    sc container rm nosuch > /dev/null 2>&1
    check "rm of a missing container fails" 1 $?
    check "rm --ignore of a missing container" "" "$(sc container rm --ignore nosuch 2>&1)"
    sc container rm -i nosuch > /dev/null 2>&1
    check "rm -i is --ignore" 0 $?
    sc container stop --ignore nosuch > /dev/null 2>&1
    check "stop --ignore of a missing container" 0 $?
    sc pod rm nosuch > /dev/null 2>&1
    check "pod rm of a missing pod fails" 1 $?
    sc pod rm --ignore nosuch > /dev/null 2>&1
    check "pod rm --ignore" 0 $?
    sc pod stop --ignore nosuch > /dev/null 2>&1
    check "pod stop --ignore" 0 $?
    sc volume create ev1 > /dev/null
    sc volume create ev1 > /dev/null 2>&1
    check "volume create of an existing volume fails" 125 $?
    check "volume create --ignore prints the name" ev1 "$(sc volume create --ignore ev1)"
    sc volume remove ev1 > /dev/null
    sc network create -d host en1 > /dev/null
    sc network create -d host en1 > /dev/null 2>&1
    check "network create of an existing network fails" 125 $?
    check "network create --ignore prints the name" en1 "$(sc network create -d host --ignore en1)"
    sc network remove en1 > /dev/null
}

@test "inspect of a missing name is 125, of all found is 0" {
    sc volume create iv1 > /dev/null
    sc pod create ip1 > /dev/null
    sc volume inspect iv1 > /dev/null
    check "volume inspect of a volume" 0 $?
    sc volume inspect nosuch > /dev/null 2>&1
    check "volume inspect of a missing volume fails" 125 $?
    out=$(sc volume inspect iv1 nosuch 2> /dev/null)
    check "volume inspect of a volume and a missing one fails" 125 $?
    check_match "the volume found is still printed" '"Name": "iv1"' "$out"
    sc pod inspect ip1 > /dev/null
    check "pod inspect of a pod" 0 $?
    sc pod inspect nosuch > /dev/null 2>&1
    check "pod inspect of a missing pod fails" 125 $?
    sc pod inspect ip1 nosuch > /dev/null 2>&1
    check "pod inspect of a pod and a missing one fails" 125 $?
    for what in container image network; do
        sc $what inspect nosuch > /dev/null 2>&1
        check "$what inspect of a missing name fails" 125 $?
    done
    sc secret inspect nosuch > /dev/null 2>&1
    check "secret inspect of a missing name fails" 125 $?
    sc system inspect nosuch > /dev/null 2>&1
    check "inspect of a missing name fails" 125 $?
    sc system inspect iv1 > /dev/null
    check "inspect finds a volume" 0 $?
    sc pod rm nosuch > /dev/null 2>&1
    check "pod rm of only missing pods is still 1" 1 $?
    sc volume rm nosuch > /dev/null 2>&1
    check "volume rm of only missing volumes is 1" 1 $?
    sc pod rm -t 0 -f ip1 > /dev/null
    sc volume remove iv1 > /dev/null
}

@test "--replace makes a new container" {
    id1=$(sc container create --name rep $IMG /bin/true)
    sc container create --name rep $IMG /bin/true > /dev/null 2>&1
    check "create of an existing name fails" 125 $?
    id2=$(sc container create --replace --name rep $IMG /bin/true)
    [ -n "$id2" ] && [ "$id1" != "$id2" ]
    check "--replace makes a new container" 0 $?
    check "--replace removed the old one" 0 "$(sc container list -a | grep -c "${id1:0:12}")"
    id3=$(sc container create --replace --name fresh $IMG /bin/true)
    check_match "--replace of a missing name just creates" '^[0-9a-f]{12,}$' "$id3"
    sc container rm -t 0 -f rep fresh > /dev/null
}

@test "--cidfile holds the id, an existing file is replaced as podman does" {
    cid=$WORKDIR/cid
    id=$(sc container create --cidfile "$cid" --name cidc $IMG /bin/true)
    check "cidfile has the id" "$id" "$(cat "$cid")"
    sc container create --cidfile "$cid" --name cidc $IMG /bin/true > /dev/null 2>&1
    check "a create that fails leaves the file that was there" "$id" "$(cat "$cid")"
    id2=$(sc container create --cidfile "$cid" $IMG /bin/true 2>&1)
    check "a cidfile that exists is written again" "$id2" "$(cat "$cid")"
    sc container rm -t 0 -f "$id2" > /dev/null
    sc container create --cidfile "$WORKDIR/cid2" --name cidc $IMG /bin/true > /dev/null 2>&1
    check "no cidfile when the create fails" 1 "$([ -e "$WORKDIR/cid2" ] && echo 0 || echo 1)"
    sc container rm -t 0 -f cidc > /dev/null
}

@test "--pull policies" {
    out=$(sc container create --pull=never localhost/e2e-missing:1 /bin/true 2>&1)
    check "--pull=never does not pull" 0 "$(echo "$out" | grep -c "Trying to pull")"
    sc container create --pull=bogus $IMG /bin/true > /dev/null 2>&1
    check "--pull with a bad policy is an error" 125 $?
    out=$(sc container create --pull=missing --name pm $IMG /bin/true 2>&1)
    check "--pull=missing does not pull a present image" 0 "$(echo "$out" | grep -c "Trying to pull")"
    out=$(sc container create --pull=missing localhost:1/e2e-absent:1 /bin/true 2>&1)
    check_match "--pull=missing pulls an absent image" "Trying to pull localhost:1/e2e-absent:1" "$out"
    out=$(sc container create --pull=always localhost:1/e2e-base:1 /bin/true 2>&1)
    check_match "--pull=always pulls" "Trying to pull localhost:1/e2e-base:1" "$out"
    sc container rm -t 0 -f pm > /dev/null
}

@test "--secret mounts a file, with a target or as an environment variable" {
    printf 's3cret' | sc secret create sec1 - > /dev/null
    check "secret create" 0 $?
    out=$(sc container run --rm --secret sec1 $IMG /bin/cat /run/secrets/sec1)
    check "--secret mounts a file" s3cret "$out"
    out=$(sc container run --rm --secret sec1,target=/etc/other,mode=0600 $IMG /bin/cat /etc/other)
    check "--secret target" s3cret "$out"
    out=$(sc container run --rm --secret sec1,type=env,target=SEC $IMG /bin/env)
    check_match "--secret type=env" "(^|[[:space:]])SEC=s3cret" "$out"
    sc container run --rm --secret nosuch $IMG /bin/true > /dev/null 2>&1
    check "--secret of a missing secret fails" 125 $?
}

@test "the secret commands" {
    sc secret exists sec1 || { echo "needs the secret sec1 of the test '--secret mounts a file'" >&2; exit 1; }
    check "secret ls -q" "$(sc secret inspect sec1 | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["ID"])')" "$(sc secret ls -q)"
    check_match "secret ls table" "^ID +NAME +DRIVER +CREATED +UPDATED" "$(sc secret ls)"
    check "secret ls --format" "sec1 file" "$(sc secret ls --format '{{.Name}} {{.Driver}}')"
    check "secret inspect hides the data" 0 "$(sc secret inspect sec1 | grep -c SecretData)"
    check "secret inspect --showsecret" s3cret "$(sc secret inspect --showsecret sec1 | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["SecretData"])')"
    sc secret exists sec1
    check "secret exists" 0 $?
    sc secret exists nosuch
    check "secret exists of a missing secret" 1 $?
    printf 'x' | sc secret create sec1 - > /dev/null 2>&1
    check "secret create of an existing name fails" 125 $?
    FOO=fromenv sc secret create --env -l a=b sec2 FOO > /dev/null
    check "secret create --env" fromenv "$(sc secret inspect --showsecret sec2 | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["SecretData"])')"
    check "secret labels" b "$(sc secret inspect sec2 | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[0]["Spec"]["Labels"]["a"])')"
    sc secret rm nosuch > /dev/null 2>&1
    check "secret rm of a missing secret fails" 125 $?
    sc secret rm -i nosuch > /dev/null 2>&1
    check "secret rm --ignore" 0 $?
    check "secret rm prints the name" sec2 "$(sc secret rm sec2)"
    sc secret rm --all
    check "secret rm --all" "" "$(sc secret ls -q)"
}

@test "secrets: owner and mode, --replace, --ignore and the shell driver" {
    printf 'own' | sc secret create sown - > /dev/null
    out=$(sc container run --rm --secret sown,uid=1000,gid=1001,mode=0400 $IMG /bin/stat -c '%u %g %a' /run/secrets/sown)
    check "--secret uid, gid and mode" "1000 1001 400" "$out"
    out=$(sc container run --rm --user 1000 --secret sown,uid=1000,mode=0400 $IMG /bin/cat /run/secrets/sown)
    check "the user of the secret reads it" own "$out"
    old_id=$(sc secret ls -q)
    printf 'new' | sc secret create --replace sown - > /dev/null
    check "secret create --replace" new "$(showsecret sown)"
    check "--replace makes a new id" 1 "$([ "$(sc secret ls -q)" != "$old_id" ] && echo 1)"
    printf 'other' | sc secret create --ignore sown - > /dev/null
    check "secret create --ignore keeps the secret" new "$(showsecret sown)"
    sc secret rm sown > /dev/null
    SH_STORE=$WORKDIR/shell-secrets
    mkdir -p "$SH_STORE"
    printf 'viashell' | sc secret create --driver shell \
        --driver-opts "list=ls $SH_STORE,lookup=cat $SH_STORE/\$SECRET_ID" \
        --driver-opts "store=cat > $SH_STORE/\$SECRET_ID,delete=rm $SH_STORE/\$SECRET_ID" ssh - > /dev/null
    check "secret create --driver shell" 1 "$(ls "$SH_STORE" | wc -l)"
    check "shell driver: the data" viashell "$(showsecret ssh)"
    check "shell driver: in a container" viashell "$(sc container run --rm --secret ssh $IMG /bin/cat /run/secrets/ssh)"
    check "shell driver: inspect shows the driver" shell "$(sc secret ls --format '{{.Driver}}')"
    sc secret rm ssh > /dev/null
    check "shell driver: rm deletes the data" 0 "$(ls "$SH_STORE" | wc -l)"
    printf 'x' | sc secret create --driver shell --driver-opts "list=true" sbad - > /dev/null 2>&1
    check "shell driver without its commands fails" 125 $?
}

@test "the pass driver encrypts a secret" {
    command -v gpg > /dev/null || skip "no gpg"
    export GNUPGHOME_E2E=$WORKDIR/gnupg
    mkdir -m 700 -p "$GNUPGHOME_E2E"
    gpg --homedir "$GNUPGHOME_E2E" --batch --passphrase '' --quick-gen-key 'e2e <e2e@example.com>' default default never > /dev/null 2>&1
    printf 'viapass' | sc secret create --driver pass \
        --driver-opts "root=$WORKDIR/pass,key=e2e@example.com,gpghomedir=$GNUPGHOME_E2E" spass - > /dev/null
    check "secret create --driver pass" 0 $?
    check "pass driver: encrypted at rest" 0 "$(cat "$WORKDIR"/pass/*.gpg | grep -c viapass)"
    check "pass driver: the data" viapass "$(showsecret spass)"
    check "pass driver: in a container" viapass "$(sc container run --rm --secret spass $IMG /bin/cat /run/secrets/spass)"
    sc secret rm spass > /dev/null
    check "pass driver: rm deletes the data" 0 "$(ls "$WORKDIR/pass" | wc -l)"
    gpgconf --homedir "$GNUPGHOME_E2E" --kill all 2> /dev/null
}

@test "pod create options" {
    sc pod create --infra-image $IMG --infra-name ep1-i --exit-policy continue ep1 > /dev/null
    check "pod create with --infra-name and --exit-policy" 0 $?
    sc pod create --infra-image $IMG ep1 > /dev/null 2>&1
    check "pod create of an existing name fails" 125 $?
    id1=$(sc pod inspect ep1 | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d["Id"])')
    sc pod create --infra-image $IMG --replace ep1 > /dev/null
    check "pod create --replace" 0 $?
    id2=$(sc pod inspect ep1 | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d["Id"])')
    [ -n "$id2" ] && [ "$id1" != "$id2" ]
    check "--replace made a new pod" 0 $?
    sc pod create bad --exit-policy sometimes > /dev/null 2>&1
    check "bad exit policy" 125 $?
    sc pod rm -t 0 -f ep1 > /dev/null
}

@test "pod create takes its name as an argument, --name or -n" {
    # the name: an argument, --name or -n, as podman; made up without one
    sc pod create --infra-image $IMG --name epn > /dev/null
    check "pod create --name" 0 $?
    sc pod create --infra-image $IMG -n epn2 > /dev/null
    check "pod create -n" 0 $?
    sc pod create --infra-image $IMG --name epn3 epn4 > /dev/null 2>&1
    check "pod create with a name and --name fails" 125 $?
    before=$(sc pod inspect epn3 epn4 > /dev/null 2>&1; echo $?)
    check "and makes no pod" 125 "$before"
    sc pod create --infra-image $IMG > /dev/null
    check "pod create without a name" 0 $?
    check "a pod without a name gets one" 1 "$(sc pod list -a | grep -cE ' pod-[0-9a-f]{12} ')"
    sc pod list -a | grep -oE 'pod-[0-9a-f]{12}' | xargs -r sc pod rm -t 0 -f > /dev/null 2>&1
    sc pod rm -t 0 -f epn epn2 > /dev/null
}

@test "a container with no network keeps the resolv.conf of its image" {
    # as podman: nothing is mounted on it, inspect has no path for it
    image=$(sc run --rm --network none --entrypoint sh $IMG -c 'cat /etc/resolv.conf 2>&1; true')
    sc create --name nodns --network none $IMG true > /dev/null
    check "--network none: no ResolvConfPath" "" "$(sc container inspect nodns --format '{{.ResolvConfPath}}')"
    sc container rm -t 0 -f nodns > /dev/null
    check "--network none: no default name servers" 0 "$(echo "$image" | grep -c 8.8.8.8)"
    mounted=$(sc run --rm --network none --entrypoint sh $IMG -c \
        'while read -r l; do case "$l" in *" /etc/resolv.conf "*) echo mounted ;; esac; done < /proc/self/mountinfo')
    check "--network none: no mount on /etc/resolv.conf" "" "$mounted"
}

@test "a container has no resolv.conf, hostname and hosts paths before it is initialized" {
    # as podman: the files are made by the init
    sc create --name nopaths $IMG true > /dev/null
    for f in ResolvConfPath HostnamePath HostsPath; do
        check "created: no $f" "" "$(sc container inspect nopaths --format "{{.$f}}")"
    done
    sc container init nopaths > /dev/null
    for f in ResolvConfPath HostnamePath HostsPath; do
        check_match "initialized: $f" "/" "$(sc container inspect nopaths --format "{{.$f}}")"
    done
    sc container rm -t 0 -f nopaths > /dev/null
}

@test "the members of a pod resolve as the pod does, a host network pod's use the host's" {
    # the members of a pod resolve as the pod does, and a host network pod's use the host's namespace
    sc pod create --name pdns --dns 10.1.2.3 --dns-search foo.example --dns-option ndots:3 > /dev/null
    check "pod DNS settings: in a member" "search foo.example
nameserver 10.1.2.3
options ndots:3" "$(sc run --rm --pod pdns $IMG cat /etc/resolv.conf 2>&1)"
    # the files of the infra container are the members': a change of them in
    # place reaches a member that runs
    sc run -d --name pdm --pod pdns $IMG /bin/sleep 300 > /dev/null
    check "a member of the pod runs" 0 $?
    infra=$(sc pod inspect pdns | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d[0] if isinstance(d,list) else d; print(d["InfraContainerID"])')
    echo "nameserver 10.7.7.7" > "$(sc container inspect "$infra" --format '{{.ResolvConfPath}}')"
    check "a change of the resolv.conf of the infra container reaches a member" "nameserver 10.7.7.7" \
        "$(sc exec pdm cat /etc/resolv.conf 2>&1)"
    echo "10.7.7.8 added.test" >> "$(sc container inspect "$infra" --format '{{.HostsPath}}')"
    check_match "and so does a change of its /etc/hosts" "10.7.7.8 added.test" "$(sc exec pdm cat /etc/hosts 2>&1)"
    sc container rm -t 0 -f pdm > /dev/null
    check_match "pod DNS settings: a member's own are refused" "conflicting options: dns and the network mode: container" \
        "$(sc run --rm --pod pdns --dns 10.9.9.9 $IMG cat /etc/resolv.conf 2>&1)"
    sc pod rm -t 0 -f pdns > /dev/null
    sc pod create --name pplain > /dev/null
    check "pod without DNS settings: a member resolves as a container alone" "$(sc run --rm $IMG cat /etc/resolv.conf 2>&1)" \
        "$(sc run --rm --pod pplain $IMG cat /etc/resolv.conf 2>&1)"
    sc pod rm -t 0 -f pplain > /dev/null
    sc pod create --name phost --network host > /dev/null
    hostns=$(readlink /proc/self/ns/net)
    check "host network pod: a member is in the host network namespace" "$hostns" \
        "$(sc run --rm --pod phost $IMG ls -l /proc/self/ns/net 2>&1 | sed 's/.* -> //')"
    # (podman's: the servers, search domains and options of the host's)
    check "host network pod: a member has the host's resolv.conf" \
        "$(grep -E '^[[:space:]]*nameserver' /etc/resolv.conf | awk '{ print $1, $2 }')" \
        "$(sc run --rm --pod phost $IMG cat /etc/resolv.conf 2>&1 | grep '^nameserver')"
    check "and a container of the host network the same" \
        "$(sc run --rm --network host $IMG cat /etc/resolv.conf 2>&1)" \
        "$(sc run --rm --pod phost $IMG cat /etc/resolv.conf 2>&1)"
    sc run --rm --pod phost --network none $IMG true > /dev/null 2>&1
    check "host network pod: a member cannot ask for another network" 125 $?
    sc pod rm -t 0 -f phost > /dev/null
}

@test "volume create options" {
    sc volume create --uid 0 --gid 0 ev2 > /dev/null
    check "volume create --uid --gid" 0 $?
    sc volume create --opt o=uid=0 --opt copy ev3 > /dev/null
    check "volume create --opt o=uid= and copy" 0 $?
    sc volume create --opt bogus=1 ev4 > /dev/null 2>&1
    check "volume create refuses unknown options" 125 $?
    sc volume remove ev2 ev3 > /dev/null
}

@test "network create options" {
    sc network create -d host --label a=b --opt k=v --ipam-driver host-local en2 > /dev/null
    check "network create with --label --opt --ipam-driver" 0 $?
    # The bridge options mean nothing for a host network: refused, and nothing
    # is left (a name already taken would make the checks vacuous).
    for f in --internal --ipv6 --disable-dns "--dns 1.1.1.1" "--ip-range 10.0.0.0/24" "--ipam-driver dhcp"; do
        out=$(sc network create -d host $f en3 2>&1)
        check "network create -d host $f is refused" 125 $?
        sc network exists en3
        check "network create -d host $f left no network" 1 $?
        sc network remove en3 > /dev/null 2>&1
    done
    sc network create --internal --disable-dns --dns 1.1.1.1 --ip-range 10.90.77.0/25 --subnet 10.90.77.0/24 en3 > /dev/null
    check "the bridge takes --internal --disable-dns --dns --ip-range" 0 $?
    sc network remove en3 > /dev/null
    # a host or none network has no interface to add to a container
    sc container create --name en-c $IMG /bin/true > /dev/null
    sc network create -d none en-none > /dev/null
    for n in en2:host en-none:none; do
        out=$(sc network connect "${n%%:*}" en-c 2>&1)
        check "network connect to a ${n##*:} network is refused" 125 $?
        check_match "and names the network and the driver" "connect to the network \`${n%%:*}\`: the ${n##*:} driver" "$out"
        out=$(sc network disconnect "${n%%:*}" en-c 2>&1)
        check "network disconnect from a ${n##*:} network is refused" 125 $?
        check_match "and names the network and the driver" "disconnect from the network \`${n%%:*}\`: the ${n##*:} driver" "$out"
    done
    sc container remove -f en-c > /dev/null
    sc network remove en-none en2 > /dev/null
}

@test "ps takes --external and --sync: the store has no containers of other tools, the state is the runtime's" {
    e2e_label_for_containers "$ROOT"
    sc container run -d --name psx --network none --rootfs "$ROOT" /bin/sleep 100 > /dev/null
    for f in --external --sync "--external --sync"; do
        check "ps $f" "psx" "$(sc ps $f --format '{{.Names}}')"
    done
    sc container remove -f -t 0 psx > /dev/null
}

@test "--rootfs runs a directory as the root file system" {
    e2e_label_for_containers "$ROOT"
    out=$(sc container run --rm --rootfs "$ROOT" /bin/echo rootfs 2>&1)
    check "--rootfs runs a directory as the root file system" "rootfs" "$out"
}

@test "auto-update restarts the units of the updated images" {
    au_systemctl is-active default.target > /dev/null 2>&1 ||
        skip "no systemd manager"
    # A transient unit runs a container labelled for the local policy.  It is
    # one-shot: the container is detached and the unit stays active.
    mkimage () { # name: a copy of the base image with /bin/true removed or kept
        rm -rf "$WORKDIR/img2"; cp -a "$ROOT" "$WORKDIR/img2"
        echo "$2 $RANDOM" > "$WORKDIR/img2/etc/version"
        [ "$2" = broken ] && rm -f "$WORKDIR/img2/bin/true" "$WORKDIR/img2/bin/sleep"
        tar -C "$WORKDIR/img2" -cf "$WORKDIR/img2.tar" .
        sc image import "$WORKDIR/img2.tar" "$1" > /dev/null
    }
    userctl () { au_systemctl "$@"; }
    sc image tag $IMG localhost/e2e-au:1
    UNIT=$AU_UNIT.service
    au_systemd_run --quiet --unit=$AU_UNIT \
        -p Type=oneshot -p RemainAfterExit=yes -p Environment=PODMAN_SYSTEMD_UNIT=$AU_UNIT.service \
        "$BIN/velarx" --config "$XDG_CONFIG_HOME/velarx/config.toml" --socket "$ESOCK" container run -d --replace --name au \
        --label io.containers.autoupdate=local localhost/e2e-au:1 /bin/sleep 300
    check "the unit runs the container" 0 $?
    check_match "the unit is recorded in a label" "$UNIT" \
        "$(sc container inspect au | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["labels"])')"
    first=$(sc container inspect au | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    out=$(XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR sc auto-update --format '{{.Unit}} {{.Policy}} {{.Updated}}')
    check "nothing to update" "$UNIT local false" "$out"

    mkimage localhost/e2e-au:1 good
    [ -n "${E2E_DEBUG:-}" ] && { sc image list; sc container list -a; XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR sc auto-update --dry-run --format json; }
    out=$(XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR sc auto-update --dry-run --format '{{.Unit}} {{.Updated}}')
    check "dry run reports the update" "$UNIT pending" "$out"
    check "dry run restarts nothing" "$first" "$(sc container inspect au | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
    out=$(XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR sc auto-update --format '{{.Unit}} {{.Updated}}')
    check "the update restarts the unit" "$UNIT true" "$out"
    second=$(sc container inspect au | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    [ -n "$second" ] && [ "$second" != "$first" ]
    check "the container was replaced" 0 $?

    mkimage localhost/e2e-au:1 broken
    out=$(XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR sc auto-update --format '{{.Unit}} {{.Updated}}' 2> /dev/null)
    check "a unit that fails with the new image is rolled back" "$UNIT rolled back" "$out"
    check "the unit is active again" active "$(userctl show -P ActiveState $UNIT)"
    out=$(XDG_RUNTIME_DIR=$REAL_RUNTIME_DIR sc auto-update --rollback=false --format '{{.Updated}}' 2> /dev/null)
    check "nothing more to do after the rollback" false "$out"
    userctl stop $UNIT 2> /dev/null
    sc container rm -t 0 -f au > /dev/null 2>&1
}

# an option velarx cannot honour is an error that names it, never ignored
@test "options that velarx does not honour are refused" {
    local args pattern
    while IFS='|' read -r args pattern; do
        [ -n "$args" ] || continue
        # shellcheck disable=SC2086
        out=$(sc $args 2>&1)
        check "$args: exit code" 125 $?
        check_match "$args: says so" "$pattern" "$out"
    done << 'EOF'
image save --compress -o /dev/null x|--compress can only be set when --format is 'docker-dir'
manifest add --artifact --all nolist nofile|--all is not supported
manifest add --artifact --creds u:p nolist nofile|--creds is not supported
EOF
}
