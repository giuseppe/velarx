# SPDX-License-Identifier: Apache-2.0
# System routes: ping, version, info, system check, login and the disk usage.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

@test "ping, unknown route and wrong method" {
    out=$(api -i http://d/v5.0.0/libpod/_ping | tr -d '\r')
    check_match "_ping" "^OK$" "$out"
    check_match "_ping Libpod-Api-Version" "^[Ll]ibpod-[Aa]pi-[Vv]ersion: [5-9]\." "$out"
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/nothing)
    check "unknown route" 404 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v5.0.0/libpod/_ping)
    check "wrong method" 405 "$out"
}

@test "version and info" {
    out=$(pm version --format '{{.Server.APIVersion}}')
    check_match "version" "^[5-9]\." "$out"
    out=$(pm info --format '{{.Host.RemoteSocket.Path}}')
    check "info remote socket" "$SOCK" "$out"
    out=$(pm info --format '{{.Host.OS}} {{.Store.GraphDriverName}}')
    check_match "info" "^linux " "$out"
    out=$(api http://d/v1.41/info | jq -r .OSType)
    check "compat info" linux "$out"
    expected=$(. /etc/os-release; echo "$ID $VERSION_ID")
    out=$(pm info --format '{{.Host.Distribution.Distribution}} {{.Host.Distribution.Version}}')
    check "info distribution" "$expected" "$out"
    out=$(api http://d/v1.41/info | jq -r '.OSVersion + " " + .OperatingSystem')
    check "compat info OSVersion and OperatingSystem" "$(. /etc/os-release; echo "$VERSION_ID $PRETTY_NAME")" "$out"
}

@test "system check" {
    # podman system check: velarx's storage check
    pm system check --quick > "$WORKDIR/check.out" 2>&1
    check "system check" 0 $?
    out=$(api -X POST "http://d/v5.0.0/libpod/system/check?quick=true" | jq -r '"\(.Errors) \(.Layers | length)"')
    check "system check report" "false 0" "$out"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/system/check?unreferenced_layer_max_age=1d")
    check "system check with a bad age" 400 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/system/check?repair_lossy=true&unreferenced_layer_max_age=1h0m0s")
    check "system check with a Go duration" 200 "$code"
    out=$(api -X POST "http://d/v5.0.0/libpod/system/check" | jq -c '[.Errors, .Layers, .RemovedContainers]')
    check "system check: nothing is null" '[false,null,null]' "$out"
    out=$(api http://d/v1.41/version | jq -r .Os)
    check "compat version" linux "$out"
}

@test "docker info" {
    command -v docker > /dev/null || skip "no docker client"
    out=$(dk info --format '{{.OSType}}')
    check "docker info" "linux" "$out"
}

@test "auth through the API" {
    out=$(api -X POST -H 'Content-Type: application/json' \
              -d "{\"username\":\"u\",\"password\":\"p\",\"serveraddress\":\"$E2E_REGISTRY\"}" http://d/v1.41/auth | jq -r .Status)
    check "auth" "Login Succeeded" "$out"
    # a registry that wants credentials checks them (E2E_AUTH_REGISTRY)
    if [ -n "${E2E_AUTH_REGISTRY:-}" ]; then
        auth () {
            api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
                -d "{\"username\":\"$E2E_AUTH_USER\",\"password\":\"$1\",\"serveraddress\":\"$E2E_AUTH_REGISTRY\"}" http://d/v1.41/auth
        }
        check "auth with the password" 200 "$(auth "$E2E_AUTH_PASSWORD")"
        check "auth with a wrong password" 500 "$(auth "wrong-$E2E_AUTH_PASSWORD")"
    fi
    out=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
              -d '{"username":"u","password":"p","serveraddress":"localhost:1"}' http://d/v1.41/auth)
    # podman: a failed login is a 500
    check "auth failure" 500 "$out"
    check_match "login to an unreachable registry says so" 'authenticating creds for "localhost:1": pinging container registry localhost:1' \
        "$(printf 'pw\n' | "$CLI" --socket "$ESOCK" login -u u --password-stdin localhost:1 2>&1)"
}

@test "login and logout with the CLI" {
    # (an auth file of the test: root's default one is the host's, in /run,
    # and its credentials would win over the credential helpers of the other
    # files)
    export REGISTRY_AUTH_FILE=$WORKDIR/auth.json
    out=$("$CLI" --remote --root /x version 2>&1); check "--remote has no --root" "Error: unknown flag: --root 125" "$out $?"
    out=$(printf 'pw  \n' | "$CLI" --socket "$ESOCK" login --tls-verify=false -u u --password-stdin $E2E_REGISTRY 2>&1)
    check "login keeps the spaces of a password, takes the newline off" "Login Succeeded!" "$out"
    check "the user and the password are in the auth file" "u:pw  " "$(jq -r '.auths["'"$E2E_REGISTRY"'"].auth' "$REGISTRY_AUTH_FILE" | base64 -d)"
    printf 'sekret' | "$CLI" secret create loginsec - > /dev/null 2>&1
    rm -f "$WORKDIR/compat.json"
    out=$("$CLI" login --tls-verify=false --secret loginsec --compat-auth-file "$WORKDIR/compat.json" $E2E_REGISTRY 2>&1)
    check "login --secret --compat-auth-file" "Login Succeeded!" "$out"
    check "the user is the name of the secret, the password its data" "loginsec:sekret" "$(jq -r '.auths["'"$E2E_REGISTRY"'"].auth' "$WORKDIR/compat.json" | base64 -d)"
    check "logout --compat-auth-file" "Removed login credentials for $E2E_REGISTRY" "$("$CLI" logout --compat-auth-file "$WORKDIR/compat.json" $E2E_REGISTRY 2>&1)"
    check_match "--authfile and --compat-auth-file" "can not be set simultaneously" "$("$CLI" login --authfile "$WORKDIR/a" --compat-auth-file "$WORKDIR/b" $E2E_REGISTRY 2>&1)"
    check "--secret with --password" "Error: --secret can not be used with --password options" "$("$CLI" login --secret loginsec -p x $E2E_REGISTRY 2>&1)"
    "$CLI" secret rm loginsec > /dev/null 2>&1
    out=$(printf 'pw\n' | "$CLI" --socket "$ESOCK" login -u u -p x --password-stdin $E2E_REGISTRY 2>&1); check "--password and --password-stdin" "Error: can't specify both --password-stdin and --password 125" "$out $?"
    out=$(printf 'pw\n' | "$CLI" --socket "$ESOCK" login --password-stdin $E2E_REGISTRY 2>&1); check "--password-stdin needs --username" "Error: must provide --username with --password-stdin 125" "$out $?"
    out=$(api -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' http://d/v1.41/auth)
    check "auth without credentials" 500 "$out"
}

@test "system df" {
    out=$(api http://d/v5.0.0/libpod/system/df | jq -r 'keys | join(" ")')
    check "system df" "Containers Images ImagesSize Volumes" "$out"
    out=$(api http://d/v1.41/system/df | jq -r 'keys | join(" ")')
    check "compat system df" "BuildCache Containers Images LayersSize Volumes" "$out"
    out=$(pm system df --format '{{.Type}}' | tr '\n' ' ')
    check "podman system df" "Images Containers Local Volumes " "$out"
}

@test "system df -v and the command of a container" {
    # the COMMAND of `system df -v` is the command, without the entrypoint
    # (podman's)
    pm run -d --name dfx "$IMG" sleep 100 > /dev/null 2>&1
    pm create --name dfy --entrypoint /bin/sh "$IMG" -c 'echo a' > /dev/null 2>&1
    check "system df -v: the command of a container" "sleep 100" "$("$CLI" system df -v | awk '/ dfx$/ { print $3, $4 }')"
    check "system df -v: not its entrypoint" "-c echo a" "$("$CLI" system df -v | awk '/ dfy$/ { print $3, $4, $5 }')"
    check "system df: the command in libpod's report" "sleep 100" "$(api http://d/v5.0.0/libpod/system/df | jq -r '.Containers[] | select(.Names == "dfx") | .Command | join(" ")')"
    check "system df: the command in Docker's report" "-c echo a" "$(api http://d/v1.41/system/df | jq -r '.Containers[] | select(.Names[0] == "/dfy") | .Command')"
    pm rm -f -t 0 dfx dfy > /dev/null 2>&1
}

@test "system prune" {
    out=$(api -X POST http://d/v5.0.0/libpod/system/prune | jq -r 'keys | join(" ")')
    check "system prune" "ContainerPruneReports ImagePruneReports NetworkPruneReports PodPruneReport ReclaimedSpace VolumePruneReports" "$out"
}

@test "docker system df" {
    command -v docker > /dev/null || skip "no docker client"
    pm volume create dfvol > /dev/null
    pm create --name dfc "$IMG" true > /dev/null
    out=$(dk system df --format '{{.Type}} {{.TotalCount}}' 2>&1)
    check_match "system df counts the images" "^Images [1-9]" "$out"
    check_match "system df counts the containers" "^Containers [1-9]" "$out"
    check_match "system df counts the volumes" "^Local Volumes [1-9]" "$out"
    pm rm dfc > /dev/null
    pm volume rm dfvol > /dev/null
}
