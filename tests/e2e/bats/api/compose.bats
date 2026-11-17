# SPDX-License-Identifier: Apache-2.0
# docker-compose (v2) and podman-compose against velarx-api: a project with a
# database that has a health check, a web service built from a context that
# waits for it, a network with an alias, a named volume, an environment file,
# a published port, restart policies and a profile (tests/e2e/compose),
# through up, ps, logs, exec, stop, start, restart and down -v.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/api/compose.bats
#
# The tools are fetched once into the cache shared by the tests
# ($VELARX_TEST_CACHE, else $XDG_CACHE_HOME/velarx-tests, else
# ~/.cache/velarx-tests, made private), by https, and run from a copy in the
# work directory whose sha256 is the one pinned in tests/e2e/compose/versions:
# docker-compose is one binary of the releases of github.com/docker/compose,
# podman-compose and python-dotenv the wheels of PyPI (no pip), run with the
# PyYAML of the system.  A test skips without its tool (offline, no PyYAML),
# and without a registry at E2E_REGISTRY (default localhost:5000) with
# E2E_IMAGE (default $E2E_REGISTRY/alpine:chunked), a podman remote client (podman-compose runs
# `podman` against the socket) or the docker client (the checks inspect).
#
# The build goes through the classic builder (DOCKER_BUILDKIT=0, as against
# podman's service): the BuildKit protocol is not served.  podman-compose runs
# without a pod (--in-pod=false): a pod always has an infra container here.

load ../helpers
load ../api_helpers

sha256_of () { sha256sum "$1" | cut -d' ' -f1; }

# fetch_pinned NAME URL SHA256: the path of a private copy of the file NAME of
# the cache ($TOOLS/NAME), verified against SHA256; the cache gets it from URL
# once.  Prints nothing when it cannot be had (offline); fails when what was
# downloaded is not what is pinned.
fetch_pinned () {
    local name=$1 url=$2 want=$3 copy=$TOOLS/$1 tmp=$TOOLS/.$1.part got
    (
        flock 9
        if [ -f "$CACHE/$name" ]; then
            cp "$CACHE/$name" "$copy" && [ "$(sha256_of "$copy")" = "$want" ] && exit 0
            rm -f "$copy"
        fi
        curl -fsSL --proto =https --proto-redir =https --max-time 300 -o "$tmp" "$url" 2> /dev/null || { rm -f "$tmp"; exit 0; }
        got=$(sha256_of "$tmp")
        if [ "$got" != "$want" ]; then
            echo "the sha256 of $url is $got, not the pinned $want" >&2
            rm -f "$tmp"
            exit 1
        fi
        cp "$tmp" "$CACHE/$name.part" && mv -f "$CACHE/$name.part" "$CACHE/$name"
        mv "$tmp" "$copy"
    ) 9> "$CACHE/.$name.lock" || return 1
    [ ! -f "$copy" ] || echo "$copy"
}

# fetch_tools: $DOCKER_COMPOSE and $PODMAN_COMPOSE, the commands (empty
# without them)
fetch_tools () {
    local want pc dotenv
    . "$E2E_DIR/compose/versions"
    TOOLS=$WORKDIR/tools
    mkdir -p "$TOOLS"
    case $(uname -m) in
        x86_64) want=$DOCKER_COMPOSE_SHA256_X86_64 ;;
        aarch64) want=$DOCKER_COMPOSE_SHA256_AARCH64 ;;
        *) want= ;;
    esac
    DOCKER_COMPOSE=
    if [ -n "$want" ]; then
        DOCKER_COMPOSE=$(fetch_pinned "docker-compose-$DOCKER_COMPOSE_VERSION-$(uname -m)" \
            "https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-linux-$(uname -m)" "$want") || return 1
        [ -z "$DOCKER_COMPOSE" ] || chmod 0700 "$DOCKER_COMPOSE"
    fi
    PODMAN_COMPOSE=
    pc=$(fetch_pinned "${PODMAN_COMPOSE_URL##*/}" "$PODMAN_COMPOSE_URL" "$PODMAN_COMPOSE_SHA256") || return 1
    dotenv=$(fetch_pinned "${PYTHON_DOTENV_URL##*/}" "$PYTHON_DOTENV_URL" "$PYTHON_DOTENV_SHA256") || return 1
    if [ -n "$pc" ] && [ -n "$dotenv" ] && python3 -I -c 'import yaml' 2> /dev/null; then
        # (-I: no module of the environment, the user or the current directory)
        PODMAN_COMPOSE=$TOOLS/podman-compose
        cat > "$PODMAN_COMPOSE" <<EOT
#!/bin/sh
exec python3 -I -c 'import sys; sys.path[:0] = sys.argv[1:3]; sys.argv[:3] = ["podman-compose"]; import podman_compose; sys.exit(podman_compose.main())' "$pc" "$dotenv" "\$@"
EOT
        chmod 0700 "$PODMAN_COMPOSE"
    fi
    export DOCKER_COMPOSE PODMAN_COMPOSE
}

setup_file () {
    # (before api_setup_file, which moves HOME into the work directory)
    CACHE=${VELARX_TEST_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/velarx-tests}
    api_setup_file
    [ -z "${NO_PODMAN:-}" ] || return 0
    # the cache is private: what is run from it is verified first
    mkdir -p -m 0700 "$CACHE" && [ -O "$CACHE" ] && chmod 0700 "$CACHE" || {
        echo "$CACHE: not a directory of the user" >&2
        return 1
    }
    fetch_tools || return 1
    # the project, in a directory of its own (compose writes nothing there, but
    # names the project by the directory)
    mkdir -p "$WORKDIR/project"
    cp -r "$E2E_DIR/compose/." "$WORKDIR/project/"
    rm "$WORKDIR/project/versions"
    WEB_PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    export WEB_PORT E2E_IMAGE=$IMG
    # podman-compose runs `podman` against the socket of velarx-api
    mkdir -p "$WORKDIR/bin"
    printf '#!/bin/sh\nexec %s --url unix://%s "$@"\n' "$PODMAN_REMOTE" "$SOCK" > "$WORKDIR/bin/podman"
    chmod +x "$WORKDIR/bin/podman"
}

teardown_file () {
    # (a test that failed midway leaves its project: down -v, as its user
    # would; the rootless network namespace outlives a store with networks)
    if [ -n "${WORKDIR:-}" ] && [ -S "${SOCK:-}" ] && [ -d "$WORKDIR/project" ]; then
        [ -z "${DOCKER_COMPOSE:-}" ] || dc --profile debug down -v > /dev/null
        [ -z "${DOCKER_COMPOSE:-}" ] || dc -f job.yaml down -v > /dev/null
        [ -z "${PODMAN_COMPOSE:-}" ] || pc down -v > /dev/null
    fi
    api_teardown_file
}

setup () { api_setup; api_state_load; }

dc () {
    (
        cd "$WORKDIR/project" || exit 1
        DOCKER_HOST="unix://$SOCK" COMPOSE_PROGRESS=plain DOCKER_BUILDKIT=0 \
            timeout 300 "$DOCKER_COMPOSE" "$@" < /dev/null 2>&1
    )
}

pc () {
    (
        cd "$WORKDIR/project" || exit 1
        timeout 300 "$PODMAN_COMPOSE" --in-pod=false --podman-path "$WORKDIR/bin/podman" "$@" < /dev/null 2>&1
    )
}

skip_unless_docker_compose () {
    command -v docker > /dev/null || skip "no docker client"
    [ -n "$DOCKER_COMPOSE" ] || skip "no docker-compose (offline?)"
}

skip_unless_podman_compose () {
    command -v docker > /dev/null || skip "no docker client"
    [ -n "$PODMAN_COMPOSE" ] || skip "no podman-compose (offline, or no PyYAML: python3-pyyaml, python3-yaml)"
}

# state PROJECT: the containers, networks and volumes of a compose project, by
# the labels both tools give them (docker-compose's and podman-compose's)
left () {
    local project=$1 f
    f="{\"label\":[\"com.docker.compose.project=$project\"]}"
    echo "containers=[$(api -G "http://d/v1.44/containers/json?all=1" --data-urlencode "filters=$f" | jq -r '[.[].Names[0]] | sort | join(" ")')]"
    echo "networks=[$(api -G "http://d/v1.44/networks" --data-urlencode "filters=$f" | jq -r '[.[].Name] | sort | join(" ")')]"
    echo "volumes=[$(api -G "http://d/v1.44/volumes" --data-urlencode "filters=$f" | jq -r '[.Volumes // [] | .[].Name] | sort | join(" ")')]"
}

EMPTY="containers=[]
networks=[]
volumes=[]"

# cexec NAME CMD...: a command in a container, through the API
cexec () {
    local name=$1
    shift
    dk exec "$name" "$@"
}

@test "docker-compose: up -d builds web, waits for the healthy db, and starts both" {
    skip_unless_docker_compose
    out=$(dc up -d)
    check "up -d" 0 $?
    check_match "the image was built" "Service web +Built" "$out"
    check_match "db healthy before web starts" "vxcompose-db-1 +Healthy" "$out"
    check "web is running" running "$(dk inspect -f '{{.State.Status}}' vxcompose-web-1)"
    check "db is healthy" healthy "$(dk inspect -f '{{.State.Health.Status}}' vxcompose-db-1)"
    check "the debug profile did not start" "" "$(dk ps -aq --filter name=vxcompose-debug)"
    # the build: the context, the arguments
    check "the build argument" "hi from the build" "$(cexec vxcompose-web-1 cat /greeting)"
    # the environment file and the environment
    check "env_file and environment" "compose-test database" \
        "$(cexec vxcompose-web-1 sh -c 'echo $APP_MODE $DB_HOST')"
    # the alias on the network
    check_match "the alias resolves on the network" "^[0-9.]+ +database" \
        "$(cexec vxcompose-web-1 getent hosts database)"
    # the volume is shared
    cexec vxcompose-db-1 sh -c 'echo shared > /data/file' > /dev/null
    check "the named volume is shared" shared "$(cexec vxcompose-web-1 cat /shared/file)"
    # the port, the policies
    check "port" "127.0.0.1:$WEB_PORT" "$(dc port web 80)"
    check "restart on-failure" on-failure "$(dk inspect -f '{{.HostConfig.RestartPolicy.Name}}' vxcompose-web-1)"
    check "restart unless-stopped" unless-stopped "$(dk inspect -f '{{.HostConfig.RestartPolicy.Name}}' vxcompose-db-1)"
    check "network" vxcompose_backend "$(dk inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' vxcompose-web-1)"
    dk inspect -f '{{.Id}}' vxcompose-db-1 vxcompose-web-1 > "$WORKDIR/ids.before"
}

@test "docker-compose: ps and logs" {
    skip_unless_docker_compose
    out=$(dc ps --format '{{.Service}} {{.State}}')
    check "ps" "db running
web running" "$(echo "$out" | sort)"
    out=$(dc logs --no-log-prefix web)
    check_match "logs of web" "hi from the build" "$out"
    check_match "logs of web, the second line" "web-started" "$out"
    check_match "logs of db with the prefix" "db-1 +\| db-ready" "$(dc logs db)"
    check "ps of one service by name" "vxcompose-web-1" "$(dc ps --format '{{.Name}}' web)"
}

@test "docker-compose: exec, run and cp" {
    skip_unless_docker_compose
    check "exec" "ready" "$(dc exec -T db sh -c 'test -f /tmp/ready && echo ready')"
    check "exec exit status" 3 "$(dc exec -T db sh -c 'exit 3' > /dev/null; echo $?)"
    check "run --rm" "run-ok" "$(dc run --rm --no-deps db echo run-ok | tail -1)"
    dc cp web:/greeting "$WORKDIR/greeting" > /dev/null
    check "cp out of a container" "hi from the build" "$(cat "$WORKDIR/greeting")"
}

@test "docker-compose: a second up changes nothing" {
    skip_unless_docker_compose
    out=$(dc up -d)
    check "up -d" 0 $?
    check_match "running containers are left" "vxcompose-web-1 +Running" "$out"
    check "no container was recreated" "$(cat "$WORKDIR/ids.before")" \
        "$(dk inspect -f '{{.Id}}' vxcompose-db-1 vxcompose-web-1)"
}

@test "docker-compose: stop, start, restart and up keep the containers" {
    skip_unless_docker_compose
    dc stop > /dev/null
    check "stopped" "exited exited" "$(dk inspect -f '{{.State.Status}}' vxcompose-db-1 vxcompose-web-1 | tr '\n' ' ' | sed 's/ $//')"
    out=$(dc start)
    check "start" 0 $?
    check_match "start waits for the health" "vxcompose-db-1 +Healthy" "$out"
    check "running again" "running running" "$(dk inspect -f '{{.State.Status}}' vxcompose-db-1 vxcompose-web-1 | tr '\n' ' ' | sed 's/ $//')"
    dc restart > /dev/null
    check "restart" 0 $?
    check "running after the restart" "running running" "$(dk inspect -f '{{.State.Status}}' vxcompose-db-1 vxcompose-web-1 | tr '\n' ' ' | sed 's/ $//')"
    check "the same containers" "$(cat "$WORKDIR/ids.before")" "$(dk inspect -f '{{.Id}}' vxcompose-db-1 vxcompose-web-1)"
    # an up of the stopped project starts them again, not new ones
    dc stop > /dev/null
    dc up -d > /dev/null
    check "up -d after stop" 0 $?
    check "running after the up" "running running" "$(dk inspect -f '{{.State.Status}}' vxcompose-db-1 vxcompose-web-1 | tr '\n' ' ' | sed 's/ $//')"
    check "the same containers after the up" "$(cat "$WORKDIR/ids.before")" "$(dk inspect -f '{{.Id}}' vxcompose-db-1 vxcompose-web-1)"
}

@test "docker-compose: a profile starts its service" {
    skip_unless_docker_compose
    dc --profile debug up -d debug > /dev/null
    check "up debug" 0 $?
    check "debug is running" running "$(dk inspect -f '{{.State.Status}}' vxcompose-debug-1)"
    check "top of a service" 0 "$(dc top debug > /dev/null; echo $?)"
}

@test "docker-compose: an attached up runs a job, then the service that waits for its success" {
    skip_unless_docker_compose
    out=$(dc -f job.yaml up)
    check "up" 0 $?
    check_match "the job's output" "job-1 +\| job-output" "$out"
    check_match "the dependent service ran after the job" "failing-1 +\| failing" "$out"
    check "the job's status" 0 "$(dk inspect -f '{{.State.ExitCode}}' vxjob-job-1)"
    check "the service's status" 7 "$(dk inspect -f '{{.State.ExitCode}}' vxjob-failing-1)"
    dc -f job.yaml down -v > /dev/null
    check "down" 0 $?
    check "nothing is left" "$EMPTY" "$(left vxjob)"
}

@test "docker-compose: down -v removes the containers, the network and the volume" {
    skip_unless_docker_compose
    out=$(dc --profile debug down -v)
    check "down -v" 0 $?
    check_match "volume removed" "Volume vxcompose_dbdata +Removed" "$out"
    check_match "network removed" "Network vxcompose_backend +Removed" "$out"
    check "nothing is left" "$EMPTY" "$(left vxcompose)"
}

@test "podman-compose: up -d --build, ps, logs, exec" {
    skip_unless_podman_compose
    out=$(pc up -d --build)
    check "up -d --build" 0 $?
    check "db is running" running "$(dk inspect -f '{{.State.Status}}' vxcompose_db_1)"
    check "web is running" running "$(dk inspect -f '{{.State.Status}}' vxcompose_web_1)"
    check "the build argument" "hi from the build" "$(pc exec -T web cat /greeting)"
    check "env_file and environment" "compose-test database" \
        "$(pc exec -T web sh -c 'echo $APP_MODE $DB_HOST')"
    check_match "the alias resolves on the network" "^[0-9.]+ +database" \
        "$(pc exec -T web getent hosts database)"
    pc exec -T db sh -c 'echo shared > /data/file' > /dev/null
    check "the named volume is shared" shared "$(pc exec -T web cat /shared/file)"
    out=$(pc ps)
    check_match "ps lists db" "vxcompose_db_1" "$out"
    check_match "ps lists web with its port" "127.0.0.1:$WEB_PORT->80/tcp +vxcompose_web_1" "$out"
    out=$(pc logs)
    check_match "logs of web" "hi from the build" "$out"
    check_match "logs of db" "db-ready" "$out"
    check "restart on-failure" on-failure "$(dk inspect -f '{{.HostConfig.RestartPolicy.Name}}' vxcompose_web_1)"
    check "the debug profile did not start" "" "$(dk ps -aq --filter name=vxcompose_debug)"
}

@test "podman-compose: stop, start and down -v" {
    skip_unless_podman_compose
    pc stop > /dev/null
    check "stopped" "exited exited" "$(dk inspect -f '{{.State.Status}}' vxcompose_db_1 vxcompose_web_1 | tr '\n' ' ' | sed 's/ $//')"
    pc start > /dev/null
    check "started" "running running" "$(dk inspect -f '{{.State.Status}}' vxcompose_db_1 vxcompose_web_1 | tr '\n' ' ' | sed 's/ $//')"
    pc down -v > /dev/null
    check "down -v" 0 $?
    check "nothing is left" "$EMPTY" "$(left vxcompose)"
}
