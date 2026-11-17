# SPDX-License-Identifier: Apache-2.0
# The events of the life of a container, in podman's order, and a stop that
# comes while a restart is under way.  Run it as an ordinary user or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# evs NAME: the events of the container, one line
evs () { sh_ events --stream=false --since 5m --filter container="$1" --format '{{.Status}}' 2>&1 | tr '\n' ' ' | sed 's/ $//'; }

# a container that ignores the stop signal
stubborn () { sh_ container run -d --name "$1" --network none --stop-timeout 1 "${@:2}" "$IMAGE" sleep 1000 > /dev/null; }

@test "events of a start, a restart, a stop and a removal" {
    stubborn ev1
    check "run" "create init start" "$(evs ev1)"
    sh_ container restart ev1 > /dev/null
    check "restart: restart first, then the died of the stop, init, start" \
        "create init start restart died cleanup init start" "$(evs ev1)"
    sh_ container stop ev1 > /dev/null
    check "stop: died and cleanup, no stop" \
        "create init start restart died cleanup init start died cleanup" "$(evs ev1)"
    sh_ container rm ev1 > /dev/null
    check "rm" "create init start restart died cleanup init start died cleanup remove" "$(evs ev1)"
}

@test "events of a restart by the restart policy" {
    sh_ container run -d --name ev2 --network none --restart on-failure:1 "$IMAGE" sh -c 'exit 3' > /dev/null
    for _ in $(seq 100); do
        case $(evs ev2) in *"died cleanup") break ;; esac
        sleep 0.1
    done
    check "died, restart, init, start; then died and cleanup" \
        "create init start died restart init start died cleanup" "$(evs ev2)"
}

@test "an --rm container has no cleanup" {
    sh_ container run -d --rm --name ev3 --network none "$IMAGE" true > /dev/null
    for _ in $(seq 100); do
        case $(evs ev3) in *remove) break ;; esac
        sleep 0.1
    done
    check "run --rm" "create init start died remove" "$(evs ev3)"
}

@test "a stop that comes while a restart is under way ends with that stop" {
    stubborn ev4 --stop-timeout 3
    sh_ container restart ev4 > /dev/null 2>&1 3>&- &
    local restarting=$!
    until [ "$(evs ev4)" != "create init start" ]; do sleep 0.1; done
    sh_ container stop -t 0 ev4 > /dev/null
    check "stop succeeds" 0 $?
    wait "$restarting"
    check "the container is stopped, not started again" exited \
        "$(sh_ container inspect --format '{{.State.Status}}' ev4)"
}
