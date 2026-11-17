# SPDX-License-Identifier: Apache-2.0
# The conditions of a wait (podman's `wait --condition`, Docker's
# `not-running`, `next-exit`, `removed`), through the three ways in: the
# command line on the engine, libpod's and Docker's routes of velarx-api.
# The engine has one implementation of them (ContainerWait): the same
# scenario gives the same answer through each.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/api/wait.bats
#
# Needs a registry at E2E_REGISTRY (default localhost:5000) with E2E_IMAGE
# (default $E2E_REGISTRY/alpine:chunked) and a podman remote client.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

# w VIA CONDITION NAME: the answer of a wait through VIA (cli, libpod,
# docker): the exit code, or `E<status>` for an error (the HTTP status, or
# the exit status of the command).
w () {
    local via=$1 cond=$2 name=$3 out code
    case $via in
        cli)
            out=$(timeout 60 "$SH" --socket "$ESOCK" wait ${cond:+--condition "$cond"} "$name" 2> /dev/null)
            code=$?
            if [ "$code" = 0 ]; then echo "$out"; else echo "E$code"; fi
            ;;
        libpod)
            out=$(api -m 60 -w '\n%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/$name/wait${cond:+?condition=$cond}")
            code=$(echo "$out" | tail -1)
            if [ "$code" = 200 ]; then echo "$out" | head -1; else echo "E$code"; fi
            ;;
        docker)
            out=$(api -m 60 -w '\n%{http_code}' -X POST "http://d/v1.41/containers/$name/wait${cond:+?condition=$cond}")
            code=$(echo "$out" | tail -1)
            if [ "$code" = 200 ]; then echo "$out" | head -1 | jq -r .StatusCode; else echo "E$code"; fi
            ;;
    esac
}

# create NAME CMD...: a container that is not started.
create () {
    local name=$1
    shift
    sc create --name "$name" --network none "$IMG" "$@" > /dev/null
}

@test "wait: a container that never ran is not running, through every way in" {
    create wnew true
    for via in cli libpod docker; do
        check "$via default" 0 "$(w $via "" wnew)"
        check "$via not-running" 0 "$(w $via not-running wnew)"
    done
    for via in cli libpod; do
        check "$via exited" 0 "$(w $via exited wnew)"
        check "$via stopped" 0 "$(w $via stopped wnew)"
        check "$via created" -1 "$(w $via created wnew)"
    done
    check "cli several conditions, one met" 0 "$(w cli running,exited wnew)"
    sc rm wnew > /dev/null
}

@test "wait: next-exit waits for the next run, not-running answers its code" {
    # (the sleep in the container leaves the wait time to arm: the command
    # line and libpod tell nobody when it is)
    create wnext sh -c "sleep 3; exit 7"
    for via in cli libpod docker; do
        w $via next-exit wnext > "$WORKDIR/next.$via" 3>&- &
        pid=$!
        sc start wnext > /dev/null
        wait $pid
        check "$via next-exit of a container that runs later" 7 "$(cat "$WORKDIR/next.$via")"
        check "$via not-running of an exited container" 7 "$(w $via not-running wnext)"
        check "$via exited of an exited container" 7 "$(w $via "" wnext)"
    done
    sc rm wnext > /dev/null
}

@test "wait: Docker's next-exit is armed when the head of the answer comes" {
    create wdk sh -c "exit 5"
    fifo=$WORKDIR/head
    mkfifo "$fifo"
    api -m 60 -D "$fifo" -X POST "http://d/v1.41/containers/wdk/wait?condition=next-exit" > "$WORKDIR/dk.out" 3>&- &
    pid=$!
    # (the head is read whole: curl writes nothing more to it)
    while IFS= read -r line; do
        [ "$line" = $'\r' ] && break
    done < "$fifo"
    sc start wdk > /dev/null
    wait $pid
    check "docker next-exit started after the head" "5 null" "$(jq -r '"\(.StatusCode) \(.Error)"' "$WORKDIR/dk.out")"
    sc rm wdk > /dev/null
}

@test "wait: removed waits for the removal and answers the last exit code" {
    # (the --rm container goes 2 s after its start: the wait is armed by then)
    for via in cli libpod docker; do
        sc run -d --rm --name "wrm$via" --network none "$IMG" sh -c "sleep 2; exit 4" > /dev/null
        check "$via removed of an --rm container" 4 "$(w $via removed "wrm$via")"
        check "$via the --rm container is gone" 1 "$(sc container exists "wrm$via" > /dev/null 2>&1; echo $?)"
    done
    # a container that never ran: 0, and its removal ends next-exit; the
    # head of Docker's answer says the wait is armed
    fifo=$WORKDIR/head.rm
    mkfifo "$fifo"
    for cond in removed next-exit; do
        create wrn true
        api -m 60 -D "$fifo" -X POST "http://d/v1.41/containers/wrn/wait?condition=$cond" > "$WORKDIR/rn.out" 3>&- &
        pid=$!
        while IFS= read -r line; do
            [ "$line" = $'\r' ] && break
        done < "$fifo"
        sc rm wrn > /dev/null
        wait $pid
        check "docker $cond of a container removed before it ran" "0 null" "$(jq -r '"\(.StatusCode) \(.Error)"' "$WORKDIR/rn.out")"
    done
}

@test "wait: what is refused, the same through every way in" {
    create wbad true
    check "cli unknown condition" E125 "$(w cli bogus wbad)"
    # (podman 5.8.9's libpod route answers 0 for a condition it cannot read)
    check "libpod unknown condition" 0 "$(w libpod bogus wbad)"
    check "docker unknown condition" E400 "$(w docker bogus wbad)"
    # Docker takes its three only
    check "docker podman's condition" E400 "$(w docker running wbad)"
    check_match "cli says the conditions" "unknown wait condition \"bogus\"" \
        "$(sc wait --condition bogus wbad 2>&1)"
    # a negative interval is refused by the engine, a bare number is
    # milliseconds for the command line, as podman's
    check "cli negative interval" 125 "$(sc wait -i -1s wbad > /dev/null 2>&1; echo $?)"
    check "cli interval in milliseconds" 0 "$(sc wait -i 5000 wbad 2>&1)"
    check "cli interval not a duration" 125 "$(sc wait --interval 100days wbad > /dev/null 2>&1; echo $?)"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/wbad/wait?interval=-1s")
    # (Go reads it, podman's wait takes it as its poll interval)
    check "libpod negative interval" 200 "$code"
    code=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/containers/wbad/wait?interval=1s")
    check "libpod interval" 200 "$code"
    sc rm wbad > /dev/null
    # a container that is not there
    for via in cli libpod docker; do
        for cond in not-running next-exit removed; do
            out=$(w $via $cond wbad)
            case $via in cli) want=E125 ;; *) want=E404 ;; esac
            check "$via $cond of a container that is not there" "$want" "$out"
        done
    done
    check "cli --ignore" -1 "$(sc wait --ignore wbad 2>&1)"
    check "cli without a container" 125 "$(sc wait > /dev/null 2>&1; echo $?)"
    check "cli --latest and a name" 125 "$(sc wait --latest wbad > /dev/null 2>&1; echo $?)"
    check "cli refuses what podman's wait has not" 125 "$(sc wait --cidfile x wbad > /dev/null 2>&1; echo $?)"
}

@test "wait: --exit-first-match answers the first container that meets a condition" {
    create wslow sleep 100
    create wfast sh -c "exit 6"
    sc start wslow > /dev/null
    sc start wfast > /dev/null
    check "exit-first-match" 6 "$(timeout 60 "$SH" --socket "$ESOCK" wait --exit-first-match wslow wfast 2>&1)"
    sc rm -f -t 0 wslow wfast > /dev/null
}

# The state `stopping` is the engine's: a container that has to obey a stop
# is stopping whoever asked for the stop (command line, libpod, Docker), for
# every way to wait and to inspect.
@test "wait: stopping is met by a stop from every way in" {
    for via in cli libpod docker; do
        n=wst$via
        create $n sh -c 'trap "" TERM; while :; do sleep 1; done'
        sc start $n > /dev/null
        case $via in
            cli) (sc stop -t 4 $n > /dev/null 2>&1) 3>&- & ;;
            libpod) api -m 30 -o /dev/null -X POST "http://d/v5.0.0/libpod/containers/$n/stop?timeout=4" 3>&- & ;;
            docker) api -m 30 -o /dev/null -X POST "http://d/v1.41/containers/$n/stop?t=4" 3>&- & ;;
        esac
        stopper=$!
        # (the container ignores the signal: it is stopping for 4 s)
        check "cli wait after a $via stop" -1 "$(w cli stopping $n)"
        check "libpod wait after a $via stop" -1 "$(w libpod stopping $n)"
        check "inspect agrees after a $via stop" stopping \
            "$(api "http://d/v5.0.0/libpod/containers/$n/json" | jq -r .State.Status)"
        wait $stopper
        sc rm -f -t 0 $n > /dev/null
    done
}

# 100 waits at once (a `docker compose up` of 100 services, 100 `podman
# wait`): each holds a connection to the engine for as long as the container
# runs, from a budget of its own, so a start and a list are answered
# meanwhile, and all the waits get the exit code.
@test "wait: 100 waits in progress do not starve the other requests" {
    create wmany sh -c "sleep 2; exit 9"
    for i in $(seq 100); do
        api -m 90 -D "$WORKDIR/mw.$i.head" -o "$WORKDIR/mw.$i.out" \
            -X POST "http://d/v1.41/containers/wmany/wait?condition=next-exit" 3>&- &
    done
    # (Docker's answer has its head once the wait is armed)
    for i in $(seq 100); do
        e2e_wait_line "$WORKDIR/mw.$i.head" '^HTTP/1.1 200' 60 || fail "the wait $i is not armed within 60 s"
    done
    check "a start with 100 waits in progress" 204 \
        "$(api -m 10 -o /dev/null -w '%{http_code}' -X POST http://d/v1.41/containers/wmany/start)"
    check "a list with 100 waits in progress" 200 \
        "$(api -m 10 -o /dev/null -w '%{http_code}' http://d/v1.41/containers/json)"
    wait
    check "every wait has the exit code" "100 9" \
        "$(cat "$WORKDIR"/mw.*.out | jq -r .StatusCode | sort | uniq -c | awk '{print $1, $2}')"
    rm -f "$WORKDIR"/mw.*
    sc rm wmany > /dev/null
}
