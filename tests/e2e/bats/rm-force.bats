# SPDX-License-Identifier: Apache-2.0
# End to end tests of `rm -f` of a running container: as podman's, it stops
# the container with its stop signal, waits its stop timeout (or the -t
# given) and only then kills it; -t 0 kills at once.  The containers log
# the signal they get to a file of the work directory.  Run it as an
# ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
    mkdir -p "$WORKDIR/rf"
}

teardown_file () {
    run_teardown_file
}

# rf_run NAME SIGNAL KEEP [OPTIONS...]: a container that logs SIGNAL to
# $WORKDIR/rf/NAME, and its name to $WORKDIR/rf/order (the containers in the
# order they got their signal: the clock of busybox's date counts seconds),
# and then exits (KEEP no) or goes on (KEEP yes).
rf_run () {
    local name=$1 sig=$2 keep=$3 act net=(--network none)
    shift 3
    # (a pod has the network of its infra container)
    case " $* " in *" --pod "* | *" --network "*) net=() ;; esac
    act="echo $sig >> /rf/$name; echo $name >> /rf/order"
    [ "$keep" = yes ] || act="$act; exit 7"
    sh_ container run -d --name "$name" --log-driver k8s-file "${net[@]}" -v "$WORKDIR/rf:/rf:z" "$@" "$IMAGE" \
        sh -c "trap '$act' $sig; echo ready; while :; do sleep 0.1; done" > /dev/null
    wait_log "$name" ready
}

# rf_time COMMAND...: the milliseconds the command took, in $elapsed.
rf_time () {
    local start; start=$(now_ms)
    "$@" > "$WORKDIR/rf.out" 2>&1
    rc=$?
    elapsed=$(( $(now_ms) - start ))
}

# rf_plain: the output of rf_time with podman's log lines of warnings as WARN TEXT
rf_plain () { sed 's/^time="[^"]*" level=warning msg="\(.*\)"$/WARN \1/' "$WORKDIR/rf.out"; }

@test "rm -f of a container that ignores the stop signal waits the stop timeout, then kills it" {
    rf_run rf1 TERM yes --stop-timeout 2
    rf_time sh_ container rm -f rf1
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 8000
    check "it took the stop timeout (${elapsed}ms)" 0 $?
    check "the container got SIGTERM first" TERM "$(cat "$WORKDIR/rf/rf1")"
    check_match "the kill is told as podman tells it" \
        "^time=\"[^\"]+\" level=warning msg=\"StopSignal SIGTERM failed to stop container rf1 in 2 seconds, resorting to SIGKILL\"$" \
        "$(cat "$WORKDIR/rf.out")"
    check "the container is gone" no "$(sh_ container exists rf1 > /dev/null 2>&1 && echo yes || echo no)"
}

@test "rm -f of a container that obeys the stop signal is prompt, with the signal logged" {
    rf_run rf2 TERM no --stop-timeout 60
    rf_time sh_ container rm -f rf2
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -lt 10000
    check "it did not wait the stop timeout (${elapsed}ms)" 0 $?
    check "the container got SIGTERM" TERM "$(cat "$WORKDIR/rf/rf2")"
    check "and nothing is said of a kill" "rf2" "$(cat "$WORKDIR/rf.out")"
}

@test "rm -f uses the stop signal of the container" {
    rf_run rf3 USR1 no --stop-signal USR1 --stop-timeout 60
    rf_time sh_ container rm -f rf3
    check "rm -f succeeds" 0 "$rc"
    check "the container got its stop signal" USR1 "$(cat "$WORKDIR/rf/rf3")"
}

@test "rm -f -t 0 kills at once, without any signal before" {
    rf_run rf4 TERM yes --stop-timeout 60
    rf_time sh_ container rm -f -t 0 rf4
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -lt 10000
    check "it did not wait (${elapsed}ms)" 0 $?
    check "the container got no signal" no "$(test -s "$WORKDIR/rf/rf4" && echo yes || echo no)"
    check "and nothing is said of a kill" "rf4" "$(cat "$WORKDIR/rf.out")"
}

@test "rm -f -t N waits N seconds, not the stop timeout of the container" {
    rf_run rf5 TERM yes --stop-timeout 60
    rf_time sh_ container rm -f -t 2 rf5
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 20000
    check "it took the time given (${elapsed}ms)" 0 $?
    check_match "and the kill names it" "in 2 seconds, resorting to SIGKILL" "$(cat "$WORKDIR/rf.out")"
    rf_run rf5 TERM yes --stop-timeout 1
    rf_time sh_ container rm -f --time 3 rf5
    test "$elapsed" -ge 2800
    check "a longer time is waited too (${elapsed}ms)" 0 $?
}

@test "rm -f of a paused container kills it at once" {
    rf_run rf6 TERM yes --stop-timeout 60
    sh_ container pause rf6 > /dev/null
    rf_time sh_ container rm -f rf6
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -lt 10000
    check "it did not wait (${elapsed}ms)" 0 $?
    check "the container got no signal" no "$(test -s "$WORKDIR/rf/rf6" && echo yes || echo no)"
}

@test "rm -f of an --rm container stops it as well" {
    rf_run rf7 TERM yes --rm --stop-timeout 2
    rf_time sh_ container rm -f rf7
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 8000
    check "it took the stop timeout (${elapsed}ms)" 0 $?
    check "the container is gone" no "$(sh_ container exists rf7 > /dev/null 2>&1 && echo yes || echo no)"
}

@test "rm -f of a container with dependents is refused; --depend removes them first, each stopped as it is set" {
    rf_run rfb TERM no --stop-timeout 60
    rf_run rfd TERM no --stop-timeout 60 --requires rfb
    rm -f "$WORKDIR/rf/order"
    out=$(sh_ container rm -f rfb 2>&1)
    check "rm -f of the container others depend on fails" yes "$(test $? -ne 0 && echo yes)"
    check_match "and says why" "has dependent containers which must be removed before it" "$out"
    check "nothing was stopped" "running running" "$(state_of rfb) $(state_of rfd)"
    rf_time sh_ container rm -f --depend rfb
    check "rm -f --depend succeeds" 0 "$rc"
    check "the dependent got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfd")"
    check "the container got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfb")"
    check "the dependent was stopped first" "rfd rfb" "$(echo $(cat "$WORKDIR/rf/order"))"
    check "both are gone" 0 "$(sh_ container list -a -q | wc -l)"
    check_match "the dependent is told, then the container" "^[0-9a-f]{64}$" "$(head -n 1 "$WORKDIR/rf.out")"
    check "the container is named last" rfb "$(tail -n 1 "$WORKDIR/rf.out")"
}

@test "pod rm -f stops the containers together, each with its stop timeout; -t overrides" {
    sh_ pod create --name rfp > /dev/null
    rf_run rfp1 TERM yes --pod rfp --stop-timeout 2
    rf_run rfp2 TERM yes --pod rfp --stop-timeout 2
    rf_time sh_ pod rm -f rfp
    check "pod rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 3900
    check "the containers stopped together (${elapsed}ms)" 0 $?
    check "the first got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfp1")"
    check "the second got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfp2")"
    check_match "the kill is told" "failed to stop container rfp1 in 2 seconds" "$(cat "$WORKDIR/rf.out")"
    check "the pod is gone" no "$(sh_ pod exists rfp > /dev/null 2>&1 && echo yes || echo no)"

    sh_ pod create --name rfp > /dev/null
    rf_run rfp3 TERM yes --pod rfp --stop-timeout 60
    rf_time sh_ pod rm -f -t 0 rfp
    check "pod rm -f -t 0 succeeds" 0 "$rc"
    test "$elapsed" -lt 10000
    check "it did not wait (${elapsed}ms)" 0 $?
    check "the container got no signal" no "$(test -s "$WORKDIR/rf/rfp3" && echo yes || echo no)"
}

@test "rm without -f refuses a running container, and a stopped one is removed at once" {
    rf_run rf8 TERM yes --stop-timeout 60
    out=$(sh_ container rm rf8 2>&1)
    check "rm of a running container fails" yes "$(test $? -ne 0 && echo yes)"
    check_match "with podman's words" "cannot remove container .* as it is running - running or paused containers cannot be removed without force" "$out"
    check "and it was not signalled" no "$(test -s "$WORKDIR/rf/rf8" && echo yes || echo no)"
    sh_ container stop -t 0 rf8 > /dev/null
    rf_time sh_ container rm rf8
    check "a stopped container is removed" 0 "$rc"
}

@test "volume rm -f, network rm -f and image rm -f stop the containers that use them as rm -f does" {
    sh_ volume create rfvol > /dev/null
    rf_run rfv TERM yes --stop-timeout 2 -v rfvol:/data
    rf_time sh_ volume rm -f rfvol
    check "volume rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 8000
    check "it took the stop timeout of the container (${elapsed}ms)" 0 $?
    check "the container got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfv")"
    check "the kill is told as podman tells it" \
        "WARN StopSignal SIGTERM failed to stop container rfv in 2 seconds, resorting to SIGKILL
rfvol" "$(rf_plain)"

    sh_ network create rfnet > /dev/null
    rf_run rfn TERM yes --stop-timeout 60 --network rfnet
    rf_time sh_ network rm -f -t 1 rfnet
    check "network rm -f -t 1 succeeds" 0 "$rc"
    test "$elapsed" -ge 800 -a "$elapsed" -lt 20000
    check "it took the time given (${elapsed}ms)" 0 $?
    check "the container got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfn")"
    check "the kill is told" \
        "WARN StopSignal SIGTERM failed to stop container rfn in 1 seconds, resorting to SIGKILL
rfnet" "$(rf_plain)"

    # (an image of its own: the removal of one name of several only untags)
    sh_ container create --name rfc "$IMAGE" true > /dev/null
    sh_ image commit -q rfc localhost/rf-image > /dev/null 2>&1
    sh_ container rm rfc > /dev/null
    IMAGE=localhost/rf-image rf_run rfi TERM yes --stop-timeout 2
    rf_time sh_ image rm -f localhost/rf-image
    check "image rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 1800 -a "$elapsed" -lt 8000
    check "it took the stop timeout of the container (${elapsed}ms)" 0 $?
    check "the container got SIGTERM" TERM "$(cat "$WORKDIR/rf/rfi")"
    check_match "the kill is told" \
        "^time=\"[^\"]+\" level=warning msg=\"StopSignal SIGTERM failed to stop container rfi in 2 seconds, resorting to SIGKILL\"$" \
        "$(cat "$WORKDIR/rf.out")"
    check "the container is gone" no "$(sh_ container exists rfi > /dev/null 2>&1 && echo yes || echo no)"
}

@test "rm -f and stop of several containers stop them together" {
    rf_run rfp1 TERM yes --stop-timeout 3
    rf_run rfp2 TERM yes --stop-timeout 3
    rf_run rfp3 TERM yes --stop-timeout 3
    rf_time sh_ container rm -f rfp1 rfp2 rfp3
    check "rm -f succeeds" 0 "$rc"
    test "$elapsed" -ge 2800 -a "$elapsed" -lt 6000
    check "the stop timeouts did not add up (${elapsed}ms)" 0 $?
    check "the names are printed in the order given" "rfp1 rfp2 rfp3" "$(grep '^rfp' "$WORKDIR/rf.out" | tr '\n' ' ' | sed 's/ $//')"
    rf_run rfp4 TERM yes --stop-timeout 3
    rf_run rfp5 TERM yes --stop-timeout 3
    rf_time sh_ container stop rfp4 rfp5
    check "stop succeeds" 0 "$rc"
    test "$elapsed" -ge 2800 -a "$elapsed" -lt 5500
    check "the stops are together (${elapsed}ms)" 0 $?
    sh_ container rm -f rfp4 rfp5 > /dev/null
}
