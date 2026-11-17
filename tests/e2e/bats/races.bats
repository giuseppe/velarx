# SPDX-License-Identifier: Apache-2.0
# End to end tests of the races between commands on one object: the
# start, removal and init of a container, ... Each test runs commands
# side by side at the same instant (a start barrier, no sleeps) and checks that
# one outcome of the allowed ones happens and that nothing is left behind.
# Run it as an ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# barrier_run COMMAND...: run the commands given as "N:command" words (N the
# number of the output file) at the same instant: every one waits on a FIFO
# that is released once all have started.
#
# parallel_run OUTPUT_PREFIX CMD1 CMD2...: the commands as shell strings.
parallel_run () {
    local prefix=$1 n=0 cmd fifo=$WORKDIR/barrier.$$
    shift
    rm -f "$fifo"
    mkfifo "$fifo"
    for cmd in "$@"; do
        n=$((n + 1))
        (
            read -r <> "$fifo"
            eval "$cmd" > "$prefix.$n.out" 2>&1
            echo $? > "$prefix.$n.rc"
        ) 3>&- &
    done
    # (the readers block in `read` until a line comes; the FIFO is kept open
    # until all of them have read: a reader that opens it after the others
    # closed it would find the lines gone, and wait for ever)
    exec 7<> "$fifo"
    for cmd in "$@"; do echo go >&7; done
    wait
    exec 7>&-
    rm -f "$fifo"
}

# What a container leaves on disk and in the process table, by its id: the
# directory of its logs, the one of its monitor, its lock.
leftovers_of () {
    local id=$1 p out=
    [ -e "$XDG_DATA_HOME/velarx/logs/$id" ] && out="$out logs"
    [ -e "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}" ] && out="$out mon"
    for p in /proc/[0-9]*; do
        case "$(cat "$p/comm" 2> /dev/null)" in
        pasta*) ;;
        *) continue ;;
        esac
        tr '\0' ' ' < "$p/cmdline" 2> /dev/null | grep -q -- "$WORKDIR" && out="$out pasta"
    done
    echo "$out"
}

@test "start and rm -f of one container side by side leave nothing behind" {
    local i bad=0 id left
    for i in $(seq "${RACE_ROUNDS:-12}"); do
        id=$(sh_ container create --name rs$i "$IMAGE" sleep 1000)
        parallel_run "$WORKDIR/rs$i" "sh_ container start rs$i" "sh_ container rm -t 0 -f rs$i"
        # one of them removed it: the other started it first, or failed
        sh_ container rm -t 0 -f rs$i > /dev/null 2>&1
        left=$(leftovers_of "$id")
        if [ -n "$left" ]; then
            echo "# round $i: left behind:$left" >&3
            bad=$((bad + 1))
        fi
    done
    check "rounds that left something" 0 "$bad"
}

@test "init and start of one container side by side: one monitor, no raw error" {
    local i bad=0 id out
    for i in $(seq "${RACE_ROUNDS:-12}"); do
        id=$(sh_ container create --name ri$i --network none "$IMAGE" sleep 1000)
        parallel_run "$WORKDIR/ri$i" "sh_ container init ri$i" "sh_ container start ri$i"
        out=$(cat "$WORKDIR"/ri$i.*.out)
        # the start wins (the init may fail, it is told the container
        # exists already); a start that fails must say why in podman's words
        if [ "$(sh_ container inspect ri$i --format '{{.State.Status}}' 2> /dev/null)" != running ]; then
            echo "# round $i: not running: $out" >&3
            bad=$((bad + 1))
        elif echo "$out" | grep -q "os error\|ENOENT\|fsconfig"; then
            echo "# round $i: raw error: $out" >&3
            bad=$((bad + 1))
        fi
        sh_ container rm -t 0 -f ri$i > /dev/null 2>&1
        [ -z "$(leftovers_of "$id")" ] || bad=$((bad + 1))
    done
    check "rounds that went wrong" 0 "$bad"
}

@test "a stop that comes while the container starts stops what the start made" {
    local i bad=0 seen=0 id ids= lock sp src state left
    sh_ network create racenet > /dev/null
    for i in $(seq "${RACE_ROUNDS:-8}"); do
        id=$(sh_ container create --name rst$i --network racenet "$IMAGE" sleep 1000)
        lock=$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}.lock
        sh_ container start rst$i > "$WORKDIR/rst$i.start" 2>&1 &
        sp=$!
        # (the stop comes once the start holds its lock, while it runs)
        while flock -n "$lock" true 2> /dev/null && kill -0 $sp 2> /dev/null; do :; done
        if kill -0 $sp 2> /dev/null; then
            seen=$((seen + 1))
            if ! sh_ container stop -t 0 rst$i > "$WORKDIR/rst$i.stop" 2>&1; then
                echo "# round $i: stop: $(cat "$WORKDIR/rst$i.stop")" >&3
                bad=$((bad + 1))
            fi
        fi
        wait $sp
        src=$?
        state=$(sh_ container inspect rst$i --format '{{.State.Status}}')
        if [ "$src" != 0 ]; then
            echo "# round $i: start rc=$src: $(cat "$WORKDIR/rst$i.start")" >&3
            bad=$((bad + 1))
        elif [ -e "$WORKDIR/rst$i.stop" ] && [ "$state" != exited ]; then
            echo "# round $i: stopped during the start, now $state" >&3
            bad=$((bad + 1))
        fi
        sh_ container rm -t 0 -f rst$i > /dev/null 2>&1
        ids="$ids $id"
    done
    # (the network's namespace and its pasta stay while the network has
    # containers)
    sh_ network rm racenet > /dev/null 2>&1
    for id in $ids; do
        left=$(leftovers_of "$id")
        if [ -n "$left" ]; then
            echo "# ${id:0:12}: left behind:$left" >&3
            bad=$((bad + 1))
        fi
    done
    echo "# rounds with the stop during the start: $seen" >&3
    check "rounds that went wrong" 0 "$bad"
}

# (the command line on the engine's socket: the calls go through the engine)
ec_ () {
    "$SH" --socket "$ESOCK" "$@" 3>&-
}

@test "a connection made right after a restart of the engine is served by the engine that follows" {
    local i bad=0 out
    for i in $(seq "${RACE_ROUNDS:-10}"); do
        out=$(python3 -I "$E2E_DIR/restart_race.py" "$ESOCK" 2>&1)
        if [ "$out" != ok ]; then
            echo "# round $i: $out" >&3
            bad=$((bad + 1))
        fi
    done
    check "rounds where the connection was cut" 0 "$bad"
}

@test "a stop in progress finishes when the engine is stopped with SIGTERM" {
    mkdir -p "$WORKDIR/st"
    mkfifo "$WORKDIR/st/f"
    ec_ container run -d --name st1 --network none -v "$WORKDIR/st:/st:z" "$IMAGE" \
        sh -c 'trap "echo got > /st/f" TERM; while :; do sleep 1 & wait $!; done' > /dev/null
    ec_ container stop -t 4 st1 > "$WORKDIR/st1.out" 2>&1 &
    local stopper=$!
    # (the stop is under way once the container has its stop signal; it
    # does not end by it)
    read -r < "$WORKDIR/st/f"
    kill -TERM "$DAEMON_PID"
    wait "$stopper"
    local rc=$?
    echo "# stop: rc=$rc $(cat "$WORKDIR/st1.out")" >&3
    check "the stop was answered" 0 "$rc"
    check "the container is stopped" exited "$(sh_ container inspect st1 --format '{{.State.Status}}')"
    sh_ container rm -t 0 -f st1 > /dev/null 2>&1
}

@test "networks created at once get different subnets" {
    local i cmds=() subnets
    for i in $(seq 10); do cmds+=("sh_ network create rn$i"); done
    parallel_run "$WORKDIR/rn" "${cmds[@]}"
    for i in $(seq 10); do
        check "network create rn$i" 0 "$(cat "$WORKDIR/rn.$i.rc")"
    done
    subnets=$(for i in $(seq 10); do sh_ network inspect rn$i | grep -o '"[Ss]ubnet": *"[^"]*"'; done | sort -u | wc -l)
    for i in $(seq 10); do sh_ network rm rn$i > /dev/null 2>&1; done
    check "distinct subnets of 10 networks" 10 "$subnets"
}

@test "rm of a network and a run on it at once: one fails, no container is left on a missing network" {
    local i bad=0 out
    for i in $(seq "${RACE_ROUNDS:-8}"); do
        sh_ network create rnet$i > /dev/null
        parallel_run "$WORKDIR/rd$i" "sh_ container create --name rdc$i --network rnet$i $IMAGE true" "sh_ network rm rnet$i"
        if [ -n "$(sh_ container list -a --format '{{.Names}}' | grep -x rdc$i)" ] &&
           ! sh_ network inspect rnet$i > /dev/null 2>&1; then
            echo "# round $i: container rdc$i on the removed network rnet$i" >&3
            bad=$((bad + 1))
        fi
        sh_ container rm -t 0 -f rdc$i > /dev/null 2>&1
        sh_ network rm -t 0 -f rnet$i > /dev/null 2>&1
    done
    check "rounds that left a container on a removed network" 0 "$bad"
}

@test "containers created at once with -p 80 get different host ports" {
    local b i n=0 ports dup
    for b in $(seq "${RACE_BATCHES:-30}"); do
        local cmds=()
        for i in $(seq 20); do
            n=$((n + 1))
            cmds+=("sh_ container create --name hp$n --network pasta -p 80 $IMAGE true")
        done
        parallel_run "$WORKDIR/hp$b" "${cmds[@]}"
    done
    ports=$(for i in $(seq $n); do
        sh_ container inspect hp$i 2> /dev/null | awk '/"bound_ports"/ { f = 1 } f && /"host_port"/ { print $2; exit }'
    done)
    dup=$(echo "$ports" | sort | uniq -d | wc -l)
    for i in $(seq $n); do sh_ container rm -t 0 -f hp$i > /dev/null 2>&1; done
    check "containers created" "$n" "$(echo "$ports" | wc -l)"
    check "host ports given to two containers" 0 "$dup"
}

@test "pod rm -f and run --pod at once: the pod goes, with every container that joined it" {
    local i bad=0 left
    for i in $(seq "${RACE_ROUNDS:-10}"); do
        sh_ pod create --name rp$i > /dev/null
        parallel_run "$WORKDIR/rp$i" "sh_ pod rm -t 0 -f rp$i" "sh_ container create --pod rp$i --name rpc$i $IMAGE true"
        left=$(sh_ container list -a --format '{{.Names}}' | grep -c '^rpc' ; true)
        if [ "$(cat "$WORKDIR/rp$i.1.rc")" != 0 ] || [ "$left" != 0 ] || sh_ pod exists rp$i 2> /dev/null; then
            echo "# round $i: rm rc=$(cat "$WORKDIR/rp$i.1.rc") containers left=$left: $(cat "$WORKDIR/rp$i.1.out" "$WORKDIR/rp$i.2.out" | tr '\n' ' ')" >&3
            bad=$((bad + 1))
            sh_ pod rm -t 0 -f rp$i > /dev/null 2>&1
            sh_ container rm -t 0 -f rpc$i > /dev/null 2>&1
        fi
    done
    check "rounds that went wrong" 0 "$bad"
}

# wait_line FILE PATTERN: return when a line of FILE matches PATTERN (the
# end of the file is followed: inotify through tail -F), at most 20 s.
wait_line () {
    timeout 20 tail -n +1 -F "$1" 2> /dev/null | grep -q -m1 -- "$2"
}

@test "events --stream shows an event at once, and one kept late" {
    local cfg=$WORKDIR/events.toml since log
    sed 's/^\[server\]/[server]\nevents_logger = "file"/' "$CONFIG" > "$cfg"
    log=$XDG_DATA_HOME/velarx/events/events.log
    since=$(( $(date +%s) - 60 ))
    "$BIN/velarx" --config "$cfg" events --stream --since "$since" > "$WORKDIR/ev.out" 2>&1 3>&- &
    local follower=$!
    "$BIN/velarx" --config "$cfg" container create --name evc1 --network none "$IMAGE" true > /dev/null
    wait_line "$WORKDIR/ev.out" evc1 || { kill "$follower"; e2e_die "no event for evc1"; }
    # an event kept 5 s after its time, by a slow writer
    printf '{"Type":"container","Status":"late","ID":"x","Name":"latebird","Image":"","Attributes":{},"TimeNano":%s}\n' \
        "$(( ($(date +%s) - 5) * 1000000000 ))" >> "$log"
    wait_line "$WORKDIR/ev.out" latebird || { kill "$follower"; e2e_die "the late event was not shown"; }
    kill "$follower"
    wait "$follower" 2> /dev/null
    "$BIN/velarx" --config "$cfg" container rm -t 0 -f evc1 > /dev/null 2>&1
}

# pod_db_state POD: the state the pod is recorded in.
pod_db_state () {
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["state"])' \
        "$(ls "$XDG_DATA_HOME"/velarx/pods/*.json | head -1)"
}

# pod_stress_round SECONDS POD: four processes start and stop the pod and
# its members for SECONDS (no pause between the commands).
pod_stress_round () {
    local end=$(( $(date +%s) + $1 )) pod=$2 w pids=()
    for w in 1 2 3 4; do
        (
            while [ "$(date +%s)" -lt "$end" ]; do
                case $((RANDOM % 4)) in
                0) "$SH" pod start "$pod" ;;
                1) "$SH" pod stop -t 0 "$pod" ;;
                2) "$SH" container start "${pod}a" ;;
                3) "$SH" container stop -t 0 "${pod}b" ;;
                esac
            done > /dev/null 2>&1
        ) 3>&- &
        pids+=($!)
    done
    wait "${pids[@]}"
}

@test "pod start, pod stop and start and stop of its members at once: the pod is recorded as its containers are" {
    local live db bad=0 round m
    sh_ pod create --name sp > /dev/null
    for m in a b c d e f; do
        sh_ container create --pod sp --name sp$m "$IMAGE" sleep 1000 > /dev/null
    done
    for round in $(seq "${RACE_POD_ROUNDS:-3}"); do
        pod_stress_round "${RACE_POD_SECONDS:-5}" sp
        # (every command ended: what is recorded is what is there)
        live=$(sh_ container list --format '{{.Names}}' | grep -c '^sp')
        db=$(pod_db_state)
        if { [ "$live" -gt 0 ] && [ "$db" != running ]; } || { [ "$live" = 0 ] && [ "$db" = running ]; }; then
            echo "# round $round: $live containers run, the pod is recorded $db" >&3
            bad=$((bad + 1))
        fi
    done
    sh_ pod rm -f -t 0 sp > /dev/null 2>&1
    check "rounds with a pod recorded other than its containers are" 0 "$bad"
}

@test "a container started again right after its stop or kill gets its scope without waiting for the old one" {
    local i t0 worst=0 ms
    sh_ container create --name scs --network none "$IMAGE" sleep 1000 > /dev/null
    for i in $(seq "${RACE_ROUNDS:-12}"); do
        sh_ container start scs > /dev/null
        if [ $((i % 2)) = 0 ]; then
            sh_ container stop -t 0 scs > /dev/null
        else
            # (no wait for the end: the start comes while the scope goes)
            sh_ container kill scs > /dev/null
        fi
        t0=$(now_ms)
        sh_ container start scs > /dev/null
        ms=$(( $(now_ms) - t0 ))
        [ "$ms" -gt "$worst" ] && worst=$ms
        echo "# start $i after the stop: $ms ms" >&3
    done
    sh_ container rm -f -t 0 scs > /dev/null
    # (a wait for the old scope that ran to its limit would take 2 s)
    [ "$worst" -lt 1500 ] || e2e_die "a start after a stop took $worst ms"
}

@test "run -d and rm -f of one name side by side: a container removed while it starts is not a command not found (126, as podman)" {
    local end=$(( $(date +%s) + ${RACE_SECONDS:-15} )) w pids=() n127=0 total=0
    sh_ network create rn > /dev/null
    for w in 1 2 3 4; do
        (
            while [ "$(date +%s)" -lt "$end" ]; do
                if [ $((RANDOM % 2)) = 0 ]; then
                    "$SH" container run -d --name rz1 --network rn "$IMAGE" sleep 1000
                else
                    "$SH" container rm -f -t 0 rz1
                fi > /dev/null 2>&1 < /dev/null
                echo $? >> "$WORKDIR/rz.$w.rc"
            done
        ) 3>&- &
        pids+=($!)
    done
    wait "${pids[@]}"
    total=$(cat "$WORKDIR"/rz.*.rc | wc -l)
    n127=$(grep -c '^127$' "$WORKDIR"/rz.*.rc | awk -F: '{s += $2} END {print s + 0}')
    echo "# $total commands, $n127 exited 127" >&3
    sh_ container rm -f -t 0 rz1 > /dev/null 2>&1
    sh_ network rm -t 0 -f rn > /dev/null 2>&1
    check "commands that exited 127" 0 "$n127"
}
