# SPDX-License-Identifier: Apache-2.0
# End to end tests of the foreground run (with and without a monitor
# process) and of the commands that run with no engine service, in the engine of
# their own process, and of velarx-client, through a daemon of its own.
# Run it as an ordinary user for the rootless daemon, or as root.

load helpers
load run_lib

# (the events are kept in a file: the journal of a busy host drops what the
# units of a user send above its rate limit, and the tests are not about it)
events_in_a_file () {
    sed -i '/^\[server\]/a events_logger = "file"' "$CONFIG"
}

setup_file () {
    E2E_BEFORE_DAEMON=events_in_a_file run_setup_file
}

teardown_file () {
    run_teardown_file
}

# The monitors of the store that run now.
monitor_count () {
    e2e_monitors "$WORKDIR" | wc -l
}

# What a foreground run does, the same with a monitor process and with
# --no-monitor: $1 is the mode ("" or --no-monitor).
foreground_checks () {
    local mode=$1 tag=${1:-monitor}
    out=$(sh_ container run --rm $mode --network none "$IMAGE" sh -c 'echo out; echo err >&2' 2> /dev/null)
    check "$tag: stdout" "out" "$out"
    out=$(sh_ container run --rm $mode --network none "$IMAGE" sh -c 'echo out; echo err >&2' 2>&1 > /dev/null)
    check "$tag: stderr" "err" "$out"
    out=$(echo from-stdin | sh_ container run --rm -i $mode --network none "$IMAGE" cat)
    check "$tag: stdin with -i" "from-stdin" "$out"
    sh_ container run --rm $mode --network none "$IMAGE" sh -c 'exit 7'
    check "$tag: the exit code" 7 $?
    big=$(sh_ container run --rm $mode --network none "$IMAGE" sh -c 'i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); done' | md5sum)
    check "$tag: a lot of output" "$(i=0; while [ $i -lt 20000 ]; do echo line-$i; i=$((i+1)); done | md5sum)" "$big"

    # while it runs: other clients see it, exec into it, attach to it, its
    # health is checked; then its log is there
    before=$(monitor_count)
    "$SH" container run $mode --name fg --log-driver k8s-file --network none --health-cmd 'test -f /tmp/ok' --health-interval 1s \
        --health-retries 1 "$IMAGE" sh -c 'echo start; i=0; while [ ! -f /tmp/done ]; do sleep 0.2; i=$((i+1)); [ $i -lt 100 ] || break; done; echo end; exit 3' \
        > "$WORKDIR/fg.out" 2>&1 3>&- &
    fg=$!
    wait_for 15 state_is fg running
    check "$tag: running" 0 $?
    if test -n "$mode"; then
        check "$tag: no monitor process" "$before" "$(monitor_count)"
    else
        check "$tag: a monitor process" "$((before + 1))" "$(monitor_count)"
    fi
    check "$tag: exec" "in-fg" "$(sh_ container exec fg echo in-fg 2>&1)"
    wait_health fg unhealthy
    check "$tag: health checks" 0 $?
    sh_ container exec fg touch /tmp/ok
    wait_health fg healthy
    check "$tag: healthy" 0 $?
    "$SH" container attach --no-stdin fg > "$WORKDIR/fg-attach.out" 2>&1 3>&- &
    at=$!
    # (no event says that an attach is connected: a moment for it)
    sleep 0.5
    sh_ container exec fg touch /tmp/done
    wait "$fg"
    check "$tag: the run ends with the container" 3 $?
    wait "$at"
    check "$tag: the output" "start
end" "$(cat "$WORKDIR/fg.out")"
    check "$tag: another client attached" "end" "$(cat "$WORKDIR/fg-attach.out")"
    check "$tag: logs" "start
end" "$(sh_ container logs fg 2>&1)"
    check_match "$tag: the exit is recorded" "^3$" "$(sh_ container wait fg)"
    sh_ container rm fg > /dev/null
}

# The processes of the store but the processes of the commands `$@` and
# everything they started (a short-lived fork of a command is not a helper):
# one snapshot of the process table, the closure of the children computed
# from it.
helpers_of_store () {
    ps -eo pid=,ppid=,args= | awk -v config="--config $CONFIG" -v roots="$*" '
        BEGIN { n = split(roots, r, " "); for (i = 1; i <= n; i++) mine[r[i]] = 1 }
        { pid[NR] = $1; ppid[NR] = $2; line[NR] = $0 }
        END {
            do {
                grew = 0
                for (i = 1; i <= NR; i++)
                    if ((ppid[i] in mine) && !(pid[i] in mine)) { mine[pid[i]] = 1; grew = 1 }
            } while (grew)
            for (i = 1; i <= NR; i++)
                if (!(pid[i] in mine) && index(line[i], config) && !index(line[i], "awk -v config=")) c++
            print c + 0
        }'
}

# Start `velarx ARGS` in a process group of its own, with the default
# actions of SIGINT and SIGQUIT (a shell ignores them for what it starts in
# the background): BG is its pid.
start_in_group () {
    setsid perl -e '$SIG{INT} = "DEFAULT"; $SIG{QUIT} = "DEFAULT"; exec @ARGV' \
        "$SH" "$@" 3>&- &
    BG=$!
}

# The mounts of the bundles of containers, in the namespaces of the engine.
mounts_of_bundles () {
    if test "$(id -u)" = 0; then
        grep -c '/bundles/' /proc/self/mountinfo
    else
        sh_ unshare sh -c "grep -c '/bundles/' /proc/self/mountinfo; true" 2> /dev/null
    fi
}

# Wait (at most 60 seconds) until FILE has a line that matches PATTERN
# (inotify on the file, no tail left behind).
wait_for_line () {
    e2e_wait_line "$1" "$2" 60
}

@test "foreground run with and without a monitor process, a terminal, signals, killed" {
    foreground_checks ""
    foreground_checks --no-monitor

    # a terminal: input, its size, the exit code
    if command -v python3 > /dev/null; then
        out=$($PTY_RUN --size 30,90 --expect '# ' --input 'tty; stty size\r' --input 'exit 4\r' -- \
            "$SH" container run -it --rm --no-monitor --network none "$IMAGE" sh)
        check "--no-monitor -it: the exit code" 4 $?
        check_match "--no-monitor -it: a terminal" "/dev/pts/[0-9]" "$out"
        check_match "--no-monitor -it: its size" "30 90" "$out"
    fi

    sh_ container run -d --no-monitor --network none "$IMAGE" true > /dev/null 2>&1
    check "--no-monitor with -d is refused" 125 $?
    out=$("$SH" --socket "$ESOCK" container run --no-monitor --network none "$IMAGE" true 2>&1)
    check_match "--no-monitor through the server is refused" "without --socket" "$out"

    # the signals of the process go to the container
    # (not through a function: $! is then the process of the command)
    "$SH" container run --rm --no-monitor --network none "$IMAGE" \
        sh -c 'trap "echo got-term; exit 9" TERM; echo trapped; sleep 30 & wait' > "$WORKDIR/nmsig.out" 2>&1 3>&- &
    p=$!
    # (the trap is set once the command said so)
    e2e_wait_line "$WORKDIR/nmsig.out" '^trapped$' 30 || e2e_die "the command did not set its trap within 30 s"
    kill -TERM "$p"
    wait "$p"
    check "SIGTERM goes to the container" 9 $?
    check "which got it" "trapped
got-term" "$(cat "$WORKDIR/nmsig.out")"

    # killed, the process leaves a consistent state: the exit is recorded
    # later, nothing stays mounted
    "$SH" container run --no-monitor --name nmk --network none \
        "$IMAGE" sleep 2 > /dev/null 2>&1 3>&- &
    p=$!
    wait_for 15 state_is nmk running
    id=$(sh_ container inspect nmk | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    kill -KILL "$p"
    wait "$p" 2> /dev/null
    wait_state nmk exited 30
    check "killed: the exit is recorded" 0 $?
    sh_ container rm -t 0 -f nmk > /dev/null
    check "killed: the container goes" "" "$(state_of nmk)"
    n=$(awk -v id="$id" 'index($5, id) > 0' /proc/self/mountinfo | wc -l)
    check "killed: nothing stays mounted" 0 "$n"
}

# With no engine service, a command runs in the engine of its own process:
# no helper process, no socket of its own; `events` follows what the
# backend keeps.
@test "no server: images, volumes, networks, a runtime of the configuration" {
    stop_daemon
    out=$(sh_ volume list 2>&1 > /dev/null)
    check "no server: the command runs in its process, quietly" "" "$out"
    sh_ image list > "$WORKDIR/dl.out" 2>&1
    check "no server: image list" 0 $?
    check_match "no server: the images are there" "alpine" "$(cat "$WORKDIR/dl.out")"
    sh_ image tag "$IMAGE" localhost/dl:1 > /dev/null
    check "no server: image tag" 0 $?
    check_match "no server: image inspect" '"Digest": "sha256:' "$(sh_ image inspect localhost/dl:1 2>&1)"
    sh_ image remove localhost/dl:1 > /dev/null
    check "no server: image rm" 0 $?
    check "no server: the tag goes" "" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' | grep 'localhost/dl:1')"
    check_match "no server: the image stays" "${IMAGE#*/}" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    sh_ image pull "$IMAGE" > /dev/null 2>&1
    check "no server: image pull" 0 $?
    check_match "no server: the image is back" "${IMAGE#*/}" "$(sh_ image list --format '{{.Repository}}:{{.Tag}}' 2>&1)"
    # the configuration's [server] runtime (its last section), a name of [runtimes]
    { cat "$CONFIG"; printf 'runtime = "idonotexist"\n'; } > "$WORKDIR/rt.toml"
    out=$(sh_ --config "$WORKDIR/rt.toml" container run --rm "$IMAGE" true 2>&1)
    check "no server: a runtime of the configuration that is not there is 125" 125 $?
    check_match "no server: and says so" 'runtime.*idonotexist' "$out"
    { cat "$CONFIG"; printf 'runtime = "myrt"\n[runtimes]\nmyrt=["/nonexistent/crun", "%s"]\n' "$(command -v crun)"; } > "$WORKDIR/rt.toml"
    check "no server: a name of [runtimes]: its first path that is there" ok \
        "$(sh_ --config "$WORKDIR/rt.toml" container run --rm "$IMAGE" echo ok 2>&1)"
    sh_ volume create dlv > /dev/null
    check "no server: volume create" 0 $?
    check_match "no server: volume list" "dlv" "$(sh_ volume list 2>&1)"
    check_match "no server: volume inspect" "dlv" "$(sh_ volume inspect dlv 2>&1)"
    check_match "no server: network list" "podman" "$(sh_ network ls 2>&1)"
}

@test "no server: a pod with the exit policy stop ends when its containers did; the infra and the networks it reports" {
    stop_daemon
    sh_ pod create --exit-policy stop pxe > /dev/null
    infra=$(sh_ pod inspect pxe --format '{{.InfraContainerID}}')
    sh_ container run --pod pxe --log-driver k8s-file "$IMAGE" true > /dev/null
    check "run in the pod" 0 $?
    timeout 60 "$SH" container wait --condition stopped "$infra" > /dev/null 3>&-
    check "no server: the infra container stopped with the last container" Exited \
        "$(sh_ pod inspect pxe --format '{{.State}}')"
    check "the pod has an infra container" true "$(sh_ pod inspect pxe --format '{{.CreateInfra}}')"
    if [ "$(id -u)" != 0 ]; then
        check "a rootless pod is on pasta: no network" "" "$(sh_ pod ps --format '{{.Networks}}' | head -1)"
    fi
    sh_ pod create --infra=false pnoinfra > /dev/null
    check "a pod without infra container" false "$(sh_ pod inspect pnoinfra --format '{{.CreateInfra}}')"
    sh_ pod rm -f pxe pnoinfra > /dev/null
}

# (the logs are read from a file: the journal of a busy host drops what the
# units of a user send above its rate limit, and these tests are not about it)
@test "no server: containers, wait --condition, the events kept, no helper process" {
    stop_daemon
    sh_ container run -d --name dl1 --log-driver k8s-file --network none -v dlv:/data "$IMAGE" \
        sh -c 'echo hello > /data/f; echo out; sleep 2; exit 5' > /dev/null
    check "no server: run -d" 0 $?
    check "no server: exec" "hello" "$(sh_ container exec dl1 cat /data/f 2>&1)"
    check_match "no server: inspect" '"name": "dl1"' "$(sh_ container inspect dl1 2>&1)"
    check_match "no server: wait" "^5$" "$(sh_ container wait dl1 2>&1)"
    check "no server: logs" "out" "$(sh_ container logs dl1 2>&1)"

    # `wait --condition` of a container another process made and runs: the
    # changes the other processes record wake it (no timer)
    sh_ container create --name dlw --network none "$IMAGE" sleep 100 > /dev/null
    "$SH" container wait --condition running dlw > "$WORKDIR/dl-wait.out" 2>&1 3>&- &
    waiter=$!
    sh_ container start dlw > /dev/null
    wait "$waiter"
    check "no server: wait --condition running sees the start made by another process" "0 -1" "$? $(cat "$WORKDIR/dl-wait.out")"
    "$SH" container wait --condition stopped dlw > "$WORKDIR/dl-wait.out" 2>&1 3>&- &
    waiter=$!
    "$SH" container wait --condition exited dlw > "$WORKDIR/dl-wait2.out" 2>&1 3>&- &
    waiter2=$!
    sh_ container stop -t 1 dlw > /dev/null
    wait "$waiter"; st1=$?
    wait "$waiter2"; st2=$?
    check "no server: wait --condition stopped and exited see the stop made by another process" "0 0 137 137" \
        "$st1 $st2 $(cat "$WORKDIR/dl-wait.out") $(cat "$WORKDIR/dl-wait2.out")"
    sh_ container rm dlw > /dev/null
    # next-exit and removed in the engine of this process, of an exit and a
    # removal another process makes (the sleep in the container leaves the
    # wait the time to arm)
    sh_ container create --name dln --network none "$IMAGE" sh -c 'sleep 2; exit 7' > /dev/null
    "$SH" container wait --condition next-exit dln > "$WORKDIR/dl-next.out" 2>&1 3>&- &
    waiter=$!
    sh_ container start dln > /dev/null
    wait "$waiter"
    check "no server: wait --condition next-exit sees the run another process started" "0 7" \
        "$? $(cat "$WORKDIR/dl-next.out")"
    sh_ container rm dln > /dev/null
    sh_ container run -d --rm --name dlr --network none "$IMAGE" sh -c 'sleep 2; exit 3' > /dev/null
    check "no server: wait --condition removed of an --rm container" 3 \
        "$(sh_ container wait --condition removed dlr 2>&1)"
    sh_ container run -d --rm --name dlr2 --network none "$IMAGE" sh -c 'sleep 2; exit 4' > /dev/null
    check "no server: wait of an --rm container" 4 "$(sh_ container wait dlr2 2>&1)"
    check_match "no server: the events kept" "died .*name=dl1" "$(sh_ events --stream=false --filter container=dl1 2>&1)"
    # following the events: those the backend keeps, which every process writes
    # (the stream is live once it shows the kept event of a marker made before)
    sh_ container create --name dlmark --network none "$IMAGE" true > /dev/null
    timeout 30 "$SH" events --since 5m --filter container=dlmark --filter container=dlf > "$WORKDIR/dl-follow.out" 2>&1 3>&- &
    follower=$!
    e2e_wait_line "$WORKDIR/dl-follow.out" 'create .*name=dlmark' 30 || e2e_die "the events stream does not start"
    sh_ container rm dlmark > /dev/null
    sh_ container run --rm --name dlf --network none "$IMAGE" true > /dev/null
    e2e_wait_line "$WORKDIR/dl-follow.out" 'died .*name=dlf' 30
    kill "$follower" 2> /dev/null
    wait "$follower" 2> /dev/null
    check_match "no server: events follows a run of another process" "died .*name=dlf" \
        "$(cat "$WORKDIR/dl-follow.out")"
    check "no server: no helper process is left" 0 "$(helpers_of_store)"
    check "no server: no socket of an engine" no \
        "$(test -e "$(sh_ info --format '{{.Store.RunRoot}}')/engine" && echo yes || echo no)"

}

# the commands that run containers and move images, in process too
@test "no server: build" {
    stop_daemon
    ctx=$WORKDIR/dl-ctx
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN echo built > /built\nCOPY file /file\nCMD ["cat", "/built", "/file"]\n' "$IMAGE" > "$ctx/Containerfile"
    echo copied > "$ctx/file"
    sh_ build -t localhost/dl-build:1 "$ctx" > "$WORKDIR/dl.out" 2> "$WORKDIR/dl.err"
    check "no server: build" 0 $?
    check_match "no server: build shows its progress" "STEP 2/4: RUN" "$(cat "$WORKDIR/dl.err" "$WORKDIR/dl.out")"
    check "no server: build, the RUN step ran in the command and the image is there" "built
copied" "$(sh_ container run --rm --network none localhost/dl-build:1 2>&1)"
    id=$(sh_ build -q -t localhost/dl-build:2 "$ctx" 2> "$WORKDIR/dl.err")
    check "no server: build -q" 0 $?
    check_match "no server: build -q prints the id" "^[0-9a-f]{12,64}$" "$id"
    check "no server: build -q is quiet" "" "$(cat "$WORKDIR/dl.err")"
    sh_ build -q --squash-all -t localhost/dl-build:squashed "$ctx" > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: build --squash-all" "0 " "$? $(cat "$WORKDIR/dl.err")"
    check "no server: build --squash-all, one layer with the content" "1 built
copied" "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/dl-build:squashed) $(sh_ container run --rm --network none localhost/dl-build:squashed 2>&1)"
    printf 'FROM %s\nRUN exit 7\n' "$IMAGE" > "$ctx/Failing"
    out=$(sh_ build -f "$ctx/Failing" "$ctx" 2>&1)
    check "no server: a failing RUN is the exit status 125" 125 $?
    check_match "and says which" "building at STEP .RUN exit 7.: .exit 7. failed with exit code 7" "$out"
    check "no server: no helper process is left after the build" 0 "$(helpers_of_store)"

}

# `build -`: the context on the standard input, a tar or a Containerfile
@test "no server: build - with a tar, a tar.gz or a Containerfile" {
    stop_daemon
    ctx=$WORKDIR/dl-ctx
    tar -C "$ctx" -cf - Containerfile file | sh_ build -q -t localhost/dl-stdin:1 - > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: build - with a tar" "0 " "$? $(cat "$WORKDIR/dl.err")"
    tar -C "$ctx" -czf - Containerfile file | sh_ build -q -t localhost/dl-stdin:2 - > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: build - with a tar.gz" "0 " "$? $(cat "$WORKDIR/dl.err")"
    printf 'FROM %s\nRUN echo piped > /piped\n' "$IMAGE" | sh_ build -q -t localhost/dl-stdin:3 - > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: build - with a Containerfile" "0 " "$? $(cat "$WORKDIR/dl.err")"
    check "no server: the images of build -" "built
copied piped" "$(sh_ container run --rm --network none localhost/dl-stdin:2 2>&1) $(sh_ container run --rm --network none localhost/dl-stdin:3 cat /piped 2>&1)"

}

# a file with holes in the context: the tar of the context has it as a sparse
# entry, GNU tar writes it in the old GNU format or the pax ones; the build
# sees the same file (its size and content), whichever sent it
@test "no server: build with sparse files in the context" {
    stop_daemon
    ctx=$WORKDIR/dl-sparse
    mkdir -p "$ctx/dir"
    truncate -s 2M "$ctx/hole"
    head -c 4096 /dev/urandom > "$ctx/dir/data-hole"
    truncate -s 64M "$ctx/dir/data-hole"
    printf end | dd of="$ctx/dir/data-hole" bs=1 seek=33554432 conv=notrunc 2> /dev/null
    printf 'FROM %s\nCOPY hole /hole\nCOPY dir /dir/\nADD sparse.tar /unpacked/\n' "$IMAGE" > "$ctx/Containerfile"
    tar -C "$ctx" --sparse -cf "$ctx/sparse.tar" dir
    want=$(cd "$ctx" && sha256sum hole dir/data-hole | awk '{print $1}')
    show='cd / && sha256sum hole dir/data-hole unpacked/dir/data-hole; stat -c "%s" hole dir/data-hole'
    sh_ build -q -t localhost/dl-sparse:1 "$ctx" > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: build with sparse files, from a directory" "0 " "$? $(cat "$WORKDIR/dl.err")"
    out=$(sh_ container run --rm --network none localhost/dl-sparse:1 sh -c "$show" 2>&1 | sed 's|  | |')
    check "no server: the sparse files of a directory, content and size" "$(echo "$want" | sed -n 1p) hole
$(echo "$want" | sed -n 2p) dir/data-hole
$(echo "$want" | sed -n 2p) unpacked/dir/data-hole
2097152
67108864" "$out"
    n=0
    for fmt in gnu "posix --sparse-version=0.0" "posix --sparse-version=0.1" "posix --sparse-version=1.0"; do
        n=$((n + 1))
        # shellcheck disable=SC2086
        tar -C "$ctx" --sparse --format=$fmt -cf - Containerfile hole dir sparse.tar \
            | sh_ build -q -t localhost/dl-sparse:t$n - > /dev/null 2> "$WORKDIR/dl.err"
        check "no server: build - with a sparse tar ($fmt)" "0 " "$? $(cat "$WORKDIR/dl.err")"
        check "no server: the sparse files of a tar ($fmt) are the same" "$out" \
            "$(sh_ container run --rm --network none localhost/dl-sparse:t$n sh -c "$show" 2>&1 | sed 's|  | |')"
    done
}

# during a build: the command alone, no process that serves it
@test "no server: Ctrl-C during the RUN and the COPY of a build leaves nothing" {
    stop_daemon
    ctx=$WORKDIR/dl-ctx
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN echo started; sleep 60\n' "$IMAGE" > "$ctx/Slow"
    : > "$WORKDIR/dl-slow.out"
    start_in_group build --no-cache -f "$ctx/Slow" "$ctx" > "$WORKDIR/dl-slow.out" 2>&1
    wait_for_line "$WORKDIR/dl-slow.out" started
    check "no server: the RUN of a build runs" 0 $?
    check "no server: no helper process during the build" 0 "$(helpers_of_store "$BG")"
    # Ctrl-C: the build stops, its container, its mounts, its lease go
    kill -INT -- "-$BG"
    wait "$BG"
    check "no server: Ctrl-C ends the build with the status of SIGINT" 130 $?
    check "no server: Ctrl-C leaves no container of the build" "" \
        "$(sh_ ps -a -q --filter label=io.velarx.build=1 2>&1)"
    run_root=$(sh_ info --format '{{.Store.RunRoot}}')
    graph_root=$(sh_ info --format '{{.Store.GraphRoot}}')
    wait_for 30 monitors_gone "$run_root"
    check "no server: Ctrl-C leaves no monitor" "" "$(e2e_monitors "$run_root")"
    check "no server: Ctrl-C leaves no mount of a container" 0 "$(mounts_of_bundles)"
    check "no server: Ctrl-C leaves nothing of the build" "" \
        "$(ls "$graph_root/build/contexts" 2> /dev/null; ls -d "$graph_root"/build/build-* 2> /dev/null)"
    out=$(sh_ system check 2>&1)
    check "no server: Ctrl-C leaves no lease (system check)" "0 " "$? $out"

    # Ctrl-C during a COPY (the worker copying a big file) ends the build at
    # once and leaves nothing, as during a RUN
    truncate -s 1G "$ctx/big"
    printf 'FROM %s\nCOPY big /big\nCOPY big /big2\n' "$IMAGE" > "$ctx/Copy"
    : > "$WORKDIR/dl-copy.out"
    start_in_group build --no-cache -f "$ctx/Copy" "$ctx" > "$WORKDIR/dl-copy.out" 2>&1
    wait_for_line "$WORKDIR/dl-copy.out" "COPY big /big"
    check "no server: the COPY of a build runs" 0 $?
    kill -INT -- "-$BG"
    wait "$BG"
    check "no server: Ctrl-C during a COPY ends the build with the status of SIGINT" 130 $?
    rm -f "$ctx/big"
    check "no server: Ctrl-C during a COPY leaves no container" "" \
        "$(sh_ ps -a -q --filter label=io.velarx.build=1 2>&1)"
    check "no server: Ctrl-C during a COPY leaves no monitor" "" "$(e2e_monitors "$run_root")"
    check "no server: Ctrl-C during a COPY leaves nothing of the build" "" \
        "$(ls "$graph_root/build/contexts" 2> /dev/null; ls -d "$graph_root"/build/build-* 2> /dev/null)"
    out=$(sh_ system check 2>&1)
    check "no server: Ctrl-C during a COPY leaves no lease (system check)" "0 " "$? $out"

}

# Ctrl-C during `stop a b`: both are told to stop together (as podman's) and
# the command ends with the status of SIGINT
@test "no server: Ctrl-C during stop a b" {
    stop_daemon
    for c in dls1 dls2; do
        sh_ container run -d --name $c --log-driver k8s-file --network none "$IMAGE" \
            sh -c 'trap "echo got-term" TERM; echo ready; while :; do sleep 1000 & wait $!; done' > /dev/null
    done
    : > "$WORKDIR/dl-term.out"
    "$SH" container logs -f dls1 > "$WORKDIR/dl-term.out" 2>&1 3>&- &
    follower=$!
    wait_for_line "$WORKDIR/dl-term.out" ready
    start_in_group container stop -t 20 dls1 dls2 > /dev/null 2>&1
    wait_for_line "$WORKDIR/dl-term.out" got-term
    check "no server: stop a b, the first is told to stop" 0 $?
    for i in 1 2 3 4 5 6 7 8; do kill -INT -- "-$BG" 2> /dev/null; done
    wait "$BG"
    check "no server: Ctrl-C during stop a b ends the command with the status of SIGINT" 130 $?
    # (the containers of one stop are stopped together: b was told as well)
    check_match "no server: and b was told to stop as well" "got-term" "$(sh_ container logs dls2 2>&1)"
    kill "$follower" 2> /dev/null
    wait "$follower" 2> /dev/null
    sh_ container rm -f -t 0 dls1 dls2 > /dev/null 2>&1

}

@test "no server: two builds at once, image push" {
    stop_daemon
    ctx=$WORKDIR/dl-ctx
    printf 'FROM %s\nRUN echo one > /one\n' "$IMAGE" > "$ctx/One"
    printf 'FROM %s\nRUN echo two > /two\n' "$IMAGE" > "$ctx/Two"
    "$SH" build -q --no-cache -t localhost/dl-one:1 -f "$ctx/One" "$ctx" > "$WORKDIR/dl-one.out" 2>&1 3>&- &
    one=$!
    "$SH" build -q --no-cache -t localhost/dl-two:1 -f "$ctx/Two" "$ctx" > "$WORKDIR/dl-two.out" 2>&1 3>&- &
    two=$!
    wait "$one"; st1=$?
    wait "$two"; st2=$?
    if [ "$st1 $st2" != "0 0" ]; then
        cat "$WORKDIR/dl-one.out" "$WORKDIR/dl-two.out" >&2
    fi
    check "no server: two builds at once" "0 0" "$st1 $st2"
    check "and both images are there" "one two" \
        "$(sh_ run --rm --network none localhost/dl-one:1 cat /one 2>&1) $(sh_ run --rm --network none localhost/dl-two:1 cat /two 2>&1)"
    for i in dl-stdin:1 dl-stdin:2 dl-stdin:3 dl-one:1 dl-two:1; do sh_ image remove localhost/$i > /dev/null 2>&1; done

    out=$(sh_ image push --tls-verify=false localhost/dl-build:1 "$E2E_REGISTRY/e2e/dl-build:1" 2>&1)
    check "no server: image push" 0 $?
    check_match "no server: push says the digest" "Digest: sha256:[0-9a-f]{64}" "$out"
    check "no server: the registry has it" 200 "$(curl -s -o /dev/null -w '%{http_code}' \
        -H 'Accept: application/vnd.oci.image.manifest.v1+json' "http://$E2E_REGISTRY/v2/e2e/dl-build/manifests/1")"
    sh_ push -q --tls-verify=false localhost/dl-build:1 "$E2E_REGISTRY/e2e/dl-build:2" > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: push -q" 0 $?
    check "no server: push -q shows no progress" "" "$(cat "$WORKDIR/dl.err")"

}

@test "no server: container commit and image commit, system check" {
    stop_daemon
    sh_ container run -d --name dlc --network none "$IMAGE" sleep 100 > /dev/null
    sh_ container exec dlc sh -c 'echo committed > /committed' > /dev/null
    # a sparse file of 256 MiB: its holes stay holes in the image
    sh_ container exec dlc sh -c 'truncate -s 256M /sparse && printf end | dd of=/sparse bs=1 seek=268435453 conv=notrunc 2> /dev/null' > /dev/null
    sh_ container exec -d dlc sleep 997
    check_match "no server: exec -d goes on after the command returned" "sleep 997" \
        "$(sh_ container exec dlc ps -o args 2>&1)"
    sh_ container commit dlc localhost/dl-commit:1 > "$WORKDIR/dl.out" 2>&1
    check "no server: container commit" 0 $?
    sh_ image commit dlc localhost/dl-commit:2 > /dev/null 2>&1
    check "no server: image commit" 0 $?
    check "no server: the committed image has the file" "committed" \
        "$(sh_ container run --rm --network none localhost/dl-commit:1 cat /committed 2>&1)"
    # (the kernel's overlay guesses the blocks of a file of a data-only
    # layer from its size until the file is opened)
    out=$(sh_ container run --rm --network none localhost/dl-commit:1 sh -c 'tail -c 3 /sparse > /dev/null; stat -c "%s %b" /sparse; tail -c 3 /sparse' 2>&1)
    check_match "no server: a committed sparse file has its size and its end, and not the blocks of its size" \
        "^268435456 [0-9]{1,4}"$'\n'"end$" "$out"
    sh_ container commit -q --squash dlc localhost/dl-commit:sq > /dev/null 2> "$WORKDIR/dl.err"
    check "no server: commit --squash" "0 " "$? $(cat "$WORKDIR/dl.err")"
    check "no server: commit --squash, one layer with the content" "1 committed" \
        "$(sh_ image inspect --format '{{len .RootFS.Layers}}' localhost/dl-commit:sq) $(sh_ container run --rm --network none localhost/dl-commit:sq cat /committed 2>&1)"
    sh_ container rm -t 0 -f dlc > /dev/null
    out=$(sh_ system check 2>&1)
    check "no server: system check" "0 " "$? $out"
    check "no server: no helper process is left after them" 0 "$(helpers_of_store)"

}

@test "no server: save and load through pipes, streams that are not tar archives" {
    stop_daemon
    graph_root=$(sh_ info --format '{{.Store.GraphRoot}}')
    # the archives through pipes: what reads them may go
    sh_ save "$IMAGE" 2> /dev/null | head -c 10 > /dev/null
    check "no server: save to a pipe closed early ends as SIGPIPE" 141 "${PIPESTATUS[0]}"
    sh_ save -q "$IMAGE" | sh_ load -q > /dev/null 2>&1
    check "no server: save | load" "0 0" "${PIPESTATUS[0]} ${PIPESTATUS[1]}"

    # a stream that is not a tar archive is refused at its first block,
    # not staged until the disk is full
    out=$(head -c 300M /dev/zero | sh_ load 2>&1)
    check "no server: load of zeros fails" 125 $?
    check_match "and says it is not a tar archive" "not a tar archive" "$out"
    out=$(head -c 300M /dev/zero | sh_ image import - localhost/dl-zeros:1 2>&1)
    check "no server: import of zeros fails" 125 $?
    check_match "and says so" "not a tar archive" "$out"
    out=$(head -c 300M /dev/zero | gzip -1 | sh_ load 2>&1)
    check "no server: load of gzipped zeros fails" 125 $?
    check "no server: nothing of them is staged" "" "$(find "$graph_root/staging" -type f -size +64k 2> /dev/null)"

}

@test "no server: pause, the systemd scopes of the containers" {
    stop_daemon
    # pause: a container with a scope of its own, else said
    sh_ run -d --name dlp --network none "$IMAGE" sleep 100 > /dev/null
    out=$(sh_ pause dlp 2>&1)
    st=$?
    bus=$(manager_bus)
    if test -S "${bus%%,*}"; then
        check "no server: pause, the container in a systemd scope" 0 "$st"
        sh_ unpause dlp > /dev/null 2>&1
    else
        check "no server: pause with no cgroup is refused" 125 "$st"
        check_match "and says why" "no cgroup of its own" "$out"
        out=$(sh_ create --memory 64m --network none "$IMAGE" true 2>&1)
        check "no server: limits with no cgroup are refused" 125 $?
        check_match "and say why" "no cgroup of its own" "$out"
    fi
    sh_ rm -t 0 -f dlp > /dev/null

    # the table of services/cgroups_mode.rs, with a systemd manager:
    # in the default mode EVERY container is in a scope of the manager,
    # velarx-<id>.scope, made by the command at its beginning, its monitor
    # in `monitor` below it and the container in `container`, with or
    # without limits; --cgroups=disabled touches no cgroup and asks no
    # manager; no-conmon leaves the monitor where it is.  Stopping the scope
    # of the caller takes neither the container nor its monitor with it.
    if test -S "${bus%%,*}"; then
        sctl=(systemctl)
        sdrun=(systemd-run --scope --quiet)
        if test "$(id -u)" != 0; then
            sctl=(systemctl --user)
            sdrun=(systemd-run --user --scope --quiet)
            export DBUS_SESSION_BUS_ADDRESS=unix:path=${bus%%,*}
        fi
        caller=velarx-e2e-caller-$$
        "${sdrun[@]}" --unit="$caller" "$SH" \
            run -d --name dlm --network none "$IMAGE" sleep 100 > /dev/null 2>&1
        id=$(sh_ container inspect --format '{{.Id}}' dlm 2> /dev/null)
        mon=$(monitor_of dlm)
        cpid=$(sh_ container inspect --format '{{.State.Pid}}' dlm 2> /dev/null)
        check "no server: a container with no limits has a scope unit" active \
            "$("${sctl[@]}" show -P ActiveState "velarx-$id.scope" 2> /dev/null)"
        check_match "no server: the container is in it" \
            "/velarx-$id.scope/container$" "$(cat "/proc/${cpid:-0}/cgroup" 2> /dev/null)"
        check_match "no server: and its monitor" \
            "/velarx-$id.scope/monitor$" "$(cat "/proc/${mon:-0}/cgroup" 2> /dev/null)"
        # (the container's init and the monitor: the holder the scope was
        # made around is gone)
        scopecg=$("${sctl[@]}" show -P ControlGroup "velarx-$id.scope" 2> /dev/null)
        check "no server: only the monitor and the container are in the scope" 2 \
            "$(for p in $(find "/sys/fs/cgroup$scopecg" -name cgroup.procs -exec cat {} + 2> /dev/null); do
                tr '\0' ' ' < "/proc/$p/cmdline" 2> /dev/null | grep -v ' cleanup \| image server ' ; done | wc -l)"
        # (a rootless engine's image server serves the root: it is in the
        # scope of the container too, and root's kernel mount has none)
        check "no server: the image server of a rootless root is in the scope" "$(test "$(id -u)" = 0 && echo 0 || echo 1)" \
            "$(for p in $(find "/sys/fs/cgroup$scopecg" -name cgroup.procs -exec cat {} + 2> /dev/null); do
                tr '\0' ' ' < "/proc/$p/cmdline" 2> /dev/null | grep ' image server ' ; done | wc -l)"
        cgdir=/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/${mon:-0}/cgroup" 2> /dev/null | sed 's|/monitor$||')
        # a start asks the manager once, for the scope; --cgroups=disabled asks
        # nothing and makes no cgroup (the connections and the directories of
        # an strace); a limit changes the way, not the scope
        for mode in "enabled:1" "disabled:0" "enabled --memory=64m:1"; do
            : > "$WORKDIR/dl-trace"
            VELARX_TRACE_FILE=$WORKDIR/dl-trace "${sdrun[@]}" "$SH" \
                run --rm --cgroups=${mode%:*} --network none "$IMAGE" true > /dev/null 2>&1
            check "no server: --cgroups=${mode%:*}, scope requests" "${mode##*:}" \
                "$(grep -c ' scope requested$' "$WORKDIR/dl-trace")"
        done
        if command -v strace > /dev/null; then
            rm -f "$WORKDIR"/dl-strace*
            strace -f -o "$WORKDIR/dl-strace" -e trace=connect,mkdir,mkdirat,openat,execve \
                "$SH" run --rm --cgroups=disabled --network none \
                "$IMAGE" true > /dev/null 2>&1
            check "no server: --cgroups=disabled opens no cgroup file" 0 \
                "$(grep -c '/sys/fs/cgroup/[^"]*\(cgroup\.\|velarx\)' "$WORKDIR/dl-strace")"
            check "no server: and no connection to a manager" 0 \
                "$(grep -c 'connect(.*\(systemd/private\|/bus\|system_bus_socket\)' "$WORKDIR/dl-strace")"
            # (what the monitor does when the container ends, in its own
            # threads, is in the same trace: it starts no other program; the
            # commands that handle the container afterwards need no cgroup
            # either)
            check "no server: --cgroups=disabled, the monitor records the exit by itself" 0 \
                "$(grep -c 'execve(.*"cleanup"' "$WORKDIR/dl-strace")"
            sh_ create --name dld --cgroups=disabled --network none "$IMAGE" true > /dev/null 2>&1
            rm -f "$WORKDIR"/dl-strace*
            strace -f -o "$WORKDIR/dl-strace" -e trace=connect,mkdir,mkdirat,openat \
                "$SH" inspect dld > /dev/null 2>&1
            strace -f -o "$WORKDIR/dl-strace.rm" -e trace=connect,mkdir,mkdirat,openat \
                "$SH" rm -f dld > /dev/null 2>&1
            check "no server: inspect and rm of a --cgroups=disabled container touch no cgroup" 0 \
                "$(cat "$WORKDIR"/dl-strace* | grep -c '/sys/fs/cgroup/[^"]*\(cgroup\.\|velarx\)')"
            check "no server: and connect to no manager" 0 \
                "$(cat "$WORKDIR"/dl-strace* | grep -c 'connect(.*\(systemd/private\|/bus\|system_bus_socket\)')"
        fi
        "${sctl[@]}" stop "$caller.scope" 2> /dev/null
        check "no server: the container survives the scope of its caller" running "$(state_of dlm)"
        check "no server: and its monitor" 0 "$(kill -0 "${mon:-0}" 2> /dev/null; echo $?)"
        out=$(sh_ pause dlm 2>&1)
        check "no server: pause, the container in its cgroup" 0 $?
        check "no server: its cgroup is frozen" "frozen 1" \
            "$(grep '^frozen' "$cgdir/container/cgroup.events" 2> /dev/null)"
        sh_ unpause dlm > /dev/null 2>&1
        # the controllers a scope had: memory for stats and the OOM counter
        check_match "no server: the memory of the container is accounted" '^[1-9]' \
            "$(cat "$cgdir/container/memory.current" 2> /dev/null)"
        check "no server: and its OOM kills counted" 1 \
            "$(grep -c '^oom_kill ' "$cgdir/container/memory.events" 2> /dev/null)"
        sh_ stats --no-stream dlm > /dev/null 2>&1
        check "no server: stats of a container in its scope" 0 $?
        sh_ rm -t 0 -f dlm > /dev/null 2>&1
        # (the monitor goes after the container, and systemd drops its empty scope)
        no_scope_of () {
            test -z "$("${sctl[@]}" list-units --all --plain --no-legend "velarx-*$1*" 2> /dev/null)"
        }
        wait_for 10 no_scope_of "$id"
        check "no server: the scope and its cgroups are gone after rm" 0 $?
        check "no server: no cgroup is left" 0 "$(test -e "$cgdir"; echo $((1 - $?)))"
        # no-conmon: the container in a scope, the monitor stays with its caller
        sh_ run -d --name dln --cgroups=no-conmon --network none "$IMAGE" sleep 100 > /dev/null 2>&1
        id=$(sh_ container inspect --format '{{.Id}}' dln 2> /dev/null)
        mon=$(monitor_of dln)
        cpid=$(sh_ container inspect --format '{{.State.Pid}}' dln 2> /dev/null)
        check_match "no server: no-conmon, the container in a scope" \
            "/velarx-$id.scope/container$" "$(cat "/proc/${cpid:-0}/cgroup" 2> /dev/null)"
        check "no server: no-conmon, the monitor is not in it" 0 \
            "$(grep -c "velarx-$id" "/proc/${mon:-0}/cgroup" 2> /dev/null)"
        # (the holder of the scope ended only once the container was in it:
        # with the monitor elsewhere the scope would have gone before)
        check "no server: no-conmon, the scope unit holds the container" active \
            "$("${sctl[@]}" show -P ActiveState "velarx-$id.scope" 2> /dev/null)"
        # a start of the existing container asks for its scope again, also
        # while the unit of the last start is being collected
        starts=
        for i in 1 2 3 4 5; do
            sh_ stop -t 0 dln > /dev/null 2>&1
            sh_ start dln > /dev/null 2>&1
            starts="$starts $("${sctl[@]}" show -P ActiveState "velarx-$id.scope" 2> /dev/null)"
        done
        check "no server: stop and start, a scope each time" \
            " active active active active active" "$starts"
        sh_ rm -t 0 -f dln > /dev/null 2>&1
        wait_for 10 no_scope_of "$id"
        check "no server: no-conmon, no scope is left after rm" 0 $?
        check "no server: no-conmon, no cgroup is left" 1 \
            "$(test -e "/sys/fs/cgroup$(dirname "$scopecg")/velarx-$id.scope" && echo 0 || echo 1)"
        # a run that fails before its start (the name is taken) asks for a
        # scope at its beginning: the scope goes with the command, it is not
        # left running empty
        # (the scopes with nothing in them that were not there before: on a
        # host that runs other containers meanwhile, those with processes,
        # in the cgroups below their own, and those that were there are theirs)
        empty_scopes () {
            local u cg
            for u in $("${sctl[@]}" list-units --all --plain --no-legend 'velarx-*.scope' 2> /dev/null | awk '/velarx container/ { print $1 }'); do
                cg=$("${sctl[@]}" show -P ControlGroup "$u" 2> /dev/null)
                grep -qx 'populated 1' "/sys/fs/cgroup$cg/cgroup.events" 2> /dev/null || echo "$u"
            done | sort
        }
        before=$(empty_scopes)
        sh_ create --name dlx --network none "$IMAGE" true > /dev/null 2>&1
        for i in 1 2 3 4 5; do
            sh_ run --rm --name dlx --network none "$IMAGE" true > /dev/null 2>&1
        done
        sh_ rm -t 0 -f dlx > /dev/null 2>&1
        new_empty () { comm -13 <(echo "$before") <(empty_scopes); }
        # (polled: the manager tells nobody that it collected a unit)
        no_new_empty () { [ -z "$(new_empty)" ]; }
        wait_for 10 no_new_empty
        check "no server: a run that fails before its start leaves no scope" "" "$(new_empty)"
        # --no-monitor: the command monitors the container, in its scope
        "$SH" run --no-monitor --name dlnm --network none "$IMAGE" sleep 100 > /dev/null 2>&1 3>&- &
        nm=$!
        running_dlnm () { test "$(state_of dlnm)" = running; }
        wait_for 10 running_dlnm
        id=$(sh_ container inspect --format '{{.Id}}' dlnm 2> /dev/null)
        cpid=$(sh_ container inspect --format '{{.State.Pid}}' dlnm 2> /dev/null)
        check "no server: --no-monitor, the container has a scope" active \
            "$("${sctl[@]}" show -P ActiveState "velarx-$id.scope" 2> /dev/null)"
        check "no server: --no-monitor, the container is in it" "$cpid" \
            "$(cat "/sys/fs/cgroup$(dirname "$scopecg")/velarx-$id.scope/container/cgroup.procs" 2> /dev/null)"
        sh_ rm -t 0 -f dlnm > /dev/null 2>&1
        wait "$nm" 2> /dev/null
        wait_for 10 no_scope_of "$id"
        check "no server: --no-monitor, no scope is left after rm" 0 $?
        # limits: the runtime asks the manager for the scope and applies them
        # there, and the monitor has a scope of its own
        sh_ run -d --name dlq --memory 64m --network none "$IMAGE" sleep 100 > /dev/null 2>&1
        id=$(sh_ container inspect --format '{{.Id}}' dlq 2> /dev/null)
        mon=$(monitor_of dlq)
        cpid=$(sh_ container inspect --format '{{.State.Pid}}' dlq 2> /dev/null)
        check_match "no server: with limits the container is in a scope of the manager" \
            "velarx-$id.scope" "$(cat "/proc/${cpid:-0}/cgroup" 2> /dev/null)"
        check_match "no server: and its monitor in another" \
            "velarx-monitor-$id.scope" "$(cat "/proc/${mon:-0}/cgroup" 2> /dev/null)"
        cg=$(sed -n 's/^0:://p' "/proc/${cpid:-0}/cgroup" 2> /dev/null)
        check "no server: the limit applies" 67108864 "$(cat "/sys/fs/cgroup$cg/memory.max" 2> /dev/null)"
        sh_ rm -t 0 -f dlq > /dev/null 2>&1
        wait_for 10 no_scope_of "$id"
        check "no server: no scope is left after rm with limits" 0 $?
    fi

}

@test "no server: the database is opened cold once, health checks of a container started with no server" {
    stop_daemon
    # a run opens the store's database cold (rebuilding the index of its log
    # from the whole -wal file) once, rootless too, where the join of the
    # namespaces reads it first
    : > "$WORKDIR/dl-trace"
    VELARX_TRACE_FILE=$WORKDIR/dl-trace "$SH" \
        run --rm --cgroups=disabled --network none "$IMAGE" true > /dev/null 2>&1
    # (the monitor records by itself, with a connection of its own: the
    # trace counts the engine's opens)
    check "no server: a run opens the database cold once" 1 \
        "$(awk '$3 == "db" && $4 == "open" && $5 == "cold" { n[$1]++ } END { m = 0; for (p in n) if (n[p] > m) m = n[p]; print m }' "$WORKDIR/dl-trace")"

    # health checks of a container started with no server: its monitor
    # runs them and says what they found
    sh_ run -d --name dlh --network none --health-cmd true --health-interval 1s "$IMAGE" sleep 100 > /dev/null
    out=$(timeout 60 "$SH" container wait --condition healthy dlh 2>&1)
    check "no server: wait --condition healthy follows the monitor of another process" "-1 0" "$out $?"
    check_match "no server: the health of a container started with no server" "dlh .*healthy" \
        "$(sh_ healthcheck ls 2>&1)"
    sh_ rm -t 0 -f dlh > /dev/null
    for i in dl-build:1 dl-build:2 dl-commit:1 dl-commit:2; do sh_ image remove localhost/$i > /dev/null 2>&1; done

}

no_monitors () {
    test "$(e2e_monitors "$WORKDIR" | wc -l)" = 0
}

# no monitor runs for the run root $1
monitors_gone () {
    test -z "$(e2e_monitors "$1")"
}

# the monitor looks after its container and records
# what happens to it: nothing else runs, the command that started it is gone
@test "no server: the monitor records the exit, the restarts and the health, and removes an --rm container" {
    stop_daemon
    # a foreground --rm run killed (-9) before its container exits: the
    # monitor removes the container and records its exit, once
    "$SH" container run --rm --name lk --network none --cgroups=disabled "$IMAGE" sleep 3 \
        3>&- > /dev/null 2>&1 &
    p=$!
    wait_for 15 state_is lk running
    kill -9 "$p"
    wait "$p" 2> /dev/null
    wait_removed lk
    check "a killed run --rm: removed by its monitor, no command, no server" no \
        "$(sh_ container exists lk > /dev/null 2>&1 && echo yes || echo no)"
    out=$(sh_ events --stream=false --since 1m --filter container=lk 2>&1)
    check "a killed run --rm: one died event" 1 "$(grep -c ' died ' <<< "$out")"
    check "a killed run --rm: one remove event" 1 "$(grep -c ' remove ' <<< "$out")"
    wait_for 30 no_monitors
    check "a killed run --rm: no monitor is left" 0 "$(e2e_monitors "$WORKDIR" | wc -l)"

    # a detached container with a restart policy: the monitor restarts it
    # and records every run, and the last exit
    sh_ container run -d --name lrp --restart on-failure:2 --network none --cgroups=disabled \
        "$IMAGE" sh -c 'sleep 0.3; exit 3' > /dev/null
    wait_restarts lrp 2 60
    wait_for 30 no_monitors
    check "restart policy, no server: the monitor restarted it twice" 2 "$(field restart_count lrp)"
    check "restart policy, no server: the last exit" 3 "$(field exit_code lrp)"
    out=$(sh_ events --stream=false --since 1m --filter container=lrp 2>&1)
    check "restart policy, no server: a died event for each run" 3 "$(grep -c ' died ' <<< "$out")"
    sh_ rm -t 0 -f lrp > /dev/null

    # health: a change of the status is an event, recorded by the monitor
    sh_ container run -d --name lhe --network none --cgroups=disabled --health-cmd true \
        --health-interval 1s "$IMAGE" sleep 100 > /dev/null
    wait_health lhe healthy 30
    check "health, no server: healthy" 0 $?
    out=$(sh_ events --stream=false --since 1m --filter container=lhe --filter event=health_status 2>&1)
    check_match "health, no server: a health_status event" "health_status" "$out"
    sh_ rm -t 0 -f lhe > /dev/null

    # a container killed by its user: stopped, once
    sh_ container run -d --name lkl --network none --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    sh_ container kill lkl > /dev/null
    wait_state lkl exited 30
    check "kill, no server: the exit code" 137 "$(field exit_code lkl)"
    sh_ rm -t 0 -f lkl > /dev/null
}

# run --rm returns with the container gone, as podman's: its row, its
# anonymous volumes (its files a moment later); a detached one goes
# asynchronously but no command sees it half removed
@test "no server: run --rm returns with the container, its volumes and its files gone" {
    stop_daemon
    local vols bundles
    vols=$(sh_ volume ls -q | wc -l)
    bundles=$(ls "$XDG_DATA_HOME/velarx/bundles" 2> /dev/null | wc -l)
    for i in 1 2 3; do
        sh_ container run --rm --network none -v /data "$IMAGE" true > /dev/null
        check "run --rm -v /data: the anonymous volume is gone when run returns ($i)" \
            "$vols" "$(sh_ volume ls -q | wc -l)"
    done
    # (its files, which no command shows, go when its monitor has released
    # its mounts, a moment later)
    bundles_back () { test "$(ls "$XDG_DATA_HOME/velarx/bundles" 2> /dev/null | wc -l)" = "$bundles"; }
    wait_for 10 bundles_back
    check "run --rm: its files go too" 0 $?
    sh_ container run --rm --network none --name rmc "$IMAGE" sh -c 'exit 3' > /dev/null
    check "run --rm: the exit code" 3 $?
    check "run --rm: no container when run returns" 1 "$(sh_ container exists rmc; echo $?)"

    # detached: what ps -a lists can be inspected (or is gone: never a row
    # whose files went), rm of it either removes it or finds nothing
    local bad=0 id
    for i in 1 2 3 4 5 6; do
        sh_ container run -d --rm --network none --name "drm$i" -v /data "$IMAGE" sleep 0.$i > /dev/null
    done
    for i in $(seq 40); do
        for id in $(sh_ ps -a -q --filter name=drm); do
            out=$(sh_ container inspect -f '{{.State.Status}}' "$id" 2>&1) || {
                grep -q 'no such' <<< "$out" || { echo "# inspect $id: $out" >&3; bad=$((bad + 1)); }
            }
        done
        # (the inspections race with the removals on purpose)
        sleep 0.05
    done
    out=$(sh_ container rm -t 0 -f drm6 2>&1) || grep -q 'no such' <<< "$out" || bad=$((bad + 1))
    wait_removed drm5
    check "run -d --rm: never seen half removed" 0 "$bad"
    wait_removed drm6
    check "run -d --rm: its anonymous volumes go with it" "$vols" "$(sh_ volume ls -q | wc -l)"
}

# a monitor killed with -9 records nothing: the next command that looks at
# its container (ps, inspect, wait) does what the monitor would have done
@test "no server: ps, inspect and wait settle a container whose monitor was killed" {
    stop_daemon
    local cmd id mon
    # killed_monitor NAME [OPTIONS]: a container that ends once its monitor
    # is gone (when the test writes to the FIFO it reads)
    killed_monitor () {
        local name=$1
        shift
        rm -f "$WORKDIR/km/go"
        mkdir -p "$WORKDIR/km"
        mkfifo "$WORKDIR/km/go"
        id=$(sh_ container run -d "$@" --network none --name "$name" -v "$WORKDIR/km:/km:z" "$IMAGE" sh -c 'read l < /km/go')
        cpid=$(inspect_of "$name" pid)
        check_match "$name runs" "^[1-9][0-9]*$" "$cpid"
        mon=$(cat "$XDG_RUNTIME_DIR/velarx/mon/${id:0:12}/monitor.pid")
        kill -9 "$mon"
        e2e_wait_exit "$mon" || e2e_die "the killed monitor of $name is still there"
        timeout 30 sh -c 'echo end > "$1"' sh "$WORKDIR/km/go" || e2e_die "$name does not read its FIFO"
        e2e_wait_exit "$cpid" || e2e_die "$name did not end"
    }
    for cmd in "ps -a -q" "container inspect kmr" "wait kmr"; do
        killed_monitor kmr --rm
        sh_ $cmd > /dev/null 2>&1
        check "a killed monitor of an --rm container: $cmd removes it" 1 \
            "$(sh_ container exists kmr; echo $?)"
        sh_ rm -t 0 -f kmr > /dev/null 2>&1
    done
    killed_monitor kms
    check "a killed monitor: ps -a says it exited" 1 \
        "$(sh_ ps -a --filter name=kms --format '{{.Status}}' 2> /dev/null | grep -c Exited)"
    sh_ container start kms > /dev/null 2>&1
    check "and it can be started again" running "$(state_of kms)"
    sh_ rm -f -t 0 kms > /dev/null
}

# two starts of one container at once: the second waits for the first and
# finds it running
@test "no server: concurrent starts of one container are serialised" {
    stop_daemon
    sh_ container create --name lcs --network none --cgroups=disabled "$IMAGE" sleep 100 > /dev/null
    for i in 1 2 3 4; do
        "$SH" container start lcs > "$WORKDIR/lcs.$i" 2>&1 3>&- &
        eval "p$i=$!"
    done
    for i in 1 2 3 4; do eval "wait \$p$i"; done
    check "concurrent starts: one runs" running "$(state_of lcs)"
    check "concurrent starts: one monitor" 1 "$(e2e_monitors "$WORKDIR" | wc -l)"
    check "concurrent starts: nobody fails" 0 "$(cat "$WORKDIR"/lcs.? | grep -c -i 'error')"
    sh_ rm -t 0 -f lcs > /dev/null
}

# A command with no server asks the engine of its process through the client
# of the engine service (one path for the commands, with or without a
# server), run and start too: the trace points of the client name each call.
@test "no server: run and start ask their engine through the client" {
    stop_daemon
    local trace=$WORKDIR/ip-trace out rc
    calls () {
        grep -o ' client request [A-Za-z]*$' "$trace" 2> /dev/null | awk '{print $3}' | sort -u | tr '\n' ' '
    }
    rm -f "$trace"
    out=$(VELARX_TRACE_FILE=$trace \
        sh_ container run --rm --name iprun --network none "$IMAGE" sh -c 'echo ran; exit 7')
    rc=$?
    check "run: its output and exit code" "ran 7" "$out $rc"
    check_match "run: the container is made through the client" "(^| )ContainerCreate " "$(calls)"
    check_match "run: and started through it" "(^| )ContainerStart[A-Za-z]* " "$(calls)"
    check "run --rm: the container is gone when run returns" 1 "$(sh_ container exists iprun; echo $?)"
    sh_ container create --name ipstart --network none "$IMAGE" true > /dev/null
    rm -f "$trace"
    VELARX_TRACE_FILE=$trace sh_ container start ipstart > /dev/null
    check "start: through the client" 0 $?
    check_match "start: the container is started through the client" "(^| )ContainerStart " "$(calls)"
    sh_ container rm -f -t 0 ipstart > /dev/null
}

# The service of the command takes a socket pair for each connection: no
# socket a name leads to (none in the file system, which a command that is
# killed would leave behind, and none in the abstract namespace, which any
# process of the network namespace can connect to, another user or a container
# of the host network too).
@test "no server: the service of the command has no socket a name leads to, and leaves nothing when the command is killed" {
    stop_daemon
    local tmp=$WORKDIR/ip-tmp pid
    mkdir -p "$tmp"
    TMPDIR=$tmp sh_ container run --rm --network none "$IMAGE" true
    check "a command that ends" "" "$(ls -A "$tmp")"
    TMPDIR=$tmp sh_ container run --name ipkill --network none "$IMAGE" sleep 100 > /dev/null 2>&1 3>&- &
    pid=$!
    ipkill_runs () { [ "$(state_of ipkill)" = running ]; }
    wait_for 30 ipkill_runs || e2e_die "the container does not run"
    # (the process of the command: the background shell or its child)
    local cmd p ino listening=
    for p in $pid $(cat /proc/$pid/task/*/children 2> /dev/null); do
        [ "$(cat /proc/$p/comm 2> /dev/null)" = velarx ] && cmd=$p
    done
    [ -n "$cmd" ] || e2e_die "cannot find the process of the command"
    for ino in $(ls -l /proc/$cmd/fd 2> /dev/null | sed -n 's/.*socket:\[\([0-9]*\)\]$/\1/p'); do
        listening+=$(awk -v i="$ino" '$7 == i && $4 == "00010000" { print " " $7 ($8 == "" ? "" : ":" $8) }' /proc/net/unix)
    done
    check "while it runs, the command listens on no socket" "" "$listening"
    kill -KILL "$pid"
    wait "$pid" 2> /dev/null
    check "a command that is killed" "" "$(ls -A "$tmp")"
    sh_ container rm -f -t 0 ipkill > /dev/null
}

# with a server, a command uses it (it says what happened as it
# happens): what a command does is in the events the server follows
@test "with a server, a command runs in its own engine and the server finds what the commands did" {
    stop_daemon
    start_daemon
    # (the stream is live once it shows the kept event of a marker made before)
    sh_ volume create dl-mark > /dev/null
    timeout 20 "$SH" events --since 5m --filter type=volume > "$WORKDIR/dl-events.out" 2>&1 3>&- &
    ev=$!
    e2e_wait_line "$WORKDIR/dl-events.out" "volume create dl-mark" 30 || e2e_die "the events stream does not start"
    sh_ volume rm dl-mark > /dev/null
    sh_ volume create dl-pref > /dev/null
    wait_for_line "$WORKDIR/dl-events.out" "volume create dl-pref"
    check "with a server, events follows what a command did" 0 $?
    kill "$ev" 2> /dev/null; wait "$ev" 2> /dev/null
    # the command line never connects to the server it did not name
    if command -v strace > /dev/null; then
        rm -f "$WORKDIR"/dl-cstrace*
        st () { strace -f -b execve -o "$WORKDIR/dl-cstrace.$1" -e trace=connect "$SH" "${@:2}"; }
        st 1 container run --rm --network none "$IMAGE" true 3>&- > /dev/null 2>&1
        st 2 container run -d --name dl-nc --restart on-failure:1 --network none \
            "$IMAGE" sh -c 'sleep 1; exit 3' 3>&- > /dev/null 2>&1
        st 3 container wait --condition running dl-nc 3>&- > /dev/null 2>&1
        check "run, run -d and wait with a server: no connection to it" 0 \
            "$(cat "$WORKDIR"/dl-cstrace* | grep -c "connect(.*$(basename "$ESOCK")")"
        # the monitor applies the restart policy of a detached run
        wait_restarts dl-nc 1
        check "the monitor applies the restart policy of a detached run" 0 $?
        sh_ container rm -t 0 -f dl-nc > /dev/null 2>&1
    fi
    # an --rm container stopped by a command: its monitor records the exit
    # and removes it, once, and the command says nothing else
    sh_ container run -d --rm --name dlrs --network none "$IMAGE" sleep 300 > /dev/null
    out=$(sh_ container stop -t 0 dlrs 2>&1)
    check "stop of an --rm container says nothing else" dlrs "$out"
    timeout 30 "$SH" container wait --condition removed dlrs > /dev/null 2>&1
    out=$(sh_ events --stream=false --since 1m --filter container=dlrs 2>&1)
    check "one died event" 1 "$(grep -c ' died ' <<< "$out")"
    check "one remove event" 1 "$(grep -c ' remove ' <<< "$out")"
    check "and it is gone" no "$(sh_ container exists dlrs && echo yes || echo no)"
    sh_ volume remove dl-pref > /dev/null
    check "VELARX_SOCKET of no server is an error, not the engine" 125 \
        "$(VELARX_SOCKET=$WORKDIR/none.sock "$SH" image list > /dev/null 2>&1; echo $?)"

    # the server finds what the commands did
    check "the server sees the container" exited "$(state_of dl1)"
    sh_ container rm dl1 > /dev/null
    sh_ volume inspect dlv > /dev/null 2>&1
    check "the server sees the volume" 0 $?
    sh_ volume remove dlv > /dev/null
    check "the server removes the volume" "" "$(sh_ volume list | awk '$2 == "dlv" || $1 == "dlv"')"
}

# velarx-client: a client of the server that opens no store; with
# no server it fails: it never runs the engine itself.
@test "velarx-client" {
    fresh=$WORKDIR/fresh
    mkdir -p "$fresh"
    printf '[engine]\nsocket = "%s"\n[server]\nstate_dir = "%s/state"\nroot_dir = "%s/root"\n[storage]\nroot = "%s/storage"\n' \
        "$ESOCK" "$fresh" "$fresh" "$fresh" > "$fresh/config.toml"
    out=$("$BIN/velarx-client" --config "$fresh/config.toml" image list --format '{{.Repository}}:{{.Tag}}' 2>&1)
    check_match "client: the images of the server" "${IMAGE#*/}" "$out"
    # (a prune filter without a value is refused through the engine as
    # without one: it would select everything)
    for kind in container volume network; do
        out=$("$BIN/velarx-client" --config "$fresh/config.toml" $kind prune -f --filter label 2>&1)
        check "client: $kind prune --filter label" "Error: filter input must be in the form of filter=value: label is invalid 125" "$out $?"
    done
    check "client: no store of its own" no "$(test -e "$fresh/storage" -o -e "$fresh/state" && echo yes || echo no)"
    check_match "client: --version" "^velarx " "$("$BIN/velarx-client" --version)"
    # (an exec without a terminal or input: the engine's ExecStart, whose
    # streams come on its channel)
    "$BIN/velarx-client" --config "$fresh/config.toml" run -d --name vc-exec --network none "$IMAGE" sleep 300 > /dev/null 2>&1
    out=$("$BIN/velarx-client" --config "$fresh/config.toml" container exec vc-exec sh -c 'echo out; echo err >&2; exit 3' 2> "$WORKDIR/exec.err")
    st=$?
    check "client: exec, its output, its errors, its status" "out err 3" "$out $(cat "$WORKDIR/exec.err") $st"
    "$BIN/velarx-client" --config "$fresh/config.toml" container rm -f -t 0 vc-exec > /dev/null 2>&1

    stop_daemon
    out=$("$BIN/velarx-client" --config "$CONFIG" image list --format '{{.Repository}}:{{.Tag}}' 2>&1)
    st=$?
    check "client, no server: fails" 125 "$st"
    check_match "client, no server: says why" "cannot connect to the engine service" "$out"
    out=$("$BIN/velarx-client" --config "$CONFIG" run --rm --network none "$IMAGE" true 2>&1)
    check "client, no server: run fails" 125 "$?"
    check "client, no server: runs nothing" 0 "$(grep -c "${IMAGE#*/}" <<< "$out")"
    start_daemon
}
