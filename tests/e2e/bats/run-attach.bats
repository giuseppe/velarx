# SPDX-License-Identifier: Apache-2.0
# End to end tests of the terminal, attach and exec of the containers (detach
# keys, resize, signals proxied to the container, many clients, exec), through
# a daemon of its own.  Run it as an ordinary user for the rootless daemon, or
# as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

@test "run -it and run -t have a terminal" {
    command -v python3 > /dev/null || skip "python3 missing"

    out=$($PTY_RUN --expect '# ' --input 'tty\r' --input 'exit 4\r' -- "$SH" container run -it --rm --network none "$IMAGE" sh)
    check "run -it exit code" 4 $?
    check_match "run -it has a terminal" "/dev/pts/[0-9]" "$out"

    out=$($PTY_RUN -- "$SH" container run -t --rm --network none "$IMAGE" sh -c 'test -t 1 && echo is-a-tty')
    check_match "run -t" "is-a-tty" "$out"
}

@test "attach: detach keys, exec -it detach, start -ai, a partial detach sequence, the exit code" {
    sh_ container run -dit --name at --network none "$IMAGE" sh > /dev/null
    out=$($PTY_RUN --input 'echo attached\r' --input '\x10\x11' -- "$SH" container attach at)
    check "attach detach keys exit code" 0 $?
    check_match "attach output" "attached" "$out"
    check "running after detach" running "$(state_of at)"

    out=$($PTY_RUN --input 'echo custom\r' --input '\x01x' -- "$SH" container attach --detach-keys ctrl-a,x at)
    check "attach with other detach keys" 0 $?
    check_match "custom detach keys output" "custom" "$out"
    check "running after the second detach" running "$(state_of at)"

    # the default of the configuration, bad keys, exec and start -a
    { cat "$CONFIG"; printf '[containers]\ndetach_keys = "ctrl-b,y"\n'; } > "$WORKDIR/dk.toml"
    out=$($PTY_RUN --input 'echo conf\r' --input '\x10\x11' --input '\x02y' -- "$SH" --config "$WORKDIR/dk.toml" container attach at)
    check "attach with the detach keys of the configuration" 0 $?
    check "running after the third detach" running "$(state_of at)"
    "$SH" container attach --detach-keys ctrl-1 at > "$WORKDIR/dkerr" 2>&1 < /dev/null
    check "bad detach keys are refused" 125 $?
    check_match "and said so" "invalid detach keys" "$(cat "$WORKDIR/dkerr")"
    check "running after the bad keys" running "$(state_of at)"
    for k in default custom; do
        case $k in
        default) keys='\x10\x11' opt= ;;
        custom) keys='\x01x' opt="--detach-keys ctrl-a,x" ;;
        esac
        $PTY_RUN --input "$keys" -- "$SH" container exec -it $opt at sleep 4141 > /dev/null
        check "exec -it detach ($k keys)" 0 $?
        # (no wait: the command of a session is executed before its start returns)
        check "the command goes on after the detach ($k keys)" 1 \
            "$(sh_ container exec at sh -c 'for p in /proc/[0-9]*; do cat $p/cmdline 2> /dev/null | tr "\0" " "; echo; done | grep -c "[4]141"')"
        sh_ container exec at pkill -f 'sleep 4141'
    done
    sh_ container create -it --name sad --network none "$IMAGE" sh > /dev/null
    $PTY_RUN --input 'echo x\r' --input '\x10\x11' -- "$SH" container start -ai sad > /dev/null
    check "start -ai detach" 0 $?
    check "running after start -ai detach" running "$(state_of sad)"
    sh_ container rm -t 0 -f sad > /dev/null

    # A key that starts the sequence but does not end it is typed.
    sh_ container run -dit --name at4 --network none "$IMAGE" cat -v > /dev/null
    out=$($PTY_RUN --input 'a\x10b\r' --input '\x10\x11' -- "$SH" container attach at4)
    check_match "a partial detach sequence is forwarded" 'a\^Pb' "$out"
    sh_ container rm -t 0 -f at4 > /dev/null

    out=$($PTY_RUN --input 'tty; exit 9\r' -- "$SH" container attach at)
    check "attach returns the exit code" 9 $?
    check "stopped by the exit" exited "$(state_of at)"
    sh_ container rm at > /dev/null

}

# The size of the terminal reaches the container, and its changes too.
@test "the size of the terminal and its changes reach the container" {
    sh_ container run -dit --name rs --network none "$IMAGE" sh > /dev/null
    out=$($PTY_RUN --size 21,77 --input 'stty size\r' --resize 33,101 --input 'stty size\r' --input 'exit\r' -- "$SH" container attach rs | tr -d '\r')
    check_match "terminal size at attach" "(^|[^0-9])21 77($|[^0-9])" "$out"
    check_match "terminal resize" "(^|[^0-9])33 101($|[^0-9])" "$out"
    sh_ container rm -t 0 -f rs > /dev/null

}

@test "start -a, attach without a terminal, attach to a created container" {
    sh_ container create --name sa "$IMAGE" sh -c 'echo started-attached; exit 3' > /dev/null
    out=$(sh_ container start -a sa)
    check "start -a exit code" 3 $?
    check "start -a output" "started-attached" "$out"
    sh_ container rm sa > /dev/null

    # no terminal: stdin and exit code
    sh_ container run -d -i --name at2 --network none "$IMAGE" sh -c 'read x; echo got-$x; exit 2' > /dev/null
    out=$(echo hi | sh_ container attach at2)
    check "attach without a terminal: exit code" 2 $?
    check "attach without a terminal: output" "got-hi" "$out"
    sh_ container rm at2 > /dev/null

    sh_ container create --name at3 "$IMAGE" true > /dev/null
    sh_ container attach at3 > /dev/null 2>&1
    check "attach to a created container fails" 125 $?
    sh_ container rm at3 > /dev/null
}

# sig_proxy_run OUTFILE COMMAND...: COMMAND in the background; once it
# printed "ready" it gets SIGTERM; its output and "client status N".
sig_proxy_run () {
    local out=$1 pid rc
    shift
    "$@" > "$out" 2>&1 &
    pid=$!
    e2e_wait_line "$out" '^ready$' 30 || e2e_die "the command did not print ready within 30 s"
    kill -TERM $pid
    wait $pid
    rc=$?
    cat "$out"
    echo "client status $rc"
}

# ex_present N: until a process of the container ex has N in its command
# line (the loop runs in the container)
ex_present () {
    sh_ container exec ex timeout 30 sh -c "until grep -l '[${1:0:1}]${1:1}' /proc/[0-9]*/cmdline 2> /dev/null | grep -q .; do :; done" ||
        e2e_die "no process $1 in the container within 30 s"
}

# ex_gone N: until no process of the container ex has 'sleep N' in its
# command line (the loop runs in the container)
ex_gone () {
    sh_ container exec ex timeout 30 sh -c "while grep -l '[${1:0:1}]${1:1}' /proc/[0-9]*/cmdline 2> /dev/null | grep -q .; do :; done"
}

# Signals the client gets reach the container (--sig-proxy).
@test "signals of the client reach the container (sig-proxy)" {
    out=$(sig_proxy_run "$WORKDIR/sp.out" "$SH" container run --rm --network none "$IMAGE" \
        sh -c 'trap "echo got-term; exit 33" TERM; echo ready; while :; do sleep 0.1; done' 2>&1 3>&-)
    check_match "SIGTERM reaches the container" "got-term" "$out"
    check_match "and the container decides the status" "client status 33" "$out"

    out=$(sig_proxy_run "$WORKDIR/sp.out" "$SH" container run --rm --sig-proxy=false --network none "$IMAGE" \
        sh -c 'trap "echo got-term; exit 33" TERM; echo ready; sleep 3' 2>&1 3>&-)
    check_match "no signal without --sig-proxy" "client status 143" "$out"
    sh_ container stop -t 1 $(sh_ container list | awk 'NR > 1 { print $1 }') > /dev/null 2>&1
}

# Many clients, a big output, a client that goes away.
@test "many attached clients, a client that goes away" {
    sh_ container run -d --name ac --network none "$IMAGE" sh -c 'sleep 1; i=0; while [ $i -lt 5000 ]; do echo line-$i; i=$((i+1)); done; sleep 1' > /dev/null
    "$SH" container attach --no-stdin ac > "$WORKDIR/ac1.out" 3>&- &
    p1=$!
    "$SH" container attach --no-stdin ac > "$WORKDIR/ac2.out" 3>&- &
    p2=$!
    e2e_reap $p1 "the first attach"
    e2e_reap $p2 "the second attach"
    exp=$(i=0; while [ $i -lt 5000 ]; do echo line-$i; i=$((i+1)); done | md5sum)
    check "the first client gets the output" "$exp" "$(md5sum < "$WORKDIR/ac1.out")"
    check "the second client gets the same" "$exp" "$(md5sum < "$WORKDIR/ac2.out")"
    sh_ container rm ac > /dev/null

    id=$(sh_ container run -d --name ac2 --network none "$IMAGE" sh -c 'sleep 5')
    # The monitor of this container, not one of another that is ending.
    mp=$(pgrep -f "^velarx-monitor: ${id:0:12} " | head -1)
    check "the monitor of the container is found" yes "$([ -n "$mp" ] && echo yes)"
    before=$(ls /proc/"$mp"/fd | wc -l)
    for i in 1 2 3 4 5; do
        "$SH" container attach --no-stdin ac2 > /dev/null 3>&- &
        p=$!
        # (no event says that an attach is connected: the client is killed at some point of its request)
        sleep 0.3
        kill -9 $p
        wait $p 2> /dev/null
    done
    # (the monitor closes the connections of the clients that went: a poll of
    # a count of the kernel, which tells nobody; 3 s at most, the container
    # lives 5)
    for i in $(seq 60); do [ "$(ls /proc/"$mp"/fd | wc -l)" -le "$before" ] && break; sleep 0.05; done
    check "a client that is killed does not affect the container" running "$(state_of ac2)"
    check "no descriptors leaked by the clients that went" "$before" "$(ls /proc/"$mp"/fd | wc -l)"
    sh_ container rm -t 0 -f ac2 > /dev/null
}

@test "exec: user, workdir, environment, -d, a missing executable" {
    sh_ container run -d --name ex --network none "$IMAGE" sleep 1000 > /dev/null

    out=$(sh_ container exec ex echo from-exec 2>&1)
    check "exec" "from-exec" "$out"

    sh_ container exec ex sh -c 'exit 5'
    check "exec exit code" 5 $?

    out=$(sh_ container exec ex sh -c 'echo out; echo err >&2' 2> /dev/null)
    check "exec keeps stderr apart" "out" "$out"

    out=$(sh_ container exec -u nobody -w /tmp -e X=1 ex sh -c 'echo $(id -un) $(pwd) $X' 2>&1)
    check "exec user, workdir, env" "nobody /tmp 1" "$out"

    out=$(sh_ container exec -u 1000:1001 ex id -u 2>&1)
    check "exec numeric user" "1000" "$out"

    sh_ container exec -u nosuchuser ex id > /dev/null 2>&1
    check "exec of an unknown user fails" 125 $?

    # The groups and the home podman gives the user of an exec: its group,
    # `--group-add`, the image's groups of the user unless it names its
    # group (crun's `exec --user` would give none)
    sh_ container run -d --name exg --network none --group-add 10 --group-add 1234 \
        "$IMAGE" sleep 1000 > /dev/null
    out=$(sh_ container exec -u daemon exg sh -c 'echo $(id -G) $HOME' 2>&1)
    check "exec user groups and home" "2 1 4 10 1234 /sbin" "$out"
    out=$(sh_ container exec -u 2:2 exg id -G 2>&1)
    check "exec user:group groups" "2 10 1234" "$out"
    out=$(sh_ container exec --privileged exg grep CapEff /proc/self/status 2>&1)
    check_match "exec --privileged: every capability" "CapEff:.*ff" "$out"
    sh_ container rm -f -t0 exg > /dev/null

    out=$(echo in | sh_ container exec -i ex cat 2>&1)
    check "exec -i" "in" "$out"

    # (a FIFO: the read ends when the detached command has written)
    sh_ container exec ex mkfifo /tmp/marker
    sh_ container exec -d ex sh -c 'echo detached > /tmp/marker'
    out=$(timeout 30 "$SH" container exec ex cat /tmp/marker 2>&1 3>&-)
    check "exec -d" "detached" "$out"

    # --workdir: checked at each start (a copy into the container counts),
    # a file is not a directory, and a refused start leaves it created
    sh_ container create --name wd1 --workdir /i/do/not/exist "$IMAGE" pwd > /dev/null
    check_match "start: a workdir that is not there" "workdir \"/i/do/not/exist\" does not exist" \
        "$(sh_ container start -a wd1 2>&1)"
    mkdir -p "$WORKDIR/wd/i/do/not/exist"
    sh_ container cp "$WORKDIR/wd/i" wd1:/ > /dev/null 2>&1
    check "start: the workdir a cp made" "/i/do/not/exist" "$(sh_ container start -a wd1 2>&1)"
    sh_ container create --name wd2 --workdir /etc/passwd "$IMAGE" true > /dev/null
    check_match "start: a file as workdir" "exists on container .*, but is not a directory" \
        "$(sh_ container start -a wd2 2>&1)"
    check "a refused start leaves it created" created "$(sh_ container inspect --format '{{.State.Status}}' wd2)"
    sh_ run --rm --workdir /etc/passwd "$IMAGE" true > /dev/null 2>&1
    check "run: a file as workdir" 126 $?
    check "run: a workdir on the engine's /dev" /dev/shm "$(sh_ run --rm --workdir /dev/shm "$IMAGE" pwd 2>&1)"
    sh_ container rm -t 0 -f wd1 wd2 > /dev/null 2>&1

    # the detached command goes on after the exec returned
    sh_ container exec -d ex sleep 997
    out=$(sh_ container exec ex ps -o args 2>&1)
    check_match "exec -d: the command is still there" "sleep 997" "$out"

    sh_ container exec ex /does/not/exist > /dev/null 2>&1
    check "exec of a missing executable" 127 $?
    sh_ container rm -f -t 0 ex > /dev/null
}

@test "exec: the timeout, a client that is killed, SIGTERM, a terminal" {
    sh_ container run -d --name ex --network none "$IMAGE" sleep 1000 > /dev/null

    # The timeout kills the command and what it started.
    start=$(now_ms)
    out=$(sh_ container exec --timeout 1 ex sh -c 'sleep 4242 & sleep 4242' 2>&1)
    check "exec --timeout exit code" 124 $?
    elapsed=$(( $(now_ms) - start ))
    # (the error says so)
    check_match "exec --timeout says it timed out" "timed out" "$out"
    test $elapsed -ge 900 -a $elapsed -lt 4000
    check "exec --timeout returns at the deadline (${elapsed}ms)" 0 $?
    out=$(sh_ container exec ex sh -c 'ls /proc | grep -c "^[0-9]"')
    sh_ container exec ex sh -c 'for p in /proc/[0-9]*; do cat $p/cmdline 2> /dev/null | tr "\0" " "; echo; done | grep -c "[4]242"' > "$WORKDIR/left" 2>&1
    check "the process group is gone after a timeout" 0 "$(cat "$WORKDIR/left")"

    # A client that is killed leaves its command running, as podman's
    # (with and without a terminal)
    "$SH" container exec ex sh -c 'sleep 4343' 3>&- &
    p=$!
    ex_present 4343
    kill -9 $p
    wait $p 2> /dev/null
    if command -v python3 > /dev/null; then
        # (killed in its terminal once the command is there)
        python3 -c '
import os, pty, signal, subprocess, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
for _ in range(300):
    out = subprocess.run(sys.argv[1:3] + ["exec", "ex", "sh", "-c", "grep -l \"[4]343\" /proc/[0-9]*/cmdline | wc -l"], capture_output=True, text=True).stdout
    if out.strip() == "2":
        break
    time.sleep(0.1)
os.kill(pid, signal.SIGKILL)
os.waitpid(pid, 0)
' $SH container exec -it ex sleep 4343 > /dev/null 2>&1 3>&-
    fi
    # (a window: a command that is cancelled is killed within a moment)
    sleep 1
    sh_ container exec ex sh -c 'for p in /proc/[0-9]*; do cat $p/cmdline 2> /dev/null | tr "\0" " "; echo; done | grep -c "[4]343"' > "$WORKDIR/left" 2>&1
    check "a command goes on without its killed client" "$(command -v python3 > /dev/null && echo 2 || echo 1)" "$(cat "$WORKDIR/left")"
    sh_ container exec ex pkill -f 'sleep 4343'

    # Clients killed at any point of their request (before the monitor
    # answered too), each followed at once by others: those are
    # served (the commands of the killed ones go on).
    bad=0
    for i in $(seq 12); do
        "$SH" container exec ex sh -c 'sleep 4444' 3>&- &
        p=$!
        sleep "0.$(( (i * 37) % 10 ))"
        kill -9 $p
        wait $p 2> /dev/null
        pids=()
        for k in 1 2 3; do
            "$SH" container exec ex echo "next$k" > "$WORKDIR/next$k" 2>&1 3>&- &
            pids+=($!)
        done
        for k in 1 2 3; do
            wait "${pids[$((k - 1))]}"
            rc=$?
            if [ "$rc" != 0 ] || [ "$(cat "$WORKDIR/next$k")" != "next$k" ]; then
                bad=$((bad + 1))
                echo "     try $i exec $k: $rc $(cat "$WORKDIR/next$k")"
            fi
        done
    done
    check "the execs right after killed clients are served" 0 "$bad"
    sh_ container exec ex pkill -f 'sleep 4444'

    # SIGTERM to the client does not reach the command: podman's exec has no
    # --sig-proxy
    out=$(sig_proxy_run "$WORKDIR/sp.out" "$SH" container exec -i ex sh -c 'trap "echo got-term; exit 21" TERM; echo ready; while :; do sleep 0.1; done' 2>&1 3>&- < /dev/null)
    check_match "the client ends at SIGTERM" "client status 143" "$out"
    check "the command goes on" 0 "$(sh_ container exec ex pkill -0 -f '[g]ot-term' > /dev/null 2>&1; echo $?)"
    sh_ container exec ex pkill -f '[g]ot-term'

    # With a terminal
    if command -v python3 > /dev/null; then
        out=$($PTY_RUN --expect '# ' --input 'echo in-pty\r' --input 'exit 6\r' -- "$SH" container exec -it ex sh)
        check "exec -it exit code" 6 $?
        check_match "exec -it output" "in-pty" "$out"
        out=$($PTY_RUN --size 25,90 --expect '# ' --input 'stty size\r' --resize 31,100 --input 'stty size\r' --input 'exit\r' -- "$SH" container exec -it ex sh | tr -d '\r')
        check_match "exec -it size" "(^|[^0-9])25 90($|[^0-9])" "$out"
        check_match "exec -it resize" "(^|[^0-9])31 100($|[^0-9])" "$out"
    fi

    sh_ container rm -f -t 0 ex > /dev/null
}

@test "exec to a file or a pipe has the output as it comes" {
    mkdir -p "$WORKDIR/exo"
    mkfifo "$WORKDIR/exo/go"
    sh_ container run -d --name exo --network none -v "$WORKDIR/exo:/x:z" "$IMAGE" sleep 1000 > /dev/null
    # (in the engine of the command, and through the engine service)
    for via in command service; do
        sock=()
        [ "$via" = service ] && sock=(--socket "$ESOCK")
        "$SH" "${sock[@]}" container exec exo sh -c 'echo first; echo first-error >&2; cat /x/go; echo second' > "$WORKDIR/exo.out" 2> "$WORKDIR/exo.err" 3>&- &
        p=$!
        # (the command waits for the fifo: what it wrote before is there)
        e2e_wait_line "$WORKDIR/exo.out" '^first$' 10
        check "the output is there while the command runs ($via)" 0 $?
        e2e_wait_line "$WORKDIR/exo.err" '^first-error$' 10
        check "and so are the errors ($via)" 0 $?
        echo > "$WORKDIR/exo/go"
        wait $p
        check "the status ($via)" 0 $?
        check "the whole output ($via)" "first second" "$(xargs < "$WORKDIR/exo.out")"
        # a reader that goes away ends the client as SIGPIPE does
        "$SH" "${sock[@]}" container exec exo yes 3>&- | head -1 > /dev/null
        check "a reader that went away ($via)" 141 "${PIPESTATUS[0]}"
    done
    sh_ container rm -f -t 0 exo > /dev/null
}

@test "exec in a stopped container" {
    sh_ container run -d --name ex --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container stop -t 1 ex > /dev/null
    sh_ container exec ex echo x > /dev/null 2>&1
    check "exec in a stopped container fails, with podman's status" 255 $?
    out=$(sh_ container exec ex echo x 2>&1)
    # (podman's words, with or without an engine service)
    check "and says why, as podman" "Error: can only create exec sessions on running containers: container state improper" "$out"
    sh_ container rm ex > /dev/null
}

@test "the monitor serves org.velarx.Monitor to varlink clients" {
    command -v varlinkctl > /dev/null || skip "varlinkctl missing"
    sh_ container run -d --name vm --network none "$IMAGE" sleep 1000 > /dev/null
    sock=$XDG_RUNTIME_DIR/velarx/mon/$(inspect_of vm id | cut -c1-12)/monitor.sock
    check "its socket" 0 "$(test -S "$sock"; echo $?)"
    out=$(varlinkctl introspect "unix:$sock" org.velarx.Monitor)
    check_match "its interface" "method Attach" "$out"
    out=$(varlinkctl call "unix:$sock" org.velarx.Monitor.GetStatus '{}')
    check_match "its status" '"running"' "$out"
    out=$(varlinkctl call "unix:$sock" org.velarx.Monitor.Exec '{"command":["true"]}' 2>&1)
    check_match "a stream without more" "ExpectedMore|without .more. flag" "$out"
    sh_ container rm -f -t 0 vm > /dev/null
    check "and the socket goes with it" 1 "$(test -S "$sock"; echo $?)"
}
