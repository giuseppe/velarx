# SPDX-License-Identifier: Apache-2.0
# End to end tests of the logs of the containers: the CRI format, logs and
# its options, rotation, the log drivers, reopen-log, syslog and journald,
# through a daemon of its own.  Run it as an ordinary user for the rootless
# daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# The CRI format, `logs` and its options.
@test "the CRI log format and logs with its options" {
    id=$(sh_ container run -d --name lg --network none --log-driver k8s-file "$IMAGE" sh -c 'echo first; sleep 0.1; echo oops >&2; sleep 0.1; printf partial; sleep 0.3; echo " done"; echo last')
    log=$XDG_DATA_HOME/velarx/logs/$id/container.log
    e2e_wait_line "$log" ' stdout F last$' 30 || e2e_die "no last line in $log within 30 s"
    check_match "log file in the CRI format" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}\.[0-9]{9}(Z|[+-][0-9]{2}:[0-9]{2}) stdout F first$' "$(head -1 "$log")"
    check_match "stderr records" ' stderr F oops$' "$(grep stderr "$log")"
    check_match "partial record" ' stdout P partial$' "$(grep ' P ' "$log")"
    check_match "the line is ended" ' stdout F  done$' "$(grep ' F  done' "$log")"
    out=$(sh_ container logs lg 2>&1)
    check "logs" "first
oops
partial done
last" "$out"
    out=$(sh_ container logs lg 2> /dev/null)
    check "logs keeps stderr apart" "first
partial done
last" "$out"
    out=$(sh_ container logs -t lg 2> /dev/null | head -1)
    check_match "logs -t" '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2}) first$' "$out"
    out=$(TZ=Asia/Tokyo sh_ container logs -t lg 2> /dev/null | head -1)
    check_match "logs -t is in the time zone of the caller, as podman's" '^[0-9T:.-]+\+09:00 first$' "$out"
    out=$(sh_ container logs --tail 1 lg 2>&1)
    check "logs --tail" "last" "$out"
    out=$(sh_ container logs --tail 2 lg 2> /dev/null)
    check "logs --tail counts lines" "partial done
last" "$out"
    out=$(sh_ container logs --since 1h lg 2>&1 | wc -l)
    check "logs --since 1h" 4 "$out"
    out=$(sh_ container logs --since 2099-01-01T00:00:00Z lg 2>&1 | wc -l)
    check "logs --since in the future is empty" 0 "$out"
    # (podman's: a duration of --until is from now, -1h is an hour ago)
    out=$(sh_ container logs --until -1h lg 2>&1 | wc -l)
    check "logs --until -1h is empty" 0 "$out"
    out=$(sh_ container logs --until 1h lg 2>&1 | wc -l)
    check "logs --until 1h has them all" 4 "$out"
    sh_ container logs --since garbage lg > /dev/null 2>&1
    check "logs with an invalid time fails" 125 $?
    sh_ container rm lg > /dev/null
}

@test "logs -f" {
    sh_ container run -d --name follow --network none "$IMAGE" sh -c 'for i in 1 2 3; do echo line$i; sleep 0.2; done' > /dev/null
    out=$(timeout 10 "$SH" container logs -f follow 2>&1)
    check "logs -f" "line1
line2
line3" "$out"
    sh_ container rm follow > /dev/null
}

@test "log rotation, compression, the global limit, a path" {
    sh_ container run -d --name rot --network none --log-driver k8s-file --log-opt max-size=4k --log-opt max-file=50 "$IMAGE" \
       sh -c 'i=1; while test $i -le 2000; do echo $i; i=$((i+1)); test $((i % 100)) = 0 && sleep 0.2; done' > /dev/null
    sh_ container logs -f rot > "$WORKDIR/rot.out"
    check "logs -f across rotations" "$(seq 1 2000 | md5sum)" "$(md5sum < "$WORKDIR/rot.out")"
    id=$(sh_ container inspect rot | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    log=$XDG_DATA_HOME/velarx/logs/$id/container.log
    test -e "$log.1"
    check "the log was rotated" 0 $?
    sh_ container rm rot > /dev/null

    sh_ container run -d --name rot2 --network none --log-driver k8s-file --log-opt max-size=2k --log-opt max-file=2 "$IMAGE" \
       sh -c 'i=1; while test $i -le 2000; do echo $i; i=$((i+1)); test $((i % 100)) = 0 && sleep 0.1; done' > /dev/null
    sh_ container wait rot2 > /dev/null
    out=$(sh_ container logs rot2)
    check "logs after rotations end with the last line" "2000" "$(echo "$out" | tail -1)"
    first=$(echo "$out" | head -1)
    check "logs after rotations are contiguous" "$(seq "$first" 2000 | md5sum)" "$(echo "$out" | md5sum)"
    test "$first" -gt 1
    check "old logs are rotated away" 0 $?
    id=$(sh_ container inspect rot2 | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    log=$XDG_DATA_HOME/velarx/logs/$id/container.log
    test ! -e "$log.2"
    check "max-file is honoured" 0 $?
    sh_ container rm rot2 > /dev/null

    sh_ container run -d --name rot3 --network none --log-driver k8s-file --log-opt max-size=2k --log-opt max-file=10 --log-opt global-size-max=5k "$IMAGE" \
       sh -c 'i=1; while test $i -le 1000; do echo $i; i=$((i+1)); test $((i % 100)) = 0 && sleep 0.1; done' > /dev/null
    sh_ container wait rot3 > /dev/null
    id=$(sh_ container inspect rot3 | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    total=$(cat "$XDG_DATA_HOME/velarx/logs/$id"/container.log* | wc -c)
    test "$total" -le 5120
    check "the global limit is honoured ($total bytes)" 0 $?
    sh_ container rm rot3 > /dev/null
}

# compressed rotations: read by logs, logs --tail and logs -f
@test "compressed log rotations" {
    sh_ container run -d --name rot5 --network none --log-driver k8s-file --log-opt max-size=2k --log-opt max-file=6 --log-opt compress=true "$IMAGE" \
       sh -c 'i=1; while test $i -le 1500; do echo $i; i=$((i+1)); test $((i % 100)) = 0 && sleep 0.1; done' > /dev/null
    sh_ container logs -f rot5 > "$WORKDIR/rot5.out"
    first=$(head -1 "$WORKDIR/rot5.out")
    check "logs -f across compressing rotations" "$(seq "$first" 1500 | md5sum)" "$(md5sum < "$WORKDIR/rot5.out")"
    sh_ container wait rot5 > /dev/null
    id=$(sh_ container inspect rot5 | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    log=$XDG_DATA_HOME/velarx/logs/$id/container.log
    test -f "$log.1" -a -f "$log.2.gz" -a -f "$log.5.gz" -a ! -e "$log.2" -a ! -e "$log.6.gz"
    check "the rotated files but the newest are compressed" 0 $?
    gzip -t "$log.2.gz"
    check "they are gzip files" 0 $?
    out=$(sh_ container logs rot5)
    first=$(echo "$out" | head -1)
    check "logs of compressed rotations" "$(seq "$first" 1500 | md5sum)" "$(echo "$out" | md5sum)"
    test "$first" -gt 1 -a "$first" -lt 1400
    check "logs reach into the compressed files ($first)" 0 $?
    check "logs --tail of compressed rotations" "$(seq 1301 1500 | md5sum)" "$(sh_ container logs --tail 200 rot5 | md5sum)"
    # several containers: each line after the ID of its container, the
    # compressed rotations read too
    sh_ container run --name rot6 --network none --log-driver k8s-file "$IMAGE" echo other > /dev/null
    out=$(sh_ container logs rot5 rot6)
    check "logs of two containers, the compressed rotations of one" "$(seq "$first" 1500 | sed "s/^/${id:0:12} /" | md5sum)" \
        "$(echo "$out" | grep "^${id:0:12} " | md5sum)"
    check_match "and the line of the other" "^[0-9a-f]{12} other$" "$(echo "$out" | grep -v "^${id:0:12} ")"
    check "logs -f of two that ended" "$(echo "$out" | sort | md5sum)" "$(sh_ container logs -f rot5 rot6 | sort | md5sum)"
    sh_ container rm rot5 rot6 > /dev/null
    sh_ container run --rm --network none --log-opt compress=maybe "$IMAGE" true > /dev/null 2>&1
    check "a bad compress is refused" 125 $?
}

@test "a log path of the container" {
    sh_ container run -d --name rot4 --network none --log-driver k8s-file --log-opt path="$WORKDIR/custom.log" "$IMAGE" echo to-a-path > /dev/null
    sh_ container wait rot4 > /dev/null
    check_match "log-opt path" ' stdout F to-a-path$' "$(cat "$WORKDIR/custom.log")"
    out=$(sh_ container logs rot4)
    check "logs of a custom path" "to-a-path" "$out"
    sh_ container rm rot4 > /dev/null
}

@test "reopen-log after the file is moved" {
    sh_ container run -d --name ro --network none --log-driver k8s-file "$IMAGE" sh -c 'echo before; sleep 1; echo after; sleep 1' > /dev/null
    id=$(sh_ container inspect ro | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    log=$XDG_DATA_HOME/velarx/logs/$id/container.log
    e2e_wait_line "$log" ' stdout F before$' 30 || e2e_die "no first line in $log within 30 s"
    mv "$log" "$log.kubelet"
    sh_ container reopen-log ro > /dev/null
    check "reopen-log" 0 $?
    sh_ container wait ro > /dev/null
    check_match "the new file has what came after" ' stdout F after$' "$(cat "$log")"
    check_match "the moved file keeps what came before" ' stdout F before$' "$(cat "$log.kubelet")"
    sh_ container reopen-log ro > /dev/null 2>&1
    check "reopen-log of a stopped container fails" 125 $?
    sh_ container rm ro > /dev/null
}

@test "log drivers: none, passthrough, and the ones that are refused" {
    sh_ container run -d --name ln --network none --log-driver none "$IMAGE" echo discarded > /dev/null
    sh_ container wait ln > /dev/null
    out=$(sh_ container logs ln 2>&1)
    check "logs of the none driver fail, in podman's words" \
        "Error: this container is using the 'none' log driver, cannot read logs: this container is not logging output 125" \
        "$out $?"
    id=$(sh_ container inspect ln | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    test ! -e "$XDG_DATA_HOME/velarx/logs/$id/container.log"
    check "the none driver writes nothing" 0 $?
    sh_ container rm ln > /dev/null

    out=$(sh_ container run --rm --network none --log-driver none "$IMAGE" echo still-attachable)
    check "output is still streamed with the none driver" "still-attachable" "$out"

    # The server cannot write to the output of its client; the client runs
    # such a container in the engine, from its own process tree.
    out=$(sh_ --socket "$ESOCK" container run -d --network none --log-driver passthrough "$IMAGE" echo x 2>&1)
    check_match "passthrough through the server is refused" "caller's output" "$out"
    out=$(sh_ container run --rm --network none --log-driver passthrough "$IMAGE" echo pass-through 2>&1)
    check_match "passthrough writes to the output of the client" "pass-through" "$out"
    # nothing to read or attach to: podman's words
    id=$(sh_ container create --name lp --network none --log-driver passthrough "$IMAGE" sleep 100)
    sh_ container start lp > /dev/null
    out=$(sh_ container logs lp 2>&1)
    check "logs of the passthrough driver fail, in podman's words" \
        "Error: this container is using the 'passthrough' log driver, cannot read logs: this container is not logging output 125" \
        "$out $?"
    out=$(sh_ container attach lp < /dev/null 2>&1)
    check "...and an attach" \
        "Error: attaching to container $id: this container is using the 'passthrough' log driver, cannot attach: this container is not logging output 125" \
        "$out $?"
    sh_ container rm -f -t 0 lp > /dev/null

    sh_ container run --network none --log-driver nonsense "$IMAGE" true > /dev/null 2>&1
    check "an unknown driver is refused" 125 $?
    sh_ container run --network none --log-opt max-size=lots "$IMAGE" true > /dev/null 2>&1
    check "an invalid size is refused" 125 $?
    sh_ container run --network none --log-opt nonsense=1 "$IMAGE" true > /dev/null 2>&1
    check "an unknown log option is refused" 125 $?
    sh_ container run --network none --log-driver k8s-file,k8s-file "$IMAGE" true > /dev/null 2>&1
    check "a driver twice is refused" 125 $?
    sh_ container run --network none --log-driver none,syslog "$IMAGE" true > /dev/null 2>&1
    check "none with another driver is refused" 125 $?

}

@test "passthrough to a file: the output is lost only where the engine says the policy withholds it" {
    command -v selinuxenabled > /dev/null && selinuxenabled || skip "needs SELinux"
    # With SELinux the container gets /dev/null for the descriptors its type
    # may not write (a file of the user's, for container_t): its output is
    # lost, and the engine has to say so.
    sh_ container run --rm --network none --log-driver passthrough "$IMAGE" echo to-a-file \
        > "$WORKDIR/pt.out" 2>&1
    if grep -q 'does not let .* write to the standard output' "$WORKDIR/pt.out"; then
        check "withheld: the output is lost" 0 "$(grep -c '^to-a-file$' "$WORKDIR/pt.out")"
        sh_ container run --rm --network none --log-driver passthrough --security-opt label=disable \
            "$IMAGE" echo to-a-file > "$WORKDIR/pt.out" 2>&1
        check "label=disable gives the output" 1 "$(grep -c '^to-a-file$' "$WORKDIR/pt.out")"
        check "and the engine says nothing" 0 "$(grep -c 'does not let' "$WORKDIR/pt.out")"
        # (start hands its own output over in the same way)
        sh_ container create --name ptstart --network none --log-driver passthrough "$IMAGE" true > /dev/null
        sh_ container start ptstart > "$WORKDIR/pt.out" 2>&1
        check "start says so too" 1 "$(grep -c 'does not let .* write to the standard output' "$WORKDIR/pt.out")"
        sh_ container rm -t 0 -f ptstart > /dev/null
    else
        check "not withheld: the output is there" 1 "$(grep -c '^to-a-file$' "$WORKDIR/pt.out")"
    fi
    out=$(sh_ container run --rm --network none --log-driver passthrough "$IMAGE" echo to-a-pipe 2>&1 | cat)
    check "a pipe is never withheld" 1 "$(grep -c '^to-a-pipe$' <<< "$out")"
}

# The allowlist of log paths: a path in it, below it without symbolic links
@test "the allowlist of log paths" {
    mkdir -p "$WORKDIR/allowed/sub" "$WORKDIR/elsewhere"
    ln -s "$WORKDIR/elsewhere" "$WORKDIR/allowed/link"
    stop_daemon
    cp "$CONFIG" "$CONFIG.orig"
    printf '[containers]\nlog_path_allowlist = ["%s"]\n' "$WORKDIR/allowed" >> "$CONFIG"
    start_daemon
    out=$(sh_ container run --rm --network none --log-driver k8s-file --log-opt path="$WORKDIR/allowed/sub/in.log" "$IMAGE" echo allowed 2>&1)
    check "a log path in the allowlist" "allowed" "$out"
    check_match "it is written" " stdout F allowed$" "$(cat "$WORKDIR/allowed/sub/in.log" 2> /dev/null)"
    out=$(sh_ container run --rm --network none --log-driver k8s-file --log-opt path="$WORKDIR/elsewhere/out.log" "$IMAGE" true 2>&1)
    check "a log path out of the allowlist is refused" 125 $?
    check_match "and said so" "log_path_allowlist" "$out"
    sh_ container run --rm --network none --log-driver k8s-file --log-opt path="$WORKDIR/allowed/link/out.log" "$IMAGE" true > /dev/null 2>&1
    check_match "a link out of the allowlist is not followed" "^[1-9]" "$?"
    test ! -e "$WORKDIR/elsewhere/out.log"
    check "nothing was written through the link" 0 $?
    stop_daemon
    mv "$CONFIG.orig" "$CONFIG"
    start_daemon
}

# syslog, alone and with a file: it needs /dev/log, and a journal
# this user can read to look at the messages.
@test "syslog with the file driver: logs reads the file, the journal has the lines" {
    if ! test -S /dev/log || ! command -v journalctl > /dev/null; then
        skip "no /dev/log or journalctl"
    fi
    tag=e2e-sl-$$
    cursor=$(journal_cursor)
    sh_ container run --name sl --network none --log-driver k8s-file,syslog --log-opt tag="$tag-{{.Name}}" "$IMAGE" sh -c 'echo to-both; echo bad >&2' > /dev/null 2>&1
    out=$(sh_ container logs sl 2>&1)
    check "with k8s-file,syslog logs reads the file" "to-both
bad" "$out"
    wait_journal "$cursor" -t "$tag-sl"
    out=$(journalctl --no-pager -o cat -t "$tag-sl" 2> /dev/null)
    if test -z "$out"; then
        sh_ container rm sl > /dev/null
        skip "the journal cannot be read by this user"
    fi
    check "syslog has the lines, tagged" "to-both
bad" "$out"
    check "stderr has the err priority" "bad" "$(journalctl --no-pager -o cat -p 3 -t "$tag-sl" 2> /dev/null)"
    sh_ container rm sl > /dev/null
}

@test "syslog alone: the container runs, logs cannot read it back" {
    if ! test -S /dev/log || ! command -v journalctl > /dev/null; then
        skip "no /dev/log or journalctl"
    fi
    sh_ container run --name sl2 --network none --log-driver syslog "$IMAGE" echo only-syslog > /dev/null 2>&1
    check "a container that logs to syslog runs" exited "$(state_of sl2)"
    out=$(sh_ container logs sl2 2>&1)
    check_match "logs of syslog cannot be read back" "syslog" "$out"
    sh_ container rm sl2 > /dev/null
}

# Needs a journal that takes messages from this user, and journalctl.
@test "journald driver, logs and logs -f" {
    if ! test -S /run/systemd/journal/socket || ! command -v journalctl > /dev/null; then
        skip "no journal"
    fi
    cursor=$(journal_cursor)
    sh_ container run -d --name jd --network none --log-driver journald --log-opt tag=e2e-tag "$IMAGE" sh -c 'echo to-the-journal; echo bad >&2' > /dev/null
    id=$(sh_ container inspect jd | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    sh_ container wait jd > /dev/null
    wait_journal "$cursor" "CONTAINER_ID_FULL=$id"
    out=$(journalctl --no-pager -o cat "CONTAINER_ID_FULL=$id" 2> /dev/null)
    if test -z "$out"; then
        sh_ container rm jd > /dev/null
        skip "the journal cannot be read by this user"
    fi
    check "the journal has the output" "to-the-journal
bad" "$out"
    out=$(journalctl --no-pager -o cat -p 3 "CONTAINER_ID_FULL=$id" 2> /dev/null)
    check "stderr has the error priority" "bad" "$out"
    # (the output of the container on the standard output, its errors on the
    # standard error, as podman's logs of any driver)
    out=$(sh_ container logs jd 2> /dev/null)
    check "logs reads the journal" "to-the-journal" "$out"
    out=$(sh_ container logs jd 2>&1 > /dev/null)
    check "and its errors are on the standard error" "bad" "$out"
    sh_ container rm jd > /dev/null

    # logs --follow: what the journal has, then what comes, up to the end
    # (journald first of a list of drivers: the journal is what logs read)
    sh_ container run -d --name jdf --network none --log-driver journald,k8s-file "$IMAGE" \
        sh -c 'echo first; sleep 2; echo second; sleep 1' > /dev/null
    out=$(timeout 20 "$SH" container logs -f jdf 2>&1)
    check "logs -f follows the journal until the container ends" "0 first
second" "$? $out"
    out=$(timeout 20 "$SH" container logs -f --tail 1 jdf 2>&1)
    check "logs -f --tail of an exited container" "second" "$out"
    sh_ container rm jdf > /dev/null
}

@test "the default log driver is podman's: journald when the host has a readable journal, else k8s-file" {
    want=k8s-file
    if [ -d /run/systemd/system ]; then
        for d in /run/log/journal/* /var/log/journal/*; do
            if [ -d "$d" ] && ls "$d" > /dev/null 2>&1; then want=journald; fi
        done
    fi
    sh_ container run --name dl --network none "$IMAGE" echo by-default > /dev/null
    check "the driver of a container" "$want" "$(sh_ container inspect --format '{{.HostConfig.LogConfig.Type}}' dl)"
    check "info" "$want" "$(sh_ info --format '{{.Host.LogDriver}}')"
    check "logs reads it back" "by-default" "$(sh_ container logs dl 2>&1)"
    sh_ container rm dl > /dev/null
    sh_ container run --name dl2 --network none --log-driver k8s-file "$IMAGE" echo by-file > /dev/null
    check "a driver that is asked for" "k8s-file" "$(sh_ container inspect --format '{{.HostConfig.LogConfig.Type}}' dl2)"
    sh_ container rm dl2 > /dev/null
}
