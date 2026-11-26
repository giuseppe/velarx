# SPDX-License-Identifier: Apache-2.0
# End to end tests of the configuration read by the engine and its effects:
# CDI devices, the events (file, none, journald), the OCI hooks, and
# checkpoint and restore, through a daemon of its own.  Run it as an ordinary
# user for the rootless daemon, or as root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

skip_unless_criu () {
    skip_unless_root
    command -v criu > /dev/null || skip "no criu"
}

# wait_count NAME REGEX: until the counter the container NAME runs printed a
# number that matches REGEX (a line of its log file).
wait_count () {
    e2e_wait_line "$XDG_DATA_HOME/velarx/logs/$(inspect_of "$1" id)/container.log" " stdout F $2\$" 30 ||
        e2e_die "the counter of $1 printed no $2 within 30 s"
}

label_of () {
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["process"].get("selinuxLabel", ""))' \
        "$XDG_DATA_HOME/velarx/bundles/$1/config.json"
}

# craft OUT PYTHON-EXPRESSION-ON-req: the plain archive of cpi, edited
craft () {
    python3 -I - "$WORKDIR/plain.tar" "$1" "$2" << 'EOT'
import io, json, sys, tarfile
src, out, edit = sys.argv[1:4]
with tarfile.open(src) as t, tarfile.open(out, "w") as o:
    for m in t.getmembers():
        data = t.extractfile(m).read() if m.isfile() else None
        if m.name == "config.dump":
            d = json.loads(data)
            req = d["request"]
            exec(edit)
            data = json.dumps(d).encode()
            m.size = len(data)
        o.addfile(m, io.BytesIO(data) if data is not None else None)
EOT
}

# CDI: a spec directory of a fake vendor (the host's /dev/zero as the device
# node, a variable, a mount of a directory), read at each create.
@test "CDI devices" {
    cdi=$WORKDIR/cdi
    mkdir -p "$cdi/data"
    chmod 755 "$cdi"
    echo from-the-host > "$cdi/data/file"
    e2e_label_for_containers "$cdi/data"
    cat > "$cdi/fake.json" << EOT
{"cdiVersion": "0.6.0", "kind": "fake.vendor.com/dev",
 "devices": [{"name": "d0", "containerEdits": {
    "env": ["FAKE_DEV=d0"],
    "deviceNodes": [{"path": "/dev/fake0", "hostPath": "/dev/zero"}],
    "mounts": [{"hostPath": "$cdi/data", "containerPath": "/fake", "options": ["ro", "nosuid", "nodev", "bind"]}]}}],
 "containerEdits": {"env": ["FAKE_KIND=1"]}}
EOT
    chmod 644 "$cdi/fake.json"
    events_daemon "[containers]
cdi_spec_dirs = [\"$cdi\"]"

    out=$(sh_ container run --rm --network none --device fake.vendor.com/dev=d0 "$IMAGE" \
        sh -c 'echo $FAKE_DEV $FAKE_KIND; cat /fake/file; test -c /dev/fake0 && head -c 3 /dev/fake0 | od -An -tx1 | tr -d " "' 2>&1)
    check "a CDI device: its variables, mount and node" "d0 1
from-the-host
000000" "$out"
    out=$(sh_ container run --rm --network none --device fake.vendor.com/dev=d0 "$IMAGE" \
        sh -c 'touch /fake/x 2>&1; echo $?' 2>&1)
    check_match "the mount is read only as the spec says" "Read-only file system" "$out"
    out=$(sh_ container run --rm --network none --device fake.vendor.com/dev=d0 --device /dev/null:/dev/other "$IMAGE" \
        sh -c 'echo $FAKE_DEV; test -c /dev/other && echo other' 2>&1)
    check "a path device next to a CDI one" "d0
other" "$out"

    # --gpus: the devices of the CDI class nvidia.com/gpu
    cat > "$cdi/nvidia.json" << EOT
{"cdiVersion": "0.6.0", "kind": "nvidia.com/gpu",
 "devices": [{"name": "0", "containerEdits": {"env": ["GPU_0=1"]}},
             {"name": "all", "containerEdits": {"env": ["GPU_ALL=1"]}}]}
EOT
    chmod 644 "$cdi/nvidia.json"
    out=$(sh_ container run --rm --network none --gpus all "$IMAGE" sh -c 'echo ${GPU_ALL:-no} ${GPU_0:-no}' 2>&1)
    check "--gpus all is the device nvidia.com/gpu=all" "1 no" "$out"
    out=$(sh_ container run --rm --network none --gpus 0 --gpus all --device fake.vendor.com/dev=d0 "$IMAGE" \
        sh -c 'echo $GPU_ALL $GPU_0 $FAKE_DEV' 2>&1)
    check "--gpus twice, next to --device" "1 1 d0" "$out"
    out=$(sh_ container run --rm --network none --gpus 7 "$IMAGE" true 2>&1)
    check_match "an unknown GPU is named" "unresolvable CDI devices nvidia.com/gpu=7" "$out"

    out=$(sh_ container run --rm --network none --device fake.vendor.com/dev=nope "$IMAGE" true 2>&1)
    check_match "an unknown device is named" "unresolvable CDI devices fake.vendor.com/dev=nope" "$out"
    sh_ container run --rm --network none --device fake.vendor.com/dev=nope "$IMAGE" true > /dev/null 2>&1
    check "and refuses the container" 125 $?
    out=$(sh_ container run --rm --network none --device notadevice "$IMAGE" true 2>&1)
    check_match "a name that is not qualified" "unqualified device" "$out"

    # the files are read at each create: a new device, no restart
    sed 's/"d0"/"d1"/; s/FAKE_DEV=d0/FAKE_DEV=d1/' "$cdi/fake.json" > "$cdi/other.json"
    chmod 644 "$cdi/other.json"
    rm -f "$cdi/fake.json"
    out=$(sh_ container run --rm --network none --device fake.vendor.com/dev=d1 "$IMAGE" sh -c 'echo $FAKE_DEV' 2>&1)
    check "a spec file added or removed counts at once" "d1" "$out"

    # a spec that others can write is not trusted
    chmod 666 "$cdi/other.json"
    out=$(sh_ container run --rm --network none --device fake.vendor.com/dev=d1 "$IMAGE" true 2>&1)
    check_match "a spec writable by others is refused" "writable by its group or others" "$out"
    chmod 644 "$cdi/other.json"

    out=$(sh_ info 2> /dev/null)
    check_match "info lists the spec directories and the devices" "fake.vendor.com/dev=d1" "$out"
    events_daemon ""
}

@test "events: a file keeps them across a restart of the daemon" {
    events_daemon "events_logger = \"file\"
events_logfile_path = \"$WORKDIR/ev/events.log\""
    sh_ container run --name evf --network none "$IMAGE" sh -c 'exit 6' > /dev/null 2>&1
    events_daemon "events_logger = \"file\"
events_logfile_path = \"$WORKDIR/ev/events.log\""
    out=$(sh_ events --stream=false --since 5m --filter event=died --filter container=evf)
    check_match "file: the died of before the restart" "container died [0-9a-f]+ \(.*name=evf.*containerExitCode=6" "$out"
    out=$(sh_ events --stream=false --since 5m --filter container=nothere)
    check "file: filters apply to the kept events" "" "$out"
    grep -q '"Name":"evf"' "$WORKDIR/ev/events.log"
    check "file: the events are in the file" 0 $?
    # exactly one died per exit: run --rm, run -d and stop
    sh_ container run --rm --name evr --network none "$IMAGE" true > /dev/null 2>&1
    sh_ container run -d --name evd --network none "$IMAGE" sleep 100 > /dev/null
    sh_ container stop -t 1 evd > /dev/null
    sh_ container wait evd > /dev/null 2>&1
    for n in evr evd; do
        e2e_wait_line "$WORKDIR/ev/events.log" "(?=.*\"Status\":\"died\")(?=.*\"Name\":\"$n\")" 30 ||
            e2e_die "no died event of $n in the file within 30 s"
    done
    for n in evr evd; do
        check "file: one died of $n" 1 \
            "$(grep '"Status":"died"' "$WORKDIR/ev/events.log" | grep -c "\"Name\":\"$n\"")"
    done
    sh_ container rm evd > /dev/null
    sh_ container rm evf > /dev/null
    # streamed: the kept events, then those that happen, until the end
    "$SH" events --since 5m --until $(( $(date +%s) + 4 )) --filter event=died > "$WORKDIR/evstream" 2>&1 3>&- &
    evpid=$!
    # (the stream is live once it shows a kept event)
    e2e_wait_line "$WORKDIR/evstream" 'died .*name=evd' 30 || e2e_die "the events stream does not start"
    sh_ container run --rm --name evs --network none "$IMAGE" true > /dev/null 2>&1
    wait "$evpid"
    out=$(cat "$WORKDIR/evstream")
    check_match "stream: the kept events first" "name=evf" "$out"
    check_match "stream: then the new ones" "name=evs" "$out"
    events_daemon ""
}

@test "events: none keeps them in memory only" {
    events_daemon 'events_logger = "none"'
    sh_ container run --name evn --network none "$IMAGE" true > /dev/null 2>&1
    # (the run had its engine, whose memory went with it, as podman's)
    # (podman's: there is nothing to read, and it says so)
    out=$(sh_ events --stream=false --since 5m --filter container=evn 2>&1)
    check "none: nothing is read" 125 $?
    check "none: says so" 'Error: cannot read events with the "none" backend' "$out"
    check "none: nothing is written" no "$(grep -qs '"Name":"evn"' "$WORKDIR/ev/events.log" && echo yes || echo no)"
    out=$(timeout 5 "$SH" events 2>&1 3>&-)
    check "none: nothing to follow" 125 $?
    check_match "and says so" 'cannot read events with the "none" backend' "$out"
    sh_ container rm evn > /dev/null
    events_daemon ""
}

@test "events: journald" {
    if ! test -S /run/systemd/journal/socket || ! command -v journalctl > /dev/null; then
        skip "no journal"
    fi
    events_daemon 'events_logger = "journald"'
    cursor=$(journal_cursor)
    sh_ container run --name evj --network none --log-driver journald "$IMAGE" sh -c 'echo only-output; exit 7' > /dev/null 2>&1
    wait_journal "$cursor" SYSLOG_IDENTIFIER=velarx PODMAN_NAME=evj PODMAN_EVENT=died
    j=$(journalctl --no-pager -o json SYSLOG_IDENTIFIER=velarx PODMAN_NAME=evj PODMAN_EVENT=died 2> /dev/null)
    if test -z "$j"; then
        sh_ container rm evj > /dev/null
        events_daemon ""
        skip "the journal cannot be read by this user"
    fi
    check "journald: one died, of this store only" 1 \
        "$(journalctl --no-pager -o json SYSLOG_IDENTIFIER=velarx PODMAN_NAME=evj PODMAN_EVENT=died \
            VELARX_ROOT="$(sh_ info --format '{{.Store.GraphRoot}}' 2> /dev/null)" 2> /dev/null | wc -l)"
    for f in '"PODMAN_EVENT":"died"' '"PODMAN_TYPE":"container"' '"PODMAN_ID":"[0-9a-f]{64}"' '"PODMAN_NAME":"evj"' '"PODMAN_EXIT_CODE":"7"'; do
        check_match "journald: $f" "$f" "$j"
    done
    events_daemon 'events_logger = "journald"'
    out=$(sh_ events --stream=false --since 5m --filter event=died --filter container=evj)
    check_match "journald: the died of before the restart" "container died [0-9a-f]+ \(.*name=evj.*containerExitCode=7" "$out"
    out=$(sh_ container logs evj 2> /dev/null)
    check "journald: the logs have no events" "only-output" "$out"
    sh_ container rm evj > /dev/null
    events_daemon ""
}

# The events of a container that exits with 3, with podman's
# --stream=false (velarx events follows the new events after the kept
# ones, as podman) and podman's line (the time is 4 fields: the status is
# the 6th).
@test "events of a container that exits with 3" {
    since=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    "$SH" events --format '{{.Type}} {{.Status}} {{.Name}} {{.ContainerExitCode}}' > "$WORKDIR/evcstream" 2>&1 3>&- &
    evpid=$!
    # (the stream is there once it shows an event made after it)
    sh_ container create --name evmark --network none "$IMAGE" true > /dev/null
    e2e_wait_line "$WORKDIR/evcstream" '^container create evmark ' 30 || e2e_die "the events stream does not start"
    sh_ container rm evmark > /dev/null
    sh_ container run --name evc --network none "$IMAGE" sh -c 'exit 3' > /dev/null 2>&1
    sh_ container rm evc > /dev/null
    e2e_wait_line "$WORKDIR/evcstream" '^container remove evc 3$' 30 || e2e_die "no remove event of evc in the stream"
    kill "$evpid" 2> /dev/null
    wait "$evpid" 2> /dev/null
    # (the remove has the exit code, as podman's)
    # (podman's: no exit code before the container died)
    check "events stream" "container create evc <nil>,container start evc <nil>,container died evc 3,container cleanup evc <nil>,container remove evc 3," \
        "$(grep ' evc ' "$WORKDIR/evcstream" | grep -v ' init \| attach ' | tr '\n' ',')"
    out=$(sh_ events --stream=false --since "$since" --filter container=evc)
    check "events since" "create start died cleanup remove" \
        "$(echo "$out" | awk '$6 != "init" && $6 != "attach" {print $6}' | tr '\n' ' ' | sed 's/ $//')"
    check_match "died exit code" "containerExitCode=3" "$out"
    check_match_lines "the full ID, as podman's" "^[^ ]+ [^ ]+ [^ ]+ [^ ]+ container create [0-9a-f]{64} \(image=" "$out"
    out=$(sh_ events --stream=false --since "$since" --filter container=evc --format json | head -1)
    check_match "events json" '"Status":"create".*"Type":"container"' "$out"
    out=$(sh_ events --stream=false --since 1m --filter event=died --filter container=evc --format '{{.Name}}')
    check "events history with filters" "evc" "$out"
    check_match "events relative since" "container remove" "$(sh_ events --stream=false --since 5m)"
    check "events until" "" "$(sh_ events --stream=false --until 2000-01-01T00:00:00Z)"
    out=$(sh_ events --stream=false --since yesterday 2>&1)
    check "events invalid time" 125 $?
    check_match "events invalid time says so" "invalid since" "$out"
    out=$(sh_ events --stream=false --since inf 2>&1)
    check "events rejects an infinite time" 125 $?
    sh_ volume create evvol > /dev/null
    sh_ volume rm evvol > /dev/null
    check "volume events" "create remove" \
        "$(sh_ events --stream=false --since "$since" --filter type=volume | awk '{print $6}' | tr '\n' ' ' | sed 's/ $//')"
}

# OCI hooks from hooks.d directories: each stage runs, the
# conditions select, precreate edits the configuration.
@test "OCI hooks" {
    hd=$WORKDIR/hooks.d
    mkdir -p "$hd"
    : > "$WORKDIR/hooks.out"
    cat > "$WORKDIR/hook.sh" << EOT
#!/bin/sh
# hook.sh STAGE: the stage and the status the runtime gives
status=\$(python3 -I -c 'import json, sys; print(json.load(sys.stdin).get("status", ""))' 2> /dev/null)
echo "\$1 \$status" >> "$WORKDIR/hooks.out"
EOT
    cat > "$WORKDIR/precreate.sh" << 'EOT'
#!/bin/sh
exec python3 -I -c 'import json, sys
c = json.load(sys.stdin)
c["process"]["env"].append("HOOKED=by-precreate")
json.dump(c, sys.stdout)'
EOT
    chmod +x "$WORKDIR/hook.sh" "$WORKDIR/precreate.sh"
    for st in createRuntime createContainer poststart poststop prestart; do
        printf '{"version":"1.0.0","hook":{"path":"%s","args":["hook.sh","%s"]},"when":{"annotations":{"^e2e.hooks$":"^yes$"}},"stages":["%s"]}\n' \
            "$WORKDIR/hook.sh" "$st" "$st" > "$hd/10-$st.json"
    done
    # startContainer runs in the container: its program is the container's
    printf '{"version":"1.0.0","hook":{"path":"/bin/sh","args":["sh","-c","echo from-startContainer > /tmp/startc"]},"when":{"annotations":{"^e2e.hooks$":"^yes$"}},"stages":["startContainer"]}\n' > "$hd/20-start.json"
    printf '{"version":"1.0.0","hook":{"path":"%s"},"when":{"annotations":{"^e2e.hooks$":"^yes$"}},"stages":["precreate"]}\n' "$WORKDIR/precreate.sh" > "$hd/30-precreate.json"
    # 0.1.0, for another command only
    printf '{"hook":"%s","arguments":["old"],"stage":["prestart"],"cmds":["^/bin/never$"]}\n' "$WORKDIR/hook.sh" > "$hd/40-old.json"
    events_daemon "[containers]
hooks_dir = [\"$hd\"]"

    out=$(sh_ container run --name hk --network none --annotation e2e.hooks=yes "$IMAGE" sh -c 'cat /tmp/startc; echo $HOOKED' 2>&1)
    check "startContainer ran in the container" "from-startContainer
by-precreate" "$out"
    sh_ container rm hk > /dev/null
    e2e_wait_line "$WORKDIR/hooks.out" '^poststop ' 30 || e2e_die "the poststop hook did not run within 30 s"
    for st in createRuntime createContainer poststart; do
        check_match_lines "the $st hook ran" "^$st (creating|created|running)$" "$(grep "^$st " "$WORKDIR/hooks.out")"
    done
    check_match_lines "prestart runs at createRuntime, as podman's" "^prestart (creating|created)$" "$(grep '^prestart ' "$WORKDIR/hooks.out")"
    check_match_lines "the poststop hook ran" "^poststop stopped$" "$(grep '^poststop ' "$WORKDIR/hooks.out")"
    check "a 0.1.0 hook for another command did not" "" "$(grep '^old' "$WORKDIR/hooks.out")"

    : > "$WORKDIR/hooks.out"
    out=$(sh_ container run --rm --network none "$IMAGE" sh -c 'echo ${HOOKED:-none}' 2>&1)
    check "without the annotation no hook runs" "none" "$out"
    check "and none ran" "" "$(cat "$WORKDIR/hooks.out")"

    printf '{"version":"1.0.0","hook":{"path":"/nonexistent"},"when":{"always":true},"stages":["prestart"]}\n' > "$hd/50-bad.json"
    sh_ container run --rm --network none "$IMAGE" true > /dev/null 2>&1
    check "a hook that cannot run refuses the container" 125 $?
    rm -f "$hd/50-bad.json"
    events_daemon ""
}

# Checkpoint and restore through the runtime: root only (CRIU).
@test "checkpoint and restore" {
    if test "$(id -u)" != 0; then
        out=$(sh_ container checkpoint nothere 2>&1)
        check_match "rootless: checkpoint says it needs root" "need root" "$out"
    fi
    skip_unless_criu
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    sh_ container run -d --name cp --network none --log-driver k8s-file --restart always "$IMAGE" sh -c "$count" > /dev/null
    wait_count cp 3
    out=$(sh_ container checkpoint cp 2>&1)
    check "checkpoint" "cp" "$out"
    check "stopped by the checkpoint, not restarted" exited "$(state_of cp)"
    # (a window: the restart policy would have started it by now)
    sleep 1
    check "still stopped a moment later" exited "$(state_of cp)"
    id=$(sh_ container inspect cp | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    bundle=$XDG_DATA_HOME/velarx/bundles/$id/checkpoint
    check "the images are 0700" 700 "$(stat -c %a "$bundle" 2> /dev/null)"
    last=$(sh_ container logs cp | tail -1)
    out=$(sh_ container restore cp 2>&1)
    check "restore" "cp" "$out"
    check "running after the restore" running "$(state_of cp)"
    wait_count cp $((last + 2))
    next=$(sh_ container logs cp | tail -1)
    test "$next" -gt "$last"
    check "the count goes on ($last, then $next)" 0 $?
    sh_ container logs cp | awk -v l="$last" '$1 == l + 1 { found = 1 } END { exit !found }'
    check "from where it was" 0 $?
    test ! -e "$bundle"
    check "the images are removed after the restore" 0 $?
    sh_ container exec cp true
    check "exec in the restored container" 0 $?
    sh_ container stop -t 1 cp > /dev/null
    check "stop of the restored container" exited "$(state_of cp)"
}

# An image whose /etc is a link: the runtime makes the bind mounts of /etc/hosts
# and /etc/hostname at /var/etc, and has to tell CRIU of them there.  The spec
# carries the destinations as given; resolving them for CRIU is the runtime's
# job (crun 1.30 did not, and CRIU refused the checkpoint: "doesn't have a
# proper root mount"; crun 1.31 does).
@test "checkpoint and restore of an image whose /etc is a link" {
    skip_unless_criu
    mkdir "$WORKDIR/etclink" "$WORKDIR/etcbind"
    echo bound > "$WORKDIR/etcbind/f"
    printf 'FROM %s\nRUN mkdir -p /var && mv /etc /var/etc && ln -s /var/etc /etc\n' "$IMAGE" > "$WORKDIR/etclink/Dockerfile"
    sh_ build --tls-verify=false -t localhost/e2e-etclink:1 "$WORKDIR/etclink" > "$WORKDIR/etclink.log" 2>&1
    check "the image is built" 0 $?
    sh_ container run -d --name cpl --network none -v "$WORKDIR/etcbind:/etc/bound:z" \
        localhost/e2e-etclink:1 sh -c 'while :; do sleep 0.2; done' > /dev/null
    check "/etc is a link" "/var/etc" "$(sh_ container exec cpl readlink /etc)"
    check "inspect shows the destination given" "/etc/bound" \
        "$(sh_ container inspect --format '{{range .Mounts}}{{.Destination}}{{end}}' cpl)"
    sh_ container checkpoint cpl > /dev/null
    check "the checkpoint" 0 $?
    sh_ container restore cpl > /dev/null
    check "the restore" 0 $?
    check "the bind mount below the link after the restore" bound \
        "$(sh_ container exec cpl cat /etc/bound/f)"
    sh_ container rm -t 0 -f cpl > /dev/null
    sh_ image rm -f localhost/e2e-etclink:1 > /dev/null
}

# --leave-running and --keep
@test "checkpoint --leave-running, restore --keep, a restore that fails" {
    skip_unless_criu
    id=$(sh_ container inspect cp | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    [ -n "$id" ] || { echo "needs the container cp of the test 'checkpoint and restore'" >&2; exit 1; }
    bundle=$XDG_DATA_HOME/velarx/bundles/$id/checkpoint
    sh_ container start cp > /dev/null
    sh_ container checkpoint --leave-running cp > /dev/null
    check "--leave-running leaves it running" running "$(state_of cp)"
    sh_ container restore cp > /dev/null 2>&1
    check "a running container is not restored" 125 $?
    sh_ container stop -t 1 cp > /dev/null
    sh_ container restore --keep cp > /dev/null
    check "restore of a --leave-running checkpoint" running "$(state_of cp)"
    test -d "$bundle"
    check "--keep keeps the images" 0 $?

    # a restore that fails leaves the container stopped and removable
    sh_ container stop -t 1 cp > /dev/null
    rm -f "$bundle"/pages-*.img
    sh_ container restore cp > /dev/null 2>&1
    check "a broken checkpoint is not restored" 125 $?
    check "the container stays stopped" exited "$(state_of cp)"
    check "no monitor is left" 0 "$(pgrep -fc "^velarx-monitor: ${id:0:12} " || true)"
    check "no runtime state is left" "" "$(crun --root /run/crun list -q 2> /dev/null | grep "$id"; ls "$XDG_RUNTIME_DIR"/crun 2>/dev/null | grep "$id")"
    sh_ container rm cp > /dev/null
    check "and it is removed" 0 $?
}

# --export and --import: a new container from the archive, with
# the changes of the root file system
@test "checkpoint --export and restore --import" {
    skip_unless_criu
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    sh_ container run -d --name cpe --network none --log-driver k8s-file "$IMAGE" sh -c "echo new > /new; rm /etc/issue; $count" > /dev/null
    wait_count cpe 3
    # an xattr of a file the container made goes with its layer (where the
    # file system of the upper directory has user xattrs)
    upper=$(sh_ container inspect --format '{{.GraphDriver.Data.UpperDir}}' cpe)
    xattr=0
    setfattr -n user.velarx-test -v kept "$upper/new" 2> /dev/null && xattr=1
    sh_ container checkpoint --export "$WORKDIR/cp.tar.zst" cpe > /dev/null
    check "checkpoint --export" exited "$(state_of cpe)"
    check "the archive is 0600" 600 "$(stat -c %a "$WORKDIR/cp.tar.zst")"
    eid=$(sh_ container inspect cpe | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    test ! -e "$XDG_DATA_HOME/velarx/bundles/$eid/checkpoint"
    check "without --keep the images go after the export" 0 $?
    last=$(sh_ container logs cpe | tail -1)
    new=$(sh_ container restore --import "$WORKDIR/cp.tar.zst" --name cpi 2>&1)
    check_match_lines "restore --import prints the new container" "^[0-9a-f]{64}$" "$new"
    check "the imported container runs" running "$(state_of cpi)"
    wait_count cpi '[0-9]+'
    first=$(sh_ container logs cpi | head -1)
    test -n "$first" && test "$first" -gt "$last"
    check "it goes on counting ($last, then $first)" 0 $?
    n=$(sh_ container logs cpi 2>&1 | wc -l)
    test "$n" -le 30 && ! sh_ container logs cpi 2>&1 | grep -q "denied"
    check "the restored processes run as before (its sleeps work: $n lines)" 0 $?
    check "a file it made is there" new "$(sh_ container exec cpi cat /new 2>&1)"
    if [ $xattr = 1 ]; then
        upper=$(sh_ container inspect --format '{{.GraphDriver.Data.UpperDir}}' cpi)
        check "with its xattr" kept "$(getfattr --absolute-names --only-values -n user.velarx-test "$upper/new" 2>&1)"
    fi
    sh_ container exec cpi test -e /etc/issue
    check "a file it removed is not" 1 $?
    # the restored processes get the new container's labels (its own MCS
    # level: the archive's is cpe's, which still exists)
    if command -v selinuxenabled > /dev/null && selinuxenabled; then
        iid=$(sh_ container inspect cpi | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
        ipid=$(sh_ container inspect cpi | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["pid"])')
        want=$(label_of "$iid")
        check "the restored process has the container's label" "$want" "$(ps -o label= -p "$ipid")"
        test "${want##*:s0:}" != "$(label_of "$eid" | sed 's/.*:s0://')"
        check "a level of its own, not the one cpe has" 0 $?
    fi
}

# A restored container.  CRIU resumes a process that was blocked
# in `nanosleep` with the call failed with EINTR (its dump.log: "Will restore
# PID with interrupted system call"), and busybox's `sleep` does not sleep
# again: a bare `sleep` exits at once (with `crun restore` alone too), and that
# is not an error of the restore: the container is restored and has exited.
# An init that keeps blocking (`tail -f`, a shell that loops) runs on.
@test "restore of a container whose init is a bare sleep" {
    skip_unless_criu
    local out
    sh_ container run -d --name rs-sleep --network none "$IMAGE" sleep 1000 > /dev/null
    check "the sleep runs" running "$(state_of rs-sleep)"
    sh_ container checkpoint rs-sleep > /dev/null
    check "checkpoint" exited "$(state_of rs-sleep)"
    out=$(sh_ container restore rs-sleep 2>&1)
    check "restore is not an error (the sleep ends at once)" rs-sleep "$out"
    wait_state rs-sleep exited 30
    check "the restored sleep exited" exited "$(state_of rs-sleep)"
    check "with status 0" 0 "$(inspect_of rs-sleep exit_code)"
    sh_ container run -d --name rs-sleep2 --network none "$IMAGE" sleep 1000 > /dev/null
    sh_ container checkpoint --export "$WORKDIR/rs-sleep.tar.gz" rs-sleep2 > /dev/null
    out=$(sh_ container restore --import "$WORKDIR/rs-sleep.tar.gz" --name rs-sleep-i 2>&1)
    check_match_lines "restore --import is not an error" "^[0-9a-f]{64}$" "$out"
    wait_state rs-sleep-i exited 30
    check "the imported sleep exited with status 0" 0 "$(inspect_of rs-sleep-i exit_code)"
    sh_ container rm -t 0 -f rs-sleep rs-sleep2 rs-sleep-i > /dev/null 2>&1
}

# In the pid namespace of the host the init's exit does not end the others: a
# restored init that exits at once (a bare `sleep`) is not an error, and the
# process that outlived it ends with the container, as any of its processes.
@test "restore with --pid host of an init that exits" {
    skip_unless_criu
    local out tail i
    mkdir "$WORKDIR/rs-host"
    sh_ container run -d --name rs-host --pid host --network none -v "$WORKDIR/rs-host:/w" "$IMAGE" \
        sh -c 'tail -f /dev/null & echo $! > /w/t; mv /w/t /w/tail; exec sleep 1000' > /dev/null
    e2e_wait_path "$WORKDIR/rs-host/tail" 30 || e2e_die "no tail in rs-host"
    tail=$(cat "$WORKDIR/rs-host/tail")
    check "the tail runs" tail "$(cat "/proc/$tail/comm")"
    sh_ container checkpoint rs-host > /dev/null
    out=$(sh_ container restore rs-host 2>&1)
    check "restore is not an error (the sleep ends at once)" rs-host "$out"
    wait_state rs-host exited 30
    # (CRIU gives back the same pids in the namespace of the host)
    for i in $(seq 50); do
        [ "$(cat "/proc/$tail/comm" 2> /dev/null)" = tail ] || break
        sleep 0.2
    done
    check "the tail left ended with the container" "" "$(cat "/proc/$tail/comm" 2> /dev/null)"
    sh_ container rm -t 0 -f rs-host > /dev/null 2>&1
}

@test "restore: a tail and a shell loop as init" {
    skip_unless_criu
    local shape name out pid
    for shape in tail shell; do
        name=rs-$shape
        if [ $shape = tail ]; then
            sh_ container run -d --name $name --network none "$IMAGE" tail -f /dev/null > /dev/null
        else
            sh_ container run -d --name $name --network none "$IMAGE" sh -c 'while :; do sleep 0.1; done' > /dev/null
        fi
        # in place
        sh_ container checkpoint $name > /dev/null
        check "$shape: checkpoint" exited "$(state_of $name)"
        out=$(sh_ container restore $name 2>&1)
        check "$shape: restore in place" $name "$out"
        check "$shape: running after the restore" running "$(state_of $name)"
        pid=$(inspect_of $name pid)
        kill -0 "$pid"
        check "$shape: the restored init is alive" 0 $?
        # --export and --import
        sh_ container checkpoint --export "$WORKDIR/$shape.tar.gz" $name > /dev/null
        out=$(sh_ container restore --import "$WORKDIR/$shape.tar.gz" --name $name-i 2>&1)
        check_match_lines "$shape: restore --import" "^[0-9a-f]{64}$" "$out"
        check "$shape: the imported container runs" running "$(state_of $name-i)"
        check "$shape: it works" ok "$(sh_ container exec $name-i sh -c 'echo ok' 2>&1)"
        sh_ container rm -t 0 -f $name $name-i > /dev/null 2>&1
    done
}

# crafted config.dump: from a plain archive of cpi, edited
@test "restore --import of an archive with a crafted config.dump" {
    skip_unless_criu
    [ "$(state_of cpi)" = running ] || { echo "needs the container cpi of the test 'checkpoint --export and restore --import'" >&2; exit 1; }
    sh_ container checkpoint --export "$WORKDIR/plain.tar" --compress none --leave-running cpi > /dev/null
    craft "$WORKDIR/c-id.tar" "req['id'] = '../../../../$WORKDIR/id-escape'; req['pidfile'] = '$WORKDIR/pid-escape'; req['conmon_pidfile'] = '$WORKDIR/cpid-escape'; d['name'] = 'cpx'"
    new=$(sh_ container restore --import "$WORKDIR/c-id.tar" 2>&1)
    check_match_lines "an id in the archive is not taken" "^[0-9a-f]{64}$" "$new"
    test ! -e "$WORKDIR/id-escape" -a ! -e "$WORKDIR/pid-escape" -a ! -e "$WORKDIR/cpid-escape"
    check "nor its pid files: nothing is written there" 0 $?
    sh_ container rm -t 0 -f cpx > /dev/null 2>&1
    for c in "privileged:req['privileged'] = True" "the mount:req['volumes'] = ['/etc:/hostetc'] " \
        "capabilities:req['cap_add'] = ['SYS_ADMIN']" "namespace:req['pid_mode'] = 'host'" \
        "security options:req['security_opt']['seccomp_unconfined'] = True"; do
        craft "$WORKDIR/c-bad.tar" "${c#*:}; d['name'] = 'cpbad'"
        out=$(sh_ container restore --import "$WORKDIR/c-bad.tar" 2>&1)
        check_match "an archive asking for ${c%%:*} is refused" "${c%%:*}" "$out"
    done
    check "and none was made" 125 "$(sh_ container inspect cpbad > /dev/null 2>&1; echo $?)"
    # A: a resolved mount of host / named after a volume; C: the parser
    # keeps the last type=; E: U on a volume; another network
    for c in "resolved form:req['volumes'] = ['v:/v']; req['mounts'] = [{'source': '/', 'target': '/host', 'mount_type': 'bind', 'volume': 'v', 'chown': True}]" \
        "the mount:req['mount'] = ['type=volume,type=bind,src=/,dst=/host']" \
        "the mount:req['volumes'] = ['v:/v:U']" \
        "networks:req['networks'] = ['othernet']"; do
        craft "$WORKDIR/c-bad.tar" "${c#*:}; d['name'] = 'cpbad'"
        out=$(sh_ container restore --import "$WORKDIR/c-bad.tar" 2>&1)
        check_match "an archive asking for ${c%%:*} is refused (${c#*:})" "${c%%:*}" "$out"
    done
    check "and none was made" 125 "$(sh_ container inspect cpbad > /dev/null 2>&1; echo $?)"
    sh_ volume create cpexisting > /dev/null
    craft "$WORKDIR/c-bad.tar" "req['volumes'] = ['cpexisting:/v']; d['name'] = 'cpbad'"
    out=$(sh_ container restore --import "$WORKDIR/c-bad.tar" 2>&1)
    check_match "an archive does not attach a volume of this host" "exists on this host" "$out"
    sh_ volume rm cpexisting > /dev/null
    # B: readonly paths do not replace the defaults
    craft "$WORKDIR/c-ro.tar" "req['security_opt']['readonly_paths'] = ['/nothing']; d['name'] = 'cpro'"
    sh_ container restore --import "$WORKDIR/c-ro.tar" > /dev/null 2>&1
    out=$(sh_ container exec cpro awk '$5 == "/proc/sys" {print $6}' /proc/self/mountinfo 2>&1)
    check_match_lines "/proc/sys stays read-only" "^ro," "$out"
    sh_ container rm -t 0 -f cpro > /dev/null 2>&1
    # D: the archive's level, as the allocator makes them and overlapping
    # no other container's, or one of its own
    if command -v selinuxenabled > /dev/null && selinuxenabled; then
        iid=$(sh_ container inspect cpi | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
        ilevel=$(label_of "$iid" | sed 's/.*:\(s0:.*\)$/\1/')
        rev=$(echo "$ilevel" | sed 's/s0:\(c[0-9]*\),\(c[0-9]*\)/s0:\2,\1/')
        for lv in "$ilevel" "$rev" "s0:c0.c1023"; do
            craft "$WORKDIR/c-lv.tar" "d['selinux_level'] = '$lv'; d['name'] = 'cplv'"
            sh_ container restore --import "$WORKDIR/c-lv.tar" > /dev/null 2>&1
            lid=$(sh_ container inspect cplv | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
            got=$(label_of "$lid" | sed 's/.*:\(s0:.*\)$/\1/')
            python3 -I - "$got" "$ilevel" << 'EOT'
import sys
def cats(l):
    return set(l.split(":", 1)[1].split(",")) if ":" in l else set()
a, b = cats(sys.argv[1]), cats(sys.argv[2])
sys.exit(1 if a <= b or b <= a else 0)
EOT
            check "the archive's level $lv (cpi's, or an alias) gives another: $got" 0 $?
            sh_ container rm -t 0 -f cplv > /dev/null 2>&1
        done
    fi
    craft "$WORKDIR/c-replace.tar" "req['replace'] = True; d['name'] = 'cpi'"
    out=$(sh_ container restore --import "$WORKDIR/c-replace.tar" 2>&1)
    check_match "replace in the archive does not remove a container" "already|exists|in use" "$out"
    check "the one of that name runs on" running "$(state_of cpi)"
}

@test "restore --import and checkpoint --export: no path of the engine, a link, a fifo, a name that is taken" {
    skip_unless_criu
    [ -s "$WORKDIR/cp.tar.zst" ] && [ "$(state_of cpi)" = running ] ||
        { echo "needs cpi and cp.tar.zst of the test 'checkpoint --export and restore --import'" >&2; exit 1; }
    # (the archive is streamed: the engine takes no path of its own)
    echo keep > "$WORKDIR/victim"
    ln -sf "$WORKDIR/victim" "$WORKDIR/link.tar"
    sh_ container checkpoint --export "$WORKDIR/link.tar" --leave-running cpi > /dev/null
    check "an export over a link replaces the link" keep "$(cat "$WORKDIR/victim")"
    test -f "$WORKDIR/link.tar" -a ! -L "$WORKDIR/link.tar"
    check "with the archive" 0 $?
    mkfifo "$WORKDIR/fifo.tar"
    out=$(timeout 10 "$SH" container restore --import "$WORKDIR/fifo.tar" 2>&1)
    check_match "a fifo is not imported" "not a regular file" "$out"
    out=$(sh_ container restore --import "$WORKDIR/cp.tar.zst" --name cpi 2>&1)
    check_match "an import under a taken name fails" "already|exists|in use" "$out"
    check "and makes no container" 1 "$(sh_ container list -a 2>/dev/null | grep -c ' cpi$\|cpi ')"
    sh_ container rm -t 0 -f cpi cpe > /dev/null
}

@test "restore --import of an archive made to escape, and of volumes" {
    skip_unless_criu
    # an archive made to escape
    python3 -I - "$WORKDIR/evil.tar" << 'EOT'
import io, sys, tarfile
with tarfile.open(sys.argv[1], "w") as t:
    for name, data in (("checkpoint/inventory.img", b"x"), ("config.dump", b"{}"), ("../../evil-escape", b"x")):
        i = tarfile.TarInfo(name)
        i.size = len(data)
        t.addfile(i, io.BytesIO(data))
EOT
    before=$(sh_ container list -aq 2> /dev/null | wc -l)
    out=$(sh_ container restore --import "$WORKDIR/evil.tar" 2>&1)
    check "a crafted archive is refused" 125 $?
    check_match "and said so" "leaves the archive" "$out"
    test ! -e "$XDG_DATA_HOME/velarx/evil-escape" -a ! -e "$XDG_DATA_HOME/evil-escape"
    check "nothing was written out of it" 0 $?
    check "no container was made" "$before" "$(sh_ container list -aq 2> /dev/null | wc -l)"
    sh_ container run -d --name cpv --network none -v cpvol:/data "$IMAGE" sleep 100 > /dev/null
    out=$(sh_ container checkpoint --export "$WORKDIR/v.tar" cpv 2>&1)
    check_match "volumes are not exported without --ignore-volumes" "ignore-volumes" "$out"
    check "and the container still runs" running "$(state_of cpv)"
    sh_ container rm -t 0 -f cpv > /dev/null
    sh_ volume rm cpvol > /dev/null 2>&1

}

# --print-stats: podman's document, with what CRIU wrote in its images
@test "checkpoint --print-stats and restore --print-stats" {
    skip_unless_criu
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    sh_ container run -d --name cps --network none --log-driver k8s-file "$IMAGE" sh -c "$count" > /dev/null
    wait_count cps 3
    id=$(inspect_of cps id)
    sh_ container checkpoint --print-stats cps > "$WORKDIR/stats.json"
    check "checkpoint --print-stats" 0 $?
    python3 -I - "$WORKDIR/stats.json" "$id" << 'EOT'
import json, sys
raw = open(sys.argv[1]).read()
d = json.loads(raw)
assert list(d) == ["podman_checkpoint_duration", "container_statistics"], list(d)
assert d["podman_checkpoint_duration"] > 0
(c,) = d["container_statistics"]
assert list(c)[:3] == ["Id", "runtime_checkpoint_duration", "criu_statistics"], list(c)
assert c["Id"] == sys.argv[2] and c["runtime_checkpoint_duration"] > 0
s = c["criu_statistics"]
assert s["pages_scanned"] > 0 and s["pages_written"] > 0 and s["frozen_time"] > 0, s
assert set(s) <= {"freezing_time", "frozen_time", "memdump_time", "memwrite_time", "pages_scanned", "pages_written"}, s
# (four spaces, as podman's)
assert raw.startswith('{\n    "podman_checkpoint_duration"'), raw
EOT
    check "the document is podman's" 0 $?
    sh_ container restore --print-stats cps > "$WORKDIR/stats.json"
    check "restore --print-stats" 0 $?
    python3 -I - "$WORKDIR/stats.json" "$id" << 'EOT'
import json, sys
d = json.load(open(sys.argv[1]))
assert list(d) == ["podman_restore_duration", "container_statistics"], list(d)
(c,) = d["container_statistics"]
assert c["Id"] == sys.argv[2] and c["runtime_restore_duration"] > 0
s = c["criu_statistics"]
assert s["restore_time"] > 0 and s["pages_restored"] > 0, s
assert set(s) <= {"pages_compared", "pages_skipped_cow", "forking_time", "restore_time", "pages_restored"}, s
EOT
    check "the restore document is podman's" 0 $?
    check "running after the restore" running "$(state_of cps)"
    sh_ container checkpoint --print-stats --export "$WORKDIR/x.tar" cps > "$WORKDIR/stats.json"
    check "--print-stats with --export" 0 $?
    test -s "$WORKDIR/x.tar" && grep -q '"podman_checkpoint_duration"' "$WORKDIR/stats.json"
    check "the archive and the document are there" 0 $?
    sh_ container rm -t 0 -f cps > /dev/null
}

# --pre-checkpoint and --with-previous: a dump of the memory with the
# container running, and the checkpoint on top of it
@test "checkpoint --pre-checkpoint, --with-previous and the restore of the chain" {
    skip_unless_criu
    if ! criu check --feature mem_dirty_track > /dev/null 2>&1; then
        out=$(sh_ container checkpoint --pre-checkpoint nothere 2>&1)
        check_match "no memory tracking is said" "memory tracking" "$out"
        skip "no memory tracking"
    fi
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    sh_ container run -d --name cpp --network none --log-driver k8s-file "$IMAGE" sh -c "$count" > /dev/null
    wait_count cpp 3
    id=$(inspect_of cpp id)
    pre=$XDG_DATA_HOME/velarx/bundles/$id/pre-checkpoint
    out=$(sh_ container checkpoint --with-previous cpp 2>&1)
    check_match "no pre-checkpoint, no --with-previous" "no pre-checkpoint" "$out"
    out=$(sh_ container checkpoint --pre-checkpoint --with-previous cpp 2>&1)
    check_match "the two do not go together" "can not be used with" "$out"
    out=$(sh_ container checkpoint --pre-checkpoint cpp 2>&1)
    check "the pre-checkpoint says the container" "cpp" "$out"
    check "the container goes on" running "$(state_of cpp)"
    check "the pre-checkpoint is 0700" 700 "$(stat -c %a "$pre")"
    test -s "$pre/inventory.img" && ls "$pre"/pages-*.img > /dev/null
    check "its images are there" 0 $?
    sh_ container checkpoint --pre-checkpoint --print-stats cpp | grep -q '"pages_written"'
    check "its statistics are CRIU's" 0 $?
    sh_ container checkpoint --with-previous --print-stats cpp > "$WORKDIR/stats.json"
    check "checkpoint --with-previous" 0 $?
    grep -q '"pages_written"' "$WORKDIR/stats.json"
    check "with statistics" 0 $?
    check "stopped by the checkpoint" exited "$(state_of cpp)"
    test -e "$XDG_DATA_HOME/velarx/bundles/$id/checkpoint/parent"
    check "the checkpoint builds on the pre-checkpoint" 0 $?
    last=$(sh_ container logs cpp | tail -1)
    sh_ container restore cpp > /dev/null
    check "restore of the chain" running "$(state_of cpp)"
    wait_count cpp $((last + 2))
    sh_ container logs cpp | awk -v l="$last" '$1 == l + 1 { found = 1 } END { exit !found }'
    check "the count goes on from where it was" 0 $?
    test ! -e "$pre"
    check "the pre-checkpoint is removed after the restore" 0 $?
    sh_ container rm -t 0 -f cpp > /dev/null
}

@test "checkpoint and restore refusals" {
    skip_unless_criu
    sh_ container run -d -t --name cpt --network none "$IMAGE" sleep 100 > /dev/null
    out=$(sh_ container checkpoint cpt 2>&1)
    check_match "a terminal is refused" "terminal" "$out"
    sh_ container rm -t 0 -f cpt > /dev/null
    sh_ container create --name cpn --network none "$IMAGE" true > /dev/null
    out=$(sh_ container restore cpn 2>&1)
    check_match "no checkpoint, no restore" "no checkpoint" "$out"
    out=$(sh_ container checkpoint --create-image img --export x.tar cpn 2>&1)
    check_match "--create-image is refused with --export" "create-image can not be used with --export" "$out"
    out=$(sh_ container restore --import-previous x.tar cpn 2>&1)
    check_match "--import-previous is refused without --import" "import-previous can only be used with --import" "$out"
    sh_ container rm cpn > /dev/null
}

# podman checkpoints a `--rm` container only with --export, and the container
# is removed once it is exported
@test "checkpoint of a --rm container needs --export, which removes it" {
    skip_unless_criu
    count='i=0; while :; do echo $i; i=$((i+1)); sleep 0.1; done'
    sh_ container run -d --rm --name cprm --network none --log-driver k8s-file "$IMAGE" sh -c "$count" > /dev/null
    wait_count cprm 3
    for opts in "" "--leave-running"; do
        rc=0
        out=$("$SH" container checkpoint $opts cprm 2>&1) || rc=$?
        check "checkpoint $opts" "125 Error: cannot checkpoint containers that have been started with '--rm' unless '--export' is used" "$rc $out"
    done
    check "refused, so it runs" running "$(state_of cprm)"
    out=$(sh_ container checkpoint --export "$WORKDIR/cprm.tar" cprm 2>&1)
    check "checkpoint --export" "0 cprm" "$? $out"
    test -s "$WORKDIR/cprm.tar"
    check "the archive is there" 0 $?
    check "and the container is gone" 0 "$(sh_ container list -a | grep -c cprm)"
    out=$(sh_ container restore --import "$WORKDIR/cprm.tar" 2>&1)
    check_match_lines "the archive restores" "^[0-9a-f]{64}$" "$out"
    # (`--rm` as the checkpointed one was: one that ended is gone already)
    check_match "a --rm container" "^(true|gone)$" \
        "$(sh_ container inspect --format '{{.HostConfig.AutoRemove}}' cprm 2> /dev/null || echo gone)"
    sh_ container rm -t 0 -f cprm > /dev/null 2>&1
    sh_ container run -d --rm --name cprm2 --network none "$IMAGE" sleep 1000 > /dev/null
    out=$(sh_ container checkpoint --leave-running --export "$WORKDIR/cprm2.tar" cprm2 2>&1)
    check "--leave-running with --export is not refused" "0 cprm2" "$? $out"
    sh_ container rm -t 0 -f cprm2 > /dev/null 2>&1
}

# A device node of an image: the root file system the container sees is the
# runtime's remount (crun 1.30 drops `nodev`, see the threat model), so as
# root the device cgroup is what refuses a node for a device the container
# does not have; rootless, the user namespace refuses every node.  The
# container's own /dev works.
@test "a device node of an image does not open a device the container does not have" {
    hostile_image
    out=$(sh_ container run --rm --network none "$EVIL" sh -c \
        'for n in null loop0; do head -c1 /evil/$n > /dev/null 2>&1 && echo "$n opens" || echo "$n refused"; done
         head -c1 /dev/null && echo "dev-null ok"' 2>&1)
    check_match "loop0 (7:0, not in the device cgroup) is refused" "^loop0 refused$" "$out"
    check_match "the /dev of the container works" "^dev-null ok$" "$out"
    if [ "$(id -u)" != 0 ]; then
        check_match "rootless: no node of the image opens" "^null refused$" "$out"
    fi
}

@test "--device works, inside /dev and outside it" {
    hostile_image
    out=$(sh_ container run --rm --network none --device /dev/null:/dev/other --device /dev/zero:/mnt/zero "$EVIL" \
        sh -c 'head -c1 /dev/other && echo "dev ok"; head -c1 /mnt/zero > /dev/null && echo "mnt ok"' 2>&1)
    check "a device in /dev and one in the root file system" "dev ok
mnt ok" "$out"
}

@test "an image mount is nodev: a device node of the mounted image does not open" {
    hostile_image
    out=$(sh_ container run --rm --network none --mount "type=image,source=$EVIL,destination=/img" "$EVIL" sh -c \
        'while read -r a b c d e f rest; do [ "$e" = /img ] && echo "mount: $f"; done < /proc/self/mountinfo
         head -c1 /img/evil/null > /dev/null 2>&1 && echo "null opens" || echo "null refused"' 2>&1)
    check_match "the image mount is nodev" "^mount: .*nodev" "$out"
    check_match "and its device node is refused" "^null refused$" "$out"
}
