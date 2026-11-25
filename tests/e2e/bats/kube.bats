# SPDX-License-Identifier: Apache-2.0
# velarx-kube (generate, play, down) against a daemon in a scratch HOME, root or
# rootless; the same YAML is read back with python's yaml.
#
#   VELARX_BINDIR=target/debug IMAGE=localhost:5000/alpine:chunked bats tests/e2e/bats/kube.bats

load helpers
. "$BATS_TEST_DIRNAME/../cleanup.sh"

# free_port: a TCP port nothing listens on now (two runs at once do not
# collide on a fixed one)
free_port () { python3 -I -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1])'; }
# y EXPR: EXPR of the documents of the YAML on stdin (`d` is the list)
y () { python3 -I -c "import sys, yaml; d = list(yaml.safe_load_all(sys.stdin)); print($1)"; }
c='d[0]["spec"]["containers"][0]'
# what a container sees: wait for the file it writes
wait_file () { # CONTAINER PATH
    sc container exec "$1" timeout 30 sh -c "until test -e '$2'; do :; done" 2> /dev/null
}
# kc ARGS: velarx-kube against the daemon of the file
kc () { "$BIN/velarx-kube" --engine-socket "$ESOCK" --no-start-engine "$@"; }
lp () { curl -s --unix-socket "$SOCK" "$@"; }
exists () { lp -o /dev/null -w '%{http_code}' "http://d/v5.0.0/libpod/$1/$2/exists"; }
status_of () { lp "http://d/v5.0.0/libpod/containers/$1/json" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["State"]["Status"])'; }
addr_of () { # container: its IPv4 address and MAC on eth0
    sc container exec "$1" sh -c 'ip -4 -o addr show eth0 | awk "{print \$4}" | cut -d/ -f1; cat /sys/class/net/eth0/address' 2>&1 | tr '\n' ' ' | sed 's/ $//'
}

setup_file () {
    e2e_setup_file
    export IMAGE=${IMAGE:-$E2E_REGISTRY/alpine:chunked}
    export P1 P2
    P1=$(free_port)
    P2=$(free_port)
    while [ "$P2" = "$P1" ]; do P2=$(free_port); done
    e2e_start_daemon
    e2e_start_api
    sc image pull --tls-verify=false "$IMAGE" > /dev/null 2>&1
}

# a failing check must not leave the network and the pods of the test on the
# host
teardown () {
    set +e
    [ ! -f "$WORKDIR/addr.yaml" ] || kc down "$WORKDIR/addr.yaml" > /dev/null 2>&1
    sc pod rm -t 0 -f -i kaddr1 kaddr2 > /dev/null 2>&1
    sc network rm -t 0 -f kaddrnet > /dev/null 2>&1
    return 0
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    local p
    sc pod rm -t 0 -f kp > /dev/null 2>&1
    e2e_remove_containers "$SH" "$ESOCK"
    for p in $(e2e_store_processes "$WORKDIR" | awk '{ print $1 }'); do kill -INT "$p" 2> /dev/null; done
    e2e_detach_mounts "$WORKDIR"
    e2e_teardown_file
}

@test "generate: a container of its own" {
    sc container run -d --name kubec --env K=V -p "$P1:80" -v kubevol:/data --cap-add NET_ADMIN \
        --memory 64m --tls-verify=false "$IMAGE" sh -c 'echo "q"; sleep 100' > /dev/null
    check "a container" 0 $?
    gen=$(kc generate kubec)
    check "kube generate" "Pod kubec-pod kubec" \
        "$(echo "$gen" | y 'd[0]["kind"], d[0]["metadata"]["name"], d[0]["spec"]["containers"][0]["name"]' | tr -d "(),'")"
    c='d[0]["spec"]["containers"][0]'
    check "the command" "['sh', '-c', 'echo \"q\"; sleep 100']" "$(echo "$gen" | y "$c[\"args\"]")"
    check "the environment of the user only" "[{'name': 'K', 'value': 'V'}]" "$(echo "$gen" | y "$c[\"env\"]")"
    check "the published port" "[{'containerPort': 80, 'hostPort': $P1}]" "$(echo "$gen" | y "$c[\"ports\"]")"
    check "the volume" "/data kubevol" \
        "$(echo "$gen" | y "$c['volumeMounts'][0]['mountPath'], d[0]['spec']['volumes'][0]['persistentVolumeClaim']['claimName']" | tr -d "(),'")"
    check "the capabilities" "['NET_ADMIN']" "$(echo "$gen" | y "$c['securityContext']['capabilities']['add']")"
    check "the memory limit" "64Mi" "$(echo "$gen" | y "$c['resources']['limits']['memory']")"
    check "the image" "$IMAGE" "$(echo "$gen" | y "$c['image']")"
    check "podman's header" "# Save the output of this file and use kubectl create -f to import" "$(echo "$gen" | head -1)"
}

# Without --no-start-engine: velarx-kube holds the engine that serves the
# socket, or starts one (in its own runtime, before it confines itself).
@test "velarx-kube holds an engine that runs, and starts one that does not" {
    sc container create --name kheld --tls-verify=false "$IMAGE" true > /dev/null
    check "a container" 0 $?
    gen=$("$BIN/velarx-kube" --engine-socket "$ESOCK" generate kheld 2>&1)
    check "with the engine of the daemon" "Pod kheld-pod" \
        "$(echo "$gen" | y 'd[0]["kind"], d[0]["metadata"]["name"]' | tr -d "(),'")"
    sc container rm kheld > /dev/null
    # an engine of a store of its own, started by velarx-kube
    local k=$WORKDIR/kstart
    mkdir -p -m 700 "$k" "$k/run"
    printf '[engine]\nsocket = "%s"\n[server]\nsocket = "%s"\nstate_dir = "%s"\nroot_dir = "%s"\n[storage]\nroot = "%s"\n' \
        "$k/run/engine.sock" "$k/run/api.sock" "$k/state" "$k/root" "$k/store" > "$k/config.toml"
    out=$("$BIN/velarx-kube" --config "$k/config.toml" --engine-socket "$k/run/engine.sock" generate knone 2>&1)
    rc=$?
    check "an engine started for it answers" 1 "$([ $rc != 0 ] && [[ "$out" == *knone* ]] && echo 1 || echo "$rc $out")"
    check "nothing panicked" "" "$(echo "$out" | grep -i panick)"
    # (it leaves with velarx-kube, which held it)
    local pid
    pid=$(e2e_service_pid "$k/run/engine.sock")
    [ -z "$pid" ] || e2e_wait_exit "$pid"
}

@test "generate: --service, --type, unknown type and name" {
    gen=$(kc generate --service kubec)
    check "--service" "Pod Service NodePort yes" \
        "$(echo "$gen" | y 'd[0]["kind"], d[1]["kind"], d[1]["spec"]["type"], "yes" if 30000 <= d[1]["spec"]["ports"][0]["nodePort"] <= 32767 else "no"' | tr -d "(),'")"
    check "--service: the pod publishes nothing itself" "[{'containerPort': 80}]" "$(echo "$gen" | y "$c[\"ports\"]")"
    gen=$(kc generate --type deployment --replicas 2 kubec)
    check "--type deployment" "Deployment kubec-pod-deployment 2" \
        "$(echo "$gen" | y 'd[0]["kind"], d[0]["metadata"]["name"], d[0]["spec"]["replicas"]' | tr -d "(),'")"
    check "--type job" "Job Never" \
        "$(kc generate --type job kubec | y 'd[0]["kind"], d[0]["spec"]["template"]["spec"]["restartPolicy"]' | tr -d "(),'")"
    kc generate --type cronjob kubec > /dev/null 2>&1
    check "an unknown type fails" 125 $?
    kc generate nosuchthing > /dev/null 2>&1
    check "a missing name fails" 125 $?
}

@test "generate: a pod, the ports of its infra container" {
    sc pod create --infra-image "$IMAGE" -p "$P2:80" --label tier=front kp > /dev/null
    # (through the libpod API, which records the member in the pod)
    curl -s --unix-socket "$SOCK" -H 'Content-Type: application/json' \
        -d "{\"image\": \"$IMAGE\", \"name\": \"kpc\", \"pod\": \"kp\", \"command\": [\"sleep\", \"100\"]}" \
        http://d/v5.0.0/libpod/containers/create > /dev/null
    gen=$(kc generate kp)
    check "kube generate of a pod" "Pod kp ['kpc'] front" \
        "$(echo "$gen" | y 'd[0]["kind"], d[0]["metadata"]["name"], [c["name"] for c in d[0]["spec"]["containers"]], d[0]["metadata"]["labels"]["tier"]' | tr -d "(),'" | sed "s/\[kpc\]/['kpc']/")"
    check "the ports of the pod" "[{'containerPort': 80, 'hostPort': $P2}]" "$(echo "$gen" | y "$c[\"ports\"]")"
}

@test "generate: a volume, its claim" {
    check "kube generate of a volume" "PersistentVolumeClaim kubevol" \
        "$(kc generate kubevol | y 'd[0]["kind"], d[0]["metadata"]["name"]' | tr -d "(),'")"
}

@test "kube play: a deployment with a ConfigMap, a Secret and volumes" {
    mkdir -p "$WORKDIR/hostdir"
    cat > "$WORKDIR/kube.yaml" <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: kubeplayvol
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kcfg
data:
  greeting: hello kube
  app.conf: "a=1"
---
apiVersion: v1
kind: Secret
metadata:
  name: ksec
stringData:
  password: hunter2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kweb
spec:
  template:
    metadata:
      labels:
        app: kweb
    spec:
      containers:
      - name: srv
        image: $IMAGE
        command: [sh, -c]
        args: ['echo "\$MSG" > /data/msg; echo "\$PW" > /data/pw; trap "exit 0" TERM; sleep 1000 & wait']
        env:
        - name: MSG
          valueFrom:
            configMapKeyRef: {name: kcfg, key: greeting}
        - name: PW
          valueFrom:
            secretKeyRef: {name: ksec, key: password}
        resources:
          limits:
            memory: 64Mi
        volumeMounts:
        - {name: data, mountPath: /data}
        - {name: scratch, mountPath: /scratch}
        - {name: conf, mountPath: /etc/app}
        - {name: host, mountPath: /host}
      volumes:
      - name: data
        persistentVolumeClaim: {claimName: kubeplayvol}
      - name: scratch
        emptyDir: {medium: Memory}
      - name: conf
        configMap:
          name: kcfg
          items:
          - {key: app.conf, path: app.conf, mode: 0600}
      - name: host
        hostPath: {path: $WORKDIR/hostdir/made, type: DirectoryOrCreate}
YAML
    out=$(kc play --tls-verify=false "$WORKDIR/kube.yaml" 2>&1)
    check "kube play" 0 $?
    check "kube play reports the pod" 1 "$(echo "$out" | grep -c '^Pod:')"
    wait_file kweb-pod-srv /data/pw || { echo "FAIL the file does not appear" >&2; exit 1; }
    check "kube play: the container runs" "hello kube" "$(sc container exec kweb-pod-srv cat /data/msg 2>&1)"
    check "kube play: a variable of a Secret" "hunter2" "$(sc container exec kweb-pod-srv cat /data/pw 2>&1)"
    check "kube play: the memory limit" 67108864 \
        "$(lp http://d/v5.0.0/libpod/containers/kweb-pod-srv/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["HostConfig"]["Memory"])')"
    check "kube play: emptyDir Memory is a tmpfs" tmpfs \
        "$(sc container exec kweb-pod-srv sh -c 'grep " /scratch " /proc/mounts | cut -d" " -f3')"
    check "kube play: a ConfigMap volume" "a=1 600" \
        "$(sc container exec kweb-pod-srv sh -c 'cat /etc/app/app.conf; echo " $(stat -c %a /etc/app/app.conf)"' | tr -d '\n')"
    check "kube play: DirectoryOrCreate made the host path" 1 "$(test -d "$WORKDIR/hostdir/made" && echo 1)"
}

@test "kube play: a subPath of a hostPath is looked up inside it" {
    h=$WORKDIR/hsub
    rm -rf "$h"
    mkdir -p "$h/dir"
    echo indir > "$h/dir/f"
    echo conf > "$h/app.conf"
    ln -s / "$h/escape"
    e2e_label_for_containers "$h"
    cat > "$WORKDIR/hsub.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: khsub
spec:
  containers:
  - name: c
    image: $IMAGE
    command: [sleep, "1000"]
    volumeMounts:
    - {name: h, mountPath: /d, subPath: dir}
    - {name: h, mountPath: /etc/app.conf, subPath: app.conf, readOnly: true}
    - {name: h, mountPath: /e, subPath: escape}
  volumes:
  - name: h
    hostPath: {path: $h}
YAML
    kc play --tls-verify=false "$WORKDIR/hsub.yaml" > /dev/null
    check "kube play" 0 $?
    check "a directory of the host path" indir "$(sc container exec khsub-c cat /d/f 2>&1)"
    check "a file of the host path" conf "$(sc container exec khsub-c cat /etc/app.conf 2>&1)"
    check "a link to / is the host path" "ok" \
        "$(sc container exec khsub-c sh -c 'test -f /e/app.conf && test ! -e /e/usr && echo ok' 2>&1)"
    # a link put in place of the directory after the play: the next start
    # looks the sub path up inside the host path again
    sc container stop -t 0 khsub-c > /dev/null
    rm -rf "$h/dir"
    ln -s /etc "$h/dir"
    out=$(sc container start khsub-c 2>&1)
    rc=$?
    check "the start through a link that leads out fails" 1 "$(test $rc -ne 0 && echo 1)"
    check_match "the start says why" "has no dir" "$out"
    kc down "$WORKDIR/hsub.yaml" > /dev/null
}

@test "kube play of an existing pod fails, --replace and --start=false" {
    kc play --tls-verify=false "$WORKDIR/kube.yaml" > /dev/null 2>&1
    check "kube play of an existing pod fails" 125 $?
    kc play --tls-verify=false --replace --start=false "$WORKDIR/kube.yaml" > /dev/null
    check "kube play --replace" 0 $?
    check "kube play --start=false" created "$(status_of kweb-pod-srv)"
    mp=$(lp http://d/v5.0.0/libpod/volumes/kubeplayvol/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["Mountpoint"])')
    check "the volume kept its data" "hello kube" "$(cat "$mp/msg" 2>&1)"
}

@test "kube down" {
    sid=$(lp http://d/v5.0.0/libpod/secrets/ksec/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["ID"])')
    out=$(kc down "$WORKDIR/kube.yaml")
    check "kube down" 0 $?
    check "kube down removes the pod" 404 "$(exists pods kweb-pod)"
    check "kube down keeps the volume" 204 "$(exists volumes kubeplayvol)"
    # as podman: the secrets of the documents go, every heading is printed
    check "kube down removes the secret" 404 "$(exists secrets ksec)"
    check_match "kube down prints podman's report" \
        "^Pods stopped:.*Pods removed:.*Secrets removed: $sid Volumes removed:\$" "$(echo $out)"
}

@test "kube play skips a Service, so it plays what kube generate -s wrote; auto-update and the unit are labels" {
    cat > "$WORKDIR/svc.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ksvc
  labels: {app: ksvc}
  annotations:
    io.containers.autoupdate: registry
    io.containers.autoupdate/c2: local
spec:
  containers:
  - name: c
    image: $IMAGE
    command: [sleep, "1000"]
    ports: [{containerPort: 80, hostPort: $P2}]
  - name: c2
    image: $IMAGE
    command: [sleep, "1000"]
YAML
    PODMAN_SYSTEMD_UNIT=kube-ksvc.service kc play --tls-verify=false "$WORKDIR/svc.yaml" > /dev/null
    check "play" 0 $?
    check "the label of the pod's annotation" "registry" \
        "$(sc container inspect --format '{{index .Config.Labels "io.containers.autoupdate"}}' ksvc-c)"
    check "the label of the container's own annotation" "local" \
        "$(sc container inspect --format '{{index .Config.Labels "io.containers.autoupdate"}}' ksvc-c2)"
    check "the labels of the pod" "ksvc" \
        "$(sc container inspect --format '{{index .Config.Labels "app"}}' ksvc-c2)"
    check "the unit" "kube-ksvc.service" \
        "$(sc container inspect --format '{{index .Config.Labels "PODMAN_SYSTEMD_UNIT"}}' ksvc-c)"
    kc generate --service ksvc > "$WORKDIR/svc-gen.yaml"
    check "the generated file has a Service" "Service" "$(y 'd[1]["kind"]' < "$WORKDIR/svc-gen.yaml")"
    kc down "$WORKDIR/svc.yaml" > /dev/null
    kc play --tls-verify=false "$WORKDIR/svc-gen.yaml" > /dev/null 2>&1
    check "kube play of kube generate --service" 0 $?
    kc down "$WORKDIR/svc-gen.yaml" > /dev/null 2>&1
}

@test "a round trip: generate what play made, take it down, play the generated" {
    cat > "$WORKDIR/rt.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: rt
spec:
  containers:
  - name: c
    image: $IMAGE
    command: [sh, -c, 'echo "\$K" > /tmp/k; trap "exit 0" TERM; sleep 1000 & wait']
    env:
    - {name: K, value: round}
    volumeMounts:
    - {name: v, mountPath: /v}
    securityContext:
      capabilities:
        add: [NET_ADMIN]
  volumes:
  - name: v
    persistentVolumeClaim: {claimName: kubeplayvol}
YAML
    kc play --tls-verify=false "$WORKDIR/rt.yaml" > /dev/null
    kc generate rt > "$WORKDIR/rt-gen.yaml"
    kc down "$WORKDIR/rt.yaml" > /dev/null
    kc play --tls-verify=false "$WORKDIR/rt-gen.yaml" > /dev/null
    check "kube play of what generate wrote" 0 $?
    wait_file rt-c /tmp/k || { echo "FAIL the file does not appear" >&2; exit 1; }
    check "the round trip keeps the command and the environment" round "$(sc container exec rt-c cat /tmp/k 2>&1)"
    capeff=$(sc container exec rt-c grep CapEff /proc/self/status | awk '{print $2}')
    check "and the capability (NET_ADMIN)" 1 "$(python3 -I -c 'import sys; print(int(sys.argv[1], 16) >> 12 & 1)' "${capeff:-0}")"
    kc down "$WORKDIR/rt-gen.yaml" > /dev/null
}

@test "a second play, replace, down, bad YAML, an alias bomb, an unknown kind" {
    out=$(kc play --tls-verify=false "$WORKDIR/rt.yaml" 2>&1)
    check "a play" 0 $?
    check_match "prints the pod and its container" "^Pod:.*Container:" "$(echo $out)"
    kc play --tls-verify=false "$WORKDIR/rt.yaml" > /dev/null 2>&1
    check "a second play fails" 125 $?
    kc play --tls-verify=false --replace "$WORKDIR/rt.yaml" > /dev/null
    check "--replace" 0 $?
    out=$(kc down "$WORKDIR/rt.yaml")
    check "kube down" 0 $?
    check_match "prints podman's report" "^Pods stopped:.*Pods removed:" "$(echo $out)"
    check "and the pod is gone" 404 "$(exists pods rt)"
    printf 'a: [' > "$WORKDIR/bad.yaml"
    kc play "$WORKDIR/bad.yaml" > /dev/null 2>&1
    check "bad YAML fails" 125 $?
    bomb='a0: &a0 [x, x]'
    for i in $(seq 1 30); do bomb="$bomb
a$i: &a$i [*a$((i - 1)), *a$((i - 1))]"; done
    printf '%s\n' "$bomb" > "$WORKDIR/bomb.yaml"
    kc play "$WORKDIR/bomb.yaml" > /dev/null 2>&1
    check "an alias bomb fails" 125 $?
    printf 'kind: CronJob\nmetadata:\n  name: x\n' | kc play - > /dev/null 2>&1
    check "an unknown kind fails" 125 $?
}

@test "kube down --force removes the volumes" {
    kc down --force "$WORKDIR/kube.yaml" > /dev/null
    check "kube down --force removes the volumes" 404 "$(exists volumes kubeplayvol)"
}

@test "--ip and --mac-address: the n-th to the n-th pod" {
    cat > "$WORKDIR/addr.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: kaddr1
spec:
  containers:
  - name: c
    image: $IMAGE
    command: [sh, -c, 'trap "exit 0" TERM; sleep 1000 & wait']
---
apiVersion: v1
kind: Pod
metadata:
  name: kaddr2
spec:
  containers:
  - name: c
    image: $IMAGE
    command: [sh, -c, 'trap "exit 0" TERM; sleep 1000 & wait']
YAML
    skip_unless_bridges
    check "network create" 0 "$(sc network create --subnet 10.213.30.0/24 kaddrnet > /dev/null 2>&1; echo $?)"
    kc play --network kaddrnet --ip 10.213.30.20,10.213.30.21 --mac-address 02:13:30:00:00:20 \
        "$WORKDIR/addr.yaml" > /dev/null 2>&1
    check "kube play --ip --mac-address" 0 $?
    check "the first pod has the first address and MAC" "10.213.30.20 02:13:30:00:00:20" "$(addr_of kaddr1-c)"
    check_match "the second the second address, a MAC picked" "^10.213.30.21 " "$(addr_of kaddr2-c)"
    kc down "$WORKDIR/addr.yaml" > /dev/null
    kc play --ip nope "$WORKDIR/addr.yaml" > /dev/null 2>&1
    check "an invalid address fails" 125 $?
}

@test "the API serves no kube route, velarx kube is the program velarx-kube" {
    for route in "POST play/kube" "POST kube/play" "DELETE play/kube" "POST kube/apply" "GET generate/kube?names=kubec" "GET kube/generate?names=kubec"; do
        code=$(lp -o "$WORKDIR/k.json" -w '%{http_code}' -X "${route%% *}" "http://d/v5.0.0/libpod/${route#* }")
        check "$route is 501" 501 "$code"
        check_match "and says where the command is" "velarx-kube" "$(cat "$WORKDIR/k.json")"
    done
    out=$("$SH" kube --version 2>&1)
    check "velarx kube runs velarx-kube" 0 $?
    check_match "and it is velarx-kube" "velarx-kube" "$out"
}

@test "init containers and the annotations of podman" {
    cat > "$WORKDIR/init.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: kinit
  annotations:
    io.podman.annotations.ulimit/main: nofile=1024:1024
    io.podman.annotations.init/main: "true"
spec:
  initContainers:
  - name: setup
    image: $IMAGE
    command: [sh, -c, 'echo initialized > /v/ready']
    volumeMounts:
    - {name: v, mountPath: /v}
  containers:
  - name: main
    image: $IMAGE
    command: [sh, -c, 'cat /v/ready > /tmp/seen; trap "exit 0" TERM; sleep 1000 & wait']
    volumeMounts:
    - {name: v, mountPath: /v}
  volumes:
  - name: v
    persistentVolumeClaim: {claimName: kinitvol}
YAML
    out=$(kc play --tls-verify=false "$WORKDIR/init.yaml" 2>&1)
    check "kube play with an init container" 0 $?
    check "and prints the container of the pod" 1 "$(echo "$out" | grep -c '^Container:')"
    wait_file kinit-main /tmp/seen || { echo "FAIL the file does not appear" >&2; exit 1; }
    check "the init container ran first" initialized "$(sc container exec kinit-main cat /tmp/seen 2>&1)"
    check "and is gone (once)" 404 "$(lp -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/containers/kinit-setup/exists)"
    check "io.podman.annotations.ulimit" "1024 1024" \
        "$(sc container exec kinit-main sh -c 'grep "open files" /proc/1/limits' 2>&1 | awk '{print $4, $5}')"
    check "io.podman.annotations.init: an init is PID 1" 1 \
        "$(test "$(sc container exec kinit-main cat /proc/1/comm 2>&1)" != sh && echo 1)"
    kc down --force "$WORKDIR/init.yaml" > /dev/null
}

@test "a failing init container and an annotation that is not supported" {
    cat > "$WORKDIR/badinit.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: kbadinit
spec:
  initContainers:
  - name: fail
    image: $IMAGE
    command: [sh, -c, 'exit 3']
  containers:
  - name: main
    image: $IMAGE
    command: [sh, -c, 'trap "exit 0" TERM; sleep 1000 & wait']
YAML
    out=$(kc play --tls-verify=false "$WORKDIR/badinit.yaml" 2>&1)
    check "a failing init container fails the play" 125 $?
    check_match "and says which" "the init container kbadinit-fail exited with 3" "$out"
    check "and leaves no pod" 404 "$(exists pods kbadinit)"
    printf 'kind: Pod\nmetadata:\n  name: kann\n  annotations:\n    io.podman.annotations.volumes-from/c: x\nspec:\n  containers:\n  - {name: c, image: %s}\n' "$IMAGE" > "$WORKDIR/ann.yaml"
    kc play "$WORKDIR/ann.yaml" > /dev/null 2>&1
    check "an annotation of podman that is not supported fails" 125 $?
}

@test "validate" {
    printf 'kind: Pod\nmetadata:\n  name: kval\nspec:\n  containers:\n  - name: c\n    image: %s\n    command: [sh, -c, \x27trap \"exit 0\" TERM; sleep 1000 & wait\x27]\n    bogusfield: nope\n' "$IMAGE" > "$WORKDIR/val.yaml"
    out=$(kc play --tls-verify=false "$WORKDIR/val.yaml" 2>&1)
    check "an unknown field is refused" 125 $?
    check_match "naming it" "bogusfield" "$out"
    check "and makes nothing" 404 "$(exists pods kval)"
}

@test "kube play: probes, stopSignal, --publish-all, --no-pod-prefix, --no-hosts, --no-hostname" {
    P3=$(free_port)
    cat > "$WORKDIR/opts.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: kopt
spec:
  hostUsers: true
  containers:
  - name: koptc
    image: $IMAGE
    command: [sh, -c, 'trap "exit 0" USR1 TERM; sleep 1000 & wait']
    ports:
    - containerPort: $P3
    livenessProbe:
      tcpSocket: {port: $P3}
      periodSeconds: 30
    startupProbe:
      exec: {command: ["true"]}
    readinessProbe:
      httpGet: {port: $P3}
    lifecycle: {stopSignal: SIGUSR1}
YAML
    kc play --tls-verify=false --publish-all --no-pod-prefix --no-hosts --no-hostname "$WORKDIR/opts.yaml" > /dev/null
    check "kube play with the options" 0 $?
    check "--no-pod-prefix: the container is named as in the YAML" 204 "$(exists containers koptc)"
    lp http://d/v5.0.0/libpod/containers/koptc/json > "$WORKDIR/koptc.json"
    check "the liveness probe is a health check" "CMD-SHELL nc -z -v 'localhost' $P3 || exit 1" \
        "$(python3 -I -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1]))["Config"]["Healthcheck"]["Test"]))' "$WORKDIR/koptc.json")"
    check "the startup probe" "CMD true" \
        "$(python3 -I -c 'import json, sys; print(" ".join(json.load(open(sys.argv[1]))["Config"]["StartupHealthCheck"]["Test"]))' "$WORKDIR/koptc.json" 2>&1)"
    check "lifecycle.stopSignal" SIGUSR1 \
        "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["Config"]["StopSignal"])' "$WORKDIR/koptc.json")"
    check_match "--publish-all publishes the containerPort" "\"$P3/tcp\"" \
        "$(lp http://d/v5.0.0/libpod/pods/kopt/json | python3 -I -c 'import json, sys; print(json.dumps(json.load(sys.stdin)["InfraConfig"]["PortBindings"]))')"
    check "--no-hosts: the image's /etc/hosts" 0 "$(sc container exec koptc grep -c kopt /etc/hosts)"
    check "--no-hostname: the image's /etc/hostname" 1 "$(test "$(sc container exec koptc cat /etc/hostname)" != kopt && echo 1)"
    kc down "$WORKDIR/opts.yaml" > /dev/null
    check "and down" 404 "$(exists pods kopt)"
}

@test "kube play: what it refuses, runAsNonRoot and --context-dir" {
    printf 'kind: Pod\nmetadata:\n  name: knonroot\nspec:\n  securityContext: {runAsNonRoot: true}\n  containers:\n  - {name: c, image: %s}\n' "$IMAGE" > "$WORKDIR/nonroot.yaml"
    out=$(kc play --tls-verify=false "$WORKDIR/nonroot.yaml" 2>&1)
    check "runAsNonRoot with an image of root fails" 125 $?
    check_match "and says why" "runAsNonRoot" "$out"
    check "and makes no pod" 404 "$(exists pods knonroot)"
    printf 'kind: Pod\nmetadata:\n  name: kgrpc\nspec:\n  containers:\n  - {name: c, image: %s, livenessProbe: {grpc: {port: 9}}}\n' "$IMAGE" > "$WORKDIR/grpc.yaml"
    check_match "a gRPC probe is refused by name" "gRPC livenessProbe of c is not supported" \
        "$(kc play "$WORKDIR/grpc.yaml" 2>&1)"
    out=$(kc play --force "$WORKDIR/grpc.yaml" 2>&1)
    check "--force is an option of down" 2 $?
    out=$(kc play --context-dir "$WORKDIR" "$WORKDIR/grpc.yaml" 2>&1)
    check "--context-dir without --build" "125 Error: --build must be specified when using --context-dir option" "$? $out"
    kc play --authfile "$WORKDIR/nosuch.json" "$WORKDIR/grpc.yaml" > /dev/null 2>&1
    check "a missing --authfile" 125 $?
}

# The credentials of the images are resolved before velarx-kube confines
# itself, where it can run no program: a credential helper of --authfile
# is asked, for the pull (Always) and the play goes on.
@test "kube play: a credential helper of --authfile is run before the confinement" {
    local h=$WORKDIR/helpers
    mkdir -p "$h"
    printf '#!/bin/sh\nread server\necho "$server" >> "%s/helper.log"\nprintf %s\n' \
        "$WORKDIR" "'{\"Username\":\"u\",\"Secret\":\"s\"}'" > "$h/docker-credential-kubefake"
    chmod +x "$h/docker-credential-kubefake"
    printf '{"credHelpers": {"%s": "kubefake"}}' "${IMAGE%%/*}" > "$WORKDIR/helper-auth.json"
    printf 'kind: Pod\nmetadata:\n  name: khelper\nspec:\n  containers:\n  - {name: c, image: %s, imagePullPolicy: Always, command: [true]}\n' "$IMAGE" > "$WORKDIR/helper.yaml"
    out=$(PATH=$h:$PATH kc play --tls-verify=false --start=false --authfile "$WORKDIR/helper-auth.json" "$WORKDIR/helper.yaml" 2>&1)
    check "the play succeeds" 0 $?
    if [ "$(id -u)" = 0 ]; then
        # root looks for its helpers in a fixed path, never in $PATH: the
        # helper of $PATH is not asked (the registry takes no credentials)
        check "root does not run a helper of \$PATH" "" "$(cat "$WORKDIR/helper.log" 2> /dev/null)"
    else
        check_match "the helper was asked for the registry" "^${IMAGE%%/*}$" "$(cat "$WORKDIR/helper.log" 2> /dev/null)"
    fi
    kc down "$WORKDIR/helper.yaml" > /dev/null 2>&1
}

@test "kube play --build and --context-dir, and the build of a missing image" {
    B=$WORKDIR/clibuild
    mkdir -p "$B/kbuilt"
    printf 'FROM %s\nLABEL from="cli-build"\n' "$IMAGE" > "$B/kbuilt/Containerfile"
    printf 'kind: Pod\nmetadata:\n  name: kcli\nspec:\n  containers:\n  - name: c\n    image: localhost/kbuilt:1\n    imagePullPolicy: Never\n    command: [sh, -c, \x27trap "exit 0" TERM; sleep 1000 & wait\x27]\n' > "$WORKDIR/build.yaml"
    kc play --build --context-dir "$B" "$WORKDIR/build.yaml" > /dev/null
    check "kube play --build --context-dir" 0 $?
    check "the image was built from the directory" cli-build \
        "$(lp http://d/v5.0.0/libpod/containers/kcli-c/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["Config"]["Labels"]["from"])' 2>&1)"
    kc down "$WORKDIR/build.yaml" > /dev/null
    sc image rm localhost/kbuilt:1 > /dev/null
    kc play --build=false --context-dir "$B" "$WORKDIR/build.yaml" > /dev/null 2>&1
    check "--build=false builds nothing" 125 $?
    (cd "$B" && kc play "$WORKDIR/build.yaml" > /dev/null)
    check "a missing image is built from the current directory" cli-build \
        "$(lp http://d/v5.0.0/libpod/containers/kcli-c/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["Config"]["Labels"]["from"])' 2>&1)"
    kc down "$WORKDIR/build.yaml" > /dev/null
}

@test "kube play --build: the context directory is a link with a name that a shell trips on" {
    # the directory is opened by kube, and the engine is given the descriptor:
    # the link is followed once, by the user's process, and nothing is looked
    # up by path afterwards
    B="$WORKDIR/odd ctx"
    mkdir -p "$B/real/kodd"
    printf 'data from the context\n' > "$B/real/kodd/-file name"
    printf 'FROM %s\nCOPY ["-file name", "/data"]\nLABEL from="fd-build"\n' "$IMAGE" > "$B/real/kodd/Containerfile"
    ln -s "$B/real" "$B/link to ctx"
    printf 'kind: Pod\nmetadata:\n  name: kfd\nspec:\n  containers:\n  - name: c\n    image: localhost/kodd:1\n    imagePullPolicy: Never\n    command: [sh, -c, \x27trap "exit 0" TERM; sleep 1000 & wait\x27]\n' > "$WORKDIR/fd.yaml"
    kc play --build --context-dir "$B/link to ctx" "$WORKDIR/fd.yaml" > /dev/null
    check "kube play --build with a context that is a link" 0 $?
    check "the image was built from the directory the link names" fd-build \
        "$(lp http://d/v5.0.0/libpod/containers/kfd-c/json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["Config"]["Labels"]["from"])' 2>&1)"
    check "its files are the directory's" "data from the context" \
        "$(sc container exec kfd-c cat /data 2>&1)"
    kc down "$WORKDIR/fd.yaml" > /dev/null
    sc image rm localhost/kodd:1 > /dev/null
    # an image whose directory is a link is not built (it would name a
    # place outside the context)
    mv "$B/real/kodd" "$B/kodd-real"
    ln -s "$B/kodd-real" "$B/real/kodd"
    kc play --build --context-dir "$B/link to ctx" "$WORKDIR/fd.yaml" > /dev/null 2>&1
    check "a directory of an image that is a link is not a context" 125 $?
}

@test "kube play --build: RUN mounts of the context come from the descriptor, in place" {
    # the directory is never copied: a step binds the node of the descriptor
    # (a directory, a file, a link inside the context), one that writes gets
    # an overlay or a copy and the user's tree stays as it was, a link out of
    # the context is not followed, and the label of the tree is not changed
    B="$WORKDIR/inplace ctx"
    mkdir -p "$B/img/src/deep dir"
    printf 'from the tree\n' > "$B/img/src/inner"
    # (a file named as its directory: the directory is what is mounted)
    printf 'not this\n' > "$B/img/src/src"
    printf 'odd\n' > "$B/img/src/deep dir/-file name"
    printf 'fl\n' > "$B/img/flat"
    ln -s src/inner "$B/img/link-inner"
    ln -s /etc/hostname "$B/img/link-out"
    cat > "$B/img/Containerfile" <<EOF
FROM $IMAGE
COPY ["src/deep dir/-file name", "/data"]
RUN --mount=type=bind,target=/ctx cat /ctx/src/inner /ctx/link-inner > /seen && ls /ctx | sort >> /seen
RUN --mount=type=bind,source=src,target=/sub cat /sub/inner >> /seen
RUN --mount=type=bind,source=flat,target=/one cat /one >> /seen
RUN --mount=type=bind,source=link-inner,target=/via cat /via >> /seen
RUN --mount=type=bind,source=src,target=/rw,rw sh -c 'echo changed > /rw/inner && echo made > /rw/new && cat /rw/inner >> /seen'
RUN --mount=type=bind,source=flat,target=/rwfile,rw sh -c 'echo changed > /rwfile && cat /rwfile >> /seen'
LABEL from="inplace"
EOF
    printf 'kind: Pod\nmetadata:\n  name: kin\nspec:\n  containers:\n  - name: c\n    image: localhost/img:1\n    imagePullPolicy: Never\n    command: [sh, -c, \x27trap "exit 0" TERM; sleep 1000 & wait\x27]\n' > "$WORKDIR/in.yaml"
    kc play --build --context-dir "$B" "$WORKDIR/in.yaml" > "$WORKDIR/in.out" 2>&1
    rc=$?
    [ $rc = 0 ] || cat "$WORKDIR/in.out"
    check "kube play --build with RUN mounts of the context" 0 $rc
    check "what the steps saw" "from the tree
from the tree
Containerfile
flat
link-inner
link-out
src
from the tree
fl
from the tree
changed
changed" "$(sc container exec kin-c cat /seen 2>&1)"
    check "COPY of a name that starts with a dash" odd "$(sc container exec kin-c cat /data 2>&1)"
    check "the tree was not written by an overlay" "from the tree" "$(cat "$B/img/src/inner")"
    check "nor by the copy of a file" fl "$(cat "$B/img/flat")"
    check "and nothing was made in it" "Containerfile flat link-inner link-out src" "$(cd "$B/img" && echo *)"
    kc down "$WORKDIR/in.yaml" > /dev/null
    # a link that leaves the context is no source (the build does not follow it
    # out of the tree), and says so
    printf 'FROM %s\nRUN --mount=type=bind,source=link-out,target=/x cat /x\n' "$IMAGE" > "$B/img/Containerfile"
    kc play --build --context-dir "$B" "$WORKDIR/in.yaml" > "$WORKDIR/in.out" 2>&1
    check "a link out of the context is not a source" 125 $?
    check_match "and the error names the mount" "the source of the mount at /x" "$(cat "$WORKDIR/in.out")"
    sc image rm localhost/img:1 > /dev/null
}

@test "kube play --build: the directory play opened is built from when its path is swapped" {
    # a step of the build (the download of ADD) moves the directory away,
    # puts another one at its path and changes a file of the moved one: the
    # steps after it read the directory play opened, as it is then
    B="$WORKDIR/swap ctx"
    mkdir -p "$B/img"
    printf 'original\n' > "$B/img/data"
    printf 'before\n' > "$B/img/later"
    cat > "$WORKDIR/gate.py" << 'EOT'
import http.server, os, sys
base = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if not os.path.exists(base + "/img.moved"):
            os.rename(base + "/img", base + "/img.moved")
            os.mkdir(base + "/img")
            with open(base + "/img/data", "w") as f:
                f.write("decoy\n")
            with open(base + "/img/Containerfile", "w") as f:
                f.write("FROM scratch\n")
            with open(base + "/img.moved/later", "w") as f:
                f.write("after\n")
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"gate\n")
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
print(s.server_port, flush=True)
s.serve_forever()
EOT
    python3 -I "$WORKDIR/gate.py" "$B" > "$WORKDIR/gate.port" 3>&- &
    gate_pid=$!
    e2e_wait_line "$WORKDIR/gate.port" . 10
    cat > "$B/img/Containerfile" <<EOF
FROM $IMAGE
ADD http://127.0.0.1:$(cat "$WORKDIR/gate.port")/gate /gate
COPY data later /got/
RUN --mount=type=bind,target=/ctx cat /ctx/data /ctx/later > /mounted
EOF
    printf 'kind: Pod\nmetadata:\n  name: ksw\nspec:\n  containers:\n  - name: c\n    image: localhost/img:1\n    imagePullPolicy: Never\n    command: [sh, -c, \x27trap "exit 0" TERM; sleep 1000 & wait\x27]\n' > "$WORKDIR/sw.yaml"
    kc play --build --context-dir "$B" "$WORKDIR/sw.yaml" > "$WORKDIR/sw.out" 2>&1
    rc=$?
    kill -TERM "$gate_pid"
    wait "$gate_pid" 2>/dev/null
    [ $rc = 0 ] || cat "$WORKDIR/sw.out"
    check "kube play --build with the path swapped during the build" 0 $rc
    check "the download ran after the open" gate "$(sc container exec ksw-c cat /gate 2>&1)"
    check "COPY read the directory that was opened, as it is then" "original
after" "$(sc container exec ksw-c cat /got/data /got/later 2>&1)"
    check "and so did the mount of a RUN" "original
after" "$(sc container exec ksw-c cat /mounted 2>&1)"
    check "the directory at the path was not read" "decoy" "$(cat "$B/img/data")"
    kc down "$WORKDIR/sw.yaml" > /dev/null
    sc image rm localhost/img:1 > /dev/null
}

@test "kube play --wait: down when the pods exit, and on SIGINT" {
    printf 'kind: Pod\nmetadata:\n  name: kwait\nspec:\n  restartPolicy: Never\n  containers:\n  - {name: c, image: %s, command: [sh, -c, "exit 0"]}\n' "$IMAGE" > "$WORKDIR/wait.yaml"
    out=$(kc play --wait --tls-verify=false "$WORKDIR/wait.yaml" 2>&1)
    check "kube play --wait ends with the pod" 0 $?
    check_match "and cleans up" "Cleaning up containers, pods, and volumes" "$out"
    check "the pod is gone" 404 "$(exists pods kwait)"
    printf 'kind: Pod\nmetadata:\n  name: kwait2\nspec:\n  containers:\n  - {name: c, image: %s, command: [sh, -c, \x27trap "exit 0" TERM; sleep 1000 & wait\x27]}\n' "$IMAGE" > "$WORKDIR/wait2.yaml"
    # (the command itself, not the function: the signal goes to its process)
    "$BIN/velarx-kube" --engine-socket "$ESOCK" --no-start-engine play -w --tls-verify=false "$WORKDIR/wait2.yaml" > "$WORKDIR/wait2.out" 2>&1 &
    pid=$!
    e2e_wait_condition kwait2-c running 30
    kill -INT "$pid"
    wait "$pid"
    check "SIGINT ends kube play --wait" 0 $?
    check_match "and cleans up" "Cleaning up containers, pods, and volumes" "$(cat "$WORKDIR/wait2.out")"
    check "the pod is gone" 404 "$(exists pods kwait2)"
}

@test "kube apply: a file, and the YAML of what exists" {
    # the documents go to the API server of the kubeconfig's cluster (a fake
    # one here, over HTTP)
    cat > "$WORKDIR/fake-k8s.py" << 'EOT'
import http.server, sys
log = open(sys.argv[1], "a")
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        auth = self.headers.get("Authorization") == "Bearer secret-token"
        log.write(f"{self.path} {self.headers.get('Content-Type')} {body.count('replicas: 3')} {auth}\n")
        log.flush()
        self.send_response(201)
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
print(s.server_port, flush=True)
s.serve_forever()
EOT
    : > "$WORKDIR/k8s.log"
    python3 -I "$WORKDIR/fake-k8s.py" "$WORKDIR/k8s.log" > "$WORKDIR/k8s.port" 3>&- &
    k8s_pid=$!
    e2e_wait_line "$WORKDIR/k8s.port" . 10
    printf 'apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: http://127.0.0.1:%s\nusers:\n- name: u\n  user:\n    token: secret-token\n' \
        "$(cat "$WORKDIR/k8s.port")" > "$WORKDIR/kubeconfig"
    printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: kp\nspec:\n  replicas: 3\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: ks\n' > "$WORKDIR/apply.yaml"
    out=$(kc apply --kubeconfig "$WORKDIR/kubeconfig" --ns ns1 -f "$WORKDIR/apply.yaml")
    check "kube apply" 0 $?
    check "and answers podman's" "Deployed!" "$out"
    check "the service first, then the pod, as written, with the token" \
        "/api/v1/namespaces/ns1/services application/yaml 0 True,/api/v1/namespaces/ns1/pods application/yaml 1 True," \
        "$(tr '\n' ',' < "$WORKDIR/k8s.log")"
    : > "$WORKDIR/k8s.log"
    KUBECONFIG=$WORKDIR/kubeconfig kc apply kubec > /dev/null
    check "kube apply of a container" 0 $?
    check "makes a request" 1 "$(wc -l < "$WORKDIR/k8s.log")"
    printf 'kind: Deployment\nmetadata:\n  name: d\n' > "$WORKDIR/apply-bad.yaml"
    out=$(kc apply --kubeconfig "$WORKDIR/kubeconfig" -f "$WORKDIR/apply-bad.yaml" 2>&1)
    check "an unsupported kind is refused" 125 $?
    check_match "and says so" "unsupported Kubernetes kind" "$out"
    kc apply -f "$WORKDIR/apply.yaml" > /dev/null 2>&1
    check "without a kubeconfig it fails" 125 $?
    kill "$k8s_pid" 2> /dev/null
    wait "$k8s_pid" 2> /dev/null
}

@test "kube generate --podman-only" {
    sc container create --name kgenpo --init --tls-verify=false "$IMAGE" sleep 100 > /dev/null
    check "without --podman-only podman's own annotations are left out" None \
        "$(kc generate kgenpo | y 'd[0]["metadata"].get("annotations")')"
    check "--podman-only adds them" TRUE \
        "$(kc generate --podman-only kgenpo | y 'd[0]["metadata"]["annotations"]["io.podman.annotations.init/kgenpo"]')"
    sc container rm -t 0 -f kgenpo > /dev/null
}

@test "kube play: an init container of type always runs at each start of the pod" {
    cat > "$WORKDIR/always.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: kalways
  annotations:
    io.podman.annotations.init.container.type/setup: always
spec:
  initContainers:
  - name: setup
    image: $IMAGE
    command: [sh, -c, 'echo run >> /v/log']
    volumeMounts:
    - {name: v, mountPath: /v}
  containers:
  - name: main
    image: $IMAGE
    command: [sh, -c, 'trap "exit 0" TERM; sleep 1000 & wait']
    volumeMounts:
    - {name: v, mountPath: /v}
  volumes:
  - name: v
    persistentVolumeClaim: {claimName: kalwaysvol}
YAML
    kc play --tls-verify=false "$WORKDIR/always.yaml" > /dev/null 2>&1
    check "kube play with an init container of type always" 0 $?
    check "it is kept" 204 "$(exists containers kalways-setup)"
    check "it ran once" 1 "$(sc container exec kalways-main wc -l /v/log 2>&1 | awk '{print $1}')"
    sc pod restart kalways > /dev/null 2>&1
    check "the pod restarted" 0 $?
    check "it ran again" 2 "$(sc container exec kalways-main wc -l /v/log 2>&1 | awk '{print $1}')"
    kc down --force "$WORKDIR/always.yaml" > /dev/null
}

@test "kube play: --annotation labels for auto-update, and the YAML can be an http address" {
    cat > "$WORKDIR/web.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: kweb
spec:
  containers:
  - name: c
    image: $IMAGE
    command: [sleep, "1000"]
YAML
    local port; port=$(free_port)
    python3 -I -m http.server --bind 127.0.0.1 --directory "$WORKDIR" "$port" > /dev/null 2>&1 &
    local srv=$!
    until curl -s -o /dev/null "http://127.0.0.1:$port/web.yaml"; do sleep 0.1; done
    kc play --tls-verify=false --annotation io.containers.autoupdate=registry "http://127.0.0.1:$port/web.yaml" > /dev/null 2>&1
    check "play of an http address" 0 $?
    check "--annotation is an annotation of the pod: the label of auto-update" "registry" \
        "$(sc container inspect --format '{{index .Config.Labels "io.containers.autoupdate"}}' kweb-c)"
    kc down "http://127.0.0.1:$port/web.yaml" > /dev/null 2>&1
    check "down of an http address" 0 $?
    check "the pod is gone" 404 "$(exists pods kweb)"
    kc play "http://127.0.0.1:$port/missing.yaml" > /dev/null 2>&1
    check "an address that is not found fails" 125 $?
    kill "$srv"
}
