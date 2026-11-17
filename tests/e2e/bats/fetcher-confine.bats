# SPDX-License-Identifier: Apache-2.0
# The confinement of the registry fetcher, rootless and as root: the front
# and a worker it starts try from inside what their sandboxes allow and
# refuse (`velarx-registry --self-test`, with the staging handed as a
# descriptor as the engine hands it), a pull works through the fetcher.
#
# As root only: the front started on demand by a root engine (no systemd
# unit, so no ProtectKernelTunables=) has the kernel's files read-only in its
# mount namespace, a write to /proc/sys is refused, and a credential helper
# (credsStore) still runs, in the unconfined runner that the front forked
# before it confined itself.
#
# Root's credential helpers are found in the system's directories only: the
# fake one is put there in a mount namespace of the run, which is that of
# bats: run it under `FCONF_PRIVATE_MOUNTS=1 unshare -m --propagation private`.
# The variable alone is not trusted: the file also checks that `/` is not a
# shared mount of this mount namespace (a bind mount over /usr/local/bin would
# reach the host).
#
#   VELARX_BINDIR=target/debug E2E_IMAGE=image bats tests/e2e/bats/fetcher-confine.bats
#
# What the tests learn for the next ones (the front and the runner) is in
# $WORKDIR/vars; the daemon's pid in $WORKDIR/daemon.pid.

load helpers

E2E_PUSH_REGISTRY=${E2E_PUSH_REGISTRY:-$E2E_REGISTRY}

# as_root: whether the file runs as root of the initial user namespace
as_root () {
    [ "$(id -u)" = 0 ] && [ "$(tr -s ' ' < /proc/self/uid_map | sed 's/^ //')" = "0 0 4294967295" ]
}

setup_file () {
    curl -sf -m 5 "http://$E2E_REGISTRY/v2/" > /dev/null || skip "no registry at $E2E_REGISTRY"
    if as_root; then
        e2e_require_private_mounts FCONF_PRIVATE_MOUNTS
        # (root's auth file of the host comes before the helper of ~/.docker:
        # an empty one is over it in this private mount namespace)
        if grep -qs "\"$E2E_REGISTRY\"" /run/velarx/auth/auth.json; then
            : > "$BATS_FILE_TMPDIR/no-auth.json"
            mount --bind "$BATS_FILE_TMPDIR/no-auth.json" /run/velarx/auth/auth.json ||
                e2e_die "cannot hide /run/velarx/auth/auth.json of the host"
        fi
    fi
    e2e_setup_file
    local b
    for b in velarx velarx-registry; do
        [ -x "$BIN/$b" ] || skip "cannot find $BIN/$b"
    done
    mkdir -p "$XDG_DATA_HOME"
    # (the daemon's socket in a directory of 80 bytes, whatever E2E_TMPDIR
    # is: its own path fits in the 107 bytes of a socket address, and the
    # fetcher's below it, in services/, does not and is bound all the same)
    export FCONF_DIR SOCKDIR
    FCONF_DIR=$(mktemp -d /var/tmp/fconf.XXXXXX)
    SOCKDIR=$FCONF_DIR/s
    while [ ${#SOCKDIR} -lt 80 ]; do SOCKDIR=${SOCKDIR}x; done
    mkdir -m 0700 "$SOCKDIR"
    export IMAGE=${E2E_IMAGE:-$E2E_REGISTRY/alpine:chunked}
    printf '[[registry]]\nlocation = "%s"\ninsecure = true\n[[registry]]\nlocation = "%s"\ninsecure = true\n' \
        "$E2E_REGISTRY" "$E2E_PUSH_REGISTRY" > "$WORKDIR/registries.conf"
    export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf
    cat > "$WORKDIR/sh.toml" <<EOT
[engine]
socket = "$SOCKDIR/sh.sock"
[server]
socket = "$SOCKDIR/sh.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$WORKDIR/store"
[pull]
lazy_completers = 0
EOT
    # a credential helper for every registry, as root: the confined front
    # cannot run it
    local HELPERS=$WORKDIR/helpers
    mkdir -p "$HELPERS" "$HOME/.docker"
    if as_root; then
    cat > "$HELPERS/docker-credential-fake" <<EOT
#!/bin/sh
read server
echo "\$PPID \$server" >> "$WORKDIR/helper.log"
printf '{"Username":"fake","Secret":"s3cret"}'
EOT
    chmod +x "$HELPERS/docker-credential-fake"
    echo '{"credsStore": "fake"}' > "$HOME/.docker/config.json"
    mount --bind "$HELPERS" /usr/local/bin
    export FCONF_MOUNTED=1
    fi

    # (the daemon says READY=1 when it serves)
    E2E_SPAWN_LOG=$WORKDIR/sh.log e2e_spawn_ready DAEMON_PID "$BIN/velarx" --config "$WORKDIR/sh.toml" varlink
    ready=$?
    echo "$DAEMON_PID" > "$WORKDIR/daemon.pid"
    [ "$ready" = 0 ] || { echo "the daemon does not start"; cat "$WORKDIR/sh.log"; exit 1; }
}

teardown_file () {
    [ -n "${WORKDIR:-}" ] || return 0
    local pid i
    pid=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -n "$pid" ]; then
        "$BIN/velarx" --config "$WORKDIR/sh.toml" --socket "$SOCKDIR/sh.sock" container rm -t 0 -f held > /dev/null 2>&1
        kill -INT "$pid" 2> /dev/null
        e2e_wait_exit "$pid"
        kill -KILL "$pid" 2> /dev/null
        rm -f "$WORKDIR/daemon.pid"
    fi
    [ -z "${FCONF_MOUNTED:-}" ] || umount /usr/local/bin 2> /dev/null
    if [ -z "${E2E_KEEP:-}" ]; then
        findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    fi
    [ -z "${FCONF_DIR:-}" ] || rm -rf "$FCONF_DIR"
    e2e_teardown_file
}

setup () {
    set +e
    DAEMON_PID=$(cat "$WORKDIR/daemon.pid" 2> /dev/null)
    if [ -f "$WORKDIR/vars" ]; then . "$WORKDIR/vars"; fi
}

# the front process: a descendant of the daemon running `fetcher`
descends () { # pid
    local p=$1
    while [ "$p" -gt 1 ]; do
        [ "$p" = "$DAEMON_PID" ] && return 0
        p=$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2> /dev/null) || return 1
        [ -n "$p" ] || return 1
    done
    return 1
}

@test "the front and a worker try their confinement from inside" {
    local staging=$WORKDIR/store/staging/layers out
    mkdir -p "$staging"
    chmod 700 "$WORKDIR/store/staging" "$staging"
    out=$("$BIN/velarx-registry" --config "$WORKDIR/sh.toml" --staging-fd 5 --self-test 5< "$staging" 2> "$WORKDIR/selftest.err")
    rc=$?
    [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/selftest.err"
    check "the self-test runs" 0 $rc
    # every probe as it should be, and those of the brief there
    check "what failed" "" "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print(" | ".join(w for w, ok in json.load(sys.stdin) if not ok))')"
    local want
    for want in "makes a file beneath the staging" "makes nothing next to the staging" \
        "executes nothing" "starts no process" "makes no namespace" \
        "signals no process outside its domain" \
        "binds no TCP port" "connects to no TCP port" "connects to no UNIX socket by name" \
        "worker: connect to a TCP port it was not given" \
        "worker: connect to a TCP port it was given" "worker: signal the daemon" \
        "worker: execve" "worker: create a file"; do
        check "probe: $want" yes "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print("yes" if sys.argv[1] in [w for w, _ in json.load(sys.stdin)] else "no")' "$want")"
    done
}

@test "the pusher of a path tries its confinement from inside" {
    local mode dest redirect out want
    for mode in oci: dir: oci-archive:; do
        mkdir -p "$WORKDIR/dirpush"
        : > "$WORKDIR/dirpush/file"
        rm -rf "$WORKDIR/dirpush/dest"
        mkdir "$WORKDIR/dirpush/dest"
        dest=dest redirect="<"
        # (a directory is opened for reading, an archive for writing)
        if [ "$mode" = oci-archive: ]; then dest=file redirect="<>"; fi
        out=$(eval '"$BIN/velarx-dir" --push --self-test "$mode" 5'"$redirect"'"$WORKDIR/dirpush/$dest"' 2> "$WORKDIR/dirpush.err")
        rc=$?
        [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/dirpush.err"
        check "the self-test of $mode runs" 0 $rc
        check "what failed in $mode" "" "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print(" | ".join(w for w, ok in json.load(sys.stdin) if not ok))')"
        for want in "executes nothing" "starts no process" "makes no namespace" \
            "binds no TCP port" "connects to no TCP port" "creates no file by a name" \
            "reads nothing it does not need"; do
            check "$mode probe: $want" yes "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print("yes" if sys.argv[1] in [w for w, _ in json.load(sys.stdin)] else "no")' "$want")"
        done
    done
}

@test "the origin of a path tries its confinement from inside and opens no file outside it" {
    local scheme target out want staging=$WORKDIR/store/staging/layers
    mkdir -p "$staging" "$WORKDIR/dirorigin/layout"
    chmod 700 "$WORKDIR/store/staging" "$staging"
    echo '{}' > "$WORKDIR/dirorigin/layout/index.json"
    echo x > "$WORKDIR/dirorigin/archive"
    for scheme in oci: oci-archive:; do
        target=layout
        [ "$scheme" = oci: ] || target=archive
        out=$("$BIN/velarx-dir" --origin --staging-fd 6 --self-test "$scheme" 5< "$WORKDIR/dirorigin/$target" 6< "$staging" 2> "$WORKDIR/dirorigin.err")
        rc=$?
        [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/dirorigin.err"
        check "the self-test of the origin $scheme runs" 0 $rc
        check "what failed in the origin $scheme" "" "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print(" | ".join(w for w, ok in json.load(sys.stdin) if not ok))')"
        for want in "executes nothing" "starts no process" "makes no namespace" \
            "binds no TCP port" "connects to no TCP port" "makes a file beneath the staging" \
            "makes nothing next to the staging" "opens no file outside its origin" \
            "writes nothing in its origin"; do
            check "origin $scheme probe: $want" yes "$(printf '%s' "$out" | python3 -I -c 'import json,sys; print("yes" if sys.argv[1] in [w for w, _ in json.load(sys.stdin)] else "no")' "$want")"
        done
    done
}

@test "a pull through the fetcher" {
    # Only the layers whose TOCs give the fs-verity digests of their files
    # stay lazy: the image is pushed again by velarx (gzip, and back as
    # zstd:chunked), from a store of its own, to $E2E_PUSH_REGISTRY.
    local sealed=$E2E_PUSH_REGISTRY/velarx-e2e/dlconfine-$$ rc
    sed -e "s#$WORKDIR/\(state\|root\|store\)\"#$WORKDIR/seal-\1\"#" \
        -e "s#/sh.sock\"#/seal.sock\"#" "$WORKDIR/sh.toml" > "$WORKDIR/seal.toml"
    seal () { "$BIN/velarx" --config "$WORKDIR/seal.toml" "$@"; }
    { seal image pull --tls-verify=false "$IMAGE" &&
      seal image push --tls-verify=false --compression-format gzip "$IMAGE" "$sealed:gzip" &&
      seal image pull --tls-verify=false "$sealed:gzip" &&
      seal image push --tls-verify=false --compression-format zstd:chunked "$sealed:gzip" "$sealed:zstd"
    } > "$WORKDIR/seal.log" 2>&1
    rc=$?
    [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/seal.log"
    check "the image is sealed" 0 $rc
    "$BIN/velarx" --config "$WORKDIR/sh.toml" --socket "$SOCKDIR/sh.sock" image pull --lazy --tls-verify=false "$sealed:zstd" > "$WORKDIR/pull.log" 2>&1
    rc=$?
    [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/pull.log"
    check "a pull through the fetcher" 0 $rc
    # (the fetcher leaves with the last connection of the engine service:
    # the layers of a pull that is not completed in the background
    # (`lazy_completers = 0`) stay staged, and the service keeps the list of
    # fetchers they are fetched with, which the next tests look at; the first
    # read of the container has the front ask the helper again)
    : > "$WORKDIR/helper.log"
    "$BIN/velarx" --config "$WORKDIR/sh.toml" --socket "$SOCKDIR/sh.sock" container run -d --lazy --network none --name held "$sealed:zstd" sleep 600 > "$WORKDIR/run.log" 2>&1
    rc=$?
    [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/run.log"
    check "a container with lazy layers runs" 0 $rc
    check_match "it reads a file of the image" "^[0-9]+\.[0-9]+" \
        "$("$BIN/velarx" --config "$WORKDIR/sh.toml" --socket "$SOCKDIR/sh.sock" container exec held cat /etc/alpine-release 2>&1)"
}

@test "the front is confined and the credential helper runs in an unconfined runner" {
    as_root || skip "not root"
    local FRONT= RUNNER d pid
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        tr '\0' ' ' 2> /dev/null < "$d/cmdline" | grep -q 'velarx-registry --listen-fd' || continue
        descends "$pid" && { FRONT=$pid; break; }
    done
    [ -n "$FRONT" ] || { echo "FAIL no fetcher of this daemon is running" >&2; exit 1; }
    # the helper ran for the pull of the front, in a child of the front that no
    # seccomp filter and no Landlock domain confines
    check "the helper was asked for the registry" "$E2E_REGISTRY" "$(awk '{print $2}' "$WORKDIR/helper.log" 2> /dev/null | sort -u)"
    # (the last one: the front the container's reads went to; an earlier
    # one served the start and left with its connections)
    RUNNER=$(awk 'END {print $1}' "$WORKDIR/helper.log" 2> /dev/null)
    echo "FRONT=$FRONT" >> "$WORKDIR/vars"
    echo "RUNNER=$RUNNER" >> "$WORKDIR/vars"
    check "the helper runs in a child of the front" "$FRONT" "$(awk '/^PPid:/ {print $2}' /proc/${RUNNER:-0}/status 2> /dev/null)"
    check "the runner is not under seccomp" 0 "$(awk '/^Seccomp:/ {print $2}' /proc/${RUNNER:-0}/status 2> /dev/null)"
    # (the front installs its filter after its Landlock domain, which the
    # kernel shows nowhere: a filter says that the domain was made and is
    # enforced, else the front had stopped; what the domain refuses is
    # checked by the self-test of the confinement, confine.rs.  Its filter
    # and its domain set no_new_privs too: the NoNewPrivs line below is seen
    # with them, never alone)
    check "the front is under seccomp" 2 "$(awk '/^Seccomp:/ {print $2}' /proc/$FRONT/status)"
    # (the confinement is of the process: every thread, those its runtime made
    # after it too)
    check "every thread of the front is under seccomp" 2 "$(awk '/^Seccomp:/ {print $2}' /proc/$FRONT/task/*/status | sort -u)"
    check "every thread of the front has no_new_privs" 1 "$(awk '/^NoNewPrivs:/ {print $2}' /proc/$FRONT/task/*/status | sort -u)"
    check "the front process is root" 0 "$(awk '/^Uid:/ {print $2}' /proc/$FRONT/status)"
    check "it has a mount namespace of its own" different \
        "$([ "$(readlink /proc/$FRONT/ns/mnt)" != "$(readlink /proc/$DAEMON_PID/ns/mnt)" ] && echo different || echo same)"
}

@test "the kernel's files are read-only in its mount namespace" {
    local mp opts loose daemon_opts below
    as_root || skip "not root"
    [ -n "${FRONT:-}" ] || { echo "no front of the earlier test (it failed or did not run)" >&2; exit 1; }
    for mp in /proc/sys /proc/sysrq-trigger /proc/irq /sys; do
        opts=$(awk -v mp="$mp" '$5 == mp {o = $6} END {print o}' /proc/$FRONT/mountinfo)
        case ",$opts," in
        *,ro,*) ;;
        *) echo "FAIL $mp is not read-only for it: '$opts'" >&2; exit 1 ;;
        esac
    done
    # every mount at or below them (binfmt_misc, the control groups...) is
    # read-only, and private: nothing the host mounts there later comes in
    # (the last mount on a mount point is the one that is seen)
    loose=$(awk '
        $5 ~ "^(/proc/sys|/sys)(/|$)" {
            prop = ""
            for (i = 7; $i != "-"; i++) prop = prop " " $i
            last[$5] = ("," $6 ",") ~ /,ro,/ && prop == "" ? "" : $5 " " $6 prop
        }
        END { for (m in last) if (last[m] != "") print last[m] }' /proc/$FRONT/mountinfo)
    check "the mounts below /proc/sys and /sys are read-only and private" "" "$loose"
    daemon_opts=$(awk '$5 == "/proc/sys" {o = $6} END {print o}' /proc/$DAEMON_PID/mountinfo)
    case ",$daemon_opts," in
    *,ro,*) echo "FAIL /proc/sys is read-only for the daemon, too" >&2; exit 1 ;;
    esac
    # what is mounted below /proc/sys is not hidden by the read-only copy
    below=$(awk '$5 == "/proc/sys/fs/binfmt_misc"' /proc/$DAEMON_PID/mountinfo | wc -l)
    if [ "$below" -gt 0 ] && [ "$(awk '$5 == "/proc/sys/fs/binfmt_misc"' /proc/$FRONT/mountinfo | wc -l)" -lt "$below" ]; then
        echo "FAIL binfmt_misc below /proc/sys is hidden" >&2; exit 1
    fi
}

# the runner ends with the front

@test "the runner ends with the front" {
    local i
    as_root || skip "not root"
    [ -n "${FRONT:-}" ] && [ -n "${RUNNER:-}" ] || { echo "no front or runner of the earlier test (it failed or did not run)" >&2; exit 1; }
    kill -KILL "$FRONT"
    e2e_wait_exit "$RUNNER"
    check "the runner ended with the front" gone "$(e2e_alive "$RUNNER")"
}

# The engine as `sudo` runs it for a user: the binary and the home directory
# (credentials) below a private directory (mode 0700, another owner) that the
# front process, root without CAP_DAC_OVERRIDE, can only look up with
# CAP_DAC_READ_SEARCH.  Without it the worker could not be executed (Landlock
# had no rule for its path: "pull worker: lost: Connection reset by peer")
# and a missing ~/.docker was "permission denied".  A pull without a daemon.

@test "a pull as root with the binary and HOME in a private directory" {
    as_root || skip "not root"
    local PRIV=$WORKDIR/private b
    install -d -m 0700 -o 65534 -g 65534 "$PRIV" "$PRIV/bin" "$PRIV/home"
    for b in velarx velarx-registry; do
        cp "$BIN/$b" "$PRIV/bin/$b" && chown 65534:65534 "$PRIV/bin/$b"
    done
    cat > "$WORKDIR/sh-cli.toml" <<EOT
[engine]
socket = "$WORKDIR/state-cli/velarx.sock"
[server]
socket = "$WORKDIR/state-cli/velarx.sock"
state_dir = "$WORKDIR/state-cli"
root_dir = "$WORKDIR/root-cli"
[storage]
root = "$WORKDIR/store-cli"
[pull]
EOT
    (cd "$PRIV" && env HOME="$PRIV/home" SUDO_USER=nobody SUDO_UID=65534 SUDO_GID=65534 \
        "$PRIV/bin/velarx" --config "$WORKDIR/sh-cli.toml" pull --tls-verify=false "$IMAGE") \
        > "$WORKDIR/pull-cli.log" 2>&1
    rc=$?
    [ $rc = 0 ] || sed "s/^/# /" "$WORKDIR/pull-cli.log"
    check "a pull as root with the binary and HOME in a private directory" 0 $rc
}
