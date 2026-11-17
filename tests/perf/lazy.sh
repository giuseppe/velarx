#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# What the start of a lazily pulled image costs: the time to run `true` and
# to read N files of the image on a cold store, through a registry with a
# round-trip time (delay-proxy.py), with and without the window of files
# fetched after a miss and the startup profile.  Rootless.
#
#   VELARX_BINDIR=target/release tests/perf/lazy.sh [image]
#
# LAZY_RTT_MS (default 20), LAZY_FILES (300), LAZY_RUNS (3: the best is
# reported), LAZY_PROXY_PORT (5099), E2E_REGISTRY (localhost:5000).
set -u

top_srcdir=$(cd "$(dirname "$0")/../.." && pwd)
BINDIR=${VELARX_BINDIR:-$top_srcdir/target/debug}
REGISTRY=${E2E_REGISTRY:-localhost:5000}
IMAGE_PATH=${1:-bench/fedora:44-chunked}
RTT=${LAZY_RTT_MS:-20}
FILES=${LAZY_FILES:-300}
RUNS=${LAZY_RUNS:-3}
PORT=${LAZY_PROXY_PORT:-5099}
SH=$BINDIR/velarx
IMAGE=localhost:$PORT/$IMAGE_PATH

curl -sf -m 5 "http://$REGISTRY/v2/" > /dev/null || { echo "# no registry at $REGISTRY"; exit 77; }

WORKDIR=$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-lazy.XXXXXX")
DAEMON_PID=
PROXY_PID=

stop_daemon () {
    if test -n "$DAEMON_PID"; then
        kill -INT "$DAEMON_PID" 2> /dev/null
        for i in $(seq 100); do kill -0 "$DAEMON_PID" 2> /dev/null || break; sleep 0.1; done
        kill -KILL "$DAEMON_PID" 2> /dev/null
        wait "$DAEMON_PID" 2> /dev/null
        DAEMON_PID=
    fi
}
cleanup () {
    stop_daemon
    test -n "$PROXY_PID" && kill "$PROXY_PID" 2> /dev/null
    findmnt -rn -o TARGET | grep "^$WORKDIR/" | sort -r | while read -r m; do umount -l "$m"; done
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

"$top_srcdir/tests/perf/delay-proxy.py" "$PORT" "$REGISTRY" "$RTT" &
PROXY_PID=$!
sleep 0.5

export HOME=$WORKDIR/home XDG_RUNTIME_DIR=$WORKDIR/run
export XDG_CONFIG_HOME=$HOME/.config XDG_DATA_HOME=$HOME/data
mkdir -p "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"
printf '[[registry]]\nlocation = "localhost:%s"\ninsecure = true\n' "$PORT" > "$WORKDIR/registries.conf"
export VELARX_REGISTRIES_CONF=$WORKDIR/registries.conf

# A fresh store and daemon with these [pull] settings.
start () { # extra [pull] lines
    stop_daemon
    rm -rf "$WORKDIR/store" "$WORKDIR/root" "$WORKDIR/state"
    cat > "$WORKDIR/sh.toml" <<EOT
[server]
socket = "$WORKDIR/sh.sock"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/root"
[storage]
root = "$WORKDIR/store"
[pull]
$1
EOT
    "$SH" --config "$WORKDIR/sh.toml" varlink >> "$WORKDIR/sh.log" 2>&1 &
    DAEMON_PID=$!
    for i in $(seq 200); do
        "$SH" --socket "$WORKDIR/sh.sock" image list > /dev/null 2>&1 && break
        sleep 0.05
    done
    "$SH" --socket "$WORKDIR/sh.sock" image pull --lazy --tls-verify=false "$IMAGE" > /dev/null 2>&1
}
sh_ () { "$SH" --socket "$WORKDIR/sh.sock" "$@"; }
now () { date +%s.%N; }
run () { # command...: seconds
    local t0 t1
    t0=$(now)
    sh_ container run --rm --lazy --network none "$IMAGE" "$@" > /dev/null 2>&1
    t1=$(now)
    echo "$t1 - $t0" | bc -l
}
READ="find /usr/bin /usr/lib64 /usr/share -type f -size +0 2>/dev/null | head -$FILES | xargs cat > /dev/null"

best () { sort -n | head -1; }
table_row () { printf '%-26s %8.2f %8.2f %8.2f\n' "$@"; }

echo "# $IMAGE, rtt $RTT ms, $FILES files, best of $RUNS"
printf '%-26s %8s %8s %8s\n' configuration "true" "read" "read 2nd"

scenario () { # name pull-settings
    : > "$WORKDIR/t.true"; : > "$WORKDIR/t.read"; : > "$WORKDIR/t.second"
    for i in $(seq "$RUNS"); do
        start "$2"; run true >> "$WORKDIR/t.true"
        start "$2"; run sh -c "$READ" >> "$WORKDIR/t.read"
        # the second run of the image on a store that never got its files (the
        # image is not complete after the first): with a profile, the first
        # run noted it
        start "$2"; run sh -c "$READ" > /dev/null; run sh -c "$READ" >> "$WORKDIR/t.second"
    done
    table_row "$1" "$(best < "$WORKDIR/t.true")" "$(best < "$WORKDIR/t.read")" "$(best < "$WORKDIR/t.second")"
}

scenario "no window, no profile" $'lazy_window_files = 0\nlazy_profile_secs = 0'
scenario "window" $'lazy_profile_secs = 0'
scenario "profile" $'lazy_window_files = 0'
scenario "window and profile" ''
