#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Run the end to end bats files, several at a time, and report each one's
# result and time:
#
#   tests/e2e/run-all.sh [-j JOBS] [NAME...] [-- BATS_ARGS...]
#
# NAME is a file of tests/e2e/bats ("run-lifecycle", "kube.bats",
# "api/images"); all of them by default.  Every file has a work directory, a
# daemon, a socket and a store of its own, so they run side by side; JOBS
# (default E2E_JOBS, else 6) of them at a time, each in its own `bats` (the
# tests of a file run in order).  Not `bats --jobs`: that has no timeout per
# file, no order and no way to keep unit.bats away from the files that
# reload the user manager.  The tests that need what this machine lacks
# (root, a registry, podman's sources, velarx-p2p...) skip themselves.
#
# VELARX_BINDIR is the directory of velarx, velarx-client and
# velarx-monitor (default the debug build: $CARGO_TARGET_DIR/debug, else
# target/debug of the source tree); it is given to the files under each of
# the names they read.  Run them from a copy of the binaries when another
# build can replace them meanwhile.  BATS_ARGS are given to bats (--filter
# ...).  E2E_TIMEOUT (default 1800) is the seconds a file may take.
# E2E_LOGDIR (default a new directory in /var/tmp) keeps the output (TAP) of
# each file.  VELARX_E2E_HOST_CHANGES=1 runs the tests that change a setting
# of the whole host for a while (the I/O scheduler of /dev/nullb0); they put
# it back in their teardown and skip themselves without it.
#
# As root, fetcher-confine mounts over the system directories:
# it runs in a mount namespace of its own (unshare -m --propagation
# private) and is told so (FCONF_PRIVATE_MOUNTS).
# Exits 1 if a file failed.
set -u

top_srcdir=$(cd "$(dirname "$0")/../.." && pwd)
JOBS=${E2E_JOBS:-6}
while getopts j: o; do
    case $o in
    j) JOBS=$OPTARG ;;
    *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))

names=()
while [ $# -gt 0 ] && [ "$1" != -- ]; do names+=("${1%.bats}"); shift; done
[ "${1:-}" = -- ] && shift
BATS_ARGS=("$@")

BINDIR=$(realpath "${VELARX_BINDIR:-${CARGO_TARGET_DIR:-$top_srcdir/target}/debug}")
[ -x "$BINDIR/velarx" ] || { echo "no $BINDIR/velarx (cargo build)" >&2; exit 2; }
export VELARX_BINDIR=$BINDIR BIN=$BINDIR VELARX_DAEMON=$BINDIR/velarx
command -v bats > /dev/null || { echo "bats is not installed" >&2; exit 2; }
BATSDIR=$top_srcdir/tests/e2e/bats
LOGDIR=${E2E_LOGDIR:-$(mktemp -d "${TMPDIR:-/var/tmp}/velarx-e2e-logs.XXXXXX")}
mkdir -p "$LOGDIR"

# The longest first, so that the run takes about as long as the longest
# file; then the others in the order of their names.  The files that
# reload the user manager come first of all: unit.bats waits for them.
LONGEST="quadlet units engine engine-api unit api/* run-* kube build-loop userns/* userns-tree"
# unit.bats times its units' start (TimeoutStartSec): a daemon-reload of the
# manager in the middle cuts the extension, so the files that reload it end
# before unit.bats starts.
declare -A AFTER=([unit]="quadlet units engine engine-api")

if [ ${#names[@]} -eq 0 ]; then
    mapfile -t all < <(cd "$BATSDIR" && find . -name '*.bats' | sed 's|^\./||; s|\.bats$||' | sort)
    for pat in $LONGEST; do
        for n in "${all[@]}"; do
            # shellcheck disable=SC2254
            case $n in $pat) names+=("$n") ;; esac
        done
    done
    names+=("${all[@]}")
    mapfile -t names < <(printf '%s\n' "${names[@]}" | awk '!seen[$0]++')
fi
for n in "${names[@]}"; do
    [ -f "$BATSDIR/$n.bats" ] || { echo "no tests/e2e/bats/$n.bats" >&2; exit 2; }
done
SCRIPTS=("${names[@]}")

now () { date +%s.%N; }
start=$(now)
declare -A PID_OF=() STARTED=() DONE=()
results=()

# Ctrl-C or a TERM: a file's timeout passes the TERM on to the process group
# of the file (not in ours), whose teardown_file cleans up.
stop () {
    trap - INT TERM
    [ ${#PID_OF[@]} -gt 0 ] && kill -TERM "${!PID_OF[@]}" 2> /dev/null
    wait
    echo "e2e: interrupted, logs in $LOGDIR" >&2
    exit 130
}
trap stop INT TERM

logof () { echo "$LOGDIR/${1//\//_}.log"; }

finish () { # pid status
    local name=${PID_OF[$1]} status=$2 secs what log extra=
    local total skipped
    log=$(logof "$name")
    secs=$(echo "$(now) - ${STARTED[$name]}" | bc)
    total=$(grep -c -E '^(not )?ok ' "$log")
    skipped=$(grep -c -E '^ok .* # skip' "$log")
    case $status in
    0)
        if [ "$total" -gt 0 ] && [ "$skipped" = "$total" ]; then
            what=skip
        else
            what=ok
            [ "$skipped" -gt 0 ] && extra=" ($skipped of $total skipped)"
        fi
        ;;
    124 | 137) what=TIMEOUT ;;
    *) what=FAIL ;;
    esac
    results+=("$(printf '%-8s %7.1f s  %s' "$what" "$secs" "$name")")
    printf '%-8s %7.1f s  %s%s\n' "$what" "$secs" "$name" "$extra"
    if [ "$what" = skip ]; then
        printf '         (%s)\n' "$(grep -E '^ok .* # skip' "$log" | tail -1 | sed 's/.*# skip *//')"
    fi
    DONE[$name]=1
    unset "PID_OF[$1]"
}

# Whether the files NAME waits for (AFTER) are done or not run at all.
ready () {
    local n
    for n in ${AFTER[$1]:-}; do
        if [ -z "${DONE[$n]:-}" ] && printf '%s\n' "${QUEUE[@]}" "${PID_OF[@]}" | grep -qx "$n"; then
            return 1
        fi
    done
}

# start_file NAME: bats on the file, with a timeout, its TAP output in the log.
# As root the files that mount over the system directories get a mount
# namespace of their own, with private propagation, and are told so.
start_file () {
    local name=$1 pre=()
    if [ "$(id -u)" = 0 ]; then
        case $name in
        fetcher-confine) pre=(unshare -m --propagation private env FCONF_PRIVATE_MOUNTS=1) ;;
        esac
    fi
    STARTED[$name]=$(now)
    timeout -k 30 "${E2E_TIMEOUT:-1800}" "${pre[@]}" \
        bats --tap --timing "${BATS_ARGS[@]}" "$BATSDIR/$name.bats" \
        > "$(logof "$name")" 2>&1 < /dev/null &
    PID_OF[$!]=$name
}

QUEUE=("${SCRIPTS[@]}")
while [ ${#QUEUE[@]} -gt 0 ] || [ ${#PID_OF[@]} -gt 0 ]; do
    next=
    if [ ${#PID_OF[@]} -lt "$JOBS" ]; then
        for i in "${!QUEUE[@]}"; do
            if ready "${QUEUE[$i]}"; then
                next=${QUEUE[$i]}
                unset "QUEUE[$i]"
                QUEUE=("${QUEUE[@]}")
                break
            fi
        done
    fi
    if [ -n "$next" ]; then
        start_file "$next"
    else
        wait -n -p done_pid "${!PID_OF[@]}"
        finish "$done_pid" $?
    fi
done

failed=$(printf '%s\n' "${results[@]}" | grep -c -e '^FAIL' -e '^TIMEOUT')
printf 'e2e: %d files, %d failed, %.0f s wall, logs in %s\n' \
    ${#results[@]} "$failed" "$(echo "$(now) - $start" | bc)" "$LOGDIR"
printf '%s\n' "${results[@]}" | grep -e '^FAIL' -e '^TIMEOUT' | while read -r _ _ _ name; do
    echo "--- $name"
    grep -e '^not ok' -e FAIL -e panicked "$(logof "$name")" | head -5
done
[ "$failed" = 0 ]
