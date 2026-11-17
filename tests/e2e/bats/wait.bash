# SPDX-License-Identifier: Apache-2.0
# The waits of the end to end tests, ended by an event and not by a loop of
# sleeps (tests/e2e/wait.py): load it after helpers.
#
#   e2e_wait_path PATH [LIMIT]          until PATH exists
#   e2e_wait_path_of PATH PID [LIMIT]   until PATH exists, failing when PID ends
#   e2e_wait_glob PATTERN [LIMIT]       until a file matches PATTERN
#   e2e_wait_gone PATH [LIMIT]          until PATH does not exist
#   e2e_wait_exit PID [LIMIT]           until the process has ended
#   e2e_wait_group PGID [LIMIT]         until the process group is empty
#   e2e_wait_line FILE REGEX [LIMIT [COUNT]]
#                                       until COUNT (1) lines of FILE match REGEX
#   e2e_wait_content FILE REGEX [LIMIT] until the whole FILE matches REGEX
#   e2e_wait_condition CTR COND [LIMIT] `velarx wait --condition COND CTR`
#   e2e_wait_unit_state UNIT STATE [LIMIT]
#                                       until the ActiveState of the systemd unit is STATE (SCTL is
#                                       the systemctl command of the file)
#   e2e_wait_listening CTR [PORT]       until the container listens on the port
#   e2e_spawn_ready NAME COMMAND...     COMMAND in the background, as
#                                       a service that says READY=1
#
# LIMIT (seconds, default 30) is an upper bound.  The status is 0 when the
# event came.

E2E_WAIT=${E2E_WAIT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/wait.py}

e2e_wait_path () { python3 -I "$E2E_WAIT" path "$1" "${2:-30}"; }
e2e_wait_path_of () { python3 -I "$E2E_WAIT" path "$1" "${3:-30}" "$2"; }
e2e_wait_glob () { python3 -I "$E2E_WAIT" glob "$1" "${2:-30}"; }
e2e_wait_gone () { python3 -I "$E2E_WAIT" gone "$1" "${2:-30}"; }
e2e_wait_exit () { python3 -I "$E2E_WAIT" exit "$1" "${2:-30}"; }
e2e_wait_group () { python3 -I "$E2E_WAIT" group "$1" "${2:-30}"; }
e2e_wait_line () { python3 -I "$E2E_WAIT" line "$1" "$2" "${3:-30}" "${4:-1}"; }

e2e_wait_content () { python3 -I "$E2E_WAIT" content "$1" "$2" "${3:-30}"; }

# e2e_wait_condition CONTAINER CONDITION [LIMIT]: the wait of the container
# engine itself, which follows the events (no interval).
e2e_wait_condition () {
    timeout "${3:-30}" "$SH" --socket "$ESOCK" container wait --condition "$2" "$1" > /dev/null 2>&1
}

# e2e_wait_log CONTAINER REGEX [LIMIT]: until a line of the log of the
# container matches REGEX: the engine's own follow of the log, no interval.
e2e_wait_log () {
    local f p rc
    f=$(mktemp "${WORKDIR:-/var/tmp}/wait-log.XXXXXX")
    "$SH" --socket "$ESOCK" container logs --follow "$1" > "$f" 2>&1 3>&- &
    p=$!
    e2e_wait_line "$f" "$2" "${3:-30}"
    rc=$?
    kill "$p" 2> /dev/null
    wait "$p" 2> /dev/null
    rm -f "$f"
    return $rc
}

# e2e_wait_no_containers [LIMIT]: until the engine lists no container, each
# remove event of the stream (replayed from an hour back, then followed) being
# a reason to look at the list again: no interval.
e2e_wait_no_containers () {
    local f p n=0 rc=0
    f=$(mktemp "${WORKDIR:-/var/tmp}/wait-rm.XXXXXX")
    "$SH" --socket "$ESOCK" events --since 1h --stream --filter type=container --filter event=remove > "$f" 2>&1 3>&- &
    p=$!
    while [ -n "$("$SH" --socket "$ESOCK" ps -a --format '{{.ID}}' 2>&1)" ]; do
        n=$((n + 1))
        e2e_wait_line "$f" 'container remove' "${1:-30}" "$n" || { rc=1; break; }
    done
    kill "$p" 2> /dev/null
    wait "$p" 2> /dev/null
    rm -f "$f"
    return $rc
}

# e2e_wait_unit_state UNIT STATE [LIMIT]: until the ActiveState of the unit is
# STATE.  (A poll, the only one: the state of a unit is the manager's, which
# sends no notification to a shell that is not on its bus.)
e2e_wait_unit_state () {
    local i
    for ((i = 0; i < ${3:-30} * 10; i++)); do
        [ "$("${SCTL[@]}" show -P ActiveState "$1")" = "$2" ] && return 0
        sleep 0.1
    done
    return 1
}

# e2e_spawn_ready PIDVAR COMMAND...: COMMAND runs in the background with
# NOTIFY_SOCKET set (as a service of systemd would have it), its output
# appended to E2E_SPAWN_LOG; returns once it said READY=1 (30 s at most),
# with its pid in PIDVAR.
e2e_spawn_ready () {
    local var=$1 sock line rfd
    shift
    sock=$(mktemp -u "${E2E_TMPDIR:-/var/tmp}/e2e-notify.XXXXXX")
    coproc E2E_READY { python3 -I "$E2E_WAIT" ready "$sock" 30; }
    # (a copy of the descriptor: bash closes the coproc's when it ends, and
    # a daemon that is quick makes it end before the read)
    exec {rfd}<&"${E2E_READY[0]}"
    # (bound: the notification cannot be lost)
    read -r -u "$rfd" line
    NOTIFY_SOCKET=$sock "$@" >> "${E2E_SPAWN_LOG:-/dev/null}" 2>&1 3>&- {rfd}>&- &
    printf -v "$var" %s "$!"
    read -r -u "$rfd" line
    exec {rfd}<&-
    rm -f "$sock"
    wait "$E2E_READY_PID" 2> /dev/null
    [ "$line" = ready ]
}

# e2e_wait_listening CONTAINER [PORT]: until the container listens on the
# port (80), a TCP server that says nothing when it is ready.  The loop runs
# in the container (up to 30 s): the exec returns when it does.
# Needs sh_ of the file.
e2e_wait_listening () {
    sh_ container exec "$1" timeout "${3:-30}" sh -c "until nc -z 127.0.0.1 ${2:-80}; do :; done" 3>&- ||
        e2e_die "$1 does not listen on ${2:-80}"
}
