# SPDX-License-Identifier: Apache-2.0
# Cleanup helpers of the e2e scripts (POSIX sh, sourced).

# e2e_remove_containers CLI SOCKET: remove every container while the daemon
# runs.  The containers outlive the daemon (their monitors serve their root
# file systems), so stopping the daemon leaves them running.
e2e_remove_containers () {
    test -S "$2" || return 0
    for c in $(timeout 30 "$1" --socket "$2" container list -a 2> /dev/null | awk 'NR > 1 { print $1 }'); do
        timeout 30 "$1" --socket "$2" container rm -t 0 -f "$c" > /dev/null 2>&1
    done
}

# e2e_detach_mounts DIR: detach what is still mounted below DIR (the mounts
# of a monitor that was killed), the deepest first, so it can be removed.
e2e_detach_mounts () {
    awk -v d="$1" 'index($5, d "/") == 1 { print $5 }' /proc/self/mountinfo | sort -r |
        while read -r m; do umount -l "$m" 2> /dev/null; done
}

# e2e_monitors DIR: the pids of the monitors of the stores below DIR that
# live, from their pid files (the command line of a monitor says its
# container, not where its store is).
e2e_monitors () {
    local f p
    for f in $(find "$1" -path '*/mon/*/monitor.pid' 2> /dev/null); do
        p=$(cat "$f" 2> /dev/null)
        case "$(cat "/proc/${p:-0}/comm" 2> /dev/null)" in
        velarx-monitor*) echo "$p" ;;
        esac
    done
}

# e2e_store_processes DIR: the velarx processes of the store in DIR (the
# daemon, monitors, helpers), one "pid name" per line: those whose command
# line names a path below DIR, and its monitors.
e2e_store_processes () {
    for p in $(e2e_monitors "$1"); do
        echo "$p $(cat "/proc/$p/comm" 2> /dev/null)"
    done
    for p in /proc/[0-9]*; do
        case "$(cat "$p/comm" 2> /dev/null)" in
        velarx-monitor*) continue ;;
        velarx*) ;;
        *) continue ;;
        esac
        tr '\0' '\n' < "$p/cmdline" 2> /dev/null |
            awk -v d="$1/" 'index($0, d) == 1 { found = 1 } END { exit !found }' || continue
        echo "${p#/proc/} $(cat "$p/comm" 2> /dev/null)"
    done
}

# e2e_count_processes DIR: how many there are; at the start of a script
# (none: the store is new) and after its cleanup (none must be left).
e2e_count_processes () {
    e2e_store_processes "$1" | wc -l
}

# e2e_check_left DIR: after the cleanup, wait (10 s at most) for the
# processes of the store in DIR to be gone; name those that stay, and fail.
e2e_check_left () {
    local w=${E2E_WAIT:-$(dirname "${BASH_SOURCE[0]}")/wait.py} p _
    # (each process is waited for by its pidfd, 10 s at most in all)
    local limit=$(( $(date +%s) + 10 ))
    while read -r p _; do
        [ -n "$p" ] || continue
        python3 -I "$w" exit "$p" $(( limit - $(date +%s) > 0 ? limit - $(date +%s) : 1 )) 2> /dev/null
    done < <(e2e_store_processes "$1")
    test "$(e2e_count_processes "$1")" = 0 && return 0
    echo "FAIL processes of $1 are left:" >&2
    e2e_store_processes "$1" >&2
    return 1
}

# e2e_remove_workdir DIR [VELARX...]: remove the work directory DIR of a
# script, the files of the containers' sub ids too: what the user cannot
# remove is removed in the rootless namespaces (`VELARX... unshare`,
# the command line of the script's store); as root its bridge slot is freed
# (e2e_bridge_release of helpers.bash).
e2e_remove_workdir () {
    local dir=$1 i api
    shift
    e2e_bridge_release "$dir"
    # (the velarx-api of the file, started by e2e_start_api, goes first)
    api=$(cat "$dir/api.pid" 2> /dev/null)
    [ -z "$api" ] || kill "$api" 2> /dev/null
    # (a process of the store that is still going away, a monitor that
    # removes its container, may write in it meanwhile: again, for a few
    # seconds)
    for i in 1 2 3 4 5; do
        e2e_detach_mounts "$dir"
        chmod -R u+rwX "$dir" 2> /dev/null
        rm -rf "$dir" 2> /dev/null && return 0
        if test $# -gt 0 && test "$(id -u)" != 0; then
            "$@" unshare rm -rf "$dir" > /dev/null 2>&1
        fi
        rm -rf "$dir" 2> /dev/null && return 0
        sleep 1
    done
    echo "cannot remove $dir" >&2
    return 1
}
