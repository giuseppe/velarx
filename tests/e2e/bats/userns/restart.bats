# SPDX-License-Identifier: Apache-2.0
# Restarts by the restart policy, which the monitor makes in the user and
# network namespaces of the first run.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

restart_count () {
    sh_ container inspect "$1" | sed -n 's/.*"restart_count": \([0-9]*\).*/\1/p' | head -1
}

@test "restarts keep the user and network namespaces of the first run" {
    name=uns-restart
    # shellcheck disable=SC2086
    bg "--name $name --restart on-failure:1 $MAPOPTS" \
        sh -c 'tr -s " " < /proc/self/uid_map; test -e /tmp/ran && echo again; touch /tmp/ran; ls /sys/class/net | wc -l; sleep 0.3; exit 1' > /dev/null
    # The second run is the last: on-failure:1.  Its line "again" is in the log
    # after the restart; then the container ends for good.
    id=$(sh_ container inspect $name | sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' | head -1)
    e2e_wait_line "$WORKDIR/root/logs/$id/container.log" ' stdout F again$' 30 || e2e_die "no restart"
    e2e_wait_condition $name stopped || e2e_die "not stopped"
    check "restarted once with a user namespace" 1 "$(restart_count $name)"
    out=$(sh_ container logs $name)
    maphost=$(echo "$MAPOPTS" | sed 's/^--uidmap 0:\([0-9]*\):.*/\1/')
    check "the restart has the mappings of the first run" 2 "$(echo "$out" | grep -c "^ *0 $maphost 65536")"
    check "and its root file system" 1 "$(echo "$out" | grep -c again)"
    nets=$(echo "$out" | grep -E '^[0-9]+$' | sort -u | wc -l)
    check "and its network" 1 "$nets"
    sh_ container rm -t 0 -f $name > /dev/null
}
