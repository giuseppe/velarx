#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# A CNI plugin for crates/core/tests/cni.rs, copied to bin/ under the name of
# each plugin: it logs its environment and its input to ../log, answers ADD
# with an address, fails the ADD of the plugin named in ../fail and the
# STATUS of the one in ../notready, and sleeps when it is called `slow`.
type=$(basename "$0")
root=$(dirname "$0")/..
{
    echo "== $type $CNI_COMMAND"
    env | grep '^CNI_' | sort
    cat
    echo
} >> "$root/log"
if test "$type" = slow; then
    exec sleep 3600
fi
if test "$CNI_COMMAND" = ADD; then
    if test "$(cat "$root/fail" 2> /dev/null)" = "$type"; then
        printf '{"cniVersion":"1.0.0","code":7,"msg":"boom","details":"fake failure"}'
        exit 1
    fi
    printf '{"cniVersion":"1.0.0","interfaces":[{"name":"eth0","mac":"aa:bb:cc:dd:ee:ff","sandbox":"%s"}],"ips":[{"address":"10.1.2.3/24","gateway":"10.1.2.1","interface":0},{"address":"fd00::3/64","interface":0}]}' "$CNI_NETNS"
fi
if test "$CNI_COMMAND" = STATUS && test "$(cat "$root/notready" 2> /dev/null)" = "$type"; then
    printf '{"cniVersion":"1.1.0","code":51,"msg":"not ready"}'
    exit 1
fi
exit 0
