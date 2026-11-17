# SPDX-License-Identifier: Apache-2.0
# Secrets in a user namespace: the owner of a mounted secret is given
# through the mappings of the container.

load ../helpers
load ../userns

setup_file () { userns_setup_file; }
teardown_file () { userns_teardown_file; }

@test "secrets in a user namespace" {
    printf 'mapped' | sh_ secret create usec - > /dev/null
    out=$(runo "$MAPOPTS --secret usec,uid=1000,gid=1000,mode=0400" sh -c 'stat -c "%u %g %a" /run/secrets/usec')
    check "secret owner in a user namespace" "1000 1000 400" "$out"
    out=$(runo "$MAPOPTS --user 1000 --secret usec,uid=1000,mode=0400" cat /run/secrets/usec)
    check "the user of the container reads it" mapped "$out"
    out=$(runo "--userns auto --user 1000 --secret usec,uid=1000,mode=0400" cat /run/secrets/usec)
    check "and with --userns auto" mapped "$out"
    out=$(runo "$MAPOPTS --user 1000 --secret usec,mode=0400" cat /run/secrets/usec)
    check_match "another user cannot" "Permission denied" "$out"
    sh_ secret rm usec > /dev/null
}
