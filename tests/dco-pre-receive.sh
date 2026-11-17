#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Server-side git hook (pre-receive) that refuses a push of commits without a
# Signed-off-by line.  Install it as the `pre-receive` hook of the bare
# repository (a git server may offer a settings page for it, or
# <repo>.git/hooks/pre-receive) together with tests/check-dco.sh, whose path
# is the first argument or $DCO_CHECK:
#
#   exec /path/to/dco-pre-receive.sh /path/to/check-dco.sh
set -eu

check=${1:-${DCO_CHECK:-}}
[ -x "$check" ] || { echo "dco-pre-receive: no check-dco.sh at '$check'" >&2; exit 2; }
zero=0000000000000000000000000000000000000000

while read -r old new ref; do
    [ "$new" = "$zero" ] && continue
    case "$ref" in refs/heads/*) ;; *) continue ;; esac
    if [ "$old" = "$zero" ]; then
        # a new branch: the commits that no existing branch has
        first=$(git rev-list --no-merges "$new" --not --branches | tail -n 1)
        [ -n "$first" ] || continue
        old=$(git rev-parse -q --verify "$first^") || continue
    fi
    "$check" "$old" "$new" || exit 1
done
