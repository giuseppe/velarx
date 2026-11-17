#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Check that every commit of a range carries a Developer Certificate of
# Origin sign-off, `Signed-off-by: Name <email>` (git commit -s):
#
#   tests/check-dco.sh BASE [HEAD]      # the commits of BASE..HEAD
#   make check-dco BASE=origin/main
#
# The range starts at BASE (the history before it is not looked at); merge
# commits are skipped.  Exits 1 and lists the commits without a sign-off.
set -eu

base=${1:-}
head=${2:-HEAD}
if [ -z "$base" ]; then
    echo "usage: $0 BASE [HEAD]" >&2
    exit 2
fi

missing=0
count=0
for c in $(git rev-list --no-merges "$base..$head"); do
    count=$((count + 1))
    if ! git show -s --format=%B "$c" | git interpret-trailers --parse \
        | grep -Eq '^Signed-off-by: [^<>]+ <[^<>@ ]+@[^<>@ ]+>$'; then
        echo "no Signed-off-by: $(git show -s --format='%h %s' "$c")" >&2
        missing=$((missing + 1))
    fi
done

if [ "$missing" -ne 0 ]; then
    echo "$missing of $count commits lack a Signed-off-by line (git commit -s)" >&2
    exit 1
fi
echo "ok: $count commits signed off"
