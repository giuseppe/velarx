#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The failed checks of a run of podman's apiv2 suite that podman-apiv2.skips
# does not expect, and the skips that matched nothing.
#
#   apiv2-unexpected.py SUITE.LOG podman-apiv2.skips
#
# Prints each unexpected failure (the line of the suite and what it printed
# under it) and each skip of a file that ran that matched no failure ("stale
# skip"), and exits with 1 when it printed any, 2 when the skips file is
# malformed, 0 otherwise.
import re
import sys


def skips(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            fields = line.split("\t")
            if len(fields) != 3 or not all(fields):
                print(f"{path}:{n}: not three fields: {line}", file=sys.stderr)
                sys.exit(2)
            file, regex, reason = fields
            try:
                out.append((file, re.compile(regex), line))
            except re.error as e:
                print(f"{path}:{n}: {e}: {regex}", file=sys.stderr)
                sys.exit(2)
    return out


def failures(path):
    """(file, 'description # expected... # actual...') of each failed check"""
    blocks = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = re.match(r"not ok \d+ \[([^]]+)\] (.*)", line)
            if m:
                blocks.append([m.group(1), m.group(2)])
            elif blocks and line.startswith("#"):
                blocks[-1][1] += " " + line
    return blocks


def main(log, skip_file):
    expected = skips(skip_file)
    ran = set()
    with open(log, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"(?:not )?ok \d+ \[([^]]+)\]", line)
            if m:
                ran.add(m.group(1))
    used = set()
    bad = 0
    for file, text in failures(log):
        for i, (f, regex, _) in enumerate(expected):
            if f == file and regex.search(text):
                used.add(i)
                break
        else:
            bad += 1
            print(f"unexpected failure [{file}] {text}")
    for i, (f, _, line) in enumerate(expected):
        if i not in used and f in ran:
            bad += 1
            print(f"stale skip: {line}")
    return 1 if bad else 0


sys.exit(main(sys.argv[1], sys.argv[2]))
