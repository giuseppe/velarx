#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# velarx - per phase timing of a command from its VELARX_TRACE_FILE points
# Copyright (C) 2026 Giuseppe Scrivano <giuseppe@scrivano.org>

"""Run a command N times with VELARX_TRACE_FILE set and print the median
time of every phase.

Every trace point is "<pid> <CLOCK_MONOTONIC ns> <label>"; Python's
time.monotonic_ns () reads the same clock, so the spawn and the exit of
the command are added as the "spawn" and "exit" points.  A phase is the
interval between a point and the previous one in time order; points
are matched across runs by label (a repeated label gets a "#N" suffix).

  tests/perf/phases.py -n 80 -w 5 -- target/debug/velarx \\
      container run --network none --rm localhost:5000/alpine:chunked echo hello

Two points say what should not be there: "db open cold" (a connection
that rebuilds the index of the store's log, once per command) and
"scope requested" (a request to the systemd manager for a scope, which it
needs 10-15 ms to make: one per container, none with --cgroups=disabled);
the tests/e2e/bats/run-*.bats count them.

With no API server running, the command runs its engine in its own
process and every point (client, engine, monitor) is in the trace; with
a server, start it with the same VELARX_TRACE_FILE to see its points.
"""

import argparse
import os
import statistics
import subprocess
import sys
import tempfile
import time


def read_points(path):
    points = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.rstrip("\n").split(" ", 2)
                if len(parts) != 3:
                    continue
                points.append((int(parts[1]), int(parts[0]), parts[2]))
    except FileNotFoundError:
        pass
    return points


def run_once(cmd, trace, settle, truncate=False):
    if truncate:
        # a server keeps the file open (in append mode): emptied, not removed
        open(trace, "w").close()
    else:
        try:
            os.unlink(trace)
        except FileNotFoundError:
            pass
    env = dict(os.environ, VELARX_TRACE_FILE=trace)
    start = time.monotonic_ns()
    p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    _, err = p.communicate()
    end = time.monotonic_ns()
    if p.returncode != 0:
        sys.stderr.write(err.decode(errors="replace"))
        raise SystemExit("command failed with exit code %d" % p.returncode)
    if settle:
        time.sleep(settle)
    points = read_points(trace)
    points.append((start, 0, "spawn"))
    points.append((end, 0, "exit"))
    points.sort()
    seen = {}
    labelled = []
    for ts, pid, label in points:
        n = seen.get(label, 0) + 1
        seen[label] = n
        if n > 1:
            label = "%s#%d" % (label, n)
        labelled.append((ts - start, label))
    return labelled, end - start


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-n", "--runs", type=int, default=50)
    ap.add_argument("-w", "--warmup", type=int, default=5)
    ap.add_argument("-s", "--settle", type=float, default=0.03,
                    help="seconds to wait after each run for the trace points "
                    "written after the exit (default 0.03)")
    ap.add_argument("--trace", help="the trace file, shared with a running "
                    "API server (started with VELARX_TRACE_FILE set to it): "
                    "emptied before each run instead of removed")
    ap.add_argument("--all", action="store_true",
                    help="also print the points after the exit")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if not cmd:
        ap.error("missing command")

    with tempfile.TemporaryDirectory() as tmp:
        trace = args.trace or os.path.join(tmp, "trace")
        keep = args.trace is not None
        for _ in range(args.warmup):
            run_once(cmd, trace, args.settle, keep)
        runs = [run_once(cmd, trace, args.settle, keep) for _ in range(args.runs)]

    offsets = {}
    deltas = {}
    for points, _ in runs:
        prev = 0
        for off, label in points:
            offsets.setdefault(label, []).append(off)
            deltas.setdefault(label, []).append(off - prev)
            prev = off

    order = sorted(offsets, key=lambda l: statistics.median(offsets[l]))
    exit_med = statistics.median(offsets["exit"])
    total = [t for _, t in runs]
    print("%d runs, total median %.2f ms, min %.2f ms, mean %.2f ms" % (
        len(runs), statistics.median(total) / 1e6, min(total) / 1e6,
        statistics.mean(total) / 1e6))
    print("%9s %9s  %s" % ("at ms", "phase ms", "point (phase ends here)"))
    for label in order:
        med = statistics.median(offsets[label])
        if label == "spawn" or (med > exit_med and not args.all):
            continue
        partial = "" if len(offsets[label]) == len(runs) else \
            "  [%d/%d runs]" % (len(offsets[label]), len(runs))
        print("%9.2f %9.2f  %s%s" % (med / 1e6,
                                     statistics.median(deltas[label]) / 1e6,
                                     label, partial))


if __name__ == "__main__":
    main()
