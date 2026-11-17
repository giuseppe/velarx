#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Time pulls into empty stores: velarx (in process, no service) and,
for comparison, podman.

    pull.py [-n RUNS] [--velarx [NAME=]BIN]... [--config NAME=TOML]...
            [--podman] [--dir DIR] [--trace] [--warm IMAGE] IMAGE...

Each run pulls IMAGE into a new store under DIR (removed afterwards), the
tools in turn; the median and the best wall times are shown, and the
median CPU time of the pull and the processes it waited for.  Several
velarx binaries, or one under several configurations, are told apart by
NAME.  The images
come from an insecure registry (localhost:5000 is the default one of the
generated registries.conf; --registry adds others).  --trace prints the
median of velarx's trace phases (VELARX_TRACE_FILE) too.
"""

import argparse
import os
import resource
import shutil
import statistics
import subprocess
import sys
import tempfile
import time


def registries_conf(path, registries):
    with open(path, "w") as f:
        for r in registries:
            f.write('[[registry]]\nlocation = "%s"\ninsecure = true\n' % r)


def cpu_of_children():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def run(cmd, env, cpu=None):
    """The wall time of cmd; the CPU time of it and of the processes it
    waited for is appended to cpu."""
    start, used = time.monotonic(), cpu_of_children()
    p = subprocess.run(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    elapsed = time.monotonic() - start
    if p.returncode != 0:
        sys.exit("%s failed: %s" % (" ".join(cmd), p.stderr.decode(errors="replace")[-2000:]))
    if cpu is not None:
        cpu.append(cpu_of_children() - used)
    return elapsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--runs", type=int, default=5)
    ap.add_argument("--velarx", action="append", default=[],
                    help="a velarx binary, NAME=PATH to compare several")
    ap.add_argument("--config", action="append", default=[],
                    help="NAME=FILE: the velarx config.toml of the binary NAME")
    ap.add_argument("--podman", action="store_true")
    ap.add_argument("--dir", default=os.environ.get("TMPDIR", "/var/tmp"))
    ap.add_argument("--registry", action="append", default=["localhost:5000"])
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--warm", metavar="IMAGE",
                    help="pull IMAGE into each store first (not timed): the pull then "
                    "finds what the store has of it")
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()

    work = tempfile.mkdtemp(prefix="p", dir=a.dir)
    conf = os.path.join(work, "registries.conf")
    registries_conf(conf, a.registry)
    tools = []
    engines = {}
    for spec in a.velarx:
        name, _, path = spec.rpartition("=")
        name = name or "velarx"
        engines[name] = path
        tools.append(name)
    configs = dict(c.split("=", 1) for c in a.config)
    if a.podman:
        tools.append("podman")
    try:
        for image in a.images:
            times = {t: [] for t in tools}
            cpus = {t: [] for t in tools}
            phases = {}
            for i in range(a.runs):
                for tool in tools:
                    store = os.path.join(work, "%d%d" % (tools.index(tool), i))
                    os.makedirs(store)
                    env = dict(os.environ)
                    if tool in engines:
                        home = os.path.join(store, "home")
                        os.makedirs(os.path.join(home, ".config", "velarx"))
                        shutil.copy(conf, os.path.join(home, ".config", "velarx", "registries.conf"))
                        if tool in configs:
                            shutil.copy(configs[tool], os.path.join(home, ".config", "velarx", "config.toml"))
                        env.update(HOME=home, XDG_RUNTIME_DIR=os.path.join(store, "run"),
                                   XDG_CONFIG_HOME=os.path.join(home, ".config"),
                                   XDG_DATA_HOME=os.path.join(home, "data"))
                        os.makedirs(env["XDG_RUNTIME_DIR"])
                        if a.warm:
                            run([engines[tool], "image", "pull", a.warm], env)
                        trace = os.path.join(store, "trace")
                        if a.trace:
                            env["VELARX_TRACE_FILE"] = trace
                        cmd = [engines[tool], "image", "pull", image]
                    else:
                        podman = ["podman", "--root", os.path.join(store, "root"),
                                  "--runroot", os.path.join(store, "run"),
                                  "pull", "-q", "--tls-verify=false"]
                        if a.warm:
                            run(podman + [a.warm], env)
                        cmd = podman + [image]
                    times[tool].append(run(cmd, env, cpus[tool]))
                    if tool in engines and a.trace and os.path.exists(trace):
                        first = None
                        with open(trace) as f:
                            for line in f:
                                _, ns, label = line.split(" ", 2)
                                ns = int(ns)
                                first = ns if first is None else first
                                phases.setdefault(label.strip(), []).append((ns - first) / 1e9)
                    if tool == "podman":
                        subprocess.run(["podman", "unshare", "rm", "-rf", store])
                    else:
                        shutil.rmtree(store, ignore_errors=True)
            base = statistics.median(times[tools[0]])
            for tool in tools:
                med = statistics.median(times[tool])
                print("%-40s %-9s median %6.3fs  best %6.3fs  (%+.0f%% vs %s)  cpu %6.3fs" % (
                    image, tool, med, min(times[tool]), (med / base - 1) * 100, tools[0],
                    statistics.median(cpus[tool])))
            for label, v in sorted(phases.items(), key=lambda kv: statistics.median(kv[1])):
                print("    %-50s %6.3fs" % (label, statistics.median(v)))
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
