#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# analyze.py DIR N: summary of a rollout.sh run
import re, sys, statistics as st, glob, os
d, n = sys.argv[1], int(sys.argv[2])
tick = os.sysconf("SC_CLK_TCK")
walls, regp, fails, regmb = [], [], [], []
for i in range(1, n + 1):
    t = open(f"{d}/pull-{i}.log", errors="replace").read()
    m = re.search(r"rc=(\d+) wall=([\d.]+)", t)
    rc, wall = int(m.group(1)), float(m.group(2))
    if rc:
        fails.append((i, t.strip().splitlines()[-3:]))
    walls.append(wall)
    reg = re.search(r"From registry:\s+\d+ files, ([\d.]+) (\w+)", t)
    tot = re.search(r"Total: ([\d.]+) (\w+) \(([^)]*)\)", t)
    if tot:
        pm = re.search(r"([\d.]+)% registry", tot.group(3))
        regp.append(float(pm.group(1)) if pm else 0.0)
def mb(v, u):
    return float(v) * {"B": 1e-6, "KB": 1e-3, "MB": 1, "GB": 1e3}[u]
reqs = blob = byts = 0
by_ip = {}
for line in open(f"{d}/registry.log", errors="replace"):
    m = re.match(r'(\S+) - - \[[^\]]*\] "(\w+) (\S+) [^"]*" (\d+) (\d+)', line)
    if not m:
        continue
    reqs += 1
    b = int(m.group(5))
    byts += b
    if "/blobs/" in m.group(3):
        blob += 1
    by_ip[m.group(1)] = by_ip.get(m.group(1), 0) + b
def res(f):
    r = {}
    for line in open(f):
        k, *kv = line.split()
        r[k] = dict(x.split("=") for x in kv)
    return r
cpu, hwm = [], []
for i in range(1, n + 1):
    a, b = res(f"{d}/res-after-{i}.txt"), res(f"{d}/res-before-{i}.txt")
    c = sum(int(a[k]["ticks"]) - int(b.get(k, {"ticks": 0})["ticks"]) for k in a) / tick
    cpu.append(c)
    hwm.append(sum(int(a[k]["hwm_kb"]) for k in a) / 1024)
a0, b0 = res(f"{d}/res-after-0.txt"), res(f"{d}/res-before-0.txt")
seedcpu = sum(int(a0[k]["ticks"]) - int(b0[k]["ticks"]) for k in a0) / tick
sent = {}
for f in glob.glob(f"{d}/stats-*.json"):
    m = re.search(r'"chunks_sent": *(\d+)', open(f).read())
    sent[int(re.search(r"stats-(\d+)", f).group(1))] = int(m.group(1)) if m else 0
q = lambda v, p: sorted(v)[min(len(v) - 1, int(p * len(v)))]
print(f"pullers={n} failed={len(fails)}")
for f in fails[:5]:
    print("  FAIL", f)
print(f"wall s: min={min(walls):.2f} p50={q(walls,.5):.2f} p90={q(walls,.9):.2f} max={max(walls):.2f}")
print(f"registry share per node (%): min={min(regp):.1f} p50={q(regp,.5):.1f} max={max(regp):.1f}; nodes >50% registry: {sum(1 for r in regp if r > 50)}; nodes >1%: {sum(1 for r in regp if r > 1)}")
print(f"registry: {reqs} requests, {blob} blob requests, {byts/1e6:.1f} MB served, {len(by_ip)} client IPs")
print(f"puller cpu s: p50={q(cpu,.5):.2f} max={max(cpu):.2f}; peak rss MB (engine+p2p trees): p50={q(hwm,.5):.0f} max={max(hwm):.0f}; seed cpu s={seedcpu:.2f}")
s = sorted(sent.items(), key=lambda x: -x[1])
tot = sum(sent.values()) or 1
print(f"chunks sent total={tot}; seed(n0)={sent.get(0,0)} ({100*sent.get(0,0)/tot:.0f}%); top5={s[:5]}; nodes that sent >0: {sum(1 for _,v in s if v)}")
