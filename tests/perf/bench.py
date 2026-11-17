#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Benchmark create/start/wait/delete through the podman REST API of a
velarx server.

Usage: bench.py [-s SOCKET] [-n RUNS] [-w WARMUP] [-i IMAGE]
                [--run [--velarx BIN]] [--net MODE] [--new-conn] [-- CMD...]

By default every iteration does create, start, wait and DELETE.  With
--run it runs `velarx --socket SOCKET container run --rm IMAGE CMD`
(the client, the request and the container, end to end).  With
--new-conn every request opens a new connection.
"""

import argparse
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import time


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("d")
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)


class Client:
    def __init__(self, path, new_conn):
        self.path = path
        self.new_conn = new_conn
        self.conn = None

    def request(self, method, url, body=None, expect=(200, 201, 204)):
        if self.conn is None or self.new_conn:
            if self.conn is not None:
                self.conn.close()
            self.conn = UnixHTTPConnection(self.path)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        self.conn.request(method, "/v5.0.0/libpod" + url, body=data, headers=headers)
        resp = self.conn.getresponse()
        payload = resp.read()
        if resp.status not in expect:
            raise RuntimeError("%s %s: %d %s" % (method, url, resp.status, payload.decode(errors="replace")))
        return payload


PHASES = ("create", "start", "wait", "delete")
EXTRA = {}
VELARX = "velarx"


def run_cli(client, image, cmd):
    argv = [VELARX, "--socket", client.path, "container", "run", "--rm"]
    if "netns" in EXTRA:
        argv += ["--network", EXTRA["netns"]["nsmode"]]
    t0 = time.perf_counter()
    p = subprocess.run(argv + [image] + cmd, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    t = time.perf_counter() - t0
    if p.returncode != 0 and p.stderr:
        sys.stderr.write(p.stderr.decode(errors="replace"))
    return t, {"run": t}, p.returncode


def run_once(client, image, cmd):
    t = {}
    t0 = time.perf_counter()
    out = client.request("POST", "/containers/create", dict(EXTRA, image=image, command=cmd))
    cid = json.loads(out)["Id"]
    t1 = time.perf_counter()
    client.request("POST", "/containers/%s/start" % cid)
    t2 = time.perf_counter()
    code = int(client.request("POST", "/containers/%s/wait" % cid))
    t3 = time.perf_counter()
    client.request("DELETE", "/containers/%s?force=true" % cid)
    t4 = time.perf_counter()
    t["create"], t["start"], t["wait"], t["delete"] = t1 - t0, t2 - t1, t3 - t2, t4 - t3
    return t4 - t0, t, code


def fmt(s):
    return "%.1f ms" % (s * 1000)


def main():
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    default_sock = os.path.join(runtime, "velarx/velarx.sock") if runtime \
        else "/run/velarx/velarx.sock"
    p = argparse.ArgumentParser()
    p.add_argument("-s", "--socket", default=default_sock)
    p.add_argument("-n", "--runs", type=int, default=20)
    p.add_argument("-w", "--warmup", type=int, default=3)
    p.add_argument("-i", "--image", default="alpine")
    p.add_argument("--run", action="store_true", help="time `velarx container run --rm`")
    p.add_argument("--velarx", default="velarx", help="the velarx client for --run")
    p.add_argument("--net", help="network mode (none, host, bridge, ...), default: the server's")
    p.add_argument("--new-conn", action="store_true", help="open a new connection for every request")
    p.add_argument("cmd", nargs="*", default=["true"])
    args = p.parse_args()

    global VELARX
    VELARX = args.velarx
    if args.net:
        EXTRA["netns"] = {"nsmode": args.net}
    client = Client(args.socket, args.new_conn)
    once = run_cli if args.run else run_once
    names = ("run",) if args.run else PHASES
    for _ in range(args.warmup):
        once(client, args.image, args.cmd)

    totals = []
    phases = {k: [] for k in names}
    for i in range(args.runs):
        total, t, code = once(client, args.image, args.cmd)
        totals.append(total)
        for k in names:
            phases[k].append(t[k])
        if code != 0:
            print("run %d: exit code %d" % (i, code), file=sys.stderr)
        print("\r  %d/%d  current: %s" % (i + 1, args.runs, fmt(total)), end="", file=sys.stderr, flush=True)
    print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    mean = statistics.mean(totals)
    sd = statistics.stdev(totals) if len(totals) > 1 else 0.0
    mode = "velarx container run --rm" if args.run else "create+start+wait+delete"
    if args.net:
        mode += ", net " + args.net
    print("Benchmark: %s %s (%s, %s)" % (args.image, " ".join(args.cmd), mode, "new conn" if args.new_conn else "keep-alive"))
    print("  Time (mean ± σ):     %s ± %s" % (fmt(mean), fmt(sd)))
    print("  Range (min … max):   %s … %s    %d runs" % (fmt(min(totals)), fmt(max(totals)), len(totals)))
    print("  Per phase (mean / median):")
    for k in names:
        print("    %-7s %9s / %s" % (k, fmt(statistics.mean(phases[k])), fmt(statistics.median(phases[k]))))


if __name__ == "__main__":
    main()

