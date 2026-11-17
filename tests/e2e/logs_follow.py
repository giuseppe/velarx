#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# A client of the followed logs of the REST API (unix socket), for
# logs-follow.bats.
#
#   logs_follow.py get SOCKET PATH [SECONDS]
#       Print the lines of the framed stream of PATH (stdout and stderr, the
#       stream's name in front for stderr) and, last, `end` when the server
#       ended the stream or `timeout` after SECONDS (default 30).
#   logs_follow.py once SOCKET CONTAINER N
#       Followers of a container that prints 1..N (one number a line):
#       the first starts at once, the next ones when the first has read a
#       tenth, a quarter and half of the lines (so that the container writes
#       while they read), one more is slow (it reads a frame, then waits
#       until the others are done).  Every follower must get 1..N, once each
#       and in order.  Exits 1 if one does not.

import socket
import sys
import threading
import time


def open_stream(sock_path, path, timeout):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(sock_path)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    return s


def body_chunks(s):
    """The bytes of the body of the answer, as they come."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    if status != 200:
        raise RuntimeError(f"status {status}: {rest[:200]!r}")
    chunked = b"transfer-encoding: chunked" in head.lower()
    if not chunked:
        if rest:
            yield rest
        while True:
            d = s.recv(65536)
            if not d:
                return
            yield d
    data = rest
    while True:
        while b"\r\n" not in data:
            d = s.recv(65536)
            if not d:
                return
            data += d
        size_line, data = data.split(b"\r\n", 1)
        size = int(size_line.split(b";")[0], 16)
        if size == 0:
            return
        while len(data) < size + 2:
            d = s.recv(65536)
            if not d:
                return
            data += d
        yield data[:size]
        data = data[size + 2:]


def frames(s):
    """(stream, payload) of the frames of the body."""
    buf = b""
    for chunk in body_chunks(s):
        buf += chunk
        while len(buf) >= 8:
            n = int.from_bytes(buf[4:8], "big")
            if len(buf) < 8 + n:
                break
            yield buf[0], buf[8:8 + n]
            buf = buf[8 + n:]


def cmd_get(sock_path, path, seconds):
    s = open_stream(sock_path, path, seconds)
    pending = {1: b"", 2: b""}
    try:
        for stream, data in frames(s):
            pending[stream] += data
            while b"\n" in pending[stream]:
                line, pending[stream] = pending[stream].split(b"\n", 1)
                prefix = b"" if stream == 1 else b"[err] "
                sys.stdout.buffer.write(prefix + line + b"\n")
                sys.stdout.buffer.flush()
        print("end")
    except socket.timeout:
        print("timeout")


def cmd_once(sock_path, name, n):
    path = f"/libpod/containers/{name}/logs?stdout=true&follow=true"
    reached = {k: threading.Event() for k in (n // 10, n // 4, n // 2)}
    others_done = threading.Event()
    results = {}

    def follow(label, slow=False):
        s = open_stream(sock_path, path, 120)
        got = []
        pending = b""
        for _, data in frames(s):
            pending += data
            *lines, pending = pending.split(b"\n")
            got += [int(x) for x in lines]
            if label == "first":
                for k, ev in reached.items():
                    if got and got[-1] >= k:
                        ev.set()
            if slow and len(got) and not others_done.is_set():
                others_done.wait(120)
        results[label] = got

    threads = [threading.Thread(target=follow, args=("first",))]
    for i, k in enumerate(sorted(reached)):
        def later(k=k, i=i):
            reached[k].wait(120)
            follow(f"at {k}")
        threads.append(threading.Thread(target=later))
    def slow():
        reached[n // 4].wait(120)
        follow("slow", slow=True)
    threads.append(threading.Thread(target=slow))
    for t in threads:
        t.start()
    for t in threads[:-1]:
        t.join(150)
    others_done.set()
    threads[-1].join(150)
    want = list(range(1, n + 1))
    bad = 0
    for label in sorted(results):
        got = results[label]
        # (a follower that starts late gets the lines from the start too)
        ok = got == want
        print(f"{label}: {'ok' if ok else 'DIFFERS'} ({len(got)} lines, "
              f"{len(got) - len(set(got))} repeated)")
        bad += not ok
    if len(results) != len(threads):
        print(f"only {len(results)} of {len(threads)} followers finished")
        bad += 1
    sys.exit(1 if bad else 0)


def cmd_hold(sock_path, count, names):
    """`count` followers of the containers `names` (in turn), all kept open
    until the containers end: "ready" once each read the first line, then
    "ok" when every one read exactly `first` and `last` and then the end of
    the stream."""
    path = "/libpod/containers/%s/logs?stdout=true&follow=true"
    lock = threading.Lock()
    started = [0]
    all_started = threading.Event()
    results = []

    def follow(name):
        got = []
        pending = b""
        try:
            s = open_stream(sock_path, path % name, 120)
            for _, data in frames(s):
                pending += data
                *lines, pending = pending.split(b"\n")
                got += [x.decode() for x in lines]
                if len(got) == 1:
                    with lock:
                        started[0] += 1
                        if started[0] == count:
                            all_started.set()
            results.append(got)
        except Exception as e:
            results.append([repr(e)])

    threads = [threading.Thread(target=follow, args=(names[i % len(names)],))
               for i in range(count)]
    for t in threads:
        t.start()
    if all_started.wait(120):
        print("ready", flush=True)
    for t in threads:
        t.join(150)
    bad = [g for g in results if g != ["first", "last"]]
    if len(results) == count and not bad:
        print("ok", flush=True)
    else:
        print(f"bad: {len(results)} of {count} ended, e.g. {bad[:2]}", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "get":
        cmd_get(a[1], a[2], float(a[3]) if len(a) > 3 else 30)
    elif a[0] == "hold":
        cmd_hold(a[1], int(a[2]), a[3:])
    elif a[0] == "once":
        cmd_once(a[1], a[2], int(a[3]))
    else:
        sys.exit("usage: see the head of this file")
