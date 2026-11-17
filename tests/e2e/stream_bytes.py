#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Sends MiB through the `cat` of a container by the attach or the exec of the
# REST API (a unix socket, the connection taken over), checks that all comes
# back in order, and tells what the engine process did meanwhile: the
# descriptors it held before and while the bytes flowed (twice), and the CPU
# it used (clock ticks).  The engine does not carry the bytes of a session, so
# neither grows with the size.
#
#   stream_bytes.py SOCKET attach|exec CONTAINER ENGINE_PID MIB
#
# Prints one line of JSON.  The container of `attach` runs `cat` with its input
# open; the one of `exec` is any running container.

import json
import os
import socket
import sys
import threading

BLOCK = bytes((i * 7 + i // 251) % 256 for i in range(1 << 20))


def head(sock, request):
    sock.sendall(request)
    data = b""
    while b"\r\n\r\n" not in data:
        got = sock.recv(65536)
        if not got:
            break
        data += got
    return data.split(b"\r\n\r\n", 1)


def request(path, upgrade, body=b""):
    lines = ["POST %s HTTP/1.1" % path, "Host: d", "Content-Length: %d" % len(body)]
    if body:
        lines.append("Content-Type: application/json")
    if upgrade:
        lines += ["Connection: Upgrade", "Upgrade: tcp"]
    else:
        lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def call(path, body):
    s = socket.socket(socket.AF_UNIX)
    s.connect(SOCK)
    h, rest = head(s, request(path, False, json.dumps(body).encode()))
    data = rest
    while True:
        got = s.recv(65536)
        if not got:
            break
        data += got
    s.close()
    return json.loads(data[data.index(b"{"):])


def fds(pid):
    return len(os.listdir("/proc/%d/fd" % pid))


def ticks(pid):
    f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])


SOCK, kind, container, pid, mib = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
if kind == "exec":
    eid = call("/v1.44/containers/%s/exec" % container,
               {"Cmd": ["cat"], "AttachStdin": True, "AttachStdout": True})["Id"]
    path = "/v1.44/exec/%s/start" % eid
    body = b'{"Detach":false}'
else:
    path = "/v1.44/containers/%s/attach?stream=1&stdin=1&stdout=1" % container
    body = b""
before = fds(pid)
t0 = ticks(pid)
s = socket.socket(socket.AF_UNIX)
s.connect(SOCK)
h, got = head(s, request(path, True, body))
assert h.startswith(b"HTTP/1.1 101"), h
total = mib << 20
state = {"sent": 0}


def feed():
    try:
        while state["sent"] < total:
            s.sendall(BLOCK)
            state["sent"] += len(BLOCK)
        s.shutdown(socket.SHUT_WR)
    except OSError:
        pass


threading.Thread(target=feed, daemon=True).start()
# the frames of the output (stdout only)
buf = bytearray(got)
count = 0
ok = True
during = []
while True:
    while len(buf) >= 8:
        n = int.from_bytes(buf[4:8], "big")
        if len(buf) < 8 + n:
            break
        if buf[0] != 1:
            ok = False
        piece = memoryview(buf)[8:8 + n]
        at = count % len(BLOCK)
        # (the pieces cut at any place: compare with the pattern at the offset)
        want = (BLOCK[at:] + BLOCK)[:n] if at + n > len(BLOCK) else BLOCK[at:at + n]
        if piece != want:
            ok = False
        count += n
        piece.release()
        del buf[:8 + n]
    # (a quarter and three quarters of the way)
    if count >= total * (1 + 2 * len(during)) // 4 and len(during) < 2:
        during.append(fds(pid))
    chunk = s.recv(1 << 20)
    if not chunk:
        break
    buf += chunk
s.close()
print(json.dumps({"ok": ok and count == total, "count": count, "before": before,
                  "during": during, "ticks": ticks(pid) - t0}))
