#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# A client of the streams of the REST API (exec start, attach) on a unix
# socket: it sends the request (taking the connection over with `Upgrade:
# tcp` unless --no-upgrade), sends the inputs, and prints the head of the
# answer (without its date) and the bytes it gets, so that the transcripts of
# two servers can be compared.
#
#   hijack_client.py SOCKET METHOD PATH [--body JSON] [--no-upgrade]
#       [--pipelined TEXT] [--input TEXT[@SECONDS]]... [--eof] [--read SECONDS]
#       [--close-after SECONDS]
#
# TEXT is a Python string literal body ('ls\n', '\x10\x11').  --pipelined
# sends TEXT in the same write as the request, before the answer (input the
# server has read with the request must reach the process).  --input waits
# SECONDS (default 0.5) before it sends, --eof half closes after the inputs
# (the end of the input), --read is how long it waits for the end of the
# stream (default 10), --close-after closes the connection that many seconds
# after the head (a client that goes away).

import select
import socket
import sys
import time


def main():
    args = sys.argv[1:]
    sock_path, method, path = args[:3]
    args = args[3:]
    body = b""
    upgrade = True
    inputs = []
    eof = False
    read = 10.0
    close_after = None
    pipelined = b""
    while args:
        a = args.pop(0)
        if a == "--body":
            body = args.pop(0).encode()
        elif a == "--pipelined":
            pipelined = args.pop(0).encode().decode("unicode_escape").encode("latin-1")
        elif a == "--no-upgrade":
            upgrade = False
        elif a == "--input":
            spec = args.pop(0)
            delay = 0.5
            if "@" in spec and spec.rsplit("@", 1)[1].replace(".", "").isdigit():
                spec, d = spec.rsplit("@", 1)
                delay = float(d)
            inputs.append((delay, spec.encode().decode("unicode_escape").encode("latin-1")))
        elif a == "--eof":
            eof = True
        elif a == "--read":
            read = float(args.pop(0))
        elif a == "--close-after":
            close_after = float(args.pop(0))
        else:
            sys.stderr.write("invalid argument %s\n" % a)
            return 2

    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    req = "%s %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n" % (method, path)
    if upgrade:
        req += "Connection: Upgrade\r\nUpgrade: tcp\r\n"
    req += "Content-Length: %d\r\n\r\n" % len(body)
    s.sendall(req.encode() + body + pipelined)

    buf = b""
    deadline = time.time() + read
    while b"\r\n\r\n" not in buf and time.time() < deadline:
        r, _, _ = select.select([s], [], [], 0.2)
        if r:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    keep = [l for l in lines if not l.lower().startswith(("date:", "content-length:"))]
    print("\n".join(keep))
    status = lines[0].split(" ")[1] if lines and " " in lines[0] else "?"
    chunked = any(l.lower() == "transfer-encoding: chunked" for l in lines)
    length = None
    for l in lines:
        if l.lower().startswith("content-length:"):
            length = int(l.split(":")[1])

    data = rest
    start = time.time()
    pending = list(inputs)
    next_at = start + (pending[0][0] if pending else 0)
    closed_write = False
    while time.time() < start + read:
        now = time.time()
        if pending and now >= next_at:
            _, text = pending.pop(0)
            try:
                s.sendall(text)
            except OSError:
                pass
            next_at = now + (pending[0][0] if pending else 0)
        if not pending and eof and not closed_write and status == "101":
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            closed_write = True
        if close_after is not None and now - start >= close_after:
            break
        if length is not None and len(data) >= length and not chunked:
            break
        r, _, _ = select.select([s], [], [], 0.1)
        if r:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        if chunked and data.endswith(b"0\r\n\r\n"):
            break
    if chunked:
        out = b""
        raw = data
        while raw:
            size_line, _, raw = raw.partition(b"\r\n")
            try:
                size = int(size_line.split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += raw[:size]
            raw = raw[size + 2:]
        data = out
    print("--")
    sys.stdout.write(repr(data) + "\n")
    s.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
