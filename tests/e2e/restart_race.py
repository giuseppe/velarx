#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Ask the engine on SOCKET to restart, then at once connect again and call
GetInfo on the new connection.  The old engine must not take it: the
connection waits in the queue of the socket for the engine that follows, and
is not cut when the old one ends.  Prints "ok" when the connection is still
served after the old engine has closed the connection of the Restart (that
is when it ends), else the failure; exit status 1."""
import json, os, socket, sys, select

sock_path = sys.argv[1]


def call(s, method, parameters=None):
    s.sendall(json.dumps({"method": "org.velarx.Engine." + method,
                          "parameters": parameters or {}}).encode() + b"\0")


def reply(s, timeout):
    buf = b""
    while not buf.endswith(b"\0"):
        r, _, _ = select.select([s], [], [], timeout)
        if not r:
            return None
        data = s.recv(65536)
        if not data:
            raise EOFError("end of file")
        buf += data
    return json.loads(buf[:-1])


first = socket.socket(socket.AF_UNIX)
first.connect(sock_path)
call(first, "Restart", {"running": True})
if not reply(first, 10)["parameters"]["restarted"]:
    sys.exit("the engine did not restart")
second = socket.socket(socket.AF_UNIX)
second.connect(sock_path)
call(second, "GetInfo")
try:
    got = reply(second, 60)
    if got is None:
        sys.exit("no answer to GetInfo")
    # (the old engine ends its connections when it ends: the one of the
    # Restart is at its end of file then; one it took would be cut too)
    select.select([first], [], [], 60)
    if first.recv(1) != b"":
        sys.exit("the old engine said more after the restart")
    call(second, "Ping")
    if reply(second, 60) is None:
        sys.exit("no answer to Ping")
except (EOFError, BrokenPipeError, ConnectionResetError) as e:
    sys.exit("the connection was cut: %s" % e)
print("ok")
