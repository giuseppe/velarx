#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""network-call.py SOCKET METHOD PARAMETERS_JSON [NETNS]: one call of a network
provider (org.velarx.Network, varlink: JSON messages ended by a NUL byte) on
the unix socket SOCKET, the reply printed as JSON.  NETNS, a path such as
/run/netns/NAME, is passed as the one descriptor of the call (`Start`)."""
import array, json, os, socket, sys

sock_path, method, parameters = sys.argv[1:4]
fds = [os.open(sys.argv[4], os.O_RDONLY)] if len(sys.argv) > 4 else []
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
message = json.dumps({"method": method, "parameters": json.loads(parameters)}).encode() + b"\0"
s.sendmsg([message], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else [])
reply = b""
while not reply.endswith(b"\0"):
    data = s.recv(65536)
    if not data:
        break
    reply += data
reply = json.loads(reply.rstrip(b"\0"))
print(json.dumps(reply))
sys.exit(1 if "error" in reply else 0)
