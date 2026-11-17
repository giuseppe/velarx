# SPDX-License-Identifier: Apache-2.0
# storage-call.py SOCKET METHOD [PARAMETERS-JSON]: one call of org.velarx.Storage
# on the service at SOCKET, as an administrator would make it (ListStores, DropStore
# ...): prints the reply as a line of JSON, "error NAME {parameters}" for an error.
# Exits 1 for an error, 2 when the service does not answer.
import json, socket, sys

sock, method = sys.argv[1], sys.argv[2]
params = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(20)
try:
    s.connect(sock)
    s.sendall(json.dumps({"method": "org.velarx.Storage." + method, "parameters": params}).encode() + b"\0")
    buf = b""
    while not buf.endswith(b"\0"):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
except OSError as e:
    print(f"no answer: {e}")
    sys.exit(2)
reply = json.loads(buf.rstrip(b"\0") or b"{}")
if "error" in reply:
    print("error", reply["error"].rsplit(".", 1)[-1], json.dumps(reply.get("parameters", {})))
    sys.exit(1)
print(json.dumps(reply.get("parameters", {})))
