# SPDX-License-Identifier: Apache-2.0
# storage-fake.py SOCKET PROTO: a storage service that answers every call with
# a GetInfo of the protocol version PROTO (the other fields are those of a
# service of that version, which the engine must not read), for the tests of
# a service of another version.  It ends on SIGTERM.
import json, os, signal, socket, sys, threading

path, proto = sys.argv[1], int(sys.argv[2])
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
os.chmod(path, 0o600)
srv.listen(16)
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))


def serve(conn):
    with conn:
        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            while b"\0" in buf:
                _, buf = buf.split(b"\0", 1)
                reply = {"parameters": {"proto": proto, "version": "9.9.9", "name": "fake-future",
                                        "something": {"the": "engine cannot read"}}}
                conn.sendall(json.dumps(reply).encode() + b"\0")


while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
