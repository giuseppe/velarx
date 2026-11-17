#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""A smart HTTP git server for the tests: git http-backend behind a WSGI
server on 127.0.0.1.

    git_http.py ROOT PORTFILE

serves the repositories below ROOT at http://127.0.0.1:PORT/NAME.git and
writes PORT to PORTFILE once it listens.
"""

import os
import subprocess
import sys
from wsgiref.simple_server import WSGIRequestHandler, make_server

ROOT = os.path.abspath(sys.argv[1])
BACKEND = "/usr/libexec/git-core/git-http-backend"


def app(environ, start_response):
    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length) if length else b""
    env = {
        "GIT_PROJECT_ROOT": ROOT,
        "GIT_HTTP_EXPORT_ALL": "1",
        "PATH_INFO": environ.get("PATH_INFO", ""),
        "QUERY_STRING": environ.get("QUERY_STRING", ""),
        "REQUEST_METHOD": environ["REQUEST_METHOD"],
        "CONTENT_TYPE": environ.get("CONTENT_TYPE", ""),
        "CONTENT_LENGTH": str(len(body)),
        "HTTP_GIT_PROTOCOL": environ.get("HTTP_GIT_PROTOCOL", ""),
        "REMOTE_ADDR": "127.0.0.1",
        "PATH": "/usr/bin:/bin",
    }
    out = subprocess.run([BACKEND], input=body, env=env, capture_output=True).stdout
    head, _, rest = out.partition(b"\r\n\r\n")
    status = "200 OK"
    headers = []
    for line in head.decode("latin-1").split("\r\n"):
        if not line:
            continue
        k, _, v = line.partition(":")
        if k.lower() == "status":
            status = v.strip()
        else:
            headers.append((k, v.strip()))
    start_response(status, headers)
    return [rest]


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


server = make_server("127.0.0.1", 0, app, handler_class=Quiet)
with open(sys.argv[2] + ".tmp", "w") as f:
    f.write(str(server.server_port))
os.rename(sys.argv[2] + ".tmp", sys.argv[2])
server.serve_forever()
