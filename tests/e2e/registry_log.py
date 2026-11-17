#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""A registry that tells what it served: the pulls (GET, HEAD) of the registry
UPSTREAM (host:port, plain HTTP), each request a line of the file LOG once it
is answered:

  METHOD PATH STATUS BYTES

(BYTES: the bytes of the body sent, the part asked for by a range).

  registry_log.py UPSTREAM LOG

Listens on a free port of 127.0.0.1 and prints it on a line of its own;
serves until it is killed.
"""
import http.server
import sys
import threading
import urllib.error
import urllib.request

UPSTREAM, LOG = sys.argv[1], sys.argv[2]
LOCK = threading.Lock()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def forward(self):
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in ("host", "connection")
        }
        req = urllib.request.Request(
            f"http://{UPSTREAM}{self.path}", method=self.command, headers=headers
        )
        try:
            reply = OPENER.open(req)
        except urllib.error.HTTPError as e:
            reply = e
        self.send_response(reply.status)
        for k, v in reply.headers.items():
            if k.lower() not in ("connection", "transfer-encoding"):
                self.send_header(k, v)
        body = b"" if self.command == "HEAD" else reply.read()
        if reply.headers.get("Content-Length") is None:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        with LOCK, open(LOG, "a") as f:
            f.write(f"{self.command} {self.path} {reply.status} {len(body)}\n")

    do_GET = forward
    do_HEAD = forward

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
print(server.server_address[1], flush=True)
server.serve_forever()
