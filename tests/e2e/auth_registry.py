#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""A registry that asks for credentials: the pulls of the registry UPSTREAM
(host:port, plain HTTP) for a client that sends USER:PASSWORD (HTTP basic
authentication), a 401 with its challenge for one that does not.

  auth_registry.py UPSTREAM USER:PASSWORD

Listens on a free port of 127.0.0.1 and prints it on a line of its own;
serves until it is killed.  Each request it refused is told on the standard
error (the tests look for them).
"""
import base64
import http.server
import sys
import urllib.error
import urllib.request

UPSTREAM, CREDENTIALS = sys.argv[1], sys.argv[2]
EXPECTED = "Basic " + base64.b64encode(CREDENTIALS.encode()).decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def forward(self):
        if self.headers.get("Authorization") != EXPECTED:
            print(f"refused {self.command} {self.path}", file=sys.stderr, flush=True)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="velarx-e2e"')
            self.send_header("Docker-Distribution-API-Version", "registry/2.0")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in ("host", "authorization", "connection")
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

    do_GET = forward
    do_HEAD = forward

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
print(server.server_address[1], flush=True)
server.serve_forever()
