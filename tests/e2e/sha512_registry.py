#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""A registry in memory that takes blobs and manifests with sha512 digests, for
the tests of the digests of an image.

  sha512_registry.py MODE

MODE is `distribution` (a manifest is addressed by its sha256 only, as
registry:2 and registry:3 do: a GET by its sha512 is a 404, and the
Docker-Content-Digest is the sha256) or `zot` (a manifest put by its sha512
is addressed by it as well as by the sha256 of its bytes, as zot does).  A blob is stored under the
digest it is uploaded with, in either algorithm, after its bytes are
hashed with it.

Listens on a free port of 127.0.0.1 and prints it and its pid on a line of
its own (the test stops it by that pid);
serves until it is killed.
"""
import hashlib
import http.server
import json
import os
import sys
import uuid

ZOT = sys.argv[1] == "zot"
BLOBS = {}
MANIFESTS = {}
UPLOADS = {}


def digest_of(algorithm, data):
    return f"{algorithm}:{hashlib.new(algorithm, data).hexdigest()}"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, body=b"", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def route(self):
        path, _, query = self.path.partition("?")
        params = dict(p.partition("=")[::2] for p in query.split("&") if p)
        parts = path.strip("/").split("/")
        # v2/REPOSITORY.../(blobs|manifests|tags)/...
        for i, part in enumerate(parts):
            if part in ("blobs", "manifests", "tags") and i >= 2:
                return "/".join(parts[1:i]), part, parts[i + 1 :], params
        return None, None, None, params

    def do_GET(self):
        if self.path.rstrip("/") == "/v2":
            return self.reply(200, b"{}", {"Docker-Distribution-API-Version": "registry/2.0"})
        repo, kind, rest, _ = self.route()
        if kind == "blobs" and rest and rest[0] != "uploads":
            blob = BLOBS.get((repo, rest[0]))
            if blob is None:
                return self.reply(404)
            return self.reply(200, blob, {"Docker-Content-Digest": rest[0]})
        if kind == "manifests" and rest:
            found = MANIFESTS.get((repo, rest[0]))
            if found is None:
                return self.reply(404)
            body, media = found
            return self.reply(
                200,
                body,
                {
                    "Content-Type": media,
                    "Docker-Content-Digest": digest_of("sha256", body),
                },
            )
        if kind == "tags":
            tags = sorted(r for (p, r) in MANIFESTS if p == repo and ":" not in r)
            return self.reply(200, json.dumps({"name": repo, "tags": tags}).encode())
        self.reply(404)

    do_HEAD = do_GET

    def do_POST(self):
        repo, kind, rest, params = self.route()
        if kind != "blobs":
            return self.reply(404)
        self.body()
        if "mount" in params and (params.get("from", ""), params["mount"]) in BLOBS:
            BLOBS[(repo, params["mount"])] = BLOBS[(params["from"], params["mount"])]
            return self.reply(201)
        session = uuid.uuid4().hex
        UPLOADS[session] = b""
        self.reply(
            202,
            headers={"Location": f"/v2/{repo}/blobs/uploads/{session}", "Range": "0-0"},
        )

    def do_PATCH(self):
        repo, kind, rest, _ = self.route()
        session = rest[-1]
        if session not in UPLOADS:
            return self.reply(404)
        UPLOADS[session] += self.body()
        self.reply(
            202,
            headers={
                "Location": f"/v2/{repo}/blobs/uploads/{session}",
                "Range": f"0-{max(len(UPLOADS[session]) - 1, 0)}",
            },
        )

    def do_PUT(self):
        repo, kind, rest, params = self.route()
        data = self.body()
        if kind == "blobs":
            session = rest[-1]
            if session not in UPLOADS:
                return self.reply(404)
            data = UPLOADS.pop(session) + data
            want = params.get("digest", "").replace("%3A", ":")
            algorithm = want.partition(":")[0]
            if algorithm not in ("sha256", "sha512") or digest_of(algorithm, data) != want:
                return self.reply(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}')
            BLOBS[(repo, want)] = data
            return self.reply(201, headers={"Docker-Content-Digest": want})
        if kind == "manifests":
            reference = rest[0]
            media = self.headers.get("Content-Type", "")
            sha256 = digest_of("sha256", data)
            if ":" in reference and reference.partition(":")[0] != "sha256" and not ZOT:
                return self.reply(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}')
            if ":" in reference and digest_of(reference.partition(":")[0], data) != reference:
                return self.reply(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}')
            # (named by the tag put and the sha256 of the bytes, as registry:3
            # and zot do: the sha512 is a name only when it is put by it)
            names = {reference, sha256}
            for name in names:
                MANIFESTS[(repo, name)] = (data, media)
            # (zot answers a put by a sha512 with it)
            named = reference if ":" in reference else sha256
            return self.reply(201, headers={"Docker-Content-Digest": named})
        self.reply(404)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print(server.server_address[1], os.getpid(), flush=True)
server.serve_forever()
