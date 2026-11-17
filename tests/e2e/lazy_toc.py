#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""What the layers of an image of a registry say about a lazy pull, as the
test of tools/make-lazy-fixtures reads it.

  lazy_toc.py REGISTRY REPOSITORY TAG

Prints one line, `gzip` when no layer states zstd:chunked metadata, else
`chunked REG VERITY SHA256`: over every layer, the regular files with
content, those whose table of contents gives `fsverity` (`sha256-12:HEX`),
and those that give `digest` (`sha256:HEX`).  Exits 1 when a table of
contents does not verify against `manifest-checksum` or a value is not of
those forms.
"""
import hashlib
import json
import re
import subprocess
import sys

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from registry_client import call  # noqa: E402

PREFIX = "io.github.containers.zstd-chunked."
OCI = "application/vnd.oci.image.manifest.v1+json"


def main(registry, repo, tag):
    base = f"http://{registry}/v2/{repo}"
    _, _, body = call("GET", f"{base}/manifests/{tag}", headers={"Accept": OCI})
    layers = json.loads(body)["layers"]
    if not any(PREFIX + "manifest-position" in (l.get("annotations") or {}) for l in layers):
        print("gzip")
        return 0
    reg = verity = sha = 0
    for layer in layers:
        notes = layer.get("annotations") or {}
        offset, length, _, _ = (int(x) for x in notes[PREFIX + "manifest-position"].split(":"))
        _, _, z = call(
            "GET",
            f"{base}/blobs/{layer['digest']}",
            headers={"Range": f"bytes={offset}-{offset + length - 1}"},
        )
        if "sha256:" + hashlib.sha256(z).hexdigest() != notes[PREFIX + "manifest-checksum"]:
            print("the table of contents does not match manifest-checksum", file=sys.stderr)
            return 1
        toc = json.loads(subprocess.run(["zstd", "-dc"], input=z, capture_output=True, check=True).stdout)
        for e in toc["entries"]:
            if e["type"] != "reg" or not e.get("size"):
                continue
            reg += 1
            if "fsverity" in e:
                if not re.fullmatch(r"sha256-12:[0-9a-f]{64}", e["fsverity"]):
                    print(f"bad fsverity {e['fsverity']}", file=sys.stderr)
                    return 1
                verity += 1
            if "digest" in e:
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", e["digest"]):
                    print(f"bad digest {e['digest']}", file=sys.stderr)
                    return 1
                sha += 1
    print("chunked", reg, verity, sha)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
