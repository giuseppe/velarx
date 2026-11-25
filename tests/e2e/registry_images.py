#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Images made in a registry by their bytes, for the tests of the chain of
trust of an image named by its digest.

  registry_images.py variant REGISTRY REPOSITORY TAG NEW-TAG
      a copy of the image REPOSITORY:TAG whose configuration has another
      label: another manifest (and configuration) over the same layers.
      Prints its manifest digest.
  registry_images.py index REGISTRY REPOSITORY TAG NEW-TAG [TAG...]
      an OCI index of the manifest REPOSITORY:TAG (and of the more TAGs
      after it, in that order), each for the platform of its configuration.
      Prints the digest of the index.
  registry_images.py digest REGISTRY REPOSITORY TAG
      the digest of the manifest REPOSITORY:TAG.
  registry_images.py copy REGISTRY REPOSITORY TAG NEW-REPOSITORY NEW-TAG
      the manifest REPOSITORY:TAG, with its blobs, in NEW-REPOSITORY (an
      image of another writer, in a repository of the test): the digests of
      EROFS images that its writer stated (a layer's
      io.containers.composefs.digest, the composefs.merged.* of the manifest)
      are taken off, as another writer states none.  Prints its manifest
      digest.
  registry_images.py annotate REGISTRY REPOSITORY TAG NEW-TAG N [VALUE]
      a copy of the image REPOSITORY:TAG whose layer N (from 1) states VALUE
      as the digests of its EROFS image (io.containers.composefs.digest), or
      none without VALUE.  Prints its manifest digest.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from registry_client import call, upload_blob  # noqa: E402

ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def get_manifest(base, repo, ref):
    _, headers, body = call("GET", f"{base}/v2/{repo}/manifests/{ref}", headers={"Accept": ACCEPT})
    return body, headers.get("Content-Type", "")


def put_manifest(base, repo, ref, body, media_type):
    call("PUT", f"{base}/v2/{repo}/manifests/{ref}", body, {"Content-Type": media_type})


def put_blob(base, repo, data):
    upload_blob(base, repo, data, sha(data))


def main(argv):
    what, registry, repo, tag = argv[:4]
    base = f"http://{registry}"
    body, media_type = get_manifest(base, repo, tag)
    if what == "digest":
        print(sha(body))
        return
    if what == "copy":
        dest, new_tag = argv[4:6]
        manifest = json.loads(body)
        for blob in [manifest["config"]] + manifest["layers"]:
            _, _, data = call("GET", f"{base}/v2/{repo}/blobs/{blob['digest']}")
            put_blob(base, dest, data)
        for layer in manifest["layers"]:
            layer.get("annotations", {}).pop("io.containers.composefs.digest", None)
            if not layer.get("annotations", True):
                del layer["annotations"]
        annotations = manifest.get("annotations", {})
        for key in [k for k in annotations if k.startswith("composefs.merged.")]:
            del annotations[key]
        out = json.dumps(manifest, separators=(",", ":")).encode()
        put_manifest(base, dest, new_tag, out, media_type)
        print(sha(out))
        return
    if what == "annotate":
        new_tag, n = argv[4], int(argv[5])
        manifest = json.loads(body)
        if not 1 <= n <= len(manifest["layers"]):
            sys.exit(f"no layer {n} in {repo}:{tag}")
        annotations = manifest["layers"][n - 1].setdefault("annotations", {})
        if len(argv) > 6:
            annotations["io.containers.composefs.digest"] = argv[6]
        else:
            annotations.pop("io.containers.composefs.digest", None)
        out = json.dumps(manifest, separators=(",", ":")).encode()
        put_manifest(base, repo, new_tag, out, media_type)
        print(sha(out))
        return
    new_tag = argv[4]
    if what == "variant":
        manifest = json.loads(body)
        _, _, config = call("GET", f"{base}/v2/{repo}/blobs/{manifest['config']['digest']}")
        config = json.loads(config)
        config.setdefault("config", {}).setdefault("Labels", {})["velarx.e2e"] = "variant"
        data = json.dumps(config, separators=(",", ":")).encode()
        put_blob(base, repo, data)
        manifest["config"]["digest"] = sha(data)
        manifest["config"]["size"] = len(data)
        out = json.dumps(manifest, separators=(",", ":")).encode()
        put_manifest(base, repo, new_tag, out, media_type)
        print(sha(out))
    elif what == "index":
        entries = []
        for t in [tag] + argv[5:]:
            body, media_type = get_manifest(base, repo, t)
            manifest = json.loads(body)
            _, _, config = call("GET", f"{base}/v2/{repo}/blobs/{manifest['config']['digest']}")
            config = json.loads(config)
            entries.append(
                {
                    "mediaType": media_type,
                    "digest": sha(body),
                    "size": len(body),
                    "platform": {"os": config["os"], "architecture": config["architecture"]},
                }
            )
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": entries,
        }
        out = json.dumps(index, separators=(",", ":")).encode()
        put_manifest(base, repo, new_tag, out, index["mediaType"])
        print(sha(out))
    else:
        sys.exit(f"unknown command {what}")


main(sys.argv[1:])
