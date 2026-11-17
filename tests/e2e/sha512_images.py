#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Images whose digests are sha512, made in a registry from the bytes of an
image with gzip layers, for the tests of the digests of an image.

  sha512_images.py mixed REGISTRY REPOSITORY TAG NEW-TAG
      the image REPOSITORY:TAG with a sha512 configuration, sha512 diff ids and
      a manifest that is named by its sha512, over its layers as they are
      (sha256 blobs).  Prints the sha512 digest of the manifest.
  sha512_images.py all REGISTRY REPOSITORY TAG NEW-TAG
      the same, with the layer blobs sha512 too.  Prints the sha512 digest of
      the manifest.

The manifest is put by its tag: a distribution registry does not address a
manifest by a sha512 (it takes the blobs and the manifests that name them).
"""
import gzip
import hashlib
import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from registry_client import call, upload_blob  # noqa: E402

OCI = "application/vnd.oci.image.manifest.v1+json"


def sha512(data):
    return "sha512:" + hashlib.sha512(data).hexdigest()


def get_blob(base, repo, digest):
    return call("GET", f"{base}/v2/{repo}/blobs/{digest}")[2]


def put_blob(base, repo, data):
    """The blob under its sha512 (`digest-algorithm` tells the registry)."""
    digest = sha512(data)
    upload_blob(base, repo, data, digest, "sha512")
    return digest


def put_manifest(base, repo, tag, body):
    """The manifest by its tag, and by its sha512 too (a registry that names
    a tag's manifest by its sha256 only takes the second or refuses it)."""
    call("PUT", f"{base}/v2/{repo}/manifests/{tag}", body, {"Content-Type": OCI})
    try:
        call("PUT", f"{base}/v2/{repo}/manifests/{sha512(body)}", body, {"Content-Type": OCI})
    except urllib.error.HTTPError as e:
        if not 400 <= e.code < 500:
            raise


def main():
    kind, reg, repo, tag, new = sys.argv[1:6]
    base = f"http://{reg}"
    _, _, body = call(
        "GET", f"{base}/v2/{repo}/manifests/{tag}", headers={"Accept": OCI}
    )
    manifest = json.loads(body)
    if kind == "state":
        # the same image, its layers stating the digests of their EROFS
        # images (argv[6:], one each, `sha512:HEX`)
        for layer, erofs in zip(manifest["layers"], sys.argv[6:]):
            layer["annotations"] = dict(
                layer.get("annotations", {}), **{"io.containers.composefs.digest": erofs}
            )
        body = json.dumps(manifest, separators=(",", ":")).encode()
        put_manifest(base, repo, new, body)
        print(sha512(body))
        return
    config = json.loads(get_blob(base, repo, manifest["config"]["digest"]))
    diff_ids = []
    layers = []
    for layer in manifest["layers"]:
        blob = get_blob(base, repo, layer["digest"])
        if not blob.startswith(b"\x1f\x8b"):
            sys.exit(f"the layer {layer['digest']} is not gzip")
        diff_ids.append(sha512(gzip.decompress(blob)))
        if kind == "all":
            layer = dict(layer, digest=put_blob(base, repo, blob))
        layers.append(layer)
    config["rootfs"]["diff_ids"] = diff_ids
    config_bytes = json.dumps(config, separators=(",", ":")).encode()
    manifest["config"] = {
        "mediaType": manifest["config"]["mediaType"],
        "digest": put_blob(base, repo, config_bytes),
        "size": len(config_bytes),
    }
    manifest["layers"] = layers
    # (the merged-tree digest of the base is the one of its sha256 objects: an
    # image with other digests than its layers has none)
    manifest["annotations"] = {
        k: v
        for k, v in manifest.get("annotations", {}).items()
        if not k.startswith("composefs.merged.")
    }
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
    put_manifest(base, repo, new, manifest_bytes)
    print(sha512(manifest_bytes))


main()
