# SPDX-License-Identifier: Apache-2.0
"""Make an oci-archive of an image of LAYERS layers: the layers of another
and, on top of them, as many as it takes, each with one small file
(`/many/NNNN`), so the image runs as the base does.

  python3 -I many_layers.py BASE-OCI-ARCHIVE OUT-OCI-ARCHIVE LAYERS

It prints how many layers it added.
"""
import gzip
import hashlib
import io
import json
import sys
import tarfile

base, out, layers = sys.argv[1], sys.argv[2], int(sys.argv[3])
src = tarfile.open(base)


def blob(digest):
    return src.extractfile("blobs/sha256/" + digest.split(":")[1]).read()


def digest_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


index = json.load(src.extractfile("index.json"))
manifest = json.loads(blob(index["manifests"][0]["digest"]))
config = json.loads(blob(manifest["config"]["digest"]))

blobs = {}


def put(data):
    d = digest_of(data)
    blobs[d] = data
    return d


# (the digests of the EROFS images that the base was saved with are of its
# layers alone)
for annotations in [manifest] + manifest["layers"]:
    for key in list(annotations.get("annotations", {})):
        if key.startswith("composefs."):
            del annotations["annotations"][key]
    if not annotations.get("annotations", True):
        del annotations["annotations"]
for layer in manifest["layers"]:
    put(blob(layer["digest"]))

extra = layers - len(manifest["layers"])
if extra < 0:
    sys.exit("the base has %d layers, more than %d" % (len(manifest["layers"]), layers))
for i in range(extra):
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w", format=tarfile.PAX_FORMAT) as t:
        data = b"%d\n" % i
        info = tarfile.TarInfo("many/%04d" % i)
        info.size = len(data)
        info.mtime = 0
        t.addfile(info, io.BytesIO(data))
    raw = tar.getvalue()
    # (mtime 0: the same bytes for the same N)
    packed = gzip.compress(raw, mtime=0)
    manifest["layers"].append(
        {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": put(packed),
            "size": len(packed),
        }
    )
    config["rootfs"]["diff_ids"].append(digest_of(raw))
    config.setdefault("history", []).append({"created_by": "many_layers %d" % i})

manifest["config"]["digest"] = put(json.dumps(config).encode())
manifest["config"]["size"] = len(blobs[manifest["config"]["digest"]])
manifest_bytes = json.dumps(manifest).encode()
descriptor = {
    "mediaType": manifest["mediaType"] if "mediaType" in manifest else "application/vnd.oci.image.manifest.v1+json",
    "digest": put(manifest_bytes),
    "size": len(manifest_bytes),
}

dest = tarfile.open(out, "w")


def add(name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    dest.addfile(info, io.BytesIO(data))


add("oci-layout", b'{"imageLayoutVersion": "1.0.0"}')
for d, data in blobs.items():
    add("blobs/sha256/" + d.split(":")[1], data)
add("index.json", json.dumps({"schemaVersion": 2, "manifests": [descriptor]}).encode())
dest.close()
print(extra)
