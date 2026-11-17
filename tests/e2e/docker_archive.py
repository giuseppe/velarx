# SPDX-License-Identifier: Apache-2.0
"""Make a docker-archive (`docker save`: manifest.json, the configuration and
the layers as members) from an oci-archive of one image.

  python3 -I docker_archive.py OCI-ARCHIVE DOCKER-ARCHIVE REPO-TAG
"""
import io
import json
import sys
import tarfile

src = tarfile.open(sys.argv[1])


def blob(digest):
    return src.extractfile("blobs/sha256/" + digest.split(":")[1]).read()


index = json.load(src.extractfile("index.json"))
manifest = json.loads(blob(index["manifests"][0]["digest"]))
out = tarfile.open(sys.argv[2], "w")


def add(name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    out.addfile(info, io.BytesIO(data))


add("config.json", blob(manifest["config"]["digest"]))
layers = []
for i, layer in enumerate(manifest["layers"]):
    layers.append("l%d/layer.tar" % i)
    add(layers[-1], blob(layer["digest"]))
add(
    "manifest.json",
    json.dumps([{"Config": "config.json", "RepoTags": [sys.argv[3]], "Layers": layers}]).encode(),
)
out.close()
