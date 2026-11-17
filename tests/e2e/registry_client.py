# SPDX-License-Identifier: Apache-2.0
"""What the scripts that make images in a registry share: one HTTP call and
the upload of a blob by the Location the registry gives (registry_images.py,
sha512_images.py)."""
import urllib.request


def call(method, url, body=None, headers=None, timeout=60):
    """(status, headers, body) of the request; an error status raises."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read()


def upload_blob(base, repo, data, digest, algorithm=None):
    """The blob DATA under DIGEST in REPO; ALGORITHM tells a registry that
    names its blobs by another digest than sha256 (`digest-algorithm`)."""
    start = f"{base}/v2/{repo}/blobs/uploads/"
    if algorithm:
        start += f"?digest-algorithm={algorithm}"
    _, headers, _ = call("POST", start, b"")
    location = headers["Location"]
    if location.startswith("/"):
        location = base + location
    sep = "&" if "?" in location else "?"
    call(
        "PUT",
        f"{location}{sep}digest={digest}",
        data,
        {"Content-Type": "application/octet-stream"},
    )
