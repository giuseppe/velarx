#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""CheckpointPod and RestorePod of the CRI, which crictl does not call.

  cri_grpc.py SOCKET checkpointp POD OUTPUT_PATH CONTAINER...
  cri_grpc.py SOCKET restorep CHECKPOINT_PATH POD.json CONTAINER.json...

The JSON files are crictl's (the subset these tests use: anything else is an
error).  gRPC is HTTP/2 with protobuf messages: curl speaks the first, the
messages are encoded here.  Prints the answer as JSON: the IDs, or the status
of the error as `ERROR CODE message` on the standard error, exit status 1.
"""
import json
import subprocess
import sys
import tempfile
import urllib.parse


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field(num, payload):
    if isinstance(payload, str):
        payload = payload.encode()
    return varint(num << 3 | 2) + varint(len(payload)) + payload


def number(num, value):
    return varint(num << 3) + varint(value) if value else b""


def strings(num, values):
    return b"".join(field(num, v) for v in values)


def table(num, kv):
    return b"".join(field(num, field(1, k) + field(2, v)) for k, v in sorted(kv.items()))


def only(d, allowed, what):
    extra = set(d) - set(allowed)
    if extra:
        sys.exit(f"{what}: {sorted(extra)} not supported by this helper")


def pod_config(d):
    only(d, ["metadata", "hostname", "log_directory", "labels", "annotations"], "pod config")
    m = d["metadata"]
    only(m, ["name", "namespace", "uid", "attempt"], "pod metadata")
    meta = field(1, m["name"]) + field(2, m.get("uid", "")) + field(3, m.get("namespace", "")) + number(4, m.get("attempt", 0))
    return (
        field(1, meta)
        + field(2, d.get("hostname", ""))
        + field(3, d.get("log_directory", ""))
        + table(6, d.get("labels", {}))
        + table(7, d.get("annotations", {}))
    )


def container_config(d):
    only(d, ["metadata", "image", "command", "args", "log_path", "labels", "annotations", "working_dir"], "container config")
    meta = field(1, d["metadata"]["name"]) + number(2, d["metadata"].get("attempt", 0))
    return (
        field(1, meta)
        + field(2, field(1, d["image"]["image"]))
        + strings(3, d.get("command", []))
        + strings(4, d.get("args", []))
        + field(5, d.get("working_dir", ""))
        + table(9, d.get("labels", {}))
        + table(10, d.get("annotations", {}))
        + field(11, d.get("log_path", ""))
    )


def read_fields(data):
    """The (number, value) pairs of a message: the value is bytes or an int."""
    i, out = 0, []
    while i < len(data):
        key = shift = 0
        while True:
            b = data[i]
            i += 1
            key |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        num, kind = key >> 3, key & 7
        if kind == 2:
            n = shift = 0
            while True:
                b = data[i]
                i += 1
                n |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            out.append((num, data[i : i + n]))
            i += n
        elif kind == 0:
            v = shift = 0
            while True:
                b = data[i]
                i += 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            out.append((num, v))
        else:
            sys.exit(f"unexpected wire type {kind}")
    return out


def call(sock, method, message):
    body = b"\x00" + len(message).to_bytes(4, "big") + message
    with tempfile.TemporaryDirectory() as tmp:
        req, resp, hdr = (f"{tmp}/{n}" for n in ("req", "resp", "hdr"))
        with open(req, "wb") as f:
            f.write(body)
        subprocess.run(
            [
                "curl", "-s", "--http2-prior-knowledge", "--unix-socket", sock,
                f"http://localhost/runtime.v1.RuntimeService/{method}",
                "-H", "content-type: application/grpc", "-H", "te: trailers",
                "--data-binary", f"@{req}", "-D", hdr, "-o", resp,
            ],
            check=True,
        )
        headers = {}
        for line in open(hdr, errors="replace"):
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        data = open(resp, "rb").read()
    status = int(headers.get("grpc-status", "-1"))
    if status != 0:
        message = urllib.parse.unquote(headers.get("grpc-message", ""))
        print(f"ERROR {status} {message}", file=sys.stderr)
        sys.exit(1)
    return data[5 : 5 + int.from_bytes(data[1:5], "big")] if data else b""


def main():
    sock, op, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    if op == "checkpointp":
        pod, output, containers = args[0], args[1], args[2:]
        call(sock, "CheckpointPod", field(1, pod) + field(2, output) + strings(3, containers))
        print("{}")
    elif op == "restorep":
        path, pod, containers = args[0], args[1], args[2:]
        message = field(1, path) + field(2, pod_config(json.load(open(pod))))
        for c in containers:
            message += field(5, container_config(json.load(open(c))))
        answer = read_fields(call(sock, "RestorePod", message))
        result = {"pod_sandbox_id": "", "restored_containers": {}}
        for num, value in answer:
            if num == 1:
                result["pod_sandbox_id"] = value.decode()
            elif num == 2:
                got = dict(read_fields(value))
                result["restored_containers"][got[1].decode()] = got[2].decode()
        print(json.dumps(result))
    else:
        sys.exit(f"unknown operation {op}")


main()
