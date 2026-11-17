#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The --format fields of velarx against podman's: every placeholder of the
# "Valid placeholders" tables of podman's man pages (docs/source/markdown),
# rendered as {{.Field}} by both tools on the same objects, and the
# template functions.  The objects (a container c1, a pod p1, a volume v1,
# a network n1, a secret s1) are made by the script: give each tool a
# throwaway store, e.g.
#
#   VELARX="velarx" PODMAN="podman --root R --runroot RR --storage-driver vfs" \
#     tools/parity-report/formats.py PODMAN_SRC IMAGE [--json OUT]
#
# with HOME and XDG_* of velarx pointing to a scratch directory.  IMAGE is
# pulled by both (an OCI image; `--tls-verify=false` is passed).
import json
import os
import re
import shlex
import subprocess
import sys

# (man page, the command of both tools; the operand is added by need)
TABLES = [
    ("podman-ps.1.md.in", ["ps", "-a"]),
    ("podman-images.1.md.in", ["images"]),
    ("podman-pod-ps.1.md.in", ["pod", "ps"]),
    ("podman-network-ls.1.md.in", ["network", "ls"]),
    ("podman-volume-ls.1.md.in", ["volume", "ls"]),
    ("podman-secret-ls.1.md.in", ["secret", "ls"]),
    ("podman-stats.1.md.in", ["stats", "--no-stream", "c1"]),
    ("podman-pod-stats.1.md.in", ["pod", "stats", "--no-stream", "p1"]),
    ("podman-history.1.md", ["history", "IMAGE"]),
    ("podman-system-df.1.md", ["system", "df"]),
    ("podman-info.1.md", ["info"]),
    ("podman-version.1.md", ["version"]),
    ("podman-container-inspect.1.md.in", ["container", "inspect", "c1"]),
    ("podman-image-inspect.1.md", ["image", "inspect", "IMAGE"]),
    ("podman-volume-inspect.1.md", ["volume", "inspect", "v1"]),
    ("podman-network-inspect.1.md", ["network", "inspect", "n1"]),
    ("podman-pod-inspect.1.md", ["pod", "inspect", "p1"]),
    ("podman-secret-inspect.1.md", ["secret", "inspect", "s1"]),
    ("podman-events.1.md", ["events", "--stream=false", "--since", "10m"]),
]

FUNCS = {
    "json": "{{json .ID}}", "upper": "{{upper .ID}}", "lower": "{{lower .ID}}",
    "title": "{{title .ID}}", "join": '{{join .Names ","}}', "split": '{{split .ID "a"}}',
    "truncate": "{{truncate .ID 3}}", "pad": "{{pad .ID 1 1}}", "len": "{{len .ID}}",
    "index": "{{index .Labels \"a\"}}", "printf": '{{printf "%s" .ID}}', "print": "{{print .ID}}",
    "println": "{{println .ID}}", "slice": "{{slice .ID 0 2}}", "eq": "{{eq .ID .ID}}",
    "ne": "{{ne .ID .ID}}", "lt": "{{lt 1 2}}", "le": "{{le 1 2}}", "gt": "{{gt 1 2}}",
    "ge": "{{ge 1 2}}", "and": "{{and 1 2}}", "or": "{{or 1 2}}", "not": "{{not 1}}",
    "html": "{{html .ID}}", "js": "{{js .ID}}", "urlquery": "{{urlquery .ID}}",
}


JSON_CMDS = [["ps", "-a"], ["images"], ["container", "inspect", "c1"], ["image", "inspect", "IMAGE"],
             ["info"], ["version"], ["stats", "--no-stream", "c1"], ["pod", "ps"], ["pod", "inspect", "p1"],
             ["network", "inspect", "n1"], ["volume", "inspect", "v1"]]


def key_paths(v, prefix="", depth=2):
    """The keys of a JSON document, to a depth of two."""
    out = set()
    if isinstance(v, dict):
        for k, x in v.items():
            out.add(prefix + k)
            if depth > 1:
                out |= key_paths(x, prefix + k + ".", depth - 1)
    return out


def sh(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout, r.stderr


def placeholders(path):
    out = []
    for line in open(path):
        m = re.match(r"^\|\s*(\.[A-Z][A-Za-z0-9.]*)\s*([^|]*)\|", line)
        if m:
            arg = ' "a"' if "*string*" in m.group(2) or "*" in m.group(2).split("...")[0] else ""
            out.append(m.group(1) + arg)
    return out


def setup(tool, image):
    for argv in (["pull", "--tls-verify=false", image],
                 ["pod", "create", "--name", "p1"],
                 ["volume", "create", "--label", "a=b", "v1"],
                 ["network", "create", "n1"],
                 ["run", "-d", "--name", "c1", "--label", "a=b", "-v", "v1:/v", image, "sleep", "600"],
                 ["run", "-d", "--name", "c2", "--pod", "p1", image, "sleep", "600"]):
        sh(tool + argv)
    p = subprocess.run(tool + ["secret", "create", "s1", "-"], input="x", capture_output=True, text=True)
    return p.returncode


def render(tool, cmd, field):
    rc, out, err = sh(tool + cmd + ["--format", "{{" + field + "}}"])
    text = out.strip()
    bad = rc != 0 or "<no value>" in text
    if rc != 0:
        text = (err.strip().splitlines() or [""])[-1]
    return not bad, text


def main():
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print("usage: formats.py PODMAN_SRC IMAGE [--json OUT]", file=sys.stderr)
        return 2
    docs = os.path.join(args[0], "docs/source/markdown")
    image = args[1]
    velarx = shlex.split(os.environ.get("VELARX", "velarx"))
    podman = shlex.split(os.environ.get("PODMAN", "podman"))
    if os.environ.get("SETUP", "1") == "1":
        setup(velarx, image)
        setup(podman, image)
    report = {"tables": {}, "functions": {}}
    for page, cmd in TABLES:
        cmd = [image if a == "IMAGE" else a for a in cmd]
        path = os.path.join(docs, page)
        if not os.path.exists(path):
            path += ".in"
        if not os.path.exists(path):
            continue
        fields = placeholders(path)
        rows = {}
        for f in fields:
            pok, pv = render(podman, cmd, f)
            vok, vv = render(velarx, cmd, f)
            rows[f] = {"podman": pok, "velarx": vok, "velarx_out": vv[:120]}
        report["tables"][" ".join(cmd)] = rows
    for name, tmpl in FUNCS.items():
        _, pv, perr = sh(podman + ["ps", "-a", "--filter", "name=c1", "--format", tmpl])
        rc, vv, verr = sh(velarx + ["ps", "-a", "--filter", "name=c1", "--format", tmpl])
        report["functions"][name] = {"velarx": rc == 0 and "<no value>" not in vv,
                                     "podman": not perr.strip(), "velarx_err": verr.strip()[-120:]}
    report["json"] = {}
    for cmd in JSON_CMDS:
        keys = []
        for tool in (podman, velarx):
            rc, out, _ = sh(tool + [image if a == "IMAGE" else a for a in cmd] + ["--format", "json"])
            try:
                v = json.loads(out)
            except ValueError:
                v = None
            keys.append(key_paths(v[0] if isinstance(v, list) and v else v) if rc == 0 else None)
        report["json"][" ".join(cmd)] = {
            "podman": sorted(keys[0] or []), "velarx": None if keys[1] is None else sorted(keys[1])}
    if out_json:
        with open(out_json, "w") as f:
            json.dump(report, f, indent=1)
    tot = ok = 0
    print("| command | podman fields | velarx renders | velarx lacks |\n|---|---|---|---|")
    for cmd, rows in report["tables"].items():
        known = [f for f, r in rows.items() if r["podman"]]
        lacks = [f for f in known if not rows[f]["velarx"]]
        tot += len(known)
        ok += len(known) - len(lacks)
        print(f"| `{cmd}` | {len(known)} | {len(known) - len(lacks)} | {' '.join(lacks) or '-'} |")
    print(f"\nfields: {ok} of {tot}")
    lf = [n for n, r in report["functions"].items() if r["podman"] and not r["velarx"]]
    print(f"template functions velarx lacks: {' '.join(lf) or 'none'}")
    print("\n| --format json of | podman keys (depth 2) | velarx has | velarx lacks (top level first) |\n|---|---|---|---|")
    for cmd, r in report["json"].items():
        p = set(r["podman"])
        if r["velarx"] is None:
            print(f"| `{cmd}` | {len(p)} | no JSON | - |")
            continue
        v = set(r["velarx"])
        lacks = sorted(p - v, key=lambda k: (k.count("."), k))
        print(f"| `{cmd}` | {len(p)} | {len(p & v)} | {' '.join(lacks[:25])}{' ...' if len(lacks) > 25 else ''} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
