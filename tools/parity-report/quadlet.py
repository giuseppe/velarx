#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# Quadlet keys against velarx: for each key of each unit type that podman's
# generator supports (the SupportedKeys tables of podman's
# pkg/systemd/quadlet/quadlet.go), write the type's basic unit of podman's
# fixtures (test/e2e/quadlet/basic.TYPE) plus that key (a value taken from
# the fixtures, else a generic one), run `quadlet -dryrun` with
# PODMAN=VELARX, and take the options that the key adds to the Exec lines.
# Each option is then looked up in velarx:
#   works    `velarx COMMAND --help` shows it
#   refused  velarx knows it and refuses it with a message (a hidden
#            option, a global option of podman velarx refuses, or one
#            listed with "refused" in tests/e2e/quadlet-flags.allow)
#   missing  velarx does not know it ("unknown flag: --x", or clap's
#            "unexpected argument")
# A key is the worst state of its options; a key that adds no option is
# "generator" (systemd-side or a name), GlobalArgs/PodmanArgs are
# "free-form", and one no value could be found for is "untested".
#
#   PODMAN_SRC=... [QUADLET=...] tools/parity-report/quadlet.py VELARX [--json OUT]
import collections
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

QUADLET = os.environ.get("QUADLET", "/usr/libexec/podman/quadlet")
EXT = {"Container": "container", "Pod": "pod", "Kube": "kube", "Network": "network",
       "Volume": "volume", "Image": "image", "Build": "build", "Artifact": "artifact"}
CMD_GROUPS = ("pod", "network", "volume", "image", "kube", "artifact", "container", "secret", "manifest")
GENERIC = ["true", "x", "1", "/tmp:/tmp", "a=b", "10", "1g", "localhost/x", "yes"]
GLOBAL_REFUSED = None


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def podman_keys(src):
    text = read(os.path.join(src, "pkg/systemd/quadlet/quadlet.go"))
    consts = dict(re.findall(r"^\s*(Key\w+)\s*=\s*\"([^\"]+)\"", text, re.M))
    groups = {}
    for m in re.finditer(r"^\t\t(\w+)Group: \{.*?SupportedKeys: map\[string\]bool\{(.*?)\n\t\t\t\},", text, re.S | re.M):
        groups[m.group(1)] = sorted(consts[k] for k in re.findall(r"(Key\w+):\s*true", m.group(2)) if k in consts)
    return groups


def parse_unit(text):
    out, group, cont = collections.defaultdict(list), None, None
    for line in text.splitlines():
        if cont is not None:
            cont[1] += " " + line.strip().rstrip("\\")
            if not line.rstrip().endswith("\\"):
                out[(group, cont[0])].append(cont[1].strip())
                cont = None
            continue
        s = line.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if s.startswith("["):
            group = s.strip("[]")
            continue
        if "=" in s and group:
            k, v = s.split("=", 1)
            if v.rstrip().endswith("\\"):
                cont = [k.strip(), v.rstrip()[:-1]]
            else:
                out[(group, k.strip())].append(v.strip())
    return out


def fixture_values(src):
    d = os.path.join(src, "test/e2e/quadlet")
    vals = collections.defaultdict(list)
    for f in sorted(os.listdir(d)):
        p = os.path.join(d, f)
        if os.path.isfile(p):
            for k, vs in parse_unit(read(p)).items():
                for v in vs:
                    if v not in vals[k]:
                        vals[k].append(v)
    return vals


def exec_options(unit_text, ext, work):
    d = tempfile.mkdtemp(dir=work)
    with open(os.path.join(d, "test." + ext), "w", encoding="utf-8") as f:
        f.write(unit_text)
    env = dict(os.environ, PODMAN="VELARX", QUADLET_UNIT_DIRS=d)
    r = subprocess.run([QUADLET, "-dryrun"], env=env, capture_output=True, text=True, timeout=60)
    shutil.rmtree(d)
    pairs = set()
    found = False
    for line in r.stdout.splitlines():
        m = re.match(r"^(ExecStart|ExecStartPre|ExecStop|ExecStopPost|ExecReload)=-?VELARX (.*)$", line)
        if not m:
            continue
        found = True
        try:
            argv = shlex.split(m.group(2).replace("\\x20", " "))
        except ValueError:
            continue
        i = 0
        while i < len(argv) and argv[i].startswith("-"):
            pairs.add(("(global)", argv[i].split("=")[0]))
            i += 1
        n = 2 if i < len(argv) and argv[i] in CMD_GROUPS else 1
        cmd = " ".join(argv[i:i + n])
        for a in argv[i + n:]:
            if a.startswith("--") or re.match(r"^-[a-zA-Z]$", a):
                pairs.add((cmd, a.split("=")[0]))
    return (pairs if found else None), r.stderr.strip()


_help, _state = {}, {}
RUNTIME_REFUSED = set()
# free-form keys: their options are the user's
FREE_FORM = {"GlobalArgs", "PodmanArgs"}
# keys that need others: (lines to add, keys of the basic unit to drop)
COMPANIONS = {
    ("Container", "Group"): ("User=1\n", ()),
    ("Container", "RemapUid"): ("RemapUsers=manual\n", ()),
    ("Container", "RemapGid"): ("RemapUsers=manual\n", ()),
    ("Pod", "RemapUid"): ("RemapUsers=manual\n", ()),
    ("Pod", "RemapGid"): ("RemapUsers=manual\n", ()),
    ("Kube", "RemapUid"): ("RemapUsers=manual\n", ()),
    ("Kube", "RemapGid"): ("RemapUsers=manual\n", ()),
    ("Container", "Rootfs"): ("", ("Image",)),
    ("Network", "Gateway"): ("Subnet=10.89.0.0/24\n", ()),
    ("Network", "IPRange"): ("Subnet=10.89.0.0/24\n", ()),
    ("Volume", "Type"): ("Device=/dev/x\n", ()),
    ("Volume", "Options"): ("Device=/dev/x\n", ()),
}


def runtime_refused(repo):
    """Options velarx shows in its help but refuses when given:
    `bail!("--x is not supported...")` in src/cli."""
    out = set()
    for root, _, files in os.walk(os.path.join(repo, "src/cli")):
        for f in files:
            if f.endswith(".rs"):
                out |= set(re.findall(r'"(--[a-z0-9-]+)(?:=\w+)? is not supported', read(os.path.join(root, f))))
    return out


def velarx_state(velarx, cmd, flag, allow):
    key = (cmd, flag)
    if key in _state:
        return _state[key]
    path = [] if cmd == "(global)" else cmd.split()
    if cmd not in _help:
        h = subprocess.run([velarx, *path, "--help"], capture_output=True, text=True, timeout=30)
        _help[cmd] = h.stdout + h.stderr
    text = _help[cmd]
    reason = allow.get((cmd, flag)) or allow.get(("*", flag))
    if cmd == "(global)" and flag in GLOBAL_REFUSED:
        st = "refused"
    elif reason and "placeholder" in reason:
        st = "works"
    elif re.search(r"(^|[\s,])" + re.escape(flag) + r"([\s=,<\[]|$)", text, re.M):
        st = "refused" if flag in RUNTIME_REFUSED else "works"
    else:
        probe = [velarx, *path, f"{flag}=x" if flag.startswith("--") else flag, "--help"]
        r = subprocess.run(probe, capture_output=True, text=True, timeout=30)
        said = r.stdout + r.stderr
        st = "missing" if "unexpected argument" in said or "unknown flag: " in said else "refused"
    _state[key] = st
    return st


def load_allow(path):
    allow = {}
    for line in open(path, encoding="utf-8"):
        parts = line.split("#", 1)
        words = parts[0].split()
        if words:
            *cmd, flag = words
            allow[(" ".join(cmd) or "*", flag)] = parts[1].strip() if len(parts) > 1 else ""
    return allow


def main():
    global GLOBAL_REFUSED
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    src = os.environ.get("PODMAN_SRC", "")
    if len(args) != 1:
        print("usage: PODMAN_SRC=... quadlet.py VELARX [--json OUT]", file=sys.stderr)
        return 2
    if not os.access(QUADLET, os.X_OK) or not os.path.isdir(os.path.join(src, "test/e2e/quadlet")):
        print("skip: needs podman's quadlet and PODMAN_SRC")
        return 77
    velarx = os.path.abspath(args[0])
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    allow = load_allow(os.path.join(repo, "tests/e2e/quadlet-flags.allow"))
    layout = read(os.path.join(repo, "src/cli/layout.rs"))
    m = re.search(r"REFUSED_OPTIONS: &\[\(&str, &str\)\] = &\[(.*?)\n\];", layout, re.S)
    GLOBAL_REFUSED = set(re.findall(r'\(\s*"(-[-\w]+)"', m.group(1)))
    RUNTIME_REFUSED.update(runtime_refused(repo))
    groups = podman_keys(src)
    values = fixture_values(src)
    work = tempfile.mkdtemp(prefix="quadlet-keys-")
    report = {}
    try:
        for group, ext in EXT.items():
            keys = groups.get(group, [])
            base_text = read(os.path.join(src, f"test/e2e/quadlet/basic.{ext}"))
            base = {k: v for (g, k), v in parse_unit(base_text).items() if g == group}
            base_lines = "".join(f"{k}={v}\n" for k, vs in base.items() for v in vs)
            base_opts, err = exec_options(f"[{group}]\n{base_lines}", ext, work)
            if base_opts is None:
                print(f"{group}: the basic unit does not generate: {err}", file=sys.stderr)
                base_opts = set()
            rows = []
            for key in keys:
                if key in FREE_FORM:
                    rows.append({"key": key, "state": "free-form", "options": []})
                    continue
                extra, drop = COMPANIONS.get((group, key), ("", ()))
                cands = values.get((group, key), []) + GENERIC
                added, used = None, None
                for v in cands[:12]:
                    lines = "".join(f"{k}={x}\n" for k, xs in base.items()
                                    if k != key and k not in drop for x in xs)
                    opts, _ = exec_options(f"[{group}]\n{lines}{extra}{key}={v}\n", ext, work)
                    if opts is not None:
                        added, used = opts - base_opts, v
                        break
                if added is None:
                    rows.append({"key": key, "state": "untested", "options": []})
                    continue
                opts = sorted(added)
                states = [velarx_state(velarx, c, f, allow) for c, f in opts]
                state = ("missing" if "missing" in states else "refused" if "refused" in states
                         else "works" if states else "generator")
                rows.append({"key": key, "value": used, "state": state,
                             "options": [{"command": c, "option": f, "state": s}
                                         for (c, f), s in zip(opts, states)]})
            report[group] = rows
    finally:
        shutil.rmtree(work)
    print("| unit | keys | works | generator only | free-form | refused | missing | untested |")
    print("|---|---|---|---|---|---|---|---|")
    for group, rows in report.items():
        c = collections.Counter(r["state"] for r in rows)
        print(f"| .{EXT[group]} | {len(rows)} | {c['works']} | {c['generator']} | {c['free-form']} | {c['refused']} | {c['missing']} | {c['untested']} |")
    for group, rows in report.items():
        bad = [r for r in rows if r["state"] in ("refused", "missing", "untested")]
        if bad:
            print(f"\n.{EXT[group]}:")
            for r in bad:
                o = ", ".join(f"{x['command']} {x['option']} ({x['state']})" for x in r["options"]
                              if x["state"] != "works")
                print(f"- {r['key']}: {r['state']}{': ' + o if o else ''}")
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
