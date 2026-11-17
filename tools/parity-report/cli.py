#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The command line of velarx against podman's: every command and option of
# `podman ... --help`, looked up in velarx.  For each podman command:
# present, refused on purpose (exit 125, "is not supported by velarx") or
# missing; for each option of a present command: works (in the help),
# refused (hidden, or its help says refused/not supported) or unknown
# ("unknown flag: --x", or clap's "unexpected argument" of an older build).  Also the short forms that differ and the
# options velarx has that podman has not.  Only --help is run: nothing is
# created.
#
#   tools/parity-report/cli.py VELARX [PODMAN] [--json OUT] [--src VELARX_SRC]
#
# Commands that are aliases in podman (`ps`, `container ps`, `container
# list`...) have the same help but for their names: they are counted once
# (`unique`), under the first name.
import json
import os
import re
import subprocess
import sys

SKIP = {"help"}
# hidden options that velarx takes on purpose, as podman does
ACCEPTED_HIDDEN = {"--kernel-memory"}


def run(argv):
    env = dict(os.environ, LC_ALL="C", NO_COLOR="1")
    r = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env,
                       stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def podman_tree(podman, path=()):
    _, text = run([podman, *path, "--help"])
    out = [(path, text)]
    m = re.search(r"Available Commands:\n(.*?)\n\n", text, re.S)
    if m:
        for line in m.group(1).splitlines():
            name = line.split()[0] if line.strip() else ""
            if name and name not in SKIP:
                out.extend(podman_tree(podman, path + (name,)))
    return out


OPT = re.compile(r"^\s+(?:-([A-Za-z0-9]), )?--([a-z0-9][a-z0-9-]*)", re.M)


def podman_options(text, section=r"(?:Flags|Options)"):
    m = re.search(r"\n" + section + r":\n(.*?)(?:\n\n|\Z)", text, re.S)
    if not m:
        return {}
    return {"--" + lng: s for s, lng in OPT.findall(m.group(1)) if lng != "help"}


def velarx_options(text):
    """long option -> (short, help text of the option)."""
    m = re.search(r"\nOptions:\n(.*)", text, re.S)
    if not m:
        return {}
    out, cur = {}, None
    for line in m.group(1).splitlines():
        o = re.match(r"^\s{2,6}(?:-([A-Za-z0-9]), )?--([a-z0-9][a-z0-9-]*)(.*)", line)
        if o:
            cur = "--" + o.group(2)
            out[cur] = [o.group(1) or "", o.group(3)]
        elif cur and line.strip():
            out[cur][1] += " " + line.strip()
    return {k: (s, h) for k, (s, h) in out.items() if k != "--help"}


def refused_text(h, takes_value):
    """refused, partial (some values refused) or works, by its help."""
    if not re.search(r"\b(refused|not supported|Refused)\b", h):
        return "works"
    return "partial" if takes_value else "refused"


def source_aliases(src):
    """The hidden aliases of velarx's options (`alias = "ns"`)."""
    names = set()
    for d, _, files in os.walk(os.path.join(src, "src/cli")):
        for f in files:
            if f.endswith(".rs"):
                t = open(os.path.join(d, f)).read()
                for m in re.finditer(r'\balias(?:es)?\s*=\s*(\[[^\]]*\]|"[^"]*")', t):
                    names |= {"--" + n for n in re.findall(r'"([^"]+)"', m.group(1))}
    return names


def velarx_command(velarx, path):
    rc, text = run([velarx, *path, "--help"])
    if rc == 125 and "is not supported by velarx" in text:
        why = text.strip().splitlines()[-1].split(": ", 2)[-1]
        return "refused", why
    if rc != 0 or "unrecognized subcommand" in text:
        return "missing", text.strip().splitlines()[0] if text.strip() else ""
    return "present", text


def is_unknown(text, opt):
    """Does the answer to an option say velarx does not know it?  velarx
    says "unknown flag: --x" (podman's cobra), clap "unexpected argument
    '--x' found" and, for a short one, "unknown shorthand flag"."""
    return (f"unknown flag: {opt}" in text
            or f"unexpected argument '{opt}" in text
            or ("unknown shorthand flag" in text and opt in text))


def probe(velarx, path, opt):
    """Does velarx know an option it does not show?"""
    _, text = run([velarx, *path, opt + "=x", "--help"])
    return not is_unknown(text, opt)


def main():
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../..")
    if "--src" in args:
        i = args.index("--src")
        src = args[i + 1]
        del args[i:i + 2]
    aliases = source_aliases(src)
    if not args:
        print(__doc__ or "usage: cli.py VELARX [PODMAN] [--json OUT]", file=sys.stderr)
        return 2
    velarx = os.path.abspath(args[0])
    podman = args[1] if len(args) > 1 else "podman"
    pver = run([podman, "--version"])[1].strip()
    vver = run([velarx, "--version"])[1].strip()
    report = {"podman": pver, "velarx": vver, "commands": {}}
    tree = podman_tree(podman)
    refused_prefix = []
    for path, ptext in tree:
        name = " ".join(path) or "(global)"
        popts = podman_options(ptext) if path else podman_options(ptext, r"(?:Flags|Options)")
        about = next((ln for ln in ptext.splitlines() if ln.strip()), "")
        entry = {"podman_options": sorted(popts), "status": None, "options": {},
                 "about": about}
        report["commands"][name] = entry
        if any(name.startswith(r + " ") for r in refused_prefix):
            entry["status"] = "refused"
            entry["why"] = "with its parent"
            continue
        if path:
            status, text = velarx_command(velarx, list(path))
        else:
            status, text = "present", run([velarx, "--help"])[1]
        entry["status"] = status
        if status == "refused":
            entry["why"] = text
            refused_prefix.append(name)
            continue
        if status == "missing":
            continue
        vopts = velarx_options(text)
        probe_path = list(path)
        for o, short in sorted(popts.items()):
            if o in vopts:
                vs, h = vopts[o]
                st = refused_text(h, "<" in h.split("  ")[0] if h else False)
                entry["options"][o] = {"status": st}
                if short and vs != short:
                    entry["options"][o]["short"] = f"podman -{short}, velarx {'-' + vs if vs else 'none'}"
            elif probe(velarx, probe_path, o):
                st = "works" if o in ACCEPTED_HIDDEN or o in aliases else "refused"
                entry["options"][o] = {"status": st, "hidden": True}
            else:
                entry["options"][o] = {"status": "unknown"}
        entry["velarx_only"] = sorted(o for o in vopts if o not in popts)
    # velarx commands podman has not
    def vtree(path=()):
        _, text = run([velarx, *path, "--help"])
        m = re.search(r"\nCommands:\n(.*?)(?:\n\n|\Z)", text, re.S)
        out = [path] if path else []
        if m:
            for line in m.group(1).splitlines():
                w = line.split()
                if w and w[0] != "help":
                    out.extend(vtree(path + (w[0],)))
        return out
    pnames = set(report["commands"])
    report["velarx_only_commands"] = sorted(
        " ".join(p) for p in vtree() if " ".join(p) not in pnames)
    if out_json:
        with open(out_json, "w") as f:
            json.dump(report, f, indent=1, sort_keys=True)
    summarize(report)
    return 0


def unique(cmds):
    """The commands without podman's aliases: the first name of each."""
    seen, out = {}, {}
    order = sorted(cmds, key=lambda n: (n.count(" ") == 0, n))
    for n in order:
        e = cmds[n]

        key = (e["about"], tuple(e["podman_options"]))
        if key in seen and cmds[n]["status"] == cmds[seen[key]]["status"]:
            cmds[seen[key]].setdefault("aliases", []).append(n)
            continue
        seen[key] = n
        out[n] = e
    # a parent that velarx has not, but all of whose children it has
    for n, e in out.items():
        kids = [k for k in cmds if k.startswith(n + " ") and k.count(" ") == n.count(" ") + 1]
        if e["status"] == "missing" and kids and all(cmds[k]["status"] != "missing" for k in kids):
            e["status"] = "present"
            e["note"] = "only as its subcommands"
    return out


GROUPS = ("container", "image", "pod", "network", "volume", "system", "kube", "manifest",
          "artifact", "secret", "machine", "farm", "quadlet", "generate", "healthcheck")


def by_area(cmds):
    rows = {}
    for n, e in cmds.items():
        w = n.split()[0]
        a = w if w in GROUPS else ("(global)" if n == "(global)" else "other top-level")
        d = rows.setdefault(a, dict.fromkeys(
            ("commands", "present", "refused", "missing", "options", "works", "partial",
             "opt refused", "unknown", "of absent commands"), 0))
        d["commands"] += 1
        d[e["status"]] += 1
        d["options"] += len(e["podman_options"])
        if e["status"] == "present":
            for o in e["options"].values():
                d["opt refused" if o["status"] == "refused" else o["status"]] += 1
        else:
            d["of absent commands"] += len(e["podman_options"])
    return rows


def summarize(r):
    every = r["commands"]
    cmds = unique(every)
    r["unique_commands"] = sorted(cmds)
    by = {"present": [], "refused": [], "missing": []}
    for n, e in cmds.items():
        by[e["status"]].append(n)
    ostat = {"works": 0, "partial": 0, "refused": 0, "unknown": 0}
    ocmd_missing = 0
    for n, e in cmds.items():
        if e["status"] == "present":
            for o in e["options"].values():
                ostat[o["status"]] += 1
        else:
            ocmd_missing += len(e["podman_options"])
    total = sum(ostat.values()) + ocmd_missing
    print(f"# {r['podman']} against {r['velarx']}\n")
    print(f"commands: {len(every)} names in podman, {len(cmds)} without aliases: "
          f"{len(by['present'])} present, "
          f"{len(by['refused'])} refused, {len(by['missing'])} missing")
    print(f"options (without aliases): {total} in podman: {ostat['works']} work, "
          f"{ostat['partial']} partly (some values refused), {ostat['refused']} refused, "
          f"{ostat['unknown']} unknown, {ocmd_missing} of commands velarx lacks or refuses\n")
    rows = by_area(cmds)
    cols = list(next(iter(rows.values())))
    print("| area | " + " | ".join(cols) + " |\n|" + "---|" * (len(cols) + 1))
    for a in sorted(rows):
        print(f"| {a} | " + " | ".join(str(rows[a][c]) for c in cols) + " |")
    print()
    print(f"## Missing commands ({len(by['missing'])})\n")
    print(", ".join(f"`{c}`" for c in sorted(by["missing"])) or "none")
    print(f"\n## Refused commands ({len(by['refused'])})\n")
    for c in sorted(by["refused"]):
        print(f"- `{c}`: {cmds[c].get('why', '')}")
    print("\n## Options by command (refused / unknown)\n")
    for n in sorted(by["present"]):
        e = cmds[n]
        ref = [o for o, v in e["options"].items() if v["status"] == "refused"]
        par = [o for o, v in e["options"].items() if v["status"] == "partial"]
        unk = [o for o, v in e["options"].items() if v["status"] == "unknown"]
        if ref or unk or par:
            al = f" (= {', '.join(e['aliases'])})" if e.get("aliases") else ""
            print(f"- `{n}`{al} ({len(e['options'])}): unknown {' '.join(unk) or '-'}; "
                  f"refused {' '.join(ref) or '-'}; partly {' '.join(par) or '-'}")
    print("\n## Short forms that differ\n")
    for n in sorted(by["present"]):
        for o, v in sorted(cmds[n]["options"].items()):
            if "short" in v:
                print(f"- `{n} {o}`: {v['short']}")
    print("\n## velarx extensions\n")
    print("commands: " + (", ".join(f"`{c}`" for c in r["velarx_only_commands"]) or "none"))
    for n in sorted(by["present"]):
        if cmds[n].get("velarx_only"):
            print(f"- `{n}`: {' '.join(cmds[n]['velarx_only'])}")


if __name__ == "__main__":
    sys.exit(main())
