#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The REST API of velarx-api against podman's: the routes of podman's
# server (pkg/api/server/register_*.go, the manifest subrouter too)
# against the route! tables of crates/api/src/podman (what velarx-api
# serves; a route of forward.rs is answered by the engine's handler of
# the same route in src/api/podman), and the parameters and body fields
# that the handlers refuse by name (refuse_params, refuse_set,
# refuse_field, not_implemented).
#
#   tools/parity-report/api.py VELARX_SRC PODMAN_SRC [--json OUT]
import collections
import glob
import json
import os
import re
import sys

GO_ROUTE = re.compile(
    r'(\w+)\.Handle(?:Func)?\(\s*(VersionedPath\()?"([^"]+)"\)?\s*,(.*?)\)\s*(?:\.Methods\(([^)]*)\))?\s*(?:\.|$)',
    re.M)
RS_ROUTE = re.compile(r'route!\(\s*"(\w+)",\s*"([^"]+)",\s*(\w+),\s*(\w+),\s*([\w:]+)\s*,?\s*\)', re.S)
FLAGS = {"LIBPOD": 1, "COMPAT": 2, "BOTH": 3}


def norm_go(path):
    # {name:.*} matches several segments, {id} one
    path = re.sub(r"\{[^}:]+:\.\*\}", "{*}", path)
    return re.sub(r"\{[^}]+\}", "{}", path)


def podman_routes(src):
    routes = {}
    unsupported = set()
    for f in sorted(glob.glob(os.path.join(src, "pkg/api/server/register_*.go"))):
        text = open(f).read()
        prefixes = dict(re.findall(r'(\w+)\s*:=\s*r\.PathPrefix\("([^"]+)"\)\.Subrouter\(\)', text))
        for m in GO_ROUTE.finditer(text):
            var, versioned, path, handler, methods = m.groups()
            if var in prefixes:
                path = "/libpod/manifests" + path
            elif not versioned and not path.startswith("/"):
                continue
            meths = re.findall(r"Method(\w+)", methods or "") or ["ANY"]
            p = norm_go(path)
            api = "libpod" if p.startswith("/libpod") else "compat"
            if api == "libpod":
                p = p[len("/libpod"):] or "/"
            group = os.path.basename(f)[len("register_"):-3]
            for meth in meths:
                meth = meth.upper()
                if meth == "HEAD" and "Get" in meths:
                    continue
                key = (meth, p, api)
                routes[key] = group
                if "UnsupportedHandler" in handler:
                    unsupported.add(key)
    return routes, unsupported


def strip_comments(text):
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))


def rust_routes(directory):
    out = []
    for f in sorted(glob.glob(os.path.join(directory, "**/*.rs"), recursive=True)):
        for m in RS_ROUTE.finditer(strip_comments(open(f).read())):
            meth, pat, flags, kind, handler = m.groups()
            for api, bit in (("libpod", 1), ("compat", 2)):
                if FLAGS[flags] & bit:
                    out.append(dict(method=meth, pattern=pat, api=api, handler=handler,
                                    file=os.path.relpath(f, directory)))
    return out


def matches(pattern, path):
    """match_segments of mod.rs: {} one segment, {*} one or more."""
    p, s = pattern.strip("/").split("/"), path.strip("/").split("/")

    def go(i, j):
        if i == len(p):
            return j == len(s)
        if j >= len(s):
            return False
        if p[i] == "{*}":
            return any(go(i + 1, k) for k in range(j + 1, len(s) + 1))
        return (p[i] == "{}" or p[i] == s[j]) and go(i + 1, j + 1)

    return go(0, 0) if pattern != "/" else path == "/"


def sample(path):
    return path.replace("{*}", "x").replace("{}", "x")


def find(routes, meth, path, api):
    for r in routes:
        if r["api"] == api and (r["method"] == meth or meth == "ANY"
                                or (meth == "HEAD" and r["method"] == "GET")) \
                and matches(r["pattern"], sample(path)):
            return r
    return None


FN = re.compile(r"^(?:pub(?:\([^)]*\))? )?(?:async )?fn (\w+)", re.M)
REFUSAL = [
    (re.compile(r"refuse_(?:params|set)\(\s*&\[(.*?)\]", re.S), "param"),
    (re.compile(r'refuse_field\(\s*"([^"]+)"'), "field"),
    (re.compile(r"refuse_cr_options\(\s*&call,\s*&\[(.*?)\]\s*,?\s*\)", re.S), "cr"),
    (re.compile(r'\brefuse\(\s*&?(?:format!\()?\s*"([^"]+)"', re.S), "501"),
    (re.compile(r'not_implemented\(\s*(?:format!\()?\s*"([^"]+)"', re.S), "501"),
]


def refusals(directory):
    """(file, fn) -> [(what, name)]"""
    out = collections.defaultdict(list)
    for f in sorted(glob.glob(os.path.join(directory, "**/*.rs"), recursive=True)):
        text = strip_comments(open(f).read())
        cut = text.find("#[cfg(test)]")
        if cut >= 0:
            text = text[:cut]
        starts = [(m.start(), m.group(1)) for m in FN.finditer(text)]
        rel = os.path.relpath(f, directory)
        for rx, what in REFUSAL:
            for m in rx.finditer(text):
                fn = next((n for at, n in reversed(starts) if at <= m.start()), "?")
                if what == "param":
                    for name in re.findall(r'"([^"]+)"', m.group(1)):
                        out[(rel, fn)].append((what, name))
                elif what == "cr":
                    for name in re.findall(r'\(\s*"([^"]+)"', m.group(1)):
                        out[(rel, fn)].append(("param", name))
                else:
                    out[(rel, fn)].append((what, m.group(1)))
    # the list of the build route (refuse_unsupported of build.rs)
    for f in glob.glob(os.path.join(directory, "build.rs")):
        text = open(f).read()
        m = re.search(r"fn refuse_unsupported.*?\n}\n", text, re.S)
        if m:
            for name in re.findall(r'"([A-Za-z][\w-]*)"', m.group(0)):
                if not name.startswith("the"):
                    out[("build.rs", "refuse_unsupported")].append(("param", name))
    return out


def main():
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print("usage: api.py VELARX_SRC PODMAN_SRC [--json OUT]", file=sys.stderr)
        return 2
    vsrc, psrc = args
    pod, pod_unsup = podman_routes(psrc)
    front = rust_routes(os.path.join(vsrc, "crates/api/src/podman"))
    engine = rust_routes(os.path.join(vsrc, "src/api/podman"))
    ref_front = refusals(os.path.join(vsrc, "crates/api/src/podman"))
    ref_engine = refusals(os.path.join(vsrc, "src/api/podman"))
    groups = collections.defaultdict(lambda: collections.Counter())
    rows = []
    for (meth, path, api), group in sorted(pod.items()):
        g = f"{api}:{group}"
        groups[g]["podman"] += 1
        row = dict(method=meth, path=path, api=api, group=group,
                   podman_unsupported=(meth, path, api) in pod_unsup)
        r = find(front, meth, path, api)
        if r is None:
            row["status"] = "missing"
        else:
            row["velarx"] = r
            hfile, hname = r["file"], r["handler"].split("::")[-1]
            refs = ref_front
            if r["handler"] == "forward":
                e = find(engine, meth, path, api)
                if e:
                    row["engine"] = e
                    mod = e["handler"].split("::")
                    hname = mod[-1]
                    hfile = (mod[-2] + ".rs") if len(mod) > 1 else e["file"]
                    refs = ref_engine
            else:
                mod = r["handler"].split("::")
                if len(mod) > 1:
                    hfile = mod[-2] + ".rs"
            rdir = os.path.dirname((row.get("engine") or r)["file"])
            found = [x for (f, fn), xs in refs.items()
                     if fn == hname and (os.path.basename(f) == hfile
                                         or (rdir and os.path.dirname(f) == rdir)
                                         or os.path.dirname(f) == hfile[:-3]) for x in xs]
            row["refused"] = sorted(set(found))
            whole = any(w == "501" and not n.startswith("the parameter") and
                        ("is not supported" in n and "{" not in n and "`" not in n)
                        for w, n in found)
            row["status"] = "refused" if whole else "served"
        groups[g][row["status"]] += 1
        rows.append(row)
    total = collections.Counter(r["status"] for r in rows)
    print(f"# podman {os.path.basename(os.path.abspath(psrc))} REST routes against velarx-api\n")
    print(f"podman routes: {len(rows)} (method+path, compat and libpod apart, HEAD of a GET folded;"
          f" {len(pod_unsup)} are podman's own UnsupportedHandler)")
    print(f"served: {total['served']}, refused whole (501): {total['refused']}, missing: {total['missing']}\n")
    print("| group | podman | served | refused | missing |\n|---|---|---|---|---|")
    for g in sorted(groups):
        c = groups[g]
        print(f"| {g} | {c['podman']} | {c['served']} | {c['refused']} | {c['missing']} |")
    print("\n## Missing routes\n")
    for r in rows:
        if r["status"] == "missing":
            extra = " (podman: UnsupportedHandler)" if r["podman_unsupported"] else ""
            print(f"- {r['api']} {r['method']} {r['path']}{extra}")
    print("\n## Refused whole\n")
    for r in rows:
        if r["status"] == "refused":
            print(f"- {r['api']} {r['method']} {r['path']}")
    print("\n## Parameters, fields and values refused by name (per route handler)\n")
    for r in rows:
        if r.get("refused"):
            names = "; ".join(f"{w}:{n}" for w, n in r["refused"])
            print(f"- {r['api']} {r['method']} {r['path']}: {names}")
    print("\n## Refusals in helpers (all files)\n")
    for label, refs in (("crates/api/src/podman", ref_front), ("src/api/podman", ref_engine)):
        for (f, fn), xs in sorted(refs.items()):
            print(f"- {label}/{f} {fn}: " + "; ".join(sorted(set(f"{w}:{n}" for w, n in xs))))
    extra = [r for r in front if not any(find([r], m, p, a) for (m, p, a) in pod)]
    print(f"\n## velarx-api routes podman lacks ({len(extra)})\n")
    for r in extra:
        print(f"- {r['api']} {r['method']} {r['pattern']}")
    if out_json:
        with open(out_json, "w") as f:
            json.dump(dict(routes=rows, groups={g: dict(c) for g, c in groups.items()},
                           totals=dict(total), velarx_only=extra,
                           refusals_frontend={f"{a}:{b}": v for (a, b), v in ref_front.items()},
                           refusals_engine={f"{a}:{b}": v for (a, b), v in ref_engine.items()}),
                      f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
