#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The keys of the configuration files whose format velarx shares with
# podman (in velarx's own directories) against podman's: every key that
# containers/image defines (the toml/json tags of its Go structs, read from
# podman's vendor directory) for registries.conf and policy.json,
# classified by the tables of velarx's sources (velarx reads no
# containers.conf or storage.conf: its settings are config.toml's):
#   implemented  velarx reads it
#   warned       velarx knows the key, warns "is not supported by velarx"
#                and goes on (or refuses the value)
#   unknown      velarx does not know the key: an "unknown key" error in a
#                file outside /usr/share
#
#   tools/parity-report/config.py VELARX_SRC PODMAN_SRC [--json OUT]
import json
import os
import re
import sys

# keys that scripts and distributions set often
COMMON = {
    "registries.conf": {
        "unqualified-search-registries", "short-name-mode", "registry.prefix",
        "registry.location", "registry.insecure", "registry.blocked", "registry.mirror",
        "registry.mirror.location", "registry.mirror.insecure", "credential-helpers", "aliases",
    },
    "policy.json": {"default", "transports", "type=insecureAcceptAnything", "type=reject",
                    "type=signedBy", "type=sigstoreSigned", "keyType=GPGKeys"},
}


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)


def matching(text, i):
    """The index after the brace that closes the one at text[i]."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    raise ValueError("unbalanced braces")


def go_structs(*paths):
    """{name: body} of the `type NAME struct {...}` of the files."""
    out = {}
    for p in paths:
        text = strip_comments(read(p))
        for m in re.finditer(r"^type\s+(\w+)\s+struct\s*{", text, re.M):
            start = m.end() - 1
            out[m.group(1)] = text[start + 1:matching(text, start) - 1]
    return out


def fields(body):
    """(name, type, tag) of the fields of a struct body; inline struct
    types come back as ('struct', BODY)."""
    out, i = [], 0
    while i < len(body):
        while i < len(body) and body[i] in " \t\n;":
            i += 1
        if i >= len(body):
            break
        end = body.find("\n", i)
        end = len(body) if end < 0 else end
        line = body[i:end]
        brace = line.find("{")
        if re.match(r"\w+\s+struct\s*{", line) or re.match(r"struct\s*{", line):
            start = i + brace
            close = matching(body, start)
            inner = body[start + 1:close - 1]
            rest_end = body.find("\n", close)
            rest_end = len(body) if rest_end < 0 else rest_end
            rest = body[close:rest_end]
            name = line.split()[0] if not line.startswith("struct") else ""
            out.append((name, ("struct", inner), tag_of(rest)))
            i = rest_end
            continue
        words = line.split("`")[0].split()
        tag = tag_of(line)
        if len(words) == 1:
            out.append(("", words[0], tag))
        elif len(words) >= 2:
            for n in words[0].split(","):
                out.append((n.strip(), words[1], tag))
        i = end
    return out


def tag_of(text):
    m = re.search(r'toml:"([^",]*)', text) or re.search(r'json:"([^",]*)', text)
    return m.group(1) if m else None


def walk(structs, body, prefix, out, open_tables):
    for name, typ, tag in fields(body):
        if tag == "-" or (tag is None and name and name[0].islower()):
            continue
        if isinstance(typ, tuple):
            inner = typ[1]
        else:
            base = typ.lstrip("*[]").split(".")[-1]
            inner = structs.get(base) if not typ.startswith(("[]", "map[")) else None
        if tag is None:
            # an embedded struct: its fields are this table's
            if inner is not None:
                walk(structs, inner, prefix, out, open_tables)
            continue
        key = f"{prefix}.{tag}" if prefix else tag
        out.append(key)
        if isinstance(typ, str) and typ.startswith("map["):
            open_tables.add(key)
        elif inner is not None and not (isinstance(typ, str) and typ.startswith("[]")):
            walk(structs, inner, key, out, open_tables)


def podman_registries_conf(podman):
    p = os.path.join(podman, "vendor/go.podman.io/image/v5/pkg/sysregistriesv2/system_registries_v2.go")
    structs = go_structs(p)
    out, opens = [], set()
    walk(structs, structs["V2RegistriesConf"], "", out, opens)
    out += ["aliases"]  # shortNameAliasConf, the [aliases] table
    out += ["registries.search.registries", "registries.insecure.registries", "registries.block.registries"]
    return sorted(set(out))


def podman_policy(podman):
    d = os.path.join(podman, "vendor/go.podman.io/image/v5/signature")
    text = "".join(read(os.path.join(d, f)) for f in sorted(os.listdir(d)) if f.endswith(".go"))
    out = ["default", "transports"]
    out += ["type=" + t for t in re.findall(r'prType\w+\s+prTypeIdentifier = "(\w+)"', text)]
    out += ["keyType=" + t for t in re.findall(r'SBKeyType\w+\s+sbKeyType = "(\w+)"', text)]
    out += ["signedIdentity=" + t for t in re.findall(r'prmType\w+\s+prmTypeIdentifier = "(\w+)"', text)]
    for k in re.findall(r'json:"(\w+)', read(os.path.join(d, "policy_types.go"))):
        if k not in ("type", "default", "transports"):
            out.append("field=" + k)
    return sorted(set(out))


def velarx_registries_conf(src):
    t = read(os.path.join(src, "crates/registry/src/config.rs"))
    renames = set(re.findall(r'rename = "([^"]+)"', t))
    plain = {"prefix", "location", "insecure", "blocked", "mirror", "aliases"}
    impl = set()
    for k in podman_keys_cache["registries.conf"]:
        leaf = k.rsplit(".", 1)[-1]
        if leaf in renames or leaf in plain or k.startswith("registries."):
            impl.add(k)
        if k == "registry":
            impl.add(k)
    warned = {k for k in impl if k in re.findall(r'warn!\("\{file_name\}: ([\w-]+) is not supported', t)}
    return impl | warned, impl - warned


def velarx_policy(src):
    d = os.path.join(src, "crates/signature/src")
    pol = read(os.path.join(d, "policy.rs")) + read(os.path.join(d, "reference.rs"))
    ev = read(os.path.join(d, "evaluate.rs"))
    known = {"default", "transports"}
    camel = lambda n: n[0].lower() + n[1:]
    m = re.search(r"pub enum PolicyRequirement \{(.*?)\n\}", pol, re.S)
    known |= {"type=" + camel(n) for n in re.findall(r"^    ([A-Z]\w+)", m.group(1), re.M)}
    m = re.search(r"pub enum KeyType \{(.*?)\n\}", pol, re.S)
    known |= {"keyType=" + n for n in re.findall(r'rename = "(\w+)"', m.group(1))}
    m = re.search(r"pub enum SignedIdentity \{(.*?)\n\}", pol, re.S)
    known |= {"signedIdentity=" + camel(n) for n in re.findall(r"^    ([A-Z]\w+)", m.group(1), re.M)}
    enum_body = re.search(r"pub enum KeyType \{.*?\n\}", pol, re.S).group(0)
    known |= {"field=" + f for f in re.findall(r'rename = "(\w+)"', pol.replace(enum_body, ""))}
    known |= {"field=prefix"} if re.search(r"RemapIdentity \{\s*prefix:", pol) else set()
    known |= {"field=" + re.sub(r"_(\w)", lambda x: x.group(1).upper(), f)
              for f in re.findall(r"pub (\w+): Option", pol)}
    known |= {"field=" + f for f in ("fulcio", "pki", "keyType")}
    refused = set()
    if "signedBaseLayer requirements are not implemented" in ev:
        refused.add("type=signedBaseLayer")
    if "if key_type != KeyType::GpgKeys" in ev:
        refused |= {k for k in known if k.startswith("keyType=") and k != "keyType=GPGKeys"}
    return known, known - refused


podman_keys_cache = {}


def main():
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        print("usage: config.py VELARX_SRC PODMAN_SRC [--json OUT]", file=sys.stderr)
        return 2
    src, podman = args
    podman_keys_cache.update({
        "registries.conf": podman_registries_conf(podman),
        "policy.json": podman_policy(podman),
    })
    velarx = {
        "registries.conf": velarx_registries_conf(src),
        "policy.json": velarx_policy(src),
    }
    report = {}
    for f, keys in podman_keys_cache.items():
        known, impl = velarx[f]
        rows = []
        for k in keys:
            # a key under a table velarx reads as a whole (runtimes...)
            parent = any(k.startswith(i + ".") for i in impl)
            state = ("implemented" if k in impl or parent else
                     "warned" if k in known or any(k.startswith(x + ".") for x in known) else "unknown")
            rows.append({"key": k, "state": state, "common": k in COMMON.get(f, ())})
        extra = sorted(k for k in known if k not in keys
                       and not any(k.startswith(x + ".") or x.startswith(k + ".") for x in keys))
        report[f] = {"keys": rows, "velarx_only": extra}
    print(f"# configuration keys: podman ({podman}) against velarx ({src})\n")
    print("| file | podman keys | implemented | warned (not supported) | unknown to velarx |")
    print("|---|---|---|---|---|")
    for f, r in report.items():
        c = {s: sum(1 for x in r["keys"] if x["state"] == s) for s in ("implemented", "warned", "unknown")}
        print(f"| {f} | {len(r['keys'])} | {c['implemented']} | {c['warned']} | {c['unknown']} |")
    for f, r in report.items():
        print(f"\n## {f}\n")
        for state in ("warned", "unknown"):
            ks = [x for x in r["keys"] if x["state"] == state]
            if not ks:
                continue
            by = {}
            for x in ks:
                sec = x["key"].split(".")[0] if "." in x["key"] else "(top)"
                by.setdefault(sec, []).append(x["key"] + (" (*)" if x["common"] else ""))
            print(f"{state}:")
            for sec, l in sorted(by.items()):
                print(f"- [{sec}] {', '.join(l)}")
        if r["velarx_only"]:
            print(f"velarx's list has keys podman's sources lack: {', '.join(r['velarx_only'])}")
    print("\n(*) commonly set")
    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
