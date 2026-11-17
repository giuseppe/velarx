# SPDX-License-Identifier: Apache-2.0
# The JSON fields of a Go struct, as encoding/json decodes it: the names of
# the `json:"..."` tags (the Go name without one), embedded structs flattened,
# the structs of fields followed (the types are looked up in the package of
# the file, or through its imports, in podman's sources and its vendor
# directory).  Used by fields.py.
import glob
import os
import re

SKIP_FILE = re.compile(r"_(test|windows|freebsd|darwin|bsd|unsupported|remote)\.go$")
# decoded by their own UnmarshalJSON or not structs of fields: leaves
OPAQUE = {"time", "net", "netip", "url", "big", "json", "sync", "os", "fs"}
MAX_DEPTH = 6
# swarm: one row each, the fields below are those of its own API
STOP_DESCEND = {"ClusterVolumeSpec", "ClusterOptions"}


class Source:
    def __init__(self, psrc):
        self.psrc = psrc
        self.files = {}
        self.decls = {}

    def dir_of(self, path):
        pre = "github.com/containers/podman/v5/"
        if path.startswith(pre):
            return os.path.join(self.psrc, path[len(pre):])
        return os.path.join(self.psrc, "vendor", path)

    def package_of(self, d):
        for f in sorted(glob.glob(os.path.join(d, "*.go"))):
            if SKIP_FILE.search(f):
                continue
            m = re.search(r"^package (\w+)", open(f).read(), re.M)
            if m:
                return m.group(1)
        return None

    def load(self, d):
        if d in self.decls:
            return self.decls[d]
        out = {}
        for f in sorted(glob.glob(os.path.join(d, "*.go"))):
            if SKIP_FILE.search(f):
                continue
            text = strip_go_comments(open(f).read())
            imports = parse_imports(text)
            for name, rhs in top_level_types(text):
                out.setdefault(name, (rhs, imports))
            for m in re.finditer(r"^func \(\w+ \*?(\w+)\) UnmarshalJSON\(", text, re.M):
                out.setdefault("!" + m.group(1), ("", imports))
        self.decls[d] = out
        return out


def strip_go_comments(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
        elif c == "`":
            j = text.find("`", i + 1)
            j = n - 1 if j < 0 else j
            out.append(text[i:j + 1])
            i = j + 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_imports(text):
    imports = {}
    blocks = re.findall(r"^import \((.*?)^\)", text, re.S | re.M)
    singles = re.findall(r'^import (?:(\w+) )?"([^"]+)"', text, re.M)
    for b in blocks:
        for m in re.finditer(r'^\s*(?:([\w.]+)\s+)?"([^"]+)"', b, re.M):
            singles.append((m.group(1), m.group(2)))
    for alias, path in singles:
        if not alias:
            parts = path.split("/")
            alias = parts[-1]
            if re.fullmatch(r"v\d+", alias) and len(parts) > 1:
                alias = parts[-2]
            # (the package clause of the directory may name it otherwise)
            imports.setdefault("\0" + path, path)
        imports[alias] = path
    return imports


def match_brace(text, open_at):
    depth = 0
    i = open_at
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "`":
            i = text.find("`", i + 1)
            if i < 0:
                return len(text)
        elif c in "{(":
            depth += 1
        elif c in "})":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


def top_level_types(text):
    for m in re.finditer(r"^type[ \t]+(\()?", text, re.M):
        if m.group(1):
            end = match_brace(text, m.end() - 1)
            block = text[m.end():end - 1]
            for d in split_block(block):
                yield d
        else:
            nm = re.match(r"(\w+)(?:\[[^\]]*\])?[ \t]+(=[ \t]*)?", text[m.end():])
            if not nm:
                continue
            at = m.end() + nm.end()
            yield nm.group(1), rhs_at(text, at)


def split_block(block):
    # declarations at depth 0 of a `type ( ... )` block
    i = 0
    while i < len(block):
        m = re.compile(r"[ \t\n]*(\w+)(?:\[[^\]]*\])?[ \t]+(=[ \t]*)?").match(block, i)
        if not m:
            break
        at = m.end()
        rhs = rhs_at(block, at)
        yield m.group(1), rhs
        i = at + len(rhs)
        nl = block.find("\n", i)
        i = len(block) if nl < 0 else nl + 1


def rhs_at(text, at):
    if text.startswith("struct", at):
        o = text.find("{", at)
        return text[at:match_brace(text, o)]
    nl = text.find("\n", at)
    return text[at:nl if nl >= 0 else len(text)].strip()


def split_fields(body):
    """The entries of a struct body: (names, type, tag)."""
    entries = []
    i = 0
    inner = body[body.find("{") + 1:body.rfind("}")]
    lines = inner.split("\n")
    buf = []
    depth = 0
    for line in lines:
        buf.append(line)
        depth += line.count("{") - line.count("}")
        # a tag may hold braces inside backquotes: ignore them
        if "`" in line:
            tag = line[line.find("`"):]
            depth -= tag.count("{") - tag.count("}")
        if depth == 0:
            entries.append("\n".join(buf).strip())
            buf = []
    return [e for e in entries if e]


def field_of(entry):
    tag = ""
    m = re.search(r"`([^`]*)`", entry)
    if m:
        tag = m.group(1)
        entry = entry[:m.start()].rstrip()
    json_tag = None
    jm = re.search(r'json:"([^"]*)"', tag)
    if jm:
        json_tag = jm.group(1)
    m = re.match(r"^(\*?[\w]+(?:\.\w+)?)(?:\[[^\]]*\])?$", entry)
    if m:  # embedded
        return ([], m.group(1), json_tag, True)
    m = re.match(r"^([\w, \t]+?)[ \t]+(.+)$", entry, re.S)
    if not m:
        return None
    names = [n.strip() for n in m.group(1).split(",")]
    return (names, m.group(2).strip(), json_tag, False)


def base_type(t):
    t = t.strip()
    while True:
        if t.startswith("*"):
            t = t[1:].strip()
        elif t.startswith("[]"):
            t = t[2:].strip()
        elif re.match(r"\[\d*\]", t):
            t = re.sub(r"^\[\d*\]", "", t).strip()
        elif t.startswith("map["):
            depth = 0
            for i, c in enumerate(t):
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                    if depth == 0:
                        t = t[i + 1:].strip()
                        break
        else:
            return t


class Walker:
    def __init__(self, src):
        self.src = src

    def lookup(self, dirpath, imports, ref):
        """(dir, name, rhs, imports) of a type reference, or None."""
        ref = re.sub(r"\[.*$", "", ref)
        if "." in ref:
            alias, name = ref.split(".", 1)
            if alias in OPAQUE and alias not in imports:
                return None
            path = imports.get(alias)
            if path is None:
                for k, p in imports.items():
                    if k.startswith("\0") and self.src.package_of(self.src.dir_of(p)) == alias:
                        path = p
                        break
            if path is None or alias in OPAQUE and path in ("time", "net", "net/url", "math/big", "net/netip"):
                return None
            d = self.src.dir_of(path)
        else:
            d, name = dirpath, ref
        decls = self.src.load(d)
        if name not in decls:
            return None
        rhs, imps = decls[name]
        return d, name, rhs, imps

    def fields(self, dirpath, typename, depth=0, stack=()):
        """The (JSON path, Go name) fields of a struct type in a directory."""
        decls = self.src.load(dirpath)
        if typename not in decls:
            raise KeyError(f"{dirpath}: no type {typename}")
        rhs, imports = decls[typename]
        out = []
        self.walk(dirpath, typename, rhs, imports, "", depth, stack, out)
        seen = set()
        uniq = []
        for p in out:
            if p[0] not in seen:
                seen.add(p[0])
                uniq.append(p)
        return uniq

    def walk(self, d, name, rhs, imports, prefix, depth, stack, out):
        if (d, name) in stack:
            return
        stack = stack + ((d, name),)
        if not rhs.startswith("struct"):
            # `type A B`, `type A = pkg.B`
            r = self.lookup(d, imports, base_type(rhs))
            if r and r[2].startswith("struct") and f"!{r[1]}" not in self.src.load(r[0]):
                self.walk(r[0], r[1], r[2], r[3], prefix, depth, stack, out)
            return
        for entry in split_fields(rhs):
            f = field_of(entry)
            if not f:
                continue
            names, typ, jt, embedded = f
            if embedded:
                if jt is not None and jt.split(",")[0] not in ("",):
                    names = [typ.lstrip("*").split(".")[-1]]
                    embedded = False
                else:
                    r = self.lookup(d, imports, typ.lstrip("*"))
                    if r and r[2].startswith("struct"):
                        self.walk(r[0], r[1], r[2], r[3], prefix, depth, stack, out)
                    continue
            for n in names:
                if not n[:1].isupper():
                    continue
                if jt is not None:
                    jn = jt.split(",")[0]
                    if jn == "-" and "," not in jt:
                        continue
                    jn = jn or n
                else:
                    jn = n
                path = prefix + jn
                out.append((path, n))
                if depth >= MAX_DEPTH or jn in STOP_DESCEND:
                    continue
                self.descend(d, imports, typ, path, depth, stack, out)

    def descend(self, d, imports, typ, path, depth, stack, out):
        if typ.startswith("struct"):
            self.walk(d, path, typ, imports, path + ".", depth + 1, stack, out)
            return
        base = base_type(typ)
        if base.startswith("struct"):
            self.walk(d, path, base, imports, path + ".", depth + 1, stack, out)
            return
        r = self.lookup(d, imports, base)
        if not r:
            return
        rd, rn, rrhs, rimps = r
        if f"!{rn}" in self.src.load(rd):
            return  # its own decoder
        if rrhs.startswith("struct"):
            self.walk(rd, rn, rrhs, rimps, path + ".", depth + 1, stack, out)
        else:
            rb = base_type(rrhs)
            r2 = self.lookup(rd, rimps, rb)
            if r2 and r2[2].startswith("struct") and f"!{r2[1]}" not in self.src.load(r2[0]):
                self.walk(r2[0], r2[1], r2[2], r2[3], path + ".", depth + 1, stack, out)
