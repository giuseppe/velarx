#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The query parameters podman's handlers decode (the `schema:"..."` tags of
# pkg/api/handlers, per route) against the handlers of velarx-api: writes
# crates/api/tests/parameters.txt, the table that the test
# crates/api/tests/parameters.rs checks against the sources.
#
#   tools/parity-report/params.py VELARX_SRC PODMAN_SRC
#
# PODMAN_SRC is a checkout of podman's sources at the release the table is
# compared with (v5.8); nothing is downloaded.  The rows are recomputed from
# podman's handlers; the decision of a row already in the table is kept (a
# person made it, crates/api/tests/parameters.rs checks it against the
# handler of the route), and a row of the table that podman's handlers no
# longer give is kept and named on stderr, for a person to look at.  A new
# parameter is `implemented` or `refused` when its name is in the code of
# the handler (found by name, so a handler that reads it through a helper of
# another file shows as `review` until a person decides), or `noop` with the
# reason of `NOOP` below.
import importlib.util, os, re, sys, glob, collections
here=os.path.dirname(os.path.abspath(__file__))
spec=importlib.util.spec_from_file_location("api", here+"/api.py"); api=importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
vsrc, psrc = sys.argv[1:3]
from collections import defaultdict
OP=re.compile(r"swagger:operation\s+(\w+)\s+(\S+)\s+(\w+)")
def swagger(psrc):
    out={}
    for f in sorted(glob.glob(psrc+"/pkg/api/server/register_*.go")):
        text=open(f).read()
        ops=[(m.start(),m) for m in OP.finditer(text)]
        for i,(at,m) in enumerate(ops):
            end=ops[i+1][0] if i+1<len(ops) else len(text)
            block=text[at:end]
            meth,path,tag=m.groups()
            api_="libpod" if path.startswith("/libpod") else "compat"
            p=path[len("/libpod"):] if api_=="libpod" else path
            p=api.norm_go(p)
            names=re.findall(r"in:\s*query\s*\n\s*//\s*name:\s*(\S+)",block)
            out[(meth.upper(),p,api_)]=names
    return out
sw=swagger(psrc)

def build_params():
    """The parameters the build handler of velarx-api reads (also through
    its helpers: `q_number(call, "memory")`, `values("volume")`...) and
    those of its table of refusals."""
    t=api.strip_comments(open(os.path.join(vsrc,"crates/api/src/podman/build.rs")).read())
    t=t[:t.find("#[cfg(test)]")] if "#[cfg(test)]" in t else t
    a=t.index("const REFUSED"); b=t.index("];",a)
    refused={x.lower() for x in re.findall(r'\(\s*"([^"]+)"\s*,\s*Given',t[a:b])}
    read={x.lower() for x in re.findall(r'(?:\(call,\s*|\bvalues\(|\bduration\(|\.q(?:_bool|_all)?\()\s*"([^"]+)"',t)}
    return read-refused,refused

def fn_index(directory):
    idx=collections.defaultdict(list)
    for f in sorted(glob.glob(os.path.join(directory,"**/*.rs"),recursive=True)):
        text=api.strip_comments(open(f).read())
        cut=text.find("#[cfg(test)]")
        if cut>=0: text=text[:cut]
        for m in api.FN.finditer(text):
            # body: from the first "{" after the signature to the matching "}"
            i=text.find("{",m.end())
            # skip generics/where braces: signature ends at first "{" at depth 0 after ")"
            depth=0; j=i
            while j<len(text):
                c=text[j]
                if c=="{": depth+=1
                elif c=="}":
                    depth-=1
                    if depth==0: break
                j+=1
            idx[m.group(1)].append((os.path.relpath(f,directory),text[m.start():j+1]))
    return idx
STOP={"new","from","get","q","q_bool","q_i64","q_set","q_all","json","len","map","iter","into","clone","unwrap","ok","some","default","push","insert","to_string","as_str","contains","format","filters","header","param","err","is_empty"}
CALL=re.compile(r"\b([a-z_][a-z0-9_]*)\s*(?:::<[^>]*>)?\(")
def closure(idx, hname, hfile=None, depth=5):
    seen=set(); texts=[]
    def go(n,d,f):
        if (n,f) in seen or n in STOP or d<0: return
        seen.add((n,f))
        ents=idx.get(n,[])
        same=[e for e in ents if f and os.path.basename(e[0])==os.path.basename(f)]
        pick=same or (ents if len(ents)==1 else [])
        for ef,body in pick:
            texts.append(body)
            for c in set(CALL.findall(body)):
                go(c,d-1,ef)
    go(hname,depth,hfile)
    return "\n".join(texts)
def strings(text):
    return {s.lower() for s in re.findall(r'"([A-Za-z][\w.\-]*)"',text)}
REFUSE=re.compile(r"refuse_(?:params|set)\(\s*&\[(.*?)\]",re.S)
def refused(text):
    out=set()
    for m in REFUSE.finditer(text):
        out|={s.lower() for s in re.findall(r'"([^"]+)"',m.group(1))}
    return out


GOFN=re.compile(r"^func (?:\([^)]*\) )?(\w+)\(",re.M)
# (a function ends where the next top level declaration starts)
GOTOP=re.compile(r"^(?:func|type|var|const) ",re.M)
def go_index(psrc):
    idx={}
    for pkg in ("compat","libpod","utils"):
        for f in glob.glob(f"{psrc}/pkg/api/handlers/{pkg}/*.go"):
            t=open(f).read()
            for m in GOFN.finditer(t):
                n=GOTOP.search(t,m.end())
                idx[(pkg,m.group(1))]=t[m.start():n.start() if n else len(t)]
    return idx
GOIDX=go_index(psrc)
GOCALL=re.compile(r"\b(?:(utils|libpod|compat)\.)?([A-Za-z_]\w*)\(")
def go_tags(pkg,name,depth=3,seen=None):
    seen=seen if seen is not None else set()
    if (pkg,name) in seen or depth<0: return set()
    seen.add((pkg,name))
    body=GOIDX.get((pkg,name))
    if body is None: return set()
    tags=set(re.findall(r'schema:"([^",]+)',body))
    for q,fn in set(GOCALL.findall(body)):
        for p in ((q,) if q else (pkg,"utils")):
            if (p,fn) in GOIDX: tags|=go_tags(p,fn,depth-1,seen)
    return tags
HANDLER=re.compile(r'(\w+)\.Handle(?:Func)?\(\s*(?:VersionedPath\()?"([^"]+)"\)?\s*,\s*(?:s\.)?(?:APIHandler|StreamingAPIHandler)?\(?\s*(\w+)\.(\w+)')
def go_handlers(psrc):
    out={}
    for f in sorted(glob.glob(psrc+"/pkg/api/server/register_*.go")):
        text=open(f).read()
        prefixes=dict(re.findall(r'(\w+)\s*:=\s*r\.PathPrefix\("([^"]+)"\)\.Subrouter\(\)',text))
        for m in re.finditer(r'(\w+)\.Handle(?:Func)?\(\s*(VersionedPath\()?"([^"]+)"\)?\s*,(.*?)\)\s*\.Methods\(([^)]*)\)',text,re.S):
            var,vp,path,h,meths=m.groups()
            hm=re.search(r'(compat|libpod|utils)\.(\w+)',h)
            if not hm: continue
            if var in prefixes: path="/libpod/manifests"+path
            elif not vp and not path.startswith("/"): continue
            p=api.norm_go(path)
            api_="libpod" if p.startswith("/libpod") else "compat"
            if api_=="libpod": p=p[len("/libpod"):] or "/"
            for meth in re.findall(r"Method(\w+)",meths):
                out[(meth.upper(),p,api_)]=(hm.group(1),hm.group(2))
    return out
GOH=go_handlers(psrc)

front_dir=os.path.join(vsrc,"crates/api/src/podman"); eng_dir=os.path.join(vsrc,"src/api/podman")
fidx=fn_index(front_dir); eidx=fn_index(eng_dir)
front=api.rust_routes(front_dir); engine=api.rust_routes(eng_dir)
rows=[]
for (meth,path,api_),swnames in sorted(sw.items()):
    gh=GOH.get((meth,path,api_))
    names=sorted(go_tags(*gh)) if gh else swnames
    names=[n for n in names if n not in ('',)]
    if not names: continue
    r=api.find(front,meth,path,api_)
    where="missing"; text=""
    if r:
        hn=r["handler"].split("::")[-1]
        if r["handler"]=="forward" or hn=="forward":
            e=api.find(engine,meth,path,api_)
            if e:
                where="engine"; text=closure(eidx,e["handler"].split("::")[-1],e["file"])
            else: where="forward-unresolved"
        else:
            where="frontend"; text=closure(fidx,hn,r["file"])
    e2=api.find(engine,meth,path,api_)
    if e2 and where=="frontend" and r["handler"].split("::")[-1] in ("build","local_build","forward"):
        text+="\n"+closure(eidx,e2["handler"].split("::")[-1])
        tf=api.strip_comments(open(os.path.join(eng_dir,e2["file"])).read()) if False else ""
        mod=e2["handler"].split("::")
        for fn in glob.glob(os.path.join(eng_dir,"**",(mod[-2] if len(mod)>1 else "x")+".rs"),recursive=True):
            text+="\n"+api.strip_comments(open(fn).read())
    st=strings(text); rf=refused(text)
    if path in ("/build","/local/build"):
        bp,brf=build_params()
        st|=bp
        rf|=brf
    if ".filters()" in text or "Filters" in text: st.add("filters")
    # struct fields (serde decoded queries): of the files that hold the handler
    if r:
        for f2,_ in (fidx if where=="frontend" else eidx).get(hn if where=="frontend" else e["handler"].split("::")[-1],[]):
            base=front_dir if where=="frontend" else eng_dir
            t=api.strip_comments(open(os.path.join(base,f2)).read())
            st|={x.lower() for x in re.findall(r'rename\s*=\s*"([^"]+)"',t)}
            st|={x.lower().replace("_","") for x in re.findall(r"^\s*(?:pub\s+)?(\w+)\s*:\s*[A-Za-z]",t,re.M)}
            st|={x.lower() for x in re.findall(r"^\s*(?:pub\s+)?(\w+)\s*:\s*[A-Za-z]",t,re.M)}
    for n in names:
        k=n.lower()
        k2=k.replace('_','')
        if where in("missing",): status="route-missing"
        elif k in rf: status="refused"
        elif k in st or k2 in st: status="named"
        else: status="IGNORED?"
        rows.append((api_,meth,path,n,status,where))
NOOP = {
    "external": "velarx has no external (buildah) containers or images",
    "sync": "the state is read from the monitor, it is never stale",
    "copyuidgid": "a parameter of PUT; podman's GET does not read it",
    "nooverwritedirnondir": "a parameter of PUT; podman's GET does not read it",
    "rename": "a parameter of PUT; podman's GET does not read it",
    "verbose": "podman does not use it either",
    "removesignatures": "velarx never copies signatures",
    "quiet": "the progress lines are always sent",
    "artifactmimetype": "a parameter of another route (shared helper of podman)",
    "filemimetype": "a parameter of another route (shared helper of podman)",
    "path": "a parameter of another route (shared helper of podman)",
}
# read through a helper or a file the name search does not reach (checked)
OK = {"retry", "retrydelay", "compressionformat", "compressionlevel", "forcecompressionformat",
      "addcompression", "stream", "one-shot", "running", "annotations", "all", "compress"}
out = []
for api_, meth, path, n, status, where in rows:
    k = n.lower()
    if status == "IGNORED?":
        if k in OK:
            status = "implemented"
        elif k in NOOP:
            status = "noop " + NOOP[k]
        else:
            status = "review"
    elif status == "named":
        status = "implemented"
    elif status == "route-missing":
        continue
    out.append(f"{api_} {meth} {path} {n} {status}")
# what the handlers read that the tags above did not give (podman decodes
# these through a struct or a helper of its own): the build parameters and
# the names found in the calls
known = {o.split(" ")[3].lower() for o in out}
code = ""
for d in (front_dir, eng_dir):
    for f in glob.glob(os.path.join(d, "**/*.rs"), recursive=True):
        t = open(f).read()
        code += t[:t.find("#[cfg(test)]")] if "#[cfg(test)]" in t else t
extra = {}
bp, brf = build_params()
for n in bp:
    extra[n] = "implemented"
for n in brf:
    extra[n] = "refused"
for m in re.finditer(r'\.q(?:_bool|_i64|_set|_all)?\(\s*"([^"]+)"', code):
    extra.setdefault(m.group(1).lower(), "implemented")
for m in re.finditer(r'refuse_(?:params|set)\(\s*&\[(.*?)\]', code, re.S):
    for n in re.findall(r'"([^"]+)"', m.group(1)):
        extra.setdefault(n.lower(), "refused")
for n, w in sorted(extra.items()):
    if n not in known:
        out.append(f"any ANY * {n} {w}")
dest = os.path.join(vsrc, "crates/api/tests/parameters.txt")
# the decisions of the table win; its rows that were not recomputed stay
before = {}
if os.path.exists(dest):
    for l in open(dest).read().splitlines():
        if l and not l.startswith("#"):
            before[" ".join(l.split(" ")[:4])] = l
made = {" ".join(o.split(" ")[:4]): o for o in out}
for k, l in before.items():
    if k not in made:
        print("kept, not in podman's handlers here:", l, file=sys.stderr)
out = list({**made, **before}.values())
with open(dest, "w") as f:
    f.write("# SPDX-License-Identifier: Apache-2.0\n")
    f.write("# api METHOD PATH PARAMETER implemented|refused|noop REASON\n")
    f.write("# (generated by tools/parity-report/params.py from podman's handlers; the decisions are kept)\n")
    f.write("\n".join(sorted(set(out))) + "\n")
print(len(out), "parameters,", sum(1 for o in out if o.endswith(" review")), "to review")
