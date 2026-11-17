#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The body fields podman's handlers decode (the JSON fields of the Go types
# of the bodies: SpecGenerator, CreateContainerConfig, PodSpecGenerator,
# Network, VolumeCreateOptions...) against the handlers of velarx-api: writes
# crates/api/tests/fields.txt, the table that crates/api/tests/fields.rs
# checks against the sources, as parameters.txt is for the query.
#
#   tools/parity-report/fields.py VELARX_SRC PODMAN_SRC
#
# PODMAN_SRC is a checkout of podman's sources (vendor directory included) at
# the release the table is compared with (v5.8); nothing is downloaded.  The
# rows are recomputed from the Go types (gostruct.py); the decision of a row
# already in the table is kept (a person made it), a new field is
# `implemented` when its name is in the code that reads the body (named in
# the `scope` lines below: a function with what it calls, a struct, a file),
# `noop` with its reason when `NOOP` has one, else `review`: a person
# decides (implemented, refused naming the field, or noop with the reason).
import glob
import importlib.util
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, f"{here}/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gostruct = load("gostruct")
vsrc, psrc = sys.argv[1:3]

API = "crates/api/src/podman"
ENG = "src/api/podman"
SPEC = f"{ENG}/spec.rs"
NET = f"{API}/networks.rs"
HANDLERS = "pkg/api/handlers"
DOCKER = "vendor/github.com/docker/docker/api/types"

# (apis, method, path, [(go dir, go type)], [scope items of velarx: file::name])
BODIES = [
    (["libpod"], "POST", "/containers/create",
     [("pkg/specgen", "SpecGenerator")], [f"{SPEC}::from_spec"]),
    (["compat"], "POST", "/containers/create",
     [(HANDLERS, "CreateContainerConfig")], [f"{SPEC}::from_docker"]),
    (["libpod"], "POST", "/containers/{}/update",
     [(HANDLERS, "UpdateEntities")], [f"{ENG}/containers.rs::libpod_update", f"{ENG}/containers.rs::update_device_limits",
      f"{ENG}/containers.rs::update_rlimits", f"{ENG}/containers.rs::health_update",
      f"{ENG}/containers.rs::check_device_rule", f"{ENG}/containers.rs::libpod_rlimits"]),
    (["compat"], "POST", "/containers/{}/update",
     [(f"{DOCKER}/container", "UpdateConfig")],
     [f"{ENG}/containers.rs::docker_update", f"{ENG}/containers.rs::docker_rlimits",
      f"{ENG}/containers.rs::update_rlimits"]),
    (["libpod", "compat"], "POST", "/containers/{}/exec",
     [(HANDLERS, "ExecCreateConfig")], [f"{API}/exec.rs::spec_of"]),
    (["libpod", "compat"], "POST", "/exec/{}/start",
     [(HANDLERS, "ExecStartConfig")], [f"{API}/exec.rs::start"]),
    (["libpod"], "POST", "/exec/{}/remove",
     [(HANDLERS, "ExecRemoveConfig")], [f"{API}/exec.rs::remove"]),
    (["libpod"], "POST", "/pods/create",
     [("pkg/specgen", "PodSpecGenerator")], ["crates/proto/src/podgen.rs::*", "crates/proto/src/pod.rs::from_podman"]),
    (["libpod"], "POST", "/networks/create",
     [("vendor/go.podman.io/common/libnetwork/types", "Network")],
     [f"{NET}::parse_libpod", f"{NET}::PodmanCreate", f"{NET}::PodmanSubnet",
      f"{NET}::LeaseRange", f"{NET}::PodmanRoute"]),
    (["compat"], "POST", "/networks/create",
     [(f"{DOCKER}/network", "CreateRequest")],
     [f"{NET}::parse_docker", f"{NET}::DockerCreate", f"{NET}::DockerIpam",
      f"{NET}::DockerIpamConfig"]),
    (["libpod"], "POST", "/networks/{}/update",
     [("pkg/domain/entities", "NetworkUpdateOptions")], [f"{NET}::UpdateBody", f"{NET}::update"]),
    (["libpod"], "POST", "/networks/{}/connect",
     [("pkg/domain/entities", "NetworkConnectOptions")], [f"{NET}::connect", f"{NET}::ConnectBody"]),
    (["compat"], "POST", "/networks/{}/connect",
     [(f"{DOCKER}/network", "ConnectOptions")],
     [f"{NET}::connect", f"{NET}::ConnectBody", f"{NET}::EndpointConfig", f"{NET}::IpamConfig"]),
    (["libpod", "compat"], "POST", "/networks/{}/disconnect",
     [(f"{DOCKER}/network", "DisconnectOptions")], [f"{NET}::disconnect", f"{NET}::DisconnectBody"]),
    (["libpod"], "POST", "/volumes/create",
     [("pkg/domain/entities", "VolumeCreateOptions")], [f"{API}/volumes.rs::CreateBody", f"{API}/volumes.rs::create"]),
    (["compat"], "POST", "/volumes/create",
     [(f"{DOCKER}/volume", "CreateOptions")], [f"{API}/volumes.rs::CreateBody", f"{API}/volumes.rs::create"]),
    (["compat"], "POST", "/secrets/create",
     [("pkg/domain/entities", "SecretCreateRequest")], [f"{API}/secrets.rs::DockerSecret", f"{API}/secrets.rs::DockerDriver", f"{API}/secrets.rs::create"]),
    (["libpod"], "POST", "/manifests/{*}",
     [("pkg/domain/entities", "ManifestModifyOptions")], [f"{API}/manifests.rs::create", f"{API}/manifests.rs::Modify"]),
    (["libpod"], "POST", "/manifests/{*}/add",
     [("pkg/domain/entities", "ManifestAddOptions")], [f"{API}/manifests.rs::add_v3", f"{API}/manifests.rs::Modify"]),
    (["libpod"], "PUT", "/manifests/{*}",
     [("pkg/domain/entities", "ManifestModifyOptions")], [f"{API}/manifests.rs::modify", f"{API}/manifests.rs::apply", f"{API}/manifests.rs::Modify"]),
    (["libpod", "compat"], "POST", "/commit",
     [("vendor/go.podman.io/image/v5/manifest", "Schema2Config")], [f"{API}/images.rs::commit", f"{ENG}/images/commit.rs::commit_of",
      "crates/core/src/services/container/commit.rs::override_edits"]),
    (["libpod", "compat"], "POST", "/auth",
     [(f"{DOCKER}/registry", "AuthConfig")], [f"{API}/system.rs::auth"]),
]

def read(path):
    return open(os.path.join(vsrc, path)).read()


def strip_rs(text):
    text = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))
    cut = text.find("#[cfg(test)]")
    return text[:cut] if cut >= 0 else text


def brace_end(text, at):
    depth = 0
    i = at
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c in "{(":
            depth += 1
        elif c in "})":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


FILES = {}


def rs_files():
    if not FILES:
        for d in (API, ENG, "crates/proto/src", "crates/core/src/services/container"):
            for f in glob.glob(os.path.join(vsrc, d, "**/*.rs"), recursive=True):
                FILES[os.path.relpath(f, vsrc)] = strip_rs(open(f).read())
    return FILES


def functions():
    out = []
    for f, text in rs_files().items():
        for m in re.finditer(r"(?<![\w])fn (\w+)", text):
            args = text.find("(", m.end())
            after = brace_end(text, args)
            o = re.compile(r"[{;]").search(text, after)
            if not o or text[o.start()] == ";":
                continue
            out.append((m.group(1), f, text[m.start():brace_end(text, o.start())]))
    return out


FNS = None
STOP = {"new", "from", "get", "q", "q_bool", "q_i64", "q_set", "q_all", "json", "len", "map",
        "iter", "into", "clone", "unwrap", "ok", "some", "default", "push", "insert", "to_string",
        "as_str", "contains", "format", "is_empty", "err"}


def closure(name, f, depth=5, seen=None):
    seen = set() if seen is None else seen
    if (name, f) in seen or name in STOP or depth < 0:
        return ""
    seen.add((name, f))
    cands = [x for x in FNS if x[0] == name]
    same = [x for x in cands if x[1] == f]
    pick = same or (cands if len(cands) == 1 else [])
    text = ""
    for _, ff, body in pick:
        text += body + "\n"
        for c in set(re.findall(r"\b([a-z_][a-z0-9_]*)\s*(?:::<[^>]*>)?\(", body)):
            text += closure(c, ff, depth - 1, seen)
    return text


def struct_text(f, name):
    m = re.search(rf"(?:struct|enum) {name}\b[^{{;]*\{{", rs_files()[f])
    if not m:
        return ""
    return rs_files()[f][m.start():brace_end(rs_files()[f], m.end() - 1)]


def scope_names(items):
    """The names the code of a scope reads: its string literals, and the
    fields of its structs that are read (`.field`)."""
    global FNS
    if FNS is None:
        FNS = functions()
    text = ""
    structs = ""
    for it in items:
        f, name = it.split("::")
        if name == "*":
            text += rs_files()[f]
            structs += rs_files()[f]
        elif struct_text(f, name):
            structs += struct_text(f, name)
        else:
            text += closure(name, f)
    names = {s.lower() for s in re.findall(r'"([^"\n\\]*)"', text + structs)}
    for field in re.findall(r"^\s*(?:pub\s+)?(\w+)\s*:\s*[A-Za-z]", structs, re.M):
        if re.search(rf"\.{field}\b", text + rs_files_all(items)):
            names.add(field.lower())
    return names


def rs_files_all(items):
    # reads of a field may be in the file of the struct, outside the closure
    return "".join(rs_files()[it.split("::")[0]] for it in items)


# The decisions that the name search cannot make: (route, field path, status
# and reason, only for a field the search left to review).  A refusal that
# the code makes for a whole object says `via` the member it looks at.  The
# first rule that matches wins; the decision of a row already in the table
# wins over these.
OUTPUT = "state of the endpoint that the engine reports, not a setting"
RULES = [
    # libpod containers/create
    (r"libpod POST /containers/create$", r"devices\.(type|major|minor|uid|gid|fileMode)$", "noop", "podman reads only the path of a device", False),
    (r"libpod POST /containers/create$", r"host_device_list\..*", "refused", "via host_device_list", False),
    (r"libpod POST /containers/create$", r"Networks\.(options|interface_name)$", "refused", "", False),
    (r"libpod POST /containers/create$", r"(containerCreateCommand|raw_image_name)$", "noop", "kept by podman for inspect, no effect on the container", False),
    (r"libpod POST /containers/create$", r"volatile$", "noop", "a hint that the upper layer needs no sync", False),
    (r"libpod POST /containers/create$", r"create_working_dir$", "noop", "a missing working directory is always made", False),
    (r"libpod POST /containers/create$", r"idmappings\.Host(UID|GID)Mapping$", "noop", "only podman's command line reads it", False),
    (r"libpod POST /containers/create$", r"idmappings\.AutoUserNsOpts\.(InitialSize|PasswdFile|GroupFile)$", "refused", "", False),
    (r"libpod POST /containers/create$", r"idmappings\.AutoUserNsOpts\.Additional(U|G)IDMappings\..*", "refused", r"via Additional\1IDMappings", False),
    (r"libpod POST /containers/create$", r"idmappings\.AutoUserNsOpts\.Additional(U|G)IDMappings$", "refused", "", False),
    (r"libpod POST /containers/create$", r"mounts\.(u|g)idMappings\..*", "refused", r"via \1idMappings", False),
    (r"libpod POST /containers/create$", r"mounts\.(u|g)idMappings$", "refused", "", False),
    (r"libpod POST /containers/create$", r"personality\.flags$", "refused", "", False),
    (r"libpod POST /containers/create$", r"intelRdt\.(enableCMT|enableMBM|l3CacheSchema|memBwSchema)$", "refused", "via intelRdt", False),
    (r"libpod POST /containers/create$", r"resource_limits\.(network|rdma)\..*", "refused", r"via \1", False),
    (r"libpod POST /containers/create$", r"resource_limits\.(network|rdma)$", "refused", "", False),
    (r"libpod POST /containers/create$", r"resource_limits\.(memory\.(kernel|kernelTCP|useHierarchy|checkBeforeUpdate)|cpu\.(burst|idle)|blockIO\.leafWeight|blockIO\.weightDevice\.leafWeight)$", "refused", "", False),
    (r"libpod POST /containers/create$", r"resource_limits\.blockIO\.throttle\w+Device\..*", "refused", "via blockIO", False),
    (r"libpod POST /containers/create$", r"resource_limits\.blockIO\.throttle\w+Device$", "refused", "", False),
    (r"libpod POST /containers/create$", r"weightDevice\.leafWeight$", "refused", "", False),
    (r"libpod POST /containers/create$", r"(weightDevice|throttle\w+Device)\.(major|minor)$", "noop", "podman takes the device from the path, the key of the map", False),
    # compat containers/create
    (r"compat POST /containers/create$", r"(AttachStdin|AttachStdout|AttachStderr|StdinOnce)$", "noop", "what is attached is chosen by the attach, not by the create", False),
    (r"compat POST /containers/create$", r"(Shell|OnBuild)$", "noop", "metadata of a build: a container does not use it", False),
    (r"compat POST /containers/create$", r"ArgsEscaped$", "noop", "Windows only", False),
    (r"compat POST /containers/create$", r"HostConfig\.ConsoleSize$", "noop", "the attach sizes the terminal", False),
    (r"compat POST /containers/create$", r"HostConfig\.ContainerIDFile$", "noop", "the client writes the file", False),
    (r"compat POST /containers/create$", r"HostConfig\.DeviceRequests\.(Capabilities|Count|Options)$", "noop", "the cdi driver names the devices by their ids", False),
    (r"compat POST /containers/create$", r"HostConfig\.Mounts\.Consistency$", "noop", "no effect on Linux", False),
    (r"compat POST /containers/create$", r"HostConfig\.KernelMemory(TCP)?$", "refused", "", False),
    (r"compat POST /containers/create$", r"HostConfig\.Mounts\.BindOptions\.(CreateMountpoint|ReadOnlyNonRecursive|ReadOnlyForceRecursive)$", "refused", "", False),
    (r"compat POST /containers/create$", r"HostConfig\.Mounts\.ClusterOptions$", "refused", "", False),
    (r"compat POST /containers/create$", r"HostConfig\.Mounts\.VolumeOptions\.Labels$", "refused", "", False),
    (r"compat POST /containers/create$", r"HostConfig\.Mounts\.VolumeOptions\.DriverConfig\.Options$", "refused", "", False),
    (r"compat POST /containers/create$", r"NetworkingConfig\.EndpointsConfig\.(DriverOpts|GwPriority|Links)$", "noop", "the network backends of podman do not read it, the field is dropped as podman drops it", False),
    (r"compat POST /containers/create$", r"NetworkingConfig\.EndpointsConfig\.IPAMConfig\.LinkLocalIPs$", "refused", "", False),
    (r"compat POST /containers/create$", r"NetworkingConfig\.EndpointsConfig\.(DNSNames|EndpointID|Gateway|GlobalIPv6Address|GlobalIPv6PrefixLen|IPPrefixLen|IPv6Gateway|NetworkID)$", "noop", OUTPUT + " (the names of a container are its aliases)", False),
    # updates
    (r"compat POST /containers/\{\}/update$", r"(CpuCount|CpuPercent|IOMaximumBandwidth|IOMaximumIOps|KernelMemory|KernelMemoryTCP|OomKillDisable|CgroupParent|MemorySwappiness|CpuRealtimeRuntime|CpuRealtimePeriod)$", "refused", "", False),
    (r"compat POST /containers/\{\}/update$", r"(Devices|DeviceRequests)\..*", "refused", r"via \1", False),
    (r"compat POST /containers/\{\}/update$", r"(Devices|DeviceRequests)$", "refused", "", False),
    (r"libpod POST /containers/\{\}/update$", r"(memory\.(kernel|kernelTCP|useHierarchy|checkBeforeUpdate|disableOOMKiller)|cpu\.(burst|idle))$", "refused", "", False),
    (r"libpod POST /containers/\{\}/update$", r"(hugepageLimits|network|rdma)\..*", "refused", r"via \1", False),
    (r"libpod POST /containers/\{\}/update$", r"(hugepageLimits|network|rdma|unified)$", "refused", "", False),
    (r"libpod POST /containers/\{\}/update$", r"devices\.(allow|type|major|minor|access)$", "implemented", "via devices", False),
    # pods
    (r"libpod POST /pods/create$", r"Networks\.(aliases|static_ips|static_mac|interface_name|options)$", "refused", "", False),
    (r"libpod POST /pods/create$", r"idmappings\.Host(UID|GID)Mapping$", "noop", "only podman's command line reads it", False),
    (r"libpod POST /pods/create$", r"idmappings\.AutoUserNsOpts\.(InitialSize|PasswdFile|GroupFile)$", "refused", "", False),
    (r"libpod POST /pods/create$", r"idmappings\.AutoUserNsOpts\.Additional(U|G)IDMappings\..*", "refused", r"via Additional\1IDMappings", False),
    (r"libpod POST /pods/create$", r"idmappings\.AutoUserNsOpts\.Additional(U|G)IDMappings$", "refused", "", False),
    (r"libpod POST /pods/create$", r"image_volumes\..*", "refused", "via image_volumes", False),
    (r"libpod POST /pods/create$", r"mounts\.(u|g)idMappings\..*", "refused", r"via \1idMappings", False),
    (r"libpod POST /pods/create$", r"mounts\.(u|g)idMappings$", "refused", "", False),
    (r"libpod POST /pods/create$", r"(network_options|volumes\.SubPath)$", "refused", "", False),
    (r"libpod POST /pods/create$", r"resource_limits\.(memory\.limit|memory\.swap|cpu\.(shares|quota|period|cpus|mems)|blockIO\.weight|blockIO\.weightDevice(\.(major|minor|weight))?|blockIO\.throttle(Read|Write)BpsDevice(\.(major|minor|rate))?|memory|cpu|blockIO)$", "implemented", "", False),
    (r"libpod POST /pods/create$", r"resource_limits\..*", "refused", "via resource_limits", False),
    # the rest
    (r"libpod POST /exec/\{\}/start$|compat POST /exec/\{\}/start$", r"Tty$", "noop", "podman does not read it either", False),
    (r"POST /containers/\{\}/exec$", r"(ConsoleSize|Detach)$", "noop", "podman does not read it either", False),
    (r"POST /auth$", r"(auth|email|identitytoken|registrytoken)$", "noop", "podman does not read it either", False),
    (r"libpod POST /networks/create$", r"(created|id)$", "noop", "output only: the engine makes them", False),
    (r"compat POST /networks/create$", r"CheckDuplicate$", "noop", "a name that is taken is always refused", False),
    (r"compat POST /networks/create$", r"ConfigFrom\..*", "refused", "via ConfigFrom", False),
    (r"compat POST /networks/create$", r"EnableIPv4$", "refused", "", False),
    (r"compat POST /networks/\{\}/connect$", r"EndpointConfig\.(DriverOpts|GwPriority|Links)$", "noop", "the network backends of podman do not read it, the field is dropped as podman drops it", False),
    (r"compat POST /networks/\{\}/connect$", r"EndpointConfig\.IPAMConfig\.LinkLocalIPs$", "refused", "", False),
    (r"compat POST /networks/\{\}/connect$", r"EndpointConfig\.(DNSNames|EndpointID|Gateway|GlobalIPv6Address|GlobalIPv6PrefixLen|IPPrefixLen|IPv6Gateway|NetworkID)$", "noop", OUTPUT, False),
    (r"libpod POST /networks/\{\}/connect$", r"options$", "refused", "", False),
    (r"libpod POST /manifests/\{\*\}(/add)?$", r"(operation|artifact_\w+)$", "noop", "podman reads it on PUT only", False),
    (r"libpod PUT /manifests/\{\*\}$", r"artifact_files$", "refused", "", False),
    (r"POST /commit$", r"(Hostname|Domainname|AttachStdin|AttachStdout|AttachStderr|Tty|OpenStdin|StdinOnce|ArgsEscaped|Image|NetworkDisabled|MacAddress|OnBuild|StopTimeout|Shell)$", "refused", "", False),
    (r"POST /commit$", r"Healthcheck\..*", "refused", "via Healthcheck", False),
    (r"POST /commit$", r"Healthcheck$", "refused", "", False),
    (r"libpod POST /volumes/create$", r"(UID|GID)$", "implemented", "", False),
]


def decide(route, path, default):
    for rx, prx, status, reason, only_review in RULES:
        m = re.fullmatch(prx, path)
        if m and re.search(rx, route):
            if only_review and default != "review":
                continue
            return f"{status} {m.expand(reason)}".strip()
    return default


CORPUS = None


def podman_reads(go):
    """How often the Go sources of podman (not its vendor directory, not its
    tests) use the field `go` of a struct."""
    global CORPUS
    if CORPUS is None:
        CORPUS = ""
        for d in ("pkg", "libpod", "cmd"):
            for f in glob.glob(os.path.join(psrc, d, "**/*.go"), recursive=True):
                if f.endswith("_test.go") or "_windows" in f or "_freebsd" in f or "_darwin" in f:
                    continue
                CORPUS += open(f).read()
    return len(re.findall(rf"\.{re.escape(go)}\b", CORPUS))


def rows():
    src = gostruct.Source(psrc)
    walker = gostruct.Walker(src)
    out = []
    scopes = []
    for apis, meth, path, gos, items in BODIES:
        fields = []
        for d, t in gos:
            for p in walker.fields(os.path.join(psrc, d), t):
                if p[0] not in [f[0] for f in fields]:
                    fields.append(p)
        names = scope_names(items)
        for api in apis:
            scopes.append(f"# scope {api} {meth} {path} {' '.join(items)}")
            for p, go in fields:
                last = p.split(".")[-1].lower()
                if last in names:
                    st = "implemented"
                elif podman_reads(go) == 0:
                    st = "noop podman does not read it either"
                else:
                    st = "review"
                st = decide(f"{api} {meth} {path}", p, st)
                out.append(f"{api} {meth} {path} {p} {st}")
    return scopes, out


def podman_version():
    """The release of the podman sources the table is made from."""
    text = open(os.path.join(psrc, "version/rawversion/version.go")).read()
    m = re.search(r'RawVersion = "([^"]+)"', text)
    return m.group(1) if m else "unknown"


def main():
    dest = os.path.join(vsrc, "crates/api/tests/fields.txt")
    scopes, out = rows()
    before = {}
    if os.path.exists(dest):
        for l in open(dest).read().splitlines():
            if l and not l.startswith("#"):
                before[" ".join(l.split(" ")[:4])] = l
    made = {" ".join(o.split(" ")[:4]): o for o in out}
    for k, l in before.items():
        if k not in made:
            print("kept, not in podman's types here:", l, file=sys.stderr)
    merged = {**made, **before}
    with open(dest, "w") as f:
        f.write("# SPDX-License-Identifier: Apache-2.0\n")
        f.write("# api METHOD PATH FIELD implemented|refused|noop REASON\n")
        f.write("# FIELD is the JSON path of the field in the body (generated by\n")
        f.write("# tools/parity-report/fields.py from podman's Go types; the decisions are kept).\n")
        f.write(f"# podman v{podman_version()}\n")
        f.write("# `scope` lines: the code of velarx-api that reads the body of a route.\n")
        f.write("\n".join(scopes) + "\n")
        f.write("\n".join(sorted(merged.values())) + "\n")
    rev = sum(1 for o in merged.values() if o.endswith(" review"))
    print(len(merged), "fields,", rev, "to review")


main()
