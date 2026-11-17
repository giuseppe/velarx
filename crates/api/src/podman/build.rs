// SPDX-License-Identifier: Apache-2.0
//! The build routes: the request (the query, the headers, the Containerfile,
//! the secrets, the named contexts, the multipart body) is decoded here into
//! a typed [`BuildSpec`]; the context tar streams from the client to the
//! engine through a pipe, the named directories as descriptors, and the
//! progress comes back as a stream.  What a build does not have is refused
//! by the name of its parameter.

use super::call::Call;
use super::error::{ApiError, ApiResult};
use super::reply;
use super::{route, Route};
use crate::engine::engine_call;
use crate::engine::Context;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use velarx_proto::buildspec::{
    parse_output, BuildClient, BuildContextKind, BuildContextSpec, BuildFlags, BuildPair,
    BuildPull, BuildSecretKind, BuildSecretSpec, BuildSpec,
};
use velarx_proto::godecode::parse_bool;
use velarx_proto::request::{BuildRun, DeviceMapping, ResourceLimits, Ulimit};
use velarx_proto::retry::Retry;

/// podman sends a JSON array of paths, Docker a path: relative to the
/// context, never outside of it.
fn containerfile_path(param: &str) -> ApiResult<Option<String>> {
    let path = if param.starts_with('[') {
        let list: Vec<String> = serde_json::from_str(param)
            .map_err(|e| ApiError::bad_request(format!("invalid dockerfile `{param}`: {e}")))?;
        match list.into_iter().next() {
            Some(p) => p,
            None => return Ok(None),
        }
    } else {
        param.to_string()
    };
    if path.is_empty() {
        return Ok(None);
    }
    not_preprocessed(&path)?;
    let mut clean = PathBuf::new();
    for c in Path::new(&path).components() {
        match c {
            Component::Normal(n) => clean.push(n),
            Component::CurDir | Component::RootDir => {}
            _ => {
                return Err(ApiError::bad_request(format!(
                    "the dockerfile `{path}` is outside of the context"
                )))
            }
        }
    }
    Ok(Some(clean.to_string_lossy().into_owned()))
}

/// The `dockerfile` parameter when it is an http(s) URL (or a list whose
/// first item is one).
fn url_containerfile(param: &str) -> ApiResult<Option<String>> {
    let first = if param.starts_with('[') {
        let list: Vec<String> = serde_json::from_str(param)
            .map_err(|e| ApiError::bad_request(format!("invalid dockerfile `{param}`: {e}")))?;
        list.into_iter().next().unwrap_or_default()
    } else {
        param.to_string()
    };
    Ok((first.starts_with("https://") || first.starts_with("http://")).then_some(first))
}

/// A Containerfile named `*.in` is run through cpp by the command line
/// (podman's service runs cpp on the files of the context): the routes
/// refuse it rather than read it as it is.
fn not_preprocessed(path: &str) -> ApiResult<()> {
    if path.ends_with(".in") {
        return Err(ApiError::bad_request(format!(
            "the dockerfile `{path}`: a Containerfile named *.in is not supported by velarx's build routes (no cpp on the engine's side): build it with velarx build"
        )));
    }
    Ok(())
}

/// The operating systems and architectures a platform may name (those of
/// containerd's platforms package, which podman parses them with).
const KNOWN_OS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "nacl",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];
const KNOWN_ARCH: &[&str] = &[
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "armbe",
    "arm64",
    "arm64be",
    "loong64",
    "mips",
    "mipsle",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
    "x86_64",
    "x86-64",
    "aarch64",
    "armhf",
    "armel",
    "i386",
    "i486",
    "i586",
    "i686",
];

/// A platform of `platform`, checked as podman checks it: an error in
/// podman's words.
fn check_platform(p: &str) -> Result<(), String> {
    let parts: Vec<&str> = p.split('/').collect();
    let known = |os: &str, arch: &str| {
        KNOWN_OS.contains(&os.to_ascii_lowercase().as_str())
            && KNOWN_ARCH.contains(&arch.to_ascii_lowercase().as_str())
    };
    let ok = match parts.as_slice() {
        [one] => {
            let one = one.to_ascii_lowercase();
            KNOWN_OS.contains(&one.as_str()) || KNOWN_ARCH.contains(&one.as_str())
        }
        [os, arch] | [os, arch, _] => known(os, arch),
        _ => false,
    };
    if ok {
        return Ok(());
    }
    Err(format!(
        "failed to parse query parameter 'platform': \"{p}\": invalid platform syntax for --platform=\"{p}\": \"{p}\": unknown operating system or architecture: invalid argument"
    ))
}

/// A parameter that is a list: podman sends it as a JSON array, Docker
/// as a comma-separated string, or one value a parameter.
fn list_param(call: &Call, name: &str) -> ApiResult<Vec<String>> {
    let mut out = Vec::new();
    for v in call.q_all(name) {
        if v.is_empty() {
            continue;
        }
        if v.starts_with('[') {
            let list: Vec<String> = serde_json::from_str(v)
                .map_err(|e| ApiError::bad_request(format!("invalid {name} `{v}`: {e}")))?;
            out.extend(list);
        } else {
            out.extend(v.split(',').map(str::to_string));
        }
    }
    Ok(out)
}

/// A parameter that is a list of values that may have commas: a JSON array,
/// or one value a parameter.
fn json_values(call: &Call, name: &str) -> ApiResult<Vec<String>> {
    let mut out = Vec::new();
    for v in call
        .q_all(name)
        .into_iter()
        .filter(|v| !v.is_empty() && *v != "null")
    {
        if v.starts_with('[') {
            let list: Vec<String> = serde_json::from_str(v)
                .map_err(|e| ApiError::bad_request(format!("invalid {name} `{v}`: {e}")))?;
            out.extend(list);
        } else {
            out.push(v.to_string());
        }
    }
    Ok(out)
}

/// [`json_values`] as the pairs of `NAME=VALUE`.
fn pair_values(call: &Call, name: &str) -> ApiResult<Vec<BuildPair>> {
    Ok(json_values(call, name)?
        .iter()
        .map(|v| BuildPair::parse(v))
        .collect())
}

/// The options of the RUN containers and of the final image the request
/// has, as the command line's `build` takes them.
fn run_of(call: &Call) -> ApiResult<(BuildRun, Vec<(String, String)>)> {
    let values = |name: &str| -> Vec<String> {
        call.q_all(name)
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect()
    };
    // podman sends ["nofile=1:2"], Docker [{"Name": "nofile", "Soft": 1, "Hard": 2}]
    let ulimits: Vec<String> = match call.q("ulimits").filter(|u| !u.is_empty()) {
        Some(u) => {
            // (Docker's client sends `null` for none)
            let limits: Option<Vec<Value>> = serde_json::from_str(u)
                .map_err(|e| ApiError::bad_request(format!("invalid ulimits `{u}`: {e}")))?;
            let limits = limits.unwrap_or_default();
            limits
                .iter()
                .map(|l| match l {
                    Value::String(s) => Ok(s.clone()),
                    l => match (l["Name"].as_str(), l["Soft"].as_i64(), l["Hard"].as_i64()) {
                        (Some(n), Some(s), Some(h)) => Ok(format!("{n}={s}:{h}")),
                        _ => Err(ApiError::bad_request(format!("invalid ulimits `{u}`"))),
                    },
                })
                .collect::<ApiResult<_>>()?
        }
        None => Vec::new(),
    };
    let mut security_opts = Vec::new();
    // (podman sends its default profile as a path, and the default size of
    // /dev/shm: not options)
    const DEFAULT_SECCOMP: &str = "/usr/share/containers/seccomp.json";
    const DEFAULT_SHM: u64 = 64 << 20;
    for (param, key) in [("seccomp", "seccomp"), ("apparmor", "apparmor")] {
        if let Some(v) = call
            .q(param)
            .filter(|v| !v.is_empty() && *v != DEFAULT_SECCOMP)
        {
            security_opts.push(format!("{key}={v}"));
        }
    }
    security_opts.extend(
        list_param(call, "labelopts")?
            .into_iter()
            .map(|o| format!("label={o}")),
    );
    // the output format: only OCI's is written
    match call.q("outputformat").filter(|f| !f.is_empty()) {
        None => {}
        Some(f) if f.contains("docker") => {
            return Err(ApiError::not_implemented(velarx_base::docker::refusal(
                &format!("the output format {f:?}"),
            )))
        }
        Some(f) if f.contains("oci") => {}
        Some(f) => {
            return Err(ApiError::bad_request(format!(
                "unrecognized image type {f:?}"
            )))
        }
    }
    let mut run = BuildRun {
        volumes: values("volume"),
        add_hosts: list_param(call, "extrahosts")?,
        dns: list_param(call, "dnsservers")?,
        dns_search: list_param(call, "dnssearch")?,
        dns_options: list_param(call, "dnsoptions")?,
        cap_add: list_param(call, "addcaps")?,
        cap_drop: list_param(call, "dropcaps")?,
        security_opts,
        devices: list_param(call, "devices")?
            .iter()
            .map(|d| DeviceMapping::parse(d))
            .collect(),
        shm_size: match call.q("shmsize").filter(|s| !s.is_empty()) {
            Some(s) => Some(
                s.parse::<u64>()
                    .map_err(|_| ApiError::bad_request(format!("invalid shmsize `{s}`")))?,
            )
            // (0 is Docker's "not set")
            .filter(|n| *n != DEFAULT_SHM && *n != 0),
            None => None,
        },
        ..run_more_of(call)?
    };
    run.ulimits = ulimits
        .iter()
        .map(|u| Ulimit::parse(u))
        .collect::<Result<_, _>>()
        .map_err(ApiError::bad_request)?;
    // (`KEY` without a value: the engine has no caller's environment to
    // take it from)
    let env = values("setenv")
        .into_iter()
        .map(|e| match e.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (e, String::new()),
        })
        .collect();
    Ok((run, env))
}

/// A number of the query, 0 (what podman sends for none) as none.
fn q_number<T: std::str::FromStr + PartialEq + Default>(
    call: &Call,
    name: &str,
) -> ApiResult<Option<T>> {
    match call.q(name).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => {
            let n: T = v.parse().map_err(|_| call.bad_parameter(name))?;
            Ok((n != T::default()).then_some(n))
        }
    }
}

/// The options of the RUN containers that are not text: the groups, the
/// hosts file, the resources.
fn run_more_of(call: &Call) -> ApiResult<BuildRun> {
    let resources = ResourceLimits {
        memory: q_number(call, "memory")?,
        memory_swap: q_number(call, "memswap")?,
        cpu_period: q_number(call, "cpuperiod")?,
        cpu_quota: q_number(call, "cpuquota")?,
        cpu_shares: q_number(call, "cpushares")?,
        cpuset_cpus: call
            .q("cpusetcpus")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        cpuset_mems: call
            .q("cpusetmems")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        ..Default::default()
    };
    let limited = resources.memory.is_some()
        || resources.memory_swap.is_some()
        || resources.cpu_period.is_some()
        || resources.cpu_quota.is_some()
        || resources.cpu_shares.is_some()
        || resources.cpuset_cpus.is_some()
        || resources.cpuset_mems.is_some();
    Ok(BuildRun {
        group_add: list_param(call, "groupadd")?,
        no_hosts: call.q_bool("nohosts", false)?,
        resources: limited.then_some(resources),
        cgroup_parent: call
            .q("cgroupparent")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        ..Default::default()
    })
}

/// `from`, `retry`, the times, `omithistory`, `inheritlabels`,
/// `skipunusedstages`, `cachettl` (podman's durations are Go's).
fn flags_of(call: &Call) -> ApiResult<BuildFlags> {
    let duration = |name: &str| -> ApiResult<Option<u64>> {
        match call.q(name).filter(|v| !v.is_empty()) {
            None => Ok(None),
            Some(v) => velarx_proto::duration::parse_go_duration(v)
                .map(|d| Some(d.as_millis() as u64))
                .ok_or_else(|| call.bad_parameter(name)),
        }
    };
    let flags = BuildFlags {
        from: call.q("from").filter(|v| !v.is_empty()).map(str::to_string),
        retry: Retry {
            // (podman's: 3 tries, 2 s apart)
            count: q_number(call, "retry")?.unwrap_or(3),
            delay_ms: Some(duration("retry-delay")?.unwrap_or(2000)),
        },
        timestamp: q_number(call, "timestamp")?,
        source_date_epoch: q_number(call, "sourcedateepoch")?,
        rewrite_timestamp: call.q_bool("rewritetimestamp", false)?,
        omit_history: call.q_bool("omithistory", false)?,
        inherit_labels: call.q_bool("inheritlabels", true)?,
        skip_unused_stages: call.q_bool("skipunusedstages", true)?,
        jobs: match call.q("jobs").filter(|v| !v.is_empty()) {
            None => 1,
            Some(v) => v.parse().map_err(|_| call.bad_parameter("jobs"))?,
        },
        // (0: no time limit, podman's default)
        cache_ttl_ms: duration("cachettl")?.filter(|d| *d > 0),
        annotations: pair_values(call, "annotations")?,
        unset_annotations: json_values(call, "unsetannotation")?,
        inherit_annotations: call.q_bool("inheritannotations", true)?,
        created_annotation: call.q_bool("createdannotation", true)?,
        os_version: call
            .q("osversion")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        os_features: json_values(call, "osfeature")?,
        compat_volumes: call.q_bool("compatvolumes", false)?,
        identity_label: match call.q("identitylabel").filter(|v| !v.is_empty()) {
            None => None,
            Some(_) => Some(call.q_bool("identitylabel", true)?),
        },
        cache_from: json_values(call, "cachefrom")?,
        cache_to: json_values(call, "cacheto")?,
        layer_labels: pair_values(call, "layerLabel")?,
        sbom: velarx_proto::buildspec::SbomFlags {
            preset: None,
            scanner_image: call
                .q("sbom-scanner-image")
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            scanner_commands: json_values(call, "sbom-scanner-command")?,
            merge_strategy: call
                .q("sbom-merge-strategy")
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            output: call
                .q("sbom-output")
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            purl_output: call
                .q("sbom-purl-output")
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            image_output: call
                .q("sbom-image-output")
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            image_purl_output: call
                .q("sbom-image-purl-output")
                .filter(|v| !v.is_empty())
                .map(str::to_string),
        },
        // (the proxy of the engine's environment: `http_proxy` of the spec)
        proxy_env: Vec::new(),
    };
    Ok(flags)
}

/// What a client asks of a build parameter that velarx does not have.
#[derive(Clone, Copy)]
enum Given {
    /// Any value that is not empty
    Any,
    /// A boolean that is true
    True,
    /// A value that is none of these (what the client sends by default)
    NotIn(&'static [&'static str]),
    /// podman's namespace options that are not the host's
    Namespaces,
    /// podman's ID mapping options that are not the host's
    IdMapping,
}

/// The parameters of [`velarx_proto::build::BUILD_REFUSED`] and what makes
/// a request for one: podman's client sends the defaults of several of
/// them (`isolation=0`, `rusage=false`...), which are not asks.
/// `rm`, `forcerm`, `excludes` and `ignorefile` are
/// not here: they change nothing of the image (no intermediate container
/// is kept, the client leaves the ignored files out of the tar it sends).
const REFUSED: &[(&str, Given)] = &[
    ("compressionformat", Given::Any),
    ("compressionlevel", Given::Any),
    ("cppflags", Given::Any),
    ("forcecompressionformat", Given::True),
    ("idmappingoptions", Given::IdMapping),
    ("ignore", Given::True),
    // (0 the default, 1 OCI, 3 rootless OCI; 2 is chroot)
    (
        "isolation",
        Given::NotIn(&["0", "1", "3", "default", "oci", "rootless"]),
    ),
    ("nsoptions", Given::Namespaces),
    ("rusage", Given::True),
    ("rusagelogfile", Given::Any),
    ("save-stages", Given::True),
    ("securityopt", Given::Any),
    ("sourcePolicy", Given::Any),
    ("stage-labels", Given::True),
    ("transientRunMounts", Given::Any),
];

fn given(rule: Given, values: &[&str]) -> bool {
    let set = |v: &&str| !v.is_empty();
    match rule {
        Given::Any => values.iter().any(set),
        Given::True => values.iter().any(|v| parse_bool(v) == Some(true)),
        Given::NotIn(defaults) => values.iter().any(|v| set(v) && !defaults.contains(v)),
        Given::Namespaces => values.iter().any(|v| {
            set(v)
                && serde_json::from_str::<Vec<Value>>(v).map_or(true, |l| {
                    l.iter().any(|o| {
                        o["Host"].as_bool() != Some(true)
                            || !o["Path"].as_str().unwrap_or("").is_empty()
                    })
                })
        }),
        Given::IdMapping => values.iter().any(|v| {
            set(v)
                && serde_json::from_str::<Value>(v).map_or(true, |o| {
                    let host = |k: &str| o[k].as_bool() != Some(false);
                    let list = |k: &str| o[k].as_array().is_some_and(|a| !a.is_empty());
                    !host("HostUIDMapping")
                        || !host("HostGIDMapping")
                        || list("UIDMap")
                        || list("GIDMap")
                        || o["AutoUserNs"].as_bool() == Some(true)
                })
        }),
    }
}

/// Whether podman's `nsoptions` ask for the network of the host.
fn host_network(call: &Call) -> bool {
    call.q_all("nsoptions").iter().any(|v| {
        serde_json::from_str::<Vec<Value>>(v).is_ok_and(|l| {
            l.iter().any(|o| {
                o["Name"].as_str() == Some("network")
                    && o["Host"].as_bool() == Some(true)
                    && o["Path"].as_str().unwrap_or("").is_empty()
            })
        })
    })
}

/// A parameter that asks for what the build does not have is refused
/// rather than ignored.
fn refuse_unsupported(call: &Call) -> ApiResult<()> {
    for (name, rule) in REFUSED {
        if given(*rule, &call.q_all(name)) {
            return Err(ApiError::not_implemented(format!(
                "the build parameter `{name}` is not supported"
            )));
        }
    }
    Ok(())
}

/// The request as a spec, and the credentials it carries (they cross in a
/// pipe of their own).  `local`: the build of a directory of the host of
/// the engine.
fn spec_of(
    call: &Call,
    local: bool,
) -> ApiResult<(BuildSpec, velarx_registry::auth::RegistryAccess)> {
    refuse_unsupported(call)?;
    let docker = !call.libpod;
    let quiet = call.q_bool("q", false)?;
    let tags: Vec<String> = call
        .q_all("t")
        .iter()
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect();
    let target = call
        .q("target")
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let no_cache = call.q_bool("nocache", false)?;
    // podman sends it when it is true (--layers=false sends nothing): a
    // libpod request without it keeps no layers; a Docker client does not
    // know it, and keeps its layers.
    let layers = call.q_bool("layers", docker)?;
    let build_args: BTreeMap<String, String> = match call.q("buildargs").filter(|a| !a.is_empty()) {
        Some(a) => serde_json::from_str(a)
            .map_err(|e| ApiError::bad_request(format!("invalid buildargs `{a}`: {e}")))?,
        None => BTreeMap::new(),
    };
    let labels = match call.q("labels").filter(|a| !a.is_empty()) {
        Some(a) => build_labels(a)?,
        None => BTreeMap::new(),
    };
    // podman sends one platform a parameter, Docker a list.
    let platforms: Vec<&str> = call
        .q_all("platform")
        .into_iter()
        .flat_map(|p| p.split(','))
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    for p in &platforms {
        check_platform(p).map_err(ApiError::bad_request)?;
    }
    let platform = (!platforms.is_empty()).then(|| platforms.join(","));
    let manifest = call
        .q("manifest")
        .filter(|m| !m.is_empty())
        .map(str::to_string);
    // libpod's `squash` is buildah's (podman build --squash-all: one
    // layer, the base's files too; podman's --squash sends layers=0);
    // Docker's squashes the new layers onto the base.
    let squash_param = call.q_bool("squash", false)?;
    let (squash, squash_all) = (squash_param && docker, squash_param && !docker);
    // podman sends buildah's policy as a number: 0 default, 1 disabled,
    // 2 enabled; Docker a mode.
    let network = match call.q("networkmode").unwrap_or("") {
        "" | "default" | "0" => None,
        // (`--network=host` is the policy 2 and a host network entry of
        // the namespace options)
        "2" if host_network(call) => Some("host".to_string()),
        "2" => None,
        "1" => Some("none".to_string()),
        n => Some(n.to_string()),
    };
    let tls_verify = call.q_bool("tlsVerify", true)?;
    // libpod's `pullpolicy`, else the `pull` boolean (Docker's, and
    // podman's older clients): pull every time when true.
    let pull = match call.q("pullpolicy").filter(|p| !p.is_empty()) {
        Some(p) => BuildPull::parse(p)
            .ok_or_else(|| ApiError::bad_request(format!("invalid pull policy `{p}`")))?,
        None => match call.q("pull").filter(|p| !p.is_empty()) {
            None => BuildPull::Missing,
            // (Docker's boolean: `false` is not "never")
            Some(p) if p.eq_ignore_ascii_case("false") => BuildPull::Missing,
            Some(p) => match BuildPull::parse(p) {
                Some(policy) => policy,
                None if call.q_bool("pull", false)? => BuildPull::Always,
                None => BuildPull::Missing,
            },
        },
    };
    // Docker sends the credentials of every registry in X-Registry-Config,
    // podman in X-Registry-Auth.
    let access = match call
        .header("x-registry-config")
        .or_else(|| call.header("x-registry-auth"))
    {
        Some(h) => velarx_registry::auth::RegistryAccess::from_registry_auth(h)
            .map_err(ApiError::bad_request)?,
        None => Default::default(),
    };
    let (run, env) = run_of(call)?;
    let all_platforms = call.q_bool("allplatforms", false)?;
    let flags = flags_of(call)?;
    // (as `outputs`: the engine's working directory means nothing to the
    // client)
    for (name, path) in [
        ("sbom-output", &flags.sbom.output),
        ("sbom-purl-output", &flags.sbom.purl_output),
    ] {
        if let Some(p) = path.as_deref().filter(|p| !Path::new(p).is_absolute()) {
            return Err(ApiError::bad_request(format!(
                "{name}: {p}: an absolute path of the engine's host"
            )));
        }
    }
    let http_proxy = call.q_bool("httpproxy", false)?;
    let output = match call.q("outputs").filter(|o| !o.is_empty()) {
        None => None,
        Some(o) => match parse_output(o) {
            Ok(None) => {
                return Err(ApiError::bad_request(
                    "outputs: the files go to a path of this host, not to the standard output",
                ))
            }
            Ok(Some(ref o)) if !Path::new(&o.path).is_absolute() => {
                return Err(ApiError::bad_request(format!(
                    "outputs: {}: an absolute path of the engine's host",
                    o.path
                )))
            }
            Ok(output) => output,
            Err(e) => return Err(ApiError::bad_request(e)),
        },
    };
    // (the local route builds its directory: a remote context is not one
    // of its parameters)
    let remote = call
        .q("remote")
        .filter(|r| !local && !r.is_empty())
        .map(str::to_string);
    let secrets = secret_specs(call, local)?;
    if remote.is_some() && !secrets.is_empty() {
        return Err(ApiError::bad_request(
            "the secrets of a remote context: send them in the context",
        ));
    }
    let contexts = named_contexts(call, local)?;
    let dockerfile = call.q("dockerfile").unwrap_or("");
    let (mut containerfile, mut containerfile_host, mut local_dir) = (None, None, None);
    // (a Containerfile of an http(s) URL is fetched by the engine)
    let containerfile_url = url_containerfile(dockerfile)?;
    let dockerfile = if containerfile_url.is_some() {
        ""
    } else {
        dockerfile
    };
    if local {
        local_dir = Some(call.q("localcontextdir").unwrap_or("").to_string());
        // a list, the first path, or a path: absolute is a file of the host
        let dockerfile = if dockerfile.starts_with('[') {
            let list: Vec<String> = serde_json::from_str(dockerfile).map_err(|e| {
                ApiError::bad_request(format!("invalid dockerfile `{dockerfile}`: {e}"))
            })?;
            list.into_iter().next().unwrap_or_default()
        } else {
            dockerfile.to_string()
        };
        if Path::new(&dockerfile).is_absolute() {
            not_preprocessed(&dockerfile)?;
            containerfile_host = Some(dockerfile);
        } else {
            containerfile = containerfile_path(&dockerfile)?;
        }
    } else {
        check_content_type(call)?;
        containerfile = containerfile_path(dockerfile)?;
    }
    let spec = BuildSpec {
        client: if docker {
            BuildClient::Docker
        } else {
            BuildClient::Libpod
        },
        quiet,
        tags,
        build_args: pairs(build_args),
        labels: pairs(labels),
        no_cache,
        layers,
        target,
        platform,
        manifest,
        all_platforms,
        squash,
        squash_all,
        network,
        tls_verify,
        pull,
        run,
        env: env
            .into_iter()
            .map(|(name, value)| BuildPair { name, value })
            .collect(),
        unset_env: call
            .q_all("unsetenv")
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect(),
        unset_labels: call
            .q_all("unsetlabel")
            .into_iter()
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .collect(),
        secrets,
        contexts,
        flags,
        http_proxy,
        containerfile,
        containerfile_host,
        containerfile_url,
        remote,
        local_dir,
        output,
        ..Default::default()
    };
    Ok((spec, access))
}

/// podman's `secrets`: a JSON list of `id=ID,src=FILE[,type=file]` (or
/// one of them), FILE a file podman's client put at the top of the context
/// (the local route: a path of the host of the engine).
fn secret_specs(call: &Call, local: bool) -> ApiResult<Vec<BuildSecretSpec>> {
    let mut specs = Vec::new();
    for v in call.q_all("secrets").into_iter().filter(|v| !v.is_empty()) {
        let list: Vec<String> = if v.trim_start().starts_with('[') {
            serde_json::from_str(v)
                .map_err(|e| ApiError::bad_request(format!("invalid secrets: {e}")))?
        } else {
            vec![v.to_string()]
        };
        for spec in list {
            let (mut id, mut src) = (None, None);
            for token in spec.split(',') {
                match token.split_once('=') {
                    Some(("id", v)) => id = Some(v.to_string()),
                    Some(("src", v)) => src = Some(v.to_string()),
                    Some(("type", "file")) => {}
                    _ => {
                        return Err(ApiError::bad_request(format!(
                            "invalid secret `{}`: id=ID,src=FILE",
                            token.split_once('=').map_or(token, |(k, _)| k)
                        )))
                    }
                }
            }
            let id = id
                .filter(|i| !i.is_empty())
                .ok_or_else(|| ApiError::bad_request("a secret without an id"))?;
            let src = src.unwrap_or_else(|| id.clone());
            specs.push(BuildSecretSpec {
                id,
                kind: if local {
                    BuildSecretKind::HostFile
                } else {
                    BuildSecretKind::ContextFile
                },
                source: src,
            });
        }
    }
    Ok(specs)
}

/// podman's `additionalbuildcontexts` (`NAME=url:URL`, `NAME=image:REF`;
/// the local route also `NAME=localpath:PATH`).
fn named_contexts(call: &Call, local: bool) -> ApiResult<Vec<BuildContextSpec>> {
    let mut out = Vec::new();
    for spec in call.q_all("additionalbuildcontexts") {
        if spec.is_empty() {
            continue;
        }
        let (name, value) = spec.split_once('=').ok_or_else(|| {
            ApiError::bad_request(format!(
                "additionalbuildcontexts must be in name=value format: {spec:?}"
            ))
        })?;
        let (kind, source) = if let Some(i) = value.strip_prefix("image:") {
            (BuildContextKind::Image, i.to_string())
        } else if let Some(url) = value.strip_prefix("url:") {
            (BuildContextKind::Url, url.to_string())
        } else if let Some(p) = value.strip_prefix("localpath:") {
            if !local {
                return Err(ApiError::bad_request(format!(
                    "the build context {name}: a path of the client goes in a multipart body"
                )));
            }
            (BuildContextKind::Host, p.to_string())
        } else {
            return Err(ApiError::bad_request(format!(
                "unsupported build context {value:?}: url:, image: or localpath:"
            )));
        };
        out.push(BuildContextSpec {
            name: name.to_string(),
            kind,
            source,
        });
    }
    Ok(out)
}

/// The `labels` of a build: a map, or as podman's clients of 5 send them a
/// list of `KEY=VALUE` (or `KEY`, an empty value).
fn build_labels(a: &str) -> ApiResult<BTreeMap<String, String>> {
    if let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(a) {
        return Ok(map);
    }
    let list: Vec<String> = serde_json::from_str(a)
        .map_err(|e| ApiError::bad_request(format!("invalid labels `{a}`: {e}")))?;
    Ok(list
        .into_iter()
        .map(|l| match l.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (l, String::new()),
        })
        .collect())
}

/// The boundary of a `multipart/form-data` body.
fn multipart_boundary(call: &Call) -> Option<String> {
    let ct = call.header("content-type")?;
    let mut parts = ct.split(';');
    if !parts
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    // (at most 70 bytes, as RFC 2046 says: the search for a delimiter
    // costs its length for each byte of the body)
    parts.find_map(|p| {
        let (k, v) = p.split_once('=')?;
        let v = v.trim().trim_matches('"');
        (k.trim().eq_ignore_ascii_case("boundary") && v.len() <= 70).then(|| v.to_string())
    })
}

/// podman's libpod build takes a tar (or multipart) body only.
fn check_content_type(call: &Call) -> ApiResult<()> {
    let Some(ct) = call.header("content-type") else {
        return Ok(());
    };
    let media = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if call.libpod
        && !matches!(
            media.as_str(),
            "application/x-tar" | "application/tar" | "multipart/form-data"
        )
    {
        return Err(ApiError::bad_request(format!(
            "Content-Type: {ct} is not supported. Should be \"application/x-tar\""
        )));
    }
    Ok(())
}

/// The most parts of a multipart build body: the main context and the
/// named ones.
const MAX_PARTS: usize = 65;

/// The sections of a multipart body as frames, written to a pipe by the
/// thread that splits the body.
struct Sections {
    out: std::fs::File,
    /// The content not written yet
    buf: Vec<u8>,
    /// The main context came
    main: bool,
}

impl Sections {
    fn frame(&mut self, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.out.write_all(&(data.len() as u32).to_be_bytes())?;
        self.out.write_all(data)
    }

    /// The content so far, as a frame.
    fn flush_frame(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        if !self.buf.is_empty() {
            self.out.write_all(&(self.buf.len() as u32).to_be_bytes())?;
            self.out.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
}

impl super::multipart::Sink for Sections {
    fn open(&mut self, name: &str, _: Option<&str>) -> std::io::Result<()> {
        let header = if name == "MainContext" {
            self.main = true;
            velarx_proto::build::SECTION_MAIN.to_string()
        } else if let Some(n) = name.strip_prefix("build-context-") {
            format!("{}{n}", velarx_proto::build::SECTION_CONTEXT)
        } else {
            return Err(std::io::Error::other(Refused(format!(
                "an unknown part {name:?} of the build body"
            ))));
        };
        self.frame(header.as_bytes())
    }

    fn content(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= 256 * 1024 {
            self.flush_frame()?;
        }
        Ok(())
    }

    /// The end of a section: what is left, then the empty frame.
    fn close(&mut self) -> std::io::Result<()> {
        self.flush_frame()?;
        self.frame(&[])
    }
}

/// Why a multipart body is not one a build takes, in the words of the
/// request (not a failure of the pipe).
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// The sections of the multipart body `input`, as frames to `out`: for each
/// part a frame with its name (`main` for `MainContext`, `context:NAME` for
/// `build-context-NAME`), the frames of its content and the empty frame;
/// the empty frame ends the sections.  A body that is not one a build takes
/// ends with the frame that gives the upload up and says why.
pub(crate) fn write_sections(input: impl std::io::Read, boundary: &str, out: std::fs::File) {
    let mut sections = Sections {
        out,
        buf: Vec::new(),
        main: false,
    };
    let result = super::multipart::each_part(input, boundary, MAX_PARTS, &mut sections);
    let result = match result {
        Ok(()) if !sections.main => Err(std::io::Error::other(Refused(
            "the multipart body has no MainContext".into(),
        ))),
        other => other,
    };
    match result {
        Ok(()) => {
            let _ = sections.frame(&[]);
        }
        Err(e) => {
            let reason = match e.get_ref().and_then(|r| r.downcast_ref::<Refused>()) {
                Some(r) => r.0.clone(),
                None => format!("invalid multipart body: {e}"),
            };
            use std::io::Write;
            let reason =
                &reason.as_bytes()[..reason.len().min(velarx_proto::build::MAX_ABORT_REASON)];
            let mut frame = velarx_proto::build::FRAME_ABORT.to_be_bytes().to_vec();
            frame.extend_from_slice(&(reason.len() as u32).to_be_bytes());
            frame.extend_from_slice(reason);
            let _ = sections.out.write_all(&frame);
        }
    }
}

/// A map as the list of pairs of a spec.
fn pairs(map: BTreeMap<String, String>) -> Vec<BuildPair> {
    velarx_proto::buildspec::pairs(map)
}

/// `POST /build`
async fn build(mut call: Call) -> ApiResult {
    let (spec, access) = spec_of(&call, false)?;
    // (a remote context: the body is ignored)
    let context = if spec.remote.is_some() {
        None
    } else if let Some(boundary) = multipart_boundary(&call) {
        Some(Context::Sections(call.take_body(), boundary))
    } else {
        Some(Context::Body(call.take_body()))
    };
    let lines = lines_of(&spec);
    let progress = call.engine.image_build(&spec, &access, context).await?;
    Ok(reply::with_type(
        200,
        "application/json",
        progress.build_body(lines),
    ))
}

/// `POST /libpod/local/build`
async fn local_build(call: Call) -> ApiResult {
    let (spec, access) = spec_of(&call, true)?;
    let lines = lines_of(&spec);
    let progress = call.engine.image_build(&spec, &access, None).await?;
    Ok(reply::with_type(
        200,
        "application/json",
        progress.build_body(lines),
    ))
}

/// How the progress of the build of `spec` is told to its client.
fn lines_of(spec: &BuildSpec) -> velarx_shape::build::BuildLines {
    velarx_shape::build::BuildLines {
        quiet: spec.quiet,
        docker: spec.client == velarx_proto::buildspec::BuildClient::Docker,
    }
}

/// `POST /build/prune`
async fn build_prune(call: Call) -> ApiResult {
    // (Docker's client sends 0 for the sizes it does not set, and a
    // filter map that is empty)
    if call.q("filters").is_some_and(|f| !matches!(f, "" | "{}")) {
        return Err(ApiError::not_implemented(
            "the parameter `filters` is not supported",
        ));
    }
    for name in [
        "keep-storage",
        "min-free-space",
        "max-used-space",
        "reserved-space",
    ] {
        if call.q(name).is_some_and(|v| !matches!(v, "" | "0")) {
            return Err(ApiError::not_implemented(format!(
                "the parameter `{name}` is not supported"
            )));
        }
    }
    let pruned = engine_call!(call.engine, build_prune())?;
    Ok(reply::json(
        200,
        &serde_json::json!({"CachesDeleted": pruned.ids, "SpaceReclaimed": pruned.space}),
    ))
}

pub(super) static ROUTES: &[Route] = &[
    route!("POST", "/build", BOTH, Image, build),
    route!("POST", "/local/build", LIBPOD, Image, local_build),
    route!("POST", "/build/prune", COMPAT, None, build_prune),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_as_podman_parses_them() {
        for ok in [
            "linux/amd64",
            "linux/arm64/v8",
            "amd64",
            "linux",
            "windows/amd64",
        ] {
            assert!(check_platform(ok).is_ok(), "{ok}");
        }
        assert_eq!(
            check_platform("test").unwrap_err(),
            "failed to parse query parameter 'platform': \"test\": invalid platform syntax for --platform=\"test\": \"test\": unknown operating system or architecture: invalid argument"
        );
        assert!(check_platform("linux/z80").is_err());
        assert!(check_platform("a/b/c/d").is_err());
    }

    #[test]
    fn containerfile_paths() {
        assert_eq!(containerfile_path("").unwrap(), None);
        assert_eq!(containerfile_path("Bad").unwrap().as_deref(), Some("Bad"));
        assert_eq!(containerfile_path("./a/b").unwrap().as_deref(), Some("a/b"));
        assert_eq!(containerfile_path("/a/b").unwrap().as_deref(), Some("a/b"));
        assert_eq!(
            containerfile_path(r#"["x/Containerfile"]"#)
                .unwrap()
                .as_deref(),
            Some("x/Containerfile")
        );
        assert!(containerfile_path("../x").is_err());
        assert!(containerfile_path("a/../../x").is_err());
        assert!(containerfile_path("Containerfile.in").is_err());
        assert_eq!(
            url_containerfile(r#"["https://h/Containerfile"]"#).unwrap(),
            Some("https://h/Containerfile".into())
        );
        assert_eq!(url_containerfile("Containerfile").unwrap(), None);
    }

    /// (rule, values that ask for something, values a client sends by default)
    #[test]
    fn what_is_an_ask_and_what_is_a_default() {
        let table: &[(Given, &[&str], &[&str])] = &[
            (Given::Any, &["x"], &[""]),
            (Given::True, &["1", "true"], &["0", "false", ""]),
            (
                Given::NotIn(&["0", "default"]),
                &["2"],
                &["0", "default", ""],
            ),
            (
                Given::Namespaces,
                &[r#"[{"Name":"pid","Host":false}]"#, "x"],
                &[r#"[{"Name":"user","Host":true,"Path":""}]"#],
            ),
            (
                Given::IdMapping,
                &[
                    r#"{"HostUIDMapping":false}"#,
                    r#"{"AutoUserNs":true}"#,
                    r#"{"UIDMap":[{}]}"#,
                ],
                &[
                    r#"{"HostUIDMapping":true,"HostGIDMapping":true,"UIDMap":[],"GIDMap":[],"AutoUserNs":false}"#,
                ],
            ),
        ];
        for (rule, asks, defaults) in table {
            for v in *asks {
                assert!(given(*rule, &[v]), "{v:?} is an ask");
            }
            for v in *defaults {
                assert!(!given(*rule, &[v]), "{v:?} is a default");
            }
        }
    }

    #[test]
    fn labels_as_a_map_or_a_list() {
        assert_eq!(build_labels(r#"{"a":"1"}"#).unwrap()["a"], "1");
        let l = build_labels(r#"["xyz","k=v=w"]"#).unwrap();
        assert_eq!((l["xyz"].as_str(), l["k"].as_str()), ("", "v=w"));
        assert!(build_labels("[1]").is_err());
    }

    /// The sections of a multipart body, as the frames the engine reads: a
    /// name, the content, the empty frame; a body that is none a build takes
    /// ends with the frame that gives it up and says why.
    #[test]
    fn a_multipart_body_is_sections_or_a_reason() {
        use std::io::Read;
        let run = |body: &str| {
            let (read, write) = rustix::pipe::pipe().unwrap();
            super::write_sections(body.as_bytes(), "B", std::fs::File::from(write));
            let mut out = Vec::new();
            std::fs::File::from(read).read_to_end(&mut out).unwrap();
            out
        };
        let part = |name: &str, data: &str| {
            format!("--B\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{data}\r\n")
        };
        let frame = |data: &[u8]| {
            let mut f = (data.len() as u32).to_be_bytes().to_vec();
            f.extend_from_slice(data);
            f
        };
        let ok = run(&format!(
            "{}{}--B--\r\n",
            part("MainContext", "MAIN"),
            part("build-context-x", "X")
        ));
        let want: Vec<u8> = [
            frame(b"main"),
            frame(b"MAIN"),
            frame(b""),
            frame(b"context:x"),
            frame(b"X"),
            frame(b""),
            frame(b""),
        ]
        .concat();
        assert_eq!(ok, want);
        for (body, reason) in [
            (
                format!("{}--B--\r\n", part("other", "x")),
                "an unknown part",
            ),
            (
                format!("{}--B--\r\n", part("build-context-x", "x")),
                "no MainContext",
            ),
            ("--B\r\nContent".to_string(), "invalid multipart body"),
        ] {
            let out = run(&body);
            let at = out
                .windows(4)
                .position(|w| w == velarx_proto::build::FRAME_ABORT.to_be_bytes())
                .unwrap_or_else(|| panic!("{reason}: {out:?}"));
            let text = String::from_utf8_lossy(&out[at + 8..]).into_owned();
            assert!(text.contains(reason), "{text}");
        }
    }
}
