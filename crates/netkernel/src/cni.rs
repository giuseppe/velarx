// SPDX-License-Identifier: Apache-2.0
//! A CNI executor (specification 1.0 and 1.1): the plugins of a network configuration are run in order for ADD and in
//! reverse order for DEL, each with the result of the previous one
//! (`prevResult`), its capabilities as `runtimeConfig`, and the results
//! are cached in libcni's format so that DEL works after a restart.
//!
//! The plugins are programs of the bin directories named by the `type`
//! of a plugin configuration (no path in it); each runs with a timeout,
//! its output capped, in `/`, with the environment of this process but
//! its `CNI_*` variables.

use base64::Engine;
use serde_json::{json, Map, Value};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The most a plugin may write on its standard output.
const OUTPUT_MAX: u64 = 1024 * 1024;
/// What of its standard error is kept for the error message.
const STDERR_MAX: u64 = 64 * 1024;
/// The largest configuration file read.
const CONFIG_MAX: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CniError {
    /// No configuration (`Status` says the network is not ready).
    #[error("{0}")]
    NoConfig(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Plugin(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub type CniResult<T> = Result<T, CniError>;

/// Where the configurations, the plugins and the cache are.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CniConfig {
    pub conf_dir: PathBuf,
    pub bin_dirs: Vec<PathBuf>,
    pub cache_dir: PathBuf,
    pub timeout: Duration,
}

impl Default for CniConfig {
    fn default() -> Self {
        Self {
            conf_dir: "/etc/cni/net.d".into(),
            bin_dirs: vec!["/opt/cni/bin".into(), "/usr/libexec/cni".into()],
            cache_dir: "/var/lib/velarx/cni".into(),
            timeout: Duration::from_secs(60),
        }
    }
}

/// A network configuration (a `.conflist`, or a single plugin `.conf`).
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    pub file: PathBuf,
    pub name: String,
    pub cni_version: String,
    pub plugins: Vec<Value>,
    /// The whole configuration, cached with the result.
    pub text: String,
}

/// A port of a pod published on the host (CRI PortMapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    /// tcp, udp, sctp.
    pub protocol: String,
    pub host_ip: String,
}

/// What an attachment is about.
#[derive(Debug, Clone, Default)]
pub struct Attachment {
    pub container_id: String,
    /// The network namespace (a path); none for DEL of a gone namespace.
    pub netns: Option<PathBuf>,
    pub ifname: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub pod_uid: String,
    pub port_mappings: Vec<PortMapping>,
    /// The subnets the node gives its pods (the pod CIDR of the kubelet),
    /// for the plugins that ask for `ipRanges`.
    pub ip_ranges: Vec<String>,
    /// The annotations of the pod (bandwidth, the pod annotations).
    pub annotations: Map<String, Value>,
    /// The CRI DNS config: `{"servers": [...], "searches": [...], "options": [...]}`.
    pub dns: Option<Value>,
}

fn invalid(msg: impl Into<String>) -> CniError {
    CniError::Invalid(msg.into())
}

/// Whether S is a plugin type: a file name, nothing that walks a path.
fn valid_type(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/') && !s.contains('\0')
}

/// Parse the text of a `.conf`, `.conflist` or `.json` file.
pub fn parse(file: &Path, text: &str) -> CniResult<Network> {
    let conf: Value = serde_json::from_str(text)
        .map_err(|e| invalid(format!("`{}` is not JSON: {e}", file.display())))?;
    let obj = conf
        .as_object()
        .ok_or_else(|| invalid(format!("`{}` is not a JSON object", file.display())))?;
    let name = obj
        .get("name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| invalid(format!("`{}` has no network name", file.display())))?;
    let version = obj
        .get("cniVersion")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or("0.1.0");
    let plugins = match obj.get("plugins") {
        Some(Value::Array(p)) if !p.is_empty() => p.clone(),
        Some(_) => return Err(invalid(format!("`{}` has no plugins", file.display()))),
        // A single plugin: the configuration is the plugin.
        None => vec![conf.clone()],
    };
    for p in &plugins {
        if !p
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(valid_type)
        {
            return Err(invalid(format!(
                "invalid plugin type in `{}`",
                file.display()
            )));
        }
    }
    Ok(Network {
        file: file.to_path_buf(),
        name: name.to_string(),
        cni_version: version.to_string(),
        plugins,
        text: text.to_string(),
    })
}

fn read_capped(path: &Path, max: u64) -> io::Result<String> {
    velarx_base::conf::read_config_file(path, max)
}

/// The configuration files of the directory, by name.
fn config_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            !n.starts_with('.')
                && (n.ends_with(".conf") || n.ends_with(".conflist") || n.ends_with(".json"))
        })
        .collect();
    files.sort();
    files
}

/// The network NAME of the configuration directory, or its first valid
/// configuration when NAME is None.
pub fn load(cfg: &CniConfig, name: Option<&str>) -> CniResult<Network> {
    let mut invalid_one = None;
    for path in config_files(&cfg.conf_dir) {
        let net = read_capped(&path, CONFIG_MAX)
            .map_err(CniError::from)
            .and_then(|text| parse(&path, &text));
        match net {
            Ok(n) if name.is_none_or(|w| w == n.name) => return Ok(n),
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("ignoring the CNI configuration `{}`: {e}", path.display());
                invalid_one = Some(e.to_string());
            }
        }
    }
    let dir = cfg.conf_dir.display();
    Err(match (name, invalid_one) {
        (Some(n), _) => CniError::NoConfig(format!("no CNI network `{n}` in `{dir}`")),
        (None, Some(e)) => invalid(format!("no valid CNI configuration in `{dir}`: {e}")),
        (None, None) => CniError::NoConfig(format!("no CNI configuration file in `{dir}`")),
    })
}

fn version_at_least(v: &str, major: u32, minor: u32) -> bool {
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let (a, b) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    a > major || (a == major && b >= minor)
}

/// A quantity of the bandwidth annotations: `10M`, `1Gi`, `100k`; none when
/// it is no quantity or does not fit in 64 bits.
fn parse_quantity(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let v: f64 = num.parse().ok().filter(|v: &f64| *v >= 0.0)?;
    let mult = match unit {
        "" => 1.0,
        "k" | "K" => 1e3,
        "M" => 1e6,
        "G" => 1e9,
        "T" => 1e12,
        "P" => 1e15,
        "E" => 1e18,
        "Ki" => 1024.0,
        "Mi" => 1024.0 * 1024.0,
        "Gi" => 1024.0 * 1024.0 * 1024.0,
        "Ti" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "Pi" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "Ei" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    let bits = v * mult;
    // (u64::MAX as f64 is 2^64, which does not fit)
    (bits < u64::MAX as f64).then_some(bits as u64)
}

/// Whether S may be a value of `CNI_ARGS` (`K=V;K=V`): a `;` or a `=` would
/// make it other arguments.
fn valid_cni_arg(s: &str) -> bool {
    !s.contains([';', '=', '\0'])
}

/// The annotations of the pod that limit its bandwidth, in the
/// `bandwidth` capability's form: the rates in bits per second.
fn bandwidth(a: &Attachment) -> Map<String, Value> {
    let mut bw = Map::new();
    for (key, rate, burst) in BANDWIDTH_ANNOTATIONS {
        if let Some(v) = a
            .annotations
            .get(key)
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            .filter(|v| *v > 0)
        {
            bw.insert(rate.into(), json!(v));
            bw.insert(burst.into(), json!(i32::MAX));
        }
    }
    bw
}

/// The annotations of a pod that limit its bandwidth, and the fields of the
/// capability they are.
const BANDWIDTH_ANNOTATIONS: [(&str, &str, &str); 2] = [
    (
        "kubernetes.io/ingress-bandwidth",
        "ingressRate",
        "ingressBurst",
    ),
    (
        "kubernetes.io/egress-bandwidth",
        "egressRate",
        "egressBurst",
    ),
];

/// What the pod asks for that the plugins of NET must be able to give: an
/// invalid bandwidth, or one that no plugin of the network has the
/// capability for, is refused (the limit would be silently absent).
pub fn check_requests(net: &Network, a: &Attachment) -> CniResult<()> {
    for (key, v) in [
        ("K8S_POD_NAMESPACE", &a.pod_namespace),
        ("K8S_POD_NAME", &a.pod_name),
        ("K8S_POD_UID", &a.pod_uid),
    ] {
        if !valid_cni_arg(v) {
            return Err(invalid(format!(
                "{key} {v:?} of the pod has a `;` or a `=`, which CNI_ARGS cannot carry"
            )));
        }
    }
    for (key, _, _) in BANDWIDTH_ANNOTATIONS {
        let Some(v) = a.annotations.get(key) else {
            continue;
        };
        let text = v.as_str().unwrap_or_default();
        if parse_quantity(text).filter(|v| *v > 0).is_none() {
            return Err(invalid(format!(
                "annotation {key}: {text:?} is not a positive quantity"
            )));
        }
        let has = net.plugins.iter().any(|p| {
            p.pointer("/capabilities/bandwidth")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        });
        if !has {
            return Err(invalid(format!(
                "the pod sets {key} and no plugin of the CNI network {:?} has the `bandwidth` capability (add the bandwidth plugin to the configuration {})",
                net.name,
                net.file.display()
            )));
        }
    }
    Ok(())
}

/// The `runtimeConfig` of a plugin: what its capabilities ask for.
fn runtime_config(plugin: &Value, a: &Attachment) -> Option<Value> {
    let caps = plugin.get("capabilities")?;
    let cap = |k: &str| caps.get(k).and_then(Value::as_bool).unwrap_or(false);
    let mut rc = Map::new();
    if cap("portMappings") {
        let pm: Vec<Value> = a
            .port_mappings
            .iter()
            .filter(|m| m.host_port != 0)
            .map(|m| {
                json!({"hostPort": m.host_port, "containerPort": m.container_port,
                       "protocol": m.protocol, "hostIP": m.host_ip})
            })
            .collect();
        if !pm.is_empty() {
            rc.insert("portMappings".into(), Value::Array(pm));
        }
    }
    if cap("bandwidth") {
        let bw = bandwidth(a);
        if !bw.is_empty() {
            rc.insert("bandwidth".into(), Value::Object(bw));
        }
    }
    if cap("ipRanges") && !a.ip_ranges.is_empty() {
        let sets: Vec<Value> = a
            .ip_ranges
            .iter()
            .map(|subnet| json!([{"subnet": subnet}]))
            .collect();
        rc.insert("ipRanges".into(), Value::Array(sets));
    }
    if cap("dns") {
        if let Some(Value::Object(d)) = &a.dns {
            let dns: Map<String, Value> = d
                .iter()
                .filter(|(k, _)| matches!(k.as_str(), "servers" | "searches" | "options"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if !dns.is_empty() {
                rc.insert("dns".into(), Value::Object(dns));
            }
        }
    }
    if cap("io.kubernetes.cri.pod-annotations") && !a.annotations.is_empty() {
        rc.insert(
            "io.kubernetes.cri.pod-annotations".into(),
            Value::Object(a.annotations.clone()),
        );
    }
    (!rc.is_empty()).then_some(Value::Object(rc))
}

/// What a plugin is given on its standard input.
fn plugin_input(net: &Network, plugin: &Value, prev: Option<&Value>, a: &Attachment) -> String {
    let mut conf = plugin.clone();
    if let Some(o) = conf.as_object_mut() {
        o.insert("cniVersion".into(), json!(net.cni_version));
        o.insert("name".into(), json!(net.name));
        if let Some(p) = prev {
            o.insert("prevResult".into(), p.clone());
        }
        if let Some(rc) = runtime_config(plugin, a) {
            o.insert("runtimeConfig".into(), rc);
        }
    }
    conf.to_string()
}

fn find_plugin(cfg: &CniConfig, ty: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    cfg.bin_dirs.iter().map(|d| d.join(ty)).find(|p| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// The environment of a plugin: the one of this process but its `CNI_*`
/// variables, and the ones of CNI.
fn plugin_env(cfg: &CniConfig, command: &str, a: &Attachment) -> Vec<(String, String)> {
    plugin_env_from(std::env::vars(), cfg, command, a)
}

fn plugin_env_from(
    parent: impl Iterator<Item = (String, String)>,
    cfg: &CniConfig,
    command: &str,
    a: &Attachment,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = parent.filter(|(k, _)| !k.starts_with("CNI_")).collect();
    let path = cfg
        .bin_dirs
        .iter()
        .map(|d| d.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    let netns = a
        .netns
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    // (ADD refuses such a value: check_requests; it is left out of a DEL)
    let arg = |v: &str| {
        if valid_cni_arg(v) {
            v.to_string()
        } else {
            String::new()
        }
    };
    env.extend([
        ("CNI_COMMAND".into(), command.into()),
        ("CNI_CONTAINERID".into(), a.container_id.clone()),
        ("CNI_NETNS".into(), netns),
        ("CNI_IFNAME".into(), a.ifname.clone()),
        ("CNI_PATH".into(), path),
        (
            "CNI_ARGS".into(),
            format!(
                "IgnoreUnknown=1;K8S_POD_NAMESPACE={};K8S_POD_NAME={};K8S_POD_INFRA_CONTAINER_ID={};K8S_POD_UID={}",
                arg(&a.pod_namespace),
                arg(&a.pod_name),
                arg(&a.container_id),
                arg(&a.pod_uid)
            ),
        ),
    ]);
    env
}

/// Run PATH with INPUT; its exit status, standard output and error.  A
/// plugin that has not ended in TIMEOUT is killed.
fn exec_plugin(
    path: &Path,
    env: &[(String, String)],
    input: String,
    timeout: Duration,
) -> CniResult<(i32, Vec<u8>, Vec<u8>)> {
    use std::os::unix::process::ExitStatusExt;
    let mut child = Command::new(path)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| CniError::Plugin(format!("cannot run `{}`: {e}", path.display())))?;
    let pid = rustix::process::Pid::from_child(&child);
    let mut stdin = child.stdin.take();
    let writer = std::thread::spawn(move || {
        if let Some(s) = stdin.as_mut() {
            let _ = s.write_all(input.as_bytes());
        }
    });
    let deadline = std::time::Instant::now() + timeout;
    let out = velarx_sys::pipe::drain(child.stdout.take(), OUTPUT_MAX);
    let err = velarx_sys::pipe::drain(child.stderr.take(), STDERR_MAX);
    let (ended, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended.send(child.wait());
    });
    let status = match wait.recv_timeout(timeout) {
        Ok(status) => status?,
        Err(_) => {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
            let _ = wait.recv();
            return Err(CniError::Plugin(format!(
                "the plugin `{}` did not answer in {} seconds",
                path.display(),
                timeout.as_secs()
            )));
        }
    };
    let _ = writer.join();
    // (a child of the plugin that keeps the pipes open is not waited for
    // past the deadline)
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    let out = out.recv_timeout(left).map_err(|_| {
        CniError::Plugin(format!(
            "the plugin `{}` left a process that keeps its output open",
            path.display()
        ))
    })?;
    let mut errout = err.recv_timeout(left).unwrap_or_default();
    errout.truncate(STDERR_MAX as usize);
    if out.len() as u64 > OUTPUT_MAX {
        return Err(CniError::Plugin(format!(
            "the plugin `{}` wrote more than {OUTPUT_MAX} bytes",
            path.display()
        )));
    }
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    Ok((code, out, errout))
}

/// Run COMMAND for one plugin: its result, if it printed one.
fn run_plugin(
    cfg: &CniConfig,
    net: &Network,
    plugin: &Value,
    command: &str,
    prev: Option<&Value>,
    a: &Attachment,
) -> CniResult<Option<Value>> {
    let ty = plugin.get("type").and_then(Value::as_str).unwrap_or("");
    let path = find_plugin(cfg, ty).ok_or_else(|| {
        CniError::Plugin(format!("cannot find the CNI plugin `{ty}` in the bin dirs"))
    })?;
    let input = plugin_input(net, plugin, prev, a);
    let (code, out, errout) = exec_plugin(&path, &plugin_env(cfg, command, a), input, cfg.timeout)?;
    if code != 0 {
        let e: Value = serde_json::from_slice(&out).unwrap_or(Value::Null);
        let msg = e
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or(if code == 127 {
                "cannot execute the plugin"
            } else {
                "no error message"
            });
        let mut text = format!("CNI plugin `{ty}` failed ({command}): {msg}");
        if let Some(d) = e.get("details").and_then(Value::as_str) {
            text.push_str(": ");
            text.push_str(d);
        }
        let errout = String::from_utf8_lossy(&errout);
        if !errout.trim().is_empty() {
            text.push_str(": ");
            text.push_str(errout.trim());
        }
        return Err(CniError::Plugin(text));
    }
    if out.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    serde_json::from_slice(&out).map(Some).map_err(|_| {
        CniError::Plugin(format!(
            "CNI plugin `{ty}` ({command}) returned an invalid result"
        ))
    })
}

/// Whether S may be a part of a cache file name.
fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s != "."
        && s != ".."
        && !s.contains('/')
        && !s.contains('\0')
}

fn cache_file(cfg: &CniConfig, net: &str, container_id: &str, ifname: &str) -> CniResult<PathBuf> {
    if !(valid_component(net) && valid_component(container_id) && valid_component(ifname)) {
        return Err(invalid("invalid network, container or interface name"));
    }
    Ok(cfg
        .cache_dir
        .join("results")
        .join(format!("{net}-{container_id}-{ifname}")))
}

fn write_cache(
    cfg: &CniConfig,
    net: &Network,
    a: &Attachment,
    result: Option<&Value>,
) -> CniResult<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = cfg.cache_dir.join("results");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let path = cache_file(cfg, &net.name, &a.container_id, &a.ifname)?;
    let mut o = json!({
        "kind": "cniCacheV1",
        "containerId": a.container_id,
        "config": base64::engine::general_purpose::STANDARD.encode(net.text.as_bytes()),
        "ifName": a.ifname,
        "networkName": net.name,
        "cniArgs": [
            ["K8S_POD_NAMESPACE", a.pod_namespace],
            ["K8S_POD_NAME", a.pod_name],
            ["K8S_POD_INFRA_CONTAINER_ID", a.container_id],
            ["K8S_POD_UID", a.pod_uid],
        ],
    });
    if let (Some(r), Some(m)) = (result, o.as_object_mut()) {
        m.insert("result".into(), r.clone());
    }
    // (libcni's capabilityArgs: a DEL gets what the ADD got, as the caller of
    // a DEL, a removal or the GC, may know no pod CIDR or ports)
    let mut args = Map::new();
    if !a.ip_ranges.is_empty() {
        let sets: Vec<Value> = a
            .ip_ranges
            .iter()
            .map(|subnet| json!([{ "subnet": subnet }]))
            .collect();
        args.insert("ipRanges".into(), Value::Array(sets));
    }
    if !a.port_mappings.is_empty() {
        let pm: Vec<Value> = a
            .port_mappings
            .iter()
            .map(|m| {
                json!({"hostPort": m.host_port, "containerPort": m.container_port,
                       "protocol": m.protocol, "hostIP": m.host_ip})
            })
            .collect();
        args.insert("portMappings".into(), Value::Array(pm));
    }
    if let (false, Some(m)) = (args.is_empty(), o.as_object_mut()) {
        m.insert("capabilityArgs".into(), Value::Object(args));
    }
    // (a name of its own: the ADDs of several pods write at the same time)
    let mut f = tempfile::Builder::new()
        .prefix(".cache")
        .suffix(".tmp")
        .permissions(std::fs::Permissions::from_mode(0o600))
        .tempfile_in(&dir)?;
    f.write_all(o.to_string().as_bytes())?;
    f.as_file().sync_all()?;
    f.persist(&path).map_err(|e| e.error)?;
    Ok(())
}

/// The cached configuration and result of the attachment, for the
/// network NET.
fn read_cache(cfg: &CniConfig, net: &str, a: &Attachment) -> Option<(Network, Option<Value>)> {
    read_cache_entry(cfg, net, a).map(|(net, result, _)| (net, result))
}

/// The same, with the attachment A as the ADD had it: the pod CIDR and the
/// ports of the cache where A has none (what a DEL is given).
fn read_cache_entry(
    cfg: &CniConfig,
    net: &str,
    a: &Attachment,
) -> Option<(Network, Option<Value>, Attachment)> {
    let path = cache_file(cfg, net, &a.container_id, &a.ifname).ok()?;
    let o: Value = serde_json::from_str(&read_capped(&path, CONFIG_MAX).ok()?).ok()?;
    let conf = base64::engine::general_purpose::STANDARD
        .decode(o.get("config")?.as_str()?)
        .ok()?;
    let net = parse(&path, std::str::from_utf8(&conf).ok()?).ok()?;
    let mut added = a.clone();
    let args = o.get("capabilityArgs");
    if added.ip_ranges.is_empty() {
        added.ip_ranges = args
            .and_then(|c| c.get("ipRanges"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|set| set.get(0)?.get("subnet")?.as_str().map(String::from))
            .collect();
    }
    if added.port_mappings.is_empty() {
        let num = |m: &Value, k: &str| {
            m.get(k)
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok())
                .unwrap_or(0)
        };
        let text = |m: &Value, k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        added.port_mappings = args
            .and_then(|c| c.get("portMappings"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|m| PortMapping {
                host_port: num(m, "hostPort"),
                container_port: num(m, "containerPort"),
                protocol: text(m, "protocol"),
                host_ip: text(m, "hostIP"),
            })
            .collect();
    }
    Some((net, o.get("result").cloned(), added))
}

/// The configuration and the result the cache has for the attachment A (of
/// any network).
pub fn cached_result(cfg: &CniConfig, a: &Attachment) -> Option<(Network, Option<Value>)> {
    cached_networks(cfg, a)
        .into_iter()
        .find_map(|name| read_cache(cfg, &name, a))
}

/// The networks of the cache that have an attachment of A.
fn cached_networks(cfg: &CniConfig, a: &Attachment) -> Vec<String> {
    let suffix = format!("-{}-{}", a.container_id, a.ifname);
    std::fs::read_dir(cfg.cache_dir.join("results"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_suffix(&suffix)
                .filter(|net| !net.is_empty())
                .map(String::from)
        })
        .collect()
}

/// DEL with the plugins of NET in reverse order: every one is tried, the
/// first failure is returned.
fn del_with(cfg: &CniConfig, net: &Network, a: &Attachment, prev: Option<&Value>) -> CniResult<()> {
    let mut first = None;
    for p in net.plugins.iter().rev() {
        if let Err(e) = run_plugin(cfg, net, p, "DEL", prev, a) {
            first.get_or_insert(e);
        }
    }
    first.map_or(Ok(()), Err)
}

/// ADD: the result of the last plugin.  A failed ADD is undone; the
/// result is cached (an ADD that cannot be cached is undone as well).
pub fn add(cfg: &CniConfig, net: &Network, a: &Attachment) -> CniResult<Value> {
    check_requests(net, a)?;
    let mut prev: Option<Value> = None;
    for p in &net.plugins {
        match run_plugin(cfg, net, p, "ADD", prev.as_ref(), a) {
            Ok(Some(r)) => prev = Some(r),
            Ok(None) => {}
            Err(e) => {
                if let Err(d) = del_with(cfg, net, a, prev.as_ref()) {
                    tracing::debug!("CNI cleanup after a failed ADD: {d}");
                }
                return Err(e);
            }
        }
    }
    if let Err(e) = write_cache(cfg, net, a, prev.as_ref()) {
        if let Err(d) = del_with(cfg, net, a, prev.as_ref()) {
            tracing::warn!("CNI DEL after the cache could not be written: {d}");
        }
        return Err(e);
    }
    Ok(prev.unwrap_or_else(|| json!({})))
}

/// DEL with the cached results of the ADD, else with the current
/// configuration; nothing to delete is no error.
pub fn del(cfg: &CniConfig, a: &Attachment) -> CniResult<()> {
    let cached = cached_networks(cfg, a);
    if !cached.is_empty() {
        let mut first = None;
        for name in cached {
            let Some((net, result, added)) = read_cache_entry(cfg, &name, a) else {
                first.get_or_insert(CniError::Invalid(format!(
                    "the cached attachment of `{name}` cannot be read"
                )));
                continue;
            };
            match del_with(cfg, &net, &added, result.as_ref()) {
                Ok(()) => {
                    if let Ok(p) = cache_file(cfg, &name, &a.container_id, &a.ifname) {
                        let _ = std::fs::remove_file(p);
                    }
                }
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        return first.map_or(Ok(()), Err);
    }
    match load(cfg, None) {
        Ok(net) => del_with(cfg, &net, a, None),
        Err(CniError::NoConfig(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// CHECK (CNI 0.4 and later): whether the attachment is as the cached
/// result says.
pub fn check(cfg: &CniConfig, net: &Network, a: &Attachment) -> CniResult<()> {
    if !version_at_least(&net.cni_version, 0, 4) {
        return Ok(());
    }
    let prev = read_cache(cfg, &net.name, a).and_then(|(_, r)| r);
    for p in &net.plugins {
        run_plugin(cfg, net, p, "CHECK", prev.as_ref(), a)?;
    }
    Ok(())
}

/// STATUS (CNI 1.1 and later; an older network is ready when it has a
/// configuration).
pub fn status(cfg: &CniConfig, net: &Network) -> CniResult<()> {
    if !version_at_least(&net.cni_version, 1, 1) {
        return Ok(());
    }
    let a = Attachment {
        container_id: "status".into(),
        ifname: "eth0".into(),
        ..Attachment::default()
    };
    for p in &net.plugins {
        run_plugin(cfg, net, p, "STATUS", None, &a)?;
    }
    Ok(())
}

/// The addresses of a result for the interface IFNAME, the primary first:
/// those of IFNAME in the sandbox, else of any interface in the sandbox,
/// else all of them.
pub fn result_ips(result: &Value, ifname: &str) -> Vec<IpAddr> {
    let ips = result.get("ips").and_then(Value::as_array);
    let ifaces = result.get("interfaces").and_then(Value::as_array);
    let in_sandbox = |i: &Value| {
        i.get("sandbox")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    };
    for pass in 0..3 {
        let list: Vec<IpAddr> = ips
            .into_iter()
            .flatten()
            .filter(|ip| {
                let idx = ip.get("interface").and_then(Value::as_u64);
                let iface = idx.and_then(|i| ifaces.and_then(|f| f.get(i as usize)));
                match pass {
                    0 => match iface {
                        None => idx.is_none(),
                        Some(f) => {
                            f.get("name").and_then(Value::as_str) == Some(ifname) && in_sandbox(f)
                        }
                    },
                    1 => iface.is_some_and(in_sandbox),
                    _ => true,
                }
            })
            .filter_map(|ip| {
                let addr = ip.get("address")?.as_str()?;
                addr.split('/').next()?.parse().ok()
            })
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    Vec::new()
}

/// An address of a result, with its prefix length and gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultAddress {
    pub address: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
}

/// The addresses of a result for IFNAME as [`result_ips`] picks them, with
/// their prefixes and gateways.
pub fn result_addresses(result: &Value, ifname: &str) -> Vec<ResultAddress> {
    let wanted = result_ips(result, ifname);
    result
        .get("ips")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|ip| {
            let text = ip.get("address")?.as_str()?;
            let (addr, prefix) = text.split_once('/')?;
            let address: IpAddr = addr.parse().ok()?;
            let prefix = prefix.parse().ok()?;
            wanted.contains(&address).then(|| ResultAddress {
                address,
                prefix,
                gateway: ip
                    .get("gateway")
                    .and_then(Value::as_str)
                    .and_then(|g| g.parse().ok()),
            })
        })
        .collect()
}

/// The hardware address of IFNAME in the sandbox, as a result has it.
pub fn result_mac(result: &Value, ifname: &str) -> Option<String> {
    result
        .get("interfaces")?
        .as_array()?
        .iter()
        .find(|i| {
            i.get("name").and_then(Value::as_str) == Some(ifname)
                && i.get("sandbox")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
        })?
        .get("mac")?
        .as_str()
        .map(String::from)
}

/// The attachments of the cache whose container LIVE says is gone: DEL
/// (with the cached configuration and result, without a namespace) and
/// forgotten.  The number released.
pub fn gc(cfg: &CniConfig, live: &dyn Fn(&str) -> bool) -> usize {
    let dir = cfg.cache_dir.join("results");
    let mut released = 0;
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let path = e.path();
        let Some(o) = read_capped(&path, CONFIG_MAX)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            continue;
        };
        let field = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let (id, ifname, net) = (field("containerId"), field("ifName"), field("networkName"));
        if id.is_empty() || live(&id) {
            continue;
        }
        let arg = |k: &str| {
            o.get("cniArgs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|p| p.get(0).and_then(Value::as_str) == Some(k))
                .and_then(|p| p.get(1).and_then(Value::as_str))
                .unwrap_or("")
                .to_string()
        };
        let a = Attachment {
            container_id: id.clone(),
            ifname,
            pod_name: arg("K8S_POD_NAME"),
            pod_namespace: arg("K8S_POD_NAMESPACE"),
            pod_uid: arg("K8S_POD_UID"),
            ..Attachment::default()
        };
        let Some((network, result, a)) = read_cache_entry(cfg, &net, &a) else {
            tracing::warn!("CNI GC of {id}: the cached attachment cannot be read");
            continue;
        };
        match del_with(cfg, &network, &a, result.as_ref()) {
            Ok(()) => {
                let _ = std::fs::remove_file(&path);
                released += 1;
            }
            Err(e) => tracing::warn!("CNI GC of {id}: {e}"),
        }
    }
    released
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fifo_is_refused_not_waited_for() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        velarx_base::testing::make_fifo(&fifo);
        let r =
            velarx_base::testing::returns_within(std::time::Duration::from_secs(10), move || {
                read_capped(&fifo, 100)
            });
        assert!(r.is_err());
    }

    #[test]
    fn configurations_and_plugin_types() {
        let p = Path::new("/x.conflist");
        let n = parse(
            p,
            r#"{"cniVersion":"1.0.0","name":"n","plugins":[{"type":"bridge"},{"type":"portmap"}]}"#,
        )
        .unwrap();
        assert_eq!((n.name.as_str(), n.plugins.len()), ("n", 2));
        let single = parse(p, r#"{"name":"s","type":"bridge"}"#).unwrap();
        assert_eq!(
            (single.cni_version.as_str(), single.plugins.len()),
            ("0.1.0", 1)
        );
        for bad in [
            "[]",
            r#"{"cniVersion":"1.0.0"}"#,
            r#"{"name":"n","plugins":[]}"#,
            r#"{"name":"n","plugins":[{"type":"../../bin/sh"}]}"#,
            r#"{"name":"n","type":".."}"#,
        ] {
            assert!(parse(p, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn quantities_and_versions() {
        assert_eq!(parse_quantity("10M"), Some(10_000_000));
        assert_eq!(parse_quantity("1Gi"), Some(1 << 30));
        assert_eq!(parse_quantity("x"), None);
        assert_eq!(parse_quantity("5Q"), None);
        assert_eq!(parse_quantity("-1M"), None);
        assert_eq!(parse_quantity("2P"), Some(2_000_000_000_000_000));
        assert_eq!(parse_quantity("1Ei"), Some(1 << 60));
        assert_eq!(parse_quantity("16Ei"), None);
        assert_eq!(parse_quantity("99999999999999999999E"), None);
        assert!(version_at_least("1.1.0", 1, 1));
        assert!(!version_at_least("1.0.0", 1, 1));
        assert!(version_at_least("0.4.0", 0, 4));
    }

    #[test]
    fn runtime_config_from_capabilities() {
        let plugin = json!({"type":"portmap","capabilities":{"portMappings":true,"bandwidth":true,"dns":true}});
        let a = Attachment {
            port_mappings: vec![
                PortMapping {
                    host_port: 8080,
                    container_port: 80,
                    protocol: "tcp".into(),
                    host_ip: String::new(),
                },
                PortMapping {
                    host_port: 0,
                    container_port: 81,
                    protocol: "tcp".into(),
                    host_ip: String::new(),
                },
            ],
            annotations: [("kubernetes.io/ingress-bandwidth".to_string(), json!("1M"))]
                .into_iter()
                .collect(),
            dns: Some(json!({"servers":["10.0.0.10"],"other":1})),
            ..Attachment::default()
        };
        let rc = runtime_config(&plugin, &a).unwrap();
        assert_eq!(rc["portMappings"].as_array().unwrap().len(), 1);
        assert_eq!(rc["bandwidth"]["ingressRate"], 1_000_000);
        assert_eq!(rc["dns"], json!({"servers":["10.0.0.10"]}));
        assert!(runtime_config(&json!({"type":"bridge"}), &a).is_none());
    }

    #[test]
    fn the_pod_cidr_is_the_ip_ranges_of_the_plugins_that_ask() {
        let a = Attachment {
            ip_ranges: vec!["10.1.0.0/24".into(), "fd00:1::/64".into()],
            ..Attachment::default()
        };
        let bridge = json!({"type":"bridge","capabilities":{"ipRanges":true}});
        let rc = runtime_config(&bridge, &a).unwrap();
        assert_eq!(
            rc["ipRanges"],
            json!([[{"subnet":"10.1.0.0/24"}],[{"subnet":"fd00:1::/64"}]])
        );
        assert!(runtime_config(&json!({"type":"flannel"}), &a).is_none());
    }

    #[test]
    fn a_bandwidth_nobody_applies_is_refused() {
        let net = |caps: Value| Network {
            file: "/etc/cni/net.d/10.conflist".into(),
            name: "k8s".into(),
            cni_version: "1.0.0".into(),
            plugins: vec![
                json!({"type":"bridge"}),
                json!({"type":"bandwidth","capabilities":caps}),
            ],
            text: String::new(),
        };
        let with = |v: &str| Attachment {
            annotations: [("kubernetes.io/egress-bandwidth".to_string(), json!(v))]
                .into_iter()
                .collect(),
            ..Attachment::default()
        };
        assert!(check_requests(&net(json!({"bandwidth":true})), &with("1M")).is_ok());
        assert!(check_requests(&net(json!({"bandwidth":true})), &Attachment::default()).is_ok());
        let e = check_requests(&net(json!({})), &with("1M")).unwrap_err();
        assert!(e.to_string().contains("`bandwidth` capability"), "{e}");
        let e = check_requests(&net(json!({"bandwidth":true})), &with("fast")).unwrap_err();
        assert!(e.to_string().contains("not a positive quantity"), "{e}");
        assert!(check_requests(&net(json!({"bandwidth":true})), &with("0")).is_err());
    }

    #[test]
    fn addresses_of_a_result() {
        let r = json!({
            "interfaces":[{"name":"cni0"},{"name":"eth0","sandbox":"/run/netns/x"}],
            "ips":[{"address":"10.0.0.1/24","interface":0},{"address":"10.1.2.3/24","interface":1},
                   {"address":"fd00::3/64","interface":1}]
        });
        let ips = result_ips(&r, "eth0");
        assert_eq!(
            ips,
            vec![
                "10.1.2.3".parse::<IpAddr>().unwrap(),
                "fd00::3".parse().unwrap()
            ]
        );
        let none = json!({"ips":[{"address":"10.9.9.9/8"}]});
        assert_eq!(
            result_ips(&none, "eth0"),
            vec!["10.9.9.9".parse::<IpAddr>().unwrap()]
        );
        assert!(result_ips(&json!({}), "eth0").is_empty());
    }

    #[test]
    fn plugins_get_the_environment_but_the_variables_of_cni() {
        let cfg = CniConfig::default();
        let a = Attachment {
            container_id: "c".into(),
            ifname: "eth0".into(),
            ..Attachment::default()
        };
        let parent = [
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("CNI_COMMAND".to_string(), "leaked".to_string()),
        ];
        let env = plugin_env_from(parent.into_iter(), &cfg, "ADD", &a);
        let get = |k: &str| {
            env.iter()
                .filter(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(get("CNI_COMMAND"), ["ADD"]);
        assert_eq!(get("PATH"), ["/usr/bin"]);
        assert_eq!(get("CNI_CONTAINERID"), ["c"]);

        // a value with a `;` or a `=` is no other argument
        let a = Attachment {
            pod_name: "p;IP=10.0.0.5".into(),
            pod_namespace: "default".into(),
            ..a
        };
        let env = plugin_env_from(std::iter::empty(), &cfg, "DEL", &a);
        let args = &env.iter().find(|(k, _)| k == "CNI_ARGS").unwrap().1;
        assert!(!args.contains("IP="), "{args}");
        assert!(args.contains("K8S_POD_NAMESPACE=default;"), "{args}");
        let net = Network {
            file: "/etc/cni/net.d/10.conflist".into(),
            name: "k8s".into(),
            cni_version: "1.0.0".into(),
            plugins: vec![json!({"type":"bridge"})],
            text: String::new(),
        };
        let e = check_requests(&net, &a).unwrap_err();
        assert!(e.to_string().contains("K8S_POD_NAME"), "{e}");
    }

    /// The ADDs of several pods write their caches at the same time: each
    /// reads back its own result, and no file of a write is left.
    #[test]
    fn caches_written_at_once_are_each_their_own() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = CniConfig {
            cache_dir: dir.path().to_path_buf(),
            ..CniConfig::default()
        };
        let text = r#"{"cniVersion":"1.0.0","name":"k8s","plugins":[{"type":"bridge"}]}"#;
        let net = parse(Path::new("10.conflist"), text).unwrap();
        let attachment = |n: usize| Attachment {
            container_id: format!("c{n}"),
            ifname: "eth0".into(),
            ..Attachment::default()
        };
        let barrier = std::sync::Barrier::new(16);
        std::thread::scope(|s| {
            for n in 0..16 {
                let (cfg, net, barrier) = (&cfg, &net, &barrier);
                s.spawn(move || {
                    let result = json!({"cniVersion": "1.0.0", "n": n, "pad": "x".repeat(1 << 16)});
                    barrier.wait();
                    write_cache(cfg, net, &attachment(n), Some(&result)).unwrap();
                });
            }
        });
        for n in 0..16 {
            let (_, result) = read_cache(&cfg, "k8s", &attachment(n)).unwrap();
            assert_eq!(result.unwrap()["n"], n, "{n}");
        }
        let left: Vec<_> = std::fs::read_dir(dir.path().join("results"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with('.'))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn cache_names_are_checked() {
        let cfg = CniConfig::default();
        assert!(cache_file(&cfg, "n", "../x", "eth0").is_err());
        assert!(cache_file(&cfg, "n", "abc", "eth0").is_ok());
    }
}
