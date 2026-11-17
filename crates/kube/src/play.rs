// SPDX-License-Identifier: Apache-2.0
//! `kube play`: the documents of a Kubernetes YAML as podman's create
//! requests.  This module maps; the API layer pulls, creates and starts.
//!
//! Kinds: `Pod`; `Deployment`, `DaemonSet`, `ReplicaSet` and `Job` (their
//! pod template, the pod named `NAME-pod` as podman names it);
//! `PersistentVolumeClaim` (a named volume); `ConfigMap` and `Secret`
//! (sources of variables and of volumes).  A container NAME of the pod POD
//! is `POD-NAME`, as podman.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

/// The scalars of the YAML are text: a field as a string.
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn list<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn strings(v: &Value, k: &str) -> Vec<String> {
    list(v, k)
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn flag(v: &Value, k: &str) -> bool {
    text(v, k) == "true"
}

/// A memory quantity in bytes: `64Mi`, `1G`, `1.5Gi`, `129e6`, `1048576`.
pub fn memory_bytes(q: &str) -> Result<i64, String> {
    let bad = || format!("invalid memory quantity `{q}`");
    let q = q.trim();
    let units: [(&str, f64); 12] = [
        ("Ki", 1024.0),
        ("Mi", 1024.0 * 1024.0),
        ("Gi", 1024.0 * 1024.0 * 1024.0),
        ("Ti", 1024f64.powi(4)),
        ("Pi", 1024f64.powi(5)),
        ("Ei", 1024f64.powi(6)),
        ("k", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
        ("P", 1e15),
        ("E", 1e18),
    ];
    let (num, mult) = units
        .iter()
        .find_map(|(u, m)| q.strip_suffix(u).map(|n| (n, *m)))
        .unwrap_or((q, 1.0));
    let n: f64 = num.parse().map_err(|_| bad())?;
    let bytes = n * mult;
    if !bytes.is_finite() || bytes < 0.0 || bytes > i64::MAX as f64 {
        return Err(bad());
    }
    Ok(bytes.ceil() as i64)
}

/// A CPU quantity in millicores: `500m`, `1`, `0.25`.
pub fn cpu_millis(q: &str) -> Result<i64, String> {
    let bad = || format!("invalid cpu quantity `{q}`");
    let q = q.trim();
    let m = match q.strip_suffix('m') {
        Some(n) => n.parse::<f64>().map_err(|_| bad())?,
        None => q.parse::<f64>().map_err(|_| bad())? * 1000.0,
    };
    if !m.is_finite() || m < 0.0 || m > 1e12 {
        return Err(bad());
    }
    Ok(m.round() as i64)
}

/// What the play makes besides the pods.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct VolumePlan {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    /// The files of a ConfigMap or Secret volume: (path, content, mode),
    /// written into it at each play
    pub files: Option<Vec<(String, Vec<u8>, u32)>>,
}

/// A host path of the pod and what Kubernetes checks or makes of it.
#[derive(Debug, Clone, PartialEq)]
pub struct HostPath {
    pub path: String,
    /// "", `Directory`, `DirectoryOrCreate`, `File`, `FileOrCreate`,
    /// `Socket`, `CharDevice` or `BlockDevice`
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerPlan {
    /// `POD-NAME`
    pub name: String,
    pub image: String,
    /// `Always`, `IfNotPresent` or `Never`
    pub pull_policy: String,
    /// podman's SpecGenerator, the pod set by the caller
    pub spec: Value,
    /// `runAsNonRoot`: the user the container runs as, the image's when the
    /// spec names none, must be a number other than 0 (checked by the
    /// caller, who knows the image)
    pub run_as_non_root: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PodPlan {
    pub name: String,
    /// podman's PodSpecGenerator
    pub spec: Value,
    /// Run one after the other to their end, before the containers, the
    /// first time the pod starts (podman's `once` init containers)
    pub init_containers: Vec<ContainerPlan>,
    pub containers: Vec<ContainerPlan>,
    /// The host paths the containers mount, checked or made first
    pub host_paths: Vec<HostPath>,
}

#[derive(Default, Clone, PartialEq)]
pub struct Plan {
    pub volumes: Vec<VolumePlan>,
    /// Secret documents: the name and the data of the secret to store (a
    /// JSON object of the decoded keys)
    pub secrets: Vec<(String, Vec<u8>)>,
    pub pods: Vec<PodPlan>,
    /// What the play does otherwise than a cluster would (more replicas
    /// asked than the one played), for the caller to warn about
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secrets: Vec<(&str, usize)> = self
            .secrets
            .iter()
            .map(|(name, data)| (name.as_str(), data.len()))
            .collect();
        f.debug_struct("Plan")
            .field("volumes", &self.volumes)
            .field("secrets", &secrets)
            .field("pods", &self.pods)
            .field("warnings", &self.warnings)
            .finish()
    }
}

/// Options of the play that change the requests.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// `network`: the networks of the pods
    pub networks: Vec<String>,
    /// `userns`: of the pods
    pub userns: Option<String>,
    /// `logDriver`
    pub log_driver: Option<String>,
    /// `annotations`: added to every container
    pub annotations: BTreeMap<String, String>,
    /// `logOptions`: of every container (with `logDriver`)
    pub log_options: BTreeMap<String, String>,
    /// `publishPorts`: `[[IP:]HOSTPORT:]CONTAINERPORT[/PROTO]`, which
    /// define or replace a published port of the pods
    pub publish: Vec<String>,
    /// `publishAllPorts`: a containerPort without hostPort is published on
    /// the same port of the host
    pub publish_all: bool,
    /// `noHosts`: the containers keep the /etc/hosts of their image
    pub no_hosts: bool,
    /// `noHostname`: the containers keep the /etc/hostname of their image
    pub no_hostname: bool,
    /// `noPodPrefix`: a container NAME of the pod POD is `NAME`, not
    /// `POD-NAME`
    pub no_pod_prefix: bool,
    /// The directory of the `Localhost` seccomp profiles (none:
    /// [`SECCOMP_PROFILE_ROOT`])
    pub seccomp_profile_root: Option<String>,
    /// The systemd unit that runs the play (`PODMAN_SYSTEMD_UNIT` of its
    /// environment): a label of every container, which `auto-update` restarts
    pub systemd_unit: Option<String>,
}

/// The labels of a container that `auto-update` reads, set by annotations
/// of the pod (`KEY`, or `KEY/CONTAINER` for one container).
const AUTO_UPDATE_LABELS: [&str; 2] = [
    "io.containers.autoupdate",
    "io.containers.autoupdate.authfile",
];

/// The label of the unit that runs the containers.
const SYSTEMD_UNIT_LABEL: &str = "PODMAN_SYSTEMD_UNIT";

/// Where the kubelet, and podman's play, look up a `Localhost` seccomp
/// profile.
pub const SECCOMP_PROFILE_ROOT: &str = "/var/lib/kubelet/seccomp";

/// A port of `--publish` (kube play's): the port mapping of a pod.
fn publish_mapping(spec: &str) -> Result<Value, String> {
    let bad = || format!("invalid --publish `{spec}`: [[IP:]HOSTPORT:]CONTAINERPORT[/PROTO]");
    let (ports, proto) = spec.rsplit_once('/').unwrap_or((spec, "tcp"));
    if !matches!(proto, "tcp" | "udp") {
        return Err(bad());
    }
    let parts: Vec<&str> = ports.rsplitn(3, ':').collect();
    let port = |p: &str| p.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(bad);
    let (cp, hp, ip) = match parts.as_slice() {
        [c] => (port(c)?, port(c)?, ""),
        [c, h] => (port(c)?, port(h)?, ""),
        [c, h, ip] => (
            port(c)?,
            port(h)?,
            ip.trim_matches(|c| c == '[' || c == ']'),
        ),
        _ => return Err(bad()),
    };
    Ok(json!({"container_port": cp, "host_port": hp, "host_ip": ip, "protocol": proto}))
}

/// The ports of a pod with those of `--publish` over them (by container
/// port and protocol).
fn apply_publish(ports: &mut Vec<Value>, publish: &[String]) -> Result<(), String> {
    for spec in publish {
        let m = publish_mapping(spec)?;
        ports.retain(|p| {
            !(p["container_port"] == m["container_port"] && p["protocol"] == m["protocol"])
        });
        ports.push(m);
    }
    Ok(())
}

/// Where the values of ConfigMaps and Secrets come from: those of the
/// YAML, else the engine's (secrets stored by an earlier play or made by
/// the user).
pub trait Sources {
    /// The data of the stored secret NAME, if any.
    fn secret(&self, name: &str) -> Option<Vec<u8>>;
}

struct Lookup<'a> {
    configmaps: HashMap<String, BTreeMap<String, Vec<u8>>>,
    secrets: HashMap<String, BTreeMap<String, Vec<u8>>>,
    store: &'a dyn Sources,
}

impl Lookup<'_> {
    fn configmap(&self, name: &str) -> Option<&BTreeMap<String, Vec<u8>>> {
        self.configmaps.get(name)
    }

    /// The keys of a secret: one of the YAML, or a stored one whose data
    /// is the JSON object a play stores (else its data is the value of
    /// every key).
    fn secret(&self, name: &str) -> Option<BTreeMap<String, Vec<u8>>> {
        if let Some(s) = self.secrets.get(name) {
            return Some(s.clone());
        }
        let data = self.store.secret(name)?;
        match serde_json::from_slice::<BTreeMap<String, String>>(&data) {
            Ok(m) => Some(m.into_iter().map(|(k, v)| (k, v.into_bytes())).collect()),
            Err(_) => Some(BTreeMap::from([(String::new(), data)])),
        }
    }

    fn secret_key(&self, name: &str, key: &str) -> Option<Vec<u8>> {
        let s = self.secret(name)?;
        s.get(key).or_else(|| s.get("")).cloned()
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(clean.as_bytes())
        .map_err(|_| "invalid base64 in the data of a Secret".to_string())
}

/// The name of the pod of a document, as podman names it.
fn pod_name(kind: &str, meta_name: &str) -> String {
    match kind {
        "Pod" => meta_name.to_string(),
        _ => format!("{meta_name}-pod"),
    }
}

/// The pods a YAML names (for `kube down`).
pub fn pod_names(docs: &[Value]) -> Vec<String> {
    docs.iter()
        .filter_map(|d| {
            let kind = text(d, "kind");
            let name = text(&d["metadata"], "name");
            matches!(
                kind,
                "Pod" | "Deployment" | "DaemonSet" | "ReplicaSet" | "Job"
            )
            .then(|| pod_name(kind, name))
            .filter(|n| !n.is_empty())
        })
        .collect()
}

/// The Secrets a YAML makes (for `kube down`).
pub fn secret_names(docs: &[Value]) -> Vec<String> {
    docs.iter()
        .filter(|d| text(d, "kind") == "Secret")
        .map(|d| text(&d["metadata"], "name").to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// The volume claims a YAML names (for `kube down --force`).
pub fn volume_names(docs: &[Value]) -> Vec<String> {
    docs.iter()
        .filter(|d| text(d, "kind") == "PersistentVolumeClaim")
        .map(|d| text(&d["metadata"], "name").to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// The ConfigMap and Secret volumes of the pods of a YAML (for `kube down
/// --force`).
pub fn file_volume_names(docs: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for d in docs {
        let kind = text(d, "kind");
        if !matches!(
            kind,
            "Pod" | "Deployment" | "DaemonSet" | "ReplicaSet" | "Job"
        ) {
            continue;
        }
        let pod = pod_name(kind, text(&d["metadata"], "name"));
        let spec = if kind == "Pod" {
            &d["spec"]
        } else {
            &d["spec"]["template"]["spec"]
        };
        for v in list(spec, "volumes") {
            if v.get("configMap").is_some() || v.get("secret").is_some() {
                out.push(format!("{pod}-{}", text(v, "name")));
            }
        }
    }
    out
}

/// A name of an object: DNS-1123 subdomain characters only.
fn check_name(what: &str, n: &str) -> Result<(), String> {
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid {what} name `{n}`"))
    }
}

/// A path inside a volume: relative, no `..`.
fn check_rel(p: &str) -> Result<(), String> {
    if p.is_empty() || p.starts_with('/') || p.contains('\0') || p.split('/').any(|c| c == "..") {
        return Err(format!("invalid path `{p}` in a volume"));
    }
    Ok(())
}

fn mode_of(v: &Value, k: &str, default: u32) -> Result<u32, String> {
    match text(v, k) {
        "" => Ok(default),
        m => {
            // YAML 1.2 decimal, or octal written 0o/0 as Kubernetes users do
            let parsed = if let Some(o) = m.strip_prefix("0o") {
                u32::from_str_radix(o, 8)
            } else if m.len() > 1 && m.starts_with('0') {
                u32::from_str_radix(&m[1..], 8)
            } else {
                m.parse()
            };
            parsed
                .ok()
                .filter(|m| *m <= 0o777)
                .ok_or_else(|| format!("invalid file mode `{m}`"))
        }
    }
}

/// The map of strings `value` is (none: an empty one).  A value that is a
/// sequence or a mapping is refused, as podman's decoding of the document
/// refuses it, not made an empty string; a scalar is the text podman makes
/// of it (the parser's), a null one the empty string.
fn strings_of(value: &Value, what: &str) -> Result<BTreeMap<String, String>, String> {
    match value {
        Value::Null => Ok(BTreeMap::new()),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| match v {
                Value::String(v) => Ok((k.clone(), v.clone())),
                Value::Null => Ok((k.clone(), String::new())),
                _ => Err(format!("{what}: the value of `{k}` is not a string")),
            })
            .collect(),
        _ => Err(format!("{what} is not a map of strings")),
    }
}

/// The files of a ConfigMap or Secret volume: every key, or the `items`.
fn volume_files(
    src: &Value,
    data: &BTreeMap<String, Vec<u8>>,
    default_mode: u32,
) -> Result<Vec<(String, Vec<u8>, u32)>, String> {
    let mode = mode_of(src, "defaultMode", default_mode)?;
    let items = list(src, "items");
    if items.is_empty() {
        return data
            .iter()
            .filter(|(k, _)| !k.is_empty())
            .map(|(k, v)| check_rel(k).map(|()| (k.clone(), v.clone(), mode)))
            .collect();
    }
    items
        .iter()
        .map(|it| {
            let key = text(it, "key");
            let path = match text(it, "path") {
                "" => key,
                p => p,
            };
            check_rel(path)?;
            let v = data
                .get(key)
                .ok_or_else(|| format!("no key `{key}` for the volume"))?;
            Ok((path.to_string(), v.clone(), mode_of(it, "mode", mode)?))
        })
        .collect()
}

/// The volumes of a pod spec: what a mount of each name becomes.
enum PodVolume {
    Claim(String),
    Host(HostPath),
    Tmpfs(Option<i64>),
    Anonymous,
    Files(String),
    Image(String),
}

fn pod_volumes(
    spec: &Value,
    pod: &str,
    look: &Lookup<'_>,
    plan: &mut Plan,
) -> Result<HashMap<String, PodVolume>, String> {
    let mut out = HashMap::new();
    for v in list(spec, "volumes") {
        let name = text(v, "name");
        check_name("volume", name)?;
        let vol = if let Some(c) = v.get("persistentVolumeClaim") {
            let claim = text(c, "claimName");
            check_name("volume claim", claim)?;
            PodVolume::Claim(claim.to_string())
        } else if let Some(h) = v.get("hostPath") {
            let path = text(h, "path");
            if !path.starts_with('/') || path.contains('\0') {
                return Err(format!("the hostPath of the volume {name} is not absolute"));
            }
            // (as the API server of Kubernetes: a path is made or checked
            // where it says, not above a component it climbs out of)
            if path.split('/').any(|c| c == "..") {
                return Err(format!(
                    "the hostPath of the volume {name} has a `..` component"
                ));
            }
            let kind = text(h, "type").to_string();
            if !matches!(
                kind.as_str(),
                "" | "Directory"
                    | "DirectoryOrCreate"
                    | "File"
                    | "FileOrCreate"
                    | "Socket"
                    | "CharDevice"
                    | "BlockDevice"
            ) {
                return Err(format!("invalid hostPath type `{kind}`"));
            }
            PodVolume::Host(HostPath {
                path: path.to_string(),
                kind,
            })
        } else if let Some(e) = v.get("emptyDir") {
            if text(e, "medium") == "Memory" {
                let size = match text(e, "sizeLimit") {
                    "" => None,
                    s => Some(memory_bytes(s)?),
                };
                PodVolume::Tmpfs(size)
            } else {
                PodVolume::Anonymous
            }
        } else if let Some(c) = v.get("configMap") {
            let cm = text(c, "name");
            match look.configmap(cm) {
                Some(data) => {
                    let files = volume_files(c, data, 0o644)?;
                    let vname = format!("{pod}-{name}");
                    plan.volumes.push(VolumePlan {
                        name: vname.clone(),
                        files: Some(files),
                        ..Default::default()
                    });
                    PodVolume::Files(vname)
                }
                None if flag(c, "optional") => PodVolume::Anonymous,
                None => return Err(format!("no ConfigMap `{cm}` for the volume {name}")),
            }
        } else if let Some(s) = v.get("secret") {
            let sn = text(s, "secretName");
            match look.secret(sn) {
                Some(data) => {
                    let files = volume_files(s, &data, 0o644)?;
                    let vname = format!("{pod}-{name}");
                    plan.volumes.push(VolumePlan {
                        name: vname.clone(),
                        files: Some(files),
                        ..Default::default()
                    });
                    PodVolume::Files(vname)
                }
                None if flag(s, "optional") => PodVolume::Anonymous,
                None => return Err(format!("no Secret `{sn}` for the volume {name}")),
            }
        } else if let Some(i) = v.get("image") {
            let r = text(i, "reference");
            if r.is_empty() {
                return Err(format!("the image volume {name} has no reference"));
            }
            PodVolume::Image(r.to_string())
        } else {
            return Err(format!(
                "the volume {name} has a source that is not supported"
            ));
        };
        out.insert(name.to_string(), vol);
    }
    Ok(out)
}

/// The variables of a container.
fn env_of(c: &Value, pod: &str, look: &Lookup<'_>) -> Result<Map<String, Value>, String> {
    let mut env = Map::new();
    let utf8 =
        |b: Vec<u8>, what: &str| String::from_utf8(b).map_err(|_| format!("{what} is not UTF-8"));
    for from in list(c, "envFrom") {
        let prefix = text(from, "prefix");
        let (data, optional) = if let Some(r) = from.get("configMapRef") {
            (
                look.configmap(text(r, "name")).cloned(),
                flag(r, "optional"),
            )
        } else if let Some(r) = from.get("secretRef") {
            (look.secret(text(r, "name")), flag(r, "optional"))
        } else {
            return Err("an envFrom that is neither a configMapRef nor a secretRef".into());
        };
        match data {
            Some(d) => {
                for (k, v) in d.into_iter().filter(|(k, _)| !k.is_empty()) {
                    env.insert(format!("{prefix}{k}"), json!(utf8(v, &k)?));
                }
            }
            None if optional => {}
            None => return Err("an envFrom of a ConfigMap or Secret that does not exist".into()),
        }
    }
    for e in list(c, "env") {
        let name = text(e, "name");
        if name.is_empty() || name.contains('=') {
            return Err(format!("invalid variable name `{name}`"));
        }
        let value = match e.get("valueFrom") {
            None => Some(text(e, "value").to_string()),
            Some(from) => {
                if let Some(r) = from.get("configMapKeyRef") {
                    let found = look
                        .configmap(text(r, "name"))
                        .and_then(|m| m.get(text(r, "key")).cloned());
                    match found {
                        Some(v) => Some(utf8(v, name)?),
                        None if flag(r, "optional") => None,
                        None => return Err(format!("no ConfigMap key for the variable {name}")),
                    }
                } else if let Some(r) = from.get("secretKeyRef") {
                    match look.secret_key(text(r, "name"), text(r, "key")) {
                        Some(v) => Some(utf8(v, name)?),
                        None if flag(r, "optional") => None,
                        None => return Err(format!("no Secret key for the variable {name}")),
                    }
                } else if let Some(f) = from.get("fieldRef") {
                    match text(f, "fieldPath") {
                        "metadata.name" => Some(pod.to_string()),
                        "metadata.namespace" => Some("default".to_string()),
                        p => return Err(format!("the fieldRef `{p}` is not supported")),
                    }
                } else {
                    return Err(format!(
                        "the valueFrom of the variable {name} is not supported"
                    ));
                }
            }
        };
        if let Some(v) = value {
            env.insert(name.to_string(), json!(v));
        }
    }
    Ok(env)
}

/// The pull policy Kubernetes gives an image without one.
/// A field with a meaning on a cluster that play cannot give: given with a
/// value other than the one Kubernetes defaults to, it is refused, not
/// ignored.  (What only steers a scheduler, a rollout or the API machinery
/// of a cluster, with nothing to steer on one host, is left out of the
/// tables on purpose.)
type Refused = &'static [(&'static str, &'static [&'static str])];

const POD_SPEC_REFUSED: Refused = &[
    ("ephemeralContainers", &[]),
    ("activeDeadlineSeconds", &[]),
    ("dnsPolicy", &["ClusterFirst", "ClusterFirstWithHostNet"]),
    ("setHostnameAsFQDN", &["false"]),
    ("runtimeClassName", &[]),
    ("readinessGates", &[]),
    ("resourceClaims", &[]),
    ("schedulingGates", &[]),
    ("resources", &[]),
];

const POD_SC_REFUSED: Refused = &[
    ("windowsOptions", &[]),
    ("supplementalGroupsPolicy", &["Merge"]),
    ("fsGroup", &[]),
    ("fsGroupChangePolicy", &[]),
    ("seLinuxChangePolicy", &[]),
];

const CONTAINER_REFUSED: Refused = &[
    ("volumeDevices", &[]),
    ("stdinOnce", &["false"]),
    ("terminationMessagePath", &["/dev/termination-log"]),
    ("terminationMessagePolicy", &["File"]),
];

const CONTAINER_SC_REFUSED: Refused = &[("windowsOptions", &[])];

const RESOURCES_REFUSED: Refused = &[("claims", &[])];
const PROBE_REFUSED: Refused = &[("terminationGracePeriodSeconds", &[])];
/// A liveness probe succeeds once (Kubernetes refuses another value).
const LIVENESS_REFUSED: Refused = &[("successThreshold", &["1"])];
const LIFECYCLE_REFUSED: Refused = &[("postStart", &[]), ("preStop", &[])];
const JOB_REFUSED: Refused = &[
    ("activeDeadlineSeconds", &[]),
    ("ttlSecondsAfterFinished", &[]),
    ("suspend", &["false"]),
    ("completionMode", &["NonIndexed"]),
    ("podFailurePolicy", &[]),
    ("successPolicy", &[]),
    ("backoffLimitPerIndex", &[]),
    ("maxFailedIndexes", &[]),
    ("manualSelector", &["false"]),
    ("podReplacementPolicy", &[]),
    ("managedBy", &[]),
];
const PVC_REFUSED: Refused = &[
    ("selector", &[]),
    ("volumeName", &[]),
    ("volumeMode", &["Filesystem"]),
    ("dataSource", &[]),
    ("dataSourceRef", &[]),
    ("volumeAttributesClassName", &[]),
];

/// An error for each field of `v` that `table` refuses.
fn refuse(v: &Value, what: &str, table: Refused) -> Result<(), String> {
    for (key, default) in table {
        let Some(given) = v.get(*key) else { continue };
        let set = match given {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            _ => true,
        };
        if set && !given.as_str().is_some_and(|s| default.contains(&s)) {
            return Err(format!("{key} of {what} is not supported"));
        }
    }
    Ok(())
}

fn default_pull_policy(image: &str) -> &'static str {
    let last = image.rsplit('/').next().unwrap_or(image);
    if image.contains('@') {
        "IfNotPresent"
    } else {
        match last.rsplit_once(':') {
            Some((_, "latest")) | None => "Always",
            Some(_) => "IfNotPresent",
        }
    }
}

fn caps(sc: &Value, k: &str) -> Vec<Value> {
    strings(&sc["capabilities"], k)
        .into_iter()
        .map(|c| {
            let c = c.to_ascii_uppercase();
            json!(if c.starts_with("CAP_") || c == "ALL" {
                c
            } else {
                format!("CAP_{c}")
            })
        })
        .collect()
}

/// Kubernetes' seccomp annotations of before `seccompProfile`: of the pod,
/// and (followed by its name) of a container.
const SECCOMP_POD_ANNOTATION: &str = "seccomp.security.alpha.kubernetes.io/pod";
const SECCOMP_CONTAINER_ANNOTATION: &str = "container.seccomp.security.alpha.kubernetes.io/";

/// The profile of a `Localhost` seccomp profile: a file below `root`.
fn localhost_profile(root: &str, profile: &str, cname: &str) -> Result<String, String> {
    let rel = std::path::Path::new(profile);
    if profile.is_empty()
        || profile.contains('\0')
        || !rel
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "invalid localhost seccomp profile `{profile}` of {cname}: a path below {root}"
        ));
    }
    Ok(format!("{}/{profile}", root.trim_end_matches('/')))
}

/// The seccomp profile of an annotation (Kubernetes' or podman's):
/// `unconfined`, the default (none) or `localhost/FILE` below `root`.
fn seccomp_path(v: &str, root: &str, cname: &str) -> Result<Option<String>, String> {
    match v {
        "unconfined" => Ok(Some("unconfined".into())),
        "" | "runtime/default" | "docker/default" => Ok(None),
        v => match v.strip_prefix("localhost/") {
            Some(p) => localhost_profile(root, p, cname).map(Some),
            None => Err(format!(
                "invalid seccomp profile `{v}` of {cname}: unconfined, runtime/default or localhost/FILE"
            )),
        },
    }
}

/// A whole number of a probe (`periodSeconds`...), `default` when not set.
fn probe_number(p: &Value, k: &str, default: i64) -> Result<i64, String> {
    match text(p, k) {
        "" => Ok(default),
        v => v
            .parse::<i64>()
            .ok()
            .filter(|n| *n >= 0)
            .ok_or_else(|| format!("invalid {k} `{v}`")),
    }
}

/// A word quoted for the shell.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The health check of a probe, as podman makes it: an `exec` probe runs
/// its command, an `httpGet` one `curl` and a `tcpSocket` one `nc` in the
/// container (the image must have them); a gRPC probe is refused.
fn health_config(p: &Value, what: &str, cname: &str, ports: &[Value]) -> Result<Value, String> {
    refuse(p, &format!("the {what} of {cname}"), PROBE_REFUSED)?;
    let port = |h: &Value| -> Result<u16, String> {
        let v = text(h, "port");
        if let Ok(n) = v.parse::<u16>() {
            return Ok(n);
        }
        ports
            .iter()
            .find(|cp| !v.is_empty() && text(cp, "name") == v)
            .and_then(|cp| text(cp, "containerPort").parse().ok())
            .ok_or_else(|| format!("unknown port `{v}` of the {what} of {cname}"))
    };
    let host = |h: &Value| match text(h, "host") {
        "" => "localhost".to_string(),
        h => h.to_string(),
    };
    let test = if let Some(exec) = p.get("exec").filter(|e| e.is_object()) {
        let command = strings(exec, "command");
        if command.is_empty() {
            return Err(format!("the exec {what} of {cname} has no command"));
        }
        let mut t = vec![json!("CMD")];
        t.extend(command.into_iter().map(Value::from));
        t
    } else if let Some(h) = p.get("httpGet").filter(|h| h.is_object()) {
        let scheme = text(h, "scheme").to_ascii_lowercase();
        let scheme = match scheme.as_str() {
            "" | "http" => "http",
            "https" => "https",
            s => return Err(format!("invalid scheme `{s}` of the {what} of {cname}")),
        };
        let path = match text(h, "path") {
            "" => "/",
            p => p,
        };
        let mut cmd = String::from("curl -f");
        // the kubelet does not verify the certificate of an HTTPS probe
        if scheme == "https" {
            cmd.push_str(" -k");
        }
        for hd in list(h, "httpHeaders") {
            cmd.push_str(&format!(
                " -H {}",
                shell_quote(&format!("{}: {}", text(hd, "name"), text(hd, "value")))
            ));
        }
        let url = format!("{scheme}://{}:{}{path}", host(h), port(h)?);
        cmd.push_str(&format!(" {} || exit 1", shell_quote(&url)));
        vec![json!("CMD-SHELL"), json!(cmd)]
    } else if let Some(t) = p.get("tcpSocket").filter(|t| t.is_object()) {
        let cmd = format!("nc -z -v {} {} || exit 1", shell_quote(&host(t)), port(t)?);
        vec![json!("CMD-SHELL"), json!(cmd)]
    } else if p.get("grpc").is_some() {
        return Err(format!(
            "the gRPC {what} of {cname} is not supported (exec, httpGet or tcpSocket)"
        ));
    } else {
        return Err(format!("the {what} of {cname} has no handler"));
    };
    // Kubernetes' defaults, also for a value below its least (podman's
    // makeHealthCheck: a periodSeconds of 0 is 10, a failureThreshold of
    // 0 is 3)
    let number = |k: &str, default: i64, least: i64| -> Result<i64, String> {
        let n = probe_number(p, k, default)?;
        Ok(if n < least { default } else { n })
    };
    // in nanoseconds (a number of seconds that does not fit is refused)
    let ns = |k: &str, default: i64, least: i64| -> Result<i64, String> {
        number(k, default, least)?
            .checked_mul(1_000_000_000)
            .ok_or_else(|| format!("invalid {k} `{}` of the {what} of {cname}", text(p, k)))
    };
    Ok(json!({
        "Test": test,
        "Interval": ns("periodSeconds", 10, 1)?,
        "Timeout": ns("timeoutSeconds", 1, 1)?,
        "StartPeriod": ns("initialDelaySeconds", 0, 0)?,
        "Retries": number("failureThreshold", 3, 1)?,
    }))
}

#[derive(Clone, Copy)]
struct PodContext<'a> {
    pod: &'a str,
    /// The labels of the pod: its containers have them too
    labels: &'a BTreeMap<String, String>,
    /// The annotations of the pod (podman's io.podman.annotations.*)
    annotations: &'a BTreeMap<String, String>,
    volumes: &'a HashMap<String, PodVolume>,
    pod_sc: &'a Value,
    restart: &'a str,
    /// A Job's `backoffLimit`: the containers are run again that many
    /// times when they fail
    retries: Option<u32>,
    opts: &'a Options,
    look: &'a Lookup<'a>,
}

/// podman's annotations of the pod and of its containers.
const PODMAN_ANNOTATIONS: &str = "io.podman.annotations.";

/// The annotations podman's play reads (`KEY` for the pod, `KEY/CONTAINER`
/// for a container); the others of podman are refused rather than ignored.
fn check_podman_annotations(ann: &BTreeMap<String, String>) -> Result<(), String> {
    const POD: [&str; 2] = ["userns", "infra.name"];
    const CONTAINER: [&str; 10] = [
        "init",
        "seccomp",
        "label",
        "apparmor",
        "autoremove",
        "privileged",
        "ulimit",
        "pids-limit",
        "cpuset",
        "init.container.type",
    ];
    for k in ann.keys() {
        let Some(rest) = k.strip_prefix(PODMAN_ANNOTATIONS) else {
            continue;
        };
        let ok = match rest.split_once('/') {
            Some((key, ctr)) => CONTAINER.contains(&key) && !ctr.is_empty(),
            None => POD.contains(&rest) || rest.starts_with("checkpoint."),
        };
        if !ok {
            return Err(format!(
                "the annotation {k} is not supported (pod: {}; per container: {})",
                POD.join(", "),
                CONTAINER.join(", ")
            ));
        }
    }
    Ok(())
}

/// The value of podman's annotation `key` of the container `ctr`.
fn container_annotation<'a>(
    ann: &'a BTreeMap<String, String>,
    key: &str,
    ctr: &str,
) -> Option<&'a str> {
    ann.get(&format!("{PODMAN_ANNOTATIONS}{key}/{ctr}"))
        .map(String::as_str)
}

/// podman's annotations of a container, applied to its SpecGenerator.
fn apply_container_annotations(
    s: &mut Map<String, Value>,
    cname: &str,
    ann: &BTreeMap<String, String>,
    seccomp_root: &str,
) -> Result<(), String> {
    let truthy = |v: &str| v.eq_ignore_ascii_case("true");
    if let Some(v) = container_annotation(ann, "init", cname) {
        s.insert("init".into(), json!(truthy(v)));
    }
    if let Some(v) = container_annotation(ann, "privileged", cname) {
        if truthy(v) {
            s.insert("privileged".into(), json!(true));
        }
    }
    if let Some(v) = container_annotation(ann, "autoremove", cname) {
        s.insert("remove".into(), json!(truthy(v)));
    }
    if let Some(v) = container_annotation(ann, "seccomp", cname) {
        if let Some(p) = seccomp_path(v, seccomp_root, cname)? {
            s.insert("seccomp_profile_path".into(), json!(p));
        }
    }
    if let Some(v) = container_annotation(ann, "apparmor", cname) {
        if v.contains(['\0', '\n']) {
            return Err(format!("invalid apparmor profile of {cname}"));
        }
        s.insert("apparmor_profile".into(), json!(v));
    }
    if let Some(v) = container_annotation(ann, "label", cname) {
        // podman writes the options of --security-opt label=..., comma
        // separated: type:spc_t,level:s0:c1.c2
        let opts: Vec<Value> = v
            .split(',')
            .filter(|o| !o.is_empty())
            .map(|o| json!(o))
            .collect();
        if opts
            .iter()
            .any(|o| o.as_str().is_some_and(|o| o.contains(['\0', '\n'])))
        {
            return Err(format!("invalid label of {cname}"));
        }
        s.insert("selinux_opts".into(), json!(opts));
    }
    if let Some(v) = container_annotation(ann, "ulimit", cname) {
        let mut limits = Vec::new();
        for u in v.split(',').filter(|u| !u.is_empty()) {
            let (name, values) = u
                .split_once('=')
                .ok_or_else(|| format!("invalid ulimit `{u}` of {cname}"))?;
            let (soft, hard) = values.split_once(':').unwrap_or((values, values));
            let num = |n: &str| -> Result<i64, String> {
                if n == "-1" || n == "unlimited" {
                    Ok(-1)
                } else {
                    n.parse()
                        .map_err(|_| format!("invalid ulimit `{u}` of {cname}"))
                }
            };
            limits.push(json!({"type": format!("RLIMIT_{}", name.to_ascii_uppercase()), "soft": num(soft)?, "hard": num(hard)?}));
        }
        s.insert("r_limits".into(), json!(limits));
    }
    if !s.get("resource_limits").is_some_and(Value::is_object) {
        s.insert("resource_limits".into(), json!({}));
    }
    if let Some(v) = container_annotation(ann, "pids-limit", cname) {
        let n: i64 = v
            .parse()
            .map_err(|_| format!("invalid pids-limit `{v}` of {cname}"))?;
        s["resource_limits"]["pids"] = json!({"limit": n});
    }
    if let Some(v) = container_annotation(ann, "cpuset", cname) {
        if !v
            .bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b',' | b'-'))
        {
            return Err(format!("invalid cpuset `{v}` of {cname}"));
        }
        if !s["resource_limits"]["cpu"].is_object() {
            s["resource_limits"]["cpu"] = json!({});
        }
        s["resource_limits"]["cpu"]["cpus"] = json!(v);
    }
    if s["resource_limits"].as_object().is_some_and(Map::is_empty) {
        s.remove("resource_limits");
    }
    Ok(())
}

/// The devices a container asks for as resources, as podman reads them:
/// a resource named as a CDI device (`nvidia.com/gpu=all: 1`) is that device,
/// `podman.io/device=/dev/fuse` the host device of that path; the others
/// (cpu, memory) are not devices.
fn resource_devices(res: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for kind in ["requests", "limits"] {
        let Some(keys) = res[kind].as_object() else {
            continue;
        };
        for key in keys.keys() {
            let Some((vendor, class, name)) = velarx_base::cdi::split_cdi_device(key) else {
                continue;
            };
            let path = match (vendor, class) {
                ("podman.io", "device") => name,
                _ => key.as_str(),
            };
            if !out.iter().any(|d| d["path"] == path) {
                out.push(json!({"path": path}));
            }
        }
    }
    out
}

fn container_plan(
    c: &Value,
    ctx: &PodContext<'_>,
    ports: &mut Vec<Value>,
) -> Result<ContainerPlan, String> {
    let cname = text(c, "name");
    check_name("container", cname)?;
    let image = text(c, "image");
    if image.is_empty() {
        return Err(format!("the container {cname} has no image"));
    }
    let pull = match text(c, "imagePullPolicy") {
        "" => default_pull_policy(image),
        p @ ("Always" | "IfNotPresent" | "Never") => p,
        p => return Err(format!("invalid imagePullPolicy `{p}`")),
    };
    let what = format!("the container {cname}");
    refuse(c, &what, CONTAINER_REFUSED)?;
    refuse(&c["securityContext"], &what, CONTAINER_SC_REFUSED)?;
    refuse(&c["resources"], &what, RESOURCES_REFUSED)?;
    let mut s = Map::new();
    let name = if ctx.opts.no_pod_prefix {
        cname.to_string()
    } else {
        format!("{}-{cname}", ctx.pod)
    };
    s.insert("name".into(), json!(name));
    s.insert("image".into(), json!(image));
    let command = strings(c, "command");
    let args = strings(c, "args");
    if !command.is_empty() {
        // as Kubernetes: the command replaces the entrypoint and the image's
        // arguments
        s.insert("entrypoint".into(), json!(command));
    }
    if !args.is_empty() {
        s.insert("command".into(), json!(args));
    }
    if let Some(w) = Some(text(c, "workingDir")).filter(|w| !w.is_empty()) {
        s.insert("work_dir".into(), json!(w));
    }
    let env = env_of(c, ctx.pod, ctx.look)?;
    if !env.is_empty() {
        s.insert("env".into(), Value::Object(env));
    }
    if flag(c, "tty") {
        s.insert("terminal".into(), json!(true));
    }
    if flag(c, "stdin") {
        s.insert("stdin".into(), json!(true));
    }
    if ctx.opts.no_hosts {
        s.insert("use_image_hosts".into(), json!(true));
    }
    if ctx.opts.no_hostname {
        s.insert("use_image_hostname".into(), json!(true));
    }
    for p in list(c, "ports") {
        let cp: u16 = text(p, "containerPort")
            .parse()
            .map_err(|_| format!("invalid containerPort of {cname}"))?;
        // as podman: only a port with a hostPort is published, or with
        // publishAllPorts every port, on the same port of the host
        let host_port = match text(p, "hostPort") {
            "" if ctx.opts.publish_all => Some(cp.to_string()),
            "" => None,
            h => Some(h.to_string()),
        };
        if let Some(hp) = host_port {
            let hp: u16 = hp
                .parse()
                .map_err(|_| format!("invalid hostPort of {cname}"))?;
            let proto = match text(p, "protocol") {
                "" | "TCP" => "tcp",
                "UDP" => "udp",
                pr => return Err(format!("the protocol {pr} is not supported")),
            };
            ports.push(json!({"container_port": cp, "host_port": hp, "host_ip": text(p, "hostIP"), "protocol": proto}));
        }
    }
    let res = &c["resources"];
    let mut limits = Map::new();
    let mut memory = Map::new();
    if let Some(m) = Some(text(&res["limits"], "memory")).filter(|m| !m.is_empty()) {
        memory.insert("limit".into(), json!(memory_bytes(m)?));
    }
    if let Some(m) = Some(text(&res["requests"], "memory")).filter(|m| !m.is_empty()) {
        memory.insert("reservation".into(), json!(memory_bytes(m)?));
    }
    if !memory.is_empty() {
        limits.insert("memory".into(), Value::Object(memory));
    }
    let mut cpu = Map::new();
    if let Some(q) = Some(text(&res["limits"], "cpu")).filter(|q| !q.is_empty()) {
        // a period of 100 ms, the quota its share
        cpu.insert("period".into(), json!(100_000));
        cpu.insert("quota".into(), json!((cpu_millis(q)? * 100).max(1000)));
    }
    if let Some(q) = Some(text(&res["requests"], "cpu")).filter(|q| !q.is_empty()) {
        // the shares Kubernetes gives a request
        cpu.insert(
            "shares".into(),
            json!((cpu_millis(q)? * 1024 / 1000).clamp(2, 262_144)),
        );
    }
    if !cpu.is_empty() {
        limits.insert("cpu".into(), Value::Object(cpu));
    }
    if !limits.is_empty() {
        s.insert("resource_limits".into(), Value::Object(limits));
    }
    let devices = resource_devices(res);
    if !devices.is_empty() {
        s.insert("devices".into(), json!(devices));
    }
    // security: the container's over the pod's
    let sc = &c["securityContext"];
    let pick = |k: &str| -> String {
        match text(sc, k) {
            "" => text(ctx.pod_sc, k).to_string(),
            v => v.to_string(),
        }
    };
    if flag(sc, "privileged") {
        s.insert("privileged".into(), json!(true));
    }
    let (add, drop) = (caps(sc, "add"), caps(sc, "drop"));
    if !add.is_empty() {
        s.insert("cap_add".into(), json!(add));
    }
    if !drop.is_empty() {
        s.insert("cap_drop".into(), json!(drop));
    }
    if flag(sc, "readOnlyRootFilesystem") {
        s.insert("read_only_filesystem".into(), json!(true));
    }
    if text(sc, "allowPrivilegeEscalation") == "false" {
        s.insert("no_new_privileges".into(), json!(true));
    }
    let (user, group) = (pick("runAsUser"), pick("runAsGroup"));
    for (what, v) in [("runAsUser", &user), ("runAsGroup", &group)] {
        if !v.is_empty() && v.parse::<u32>().is_err() {
            return Err(format!("invalid {what} `{v}`"));
        }
    }
    // as the kubelet: a user given as 0 is refused here, the image's user
    // once the image is there
    let run_as_non_root = match pick("runAsNonRoot").as_str() {
        "" | "false" => false,
        "true" => true,
        v => return Err(format!("invalid runAsNonRoot `{v}` of {cname}")),
    };
    if run_as_non_root && user == "0" {
        return Err(format!(
            "the container {cname} has runAsNonRoot and its runAsUser is 0"
        ));
    }
    match text(sc, "procMount") {
        "" | "Default" => {}
        // as podman: no path of /proc masked
        "Unmasked" => {
            s.insert("unmask".into(), json!(["ALL"]));
        }
        v => return Err(format!("invalid procMount `{v}` of {cname}")),
    }
    let apparmor = if sc.get("appArmorProfile").is_some() {
        &sc["appArmorProfile"]
    } else {
        &ctx.pod_sc["appArmorProfile"]
    };
    match text(apparmor, "type") {
        "" | "RuntimeDefault" => {}
        "Unconfined" => {
            s.insert("apparmor_profile".into(), json!("unconfined"));
        }
        "Localhost" => {
            let profile = text(apparmor, "localhostProfile");
            if profile.is_empty() || profile.contains(['\0', '\n']) {
                return Err(format!(
                    "invalid localhostProfile of the appArmorProfile of {cname}"
                ));
            }
            s.insert("apparmor_profile".into(), json!(profile));
        }
        t => return Err(format!("invalid appArmorProfile type `{t}` of {cname}")),
    }
    match (user.as_str(), group.as_str()) {
        ("", "") => {}
        ("", g) => {
            s.insert("user".into(), json!(format!("0:{g}")));
        }
        (u, "") => {
            s.insert("user".into(), json!(u));
        }
        (u, g) => {
            s.insert("user".into(), json!(format!("{u}:{g}")));
        }
    }
    let groups = strings(ctx.pod_sc, "supplementalGroups");
    if !groups.is_empty() {
        s.insert("groups".into(), json!(groups));
    }
    let se = if sc.get("seLinuxOptions").is_some() {
        &sc["seLinuxOptions"]
    } else {
        &ctx.pod_sc["seLinuxOptions"]
    };
    let mut selinux = Vec::new();
    for k in ["user", "role", "type", "level"] {
        let v = text(se, k);
        if !v.is_empty() {
            if v.contains(['\0', '\n']) {
                return Err(format!("invalid SELinux {k} `{v}`"));
            }
            selinux.push(json!(format!("{k}:{v}")));
        }
    }
    if !selinux.is_empty() {
        s.insert("selinux_opts".into(), json!(selinux));
    }
    let seccomp = if sc.get("seccompProfile").is_some() {
        &sc["seccompProfile"]
    } else {
        &ctx.pod_sc["seccompProfile"]
    };
    let root = ctx
        .opts
        .seccomp_profile_root
        .as_deref()
        .unwrap_or(SECCOMP_PROFILE_ROOT);
    let profile = match text(seccomp, "type") {
        // Kubernetes' annotations of before the field: the container's,
        // else the pod's
        "" => match ctx
            .annotations
            .get(&format!("{SECCOMP_CONTAINER_ANNOTATION}{cname}"))
            .or_else(|| ctx.annotations.get(SECCOMP_POD_ANNOTATION))
        {
            Some(v) => seccomp_path(v, root, cname)?,
            None => None,
        },
        "RuntimeDefault" => None,
        "Unconfined" => Some("unconfined".to_string()),
        "Localhost" => Some(localhost_profile(
            root,
            text(seccomp, "localhostProfile"),
            cname,
        )?),
        t => return Err(format!("the seccompProfile type {t} is not supported")),
    };
    if let Some(p) = profile {
        s.insert("seccomp_profile_path".into(), json!(p));
    }
    // the probes as health checks, as podman makes them
    let probe_ports = list(c, "ports");
    let liveness = match c.get("livenessProbe").filter(|p| p.is_object()) {
        Some(p) => {
            refuse(
                p,
                &format!("the livenessProbe of {cname}"),
                LIVENESS_REFUSED,
            )?;
            Some(health_config(p, "livenessProbe", cname, probe_ports)?)
        }
        None => None,
    };
    let startup = match c.get("startupProbe").filter(|p| p.is_object()) {
        Some(p) => {
            let mut hc = health_config(p, "startupProbe", cname, probe_ports)?;
            hc["Successes"] = json!(probe_number(p, "successThreshold", 1)?);
            Some(hc)
        }
        None => None,
    };
    // a readiness probe only takes a pod out of the endpoints of its
    // Services, which a play does not make: checked, with nothing to do
    if let Some(p) = c.get("readinessProbe").filter(|p| p.is_object()) {
        health_config(p, "readinessProbe", cname, probe_ports)?;
    }
    if let Some(hc) = match (&liveness, &startup) {
        (Some(hc), _) => Some(hc.clone()),
        // a startup check goes with a health check: one that passes, at
        // the pace of the startup check (as podman)
        (None, Some(st)) => {
            let mut hc = st.clone();
            hc["Test"] = json!(["CMD-SHELL", "exit 0"]);
            if let Some(o) = hc.as_object_mut() {
                o.remove("Successes");
            }
            Some(hc)
        }
        (None, None) => None,
    } {
        s.insert("healthconfig".into(), hc);
        if let Some(st) = startup {
            s.insert("startupHealthConfig".into(), st);
        }
        // as podman: under a restart policy a failed check restarts it
        if matches!(ctx.restart, "Always" | "OnFailure") {
            s.insert("health_check_on_failure_action".into(), json!(3));
        }
    }
    if let Some(l) = c.get("lifecycle").filter(|l| l.is_object()) {
        refuse(l, &format!("the lifecycle of {cname}"), LIFECYCLE_REFUSED)?;
        match text(l, "stopSignal") {
            "" => {}
            sig if sig.len() > 3
                && sig.starts_with("SIG")
                && sig[3..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-') =>
            {
                s.insert("stop_signal".into(), json!(sig));
            }
            sig => return Err(format!("invalid stopSignal `{sig}` of {cname}")),
        }
    }
    // restarts, the log driver, the annotations
    s.insert(
        "restart_policy".into(),
        json!(match ctx.restart {
            "Never" => "no",
            "OnFailure" => "on-failure",
            _ => "always",
        }),
    );
    if let Some(n) = ctx.retries {
        s.insert("restart_policy".into(), json!("on-failure"));
        s.insert("restart_tries".into(), json!(n));
    }
    if ctx.opts.log_driver.is_some() || !ctx.opts.log_options.is_empty() {
        let mut lc = Map::new();
        if let Some(d) = &ctx.opts.log_driver {
            lc.insert("driver".into(), json!(d));
        }
        if !ctx.opts.log_options.is_empty() {
            lc.insert("options".into(), json!(ctx.opts.log_options));
        }
        s.insert("log_configuration".into(), Value::Object(lc));
    }
    if !ctx.opts.annotations.is_empty() {
        s.insert("annotations".into(), json!(ctx.opts.annotations));
    }
    let (mut mounts, mut volumes, mut images) = (Vec::new(), Vec::new(), Vec::new());
    for m in list(c, "volumeMounts") {
        let vname = text(m, "name");
        let dest = text(m, "mountPath");
        if !dest.starts_with('/') {
            return Err(format!("the mountPath of {vname} is not absolute"));
        }
        if m.get("subPathExpr").is_some() {
            return Err("subPathExpr is not supported".into());
        }
        let ro = flag(m, "readOnly");
        let sub = text(m, "subPath");
        if !sub.is_empty() {
            check_rel(sub)?;
        }
        // as podman: the propagation as a mount option
        let propagation = match text(m, "mountPropagation") {
            "" => None,
            "None" => Some("private"),
            "HostToContainer" => Some("rslave"),
            "Bidirectional" => Some("rshared"),
            p => return Err(format!("invalid mountPropagation `{p}` of {vname}")),
        };
        let rro = match text(m, "recursiveReadOnly") {
            "" | "Disabled" => false,
            "Enabled" | "IfPossible" if ro => true,
            "Enabled" | "IfPossible" => {
                return Err(format!(
                    "the recursiveReadOnly mount of {vname} must be readOnly"
                ))
            }
            r => return Err(format!("invalid recursiveReadOnly `{r}` of {vname}")),
        };
        let ro_opt = |o: &mut Vec<Value>| {
            if ro {
                o.push(json!("ro"));
            }
            if rro {
                o.push(json!("rro"));
            }
            if let Some(p) = propagation {
                o.push(json!(p));
            }
        };
        let plain = |what: &str| -> Result<(), String> {
            if propagation.is_some() || rro {
                return Err(format!(
                    "the mount of the {what} {vname} has no propagation or recursive read-only mode"
                ));
            }
            Ok(())
        };
        match ctx.volumes.get(vname) {
            None => return Err(format!("no volume {vname} for the mount at {dest}")),
            Some(PodVolume::Claim(claim)) | Some(PodVolume::Files(claim)) => {
                let mut o = Vec::new();
                if matches!(ctx.volumes.get(vname), Some(PodVolume::Files(_))) && !ro {
                    o.push(json!("ro"));
                }
                ro_opt(&mut o);
                let mut v = json!({"Name": claim, "Dest": dest, "Options": o});
                if !sub.is_empty() {
                    v["SubPath"] = json!(sub);
                }
                volumes.push(v);
            }
            Some(PodVolume::Anonymous) => {
                plain("emptyDir")?;
                volumes.push(json!({"Name": "", "Dest": dest, "IsAnonymous": true}));
            }
            Some(PodVolume::Host(h)) => {
                let source = if sub.is_empty() {
                    h.path.clone()
                } else {
                    format!("{}/{sub}", h.path.trim_end_matches('/'))
                };
                let mut o = vec![json!("rbind")];
                ro_opt(&mut o);
                mounts.push(
                    json!({"type": "bind", "source": source, "destination": dest, "options": o}),
                );
            }
            Some(PodVolume::Tmpfs(size)) => {
                if rro {
                    plain("emptyDir")?;
                }
                let mut o = vec![json!("rw")];
                if let Some(sz) = size {
                    o.push(json!(format!("size={sz}")));
                }
                ro_opt(&mut o);
                mounts.push(
                    json!({"type": "tmpfs", "source": "tmpfs", "destination": dest, "options": o}),
                );
            }
            Some(PodVolume::Image(r)) => {
                plain("image")?;
                let mut v = json!({"Source": r, "Destination": dest, "ReadWrite": false});
                if !sub.is_empty() {
                    v["SubPath"] = json!(sub);
                }
                images.push(v);
            }
        }
    }
    if !mounts.is_empty() {
        s.insert("mounts".into(), json!(mounts));
    }
    if !volumes.is_empty() {
        s.insert("volumes".into(), json!(volumes));
    }
    if !images.is_empty() {
        s.insert("image_volumes".into(), json!(images));
    }
    apply_container_annotations(&mut s, cname, ctx.annotations, root)?;
    let mut labels: Map<String, Value> = ctx
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    for label in AUTO_UPDATE_LABELS {
        let own = ctx.annotations.get(&format!("{label}/{cname}"));
        if let Some(v) = own
            .or_else(|| ctx.annotations.get(label))
            .filter(|v| !v.is_empty())
        {
            labels.insert(label.into(), json!(v));
        }
    }
    if let Some(unit) = ctx.opts.systemd_unit.as_ref().filter(|u| !u.is_empty()) {
        labels.insert(SYSTEMD_UNIT_LABEL.into(), json!(unit));
    }
    if !labels.is_empty() {
        s.insert("labels".into(), Value::Object(labels));
    }
    Ok(ContainerPlan {
        name,
        image: image.to_string(),
        pull_policy: pull.to_string(),
        spec: Value::Object(s),
        run_as_non_root,
    })
}

/// The kinds of the documents a play makes a pod of.
const POD_KINDS: &[&str] = &["Pod", "Deployment", "DaemonSet", "ReplicaSet", "Job"];

/// The metadata and the pod spec of a document of one of [`POD_KINDS`].
fn pod_template<'a>(kind: &str, doc: &'a Value) -> (&'a Value, &'a Value) {
    match kind {
        "Pod" => (&doc["metadata"], &doc["spec"]),
        _ => (
            &doc["spec"]["template"]["metadata"],
            &doc["spec"]["template"]["spec"],
        ),
    }
}

/// The images of the containers a play of the documents runs, each once,
/// the init containers of a pod first: those of the pods of
/// [`POD_KINDS`], as [`plan`] reads them (a comment, a block scalar, a
/// kind that is not played, an ephemeral container name none).
pub fn container_images(docs: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in docs {
        let kind = text(d, "kind");
        if !POD_KINDS.contains(&kind) {
            continue;
        }
        let (_, spec) = pod_template(kind, d);
        for c in list(spec, "initContainers")
            .iter()
            .chain(list(spec, "containers"))
        {
            let image = text(c, "image");
            if !image.is_empty() && !out.iter().any(|i| i == image) {
                out.push(image.to_string());
            }
        }
    }
    out
}

fn pod_plan(
    kind: &str,
    doc: &Value,
    look: &Lookup<'_>,
    opts: &Options,
    plan: &mut Plan,
) -> Result<PodPlan, String> {
    let meta_name = text(&doc["metadata"], "name");
    check_name("object", meta_name)?;
    let name = pod_name(kind, meta_name);
    let (meta, spec) = pod_template(kind, doc);
    if !spec.is_object() {
        return Err(format!("the {kind} {meta_name} has no pod spec"));
    }
    let what = format!("the {kind} {meta_name}");
    refuse(spec, &what, POD_SPEC_REFUSED)?;
    refuse(&spec["securityContext"], &what, POD_SC_REFUSED)?;
    // as podman: one replica (and one completion of a Job) is played,
    // with a warning
    let count = |k: &str| -> Result<u64, String> {
        match text(&doc["spec"], k) {
            "" => Ok(1),
            v => v
                .parse::<u64>()
                .map_err(|_| format!("invalid {k} `{v}` of {what}")),
        }
    };
    let mut retries = None;
    match kind {
        "Deployment" | "ReplicaSet" => {
            if count("replicas")? > 1 {
                plan.warnings.push(format!(
                    "{what}: limiting the replica count to 1, more than one replica is not supported"
                ));
            }
        }
        "Job" => {
            refuse(&doc["spec"], &what, JOB_REFUSED)?;
            for k in ["completions", "parallelism"] {
                if count(k)? > 1 {
                    plan.warnings
                        .push(format!("{what}: limiting {k} to 1, the Job runs one pod"));
                }
            }
            // the pod is not made again: its containers are run again
            retries = match text(&doc["spec"], "backoffLimit") {
                "" | "0" => None,
                v => Some(
                    v.parse::<u32>()
                        .map_err(|_| format!("invalid backoffLimit `{v}` of {what}"))?,
                ),
            };
        }
        _ => {}
    }
    if let Some(os) = spec.get("os").filter(|o| o.is_object()) {
        if !matches!(text(os, "name"), "" | "linux") {
            return Err(format!(
                "the os `{}` of {what} is not supported: linux only",
                text(os, "name")
            ));
        }
    }
    let stop_timeout = match text(spec, "terminationGracePeriodSeconds") {
        "" => None,
        v => Some(
            v.parse::<u32>()
                .map_err(|_| format!("invalid terminationGracePeriodSeconds `{v}` of {what}"))?,
        ),
    };
    // the annotations of the object and of its pod template
    let mut annotations = BTreeMap::new();
    for m in [&doc["metadata"], meta] {
        annotations.extend(strings_of(
            &m["annotations"],
            &format!("the annotations of {what}"),
        )?);
    }
    // `--annotation` is added to the pod's, over its own, as podman's play
    // does (so `io.containers.autoupdate` of a Quadlet `AutoUpdate=` labels
    // the containers)
    annotations.extend(opts.annotations.clone());
    check_podman_annotations(&annotations)?;
    let volumes = pod_volumes(spec, &name, look, plan)?;
    let host_paths = volumes
        .values()
        .filter_map(|v| match v {
            PodVolume::Host(h) => Some(h.clone()),
            _ => None,
        })
        .collect();
    let restart = match text(spec, "restartPolicy") {
        "" if kind == "Job" => "Never",
        "" => "Always",
        r @ ("Always" | "OnFailure" | "Never") => r,
        r => return Err(format!("invalid restartPolicy `{r}`")),
    };
    let pod_labels = strings_of(&meta["labels"], &format!("the labels of {what}"))?;
    let ctx = PodContext {
        pod: &name,
        labels: &pod_labels,
        annotations: &annotations,
        volumes: &volumes,
        pod_sc: &spec["securityContext"],
        restart,
        retries,
        opts,
        look,
    };
    let mut ports = Vec::new();
    let mut init_containers = Vec::new();
    let mut always_init = Vec::new();
    for c in list(spec, "initContainers") {
        let cname = text(c, "name");
        let kind = match container_annotation(&annotations, "init.container.type", cname)
            .unwrap_or("once")
        {
            k @ ("once" | "always") => k,
            t => return Err(format!("invalid init container type `{t}` of {cname}")),
        };
        let init_ctx = PodContext {
            restart: "Never",
            retries: None,
            ..ctx
        };
        let mut plan = container_plan(c, &init_ctx, &mut ports)?;
        // it runs to its end
        plan.spec["restart_policy"] = json!("no");
        if kind == "always" {
            // the pod runs it at each of its starts
            plan.spec["annotations"][velarx_proto::request::INIT_TYPE_ANNOTATION] = json!("always");
            always_init.push(plan);
        } else {
            init_containers.push(plan);
        }
    }
    let always_count = always_init.len();
    let mut containers = always_init;
    for c in list(spec, "containers") {
        containers.push(container_plan(c, &ctx, &mut ports)?);
    }
    if containers.len() == always_count {
        return Err(format!("the pod {name} has no containers"));
    }
    let mut seen = std::collections::HashSet::new();
    if let Some(dup) = init_containers
        .iter()
        .chain(&containers)
        .find(|c| !seen.insert(c.name.clone()))
    {
        return Err(format!("two containers named {}", dup.name));
    }
    let mut p = Map::new();
    p.insert("name".into(), json!(name));
    p.insert(
        "hostname".into(),
        json!(match text(spec, "hostname") {
            "" => name.clone(),
            h => h.to_string(),
        }),
    );
    p.insert("labels".into(), json!(pod_labels));
    apply_publish(&mut ports, &opts.publish)?;
    if !ports.is_empty() {
        p.insert("portmappings".into(), json!(ports));
    }
    if flag(spec, "hostNetwork") {
        p.insert("netns".into(), json!({"nsmode": "host"}));
    } else if !opts.networks.is_empty() {
        match opts.networks.as_slice() {
            [n] if matches!(n.as_str(), "host" | "none" | "slirp4netns" | "pasta") => {
                p.insert("netns".into(), json!({"nsmode": n}));
            }
            nets => {
                let m: Map<String, Value> = nets.iter().map(|n| (n.clone(), json!({}))).collect();
                p.insert("netns".into(), json!({"nsmode": "bridge"}));
                p.insert("Networks".into(), Value::Object(m));
            }
        }
    }
    let mut shared = vec!["ipc", "net", "uts"];
    if flag(spec, "shareProcessNamespace") {
        shared.push("pid");
    }
    p.insert("shared_namespaces".into(), json!(shared));
    let dns = &spec["dnsConfig"];
    let ns = strings(dns, "nameservers");
    if !ns.is_empty() {
        p.insert("dns_server".into(), json!(ns));
    }
    let searches = strings(dns, "searches");
    if !searches.is_empty() {
        p.insert("dns_search".into(), json!(searches));
    }
    let dns_opts: Vec<String> = list(dns, "options")
        .iter()
        .map(|o| match text(o, "value") {
            "" => text(o, "name").to_string(),
            v => format!("{}:{v}", text(o, "name")),
        })
        .collect();
    if !dns_opts.is_empty() {
        p.insert("dns_option".into(), json!(dns_opts));
    }
    let mut hosts = Vec::new();
    for a in list(spec, "hostAliases") {
        let ip = text(a, "ip");
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("invalid hostAliases address `{ip}`"));
        }
        for h in strings(a, "hostnames") {
            hosts.push(json!(format!("{h}:{ip}")));
        }
    }
    if !hosts.is_empty() {
        p.insert("hostadd".into(), json!(hosts));
    }
    if let Some(n) = annotations.get("io.podman.annotations.infra.name") {
        check_name("infra container", n)?;
        p.insert("infra_name".into(), json!(n));
    }
    // as podman: a pod that does not use the users of the host gets a user
    // namespace of its own
    let host_users = match text(spec, "hostUsers") {
        "" | "true" => true,
        "false" => false,
        v => return Err(format!("invalid hostUsers `{v}` of {what}")),
    };
    let userns = opts
        .userns
        .clone()
        .or_else(|| annotations.get("io.podman.annotations.userns").cloned())
        .or_else(|| (!host_users).then(|| "auto".to_string()));
    if let Some(u) = &userns {
        let (mode, value) = u.split_once(':').unwrap_or((u.as_str(), ""));
        p.insert("userns".into(), json!({"nsmode": mode, "value": value}));
    }
    let sysctls: Map<String, Value> = list(&spec["securityContext"], "sysctls")
        .iter()
        .map(|s| (text(s, "name").to_string(), json!(text(s, "value"))))
        .collect();
    if !sysctls.is_empty() {
        p.insert("sysctl".into(), Value::Object(sysctls));
    }
    // the members of a pod with the host's PID or IPC namespace
    for c in init_containers.iter_mut().chain(containers.iter_mut()) {
        if let Some(t) = stop_timeout {
            c.spec["stop_timeout"] = json!(t);
        }
        if flag(spec, "hostPID") {
            c.spec["pidns"] = json!({"nsmode": "host"});
        }
        if flag(spec, "hostIPC") {
            c.spec["ipcns"] = json!({"nsmode": "host"});
        }
    }
    Ok(PodPlan {
        name,
        spec: Value::Object(p),
        init_containers,
        containers,
        host_paths,
    })
}

/// The plan of the documents of a YAML.
pub fn plan(docs: &[Value], opts: &Options, store: &dyn Sources) -> Result<Plan, String> {
    let mut look = Lookup {
        configmaps: HashMap::new(),
        secrets: HashMap::new(),
        store,
    };
    let mut plan = Plan::default();
    // the sources first, wherever they are in the stream
    for d in docs {
        let name = text(&d["metadata"], "name");
        match text(d, "kind") {
            "ConfigMap" => {
                check_name("ConfigMap", name)?;
                let mut m = BTreeMap::new();
                let of = format!("the ConfigMap {name}");
                for (k, v) in strings_of(&d["data"], &format!("the data of {of}"))? {
                    m.insert(k, v.into_bytes());
                }
                for (k, v) in strings_of(&d["binaryData"], &format!("the binaryData of {of}"))? {
                    m.insert(k, base64_decode(&v)?);
                }
                look.configmaps.insert(name.to_string(), m);
            }
            "Secret" => {
                check_name("Secret", name)?;
                let mut m = BTreeMap::new();
                let of = format!("the Secret {name}");
                for (k, v) in strings_of(&d["data"], &format!("the data of {of}"))? {
                    m.insert(k, base64_decode(&v)?);
                }
                for (k, v) in strings_of(&d["stringData"], &format!("the stringData of {of}"))? {
                    m.insert(k, v.into_bytes());
                }
                // stored as a JSON object of the keys (text only)
                let text_map: BTreeMap<&String, String> = m
                    .iter()
                    .map(|(k, v)| String::from_utf8(v.clone()).map(|s| (k, s)))
                    .collect::<Result<_, _>>()
                    .map_err(|_| format!("the Secret {name} has data that is not UTF-8"))?;
                plan.secrets.push((
                    name.to_string(),
                    serde_json::to_vec(&text_map)
                        .map_err(|e| format!("the Secret {name} cannot be stored: {e}"))?,
                ));
                look.secrets.insert(name.to_string(), m);
            }
            _ => {}
        }
    }
    for d in docs {
        let kind = text(d, "kind");
        match kind {
            "ConfigMap" | "Secret" => {}
            "PersistentVolumeClaim" => {
                let name = text(&d["metadata"], "name");
                check_name("PersistentVolumeClaim", name)?;
                refuse(
                    &d["spec"],
                    &format!("the PersistentVolumeClaim {name}"),
                    PVC_REFUSED,
                )?;
                let labels = strings_of(
                    &d["metadata"]["labels"],
                    &format!("the labels of the PersistentVolumeClaim {name}"),
                )?;
                plan.volumes.push(VolumePlan {
                    name: name.to_string(),
                    labels,
                    files: None,
                });
            }
            k if POD_KINDS.contains(&k) => {
                let p = pod_plan(kind, d, &look, opts, &mut plan)?;
                if plan.pods.iter().any(|q| q.name == p.name) {
                    return Err(format!("two pods named {}", p.name));
                }
                plan.pods.push(p);
            }
            "" => return Err("a document without kind".into()),
            // (as podman's: a Service, StatefulSet, Ingress... is not played)
            _ => {}
        }
    }
    if plan.pods.is_empty() && plan.volumes.is_empty() && plan.secrets.is_empty() {
        return Err("the YAML has no pod, volume claim or secret".into());
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::parse_documents;

    #[test]
    fn the_images_of_the_containers_a_play_runs() {
        let docs = parse_documents(concat!(
            "kind: Pod\nspec:\n  initContainers:\n  - {name: i, image: init:1}\n",
            "  containers:\n  - name: a\n    image: localhost/web:1\n",
            "    imagePullPolicy: Never\n  - {name: b, image: \"quay.io/x/db@sha256:00\"}\n",
            "  - name: c\n    image: localhost/web:1\n    args: [\"image: arg\"]\n",
            "    note: |\n      image: in a block\n  - {name: e, image: \"\"}\n",
            "  ephemeralContainers:\n  - {name: x, image: ephemeral}\n",
            "  volumes:\n  - name: v\n    image: {reference: not-a-container}\n",
            "# image: commented\n",
            "---\nkind: Deployment\nspec:\n  template:\n    spec:\n",
            "      containers:\n      - {name: d, image: deep}\n",
            "---\nkind: StatefulSet\nspec:\n  template:\n    spec:\n",
            "      containers:\n      - {name: s, image: not-played}\n",
            "---\nkind: Deployment\nspec:\n  containers:\n  - {name: w, image: wrong-place}\n",
        ))
        .unwrap();
        assert_eq!(
            container_images(&docs),
            [
                "init:1",
                "localhost/web:1",
                "quay.io/x/db@sha256:00",
                "deep"
            ]
        );
        assert!(container_images(&[]).is_empty());
    }

    #[test]
    fn resources_named_as_devices_are_devices() {
        let docs = parse_documents(
            "limits: {cpu: 500m, nvidia.com/gpu=all: 1, podman.io/device=/dev/fuse: 1}\n\
             requests: {nvidia.com/gpu=all: 1, vendor.com/class=a:b: 1, memory: 32Mi}\n",
        )
        .unwrap();
        assert_eq!(
            resource_devices(&docs[0]),
            [
                json!({"path": "nvidia.com/gpu=all"}),
                json!({"path": "vendor.com/class=a:b"}),
                json!({"path": "/dev/fuse"}),
            ]
        );
        assert!(resource_devices(&json!({"limits": {"memory": "1"}})).is_empty());
    }

    struct NoStore;
    impl Sources for NoStore {
        fn secret(&self, name: &str) -> Option<Vec<u8>> {
            (name == "stored").then(|| br#"{"pw": "fromstore"}"#.to_vec())
        }
    }

    const WEB: &str = r#"
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: kubeplayvol
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  greeting: hello kube
  file.conf: "a=1"
---
apiVersion: v1
kind: Secret
metadata:
  name: sec
data:
  password: aHVudGVyMg==
stringData:
  user: admin
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kweb
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: web
    spec:
      hostname: webhost
      restartPolicy: OnFailure
      securityContext:
        runAsUser: 1000
        sysctls:
        - name: net.core.somaxconn
          value: "1024"
      hostAliases:
      - ip: 10.0.0.1
        hostnames: [db, cache]
      dnsConfig:
        nameservers: [1.1.1.1]
        options:
        - name: ndots
          value: "2"
      containers:
      - name: srv
        image: localhost:5000/alpine:chunked
        command: [sh, -c]
        args: ["sleep 1000"]
        workingDir: /data
        env:
        - name: MSG
          valueFrom:
            configMapKeyRef: {name: cfg, key: greeting}
        - name: PW
          valueFrom:
            secretKeyRef: {name: sec, key: password}
        - name: SPW
          valueFrom:
            secretKeyRef: {name: stored, key: pw}
        - name: POD
          valueFrom:
            fieldRef: {fieldPath: metadata.name}
        - name: PLAIN
          value: "1"
        envFrom:
        - configMapRef: {name: cfg}
          prefix: CM_
        ports:
        - containerPort: 80
          hostPort: 8080
        - containerPort: 9090
        resources:
          limits: {memory: 64Mi, cpu: 500m}
          requests: {memory: 32Mi, cpu: 250m}
        securityContext:
          capabilities:
            add: [NET_ADMIN]
            drop: [mknod]
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          seLinuxOptions: {level: "s0:c1,c2"}
        livenessProbe:
          exec:
            command: [cat, /tmp/ok]
          periodSeconds: 5
        volumeMounts:
        - {name: data, mountPath: /data}
        - {name: data, mountPath: /sub, subPath: a/b, readOnly: true}
        - {name: host, mountPath: /host}
        - {name: scratch, mountPath: /scratch}
        - {name: disk, mountPath: /disk}
        - {name: conf, mountPath: /etc/app}
        - {name: creds, mountPath: /creds}
      volumes:
      - name: data
        persistentVolumeClaim: {claimName: kubeplayvol}
      - name: host
        hostPath: {path: /srv/web, type: DirectoryOrCreate}
      - name: scratch
        emptyDir: {medium: Memory, sizeLimit: 16Mi}
      - name: disk
        emptyDir: {}
      - name: conf
        configMap:
          name: cfg
          items:
          - {key: file.conf, path: app.conf, mode: 0600}
      - name: creds
        secret: {secretName: sec}
"#;

    #[test]
    fn a_deployment_with_everything() {
        let docs = parse_documents(WEB).unwrap();
        let p = plan(&docs, &Options::default(), &NoStore).unwrap();
        assert_eq!(p.secrets.len(), 1);
        assert_eq!(p.secrets[0].0, "sec");
        let stored: BTreeMap<String, String> = serde_json::from_slice(&p.secrets[0].1).unwrap();
        assert_eq!(
            (stored["password"].as_str(), stored["user"].as_str()),
            ("hunter2", "admin")
        );
        let names: Vec<&str> = p.volumes.iter().map(|v| v.name.as_str()).collect();
        assert!(
            names.contains(&"kubeplayvol")
                && names.contains(&"kweb-pod-conf")
                && names.contains(&"kweb-pod-creds")
        );
        let conf = p
            .volumes
            .iter()
            .find(|v| v.name == "kweb-pod-conf")
            .unwrap();
        assert_eq!(
            conf.files,
            Some(vec![("app.conf".to_string(), b"a=1".to_vec(), 0o600)])
        );
        let creds = p
            .volumes
            .iter()
            .find(|v| v.name == "kweb-pod-creds")
            .unwrap();
        assert_eq!(creds.files.as_ref().unwrap().len(), 2);

        assert_eq!(p.pods.len(), 1);
        let pod = &p.pods[0];
        assert_eq!(pod.name, "kweb-pod");
        assert_eq!(pod.spec["hostname"], "webhost");
        assert_eq!(pod.spec["labels"], json!({"app": "web"}));
        assert_eq!(
            pod.spec["portmappings"],
            json!([{"container_port": 80, "host_port": 8080, "host_ip": "", "protocol": "tcp"}])
        );
        assert_eq!(
            pod.spec["hostadd"],
            json!(["db:10.0.0.1", "cache:10.0.0.1"])
        );
        assert_eq!(pod.spec["dns_server"], json!(["1.1.1.1"]));
        assert_eq!(pod.spec["dns_option"], json!(["ndots:2"]));
        assert_eq!(pod.spec["sysctl"], json!({"net.core.somaxconn": "1024"}));
        assert_eq!(
            pod.host_paths,
            vec![HostPath {
                path: "/srv/web".into(),
                kind: "DirectoryOrCreate".into()
            }]
        );

        let c = &pod.containers[0];
        assert_eq!(
            (c.name.as_str(), c.pull_policy.as_str()),
            ("kweb-pod-srv", "IfNotPresent")
        );
        let s = &c.spec;
        assert_eq!(s["entrypoint"], json!(["sh", "-c"]));
        assert_eq!(s["command"], json!(["sleep 1000"]));
        assert_eq!(s["work_dir"], "/data");
        assert_eq!(s["env"]["MSG"], "hello kube");
        assert_eq!(s["env"]["PW"], "hunter2");
        assert_eq!(s["env"]["SPW"], "fromstore");
        assert_eq!(s["env"]["POD"], "kweb-pod");
        assert_eq!(s["env"]["PLAIN"], "1");
        assert_eq!(s["env"]["CM_greeting"], "hello kube");
        assert_eq!(
            s["resource_limits"]["memory"],
            json!({"limit": 64 << 20, "reservation": 32 << 20})
        );
        assert_eq!(
            s["resource_limits"]["cpu"],
            json!({"period": 100000, "quota": 50000, "shares": 256})
        );
        assert_eq!(s["cap_add"], json!(["CAP_NET_ADMIN"]));
        assert_eq!(s["cap_drop"], json!(["CAP_MKNOD"]));
        assert_eq!(s["read_only_filesystem"], true);
        assert_eq!(s["no_new_privileges"], true);
        assert_eq!(s["user"], "1000");
        assert_eq!(s["selinux_opts"], json!(["level:s0:c1,c2"]));
        assert_eq!(s["restart_policy"], "on-failure");
        assert_eq!(s["healthconfig"]["Test"], json!(["CMD", "cat", "/tmp/ok"]));
        assert_eq!(s["healthconfig"]["Interval"], 5_000_000_000i64);
        let vols = s["volumes"].as_array().unwrap();
        assert_eq!(
            vols[0],
            json!({"Name": "kubeplayvol", "Dest": "/data", "Options": []})
        );
        assert_eq!(
            vols[1],
            json!({"Name": "kubeplayvol", "Dest": "/sub", "Options": ["ro"], "SubPath": "a/b"})
        );
        assert!(vols
            .iter()
            .any(|v| v["IsAnonymous"] == true && v["Dest"] == "/disk"));
        assert!(vols
            .iter()
            .any(|v| v["Name"] == "kweb-pod-conf" && v["Options"] == json!(["ro"])));
        let mounts = s["mounts"].as_array().unwrap();
        assert!(mounts.contains(&json!({"type": "bind", "source": "/srv/web", "destination": "/host", "options": ["rbind"]})));
        assert!(mounts.contains(&json!({"type": "tmpfs", "source": "tmpfs", "destination": "/scratch", "options": ["rw", "size=16777216"]})));
        assert_eq!(pod_names(&docs), ["kweb-pod"]);
        assert_eq!(volume_names(&docs), ["kubeplayvol"]);
        let docs = crate::yaml::parse_documents(
            "kind: Secret\nmetadata: {name: s1}\n---\nkind: ConfigMap\nmetadata: {name: c}\n",
        )
        .unwrap();
        assert_eq!(secret_names(&docs), ["s1"]);
    }

    #[test]
    fn refused() {
        let pod = |spec: &str| format!("kind: Pod\nmetadata:\n  name: p\nspec:\n{spec}");
        let bad = [
            "kind: CronJob\nmetadata:\n  name: x\n".to_string(),
            "metadata:\n  name: x\n".to_string(),
            pod("  containers: []\n"),
            pod("  containers:\n  - name: c\n"),
            pod("  containers:\n  - name: c\n    image: i\n  - name: c\n    image: i\n"),
            pod("  containers:\n  - name: c\n    image: i\n    volumeMounts:\n    - {name: nope, mountPath: /x}\n"),
            pod("  volumes:\n  - name: v\n    nfs: {server: s}\n  containers:\n  - name: c\n    image: i\n"),
            pod("  volumes:\n  - name: v\n    hostPath: {path: rel}\n  containers:\n  - name: c\n    image: i\n"),
            pod("  volumes:\n  - name: v\n    hostPath: {path: /tmp/x/../../etc/velarx, type: DirectoryOrCreate}\n  containers:\n  - name: c\n    image: i\n"),
            pod("  volumes:\n  - name: v\n    hostPath: {path: /srv/..}\n  containers:\n  - name: c\n    image: i\n"),
            pod("  containers:\n  - name: c\n    image: i\n    env:\n    - name: A\n      valueFrom:\n        configMapKeyRef: {name: none, key: k}\n"),
            pod("  containers:\n  - name: c\n    image: i\n    resources:\n      limits: {memory: lots}\n"),
            pod("  initContainers:\n  - name: c\n    image: i\n  containers:\n  - name: c\n    image: i\n"),
            "kind: Pod\nmetadata:\n  name: p\n  annotations:\n    io.podman.annotations.volumes-from/c: x\nspec:\n  containers:\n  - name: c\n    image: i\n".to_string(),
            "kind: Pod\nmetadata:\n  name: p\n  annotations:\n    io.podman.annotations.seccomp/c: localhost/../x.json\nspec:\n  containers:\n  - name: c\n    image: i\n".to_string(),
            pod("  volumes:\n  - name: v\n    persistentVolumeClaim: {claimName: c}\n  containers:\n  - name: c\n    image: i\n    volumeMounts:\n    - {name: v, mountPath: /x, subPath: ../up}\n"),
            "kind: Pod\nmetadata:\n  name: ../x\nspec:\n  containers:\n  - name: c\n    image: i\n".to_string(),
        ];
        for b in bad {
            let docs = parse_documents(&b).unwrap();
            assert!(plan(&docs, &Options::default(), &NoStore).is_err(), "{b}");
        }
        // an optional source that is missing is no error
        let ok = pod("  containers:\n  - name: c\n    image: i\n    env:\n    - name: A\n      valueFrom:\n        configMapKeyRef: {name: none, key: k, optional: true}\n");
        let p = plan(
            &parse_documents(&ok).unwrap(),
            &Options::default(),
            &NoStore,
        )
        .unwrap();
        assert!(p.pods[0].containers[0].spec.get("env").is_none());
        assert_eq!(p.pods[0].containers[0].pull_policy, "Always");
    }

    /// A label, an annotation or a ConfigMap value that is not a string is
    /// refused (podman's decoding of the document does), not made empty.
    #[test]
    fn values_that_are_not_strings_are_refused() {
        let bad = [
            ("kind: Pod\nmetadata:\n  name: p\n  labels: {app: [web]}\nspec:\n  containers:\n  - name: c\n    image: i\n", "labels of the Pod p"),
            ("kind: Pod\nmetadata:\n  name: p\n  annotations: {a: {b: c}}\nspec:\n  containers:\n  - name: c\n    image: i\n", "annotations of the Pod p"),
            ("kind: ConfigMap\nmetadata: {name: c}\ndata: {k: [5]}\n", "data of the ConfigMap c"),
            ("kind: Secret\nmetadata: {name: s}\nstringData: {k: [1]}\n", "stringData of the Secret s"),
            ("kind: PersistentVolumeClaim\nmetadata: {name: v, labels: {a: [2]}}\n", "labels of the PersistentVolumeClaim v"),
        ];
        for (yaml, what) in bad {
            let docs = parse_documents(yaml).unwrap();
            let e = plan(&docs, &Options::default(), &NoStore).unwrap_err();
            assert!(
                e.contains(what) && e.contains("not a string"),
                "{yaml}: {e}"
            );
        }
    }

    #[test]
    fn fields_without_an_effect_are_refused_by_name() {
        let pod = |extra: &str, cextra: &str| {
            format!("kind: Pod\nmetadata:\n  name: p\nspec:\n{extra}  containers:\n  - name: c\n    image: i\n{cextra}")
        };
        let doc = |kind: &str, spec: &str| {
            format!("kind: {kind}\nmetadata:\n  name: p\nspec:\n{spec}  template:\n    spec:\n      containers:\n      - name: c\n        image: i\n")
        };
        let cases = [
            (pod("", "    readinessProbe: {grpc: {port: 9}}\n"), "gRPC readinessProbe of c"),
            (pod("", "    startupProbe: {httpGet: {port: http}}\n"), "unknown port `http`"),
            (
                pod("", "    livenessProbe: {exec: {command: [x]}, periodSeconds: 9999999999999}\n"),
                "invalid periodSeconds",
            ),
            (pod("", "    livenessProbe: {grpc: {port: 9}}\n"), "gRPC livenessProbe"),
            (pod("", "    livenessProbe: {periodSeconds: 3}\n"), "has no handler"),
            (pod("", "    lifecycle: {preStop: {exec: {command: [x]}}}\n"), "preStop of the lifecycle of c"),
            (pod("", "    lifecycle: {postStart: {exec: {command: [x]}}}\n"), "postStart"),
            (pod("", "    lifecycle: {stopSignal: TERM}\n"), "stopSignal"),
            (pod("", "    volumeDevices: [{name: a, devicePath: /d}]\n"), "volumeDevices"),
            (pod("", "    terminationMessagePath: /x\n"), "terminationMessagePath"),
            (pod("", "    securityContext: {runAsNonRoot: true, runAsUser: 0}\n"), "runAsNonRoot"),
            (pod("", "    securityContext: {procMount: Hidden}\n"), "procMount"),
            (pod("", "    securityContext: {appArmorProfile: {type: Other}}\n"), "appArmorProfile"),
            (pod("", "    securityContext: {seccompProfile: {type: Localhost, localhostProfile: /etc/x.json}}\n"), "localhost seccomp profile"),
            (pod("", "    resources: {claims: [{name: g}]}\n"), "claims"),
            (pod("", "    livenessProbe: {exec: {command: [x]}, successThreshold: 2}\n"), "successThreshold"),
            (pod("", "    livenessProbe: {exec: {command: [x]}, terminationGracePeriodSeconds: 2}\n"), "terminationGracePeriodSeconds"),
            (pod("  volumes:\n  - {name: v, emptyDir: {}}\n", "    volumeMounts:\n    - {name: v, mountPath: /v, mountPropagation: Bidirectional}\n"), "propagation"),
            (pod("  volumes:\n  - {name: v, emptyDir: {}}\n", "    volumeMounts:\n    - {name: v, mountPath: /v, mountPropagation: Sideways}\n"), "mountPropagation"),
            (pod("  volumes:\n  - {name: v, hostPath: {path: /x}}\n", "    volumeMounts:\n    - {name: v, mountPath: /v, recursiveReadOnly: Enabled}\n"), "must be readOnly"),
            (pod("  securityContext: {fsGroup: 1000}\n", ""), "fsGroup"),
            (pod("  securityContext: {runAsNonRoot: true, runAsUser: 0}\n", ""), "runAsNonRoot"),
            (pod("  activeDeadlineSeconds: 5\n", ""), "activeDeadlineSeconds"),
            (pod("  dnsPolicy: None\n", ""), "dnsPolicy"),
            (pod("  hostUsers: maybe\n", ""), "hostUsers"),
            (pod("  setHostnameAsFQDN: true\n", ""), "setHostnameAsFQDN"),
            (pod("  runtimeClassName: gvisor\n", ""), "runtimeClassName"),
            (pod("  os: {name: windows}\n", ""), "os `windows`"),
            (pod("  terminationGracePeriodSeconds: soon\n", ""), "terminationGracePeriodSeconds"),
            (doc("Deployment", "  replicas: many\n"), "replicas"),
            (doc("Job", "  backoffLimit: -1\n"), "backoffLimit"),
            (doc("Job", "  ttlSecondsAfterFinished: 4\n"), "ttlSecondsAfterFinished"),
            ("kind: PersistentVolumeClaim\nmetadata:\n  name: p\nspec:\n  volumeMode: Block\n".to_string(), "volumeMode"),
            ("kind: PersistentVolumeClaim\nmetadata:\n  name: p\nspec:\n  dataSource: {kind: PersistentVolumeClaim, name: o}\n".to_string(), "dataSource"),
        ];
        for (yaml, field) in cases {
            let docs = parse_documents(&yaml).unwrap();
            let e = plan(&docs, &Options::default(), &NoStore).unwrap_err();
            assert!(e.contains(field), "{yaml}: {e}");
        }
        // the defaults Kubernetes fills in, and what only steers a cluster
        let ok = pod(
            "  dnsPolicy: ClusterFirst\n  nodeSelector: {a: b}\n  terminationGracePeriodSeconds: 7\n  os: {name: linux}\n  securityContext: {runAsNonRoot: false}\n",
            "    terminationMessagePath: /dev/termination-log\n    terminationMessagePolicy: File\n    stdinOnce: false\n    securityContext: {procMount: Default}\n    livenessProbe: {exec: {command: [x]}, successThreshold: 1}\n    readinessProbe:\n    lifecycle: {}\n",
        );
        let p = plan(
            &parse_documents(&ok).unwrap(),
            &Options::default(),
            &NoStore,
        )
        .unwrap();
        assert_eq!(p.pods[0].containers[0].spec["stop_timeout"], 7);
        let d = doc(
            "Deployment",
            "  replicas: 1\n  strategy: {type: Recreate}\n",
        );
        plan(&parse_documents(&d).unwrap(), &Options::default(), &NoStore).unwrap();
    }

    #[test]
    fn probes_lifecycle_and_security_as_podman_plays_them() {
        let y = r#"
kind: Pod
metadata:
  name: p
  annotations:
    container.seccomp.security.alpha.kubernetes.io/b: localhost/b.json
    seccomp.security.alpha.kubernetes.io/pod: unconfined
spec:
  hostUsers: false
  securityContext: {runAsNonRoot: true, appArmorProfile: {type: Unconfined}}
  volumes:
  - {name: h, hostPath: {path: /srv}}
  - {name: e, emptyDir: {medium: Memory}}
  containers:
  - name: a
    image: i
    ports:
    - {name: http, containerPort: 8080}
    livenessProbe:
      httpGet: {port: http, path: /healthz, httpHeaders: [{name: X-A, value: "it's"}]}
      periodSeconds: 5
    startupProbe:
      tcpSocket: {port: 8080}
      failureThreshold: 30
      successThreshold: 2
    readinessProbe: {exec: {command: [ready]}}
    lifecycle: {stopSignal: SIGUSR1}
    securityContext:
      procMount: Unmasked
      seccompProfile: {type: Localhost, localhostProfile: prof/a.json}
    volumeMounts:
    - {name: h, mountPath: /h, readOnly: true, recursiveReadOnly: Enabled, mountPropagation: HostToContainer}
    - {name: e, mountPath: /e, mountPropagation: Bidirectional}
  - name: b
    image: i
    securityContext: {runAsUser: 1000}
    startupProbe: {exec: {command: [started]}, periodSeconds: 2}
  - name: c
    image: i
"#;
        let opts = Options {
            seccomp_profile_root: Some("/etc/seccomp/".into()),
            ..Default::default()
        };
        let p = plan(&parse_documents(y).unwrap(), &opts, &NoStore).unwrap();
        let pod = &p.pods[0];
        assert_eq!(pod.spec["userns"], json!({"nsmode": "auto", "value": ""}));
        let [a, b, c] = &pod.containers[..] else {
            panic!("{:?}", pod.containers)
        };
        let ns = 1_000_000_000i64;
        assert_eq!(
            a.spec["healthconfig"],
            json!({"Test": ["CMD-SHELL", "curl -f -H 'X-A: it'\\''s' 'http://localhost:8080/healthz' || exit 1"],
                   "Interval": 5 * ns, "Timeout": ns, "StartPeriod": 0, "Retries": 3})
        );
        assert_eq!(
            a.spec["startupHealthConfig"],
            json!({"Test": ["CMD-SHELL", "nc -z -v 'localhost' 8080 || exit 1"],
                   "Interval": 10 * ns, "Timeout": ns, "StartPeriod": 0, "Retries": 30, "Successes": 2})
        );
        assert_eq!(a.spec["health_check_on_failure_action"], 3);
        assert_eq!(a.spec["stop_signal"], "SIGUSR1");
        assert_eq!(a.spec["unmask"], json!(["ALL"]));
        assert_eq!(a.spec["apparmor_profile"], "unconfined");
        assert_eq!(a.spec["seccomp_profile_path"], "/etc/seccomp/prof/a.json");
        assert!(a.run_as_non_root);
        assert_eq!(
            a.spec["mounts"],
            json!([
                {"type": "bind", "source": "/srv", "destination": "/h", "options": ["rbind", "ro", "rro", "rslave"]},
                {"type": "tmpfs", "source": "tmpfs", "destination": "/e", "options": ["rw", "rshared"]},
            ])
        );
        // a startup check alone: a health check that passes at its pace
        assert_eq!(
            b.spec["healthconfig"],
            json!({"Test": ["CMD-SHELL", "exit 0"], "Interval": 2 * ns, "Timeout": ns, "StartPeriod": 0, "Retries": 3})
        );
        assert_eq!(
            b.spec["startupHealthConfig"]["Test"],
            json!(["CMD", "started"])
        );
        assert_eq!(b.spec["seccomp_profile_path"], "/etc/seccomp/b.json");
        assert!(b.run_as_non_root);
        assert_eq!(c.spec["seccomp_profile_path"], "unconfined");
        assert!(c.spec.get("healthconfig").is_none());
        // a 0 below the least of Kubernetes is its default, as podman's
        let z = "kind: Pod\nmetadata:\n  name: z\nspec:\n  containers:\n  - name: z\n    image: i\n    livenessProbe: {exec: {command: [x]}, periodSeconds: 0, timeoutSeconds: 0, failureThreshold: 0}\n";
        let p = plan(&parse_documents(z).unwrap(), &opts, &NoStore).unwrap();
        assert_eq!(
            p.pods[0].containers[0].spec["healthconfig"],
            json!({"Test": ["CMD", "x"], "Interval": 10 * ns, "Timeout": ns, "StartPeriod": 0, "Retries": 3})
        );

        // replicas and completions: one played, with a warning; a Job's
        // backoffLimit runs its containers again
        let d = "kind: Deployment\nmetadata:\n  name: d\nspec:\n  replicas: 3\n  template:\n    spec:\n      containers:\n      - name: c\n        image: i\n---\nkind: Job\nmetadata:\n  name: j\nspec:\n  completions: 2\n  backoffLimit: 4\n  template:\n    spec:\n      restartPolicy: Never\n      containers:\n      - name: c\n        image: i\n";
        let p = plan(&parse_documents(d).unwrap(), &Options::default(), &NoStore).unwrap();
        assert_eq!(p.pods.len(), 2);
        assert_eq!(p.warnings.len(), 2, "{:?}", p.warnings);
        assert!(p.warnings[0].contains("replica") && p.warnings[1].contains("completions"));
        let job = &p.pods[1].containers[0].spec;
        assert_eq!(
            (&job["restart_policy"], &job["restart_tries"]),
            (&json!("on-failure"), &json!(4))
        );
        assert!(p.pods[0].containers[0].spec.get("restart_tries").is_none());
    }

    #[test]
    fn options_of_the_play() {
        let y = "kind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: i\n    ports:\n    - containerPort: 80\n    - {containerPort: 53, protocol: UDP}\n    - {containerPort: 443, hostPort: 8443}\n";
        let docs = parse_documents(y).unwrap();
        let p = plan(&docs, &Options::default(), &NoStore).unwrap();
        assert_eq!(p.pods[0].spec["portmappings"].as_array().unwrap().len(), 1);
        assert_eq!(p.pods[0].containers[0].name, "p-c");
        assert!(p.pods[0].containers[0]
            .spec
            .get("use_image_hosts")
            .is_none());
        let opts = Options {
            publish_all: true,
            no_hosts: true,
            no_hostname: true,
            no_pod_prefix: true,
            ..Default::default()
        };
        let p = plan(&docs, &opts, &NoStore).unwrap();
        assert_eq!(
            p.pods[0].spec["portmappings"],
            json!([
                {"container_port": 80, "host_port": 80, "host_ip": "", "protocol": "tcp"},
                {"container_port": 53, "host_port": 53, "host_ip": "", "protocol": "udp"},
                {"container_port": 443, "host_port": 8443, "host_ip": "", "protocol": "tcp"},
            ])
        );
        let c = &p.pods[0].containers[0];
        assert_eq!(c.name, "c");
        assert_eq!(
            (&c.spec["use_image_hosts"], &c.spec["use_image_hostname"]),
            (&json!(true), &json!(true))
        );
    }

    #[test]
    fn quantities_and_options() {
        assert_eq!(memory_bytes("64Mi"), Ok(64 << 20));
        assert_eq!(memory_bytes("1G"), Ok(1_000_000_000));
        assert_eq!(memory_bytes("1.5Gi"), Ok(3 << 29));
        assert_eq!(memory_bytes("129e6"), Ok(129_000_000));
        assert!(
            memory_bytes("-1").is_err()
                && memory_bytes("1Zi").is_err()
                && memory_bytes("1e400").is_err()
        );
        assert_eq!(cpu_millis("500m"), Ok(500));
        assert_eq!(cpu_millis("2"), Ok(2000));
        assert_eq!(cpu_millis("0.25"), Ok(250));
        assert!(cpu_millis("x").is_err());
        assert_eq!(default_pull_policy("alpine"), "Always");
        assert_eq!(default_pull_policy("localhost:5000/alpine"), "Always");
        assert_eq!(
            default_pull_policy("localhost:5000/alpine:3"),
            "IfNotPresent"
        );
        assert_eq!(default_pull_policy("a@sha256:00"), "IfNotPresent");
        let docs = parse_documents("kind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n  hostPID: true\n  containers:\n  - name: c\n    image: i:1\n").unwrap();
        let opts = Options {
            networks: vec!["n1".into()],
            userns: Some("auto".into()),
            log_driver: Some("k8s-file".into()),
            annotations: BTreeMap::from([("a".into(), "b".into())]),
            ..Default::default()
        };
        let p = plan(&docs, &opts, &NoStore).unwrap();
        assert_eq!(p.pods[0].spec["netns"], json!({"nsmode": "host"}));
        assert_eq!(
            p.pods[0].spec["userns"],
            json!({"nsmode": "auto", "value": ""})
        );
        let c = &p.pods[0].containers[0].spec;
        assert_eq!(c["pidns"], json!({"nsmode": "host"}));
        assert_eq!(c["log_configuration"], json!({"driver": "k8s-file"}));
        assert_eq!(c["annotations"], json!({"a": "b"}));
        assert_eq!(c["restart_policy"], "always");
        let docs = parse_documents(
            "kind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: i:1\n",
        )
        .unwrap();
        let p = plan(&docs, &opts, &NoStore).unwrap();
        assert_eq!(p.pods[0].spec["Networks"], json!({"n1": {}}));
    }

    #[test]
    fn kinds_that_are_not_played_are_skipped_and_the_auto_update_labels_are_set() {
        let y = "kind: Service\nmetadata:\n  name: s\nspec:\n  ports: [{port: 80}]\n---\nkind: StatefulSet\nmetadata:\n  name: x\n---\nkind: Pod\nmetadata:\n  name: p\n  labels: {app: web}\n  annotations:\n    io.containers.autoupdate: registry\n    io.containers.autoupdate/b: local\n    io.containers.autoupdate.authfile/b: /a.json\nspec:\n  containers:\n  - name: a\n    image: i:1\n  - name: b\n    image: i:1\n";
        let opts = Options {
            systemd_unit: Some("x.service".into()),
            ..Options::default()
        };
        let p = plan(&parse_documents(y).unwrap(), &opts, &NoStore).unwrap();
        assert_eq!(p.pods.len(), 1);
        assert_eq!(
            p.pods[0].containers[0].spec["labels"],
            json!({"app": "web", "io.containers.autoupdate": "registry", "PODMAN_SYSTEMD_UNIT": "x.service"})
        );
        assert_eq!(
            p.pods[0].containers[1].spec["labels"],
            json!({
                "app": "web",
                "io.containers.autoupdate": "local",
                "io.containers.autoupdate.authfile": "/a.json",
                "PODMAN_SYSTEMD_UNIT": "x.service"
            })
        );
        // a file of nothing that is played is still an error
        let e = plan(
            &parse_documents("kind: Service\nmetadata:\n  name: s\n").unwrap(),
            &Options::default(),
            &NoStore,
        )
        .unwrap_err();
        assert!(e.contains("no pod"), "{e}");
        let plain =
            "kind: Pod\nmetadata:\n  name: q\nspec:\n  containers:\n  - name: c\n    image: i:1\n";
        let p = plan(
            &parse_documents(plain).unwrap(),
            &Options::default(),
            &NoStore,
        )
        .unwrap();
        assert!(p.pods[0].containers[0].spec.get("labels").is_none());
    }

    #[test]
    fn an_always_init_container_is_made_with_the_others() {
        let y = "kind: Pod\nmetadata:\n  name: p\n  annotations:\n    io.podman.annotations.init.container.type/a: always\nspec:\n  initContainers:\n  - name: a\n    image: i:1\n  - name: o\n    image: i:1\n  containers:\n  - name: c\n    image: i:1\n";
        let p = plan(&parse_documents(y).unwrap(), &Options::default(), &NoStore).unwrap();
        let pod = &p.pods[0];
        assert_eq!(pod.init_containers.len(), 1);
        assert_eq!(pod.init_containers[0].name, "p-o");
        assert_eq!(pod.containers.len(), 2);
        assert_eq!(pod.containers[0].name, "p-a");
        assert_eq!(
            pod.containers[0].spec["annotations"]["io.podman.annotations.init.container.type"],
            "always"
        );
        assert!(pod.containers[1].spec.get("annotations").is_none());
    }

    #[test]
    fn the_annotation_option_labels_for_auto_update() {
        let y =
            "kind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: c\n    image: i:1\n";
        let opts = Options {
            annotations: BTreeMap::from([("io.containers.autoupdate".into(), "registry".into())]),
            ..Default::default()
        };
        let p = plan(&parse_documents(y).unwrap(), &opts, &NoStore).unwrap();
        assert_eq!(
            p.pods[0].containers[0].spec["labels"]["io.containers.autoupdate"],
            "registry"
        );
    }

    #[test]
    fn annotations_and_init_containers() {
        let y = "kind: Pod\nmetadata:\n  name: p\n  annotations:\n    io.podman.annotations.init/c: \"true\"\n    io.podman.annotations.autoremove/c: \"TRUE\"\n    io.podman.annotations.label/c: type:spc_t,level:s0\n    io.podman.annotations.seccomp/c: unconfined\n    io.podman.annotations.apparmor/c: unconfined\n    io.podman.annotations.ulimit/c: nofile=1024:2048,core=-1\n    io.podman.annotations.pids-limit/c: \"100\"\n    io.podman.annotations.cpuset/c: 0-1\n    io.podman.annotations.userns: auto\n    io.podman.annotations.infra.name: p-infra\n    other.annotation: ignored\nspec:\n  initContainers:\n  - name: setup\n    image: i:1\n    command: [touch, /v/ready]\n  containers:\n  - name: c\n    image: i:1\n";
        let p = plan(&parse_documents(y).unwrap(), &Options::default(), &NoStore).unwrap();
        let pod = &p.pods[0];
        assert_eq!(pod.spec["userns"], json!({"nsmode": "auto", "value": ""}));
        assert_eq!(pod.spec["infra_name"], "p-infra");
        assert_eq!(pod.init_containers.len(), 1);
        assert_eq!(pod.init_containers[0].name, "p-setup");
        assert_eq!(pod.init_containers[0].spec["restart_policy"], "no");
        let c = &pod.containers[0].spec;
        assert_eq!(
            (c["init"].as_bool(), c["remove"].as_bool()),
            (Some(true), Some(true))
        );
        assert_eq!(c["selinux_opts"], json!(["type:spc_t", "level:s0"]));
        assert_eq!(c["seccomp_profile_path"], "unconfined");
        assert_eq!(c["apparmor_profile"], "unconfined");
        assert_eq!(
            c["r_limits"],
            json!([{"type": "RLIMIT_NOFILE", "soft": 1024, "hard": 2048}, {"type": "RLIMIT_CORE", "soft": -1, "hard": -1}])
        );
        assert_eq!(
            c["resource_limits"],
            json!({"pids": {"limit": 100}, "cpu": {"cpus": "0-1"}})
        );
        // without annotations no empty limits are sent
        let plain =
            "kind: Pod\nmetadata:\n  name: q\nspec:\n  containers:\n  - name: c\n    image: i:1\n";
        let p = plan(
            &parse_documents(plain).unwrap(),
            &Options::default(),
            &NoStore,
        )
        .unwrap();
        assert!(p.pods[0].containers[0]
            .spec
            .get("resource_limits")
            .is_none());
    }

    #[test]
    fn publish_and_log_options() {
        assert_eq!(
            publish_mapping("8080:80").unwrap(),
            json!({"container_port": 80, "host_port": 8080, "host_ip": "", "protocol": "tcp"})
        );
        assert_eq!(
            publish_mapping("127.0.0.1:53:53/udp").unwrap()["host_ip"],
            "127.0.0.1"
        );
        assert_eq!(publish_mapping("9000").unwrap()["host_port"], 9000);
        assert!(publish_mapping("x:80").is_err());
        assert!(publish_mapping("80/sctp").is_err());
        let mut ports = vec![
            json!({"container_port": 80, "host_port": 8080, "host_ip": "", "protocol": "tcp"}),
        ];
        apply_publish(&mut ports, &["9090:80".into(), "5353:53/udp".into()]).unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["host_port"], 9090);
        let yaml = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers:\n  - {name: c, image: i}\n";
        let docs = crate::yaml::parse_documents(yaml).unwrap();
        let opts = Options {
            log_options: BTreeMap::from([("max-size".into(), "1m".into())]),
            publish: vec!["8081:81".into()],
            ..Default::default()
        };
        let p = plan(&docs, &opts, &NoStore).unwrap();
        let pod = &p.pods[0];
        assert_eq!(pod.spec["portmappings"][0]["host_port"], 8081);
        assert_eq!(
            pod.containers[0].spec["log_configuration"],
            json!({"options": {"max-size": "1m"}})
        );
    }
}
