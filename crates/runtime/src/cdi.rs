// SPDX-License-Identifier: Apache-2.0
//! Container Device Interface (CDI): devices described by spec files that a
//! vendor installs, named `vendor.com/class=name` on the command line, as
//! podman and the CDI library it uses read them
//! (<https://github.com/cncf-tags/container-device-interface>, SPEC.md).
//!
//! The spec directories (`/etc/cdi` and `/var/run/cdi`, or the
//! `[containers] cdi_spec_dirs` of the configuration) are scanned at each use, nothing is
//! cached.  A later directory wins over an earlier one for a device of the
//! same name; two files of one directory that define the same device make
//! it unusable.  [`resolve`] turns names into [`Edits`], the changes a
//! container needs (the spec-wide edits of each spec once, then the edits of
//! each device in the order asked), and [`apply`] writes them into an OCI
//! runtime spec, so a provider of devices other than spec files only has to
//! produce `Edits`.
//!
//! A spec file is refused unless it is owned by root or by the user of the
//! engine, neither it nor its directory is writable by the group or others,
//! and it is not larger than [`MAX_SPEC_SIZE`]: its hooks are programs the
//! runtime runs as the engine's user and its mounts and device nodes give
//! access to the host.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use velarx_wire::options::{self, HostDevice};

/// The default spec directories, the later one with priority.
pub const DEFAULT_SPEC_DIRS: [&str; 2] = ["/etc/cdi", "/var/run/cdi"];
/// The largest spec file read.
pub const MAX_SPEC_SIZE: u64 = 8 * 1024 * 1024;
/// The deepest nesting of a YAML spec.
const MAX_YAML_DEPTH: usize = 32;
/// The most the annotations of a spec or device may take (k8s's limit).
const MAX_ANNOTATIONS_SIZE: usize = 256 * 1024;

/// The released versions of the specification, oldest first.
const VERSIONS: [&str; 10] = [
    "0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.8.0", "1.0.0", "1.1.0",
];
/// The oldest version accepted.
const EARLIEST: &str = "0.3.0";
const HOOK_NAMES: [&str; 6] = [
    "prestart",
    "createRuntime",
    "createContainer",
    "startContainer",
    "poststart",
    "poststop",
];

/// The directories to scan: the configured ones, else the defaults.
pub fn spec_dirs(configured: &[String]) -> Vec<PathBuf> {
    let dirs: Vec<&str> = match configured {
        [] => DEFAULT_SPEC_DIRS.to_vec(),
        c => c.iter().map(String::as_str).collect(),
    };
    dirs.into_iter()
        .map(|d| PathBuf::from(d.trim_end_matches('/')))
        .collect()
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Spec {
    pub cdi_version: String,
    pub kind: String,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub container_edits: ContainerEdits,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Device {
    pub name: String,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    pub container_edits: ContainerEdits,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContainerEdits {
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub device_nodes: Vec<DeviceNode>,
    #[serde(default)]
    pub net_devices: Vec<NetDevice>,
    #[serde(default)]
    pub hooks: Vec<Hook>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub intel_rdt: Option<IntelRdt>,
    #[serde(default, deserialize_with = "lax_vec")]
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeviceNode {
    pub path: String,
    #[serde(default)]
    pub host_path: String,
    #[serde(default, rename = "type")]
    pub typ: String,
    #[serde(default, deserialize_with = "lax")]
    pub major: i64,
    #[serde(default, deserialize_with = "lax")]
    pub minor: i64,
    #[serde(default, deserialize_with = "lax_option")]
    pub file_mode: Option<u32>,
    #[serde(default)]
    pub permissions: String,
    #[serde(default, deserialize_with = "lax_option")]
    pub uid: Option<u32>,
    #[serde(default, deserialize_with = "lax_option")]
    pub gid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NetDevice {
    pub host_interface_name: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Hook {
    pub hook_name: String,
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default, deserialize_with = "lax_option")]
    pub timeout: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Mount {
    pub host_path: String,
    pub container_path: String,
    #[serde(default)]
    pub options: Vec<String>,
    #[serde(default, rename = "type")]
    pub typ: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IntelRdt {
    #[serde(default, rename = "closID")]
    pub clos_id: String,
    #[serde(default, rename = "l3CacheSchema")]
    pub l3_cache_schema: String,
    #[serde(default, rename = "memBwSchema")]
    pub mem_bw_schema: String,
    #[serde(default)]
    pub schemata: Option<Vec<String>>,
    #[serde(default, rename = "enableMonitoring", deserialize_with = "lax")]
    pub enable_monitoring: bool,
}

/// A number or a boolean written as a number or as text, which is what a
/// YAML spec gives (its scalars are all text, as in the CDI library, which
/// takes `args: [true]` for strings).
fn lax<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Lax<T> {
        Value(T),
        Text(String),
    }
    match Lax::<T>::deserialize(d)? {
        Lax::Value(v) => Ok(v),
        Lax::Text(s) => s.trim().parse().map_err(serde::de::Error::custom),
    }
}

struct Lax<T>(T);

impl<'de, T> Deserialize<'de> for Lax<T>
where
    T: Deserialize<'de> + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lax(d).map(Lax)
    }
}

fn lax_option<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    Ok(Option::<Lax<T>>::deserialize(d)?.map(|o| o.0))
}

fn lax_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + std::str::FromStr,
    T::Err: std::fmt::Display,
{
    Ok(Vec::<Lax<T>>::deserialize(d)?
        .into_iter()
        .map(|o| o.0)
        .collect())
}

/// A YAML tree as JSON, its scalars text; an alias is refused.
fn yaml_value(y: &yaml_rust2::Yaml, depth: usize) -> Result<Value, String> {
    use yaml_rust2::Yaml;
    if depth > MAX_YAML_DEPTH {
        return Err("nested too deeply".into());
    }
    Ok(match y {
        Yaml::Null => Value::Null,
        Yaml::Boolean(b) => json!(b.to_string()),
        Yaml::Integer(i) => json!(i.to_string()),
        Yaml::Real(r) => json!(r),
        Yaml::String(s) => json!(s),
        Yaml::Array(a) => Value::Array(
            a.iter()
                .map(|v| yaml_value(v, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        Yaml::Hash(h) => {
            let mut m = serde_json::Map::new();
            for (k, v) in h {
                let Yaml::String(k) = k else {
                    return Err("a key that is not a string".into());
                };
                m.insert(k.clone(), yaml_value(v, depth + 1)?);
            }
            Value::Object(m)
        }
        Yaml::Alias(_) => return Err("aliases are not supported".into()),
        Yaml::BadValue => return Err("invalid value".into()),
    })
}

/// An error if the YAML has an alias (the loader would expand them, and a
/// few lines of nested ones are gigabytes) or is nested deeper than
/// [`MAX_YAML_DEPTH`] (the tree the loader builds is dropped recursively).
fn check_yaml_shape(data: &str) -> Result<(), String> {
    use yaml_rust2::parser::{Event, Parser};
    let mut parser = Parser::new_from_str(data);
    let mut depth = 0usize;
    loop {
        match parser.next_token().map_err(|e| e.to_string())?.0 {
            Event::Alias(_) => return Err("aliases are not supported".into()),
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                depth += 1;
                if depth > MAX_YAML_DEPTH {
                    return Err("nested too deeply".into());
                }
            }
            Event::SequenceEnd | Event::MappingEnd => depth = depth.saturating_sub(1),
            Event::StreamEnd => return Ok(()),
            _ => {}
        }
    }
}

/// A spec from the text of a file: JSON or YAML, no field unknown to the
/// specification.
pub fn parse_spec(data: &str, yaml: bool) -> Result<Spec, String> {
    let value = if yaml {
        check_yaml_shape(data)?;
        let mut docs = yaml_rust2::YamlLoader::load_from_str(data).map_err(|e| e.to_string())?;
        if docs.len() != 1 {
            return Err(format!("{} YAML documents, one expected", docs.len()));
        }
        yaml_value(&docs.remove(0), 0)?
    } else {
        serde_json::from_str(data).map_err(|e| e.to_string())?
    };
    if value.is_null() {
        return Err("no Spec data".into());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}

fn version_index(v: &str) -> Option<usize> {
    VERSIONS
        .iter()
        .position(|k| *k == v.strip_prefix('v').unwrap_or(v))
}

fn all_edits(spec: &Spec) -> impl Iterator<Item = &ContainerEdits> {
    std::iter::once(&spec.container_edits).chain(spec.devices.iter().map(|d| &d.container_edits))
}

/// The oldest version of the specification a spec can be written for,
/// from the features it uses.
fn required_version(spec: &Spec) -> usize {
    let idx = |v: &str| version_index(v).unwrap_or(0);
    let rdt_v110 = |e: &ContainerEdits| {
        e.intel_rdt
            .as_ref()
            .is_some_and(|i| i.schemata.is_some() || i.enable_monitoring)
    };
    if all_edits(spec).any(|e| rdt_v110(e) || !e.net_devices.is_empty()) {
        return idx("1.1.0");
    }
    if all_edits(spec).any(|e| e.intel_rdt.is_some() || !e.additional_gids.is_empty()) {
        return idx("0.7.0");
    }
    let class_dots = spec
        .kind
        .split_once('/')
        .is_some_and(|(_, c)| c.contains('.'));
    if !spec.annotations.is_empty()
        || spec.devices.iter().any(|d| !d.annotations.is_empty())
        || class_dots
    {
        return idx("0.6.0");
    }
    if spec
        .devices
        .iter()
        .any(|d| d.name.starts_with(|c: char| c.is_ascii_digit()))
        || all_edits(spec).any(|e| e.device_nodes.iter().any(|n| !n.host_path.is_empty()))
    {
        return idx("0.5.0");
    }
    if all_edits(spec).any(|e| e.mounts.iter().any(|m| !m.typ.is_empty())) {
        return idx("0.4.0");
    }
    idx(EARLIEST)
}

fn alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// A vendor or a class: letters, digits, `_`, `-` and `.`, starting with a
/// letter and ending with a letter or a digit.
fn valid_vendor_or_class(what: &str, s: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("invalid {what}. {why}"));
    let (Some(first), Some(last)) = (s.chars().next(), s.chars().last()) else {
        return bad("empty name");
    };
    if !first.is_ascii_alphabetic() {
        return bad(&format!("{s:?}, should start with letter"));
    }
    if let Some(c) = s.chars().find(|c| !(alnum(*c) || "_-.".contains(*c))) {
        return bad(&format!("invalid character '{c}' in name {s:?}"));
    }
    if !alnum(last) {
        return bad(&format!("{s:?}, should end with a letter or digit"));
    }
    Ok(())
}

/// A device name: as a class, and `:` too, starting with a digit allowed.
fn valid_device_name(s: &str) -> Result<(), String> {
    let (Some(first), Some(last)) = (s.chars().next(), s.chars().last()) else {
        return Err("invalid (empty) device name".into());
    };
    if !alnum(first) {
        return Err(format!(
            "invalid class {s:?}, should start with a letter or digit"
        ));
    }
    if let Some(c) = s.chars().find(|c| !(alnum(*c) || "_-.:".contains(*c))) {
        return Err(format!("invalid character '{c}' in device name {s:?}"));
    }
    if !alnum(last) {
        return Err(format!(
            "invalid name {s:?}, should end with a letter or digit"
        ));
    }
    Ok(())
}

/// The vendor, class and name of a device asked for, validated.
pub fn parse_qualified(device: &str) -> Result<(&str, &str, &str), String> {
    let Some((vendor, class, name)) = options::split_cdi_device(device) else {
        return Err(format!(
            "unqualified device {device:?}: a CDI device is vendor.com/class=name"
        ));
    };
    let invalid = |e: String| format!("invalid device {device:?}: {e}");
    valid_vendor_or_class("vendor", vendor).map_err(invalid)?;
    valid_vendor_or_class("class", class).map_err(invalid)?;
    valid_device_name(name).map_err(invalid)?;
    Ok((vendor, class, name))
}

/// An annotation key is a Kubernetes qualified name: an optional DNS
/// subdomain and `/`, then a name of at most 63 characters.
fn valid_annotation_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    let (prefix, name) = match key.split_once('/') {
        Some((p, n)) => (Some(p), n),
        None => (None, key.as_str()),
    };
    let name_ok = !name.is_empty()
        && name.len() <= 63
        && name.starts_with(alnum)
        && name.ends_with(alnum)
        && name.chars().all(|c| alnum(c) || "-_.".contains(c));
    let prefix_ok = prefix.is_none_or(|p| {
        !p.is_empty()
            && p.len() <= 253
            && p.split('.').all(|l| {
                !l.is_empty()
                    && l.starts_with(alnum)
                    && l.ends_with(alnum)
                    && l.chars().all(|c| alnum(c) || c == '-')
            })
    });
    name_ok && prefix_ok
}

fn validate_annotations(what: &str, a: &BTreeMap<String, String>) -> Result<(), String> {
    if let Some(k) = a.keys().find(|k| !valid_annotation_key(k)) {
        return Err(format!("{what}.annotations.{k} is invalid"));
    }
    if a.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > MAX_ANNOTATIONS_SIZE {
        return Err(format!(
            "{what}.annotations are larger than {MAX_ANNOTATIONS_SIZE} bytes"
        ));
    }
    Ok(())
}

fn valid_env(env: &[String]) -> Result<(), String> {
    match env.iter().find(|e| e.find('=').is_none_or(|i| i == 0)) {
        Some(e) => Err(format!("invalid environment variable {e:?}")),
        None => Ok(()),
    }
}

fn valid_path(what: &str, p: &str) -> Result<(), String> {
    if !p.starts_with('/') || p.contains('\0') {
        return Err(format!(
            "invalid {what} {p:?}: an absolute path is required"
        ));
    }
    Ok(())
}

impl ContainerEdits {
    fn is_empty(&self) -> bool {
        self.env.is_empty()
            && self.device_nodes.is_empty()
            && self.net_devices.is_empty()
            && self.hooks.is_empty()
            && self.mounts.is_empty()
            && self.intel_rdt.is_none()
            && self.additional_gids.is_empty()
    }

    fn validate(&self) -> Result<(), String> {
        valid_env(&self.env).map_err(|e| format!("invalid container edits: {e}"))?;
        for n in &self.device_nodes {
            if n.path.is_empty() {
                return Err("invalid (empty) device path".into());
            }
            valid_path("device path", &n.path)?;
            if !n.host_path.is_empty() {
                valid_path("device host path", &n.host_path)?;
            }
            if !["", "b", "c", "u", "p"].contains(&n.typ.as_str()) {
                return Err(format!("device {:?}: invalid type {:?}", n.path, n.typ));
            }
            if n.major < 0 || n.minor < 0 {
                return Err(format!("device {:?}: negative device number", n.path));
            }
            if !matches!(n.permissions.as_str(), "" | "none")
                && !n.permissions.trim_matches(['r', 'w', 'm']).is_empty()
            {
                return Err(format!(
                    "device {:?}: invalid permissions {:?}",
                    n.path, n.permissions
                ));
            }
        }
        let mut hosts = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for d in &self.net_devices {
            if d.host_interface_name.is_empty() {
                return Err("invalid linux net device, empty HostInterfaceName".into());
            }
            if d.name.is_empty() {
                return Err("invalid linux net device, empty Name".into());
            }
            if !hosts.insert(&d.host_interface_name) {
                return Err(format!(
                    "invalid linux net device, duplicate HostInterfaceName {:?}",
                    d.host_interface_name
                ));
            }
            if !names.insert(&d.name) {
                return Err(format!(
                    "invalid linux net device, duplicate Name {:?}",
                    d.name
                ));
            }
        }
        for h in &self.hooks {
            if !HOOK_NAMES.contains(&h.hook_name.as_str()) {
                return Err(format!("invalid hook name {:?}", h.hook_name));
            }
            if h.path.is_empty() {
                return Err(format!("invalid hook {:?} with empty path", h.hook_name));
            }
            valid_path("hook path", &h.path)?;
            valid_env(&h.env).map_err(|e| format!("invalid hook {:?}: {e}", h.hook_name))?;
            if h.timeout.is_some_and(|t| t <= 0) {
                return Err(format!(
                    "invalid hook {:?}: the timeout must be positive",
                    h.hook_name
                ));
            }
        }
        for m in &self.mounts {
            if m.host_path.is_empty() {
                return Err("invalid mount, empty host path".into());
            }
            if m.container_path.is_empty() {
                return Err("invalid mount, empty container path".into());
            }
            valid_path("mount host path", &m.host_path)?;
            valid_path("mount container path", &m.container_path)?;
        }
        if let Some(i) = &self.intel_rdt {
            let c = i.clos_id.as_str();
            if c != "/" && (c.len() >= 4096 || c == "." || c == ".." || c.contains(['/', '\n'])) {
                return Err("invalid ClosID".into());
            }
        }
        Ok(())
    }
}

impl Spec {
    /// The checks of the library: version and the features it needs, kind,
    /// annotations, edits, device names (no duplicate) and at least one
    /// device.
    pub fn validate(&self) -> Result<(), String> {
        let want = version_index(&self.cdi_version)
            .ok_or_else(|| format!("invalid version {:?}", self.cdi_version))?;
        let need = required_version(self);
        if need > want {
            return Err(format!(
                "the spec version must be at least v{}",
                VERSIONS[need]
            ));
        }
        let Some((vendor, class)) = self
            .kind
            .split_once('/')
            .filter(|(v, c)| !v.is_empty() && !c.is_empty())
        else {
            return Err(format!(
                "invalid vendor. {:?}: the kind is vendor.com/class",
                self.kind
            ));
        };
        valid_vendor_or_class("vendor", vendor)?;
        valid_vendor_or_class("class", class)?;
        validate_annotations(&self.kind, &self.annotations)?;
        self.container_edits.validate()?;
        let mut seen = std::collections::HashSet::new();
        for d in &self.devices {
            let bad = |e: String| format!("failed add device {:?}: {e}", d.name);
            valid_device_name(&d.name).map_err(bad)?;
            validate_annotations(&format!("{}={}", self.kind, d.name), &d.annotations)
                .map_err(bad)?;
            if d.container_edits.is_empty() {
                return Err(bad("invalid device, empty device edits".into()));
            }
            d.container_edits
                .validate()
                .map_err(|e| bad(format!("invalid device {:?}: {e}", d.name)))?;
            if !seen.insert(d.name.as_str()) {
                return Err(format!("invalid spec, multiple device {:?}", d.name));
            }
        }
        if self.devices.is_empty() {
            return Err("invalid spec, no devices".into());
        }
        Ok(())
    }
}

/// Whether the owner and the mode of a spec file or directory let it be
/// trusted.
fn check_trusted(path: &Path, md: &std::fs::Metadata) -> Result<(), String> {
    let uid = md.uid();
    let own = rustix::process::geteuid().as_raw();
    // a file of the real root or of another user is an unmapped id in a
    // user namespace: which of them cannot be told, the mode and the
    // directory decide
    let unmapped =
        uid == 65534 && velarx_base::ids::in_user_namespace().map_err(|e| e.to_string())?;
    if !(uid == 0 || uid == own || unmapped) {
        return Err(format!(
            "{} is owned by user {uid}: only root and the user of the engine are trusted",
            path.display()
        ));
    }
    if md.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by its group or others (mode {:o})",
            path.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

/// The spec files found, the devices they define and what was wrong.
#[derive(Debug, Default)]
pub struct Catalog {
    dirs: Vec<PathBuf>,
    specs: Vec<(PathBuf, Spec)>,
    devices: BTreeMap<String, (usize, usize)>,
    /// Per file or directory: what is wrong with it.
    pub errors: Vec<(PathBuf, String)>,
}

fn read_spec(path: &Path) -> Result<Spec, String> {
    // (not blocked by a FIFO, no terminal taken: anything but a regular
    // file is refused below)
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|e| format!("failed to read CDI Spec: {e}"))?;
    let md = file
        .metadata()
        .map_err(|e| format!("failed to read CDI Spec: {e}"))?;
    if !md.is_file() {
        return Err("not a regular file".into());
    }
    check_trusted(path, &md)?;
    let mut data = String::new();
    file.take(MAX_SPEC_SIZE + 1)
        .read_to_string(&mut data)
        .map_err(|e| format!("failed to read CDI Spec: {e}"))?;
    if data.len() as u64 > MAX_SPEC_SIZE {
        return Err(format!("larger than {MAX_SPEC_SIZE} bytes"));
    }
    let yaml = path.extension().is_some_and(|e| e == "yaml");
    let spec = parse_spec(&data, yaml).map_err(|e| format!("failed to parse CDI Spec: {e}"))?;
    spec.validate()
        .map_err(|e| format!("invalid CDI Spec: {e}"))?;
    Ok(spec)
}

/// The specs of `dirs` (a directory that is not there has none; the later
/// directories have priority).
pub fn scan(dirs: &[PathBuf]) -> Catalog {
    let mut cat = Catalog {
        dirs: dirs.to_vec(),
        ..Default::default()
    };
    // (priority, spec index) of each device, and the devices defined twice
    // at one priority
    let mut owner: HashMap<String, (usize, usize, usize)> = HashMap::new();
    let mut conflicts: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (priority, dir) in dirs.iter().enumerate() {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                cat.errors.push((
                    dir.clone(),
                    format!("cannot read the CDI spec directory: {e}"),
                ));
                continue;
            }
        };
        if let Err(e) = std::fs::metadata(dir)
            .map_err(|e| e.to_string())
            .and_then(|md| check_trusted(dir, &md))
        {
            cat.errors.push((dir.clone(), e));
            continue;
        }
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json" || e == "yaml") && !p.is_dir())
            .collect();
        files.sort();
        for path in files {
            let spec = match read_spec(&path) {
                Ok(s) => s,
                Err(e) => {
                    cat.errors.push((path, e));
                    continue;
                }
            };
            let index = cat.specs.len();
            for (di, d) in spec.devices.iter().enumerate() {
                let name = format!("{}={}", spec.kind, d.name);
                match owner.get(&name) {
                    Some((p, _, _)) if *p > priority => continue,
                    Some((p, other, _)) if *p == priority => {
                        cat.errors.push((
                            path.clone(),
                            format!(
                                "conflicting device {name:?} (specs {:?}, {:?})",
                                path, cat.specs[*other].0
                            ),
                        ));
                        conflicts.insert(name.clone());
                    }
                    Some(_) => {
                        conflicts.remove(&name);
                    }
                    None => {}
                }
                owner.insert(name, (priority, index, di));
            }
            cat.specs.push((path, spec));
        }
    }
    for (name, (_, si, di)) in owner {
        if !conflicts.contains(&name) {
            cat.devices.insert(name, (si, di));
        }
    }
    cat
}

impl Catalog {
    /// The qualified names of the devices, sorted.
    pub fn device_names(&self) -> Vec<String> {
        self.devices.keys().cloned().collect()
    }

    /// The directories scanned.
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// The errors, one line each.
    pub fn error_lines(&self) -> Vec<String> {
        self.errors
            .iter()
            .map(|(p, e)| format!("{}: {e}", p.display()))
            .collect()
    }
}

/// What the devices ask of the container, in the order to apply it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Edits {
    pub env: Vec<String>,
    pub devices: Vec<HostDevice>,
    pub net_devices: Vec<NetDevice>,
    pub hooks: Vec<Hook>,
    pub mounts: Vec<Mount>,
    pub intel_rdt: Option<IntelRdt>,
    pub additional_gids: Vec<u32>,
}

impl Edits {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn append(&mut self, e: &ContainerEdits) -> Result<(), String> {
        self.env.extend(e.env.iter().cloned());
        for n in &e.device_nodes {
            self.devices.push(host_device(n)?);
        }
        self.net_devices.extend(e.net_devices.iter().cloned());
        self.hooks.extend(e.hooks.iter().cloned());
        self.mounts.extend(e.mounts.iter().cloned());
        if e.intel_rdt.is_some() {
            self.intel_rdt = e.intel_rdt.clone();
        }
        self.additional_gids.extend(&e.additional_gids);
        Ok(())
    }
}

/// A device node as the container gets it; what the spec leaves out (type,
/// numbers, mode) comes from the device on the host (`hostPath`, else
/// `path`), which a node that names type and numbers does not need to have.
fn host_device(n: &DeviceNode) -> Result<HostDevice, String> {
    let host = if n.host_path.is_empty() {
        &n.path
    } else {
        &n.host_path
    };
    let minimal = !n.typ.is_empty() && (n.major != 0 || n.typ == "p");
    let (mut typ, mut major, mut minor, mut mode) = (n.typ.clone(), n.major, n.minor, n.file_mode);
    match std::fs::symlink_metadata(host) {
        Err(e) if !minimal => {
            return Err(format!("failed to stat CDI host device {host:?}: {e}"));
        }
        Err(_) => {}
        Ok(md) => {
            let ft = md.file_type();
            let found = if ft.is_block_device() {
                "b"
            } else if ft.is_char_device() {
                "c"
            } else if ft.is_fifo() {
                "p"
            } else if minimal {
                ""
            } else {
                return Err(format!(
                    "failed to stat CDI host device {host:?}: not a device node"
                ));
            };
            mode = mode.or(Some(md.mode() & 0o7777));
            if !minimal {
                if typ.is_empty() {
                    typ = found.into();
                }
                let norm = |t: &str| {
                    if t == "u" {
                        "c".to_string()
                    } else {
                        t.to_string()
                    }
                };
                if norm(&typ) != found {
                    return Err(format!(
                        "CDI device ({:?}, {host:?}), host type mismatch ({typ}, {found})",
                        n.path
                    ));
                }
                if typ != "p" && major == 0 {
                    major = i64::from(rustix::fs::major(md.rdev()));
                    minor = i64::from(rustix::fs::minor(md.rdev()));
                }
            }
        }
    }
    let access = match n.permissions.as_str() {
        "" => "rwm",
        "none" => "",
        p => p,
    };
    Ok(HostDevice {
        host: host.clone(),
        path: n.path.clone(),
        typ: if typ == "u" { "c".into() } else { typ },
        major: major as u64,
        minor: minor as u64,
        mode: mode.unwrap_or(0o666),
        access: Some(access.to_string()),
        uid: n.uid,
        gid: n.gid,
    })
}

/// The edits for `devices` (`vendor.com/class=name`), from the specs of
/// `dirs`: the edits of the spec of each device once, before those of its
/// first device, then the edits of each device.  A name that no spec
/// defines is an error that lists them, and what was wrong with the spec
/// files, which may be why.
pub fn resolve(devices: &[String], dirs: &[PathBuf]) -> Result<Edits, String> {
    for d in devices {
        parse_qualified(d)?;
    }
    let cat = scan(dirs);
    let mut edits = Edits::default();
    let mut seen_specs = std::collections::HashSet::new();
    let mut unresolved = Vec::new();
    let mut found = Vec::new();
    for d in devices {
        match cat.devices.get(d) {
            Some(&(si, di)) => found.push((si, di)),
            None => unresolved.push(d.as_str()),
        }
    }
    if !unresolved.is_empty() {
        let mut msg = format!(
            "setting up CDI devices: unresolvable CDI devices {} (spec directories: {})",
            unresolved.join(", "),
            cat.dirs
                .iter()
                .map(|d| d.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !cat.errors.is_empty() {
            msg.push_str(&format!(
                "; errors in the specs: {}",
                cat.error_lines().join("; ")
            ));
        }
        return Err(msg);
    }
    for (si, di) in found {
        let spec = &cat.specs[si].1;
        let wrap = |e: String| format!("failed to inject devices: {e}");
        if seen_specs.insert(si) {
            edits.append(&spec.container_edits).map_err(wrap)?;
        }
        edits
            .append(&spec.devices[di].container_edits)
            .map_err(wrap)?;
    }
    Ok(edits)
}

/// A variable set in the environment of the process: in its place when it
/// is there, else at the end.
fn set_env(env: &mut Vec<Value>, kv: &str) {
    let key = kv.split('=').next().unwrap_or(kv);
    match env
        .iter_mut()
        .find(|e| e.as_str().is_some_and(|e| e.split('=').next() == Some(key)))
    {
        Some(e) => *e = json!(kv),
        None => env.push(json!(kv)),
    }
}

fn ensure_array<'a>(v: &'a mut Value, key: &str) -> &'a mut Vec<Value> {
    if !v[key].is_array() {
        v[key] = json!([]);
    }
    v[key].as_array_mut().expect("just made an array")
}

/// Write the edits into the OCI runtime spec (its JSON): the environment,
/// the device nodes (bind mounted with `bind_devices`, when a user
/// namespace cannot make them) with their cgroup rules, the mounts (one at
/// the destination of an earlier one replaces it; all sorted by depth),
/// the hooks, the net devices, the Intel RDT class and the additional
/// groups of the process (never group 0).
pub fn apply(spec: &mut Value, e: &Edits, bind_devices: bool) {
    if !e.env.is_empty() {
        let env = ensure_array(&mut spec["process"], "env");
        for kv in &e.env {
            set_env(env, kv);
        }
    }
    if !e.devices.is_empty() {
        let user = spec["process"]["user"].clone();
        let id = |k: &str| user[k].as_u64().filter(|v| *v > 0).map(|v| v as u32);
        let devices: Vec<HostDevice> = e
            .devices
            .iter()
            .map(|d| HostDevice {
                uid: d.uid.or(id("uid")),
                gid: d.gid.or(id("gid")),
                ..d.clone()
            })
            .collect();
        options::add_devices(spec, &devices, bind_devices, &[]);
    }
    if !e.mounts.is_empty() {
        let mounts = ensure_array(spec, "mounts");
        for m in &e.mounts {
            mounts.retain(|x| x["destination"] != m.container_path.as_str());
            let typ = if m.typ.is_empty() { "bind" } else { &m.typ };
            let mut opts = m.options.clone();
            if typ == "bind" && !opts.iter().any(|o| o == "bind" || o == "rbind") {
                opts.push("rbind".into());
            }
            mounts.push(json!({"destination": m.container_path, "type": typ,
                "source": m.host_path, "options": opts}));
        }
        let depth = |m: &Value| m["destination"].as_str().unwrap_or("").matches('/').count();
        mounts.sort_by_key(depth);
    }
    for h in &e.hooks {
        let list = ensure_array(&mut spec["hooks"], &h.hook_name);
        let mut hook = json!({"path": h.path});
        if !h.args.is_empty() {
            hook["args"] = json!(h.args);
        }
        if !h.env.is_empty() {
            hook["env"] = json!(h.env);
        }
        if let Some(t) = h.timeout {
            hook["timeout"] = json!(t);
        }
        list.push(hook);
    }
    for d in &e.net_devices {
        spec["linux"]["netDevices"][&d.host_interface_name] = json!({"name": d.name});
    }
    if let Some(i) = &e.intel_rdt {
        let mut rdt = serde_json::Map::new();
        for (k, v) in [
            ("closID", &i.clos_id),
            ("l3CacheSchema", &i.l3_cache_schema),
            ("memBwSchema", &i.mem_bw_schema),
        ] {
            if !v.is_empty() {
                rdt.insert(k.into(), json!(v));
            }
        }
        if let Some(s) = &i.schemata {
            rdt.insert("schemata".into(), json!(s));
        }
        if i.enable_monitoring {
            rdt.insert("enableMonitoring".into(), json!(true));
        }
        spec["linux"]["intelRdt"] = Value::Object(rdt);
    }
    for gid in e.additional_gids.iter().filter(|g| **g != 0) {
        let gids = ensure_array(&mut spec["process"]["user"], "additionalGids");
        if !gids.iter().any(|g| g == gid) {
            gids.push(json!(gid));
        }
    }
}

/// What `info` shows: the directories, the devices found and what is wrong
/// with the spec files.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Info {
    pub spec_dirs: Vec<String>,
    pub devices: Vec<String>,
    pub errors: Vec<String>,
}

pub fn info(configured: &[String]) -> Info {
    let cat = scan(&spec_dirs(configured));
    Info {
        spec_dirs: cat.dirs.iter().map(|d| d.display().to_string()).collect(),
        devices: cat.device_names(),
        errors: cat.error_lines(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const FULL: &str = r#"{
      "cdiVersion": "1.1.0",
      "kind": "fake.vendor.com/dev",
      "annotations": {"example.com/a": "b"},
      "devices": [
        {"name": "d0", "containerEdits": {
          "env": ["D0=1"],
          "deviceNodes": [{"path": "/dev/d0", "hostPath": "/dev/null"}]}},
        {"name": "all", "containerEdits": {"env": ["ALL=1"]}}
      ],
      "containerEdits": {
        "env": ["KIND=fake"],
        "mounts": [{"hostPath": "/tmp", "containerPath": "/opt/x", "options": ["ro"]}],
        "hooks": [{"hookName": "createContainer", "path": "/bin/true", "args": ["true", "x"],
                   "env": ["A=b"], "timeout": 5}],
        "additionalGids": [0, 44, 44]
      }
    }"#;

    fn write(dir: &Path, name: &str, text: &str) {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn base_spec() -> Value {
        json!({"process": {"env": ["PATH=/bin"], "user": {"uid": 1000, "gid": 100}},
               "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"}],
               "linux": {"resources": {"devices": [{"allow": false, "access": "rwm"}]}}})
    }

    #[test]
    fn names_are_qualified_by_vendor_class_and_name() {
        for ok in ["nvidia.com/gpu=all", "a/b=0", "a-b.c/d_e=x:y.z-1"] {
            assert!(parse_qualified(ok).is_ok(), "{ok}");
        }
        for bad in [
            "/dev/null",
            "gpu",
            "nvidia.com/gpu",
            "nvidia.com=0",
            "nvidia.com/gpu=",
            "1a.com/gpu=0",
            "a.com/gpu-=0",
            "a.com/g pu=0",
            "a.com/gpu=-0",
            "a.com/gpu=0-",
            "a.com/gpu=a b",
        ] {
            assert!(parse_qualified(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_qualified("a.com/gpu=0:1").unwrap(),
            ("a.com", "gpu", "0:1")
        );
    }

    #[test]
    fn a_json_and_a_yaml_spec_read_the_same() {
        let json = parse_spec(FULL, false).unwrap();
        let yaml = parse_spec(
            r#"
cdiVersion: "1.1.0"
kind: fake.vendor.com/dev
annotations:
  example.com/a: b
devices:
  - name: d0
    containerEdits:
      env: ["D0=1"]
      deviceNodes:
        - {path: /dev/d0, hostPath: /dev/null}
  - name: all
    containerEdits:
      env: [ALL=1]
containerEdits:
  env: [KIND=fake]
  mounts:
    - hostPath: /tmp
      containerPath: /opt/x
      options: [ro]
  hooks:
    - hookName: createContainer
      path: /bin/true
      args: [true, x]
      env: [A=b]
      timeout: 5
  additionalGids: [0, 44, 44]
"#,
            true,
        )
        .unwrap();
        assert_eq!(json, yaml);
        json.validate().unwrap();
        assert_eq!(json.devices.len(), 2);
    }

    #[test]
    fn unknown_fields_and_bad_documents_are_errors() {
        let bad = |text: &str| parse_spec(text, false).unwrap_err();
        assert!(
            bad(r#"{"cdiVersion":"0.6.0","kind":"a.com/b","devices":[],"extra":1}"#)
                .contains("unknown field")
        );
        assert!(bad("null").contains("no Spec data"));
        assert!(bad("[1]").contains("invalid type"));
        assert!(parse_spec("a: [", true).is_err());
        assert!(parse_spec("a: 1\n---\nb: 2\n", true)
            .unwrap_err()
            .contains("2 YAML documents"));
        assert!(parse_spec("a: &x 1\nb: *x\n", true)
            .unwrap_err()
            .contains("aliases"));
        let deep = format!("{}1{}", "[".repeat(100), "]".repeat(100));
        assert!(parse_spec(&deep, true).unwrap_err().contains("deeply"));
        // (refused before a tree is built: dropping one this deep would
        // overflow the stack; the scanner may refuse it first)
        let huge = "[".repeat(1 << 20);
        let err = parse_spec(&huge, true).unwrap_err();
        assert!(
            err.contains("deeply") || err.contains("recursion limit"),
            "{err}"
        );
    }

    fn spec_of(text: &str) -> Result<(), String> {
        parse_spec(text, false).unwrap().validate()
    }

    #[test]
    fn versions_and_the_features_they_need() {
        let with = |version: &str, rest: &str| {
            spec_of(&format!(
                r#"{{"cdiVersion":"{version}","kind":"a.com/b","devices":[{{"name":"d","containerEdits":{{{rest}}}}}]}}"#
            ))
        };
        assert!(with("0.3.0", r#""env":["A=b"]"#).is_ok());
        assert!(with("v0.3.0", r#""env":["A=b"]"#).is_ok());
        assert!(with("0.9.0", r#""env":["A=b"]"#)
            .unwrap_err()
            .contains("invalid version"));
        assert!(with("", r#""env":["A=b"]"#).is_err());
        let mount_type = r#""mounts":[{"hostPath":"/a","containerPath":"/b","type":"bind"}]"#;
        assert!(with("0.3.0", mount_type)
            .unwrap_err()
            .contains("at least v0.4.0"));
        assert!(with("0.4.0", mount_type).is_ok());
        let host_path = r#""deviceNodes":[{"path":"/dev/a","hostPath":"/dev/null"}]"#;
        assert!(with("0.4.0", host_path)
            .unwrap_err()
            .contains("at least v0.5.0"));
        assert!(with("0.5.0", host_path).is_ok());
        assert!(with("0.6.0", r#""additionalGids":[5]"#)
            .unwrap_err()
            .contains("v0.7.0"));
        assert!(with("0.7.0", r#""additionalGids":[5]"#).is_ok());
        assert!(with("0.8.0", r#""intelRdt":{"closID":"c"}"#).is_ok());
        assert!(with("0.8.0", r#""intelRdt":{"enableMonitoring":true}"#)
            .unwrap_err()
            .contains("v1.1.0"));
        assert!(with(
            "1.0.0",
            r#""netDevices":[{"hostInterfaceName":"e","name":"n"}]"#
        )
        .unwrap_err()
        .contains("v1.1.0"));
        assert!(with(
            "1.1.0",
            r#""netDevices":[{"hostInterfaceName":"e","name":"n"}]"#
        )
        .is_ok());
        // a digit first in a name, and a dot in the class
        let named = |version: &str, kind: &str, name: &str| {
            spec_of(&format!(
                r#"{{"cdiVersion":"{version}","kind":"{kind}","devices":[{{"name":"{name}","containerEdits":{{"env":["A=b"]}}}}]}}"#
            ))
        };
        assert!(named("0.4.0", "a.com/b", "0")
            .unwrap_err()
            .contains("v0.5.0"));
        assert!(named("0.5.0", "a.com/b", "0").is_ok());
        assert!(named("0.5.0", "a.com/b.c", "x")
            .unwrap_err()
            .contains("v0.6.0"));
        assert!(named("0.6.0", "a.com/b.c", "x").is_ok());
    }

    #[test]
    fn invalid_specs_are_refused_with_a_reason() {
        let edits = |e: &str| {
            spec_of(&format!(
                r#"{{"cdiVersion":"1.1.0","kind":"a.com/b","devices":[{{"name":"d","containerEdits":{e}}}]}}"#
            ))
        };
        let err = |e: &str| edits(e).unwrap_err();
        assert!(edits(r#"{"env":["A=b"]}"#).is_ok());
        assert!(err("{}").contains("empty device edits"));
        assert!(err(r#"{"env":["NOEQUALS"]}"#).contains("invalid environment variable"));
        assert!(err(r#"{"env":["=x"]}"#).contains("invalid environment variable"));
        assert!(err(r#"{"deviceNodes":[{"path":""}]}"#).contains("empty) device path"));
        assert!(err(r#"{"deviceNodes":[{"path":"dev/x"}]}"#).contains("absolute"));
        assert!(err(r#"{"deviceNodes":[{"path":"/dev/x","type":"z"}]}"#).contains("invalid type"));
        assert!(
            err(r#"{"deviceNodes":[{"path":"/dev/x","permissions":"rwx"}]}"#)
                .contains("invalid permissions")
        );
        assert!(err(r#"{"deviceNodes":[{"path":"/dev/x","major":-1}]}"#).contains("negative"));
        assert!(err(r#"{"hooks":[{"hookName":"nope","path":"/bin/true"}]}"#)
            .contains("invalid hook name"));
        assert!(err(r#"{"hooks":[{"hookName":"poststop","path":""}]}"#).contains("empty path"));
        assert!(err(r#"{"hooks":[{"hookName":"poststop","path":"true"}]}"#).contains("absolute"));
        assert!(
            err(r#"{"hooks":[{"hookName":"poststop","path":"/t","timeout":0}]}"#)
                .contains("timeout")
        );
        assert!(
            err(r#"{"mounts":[{"hostPath":"","containerPath":"/b"}]}"#).contains("empty host path")
        );
        assert!(err(r#"{"mounts":[{"hostPath":"/a","containerPath":""}]}"#)
            .contains("empty container path"));
        assert!(err(r#"{"intelRdt":{"closID":"a/b"}}"#).contains("ClosID"));
        assert!(err(r#"{"netDevices":[{"hostInterfaceName":"a","name":"x"},{"hostInterfaceName":"a","name":"y"}]}"#)
            .contains("duplicate HostInterfaceName"));
        let spec = |s: &str| spec_of(s).unwrap_err();
        assert!(
            spec(r#"{"cdiVersion":"1.1.0","kind":"a.com/b","devices":[]}"#).contains("no devices")
        );
        assert!(spec(r#"{"cdiVersion":"1.1.0","kind":"nokind","devices":[{"name":"d","containerEdits":{"env":["A=b"]}}]}"#)
            .contains("invalid vendor"));
        assert!(spec(
            r#"{"cdiVersion":"1.1.0","kind":"a.com/b","devices":[
            {"name":"d","containerEdits":{"env":["A=b"]}},
            {"name":"d","containerEdits":{"env":["A=c"]}}]}"#
        )
        .contains("multiple device"));
        assert!(spec(r#"{"cdiVersion":"1.1.0","kind":"a.com/b","devices":[{"name":"-d","containerEdits":{"env":["A=b"]}}]}"#)
            .contains("start with a letter or digit"));
        assert!(spec(r#"{"cdiVersion":"1.1.0","kind":"a.com/b","annotations":{"bad key":"x"},"devices":[{"name":"d","containerEdits":{"env":["A=b"]}}]}"#)
            .contains("annotations"));
    }

    #[test]
    fn devices_are_resolved_from_the_spec_dirs() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fake.json", FULL);
        write(d.path(), "ignored.txt", "not a spec");
        let e = resolve(&names(&["fake.vendor.com/dev=d0"]), &[d.path().into()]).unwrap();
        // the edits of the spec first, those of the device after
        assert_eq!(e.env, ["KIND=fake", "D0=1"]);
        assert_eq!(e.mounts.len(), 1);
        assert_eq!(e.hooks[0].hook_name, "createContainer");
        assert_eq!(e.additional_gids, [0, 44, 44]);
        let n = &e.devices[0];
        assert_eq!((n.host.as_str(), n.path.as_str()), ("/dev/null", "/dev/d0"));
        assert_eq!((n.typ.as_str(), n.major, n.minor), ("c", 1, 3));
        assert_eq!(n.access.as_deref(), Some("rwm"));
        // the edits of a spec are made once for all its devices
        let e = resolve(
            &names(&["fake.vendor.com/dev=d0", "fake.vendor.com/dev=all"]),
            &[d.path().into()],
        )
        .unwrap();
        assert_eq!(e.env, ["KIND=fake", "D0=1", "ALL=1"]);
        assert_eq!(e.mounts.len(), 1);
        assert_eq!(e.hooks.len(), 1);
        let info = info(&[d.path().to_str().unwrap().into()]);
        assert_eq!(
            info.devices,
            ["fake.vendor.com/dev=all", "fake.vendor.com/dev=d0"]
        );
        assert!(info.errors.is_empty());
    }

    #[test]
    fn an_unresolvable_device_is_an_error_naming_it_and_the_broken_files() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fake.json", FULL);
        write(d.path(), "broken.yaml", "cdiVersion: 1.1.0\nkind: [");
        let e = resolve(
            &names(&[
                "fake.vendor.com/dev=d0",
                "fake.vendor.com/dev=nope",
                "x.com/y=z",
            ]),
            &[d.path().into(), "/nonexistent/cdi".into()],
        )
        .unwrap_err();
        assert!(e.starts_with("setting up CDI devices: unresolvable CDI devices fake.vendor.com/dev=nope, x.com/y=z"), "{e}");
        assert!(e.contains("broken.yaml"), "{e}");
        // a name that is not qualified is not looked up
        let e = resolve(&names(&["gpu"]), &[d.path().into()]).unwrap_err();
        assert!(e.contains("unqualified device"), "{e}");
        // without directories, nothing is found, nothing fails but the name
        let e = resolve(&names(&["a.com/b=c"]), &[]).unwrap_err();
        assert!(e.contains("unresolvable CDI devices a.com/b=c"), "{e}");
    }

    #[test]
    fn a_later_directory_wins_and_two_files_of_a_directory_conflict() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let spec = |env: &str| {
            format!(
                r#"{{"cdiVersion":"0.6.0","kind":"a.com/b","devices":[{{"name":"d","containerEdits":{{"env":["{env}"]}}}}]}}"#
            )
        };
        write(a.path(), "x.json", &spec("FROM=first"));
        write(b.path(), "x.json", &spec("FROM=second"));
        let dirs = [a.path().to_path_buf(), b.path().to_path_buf()];
        let e = resolve(&names(&["a.com/b=d"]), &dirs).unwrap();
        assert_eq!(e.env, ["FROM=second"]);
        let e = resolve(&names(&["a.com/b=d"]), &[dirs[1].clone(), dirs[0].clone()]).unwrap();
        assert_eq!(e.env, ["FROM=first"]);
        // two files of one directory: the device is gone, and says why
        write(b.path(), "y.json", &spec("FROM=third"));
        let e = resolve(&names(&["a.com/b=d"]), &dirs).unwrap_err();
        assert!(e.contains("conflicting device"), "{e}");
        // a later directory settles the conflict of an earlier one
        let c = tempfile::tempdir().unwrap();
        write(c.path(), "z.json", &spec("FROM=fourth"));
        let e = resolve(&names(&["a.com/b=d"]), &[dirs[1].clone(), c.path().into()]).unwrap();
        assert_eq!(e.env, ["FROM=fourth"]);
    }

    #[test]
    fn specs_that_others_could_have_written_are_refused() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fake.json", FULL);
        let file = d.path().join("fake.json");
        let dirs = [d.path().to_path_buf()];
        let id = names(&["fake.vendor.com/dev=d0"]);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let e = resolve(&id, &dirs).unwrap_err();
        assert!(e.contains("writable by its group or others"), "{e}");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(resolve(&id, &dirs).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        resolve(&id, &dirs).unwrap();
        // a directory others can write to
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = resolve(&id, &dirs).unwrap_err();
        assert!(e.contains("writable by its group or others"), "{e}");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        // too large
        let big = " ".repeat(MAX_SPEC_SIZE as usize + 1);
        write(d.path(), "big.json", &big);
        let found = scan(&dirs);
        assert!(found
            .error_lines()
            .iter()
            .any(|l| l.contains("larger than")));
        // a directory named like a spec, and a symlink to a spec
        std::fs::create_dir(d.path().join("dir.json")).unwrap();
        let links = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(&file, links.path().join("link.json")).unwrap();
        assert_eq!(scan(&dirs).device_names().len(), 2);
        assert_eq!(scan(&[links.path().into()]).device_names().len(), 2);
    }

    #[test]
    fn node_info_comes_from_the_host_device() {
        let node = |json: &str| host_device(&serde_json::from_str(json).unwrap());
        // path alone: the host device of that path
        let d = node(r#"{"path": "/dev/zero"}"#).unwrap();
        assert_eq!((d.typ.as_str(), d.major, d.minor), ("c", 1, 5));
        assert_eq!(d.host, "/dev/zero");
        // hostPath, and a type of "u"
        let d = node(r#"{"path": "/dev/z", "hostPath": "/dev/zero", "type": "u"}"#).unwrap();
        assert_eq!(
            (d.typ.as_str(), d.host.as_str(), d.minor),
            ("c", "/dev/zero", 5)
        );
        assert!(d.mode & 0o777 != 0);
        // what the spec says wins, and the host device may be absent
        let d = node(
            r#"{"path": "/dev/nvx", "type": "c", "major": 195, "minor": 7,
                         "fileMode": 432, "permissions": "rw", "uid": 3, "gid": 4}"#,
        )
        .unwrap();
        assert_eq!(
            (d.typ.as_str(), d.major, d.minor, d.mode),
            ("c", 195, 7, 0o660)
        );
        assert_eq!(
            (d.access.as_deref(), d.uid, d.gid),
            (Some("rw"), Some(3), Some(4))
        );
        let d = node(
            r#"{"path": "/dev/nvx", "type": "c", "major": 1, "minor": 1,
                         "permissions": "none"}"#,
        )
        .unwrap();
        assert_eq!(d.access.as_deref(), Some(""));
        // not minimal, and no device there
        let e = node(r#"{"path": "/dev/does-not-exist"}"#).unwrap_err();
        assert!(e.contains("failed to stat CDI host device"), "{e}");
        let e = node(r#"{"path": "/etc/passwd"}"#).unwrap_err();
        assert!(e.contains("not a device node"), "{e}");
        let e = node(r#"{"path": "/dev/zero", "type": "b"}"#).unwrap_err();
        assert!(e.contains("host type mismatch"), "{e}");
    }

    #[test]
    fn the_edits_are_written_into_the_oci_spec() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fake.json", FULL);
        let e = resolve(&names(&["fake.vendor.com/dev=d0"]), &[d.path().into()]).unwrap();
        let mut s = base_spec();
        apply(&mut s, &e, false);
        assert_eq!(
            s["process"]["env"],
            json!(["PATH=/bin", "KIND=fake", "D0=1"])
        );
        // the node belongs to the user of the process, and is allowed
        let n = &s["linux"]["devices"][0];
        assert_eq!(n["path"], "/dev/d0");
        assert_eq!(
            (n["type"].as_str(), n["major"].as_u64(), n["minor"].as_u64()),
            (Some("c"), Some(1), Some(3))
        );
        assert_eq!(
            (n["uid"].as_u64(), n["gid"].as_u64()),
            (Some(1000), Some(100))
        );
        let rules = s["linux"]["resources"]["devices"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[1],
            json!({"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"})
        );
        // the mount is a bind mount, after /proc
        let m = s["mounts"].as_array().unwrap();
        assert_eq!(m[0]["destination"], "/proc");
        assert_eq!(
            m[1],
            json!({"destination": "/opt/x", "type": "bind", "source": "/tmp",
                   "options": ["ro", "rbind"]})
        );
        assert_eq!(
            s["hooks"]["createContainer"],
            json!([{"path": "/bin/true", "args": ["true", "x"], "env": ["A=b"], "timeout": 5}])
        );
        // group 0 never, a group once
        assert_eq!(s["process"]["user"]["additionalGids"], json!([44]));
        // the user the container record keeps is the one of this final spec
        let user = crate::container::SpecUser::of_spec(&s).unwrap();
        assert_eq!(user.additional_gids, [44]);
    }

    #[test]
    fn nodes_are_bind_mounts_where_a_user_namespace_cannot_make_them() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "fake.json", FULL);
        let e = resolve(&names(&["fake.vendor.com/dev=d0"]), &[d.path().into()]).unwrap();
        let mut s = base_spec();
        apply(&mut s, &e, true);
        assert!(s["linux"].get("devices").is_none());
        assert_eq!(
            s["linux"]["resources"]["devices"].as_array().unwrap().len(),
            1
        );
        assert!(s["mounts"].as_array().unwrap().iter().any(|m| m
            == &json!({"destination": "/dev/d0", "type": "bind", "source": "/dev/null",
                       "options": ["rbind", "nosuid", "noexec"]})));
    }

    #[test]
    fn variables_mounts_and_the_rest_replace_what_they_meet() {
        let mut s = json!({"process": {"env": ["A=1", "B=2"]},
            "mounts": [{"destination": "/opt/x", "type": "tmpfs", "source": "tmpfs"},
                       {"destination": "/a/b/c", "type": "tmpfs", "source": "tmpfs"}]});
        let e = Edits {
            env: vec!["A=3".into(), "C=4".into()],
            mounts: vec![Mount {
                host_path: "/h".into(),
                container_path: "/opt/x".into(),
                options: vec!["bind".into()],
                typ: "bind".into(),
            }],
            net_devices: vec![NetDevice {
                host_interface_name: "eth9".into(),
                name: "net0".into(),
            }],
            intel_rdt: Some(IntelRdt {
                clos_id: "c1".into(),
                l3_cache_schema: "L3:0=ff".into(),
                mem_bw_schema: String::new(),
                schemata: Some(vec!["L3:0=f".into()]),
                enable_monitoring: true,
            }),
            ..Default::default()
        };
        apply(&mut s, &e, false);
        assert_eq!(s["process"]["env"], json!(["A=3", "B=2", "C=4"]));
        // replaced, and the shallow mount first
        assert_eq!(
            s["mounts"],
            json!([{"destination": "/opt/x", "type": "bind", "source": "/h", "options": ["bind"]},
                   {"destination": "/a/b/c", "type": "tmpfs", "source": "tmpfs"}])
        );
        assert_eq!(s["linux"]["netDevices"], json!({"eth9": {"name": "net0"}}));
        assert_eq!(
            s["linux"]["intelRdt"],
            json!({"closID": "c1", "l3CacheSchema": "L3:0=ff", "schemata": ["L3:0=f"],
                   "enableMonitoring": true})
        );
        // nothing to apply, nothing changed
        let before = s.clone();
        apply(&mut s, &Edits::default(), false);
        assert_eq!(s, before);
        assert!(Edits::default().is_empty());
    }

    #[test]
    fn the_default_directories_and_the_configured_ones() {
        assert_eq!(
            spec_dirs(&[]),
            [PathBuf::from("/etc/cdi"), PathBuf::from("/var/run/cdi")]
        );
        assert_eq!(
            spec_dirs(&["/a/".into(), "/b".into()]),
            [PathBuf::from("/a"), PathBuf::from("/b")]
        );
    }
}
