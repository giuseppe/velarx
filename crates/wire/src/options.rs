// SPDX-License-Identifier: Apache-2.0
//! The create options that shape the OCI spec beyond the process and its
//! security: resource limits of the process, host devices, namespaces of
//! the host or of another container, /dev/shm, read-only root tmpfs,
//! annotations, personality and cgroup settings.
//!
//! They are parsed and checked at create time (`parse_*`, `resolve_*`) and
//! stored in [`CreateOptions`]; [`apply`] writes them into the spec.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

/// A process resource limit: `RLIMIT_NOFILE`, soft, hard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rlimit {
    pub typ: String,
    pub soft: u64,
    pub hard: u64,
}

/// A host device given to the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDevice {
    pub host: String,
    pub path: String,
    /// `c` or `b`
    pub typ: String,
    pub major: u64,
    pub minor: u64,
    pub mode: u32,
    /// cgroup access (`rwm`); none for the devices of `--privileged`
    pub access: Option<String>,
    /// The owner of the node (the CDI devices say; root otherwise)
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
}

/// The block IO weight of a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeightDev {
    pub major: u64,
    pub minor: u64,
    pub weight: u16,
}

/// A block IO limit of a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Throttle {
    pub major: u64,
    pub minor: u64,
    pub rate: u64,
}

/// The namespace of a kind: private (empty), `host`, a path, or
/// `container:ID`, which the start of the container resolves to the
/// namespace of the process of that container (it changes with each run
/// of it) in the spec.
pub type NsMode = String;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateOptions {
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,
    #[serde(default)]
    pub devices: Vec<HostDevice>,
    #[serde(default)]
    pub device_rules: Vec<DeviceRule>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    pub pid_ns: NsMode,
    #[serde(default)]
    pub ipc_ns: NsMode,
    #[serde(default)]
    pub uts_ns: NsMode,
    #[serde(default)]
    pub cgroup_ns: NsMode,
    /// `LINUX` or `LINUX32`
    #[serde(default)]
    pub personality: Option<String>,
    /// Intel RDT class of service (`--rdt-class`)
    #[serde(default)]
    pub rdt_class: Option<String>,
    /// bytes
    #[serde(default)]
    pub shm_size: Option<u64>,
    /// `--ipc shareable`: /dev/shm is a directory of the engine, the one
    /// the containers that join the IPC namespace of this one get as well
    #[serde(default)]
    pub shm_shareable: bool,
    /// `--ipc none`: no /dev/shm
    #[serde(default)]
    pub no_shm: bool,
    /// tmpfs on /tmp, /var/tmp and /run of a read-only root
    #[serde(default)]
    pub read_only_tmpfs: bool,
    #[serde(default)]
    pub oom_kill_disable: bool,
    #[serde(default)]
    pub blkio_weight: Option<u16>,
    #[serde(default)]
    pub weight_devices: Vec<WeightDev>,
    #[serde(default)]
    pub read_bps: Vec<Throttle>,
    #[serde(default)]
    pub write_bps: Vec<Throttle>,
    #[serde(default)]
    pub read_iops: Vec<Throttle>,
    #[serde(default)]
    pub write_iops: Vec<Throttle>,
    #[serde(default)]
    pub unified: HashMap<String, String>,
    #[serde(default)]
    pub rootfs_propagation: Option<String>,
    /// The devices are bind mounted (a user namespace cannot make nodes).
    #[serde(default)]
    pub bind_devices: bool,
    /// `--privileged`: the cgroup file system is writable
    #[serde(default)]
    pub privileged: bool,
    /// Hugepage limits: page size as the kernel names it (`2MB`) and bytes
    #[serde(default)]
    pub hugepages: Vec<(String, u64)>,
    /// systemd is the init (`--systemd`): tmpfs on /run, /run/lock, /tmp
    /// and /var/log/journal, a writable cgroup
    #[serde(default)]
    pub systemd: bool,
    /// `--shm-size-systemd`: the size of those tmpfs (bytes)
    #[serde(default)]
    pub systemd_tmpfs_size: Option<u64>,
}

/// The root propagation the volumes need, as podman's addRootPropagation:
/// `shared` when one is shared (its mounts must reach the host through the
/// root), `rslave` when one is a slave, nothing for private ones.
fn volume_propagation(spec: &Value) -> Option<String> {
    let mut out: Option<&str> = None;
    for o in spec["mounts"]
        .as_array()?
        .iter()
        .filter_map(|m| m["options"].as_array())
        .flatten()
    {
        match o.as_str() {
            Some("shared" | "rshared") => out = Some("shared"),
            Some("slave" | "rslave") if out.is_none() => out = Some("rslave"),
            _ => {}
        }
    }
    out.map(str::to_string)
}

/// Insert `add` after the default mounts of the spec (/proc, /dev...) and
/// before the others: a tmpfs of the engine on /run or /tmp goes under the
/// mounts below it.
fn insert_after_defaults(spec: &mut Value, add: Vec<Value>) {
    const DEFAULTS: [&str; 6] = [
        "/proc",
        "/dev",
        "/dev/pts",
        "/dev/shm",
        "/dev/mqueue",
        "/sys",
    ];
    match spec["mounts"].as_array_mut() {
        Some(m) => {
            let at = m
                .iter()
                .position(|m| {
                    !m["destination"]
                        .as_str()
                        .is_some_and(|d| DEFAULTS.contains(&d))
                })
                .unwrap_or(m.len());
            m.splice(at..at, add);
        }
        None => spec["mounts"] = Value::Array(add),
    }
}

/// The paths a systemd init needs as tmpfs.
pub const SYSTEMD_TMPFS: [&str; 4] = ["/run", "/run/lock", "/tmp", "/var/log/journal"];

/// Whether a container runs systemd as its init: `--systemd=always`, or
/// `true` (the default) and a command that is an init (`/sbin/init`,
/// `/usr/sbin/init`, `/usr/local/sbin/init` or a `systemd`), as podman
/// detects it (a `/bin/sh -c` prefix is skipped).
pub fn systemd_mode(setting: Option<&str>, argv: &[String]) -> Result<bool, String> {
    match setting.unwrap_or("true") {
        "always" => Ok(true),
        "false" => Ok(false),
        "true" => {
            let cmd = match argv {
                [sh, c, cmd, ..] if sh == "/bin/sh" && c == "-c" => cmd.as_str(),
                [cmd, ..] => cmd.as_str(),
                [] => return Ok(false),
            };
            Ok(matches!(
                cmd,
                "/sbin/init" | "/usr/sbin/init" | "/usr/local/sbin/init"
            ) || Path::new(cmd).file_name().is_some_and(|n| n == "systemd"))
        }
        v => Err(format!("invalid --systemd `{v}`: true, false or always")),
    }
}

/// A hugepage limit: `2MB`, `1GB` or `64KB` (any case, `B` optional),
/// a size the kernel has.
pub fn hugepage_limit(size: &str, limit: u64) -> Result<(String, u64), String> {
    let bad = || format!("invalid hugepage size `{size}`");
    let bytes = parse_size(size).filter(|b| *b >= 1024).ok_or_else(bad)?;
    let kb = bytes / 1024;
    if !Path::new(&format!("/sys/kernel/mm/hugepages/hugepages-{kb}kB")).exists() {
        return Err(format!("the kernel has no hugepages of {size}"));
    }
    // the name of the cgroup files: hugetlb.2MB.max
    let name = match kb {
        k if k % (1 << 20) == 0 => format!("{}GB", k >> 20),
        k if k % 1024 == 0 => format!("{}MB", k >> 10),
        k => format!("{k}KB"),
    };
    Ok((name, limit))
}

const RLIMITS: [&str; 16] = [
    "as",
    "core",
    "cpu",
    "data",
    "fsize",
    "locks",
    "memlock",
    "msgqueue",
    "nice",
    "nofile",
    "nproc",
    "rss",
    "rtprio",
    "rttime",
    "sigpending",
    "stack",
];

pub use velarx_proto::request::{limit_value, parse_device_rule, DeviceRule};

/// `--ulimit NAME=SOFT:HARD` (`u64::MAX` is no limit).
pub fn rlimit(name: &str, soft: u64, hard: u64) -> Result<Rlimit, String> {
    let lower = name.to_ascii_lowercase();
    let short = lower.strip_prefix("rlimit_").unwrap_or(&lower);
    if !RLIMITS.contains(&short) {
        return Err(format!("invalid ulimit type `{name}`"));
    }
    if soft > hard {
        return Err(format!(
            "the soft ulimit of `{name}` is above its hard limit"
        ));
    }
    Ok(Rlimit {
        typ: format!("RLIMIT_{}", short.to_ascii_uppercase()),
        soft,
        hard,
    })
}

/// The limits of every container: podman's, the hard limits of the daemon
/// when it cannot raise them.
pub fn default_rlimits() -> Result<Vec<Rlimit>, velarx_base::ids::IdsError> {
    use rustix::process::{getrlimit, Resource};
    let can_raise = rustix::process::geteuid().is_root() && !velarx_base::ids::in_user_namespace()?;
    let rl = |typ: &str, res: Resource, fixed: u64| {
        let hard = match can_raise {
            true => fixed,
            false => getrlimit(res).maximum.unwrap_or(u64::MAX),
        };
        Rlimit {
            typ: typ.to_string(),
            soft: hard,
            hard,
        }
    };
    Ok(vec![
        rl("RLIMIT_NOFILE", Resource::Nofile, 1048576),
        rl("RLIMIT_NPROC", Resource::Nproc, 4194304),
    ])
}

/// A device of the host: its type and numbers.
fn stat_device(host: &str) -> Result<(String, u64, u64, u32), String> {
    let md = std::fs::metadata(host).map_err(|e| format!("device `{host}`: {e}"))?;
    let ft = md.file_type();
    let typ = if ft.is_char_device() {
        "c"
    } else if ft.is_block_device() {
        "b"
    } else {
        return Err(format!("`{host}` is not a device"));
    };
    let rdev = md.rdev();
    Ok((
        typ.to_string(),
        rustix::fs::major(rdev) as u64,
        rustix::fs::minor(rdev) as u64,
        md.mode() & 0o777,
    ))
}

/// `--device HOST[:CONTAINER][:PERMS]`; a directory gives the devices in it.
pub fn resolve_device(host: &str, path: &str, access: &str) -> Result<Vec<HostDevice>, String> {
    if !host.starts_with('/') || !path.starts_with('/') {
        return Err(format!(
            "invalid device `{host}:{path}`: the paths must be absolute"
        ));
    }
    if access.is_empty() || !access.chars().all(|c| "rwm".contains(c)) {
        return Err(format!("invalid device permissions `{access}`"));
    }
    if Path::new(host).is_dir() {
        let mut out = Vec::new();
        host_devices(
            Path::new(host),
            Path::new(path),
            Some(access),
            false,
            0,
            &mut out,
        );
        if out.is_empty() {
            return Err(format!("no device in `{host}`"));
        }
        return Ok(out);
    }
    let (typ, major, minor, mode) = stat_device(host)?;
    Ok(vec![HostDevice {
        host: host.to_string(),
        path: path.to_string(),
        typ,
        major,
        minor,
        mode,
        access: Some(access.to_string()),
        uid: None,
        gid: None,
    }])
}

/// The devices below `dir` (`/dev` for `--privileged`), as podman: the
/// directories of terminals, shared memory and container tools are skipped,
/// and with `readable` only the devices the daemon may read.
fn host_devices(
    dir: &Path,
    dest: &Path,
    access: Option<&str>,
    readable: bool,
    depth: u32,
    out: &mut Vec<HostDevice>,
) {
    const SKIP: [&str; 8] = [
        "pts",
        "shm",
        "fd",
        "mqueue",
        "console",
        ".lxc",
        ".lxd-mounts",
        ".udev",
    ];
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name();
        if name.to_str().is_some_and(|n| SKIP.contains(&n)) {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        let (host, path) = (e.path(), dest.join(&name));
        if ft.is_dir() {
            if depth < 3 {
                host_devices(&host, &path, access, readable, depth + 1, out);
            }
            continue;
        }
        if !(ft.is_char_device() || ft.is_block_device()) {
            continue;
        }
        // (not opened: opening a device has effects, a serial port toggles
        // its lines, a watchdog starts counting)
        if readable && rustix::fs::access(&host, rustix::fs::Access::READ_OK).is_err() {
            continue;
        }
        let (Some(h), Some(p)) = (host.to_str(), path.to_str()) else {
            continue;
        };
        if let Ok((typ, major, minor, mode)) = stat_device(h) {
            out.push(HostDevice {
                host: h.to_string(),
                path: p.to_string(),
                typ,
                major,
                minor,
                mode,
                access: access.map(String::from),
                uid: None,
                gid: None,
            });
        }
    }
}

/// The devices of a `--privileged` container.
pub fn privileged_devices(bind: bool, systemd: bool) -> Vec<HostDevice> {
    let mut out = Vec::new();
    host_devices(
        Path::new("/dev"),
        Path::new("/dev"),
        None,
        bind,
        0,
        &mut out,
    );
    // systemd takes the terminals of a privileged container for its own
    if systemd {
        out.retain(|d| !d.path.starts_with("/dev/tty"));
    }
    // a rootless container is not given the host's ptmx (the runtime makes
    // its own) nor the virtual consoles, as podman's
    if bind {
        out.retain(|d| {
            d.path != "/dev/ptmx"
                && d.path != "/dev/tty"
                && !d
                    .path
                    .strip_prefix("/dev/tty")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        });
    }
    out
}

/// A block IO limit of the device at `path`.
pub fn throttle(path: &str, rate: u64) -> Result<Throttle, String> {
    let (typ, major, minor, _) = stat_device(path)?;
    if typ != "b" {
        return Err(format!("{path}: not a block device"));
    }
    Ok(Throttle { major, minor, rate })
}

/// The block IO weight of the device at `path`, or of the device numbered
/// `numbers`.
pub fn weight_device(
    path: &str,
    numbers: Option<(u64, u64)>,
    weight: u16,
) -> Result<WeightDev, String> {
    if !(10..=1000).contains(&weight) {
        return Err(format!("invalid block IO weight {weight}: 10 to 1000"));
    }
    let (major, minor) = match numbers {
        Some(n) => n,
        None => {
            let (typ, major, minor, _) = stat_device(path)?;
            if typ != "b" {
                return Err(format!("{path}: not a block device"));
            }
            (major, minor)
        }
    };
    Ok(WeightDev {
        major,
        minor,
        weight,
    })
}

/// `--device-read-bps PATH:RATE` (a size) and `--device-read-iops
/// PATH:RATE` (a number).
pub fn parse_throttle(s: &str, iops: bool) -> Result<Throttle, String> {
    let bad = || format!("invalid device limit `{s}`");
    let (path, rate) = s.rsplit_once(':').ok_or_else(bad)?;
    let rate = if iops {
        rate.parse().map_err(|_| bad())?
    } else {
        parse_size(rate).ok_or_else(bad)?
    };
    throttle(path, rate)
}

/// A size in podman's syntax (go-units `RAMInBytes`, see
/// `velarx_proto::size`): `512`, `64k`, `1.5m`, `2gib`.
pub fn parse_size(s: &str) -> Option<u64> {
    let n = velarx_proto::size::ram_in_bytes(s.trim()).ok()?;
    u64::try_from(n).ok()
}

/// `--personality`
pub fn parse_personality(s: &str) -> Result<String, String> {
    match s.to_ascii_uppercase().as_str() {
        p @ ("LINUX" | "LINUX32") => Ok(p.to_string()),
        _ => Err(format!("invalid personality `{s}`: LINUX or LINUX32")),
    }
}

/// `--rootfs-propagation`
pub fn parse_propagation(s: &str) -> Result<String, String> {
    const VALID: [&str; 8] = [
        "shared",
        "rshared",
        "slave",
        "rslave",
        "private",
        "rprivate",
        "unbindable",
        "runbindable",
    ];
    VALID
        .contains(&s)
        .then(|| s.to_string())
        .ok_or_else(|| format!("invalid rootfs propagation `{s}`"))
}

fn push_mount(spec: &mut Value, m: Value) {
    match spec["mounts"].as_array_mut() {
        Some(a) => a.push(m),
        None => spec["mounts"] = json!([m]),
    }
}

fn remove_mounts(spec: &mut Value, dests: &[&str]) {
    if let Some(a) = spec["mounts"].as_array_mut() {
        a.retain(|m| {
            !m["destination"]
                .as_str()
                .is_some_and(|d| dests.contains(&d))
        });
    }
}

fn has_mount(spec: &Value, dest: &str) -> bool {
    spec["mounts"]
        .as_array()
        .is_some_and(|m| m.iter().any(|m| m["destination"] == dest))
}

fn set_namespace(spec: &mut Value, typ: &str, mode: &str) {
    let ns = &mut spec["linux"]["namespaces"];
    if !ns.is_array() {
        *ns = json!([]);
    }
    let Some(list) = ns.as_array_mut() else {
        return;
    };
    list.retain(|n| n["type"] != typ);
    match mode {
        "host" => {}
        "" => list.push(json!({"type": typ})),
        path => list.push(json!({"type": typ, "path": path})),
    }
}

fn resources(spec: &mut Value) -> &mut Value {
    let r = &mut spec["linux"]["resources"];
    if !r.is_object() {
        *r = json!({});
    }
    r
}

/// Give the container `devices` and the cgroup rules `device_rules`: nodes
/// with a rule allowing each, or bind mounts when `bind` (a user namespace
/// cannot make nodes, and has no device cgroup).  A device whose path is a
/// mount or a node already is left as it is.
pub fn add_devices(
    spec: &mut Value,
    devices: &[HostDevice],
    bind: bool,
    device_rules: &[DeviceRule],
) {
    let mut rules = Vec::new();
    let mut nodes: Vec<Value> = spec["linux"]["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let added = nodes.len();
    for d in devices {
        if has_mount(spec, &d.path) || nodes.iter().any(|n| n["path"] == d.path.as_str()) {
            continue;
        }
        // A node made in the root file system may not open (a root can be
        // `nodev`, the device nodes of an image are not to open): outside
        // `/dev`, whose tmpfs is not, the device is a bind mount of the
        // host's node, with its cgroup rule.
        if bind || !d.path.starts_with("/dev/") {
            push_mount(
                spec,
                json!({"destination": d.path, "type": "bind", "source": d.host,
                "options": ["rbind", "nosuid", "noexec"]}),
            );
            if !bind {
                if let (Some(access), "b" | "c") = (&d.access, d.typ.as_str()) {
                    rules.push(
                        json!({"allow": true, "type": d.typ, "major": d.major, "minor": d.minor,
                        "access": access}),
                    );
                }
            }
            continue;
        }
        nodes.push(
            json!({"path": d.path, "type": d.typ, "major": d.major, "minor": d.minor,
            "fileMode": d.mode, "uid": d.uid.unwrap_or(0), "gid": d.gid.unwrap_or(0)}),
        );
        if let Some(access) = &d.access {
            if matches!(d.typ.as_str(), "b" | "c") {
                rules.push(
                    json!({"allow": true, "type": d.typ, "major": d.major, "minor": d.minor,
                    "access": access}),
                );
            }
        }
    }
    if nodes.len() > added {
        spec["linux"]["devices"] = Value::Array(nodes);
    }
    for r in device_rules {
        let mut rule = json!({"allow": true, "type": r.typ, "access": r.access});
        if let Some(m) = r.major {
            rule["major"] = json!(m);
        }
        if let Some(m) = r.minor {
            rule["minor"] = json!(m);
        }
        rules.push(rule);
    }
    // The allows go after the default list of the runtime (all denied, then
    // podman's devices); a privileged container has no list: every device.
    if !bind {
        let list = spec
            .get_mut("linux")
            .and_then(|l| l.get_mut("resources"))
            .and_then(|r| r.get_mut("devices"))
            .and_then(Value::as_array_mut);
        if let Some(list) = list {
            list.extend(rules);
        }
    }
}

pub use velarx_base::cdi::split_cdi_device;

/// Write the options into the spec (its JSON); `rootless` is a daemon in a
/// user namespace, which cannot mount /proc for the PID namespace of the
/// host or own the IPC one.
pub fn apply(
    spec: &mut Value,
    o: &CreateOptions,
    rootless: bool,
) -> Result<(), velarx_base::ids::IdsError> {
    let mut rlimits = default_rlimits()?;
    for r in &o.rlimits {
        rlimits.retain(|x| x.typ != r.typ);
        rlimits.push(r.clone());
    }
    spec["process"]["rlimits"] = rlimits
        .iter()
        .map(|r| json!({"type": r.typ, "soft": r.soft, "hard": r.hard}))
        .collect();

    if !o.annotations.is_empty() {
        if !spec["annotations"].is_object() {
            spec["annotations"] = json!({});
        }
        for (k, v) in &o.annotations {
            spec["annotations"][k] = json!(v);
        }
    }

    if !o.cgroup_ns.is_empty() || spec["linux"]["namespaces"].is_array() {
        set_namespace(spec, "cgroup", &o.cgroup_ns);
    }
    // systemd: its tmpfs, before the mounts of the user (who may mount
    // one of them) and of the engine (/run/.containerenv, the secrets)
    if o.systemd {
        let mut opts = vec!["rw", "rprivate", "nosuid", "nodev", "tmpcopyup"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        if let Some(size) = o.systemd_tmpfs_size {
            opts.push(format!("size={}k", size.div_ceil(1024)));
        }
        let mut add = Vec::new();
        for dest in SYSTEMD_TMPFS {
            if !has_mount(spec, dest) {
                add.push(json!({"destination": dest, "type": "tmpfs", "source": "tmpfs", "options": opts}));
            }
        }
        insert_after_defaults(spec, add);
    }

    // the cgroup of the container, read only, as podman mounts it
    if !has_mount(spec, "/sys/fs/cgroup") {
        // writable for --privileged and for systemd, as podman; but in the
        // cgroup namespace of the host that would be the whole hierarchy of
        // the host (podman binds the container's own cgroup there)
        let mode = if o.privileged || (o.systemd && o.cgroup_ns != "host") {
            "rw"
        } else {
            "ro"
        };
        let m = match o.cgroup_ns.as_str() {
            "host" => json!({"destination": "/sys/fs/cgroup", "type": "bind",
                "source": "/sys/fs/cgroup", "options": ["rbind", "nosuid", "noexec", "nodev", mode]}),
            _ => json!({"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup",
                "options": ["rprivate", "nosuid", "noexec", "nodev", "relatime", mode]}),
        };
        push_mount(spec, m);
    }
    if !o.pid_ns.is_empty() {
        set_namespace(spec, "pid", &o.pid_ns);
        // procfs is mounted only by the owner of the PID namespace
        if o.pid_ns == "host" && rootless {
            remove_mounts(spec, &["/proc"]);
            push_mount(
                spec,
                json!({"destination": "/proc", "type": "bind", "source": "/proc",
                "options": ["rbind", "nosuid", "noexec", "nodev"]}),
            );
        }
    }
    if !o.ipc_ns.is_empty() {
        set_namespace(spec, "ipc", &o.ipc_ns);
        if o.ipc_ns == "host" {
            remove_mounts(spec, &["/dev/shm", "/dev/mqueue"]);
            push_mount(
                spec,
                json!({"destination": "/dev/shm", "type": "bind", "source": "/dev/shm",
                "options": ["rbind", "nosuid", "noexec", "nodev"]}),
            );
            if Path::new("/dev/mqueue").exists() {
                push_mount(
                    spec,
                    json!({"destination": "/dev/mqueue", "type": "bind",
                    "source": "/dev/mqueue", "options": ["rbind", "nosuid", "noexec", "nodev"]}),
                );
            }
        }
    }
    if o.no_shm {
        remove_mounts(spec, &["/dev/shm"]);
    }
    if !o.uts_ns.is_empty() {
        set_namespace(spec, "uts", &o.uts_ns);
        // the hostname belongs to the namespace that is joined
        if let Some(s) = spec.as_object_mut() {
            s.remove("hostname");
            s.remove("domainname");
        }
    }

    if let Some(size) = o.shm_size {
        let mounts = spec["mounts"].as_array_mut().into_iter().flatten();
        for m in mounts.filter(|m| m["destination"] == "/dev/shm" && m["type"] == "tmpfs") {
            let mut opts: Vec<Value> = m["options"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter(|x| !x.as_str().is_some_and(|x| x.starts_with("size=")))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            opts.push(json!(format!("size={}k", size.div_ceil(1024))));
            m["options"] = Value::Array(opts);
        }
    }

    if o.read_only_tmpfs && spec["root"]["readonly"] == true {
        // before the mounts below them (/run/.containerenv, the secrets,
        // the init binary), which they would hide
        let add: Vec<Value> = ["/tmp", "/var/tmp", "/run"]
            .into_iter()
            .filter(|dir| !has_mount(spec, dir))
            .map(|dir| {
                json!({"destination": dir, "type": "tmpfs", "source": "tmpfs",
                    "options": ["rw", "nosuid", "nodev", "mode=1777"]})
            })
            .collect();
        insert_after_defaults(spec, add);
    }

    if let Some(p) = &o.personality {
        spec["linux"]["personality"] = json!({"domain": p});
    }
    if let Some(c) = &o.rdt_class {
        spec["linux"]["intelRdt"] = json!({"closID": c});
    }
    if let Some(p) = o
        .rootfs_propagation
        .clone()
        .or_else(|| volume_propagation(spec))
    {
        spec["linux"]["rootfsPropagation"] = json!(p);
    }

    add_devices(spec, &o.devices, o.bind_devices, &o.device_rules);

    if o.oom_kill_disable {
        resources(spec)["memory"]["disableOOMKiller"] = json!(true);
    }
    let throttles = |t: &[Throttle]| -> Value {
        t.iter()
            .map(|t| json!({"major": t.major, "minor": t.minor, "rate": t.rate}))
            .collect()
    };
    let mut blkio = serde_json::Map::new();
    if let Some(w) = o.blkio_weight {
        blkio.insert("weight".into(), json!(w));
    }
    if !o.weight_devices.is_empty() {
        blkio.insert(
            "weightDevice".into(),
            o.weight_devices
                .iter()
                .map(|d| json!({"major": d.major, "minor": d.minor, "weight": d.weight}))
                .collect(),
        );
    }
    for (k, t) in [
        ("throttleReadBpsDevice", &o.read_bps),
        ("throttleWriteBpsDevice", &o.write_bps),
        ("throttleReadIOPSDevice", &o.read_iops),
        ("throttleWriteIOPSDevice", &o.write_iops),
    ] {
        if !t.is_empty() {
            blkio.insert(k.into(), throttles(t));
        }
    }
    if !blkio.is_empty() {
        resources(spec)["blockIO"] = Value::Object(blkio);
    }
    if !o.unified.is_empty() {
        resources(spec)["unified"] = json!(o.unified);
    }
    if !o.hugepages.is_empty() {
        resources(spec)["hugepageLimits"] = o
            .hugepages
            .iter()
            .map(|(size, limit)| json!({"pageSize": size, "limit": limit}))
            .collect();
    }
    Ok(())
}

/// The value of `$KEY` or `${KEY}` references in `value`, from `env`.
fn expand(value: &str, env: &[String]) -> String {
    let lookup = |k: &str| {
        env.iter()
            .rev()
            .find_map(|e| e.strip_prefix(k)?.strip_prefix('='))
            .unwrap_or("")
    };
    let mut out = String::new();
    let mut rest = value;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let (name, tail) = if let Some(r) = rest.strip_prefix('{') {
            match r.find('}') {
                Some(end) => (&r[..end], &r[end + 1..]),
                None => ("", rest),
            }
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        if name.is_empty() {
            out.push('$');
        } else {
            out.push_str(lookup(name));
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Set a variable, in its place when it is there already.
fn set_var(env: &mut Vec<String>, kv: &str) {
    let key = kv.split('=').next().unwrap_or(kv);
    match env.iter_mut().find(|e| e.split('=').next() == Some(key)) {
        Some(e) => *e = kv.to_string(),
        None => env.push(kv.to_string()),
    }
}

/// What the environment of a container is made of, in podman's order.
#[derive(Debug, Default)]
pub struct EnvSources<'a> {
    pub image: &'a [String],
    /// `-e` (entries without `=` are ignored: the client resolves them)
    pub user: &'a [String],
    pub merge: &'a [String],
    pub unset: &'a [String],
    pub unset_all: bool,
    pub tty: bool,
    pub hostname: &'a str,
}

/// The environment: the defaults (PATH, TERM with a terminal, container,
/// HOSTNAME) under the image under `--env-merge` under `-e`; `--unsetenv`
/// removes from the first three, `--unsetenv-all` drops them, HOSTNAME is
/// always there.
pub fn merge_env(s: &EnvSources<'_>) -> Vec<String> {
    let mut env = Vec::new();
    if !s.unset_all {
        for e in s.image.iter().filter(|e| e.contains('=')) {
            set_var(&mut env, e);
        }
        let has = |env: &[String], k: &str| env.iter().any(|e| e.split('=').next() == Some(k));
        if !has(&env, "PATH") {
            env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
        }
        if s.tty && !has(&env, "TERM") {
            env.push("TERM=xterm".into());
        }
        // podman's default, under the image's (Fedora's says `oci`): tools
        // and images test it (systemd-detect-virt, toolbox, scripts), and
        // velarx runs what podman runs
        if !has(&env, "container") {
            env.push("container=podman".into());
        }
    }
    for k in s.unset {
        env.retain(|e| e.split('=').next() != Some(k.as_str()));
    }
    for m in s.merge {
        let v = expand(m, &env);
        if v.contains('=') {
            set_var(&mut env, &v);
        }
    }
    for e in s.user.iter().filter(|e| e.contains('=')) {
        set_var(&mut env, e);
    }
    // as podman, even with --unsetenv and --unsetenv-all
    if !env.iter().any(|e| e.starts_with("HOSTNAME=")) {
        env.push(format!("HOSTNAME={}", s.hostname));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment() {
        let image = ["PATH=/img".to_string(), "A=1".into(), "B=2".into()];
        let user = ["A=u".to_string(), "NOVALUE".into()];
        let merge = ["PATH=${PATH}:/extra".to_string(), "C=$B-$NONE".into()];
        let unset = ["B".to_string()];
        let s = EnvSources {
            image: &image,
            user: &user,
            merge: &merge,
            unset: &unset,
            tty: true,
            hostname: "h",
            ..Default::default()
        };
        assert_eq!(
            merge_env(&s),
            [
                "PATH=/img:/extra",
                "A=u",
                "TERM=xterm",
                "container=podman",
                "C=-",
                "HOSTNAME=h"
            ]
        );
        let s = EnvSources {
            image: &image,
            user: &user,
            unset_all: true,
            ..Default::default()
        };
        assert_eq!(merge_env(&s), ["A=u", "HOSTNAME="]);
        let s = EnvSources {
            image: &[],
            hostname: "x",
            ..Default::default()
        };
        assert!(merge_env(&s)[0].starts_with("PATH=/usr/local/sbin"));
        assert_eq!(expand("${A}x$A.${", &["A=1".to_string()]), "1x1.${");
        assert_eq!(expand("$", &[]), "$");
    }

    #[test]
    fn ulimits() {
        let r = rlimit("nofile", 1024, 2048).unwrap();
        assert_eq!(
            (r.typ.as_str(), r.soft, r.hard),
            ("RLIMIT_NOFILE", 1024, 2048)
        );
        assert_eq!(
            rlimit("RLIMIT_CORE", 0, u64::MAX).unwrap().typ,
            "RLIMIT_CORE"
        );
        assert!(rlimit("nofile", 2, 1).is_err());
        assert!(rlimit("bogus", 1, 1).is_err());
        assert_eq!(limit_value("-1"), Some(u64::MAX));
        assert_eq!(limit_value("unlimited"), Some(u64::MAX));
        assert_eq!(limit_value("x"), None);
        let d = default_rlimits().unwrap();
        assert_eq!(d[0].typ, "RLIMIT_NOFILE");
        assert!(d.iter().all(|r| r.soft == r.hard && r.hard > 0));
    }

    #[test]
    fn devices() {
        let d = resolve_device("/dev/null", "/dev/mynull", "rw").unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].typ.as_str(), d[0].major, d[0].minor), ("c", 1, 3));
        assert_eq!(d[0].access.as_deref(), Some("rw"));
        assert!(resolve_device("/etc/passwd", "/x", "rwm").is_err());
        assert!(resolve_device("/dev/null", "/x", "rwx").is_err());
        assert!(resolve_device("dev/null", "/x", "r").is_err());
        assert!(resolve_device("/nonexistent", "/x", "r").is_err());
        let p = privileged_devices(false, false);
        assert!(p.iter().any(|d| d.path == "/dev/null"));
        assert!(!p.iter().any(|d| d.path.starts_with("/dev/pts/")));
        // as a rootless one binds them: no ptmx, no console
        let p = privileged_devices(true, false);
        assert!(p.iter().any(|d| d.path == "/dev/null"));
        assert!(!p
            .iter()
            .any(|d| d.path == "/dev/ptmx" || d.path == "/dev/tty"));
        assert!(!p.iter().any(|d| d
            .path
            .strip_prefix("/dev/tty")
            .is_some_and(|n| n.parse::<u32>().is_ok())));
    }

    #[test]
    fn hugepages() {
        assert!(hugepage_limit("bogus", 1).is_err());
        assert!(hugepage_limit("3MB", 1).is_err());
        if Path::new("/sys/kernel/mm/hugepages/hugepages-2048kB").exists() {
            assert_eq!(
                hugepage_limit("2MB", 4 << 20),
                Ok(("2MB".to_string(), 4 << 20))
            );
            assert_eq!(hugepage_limit("2m", 1).unwrap().0, "2MB");
            let o = CreateOptions {
                hugepages: vec![hugepage_limit("2MB", 4 << 20).unwrap()],
                ..Default::default()
            };
            let mut s = json!({"linux": {}});
            apply(&mut s, &o, false).unwrap();
            assert_eq!(
                s["linux"]["resources"]["hugepageLimits"],
                json!([{"pageSize": "2MB", "limit": 4 << 20}])
            );
        }
    }

    #[test]
    fn rules_and_sizes() {
        let r = parse_device_rule("c 1:3 rwm").unwrap();
        assert_eq!((r.major, r.minor), (Some(1), Some(3)));
        let r = parse_device_rule("b *:* r").unwrap();
        assert_eq!((r.major, r.minor), (None, None));
        let r = parse_device_rule("a 7 rmw").unwrap();
        assert_eq!((r.major, r.minor), (Some(7), None));
        for bad in ["", "x 1:3 r", "c 1:3 q", "c a:3 r", "c 1:3"] {
            assert!(parse_device_rule(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_device_rule("b 7:* rmX").unwrap_err(),
            "invalid device access in device-access-add: X"
        );
        assert_eq!(parse_size("64m"), Some(64 << 20));
        assert_eq!(parse_size("1kb"), Some(1024));
        assert_eq!(parse_size("10"), Some(10));
        assert_eq!(parse_size("1G"), Some(1 << 30));
        assert_eq!(parse_size("x"), None);
        assert_eq!(parse_size("99999999999999999999t"), None);
        assert_eq!(parse_personality("linux32").unwrap(), "LINUX32");
        assert!(parse_personality("bsd").is_err());
        assert!(parse_propagation("rslave").is_ok());
        assert!(parse_propagation("weird").is_err());
    }

    fn base() -> Value {
        json!({
            "root": {"path": "/r", "readonly": true},
            "hostname": "h",
            "process": {"user": {"uid": 0, "gid": 0}, "cwd": "/"},
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {"destination": "/dev/shm", "type": "tmpfs", "source": "shm",
                 "options": ["nosuid", "size=65536k"]},
                {"destination": "/tmp", "type": "bind", "source": "/x"}
            ],
            "linux": {
                "namespaces": [{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}],
                "resources": {"devices": [
                    {"allow": false, "access": "rwm"},
                    {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"}
                ]}
            }
        })
    }

    #[test]
    fn apply_options() {
        let o = CreateOptions {
            rlimits: vec![rlimit("nofile", 10, 20).unwrap()],
            annotations: [("a".to_string(), "b".to_string())].into(),
            pid_ns: "host".into(),
            uts_ns: "/proc/7/ns/uts".into(),
            shm_size: Some(1 << 20),
            read_only_tmpfs: true,
            personality: Some("LINUX32".into()),
            rdt_class: Some("gold".into()),
            oom_kill_disable: true,
            blkio_weight: Some(300),
            weight_devices: vec![weight_device("", Some((8, 16)), 100).unwrap()],
            devices: resolve_device("/dev/null", "/dev/n", "rw").unwrap(),
            device_rules: vec![parse_device_rule("c 10:200 rwm").unwrap()],
            unified: [("memory.high".to_string(), "1G".to_string())].into(),
            ..Default::default()
        };
        let mut s = base();
        apply(&mut s, &o, true).unwrap();
        let nofile = s["process"]["rlimits"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["type"] == "RLIMIT_NOFILE")
            .unwrap();
        assert_eq!(
            (nofile["soft"].as_u64(), nofile["hard"].as_u64()),
            (Some(10), Some(20))
        );
        assert_eq!(s["annotations"]["a"], "b");
        let ns: Vec<Value> = s["linux"]["namespaces"].as_array().unwrap().clone();
        assert!(!ns.iter().any(|n| n["type"] == "pid"));
        assert!(ns.contains(&json!({"type": "uts", "path": "/proc/7/ns/uts"})));
        assert!(ns.contains(&json!({"type": "cgroup"})));
        assert!(s["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["destination"] == "/sys/fs/cgroup" && m["type"] == "cgroup"));
        assert!(s.get("hostname").is_none());
        let proc = s["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/proc")
            .unwrap();
        assert_eq!(proc["type"], "bind");
        let shm = s["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/dev/shm")
            .unwrap();
        assert_eq!(shm["options"], json!(["nosuid", "size=1024k"]));
        // /tmp is mounted already, /var/tmp and /run get a tmpfs
        let dests: Vec<&str> = s["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|m| m["destination"].as_str())
            .collect();
        assert_eq!(dests.iter().filter(|d| **d == "/tmp").count(), 1);
        assert!(dests.contains(&"/var/tmp") && dests.contains(&"/run"));
        assert_eq!(s["linux"]["personality"]["domain"], "LINUX32");
        assert_eq!(s["linux"]["intelRdt"]["closID"], "gold");
        assert_eq!(s["linux"]["devices"][0]["path"], "/dev/n");
        let rules = s["linux"]["resources"]["devices"].as_array().unwrap();
        // after the default list
        assert_eq!(rules[0], json!({"allow": false, "access": "rwm"}));
        assert_eq!(rules[1]["minor"], 3);
        assert_eq!(rules.len(), 4);
        assert_eq!(
            (rules[3]["major"].as_i64(), rules[3]["minor"].as_i64()),
            (Some(10), Some(200))
        );
        assert_eq!(s["linux"]["resources"]["memory"]["disableOOMKiller"], true);
        assert_eq!(s["linux"]["resources"]["blockIO"]["weight"], 300);
        assert_eq!(
            s["linux"]["resources"]["blockIO"]["weightDevice"],
            json!([{"major": 8, "minor": 16, "weight": 100}])
        );
        assert_eq!(s["linux"]["resources"]["unified"]["memory.high"], "1G");
        // the spec types accept the result
        let spec: oci_spec::runtime::Spec = serde_json::from_value(s).unwrap();
        assert!(spec.linux().is_some());

        // privileged: no list, none is made; the cgroup is writable
        let o = CreateOptions {
            devices: resolve_device("/dev/null", "/dev/n", "rw").unwrap(),
            device_rules: vec![parse_device_rule("c 10:200 rwm").unwrap()],
            privileged: true,
            pid_ns: "container:abc".into(),
            ..Default::default()
        };
        let mut s = base();
        s["linux"].as_object_mut().unwrap().remove("resources");
        apply(&mut s, &o, false).unwrap();
        assert!(s["linux"]["resources"].get("devices").is_none());
        let cg = s["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/sys/fs/cgroup")
            .unwrap();
        assert!(cg["options"].as_array().unwrap().contains(&json!("rw")));
        // the start puts the namespace of the target there
        assert!(s["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .contains(&json!({"type": "pid", "path": "container:abc"})));

        // in a user namespace devices are bind mounted, IPC of the host binds /dev/shm
        let o = CreateOptions {
            devices: resolve_device("/dev/null", "/dev/n", "rw").unwrap(),
            ipc_ns: "host".into(),
            bind_devices: true,
            ..Default::default()
        };
        let mut s = base();
        apply(&mut s, &o, true).unwrap();
        assert!(s["linux"].get("devices").is_none());
        let m = s["mounts"].as_array().unwrap();
        assert!(m
            .iter()
            .any(|m| m["destination"] == "/dev/n" && m["source"] == "/dev/null"));
        assert!(m
            .iter()
            .any(|m| m["destination"] == "/dev/shm" && m["type"] == "bind"));
    }

    #[test]
    fn ipc_none_has_no_dev_shm() {
        let shm = |s: &Value| {
            s["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["destination"] == "/dev/shm")
        };
        let mut s = base();
        assert!(shm(&s));
        apply(
            &mut s,
            &CreateOptions {
                no_shm: true,
                shm_size: Some(1 << 20),
                ..Default::default()
            },
            false,
        )
        .unwrap();
        assert!(!shm(&s));
    }

    #[test]
    fn systemd_detection() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for init in [
            "/sbin/init",
            "/usr/sbin/init",
            "/usr/local/sbin/init",
            "/usr/lib/systemd/systemd",
            "systemd",
        ] {
            assert_eq!(systemd_mode(None, &v(&[init])), Ok(true), "{init}");
        }
        assert_eq!(
            systemd_mode(None, &v(&["/bin/sh", "-c", "/sbin/init", "x"])),
            Ok(true)
        );
        assert_eq!(systemd_mode(Some("true"), &v(&["sh"])), Ok(false));
        assert_eq!(systemd_mode(None, &v(&["/bin/init"])), Ok(false));
        assert_eq!(systemd_mode(None, &v(&["systemd-tmpfiles"])), Ok(false));
        assert_eq!(systemd_mode(None, &[]), Ok(false));
        assert_eq!(systemd_mode(Some("false"), &v(&["/sbin/init"])), Ok(false));
        assert_eq!(systemd_mode(Some("always"), &v(&["sh"])), Ok(true));
        assert!(systemd_mode(Some("yes"), &v(&["sh"])).is_err());
    }

    #[test]
    fn container_variable_under_the_image() {
        let image = vec!["container=oci".to_string()];
        let s = EnvSources {
            image: &image,
            hostname: "h",
            ..Default::default()
        };
        assert!(merge_env(&s).contains(&"container=oci".to_string()));
        let s = EnvSources {
            hostname: "h",
            ..Default::default()
        };
        assert!(merge_env(&s).contains(&"container=podman".to_string()));
    }

    #[test]
    fn systemd_mounts() {
        let tmpfs = |s: &Value| -> Vec<String> {
            s["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| {
                    m["type"] == "tmpfs"
                        && m["options"]
                            .as_array()
                            .unwrap()
                            .contains(&json!("tmpcopyup"))
                })
                .map(|m| m["destination"].as_str().unwrap().to_string())
                .collect()
        };
        let cgroup_rw = |s: &Value| {
            s["mounts"].as_array().unwrap().iter().any(|m| {
                m["destination"] == "/sys/fs/cgroup"
                    && m["options"].as_array().unwrap().contains(&json!("rw"))
            })
        };
        // not systemd: none of it
        let mut s = base();
        apply(&mut s, &CreateOptions::default(), false).unwrap();
        assert!(tmpfs(&s).is_empty());
        assert!(!cgroup_rw(&s));

        // systemd: the four tmpfs after the default mounts and before the
        // user's (a /tmp of the user is kept), sized, the cgroup writable
        let mut s = base();
        let o = CreateOptions {
            systemd: true,
            systemd_tmpfs_size: Some(1 << 20),
            ..Default::default()
        };
        apply(&mut s, &o, false).unwrap();
        assert_eq!(tmpfs(&s), ["/run", "/run/lock", "/var/log/journal"]);
        let m = s["mounts"].as_array().unwrap();
        let at = |d: &str| m.iter().position(|m| m["destination"] == d).unwrap();
        assert!(at("/run") < at("/tmp") && at("/dev/shm") < at("/run"));
        assert!(m[at("/run")]["options"]
            .as_array()
            .unwrap()
            .contains(&json!("size=1024k")));
        assert!(cgroup_rw(&s));
        // not the hierarchy of the host
        let mut s = base();
        let o = CreateOptions {
            systemd: true,
            cgroup_ns: "host".into(),
            ..Default::default()
        };
        apply(&mut s, &o, false).unwrap();
        assert!(!cgroup_rw(&s));
    }

    #[test]
    fn root_propagation_from_the_volumes() {
        let with = |opts: &[&[&str]]| {
            let mut s = base();
            for o in opts {
                s["mounts"].as_array_mut().unwrap().push(
                    json!({"destination": "/v", "type": "bind", "source": "/s", "options": o}),
                );
            }
            apply(&mut s, &CreateOptions::default(), false).unwrap();
            s["linux"]["rootfsPropagation"].as_str().map(str::to_string)
        };
        assert_eq!(with(&[&["rbind"]]), None);
        assert_eq!(with(&[&["rbind", "rslave"]]).as_deref(), Some("rslave"));
        assert_eq!(
            with(&[&["rbind", "rslave"], &["rbind", "rshared"]]).as_deref(),
            Some("shared")
        );
        assert_eq!(
            with(&[&["rbind", "shared"], &["rbind", "slave"]]).as_deref(),
            Some("shared")
        );
        // the option of the user wins
        let mut s = base();
        s["mounts"].as_array_mut().unwrap().push(
            json!({"destination": "/v", "type": "bind", "source": "/s", "options": ["rshared"]}),
        );
        let o = CreateOptions {
            rootfs_propagation: Some("private".into()),
            ..Default::default()
        };
        apply(&mut s, &o, false).unwrap();
        assert_eq!(s["linux"]["rootfsPropagation"], "private");
    }

    #[test]
    fn read_only_tmpfs_under_the_mounts_below_them() {
        let mut s = base();
        s["root"]["readonly"] = json!(true);
        s["mounts"].as_array_mut().unwrap().push(
            json!({"destination": "/run/.containerenv", "type": "bind", "source": "/b/env", "options": ["rbind"]}),
        );
        let o = CreateOptions {
            read_only_tmpfs: true,
            ..Default::default()
        };
        apply(&mut s, &o, false).unwrap();
        let m = s["mounts"].as_array().unwrap();
        let at = |d: &str| m.iter().position(|m| m["destination"] == d).unwrap();
        assert!(at("/run") < at("/run/.containerenv"));
        assert!(at("/var/tmp") < at("/run/.containerenv"));
        // the user's /tmp is kept, no tmpfs over it
        assert_eq!(m.iter().filter(|m| m["destination"] == "/tmp").count(), 1);
    }

    #[test]
    fn a_device_outside_dev_is_a_bind_mount_with_its_rule() {
        let dev = |path: &str| HostDevice {
            host: "/dev/null".into(),
            path: path.into(),
            typ: "c".into(),
            major: 1,
            minor: 3,
            mode: 0o666,
            access: Some("rwm".into()),
            uid: None,
            gid: None,
        };
        let mut s =
            json!({"linux": {"resources": {"devices": [{"allow": false, "access": "rwm"}]}}});
        add_devices(&mut s, &[dev("/dev/in"), dev("/mnt/out")], false, &[]);
        // the node in /dev is made by the runtime, on the tmpfs of /dev; the
        // other one is a bind mount: a node made in the root may open
        // nothing (a `nodev` root)
        let nodes = s["linux"]["devices"].as_array().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0]["path"], "/dev/in");
        let m = s["mounts"].as_array().unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["destination"], "/mnt/out");
        assert_eq!(m[0]["source"], "/dev/null");
        assert!(!m[0]["options"].to_string().contains("nodev"));
        // both have their rule in the device cgroup
        let rules = s["linux"]["resources"]["devices"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert!(rules[1..]
            .iter()
            .all(|r| r["allow"] == true && r["minor"] == 3));
    }

    #[test]
    fn durations() {
        assert_eq!(
            velarx_proto::duration::parse_go_duration_ns("1m"),
            Some(60_000_000_000)
        );
        assert_eq!(
            velarx_proto::duration::parse_go_duration_ns("1h30m"),
            Some(5_400_000_000_000)
        );
        assert_eq!(
            velarx_proto::duration::parse_go_duration_ns("1.5s"),
            Some(1_500_000_000)
        );
        assert_eq!(
            velarx_proto::duration::parse_go_duration_ns("10ms"),
            Some(10_000_000)
        );
        assert_eq!(velarx_proto::duration::parse_go_duration_ns("5"), None);
        assert_eq!(velarx_proto::duration::parse_go_duration_ns(""), None);
    }
}
