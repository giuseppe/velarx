// SPDX-License-Identifier: Apache-2.0
//! The create bodies (podman's SpecGenerator, Docker's container config) to
//! the services' `CreateContainerRequest`.

use super::error::{ApiError, ApiResult};
use crate::api::AppState;
use serde_json::Value;
use std::collections::HashMap;
use velarx_core::services::MountSpec;
use velarx_proto::health::{Healthcheck, OnFailure, StartupHealthcheck};
use velarx_wire::addr::PortSpec;
use velarx_wire::request::MountConfig;
use velarx_wire::request::{
    CgroupsMode, CreateContainerRequest, DeviceMapping, HugepageLimit, NetworkMode, NsMode,
    PortMapping, ResourceLimits, RestartPolicy, SecretRef, ThrottleDevice, Ulimit, UsernsChoice,
    WeightDevice,
};

/// The member `k` of the object `v`.  Like Go's decoder, which podman's
/// handlers use, an exact match wins and the case of the name does not
/// matter otherwise (`{"Image": ...}` is a SpecGenerator's `image`).
pub fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    let o = v.as_object()?;
    o.get(k).or_else(|| {
        o.iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(k))
            .map(|(_, v)| v)
    })
}

pub fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    field(v, k).unwrap_or(&Value::Null)
}

pub fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    field(v, k).and_then(Value::as_str).unwrap_or("")
}

pub fn b(v: &Value, k: &str) -> bool {
    field(v, k).and_then(Value::as_bool).unwrap_or(false)
}

pub fn i(v: &Value, k: &str) -> i64 {
    field(v, k).and_then(Value::as_i64).unwrap_or(0)
}

pub fn strs(v: &Value, k: &str) -> Vec<String> {
    field(v, k)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    field(v, k)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Whether a setting has a value: null, false, zero, an empty string, list
/// or object is none.
pub fn is_set(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => o.values().any(is_set),
    }
}

/// Refuses, naming it, a member of the object `v` (`scope` is where it is,
/// empty at the top) that velarx has no support for when it has a value.
pub fn refuse_members(v: &Value, scope: &str, names: &[&str]) -> ApiResult<()> {
    for name in names {
        if field(v, name).is_some_and(is_set) {
            let at = if scope.is_empty() {
                name.to_string()
            } else {
                format!("{scope}.{name}")
            };
            return Err(ApiError::not_implemented(format!("{at} is not supported")));
        }
    }
    Ok(())
}

fn nonempty(v: &str) -> Option<String> {
    (!v.is_empty()).then(|| v.to_string())
}

fn kv_pairs(v: &Value) -> Vec<String> {
    match v {
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
            .collect(),
        _ => Vec::new(),
    }
}

fn kv_map(v: &Value) -> std::collections::BTreeMap<String, String> {
    match v {
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect(),
        _ => Default::default(),
    }
}

/// A binding of Docker's `PortBindings` as a [`parse_publish`] spec.  Its
/// `HostIp` of IPv6 has no brackets (`::1`), they are added.
fn binding_spec(host_ip: &str, host_port: &str, cport: &str, proto: &str) -> String {
    if host_ip.is_empty() {
        let spec = format!("{host_port}:{cport}/{proto}");
        spec.trim_start_matches(':').to_string()
    } else if host_ip.contains(':') && !host_ip.starts_with('[') {
        format!("[{host_ip}]:{host_port}:{cport}/{proto}")
    } else {
        format!("{host_ip}:{host_port}:{cport}/{proto}")
    }
}

/// `[[IP:]HOST[-END]:]CONTAINER[-END][/PROTO[,PROTO]]` to port mappings
/// (one per port and protocol): the reading of the command line's `-p`
/// (`velarx_wire::addr::PortSpec`), with the protocol list this API takes.
pub fn parse_publish(spec: &str) -> ApiResult<Vec<PortMapping>> {
    let bad = || ApiError::bad_request(format!("invalid port specification: {spec}"));
    let (addr, protos) = spec.rsplit_once('/').unwrap_or((spec, "tcp"));
    let mut out = Vec::new();
    for proto in protos.split(',') {
        let p = PortSpec::parse(&format!("{addr}/{proto}")).map_err(|_| bad())?;
        for k in 0..p.range {
            out.push(PortMapping {
                container_port: p.container_port + k,
                host_port: (p.host_port != 0).then(|| p.host_port + k),
                host_ip: p.host_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                protocol: p.proto.as_str().to_string(),
            });
        }
    }
    Ok(out)
}

/// A named volume is created when it does not exist.
async fn mount_from_spec(state: &AppState, spec: MountSpec) -> ApiResult<MountConfig> {
    Ok(state.volume_service.resolve_mount(spec).await?)
}

async fn add_volume_arg(
    state: &AppState,
    req: &mut CreateContainerRequest,
    arg: &str,
) -> ApiResult<()> {
    let spec = MountSpec::parse_volume_arg(arg)?;
    req.mounts.push(mount_from_spec(state, spec).await?);
    Ok(())
}

/// The options only a tmpfs takes (podman's ProcessOptions).
const TMPFS_ONLY: [&str; 6] = [
    "size",
    "mode",
    "tmpcopyup",
    "notmpcopyup",
    "noswap",
    "noatime",
];

fn invalid_mount_option(msg: String) -> ApiError {
    ApiError::internal(format!("{msg}: invalid mount option")).with_cause("invalid mount option")
}

/// A bind mount refuses the options of a tmpfs, as podman's.
fn check_bind_options(opts: &[String]) -> ApiResult<()> {
    for o in opts {
        let key = o.split('=').next().unwrap_or("");
        if TMPFS_ONLY.contains(&key) {
            return Err(invalid_mount_option(format!(
                "the '{key}' option is only allowed with tmpfs mounts"
            )));
        }
    }
    Ok(())
}

/// The options of a tmpfs as podman makes them: those asked, then
/// rprivate, nosuid, nodev and tmpcopyup unless their opposite was asked
/// (notmpcopyup is not passed on).
fn tmpfs_options(opts: &[String]) -> ApiResult<Vec<String>> {
    let mut out = Vec::new();
    let (mut prop, mut suid, mut dev, mut copyup) = (false, false, false, false);
    for o in opts.iter().filter(|o| !o.is_empty()) {
        match o.split('=').next().unwrap_or("") {
            "private" | "rprivate" | "slave" | "rslave" | "shared" | "rshared" | "unbindable"
            | "runbindable" => prop = true,
            "suid" | "nosuid" => suid = true,
            "dev" | "nodev" => dev = true,
            "tmpcopyup" => copyup = true,
            "notmpcopyup" => {
                copyup = true;
                continue;
            }
            "bind" | "rbind" | "z" | "Z" => {
                return Err(invalid_mount_option(format!(
                    "the '{o}' option is not allowed with tmpfs mounts"
                )))
            }
            _ => {}
        }
        out.push(o.clone());
    }
    for (asked, default) in [
        (prop, "rprivate"),
        (suid, "nosuid"),
        (dev, "nodev"),
        (copyup, "tmpcopyup"),
    ] {
        if !asked {
            out.push(default.to_string());
        }
    }
    Ok(out)
}

fn add_tmpfs(req: &mut CreateContainerRequest, dest: &str, opts: &str) -> ApiResult<()> {
    let opts: Vec<String> = opts.split(',').map(str::to_string).collect();
    req.mounts.push(MountConfig {
        source: "tmpfs".into(),
        target: dest.to_string(),
        mount_type: Some("tmpfs".into()),
        options: tmpfs_options(&opts)?,
        ..Default::default()
    });
    Ok(())
}

fn parse_device(path: &str) -> DeviceMapping {
    if !path.starts_with('/') {
        return DeviceMapping::cdi(path);
    }
    let mut p = path.splitn(3, ':');
    let host = p.next().unwrap_or("").to_string();
    let (ctr, perm) = match (p.next(), p.next()) {
        (Some(c), Some(m)) => (c.to_string(), m.to_string()),
        (Some(c), None)
            if c.chars().all(|x| "rwm".contains(x)) && !c.is_empty() && !c.starts_with('/') =>
        {
            (host.clone(), c.to_string())
        }
        (Some(c), None) => (c.to_string(), "rwm".into()),
        _ => (host.clone(), "rwm".into()),
    };
    DeviceMapping {
        path_on_host: host,
        path_in_container: ctr,
        cgroup_permissions: perm,
    }
}

/// A resource limit: a negative one is no limit.
pub fn limit(v: &Value) -> u64 {
    match v.as_i64() {
        Some(n) if n < 0 => u64::MAX,
        Some(n) => n as u64,
        None => v.as_u64().unwrap_or(0),
    }
}

/// Refuses a swappiness of the memory limits `mem` (`name` is where it is,
/// for the message): the kernel has none per cgroup.  Unset or negative
/// (podman's "not set", -1) is none.
fn refuse_swappiness(mem: &Value, key: &str, name: &str) -> ApiResult<()> {
    if field(mem, key)
        .and_then(Value::as_i64)
        .is_some_and(|v| v >= 0)
    {
        return Err(ApiError::not_implemented(format!(
            "{name} is not supported"
        )));
    }
    Ok(())
}

fn has_blkio(l: &ResourceLimits) -> bool {
    l.blkio_weight.is_some()
        || !l.blkio_weight_device.is_empty()
        || !l.blkio_device_read_bps.is_empty()
        || !l.blkio_device_write_bps.is_empty()
        || !l.blkio_device_read_iops.is_empty()
        || !l.blkio_device_write_iops.is_empty()
}

fn nanos_to_pid_limit(v: i64) -> Option<i64> {
    (v != 0).then_some(v)
}

/// A health check as podman keeps it (MakeHealthCheckFromCli): the `Test`
/// of Docker's form, `CMD ...`, `CMD-SHELL cmd` or `NONE` (`Some(None)`);
/// a bare command is `CMD` with its arguments, or `CMD-SHELL` when it is
/// one string.  An empty `Test` takes the image's command (and the times it
/// does not give); `None` is nothing to change.
///
/// What a zero time means depends on the caller.  Docker's clients (`compat`)
/// get podman's default times for a zero.  A libpod spec is kept as it is
/// when it has a command (specgen.CompleteSpec applies the overrides only
/// to the image's check): an `Interval` of 0 is no timer (the checks of
/// `healthcheck run` only, as `--health-interval=disable`), and 0 `Retries`
/// is an unhealthy container after the first failure (`FailingStreak >=
/// Retries`), and a `Timeout` of 0 is no timeout.  A spec without a
/// command (of either API) inherits the image's check, where 0 is "inherit"
/// and a negative `Interval` is the disable.
fn health_from(h: &Value, compat: bool) -> Option<Option<Healthcheck>> {
    let test = strs(h, "Test");
    let ns = |k: &str| i(h, k).max(0) as u64;
    let mut check = Healthcheck {
        test: Vec::new(),
        interval_ns: ns("Interval"),
        interval_disabled: test.is_empty() && i(h, "Interval") < 0,
        timeout_ns: ns("Timeout"),
        start_period_ns: ns("StartPeriod"),
        retries: i(h, "Retries").clamp(0, u32::MAX as i64) as u32,
        start_interval_ns: ns("StartInterval"),
        ..Default::default()
    };
    let Some(first) = test.first() else {
        let any = check.interval_ns != 0
            || check.interval_disabled
            || check.timeout_ns != 0
            || check.start_period_ns != 0
            || check.retries != 0
            || check.start_interval_ns != 0;
        return any.then_some(Some(check));
    };
    check.test = match first.to_uppercase().as_str() {
        "NONE" => return Some(None),
        "CMD" | "CMD-SHELL" => test,
        _ if test.len() > 1 => std::iter::once("CMD".to_string()).chain(test).collect(),
        _ => vec!["CMD-SHELL".to_string(), first.clone()],
    };
    if compat {
        const DEFAULT: u64 = 30_000_000_000;
        if check.interval_ns == 0 {
            check.interval_ns = DEFAULT;
        }
        if check.timeout_ns == 0 {
            check.timeout_ns = DEFAULT;
        }
        if check.retries == 0 {
            check.retries = 3;
        }
    } else {
        check.interval_disabled = check.interval_ns == 0;
    }
    Some(Some(check))
}

fn sig_name(v: &Value) -> String {
    match v {
        Value::Number(n) => n
            .as_i64()
            .filter(|n| *n > 0)
            .map(|n| super::lifecycle::signal_name(n as i32))
            .unwrap_or_default(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

/// `volumes_from` / `VolumesFrom`: the volumes and bind mounts of other
/// containers, `CONTAINER[:OPTIONS]`, before the mounts of the request,
/// which replace them at the same destination (a later container replaces
/// an earlier one).  Called once the mounts of the request are in `req`.
async fn volumes_from(
    state: &AppState,
    req: &mut CreateContainerRequest,
    list: &[String],
) -> ApiResult<()> {
    let clean = |d: &str| format!("/{}", d.trim_matches('/'));
    let mut taken: std::collections::HashSet<String> =
        req.mounts.iter().map(|m| clean(&m.target)).collect();
    for t in &req.tmpfs {
        taken.insert(clean(t.split(':').next().unwrap_or_default()));
    }
    for v in &req.volumes {
        let mut parts = v.split(':');
        let first = parts.next().unwrap_or_default();
        taken.insert(clean(parts.next().unwrap_or(first)));
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in list {
        let (name, options) = entry.split_once(':').unwrap_or((entry, ""));
        let info = super::containers::inspect_of(state, name, false)
            .await
            .map_err(|mut e| {
                if e.status == crate::api::status::StatusCode::NOT_FOUND {
                    e.message = format!(
                        "looking up container {name:?} for volumes-from: {}",
                        e.message
                    );
                }
                e
            })?;
        for (dest, arg) in velarx_wire::request::volumes_from_args(&info.mounts, options)
            .map_err(ApiError::bad_request)?
        {
            if taken.contains(&dest) {
                continue;
            }
            out.retain(|(d, _)| *d != dest);
            out.push((dest, arg));
        }
    }
    let mut mounts = Vec::new();
    for (_, arg) in out {
        let spec = MountSpec::parse_volume_arg(&arg)?;
        mounts.push(mount_from_spec(state, spec).await?);
    }
    req.mounts.splice(0..0, mounts);
    Ok(())
}

/// The network mode of `[containers] netns` (empty: the default
/// network).
fn default_network_mode(netns: &str) -> NetworkMode {
    match netns {
        "host" | "none" | "pasta" | "slirp4netns" => NetworkMode::parse(netns),
        _ => NetworkMode::Unset,
    }
}

/// The published ports of the spec: the numbers are ports, and a range ends
/// at 65535 at the latest.
fn port_mappings(spec: &Value, req: &mut CreateContainerRequest) -> ApiResult<()> {
    for p in arr(spec, "portmappings") {
        let proto = if s(p, "protocol").is_empty() {
            "tcp"
        } else {
            s(p, "protocol")
        };
        let num = |k: &str| -> ApiResult<u32> {
            u16::try_from(i(p, k))
                .map(u32::from)
                .map_err(|_| ApiError::bad_request(format!("invalid {k} in a port mapping")))
        };
        let (container, host, range) = (num("container_port")?, num("host_port")?, num("range")?);
        let range = range.max(1);
        if container + range > 65536 || (host != 0 && host + range > 65536) {
            return Err(ApiError::bad_request(
                "a port range of a port mapping goes past 65535",
            ));
        }
        for proto in proto.split(',') {
            for k in 0..range {
                req.ports.push(PortMapping {
                    container_port: (container + k) as u16,
                    host_port: (host != 0).then(|| (host + k) as u16),
                    host_ip: s(p, "host_ip").to_string(),
                    protocol: proto.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn netns(spec: &Value, req: &mut CreateContainerRequest, default: &str) -> ApiResult<()> {
    let ns = get(spec, "netns");
    let (mode, value) = (s(ns, "nsmode"), s(ns, "value"));
    req.network_mode = match mode {
        // what the configuration says when the client says nothing
        "" if !default.is_empty() => default_network_mode(default),
        "" | "default" | "private" | "pod" | "bridge" => NetworkMode::Unset,
        "host" => NetworkMode::Host,
        "none" => NetworkMode::Off,
        "pasta" => NetworkMode::Pasta(None),
        "slirp4netns" => {
            return Err(ApiError::not_implemented(
                "the network mode slirp4netns is not supported: use pasta".to_string(),
            ))
        }
        "container" => NetworkMode::Container(value.to_string()),
        "path" => NetworkMode::Ns(value.to_string()),
        m => {
            return Err(ApiError::not_implemented(format!(
                "the network mode `{m}` is not supported"
            )))
        }
    };
    let mut nets = get(spec, "Networks").as_object().cloned();
    // the deprecated list of names
    let cni = strs(spec, "cni_networks");
    if !cni.is_empty() && nets.as_ref().is_none_or(|n| n.is_empty()) {
        nets = Some(cni.into_iter().map(|n| (n, Value::Null)).collect());
    }
    let nets = nets.as_ref();
    // `--network bridge` alone: the default network, rootless too.
    if mode == "bridge" && nets.is_none_or(|n| n.is_empty()) {
        req.networks
            .push(velarx_netdetach::def::DEFAULT_NETWORK.to_string());
    }
    if let Some(nets) = nets {
        for (name, opts) in nets {
            refuse_members(opts, "Networks", &["options", "interface_name"])?;
            // podman's `--network bridge`: the bridge mode on the network
            // named `default`, the default network
            if mode == "bridge" && name == "default" {
                req.networks
                    .push(velarx_netdetach::def::DEFAULT_NETWORK.to_string());
            } else {
                req.networks.push(name.clone());
            }
            req.network_aliases.extend(strs(opts, "aliases"));
            for ip in strs(opts, "static_ips") {
                let slot = if ip.contains(':') {
                    &mut req.ip6_address
                } else {
                    &mut req.ip_address
                };
                if slot.replace(ip).is_some() {
                    return Err(ApiError::not_implemented(
                        "more than one static IP address of a family is not supported",
                    ));
                }
            }
            if let Some(mac) = nonempty(s(opts, "static_mac")) {
                if req.mac_address.replace(mac).is_some() {
                    return Err(ApiError::not_implemented(
                        "a static MAC address on more than one network is not supported",
                    ));
                }
            }
        }
    }
    if req.mac_address.is_none() {
        req.mac_address = nonempty(s(spec, "static_mac"));
    }
    Ok(())
}

fn ns_mode(spec: &Value, key: &str) -> ApiResult<NsMode> {
    let ns = get(spec, key);
    let (mode, value) = (s(ns, "nsmode"), s(ns, "value"));
    Ok(match mode {
        // (private is not the default IPC mode: shareable is)
        "private" if key == "ipcns" => NsMode::Private,
        "none" if key == "ipcns" => NsMode::Off,
        "" | "default" | "private" | "pod" => NsMode::Default,
        "host" => NsMode::Host,
        "shareable" => NsMode::Shareable,
        "container" if !value.is_empty() => NsMode::Container(value.to_string()),
        "path" if value.starts_with('/') => NsMode::Ns(value.to_string()),
        m => {
            return Err(ApiError::not_implemented(format!(
                "the {key} mode `{m}` is not supported"
            )))
        }
    })
}

/// The log driver and options of a SpecGenerator (`log_configuration`:
/// driver, options, path, size).
fn log_config(lc: &Value) -> Option<velarx_wire::request::LogConfig> {
    let driver = s(lc, "driver").to_string();
    let mut config: HashMap<String, String> = get(lc, "options")
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    if !s(lc, "path").is_empty() {
        config.insert("path".into(), s(lc, "path").to_string());
    }
    if let Some(size) = get(lc, "size").as_i64().filter(|n| *n > 0) {
        config.entry("max-size".into()).or_insert(size.to_string());
    }
    (!driver.is_empty() || !config.is_empty()).then_some(velarx_wire::request::LogConfig {
        driver,
        config: config.into_iter().collect(),
    })
}

/// The settings of the resource limits (OCI `linux.resources`) that cgroups
/// v2 or velarx have nothing for: refused when they have a value.
pub fn refuse_resources(res: &Value) -> ApiResult<()> {
    refuse_members(res, "resource_limits", &["network", "rdma"])?;
    refuse_members(
        get(res, "memory"),
        "resource_limits.memory",
        &["kernel", "kernelTCP", "useHierarchy", "checkBeforeUpdate"],
    )?;
    refuse_members(get(res, "cpu"), "resource_limits.cpu", &["burst", "idle"])?;
    let bio = get(res, "blockIO");
    refuse_members(
        bio,
        "resource_limits.blockIO",
        &[
            "leafWeight",
            "throttleReadBpsDevice",
            "throttleWriteBpsDevice",
            "throttleReadIOPSDevice",
            "throttleWriteIOPSDevice",
        ],
    )?;
    for d in arr(bio, "weightDevice") {
        refuse_members(d, "resource_limits.blockIO.weightDevice", &["leafWeight"])?;
    }
    Ok(())
}

/// The members of a SpecGenerator that velarx has no support for (the
/// ones above are the same for a pod's): refused, naming them, when they
/// have a value.
fn refuse_unsupported(spec: &Value) -> ApiResult<()> {
    refuse_members(get(spec, "personality"), "personality", &["flags"])?;
    for m in arr(spec, "mounts") {
        refuse_members(m, "mounts", &["uidMappings", "gidMappings"])?;
    }
    refuse_resources(get(spec, "resource_limits"))?;
    if let Some(o) = get(spec, "weightDevice").as_object() {
        for d in o.values() {
            refuse_members(d, "weightDevice", &["leafWeight"])?;
        }
    }
    refuse_members(
        get(get(spec, "idmappings"), "AutoUserNsOpts"),
        "idmappings.AutoUserNsOpts",
        &[
            "InitialSize",
            "PasswdFile",
            "GroupFile",
            "AdditionalUIDMappings",
            "AdditionalGIDMappings",
        ],
    )
}

/// podman's SpecGenerator.
pub async fn from_spec(
    state: &AppState,
    spec: &Value,
) -> ApiResult<(CreateContainerRequest, Vec<String>)> {
    refuse_unsupported(spec)?;
    let mut req = CreateContainerRequest::default();
    if s(spec, "rootfs").is_empty() {
        req.image = s(spec, "image").to_string();
    } else {
        req.rootfs = true;
        req.image = s(spec, "rootfs").to_string();
        let mut options = Vec::new();
        if b(spec, "rootfs_overlay") {
            options.push("O");
        }
        options.extend(Some(s(spec, "rootfs_mapping")).filter(|m| !m.is_empty()));
        if !options.is_empty() {
            req.image = format!("{}:{}", req.image, options.join(","));
        }
    }
    if req.image.is_empty() {
        return Err(ApiError::bad_request("the image must be specified"));
    }
    req.name = nonempty(s(spec, "name"));
    req.command = strs(spec, "command");
    req.entrypoint = strs(spec, "entrypoint");
    if req.entrypoint.is_empty() && field(spec, "entrypoint").is_some_and(Value::is_array) {
        // an empty entrypoint drops the one of the image
        req.entrypoint = vec![String::new()];
    }
    req.cgroup_parent = nonempty(s(spec, "cgroup_parent"));
    req.requires = strs(spec, "dependencyContainers");
    req.systemd = nonempty(s(spec, "systemd"));
    req.conmon_pidfile = nonempty(s(spec, "conmon_pid_file"));
    req.pidfile = nonempty(s(spec, "pidfile"));
    req.unsetenv = strs(spec, "unsetenv");
    req.unsetenv_all = b(spec, "unsetenvall");
    req.log_config = log_config(get(spec, "log_configuration"));
    req.env_merge = strs(spec, "envmerge");
    req.personality = nonempty(s(get(spec, "personality"), "domain"));
    req.rootfs_propagation = nonempty(s(spec, "rootfs_propagation"));
    if field(spec, "read_write_tmpfs").and_then(Value::as_bool) == Some(false) {
        req.no_read_only_tmpfs = true;
    }
    // (the device rules of the resource limits are the same list)
    let rules = arr(spec, "device_cgroup_rule")
        .iter()
        .chain(arr(get(spec, "resource_limits"), "devices").iter());
    for r in rules {
        if field(r, "allow").and_then(Value::as_bool) == Some(false) {
            return Err(ApiError::not_implemented(
                "deny rules of devices are not supported",
            ));
        }
        let num = |k: &str| {
            field(r, k)
                .and_then(Value::as_i64)
                .map_or("*".to_string(), |n| n.to_string())
        };
        let typ = if s(r, "type").is_empty() {
            "a"
        } else {
            s(r, "type")
        };
        let access = if s(r, "access").is_empty() {
            "rwm"
        } else {
            s(r, "access")
        };
        req.device_cgroup_rules
            .push(format!("{typ} {}:{} {access}", num("major"), num("minor")));
    }
    req.env = kv_pairs(get(spec, "env"));
    req.working_dir = s(spec, "work_dir").to_string();
    req.user = s(spec, "user").to_string();
    req.group_add = strs(spec, "groups");
    req.passwd_entry = nonempty(s(spec, "passwd_entry"));
    req.group_entry = nonempty(s(spec, "group_entry"));
    req.hostname = s(spec, "hostname").to_string();
    req.cap_add = strs(spec, "cap_add");
    req.cap_drop = strs(spec, "cap_drop");
    // (velarx's, for the CRI: podman has neither)
    req.cap_ambient = strs(spec, "cap_ambient");
    req.groups_strict = b(spec, "groups_strict");
    req.privileged = b(spec, "privileged");
    req.read_only_rootfs = b(spec, "read_only_filesystem");
    req.timezone = nonempty(s(spec, "timezone"));
    req.umask = nonempty(s(spec, "umask"));
    // podman's SpecGenerator says use_image_hosts; `[containers] no_hosts`
    // when it says nothing
    req.no_hosts = match field(spec, "use_image_hosts").and_then(Value::as_bool) {
        Some(b) => b,
        None => state.config.containers.no_hosts,
    };
    req.tty = b(spec, "terminal");
    req.stdin_open = b(spec, "stdin");
    req.init = b(spec, "init");
    req.init_path = nonempty(s(spec, "init_path"));
    req.labels = kv_map(get(spec, "labels"));
    req.annotations = kv_map(get(spec, "annotations"));
    req.security_opt.no_new_privileges = b(spec, "no_new_privileges");
    match s(spec, "seccomp_profile_path") {
        "" => {}
        "unconfined" => req.security_opt.seccomp_unconfined = true,
        p => req.security_opt.seccomp_profile = Some(p.to_string()),
    }
    match s(spec, "apparmor_profile") {
        "" => {}
        "unconfined" => req.security_opt.apparmor_unconfined = true,
        p => req.security_opt.apparmor_profile = Some(p.to_string()),
    }
    req.security_opt.mask_paths = strs(spec, "mask");
    req.security_opt.readonly_paths = strs(spec, "r_o_paths");
    req.security_opt.unmask_paths = strs(spec, "unmask");
    let proc_opts = strs(spec, "procfs_opts");
    if !proc_opts.is_empty() {
        req.security_opt.proc_opts = Some(proc_opts.join(","));
    }
    req.security_opts = strs(spec, "selinux_opts")
        .into_iter()
        .map(|o| format!("label={o}"))
        .collect();

    for m in arr(spec, "mounts") {
        let dest = s(m, "destination");
        if dest.is_empty() {
            return Err(ApiError::bad_request("a mount without destination"));
        }
        let opts = strs(m, "options");
        match s(m, "type") {
            "" | "bind" => {
                let src = s(m, "source");
                if src.is_empty() {
                    return Err(ApiError::bad_request("a bind mount without source"));
                }
                check_bind_options(&opts)?;
                let sub = s(m, "subpath");
                if sub.is_empty() {
                    let mut arg = format!("{src}:{dest}");
                    if !opts.is_empty() {
                        arg = format!("{arg}:{}", opts.join(","));
                    }
                    add_volume_arg(state, &mut req, &arg).await?;
                } else {
                    let spec = MountSpec::bind(src, dest, &opts)?.in_subpath(sub)?;
                    req.mounts.push(mount_from_spec(state, spec).await?);
                }
            }
            "tmpfs" => add_tmpfs(&mut req, dest, &opts.join(","))?,
            t => {
                let mut arg = format!("type={t},source={},target={dest}", s(m, "source"));
                for o in &opts {
                    arg = format!("{arg},{o}");
                }
                let spec = MountSpec::parse_mount_arg(&arg)?;
                req.mounts.push(mount_from_spec(state, spec).await?);
            }
        }
    }
    for v in arr(spec, "volumes") {
        let dest = s(v, "Dest");
        if dest.is_empty() {
            return Err(ApiError::bad_request("a volume without destination"));
        }
        let name = s(v, "Name");
        let opts = strs(v, "Options");
        let sub = match s(v, "SubPath") {
            "" => s(v, "subPath"),
            p => p,
        };
        if !sub.is_empty() {
            // podman's `--mount type=volume,...,subpath=`
            if [name, dest, sub].iter().any(|p| p.contains(',')) {
                return Err(ApiError::bad_request("invalid volume subpath"));
            }
            let mut arg = format!("type=volume,source={name},target={dest},subpath={sub}");
            for o in &opts {
                arg = format!("{arg},{o}");
            }
            let spec = MountSpec::parse_mount_arg(&arg)?;
            req.mounts.push(mount_from_spec(state, spec).await?);
            continue;
        }
        let arg = if name.is_empty() || b(v, "IsAnonymous") {
            dest.to_string()
        } else if opts.is_empty() {
            format!("{name}:{dest}")
        } else {
            format!("{name}:{dest}:{}", opts.join(","))
        };
        add_volume_arg(state, &mut req, &arg).await?;
    }
    // podman's `-v SRC:DST:O`: {destination, source, options}
    for v in arr(spec, "overlay_volumes") {
        let (src, dest) = (s(v, "source"), s(v, "destination"));
        if src.is_empty() || dest.is_empty() {
            return Err(ApiError::bad_request(
                "an overlay volume needs a source and a destination",
            ));
        }
        let mut opts = vec!["O".to_string()];
        opts.extend(strs(v, "options").into_iter().filter(|o| o != "O"));
        add_volume_arg(state, &mut req, &format!("{src}:{dest}:{}", opts.join(","))).await?;
    }
    // podman's `--mount type=image`: {Source, Destination, ReadWrite, SubPath}
    for v in arr(spec, "image_volumes") {
        let (src, dest) = (s(v, "Source"), s(v, "Destination"));
        if src.is_empty() || dest.is_empty() {
            return Err(ApiError::bad_request(
                "an image volume needs a source and a destination",
            ));
        }
        let sub = match s(v, "subPath") {
            "" => s(v, "SubPath"),
            p => p,
        };
        if src.contains(',') || dest.contains(',') || sub.contains(',') {
            return Err(ApiError::bad_request("invalid image volume"));
        }
        let mut arg = format!("type=image,source={src},target={dest}");
        if b(v, "ReadWrite") {
            arg.push_str(",rw=true");
        }
        if !sub.is_empty() {
            arg = format!("{arg},subpath={sub}");
        }
        let spec = MountSpec::parse_mount_arg(&arg)?;
        req.mounts.push(mount_from_spec(state, spec).await?);
    }

    // podman's `--mount type=artifact`: {source, destination, title,
    // digest, name}, mounted as velarx's --mount is (`artifact_mounts`)
    for v in arr(spec, "artifact_volumes") {
        let mut arg = format!(
            "type=artifact,src={},dst={}",
            s(v, "source"),
            s(v, "destination")
        );
        for key in ["title", "digest", "name"] {
            let value = s(v, key);
            if value.contains(',') {
                return Err(ApiError::bad_request("invalid artifact volume"));
            }
            if !value.is_empty() {
                arg.push_str(&format!(",{key}={value}"));
            }
        }
        if s(v, "source").contains(',') || s(v, "destination").contains(',') {
            return Err(ApiError::bad_request("invalid artifact volume"));
        }
        velarx_core::services::artifact::parse_artifact_mount(&arg)
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
        req.mount.push(arg);
    }

    for r in arr(spec, "r_limits") {
        let t = s(r, "type");
        let name = t.strip_prefix("RLIMIT_").unwrap_or(t).to_lowercase();
        if !name.is_empty() {
            req.ulimits.push(Ulimit {
                name,
                soft: limit(get(r, "soft")),
                hard: limit(get(r, "hard")),
            });
        }
    }
    let res = get(spec, "resource_limits");
    let mem = get(res, "memory");
    let cpu = get(res, "cpu");
    let mut limits = ResourceLimits::default();
    let some = |v: i64| (v != 0).then_some(v);
    limits.memory = some(i(mem, "limit"));
    limits.memory_reservation = some(i(mem, "reservation"));
    limits.memory_swap = some(i(mem, "swap"));
    // (podman's handler: a memory limit without a swap one allows as much
    // swap as memory, specgenutil.LimitToSwap)
    limits.memory_swap =
        crate::cli::run::swap_of(limits.memory, field(mem, "swap").and_then(Value::as_i64));
    limits.cpu_quota = some(i(cpu, "quota"));
    limits.cpu_period = some(i(cpu, "period")).map(|v| v.max(0) as u64);
    limits.cpu_shares = some(i(cpu, "shares")).map(|v| v.max(0) as u64);
    limits.cpuset_cpus = nonempty(s(cpu, "cpus"));
    limits.cpuset_mems = nonempty(s(cpu, "mems"));
    refuse_swappiness(mem, "swappiness", "resource_limits.memory.swappiness")?;
    refuse_members(
        cpu,
        "resource_limits.cpu",
        &["realtimeRuntime", "realtimePeriod"],
    )?;
    req.pids_limit = nanos_to_pid_limit(i(get(res, "pids"), "limit"));
    req.shm_size = some(i(spec, "shm_size")).map(|v| v.max(0) as u64);
    req.shm_size_systemd = some(i(spec, "shm_size_systemd")).map(|v| v.max(0) as u64);
    let throttles = |k: &str| -> Vec<ThrottleDevice> {
        get(spec, k)
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(path, v)| ThrottleDevice {
                        path: path.clone(),
                        rate: i(v, "rate").max(0) as u64,
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    limits.blkio_device_read_bps = throttles("throttleReadBpsDevice");
    limits.blkio_device_write_bps = throttles("throttleWriteBpsDevice");
    limits.blkio_device_read_iops = throttles("throttleReadIOPSDevice");
    limits.blkio_device_write_iops = throttles("throttleWriteIOPSDevice");
    limits.blkio_weight =
        some(i(get(res, "blockIO"), "weight")).map(|w| w.clamp(0, u16::MAX.into()) as u16);
    // by path (specgen's `weightDevice`) or by device numbers (the OCI
    // `blockIO`)
    if let Some(o) = get(spec, "weightDevice").as_object() {
        for (path, v) in o {
            limits.blkio_weight_device.push(WeightDevice {
                path: path.clone(),
                weight: i(v, "weight").clamp(0, u16::MAX.into()) as u16,
                device: None,
            });
        }
    }
    for d in arr(get(res, "blockIO"), "weightDevice") {
        limits.blkio_weight_device.push(WeightDevice {
            path: String::new(),
            weight: i(d, "weight").clamp(0, u16::MAX.into()) as u16,
            device: Some(velarx_wire::request::DeviceNumbers {
                major: i(d, "major").max(0) as u64,
                minor: i(d, "minor").max(0) as u64,
            }),
        });
    }
    limits.hugepage_limits = arr(res, "hugepageLimits")
        .iter()
        .map(|h| HugepageLimit {
            page_size: s(h, "pageSize").to_string(),
            limit: limit(get(h, "limit")),
        })
        .collect();
    // (the OCI `resources.unified` is the same map)
    let mut conf = kv_map(get(res, "unified"));
    conf.extend(kv_map(get(spec, "unified")));
    if !conf.is_empty() {
        limits.cgroup_conf = Some(conf);
    }
    if get(mem, "disableOOMKiller").as_bool() == Some(true) {
        req.oom_kill_disable = true;
    }
    if has_blkio(&limits)
        || limits.cgroup_conf.is_some()
        || !limits.hugepage_limits.is_empty()
        || limits.memory.is_some()
        || limits.memory_reservation.is_some()
        || limits.memory_swap.is_some()
        || limits.cpu_quota.is_some()
        || limits.cpu_period.is_some()
        || limits.cpu_shares.is_some()
        || limits.cpuset_cpus.is_some()
        || limits.cpuset_mems.is_some()
    {
        req.resources = Some(limits);
    }
    if let Some(v) = field(spec, "oom_score_adj").and_then(Value::as_i64) {
        req.oom_score_adj = Some(v as i32);
    }
    req.dns_options = strs(spec, "dns_option");
    req.dns = strs(spec, "dns_server");
    req.dns_search = strs(spec, "dns_search");
    req.add_hosts = strs(spec, "hostadd");
    netns(spec, &mut req, &state.config.containers.netns)?;
    port_mappings(spec, &mut req)?;
    if let Some(exp) = get(spec, "expose").as_object() {
        for (port, protos) in exp {
            let protos = protos.as_str().filter(|p| !p.is_empty()).unwrap_or("tcp");
            for proto in protos.split(',') {
                req.expose.push(format!("{port}/{proto}"));
            }
        }
    }
    for d in arr(spec, "devices") {
        let p = s(d, "path");
        if p.is_empty() {
            return Err(ApiError::bad_request("a device without path"));
        }
        req.devices.push(parse_device(p));
    }
    req.sysctls = kv_map(get(spec, "sysctl"));
    req.stop_signal = sig_name(get(spec, "stop_signal"));
    if let Some(t) = field(spec, "stop_timeout").and_then(Value::as_u64) {
        req.stop_timeout = Some(t as u32);
    }
    // `--timeout`: the time the container may run
    if let Some(t) = field(spec, "timeout").and_then(Value::as_u64) {
        req.timeout = Some(u32::try_from(t).unwrap_or(u32::MAX));
    }
    req.auto_remove = b(spec, "remove");
    req.auto_remove_image = b(spec, "removeImage");
    req.pod = nonempty(s(spec, "pod"));
    let policy = s(spec, "restart_policy");
    if !policy.is_empty() {
        req.restart_policy = Some(RestartPolicy {
            name: policy.to_string(),
            maximum_retry_count: i(spec, "restart_tries").max(0) as u32,
        });
    }
    let userns = get(spec, "userns");
    let value = s(userns, "value");
    req.userns_mode = UsernsChoice::from_spec(s(userns, "nsmode"), value)
        .ok_or_else(|| {
            ApiError::not_implemented(format!(
                "the user namespace mode `{}` is not supported",
                s(userns, "nsmode")
            ))
        })?
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let maps = get(spec, "idmappings");
    if maps.is_object() {
        let conv = |k: &str| -> Vec<velarx_wire::request::IdMapping> {
            arr(maps, k)
                .iter()
                .map(|m| velarx_wire::request::IdMapping {
                    container_id: i(m, "container_id") as u32,
                    host_id: i(m, "host_id") as u32,
                    size: i(m, "size") as u32,
                })
                .collect()
        };
        req.uid_mappings = conv("UIDMap");
        req.gid_mappings = conv("GIDMap");
        let opts = get(maps, "AutoUserNsOpts");
        if b(maps, "AutoUserNs") && req.userns_mode.is_host() {
            req.userns_mode = UsernsChoice::Auto(match i(opts, "Size") {
                0 => None,
                n => Some(format!("size={n}")),
            });
        }
    }
    req.ipc_mode = ns_mode(spec, "ipcns")?;
    req.pid_mode = ns_mode(spec, "pidns")?;
    req.uts_mode = ns_mode(spec, "utsns")?;
    req.cgroupns_mode = ns_mode(spec, "cgroupns")?;
    if let Some(h) = field(spec, "healthconfig").filter(|h| h.is_object()) {
        match health_from(h, false) {
            Some(Some(hc)) => req.healthcheck = Some(hc),
            Some(None) => req.no_healthcheck = true,
            None => {}
        }
    }
    health_extras(spec, &mut req)?;
    other_fields(spec, &mut req)?;
    check_platform(state, spec, &req.image).await?;
    let used = apply_secrets(state, spec, &mut req).await?;
    volumes_from(state, &mut req, &strs(spec, "volumes_from")).await?;
    Ok((req, used))
}

/// The fields of a SpecGenerator that the ones above do not read:
/// applied, refused with the reason, or of no effect here (said so).
fn other_fields(spec: &Value, req: &mut CreateContainerRequest) -> ApiResult<()> {
    let refuse = |what: &str| Err(ApiError::not_implemented(what.to_string()));
    // what is applied
    // `container`, podman's default, is what a container of the server
    // does when it is not told otherwise: the others are passed on
    req.sdnotify = match s(spec, "sdnotifyMode") {
        "" | "container" => String::new(),
        m => m.to_string(),
    };
    if !s(spec, "cgroups_mode").is_empty() {
        req.cgroups = CgroupsMode::parse(s(spec, "cgroups_mode"))
            .map_err(|e| ApiError::bad_request(e.to_string()))?;
    }
    // podman's `anonymous` (its default) is an anonymous volume each:
    // what velarx calls bind
    req.image_volume = match s(spec, "image_volume_mode").to_lowercase().as_str() {
        "" | "anonymous" => String::new(),
        m => m.to_string(),
    };
    req.publish_all = b(spec, "publish_image_ports");
    if b(spec, "use_image_hostname") {
        req.no_hostname = true;
    }
    if field(spec, "manage_password").and_then(Value::as_bool) == Some(false) {
        req.no_passwd = true;
    }
    // the server's environment, as podman's server does
    let (all, proxy) = (b(spec, "env_host"), b(spec, "httpproxy"));
    if all || proxy {
        let host = crate::cli::run::host_env(all, proxy, std::env::vars(), &req.env);
        req.env.splice(0..0, host);
    }
    if let Some(a) = field(spec, "health_check_on_failure_action").and_then(Value::as_i64) {
        let action = match a {
            0 => None,
            2 => Some(OnFailure::Kill),
            3 => Some(OnFailure::Restart),
            4 => Some(OnFailure::Stop),
            _ => {
                return Err(ApiError::bad_request(format!(
                    "invalid health on-failure action {a}"
                )))
            }
        };
        if let Some(action) = action {
            let Some(hc) = req.healthcheck.as_mut() else {
                return Err(ApiError::bad_request(
                    "an on-failure action needs a health check",
                ));
            };
            hc.on_failure = action;
        }
    }
    // the runtime: a name of [runtimes] or the default one's, checked when
    // the container is made
    if let Some(r) = nonempty(s(spec, "oci_runtime")) {
        req.runtime = Some(r);
    }
    if let Some(kind) = nonempty(s(spec, "init_container_type")) {
        let kind = velarx_wire::request::init_container_type(&kind, req.pod.as_deref())
            .map_err(ApiError::bad_request)?;
        req.annotations.insert(
            velarx_wire::request::INIT_TYPE_ANNOTATION.to_string(),
            kind.to_string(),
        );
    }
    // the fields of podman's composefs-verity branch: `signature_policy` is
    // `--security-opt signature=`, `verity_enforce` is `verity=enforce`
    if let Some(v) = nonempty(s(spec, "signature_policy")) {
        req.security_opts.push(format!("signature={v}"));
    }
    if b(spec, "verity_enforce") {
        req.security_opts.push("verity=enforce".into());
    }
    // what is refused
    req.host_users = strs(spec, "hostusers");
    req.chroot_dirs = strs(spec, "chroot_directories");
    for k in ["devices_from", "host_device_list"] {
        if !arr(spec, k).is_empty() {
            return refuse(&format!("{k} is not supported"));
        }
    }
    if !arr(spec, "gpus").is_empty() {
        return refuse("GPUs (--gpus) are not supported");
    }
    if get(spec, "storage_opts")
        .as_object()
        .is_some_and(|o| !o.is_empty())
    {
        return refuse("storage options of a container (--storage-opt) are not supported");
    }
    req.seccomp_policy = nonempty(s(spec, "seccomp_policy"));
    if b(spec, "label_nested") {
        return refuse("label=nested is not supported");
    }
    if b(spec, "use_image_resolve_conf") {
        return refuse("the resolv.conf of the image (--dns=none) is not supported");
    }
    req.hosts_file = nonempty(s(spec, "base_hosts_file"));
    // pasta's options (`--network pasta:OPTS`), the only ones
    if let Some(o) = get(spec, "network_options").as_object() {
        for (k, v) in o {
            let opts: Vec<String> = v
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|o| o.as_str().map(str::to_string))
                .collect();
            if opts.is_empty() {
                continue;
            }
            if k != "pasta" || req.network_mode != NetworkMode::Pasta(None) {
                return refuse(&format!(
                    "options of the network mode `{k}` are not supported"
                ));
            }
            if opts.iter().any(|o| o.contains(',')) {
                return Err(ApiError::bad_request("a pasta option with a comma"));
            }
            req.network_mode = NetworkMode::Pasta(Some(opts.join(",")));
        }
    }
    let rdt = get(spec, "intelRdt");
    if let Some(o) = rdt.as_object() {
        if let Some((k, _)) = o.iter().find(|(k, v)| k.as_str() != "closID" && is_set(v)) {
            return refuse(&format!("Intel RDT `{k}` is not supported: closID is"));
        }
        req.rdt_class = nonempty(s(rdt, "closID"));
    }
    // of no effect here: containerCreateCommand and raw_image_name (what
    // the client said, kept by podman for inspect), networkOrder (the
    // networks are attached in the order given), create_working_dir (a
    // missing working directory is always made), volatile (a hint that
    // the upper layer needs no sync)
    Ok(())
}

/// `image_os`, `image_arch`, `image_variant`: the image must be of that
/// platform.
async fn check_platform(state: &AppState, spec: &Value, image: &str) -> ApiResult<()> {
    let want = [
        ("os", s(spec, "image_os")),
        ("architecture", s(spec, "image_arch")),
        ("variant", s(spec, "image_variant")),
    ];
    if want.iter().all(|(_, v)| v.is_empty()) {
        return Ok(());
    }
    // an image that is not there: the create says so
    let Ok(rec) = state.image_service.get(image).await else {
        return Ok(());
    };
    let config: Value = serde_json::from_str(&rec.config).unwrap_or(Value::Null);
    for (k, v) in want {
        let got = s(&config, k);
        if !v.is_empty() && got != v {
            return Err(ApiError::bad_request(format!(
                "the image {image} is of {k} `{got}`, not `{v}`"
            )));
        }
    }
    Ok(())
}

/// podman's `startupHealthConfig`, `healthLogDestination`,
/// `healthMaxLogCount` and `healthMaxLogSize`: they go with a health check.
fn health_extras(spec: &Value, req: &mut CreateContainerRequest) -> ApiResult<()> {
    let startup = field(spec, "startupHealthConfig").filter(|h| h.is_object());
    let destination = field(spec, "healthLogDestination")
        .and_then(Value::as_str)
        .filter(|d| !d.is_empty());
    let count = field(spec, "healthMaxLogCount").and_then(Value::as_u64);
    let size = field(spec, "healthMaxLogSize").and_then(Value::as_u64);
    if startup.is_none() && destination.is_none() && count.is_none() && size.is_none() {
        return Ok(());
    }
    let Some(hc) = req.healthcheck.as_mut() else {
        if startup.is_some() {
            return Err(ApiError::bad_request(
                "a startup health check needs a health check".to_string(),
            ));
        }
        return Ok(());
    };
    if let Some(st) = startup {
        let test = strs(st, "Test");
        let test = match test.first().map(|t| t.to_uppercase()) {
            Some(t) if t == "CMD" || t == "CMD-SHELL" => test,
            Some(_) if test.len() > 1 => std::iter::once("CMD".to_string()).chain(test).collect(),
            Some(_) => vec!["CMD-SHELL".to_string(), test[0].clone()],
            None => {
                return Err(ApiError::bad_request(
                    "the startup health check has no command".to_string(),
                ))
            }
        };
        hc.startup = Some(StartupHealthcheck {
            test,
            interval_ns: i(st, "Interval").max(0) as u64,
            timeout_ns: i(st, "Timeout").max(0) as u64,
            retries: i(st, "Retries").clamp(0, u32::MAX as i64) as u32,
            successes: i(st, "Successes").clamp(0, u32::MAX as i64) as u32,
        });
    }
    if let Some(d) = destination {
        hc.log_destination = d.to_string();
    }
    let clamp = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
    hc.max_log_count = count.map(clamp);
    hc.max_log_size = size.map(clamp);
    Ok(())
}

/// The directory of the secrets of a container, which is gone with it.
pub fn secrets_dir(state: &AppState, id: &str) -> std::path::PathBuf {
    state.container_service.secrets_dir_of(id)
}

/// `secrets` (mounted, read only) and `secret_env` of a spec.
async fn apply_secrets(
    state: &AppState,
    spec: &Value,
    req: &mut CreateContainerRequest,
) -> ApiResult<Vec<String>> {
    let mut refs: Vec<SecretRef> = arr(spec, "secrets")
        .iter()
        .map(|m| SecretRef {
            name: s(m, "Source").to_string(),
            env: false,
            target: s(m, "Target").to_string(),
            uid: i(m, "UID").clamp(0, i64::from(u32::MAX)) as u32,
            gid: i(m, "GID").clamp(0, i64::from(u32::MAX)) as u32,
            mode: i(m, "Mode") as u32,
        })
        .collect();
    if let Some(env) = get(spec, "secret_env").as_object() {
        for (var, secret) in env {
            let name = secret
                .as_str()
                .ok_or_else(|| ApiError::bad_request(format!("invalid secret_env `{var}`")))?;
            refs.push(SecretRef {
                name: name.to_string(),
                env: true,
                target: var.clone(),
                ..Default::default()
            });
        }
    }
    resolve_secrets(state, &refs, req).await
}

/// The data of the secrets is resolved now: files in a private directory of
/// the container, bind mounted read only, and environment variables.  The
/// ids of the secrets in use.
pub async fn resolve_secrets(
    state: &AppState,
    refs: &[SecretRef],
    req: &mut CreateContainerRequest,
) -> ApiResult<Vec<String>> {
    if refs.is_empty() {
        return Ok(Vec::new());
    }
    let store = super::secrets::store(state).await?;
    let id = match &req.id {
        // (it names a directory: the engine's form only)
        Some(id) if !velarx_core::services::valid_container_id(id) => {
            return Err(ApiError::bad_request(format!(
                "invalid container id {id:?}: 64 lowercase hexadecimal digits"
            )))
        }
        Some(id) => id.clone(),
        None => velarx_core::services::new_id(),
    };
    let dir = secrets_dir(state, &id);
    let mut used = Vec::new();
    let mut files = 0;
    let result: ApiResult<()> = async {
        for r in refs {
            if r.name.is_empty() {
                return Err(ApiError::bad_request("a secret without a name"));
            }
            let (info, data) = store
                .data(&r.name)
                .await
                .map_err(|e| ApiError::no_such(super::error::Kind::Secret, e.to_string()))?;
            if r.env {
                let var = if r.target.is_empty() {
                    &info.name
                } else {
                    &r.target
                };
                let entry = format!("{var}={}", String::from_utf8_lossy(&data));
                req.secret_env.push(entry.clone());
                req.env.push(entry);
            } else {
                let target = match r.target.as_str() {
                    "" => format!("/run/secrets/{}", info.name),
                    t if t.starts_with('/') => t.to_string(),
                    t => format!("/run/secrets/{t}"),
                };
                let mode = match r.mode {
                    0 => 0o444,
                    v => v & 0o7777,
                };
                write_secret_file(&dir, files, &data, mode)?;
                req.mounts.push(MountConfig {
                    source: dir.join(files.to_string()).to_string_lossy().to_string(),
                    target,
                    mount_type: Some("bind".into()),
                    options: vec!["rbind".into(), "ro".into()],
                    // the create gives it to these ids of the container
                    secret_owner: (r.uid != 0 || r.gid != 0).then_some(
                        velarx_wire::request::Owner {
                            uid: r.uid,
                            gid: r.gid,
                        },
                    ),
                    ..Default::default()
                });
                files += 1;
            }
            used.push(info.id);
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        let _ = crate::api::off_thread(move || velarx_base::tree::remove_dir_all(dir)).await;
        return Err(e);
    }
    req.id = Some(id);
    req.resolved_secrets = refs.to_vec();
    Ok(used)
}

fn write_secret_file(dir: &std::path::Path, n: usize, data: &[u8], mode: u32) -> ApiResult<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dir.join(n.to_string()))?;
    f.write_all(data)?;
    Ok(())
}

/// The environment of a Docker create: its `Env`, and podman's `EnvMerge`,
/// `UnsetEnv` and `UnsetEnvAll` over the one of the image.
fn docker_env(body: &Value, req: &mut CreateContainerRequest) {
    req.env = strs(body, "Env");
    req.env_merge = strs(body, "EnvMerge");
    req.unsetenv = strs(body, "UnsetEnv");
    req.unsetenv_all = b(body, "UnsetEnvAll");
}

/// The `--mount` argument of an entry of Docker's `HostConfig.Mounts`, and
/// its type: what has no place in it is refused.
fn docker_mount_arg(m: &Value) -> ApiResult<(String, String)> {
    let vol = get(m, "VolumeOptions");
    refuse_members(m, "HostConfig.Mounts", &["ClusterOptions"])?;
    refuse_members(vol, "HostConfig.Mounts.VolumeOptions", &["Labels"])?;
    refuse_members(
        get(vol, "DriverConfig"),
        "HostConfig.Mounts.VolumeOptions.DriverConfig",
        &["Options"],
    )?;
    refuse_members(
        get(m, "BindOptions"),
        "HostConfig.Mounts.BindOptions",
        &[
            "CreateMountpoint",
            "ReadOnlyNonRecursive",
            "ReadOnlyForceRecursive",
        ],
    )?;
    let driver = s(get(vol, "DriverConfig"), "Name");
    // (a volume's, or an image mount's)
    let sub = match s(vol, "Subpath") {
        "" => s(get(m, "ImageOptions"), "Subpath"),
        p => p,
    };
    if sub.contains(',') {
        return Err(ApiError::bad_request("invalid volume subpath"));
    }
    if !driver.is_empty() && driver != "local" {
        return Err(ApiError::not_implemented(format!(
            "the volume driver `{driver}` is not supported"
        )));
    }
    let typ = if s(m, "Type").is_empty() {
        "bind"
    } else {
        s(m, "Type")
    };
    let mut arg = format!("type={typ},target={}", s(m, "Target"));
    if !s(m, "Source").is_empty() {
        arg = format!("{arg},source={}", s(m, "Source"));
    }
    if b(m, "ReadOnly") {
        arg.push_str(",ro");
    }
    let bind = get(m, "BindOptions");
    if !s(bind, "Propagation").is_empty() {
        arg = format!("{arg},bind-propagation={}", s(bind, "Propagation"));
    }
    if b(bind, "NonRecursive") {
        arg.push_str(",bind-nonrecursive");
    }
    if b(vol, "NoCopy") {
        arg.push_str(",nocopy");
    }
    if !sub.is_empty() {
        arg = format!("{arg},subpath={sub}");
    }
    Ok((typ.to_string(), arg))
}

/// Docker's container config with HostConfig and NetworkingConfig.
pub async fn from_docker(
    state: &AppState,
    name: Option<&str>,
    body: &Value,
) -> ApiResult<CreateContainerRequest> {
    let host = get(body, "HostConfig");
    let mut req = CreateContainerRequest {
        image: s(body, "Image").to_string(),
        ..Default::default()
    };
    if req.image.is_empty() {
        return Err(ApiError::bad_request("no image specified"));
    }
    req.name = name.filter(|n| !n.is_empty()).map(str::to_string);
    req.command = strs(body, "Cmd");
    req.entrypoint = match get(body, "Entrypoint") {
        Value::String(e) => vec![e.clone()],
        _ => strs(body, "Entrypoint"),
    };
    // an empty entrypoint drops the one of the image, not its command
    req.reset_entrypoint = req.entrypoint.is_empty() && get(body, "Entrypoint").is_array();
    docker_env(body, &mut req);
    req.working_dir = s(body, "WorkingDir").to_string();
    req.user = s(body, "User").to_string();
    req.hostname = s(body, "Hostname").to_string();
    req.tty = b(body, "Tty");
    req.stdin_open = b(body, "OpenStdin");
    req.labels = kv_map(get(body, "Labels"));
    req.stop_signal = sig_name(get(body, "StopSignal"));
    if let Some(t) = field(body, "StopTimeout").and_then(Value::as_u64) {
        req.stop_timeout = Some(t as u32);
    }
    if let Some(exp) = get(body, "ExposedPorts").as_object() {
        req.expose = exp.keys().cloned().collect();
    }
    if let Some(vols) = get(body, "Volumes").as_object() {
        // an anonymous volume gives way to a bind, mount or tmpfs of the
        // same destination, as podman's
        let clean = |p: &str| {
            let t = p.trim_end_matches('/');
            if t.is_empty() {
                "/".to_string()
            } else {
                t.to_string()
            }
        };
        let mut taken: std::collections::HashSet<String> = strs(host, "Binds")
            .iter()
            .filter_map(|b| MountSpec::parse_volume_arg(b).ok())
            .map(|m| clean(&m.target))
            .collect();
        taken.extend(arr(host, "Mounts").iter().map(|m| clean(s(m, "Target"))));
        if let Some(t) = get(host, "Tmpfs").as_object() {
            taken.extend(t.keys().map(|k| clean(k)));
        }
        for dest in vols.keys() {
            if !taken.contains(&clean(dest)) {
                add_volume_arg(state, &mut req, dest).await?;
            }
        }
    }
    if let Some(h) = field(body, "Healthcheck").filter(|h| h.is_object()) {
        match health_from(h, true) {
            Some(Some(hc)) => req.healthcheck = Some(hc),
            Some(None) => req.no_healthcheck = true,
            None => {}
        }
    }

    let binds = strs(host, "Binds");
    // Docker makes the host directory of a bind that has none
    let sources: Vec<String> = binds
        .iter()
        .filter_map(|b| b.split_once(':').map(|(src, _)| src.to_string()))
        .filter(|src| src.starts_with('/'))
        .collect();
    crate::api::off_thread(move || {
        for src in &sources {
            if !std::path::Path::new(src).exists() {
                std::fs::create_dir_all(src).map_err(|e| {
                    std::io::Error::other(format!("creating the source of the bind `{src}`: {e}"))
                })?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| ApiError::internal(e.to_string()))?;
    for bind in binds {
        add_volume_arg(state, &mut req, &bind).await?;
    }
    for m in arr(host, "Mounts") {
        let (typ, arg) = docker_mount_arg(m)?;
        if typ == "tmpfs" {
            let t = get(m, "TmpfsOptions");
            let mut opts = Vec::new();
            // Docker 1.46: [["noexec"], ["tmpfs-size", "67"]]
            for o in arr(t, "Options") {
                let kv: Vec<&str> = o
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                match kv.as_slice() {
                    [k] => opts.push(k.to_string()),
                    [k, v] => {
                        let k = k.strip_prefix("tmpfs-").unwrap_or(k);
                        opts.push(format!("{k}={v}"));
                    }
                    _ => {}
                }
            }
            if i(t, "SizeBytes") > 0 {
                opts.push(format!("size={}", i(t, "SizeBytes")));
            }
            if i(t, "Mode") > 0 {
                opts.push(format!("mode={:o}", i(t, "Mode") & 0o7777));
            }
            if b(m, "ReadOnly") && !opts.iter().any(|o| o == "ro") {
                opts.push("ro".into());
            }
            add_tmpfs(&mut req, s(m, "Target"), &opts.join(","))?;
            continue;
        }
        let spec = MountSpec::parse_mount_arg(&arg)?;
        req.mounts.push(mount_from_spec(state, spec).await?);
    }
    if let Some(t) = get(host, "Tmpfs").as_object() {
        for (path, opts) in t {
            add_tmpfs(&mut req, path, opts.as_str().unwrap_or(""))?;
        }
    }
    for d in arr(host, "Devices") {
        let host_path = s(d, "PathOnHost");
        if host_path.is_empty() {
            return Err(ApiError::bad_request("a device without PathOnHost"));
        }
        if !host_path.starts_with('/') {
            req.devices.push(DeviceMapping::cdi(host_path));
            continue;
        }
        req.devices.push(DeviceMapping {
            path_on_host: host_path.to_string(),
            path_in_container: nonempty(s(d, "PathInContainer"))
                .unwrap_or_else(|| host_path.to_string()),
            cgroup_permissions: nonempty(s(d, "CgroupPermissions")).unwrap_or_else(|| "rwm".into()),
        });
    }
    // the devices of the `cdi` driver are CDI devices, as podman's compat API
    for r in arr(host, "DeviceRequests")
        .iter()
        .filter(|r| s(r, "Driver") == "cdi")
    {
        for id in arr(r, "DeviceIDs").iter().filter_map(Value::as_str) {
            req.devices.push(DeviceMapping::cdi(id));
        }
    }
    req.sysctls = kv_map(get(host, "Sysctls"));
    req.annotations = kv_map(get(host, "Annotations"));
    req.no_hosts = state.config.containers.no_hosts;
    if let Some(pb) = get(host, "PortBindings").as_object() {
        for (port, binds) in pb {
            let (cport, proto) = port.split_once('/').unwrap_or((port, "tcp"));
            let binds = binds.as_array().cloned().unwrap_or_default();
            if binds.is_empty() {
                req.ports
                    .extend(parse_publish(&format!("{cport}/{proto}"))?);
            }
            for bnd in &binds {
                let spec = binding_spec(s(bnd, "HostIp"), s(bnd, "HostPort"), cport, proto);
                req.ports.extend(parse_publish(&spec)?);
            }
        }
    }
    let mode = s(host, "NetworkMode");
    let conf_netns = &state.config.containers.netns;
    // podman's compat create: the default bridge network, rootless too,
    // unless the configuration asks for another default
    let conf_default = matches!(conf_netns.as_str(), "" | "default" | "private" | "bridge");
    let mut default_bridge = false;
    req.network_mode = match mode {
        "" | "default" if conf_default => {
            default_bridge = true;
            NetworkMode::Unset
        }
        "" | "default" => default_network_mode(conf_netns),
        "bridge" => {
            default_bridge = true;
            NetworkMode::Unset
        }
        m => NetworkMode::parse(m),
    };
    if let Some(net) =
        field(get(body, "NetworkingConfig"), "EndpointsConfig").and_then(Value::as_object)
    {
        refuse_endpoints(net.values())?;
        // The networks: those of the endpoints and a network the mode names
        // (`docker run --network a --network b` sends the mode `a` and both
        // endpoints); one named network is the mode, more are attached one
        // by one, the default bridge network among them when it is asked.
        let special = |m: &NetworkMode| match m {
            NetworkMode::Host
            | NetworkMode::Off
            | NetworkMode::Pasta(_)
            | NetworkMode::Private
            | NetworkMode::Container(_)
            | NetworkMode::Ns(_) => true,
            NetworkMode::Network(n) => n == "slirp4netns" || n.starts_with("slirp4netns:"),
            _ => false,
        };
        if req.network_mode == NetworkMode::Unset || !special(&req.network_mode) {
            let mut names: Vec<String> = net
                .keys()
                .filter(|n| *n != "bridge" && *n != "default")
                .cloned()
                .chain(
                    Some(std::mem::take(&mut req.network_mode).to_string())
                        .filter(|m| !m.is_empty()),
                )
                .collect();
            names.sort();
            names.dedup();
            let bridge = net.contains_key("bridge") || net.contains_key("default");
            if bridge && !names.is_empty() {
                names.insert(0, velarx_netdetach::def::DEFAULT_NETWORK.to_string());
            }
            match names.as_slice() {
                [one] => req.network_mode = NetworkMode::parse(one),
                _ => req.networks.extend(names),
            }
        }
        for cfg in net.values() {
            // (`IPAddress` is a static address too, as podman takes it)
            let plain = s(cfg, "IPAddress");
            let (v4, v6) = match plain.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => (plain, ""),
                Ok(std::net::IpAddr::V6(_)) => ("", plain),
                Err(_) if plain.is_empty() => ("", ""),
                Err(_) => {
                    return Err(ApiError::bad_request(format!(
                        "failed to parse the ip address {plain:?}"
                    )))
                }
            };
            let ipam = get(cfg, "IPAMConfig");
            let or = |a: &'static str, b| Some(s(ipam, a)).filter(|v| !v.is_empty()).unwrap_or(b);
            // (the addresses are the container's: one network has them)
            for (slot, value) in [
                (&mut req.ip_address, or("IPv4Address", v4)),
                (&mut req.ip6_address, or("IPv6Address", v6)),
                (&mut req.mac_address, s(cfg, "MacAddress")),
            ] {
                if !value.is_empty() && slot.replace(value.to_string()).is_some() {
                    return Err(ApiError::not_implemented(
                        "static addresses on more than one network are not supported",
                    ));
                }
            }
            req.network_aliases.extend(strs(cfg, "Aliases"));
        }
    }
    if default_bridge && req.network_mode == NetworkMode::Unset && req.networks.is_empty() {
        req.networks
            .push(velarx_netdetach::def::DEFAULT_NETWORK.to_string());
    }
    if req.mac_address.is_none() {
        req.mac_address = nonempty(s(body, "MacAddress"));
    }
    let bridge = !matches!(
        req.network_mode,
        NetworkMode::Host
            | NetworkMode::Off
            | NetworkMode::Pasta(None)
            | NetworkMode::Container(_)
            | NetworkMode::Ns(_)
    );
    if !bridge && (req.ip_address.is_some() || req.mac_address.is_some()) {
        return Err(ApiError::internal(
            "networks and static ip/mac address can only be used with Bridge mode networking",
        ));
    }
    req.auto_remove = b(host, "AutoRemove");
    req.auto_remove_image = b(host, "AutoRemoveImage");
    req.privileged = b(host, "Privileged");
    req.read_only_rootfs = b(host, "ReadonlyRootfs");
    req.init = b(host, "Init");
    req.cap_add = strs(host, "CapAdd");
    req.cap_drop = strs(host, "CapDrop");
    // Docker sends the JSON of a seccomp profile, not its path.
    req.security_opts = strs(host, "SecurityOpt");
    req.group_add = strs(host, "GroupAdd");
    req.dns = strs(host, "Dns");
    req.dns_search = strs(host, "DnsSearch");
    req.dns_options = strs(host, "DnsOptions");
    req.add_hosts = strs(host, "ExtraHosts")
        .into_iter()
        .map(|h| match h.split_once('=') {
            Some((a, b)) if !h.contains(':') => format!("{a}:{b}"),
            _ => h,
        })
        .collect();
    for u in arr(host, "Ulimits") {
        req.ulimits.push(Ulimit {
            name: s(u, "Name").to_string(),
            soft: limit(get(u, "Soft")),
            hard: limit(get(u, "Hard")),
        });
    }
    req.device_cgroup_rules = strs(host, "DeviceCgroupRules");
    req.cgroup_parent = nonempty(s(host, "CgroupParent"));
    req.oom_kill_disable = b(host, "OomKillDisable");
    let mut limits = ResourceLimits::default();
    let some = |v: i64| (v != 0).then_some(v);
    limits.memory = some(i(host, "Memory"));
    limits.memory_reservation = some(i(host, "MemoryReservation"));
    limits.memory_swap = some(i(host, "MemorySwap"));
    // -1 without a memory limit is unlimited anyway
    if limits.memory.is_none() && limits.memory_swap == Some(-1) {
        limits.memory_swap = None;
    }
    // (podman's compat handler: no MemorySwap allows as much swap as memory;
    // -1 stays Docker's unlimited)
    if limits.memory_swap.is_none() {
        limits.memory_swap = crate::cli::run::swap_of(limits.memory, None);
    }
    let nano = i(host, "NanoCpus");
    if nano > 0 {
        limits.cpu_period = Some(100_000);
        limits.cpu_quota = Some(nano / 10_000);
    } else if i(host, "CpuQuota") > 0 {
        limits.cpu_quota = Some(i(host, "CpuQuota"));
        limits.cpu_period = some(i(host, "CpuPeriod")).map(|v| v.max(0) as u64);
    }
    limits.cpu_shares = some(i(host, "CpuShares")).map(|v| v.max(0) as u64);
    limits.cpuset_cpus = nonempty(s(host, "CpusetCpus"));
    limits.cpuset_mems = nonempty(s(host, "CpusetMems"));
    req.pids_limit = nanos_to_pid_limit(i(host, "PidsLimit"));
    req.shm_size = some(i(host, "ShmSize")).map(|v| v.max(0) as u64);
    let throttles = |k: &str| -> Vec<ThrottleDevice> {
        arr(host, k)
            .iter()
            .map(|d| ThrottleDevice {
                path: s(d, "Path").to_string(),
                rate: i(d, "Rate").max(0) as u64,
            })
            .collect()
    };
    limits.blkio_device_read_bps = throttles("BlkioDeviceReadBps");
    limits.blkio_device_write_bps = throttles("BlkioDeviceWriteBps");
    limits.blkio_device_read_iops = throttles("BlkioDeviceReadIOps");
    limits.blkio_device_write_iops = throttles("BlkioDeviceWriteIOps");
    limits.blkio_weight = some(i(host, "BlkioWeight")).map(|w| w.clamp(0, u16::MAX.into()) as u16);
    limits.blkio_weight_device = arr(host, "BlkioWeightDevice")
        .iter()
        .map(|d| WeightDevice {
            path: s(d, "Path").to_string(),
            weight: i(d, "Weight").clamp(0, u16::MAX.into()) as u16,
            device: None,
        })
        .collect();
    refuse_members(host, "", &["CpuRealtimeRuntime", "CpuRealtimePeriod"])?;
    refuse_swappiness(host, "MemorySwappiness", "MemorySwappiness")?;
    if let Some(v) = field(host, "OomScoreAdj")
        .and_then(Value::as_i64)
        .filter(|v| *v != 0)
    {
        req.oom_score_adj = Some(v as i32);
    }
    if has_blkio(&limits)
        || limits.memory.is_some()
        || limits.memory_reservation.is_some()
        || limits.memory_swap.is_some()
        || limits.cpu_quota.is_some()
        || limits.cpu_shares.is_some()
        || limits.cpuset_cpus.is_some()
        || limits.cpuset_mems.is_some()
    {
        req.resources = Some(limits);
    }

    let userns = s(host, "UsernsMode");
    match userns {
        "" | "host" => {}
        "auto" => req.userns_mode = UsernsChoice::Auto(None),
        "private" => req.userns_mode = UsernsChoice::Private,
        u if u.starts_with("container:") => {
            req.userns_mode =
                UsernsChoice::parse(u).map_err(|e| ApiError::bad_request(e.to_string()))?
        }
        u => {
            return Err(ApiError::not_implemented(format!(
                "the user namespace mode `{u}` is not supported"
            )))
        }
    }
    for (key, field) in [
        ("IpcMode", &mut req.ipc_mode),
        ("PidMode", &mut req.pid_mode),
        ("UTSMode", &mut req.uts_mode),
        ("CgroupnsMode", &mut req.cgroupns_mode),
    ] {
        match s(host, key) {
            "" => {}
            // (private is not the default IPC mode: shareable is)
            "private" if key == "IpcMode" => *field = NsMode::Private,
            "none" if key == "IpcMode" => *field = NsMode::Off,
            "private" => {}
            "host" => *field = NsMode::Host,
            "shareable" => *field = NsMode::Shareable,
            m if m.starts_with("container:") => {
                *field = NsMode::parse(m).map_err(|e| ApiError::bad_request(e.to_string()))?
            }
            m => {
                return Err(ApiError::not_implemented(format!(
                    "{key} `{m}` is not supported"
                )))
            }
        }
    }
    // (the CDI ones are devices above; podman ignores the others, which
    // would leave a container without the GPUs asked for)
    if let Some(d) = arr(host, "DeviceRequests")
        .iter()
        .find(|r| s(r, "Driver") != "cdi")
    {
        return Err(ApiError::not_implemented(format!(
            "a device request of the driver `{}` is not supported: only cdi",
            s(d, "Driver")
        )));
    }
    if get(host, "StorageOpt")
        .as_object()
        .is_some_and(|o| !o.is_empty())
    {
        return Err(ApiError::not_implemented("StorageOpt is not supported"));
    }
    let driver = s(host, "VolumeDriver");
    if !driver.is_empty() && driver != "local" {
        return Err(ApiError::not_implemented(format!(
            "the volume driver `{driver}` is not supported"
        )));
    }
    if !arr(host, "Links").is_empty() {
        // (podman's status and words)
        return Err(ApiError::bad_request(
            "bad parameter: link is not supported",
        ));
    }
    docker_other_fields(body, host, &mut req)?;
    volumes_from(state, &mut req, &strs(host, "VolumesFrom")).await?;
    let rp = get(host, "RestartPolicy");
    let name = s(rp, "Name");
    if !name.is_empty() && name != "no" {
        req.restart_policy = Some(RestartPolicy {
            name: name.to_string(),
            maximum_retry_count: i(rp, "MaximumRetryCount").max(0) as u32,
        });
    }
    Ok(req)
}

/// What an endpoint of a Docker create asks that velarx has no support for.
pub fn refuse_endpoint(cfg: &Value, scope: &str) -> ApiResult<()> {
    // `DriverOpts`, `GwPriority` and `Links` are read by no network backend
    // of podman either: they are dropped as it drops them
    refuse_members(
        get(cfg, "IPAMConfig"),
        &format!("{scope}.IPAMConfig"),
        &["LinkLocalIPs"],
    )
}

fn refuse_endpoints<'a>(cfgs: impl Iterator<Item = &'a Value>) -> ApiResult<()> {
    for cfg in cfgs {
        refuse_endpoint(cfg, "NetworkingConfig.EndpointsConfig")?;
    }
    Ok(())
}

/// The fields of a Docker create that the ones above do not read:
/// applied, refused with the reason, or of no effect here (said so).
fn docker_other_fields(
    body: &Value,
    host: &Value,
    req: &mut CreateContainerRequest,
) -> ApiResult<()> {
    let refuse = |what: &str| Err(ApiError::not_implemented(what.to_string()));
    // what is applied
    let lc = get(host, "LogConfig");
    let driver = s(lc, "Type");
    let opts: HashMap<String, String> = get(lc, "Config")
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    if !driver.is_empty() || !opts.is_empty() {
        req.log_config = Some(velarx_wire::request::LogConfig {
            driver: driver.to_string(),
            config: opts.into_iter().collect(),
        });
    }
    req.publish_all = b(host, "PublishAllPorts");
    if let Some(u) = nonempty(s(host, "Umask")) {
        req.umask = Some(u);
    }
    if b(body, "NetworkDisabled") {
        req.network_mode = NetworkMode::Off;
        req.networks.clear();
    }
    // Docker's: a list given, even empty, replaces the default ones
    let masked = field(host, "MaskedPaths").and_then(Value::as_array);
    let readonly = field(host, "ReadonlyPaths").and_then(Value::as_array);
    match (masked, readonly) {
        (None, None) => {}
        // `--security-opt systempaths=unconfined`
        (Some(m), Some(r)) if m.is_empty() && r.is_empty() => {
            req.security_opts.push("unmask=ALL".into());
        }
        _ => return refuse("lists of masked or read-only paths are not supported: use --security-opt mask= or unmask="),
    }
    // what is refused
    if !s(body, "Domainname").is_empty() {
        return refuse("a domain name (Domainname) is not supported");
    }
    if !s(host, "Cgroup").is_empty() {
        return refuse("sharing the cgroup of a container (Cgroup) is not supported");
    }
    // (the runtime is checked when the container is made: a name of
    // [runtimes] or the default one's)
    if let Some(r) = nonempty(s(host, "Runtime")) {
        req.runtime = Some(r);
    }
    match s(host, "Isolation") {
        "" | "default" => {}
        m => return refuse(&format!("the isolation `{m}` is not supported")),
    }
    for k in [
        "CpuCount",
        "CpuPercent",
        "IOMaximumIOps",
        "IOMaximumBandwidth",
    ] {
        if i(host, k) != 0 {
            return refuse(&format!("{k} (Windows) is not supported"));
        }
    }
    refuse_members(host, "HostConfig", &["KernelMemory", "KernelMemoryTCP"])?;
    // of no effect here: AttachStdin, AttachStdout, AttachStderr and
    // StdinOnce (what is attached is chosen by the attach), ArgsEscaped
    // (Windows), OnBuild and Shell (for builds), ContainerIDFile (the
    // client writes it), ConsoleSize (the attach sizes the terminal)
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_mappings_of_a_spec_are_checked() {
        use serde_json::json;
        let ports = |m: serde_json::Value| {
            let mut req = CreateContainerRequest::default();
            port_mappings(&json!({"portmappings": [m]}), &mut req).map(|_| req.ports)
        };
        let p = ports(json!({"container_port": 80, "host_port": 8080, "range": 2})).unwrap();
        assert_eq!(
            p.iter()
                .map(|m| (m.container_port, m.host_port))
                .collect::<Vec<_>>(),
            [(80, Some(8080)), (81, Some(8081))]
        );
        for bad in [
            json!({"container_port": 65616}),
            json!({"container_port": -1}),
            json!({"container_port": 80, "host_port": 70000}),
            json!({"container_port": 80, "range": 4_000_000_000u64}),
            json!({"container_port": 65535, "range": 2}),
            json!({"container_port": 80, "host_port": 65535, "range": 2}),
        ] {
            let e = ports(bad.clone()).unwrap_err();
            assert_eq!(e.status.as_u16(), 400, "{bad}");
        }
        ports(json!({"container_port": 65535})).unwrap();
    }

    #[test]
    fn a_network_namespace_path_is_the_ns_mode() {
        let mut req = CreateContainerRequest::default();
        netns(
            &serde_json::json!({"netns": {"nsmode": "path", "value": "/run/netns/x"}}),
            &mut req,
            "",
        )
        .unwrap();
        assert_eq!(req.network_mode, NetworkMode::Ns("/run/netns/x".into()));
    }

    #[test]
    fn a_swappiness_is_refused_unless_it_is_not_set() {
        use serde_json::json;
        for v in [json!(0), json!(60)] {
            let e = refuse_swappiness(&json!({"swappiness": v}), "swappiness", "x").unwrap_err();
            assert_eq!(e.status.as_u16(), 501);
        }
        refuse_swappiness(&json!({"swappiness": -1}), "swappiness", "x").unwrap();
        refuse_swappiness(&json!({"swappiness": null}), "swappiness", "x").unwrap();
        refuse_swappiness(&json!({}), "swappiness", "x").unwrap();
    }

    #[test]
    fn spec_generator_fields_are_applied_or_refused() {
        let mut req = CreateContainerRequest::default();
        other_fields(
            &serde_json::json!({
                "sdnotifyMode": "ignore", "cgroups_mode": "split",
                "image_volume_mode": "anonymous", "publish_image_ports": true,
                "use_image_hostname": true, "manage_password": false,
                "oci_runtime": "/usr/bin/crun", "seccomp_policy": "default",
                "containerCreateCommand": ["podman", "run"], "volatile": true,
            }),
            &mut req,
        )
        .unwrap();
        assert_eq!(
            (
                req.sdnotify.as_str(),
                req.cgroups,
                req.image_volume.as_str()
            ),
            ("ignore", CgroupsMode::Split, "")
        );
        assert!(req.publish_all && req.no_hostname && req.no_passwd);
        assert_eq!(req.runtime.as_deref(), Some("/usr/bin/crun"));
        for f in [
            serde_json::json!({"gpus": ["all"]}),
            serde_json::json!({"network_options": {"pasta": ["-T"]}}),
            serde_json::json!({"intelRdt": {"l3CacheSchema": "L3:0=f"}}),
        ] {
            let mut req = CreateContainerRequest::default();
            assert!(other_fields(&f, &mut req).is_err(), "{f}");
        }
        // podman's signature_policy is the security option
        let mut req = CreateContainerRequest::default();
        other_fields(
            &serde_json::json!({"signature_policy": "require", "verity_enforce": true}),
            &mut req,
        )
        .unwrap();
        assert_eq!(req.security_opts, ["signature=require", "verity=enforce"]);
        // what the request has for the options of the command line
        let mut req = CreateContainerRequest::default();
        other_fields(
            &serde_json::json!({
                "hostusers": ["bob", "1000"], "chroot_directories": ["/c"],
                "seccomp_policy": "image", "base_hosts_file": "none",
                "intelRdt": {"closID": "gold"},
            }),
            &mut req,
        )
        .unwrap();
        assert_eq!(
            (
                req.host_users,
                req.chroot_dirs,
                req.seccomp_policy.as_deref(),
                req.hosts_file.as_deref(),
                req.rdt_class.as_deref()
            ),
            (
                vec!["bob".to_string(), "1000".into()],
                vec!["/c".to_string()],
                Some("image"),
                Some("none"),
                Some("gold")
            )
        );
        // pasta's options, with pasta
        let mut req = CreateContainerRequest {
            network_mode: NetworkMode::parse("pasta"),
            ..Default::default()
        };
        other_fields(
            &serde_json::json!({"network_options": {"pasta": ["-T", "none"]}}),
            &mut req,
        )
        .unwrap();
        assert_eq!(req.network_mode.to_string(), "pasta:-T,none");
        // an on-failure action needs a health check
        let mut req = CreateContainerRequest::default();
        assert!(other_fields(
            &serde_json::json!({"health_check_on_failure_action": 2}),
            &mut req
        )
        .is_err());
    }

    #[test]
    fn docker_fields_are_applied_or_refused() {
        let mut req = CreateContainerRequest::default();
        let body = serde_json::json!({"NetworkDisabled": true, "AttachStdout": true});
        let host = serde_json::json!({
            "PublishAllPorts": true, "Umask": "0077",
            "LogConfig": {"Type": "none", "Config": {}},
            "MaskedPaths": [], "ReadonlyPaths": [],
        });
        docker_other_fields(&body, &host, &mut req).unwrap();
        assert!(req.publish_all);
        assert_eq!(req.network_mode, NetworkMode::Off);
        assert_eq!(req.umask.as_deref(), Some("0077"));
        assert_eq!(
            req.log_config.as_ref().map(|l| l.driver.as_str()),
            Some("none")
        );
        assert_eq!(req.security_opts, ["unmask=ALL"]);
        for (body, host) in [
            (
                serde_json::json!({"Domainname": "x"}),
                serde_json::json!({}),
            ),
            (
                serde_json::json!({}),
                serde_json::json!({"MaskedPaths": ["/proc/x"]}),
            ),
            (serde_json::json!({}), serde_json::json!({"CpuCount": 2})),
        ] {
            let mut req = CreateContainerRequest::default();
            assert!(
                docker_other_fields(&body, &host, &mut req).is_err(),
                "{body} {host}"
            );
        }
    }

    #[test]
    fn unsupported_spec_generator_members_are_refused() {
        use serde_json::json;
        for (body, name) in [
            (
                json!({"personality": {"flags": ["ADDR_NO_RANDOMIZE"]}}),
                "personality.flags",
            ),
            (
                json!({"mounts": [{"uidMappings": [{"containerID": 0, "hostID": 1, "size": 1}]}]}),
                "mounts.uidMappings",
            ),
            (
                json!({"mounts": [{"gidMappings": [{"containerID": 0, "hostID": 1, "size": 1}]}]}),
                "mounts.gidMappings",
            ),
            (
                json!({"idmappings": {"AutoUserNsOpts": {"InitialSize": 4}}}),
                "idmappings.AutoUserNsOpts.InitialSize",
            ),
            (
                json!({"idmappings": {"AutoUserNsOpts": {"PasswdFile": "/p"}}}),
                "idmappings.AutoUserNsOpts.PasswdFile",
            ),
            (
                json!({"idmappings": {"AutoUserNsOpts": {"AdditionalUIDMappings": [{"container_id": 0, "host_id": 1, "size": 1}]}}}),
                "idmappings.AutoUserNsOpts.AdditionalUIDMappings",
            ),
            (
                json!({"weightDevice": {"/dev/x": {"leafWeight": 5}}}),
                "weightDevice.leafWeight",
            ),
            (
                json!({"resource_limits": {"memory": {"kernel": 1}}}),
                "resource_limits.memory.kernel",
            ),
            (
                json!({"resource_limits": {"memory": {"kernelTCP": 1}}}),
                "resource_limits.memory.kernelTCP",
            ),
            (
                json!({"resource_limits": {"memory": {"useHierarchy": true}}}),
                "resource_limits.memory.useHierarchy",
            ),
            (
                json!({"resource_limits": {"memory": {"checkBeforeUpdate": true}}}),
                "resource_limits.memory.checkBeforeUpdate",
            ),
            (
                json!({"resource_limits": {"cpu": {"burst": 5}}}),
                "resource_limits.cpu.burst",
            ),
            (
                json!({"resource_limits": {"cpu": {"idle": 1}}}),
                "resource_limits.cpu.idle",
            ),
            (
                json!({"resource_limits": {"network": {"classID": 1}}}),
                "resource_limits.network",
            ),
            (
                json!({"resource_limits": {"rdma": {"mlx": {"hcaHandles": 1}}}}),
                "resource_limits.rdma",
            ),
            (
                json!({"resource_limits": {"blockIO": {"leafWeight": 10}}}),
                "resource_limits.blockIO.leafWeight",
            ),
            (
                json!({"resource_limits": {"blockIO": {"weightDevice": [{"major": 1, "minor": 2, "leafWeight": 10}]}}}),
                "resource_limits.blockIO.weightDevice.leafWeight",
            ),
            (
                json!({"resource_limits": {"blockIO": {"throttleReadBpsDevice": [{"major": 1, "minor": 2, "rate": 10}]}}}),
                "resource_limits.blockIO.throttleReadBpsDevice",
            ),
        ] {
            let e = refuse_unsupported(&body).expect_err(&body.to_string());
            assert_eq!(e.status.as_u16(), 501, "{body}");
            assert!(e.message.contains(name), "{}: {}", name, e.message);
        }
        // zero values, as a client sends them, are no setting
        refuse_unsupported(&json!({
            "personality": {"domain": "LINUX", "flags": []},
            "mounts": [{"uidMappings": null, "gidMappings": []}],
            "resource_limits": {"memory": {"kernel": 0, "useHierarchy": false}, "cpu": {"idle": 0}},
            "idmappings": {"AutoUserNsOpts": {"Size": 4, "InitialSize": 0}},
        }))
        .unwrap();
    }

    #[test]
    fn networks_of_a_spec_generator() {
        use serde_json::json;
        let mut req = CreateContainerRequest::default();
        netns(
            &json!({"netns": {"nsmode": "bridge"}, "cni_networks": ["a", "b"]}),
            &mut req,
            "",
        )
        .unwrap();
        assert_eq!(req.networks, ["a", "b"]);
        for (body, name) in [
            (
                json!({"Networks": {"n": {"options": {"mode": "x"}}}}),
                "Networks.options",
            ),
            (
                json!({"Networks": {"n": {"interface_name": "e0"}}}),
                "Networks.interface_name",
            ),
        ] {
            let mut req = CreateContainerRequest::default();
            let e = netns(&body, &mut req, "").unwrap_err();
            assert!(e.message.contains(name), "{}", e.message);
        }
        // addresses are not dropped: one of a family, on one network
        for body in [
            json!({"Networks": {"n": {"static_ips": ["10.0.0.2", "10.0.0.3"]}}}),
            json!({"Networks": {"n": {"static_ips": ["10.0.0.2"]}, "m": {"static_ips": ["10.1.0.2"]}}}),
            json!({"Networks": {"n": {"static_mac": "aa:bb:cc:dd:ee:01"}, "m": {"static_mac": "aa:bb:cc:dd:ee:02"}}}),
        ] {
            let mut req = CreateContainerRequest::default();
            assert_eq!(
                netns(&body, &mut req, "").unwrap_err().status.as_u16(),
                501,
                "{body}"
            );
        }
        let mut req = CreateContainerRequest::default();
        netns(
            &json!({"Networks": {"n": {"static_ips": ["10.0.0.2", "fd00::2"], "static_mac": "aa:bb:cc:dd:ee:01"}}}),
            &mut req,
            "",
        )
        .unwrap();
        assert_eq!(req.ip_address.as_deref(), Some("10.0.0.2"));
        assert_eq!(req.ip6_address.as_deref(), Some("fd00::2"));
    }

    #[test]
    fn docker_mounts_and_endpoints() {
        use serde_json::json;
        let (typ, arg) = docker_mount_arg(&json!({
            "Type": "bind", "Source": "/s", "Target": "/t",
            "BindOptions": {"Propagation": "rslave", "NonRecursive": true},
        }))
        .unwrap();
        assert_eq!(typ, "bind");
        assert_eq!(
            arg,
            "type=bind,target=/t,source=/s,bind-propagation=rslave,bind-nonrecursive"
        );
        // the subpath of an image mount
        let (_, arg) = docker_mount_arg(&json!({
            "Type": "image", "Source": "img", "Target": "/t",
            "ImageOptions": {"Subpath": "sub"},
        }))
        .unwrap();
        assert_eq!(arg, "type=image,target=/t,source=img,subpath=sub");
        for (m, name) in [
            (
                json!({"Type": "bind", "ClusterOptions": {"x": 1}}),
                "ClusterOptions",
            ),
            (
                json!({"Type": "volume", "VolumeOptions": {"Labels": {"a": "b"}}}),
                "VolumeOptions.Labels",
            ),
            (
                json!({"Type": "volume", "VolumeOptions": {"DriverConfig": {"Options": {"a": "b"}}}}),
                "DriverConfig.Options",
            ),
            (
                json!({"Type": "bind", "BindOptions": {"CreateMountpoint": true}}),
                "CreateMountpoint",
            ),
            (
                json!({"Type": "bind", "BindOptions": {"ReadOnlyNonRecursive": true}}),
                "ReadOnlyNonRecursive",
            ),
            (
                json!({"Type": "bind", "BindOptions": {"ReadOnlyForceRecursive": true}}),
                "ReadOnlyForceRecursive",
            ),
        ] {
            let e = docker_mount_arg(&m).unwrap_err();
            assert_eq!(e.status.as_u16(), 501, "{m}");
            assert!(e.message.contains(name), "{}", e.message);
        }
        let e = refuse_endpoint(
            &json!({"IPAMConfig": {"LinkLocalIPs": ["169.254.1.1"]}}),
            "NetworkingConfig.EndpointsConfig",
        )
        .unwrap_err();
        assert!(e.message.contains("LinkLocalIPs"), "{}", e.message);
        refuse_endpoint(
            &json!({"DriverOpts": {"a": "b"}, "GwPriority": 1, "Links": ["c:d"], "Aliases": ["x"]}),
            "e",
        )
        .unwrap();
        // podman's own members of its compat create
        let mut req = CreateContainerRequest::default();
        docker_env(
            &json!({"Env": ["A=1"], "EnvMerge": ["B=2"], "UnsetEnv": ["PATH"], "UnsetEnvAll": true}),
            &mut req,
        );
        assert_eq!(
            (req.env, req.env_merge, req.unsetenv, req.unsetenv_all),
            (
                vec!["A=1".to_string()],
                vec!["B=2".to_string()],
                vec!["PATH".to_string()],
                true
            )
        );
        let e = docker_other_fields(
            &json!({}),
            &json!({"KernelMemory": 4096}),
            &mut CreateContainerRequest::default(),
        )
        .unwrap_err();
        assert!(e.message.contains("KernelMemory"), "{}", e.message);
    }

    #[test]
    fn mount_options_as_podman() {
        let v = |o: &[&str]| o.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            tmpfs_options(&v(&["noexec", "ro", "size=67"])).unwrap(),
            v(&[
                "noexec",
                "ro",
                "size=67",
                "rprivate",
                "nosuid",
                "nodev",
                "tmpcopyup"
            ])
        );
        assert_eq!(
            tmpfs_options(&v(&["rw", "noatime", "dev", "notmpcopyup"])).unwrap(),
            v(&["rw", "noatime", "dev", "rprivate", "nosuid"])
        );
        assert!(tmpfs_options(&v(&["bind"])).is_err());
        assert!(check_bind_options(&v(&["ro", "noatime"])).is_err());
        assert!(check_bind_options(&v(&["ro", "z"])).is_ok());
    }

    #[test]
    fn fields_match_without_case_when_no_name_is_exact() {
        let v = serde_json::json!({"Image": "a", "name": "b", "Name": "c"});
        assert_eq!(s(&v, "image"), "a");
        assert_eq!(s(&v, "name"), "b");
        assert_eq!(s(&v, "Name"), "c");
        assert!(field(&v, "missing").is_none());
        assert!(field(&serde_json::json!([1]), "image").is_none());
    }

    #[test]
    fn publish_specs() {
        let p = parse_publish("8080:80/tcp").unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].container_port, p[0].host_port), (80, Some(8080)));
        let p = parse_publish("127.0.0.1:8080:80/udp").unwrap();
        assert_eq!(p[0].host_ip, "127.0.0.1");
        assert_eq!(p[0].protocol, "udp");
        let p = parse_publish("[::1]:9:80").unwrap();
        assert_eq!(p[0].host_ip, "::1");
        let p = parse_publish("80").unwrap();
        assert_eq!(p[0].host_port, None);
        let p = parse_publish("8000-8002:80-82").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!((p[2].container_port, p[2].host_port), (82, Some(8002)));
        let p = parse_publish("53/tcp,udp").unwrap();
        assert_eq!(p.len(), 2);
        assert!(parse_publish("a:b:c:d").is_err());
        assert!(parse_publish("x").is_err());
        // (the refusals the command line has: port 0, an address that is
        // none, ranges of different sizes)
        assert!(parse_publish("0:80").is_err());
        assert!(parse_publish("8080:0").is_err());
        assert!(parse_publish("nope:8080:80").is_err());
        assert!(parse_publish("8000-8002:80").is_err());
    }

    #[test]
    fn docker_port_bindings() {
        let one = |ip, port| parse_publish(&binding_spec(ip, port, "80", "tcp")).unwrap();
        let p = one("", "8080");
        assert_eq!((p[0].host_ip.as_str(), p[0].host_port), ("", Some(8080)));
        assert_eq!(one("", "")[0].host_port, None);
        assert_eq!(one("127.0.0.1", "8080")[0].host_ip, "127.0.0.1");
        assert_eq!(one("127.0.0.1", "")[0].host_port, None);
        // (IPv6 without brackets, as Docker sends it)
        let p = one("::1", "8080");
        assert_eq!((p[0].host_ip.as_str(), p[0].host_port), ("::1", Some(8080)));
        assert_eq!(one("::", "8080")[0].host_ip, "");
        assert_eq!(one("[::1]", "")[0].host_ip, "::1");
    }

    #[test]
    fn devices() {
        let d = parse_device("/dev/null:/dev/mynull");
        assert_eq!(
            (d.path_on_host.as_str(), d.path_in_container.as_str()),
            ("/dev/null", "/dev/mynull")
        );
        assert_eq!(d.cgroup_permissions, "rwm");
        let d = parse_device("/dev/fuse:rw");
        assert_eq!(d.path_in_container, "/dev/fuse");
        assert_eq!(d.cgroup_permissions, "rw");
        let d = parse_device("/dev/null:/dev/x:r");
        assert_eq!(d.cgroup_permissions, "r");
        // a CDI device is its name, whatever it holds
        let d = parse_device("vendor.com/class=a:b");
        assert_eq!(d.path_on_host, "vendor.com/class=a:b");
        assert_eq!(d.path_in_container, "");
    }

    #[test]
    fn startup_health_and_log_options() {
        let spec = serde_json::json!({
            "startupHealthConfig": {"Test": ["CMD-SHELL", "test -e /ok"], "Interval": 2_000_000_000u64,
                                    "Retries": 3, "Successes": 2},
            "healthLogDestination": "local", "healthMaxLogCount": 7, "healthMaxLogSize": 100
        });
        let mut req = CreateContainerRequest {
            healthcheck: Some(Healthcheck {
                test: vec!["CMD".into(), "true".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        health_extras(&spec, &mut req).unwrap();
        let hc = req.healthcheck.unwrap();
        let st = hc.startup.unwrap();
        assert_eq!(st.test, ["CMD-SHELL", "test -e /ok"]);
        assert_eq!(
            (st.interval_ns, st.retries, st.successes),
            (2_000_000_000, 3, 2)
        );
        assert_eq!(
            (
                hc.log_destination.as_str(),
                hc.max_log_count,
                hc.max_log_size
            ),
            ("local", Some(7), Some(100))
        );
        // A startup check without a health check is refused.
        let mut req = CreateContainerRequest::default();
        assert!(health_extras(&spec, &mut req).is_err());
    }

    #[test]
    fn health() {
        let h: Value =
            serde_json::json!({"Test": ["CMD-SHELL", "true"], "Interval": 5, "Retries": 3});
        let hc = health_from(&h, false).unwrap().unwrap();
        assert_eq!(hc.test, ["CMD-SHELL", "true"]);
        assert_eq!((hc.interval_ns, hc.retries, hc.timeout_ns), (5, 3, 0));
        assert!(health_from(&serde_json::json!({"Test": ["NONE"]}), true)
            .unwrap()
            .is_none());
        assert!(health_from(&serde_json::json!({}), true).is_none());
        // Docker's clients get the default times
        let hc = health_from(&serde_json::json!({"Test": ["true"]}), true)
            .unwrap()
            .unwrap();
        assert_eq!(hc.test, ["CMD-SHELL", "true"]);
        assert_eq!(
            (hc.interval_ns, hc.timeout_ns, hc.retries),
            (30_000_000_000, 30_000_000_000, 3)
        );
        let hc = health_from(&serde_json::json!({"Test": ["/bin/x", "a b"]}), false)
            .unwrap()
            .unwrap();
        assert_eq!(hc.test, ["CMD", "/bin/x", "a b"]);
        // no command: the image's, with these times
        let hc = health_from(&serde_json::json!({"Test": [], "Retries": 4}), true)
            .unwrap()
            .unwrap();
        assert!(hc.test.is_empty());
        assert_eq!(hc.retries, 4);
        assert!(health_from(&serde_json::json!({"Test": []}), true).is_none());
    }

    /// What a zero or negative time of a health check means: libpod keeps a
    /// spec with a command as it is (no timer for an interval of 0, an
    /// unhealthy container after one failure for 0 retries), Docker's
    /// clients get the defaults, and a spec without a command inherits.
    #[test]
    fn a_zero_health_time_means_what_the_api_says() {
        let t = |h: Value, compat| health_from(&h, compat).unwrap().unwrap();
        // libpod: interval 0 with a command is no timer, retries 0 is one,
        // timeout 0 is none; inspect shows them as given
        let hc = t(
            serde_json::json!({"Test": ["CMD-SHELL", "true"], "Interval": 0}),
            false,
        );
        assert!(hc.interval_disabled);
        assert_eq!(hc.interval(), None);
        assert_eq!(hc.failures_allowed(), 1);
        assert_eq!(hc.timeout(), None);
        assert_eq!((hc.interval_ns, hc.timeout_ns, hc.retries), (0, 0, 0));
        let hc = t(serde_json::json!({"Test": ["CMD-SHELL", "true"]}), false);
        assert!(hc.interval_disabled);
        let hc = t(
            serde_json::json!({"Test": ["CMD-SHELL", "true"], "Interval": 5_000_000_000u64, "Retries": 2}),
            false,
        );
        assert_eq!(hc.interval(), Some(std::time::Duration::from_secs(5)));
        assert_eq!(hc.failures_allowed(), 2);
        // libpod, no command: 0 inherits, a negative interval disables
        let hc = t(serde_json::json!({"Test": [], "Interval": -1}), false);
        assert!(hc.interval_disabled && hc.test.is_empty());
        let hc = t(
            serde_json::json!({"Test": [], "Interval": 0, "Retries": 4}),
            false,
        );
        assert!(!hc.interval_disabled);
        // Docker: 0 is the default with a command, a negative interval
        // disables the image's check
        let hc = t(
            serde_json::json!({"Test": ["CMD-SHELL", "true"], "Interval": 0}),
            true,
        );
        assert!(!hc.interval_disabled);
        assert_eq!(hc.interval(), Some(std::time::Duration::from_secs(30)));
        assert_eq!(hc.timeout(), Some(std::time::Duration::from_secs(30)));
        assert_eq!(hc.failures_allowed(), 3);
        let hc = t(
            serde_json::json!({"Test": ["CMD-SHELL", "true"], "Interval": -1}),
            true,
        );
        assert!(!hc.interval_disabled);
        let hc = t(serde_json::json!({"Interval": -1}), true);
        assert!(hc.interval_disabled && hc.test.is_empty());
        // NONE is no check for both
        for compat in [false, true] {
            assert!(health_from(
                &serde_json::json!({"Test": ["NONE"], "Interval": 0}),
                compat
            )
            .unwrap()
            .is_none());
        }
    }
}
