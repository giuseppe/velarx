// SPDX-License-Identifier: Apache-2.0
//! Containers: podman's InspectContainerData and ListContainer, Docker's
//! ContainerJSON and Summary.

use crate::{string_map, time::rfc3339, units::human_duration};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use velarx_proto::health::{Health, HealthStatus, LOG_ENTRIES, LOG_OUTPUT_CHARS};
use velarx_proto::workload::{
    ContainerInterface, ContainerMount, ContainerPort, ContainerRecord, DeviceLimit, MountKind,
    RunState,
};

/// podman's word of a state.
pub fn state_word(s: RunState) -> &'static str {
    match s {
        RunState::Created => "created",
        RunState::Initialized => "initialized",
        RunState::Running => "running",
        RunState::Paused => "paused",
        RunState::Stopping => "stopping",
        RunState::Exited => "exited",
        RunState::Unknown => "unknown",
    }
}

/// Docker's word of a state: it has no initialized nor stopping.
fn docker_state_word(s: RunState) -> &'static str {
    match s {
        RunState::Initialized => "created",
        RunState::Stopping => "running",
        s => state_word(s),
    }
}

/// The command line: entrypoint and command.
fn args(c: &ContainerRecord) -> Vec<String> {
    let mut a = c.process.entrypoint.clone();
    a.extend(c.process.command.iter().cloned());
    a
}

/// `"80/tcp"` keys of the published and exposed ports.
fn port_keys(c: &ContainerRecord) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    let published = c
        .network
        .ports
        .iter()
        .map(|p| format!("{}/{}", p.container_port, p.protocol));
    // (a range is one key a port, as podman's GenExposedPorts)
    let exposed = c.network.exposed.iter().flat_map(|e| {
        let (ports, proto) = e.split_once('/').unwrap_or((e.as_str(), "tcp"));
        let proto = if proto.is_empty() { "tcp" } else { proto };
        match ports
            .split_once('-')
            .map(|(a, b)| (a.parse::<u16>(), b.parse::<u16>()))
        {
            Some((Ok(first), Ok(last))) => (first..=last.max(first))
                .map(|p| format!("{p}/{proto}"))
                .collect::<Vec<_>>(),
            _ => vec![e.clone()],
        }
    });
    for k in published.chain(exposed) {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    keys
}

fn host_port(p: &ContainerPort) -> String {
    if p.host_port > 0 {
        p.host_port.to_string()
    } else {
        String::new()
    }
}

/// The ports as asked, by `"80/tcp"`; `any_ip` for those of every address.
fn port_bindings(ports: &[ContainerPort], any_ip: &str) -> Value {
    let mut out = Map::new();
    for p in ports {
        let ip = if p.host_ip.is_empty() {
            any_ip
        } else {
            &p.host_ip
        };
        let entry = json!({"HostIp": ip, "HostPort": host_port(p)});
        if let Some(a) = out
            .entry(format!("{}/{}", p.container_port, p.protocol))
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            a.push(entry)
        }
    }
    Value::Object(out)
}

/// The ports bound, as `NetworkSettings.Ports`: one entry per port of a
/// range.
fn bound_ports(ports: &[ContainerPort]) -> Value {
    let mut out = Map::new();
    for p in ports {
        let ip = if p.host_ip.is_empty() {
            "0.0.0.0"
        } else {
            &p.host_ip
        };
        for k in 0..p.range.max(1) {
            let (c, h) = (p.container_port + k, p.host_port + k);
            if c > 65535 || h > 65535 {
                break;
            }
            if let Some(a) = out
                .entry(format!("{c}/{}", p.protocol))
                .or_insert_with(|| json!([]))
                .as_array_mut()
            {
                a.push(json!({"HostIp": ip, "HostPort": h.to_string()}))
            }
        }
    }
    Value::Object(out)
}

fn state_shape(c: &ContainerRecord) -> Value {
    let mut o = Map::new();
    let running = matches!(c.state, RunState::Running | RunState::Paused);
    o.insert("OciVersion".into(), json!("1.2.1"));
    o.insert("Status".into(), json!(state_word(c.state)));
    o.insert("Running".into(), json!(running));
    o.insert("Paused".into(), json!(c.state == RunState::Paused));
    o.insert("Restarting".into(), json!(false));
    o.insert("OOMKilled".into(), json!(c.oom_killed));
    o.insert("StoppedByUser".into(), json!(c.stopped_by_user));
    o.insert("Dead".into(), json!(false));
    o.insert("Pid".into(), json!(c.pid));
    o.insert("ConmonPid".into(), json!(c.monitor_pid));
    o.insert("CgroupPath".into(), json!(c.cgroup_path));
    o.insert("ExitCode".into(), json!(c.exit_code));
    o.insert("Error".into(), json!(c.error));
    o.insert("TimedOut".into(), json!(c.timed_out));
    o.insert("StartedAt".into(), json!(rfc3339(c.started_ns)));
    o.insert("FinishedAt".into(), json!(rfc3339(c.finished_ns)));
    // podman's: the checkpoint that is there, and the last restore
    let cp = &c.checkpoint;
    o.insert("Checkpointed".into(), json!(cp.checkpointed));
    o.insert("CheckpointedAt".into(), json!(rfc3339(cp.checkpointed_ns)));
    o.insert("CheckpointPath".into(), json!(cp.path));
    o.insert("CheckpointLog".into(), json!(cp.log_path));
    o.insert("Restored".into(), json!(cp.restored));
    o.insert("RestoredAt".into(), json!(rfc3339(cp.restored_ns)));
    if let Some(h) = health_of(c) {
        o.insert("Health".into(), h);
    }
    Value::Object(o)
}

/// podman's health of a container: the results, or `starting` for a
/// check that has not run yet; `None` without a health check.
fn health_of(c: &ContainerRecord) -> Option<Value> {
    if let Some(h) = &c.health {
        return Some(health(h));
    }
    c.process
        .healthcheck
        .as_ref()
        .is_some_and(|h| h.test.first().is_some_and(|t| t != "NONE"))
        .then(|| json!({"Status": "starting", "FailingStreak": 0, "Log": []}))
}

/// podman's HealthCheckResults: the status, the failures since the last
/// success and the last results, the oldest first.
pub fn health(h: &Health) -> Value {
    let log: Vec<Value> = h
        .log
        .iter()
        .map(|r| {
            json!({
                "Start": rfc3339(r.start_ns),
                "End": rfc3339(r.end_ns),
                "ExitCode": r.exit_code,
                "Output": r.output,
            })
        })
        .collect();
    json!({"Status": h.status.word(), "FailingStreak": h.failing_streak, "Log": log})
}

fn config_shape(c: &ContainerRecord) -> Value {
    let p = &c.process;
    let mut exposed = Map::new();
    for k in port_keys(c) {
        exposed.insert(k, json!({}));
    }
    let mut o = Map::new();
    o.insert("Hostname".into(), json!(p.hostname));
    o.insert("Domainname".into(), json!(p.domainname));
    o.insert("User".into(), json!(p.user));
    o.insert("AttachStdin".into(), json!(c.stdin));
    o.insert("AttachStdout".into(), json!(false));
    o.insert("AttachStderr".into(), json!(false));
    o.insert("Tty".into(), json!(c.tty));
    o.insert("OpenStdin".into(), json!(c.stdin));
    o.insert("StdinOnce".into(), json!(false));
    o.insert("Env".into(), json!(p.env));
    o.insert("Cmd".into(), json!(p.command));
    o.insert("Image".into(), json!(c.image));
    o.insert("Volumes".into(), Value::Null);
    o.insert("ExposedPorts".into(), Value::Object(exposed));
    o.insert("WorkingDir".into(), json!(p.work_dir));
    o.insert("Entrypoint".into(), json!(p.entrypoint));
    o.insert("OnBuild".into(), Value::Null);
    o.insert("Labels".into(), string_map(&c.labels));
    o.insert("Annotations".into(), string_map(&c.annotations));
    o.insert(
        "StopSignal".into(),
        json!(if p.stop_signal.is_empty() {
            "SIGTERM"
        } else {
            &p.stop_signal
        }),
    );
    o.insert("Timeout".into(), json!(0));
    o.insert("SystemdMode".into(), json!(p.systemd));
    o.insert("StopTimeout".into(), json!(p.stop_timeout));
    if let Some(h) = &p.healthcheck {
        // an argument vector is a CMD
        let test: Vec<String> = match h.test.first().map(String::as_str) {
            Some("CMD" | "CMD-SHELL" | "NONE") => h.test.clone(),
            _ => std::iter::once("CMD".to_string())
                .chain(h.test.iter().cloned())
                .collect(),
        };
        let mut check = json!({
            "Test": test,
            "Interval": h.interval_ns,
            "Timeout": h.timeout_ns,
            "StartPeriod": h.start_period_ns,
            "Retries": h.retries,
        });
        if h.start_interval_ns != 0 {
            check["StartInterval"] = json!(h.start_interval_ns);
        }
        o.insert("Healthcheck".into(), check);
        // libpod's startup check
        if let Some(st) = &h.startup {
            o.insert(
                "StartupHealthCheck".into(),
                json!({
                    "Test": st.test,
                    "Interval": st.interval_ns,
                    "Timeout": st.timeout_ns,
                    "Retries": st.retries,
                    "Successes": st.successes,
                }),
            );
        }
    }
    // libpod's
    let on_failure = p
        .healthcheck
        .as_ref()
        .map_or("none", |h| h.on_failure.word());
    o.insert("HealthcheckOnFailureAction".into(), json!(on_failure));
    // the command line that made it (none from the API)
    o.insert(
        "CreateCommand".into(),
        if p.create_command.is_empty() {
            Value::Null
        } else {
            json!(p.create_command)
        },
    );
    o.insert("Passwd".into(), json!(p.passwd));
    o.insert("sdNotifyMode".into(), json!(p.sdnotify_mode));
    // libpod's: dropped for Docker clients
    o.insert("Umask".into(), json!(p.umask));
    // the health log options of the check, else podman's defaults
    let hc = p.healthcheck.as_ref();
    o.insert(
        "HealthLogDestination".into(),
        json!(hc
            .map(|h| h.log_destination.as_str())
            .filter(|d| !d.is_empty())
            .unwrap_or("local")),
    );
    o.insert(
        "HealthcheckMaxLogCount".into(),
        json!(hc.map_or(LOG_ENTRIES, |h| h.log_count())),
    );
    o.insert(
        "HealthcheckMaxLogSize".into(),
        json!(hc.map_or(LOG_OUTPUT_CHARS, |h| h.log_size())),
    );
    Value::Object(o)
}

/// A mount as `Mounts` of the inspect has it.
fn mount_shape(m: &ContainerMount) -> Value {
    let mut o = Map::new();
    match m.kind {
        MountKind::Image => {
            o.insert("Type".into(), json!("image"));
            o.insert("SubPath".into(), json!(m.sub_path));
        }
        MountKind::Volume => {
            o.insert("Type".into(), json!("volume"));
            o.insert("Name".into(), json!(m.name));
            o.insert("Driver".into(), json!("local"));
        }
        MountKind::Tmpfs => {
            o.insert("Type".into(), json!("tmpfs"));
        }
        MountKind::Bind => {
            o.insert("Type".into(), json!("bind"));
        }
    }
    o.insert("Source".into(), json!(m.source));
    o.insert("Destination".into(), json!(m.destination));
    o.insert("Mode".into(), json!(""));
    o.insert("Options".into(), json!(m.options));
    o.insert("RW".into(), json!(!m.read_only));
    o.insert(
        "Propagation".into(),
        json!(if m.kind == MountKind::Bind {
            m.propagation.as_str()
        } else {
            ""
        }),
    );
    Value::Object(o)
}

fn endpoint(c: &ContainerRecord, i: Option<&ContainerInterface>) -> Value {
    let s = |f: fn(&ContainerInterface) -> &String| i.map(f).cloned().unwrap_or_default();
    let ip6 = s(|i| &i.ip6);
    let mac = match i {
        Some(i) => i.mac.clone(),
        None => c.network.mac_address.clone(),
    };
    json!({
        "EndpointID": "",
        "Gateway": s(|i| &i.gateway),
        "IPAddress": s(|i| &i.ip),
        "IPPrefixLen": i.map_or(0, |i| i.prefix_len),
        "IPv6Gateway": s(|i| &i.gateway6),
        "GlobalIPv6Address": ip6,
        "GlobalIPv6PrefixLen": if ip6.is_empty() { 0 } else { i.map_or(0, |i| i.prefix6_len) },
        "MacAddress": mac,
        "NetworkID": s(|i| &i.network_id),
        "Aliases": i.map(|i| i.aliases.clone()),
        "DriverOpts": null, "IPAMConfig": null, "Links": null,
        "GwPriority": 0, "DNSNames": null,
    })
}

fn network_settings(c: &ContainerRecord) -> Value {
    let n = &c.network;
    let mut nets = Map::new();
    if n.interfaces.is_empty() {
        for name in &n.networks {
            nets.insert(name.clone(), endpoint(c, None));
        }
    }
    for i in &n.interfaces {
        nets.insert(i.network.clone(), endpoint(c, Some(i)));
    }
    // the host ports bound (a free one picked for those not given)
    let mut ports = if n.bound_ports.is_empty() {
        port_bindings(&n.ports, "0.0.0.0")
    } else {
        bound_ports(&n.bound_ports)
    };
    if let Some(o) = ports.as_object_mut() {
        for k in port_keys(c) {
            o.entry(k).or_insert(Value::Null);
        }
    }
    let mut top = endpoint(c, n.interfaces.first());
    if let Some(o) = top.as_object_mut() {
        for k in [
            "NetworkID",
            "Aliases",
            "DriverOpts",
            "IPAMConfig",
            "Links",
            "GwPriority",
            "DNSNames",
        ] {
            o.remove(k);
        }
        o.insert("Bridge".into(), json!(""));
        o.insert("SandboxID".into(), json!(""));
        o.insert("HairpinMode".into(), json!(false));
        o.insert("LinkLocalIPv6Address".into(), json!(""));
        o.insert("LinkLocalIPv6PrefixLen".into(), json!(0));
        o.insert("Ports".into(), ports);
        o.insert("SandboxKey".into(), json!(n.sandbox_key));
        o.insert("Networks".into(), Value::Object(nets));
    }
    top
}

const PROPAGATIONS: &[&str] = &[
    "private",
    "rprivate",
    "slave",
    "rslave",
    "shared",
    "rshared",
    "unbindable",
    "runbindable",
];

/// A mount as podman's HostConfig.Binds has it: a volume by name with the
/// options asked, a bind with the options it is mounted with (rprivate and
/// rbind unless others were asked, as podman adds them).
fn bind_entry(m: &ContainerMount) -> String {
    if m.named {
        return if m.options.is_empty() {
            format!("{}:{}", m.name, m.destination)
        } else {
            format!("{}:{}:{}", m.name, m.destination, m.options.join(","))
        };
    }
    let mut opts = m.options.clone();
    let has = |o: &[String], set: &[&str]| o.iter().any(|x| set.contains(&x.as_str()));
    if !has(&opts, PROPAGATIONS) {
        opts.push("rprivate".into());
    }
    if !has(&opts, &["bind", "rbind"]) {
        opts.push("rbind".into());
    }
    format!("{}:{}:{}", m.source, m.destination, opts.join(","))
}

/// A size as go-units shows it: powers of 1000, four significant digits.
pub fn human_size(bytes: u64) -> String {
    crate::units::go_size(bytes as f64)
}

fn host_config(c: &ContainerRecord) -> Value {
    let h = &c.host;
    let r = &c.resources;
    let cpus =
        velarx_limit_core::nano_cpus_of(r.cpu_quota, u64::try_from(r.cpu_period).unwrap_or(0));
    let binds: Vec<String> = c
        .mounts
        .iter()
        .filter(|m| m.kind != MountKind::Tmpfs)
        .map(bind_entry)
        .collect();
    let mut tmpfs = Map::new();
    for m in c.mounts.iter().filter(|m| m.kind == MountKind::Tmpfs) {
        tmpfs.insert(m.destination.clone(), json!(m.options.join(",")));
    }
    // the annotations of the create and those podman records of the
    // options (the record has them); null when there are none
    let annotations = c.annotations.clone();
    // (podman's order: GetSecurityOptions)
    let mut security = Vec::new();
    if h.no_new_privileges {
        security.push("no-new-privileges".to_string());
    }
    if let Some(label) = annotations.get("io.podman.annotations.label") {
        security.push(format!("label={label}"));
    }
    if !h.seccomp_profile.is_empty() {
        security.push(format!("seccomp={}", h.seccomp_profile));
    }
    if !h.apparmor_profile.is_empty() {
        security.push(format!("apparmor={}", h.apparmor_profile));
    }
    if c.privileged {
        security.push("unmask=all".to_string());
    }
    // as podman's inspect: RLIMIT_ and the name in capitals
    let ulimits: Vec<Value> = h
        .ulimits
        .iter()
        .map(|u| {
            let name = u.name.to_uppercase();
            let name = if name.starts_with("RLIMIT_") {
                name
            } else {
                format!("RLIMIT_{name}")
            };
            json!({"Name": name, "Soft": u.soft, "Hard": u.hard})
        })
        .collect();
    let mut o = Map::new();
    let mut put = |k: &str, v: Value| {
        o.insert(k.to_string(), v);
    };
    put("Binds", json!(binds));
    put("CgroupMode", json!(h.cgroupns_mode));
    put("CgroupnsMode", json!(h.cgroupns_mode));
    put("CgroupManager", json!(h.cgroup_manager));
    put("CgroupParent", json!(h.cgroup_parent));
    // (podman's: the cid-file annotation)
    put(
        "ContainerIDFile",
        json!(c
            .annotations
            .get("io.podman.annotations.cid-file")
            .map_or("", String::as_str)),
    );
    put(
        "LogConfig",
        json!({
            "Type": h.log_driver,
            "Config": if h.log_options.is_empty() { Value::Null } else { string_map(&h.log_options) },
            "Path": h.log_options.get("path").unwrap_or(&c.paths.log),
            "Tag": h.log_options.get("tag").cloned().unwrap_or_default(),
            "Size": human_size(h.log_max_size.max(0) as u64),
        }),
    );
    put("NetworkMode", json!(c.network.mode));
    put("PortBindings", port_bindings(&c.network.ports, ""));
    put(
        "RestartPolicy",
        json!({
            "Name": if h.restart_policy.is_empty() { "no" } else { &h.restart_policy },
            "MaximumRetryCount": h.restart_retries,
        }),
    );
    put("AutoRemove", json!(h.auto_remove));
    put("AutoRemoveImage", json!(h.auto_remove_image));
    put(
        "Annotations",
        if annotations.is_empty() {
            Value::Null
        } else {
            string_map(&annotations)
        },
    );
    put("VolumeDriver", json!(""));
    put("VolumesFrom", Value::Null);
    put("CapAdd", json!(h.cap_add));
    put("CapDrop", json!(h.cap_drop));
    put("Dns", json!(c.network.dns));
    put("DnsOptions", json!(c.network.dns_options));
    put("DnsSearch", json!(c.network.dns_search));
    put("ExtraHosts", json!(c.network.extra_hosts));
    put("GroupAdd", json!(h.group_add));
    put("IpcMode", json!(h.ipc_mode));
    put("Cgroup", json!(""));
    // podman's two values; `split` and `no-conmon` are in the configuration
    put(
        "Cgroups",
        json!(if h.cgroups == "disabled" {
            "disabled"
        } else {
            "default"
        }),
    );
    put("Links", Value::Null);
    put("PidMode", json!(h.pid_mode));
    put("Privileged", json!(c.privileged));
    put("PublishAllPorts", json!(c.network.publish_all));
    put("ReadonlyRootfs", json!(h.read_only_rootfs));
    put("SecurityOpt", json!(security));
    put("Tmpfs", Value::Object(tmpfs));
    put("UTSMode", json!(h.uts_mode));
    put("UsernsMode", json!(h.userns_mode));
    put("ShmSize", json!(h.shm_size));
    put(
        "Runtime",
        json!(if h.runtime.is_empty() {
            "oci"
        } else {
            &h.runtime
        }),
    );
    put("ConsoleSize", Value::Null);
    put("Isolation", json!(""));
    put("Memory", json!(r.memory_limit));
    put("NanoCpus", json!(cpus));
    put("PidsLimit", json!(h.pids_limit));
    put("CpuShares", json!(r.cpu_shares));
    put("BlkioWeight", json!(h.blkio_weight));
    put("CpusetCpus", json!(r.cpuset_cpus));
    put("CpusetMems", json!(r.cpuset_mems));
    put("MemoryReservation", json!(h.memory_reservation));
    put("MemorySwap", json!(r.memory_swap));
    put("OomScoreAdj", json!(r.oom_score_adj));
    put("OomKillDisable", json!(h.oom_kill_disable));
    put("CpuCount", json!(0));
    put("CpuPercent", json!(0));
    put("CpuPeriod", json!(r.cpu_period));
    put("CpuQuota", json!(r.cpu_quota));
    put("CpuRealtimePeriod", json!(0));
    put("CpuRealtimeRuntime", json!(0));
    put("DiskQuota", json!(0));
    put("IOMaximumBandwidth", json!(0));
    put("IOMaximumIOps", json!(0));
    put("KernelMemory", json!(0));
    put("MemorySwappiness", json!(0));
    put("HostsFile", json!(h.hosts_file));
    put(
        "CgroupConf",
        if r.unified.is_empty() {
            Value::Null
        } else {
            string_map(&r.unified)
        },
    );
    let devices: Vec<Value> = h
        .devices
        .iter()
        .map(|d| {
            json!({
                "PathOnHost": d.host_path,
                "PathInContainer": d.container_path,
                "CgroupPermissions": d.permissions,
            })
        })
        .collect();
    put("Devices", json!(devices));
    // libpod's: null when there are none
    let limits = |list: &[DeviceLimit], key: &str| {
        if list.is_empty() {
            Value::Null
        } else {
            list.iter()
                .map(|l| json!({"Path": l.path, key: l.value}))
                .collect()
        }
    };
    put(
        "BlkioDeviceReadBps",
        limits(&h.blkio_device_read_bps, "Rate"),
    );
    put(
        "BlkioDeviceWriteBps",
        limits(&h.blkio_device_write_bps, "Rate"),
    );
    put(
        "BlkioDeviceReadIOps",
        limits(&h.blkio_device_read_iops, "Rate"),
    );
    put(
        "BlkioDeviceWriteIOps",
        limits(&h.blkio_device_write_iops, "Rate"),
    );
    put(
        "BlkioWeightDevice",
        limits(&h.blkio_weight_device, "Weight"),
    );
    put("Init", json!(c.process.init));
    put("Ulimits", json!(ulimits));
    Value::Object(o)
}

/// podman's InspectContainerData (`podman container inspect`, libpod's
/// route of podman 5).
pub fn libpod_inspect(c: &ContainerRecord) -> Value {
    let args = args(c);
    let p = &c.paths;
    let mut o = Map::new();
    let mut put = |k: &str, v: Value| {
        o.insert(k.to_string(), v);
    };
    put("Id", json!(c.id));
    put("Created", json!(rfc3339(c.created_ns)));
    put("Path", json!(args.first().cloned().unwrap_or_default()));
    put("Args", json!(args.get(1..).unwrap_or_default()));
    put("State", state_shape(c));
    put("Image", json!(c.image_id));
    put("ImageDigest", json!(c.image_digest));
    put("ImageName", json!(c.image));
    put("Rootfs", json!(""));
    put("Pod", json!(c.pod_id));
    put("ResolvConfPath", json!(p.resolv_conf));
    put("HostnamePath", json!(p.hostname));
    put("HostsPath", json!(p.hosts));
    put("OCIConfigPath", json!(p.oci_config));
    put("StaticDir", json!(p.bundle));
    put("OCIRuntime", json!(c.oci_runtime));
    put("ConmonPidFile", json!(p.monitor_pid_file));
    put("PidFile", json!(p.pid_file));
    put("Name", json!(c.name));
    put("RestartCount", json!(c.restart_count));
    put("Driver", json!(p.graph_driver));
    put("MountLabel", json!(c.host.mount_label));
    put("ProcessLabel", json!(c.host.process_label));
    put("AppArmorProfile", json!(c.host.process_apparmor));
    put("EffectiveCaps", json!(c.host.effective_caps));
    put("BoundingCaps", json!(c.host.bounding_caps));
    put("ExecIDs", json!([]));
    put(
        "GraphDriver",
        json!({"Name": p.graph_driver, "Data": p.graph_data}),
    );
    put(
        "Mounts",
        Value::Array(c.mounts.iter().map(mount_shape).collect()),
    );
    put("Dependencies", json!([]));
    put("NetworkSettings", network_settings(c));
    put("Namespace", json!(""));
    put("IsInfra", json!(c.is_infra));
    put("IsService", json!(false));
    put("KubeExitCodePropagation", json!("invalid"));
    put("lockNumber", json!(0));
    put("Config", config_shape(c));
    put("HostConfig", host_config(c));
    put("UseImageHosts", json!(false));
    put("UseImageHostname", json!(false));
    if let Some(rw) = c.size_rw {
        put("SizeRw", json!(rw));
        put("SizeRootFs", json!(c.size_root_fs.unwrap_or(rw)));
    }
    Value::Object(o)
}

/// podman's InspectContainerData as clients older than 5.0 decode it:
/// Config.Entrypoint a string, Config.StopSignal a number (podman's
/// V4PodmanCompatMarshal).
pub fn libpod_v4_inspect(c: &ContainerRecord) -> Value {
    let mut d = libpod_inspect(c);
    d["Config"]["Entrypoint"] = json!(c.process.entrypoint.join(" "));
    d["Config"]["StopSignal"] = json!(c.process.stop_signal_number);
    d
}

/// Docker's ContainerJSON.
pub fn docker_inspect(c: &ContainerRecord) -> Value {
    let mut d = libpod_inspect(c);
    d["Name"] = json!(format!("/{}", c.name));
    if let Some(cfg) = d["Config"].as_object_mut() {
        for k in [
            "Umask",
            "HealthLogDestination",
            "HealthcheckMaxLogCount",
            "HealthcheckMaxLogSize",
        ] {
            cfg.remove(k);
        }
    }
    d["State"]["Status"] = json!(docker_state_word(c.state));
    // Docker's image ids start with the algorithm
    if !c.image_id.is_empty() && crate::without_algorithm(&c.image_id) == c.image_id {
        d["Image"] = json!(crate::id_with_algorithm(&c.image_id));
    }
    d
}

/// Seconds since the epoch, Go's zero time for none.
fn ns_seconds(ns: i64) -> i64 {
    if ns > 0 {
        ns / 1_000_000_000
    } else {
        -62_135_596_800
    }
}

/// podman's ListContainer (`podman ps --format json`, libpod's list).
pub fn libpod_list_entry(c: &ContainerRecord) -> Value {
    // the host ports bound (a free one picked for those not given), else
    // those asked
    let bound = if c.network.bound_ports.is_empty() {
        &c.network.ports
    } else {
        &c.network.bound_ports
    };
    let ports: Vec<Value> = bound
        .iter()
        .map(|p| {
            json!({
                "host_ip": p.host_ip,
                "container_port": p.container_port,
                "host_port": p.host_port,
                "range": p.range.max(1),
                "protocol": p.protocol,
            })
        })
        .collect();
    let mounts: Vec<&str> = c.mounts.iter().map(|m| m.destination.as_str()).collect();
    let mut e = json!({
        "AutoRemove": c.host.auto_remove,
        "Command": args(c),
        "Created": rfc3339(c.created_ns),
        "CreatedAt": "",
        "CIDFile": "",
        "Exited": c.state == RunState::Exited,
        "ExitedAt": ns_seconds(c.finished_ns),
        "ExitCode": c.exit_code,
        "Id": c.id,
        "Image": c.image,
        "ImageID": c.image_id,
        "IsInfra": c.is_infra,
        "Labels": string_map(&c.labels),
        "Mounts": mounts,
        "Names": [c.name],
        "Namespaces": string_map(&c.namespaces),
        "Networks": c.network.networks,
        "Pid": c.pid,
        "Pod": c.pod_id,
        "PodName": c.pod_name,
        "Ports": ports,
        "ExposedPorts": exposed_ports(c),
        // (with the sizes asked for)
        "Size": null,
        "Restarts": 0,
        "StartedAt": ns_seconds(c.started_ns),
        "State": state_word(c.state),
        // (podman's: the health status, empty without a health check)
        "Status": health_of(c).map_or(Value::String(String::new()), |h| h["Status"].clone()),
    });
    if let (Some(rw), Some(root)) = (c.size_rw, c.size_root_fs) {
        e["Size"] = json!({"rwSize": rw, "rootFsSize": root});
    }
    e
}

/// The ports the image and `--expose` expose, as podman's list has them:
/// the protocols of each port number (null when there are none).
fn exposed_ports(c: &ContainerRecord) -> Value {
    let mut out: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for e in &c.network.exposed {
        let (ports, proto) = e.split_once('/').unwrap_or((e.as_str(), "tcp"));
        let proto = if proto.is_empty() { "tcp" } else { proto };
        let (first, last) = ports.split_once('-').unwrap_or((ports, ports));
        let (Ok(first), Ok(last)) = (first.parse::<u16>(), last.parse::<u16>()) else {
            continue;
        };
        for port in first..=last.max(first) {
            let protos = out.entry(port).or_default();
            if !protos.iter().any(|p| p == proto) {
                protos.push(proto.to_string());
            }
        }
    }
    if out.is_empty() {
        return Value::Null;
    }
    Value::Object(
        out.into_iter()
            .map(|(port, protos)| (port.to_string(), json!(protos)))
            .collect(),
    )
}

/// Docker's container Summary, its status told at `now_ns`.
pub fn docker_summary(c: &ContainerRecord, now_ns: i64) -> Value {
    let now = now_ns / 1_000_000_000;
    let suffix = match c.health.as_ref().map(|h| h.status) {
        Some(HealthStatus::Starting) => " (health: starting)".to_string(),
        Some(s) => format!(" ({})", s.word()),
        None => String::new(),
    };
    let status = match c.state {
        RunState::Running | RunState::Stopping => format!(
            "Up {}{suffix}",
            human_duration(now - c.started_ns / 1_000_000_000)
        ),
        RunState::Paused => "Up (Paused)".to_string(),
        RunState::Exited => format!(
            "Exited ({}) {} ago",
            c.exit_code,
            human_duration(now - c.finished_ns / 1_000_000_000)
        ),
        _ => "Created".to_string(),
    };
    let mut ports: Vec<Value> = c
        .network
        .ports
        .iter()
        .map(|p| {
            json!({
                "IP": if p.host_ip.is_empty() { "0.0.0.0" } else { p.host_ip.as_str() },
                "PrivatePort": p.container_port,
                "PublicPort": p.host_port,
                "Type": p.protocol,
            })
        })
        .collect();
    // the exposed ports that are not published: no public side
    let published = ports.len();
    for k in port_keys(c) {
        let (port, proto) = k.split_once('/').unwrap_or((&k, "tcp"));
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let taken = ports[..published]
            .iter()
            .any(|p| p["PrivatePort"] == json!(port) && p["Type"] == json!(proto));
        if !taken {
            ports.push(json!({"PrivatePort": port, "Type": proto}));
        }
    }
    let mounts: Vec<Value> = c
        .mounts
        .iter()
        .map(|m| {
            let mut d = Map::new();
            let shown = mount_shape(m);
            d.insert("Type".into(), shown["Type"].clone());
            if m.kind == MountKind::Volume {
                d.insert("Name".into(), json!(m.name));
                d.insert("Driver".into(), json!("local"));
            }
            d.insert("Source".into(), json!(m.source));
            d.insert("Destination".into(), json!(m.destination));
            d.insert("Mode".into(), json!(""));
            d.insert("RW".into(), json!(!m.read_only));
            d.insert("Propagation".into(), shown["Propagation"].clone());
            Value::Object(d)
        })
        .collect();
    // the interfaces it has on its networks (compose compares the network
    // ids to decide whether a container is up to date)
    let mut nets = Map::new();
    for n in &c.network.networks {
        let mut e = endpoint(c, None);
        // podman names the pasta "network" pasta
        if n == "pasta" {
            e["NetworkID"] = json!("pasta");
        }
        nets.insert(n.clone(), e);
    }
    for i in &c.network.interfaces {
        nets.insert(i.network.clone(), endpoint(c, Some(i)));
    }
    let mut e = json!({
        "Id": c.id,
        "Names": [format!("/{}", c.name)],
        "Image": c.image,
        "ImageID": crate::id_with_algorithm(&c.image_id),
        "Command": args(c).join(" "),
        "Created": c.created_ns / 1_000_000_000,
        "Ports": ports,
        "Labels": string_map(&c.labels),
        "State": docker_state_word(c.state),
        "Status": status,
        "HostConfig": {"NetworkMode": c.network.mode},
        "NetworkSettings": {"Networks": nets},
        "Mounts": mounts,
    });
    if let (Some(rw), Some(root)) = (c.size_rw, c.size_root_fs) {
        e["SizeRw"] = json!(rw);
        e["SizeRootFs"] = json!(root);
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::workload::{HostSettings, ProcessConfig};

    #[test]
    fn sizes_as_go_units() {
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(3_077_000), "3.077MB");
        assert_eq!(human_size(10_000_000), "10MB");
        assert_eq!(human_size(1500), "1.5kB");
        assert_eq!(human_size(999), "999B");
    }

    #[test]
    fn an_exposed_range_is_a_key_a_port() {
        let mut c = ContainerRecord::default();
        c.network.exposed = vec!["7000-7001".into(), "9000/udp".into(), "7001/tcp".into()];
        assert_eq!(port_keys(&c), ["7000/tcp", "7001/tcp", "9000/udp"]);
        c.network.exposed = vec!["x-y/tcp".into()];
        assert_eq!(port_keys(&c), ["x-y/tcp"]);
    }

    #[test]
    fn binds_carry_their_options() {
        let m = |src: &str, name: Option<&str>, opts: &[&str]| ContainerMount {
            kind: if name.is_some() {
                MountKind::Volume
            } else {
                MountKind::Bind
            },
            name: name.unwrap_or_default().into(),
            named: name.is_some(),
            source: src.into(),
            destination: "/mnt".into(),
            options: opts.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        assert_eq!(
            bind_entry(&m("/tmp", None, &[])),
            "/tmp:/mnt:rprivate,rbind"
        );
        assert_eq!(
            bind_entry(&m("/tmp", None, &["ro", "shared", "bind"])),
            "/tmp:/mnt:ro,shared,bind"
        );
        assert_eq!(bind_entry(&m("/v/_data", Some("v"), &[])), "v:/mnt");
        assert_eq!(bind_entry(&m("/v/_data", Some("v"), &["ro"])), "v:/mnt:ro");
    }

    #[test]
    fn durations() {
        assert_eq!(human_duration(0), "Less than a second");
        assert_eq!(human_duration(1), "1 second");
        assert_eq!(human_duration(5), "5 seconds");
        assert_eq!(human_duration(90), "About a minute");
        assert_eq!(human_duration(600), "10 minutes");
        assert_eq!(human_duration(3600), "About an hour");
        assert_eq!(human_duration(7200), "2 hours");
        assert_eq!(human_duration(3 * 86400), "3 days");
        assert_eq!(human_duration(86400 * 400), "13 months");
    }

    fn sample() -> ContainerRecord {
        ContainerRecord {
            id: "abc".into(),
            name: "web".into(),
            image: "quay.io/libpod/alpine:latest".into(),
            image_id: "123".into(),
            state: RunState::Stopping,
            started_ns: 1_767_323_045_000_000_000,
            process: ProcessConfig {
                entrypoint: vec!["/a".into(), "b".into()],
                command: vec!["c".into()],
                stop_signal: "SIGUSR1".into(),
                stop_signal_number: 10,
                umask: "0022".into(),
                ..Default::default()
            },
            host: HostSettings {
                log_driver: "k8s-file".into(),
                log_max_size: 3_077_000,
                ..Default::default()
            },
            health: Some(Health {
                status: HealthStatus::Healthy,
                ..Default::default()
            }),
            mounts: vec![ContainerMount {
                kind: MountKind::Tmpfs,
                destination: "/t".into(),
                options: vec!["size=1m".into()],
                ..Default::default()
            }],
            network: velarx_proto::workload::ContainerNetwork {
                mode: "bridge".into(),
                networks: vec!["podman".into()],
                ports: vec![ContainerPort {
                    container_port: 80,
                    protocol: "tcp".into(),
                    range: 1,
                    ..Default::default()
                }],
                exposed: vec!["80/tcp".into(), "53/udp".into()],
                ..Default::default()
            },
            size_rw: Some(5),
            size_root_fs: Some(7),
            ..Default::default()
        }
    }

    #[test]
    fn the_graph_driver_of_a_container_is_the_drivers() {
        let mut c = sample();
        c.paths.graph_driver = "overlay".into();
        c.paths.graph_data = [("UpperDir".to_string(), "/b/u".to_string())].into();
        let p = libpod_inspect(&c);
        assert_eq!(p["Driver"], "overlay");
        assert_eq!(
            p["GraphDriver"],
            json!({"Name": "overlay", "Data": {"UpperDir": "/b/u"}})
        );
    }

    #[test]
    fn the_inspects_of_a_container() {
        let c = sample();
        let p = libpod_inspect(&c);
        assert_eq!(p["Path"], "/a");
        assert_eq!(p["Args"], json!(["b", "c"]));
        assert_eq!(p["State"]["Status"], "stopping");
        assert_eq!(p["State"]["Running"], false);
        assert_eq!(p["State"]["Health"]["Status"], "healthy");
        assert_eq!(p["Config"]["Umask"], "0022");
        assert_eq!(p["Config"]["StopSignal"], "SIGUSR1");
        assert_eq!(
            p["Config"]["ExposedPorts"],
            json!({"80/tcp": {}, "53/udp": {}})
        );
        assert_eq!(p["HostConfig"]["Tmpfs"], json!({"/t": "size=1m"}));
        assert_eq!(p["HostConfig"]["Binds"], json!([]));
        assert_eq!(p["HostConfig"]["LogConfig"]["Size"], "3.077MB");
        assert_eq!(p["HostConfig"]["RestartPolicy"]["Name"], "no");
        assert_eq!(
            p["NetworkSettings"]["Ports"]["80/tcp"],
            json!([{"HostIp": "0.0.0.0", "HostPort": ""}])
        );
        assert_eq!(p["NetworkSettings"]["Ports"]["53/udp"], Value::Null);
        assert_eq!(p["SizeRw"], 5);
        let v4 = libpod_v4_inspect(&c);
        assert_eq!(v4["Config"]["Entrypoint"], "/a b");
        assert_eq!(v4["Config"]["StopSignal"], 10);
        let d = docker_inspect(&c);
        assert_eq!(d["Name"], "/web");
        assert_eq!(d["State"]["Status"], "running");
        assert_eq!(d["Image"], "sha256:123");
        assert!(d["Config"].get("Umask").is_none());
    }

    #[test]
    fn the_health_check_is_shown_from_its_one_type() {
        use velarx_proto::health::{Healthcheck, OnFailure};
        let mut c = sample();
        let cfg = |c: &ContainerRecord| libpod_inspect(c)["Config"].clone();
        // no check: podman's defaults
        let o = cfg(&c);
        assert_eq!(o["HealthLogDestination"], "local");
        assert_eq!(o["HealthcheckMaxLogCount"], 5);
        assert_eq!(o["HealthcheckMaxLogSize"], 500);
        assert_eq!(o["HealthcheckOnFailureAction"], "none");
        assert!(o.get("Healthcheck").is_none());
        c.process.healthcheck = Some(Healthcheck {
            test: vec!["CMD-SHELL".into(), "true".into()],
            interval_ns: 1_500_000,
            retries: 4,
            on_failure: OnFailure::Kill,
            log_destination: "/var/log/h".into(),
            max_log_count: Some(0),
            ..Default::default()
        });
        let o = cfg(&c);
        assert_eq!(
            o["Healthcheck"],
            json!({"Test": ["CMD-SHELL", "true"], "Interval": 1_500_000,
                   "Timeout": 0, "StartPeriod": 0, "Retries": 4})
        );
        assert_eq!(o["HealthLogDestination"], "/var/log/h");
        assert_eq!(o["HealthcheckMaxLogCount"], 0);
        assert_eq!(o["HealthcheckMaxLogSize"], 500);
        assert_eq!(o["HealthcheckOnFailureAction"], "kill");
    }

    #[test]
    fn the_list_entries_of_a_container() {
        let c = sample();
        let l = libpod_list_entry(&c);
        assert_eq!(l["Command"], json!(["/a", "b", "c"]));
        assert_eq!(l["Names"], json!(["web"]));
        assert_eq!(l["Mounts"], json!(["/t"]));
        assert_eq!(l["Size"], json!({"rwSize": 5, "rootFsSize": 7}));
        assert_eq!(l["ExitedAt"], -62_135_596_800i64);
        let s = docker_summary(&c, c.started_ns + 120_000_000_000);
        assert_eq!(s["Status"], "Up 2 minutes (healthy)");
        assert_eq!(s["State"], "running");
        assert_eq!(s["Command"], "/a b c");
        assert_eq!(s["SizeRootFs"], 7);
        assert_eq!(
            s["Ports"],
            json!([
                {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 0, "Type": "tcp"},
                {"PrivatePort": 53, "Type": "udp"},
            ])
        );
    }

    #[test]
    fn the_list_entry_names_the_networks_by_id() {
        // (compose compares them with the ids of its networks: an empty one
        // made it recreate every container on each `up`)
        let mut c = sample();
        c.network.networks = vec!["back".into(), "pasta".into()];
        c.network.interfaces = vec![ContainerInterface {
            network: "back".into(),
            network_id: "0123abcd".into(),
            ip: "10.89.0.2".into(),
            prefix_len: 24,
            gateway: "10.89.0.1".into(),
            mac: "02:42:0a:59:00:02".into(),
            aliases: vec!["db".into()],
            ..Default::default()
        }];
        let s = docker_summary(&c, c.started_ns);
        let back = &s["NetworkSettings"]["Networks"]["back"];
        assert_eq!(back["NetworkID"], "0123abcd");
        assert_eq!(back["IPAddress"], "10.89.0.2");
        assert_eq!(back["IPPrefixLen"], 24);
        assert_eq!(back["Gateway"], "10.89.0.1");
        assert_eq!(back["MacAddress"], "02:42:0a:59:00:02");
        assert_eq!(back["Aliases"], json!(["db"]));
        assert_eq!(back["DNSNames"], Value::Null);
        assert_eq!(
            s["NetworkSettings"]["Networks"]["pasta"]["NetworkID"],
            "pasta"
        );
    }
}
