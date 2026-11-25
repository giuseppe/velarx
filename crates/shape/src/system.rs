// SPDX-License-Identifier: Apache-2.0
//! The engine as a whole: the version documents of both APIs, podman's
//! `info` and Docker's SystemInfo, the disk usage of both, podman's report
//! of a system prune and of a system check.

use crate::string_map;
use crate::time::{ansic, rfc3339};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use velarx_proto::system::{
    CgroupManager, CheckAction, CheckReport, DiskUsageRecord, HostRecord, HostTool,
    SystemPruneReport, SystemRecord, VersionRecord,
};

/// velarx's own addition to podman's `host` of its `info`: the state of
/// the user's systemd manager, of a rootless engine (podman's document
/// has none of it; the record of the engine is what it is made of).
fn host_systemd(s: &velarx_proto::system::SystemdRecord) -> Value {
    json!({
        "userManager": s.user_manager,
        "linger": s.linger,
        // empty when nothing is wrong
        "warning": s.warning,
    })
}

/// The version of podman's API the documents are of.
pub const LIBPOD_VERSION: &str = "5.8.9";
pub const LIBPOD_MIN_VERSION: &str = "4.0.0";
/// The version of Docker's API the documents are of.
pub const COMPAT_VERSION: &str = "1.44";
pub const COMPAT_MIN_VERSION: &str = "1.24";

/// The architecture as Go names it.
pub fn go_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "i686" | "i386" => "386",
        "armv7l" | "armv6l" => "arm",
        "powerpc64" => "ppc64le",
        a => a,
    }
}

/// The API `version` (major, minor) of a request is at least `major.minor`
/// (none: the newest).
pub(crate) fn at_least(version: Option<(u32, u32)>, major: u32, minor: u32) -> bool {
    version.is_none_or(|v| v >= (major, minor))
}

/// `GET /version` of both APIs: the same document.
pub fn version(v: &VersionRecord) -> Value {
    let arch = go_arch(&v.arch);
    // RFC 3339, which the podman client reads
    let built = if v.built_ns > 0 {
        rfc3339(v.built_ns)
    } else {
        String::new()
    };
    json!({
        "Platform": {"Name": "linux/velarx"},
        "Components": [{
            // the name the podman client looks for to read the API version
            "Name": "Podman Engine",
            "Version": v.version,
            "Details": {
                "APIVersion": LIBPOD_VERSION,
                "Arch": arch,
                "BuildTime": built,
                "Experimental": "false",
                "GitCommit": v.commit,
                "GoVersion": "rust",
                "KernelVersion": v.kernel,
                "MinAPIVersion": LIBPOD_MIN_VERSION,
                "Os": v.os,
            },
        }],
        "Version": v.version,
        "ApiVersion": COMPAT_VERSION,
        "MinAPIVersion": COMPAT_MIN_VERSION,
        "GitCommit": v.commit,
        "GoVersion": "rust",
        "Os": v.os,
        "Arch": arch,
        "KernelVersion": v.kernel,
        "BuildTime": built,
    })
}

/// The uptime of the host as podman writes it: `1h 2m 3.45s`, and the
/// days when it is more than an hour.
fn uptime(ns: i64) -> String {
    let secs = ns as f64 / 1e9;
    let hours = (secs / 3600.0).trunc();
    let mut out = format!(
        "{hours:.0}h {:.0}m {:.2}s",
        (secs / 60.0).trunc() % 60.0,
        secs.trunc() % 60.0
    );
    if hours >= 1.0 {
        out.push_str(&format!(" (Approximately {:.2} days)", hours / 24.0));
    }
    out
}

fn tool(t: &HostTool) -> Value {
    json!({"executable": t.path, "package": t.package, "version": t.version})
}

fn cgroup_manager(m: CgroupManager) -> &'static str {
    match m {
        CgroupManager::Systemd => "systemd",
        CgroupManager::Cgroupfs => "cgroupfs",
    }
}

/// podman's `idMappings`: those of a rootless engine, null for root.
fn id_mappings(h: &HostRecord) -> Value {
    if !h.rootless {
        return json!({"gidmap": null, "uidmap": null});
    }
    let map = |m: &[velarx_proto::pod::IdMapping]| {
        m.iter()
            .map(|m| json!({"container_id": m.container_id, "host_id": m.host_id, "size": m.size}))
            .collect::<Vec<_>>()
    };
    json!({"gidmap": map(&h.gid_mappings), "uidmap": map(&h.uid_mappings)})
}

/// podman's `info`; `socket` is where the client asked and whether it is
/// there.
pub fn libpod_info(s: &SystemRecord, socket: Option<(&str, bool)>) -> Value {
    let (h, st, v) = (&s.host, &s.store, &s.version);
    let version = &v.version;
    let (socket, socket_exists) = socket.unwrap_or(("", false));
    let inodes = match (st.graph_root_inodes, st.graph_root_inodes_used) {
        (Some(total), Some(used)) => json!({"total": total, "used": used}),
        _ => Value::Null,
    };
    json!({
        "host": {
            "arch": go_arch(&v.arch),
            "cdiSpecDirs": h.cdi_spec_dirs,
            "discoveredDevices": h.cdi_devices.iter()
                .map(|id| json!({"source": "cdi", "id": id})).collect::<Vec<_>>(),
            // what builds the images: velarx
            "buildahVersion": version,
            // what does conmon's work: velarx's monitor
            "conmon": {
                "path": h.monitor_path,
                "package": format!("velarx-monitor {version} (the conmon of velarx)"),
                "version": format!("velarx-monitor version {version}"),
            },
            "cgroupManager": cgroup_manager(h.cgroup_manager),
            "cgroupControllers": h.cgroup_controllers,
            "cgroupVersion": format!("v{}", h.cgroup_version),
            "cpuUtilization": {
                "userPercent": h.cpu_utilization.user_percent,
                "systemPercent": h.cpu_utilization.system_percent,
                "idlePercent": h.cpu_utilization.idle_percent,
            },
            "emulatedArchitectures": h.emulated_architectures,
            "idMappings": id_mappings(h),
            "cpus": h.cpus,
            "databaseBackend": "sqlite",
            "distribution": {"distribution": h.distribution, "version": h.distribution_version},
            "eventLogger": h.event_logger,
            "hostname": h.hostname,
            "kernel": v.kernel,
            "logDriver": h.log_driver,
            "memAvailable": h.mem_available,
            "memFree": h.mem_free,
            "memTotal": h.mem_total,
            "networkBackend": "netavark",
            // velarx's network setup and its DNS server
            "networkBackendInfo": {
                "backend": "netavark",
                "version": version,
                "package": format!("velarx {version}"),
                "path": h.engine_path,
                "dns": {"version": version, "package": format!("velarx {version}"), "path": h.engine_path},
            },
            "pasta": tool(&h.pasta),
            "slirp4netns": tool(&h.slirp4netns),
            // velarx's: the other runtimes a container can be made with
            "ociRuntimes": h.runtimes.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
            "ociRuntime": {
                "name": h.oci_runtime.name,
                "package": h.oci_runtime.package,
                "path": h.oci_runtime.path,
                "version": h.oci_runtime.version,
                "features": h.oci_runtime.features,
            },
            "os": v.os,
            "remoteSocket": {"path": socket, "exists": socket_exists},
            "rootlessNetworkCmd": "pasta",
            "serviceIsRemote": true,
            "security": {
                "apparmorEnabled": false,
                "capabilities": "CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_NET_BIND_SERVICE,CAP_SETFCAP,CAP_SETGID,CAP_SETPCAP,CAP_SETUID,CAP_SYS_CHROOT",
                "rootless": h.rootless,
                "seccompEnabled": true,
                "seccompProfilePath": "",
                "selinuxEnabled": h.selinux,
            },
            "swapFree": h.swap_free,
            "swapTotal": h.swap_total,
            // velarx's: the user's systemd manager, of a rootless engine
            "systemd": h.systemd.as_ref().map_or(Value::Null, host_systemd),
            "uptime": uptime(h.uptime_ns),
            "variant": "",
            "linkmode": "dynamic",
        },
        "store": {
            "configFile": st.config_file,
            "containerStore": {"number": st.containers, "paused": st.paused, "running": st.running, "stopped": st.stopped},
            "graphDriverName": st.graph_driver,
            // velarx's: the driver by its own name
            "storageDriver": st.storage_driver,
            "graphOptions": {},
            "graphRoot": st.graph_root,
            "graphRootInodes": inodes,
            "graphRootAllocated": st.graph_root_allocated,
            "graphRootUsed": st.graph_root_used,
            "graphStatus": st.graph_status,
            "imageCopyTmpDir": "/var/tmp",
            "imageStore": {"number": st.images},
            "runRoot": st.run_root,
            "volumePath": st.volume_path,
            "transientStore": false,
        },
        "registries": {"search": s.search_registries},
        "plugins": {
            "volume": ["local"],
            "network": ["bridge", "host", "none"],
            "log": ["k8s-file", "none", "passthrough", "journald"],
            "authorization": null,
        },
        "version": {
            "APIVersion": LIBPOD_VERSION,
            "Version": version,
            "GoVersion": "rust",
            "GitCommit": v.commit,
            "BuiltTime": if v.built_ns > 0 { ansic(v.built_ns) } else { String::new() },
            "Built": v.built_ns.div_euclid(1_000_000_000),
            "BuildOrigin": format!("velarx {version}"),
            "OsArch": format!("{}/{}", v.os, go_arch(&v.arch)),
            "Os": v.os,
        },
    })
}

/// Docker's SystemInfo of its API `version`; `now_ns` is its SystemTime.
pub fn docker_info(s: &SystemRecord, version: Option<(u32, u32)>, now_ns: i64) -> Value {
    let (h, st, v) = (&s.host, &s.store, &s.version);
    // the default runtime and those of [runtimes]
    let mut runtimes = Map::new();
    let mut default = json!({"path": h.oci_runtime.path});
    // Docker added the status of the runtimes in 1.44
    if at_least(version, 1, 44) {
        default["status"] = json!({
            "org.opencontainers.runtime-spec.features": h.oci_runtime.features,
        });
    }
    runtimes.insert(h.oci_runtime.name.clone(), default);
    for r in &h.runtimes {
        runtimes
            .entry(r.name.clone())
            .or_insert_with(|| json!({"path": r.path}));
    }
    let security = if h.rootless {
        json!(["name=seccomp,profile=default", "name=rootless"])
    } else {
        json!(["name=seccomp,profile=default"])
    };
    let mut out = json!({
        "ID": h.hostname,
        "Containers": st.containers,
        "ContainersRunning": st.running,
        "ContainersPaused": st.paused,
        "ContainersStopped": st.stopped,
        "Images": st.images,
        "Driver": st.graph_driver,
        "DriverStatus": st.graph_status.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "Plugins": {"Volume": ["local"], "Network": ["bridge", "host", "none"], "Log": ["k8s-file"]},
        "MemoryLimit": true,
        "SwapLimit": true,
        "CpuCfsPeriod": true,
        "CpuCfsQuota": true,
        "PidsLimit": true,
        "IPv4Forwarding": true,
        "Debug": false,
        "NFd": 0,
        "NGoroutines": 0,
    });
    let rest = json!({
        "SystemTime": rfc3339(now_ns),
        "LoggingDriver": h.log_driver,
        "CgroupDriver": "cgroupfs",
        "CgroupVersion": h.cgroup_version.to_string(),
        "KernelVersion": v.kernel,
        // (Docker's: the pretty name, "Linux" when there is none)
        "OperatingSystem": match h.distribution_name.as_str() {
            "" => "Linux",
            name => name,
        },
        "OSVersion": h.distribution_version,
        "OSType": v.os,
        "Architecture": v.arch,
        "NCPU": h.cpus,
        "MemTotal": h.mem_total,
        "IndexServerAddress": "https://index.docker.io/v1/",
        "DockerRootDir": st.graph_root,
        "Name": h.hostname,
        "Labels": [],
        "ExperimentalBuild": false,
        "ServerVersion": v.version,
        "Runtimes": runtimes,
        "DefaultRuntime": h.oci_runtime.name,
        "LiveRestoreEnabled": false,
        "Isolation": "",
        "InitBinary": "catatonit",
        "SecurityOptions": security,
        "Swarm": {"LocalNodeState": "inactive"},
        // the pools of the subnets of new networks (`[[network.subnet_pools]]`)
        "DefaultAddressPools": s.subnet_pools.iter()
            .map(|p| json!({"Base": p.base, "Size": p.size}))
            .collect::<Vec<_>>(),
        "Warnings": [],
        "ProductLicense": "Apache-2.0",
        "BuildahVersion": "",
        "CPURealtimePeriod": false,
        "CPURealtimeRuntime": false,
        "Rootless": h.rootless,
        "SwapFree": h.swap_free,
        "SwapTotal": h.swap_total,
        "Uptime": uptime(h.uptime_ns),
    });
    if let (Some(a), Value::Object(b)) = (out.as_object_mut(), rest) {
        a.extend(b);
    }
    out
}

/// The repository and the tag of the first name of an image (`<none>`
/// for what it has not).
fn split_name(name: Option<&String>) -> (String, String) {
    match name {
        None => ("<none>".into(), "<none>".into()),
        Some(n) => {
            let slash = n.rfind('/').map_or(0, |i| i + 1);
            match n[slash..].rfind(':') {
                Some(c) => (n[..slash + c].to_string(), n[slash + c + 1..].to_string()),
                None => (n.clone(), "<none>".into()),
            }
        }
    }
}

/// podman's `system/df`.
pub fn libpod_df(d: &DiskUsageRecord) -> Ordered {
    let images: Vec<Value> = d
        .images
        .iter()
        .map(|i| {
            let (repo, tag) = split_name(i.names.first());
            json!({
                "Repository": repo, "Tag": tag, "ImageID": i.id,
                "Created": rfc3339(i.created_ns), "Size": i.size,
                "SharedSize": i.size.saturating_sub(i.unique_size),
                "UniqueSize": i.unique_size, "Containers": i.containers,
            })
        })
        .collect();
    let containers: Vec<Value> = d
        .containers
        .iter()
        .map(|c| {
            json!({
                "ContainerID": c.id,
                "Image": c.image_id,
                "Command": c.command,
                "LocalVolumes": c.volumes,
                "Size": c.size,
                "RWSize": c.rw_size,
                "Created": rfc3339(c.created_ns),
                "Status": crate::container::state_word(c.state),
                "Names": c.name,
            })
        })
        .collect();
    let volumes: Vec<Value> = d
        .volumes
        .iter()
        .map(|v| {
            json!({"VolumeName": v.name, "Links": v.links, "Size": v.size,
                   "ReclaimableSize": if v.links > 0 { 0 } else { v.size }})
        })
        .collect();
    // members in podman's order
    Ordered(vec![
        ("ImagesSize", json!(d.images_size)),
        ("Images", Value::Array(images)),
        ("Containers", Value::Array(containers)),
        ("Volumes", Value::Array(volumes)),
    ])
}

/// A JSON object whose members are written in the order given: a map of
/// `serde_json` is sorted by its keys (no `preserve_order`), and the
/// clients of podman's API that compare the text of a document see Go's
/// order of the members of its struct.
#[derive(Debug, Clone, PartialEq)]
pub struct Ordered(pub Vec<(&'static str, Value)>);

impl Ordered {
    /// The member `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// The document as a (sorted) JSON value.
    pub fn value(&self) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
        )
    }
}

impl serde::Serialize for Ordered {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

/// Docker's `system/df` of its API `version`.
pub fn docker_df(d: &DiskUsageRecord, version: Option<(u32, u32)>) -> Ordered {
    let images: Vec<Value> = d
        .images
        .iter()
        .map(|i| {
            let mut v = json!({
                "Id": crate::id_with_algorithm(&i.id), "ParentId": "",
                "RepoTags": i.names,
                "RepoDigests": i.digests,
                "Created": i.created_ns.div_euclid(1_000_000_000),
                "Size": i.size, "SharedSize": i.size.saturating_sub(i.unique_size), "Labels": {},
                "Containers": i.containers,
            });
            // Docker dropped VirtualSize in 1.44
            if !at_least(version, 1, 44) {
                v["VirtualSize"] = json!(i.size);
            }
            v
        })
        .collect();
    let containers: Vec<Value> = d
        .containers
        .iter()
        .map(|c| {
            let image = d.images.iter().find(|i| i.id == c.image_id);
            let state = crate::container::state_word(c.state);
            json!({
                "Id": c.id, "Names": [format!("/{}", c.name)],
                "Image": image.and_then(|i| i.names.first().cloned()).unwrap_or_default(),
                "ImageID": image.map_or(String::new(), |i| crate::id_with_algorithm(&i.id)),
                "Command": c.command.join(" "), "Created": c.created_ns.div_euclid(1_000_000_000),
                "Ports": [], "Labels": {}, "State": state, "Status": state,
                "SizeRw": c.rw_size,
                "SizeRootFs": c.size,
            })
        })
        .collect();
    let volumes: Vec<Value> = d
        .volumes
        .iter()
        .map(|v| {
            json!({
                "Name": v.name, "Driver": "local", "Mountpoint": v.mountpoint,
                "CreatedAt": rfc3339(v.created_ns), "Labels": string_map(&v.labels), "Scope": "local",
                "Options": {}, "UsageData": {"Size": v.size, "RefCount": v.links},
            })
        })
        .collect();
    let total = d.images_size;
    if at_least(version, 1, 52) {
        // Docker 1.52's DiskUsage: usage objects, empty members left out
        let usage = |items: Vec<Value>| {
            if items.is_empty() {
                json!({})
            } else {
                json!({ "Items": items })
            }
        };
        let mut image_usage = usage(images);
        if total > 0 {
            image_usage["TotalSize"] = json!(total);
        }
        return Ordered(vec![
            ("ImageUsage", image_usage),
            ("ContainerUsage", usage(containers)),
            ("VolumeUsage", usage(volumes)),
            ("BuildCacheUsage", json!({})),
        ]);
    }
    // members in Docker's order
    Ordered(vec![
        ("LayersSize", json!(total)),
        ("Images", Value::Array(images)),
        ("Containers", Value::Array(containers)),
        ("Volumes", Value::Array(volumes)),
        ("BuildCache", json!([])),
    ])
}

/// podman's report of `POST /libpod/system/prune`.
pub fn libpod_prune(r: &SystemPruneReport) -> Value {
    json!({
        "PodPruneReport": r.pods.iter().map(|id| json!({"Id": id, "Err": null})).collect::<Vec<_>>(),
        "ContainerPruneReports": r.containers.iter()
            .map(|id| json!({"Id": id, "Err": null, "Size": 0}))
            .collect::<Vec<_>>(),
        "NetworkPruneReports": r.networks.iter()
            .map(|n| json!({"Name": n, "Error": null}))
            .collect::<Vec<_>>(),
        "VolumePruneReports": r.volumes.iter()
            .map(|v| json!({"Id": v.name, "Err": null, "Size": v.size}))
            .collect::<Vec<_>>(),
        "ImagePruneReports": r.images.iter()
            .map(|i| json!({"Id": i.id, "Err": null, "Size": i.size}))
            .collect::<Vec<_>>(),
        "ReclaimedSpace": r.reclaimed,
    })
}

/// podman's SystemCheckReport (what `POST /libpod/system/check` answers and
/// `system check --format json` prints): `Errors` says whether damage was
/// found, also when it was repaired; what is wrong in the store is a layer
/// (keyed by its path or kind), what is wrong with an image an image
/// (keyed by its id); what is empty is `null`.
pub fn check(r: &CheckReport) -> Value {
    let mut layers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut images: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut removed_images: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut removed_layers = Vec::new();
    let mut volumes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut repaired_volumes: Vec<String> = Vec::new();
    for p in &r.problems {
        // (what was detected, also when it was removed)
        let mut message = format!("{}: {}", p.kind, p.message);
        if let (true, Some(path)) = (p.image.is_some() || p.volume.is_some(), &p.path) {
            message.push_str(&format!(" ({path})"));
        }
        if let Some(volume) = &p.volume {
            if p.action == CheckAction::Repaired && !repaired_volumes.contains(volume) {
                repaired_volumes.push(volume.clone());
            }
            volumes.entry(volume.clone()).or_default().push(message);
            continue;
        }
        let key = p.path.clone().unwrap_or_else(|| p.kind.clone());
        match &p.image {
            Some(id) => {
                images.entry(id.clone()).or_default().push(message);
                if p.action == CheckAction::ImageRemoved {
                    let names = removed_images.entry(id.clone()).or_default();
                    if let Some(n) = p.name.iter().find(|n| !names.contains(n)) {
                        names.push(n.clone());
                    }
                }
            }
            None => {
                if p.action == CheckAction::Repaired {
                    removed_layers.push(key.clone());
                }
                layers.entry(key).or_default().push(message);
            }
        }
    }
    fn map(m: BTreeMap<String, Value>) -> Value {
        if m.is_empty() {
            Value::Null
        } else {
            Value::Object(m.into_iter().collect())
        }
    }
    let lists =
        |m: BTreeMap<String, Vec<String>>| map(m.into_iter().map(|(k, v)| (k, json!(v))).collect());
    let removed_containers: BTreeMap<String, Value> = r
        .removed_containers
        .iter()
        .map(|c| (c.id.clone(), json!(c.name)))
        .collect();
    json!({
        "Errors": !r.problems.is_empty(),
        "Layers": lists(layers),
        "ROLayers": null,
        "RemovedLayers": if removed_layers.is_empty() { Value::Null } else { json!(removed_layers) },
        "Images": lists(images),
        "ROImages": null,
        "RemovedImages": lists(removed_images),
        "Containers": null,
        "RemovedContainers": map(removed_containers),
        "Volumes": lists(volumes),
        "RepairedVolumes": if repaired_volumes.is_empty() { Value::Null } else { json!(repaired_volumes) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::system::{
        CheckProblem, CheckRemovedContainer, ContainerUsage, HostRecord, ImageUsage, RuntimePath,
        StoreRecord, VolumeUsage,
    };
    use velarx_proto::workload::{PrunedImage, RunState};

    fn problem(image: Option<&str>, name: Option<&str>, action: CheckAction) -> CheckProblem {
        CheckProblem {
            image: image.map(str::to_string),
            name: name.map(str::to_string),
            kind: "digest_mismatch".into(),
            message: "bad".into(),
            path: Some("/store/o".into()),
            action,
            ..Default::default()
        }
    }

    #[test]
    fn a_clean_check_is_podman_s_with_nulls() {
        let v = check(&CheckReport::default());
        assert_eq!(v["Errors"], false);
        for k in [
            "Layers",
            "ROLayers",
            "RemovedLayers",
            "Images",
            "ROImages",
            "RemovedImages",
            "Containers",
            "RemovedContainers",
            "Volumes",
            "RepairedVolumes",
        ] {
            assert!(v[k].is_null(), "{k}");
        }
    }

    #[test]
    fn a_volume_is_under_its_own_keys() {
        let volume = |name: &str, action| CheckProblem {
            volume: Some(name.into()),
            kind: "orphan_volume".into(),
            message: "no row".into(),
            path: Some(format!("/v/{name}")),
            action,
            ..Default::default()
        };
        let report = CheckReport {
            problems: vec![
                volume("a", CheckAction::Repaired),
                volume("b", CheckAction::None),
            ],
            ..Default::default()
        };
        let v = check(&report);
        assert_eq!(v["Errors"], true);
        assert_eq!(v["Volumes"]["a"], json!(["orphan_volume: no row (/v/a)"]));
        assert_eq!(v["Volumes"]["b"], json!(["orphan_volume: no row (/v/b)"]));
        assert_eq!(v["RepairedVolumes"], json!(["a"]));
        // (not a layer: nothing says a volume was deleted)
        assert!(v["Layers"].is_null() && v["RemovedLayers"].is_null());
    }

    #[test]
    fn what_a_check_detects_stays_when_it_is_removed() {
        let report = CheckReport {
            problems: vec![
                problem(Some("a1"), Some("localhost/x:1"), CheckAction::ImageRemoved),
                problem(Some("a1"), Some("localhost/x:1"), CheckAction::ImageRemoved),
                problem(Some("b2"), None, CheckAction::ImageInUse),
                problem(None, None, CheckAction::Repaired),
            ],
            removed_containers: vec![CheckRemovedContainer {
                id: "c1".into(),
                name: "user".into(),
            }],
            ..Default::default()
        };
        let v = check(&report);
        assert_eq!(v["Errors"], true);
        assert_eq!(v["Images"]["a1"][0], "digest_mismatch: bad (/store/o)");
        assert_eq!(v["Images"]["a1"].as_array().unwrap().len(), 2);
        assert_eq!(v["Images"]["b2"].as_array().unwrap().len(), 1);
        assert_eq!(v["RemovedImages"], json!({"a1": ["localhost/x:1"]}));
        assert_eq!(v["RemovedLayers"], json!(["/store/o"]));
        assert_eq!(v["Layers"]["/store/o"][0], "digest_mismatch: bad");
        assert_eq!(v["RemovedContainers"], json!({"c1": "user"}));
        assert!(v["Containers"].is_null());
        assert!(!report.ok());
    }

    fn system() -> SystemRecord {
        SystemRecord {
            version: VersionRecord {
                version: "1.2.3".into(),
                commit: "abc".into(),
                built_ns: 1_767_323_045_000_000_000,
                os: "linux".into(),
                arch: "x86_64".into(),
                kernel: "6.9.0".into(),
            },
            host: HostRecord {
                hostname: "h".into(),
                distribution: "fedora".into(),
                distribution_version: "46".into(),
                distribution_name: "Fedora Linux 46".into(),
                cpus: 4,
                cgroup_version: 2,
                uptime_ns: 7_384_500_000_000,
                oci_runtime: velarx_proto::system::OciRuntimeRecord {
                    name: "crun".into(),
                    path: "/usr/bin/crun".into(),
                    ..Default::default()
                },
                runtimes: vec![RuntimePath {
                    name: "runc".into(),
                    path: "/usr/bin/runc".into(),
                    ..Default::default()
                }],
                systemd: Some(velarx_proto::system::SystemdRecord {
                    user_manager: true,
                    linger: false,
                    warning: "lingering is off for faber".into(),
                }),
                ..Default::default()
            },
            store: StoreRecord {
                graph_root: "/s".into(),
                graph_root_inodes: Some(10),
                graph_root_inodes_used: Some(3),
                containers: 2,
                running: 1,
                stopped: 1,
                images: 5,
                storage_driver: "composefs".into(),
                graph_driver: "overlay".into(),
                graph_status: [("kernel mount".to_string(), "yes".to_string())].into(),
                ..Default::default()
            },
            search_registries: vec!["quay.io".into()],
            ..Default::default()
        }
    }

    #[test]
    fn the_versions_and_infos_are_podman_s_and_docker_s() {
        let v = version(&system().version);
        assert_eq!(v["Components"][0]["Details"]["Arch"], "amd64");
        assert_eq!(v["Components"][0]["Details"]["APIVersion"], LIBPOD_VERSION);
        assert_eq!(
            (v["ApiVersion"].as_str(), v["BuildTime"].as_str()),
            (Some(COMPAT_VERSION), Some("2026-01-02T03:04:05Z"))
        );
        let info = libpod_info(&system(), Some(("/run/s.sock", true)));
        assert_eq!(
            info["host"]["uptime"],
            "2h 3m 4.00s (Approximately 0.08 days)"
        );
        assert_eq!(info["host"]["cgroupVersion"], "v2");
        assert_eq!(
            info["host"]["distribution"],
            json!({"distribution": "fedora", "version": "46"})
        );
        assert_eq!(info["host"]["ociRuntimes"], json!(["runc"]));
        assert_eq!(
            info["host"]["remoteSocket"],
            json!({"path": "/run/s.sock", "exists": true})
        );
        assert_eq!(
            info["store"]["graphRootInodes"],
            json!({"total": 10, "used": 3})
        );
        assert_eq!(info["store"]["containerStore"]["running"], 1);
        // (the graph driver is the driver's: what tools key on, and
        // velarx's own name for it)
        assert_eq!(info["store"]["graphDriverName"], "overlay");
        assert_eq!(info["store"]["storageDriver"], "composefs");
        assert_eq!(info["store"]["graphStatus"], json!({"kernel mount": "yes"}));
        // (velarx's own: the state of the user's manager, null for root)
        assert_eq!(
            info["host"]["systemd"],
            json!({"userManager": true, "linger": false, "warning": "lingering is off for faber"})
        );
        let mut root = system();
        root.host.systemd = None;
        assert_eq!(libpod_info(&root, None)["host"]["systemd"], Value::Null);
        assert_eq!(info["registries"]["search"], json!(["quay.io"]));
        assert_eq!(info["version"]["BuiltTime"], "Fri Jan  2 03:04:05 2026");
        assert_eq!(info["version"]["OsArch"], "linux/amd64");
        let docker = docker_info(&system(), Some((1, 43)), 0);
        assert_eq!(docker["OSVersion"], "46");
        assert_eq!(docker["OperatingSystem"], "Fedora Linux 46");
        assert_eq!(
            (docker["Containers"].clone(), docker["Images"].clone()),
            (json!(2), json!(5))
        );
        assert_eq!(docker["Architecture"], "x86_64");
        assert_eq!(docker["Driver"], "overlay");
        assert_eq!(docker["DriverStatus"], json!([["kernel mount", "yes"]]));
        assert!(docker["Runtimes"]["crun"].get("status").is_none());
        assert!(docker_info(&system(), None, 0)["Runtimes"]["crun"]["status"].is_object());
        assert_eq!(docker["Runtimes"]["runc"]["path"], "/usr/bin/runc");
    }

    fn usage() -> DiskUsageRecord {
        DiskUsageRecord {
            images: vec![ImageUsage {
                id: "i1".into(),
                names: vec!["quay.io/a/b:1".into()],
                digests: vec!["quay.io/a/b@sha256:d".into()],
                created_ns: 2_000_000_000,
                size: 100,
                unique_size: 60,
                containers: 1,
            }],
            containers: vec![ContainerUsage {
                id: "c1".into(),
                name: "web".into(),
                image_id: "i1".into(),
                command: vec!["sh".into(), "-c".into()],
                volumes: 1,
                rw_size: 5,
                size: 105,
                created_ns: 3_000_000_000,
                state: RunState::Running,
            }],
            volumes: vec![VolumeUsage {
                name: "v1".into(),
                links: 0,
                size: 7,
                ..Default::default()
            }],
            images_size: 100,
            ..Default::default()
        }
    }

    #[test]
    fn the_disk_usage_is_podman_s_and_docker_s() {
        // (the members in podman's order, as its clients compare the text)
        let text = serde_json::to_string(&libpod_df(&DiskUsageRecord::default())).unwrap();
        assert_eq!(
            text,
            r#"{"ImagesSize":0,"Images":[],"Containers":[],"Volumes":[]}"#
        );
        let text = serde_json::to_string(&docker_df(&DiskUsageRecord::default(), Some((1, 43))));
        assert_eq!(
            text.unwrap(),
            r#"{"LayersSize":0,"Images":[],"Containers":[],"Volumes":[],"BuildCache":[]}"#
        );
        let p = libpod_df(&usage()).value();
        assert_eq!(p["ImagesSize"], 100);
        assert_eq!(
            (
                p["Images"][0]["Repository"].as_str(),
                p["Images"][0]["Tag"].as_str()
            ),
            (Some("quay.io/a/b"), Some("1"))
        );
        assert_eq!(p["Images"][0]["SharedSize"], 40);
        assert_eq!(p["Containers"][0]["Status"], "running");
        assert_eq!(p["Volumes"][0]["ReclaimableSize"], 7);
        let d = docker_df(&usage(), Some((1, 43))).value();
        assert_eq!(d["LayersSize"], 100);
        assert_eq!(d["Images"][0]["VirtualSize"], 100);
        assert_eq!(d["Images"][0]["RepoDigests"][0], "quay.io/a/b@sha256:d");
        assert_eq!(d["Containers"][0]["Image"], "quay.io/a/b:1");
        assert_eq!(d["Containers"][0]["Command"], "sh -c");
        let modern = docker_df(&usage(), None).value();
        assert_eq!(modern["ImageUsage"]["TotalSize"], 100);
        assert_eq!(modern["BuildCacheUsage"], json!({}));
        assert_eq!(
            split_name(None),
            ("<none>".to_string(), "<none>".to_string())
        );
        assert_eq!(
            split_name(Some(&"localhost:5000/x".to_string())).1,
            "<none>"
        );
    }

    #[test]
    fn a_prune_is_podman_s_report() {
        let r = SystemPruneReport {
            containers: vec!["c1".into()],
            images: vec![PrunedImage {
                id: "i1".into(),
                size: 9,
            }],
            reclaimed: 9,
            ..Default::default()
        };
        let v = libpod_prune(&r);
        assert_eq!(
            v["ContainerPruneReports"][0],
            json!({"Id": "c1", "Err": null, "Size": 0})
        );
        assert_eq!(v["ImagePruneReports"][0]["Size"], 9);
        assert_eq!(v["ReclaimedSpace"], 9);
        assert_eq!(v["PodPruneReport"], json!([]));
    }
}
