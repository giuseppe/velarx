// SPDX-License-Identifier: Apache-2.0
//! Pods: podman's ListPodsReport and InspectPodData.

use crate::container::state_word;
use crate::{string_map, time::rfc3339};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use velarx_proto::pod::{PodDeviceLimit, PodSpec};
use velarx_proto::workload::{DeviceNode, PodRecord, PodStatus};

/// podman's word of the status of a pod.
pub fn status_word(s: PodStatus) -> &'static str {
    match s {
        PodStatus::Created => "Created",
        PodStatus::Running => "Running",
        PodStatus::Degraded => "Degraded",
        PodStatus::Paused => "Paused",
        PodStatus::Exited => "Exited",
    }
}

/// The namespaces the members of a pod of `spec` share, in podman's order.
fn shared_namespaces(spec: &PodSpec) -> Vec<&'static str> {
    [
        (spec.share_ipc, "ipc"),
        (spec.share_net, "net"),
        (spec.share_pid, "pid"),
        (spec.share_uts, "uts"),
        (spec.share_cgroup, "cgroup"),
    ]
    .into_iter()
    .filter_map(|(shared, ns)| shared.then_some(ns))
    .collect()
}

/// `"80/tcp"`: the bindings of the host.
fn port_bindings(spec: &PodSpec) -> Value {
    let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for m in &spec.ports {
        out.entry(format!("{}/{}", m.container_port, m.protocol))
            .or_default()
            .push(json!({
                // (podman's address of all of them)
                "HostIp": m.host_ip.as_deref().filter(|h| !h.is_empty()).unwrap_or("0.0.0.0"),
                "HostPort": m.host_port.map(|p| p.to_string()).unwrap_or_default(),
            }));
    }
    json!(out)
}

/// The mounts of the volumes of a pod as podman's inspect has them.
fn mounts(volumes: &[String]) -> Vec<Value> {
    volumes
        .iter()
        .map(|v| {
            let mut parts = v.splitn(3, ':');
            let first = parts.next().unwrap_or_default();
            let (source, dest) = match parts.next() {
                Some(dest) => (first, dest),
                None => ("", first),
            };
            let options: Vec<&str> = parts
                .next()
                .map(|o| o.split(',').collect())
                .unwrap_or_default();
            let rw = !options.contains(&"ro");
            let propagation = options
                .iter()
                .find(|o| o.ends_with("shared") || o.ends_with("slave") || o.ends_with("private"))
                .map_or("rprivate", |o| *o);
            let (typ, mut shown) = if source.starts_with('/') {
                ("bind", vec!["rbind"])
            } else if source.is_empty() {
                ("volume", Vec::new())
            } else {
                ("volume", vec!["rbind"])
            };
            shown.extend(options.iter().copied().filter(|o| !o.is_empty()));
            let mut m = json!({
                "Type": typ,
                "Source": source,
                "Destination": dest,
                "Driver": "",
                "Mode": "",
                "Options": shown,
                "RW": rw,
                "Propagation": propagation,
            });
            if typ == "volume" && !source.is_empty() {
                m["Name"] = json!(source);
            }
            m
        })
        .collect()
}

/// The devices of a pod as podman's inspect has them (a `LinuxDevice`).
fn devices(nodes: &[DeviceNode]) -> Vec<Value> {
    nodes
        .iter()
        .map(|d| {
            let mut v = json!({"path": d.path});
            if !d.kind.is_empty() {
                v["type"] = json!(d.kind);
                v["major"] = json!(d.major);
                v["minor"] = json!(d.minor);
                v["fileMode"] = json!(d.file_mode);
            }
            v
        })
        .collect()
}

/// A list of podman's that is nil (`null`) when it is empty.
fn null_if_empty(list: &[String]) -> Value {
    if list.is_empty() {
        Value::Null
    } else {
        json!(list)
    }
}

/// podman's ListPodsReport (`pod ps`, `GET /libpod/pods/json`).
pub fn libpod_list_entry(p: &PodRecord) -> Value {
    let containers: Vec<Value> = p
        .members
        .iter()
        .map(|m| {
            json!({"Id": m.id, "Names": m.name, "Status": state_word(m.state),
                   "RestartCount": m.restart_count})
        })
        .collect();
    json!({
        "Cgroup": p.spec.cgroup_parent.as_deref().unwrap_or_default(),
        "Containers": containers,
        "Created": rfc3339(p.created_ns),
        "Id": p.id,
        "InfraId": p.infra_id,
        "Name": p.name,
        "Namespace": "",
        "Networks": p.networks,
        "Status": status_word(p.status),
        "Labels": string_map(&p.spec.labels),
    })
}

/// podman's InspectPodData (`pod inspect`, `GET /libpod/pods/{name}/json`).
pub fn libpod_inspect(p: &PodRecord) -> Value {
    let spec = &p.spec;
    let containers: Vec<Value> = p
        .members
        .iter()
        .map(|m| json!({"Id": m.id, "Name": m.name, "State": state_word(m.state)}))
        .collect();
    let no_limits = Default::default();
    let limits = spec.resources.as_ref().unwrap_or(&no_limits);
    let namespace = |host: bool, shared: bool| {
        if host {
            "host"
        } else if shared {
            "pod"
        } else {
            "private"
        }
    };
    let mut infra = json!({
        "PortBindings": port_bindings(spec),
        "HostNetwork": p.host_network,
        "StaticIP": spec.ip.as_deref().unwrap_or_default(),
        "StaticMAC": spec.mac.as_deref().unwrap_or_default(),
        "NoManageResolvConf": false,
        "DNSServer": null_if_empty(&spec.dns.servers),
        "DNSSearch": null_if_empty(&spec.dns.searches),
        "DNSOption": null_if_empty(&spec.dns.options),
        "NoManageHostname": spec.no_hostname,
        "NoManageHosts": spec.no_hosts,
        "HostAdd": null_if_empty(&spec.add_hosts),
        "HostsFile": spec.hosts_file.as_deref().unwrap_or_default(),
        "Networks": p.networks,
        "NetworkOptions": null,
        "pid_ns": namespace(spec.host_pid, spec.share_pid),
        "userns": spec.userns.clone().unwrap_or_default().to_string(),
        "uts_ns": namespace(spec.host_uts, false),
    });
    let mut doc = json!({
        "Id": p.id,
        "Name": p.name,
        "Created": rfc3339(p.created_ns),
        "ExitPolicy": spec.exit_policy.word(),
        "State": status_word(p.status),
        "Hostname": spec.hostname.as_deref().unwrap_or_default(),
        "CreateCgroup": spec.resources.is_some(),
        "CgroupParent": spec.cgroup_parent.as_deref().unwrap_or_default(),
        "CgroupPath": p.cgroup_path,
        "CreateInfra": !p.infra_id.is_empty(),
        "InfraContainerID": p.infra_id,
        "SharedNamespaces": shared_namespaces(spec),
        "NumContainers": p.members.len(),
        "Containers": containers,
        "LockNumber": 0,
    });
    // (podman leaves out what is not set)
    let mut put = |key: &str, value: Value, set: bool| {
        if set {
            doc[key] = value;
        }
    };
    put(
        "CreateCommand",
        json!(spec.create_command),
        !spec.create_command.is_empty(),
    );
    put("Labels", string_map(&spec.labels), !spec.labels.is_empty());
    if let Some(period) = limits.cpu_period.filter(|p| *p > 0) {
        infra["cpu_period"] = json!(period);
        put("cpu_period", json!(period), true);
    }
    if let Some(quota) = limits.cpu_quota.filter(|q| *q != 0) {
        infra["cpu_quota"] = json!(quota);
        put("cpu_quota", json!(quota), true);
    }
    if let Some(cpus) = limits.cpuset_cpus.as_deref().filter(|c| !c.is_empty()) {
        infra["cpuset_cpus"] = json!(cpus);
        put("cpuset_cpus", json!(cpus), true);
    }
    put(
        "cpu_shares",
        json!(limits.cpu_shares),
        limits.cpu_shares.is_some_and(|s| s > 0),
    );
    put(
        "cpuset_mems",
        json!(limits.cpuset_mems),
        limits.cpuset_mems.as_deref().is_some_and(|c| !c.is_empty()),
    );
    put(
        "memory_limit",
        json!(limits.memory),
        limits.memory.is_some_and(|m| m > 0),
    );
    put(
        "memory_swap",
        json!(limits.memory_swap),
        limits.memory_swap.is_some_and(|m| m > 0),
    );
    put(
        "blkio_weight",
        json!(limits.blkio_weight),
        limits.blkio_weight.is_some_and(|w| w > 0),
    );
    let throttles = |list: &[PodDeviceLimit]| -> Vec<Value> {
        list.iter()
            .filter(|d| d.value > 0)
            .filter(|d| !d.path.is_empty())
            .map(|d| json!({"Path": d.path, "Rate": d.value}))
            .collect()
    };
    for (key, list) in [
        ("device_read_bps", &limits.device_read_bps),
        ("device_write_bps", &limits.device_write_bps),
    ] {
        let t = throttles(list);
        put(key, json!(t), !t.is_empty());
    }
    put(
        "mounts",
        json!(mounts(&spec.volumes)),
        !spec.volumes.is_empty(),
    );
    put("devices", json!(devices(&p.devices)), !p.devices.is_empty());
    put(
        "volumes_from",
        json!(spec.volumes_from),
        !spec.volumes_from.is_empty(),
    );
    put(
        "security_opt",
        json!(spec.security_opts),
        !spec.security_opts.is_empty(),
    );
    put(
        "RestartPolicy",
        json!(spec.restart_policy.as_ref().map(|r| r.name.as_str())),
        spec.restart_policy.is_some(),
    );
    doc["InfraConfig"] = infra;
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::pod::{PodExitPolicy, PodPortMapping};
    use velarx_proto::workload::{PodMember, RunState};

    fn pod() -> PodRecord {
        PodRecord {
            id: "p".into(),
            name: "n".into(),
            created_ns: 1_767_323_045_000_000_000,
            status: PodStatus::Degraded,
            infra_id: "i".into(),
            members: vec![
                PodMember {
                    id: "i".into(),
                    name: "n-infra".into(),
                    state: RunState::Running,
                    ..Default::default()
                },
                PodMember {
                    id: "c".into(),
                    name: "c".into(),
                    state: RunState::Exited,
                    restart_count: 2,
                    ..Default::default()
                },
            ],
            networks: vec!["podman".into()],
            spec: PodSpec {
                name: "n".into(),
                labels: [("k".to_string(), "v".to_string())].into(),
                share_ipc: true,
                share_net: true,
                share_uts: true,
                exit_policy: PodExitPolicy::Stop,
                ports: vec![
                    PodPortMapping {
                        container_port: 80,
                        host_port: Some(8080),
                        host_ip: None,
                        protocol: "udp".into(),
                    },
                    PodPortMapping {
                        container_port: 80,
                        host_port: Some(8081),
                        host_ip: Some("127.0.0.1".into()),
                        protocol: "udp".into(),
                    },
                ],
                ..PodSpec::default()
            },
            ..PodRecord::default()
        }
    }

    #[test]
    fn the_list_entry_of_a_pod() {
        let l = libpod_list_entry(&pod());
        assert_eq!(l["Status"], "Degraded");
        assert_eq!(l["Created"], "2026-01-02T03:04:05Z");
        assert_eq!(l["InfraId"], "i");
        assert_eq!(l["Labels"]["k"], "v");
        assert_eq!(l["Networks"], json!(["podman"]));
        assert_eq!(l["Containers"][0]["Status"], "running");
        assert_eq!(l["Containers"][1]["Names"], "c");
        assert_eq!(l["Containers"][1]["RestartCount"], 2);
    }

    #[test]
    fn the_inspect_of_a_pod() {
        let p = libpod_inspect(&pod());
        assert_eq!(p["State"], "Degraded");
        assert_eq!(p["ExitPolicy"], "stop");
        assert_eq!(p["NumContainers"], 2);
        assert_eq!(p["Containers"][1]["State"], "exited");
        assert_eq!(p["SharedNamespaces"], json!(["ipc", "net", "uts"]));
        assert_eq!(p["InfraConfig"]["pid_ns"], "private");
        let bindings = &p["InfraConfig"]["PortBindings"]["80/udp"];
        assert_eq!(bindings[0]["HostPort"], "8080");
        // (podman's address of all of them)
        assert_eq!(bindings[0]["HostIp"], "0.0.0.0");
        assert_eq!(bindings[1]["HostIp"], "127.0.0.1");
        assert_eq!(p["Labels"]["k"], "v");
        // (podman's nil lists, and what it leaves out when not set)
        assert_eq!(p["InfraConfig"]["DNSServer"], Value::Null);
        for k in ["mounts", "devices", "memory_limit", "RestartPolicy"] {
            assert!(p.get(k).is_none(), "{k}");
        }
        let mut shared = pod();
        shared.spec.share_pid = true;
        shared.spec.share_uts = false;
        let p = libpod_inspect(&shared);
        assert_eq!(p["SharedNamespaces"], json!(["ipc", "net", "pid"]));
        assert_eq!(p["InfraConfig"]["pid_ns"], "pod");
    }

    /// The device of a rate limit is shown by the path in the record; the
    /// formatter reads nothing from the host (a device the record has no
    /// path for is not shown).
    #[test]
    fn a_throttled_device_is_shown_by_its_recorded_path() {
        use velarx_proto::pod::{PodDeviceLimit, PodResources};
        let mut p = pod();
        let dev = |path: &str| PodDeviceLimit {
            major: 7,
            minor: 0,
            value: 1 << 20,
            path: path.into(),
        };
        p.spec.resources = Some(PodResources {
            device_read_bps: vec![dev("/dev/vda"), dev("")],
            ..Default::default()
        });
        assert_eq!(
            libpod_inspect(&p)["device_read_bps"],
            json!([{"Path": "/dev/vda", "Rate": 1 << 20}])
        );
    }

    #[test]
    fn the_settings_of_a_pod_are_in_its_inspect() {
        let mut p = pod();
        p.spec.labels.clear();
        p.spec.volumes = vec!["/src:/dst:ro".into(), "vol:/v".into()];
        p.spec.host_uts = true;
        p.spec.no_hosts = true;
        p.spec.create_command = vec!["podman".into(), "pod".into(), "create".into()];
        p.spec.resources = Some(velarx_proto::pod::PodResources {
            memory: Some(1 << 20),
            ..Default::default()
        });
        p.devices = vec![DeviceNode {
            path: "/dev/n".into(),
            kind: "c".into(),
            major: 1,
            minor: 3,
            file_mode: 0o666,
        }];
        let d = libpod_inspect(&p);
        assert!(d.get("Labels").is_none());
        assert_eq!(d["CreateCommand"], json!(["podman", "pod", "create"]));
        assert_eq!(d["CreateCgroup"], true);
        assert_eq!(d["memory_limit"], 1 << 20);
        assert!(d.get("blkio_weight").is_none() && d.get("device_read_bps").is_none());
        p.spec.resources = Some(velarx_proto::pod::PodResources {
            blkio_weight: Some(50),
            ..Default::default()
        });
        assert_eq!(libpod_inspect(&p)["blkio_weight"], 50);
        assert_eq!(d["InfraConfig"]["uts_ns"], "host");
        assert_eq!(d["InfraConfig"]["NoManageHosts"], true);
        assert_eq!(d["mounts"][0]["Type"], "bind");
        assert_eq!(d["mounts"][0]["RW"], false);
        assert_eq!(d["mounts"][1]["Name"], "vol");
        assert_eq!(
            d["devices"],
            json!([{"path": "/dev/n", "type": "c", "major": 1, "minor": 3, "fileMode": 0o666}])
        );
    }
}
