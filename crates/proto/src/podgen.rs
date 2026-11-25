// SPDX-License-Identifier: Apache-2.0
//! The pod spec of podman's PodSpecGenerator (the body of `POST /pods/create`
//! and the pods a play of Kubernetes YAML makes): decoded here once, for the
//! frontends that make pods from it.

use crate::modes::UsernsChoice;
use crate::pod::{IdMapping, PodExitPolicy, PodPortMapping, PodResources, PodSpec, RestartPolicy};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Why a generator does not make a pod spec.
#[derive(Debug)]
pub enum SpecError {
    /// A value that is not valid (podman's 400)
    Invalid(String),
    /// Something a pod does not do (501)
    NotImplemented(String),
}

impl SpecError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    fn not_implemented(message: impl Into<String>) -> Self {
        Self::NotImplemented(message.into())
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Generator {
    #[serde(deserialize_with = "crate::godecode::nullable")]
    name: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    hostname: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    labels: BTreeMap<String, String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    dns_server: Vec<String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    dns_search: Vec<String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    dns_option: Vec<String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    hostadd: Vec<String>,
    shared_namespaces: Option<Vec<String>>,
    netns: Option<NsMode>,
    pidns: Option<NsMode>,
    ipcns: Option<NsMode>,
    #[serde(rename = "Networks")]
    #[serde(deserialize_with = "crate::godecode::nullable")]
    networks: HashMap<String, Value>,
    /// The deprecated list of the names of the networks
    #[serde(deserialize_with = "crate::godecode::nullable")]
    cni_networks: Vec<String>,
    /// The options of a network mode (pasta's): none is taken
    network_options: Option<Value>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    portmappings: Vec<GenPort>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    infra_image: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    infra_command: Vec<String>,
    infra_conmon_pid_file: Option<String>,
    no_infra: bool,
    userns: Option<NsMode>,
    idmappings: Option<IdMappings>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    infra_name: String,
    /// velarx's: the OCI runtime of the pod (SpecGenerator's name)
    #[serde(deserialize_with = "crate::godecode::nullable")]
    oci_runtime: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    exit_policy: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    restart_policy: String,
    restart_tries: Option<u32>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    sysctl: BTreeMap<String, String>,
    shm_size: Option<i64>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    cgroup_parent: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    security_opt: Vec<String>,
    /// velarx's: how the infra container runs (the user, the groups, the
    /// OOM score, a read-only root file system, privileged mode)
    infra_run_as_user: Option<u32>,
    infra_run_as_group: Option<u32>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    infra_supplemental_groups: Vec<u32>,
    infra_oom_score_adj: Option<i32>,
    infra_read_only: bool,
    infra_privileged: bool,
    /// velarx's: for the CNI plugins of the pod's network: the annotations
    /// of the pod, and the subnets of the node's pods
    #[serde(deserialize_with = "crate::godecode::nullable")]
    cni_annotations: BTreeMap<String, String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    cni_ip_ranges: Vec<String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    mounts: Vec<Value>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    volumes: Vec<Value>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    static_ip: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    static_mac: String,
    /// What the pod cannot do: refused when set.
    #[serde(deserialize_with = "crate::godecode::nullable")]
    overlay_volumes: Vec<Value>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    image_volumes: Vec<Value>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    pod_devices: Vec<String>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    volumes_from: Vec<String>,
    utsns: Option<NsMode>,
    shm_size_systemd: Option<i64>,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    pod_create_command: Vec<String>,
    resource_limits: Option<Value>,
    no_manage_hostname: bool,
    no_manage_hosts: bool,
    no_manage_resolv_conf: bool,
    #[serde(rename = "hostsFile", deserialize_with = "crate::godecode::nullable")]
    hosts_file: String,
    #[serde(
        rename = "serviceContainerID",
        deserialize_with = "crate::godecode::nullable"
    )]
    service_container_id: String,
    share_parent: Option<bool>,
    cpu_period: Option<u64>,
    cpu_quota: Option<i64>,
}

/// podman always sends the object, with the host mapping flags set.
#[derive(Deserialize, Default)]
#[serde(default)]
struct IdMappings {
    #[serde(rename = "UIDMap", deserialize_with = "crate::godecode::nullable")]
    uid_map: Vec<Value>,
    #[serde(rename = "GIDMap", deserialize_with = "crate::godecode::nullable")]
    gid_map: Vec<Value>,
    #[serde(rename = "AutoUserNs")]
    auto_userns: bool,
    #[serde(rename = "AutoUserNsOpts")]
    auto_userns_opts: Option<Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NsMode {
    #[serde(deserialize_with = "crate::godecode::nullable")]
    nsmode: String,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    value: String,
}

impl Generator {
    /// The generator of a pod with a name only.
    pub fn named(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Self::default()
        }
    }
}

/// Whether a setting has a value: null, false, zero, an empty string, list
/// or object is none.
fn present(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => o.values().any(present),
    }
}

/// Refuses a member of `v` that has a value (`scope` says where it is).
fn refuse_members(v: &Value, scope: &str, names: &[&str]) -> Result<(), SpecError> {
    for name in names {
        if v.get(name).is_some_and(present) {
            return Err(SpecError::not_implemented(format!(
                "{scope}.{name} is not supported for pods"
            )));
        }
    }
    Ok(())
}

/// An entry of `UIDMap` / `GIDMap`.
fn id_mapping(v: &Value) -> Result<IdMapping, SpecError> {
    let n = |k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| SpecError::invalid(format!("an ID mapping without a valid {k}")))
    };
    Ok(IdMapping {
        container_id: n("container_id")?,
        host_id: n("host_id")?,
        size: n("size")?,
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct GenPort {
    #[serde(deserialize_with = "crate::godecode::nullable")]
    host_ip: String,
    container_port: u16,
    host_port: u16,
    #[serde(deserialize_with = "crate::godecode::nullable")]
    protocol: String,
    range: u16,
}

/// The pod spec of a PodSpecGenerator; what cannot be applied is refused.
pub fn spec_of(g: Generator) -> Result<PodSpec, SpecError> {
    if g.no_infra && g.shared_namespaces.as_ref().is_some_and(|l| !l.is_empty()) {
        return Err(SpecError::invalid(
            "NoInfra and SharedNamespaces are mutually exclusive pod options: invalid pod spec",
        ));
    }
    let mut spec = PodSpec {
        no_infra: g.no_infra,
        // (the engine gives a pod without a name one)
        name: g.name,
        hostname: Some(g.hostname).filter(|h| !h.is_empty()),
        labels: g.labels,
        runtime: Some(g.oci_runtime).filter(|r| !r.is_empty()),
        add_hosts: g.hostadd,
        ..PodSpec::default()
    };
    spec.dns.servers = g.dns_server;
    spec.dns.searches = g.dns_search;
    spec.dns.options = g.dns_option;
    match g.shared_namespaces {
        None => {
            spec.share_ipc = true;
            spec.share_net = true;
            spec.share_uts = true;
        }
        Some(list) => {
            for ns in list {
                match ns.as_str() {
                    "net" => spec.share_net = true,
                    "ipc" => spec.share_ipc = true,
                    "uts" => spec.share_uts = true,
                    "pid" => spec.share_pid = true,
                    "cgroup" => spec.share_cgroup = true,
                    other => {
                        return Err(SpecError::not_implemented(format!(
                            "sharing the `{other}` namespace is not supported"
                        )))
                    }
                }
            }
        }
    }
    let mode = g.netns.map(|n| n.nsmode).unwrap_or_default();
    match mode.as_str() {
        "" | "default" | "private" | "bridge" => {}
        "host" | "none" => spec.networks.push(mode),
        other => {
            return Err(SpecError::not_implemented(format!(
                "the network mode `{other}` is not supported for pods"
            )))
        }
    }
    // the PID, IPC and UTS namespaces of the host: the pod shares none then
    for (kind, ns, host, share) in [
        ("pid", g.pidns, &mut spec.host_pid, &mut spec.share_pid),
        ("ipc", g.ipcns, &mut spec.host_ipc, &mut spec.share_ipc),
        ("uts", g.utsns, &mut spec.host_uts, &mut spec.share_uts),
    ] {
        match ns.map(|n| n.nsmode).unwrap_or_default().as_str() {
            "" | "default" | "private" | "pod" => {}
            "host" => {
                *host = true;
                *share = false;
            }
            other => {
                return Err(SpecError::not_implemented(format!(
                    "the {kind} namespace mode `{other}` is not supported for pods"
                )))
            }
        }
    }
    for opts in g.networks.values() {
        // (only the networks are taken: the pod has the addresses)
        refuse_members(
            opts,
            "Networks",
            &[
                "aliases",
                "static_ips",
                "static_mac",
                "interface_name",
                "options",
            ],
        )?;
    }
    if g.network_options.as_ref().is_some_and(present) {
        return Err(SpecError::not_implemented(
            "network_options are not supported for pods",
        ));
    }
    if !g.networks.is_empty() {
        spec.networks = g.networks.into_keys().collect();
        spec.networks.sort();
    } else if !g.cni_networks.is_empty() {
        spec.networks = g.cni_networks;
    }
    if let Some(u) = g.userns {
        // (`path` and `container` are not for pods, a value of theirs or not)
        match UsernsChoice::from_spec(&u.nsmode, &u.value) {
            Some(Ok(UsernsChoice::Host)) => {}
            Some(Ok(
                c @ (UsernsChoice::Private
                | UsernsChoice::NoMap
                | UsernsChoice::Auto(_)
                | UsernsChoice::KeepId(_)),
            )) => spec.userns = Some(c),
            _ => {
                return Err(SpecError::not_implemented(format!(
                    "the user namespace mode `{}` is not supported for pods",
                    u.nsmode
                )))
            }
        }
    }
    if let Some(m) = &g.idmappings {
        if let Some(o) = &m.auto_userns_opts {
            refuse_members(
                o,
                "idmappings.AutoUserNsOpts",
                &[
                    "InitialSize",
                    "PasswdFile",
                    "GroupFile",
                    "AdditionalUIDMappings",
                    "AdditionalGIDMappings",
                ],
            )?;
        }
        if m.auto_userns && matches!(spec.userns, None | Some(UsernsChoice::Auto(None))) {
            // (the size of the range, when the request has one)
            let size = m
                .auto_userns_opts
                .as_ref()
                .and_then(|o| o.get("Size"))
                .and_then(Value::as_u64)
                .filter(|n| *n != 0);
            spec.userns = Some(UsernsChoice::Auto(size.map(|n| format!("size={n}"))));
        }
        spec.uid_mappings = m
            .uid_map
            .iter()
            .map(id_mapping)
            .collect::<Result<_, SpecError>>()?;
        spec.gid_mappings = m
            .gid_map
            .iter()
            .map(id_mapping)
            .collect::<Result<_, SpecError>>()?;
        if !spec.uid_mappings.is_empty() || !spec.gid_mappings.is_empty() {
            // mappings of its own: a private user namespace
            spec.userns.get_or_insert(UsernsChoice::Private);
            if spec.gid_mappings.is_empty() {
                spec.gid_mappings = spec.uid_mappings.clone();
            } else if spec.uid_mappings.is_empty() {
                spec.uid_mappings = spec.gid_mappings.clone();
            }
        }
    }
    for p in g.portmappings {
        if p.container_port == 0 {
            return Err(SpecError::invalid(
                "a port mapping without a container port",
            ));
        }
        let range = p.range.max(1);
        for i in 0..range {
            spec.ports.push(PodPortMapping {
                container_port: p.container_port.saturating_add(i),
                host_port: (p.host_port != 0).then(|| p.host_port.saturating_add(i)),
                host_ip: Some(p.host_ip.clone()).filter(|h| !h.is_empty()),
                protocol: if p.protocol.is_empty() {
                    "tcp".into()
                } else {
                    p.protocol.clone()
                },
            });
        }
    }
    spec.infra_image = Some(g.infra_image).filter(|i| !i.is_empty());
    spec.infra_command = Some(g.infra_command).filter(|c| !c.is_empty());
    spec.infra_conmon_pidfile = g.infra_conmon_pid_file.filter(|p| !p.is_empty());
    spec.infra_name = Some(g.infra_name).filter(|n| !n.is_empty());
    match g.exit_policy.as_str() {
        "" => {}
        "continue" => spec.exit_policy = PodExitPolicy::Continue,
        "stop" => spec.exit_policy = PodExitPolicy::Stop,
        p => {
            return Err(SpecError::invalid(format!(
                "invalid pod exit policy: \"{p}\""
            )))
        }
    }
    match g.restart_policy.as_str() {
        "" => {}
        p @ ("no" | "always" | "on-failure" | "unless-stopped") => {
            spec.restart_policy = Some(RestartPolicy {
                name: p.into(),
                maximum_retry_count: g.restart_tries.unwrap_or(0),
            })
        }
        p => {
            return Err(SpecError::invalid(format!(
                "invalid restart policy: \"{p}\""
            )))
        }
    }
    spec.sysctls = g.sysctl;
    spec.shm_size = match g.shm_size {
        None | Some(0) => None,
        Some(n) => Some(u64::try_from(n).map_err(|_| SpecError::invalid("invalid shm size"))?),
    };
    spec.cgroup_parent = Some(g.cgroup_parent).filter(|c| !c.is_empty());
    spec.resources =
        PodResources::from_podman(g.resource_limits.as_ref(), g.cpu_period, g.cpu_quota)
            .map_err(SpecError::Invalid)?;
    spec.security_opts = g.security_opt;
    spec.security_context.run_as_user = g.infra_run_as_user;
    spec.security_context.run_as_group = g.infra_run_as_group;
    spec.security_context.supplemental_groups = g.infra_supplemental_groups;
    spec.infra_oom_score_adj = g.infra_oom_score_adj;
    spec.infra_read_only = g.infra_read_only;
    spec.infra_privileged = g.infra_privileged;
    spec.cni_annotations = g.cni_annotations;
    spec.cni_ip_ranges = g.cni_ip_ranges;
    spec.ip = Some(g.static_ip).filter(|i| !i.is_empty());
    spec.mac = Some(g.static_mac).filter(|m| !m.is_empty());
    for m in &g.mounts {
        refuse_members(m, "mounts", &["uidMappings", "gidMappings"])?;
        let field = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("");
        let (dest, src) = (field("destination"), field("source"));
        if !matches!(field("type"), "" | "bind") || dest.is_empty() || src.is_empty() {
            return Err(SpecError::not_implemented(
                "the mounts of a pod are bind mounts with a source and a destination",
            ));
        }
        spec.volumes.push(volume_arg(src, dest, m.get("options")));
    }
    for v in &g.volumes {
        refuse_members(v, "volumes", &["SubPath"])?;
        let field = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("");
        let (name, dest) = (field("Name"), field("Dest"));
        if dest.is_empty() {
            return Err(SpecError::invalid("a volume without destination"));
        }
        let anonymous = v.get("IsAnonymous").and_then(Value::as_bool) == Some(true);
        spec.volumes.push(if name.is_empty() || anonymous {
            dest.to_string()
        } else {
            volume_arg(name, dest, v.get("Options"))
        });
    }
    spec.no_hostname = g.no_manage_hostname;
    spec.no_hosts = g.no_manage_hosts;
    spec.hosts_file = Some(g.hosts_file).filter(|h| !h.is_empty());
    spec.no_share_parent = g.share_parent == Some(false);
    spec.devices = g.pod_devices;
    spec.volumes_from = g.volumes_from;
    spec.create_command = g.pod_create_command;
    spec.shm_size_systemd = match g.shm_size_systemd {
        None | Some(0) => None,
        Some(n) => {
            Some(u64::try_from(n).map_err(|_| SpecError::invalid("invalid shm size for systemd"))?)
        }
    };
    let refused: [(&str, bool); 4] = [
        ("no_manage_resolv_conf settings", g.no_manage_resolv_conf),
        ("service containers", !g.service_container_id.is_empty()),
        ("overlay volumes", !g.overlay_volumes.is_empty()),
        ("image volumes", !g.image_volumes.is_empty()),
    ];
    if let Some((what, _)) = refused.iter().find(|(_, set)| *set) {
        return Err(SpecError::not_implemented(format!(
            "{what} of a pod are not supported"
        )));
    }
    Ok(spec)
}

/// A `--volume` argument: `SOURCE:DEST[:OPTIONS]`.
fn volume_arg(src: &str, dest: &str, options: Option<&Value>) -> String {
    let opts: Vec<&str> = options
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if opts.is_empty() {
        format!("{src}:{dest}")
    } else {
        format!("{src}:{dest}:{}", opts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen(j: &str) -> Generator {
        serde_json::from_str(j).unwrap()
    }

    fn not_implemented(body: &str) -> bool {
        matches!(spec_of(gen(body)), Err(SpecError::NotImplemented(_)))
    }

    #[test]
    fn the_members_of_a_pod_that_are_not_taken_are_refused() {
        for (body, name) in [
            (
                r#"{"Networks":{"n":{"aliases":["a"]}}}"#,
                "Networks.aliases",
            ),
            (
                r#"{"Networks":{"n":{"static_ips":["10.0.0.2"]}}}"#,
                "Networks.static_ips",
            ),
            (
                r#"{"Networks":{"n":{"static_mac":"0a:00:00:00:00:01"}}}"#,
                "Networks.static_mac",
            ),
            (
                r#"{"Networks":{"n":{"interface_name":"e0"}}}"#,
                "Networks.interface_name",
            ),
            (
                r#"{"Networks":{"n":{"options":{"mode":"x"}}}}"#,
                "Networks.options",
            ),
            (
                r#"{"network_options":{"pasta":["-T","none"]}}"#,
                "network_options",
            ),
            (
                r#"{"idmappings":{"AutoUserNsOpts":{"InitialSize":4}}}"#,
                "idmappings.AutoUserNsOpts.InitialSize",
            ),
            (
                r#"{"idmappings":{"AutoUserNsOpts":{"PasswdFile":"/p"}}}"#,
                "idmappings.AutoUserNsOpts.PasswdFile",
            ),
            (
                r#"{"mounts":[{"type":"bind","source":"/s","destination":"/d","uidMappings":[{"containerID":0,"hostID":1,"size":1}]}]}"#,
                "mounts.uidMappings",
            ),
            (
                r#"{"volumes":[{"Name":"v","Dest":"/d","SubPath":"s"}]}"#,
                "volumes.SubPath",
            ),
        ] {
            match spec_of(gen(body)) {
                Err(SpecError::NotImplemented(m)) => assert!(m.contains(name), "{body}: {m}"),
                _ => panic!("{body} is not refused"),
            }
        }
        // zero values are no setting
        assert!(spec_of(gen(
            r#"{"Networks":{"n":{"aliases":null,"static_ips":[]}},"network_options":{},"idmappings":{"AutoUserNsOpts":{"InitialSize":0}}}"#
        ))
        .is_ok());
    }

    #[test]
    fn the_networks_size_and_anonymous_volumes_of_a_pod() {
        // the deprecated list of names is the networks
        let spec = spec_of(gen(r#"{"cni_networks":["b","a"]}"#)).unwrap();
        assert_eq!(spec.networks, ["b", "a"]);
        let spec = spec_of(gen(r#"{"Networks":{"x":{}},"cni_networks":["a"]}"#)).unwrap();
        assert_eq!(spec.networks, ["x"]);
        // the size of the range of an automatic user namespace
        let spec = spec_of(gen(
            r#"{"idmappings":{"AutoUserNs":true,"AutoUserNsOpts":{"Size":1024}}}"#,
        ))
        .unwrap();
        assert_eq!(spec.userns.unwrap().to_string(), "auto:size=1024");
        let spec = spec_of(gen(r#"{"idmappings":{"AutoUserNs":true}}"#)).unwrap();
        assert_eq!(spec.userns, Some(UsernsChoice::Auto(None)));
        // a volume that is anonymous has its destination only
        let spec = spec_of(gen(
            r#"{"volumes":[{"Name":"v","Dest":"/d","IsAnonymous":true},{"Name":"w","Dest":"/e"}]}"#,
        ))
        .unwrap();
        assert_eq!(spec.volumes, ["/d", "w:/e"]);
    }

    #[test]
    fn what_a_pod_cannot_do_is_refused() {
        for body in [
            r#"{"no_manage_resolv_conf":true}"#,
            r#"{"serviceContainerID":"x"}"#,
            r#"{"shared_namespaces":["user"]}"#,
            r#"{"netns":{"nsmode":"slirp4netns"}}"#,
            r#"{"userns":{"nsmode":"slirp"}}"#,
            r#"{"utsns":{"nsmode":"ns","value":"/x"}}"#,
            r#"{"mounts":[{"type":"tmpfs","destination":"/t"}]}"#,
        ] {
            assert!(not_implemented(body), "{body}");
        }
        assert!(spec_of(gen(r#"{"share_parent":true,"no_manage_hosts":false}"#)).is_ok());
        // a pod without an infra container shares nothing
        assert!(spec_of(gen(r#"{"no_infra":true}"#)).is_ok_and(|s| s.no_infra));
        assert!(matches!(
            spec_of(gen(r#"{"no_infra":true,"shared_namespaces":["net"]}"#)),
            Err(SpecError::Invalid(_))
        ));
        assert!(matches!(
            spec_of(gen(r#"{"exit_policy":"bogus"}"#)),
            Err(SpecError::Invalid(_))
        ));
        // what a pod cgroup cannot limit is refused, not dropped
        assert!(spec_of(gen(r#"{"resource_limits":{"pids":{"limit":10}}}"#)).is_err());
        assert!(spec_of(gen(r#"{"resource_limits":{"memory":{"reservation":10}}}"#)).is_err());
    }

    #[test]
    fn the_hosts_devices_and_namespaces_of_a_generator() {
        let s = spec_of(gen(
            r#"{"no_manage_hosts":true,"no_manage_hostname":true,"hostsFile":"none","share_parent":false,
                "pod_devices":["/dev/fuse:/dev/f:rw"],"volumes_from":["src:ro"],"shm_size_systemd":1048576,
                "utsns":{"nsmode":"host"},"pidns":{"nsmode":"host"},"pod_create_command":["podman","pod","create"]}"#,
        ))
        .unwrap();
        assert!(s.no_hosts && s.no_hostname && s.no_share_parent);
        assert_eq!(s.hosts_file.as_deref(), Some("none"));
        assert_eq!(s.devices, ["/dev/fuse:/dev/f:rw"]);
        assert_eq!(s.volumes_from, ["src:ro"]);
        assert_eq!(s.shm_size_systemd, Some(1 << 20));
        assert!(s.host_uts && !s.share_uts && s.host_pid);
        assert_eq!(s.create_command, ["podman", "pod", "create"]);
        let s = spec_of(gen(r#"{"share_parent":true}"#)).unwrap();
        assert!(!s.no_share_parent);
    }

    #[test]
    fn the_cni_settings_of_a_generator() {
        let s = spec_of(gen(
            r#"{"name":"a","cni_annotations":{"kubernetes.io/egress-bandwidth":"1M"},"cni_ip_ranges":["10.1.0.0/24"]}"#,
        ))
        .unwrap();
        assert_eq!(s.cni_annotations["kubernetes.io/egress-bandwidth"], "1M");
        assert_eq!(s.cni_ip_ranges, ["10.1.0.0/24"]);
    }

    #[test]
    fn the_infra_container_security_of_a_generator() {
        let s = spec_of(gen(
            r#"{"name":"a","infra_run_as_user":1000,"infra_run_as_group":2000,"infra_supplemental_groups":[3,4],"infra_oom_score_adj":-998,"infra_read_only":true,"infra_privileged":true,"security_opt":["seccomp=unconfined"]}"#,
        ))
        .unwrap();
        let sc = &s.security_context;
        assert_eq!((sc.run_as_user, sc.run_as_group), (Some(1000), Some(2000)));
        assert_eq!(sc.supplemental_groups, [3, 4]);
        assert_eq!(s.infra_oom_score_adj, Some(-998));
        assert!(s.infra_read_only && s.infra_privileged);
        assert_eq!(s.security_opts, ["seccomp=unconfined"]);
    }

    #[test]
    fn generator_defaults_and_values() {
        let s = spec_of(gen(r#"{"name":"a","labels":{"k":"v"}}"#)).unwrap();
        assert!(s.share_ipc && s.share_net && s.share_uts && !s.share_pid);
        assert_eq!(s.labels["k"], "v");
        let s = spec_of(gen(r#"{"shared_namespaces":["net","pid"]}"#)).unwrap();
        assert!(s.share_net && s.share_pid && !s.share_ipc);
        assert!(s.name.is_empty());
        let s = spec_of(gen(r#"{"userns":{"nsmode":"auto","value":"size=500"}}"#)).unwrap();
        assert_eq!(s.userns.unwrap().to_string(), "auto:size=500");
        let s = spec_of(gen(
            r#"{"idmappings":{"UIDMap":[{"container_id":0,"host_id":1,"size":1}]}}"#,
        ))
        .unwrap();
        assert_eq!(
            (s.userns, s.gid_mappings.len()),
            (Some(UsernsChoice::Private), 1)
        );
        let s = spec_of(gen(
            r#"{"exit_policy":"stop","restart_policy":"on-failure","restart_tries":3,
                "sysctl":{"net.ipv4.ip_forward":"1"},"shm_size":65536,"cgroup_parent":"/p",
                "mounts":[{"type":"bind","source":"/s","destination":"/d","options":["ro"]}],
                "volumes":[{"Name":"v","Dest":"/v"}],"static_ip":"10.0.0.9","infra_name":"inf"}"#,
        ))
        .unwrap();
        assert_eq!(s.exit_policy, PodExitPolicy::Stop);
        assert_eq!(s.restart_policy.unwrap().maximum_retry_count, 3);
        assert_eq!(s.volumes, ["/s:/d:ro", "v:/v"]);
        assert_eq!(
            (s.shm_size, s.ip.as_deref(), s.infra_name.as_deref()),
            (Some(65536), Some("10.0.0.9"), Some("inf"))
        );
        assert!(spec_of(gen(
            r#"{"resource_limits":{"cpu":{},"memory":{"limit":0}}}"#
        ))
        .is_ok());
        let limited = spec_of(gen(
            r#"{"resource_limits":{"memory":{"limit":1000,"swap":2000},"cpu":{"shares":512,"cpus":"0-1"}},"cpu_quota":50000}"#,
        ))
        .unwrap();
        let r = limited.resources.unwrap();
        assert_eq!(
            (r.memory, r.memory_swap, r.cpu_shares),
            (Some(1000), Some(2000), Some(512))
        );
        assert_eq!(
            (r.cpu_quota, r.cpuset_cpus.as_deref()),
            (Some(50000), Some("0-1"))
        );
        assert!(spec_of(gen(
            r#"{"idmappings":{"HostUIDMapping":true,"UIDMap":null}}"#
        ))
        .is_ok());
    }

    #[test]
    fn the_namespaces_a_generator_shares() {
        let s = spec_of(gen(r#"{"name":"a"}"#)).unwrap();
        assert!(s.share_ipc && s.share_net && s.share_uts && !s.share_pid);
        let s = spec_of(gen(r#"{"shared_namespaces":["net","pid"]}"#)).unwrap();
        assert!(!s.share_ipc && s.share_net && !s.share_uts && s.share_pid);
    }

    #[test]
    fn port_ranges() {
        let s = spec_of(gen(
            r#"{"portmappings":[{"container_port":80,"host_port":8080,"range":2,"protocol":"udp"}]}"#,
        ))
        .unwrap();
        assert_eq!(s.ports.len(), 2);
        assert_eq!(s.ports[1].container_port, 81);
        assert_eq!(s.ports[1].host_port, Some(8081));
        assert_eq!(s.ports[0].protocol, "udp");
    }
}
