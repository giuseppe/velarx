// SPDX-License-Identifier: Apache-2.0
//! `kube generate`: Kubernetes documents from pods, containers and volumes,
//! as podman writes them.  The callers describe what a container was made
//! with; this module only shapes the documents.

use crate::engine::Error;
use serde_json::{json, Map, Value};

/// A published port.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Port {
    pub container_port: u16,
    /// 0: not published
    pub host_port: u16,
    pub host_ip: Option<String>,
    /// `TCP`, `UDP` or `SCTP`
    pub protocol: String,
}

/// Where a mount of a container comes from.
#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    /// A named volume: a persistentVolumeClaim
    Volume(String),
    /// A directory or file of the host: a hostPath
    Host(String),
    /// A tmpfs: an emptyDir in memory
    Tmpfs,
    /// An image (`--mount type=image`)
    Image(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub target: String,
    pub source: Source,
    pub read_only: bool,
    pub subpath: Option<String>,
}

/// A health check run in the container: a livenessProbe.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Probe {
    pub command: Vec<String>,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub start_period_secs: u64,
    pub retries: u32,
}

/// What a container was made with, as much as the documents show.
#[derive(Debug, Clone, Default)]
pub struct Container {
    pub name: String,
    pub image: String,
    /// The entrypoint when it is not the image's
    pub command: Vec<String>,
    /// The arguments when they are not the image's
    pub args: Vec<String>,
    /// The variables the user set (not those of the image)
    pub env: Vec<(String, String)>,
    /// The working directory when it is not the image's
    pub working_dir: Option<String>,
    pub ports: Vec<Port>,
    pub mounts: Vec<Mount>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub privileged: bool,
    pub read_only_rootfs: bool,
    pub run_as_user: Option<u32>,
    pub run_as_group: Option<u32>,
    /// The SELinux type and level given by the user
    pub selinux_type: Option<String>,
    pub selinux_level: Option<String>,
    pub memory_limit: Option<i64>,
    /// CPUs (quota / period)
    pub cpu_limit: Option<f64>,
    pub probe: Option<Probe>,
    pub tty: bool,
    pub stdin: bool,
    /// Its annotations: those of the pod named `KEY/CONTAINER`
    pub annotations: Vec<(String, String)>,
}

/// A pod: its own, or one around a container.
#[derive(Debug, Clone, Default)]
pub struct Pod {
    pub name: String,
    pub containers: Vec<Container>,
    pub hostname: Option<String>,
    pub labels: Vec<(String, String)>,
    /// `Always`, `OnFailure` or `Never`
    pub restart_policy: Option<String>,
    pub host_network: bool,
    /// When it was created, RFC 3339
    pub created: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pod,
    Deployment,
    DaemonSet,
    Job,
}

impl std::str::FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "" | "pod" => Ok(Kind::Pod),
            "deployment" => Ok(Kind::Deployment),
            "daemonset" => Ok(Kind::DaemonSet),
            "job" => Ok(Kind::Job),
            _ => Err(format!(
                "invalid kube type `{s}`: pod, deployment, daemonset or job"
            )),
        }
    }
}

/// A DNS-1123 label, as Kubernetes names objects: lower case letters,
/// digits and `-`, starting and ending with a letter or a digit, at most 63.
pub fn dns_label(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    out.truncate(63);
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "x".into()
    } else {
        out
    }
}

/// The capabilities as Kubernetes names them (no `CAP_`).
fn cap_names(caps: &[String]) -> Vec<Value> {
    caps.iter()
        .map(|c| {
            let c = c.to_ascii_uppercase();
            json!(c.strip_prefix("CAP_").unwrap_or(&c))
        })
        .collect()
}

/// The quantity of a memory size in bytes.
fn memory_quantity(bytes: i64) -> String {
    const UNITS: [(i64, &str); 3] = [(1 << 30, "Gi"), (1 << 20, "Mi"), (1 << 10, "Ki")];
    for (size, unit) in UNITS {
        if bytes >= size && bytes % size == 0 {
            return format!("{}{unit}", bytes / size);
        }
    }
    bytes.to_string()
}

/// The quantity of a number of CPUs, in millicores when not whole.
fn cpu_quantity(cpus: f64) -> String {
    let milli = (cpus * 1000.0).round() as i64;
    if milli % 1000 == 0 {
        (milli / 1000).to_string()
    } else {
        format!("{milli}m")
    }
}

/// The name of the volume of a pod for a mount, unique in the pod.
fn volume_name(m: &Mount, n: usize) -> String {
    let base = match &m.source {
        Source::Volume(name) => format!("{}-pvc", dns_label(name)),
        Source::Host(path) => format!("{}-host-{n}", dns_label(path)),
        Source::Tmpfs => format!("{}-tmpfs-{n}", dns_label(&m.target)),
        Source::Image(_) => format!("{}-image-{n}", dns_label(&m.target)),
    };
    // room for the suffixes, still a label
    dns_label(&base)
}

fn container_doc(
    c: &Container,
    service: bool,
    volumes: &mut Vec<Value>,
    names: &mut Vec<(Source, String)>,
) -> Value {
    let mut o = Map::new();
    if !c.args.is_empty() {
        o.insert("args".into(), json!(c.args));
    }
    if !c.command.is_empty() {
        o.insert("command".into(), json!(c.command));
    }
    if !c.env.is_empty() {
        let env: Vec<Value> = c
            .env
            .iter()
            .map(|(k, v)| json!({"name": k, "value": v}))
            .collect();
        o.insert("env".into(), json!(env));
    }
    o.insert("image".into(), json!(c.image));
    if let Some(p) = &c.probe {
        let mut probe = Map::new();
        probe.insert("exec".into(), json!({"command": p.command}));
        if p.retries > 0 {
            probe.insert("failureThreshold".into(), json!(p.retries));
        }
        if p.start_period_secs > 0 {
            probe.insert("initialDelaySeconds".into(), json!(p.start_period_secs));
        }
        if p.interval_secs > 0 {
            probe.insert("periodSeconds".into(), json!(p.interval_secs));
        }
        if p.timeout_secs > 0 {
            probe.insert("timeoutSeconds".into(), json!(p.timeout_secs));
        }
        o.insert("livenessProbe".into(), Value::Object(probe));
    }
    o.insert("name".into(), json!(dns_label(&c.name)));
    if !c.ports.is_empty() {
        let ports: Vec<Value> = c
            .ports
            .iter()
            .map(|p| {
                let mut m = Map::new();
                m.insert("containerPort".into(), json!(p.container_port));
                // a Service publishes them instead
                if p.host_port != 0 && !service {
                    m.insert("hostPort".into(), json!(p.host_port));
                    if let Some(ip) = p.host_ip.as_ref().filter(|i| !i.is_empty()) {
                        m.insert("hostIP".into(), json!(ip));
                    }
                }
                if p.protocol != "TCP" {
                    m.insert("protocol".into(), json!(p.protocol));
                }
                Value::Object(m)
            })
            .collect();
        o.insert("ports".into(), json!(ports));
    }
    let mut limits = Map::new();
    if let Some(m) = c.memory_limit.filter(|m| *m > 0) {
        limits.insert("memory".into(), json!(memory_quantity(m)));
    }
    if let Some(cpus) = c.cpu_limit.filter(|c| *c > 0.0) {
        limits.insert("cpu".into(), json!(cpu_quantity(cpus)));
    }
    if !limits.is_empty() {
        o.insert("resources".into(), json!({"limits": limits}));
    }
    let mut sc = Map::new();
    if c.privileged {
        sc.insert("privileged".into(), json!(true));
    }
    if !c.cap_add.is_empty() || !c.cap_drop.is_empty() {
        let mut caps = Map::new();
        if !c.cap_add.is_empty() {
            caps.insert("add".into(), json!(cap_names(&c.cap_add)));
        }
        if !c.cap_drop.is_empty() {
            caps.insert("drop".into(), json!(cap_names(&c.cap_drop)));
        }
        sc.insert("capabilities".into(), Value::Object(caps));
    }
    if c.read_only_rootfs {
        sc.insert("readOnlyRootFilesystem".into(), json!(true));
    }
    if let Some(u) = c.run_as_user {
        sc.insert("runAsUser".into(), json!(u));
    }
    if let Some(g) = c.run_as_group {
        sc.insert("runAsGroup".into(), json!(g));
    }
    if c.selinux_type.is_some() || c.selinux_level.is_some() {
        let mut se = Map::new();
        if let Some(l) = &c.selinux_level {
            se.insert("level".into(), json!(l));
        }
        if let Some(t) = &c.selinux_type {
            se.insert("type".into(), json!(t));
        }
        sc.insert("seLinuxOptions".into(), Value::Object(se));
    }
    if !sc.is_empty() {
        o.insert("securityContext".into(), Value::Object(sc));
    }
    if c.stdin {
        o.insert("stdin".into(), json!(true));
    }
    if c.tty {
        o.insert("tty".into(), json!(true));
    }
    if !c.mounts.is_empty() {
        let mut mounts = Vec::new();
        for m in &c.mounts {
            // a named volume or a host path used twice is one volume
            let name = match names
                .iter()
                .find(|(s, _)| *s == m.source && !matches!(s, Source::Tmpfs))
            {
                Some((_, n)) => n.clone(),
                None => {
                    let n = volume_name(m, names.len());
                    let source = match &m.source {
                        Source::Volume(v) => json!({"persistentVolumeClaim": {"claimName": v}}),
                        Source::Host(p) => json!({"hostPath": {"path": p, "type": "Directory"}}),
                        Source::Tmpfs => json!({"emptyDir": {"medium": "Memory"}}),
                        Source::Image(r) => json!({"image": {"reference": r}}),
                    };
                    let mut v = source.as_object().cloned().unwrap_or_default();
                    v.insert("name".into(), json!(n));
                    volumes.push(Value::Object(v));
                    names.push((m.source.clone(), n.clone()));
                    n
                }
            };
            let mut vm = Map::new();
            vm.insert("mountPath".into(), json!(m.target));
            vm.insert("name".into(), json!(name));
            if m.read_only {
                vm.insert("readOnly".into(), json!(true));
            }
            if let Some(s) = &m.subpath {
                vm.insert("subPath".into(), json!(s));
            }
            mounts.push(Value::Object(vm));
        }
        o.insert("volumeMounts".into(), json!(mounts));
    }
    if let Some(w) = &c.working_dir {
        o.insert("workingDir".into(), json!(w));
    }
    Value::Object(o)
}

/// The labels that select the pod.
fn app_labels(pod: &Pod) -> Map<String, Value> {
    let mut labels = Map::new();
    labels.insert("app".into(), json!(dns_label(&pod.name)));
    for (k, v) in &pod.labels {
        labels.insert(k.clone(), json!(v));
    }
    labels
}

fn pod_spec(pod: &Pod, kind: Kind, service: bool) -> Value {
    let mut volumes = Vec::new();
    let mut names = Vec::new();
    let containers: Vec<Value> = pod
        .containers
        .iter()
        .map(|c| container_doc(c, service, &mut volumes, &mut names))
        .collect();
    let mut spec = Map::new();
    spec.insert("containers".into(), json!(containers));
    if let Some(h) = &pod.hostname {
        spec.insert("hostname".into(), json!(h));
    }
    if pod.host_network {
        spec.insert("hostNetwork".into(), json!(true));
    }
    // a Job's pods may not be restarted always
    let restart = match (kind, pod.restart_policy.as_deref()) {
        (Kind::Job, Some("OnFailure")) => Some("OnFailure"),
        (Kind::Job, _) => Some("Never"),
        (_, r) => r,
    };
    if let Some(r) = restart {
        spec.insert("restartPolicy".into(), json!(r));
    }
    if !volumes.is_empty() {
        spec.insert("volumes".into(), json!(volumes));
    }
    Value::Object(spec)
}

/// The documents of a pod: the pod or the workload around it, and with
/// `service` a Service of its published ports.
pub fn pod_documents(
    pod: &Pod,
    kind: Kind,
    replicas: u32,
    service: bool,
) -> Result<Vec<Value>, Error> {
    let name = dns_label(&pod.name);
    let labels = app_labels(pod);
    let mut meta = Map::new();
    if let Some(c) = &pod.created {
        meta.insert("creationTimestamp".into(), json!(c));
    }
    let annotations: Map<String, Value> = pod
        .containers
        .iter()
        .flat_map(|c| {
            c.annotations
                .iter()
                .map(|(k, v)| (format!("{k}/{}", dns_label(&c.name)), json!(v)))
        })
        .collect();
    if !annotations.is_empty() {
        meta.insert("annotations".into(), Value::Object(annotations));
    }
    meta.insert("labels".into(), Value::Object(labels.clone()));
    meta.insert("name".into(), json!(name));
    let spec = pod_spec(pod, kind, service);
    let doc = match kind {
        Kind::Pod => json!({"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": spec}),
        Kind::Deployment | Kind::DaemonSet | Kind::Job => {
            let (api, k, suffix) = match kind {
                Kind::Deployment => ("apps/v1", "Deployment", "deployment"),
                Kind::DaemonSet => ("apps/v1", "DaemonSet", "daemonset"),
                _ => ("batch/v1", "Job", "job"),
            };
            let mut wmeta = meta.clone();
            wmeta.insert("name".into(), json!(dns_label(&format!("{name}-{suffix}"))));
            let mut wspec = Map::new();
            if kind == Kind::Deployment {
                wspec.insert("replicas".into(), json!(replicas.max(1)));
            }
            if kind != Kind::Job {
                wspec.insert("selector".into(), json!({"matchLabels": labels}));
            }
            wspec.insert("template".into(), json!({"metadata": meta, "spec": spec}));
            json!({"apiVersion": api, "kind": k, "metadata": wmeta, "spec": wspec})
        }
    };
    let mut docs = vec![doc];
    if service {
        let mut used = std::collections::BTreeSet::new();
        let ports: Vec<Value> = pod
            .containers
            .iter()
            .flat_map(|c| &c.ports)
            .map(|p| {
                let mut m = Map::new();
                m.insert("name".into(), json!(p.container_port.to_string()));
                if p.host_port != 0 {
                    m.insert(
                        "nodePort".into(),
                        json!(node_port(u32::from(p.host_port), &mut used)?),
                    );
                }
                m.insert("port".into(), json!(p.container_port));
                m.insert("protocol".into(), json!(p.protocol));
                m.insert("targetPort".into(), json!(p.container_port));
                Ok(Value::Object(m))
            })
            .collect::<Result<_, Error>>()?;
        let typ = if ports.iter().any(|p| p.get("nodePort").is_some()) {
            "NodePort"
        } else {
            "ClusterIP"
        };
        docs.push(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"labels": {"app": name}, "name": name},
            "spec": {"ports": ports, "selector": {"app": name}, "type": typ},
        }));
    }
    Ok(docs)
}

/// The legal range of a Service's nodePort.
const NODE_PORTS: std::ops::RangeInclusive<u32> = 30000..=32767;

/// The nodePort for the published port `host`: the port itself when it is a
/// legal one and free, else the next free one of the range from a place the
/// port makes (the same YAML for the same pod).  It is an error when every
/// port of the range is taken.
fn node_port(host: u32, used: &mut std::collections::BTreeSet<u32>) -> Result<u32, Error> {
    let size = NODE_PORTS.end() - NODE_PORTS.start() + 1;
    if used.len() as u32 == size {
        return Err(Error::new("every node port of the range is taken"));
    }
    let first = if NODE_PORTS.contains(&host) {
        host
    } else {
        NODE_PORTS.start() + host % size
    };
    let mut port = first;
    while !used.insert(port) {
        port = NODE_PORTS.start() + (port - NODE_PORTS.start() + 1) % size;
    }
    Ok(port)
}

/// The claim of a named volume.
pub fn volume_document(name: &str, labels: &[(String, String)], created: Option<&str>) -> Value {
    let mut meta = Map::new();
    if let Some(c) = created {
        meta.insert("creationTimestamp".into(), json!(c));
    }
    if !labels.is_empty() {
        let l: Map<String, Value> = labels.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        meta.insert("labels".into(), Value::Object(l));
    }
    meta.insert("name".into(), json!(name));
    json!({
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": meta,
        "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}},
    })
}

/// The YAML of documents, with podman's header.
pub fn to_yaml(docs: &[Value]) -> String {
    format!(
        "# Save the output of this file and use kubectl create -f to import\n\
         # it into Kubernetes.\n#\n# Created with velarx-{}\n{}",
        env!("CARGO_PKG_VERSION"),
        super::yaml::emit_documents(docs)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn web() -> Pod {
        Pod {
            name: "Web_Pod".into(),
            hostname: Some("web".into()),
            restart_policy: Some("Always".into()),
            labels: vec![("tier".into(), "front".into())],
            created: Some("2026-10-11T00:00:00Z".into()),
            containers: vec![Container {
                name: "srv".into(),
                image: "localhost:5000/alpine:chunked".into(),
                args: vec!["sh".into(), "-c".into(), "echo \"q\"".into()],
                env: vec![("K".into(), "V".into())],
                working_dir: Some("/srv".into()),
                ports: vec![
                    Port {
                        container_port: 80,
                        host_port: 8181,
                        host_ip: None,
                        protocol: "TCP".into(),
                    },
                    Port {
                        container_port: 53,
                        host_port: 0,
                        host_ip: None,
                        protocol: "UDP".into(),
                    },
                ],
                mounts: vec![
                    Mount {
                        target: "/data".into(),
                        source: Source::Volume("kubevol".into()),
                        read_only: false,
                        subpath: None,
                    },
                    Mount {
                        target: "/conf".into(),
                        source: Source::Host("/etc/app".into()),
                        read_only: true,
                        subpath: None,
                    },
                    Mount {
                        target: "/sub".into(),
                        source: Source::Volume("kubevol".into()),
                        read_only: false,
                        subpath: Some("a/b".into()),
                    },
                    Mount {
                        target: "/scratch".into(),
                        source: Source::Tmpfs,
                        read_only: false,
                        subpath: None,
                    },
                ],
                cap_add: vec!["CAP_NET_ADMIN".into()],
                cap_drop: vec!["mknod".into()],
                memory_limit: Some(64 << 20),
                cpu_limit: Some(0.5),
                run_as_user: Some(1000),
                probe: Some(Probe {
                    command: vec!["true".into()],
                    interval_secs: 30,
                    timeout_secs: 5,
                    start_period_secs: 0,
                    retries: 3,
                }),
                annotations: vec![("io.podman.annotations.init".into(), "TRUE".into())],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn a_pod() {
        let docs = pod_documents(&web(), Kind::Pod, 1, false).unwrap();
        assert_eq!(docs.len(), 1);
        let d = &docs[0];
        assert_eq!(
            (d["apiVersion"].as_str(), d["kind"].as_str()),
            (Some("v1"), Some("Pod"))
        );
        assert_eq!(d["metadata"]["name"], "web-pod");
        assert_eq!(
            d["metadata"]["annotations"],
            json!({"io.podman.annotations.init/srv": "TRUE"})
        );
        assert_eq!(
            d["metadata"]["labels"],
            json!({"app": "web-pod", "tier": "front"})
        );
        let c = &d["spec"]["containers"][0];
        assert_eq!(c["name"], "srv");
        assert_eq!(c["args"], json!(["sh", "-c", "echo \"q\""]));
        assert!(c.get("command").is_none());
        assert_eq!(c["env"], json!([{"name": "K", "value": "V"}]));
        assert_eq!(
            c["ports"],
            json!([{"containerPort": 80, "hostPort": 8181}, {"containerPort": 53, "protocol": "UDP"}])
        );
        assert_eq!(
            c["resources"]["limits"],
            json!({"memory": "64Mi", "cpu": "500m"})
        );
        assert_eq!(
            c["securityContext"]["capabilities"],
            json!({"add": ["NET_ADMIN"], "drop": ["MKNOD"]})
        );
        assert_eq!(c["securityContext"]["runAsUser"], 1000);
        assert_eq!(
            c["livenessProbe"],
            json!({"exec": {"command": ["true"]}, "failureThreshold": 3, "periodSeconds": 30, "timeoutSeconds": 5})
        );
        assert_eq!(c["workingDir"], "/srv");
        // one claim for the two mounts of the volume, a host path, a tmpfs
        let vols = d["spec"]["volumes"].as_array().unwrap();
        assert_eq!(vols.len(), 3);
        assert_eq!(
            vols[0],
            json!({"name": "kubevol-pvc", "persistentVolumeClaim": {"claimName": "kubevol"}})
        );
        assert_eq!(
            vols[1]["hostPath"],
            json!({"path": "/etc/app", "type": "Directory"})
        );
        assert_eq!(vols[2]["emptyDir"], json!({"medium": "Memory"}));
        let mounts = c["volumeMounts"].as_array().unwrap();
        assert_eq!(
            mounts[0],
            json!({"mountPath": "/data", "name": "kubevol-pvc"})
        );
        assert_eq!(mounts[1]["readOnly"], true);
        assert_eq!(
            mounts[2],
            json!({"mountPath": "/sub", "name": "kubevol-pvc", "subPath": "a/b"})
        );
        assert_eq!(d["spec"]["hostname"], "web");
        assert_eq!(d["spec"]["restartPolicy"], "Always");
        // what is written parses back
        let back = crate::yaml::parse_documents(&to_yaml(&docs)).unwrap();
        assert_eq!(
            back[0]["spec"]["containers"][0]["ports"][0]["hostPort"],
            "8181"
        );
        assert!(to_yaml(&docs).starts_with("# Save the output"));
    }

    #[test]
    fn workloads_and_a_service() {
        let docs = pod_documents(&web(), Kind::Deployment, 3, true).unwrap();
        assert_eq!(docs.len(), 2);
        let d = &docs[0];
        assert_eq!(
            (d["apiVersion"].as_str(), d["kind"].as_str()),
            (Some("apps/v1"), Some("Deployment"))
        );
        assert_eq!(d["metadata"]["name"], "web-pod-deployment");
        assert_eq!(d["spec"]["replicas"], 3);
        assert_eq!(d["spec"]["selector"]["matchLabels"]["app"], "web-pod");
        assert_eq!(d["spec"]["template"]["metadata"]["name"], "web-pod");
        // the Service publishes the port, the pod does not
        let c = &d["spec"]["template"]["spec"]["containers"][0];
        assert!(c["ports"][0].get("hostPort").is_none());
        let s = &docs[1];
        assert_eq!(s["kind"], "Service");
        assert_eq!(s["spec"]["type"], "NodePort");
        assert_eq!(
            s["spec"]["ports"][0],
            json!({"name": "80", "nodePort": 32645, "port": 80, "protocol": "TCP", "targetPort": 80})
        );
        assert_eq!(s["spec"]["selector"], json!({"app": "web-pod"}));

        let job = &pod_documents(&web(), Kind::Job, 1, false).unwrap()[0];
        assert_eq!(
            (job["apiVersion"].as_str(), job["kind"].as_str()),
            (Some("batch/v1"), Some("Job"))
        );
        assert_eq!(job["spec"]["template"]["spec"]["restartPolicy"], "Never");
        assert!(job["spec"].get("selector").is_none());
        let ds = &pod_documents(&web(), Kind::DaemonSet, 1, false).unwrap()[0];
        assert_eq!(ds["kind"], "DaemonSet");
        assert!(ds["spec"].get("replicas").is_none());
        assert_eq!("job".parse::<Kind>(), Ok(Kind::Job));
        assert!("cronjob".parse::<Kind>().is_err());
    }

    #[test]
    fn node_ports_are_in_the_range_of_a_service() {
        let mut used = std::collections::BTreeSet::new();
        assert_eq!(node_port(31000, &mut used).unwrap(), 31000);
        // a taken one, and a port outside the range, give the next free
        assert_eq!(node_port(31000, &mut used).unwrap(), 31001);
        assert_eq!(node_port(8181, &mut used).unwrap(), 32645);
        assert_eq!(node_port(65535, &mut used).unwrap(), 30000 + 65535 % 2768);
        let mut used: std::collections::BTreeSet<u32> = (30000..=32766).collect();
        assert_eq!(node_port(1, &mut used).unwrap(), 32767);
        assert!(node_port(1, &mut used).is_err());
    }

    #[test]
    fn the_last_node_port_is_given_and_the_next_one_is_an_error() {
        let mut used = std::collections::BTreeSet::new();
        for n in 0..2768 {
            node_port(n, &mut used).unwrap();
        }
        assert!(node_port(0, &mut used).is_err());
    }

    #[test]
    fn names_and_quantities() {
        assert_eq!(dns_label("My_Container.1"), "my-container-1");
        assert_eq!(dns_label("--"), "x");
        assert_eq!(dns_label(&"a".repeat(80)).len(), 63);
        assert_eq!(memory_quantity(1 << 30), "1Gi");
        assert_eq!(memory_quantity(1536), "1536");
        assert_eq!(memory_quantity(3 << 10), "3Ki");
        assert_eq!(cpu_quantity(2.0), "2");
        assert_eq!(cpu_quantity(0.25), "250m");
        let v = volume_document("data", &[("k".into(), "v".into())], None);
        assert_eq!(v["kind"], "PersistentVolumeClaim");
        assert_eq!(v["metadata"], json!({"labels": {"k": "v"}, "name": "data"}));
    }
}
