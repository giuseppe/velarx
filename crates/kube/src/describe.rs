// SPDX-License-Identifier: Apache-2.0
//! `generate`: the documents of the engine's pods, containers and volumes,
//! made from the records the engine answers with.

use crate::engine::{Engine, Error, Result};
use crate::generate::{self as gen, Kind};
use velarx_proto::time::{format_rfc3339, Fraction};
use velarx_proto::workload::{ContainerRecord, ImageConfigRecord, MountKind, PodRecord};

/// podman's annotations that only podman reads: in the documents with
/// `--podman-only` only.
const PODMAN_RESERVED: [&str; 12] = [
    "io.podman.annotations.cid-file",
    "io.podman.annotations.autoremove",
    "io.podman.annotations.autoremove-image",
    "io.podman.annotations.privileged",
    "io.podman.annotations.publish-all",
    "io.podman.annotations.init",
    "io.podman.annotations.label",
    "io.podman.annotations.seccomp",
    "io.podman.annotations.apparmor",
    "TRUE",
    "FALSE",
    "io.podman.annotations.volumes-from",
];

/// What `generate` makes.
#[derive(Debug, Clone, Copy)]
pub struct GenerateOptions {
    pub kind: Kind,
    /// Of a Deployment
    pub replicas: u32,
    /// A Service of the published ports too
    pub service: bool,
    /// podman's own annotations of the containers too
    pub podman_only: bool,
}

/// The variables the user gave: not the image's, not the engine's.
fn user_env(env: &[String], image: &[String]) -> Vec<(String, String)> {
    const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    env.iter()
        .filter(|e| !image.contains(e) && e.as_str() != DEFAULT_PATH)
        .filter_map(|e| e.split_once('='))
        .filter(|(k, _)| {
            !matches!(
                *k,
                "HOSTNAME" | "container" | "container_uuid" | "TERM" | "HOME"
            )
        })
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// The mounts the user asked for, as the documents show them.
fn mounts(c: &ContainerRecord) -> Vec<gen::Mount> {
    c.mounts
        .iter()
        .filter_map(|m| {
            let source = match m.kind {
                MountKind::Volume => gen::Source::Volume(m.name.clone()),
                MountKind::Image => gen::Source::Image(m.source.clone()),
                MountKind::Tmpfs => gen::Source::Tmpfs,
                MountKind::Bind if m.source.is_empty() => return None,
                MountKind::Bind => gen::Source::Host(m.source.clone()),
            };
            Some(gen::Mount {
                target: m.destination.clone(),
                source,
                read_only: m.read_only || m.options.iter().any(|o| o == "ro"),
                subpath: Some(m.sub_path.clone()).filter(|s| !s.is_empty()),
            })
        })
        .collect()
}

/// The ports a container publishes, a range as one port each.
fn ports(c: &ContainerRecord) -> Vec<gen::Port> {
    let mut out = Vec::new();
    for p in &c.network.ports {
        for i in 0..p.range.max(1) {
            let port = |n: i64| u16::try_from(n.saturating_add(i)).unwrap_or(u16::MAX);
            out.push(gen::Port {
                container_port: port(p.container_port),
                host_port: if p.host_port == 0 {
                    0
                } else {
                    port(p.host_port)
                },
                host_ip: Some(p.host_ip.clone()).filter(|ip| !ip.is_empty()),
                protocol: p.protocol.to_ascii_uppercase(),
            });
        }
    }
    out
}

fn restart_policy(c: &ContainerRecord) -> Option<String> {
    match c.host.restart_policy.as_str() {
        "always" | "unless-stopped" => Some("Always".into()),
        "on-failure" => Some("OnFailure".into()),
        "no" => Some("Never".into()),
        _ => None,
    }
}

fn container(c: &ContainerRecord, image: &ImageConfigRecord, podman_only: bool) -> gen::Container {
    let p = &c.process;
    let (run_as_user, run_as_group) = {
        let mut it = p.user.splitn(2, ':');
        let u = it.next().and_then(|u| u.parse().ok());
        let g = it.next().and_then(|g| g.parse().ok());
        (u, g)
    };
    let cpu_limit = match (c.resources.cpu_quota, c.resources.cpu_period) {
        (q, period) if q > 0 && period > 0 => Some(q as f64 / period as f64),
        (q, _) if q > 0 => Some(q as f64 / 100_000.0),
        _ => None,
    };
    let probe = p
        .healthcheck
        .as_ref()
        .filter(|h| !h.test.is_empty())
        .map(|h| {
            let command = match h.test.first().map(String::as_str) {
                Some("CMD-SHELL") => vec!["/bin/sh".into(), "-c".into(), h.test[1..].join(" ")],
                Some("CMD") => h.test[1..].to_vec(),
                _ => h.test.clone(),
            };
            let secs = |ns: u64| ns / 1_000_000_000;
            gen::Probe {
                command,
                interval_secs: secs(h.interval_ns),
                timeout_secs: secs(h.timeout_ns),
                start_period_secs: secs(h.start_period_ns),
                retries: h.retries,
            }
        });
    let entrypoint_given = !p.entrypoint.is_empty() && p.entrypoint != image.entrypoint;
    gen::Container {
        name: c.name.clone(),
        image: c.image.clone(),
        command: if entrypoint_given {
            p.entrypoint.clone()
        } else {
            Vec::new()
        },
        args: if entrypoint_given || p.command != image.cmd {
            p.command.clone()
        } else {
            Vec::new()
        },
        env: user_env(&p.env, &image.env),
        working_dir: Some(p.work_dir.clone())
            .filter(|w| !w.is_empty() && *w != image.working_dir && w != "/"),
        ports: ports(c),
        mounts: mounts(c),
        cap_add: c.host.cap_add.clone(),
        cap_drop: c.host.cap_drop.clone(),
        privileged: c.privileged,
        read_only_rootfs: c.host.read_only_rootfs,
        run_as_user,
        run_as_group,
        selinux_type: None,
        selinux_level: None,
        memory_limit: Some(c.resources.memory_limit).filter(|m| *m > 0),
        cpu_limit,
        probe,
        tty: c.tty,
        stdin: c.stdin,
        annotations: c
            .annotations
            .iter()
            .filter(|(k, _)| podman_only || !PODMAN_RESERVED.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    }
}

fn created(ns: i64) -> Option<String> {
    Some(format_rfc3339(ns, Fraction::Groups))
}

/// The image configuration of a container (empty when its image is not in
/// the store: a root file system).
async fn image_config(engine: &Engine, c: &ContainerRecord) -> Result<ImageConfigRecord> {
    if c.image_id.is_empty() {
        return Ok(ImageConfigRecord::default());
    }
    Ok(engine
        .image(&c.image_id)
        .await?
        .map(|i| i.config)
        .unwrap_or_default())
}

/// A pod of a container of its own.
async fn container_pod(
    engine: &Engine,
    records: &[ContainerRecord],
    podman_only: bool,
) -> Result<gen::Pod> {
    let mut containers = Vec::new();
    for c in records {
        containers.push(container(c, &image_config(engine, c).await?, podman_only));
    }
    let first = &records[0];
    let short = &first.id[..first.id.len().min(12)];
    Ok(gen::Pod {
        name: format!("{}-pod", first.name),
        containers,
        hostname: Some(first.process.hostname.clone()).filter(|h| !h.is_empty() && h != short),
        labels: Vec::new(),
        restart_policy: restart_policy(first),
        host_network: first.network.mode == "host",
        created: created(first.created_ns),
    })
}

/// A pod of the engine: its containers but the infra one; the ports it
/// publishes go to its first container, as podman puts them.
async fn engine_pod(engine: &Engine, pod: &PodRecord, podman_only: bool) -> Result<gen::Pod> {
    let mut records = Vec::new();
    for m in &pod.members {
        if m.id == pod.infra_id {
            continue;
        }
        let c = engine
            .container(&m.id)
            .await?
            .ok_or_else(|| Error::new(format!("no container {} in the pod {}", m.id, pod.name)))?;
        records.push(c);
    }
    let mut containers = Vec::new();
    for c in &records {
        let mut made = container(c, &image_config(engine, c).await?, podman_only);
        // play names a container POD-NAME: the name in the pod is NAME
        if let Some(short) = made
            .name
            .strip_prefix(&format!("{}-", pod.name))
            .filter(|n| !n.is_empty())
        {
            made.name = short.to_string();
        }
        containers.push(made);
    }
    if let Some(first) = containers.first_mut() {
        first.ports.extend(pod.spec.ports.iter().map(|p| gen::Port {
            container_port: p.container_port,
            host_port: p.host_port.unwrap_or(0),
            host_ip: p.host_ip.clone().filter(|ip| !ip.is_empty()),
            protocol: p.protocol.to_ascii_uppercase(),
        }));
    }
    let mut labels: Vec<(String, String)> = pod
        .spec
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    labels.sort();
    Ok(gen::Pod {
        name: pod.name.clone(),
        containers,
        hostname: pod.spec.hostname.clone(),
        labels,
        restart_policy: records.first().and_then(restart_policy),
        host_network: pod.host_network || pod.networks.iter().any(|n| n == "host"),
        created: created(pod.created_ns),
    })
}

/// The documents of the pods, containers and volumes `names`.
pub async fn generate(engine: &Engine, names: &[String], opts: &GenerateOptions) -> Result<String> {
    let GenerateOptions {
        kind,
        replicas,
        service,
        podman_only,
    } = *opts;
    if names.is_empty() {
        return Err(Error::new("no pod, container or volume named"));
    }
    let mut docs = Vec::new();
    let mut containers = Vec::new();
    for name in names {
        if let Some(pod) = engine.pod(name).await? {
            docs.extend(gen::pod_documents(
                &engine_pod(engine, &pod, podman_only).await?,
                kind,
                replicas,
                service,
            )?);
        } else if let Some(c) = engine.container(name).await? {
            containers.push(c);
        } else if let Some(v) = engine.volume(name).await? {
            let mut labels: Vec<(String, String)> = v
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            labels.sort();
            docs.push(gen::volume_document(
                &v.name,
                &labels,
                created(v.created_ns).as_deref(),
            ));
        } else {
            return Err(Error::new(format!(
                "no pod, container or volume named {name}"
            )));
        }
    }
    // the containers that have no pod of their own share one, as podman
    if !containers.is_empty() {
        docs.extend(gen::pod_documents(
            &container_pod(engine, &containers, podman_only).await?,
            kind,
            replicas,
            service,
        )?);
    }
    Ok(gen::to_yaml(&docs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_variables_of_the_user() {
        let env = [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "container=podman",
            "HOSTNAME=abc",
            "IMG=1",
            "K=V",
            "IMG=2",
        ]
        .map(String::from);
        let image = ["IMG=1".to_string()];
        assert_eq!(
            user_env(&env, &image),
            [
                ("K".to_string(), "V".to_string()),
                ("IMG".to_string(), "2".to_string())
            ]
        );
    }
}
