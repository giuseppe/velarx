// SPDX-License-Identifier: Apache-2.0
//! CRI messages to engine requests and back.

use crate::api as cri;
use crate::engine::{IdRange, InfraSecurity, NsMode, PodCreate, Port};
use std::fmt::Write as _;
use velarx_confine_core::cri::{from_cri, Context, Profile};
use velarx_confine_core::Seccomp;
use velarx_proto::modes::{self, CgroupsMode, UsernsChoice};
use velarx_proto::pod::{Pressure, Psi, PsiData};
use velarx_proto::request::{
    BindMountRequest, CreateContainerRequest, DeviceMapping, HugepageLimit as RequestHugepageLimit,
    ImageMountRequest, LogConfig, ResourceLimits,
};
use velarx_proto::workload::{
    ContainerRecord, HugepageLimit, ImageRecord, MetricDescriptor, MetricSample, MountKind,
    PodMetrics, PodRecord, Resources, RunState, StatsRecord,
};
use velarx_registry::auth::RegistryAccess;
type Result<T> = std::result::Result<T, Status>;
use crate::meta;
use std::collections::BTreeMap;
use tonic::Status;

pub fn ts_secs_to_ns(s: i64) -> i64 {
    s.saturating_mul(1_000_000_000)
}

pub fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

pub fn signal_name(s: i32) -> &'static str {
    use cri::Signal as S;
    match S::try_from(s).unwrap_or(S::RuntimeDefault) {
        S::RuntimeDefault => "",
        S::Sigabrt => "SIGABRT",
        S::Sigalrm => "SIGALRM",
        S::Sigbus => "SIGBUS",
        S::Sigchld | S::Sigcld => "SIGCHLD",
        S::Sigcont => "SIGCONT",
        S::Sigfpe => "SIGFPE",
        S::Sighup => "SIGHUP",
        S::Sigill => "SIGILL",
        S::Sigint => "SIGINT",
        S::Sigio | S::Sigpoll => "SIGIO",
        S::Sigiot => "SIGIOT",
        S::Sigkill => "SIGKILL",
        S::Sigpipe => "SIGPIPE",
        S::Sigprof => "SIGPROF",
        S::Sigpwr => "SIGPWR",
        S::Sigquit => "SIGQUIT",
        S::Sigsegv => "SIGSEGV",
        S::Sigstkflt => "SIGSTKFLT",
        S::Sigstop => "SIGSTOP",
        S::Sigsys => "SIGSYS",
        S::Sigterm => "SIGTERM",
        S::Sigtrap => "SIGTRAP",
        S::Sigtstp => "SIGTSTP",
        S::Sigttin => "SIGTTIN",
        S::Sigttou => "SIGTTOU",
        S::Sigurg => "SIGURG",
        S::Sigusr1 => "SIGUSR1",
        S::Sigusr2 => "SIGUSR2",
        S::Sigvtalrm => "SIGVTALRM",
        S::Sigwinch => "SIGWINCH",
        S::Sigxcpu => "SIGXCPU",
        S::Sigxfsz => "SIGXFSZ",
        _ => "",
    }
}

fn unsupported(what: &str) -> Status {
    Status::unimplemented(format!("velarx: {what} is not supported by the engine"))
}

/// The hugepage limits of a container: the kubelet sends one for every
/// size of the node, 0 for those the container does not ask for.  Where the
/// cgroups of the engine have no `hugetlb` controller the zero limits are left
/// out (the container can have no huge pages of its own then either, as with
/// CRI-O) and another limit is refused.
pub fn hugepages_of(r: &mut Resources, hugetlb: bool) -> Result<()> {
    if hugetlb {
        return Ok(());
    }
    if r.hugepage_limits.iter().any(|h| h.limit != 0) {
        return Err(unsupported(
            "hugepage limits without the hugetlb cgroup controller",
        ));
    }
    r.hugepage_limits.clear();
    Ok(())
}

/// The most CPU shares of a cgroup.
const MAX_SHARES: i64 = 262_144;

/// The resources of a sandbox (or its overhead): its `unified` settings are
/// refused but `memory.oom.group`, which the kubelet sends for every sandbox
/// on cgroup v2 (`singleProcessOOMKill` false): the containers get it in their
/// own resources, and the infra container is one process, which a kill of
/// its group is the kill of.
pub fn sandbox_resources_of(r: &cri::LinuxContainerResources, what: &str) -> Result<Resources> {
    let mut resources = resources_of(r)?;
    if resources.hugepage_limits.iter().any(|h| h.limit != 0) {
        return Err(unsupported(&format!("hugepage limits of {what}")));
    }
    resources.hugepage_limits.clear();
    resources.unified.remove("memory.oom.group");
    if !resources.unified.is_empty() {
        let keys: Vec<&str> = resources.unified.keys().map(String::as_str).collect();
        return Err(unsupported(&format!(
            "unified cgroup settings of {what} ({})",
            keys.join(", ")
        )));
    }
    Ok(resources)
}

pub fn resources_of(r: &cri::LinuxContainerResources) -> Result<Resources> {
    Ok(Resources {
        memory_limit: r.memory_limit_in_bytes,
        memory_swap: r.memory_swap_limit_in_bytes,
        cpu_period: r.cpu_period,
        cpu_quota: r.cpu_quota,
        cpu_shares: r.cpu_shares,
        cpuset_cpus: r.cpuset_cpus.clone(),
        cpuset_mems: r.cpuset_mems.clone(),
        oom_score_adj: r.oom_score_adj,
        unified: r
            .unified
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        hugepage_limits: r
            .hugepage_limits
            .iter()
            .map(|h| HugepageLimit {
                page_size: h.page_size.clone(),
                limit: h.limit,
            })
            .collect(),
    })
}

/// The limits of the cgroup of a pod: the resources of the sandbox (the sum
/// of those of its containers) plus the overhead of the pod (a runtime class
/// adds it), the overhead added to each limit that is set: a sandbox with no
/// limit of a kind has none of it for the pod.  Both are the CRI's fields,
/// zero when not set.
pub fn sandbox_limits(resources: &Resources, overhead: &Resources) -> Resources {
    let sum = |r: i64, o: i64| if r > 0 { r.saturating_add(o.max(0)) } else { r };
    // (the swap limit counts the memory too: the memory of the overhead is in it)
    let swap_overhead = overhead.memory_swap.max(overhead.memory_limit);
    // (the overhead's quota is of its own period)
    let quota = match (resources.cpu_quota, overhead.cpu_quota) {
        (r, o) if r > 0 && o > 0 && overhead.cpu_period > 0 && resources.cpu_period > 0 => {
            r.saturating_add(o.saturating_mul(resources.cpu_period) / overhead.cpu_period)
        }
        (r, o) => sum(r, o),
    };
    Resources {
        memory_limit: sum(resources.memory_limit, overhead.memory_limit),
        memory_swap: sum(resources.memory_swap, swap_overhead),
        cpu_shares: sum(resources.cpu_shares, overhead.cpu_shares).min(MAX_SHARES),
        cpu_quota: quota,
        cpu_period: if resources.cpu_period > 0 {
            resources.cpu_period
        } else {
            overhead.cpu_period
        },
        cpuset_cpus: resources.cpuset_cpus.clone(),
        cpuset_mems: resources.cpuset_mems.clone(),
        ..Default::default()
    }
}

/// What a pod is made with, its metadata, and the resources of the sandbox
/// with its overhead (the limits of the cgroup of the pod, `resources` of
/// the [`PodCreate`]).
pub fn pod_create_of(
    cfg: &cri::PodSandboxConfig,
    handler: &str,
) -> Result<(PodCreate, meta::SandboxMeta)> {
    let mut resources = Resources::default();
    if cfg.windows.is_some() {
        return Err(unsupported("the windows config of a pod"));
    }
    let none = cri::PodSandboxMetadata::default();
    let md = cfg.metadata.as_ref().unwrap_or(&none);
    let sm = meta::SandboxMeta {
        name: md.name.clone(),
        uid: md.uid.clone(),
        namespace: md.namespace.clone(),
        attempt: md.attempt,
        annotations: cfg
            .annotations
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        log_directory: cfg.log_directory.clone(),
        runtime_handler: handler.to_string(),
    };
    let user: BTreeMap<_, _> = cfg
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut p = PodCreate {
        name: meta::engine_name(&[&md.name, &md.namespace, &md.uid, &md.attempt.to_string()]),
        hostname: cfg.hostname.clone(),
        labels: meta::encode("sandbox", &sm, &user)?,
        runtime: handler.to_string(),
        ..Default::default()
    };
    if let Some(d) = &cfg.dns_config {
        p.dns_servers = d.servers.clone();
        p.dns_searches = d.searches.clone();
        p.dns_options = d.options.clone();
    }
    for m in &cfg.port_mappings {
        let protocol = match cri::Protocol::try_from(m.protocol).unwrap_or(cri::Protocol::Tcp) {
            cri::Protocol::Tcp => "tcp",
            cri::Protocol::Udp => "udp",
            cri::Protocol::Sctp => return Err(unsupported("SCTP port mappings")),
        };
        if m.host_port <= 0 {
            continue;
        }
        p.ports.push(Port {
            host_ip: m.host_ip.clone(),
            host_port: u16::try_from(m.host_port)
                .map_err(|_| Status::invalid_argument("host port"))?,
            container_port: u16::try_from(m.container_port)
                .map_err(|_| Status::invalid_argument("container port"))?,
            protocol: protocol.into(),
        });
    }
    if let Some(l) = &cfg.linux {
        p.cgroup_parent = l.cgroup_parent.clone();
        p.sysctls = l
            .sysctls
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if let Some(r) = &l.resources {
            resources = sandbox_resources_of(r, "a pod")?;
        }
        let overhead = match &l.overhead {
            Some(o) => sandbox_resources_of(o, "the overhead of a pod")?,
            None => Resources::default(),
        };
        p.resources = sandbox_limits(&resources, &overhead);
        p.infra = infra_security_of(l.security_context.as_ref(), resources.oom_score_adj)?;
        if let Some(sc) = &l.security_context {
            if let Some(ns) = &sc.namespace_options {
                if ns.network == cri::NamespaceMode::Node as i32 {
                    p.net = NsMode::Host;
                }
                p.host_ipc = ns.ipc == cri::NamespaceMode::Node as i32;
                p.host_pid = ns.pid == cri::NamespaceMode::Node as i32;
                p.share_pid = ns.pid == cri::NamespaceMode::Pod as i32;
                if let Some(u) = &ns.userns_options {
                    if u.mode != cri::NamespaceMode::Pod as i32
                        && u.mode != cri::NamespaceMode::Node as i32
                    {
                        return Err(Status::invalid_argument(
                            "the user namespace mode must be POD or NODE",
                        ));
                    }
                    if u.mode == cri::NamespaceMode::Pod as i32 {
                        if u.uids.is_empty() && u.gids.is_empty() {
                            p.userns_auto = true;
                        } else {
                            let m = |v: &[cri::IdMapping]| {
                                v.iter()
                                    .map(|i| IdRange {
                                        container_id: i.container_id,
                                        host_id: i.host_id,
                                        size: i.length,
                                    })
                                    .collect()
                            };
                            p.uid_map = m(&u.uids);
                            p.gid_map = m(&u.gids);
                        }
                    }
                }
            }
        }
    }
    // a pod on the host's network publishes nothing: its ports are the host's
    // (the kubelet sends the hostPort that the API server defaults to the
    // containerPort of such a pod; containerd and CRI-O ignore them)
    if p.net == NsMode::Host {
        p.ports.clear();
    }
    if p.hostname.is_empty() {
        p.hostname = hostname_of(&md.name);
    }
    Ok((p, sm))
}

/// The hostname of a pod that has none in its config: its name, as a label
/// of at most 63 characters of a hostname.
fn hostname_of(name: &str) -> String {
    let h: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .take(63)
        .collect();
    h.trim_matches('-').to_string()
}

/// The seccomp profile a security context asks for (`Absent` when it names
/// none) and the file of a `Localhost` one: the `seccomp` message, else the
/// deprecated path.
fn seccomp_of(profile: Option<&cri::SecurityProfile>, deprecated_path: &str) -> (Profile, String) {
    use cri::security_profile::ProfileType;
    if let Some(p) = profile {
        return match ProfileType::try_from(p.profile_type).unwrap_or_default() {
            ProfileType::RuntimeDefault => (Profile::RuntimeDefault, String::new()),
            ProfileType::Unconfined => (Profile::Unconfined, String::new()),
            ProfileType::Localhost => (Profile::Localhost, p.localhost_ref.clone()),
        };
    }
    match deprecated_path {
        "" => (Profile::Absent, String::new()),
        "unconfined" => (Profile::Unconfined, String::new()),
        "runtime/default" | "docker/default" => (Profile::RuntimeDefault, String::new()),
        p => (
            Profile::Localhost,
            p.trim_start_matches("localhost/").to_string(),
        ),
    }
}

/// The AppArmor profile of a security context as the engine names it: empty
/// for the default, `unconfined`, or the name of a profile.  `deprecated` is
/// the string field (`runtime/default`, `unconfined`, `localhost/NAME`),
/// which only counts when the message is absent.
fn apparmor_of(profile: Option<&cri::SecurityProfile>, deprecated: &str) -> Result<String> {
    use cri::security_profile::ProfileType;
    if let Some(p) = profile {
        return Ok(
            match ProfileType::try_from(p.profile_type).unwrap_or_default() {
                ProfileType::RuntimeDefault => String::new(),
                ProfileType::Unconfined => "unconfined".into(),
                ProfileType::Localhost => p.localhost_ref.clone(),
            },
        );
    }
    match deprecated {
        "" | "runtime/default" => Ok(String::new()),
        "unconfined" => Ok("unconfined".into()),
        p => match p.strip_prefix("localhost/") {
            Some(n) => Ok(n.to_string()),
            None => Err(Status::invalid_argument(format!(
                "invalid apparmor_profile {p:?}"
            ))),
        },
    }
}

/// The infra container of a sandbox: its security context and OOM score.
/// What the engine cannot give is refused.
#[allow(
    deprecated,
    reason = "the kubelets before the typed security profiles send the deprecated apparmor_profile and seccomp_profile_path, which are read when the typed ones are not set"
)]
fn infra_security_of(
    sc: Option<&cri::LinuxSandboxSecurityContext>,
    oom_score_adj: i64,
) -> Result<InfraSecurity> {
    let mut i = InfraSecurity::default();
    if oom_score_adj != 0 {
        i.oom_score_adj = Some(
            i32::try_from(oom_score_adj)
                .map_err(|_| Status::invalid_argument("oom_score_adj is out of range"))?,
        );
    }
    let Some(sc) = sc else {
        return Ok(i);
    };
    i.run_as_user = sc
        .run_as_user
        .as_ref()
        .map(|v| id_of(v.value, "run_as_user"))
        .transpose()?;
    i.run_as_group = sc
        .run_as_group
        .as_ref()
        .map(|v| id_of(v.value, "run_as_group"))
        .transpose()?;
    // (the `Strict` supplemental groups policy is the infra container's
    // anyway: its image, catatonit alone, has no /etc/group to add groups)
    i.supplemental_groups = sc
        .supplemental_groups
        .iter()
        .map(|g| id_of(*g, "supplemental group"))
        .collect::<Result<_>>()?;
    i.read_only_rootfs = sc.readonly_rootfs;
    i.privileged = sc.privileged;
    if let Some(s) = &sc.selinux_options {
        i.security_opts
            .extend(selinux_opts(s).into_iter().map(|o| format!("label={o}")));
    }
    if sc.privileged {
        i.security_opts.push("label=files".into());
    }
    match seccomp_of(sc.seccomp.as_ref(), &sc.seccomp_profile_path) {
        _ if sc.privileged => i.security_opts.push("seccomp=unconfined".into()),
        (Profile::Unconfined, _) => i.security_opts.push("seccomp=unconfined".into()),
        (Profile::Localhost, path) => i.security_opts.push(format!("seccomp={path}")),
        (Profile::RuntimeDefault | Profile::Absent, _) => {}
    }
    match apparmor_of(sc.apparmor.as_ref(), "")?.as_str() {
        "" => {}
        a => i.security_opts.push(format!("apparmor={a}")),
    }
    Ok(i)
}

pub fn selinux_opts(s: &cri::SeLinuxOption) -> Vec<String> {
    let mut v = Vec::new();
    for (k, x) in [
        ("user", &s.user),
        ("role", &s.role),
        ("type", &s.r#type),
        ("level", &s.level),
    ] {
        if !x.is_empty() {
            v.push(format!("{k}:{x}"));
        }
    }
    v
}

/// An id of the kubelet: it must be one of the engine's, never a number that
/// the engine would look up as a name (`-1`).
fn id_of(v: i64, what: &str) -> Result<u32> {
    u32::try_from(v).map_err(|_| Status::invalid_argument(format!("invalid {what}")))
}

/// The user a container runs as, from its security context: `UID[:GID]`, a
/// name, or empty (the image's).
pub fn user_of(cfg: &cri::ContainerConfig) -> Result<String> {
    let Some(sc) = cfg.linux.as_ref().and_then(|l| l.security_context.as_ref()) else {
        return Ok(String::new());
    };
    if sc.run_as_group.is_some() && sc.run_as_user.is_none() && sc.run_as_username.is_empty() {
        return Err(Status::invalid_argument(
            "run_as_group is set without run_as_user",
        ));
    }
    let uid = sc
        .run_as_user
        .as_ref()
        .map(|v| id_of(v.value, "run_as_user"))
        .transpose()?;
    let gid = sc
        .run_as_group
        .as_ref()
        .map(|v| id_of(v.value, "run_as_group"))
        .transpose()?;
    Ok(match (uid, gid, sc.run_as_username.as_str()) {
        (Some(u), Some(g), _) => format!("{u}:{g}"),
        (Some(u), None, _) => u.to_string(),
        (None, Some(g), "") => format!("0:{g}"),
        (None, Some(g), n) => format!("{n}:{g}"),
        (None, None, n) => n.to_string(),
    })
}

/// The fingerprint of the environment of a container as the kubelet gave
/// it: the values may be secrets, and the metadata is a label of the
/// engine's container (its events carry the labels) and part of pod.json.
pub fn env_digest(cfg: &cri::ContainerConfig) -> String {
    use sha2::{Digest, Sha256};
    let mut envs: Vec<_> = cfg.envs.iter().map(|kv| (&kv.key, &kv.value)).collect();
    envs.sort();
    let mut h = Sha256::new();
    for (k, v) in envs {
        for part in [k.as_bytes(), v.as_slice()] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part);
        }
    }
    let mut out = String::from("sha256:");
    for byte in h.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The engine's creation record of a container of the CRI, and the
/// metadata the CRI keeps of it.  `hugetlb`: the cgroups of the engine have
/// the controller of the huge pages ([`hugepages_of`]).
#[allow(
    deprecated,
    reason = "the kubelets before the typed security profiles send the deprecated apparmor_profile and seccomp_profile_path, which are read when the typed ones are not set"
)]
pub fn container_create_of(
    pod_id: &str,
    cfg: &cri::ContainerConfig,
    log_directory: &str,
    pod_name: &str,
    sandbox: &meta::SandboxMeta,
    hugetlb: bool,
) -> Result<(CreateContainerRequest, meta::ContainerMeta)> {
    if cfg.windows.is_some() {
        return Err(unsupported("the windows config of a container"));
    }
    let (no_metadata, no_image) = (cri::ContainerMetadata::default(), cri::ImageSpec::default());
    let md = cfg.metadata.as_ref().unwrap_or(&no_metadata);
    let image = cfg.image.as_ref().unwrap_or(&no_image);
    let image_name = if !image.image.is_empty() {
        image.image.clone()
    } else {
        image.image_ref.clone()
    };
    if image_name.is_empty() {
        return Err(Status::invalid_argument("the container has no image"));
    }
    let log_path = if cfg.log_path.is_empty() {
        String::new()
    } else {
        std::path::Path::new(log_directory)
            .join(&cfg.log_path)
            .to_string_lossy()
            .into_owned()
    };
    let cm = meta::ContainerMeta {
        name: md.name.clone(),
        attempt: md.attempt,
        annotations: cfg
            .annotations
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        log_path: log_path.clone(),
        image: if image.user_specified_image.is_empty() {
            image_name.clone()
        } else {
            image.user_specified_image.clone()
        },
        stop_signal: cfg.stop_signal,
        command: cfg.command.clone(),
        args: cfg.args.clone(),
        working_dir: cfg.working_dir.clone(),
        env_digest: env_digest(cfg),
        user: user_of(cfg)?,
        stdin_once: cfg.stdin && cfg.stdin_once,
    };
    let user_labels: BTreeMap<_, _> = cfg
        .labels
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    // (the engine's creation record, as the command line fills it: the
    // mounts and devices in its words, `-v` and `--mount`)
    let env: BTreeMap<_, _> = cfg
        .envs
        .iter()
        .map(|kv| {
            (
                kv.key.clone(),
                String::from_utf8_lossy(&kv.value).into_owned(),
            )
        })
        .collect();
    let mut c = CreateContainerRequest {
        name: Some(meta::engine_name(&[
            &md.name,
            pod_name,
            &sandbox.namespace,
            &sandbox.uid,
            &md.attempt.to_string(),
        ])),
        image: image_name,
        pod: Some(pod_id.to_string()),
        entrypoint: cfg.command.clone(),
        command: cfg.args.clone(),
        working_dir: cfg.working_dir.clone(),
        env: env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        labels: meta::encode("container", &cm, &user_labels)?,
        annotations: cm
            .annotations
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        tty: cfg.tty,
        stdin_open: cfg.stdin,
        stop_signal: signal_name(cfg.stop_signal).to_string(),
        // (the kubelet manages the cgroups of a pod: `[containers] cgroups`
        // of the configuration is not the CRI's)
        cgroups: CgroupsMode::Enabled,
        // (nor `[containers] pids_limit`: the kubelet limits the pids of a
        // pod, containerd and CRI-O give a container none)
        pids_limit: Some(-1),
        // (a pod with a user namespace gives its members its own)
        userns_mode: UsernsChoice::Host,
        devices: cfg
            .cdi_devices
            .iter()
            .map(|d| DeviceMapping::cdi(&d.name))
            .collect(),
        ..Default::default()
    };
    if !log_path.is_empty() {
        c.log_config = Some(LogConfig {
            driver: "k8s-file".into(),
            config: [("path".to_string(), log_path)].into_iter().collect(),
        });
    }
    for m in &cfg.mounts {
        if let Some(image) = &m.image {
            if !m.host_path.is_empty() {
                return Err(Status::invalid_argument(
                    "a mount of an image has no host path",
                ));
            }
            if !m.readonly {
                return Err(Status::invalid_argument(
                    "a mount of an image is read-only: readonly must be set",
                ));
            }
            c.image_mounts.push(ImageMountRequest {
                image: image.image.clone(),
                target: m.container_path.clone(),
                subpath: Some(m.image_sub_path.clone()).filter(|p| !p.is_empty()),
            });
            continue;
        }
        let mut options: Vec<String> = vec![if m.readonly { "ro" } else { "rw" }.into()];
        if m.recursive_read_only {
            if !m.readonly {
                return Err(Status::invalid_argument(
                    "a recursive read-only mount is read-only: readonly must be set",
                ));
            }
            if m.propagation != cri::MountPropagation::PropagationPrivate as i32 {
                return Err(Status::invalid_argument(
                    "a recursive read-only mount has the propagation PROPAGATION_PRIVATE",
                ));
            }
            options.push("rro".into());
        }
        if m.selinux_relabel {
            options.push("z".into());
        }
        match cri::MountPropagation::try_from(m.propagation).unwrap_or_default() {
            cri::MountPropagation::PropagationPrivate => {}
            cri::MountPropagation::PropagationHostToContainer => options.push("rslave".into()),
            cri::MountPropagation::PropagationBidirectional => options.push("rshared".into()),
        }
        options.extend(m.mount_options.iter().cloned());
        if !m.uid_mappings.is_empty() || !m.gid_mappings.is_empty() {
            options.push(idmap_option(&m.uid_mappings, &m.gid_mappings)?);
        }
        c.bind_mounts.push(BindMountRequest {
            source: m.host_path.clone(),
            target: m.container_path.clone(),
            options,
        });
    }
    for d in &cfg.devices {
        c.devices.push(DeviceMapping {
            path_on_host: d.host_path.clone(),
            path_in_container: d.container_path.clone(),
            cgroup_permissions: if d.permissions.is_empty() {
                "rwm".into()
            } else {
                d.permissions.clone()
            },
        });
    }
    // a container with no security context: the engine's defaults
    let mut context = Context {
        present: false,
        privileged: false,
        seccomp: Profile::Absent,
    };
    let mut localhost = String::new();
    let mut masked = Vec::new();
    let mut readonly = Vec::new();
    if let Some(l) = &cfg.linux {
        if let Some(r) = &l.resources {
            let mut r = resources_of(r)?;
            hugepages_of(&mut r, hugetlb)?;
            c.oom_score_adj = (r.oom_score_adj != 0).then_some(r.oom_score_adj as i32);
            c.resources = limits_of(&r);
        }
        if let Some(sc) = &l.security_context {
            c.privileged = sc.privileged;
            c.read_only_rootfs = sc.readonly_rootfs;
            c.security_opt.no_new_privileges = sc.no_new_privs;
            // exactly the lists given, empty ones too (as containerd and
            // CRI-O)
            masked = sc.masked_paths.clone();
            readonly = sc.readonly_paths.clone();
            if let Some(cap) = &sc.capabilities {
                c.cap_ambient = cap.add_ambient_capabilities.clone();
                c.cap_add = cap.add_capabilities.clone();
                c.cap_drop = cap.drop_capabilities.clone();
                // dropping ALL wins over adding ALL, as in CRI-O (the engine
                // refuses both); what is added by name stays
                if c.cap_drop.iter().any(|n| n.eq_ignore_ascii_case("all")) {
                    c.cap_add.retain(|n| !n.eq_ignore_ascii_case("all"));
                }
            }
            c.user = user_of(cfg)?;
            c.groups_strict =
                cri::SupplementalGroupsPolicy::try_from(sc.supplemental_groups_policy)
                    == Ok(cri::SupplementalGroupsPolicy::Strict);
            c.group_add = sc
                .supplemental_groups
                .iter()
                .map(|g| id_of(*g, "supplemental group").map(|g| g.to_string()))
                .collect::<Result<_>>()?;
            let mut selinux = sc
                .selinux_options
                .as_ref()
                .map(selinux_opts)
                .unwrap_or_default();
            if sc.privileged {
                // the files of a privileged container have the label of the
                // others (the engine's default is none), its process `spc_t`
                selinux.push("files".into());
            }
            c.security_opts = selinux.iter().map(|o| format!("label={o}")).collect();
            let (seccomp, path) = seccomp_of(sc.seccomp.as_ref(), &sc.seccomp_profile_path);
            context = Context {
                present: true,
                privileged: sc.privileged,
                seccomp,
            };
            localhost = path;
            match apparmor_of(sc.apparmor.as_ref(), &sc.apparmor_profile)?.as_str() {
                "" => {}
                "unconfined" => c.security_opt.apparmor_unconfined = true,
                p => c.security_opt.apparmor_profile = Some(p.to_string()),
            }
            if let Some(ns) = &sc.namespace_options {
                if ns.pid == cri::NamespaceMode::Node as i32 {
                    c.pid_mode = modes::NsMode::Host;
                } else if ns.pid == cri::NamespaceMode::Target as i32 {
                    // (read as `--pid container:ID`: a target with no
                    // container is refused here, not by the engine's wire)
                    c.pid_mode = modes::NsMode::parse(&format!("container:{}", ns.target_id))
                        .map_err(|e| Status::invalid_argument(format!("namespace target: {e}")))?;
                }
            }
        }
    }
    let ask = from_cri(&context);
    match ask.seccomp {
        Seccomp::Unconfined => c.security_opt.seccomp_unconfined = true,
        Seccomp::Custom => c.security_opt.seccomp_profile = Some(localhost),
        Seccomp::Default => {}
    }
    // the CRI's lists go to the OCI spec as they are, empty ones too (an
    // unmasked /proc): they replace the defaults of the engine
    if ask.own_paths {
        c.security_opt.unmask_paths = vec!["ALL".into()];
        c.security_opt.mask_paths = masked;
        c.security_opt.readonly_paths = readonly;
    }
    Ok((c, cm))
}

/// The limits of the engine's request of the CRI's resources: those set.
fn limits_of(r: &Resources) -> Option<ResourceLimits> {
    let set = |v: i64| (v > 0).then_some(v);
    let l = ResourceLimits {
        memory: set(r.memory_limit),
        memory_swap: set(r.memory_swap),
        cpu_quota: (r.cpu_quota != 0).then_some(r.cpu_quota),
        cpu_period: set(r.cpu_period).map(|v| v as u64),
        cpu_shares: set(r.cpu_shares).map(|v| v as u64),
        cpuset_cpus: Some(r.cpuset_cpus.clone()).filter(|s| !s.is_empty()),
        cpuset_mems: Some(r.cpuset_mems.clone()).filter(|s| !s.is_empty()),
        hugepage_limits: r
            .hugepage_limits
            .iter()
            .map(|h| RequestHugepageLimit {
                page_size: h.page_size.clone(),
                limit: h.limit,
            })
            .collect(),
        cgroup_conf: Some(r.unified.clone()).filter(|u| !u.is_empty()),
        ..Default::default()
    };
    let any = l.memory.is_some()
        || l.memory_swap.is_some()
        || l.cpu_quota.is_some()
        || l.cpu_period.is_some()
        || l.cpu_shares.is_some()
        || l.cpuset_cpus.is_some()
        || l.cpuset_mems.is_some()
        || !l.hugepage_limits.is_empty()
        || l.cgroup_conf.is_some();
    any.then_some(l)
}

/// The engine's `idmap` option of an ID-mapped mount: the mappings of its
/// ids (`CONTAINER-HOST-SIZE` ranges, as the OCI mount has them).
fn idmap_option(uids: &[cri::IdMapping], gids: &[cri::IdMapping]) -> Result<String> {
    if uids.is_empty() || gids.is_empty() {
        return Err(Status::invalid_argument(
            "an ID-mapped mount needs both uid and gid mappings",
        ));
    }
    let ranges = |v: &[cri::IdMapping]| -> Result<String> {
        v.iter()
            .map(|i| {
                if i.length == 0 {
                    return Err(Status::invalid_argument(
                        "an ID mapping of a mount has a length of 0",
                    ));
                }
                Ok(format!("{}-{}-{}", i.container_id, i.host_id, i.length))
            })
            .collect::<Result<Vec<_>>>()
            .map(|r| r.join("#"))
    };
    Ok(format!(
        "idmap=uids={};gids={}",
        ranges(uids)?,
        ranges(gids)?
    ))
}

/// Where a container is in the CRI's life: made in the runtime is not
/// started yet, stopping still runs, and one that ended without starting
/// was never more than created.
pub fn run_state(c: &ContainerRecord) -> RunState {
    match c.state {
        RunState::Initialized => RunState::Created,
        RunState::Stopping => RunState::Running,
        RunState::Exited if c.started_ns == 0 => RunState::Created,
        s => s,
    }
}

pub fn container_state(c: &ContainerRecord) -> cri::ContainerState {
    match run_state(c) {
        RunState::Created | RunState::Initialized => cri::ContainerState::ContainerCreated,
        RunState::Running | RunState::Paused | RunState::Stopping => {
            cri::ContainerState::ContainerRunning
        }
        RunState::Exited => cri::ContainerState::ContainerExited,
        RunState::Unknown => cri::ContainerState::ContainerUnknown,
    }
}

fn image_spec(name: &str) -> Option<cri::ImageSpec> {
    Some(cri::ImageSpec {
        image: name.to_string(),
        user_specified_image: name.to_string(),
        ..Default::default()
    })
}

pub fn container_of(c: &ContainerRecord) -> Result<cri::Container> {
    let (cm, labels): (meta::ContainerMeta, _) = meta::decode(&c.labels)?;
    Ok(cri::Container {
        id: c.id.clone(),
        pod_sandbox_id: c.pod_id.clone(),
        metadata: Some(cri::ContainerMetadata {
            name: cm.name.clone(),
            attempt: cm.attempt,
        }),
        image: image_spec(if cm.image.is_empty() {
            &c.image
        } else {
            &cm.image
        }),
        image_ref: c.image_id.clone(),
        state: container_state(c) as i32,
        created_at: c.created_ns,
        labels: labels.into_iter().collect(),
        annotations: cm.annotations.into_iter().collect(),
        image_id: c.image_id.clone(),
    })
}

pub fn container_status_of(c: &ContainerRecord) -> Result<cri::ContainerStatus> {
    let (cm, labels): (meta::ContainerMeta, _) = meta::decode(&c.labels)?;
    let (reason, message) = match run_state(c) {
        RunState::Exited if c.oom_killed => ("OOMKilled", c.error.clone()),
        RunState::Exited if c.exit_code == 0 => ("Completed", c.error.clone()),
        RunState::Exited => ("Error", c.error.clone()),
        _ => ("", c.error.clone()),
    };
    Ok(cri::ContainerStatus {
        id: c.id.clone(),
        metadata: Some(cri::ContainerMetadata {
            name: cm.name.clone(),
            attempt: cm.attempt,
        }),
        state: container_state(c) as i32,
        created_at: c.created_ns,
        started_at: c.started_ns,
        finished_at: c.finished_ns,
        exit_code: c.exit_code,
        image: image_spec(if cm.image.is_empty() {
            &c.image
        } else {
            &cm.image
        }),
        image_ref: c.image_id.clone(),
        reason: reason.into(),
        message,
        labels: labels.into_iter().collect(),
        annotations: cm.annotations.into_iter().collect(),
        mounts: c
            .mounts
            .iter()
            .map(|m| {
                if m.kind != MountKind::Image {
                    cri::Mount {
                        container_path: m.destination.clone(),
                        host_path: m.source.clone(),
                        readonly: m.read_only,
                        propagation: match m.propagation.as_str() {
                            "rshared" | "shared" => cri::MountPropagation::PropagationBidirectional,
                            "rslave" | "slave" => cri::MountPropagation::PropagationHostToContainer,
                            _ => cri::MountPropagation::PropagationPrivate,
                        } as i32,
                        ..Default::default()
                    }
                } else {
                    // an image mounted: the image by its ID, no host path
                    cri::Mount {
                        container_path: m.destination.clone(),
                        readonly: true,
                        image: Some(cri::ImageSpec {
                            image: m.source.clone(),
                            image_ref: m.source.clone(),
                            ..Default::default()
                        }),
                        image_sub_path: m.sub_path.clone(),
                        ..Default::default()
                    }
                }
            })
            .collect(),
        log_path: cm.log_path,
        resources: Some(cri::ContainerResources {
            linux: Some(cri::LinuxContainerResources {
                cpu_period: c.resources.cpu_period,
                cpu_quota: c.resources.cpu_quota,
                cpu_shares: c.resources.cpu_shares,
                memory_limit_in_bytes: c.resources.memory_limit,
                ..Default::default()
            }),
            windows: None,
        }),
        image_id: c.image_id.clone(),
        user: None,
        stop_signal: cm.stop_signal,
    })
}

/// The user the first process of a container runs as, from the record of
/// the engine: its uid, gid and supplemental groups (none: the container
/// has no user yet).
pub fn container_user_of(
    user: Option<&velarx_proto::workload::ProcessUser>,
) -> Option<cri::ContainerUser> {
    let u = user?;
    Some(cri::ContainerUser {
        linux: Some(cri::LinuxContainerUser {
            uid: u.uid,
            gid: u.gid,
            supplemental_groups: u.additional_gids.clone(),
        }),
    })
}

pub fn sandbox_state(running: bool) -> cri::PodSandboxState {
    if running {
        cri::PodSandboxState::SandboxReady
    } else {
        cri::PodSandboxState::SandboxNotready
    }
}

/// The subnets of a pod CIDR of the kubelet: `ADDRESS/PREFIX`, two separated
/// by a comma for a dual-stack node (one of each family); empty: none.
pub fn pod_cidr_ranges(cidr: &str) -> Result<Vec<String>> {
    if cidr.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<(bool, String)> = Vec::new();
    for part in cidr.split(',').map(str::trim) {
        let bad = || Status::invalid_argument(format!("pod CIDR {part:?} is not ADDRESS/PREFIX"));
        let (addr, len) = part.split_once('/').ok_or_else(bad)?;
        let addr: std::net::IpAddr = addr.parse().map_err(|_| bad())?;
        let len: u8 = len.parse().map_err(|_| bad())?;
        if len > if addr.is_ipv4() { 32 } else { 128 } {
            return Err(bad());
        }
        if out.iter().any(|(v4, _)| *v4 == addr.is_ipv4()) {
            return Err(Status::invalid_argument(format!(
                "pod CIDR {cidr:?} has two subnets of one address family"
            )));
        }
        out.push((addr.is_ipv4(), part.to_string()));
    }
    Ok(out.into_iter().map(|(_, s)| s).collect())
}

pub fn sandbox_of(p: &PodRecord) -> Result<cri::PodSandbox> {
    let (sm, labels): (meta::SandboxMeta, _) = meta::decode(&p.spec.labels)?;
    Ok(cri::PodSandbox {
        id: p.id.clone(),
        metadata: Some(cri::PodSandboxMetadata {
            name: sm.name,
            uid: sm.uid,
            namespace: sm.namespace,
            attempt: sm.attempt,
        }),
        state: sandbox_state(p.status.is_running()) as i32,
        created_at: p.created_ns,
        labels: labels.into_iter().collect(),
        annotations: sm.annotations.into_iter().collect(),
        runtime_handler: sm.runtime_handler,
    })
}

pub fn sandbox_status_of(p: &PodRecord) -> Result<cri::PodSandboxStatus> {
    let s = sandbox_of(p)?;
    let mode = |host: bool, pod: bool| {
        (if host {
            cri::NamespaceMode::Node
        } else if pod {
            cri::NamespaceMode::Pod
        } else {
            cri::NamespaceMode::Container
        }) as i32
    };
    Ok(cri::PodSandboxStatus {
        id: s.id,
        metadata: s.metadata,
        state: s.state,
        created_at: s.created_at,
        network: Some(cri::PodSandboxNetworkStatus {
            ip: p.ips.first().cloned().unwrap_or_default(),
            additional_ips: p
                .ips
                .iter()
                .skip(1)
                .map(|ip| cri::PodIp { ip: ip.clone() })
                .collect(),
        }),
        linux: Some(cri::LinuxPodSandboxStatus {
            namespaces: Some(cri::Namespace {
                options: Some(cri::NamespaceOption {
                    network: mode(p.host_network, true),
                    pid: mode(p.host_pid, p.spec.share_pid),
                    ipc: mode(p.host_ipc, true),
                    ..Default::default()
                }),
            }),
        }),
        labels: s.labels,
        annotations: s.annotations,
        runtime_handler: s.runtime_handler,
    })
}

pub fn u64v(v: u64) -> Option<cri::UInt64Value> {
    Some(cri::UInt64Value { value: v })
}

pub fn container_stats_of(
    c: &ContainerRecord,
    s: &StatsRecord,
    ts: i64,
    mountpoint: &str,
) -> Result<cri::ContainerStats> {
    let (cm, labels): (meta::ContainerMeta, _) = meta::decode(&c.labels)?;
    Ok(cri::ContainerStats {
        attributes: Some(cri::ContainerAttributes {
            id: c.id.clone(),
            metadata: Some(cri::ContainerMetadata {
                name: cm.name,
                attempt: cm.attempt,
            }),
            labels: labels.into_iter().collect(),
            annotations: cm.annotations.into_iter().collect(),
        }),
        cpu: Some(cri::CpuUsage {
            timestamp: ts,
            usage_core_nano_seconds: u64v(s.cpu_nano),
            usage_nano_cores: u64v((s.cpu_percent / 100.0 * 1e9).max(0.0) as u64),
            psi: psi_of(s.pressure.cpu.as_ref()),
        }),
        memory: Some(cri::MemoryUsage {
            timestamp: ts,
            working_set_bytes: u64v(s.mem_working_set),
            available_bytes: u64v(s.mem_limit.saturating_sub(s.mem_working_set)),
            usage_bytes: u64v(s.mem_usage),
            rss_bytes: u64v(s.mem_anon),
            page_faults: u64v(s.page_faults),
            major_page_faults: u64v(s.major_page_faults),
            psi: psi_of(s.pressure.memory.as_ref()),
        }),
        writable_layer: Some(cri::FilesystemUsage {
            timestamp: ts,
            fs_id: Some(cri::FilesystemIdentifier {
                mountpoint: mountpoint.to_string(),
            }),
            used_bytes: u64v(s.rw_bytes.unwrap_or(0)),
            inodes_used: u64v(s.rw_inodes.unwrap_or(0)),
        }),
        swap: Some(swap_usage_of(s.mem_swap, s.swap_limit, ts)),
        io: io_usage_of(&s.pressure, ts),
    })
}

/// The pressure of a resource as the CRI has it (its total in nanoseconds).
pub fn psi_of(p: Option<&Psi>) -> Option<cri::PsiStats> {
    let data = |d: &PsiData| cri::PsiData {
        total: d.total_us.saturating_mul(1000),
        avg10: d.avg10,
        avg60: d.avg60,
        avg300: d.avg300,
    };
    p.map(|p| cri::PsiStats {
        full: Some(data(&p.full)),
        some: Some(data(&p.some)),
    })
}

/// The IO of a cgroup: the CRI has its pressure only.
pub fn io_usage_of(p: &Pressure, ts: i64) -> Option<cri::IoUsage> {
    p.io.as_ref().map(|io| cri::IoUsage {
        timestamp: ts,
        psi: psi_of(Some(io)),
    })
}

/// The swap a cgroup uses, and what it has left below its limit (no
/// available bytes without a limit).
pub fn swap_usage_of(usage: u64, limit: u64, ts: i64) -> cri::SwapUsage {
    cri::SwapUsage {
        timestamp: ts,
        swap_available_bytes: (limit > 0).then(|| cri::UInt64Value {
            value: limit.saturating_sub(usage),
        }),
        swap_usage_bytes: u64v(usage),
    }
}

pub fn metric_descriptor_of(d: &MetricDescriptor) -> cri::MetricDescriptor {
    cri::MetricDescriptor {
        name: d.name.clone(),
        help: d.help.clone(),
        label_keys: d.labels.clone(),
    }
}

fn metric_of(m: &MetricSample, counters: &[MetricDescriptor], ts: i64) -> cri::Metric {
    let counter = counters.iter().any(|d| d.name == m.name && d.counter);
    cri::Metric {
        name: m.name.clone(),
        timestamp: ts,
        metric_type: if counter {
            cri::MetricType::Counter
        } else {
            cri::MetricType::Gauge
        } as i32,
        label_values: m.labels.clone(),
        value: u64v(m.value.max(0.0) as u64),
    }
}

pub fn pod_metrics_of(p: &PodMetrics, descriptors: &[MetricDescriptor]) -> cri::PodSandboxMetrics {
    cri::PodSandboxMetrics {
        pod_sandbox_id: p.id.clone(),
        metrics: p
            .samples
            .iter()
            .map(|m| metric_of(m, descriptors, p.time_ns))
            .collect(),
        container_metrics: p
            .containers
            .iter()
            .map(|c| cri::ContainerMetrics {
                container_id: c.id.clone(),
                metrics: c
                    .samples
                    .iter()
                    .map(|m| metric_of(m, descriptors, p.time_ns))
                    .collect(),
            })
            .collect(),
    }
}

/// The interfaces of a pod from its metrics (the names of cAdvisor, the
/// interface in a label): the default one is `eth0`, else the first that is
/// not the loopback.
pub fn network_usage_of(
    p: &PodMetrics,
    descriptors: &[MetricDescriptor],
    ts: i64,
) -> Option<cri::NetworkUsage> {
    let mut ifaces: BTreeMap<String, [u64; 4]> = BTreeMap::new();
    for m in &p.samples {
        let slot = match m.name.as_str() {
            "container_network_receive_bytes_total" => 0,
            "container_network_receive_errors_total" => 1,
            "container_network_transmit_bytes_total" => 2,
            "container_network_transmit_errors_total" => 3,
            _ => continue,
        };
        let name = descriptors
            .iter()
            .find(|d| d.name == m.name)
            .and_then(|d| d.labels.iter().position(|l| l == "interface"))
            .and_then(|i| m.labels.get(i));
        if let Some(name) = name {
            ifaces.entry(name.clone()).or_default()[slot] = m.value.max(0.0) as u64;
        }
    }
    let default = if ifaces.contains_key("eth0") {
        "eth0".to_string()
    } else {
        ifaces
            .keys()
            .find(|n| *n != "lo")
            .or(ifaces.keys().next())?
            .clone()
    };
    let usage = |name: &String| {
        let v = ifaces[name];
        cri::NetworkInterfaceUsage {
            name: name.clone(),
            rx_bytes: u64v(v[0]),
            rx_errors: u64v(v[1]),
            tx_bytes: u64v(v[2]),
            tx_errors: u64v(v[3]),
        }
    };
    Some(cri::NetworkUsage {
        timestamp: ts,
        default_interface: Some(usage(&default)),
        interfaces: ifaces
            .keys()
            .filter(|n| **n != default)
            .map(usage)
            .collect(),
    })
}

/// The credentials of a pull the CRI asked for, as the access the engine
/// takes: one credential, for `server_address` only when it has one.
pub fn auth_of(a: &cri::AuthConfig) -> Result<Option<RegistryAccess>> {
    use base64::Engine as _;
    if *a == cri::AuthConfig::default() {
        return Ok(None);
    }
    let doc = serde_json::json!({
        "username": a.username, "password": a.password, "auth": a.auth,
        "serveraddress": a.server_address, "identitytoken": a.identity_token,
        "registrytoken": a.registry_token,
    });
    let header = base64::engine::general_purpose::URL_SAFE.encode(doc.to_string());
    RegistryAccess::from_registry_auth(&header)
        .map(Some)
        .map_err(tonic::Status::invalid_argument)
}

/// The CRI image of `i`; `infra_image` is the infra image of the sandboxes
/// (`--sandbox-image`, empty: the engine's).
pub fn image_of(i: &ImageRecord, infra_image: &str) -> cri::Image {
    let (uid, username) = match i.config.user.split(':').next().unwrap_or("") {
        "" => (None, String::new()),
        u => match u.parse::<i64>() {
            Ok(n) => (Some(cri::Int64Value { value: n }), String::new()),
            Err(_) => (None, u.to_string()),
        },
    };
    cri::Image {
        id: i.id.clone(),
        repo_tags: i.names.clone(),
        repo_digests: i.digests.clone(),
        size: i.size,
        uid,
        username,
        spec: Some(cri::ImageSpec {
            image: i.id.clone(),
            ..Default::default()
        }),
        // the image of the infra containers (the sandbox image, else the
        // engine's): the garbage collection of the kubelet leaves it, as
        // containerd's and CRI-O's pause image
        pinned: !infra_image.is_empty() && i.names.iter().any(|n| n == infra_image),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(f: impl FnOnce(&mut cri::ContainerConfig)) -> Result<CreateContainerRequest> {
        container_on(true, f)
    }

    /// A container on a host whose cgroups have the `hugetlb` controller or
    /// not.
    fn container_on(
        hugetlb: bool,
        f: impl FnOnce(&mut cri::ContainerConfig),
    ) -> Result<CreateContainerRequest> {
        let mut cfg = cri::ContainerConfig {
            image: Some(cri::ImageSpec {
                image: "img".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        f(&mut cfg);
        let sm = meta::SandboxMeta::default();
        container_create_of("pod", &cfg, "/log", "p", &sm, hugetlb).map(|(c, _)| c)
    }

    /// The engine's default pids limit is not a CRI container's.
    /// An id that is not a uid or a gid is refused, not given to the engine
    /// as text it looks up as a name.
    #[test]
    fn ids_out_of_range_are_refused() {
        fn int(value: i64) -> Option<cri::Int64Value> {
            Some(cri::Int64Value { value })
        }
        let with = |f: fn(&mut cri::LinuxContainerSecurityContext)| {
            container(|c| {
                let mut sc = cri::LinuxContainerSecurityContext::default();
                f(&mut sc);
                c.linux.get_or_insert_default().security_context = Some(sc);
            })
        };
        assert!(with(|sc| sc.run_as_user = int(-1)).is_err());
        assert!(with(|sc| sc.run_as_user = int(1 << 32)).is_err());
        assert!(with(|sc| {
            sc.run_as_user = int(1);
            sc.run_as_group = int(-1);
        })
        .is_err());
        assert!(with(|sc| sc.supplemental_groups = vec![5, -1]).is_err());
        assert!(with(|sc| sc.run_as_user = int(1000)).is_ok());
    }

    #[test]
    fn a_cri_container_has_no_default_pids_limit() {
        assert_eq!(container(|_| {}).unwrap().pids_limit, Some(-1));
    }

    /// Every field of a container's config the engine applies has its place
    /// in the engine's request (the record the command line fills).
    #[test]
    fn a_container_config_is_the_engines_request() {
        let c = container(|c| {
            c.metadata = Some(cri::ContainerMetadata {
                name: "web".into(),
                attempt: 2,
            });
            c.command = vec!["sh".into()];
            c.args = vec!["-c".into(), "true".into()];
            c.working_dir = "/w".into();
            c.envs = vec![cri::KeyValue {
                key: "A".into(),
                value: b"b".to_vec(),
            }];
            c.annotations = [
                ("k".to_string(), "v".to_string()),
                ("e".into(), String::new()),
            ]
            .into();
            c.log_path = "web/2.log".into();
            c.tty = true;
            c.stdin = true;
            c.stop_signal = cri::Signal::Sigint as i32;
            c.mounts = vec![
                cri::Mount {
                    container_path: "/d".into(),
                    host_path: "/h".into(),
                    readonly: true,
                    recursive_read_only: true,
                    selinux_relabel: true,
                    ..Default::default()
                },
                cri::Mount {
                    container_path: "/s".into(),
                    host_path: "/hs".into(),
                    propagation: cri::MountPropagation::PropagationBidirectional as i32,
                    ..Default::default()
                },
                cri::Mount {
                    container_path: "/i".into(),
                    image: Some(cri::ImageSpec {
                        image: "sha256:abc".into(),
                        ..Default::default()
                    }),
                    image_sub_path: "etc".into(),
                    readonly: true,
                    ..Default::default()
                },
            ];
            c.devices = vec![cri::Device {
                container_path: "/dev/x".into(),
                host_path: "/dev/y".into(),
                permissions: String::new(),
            }];
            c.cdi_devices = vec![cri::CdiDevice {
                name: "vendor.com/gpu=0".into(),
            }];
            c.linux = Some(cri::LinuxContainerConfig {
                resources: Some(cri::LinuxContainerResources {
                    memory_limit_in_bytes: 1 << 20,
                    cpu_quota: 50_000,
                    cpu_period: 100_000,
                    cpu_shares: 512,
                    cpuset_cpus: "0".into(),
                    oom_score_adj: 5,
                    unified: [("memory.high".to_string(), "1M".to_string())].into(),
                    ..Default::default()
                }),
                security_context: Some(cri::LinuxContainerSecurityContext {
                    run_as_user: Some(cri::Int64Value { value: 7 }),
                    supplemental_groups: vec![8],
                    supplemental_groups_policy: cri::SupplementalGroupsPolicy::Strict as i32,
                    readonly_rootfs: true,
                    no_new_privs: true,
                    capabilities: Some(cri::Capability {
                        add_capabilities: vec!["NET_ADMIN".into()],
                        drop_capabilities: vec!["ALL".into()],
                        add_ambient_capabilities: vec!["NET_RAW".into()],
                    }),
                    seccomp: Some(cri::SecurityProfile {
                        profile_type: cri::security_profile::ProfileType::Localhost as i32,
                        localhost_ref: "/p.json".into(),
                    }),
                    selinux_options: Some(cri::SeLinuxOption {
                        level: "s0:c1".into(),
                        ..Default::default()
                    }),
                    masked_paths: vec!["/proc/kcore".into()],
                    namespace_options: Some(cri::NamespaceOption {
                        pid: cri::NamespaceMode::Target as i32,
                        target_id: "other".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            });
        })
        .unwrap();
        assert_eq!(c.name.as_deref(), Some("k8s_web_p___2"));
        assert_eq!((c.image.as_str(), c.pod.as_deref()), ("img", Some("pod")));
        assert_eq!(
            (c.entrypoint.clone(), c.command.clone()),
            (
                vec!["sh".to_string()],
                vec!["-c".to_string(), "true".to_string()]
            )
        );
        assert_eq!(
            (c.working_dir.as_str(), c.env.clone()),
            ("/w", vec!["A=b".to_string()])
        );
        assert_eq!(c.annotations, [("k".to_string(), "v".to_string())].into());
        // (the metadata of the CRI)
        assert!(!c.labels.is_empty());
        let log = c.log_config.clone().unwrap();
        assert_eq!(
            (log.driver.as_str(), log.config["path"].as_str()),
            ("k8s-file", "/log/web/2.log")
        );
        assert!(c.tty && c.stdin_open);
        assert_eq!(c.stop_signal, "SIGINT");
        let binds: Vec<_> = c
            .bind_mounts
            .iter()
            .map(|m| (m.source.as_str(), m.target.as_str(), m.options.join(",")))
            .collect();
        assert_eq!(
            binds,
            [
                ("/h", "/d", "ro,rro,z".to_string()),
                ("/hs", "/s", "rw,rshared".to_string())
            ]
        );
        assert_eq!(c.image_mounts.len(), 1);
        let image = &c.image_mounts[0];
        assert_eq!(
            (
                image.image.as_str(),
                image.target.as_str(),
                image.subpath.as_deref()
            ),
            ("sha256:abc", "/i", Some("etc"))
        );
        // (nothing is left as the text of `-v` or `--mount`)
        assert!(c.volumes.is_empty() && c.mount.is_empty());
        let devices: Vec<_> = c
            .devices
            .iter()
            .map(|d| {
                (
                    d.path_on_host.as_str(),
                    d.path_in_container.as_str(),
                    d.cgroup_permissions.as_str(),
                )
            })
            .collect();
        let cdi = DeviceMapping::cdi("vendor.com/gpu=0");
        assert_eq!(
            devices,
            [
                (
                    cdi.path_on_host.as_str(),
                    cdi.path_in_container.as_str(),
                    cdi.cgroup_permissions.as_str()
                ),
                ("/dev/y", "/dev/x", "rwm")
            ]
        );
        let r = c.resources.clone().unwrap();
        assert_eq!(
            (
                r.memory,
                r.cpu_quota,
                r.cpu_period,
                r.cpu_shares,
                r.cpuset_cpus.as_deref()
            ),
            (
                Some(1 << 20),
                Some(50_000),
                Some(100_000),
                Some(512),
                Some("0")
            )
        );
        assert_eq!(
            r.cgroup_conf,
            Some([("memory.high".to_string(), "1M".to_string())].into())
        );
        assert_eq!(c.oom_score_adj, Some(5));
        assert_eq!(
            (c.user.as_str(), c.group_add.clone(), c.groups_strict),
            ("7", vec!["8".to_string()], true)
        );
        assert!(c.read_only_rootfs && c.security_opt.no_new_privileges && !c.privileged);
        assert_eq!(
            (c.cap_add.clone(), c.cap_drop.clone(), c.cap_ambient.clone()),
            (
                vec!["NET_ADMIN".to_string()],
                vec!["ALL".to_string()],
                vec!["NET_RAW".to_string()]
            )
        );
        assert_eq!(c.security_opt.seccomp_profile.as_deref(), Some("/p.json"));
        assert_eq!(c.security_opts, ["label=level:s0:c1"]);
        assert_eq!(
            (
                c.security_opt.mask_paths.clone(),
                c.security_opt.unmask_paths.clone()
            ),
            (vec!["/proc/kcore".to_string()], vec!["ALL".to_string()])
        );
        assert_eq!(c.pid_mode, modes::NsMode::Container("other".into()));
        assert_eq!(
            (c.cgroups, c.userns_mode),
            (CgroupsMode::Enabled, UsernsChoice::Host)
        );
    }

    #[test]
    fn dropping_all_capabilities_wins_over_adding_all() {
        let caps = |add: &[&str], drop: &[&str]| {
            let c = container(|c| {
                c.linux = Some(cri::LinuxContainerConfig {
                    security_context: Some(cri::LinuxContainerSecurityContext {
                        capabilities: Some(cri::Capability {
                            add_capabilities: add.iter().map(|s| s.to_string()).collect(),
                            drop_capabilities: drop.iter().map(|s| s.to_string()).collect(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
            })
            .unwrap();
            (c.cap_add, c.cap_drop)
        };
        assert_eq!(caps(&["ALL", "NET_RAW"], &["all"]).0, ["NET_RAW"]);
        assert_eq!(caps(&["ALL"], &["CHOWN"]).0, ["ALL"]);
        assert_eq!(caps(&["ALL"], &[]).0, ["ALL"]);
    }

    #[test]
    fn the_lists_of_paths_are_kept_as_given_and_privileged_has_none() {
        let with = |privileged, masked: &[&str], ro: &[&str]| {
            container(|c| {
                c.linux = Some(cri::LinuxContainerConfig {
                    security_context: Some(cri::LinuxContainerSecurityContext {
                        privileged,
                        masked_paths: masked.iter().map(|s| s.to_string()).collect(),
                        readonly_paths: ro.iter().map(|s| s.to_string()).collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
            })
            .unwrap()
        };
        let c = with(false, &["/proc/kcore"], &["/proc/sys"]).security_opt;
        assert_eq!(c.unmask_paths, ["ALL"]);
        assert_eq!(c.mask_paths, ["/proc/kcore"]);
        assert_eq!(c.readonly_paths, ["/proc/sys"]);
        // empty lists are an unmasked /proc, not the engine's defaults
        let c = with(false, &[], &[]);
        assert!(!c.privileged);
        let c = c.security_opt;
        assert_eq!(c.unmask_paths, ["ALL"]);
        assert!(c.mask_paths.is_empty() && c.readonly_paths.is_empty());
        let c = with(true, &["/proc/kcore"], &["/proc/sys"]).security_opt;
        assert!(
            c.mask_paths.is_empty() && c.readonly_paths.is_empty() && c.unmask_paths.is_empty()
        );
    }

    /// What the security context of the kubelet becomes for the engine:
    /// privileged x seccomp profile x lists of paths, no context, and the
    /// infra container of a sandbox.
    #[test]
    #[allow(deprecated)]
    fn the_confinement_of_every_security_context() {
        use cri::security_profile::ProfileType;
        let typed = |t: ProfileType, r: &str| {
            Some(cri::SecurityProfile {
                profile_type: t as i32,
                localhost_ref: r.into(),
            })
        };
        // (typed profile, deprecated path, what the engine gets: unconfined
        // or the profile file, none for the default profile)
        let profiles = [
            // nothing asked is unconfined, as the API says of the empty
            // deprecated path (a sandbox gets the default profile instead)
            (None, "", (true, None)),
            (typed(ProfileType::RuntimeDefault, ""), "", (false, None)),
            (typed(ProfileType::Unconfined, ""), "", (true, None)),
            (typed(ProfileType::Localhost, "/p"), "", (false, Some("/p"))),
            (None, "runtime/default", (false, None)),
            (None, "docker/default", (false, None)),
            (None, "unconfined", (true, None)),
            (None, "localhost/p", (false, Some("p"))),
            // the typed one wins over the deprecated one
            (
                typed(ProfileType::RuntimeDefault, ""),
                "unconfined",
                (false, None),
            ),
            (
                typed(ProfileType::Unconfined, ""),
                "runtime/default",
                (true, None),
            ),
            (
                typed(ProfileType::Localhost, "/p"),
                "unconfined",
                (false, Some("/p")),
            ),
        ];
        for privileged in [false, true] {
            for (seccomp, path, (unconfined, file)) in &profiles {
                for (masked, readonly) in
                    [(vec![], vec![]), (vec!["/proc/kcore"], vec!["/proc/sys"])]
                {
                    let c = container(|c| {
                        c.linux = Some(cri::LinuxContainerConfig {
                            security_context: Some(cri::LinuxContainerSecurityContext {
                                privileged,
                                seccomp: seccomp.clone(),
                                seccomp_profile_path: path.to_string(),
                                masked_paths: masked.iter().map(|s| s.to_string()).collect(),
                                readonly_paths: readonly.iter().map(|s| s.to_string()).collect(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })
                    })
                    .unwrap();
                    let so = &c.security_opt;
                    let what = format!("{seccomp:?} {path:?} privileged {privileged} {masked:?}");
                    // a privileged container has no profile (the one asked
                    // for does not apply either), and no paths
                    assert_eq!(so.seccomp_unconfined, *unconfined || privileged, "{what}");
                    assert_eq!(
                        so.seccomp_profile.as_deref(),
                        file.filter(|_| !privileged),
                        "{what}"
                    );
                    let paths = |v: &[&str]| -> Vec<String> {
                        v.iter()
                            .filter(|_| !privileged)
                            .map(|s| s.to_string())
                            .collect()
                    };
                    assert_eq!(so.mask_paths, paths(&masked), "{what}");
                    assert_eq!(so.readonly_paths, paths(&readonly), "{what}");
                    assert_eq!(
                        so.unmask_paths,
                        if privileged {
                            vec![]
                        } else {
                            vec!["ALL".to_string()]
                        }
                    );
                }
            }
        }
        // No security context at all: the engine's defaults, its default
        // seccomp profile and its paths.
        let so = container(|_| {}).unwrap().security_opt;
        assert!(!so.seccomp_unconfined && so.seccomp_profile.is_none());
        assert!(so.unmask_paths.is_empty());
        assert!(so.mask_paths.is_empty() && so.readonly_paths.is_empty());
        // A sandbox that names no profile, with a context or without one,
        // keeps the default profile for its infra container.
        let infra = |sc: Option<cri::LinuxSandboxSecurityContext>| {
            infra_security_of(sc.as_ref(), 0).unwrap().security_opts
        };
        assert!(infra(None).is_empty());
        assert!(infra(Some(Default::default())).is_empty());
        let unconfined = cri::LinuxSandboxSecurityContext {
            seccomp: typed(ProfileType::Unconfined, ""),
            ..Default::default()
        };
        assert_eq!(infra(Some(unconfined)), ["seccomp=unconfined"]);
    }

    #[test]
    fn an_id_mapped_mount_is_the_idmap_option() {
        let map = |c, h, l| cri::IdMapping {
            container_id: c,
            host_id: h,
            length: l,
        };
        let with = |uids: Vec<cri::IdMapping>, gids: Vec<cri::IdMapping>| {
            container(|c| {
                c.mounts = vec![cri::Mount {
                    container_path: "/m".into(),
                    host_path: "/h".into(),
                    uid_mappings: uids,
                    gid_mappings: gids,
                    ..Default::default()
                }]
            })
        };
        let c = with(
            vec![map(0, 100000, 65536)],
            vec![map(0, 100000, 1000), map(1000, 200000, 10)],
        )
        .unwrap();
        assert_eq!(
            c.bind_mounts[0].options,
            [
                "rw",
                "idmap=uids=0-100000-65536;gids=0-100000-1000#1000-200000-10"
            ]
        );
        for (uids, gids) in [
            (vec![map(0, 1, 1)], vec![]),
            (vec![map(0, 1, 0)], vec![map(0, 1, 1)]),
        ] {
            let e = with(uids, gids).unwrap_err();
            assert_eq!(e.code(), tonic::Code::InvalidArgument, "{e}");
        }
    }

    /// A host path is a value of the request, not a piece of the text of `-v`:
    /// a colon or a comma in it is part of the name.
    #[test]
    fn a_host_path_with_a_colon_or_a_comma_is_kept_whole() {
        for path in ["/data/a:b", "/data/a:b:c", "/data/a,b"] {
            let c = container(|c| {
                c.mounts = vec![cri::Mount {
                    container_path: "/m".into(),
                    host_path: path.into(),
                    readonly: true,
                    ..Default::default()
                }]
            })
            .unwrap();
            assert_eq!(c.bind_mounts[0].source, path);
            assert_eq!(c.bind_mounts[0].target, "/m");
            assert_eq!(c.bind_mounts[0].options, ["ro"]);
            assert!(c.volumes.is_empty());
        }
        let c = container(|c| {
            c.mounts = vec![cri::Mount {
                container_path: "/i,x".into(),
                readonly: true,
                image: Some(cri::ImageSpec {
                    image: "sha256:abc".into(),
                    ..Default::default()
                }),
                image_sub_path: "a,b".into(),
                ..Default::default()
            }]
        })
        .unwrap();
        assert_eq!(c.image_mounts[0].target, "/i,x");
        assert_eq!(c.image_mounts[0].subpath.as_deref(), Some("a,b"));
    }

    #[test]
    fn the_image_of_the_infra_containers_is_pinned() {
        let image = |name: &str| ImageRecord {
            names: vec![name.into()],
            ..Default::default()
        };
        // (the name of the engine's own pause image is not a rule of the CRI)
        let own = "localhost/velarx-pause:0.1.0";
        assert!(image_of(&image(own), own).pinned);
        assert!(!image_of(&image(own), "").pinned);
        assert!(!image_of(&image("docker.io/library/alpine:latest"), own).pinned);
        // the sandbox image of a node (containerd pins its own)
        let pause = "registry.k8s.io/pause:3.10";
        assert!(image_of(&image(pause), pause).pinned);
        assert!(!image_of(&image(pause), "").pinned);
        assert!(!image_of(&image("docker.io/library/alpine:latest"), pause).pinned);
    }

    #[test]
    fn stdin_once_is_kept_for_the_attach() {
        let meta = |stdin, stdin_once| {
            let cfg = cri::ContainerConfig {
                image: Some(cri::ImageSpec {
                    image: "img".into(),
                    ..Default::default()
                }),
                stdin,
                stdin_once,
                ..Default::default()
            };
            container_create_of(
                "pod",
                &cfg,
                "/log",
                "p",
                &meta::SandboxMeta::default(),
                true,
            )
            .unwrap()
            .1
            .stdin_once
        };
        assert!(meta(true, true));
        assert!(!meta(true, false));
        assert!(!meta(false, true), "no input to close");
    }

    #[test]
    fn the_overhead_is_in_the_swap_and_the_shares_stay_in_range() {
        let r = Resources {
            memory_limit: 100,
            memory_swap: 100,
            cpu_shares: 262_000,
            ..Default::default()
        };
        let o = Resources {
            memory_limit: 10,
            cpu_shares: 1024,
            ..Default::default()
        };
        let l = sandbox_limits(&r, &o);
        assert_eq!((l.memory_limit, l.memory_swap), (110, 110));
        assert_eq!(l.cpu_shares, 262_144);
    }

    #[test]
    fn what_the_engine_cannot_do_is_refused_not_ignored() {
        let hp = |limit| cri::HugepageLimit {
            page_size: "2MB".into(),
            limit,
        };
        let linux = |r: cri::LinuxContainerResources| cri::LinuxContainerConfig {
            resources: Some(r),
            ..Default::default()
        };
        let refused: Vec<(&str, Result<CreateContainerRequest>)> = vec![
            (
                "windows",
                container(|c| c.windows = Some(Default::default())),
            ),
            (
                "hugepage",
                container_on(false, |c| {
                    c.linux = Some(linux(cri::LinuxContainerResources {
                        hugepage_limits: vec![hp(1 << 21)],
                        ..Default::default()
                    }))
                }),
            ),
        ];
        for (what, r) in refused {
            let e = r.unwrap_err();
            assert_eq!(e.code(), tonic::Code::Unimplemented, "{what}");
            assert!(e.message().contains("not supported"), "{what}: {e}");
        }
        // the zero limits the kubelet sends for the sizes not asked for are
        // left out without the controller, and kept with it
        let with = |hugetlb, limits: Vec<cri::HugepageLimit>| {
            container_on(hugetlb, |c| {
                c.linux = Some(linux(cri::LinuxContainerResources {
                    hugepage_limits: limits,
                    ..Default::default()
                }))
            })
            .unwrap()
        };
        assert!(with(false, vec![hp(0)]).resources.is_none());
        let r = with(true, vec![hp(0), hp(1 << 21)]).resources.unwrap();
        assert_eq!(r.hugepage_limits[1].limit, 1 << 21);
        assert_eq!(r.hugepage_limits[1].page_size, "2MB");

        let pod = |f: fn(&mut cri::PodSandboxConfig)| {
            let mut cfg = cri::PodSandboxConfig::default();
            f(&mut cfg);
            pod_create_of(&cfg, "").map(|_| ())
        };
        assert!(pod(|c| c.windows = Some(Default::default())).is_err());
        assert!(pod(|c| {
            c.linux = Some(cri::LinuxPodSandboxConfig {
                resources: Some(cri::LinuxContainerResources {
                    unified: [("memory.high".to_string(), "1".to_string())].into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
        })
        .is_err());
    }

    #[test]
    #[allow(deprecated, reason = "the test is of the deprecated field")]
    fn the_deprecated_apparmor_profile_is_read() {
        let with = |p: &str| {
            container(|c| {
                c.linux = Some(cri::LinuxContainerConfig {
                    security_context: Some(cri::LinuxContainerSecurityContext {
                        apparmor_profile: p.into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
            })
        };
        let apparmor = |p| {
            let o = with(p).unwrap().security_opt;
            (o.apparmor_unconfined, o.apparmor_profile)
        };
        assert_eq!(apparmor("unconfined"), (true, None));
        assert_eq!(apparmor("localhost/prof"), (false, Some("prof".into())));
        assert_eq!(apparmor("runtime/default"), (false, None));
        assert!(with("bogus").is_err());
    }

    #[test]
    fn the_network_of_a_pod_is_its_interfaces() {
        let d = |n: &str| MetricDescriptor {
            name: n.into(),
            labels: vec!["id".into(), "interface".into()],
            ..Default::default()
        };
        let descriptors = vec![
            d("container_network_receive_bytes_total"),
            d("container_network_transmit_bytes_total"),
        ];
        let s = |n: &str, i: &str, v: f64| MetricSample {
            name: n.into(),
            labels: vec!["p".into(), i.into()],
            value: v,
        };
        let pod = PodMetrics {
            id: "p".into(),
            samples: vec![
                s("container_network_receive_bytes_total", "lo", 1.0),
                s("container_network_receive_bytes_total", "eth0", 10.0),
                s("container_network_transmit_bytes_total", "eth0", 20.0),
                s("something_else", "eth0", 5.0),
            ],
            ..Default::default()
        };
        let n = network_usage_of(&pod, &descriptors, 7).unwrap();
        let eth = n.default_interface.unwrap();
        assert_eq!(eth.name, "eth0");
        assert_eq!(eth.rx_bytes.unwrap().value, 10);
        assert_eq!(eth.tx_bytes.unwrap().value, 20);
        assert_eq!(n.interfaces.len(), 1);
        assert_eq!(n.interfaces[0].name, "lo");
        assert!(network_usage_of(&PodMetrics::default(), &descriptors, 7).is_none());
    }
}
