// SPDX-License-Identifier: Apache-2.0
//! What the engine knows of a container (its record of the database, its
//! configuration, the request it was made from, its state, health, network)
//! and the typed record `ContainerInspect` and `ContainerList` answer of it
//! (`velarx_proto::workload::ContainerRecord`; `velarx-shape` lays out
//! podman's and Docker's documents of it).

use super::convert::record_time_ns;
use super::error::ApiResult;
use super::images;
use super::lifecycle::{self, Status};
use super::record::ApiRecord;
use super::spec::{get, s, strs};
use crate::api::AppState;
use std::collections::{BTreeMap, HashMap};
use velarx_db::{ContainerRecord, ImageRecord, RecordState};
use velarx_proto::workload as typed;
use velarx_runtime::container::ContainerConfig;
use velarx_wire::monitor::proto::Health;
use velarx_wire::request::MountConfig;
use velarx_wire::request::{NetworkMode, NsMode};

/// Everything the record is made of.
pub struct Info {
    pub rec: ContainerRecord,
    pub cfg: ContainerConfig,
    pub api: Option<ApiRecord>,
    pub status: Status,
    pub image: Option<ImageRecord>,
    pub image_names: Vec<String>,
    pub pod: Option<PodInfo>,
    pub health: Option<Health>,
    pub oom_killed: bool,
    pub restart_count: u32,
    /// Killed at the end of its time limit (`--timeout`).
    pub timed_out: bool,
    /// Stopped by a user (stop, kill): its restart policy does not start it
    pub stopped_by_user: bool,
    /// The interfaces on bridge networks.
    pub interfaces: Vec<velarx_runtime::network::engine::Interface>,
    /// Its checkpoint and restore.
    pub checkpoint: velarx_wire::wire::CheckpointRecord,
    /// The published ports, their host ports picked (none: not known)
    pub ports: Option<Vec<velarx_wire::addr::PortSpec>>,
    /// The images the container mounts: the ID the engine keeps for each, and
    /// the ID of the API (what `images` and the inspect of the image say)
    pub mounted_images: std::collections::HashMap<String, String>,
}

/// An image name as podman shows it: with its tag (`:latest` if it has none
/// and no digest); an ID stays as it is.
fn with_tag(name: String) -> String {
    let last = name.rsplit('/').next().unwrap_or(&name);
    let is_id = name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit());
    if name.is_empty() || is_id || last.contains(':') || name.contains('@') {
        name
    } else {
        format!("{name}:latest")
    }
}

pub struct PodInfo {
    pub id: String,
    pub name: String,
    pub is_infra: bool,
}

pub async fn load(state: &AppState, rec: ContainerRecord) -> ApiResult<Info> {
    let status = lifecycle::status(state, &rec).await;
    let shared = Shared::read(state, [&rec]).await?;
    load_with(state, rec, status, &shared).await
}

/// A container found by [`lifecycle::resolve_observed`], with what finding
/// it learned of its runtime: the runtime is not asked again.
pub async fn load_observed(
    state: &AppState,
    found: (
        ContainerRecord,
        Option<velarx_runtime::container::ContainerStatus>,
    ),
) -> ApiResult<Info> {
    let shared = Shared::read(state, [&found.0]).await?;
    load_found(state, found, &shared).await
}

/// [`load_observed`] of one of the containers `shared` was read for.
pub async fn load_found(
    state: &AppState,
    (rec, asked): (
        ContainerRecord,
        Option<velarx_runtime::container::ContainerStatus>,
    ),
    shared: &Shared,
) -> ApiResult<Info> {
    let status = lifecycle::status_from(state, &rec, asked).await;
    load_with(state, rec, status, shared).await
}

/// What the containers of one call have in common, read once for all of
/// them: the pods, the images (and their names), and the rows of the
/// database that are per container (health and counters, network setup,
/// interfaces) in one query each.
pub struct Shared {
    pods: HashMap<String, super::pods::PodOf>,
    exts: HashMap<String, velarx_db::ContainerExt>,
    specs: HashMap<String, velarx_runtime::network::engine::SpecRead>,
    interfaces: HashMap<String, Vec<velarx_runtime::network::engine::Interface>>,
    /// The images the containers are of or mount (none: gone)
    images: HashMap<String, Option<ImageRecord>>,
    /// The names of the images the containers are of
    names: HashMap<String, Vec<String>>,
}

impl Shared {
    /// The network setup of a container, if it has one; the error of one
    /// that cannot be read.
    fn spec_of(&self, id: &str) -> ApiResult<Option<&velarx_netdetach::spec::NetSpec>> {
        match self.specs.get(id) {
            None => Ok(None),
            Some(Ok(spec)) => Ok(Some(spec)),
            Some(Err(message)) => {
                Err(velarx_netkernel::error::NetworkError::Unreadable(message.clone()).into())
            }
        }
    }

    pub async fn read<'a>(
        state: &AppState,
        recs: impl IntoIterator<Item = &'a ContainerRecord>,
    ) -> ApiResult<Self> {
        let recs: Vec<&ContainerRecord> = recs.into_iter().collect();
        let mut ids = Vec::new();
        let mut owners = Vec::new();
        let mut of = std::collections::HashSet::new();
        let mut mounted = Vec::new();
        for rec in &recs {
            ids.push(rec.id.clone());
            of.insert(rec.image_id.clone());
            // (a configuration that cannot be read fails the load of its
            // container, with its error)
            if let Ok(cfg) = lifecycle::config_of(rec) {
                if let NetworkMode::Container(owner) = &cfg.network_mode {
                    owners.push(owner.clone());
                }
                mounted.extend(
                    cfg.mounts
                        .iter()
                        .filter_map(|m| m.image.as_ref())
                        .map(|im| im.image.clone()),
                );
            }
        }
        let engine = state.network_service.engine();
        let mut with_owners = ids.clone();
        with_owners.extend(owners);
        let specs = engine.specs(&with_owners).await?;
        let alive: std::collections::HashSet<String> = recs
            .iter()
            .filter(|rec| rec.state.is_alive())
            .map(|rec| rec.id.clone())
            .collect();
        let interfaces = engine.interfaces_of(&ids, &specs, &alive).await?;
        let exts = state
            .container_service
            .container_exts(&recs)
            .await
            .unwrap_or_default();
        let mut images = HashMap::new();
        let mut names = HashMap::new();
        for id in of.iter().chain(&mounted) {
            if images.contains_key(id) {
                continue;
            }
            // (a container whose image is gone has none)
            let image = match state.db.get_image(id).await {
                Ok(i) => Some(i),
                Err(e) if e.is_not_found() => None,
                Err(e) => {
                    return Err(super::error::ApiError::db(
                        "reading the image of a container",
                        e,
                    ))
                }
            };
            if let Some(img) = image.as_ref().filter(|_| of.contains(id)) {
                names.insert(id.clone(), images::image_display_names(state, img).await?);
            }
            images.insert(id.clone(), image);
        }
        Ok(Self {
            pods: super::pods::pod_index(state).await,
            exts,
            specs,
            interfaces,
            images,
            names,
        })
    }
}

async fn load_with(
    state: &AppState,
    rec: ContainerRecord,
    status: lifecycle::Status,
    shared: &Shared,
) -> ApiResult<Info> {
    let cfg = lifecycle::config_of(&rec)?;
    let api = super::record::load(state, &rec.id).await;
    let image = shared.images.get(&rec.image_id).cloned().flatten();
    let image_names = shared.names.get(&rec.image_id).cloned().unwrap_or_default();
    let pod = shared
        .pods
        .get(&rec.id)
        .map(|(id, name, is_infra)| PodInfo {
            id: id.clone(),
            name: name.clone(),
            is_infra: *is_infra,
        });
    let ext = shared.exts.get(&rec.id).cloned().unwrap_or_default();
    let health = health_of(&ext);
    shared.spec_of(&rec.id)?;
    let interfaces = shared.interfaces.get(&rec.id).cloned().unwrap_or_default();
    // (a container in the network namespace of another, a member of a pod,
    // has the ports published for it)
    let net_owner = match &cfg.network_mode {
        NetworkMode::Container(owner) => owner,
        _ => &rec.id,
    };
    let ports = match shared.spec_of(net_owner)? {
        Some(spec) => Some(spec.port_specs()?),
        None => None,
    };
    let mut mounted_images = std::collections::HashMap::new();
    for im in cfg.mounts.iter().filter_map(|m| m.image.as_ref()) {
        if let Some(Some(rec)) = shared.images.get(&im.image) {
            mounted_images.insert(im.image.clone(), images::image_id(rec));
        }
    }
    let checkpoint = state.container_service.checkpoint_record(&rec.id);
    Ok(Info {
        mounted_images,
        rec,
        cfg,
        api,
        status,
        image,
        image_names,
        pod,
        health,
        oom_killed: ext.oom_killed,
        restart_count: ext.restart_count,
        timed_out: ext.timed_out,
        checkpoint,
        stopped_by_user: ext.stopped_by_user,
        interfaces,
        ports,
    })
}

/// The health the monitor reports.
pub(crate) fn health_of(ext: &velarx_db::ContainerExt) -> Option<Health> {
    serde_json::from_str(ext.health.as_deref()?).ok()
}

impl Info {
    pub fn name(&self) -> String {
        self.rec
            .name
            .clone()
            .unwrap_or_else(|| self.rec.id[..12.min(self.rec.id.len())].to_string())
    }

    pub fn image_name(&self) -> String {
        let name = match &self.api {
            Some(a) if !a.image_name.is_empty() => a.image_name.clone(),
            _ => self
                .image_names
                .first()
                .cloned()
                .unwrap_or_else(|| self.cfg.image.clone()),
        };
        with_tag(name)
    }

    pub fn image_id(&self) -> String {
        self.image
            .as_ref()
            .map(images::image_id)
            .unwrap_or_default()
    }

    pub fn created_ns(&self) -> i64 {
        record_time_ns(&self.rec.created_at)
    }

    pub fn req(&self) -> Option<&velarx_wire::request::CreateContainerRequest> {
        self.api.as_ref().map(|a| &a.request)
    }

    /// The command line: entrypoint and command.
    pub fn args(&self) -> Vec<String> {
        let mut a = self.cfg.entrypoint.clone();
        a.extend(self.cfg.command.iter().cloned());
        a
    }

    /// The annotations of the create.
    pub fn annotations(&self) -> std::collections::HashMap<String, String> {
        self.req()
            .map(|r| r.annotations.clone().into_iter().collect())
            .unwrap_or_default()
    }

    /// The restart policy of the create (none: empty).
    pub fn restart_policy(&self) -> &str {
        self.req()
            .and_then(|r| r.restart_policy.as_ref())
            .map_or("", |p| p.name.as_str())
    }
}

/// The destinations a Docker client wrote for the binds of its create
/// (`/test/` is `/test` once cleaned), by the cleaned destination.
fn asked_destinations(info: &Info) -> std::collections::HashMap<String, String> {
    let body = info
        .api
        .as_ref()
        .map(|a| &a.body)
        .unwrap_or(&serde_json::Value::Null);
    let mut out = std::collections::HashMap::new();
    for bind in strs(get(body, "HostConfig"), "Binds") {
        if let Some(dest) = bind.split(':').nth(1) {
            if let Ok(clean) = velarx_core::services::clean_target(dest) {
                if clean != dest {
                    out.insert(clean, dest.to_string());
                }
            }
        }
    }
    out
}

/// The propagation a mount has: the last of its options that says one, else
/// `rprivate`.
fn propagation_of(options: &[String]) -> &str {
    options
        .iter()
        .rev()
        .map(String::as_str)
        .find(|o| {
            matches!(
                *o,
                "shared"
                    | "rshared"
                    | "slave"
                    | "rslave"
                    | "private"
                    | "rprivate"
                    | "unbindable"
                    | "runbindable"
            )
        })
        .unwrap_or("rprivate")
}

/// The mounts the user asked for: podman lists those of the spec, not the
/// files the engine binds at start.
fn user_mounts(mounts: &[MountConfig]) -> impl Iterator<Item = &MountConfig> {
    mounts.iter().filter(|m| !m.engine)
}

fn mounts_of(info: &Info, server: &velarx_config::ServerConfig) -> Vec<typed::ContainerMount> {
    let asked = asked_destinations(info);
    let volumes_dir = server.root_dir.join("volumes");
    user_mounts(&info.cfg.mounts)
        .map(|m| {
            let typ = m.mount_type.as_deref().unwrap_or("bind");
            let rel = std::path::Path::new(&m.source)
                .strip_prefix(&volumes_dir)
                .ok();
            let mut out = typed::ContainerMount {
                destination: asked.get(&m.target).unwrap_or(&m.target).clone(),
                options: m.options.clone(),
                read_only: m.options.iter().any(|o| o == "ro" || o == "readonly"),
                named: m.volume.is_some(),
                source: m.source.clone(),
                ..Default::default()
            };
            if let Some(im) = &m.image {
                // an image (or a directory of it) mounted: the image by its
                // ID as the source
                out.kind = typed::MountKind::Image;
                out.sub_path = im.subpath.clone().unwrap_or_default();
                out.source = info
                    .mounted_images
                    .get(&im.image)
                    .unwrap_or(&im.image)
                    .clone();
            } else if typ == "tmpfs" {
                out.kind = typed::MountKind::Tmpfs;
                out.source = String::new();
            } else if let Some(rel) = rel {
                // the volume of the mount, or the directory of its data
                out.kind = typed::MountKind::Volume;
                out.name = m.volume.clone().unwrap_or_else(|| {
                    rel.components()
                        .next()
                        .map(|c| c.as_os_str().to_string_lossy().to_string())
                        .unwrap_or_default()
                });
            } else {
                out.kind = typed::MountKind::Bind;
                out.propagation = propagation_of(&m.options).to_string();
            }
            if out.kind != typed::MountKind::Volume {
                out.named = false;
            }
            if out.named {
                out.name = m.volume.clone().unwrap_or_default();
            }
            out
        })
        .collect()
}

/// Whether the container asked for no network and gets the rootless
/// default, pasta (the network engine's choice, as podman's).
fn default_pasta(info: &Info) -> Result<bool, velarx_base::ids::IdsError> {
    Ok(info.cfg.network_mode == NetworkMode::Unset
        && info.cfg.networks.is_empty()
        && velarx_runtime::userns::rootless::in_user_namespace()?)
}

/// The networks of a container as podman names them.
fn network_names(info: &Info) -> Result<Vec<String>, velarx_base::ids::IdsError> {
    if !info.cfg.networks.is_empty() {
        return Ok(info.cfg.networks.clone());
    }
    if default_pasta(info)? {
        return Ok(vec!["pasta".to_string()]);
    }
    Ok(match &info.cfg.network_mode {
        NetworkMode::Unset | NetworkMode::Bridge(None) => vec!["podman".to_string()],
        m => vec![m.to_string()],
    })
}

fn network_mode(info: &Info) -> Result<String, velarx_base::ids::IdsError> {
    if default_pasta(info)? {
        return Ok("pasta".to_string());
    }
    Ok(match &info.cfg.network_mode {
        NetworkMode::Unset | NetworkMode::Bridge(None) => {
            if let Some(n) = info
                .cfg
                .networks
                .first()
                .filter(|n| *n != velarx_netdetach::def::DEFAULT_NETWORK)
            {
                n.clone()
            } else {
                "bridge".to_string()
            }
        }
        m => m.to_string(),
    })
}

fn network_of(info: &Info) -> Result<typed::ContainerNetwork, velarx_base::ids::IdsError> {
    let req = info.req();
    let ports = req
        .map(|r| {
            r.ports
                .iter()
                .map(|p| typed::ContainerPort {
                    container_port: i64::from(p.container_port),
                    host_port: p.host_port.map_or(0, i64::from),
                    host_ip: p.host_ip.clone(),
                    protocol: p.protocol.clone(),
                    range: 1,
                })
                .collect()
        })
        .unwrap_or_default();
    let bound_ports = info
        .ports
        .iter()
        .flatten()
        .map(|p| typed::ContainerPort {
            container_port: i64::from(p.container_port),
            host_port: i64::from(p.host_port),
            host_ip: p.host_ip.map(|i| i.to_string()).unwrap_or_default(),
            protocol: p.proto.as_str().to_string(),
            range: i64::from(p.range),
        })
        .collect();
    let interfaces = info
        .interfaces
        .iter()
        .map(|i| {
            let routed = !i.no_gateway;
            typed::ContainerInterface {
                network: i.network.clone(),
                network_id: i.network_id.clone(),
                ip: i.ip.map(|ip| ip.to_string()).unwrap_or_default(),
                prefix_len: i64::from(i.prefix),
                ip6: i.ip6.map(|ip| ip.to_string()).unwrap_or_default(),
                prefix6_len: i64::from(i.prefix6),
                gateway: if routed {
                    i.gateway.to_string()
                } else {
                    String::new()
                },
                gateway6: i
                    .gateway6
                    .filter(|_| routed)
                    .map(|g| g.to_string())
                    .unwrap_or_default(),
                mac: i.mac.clone(),
                aliases: i.aliases.clone(),
            }
        })
        .collect();
    // the image's EXPOSE and the create's --expose
    let image_exposed: Vec<String> = info
        .image
        .as_ref()
        .and_then(|i| serde_json::from_str::<serde_json::Value>(&i.config).ok())
        .and_then(|c| {
            c.pointer("/config/ExposedPorts")
                .and_then(|p| p.as_object())
                .map(|o| o.keys().cloned().collect())
        })
        .unwrap_or_default();
    let mut exposed: Vec<String> = Vec::new();
    for e in image_exposed
        .iter()
        .chain(req.map(|r| &r.expose).into_iter().flatten())
    {
        let e = if e.contains('/') {
            e.clone()
        } else {
            format!("{e}/tcp")
        };
        if !exposed.contains(&e) {
            exposed.push(e);
        }
    }
    // the namespace of a container that runs in one of its own
    let sandbox_key =
        if info.status.alive() && info.status.pid > 0 && !info.cfg.network_mode.is_host() {
            format!("/proc/{}/ns/net", info.status.pid)
        } else {
            String::new()
        };
    let list = |f: fn(&velarx_wire::request::CreateContainerRequest) -> &Vec<String>| {
        req.map(|r| f(r).clone()).unwrap_or_default()
    };
    Ok(typed::ContainerNetwork {
        mode: network_mode(info)?,
        networks: network_names(info)?,
        interfaces,
        ports,
        bound_ports,
        exposed,
        publish_all: req.is_some_and(|r| r.publish_all),
        mac_address: req.and_then(|r| r.mac_address.clone()).unwrap_or_default(),
        sandbox_key,
        dns: list(|r| &r.dns),
        dns_search: list(|r| &r.dns_search),
        dns_options: list(|r| &r.dns_options),
        extra_hosts: list(|r| &r.add_hosts),
    })
}

fn process_of(info: &Info) -> typed::ProcessConfig {
    let cfg = &info.cfg;
    let req = info.req();
    let body = info
        .api
        .as_ref()
        .map(|a| &a.body)
        .unwrap_or(&serde_json::Value::Null);
    // what stop sends: the option, the image's, systemd's RTMIN+3
    let stop_signal = if cfg.stop_signal.is_empty() {
        req.map(|r| r.stop_signal.clone()).unwrap_or_default()
    } else {
        cfg.stop_signal.clone()
    };
    typed::ProcessConfig {
        entrypoint: cfg.entrypoint.clone(),
        command: cfg.command.clone(),
        env: cfg.env.clone(),
        work_dir: cfg.working_dir.clone(),
        user: cfg.user.clone(),
        resolved_user: cfg.spec_user.as_ref().map(|u| typed::ProcessUser {
            uid: i64::from(u.uid),
            gid: i64::from(u.gid),
            additional_gids: u.additional_gids.iter().copied().map(i64::from).collect(),
        }),
        hostname: cfg.hostname.clone(),
        domainname: s(body, "Domainname").to_string(),
        stop_signal_number: i64::from(
            lifecycle::parse_signal(if stop_signal.is_empty() {
                "SIGTERM"
            } else {
                &stop_signal
            })
            .unwrap_or(15),
        ),
        stop_signal,
        stop_timeout: i64::from(req.and_then(|r| r.stop_timeout).unwrap_or(10)),
        umask: req
            .and_then(|r| r.umask.clone())
            .unwrap_or_else(|| "0022".into()),
        systemd: cfg.options.systemd,
        init: req.is_some_and(|r| r.init),
        healthcheck: cfg.healthcheck.clone(),
        create_command: req.map(|r| r.create_command.clone()).unwrap_or_default(),
        passwd: !req.is_some_and(|r| r.no_passwd),
        sdnotify_mode: req
            .map(|r| r.sdnotify.as_str())
            .filter(|m| !m.is_empty())
            .unwrap_or("container")
            .to_string(),
    }
}

fn host_of(info: &Info) -> typed::HostSettings {
    let cfg = &info.cfg;
    let req = info.req();
    let res = req.and_then(|r| r.resources.as_ref());
    let mode = |asked: Option<&NsMode>, configured: &str, default: &str| {
        asked
            .filter(|m| **m != NsMode::Default)
            .map(NsMode::to_string)
            .or(Some(configured)
                .filter(|m| !m.is_empty())
                .map(str::to_string))
            .unwrap_or(default.to_string())
    };
    let systemd_path = cfg
        .cgroups_path
        .as_deref()
        .filter(|p| velarx_core::services::cgroups_mode::is_systemd_path(p));
    // As podman: only a parent that is not the default.
    let cgroup_parent = match systemd_path {
        Some(p) => p
            .split(':')
            .next()
            .filter(|s| *s != "machine.slice" && *s != "user.slice")
            .unwrap_or_default()
            .to_string(),
        None => req
            .and_then(|r| r.cgroup_parent.clone())
            .unwrap_or_default(),
    };
    // the driver of the container as it was given (k8s-file by default;
    // json-file is its other name)
    let log_driver = match cfg.log_driver.as_str() {
        "" => "k8s-file",
        d => d,
    };
    let restart = req.and_then(|r| r.restart_policy.as_ref());
    let list = |f: fn(&velarx_wire::request::CreateContainerRequest) -> &Vec<String>| {
        req.map(|r| f(r).clone()).unwrap_or_default()
    };
    typed::HostSettings {
        cgroupns_mode: mode(req.map(|r| &r.cgroupns_mode), "", "private"),
        ipc_mode: mode(req.map(|r| &r.ipc_mode), &cfg.options.ipc_ns, "shareable"),
        pid_mode: mode(req.map(|r| &r.pid_mode), &cfg.options.pid_ns, "private"),
        uts_mode: mode(req.map(|r| &r.uts_mode), &cfg.options.uts_ns, "private"),
        userns_mode: match cfg.userns_mode {
            velarx_runtime::container::UsernsMode::Host => String::new(),
            _ => req
                .map(|r| r.userns_mode.to_string())
                .unwrap_or_else(|| "private".into()),
        },
        // (a container of the engine is in a systemd scope, which the
        // path says: the scope of a command or the one the manager makes)
        cgroup_manager: if systemd_path.is_some()
            || cfg
                .cgroups_path
                .as_deref()
                .is_some_and(|p| velarx_core::services::cgroups_mode::engine_scope_dir(p).is_some())
        {
            "systemd"
        } else {
            "cgroupfs"
        }
        .into(),
        cgroup_parent,
        cgroups: cfg.cgroups.to_string(),
        log_driver: log_driver.into(),
        log_options: cfg
            .log_opts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        log_max_size: cfg
            .log_opts
            .get("max-size")
            .and_then(|v| velarx_config::log_opt_size(v))
            .map_or(0, |n| i64::try_from(n).unwrap_or(i64::MAX)),
        restart_policy: restart.map(|p| p.name.clone()).unwrap_or_default(),
        restart_retries: restart.map_or(0, |p| i64::from(p.maximum_retry_count)),
        auto_remove: cfg.auto_remove,
        auto_remove_image: cfg.auto_remove_image,
        cap_add: cfg.cap_add.clone(),
        cap_drop: cfg.cap_drop.clone(),
        group_add: list(|r| &r.group_add),
        no_new_privileges: cfg.security_opt.no_new_privileges,
        seccomp_profile: cfg.security_opt.seccomp.clone(),
        apparmor_profile: cfg.security_opt.apparmor.clone(),
        read_only_rootfs: cfg.read_only_rootfs,
        shm_size: req
            .and_then(|r| r.shm_size)
            .map_or(64 * 1024 * 1024, |n| i64::try_from(n).unwrap_or(i64::MAX)),
        runtime: cfg.runtime_name.clone().unwrap_or_default(),
        ulimits: req
            .map(|r| {
                r.ulimits
                    .iter()
                    .map(|u| typed::Ulimit {
                        name: u.name.clone(),
                        soft: u.soft as i64,
                        hard: u.hard as i64,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        pids_limit: cfg.pids_limit.unwrap_or(0),
        blkio_weight: res.and_then(|r| r.blkio_weight).map_or(0, i64::from),
        memory_reservation: res.and_then(|r| r.memory_reservation).unwrap_or(0),
        oom_kill_disable: req.is_some_and(|r| r.oom_kill_disable),
        hosts_file: req.and_then(|r| r.hosts_file.clone()).unwrap_or_default(),
        devices: req
            .map(|r| {
                r.devices
                    .iter()
                    .map(|d| typed::DeviceSpec {
                        host_path: d.path_on_host.clone(),
                        container_path: d.path_in_container.clone(),
                        permissions: d.cgroup_permissions.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        blkio_device_read_bps: throttles(res.map(|r| &r.blkio_device_read_bps)),
        blkio_device_write_bps: throttles(res.map(|r| &r.blkio_device_write_bps)),
        blkio_device_read_iops: throttles(res.map(|r| &r.blkio_device_read_iops)),
        blkio_device_write_iops: throttles(res.map(|r| &r.blkio_device_write_iops)),
        blkio_weight_device: res
            .map(|r| {
                r.blkio_weight_device
                    .iter()
                    .map(|w| typed::DeviceLimit {
                        path: w.path.clone(),
                        value: u64::from(w.weight),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// The limits of the block devices of a request.
fn throttles(list: Option<&Vec<velarx_wire::request::ThrottleDevice>>) -> Vec<typed::DeviceLimit> {
    list.into_iter()
        .flatten()
        .map(|t| typed::DeviceLimit {
            path: t.path.clone(),
            value: t.rate,
        })
        .collect()
}

fn resources_of(info: &Info) -> typed::Resources {
    let res = info.req().and_then(|r| r.resources.as_ref());
    let int = |v: Option<u64>| v.map_or(0, |n| i64::try_from(n).unwrap_or(i64::MAX));
    typed::Resources {
        memory_limit: res.and_then(|r| r.memory).unwrap_or(0),
        memory_swap: res.and_then(|r| r.memory_swap).unwrap_or(0),
        cpu_period: int(res.and_then(|r| r.cpu_period)),
        cpu_quota: res.and_then(|r| r.cpu_quota).unwrap_or(0),
        cpu_shares: int(res.and_then(|r| r.cpu_shares)),
        cpuset_cpus: res.and_then(|r| r.cpuset_cpus.clone()).unwrap_or_default(),
        cpuset_mems: res.and_then(|r| r.cpuset_mems.clone()).unwrap_or_default(),
        oom_score_adj: info.cfg.oom_score_adj.map_or(0, i64::from),
        unified: res
            .and_then(|r| r.cgroup_conf.as_ref())
            .map(|c| c.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default(),
        hugepage_limits: res
            .map(|r| {
                r.hugepage_limits
                    .iter()
                    .map(|h| typed::HugepageLimit {
                        page_size: h.page_size.clone(),
                        limit: h.limit,
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn paths_of(info: &Info, state: &AppState, log_driver: &str) -> typed::ContainerPaths {
    use velarx_core::services::{ETC_HOSTNAME, ETC_HOSTS, ETC_RESOLV, MONITOR_PID_FILE};
    let id = &info.rec.id;
    let bundle = state
        .container_service
        .bundle_dir(id)
        .to_string_lossy()
        .to_string();
    // (podman writes the files of the container when it initializes it)
    let made = info.status.state != typed::RunState::Created;
    let file = |name: &str| format!("{bundle}/{name}");
    let generated = |name: &str| if made { file(name) } else { String::new() };
    let mon = state.container_service.mon_dir(id);
    let path = |p: std::path::PathBuf| p.to_string_lossy().into_owned();
    let driver = state.container_service.storage();
    let writable = state.container_service.writable(id);
    typed::ContainerPaths {
        oci_config: file("config.json"),
        // (none for a container that keeps the one of its image)
        resolv_conf: if info
            .req()
            .is_some_and(velarx_core::services::keeps_image_resolv_conf)
        {
            String::new()
        } else {
            generated(ETC_RESOLV)
        },
        hostname: generated(ETC_HOSTNAME),
        // no /etc/hosts is made with no_hosts
        hosts: if info.req().is_some_and(|r| r.no_hosts) {
            String::new()
        } else {
            generated(ETC_HOSTS)
        },
        // the files of --conmon-pidfile and --pidfile, else the monitor's
        // own (podman always shows a path)
        monitor_pid_file: info
            .cfg
            .conmon_pid_file
            .clone()
            .unwrap_or_else(|| path(mon.join(MONITOR_PID_FILE))),
        pid_file: info
            .cfg
            .pid_file
            .clone()
            .unwrap_or_else(|| path(mon.join(velarx_wire::monitor::proto::PID_FILE))),
        log: if matches!(log_driver, "k8s-file" | "json-file") {
            path(super::logs::log_path(&state.container_service.log_dir(id)))
        } else {
            String::new()
        },
        graph_driver: driver.graph_name().to_string(),
        graph_data: driver.graph_data(&writable).into_iter().collect(),
        bundle,
    }
}

fn checkpoint_of(cp: &velarx_wire::wire::CheckpointRecord) -> typed::CheckpointState {
    let path = cp.path.as_ref();
    typed::CheckpointState {
        checkpointed: cp.checkpointed,
        checkpointed_ns: cp.checkpointed_at.as_deref().map_or(0, record_time_ns),
        path: path.map(|p| p.display().to_string()).unwrap_or_default(),
        log_path: path
            .map(|p| p.join("dump.log").display().to_string())
            .unwrap_or_default(),
        restored: cp.restored,
        restored_ns: cp.restored_at.as_deref().map_or(0, record_time_ns),
    }
}

/// The state of the runtime a record's state stands for, without asking the
/// runtime (`stopped`, `configured` and `removing` have none of their own).
pub(crate) fn run_state_of(state: RecordState) -> typed::RunState {
    match state {
        RecordState::Created => typed::RunState::Created,
        RecordState::Initialized => typed::RunState::Initialized,
        RecordState::Running => typed::RunState::Running,
        RecordState::Paused => typed::RunState::Paused,
        RecordState::Stopping => typed::RunState::Stopping,
        RecordState::Exited => typed::RunState::Exited,
        RecordState::Configured
        | RecordState::Stopped
        | RecordState::Removing
        | RecordState::Unknown => typed::RunState::Unknown,
    }
}

/// The annotations of a container: those of its create and those podman
/// records of its options.
pub(crate) fn podman_annotations(info: &Info) -> BTreeMap<String, String> {
    let req = info.req();
    let mut annotations: BTreeMap<String, String> = info.annotations().into_iter().collect();
    for (on, key) in [
        (info.cfg.privileged, "io.podman.annotations.privileged"),
        (info.cfg.auto_remove, "io.podman.annotations.autoremove"),
        (req.is_some_and(|r| r.init), "io.podman.annotations.init"),
    ] {
        if on {
            annotations.insert(key.into(), "TRUE".into());
        }
    }
    annotations
}

/// [`podman_annotations`] and the others podman records in the spec of a
/// container, as inspect shows them.
fn inspect_annotations(info: &Info) -> BTreeMap<String, String> {
    let mut annotations = podman_annotations(info);
    if info.cfg.auto_remove_image {
        annotations.insert(
            "io.podman.annotations.autoremove-image".into(),
            "TRUE".into(),
        );
    }
    if let Some(f) = &info.cfg.cid_file {
        annotations.insert("io.podman.annotations.cid-file".into(), f.clone());
    }
    if let Some(req) = info.req() {
        annotations.extend(velarx_core::services::podman_security_annotations(
            &req.security_opts,
        ));
    }
    annotations
}

/// The record of the container `info` is of.
pub fn record(
    info: &Info,
    state: &AppState,
) -> Result<typed::ContainerRecord, velarx_base::ids::IdsError> {
    let cfg = &info.cfg;
    let st = &info.status;
    let alive = matches!(st.state, typed::RunState::Running | typed::RunState::Paused);
    // the pid of the monitor, podman's conmon, while it runs (never 0 for
    // a container that runs: scripts `kill` it)
    let monitor_pid = if alive {
        let mon = state.container_service.mon_dir(&info.rec.id);
        std::fs::read_to_string(mon.join(velarx_core::services::MONITOR_PID_FILE))
            .ok()
            .and_then(|p| p.trim().parse::<i64>().ok())
            .filter(|p| *p > 0)
            .unwrap_or(0)
    } else {
        0
    };
    let host = host_of(info);
    let paths = paths_of(info, state, &host.log_driver);
    let policy = cfg.restart_policy.as_ref().map(|p| p.policy.word());
    let (pod_id, pod_name, is_infra) = match &info.pod {
        Some(p) => (p.id.clone(), p.name.clone(), p.is_infra),
        None => Default::default(),
    };
    Ok(typed::ContainerRecord {
        id: info.rec.id.clone(),
        name: info.name(),
        pid: i64::from(st.pid),
        pod_id,
        pod_name,
        image: info.image_name(),
        image_id: info.image_id(),
        image_digest: info
            .image
            .as_ref()
            // (a root file system that is a directory has no image)
            .filter(|i| i.id != velarx_db::ROOTFS_IMAGE_ID)
            .map(|i| i.manifest_digest.to_string())
            .unwrap_or_default(),
        image_ref: cfg.image.clone(),
        labels: cfg
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        annotations: inspect_annotations(info),
        created_ns: info.created_ns(),
        started_ns: st.started_ns,
        finished_ns: st.finished_ns,
        state: st.state,
        exit_code: st.exit_code,
        oom_killed: info.oom_killed,
        timed_out: info.timed_out,
        stopped_by_user: info.stopped_by_user,
        restart_count: i64::from(info.restart_count),
        should_start_on_boot: velarx_core::services::boot::should_start_on_boot(
            policy,
            info.stopped_by_user,
        ),
        error: if info.timed_out {
            "the container was killed at the end of its time limit (--timeout)".into()
        } else {
            String::new()
        },
        is_infra,
        monitor_pid,
        health: info.health.clone(),
        checkpoint: checkpoint_of(&info.checkpoint),
        tty: cfg.tty,
        stdin: cfg.stdin_open,
        privileged: cfg.privileged,
        oci_runtime: cfg
            .runtime_name
            .clone()
            .unwrap_or_else(velarx_runtime::container::runtime_name),
        process: process_of(info),
        host,
        resources: resources_of(info),
        network: network_of(info)?,
        mounts: mounts_of(info, &state.config.server),
        paths,
        cgroup_path: cgroup_path(st.pid),
        size_rw: None,
        size_root_fs: None,
        namespaces: BTreeMap::new(),
    })
}

/// The cgroup of a running process (`/proc/PID/cgroup`, cgroup v2), ""
/// when it does not run.
fn cgroup_path(pid: i32) -> String {
    if pid <= 0 {
        return String::new();
    }
    velarx_base::cgroup::of_process(Some(pid)).unwrap_or_default()
}

/// The namespaces of a process, by the links of /proc/PID/ns, with
/// libpod's keys (none for a container that does not run).
pub(crate) fn namespaces_of(pid: i64) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    if pid <= 0 {
        return m;
    }
    for (key, link) in [
        ("Cgroup", "cgroup"),
        ("Ipc", "ipc"),
        ("Mnt", "mnt"),
        ("Net", "net"),
        ("Pidns", "pid"),
        ("Uts", "uts"),
        ("User", "user"),
    ] {
        if let Ok(t) = std::fs::read_link(format!("/proc/{pid}/ns/{link}")) {
            let t = t.to_string_lossy();
            if let Some(n) = t.split_once('[').and_then(|(_, r)| r.strip_suffix(']')) {
                m.insert(key.into(), n.to_string());
            }
        }
    }
    m
}

/// The record with what the OCI configuration of the container gives its
/// process: its labels, its capabilities, its limits.  A container that has
/// no configuration yet keeps what it was asked.
pub(crate) async fn with_spec(
    state: &AppState,
    mut c: typed::ContainerRecord,
) -> typed::ContainerRecord {
    let path = state
        .container_service
        .bundle_dir(&c.id)
        .join("config.json");
    let Ok(text) = tokio::fs::read_to_string(&path).await else {
        return c;
    };
    let Ok(spec) = serde_json::from_str::<serde_json::Value>(&text) else {
        return c;
    };
    spec_into(&spec, &mut c.host);
    c
}

fn spec_into(spec: &serde_json::Value, host: &mut typed::HostSettings) {
    let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
    let list = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().map(&text).collect())
            .unwrap_or_default()
    };
    let process = &spec["process"];
    host.process_label = text(&process["selinuxLabel"]);
    host.mount_label = text(&spec["linux"]["mountLabel"]);
    host.process_apparmor = text(&process["apparmorProfile"]);
    // (sorted, as podman's)
    host.effective_caps = list(&process["capabilities"]["effective"]);
    host.effective_caps.sort();
    host.bounding_caps = list(&process["capabilities"]["bounding"]);
    host.bounding_caps.sort();
    // the limits the process has: the defaults of the runtime and what
    // `--ulimit` asked (an unlimited one, u64::MAX, is -1 as podman's
    // int64 of it)
    let number = |v: &serde_json::Value| {
        v.as_i64()
            .or_else(|| v.as_u64().map(|u| u as i64))
            .unwrap_or_default()
    };
    let limits: Vec<typed::Ulimit> = process["rlimits"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|l| typed::Ulimit {
                    name: text(&l["type"]),
                    soft: number(&l["soft"]),
                    hard: number(&l["hard"]),
                })
                .collect()
        })
        .unwrap_or_default();
    if !limits.is_empty() {
        // (podman's order: those `--ulimit` asked first, then the defaults
        // of the runtime)
        let rank = |l: &typed::Ulimit| {
            host.ulimits
                .iter()
                .position(|u| {
                    let n = u.name.to_ascii_uppercase();
                    l.name == n || l.name.strip_prefix("RLIMIT_") == Some(n.as_str())
                })
                .unwrap_or(usize::MAX)
        };
        let mut limits = limits;
        limits.sort_by_key(rank);
        host.ulimits = limits;
    }
}

/// The record with the size of its changes, and of them and its image.
/// `images`: the sizes of the images already read, which a listing of many
/// containers of one image reads once.
pub(crate) async fn with_size(
    state: &AppState,
    mut c: typed::ContainerRecord,
    image_id: &str,
    images: &mut HashMap<String, i64>,
) -> ApiResult<typed::ContainerRecord> {
    let rw = super::archive::upper_size(state, &c.id).await;
    let image = match images.get(image_id) {
        Some(size) => *size,
        None => {
            let size = super::images::image_size(state, image_id).await?;
            images.insert(image_id.to_string(), size);
            size
        }
    };
    c.size_rw = Some(rw);
    c.size_root_fs = Some(rw + image);
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A container whose image is gone has none; an image that cannot be
    /// read fails the inspect (it is not taken for a gone one).
    #[tokio::test]
    async fn a_failed_read_of_the_image_fails_the_container() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        let config = serde_json::to_string(&velarx_runtime::container::ContainerConfig {
            id: "c1".into(),
            ..Default::default()
        })
        .unwrap();
        test_store::container(&state, "c1", "img-a", &config).await;
        let rec = state.db.get_container("c1").await.unwrap();
        assert!(load(&state, rec.clone()).await.is_ok());
        test_store::alter(&state, "ALTER TABLE images RENAME TO gone");
        let Err(e) = load(&state, rec).await else {
            panic!("a container whose image cannot be read must fail");
        };
        assert!(
            e.message.contains("reading the image of a container"),
            "{}",
            e.message
        );
    }

    /// The listing of the containers of one image reads the image once: the
    /// size it has read is kept, and a second container of it needs no read.
    #[tokio::test]
    async fn the_size_of_an_image_is_read_once_for_a_listing() {
        use crate::api::podman::test_store;
        let dir = tempfile::tempdir().unwrap();
        let state = test_store::state_in(dir.path()).await;
        test_store::image(&state, "img-a").await;
        let record = || typed::ContainerRecord {
            id: "c1".into(),
            ..Default::default()
        };
        let mut sizes = HashMap::new();
        with_size(&state, record(), "img-a", &mut sizes)
            .await
            .unwrap();
        assert!(sizes.contains_key("img-a"));
        // (the images cannot be read any more: the one read is used)
        test_store::alter(&state, "ALTER TABLE images RENAME TO gone");
        assert!(with_size(&state, record(), "img-a", &mut sizes)
            .await
            .is_ok());
        assert!(with_size(&state, record(), "img-a", &mut HashMap::new())
            .await
            .is_err());
    }

    #[test]
    fn the_spec_gives_labels_caps_and_limits() {
        let spec = serde_json::json!({
            "process": {
                "selinuxLabel": "system_u:system_r:container_t:s0:c1,c2",
                "apparmorProfile": "velarx-default",
                "capabilities": {"effective": ["CAP_CHOWN"], "bounding": ["CAP_KILL", "CAP_CHOWN"]},
                "rlimits": [{"type": "RLIMIT_NOFILE", "soft": 1024, "hard": 4096},
                            {"type": "RLIMIT_CORE", "soft": u64::MAX, "hard": u64::MAX}],
            },
            "linux": {"mountLabel": "system_u:object_r:container_file_t:s0:c1,c2"},
        });
        let mut host = typed::HostSettings {
            ulimits: vec![typed::Ulimit {
                name: "core".into(),
                soft: 0,
                hard: 0,
            }],
            ..Default::default()
        };
        spec_into(&spec, &mut host);
        assert_eq!(host.process_label, "system_u:system_r:container_t:s0:c1,c2");
        assert_eq!(
            host.mount_label,
            "system_u:object_r:container_file_t:s0:c1,c2"
        );
        assert_eq!(host.process_apparmor, "velarx-default");
        assert_eq!(host.effective_caps, ["CAP_CHOWN"]);
        assert_eq!(host.bounding_caps, ["CAP_CHOWN", "CAP_KILL"]);
        // (`core` was asked: first)
        assert_eq!(
            (host.ulimits[1].name.as_str(), host.ulimits[1].soft),
            ("RLIMIT_NOFILE", 1024)
        );
        // unlimited: -1, as podman's
        assert_eq!(host.ulimits[0].name, "RLIMIT_CORE");
        assert_eq!((host.ulimits[0].soft, host.ulimits[0].hard), (-1, -1));
        // what --ulimit asked comes first, as podman's
        let spec = serde_json::json!({"process": {"rlimits": [
            {"type": "RLIMIT_NPROC", "soft": 10, "hard": 10},
            {"type": "RLIMIT_CPU", "soft": 1, "hard": 2},
        ]}});
        let mut host = typed::HostSettings {
            ulimits: vec![typed::Ulimit {
                name: "cpu".into(),
                soft: 1,
                hard: 2,
            }],
            ..Default::default()
        };
        spec_into(&spec, &mut host);
        assert_eq!(host.ulimits[0].name, "RLIMIT_CPU");
        assert_eq!(host.ulimits[1].name, "RLIMIT_NPROC");
        // a spec without limits keeps what was asked
        let mut host = typed::HostSettings {
            ulimits: vec![typed::Ulimit::default()],
            ..Default::default()
        };
        spec_into(&serde_json::json!({}), &mut host);
        assert_eq!(host.ulimits.len(), 1);
        assert!(host.effective_caps.is_empty() && host.process_label.is_empty());
    }

    #[test]
    fn the_files_of_the_engine_are_not_listed() {
        let m = |target: &str, engine: bool| MountConfig {
            target: target.into(),
            engine,
            ..Default::default()
        };
        let all = [
            m("/etc/hosts", true),
            m("/data", false),
            m("/run/podman-init", true),
        ];
        let listed: Vec<&str> = user_mounts(&all).map(|m| m.target.as_str()).collect();
        assert_eq!(listed, ["/data"]);
    }

    #[test]
    fn the_propagation_of_a_bind() {
        let o = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(propagation_of(&o(&[])), "rprivate");
        assert_eq!(propagation_of(&o(&["ro", "shared"])), "shared");
        assert_eq!(propagation_of(&o(&["rslave", "private"])), "private");
    }
}
