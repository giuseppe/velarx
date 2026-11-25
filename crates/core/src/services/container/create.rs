// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::container::PinnedImage;
use velarx_proto::health::{Healthcheck, OnFailure};

/// What a create that fails halfway made and must undo.  The cleanup is
/// async, so it cannot be a `Drop`.
#[derive(Default)]
pub(super) struct CreateUndo {
    /// The volumes made for a container that was not created.
    volumes: Vec<String>,
    /// The bundle and the writable layer.
    writable: Option<Writable>,
    providers: Providers,
}

/// The network providers that made interfaces for a container.
#[derive(Default)]
pub(super) struct Providers {
    /// The container.
    id: String,
    names: Vec<String>,
}

impl CreateUndo {
    async fn rollback(self, svc: &ContainerService) {
        // The network the providers made for a container that was not
        // created (its address among it).
        svc.network_providers
            .stop(&self.providers.names, &self.providers.id)
            .await;
        if let Some(writable) = self.writable {
            // What a create that failed halfway mounted and made.
            let (driver, b) = (svc.storage().clone(), writable.bundle().to_path_buf());
            let _ = crate::off_thread(move || {
                if !velarx_runtime::settle::mounts::detach_mounts_below(&b) {
                    warn!("{} stays mounted: the bundle is kept", b.display());
                } else {
                    if let Err(e) = driver.writable_remove(&writable) {
                        warn!("Cannot remove the writable layer of {}: {e}", writable.id());
                    }
                    match velarx_base::tree::remove_dir_all_confined(&b) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => warn!("Cannot remove {}: {e}", b.display()),
                    }
                }
                Ok(())
            })
            .await;
        }
        // The volumes made for a container that was not created.
        for v in self.volumes {
            if let Err(e) = svc.volume_service.remove(&v, true).await {
                warn!("Could not remove the volume {v} of a failed create: {e}");
            }
        }
    }
}

/// How many attempts a create makes when its SELinux level is taken by
/// another create at the same time: each picks a level again.
const LEVEL_ATTEMPTS: u32 = 8;

/// Run `attempt` (which undoes what it made when it fails) until it does
/// not fail with a taken SELinux level, at most `LEVEL_ATTEMPTS` times.
/// The store is locked shared: creates run at the same time and one may
/// record the level another chose.  That is rare and the next pick is
/// another level, so the create is made again, from nothing.
async fn retry_on_level_taken<T, F, Fut>(mut attempt: F) -> ContainerResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ContainerResult<T>>,
{
    for _ in 0..LEVEL_ATTEMPTS {
        match attempt().await {
            Err(ContainerError::Database(velarx_types::DbError::LevelTaken(_))) => {}
            result => return result,
        }
    }
    Err(ContainerError::LevelsTaken(LEVEL_ATTEMPTS))
}

impl ContainerService {
    pub async fn create(
        self: &Arc<Self>,
        mut req: CreateContainerRequest,
    ) -> ContainerResult<String> {
        velarx_base::trace::point("create start");
        if let Some(name) = &req.name {
            let bare = name.strip_prefix('/').unwrap_or(name);
            if !valid_container_name(bare) {
                return Err(ContainerError::InvalidArgument(
                    "running container create option: names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*: invalid argument"
                        .into(),
                ));
            }
            req.name = Some(bare.to_string());
        }
        // (`[containers] cgroups` of the configuration; an explicit mode wins,
        // and the RUN containers of a build do not take it: buildah does not)
        if req.cgroups.is_unset() && !req.labels.contains_key(crate::services::build::BUILD_LABEL) {
            req.cgroups = self.default_cgroups;
        }
        self.resolve_cgroups(
            &mut req.cgroups,
            &mut req.cgroup_mode,
            req.cgroup_parent.as_deref(),
        )
        .map_err(ContainerError::InvalidArgument)?;
        let _store = self.lock_store().await?;
        let image_name = req.image.clone();
        let result = retry_on_level_taken(|| async {
            let mut undo = CreateUndo::default();
            // (boxed: the future of a create is large, and the stack of a
            // thread that polls it is not)
            let result = Box::pin(self.create_inner(req.clone(), &mut undo)).await;
            if result.is_err() {
                undo.rollback(self).await;
            }
            result
        })
        .await;
        // (a storage error: if a layer of the image lost its EROFS image, the
        // layer is marked incomplete and the error says so; only this path
        // looks)
        let result = match result {
            Err(ContainerError::Image(velarx_types::ImageError::Storage(why))) => Err(self
                .damaged_image(&image_name)
                .await
                .unwrap_or(ContainerError::Image(velarx_types::ImageError::Storage(
                    why,
                )))),
            other => other,
        };
        if let Ok(id) = &result {
            self.notify_action_of(id, "create", Vec::new()).await;
        }
        velarx_base::trace::point("create end");
        result
    }

    pub(super) async fn create_inner(
        self: &Arc<Self>,
        req: CreateContainerRequest,
        undo: &mut CreateUndo,
    ) -> ContainerResult<String> {
        // The id names the bundle and is the runtime's last argument: only
        // the form the engine makes.
        if let Some(id) = &req.id {
            if !valid_container_id(id) {
                return Err(ContainerError::InvalidArgument(format!(
                    "invalid container id {id:?}: 64 lowercase hexadecimal digits"
                )));
            }
        }
        // the engine's own way to talk to CRIU
        if let Some(k) = req.annotations.keys().find(|k| k.starts_with("org.criu.")) {
            return Err(ContainerError::InvalidArgument(format!(
                "the annotation {k} is the engine's"
            )));
        }

        if let Some(mode) = dns_conflict(&req) {
            return Err(ContainerError::InvalidArgument(format!(
                "conflicting options: dns and the network mode: {mode}"
            )));
        }
        let network_mode = req.network_mode.clone();

        let mut rootfs_dir = req
            .rootfs
            .then(|| crate::container::RootfsDir::parse(&req.image))
            .transpose()
            .map_err(ContainerError::InvalidArgument)?;
        let image = if rootfs_dir.is_some() {
            self.rootfs_image().await?
        } else {
            let (image, staged) = self.image_for_create(&req).await?;
            velarx_base::trace::point("create image");
            // the signature policy of now
            let judging = self.signature_judging(&req.security_opt, &req.security_opts)?;
            match &staged {
                Some(pull) => {
                    self.image_service
                        .verify_staged(&req.image, pull, judging)
                        .await?
                }
                None => {
                    let tags = self.image_service.get_tags(&image.id).await?;
                    self.image_service
                        .verify_stored(&req.image, &image, &tags, judging)
                        .await?
                }
            }
            velarx_base::trace::point("create signatures");
            if image.is_lazy {
                // (the monitor of the container fetches the files, the ones
                // the container asks for first, and the pull is completed
                // in the background)
                info!("Running with an image being pulled: files will be fetched on-demand");
            }
            // (the program of the container and what its loader reads come
            // while the container is made)
            if let Some(pull) = &staged {
                let config: velarx_types::OciConfig = serde_json::from_str(&image.config)?;
                let (entrypoint, command) = process_args(&req, &config.config);
                if let Some(program) = entrypoint.into_iter().chain(command).next() {
                    let path = (req.env.iter().chain(&config.config.env))
                        .find_map(|e| e.strip_prefix("PATH="))
                        .map(str::to_string);
                    self.image_service.fetch_program(pull, program, path);
                }
            }
            image
        };

        let container_id = req
            .id
            .clone()
            .or_else(super::super::scope::early_id)
            .unwrap_or_else(new_id);

        if self.db.get_container(&container_id).await.is_ok() {
            return Err(ContainerError::AlreadyExists(format!(
                "container already exists: {container_id}"
            )));
        }

        if let Some(name) = &req.name {
            if let Ok(old) = self.db.get_container(name).await {
                if !req.replace {
                    return Err(ContainerError::AlreadyExists(format!(
                        "creating container storage: the container name \"{name}\" is already in use by {}. You have to remove that container to be able to reuse that name: that name is already in use",
                        old.id
                    )));
                }
                info!("Replacing the container {name}");
                self.delete(name, true).await?;
            }
        }

        // (the images of the layers say what a container needs)
        let layers = if rootfs_dir.is_some() {
            Vec::new()
        } else {
            self.image_layers(&image).await?
        };

        // The image is read through one view for the whole create (a mount
        // of it for a driver that has no tables of contents to read), dropped
        // when the create ends.
        let _image_view = (rootfs_dir.is_none() && !layers.is_empty())
            .then(|| self.image_view(&layers))
            .transpose()?;

        // The user namespace: its mappings, and a range reserved until the
        // container is in the database.
        let image_max_id = if matches!(req.userns_mode, UsernsChoice::Auto(_)) {
            self.image_max_id(&layers)?
        } else {
            0
        };
        let mut userns = self
            .userns_manager
            .resolve(&UsernsRequest {
                mode: req.userns_mode.clone(),
                uidmap: req.uidmap.clone(),
                gidmap: req.gidmap.clone(),
                uid_mappings: req.uid_mappings.clone(),
                gid_mappings: req.gid_mappings.clone(),
                subuidname: req.subuidname.clone(),
                subgidname: req.subgidname.clone(),
                image_max_id,
            })
            .await?;
        let mut userns_path = None;
        let userns_mode = match &userns.spec {
            UsernsSpec::Host => UsernsMode::Host,
            UsernsSpec::Container(target) => {
                let (path, uid, gid) = self.userns_of_container(target).await?;
                (userns.uid_mappings, userns.gid_mappings) = (uid, gid);
                userns_path = Some(path);
                UsernsMode::Container(target.clone())
            }
            UsernsSpec::Ns(path) => {
                let (uid, gid) = crate::userns::maps_of_namespace(path)?;
                (userns.uid_mappings, userns.gid_mappings) = (uid, gid);
                userns_path = Some(path.clone());
                UsernsMode::Path(path.clone())
            }
            _ if userns.mode == "custom" => UsernsMode::Custom,
            _ => UsernsMode::Private,
        };
        let (uid_mappings, gid_mappings) =
            (userns.uid_mappings.clone(), userns.gid_mappings.clone());
        let id_maps = IdMaps {
            uid: &uid_mappings,
            gid: &gid_mappings,
        };
        if let Some(dir) = rootfs_dir.as_mut() {
            if let Some(opt) = dir.idmap.clone() {
                if uid_mappings.is_empty() {
                    return Err(ContainerError::InvalidArgument(
                        "the idmap option of the rootfs needs a user namespace (--userns or --uidmap)"
                            .into(),
                    ));
                }
                let invalid = |e: velarx_base::idmap::IdMapError| {
                    ContainerError::InvalidArgument(e.to_string())
                };
                let (u, g) =
                    velarx_base::idmap::parse_mount_idmap(&opt, &uid_mappings, &gid_mappings)
                        .map_err(invalid)?;
                velarx_base::idmap::validate(&u).map_err(invalid)?;
                velarx_base::idmap::validate(&g).map_err(invalid)?;
                (dir.uid_mappings, dir.gid_mappings) = (u, g);
            }
        }
        velarx_base::trace::point("create userns");
        let mut req = req;
        for d in &req.chroot_dirs {
            let clean = d.starts_with('/')
                && Path::new(d)
                    .components()
                    .all(|c| !matches!(c, std::path::Component::ParentDir));
            if !clean {
                return Err(ContainerError::InvalidArgument(format!(
                    "--chrootdirs {d:?}: an absolute path without .. is expected"
                )));
            }
        }
        if let Some(f) = req.hosts_file.as_deref() {
            if !matches!(f, "" | "none" | "image") {
                if !f.starts_with('/') {
                    return Err(ContainerError::InvalidArgument(format!(
                        "--hosts-file {f:?}: it is an absolute path, \"none\" or \"image\""
                    )));
                }
                if !Path::new(f).is_file() {
                    return Err(ContainerError::InvalidArgument(format!(
                        "--hosts-file {f:?}: not a file"
                    )));
                }
            }
        }
        // keep-id: the user of the host, unless one is given
        let keep_id_user = userns.user.filter(|_| req.user.is_empty());
        if let Some((uid, gid)) = keep_id_user {
            req.user = format!("{uid}:{gid}");
        }

        let image_config: velarx_types::OciConfig = serde_json::from_str(&image.config)?;
        let stop_signal_valid = super::super::lifecycle::parse_signal(&req.stop_signal).is_some();
        if !req.stop_signal.is_empty() && !stop_signal_valid {
            return Err(ContainerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid stop signal: {}", req.stop_signal),
            )));
        }

        if req.publish_all {
            publish_exposed(&mut req, image_config.config.exposed_ports.keys())?;
        }

        // What can be checked before anything is made.
        req.user = effective_user(&req.user, &image_config.config.user);
        let umask = req
            .umask
            .as_deref()
            .map(crate::container::userspec::parse_umask)
            .transpose()?;
        crate::container::userspec::keep_groups(&req.group_add)?;
        let localtime = match req.timezone.as_deref() {
            Some(zone) => Some((zone.to_string(), read_zoneinfo(zone)?)),
            None => None,
        };

        let gathered = self
            .gather_mounts(
                &req,
                &container_id,
                &image_config.config.volumes,
                &mut undo.volumes,
            )
            .await?;

        for entry in &req.add_hosts {
            crate::services::network::parse_extra_host(entry)
                .map_err(ContainerError::InvalidArgument)?;
        }
        // podman's default hostname: the short id, the host's for a
        // container that shares the host's UTS namespace or network
        let hostname = if req.hostname.is_empty()
            && (req.uts_mode == NsMode::Host || req.has_network_mode(&NetworkMode::Host))
        {
            fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|h| h.trim().to_string())
                .unwrap_or_default()
        } else if req.hostname.is_empty() {
            container_id.chars().take(12).collect()
        } else {
            req.hostname.clone()
        };
        let mut env = velarx_wire::options::merge_env(&velarx_wire::options::EnvSources {
            image: &image_config.config.env,
            user: &req.env,
            merge: &req.env_merge,
            unset: &req.unsetenv,
            unset_all: req.unsetenv_all,
            tty: req.tty,
            hostname: &hostname,
        });
        let mut mounts = gathered;
        if req.sdnotify == "container" {
            // The monitor forwards what the container sends to this socket.
            mounts.push(MountConfig {
                source: self
                    .mon_dir(&container_id)
                    .join(velarx_wire::monitor::proto::NOTIFY_DIR)
                    .to_string_lossy()
                    .into_owned(),
                target: "/run/notify".to_string(),
                mount_type: Some("bind".to_string()),
                options: vec!["rbind".into(), "rw".into(), "nosuid".into(), "nodev".into()],
                engine: true,
                ..Default::default()
            });
            env.push(format!(
                "NOTIFY_SOCKET=/run/notify/{}",
                velarx_wire::monitor::proto::NOTIFY_SOCKET
            ));
        }

        let (mut entrypoint, mut command) = process_args(&req, &image_config.config);
        if entrypoint.is_empty() && command.is_empty() {
            // (as podman's: the container is made, and the runtime says that
            // it cannot run it when it starts)
            command = vec![String::new()];
        }

        if req.init {
            use crate::container::{InitConfig, InitManager, InitSystem};

            let init_config = if let Some(ref path) = req.init_path {
                InitConfig {
                    system: InitSystem::Custom,
                    custom_path: Some(std::path::PathBuf::from(path)),
                    ..Default::default()
                }
            } else {
                InitConfig::default()
            };

            // (asked for: no init binary is an error, not a container
            // without init; podman's words)
            let Some(init_path) = init_config.init_path() else {
                return Err(ContainerError::InvalidArgument(
                    "container-init binary not found on the host: none of catatonit, tini or \
                     dumb-init is installed; give one with --init-path"
                        .into(),
                ));
            };
            let mut full_cmd = entrypoint.clone();
            full_cmd.extend(command.clone());
            // The binary of the host, bound read only where podman
            // binds it (the image does not have it)
            const INIT_TARGET: &str = "/run/podman-init";
            let source = std::fs::canonicalize(&init_path).map_err(|e| {
                ContainerError::InvalidArgument(format!(
                    "container-init binary not found on the host: {}: {e}",
                    init_path.display()
                ))
            })?;
            mounts.push(MountConfig {
                source: source.to_string_lossy().into_owned(),
                target: INIT_TARGET.into(),
                mount_type: Some("bind".into()),
                options: vec!["bind".into(), "ro".into(), "nosuid".into(), "nodev".into()],
                engine: true,
                ..Default::default()
            });
            entrypoint = vec![INIT_TARGET.to_string()];

            let init_manager = InitManager::new(init_config);
            command = init_manager.build_args(&full_cmd);

            info!("Using init process: {:?} {:?}", entrypoint, command);
        }

        for p in [&req.pidfile, &req.conmon_pidfile].into_iter().flatten() {
            // the monitor writes them: no relative path, which would be
            // its directory's
            if !p.starts_with('/') || p.contains('\0') || p.ends_with('/') {
                return Err(ContainerError::InvalidArgument(format!(
                    "the pid file `{p}` is not an absolute file path"
                )));
            }
        }

        // systemd as the init (--systemd): podman's detection on the
        // command as it runs
        let argv: Vec<String> = entrypoint.iter().chain(&command).cloned().collect();
        let systemd = velarx_wire::options::systemd_mode(req.systemd.as_deref(), &argv)
            .map_err(ContainerError::InvalidArgument)?;
        if systemd && !env.iter().any(|e| e.starts_with("container_uuid=")) {
            // what systemd takes as the machine id of the container
            env.push(format!(
                "container_uuid={}",
                container_id.chars().take(32).collect::<String>()
            ));
        }

        let working_dir = if req.working_dir.is_empty() {
            if image_config.config.working_dir.is_empty() {
                "/".to_string()
            } else {
                image_config.config.working_dir.clone()
            }
        } else {
            req.working_dir.clone()
        };

        velarx_base::trace::point("create checks");
        let mut so = req.security_opt.clone();
        for o in &req.security_opts {
            so.apply(o).map_err(ContainerError::InvalidArgument)?;
        }
        match req.seccomp_policy.as_deref() {
            None | Some("" | "default") => {}
            // as podman's: the label wins over --security-opt seccomp=
            Some("image") => {
                let profile = image_config
                    .config
                    .labels
                    .get("io.containers.seccomp.profile")
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| {
                        ContainerError::InvalidArgument(
                            "no seccomp policy defined by image".to_string(),
                        )
                    })?;
                // (the label is the profile itself, as podman's LoadProfile
                // takes it: never a path of the engine's or `unconfined`)
                if !profile.trim_start().starts_with('{') {
                    return Err(ContainerError::InvalidArgument(
                        "loading seccomp profile failed: the label io.containers.seccomp.profile \
                         of the image is not a JSON profile"
                            .to_string(),
                    ));
                }
                so.seccomp_unconfined = false;
                so.seccomp_profile = Some(profile.clone());
            }
            Some(p) => {
                return Err(ContainerError::InvalidArgument(format!(
                    "invalid seccomp policy {p:?}: valid policies are \"default\", \"image\""
                )))
            }
        }
        let security_config = SecurityConfig {
            seccomp: if so.seccomp_unconfined {
                "unconfined".to_string()
            } else {
                so.seccomp_profile.clone().unwrap_or_default()
            },
            apparmor: if so.apparmor_unconfined {
                "unconfined".to_string()
            } else {
                so.apparmor_profile.clone().unwrap_or_default()
            },
            selinux_label: so.selinux_label.clone().unwrap_or_default(),
            no_new_privileges: so.no_new_privileges,
            mask_paths: so.mask_paths.clone(),
            readonly_paths: so.readonly_paths.clone(),
            unmask_paths: so.unmask_paths.clone(),
            proc_opts: so.proc_opts.clone(),
            verity_enforce: so.verity_enforce,
            verity_off: so.verity_off,
            seccomp_bpf: match so.seccomp_bpf.clone() {
                Some(p) => Some(
                    tokio::task::spawn_blocking(move || read_bpf_filter(&p))
                        .await
                        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))??,
                ),
                None => None,
            },
            signature_require: so.signature.as_deref() == Some("require"),
            signature_check: so.signature.as_deref() == Some("check"),
            apparmor_profile: {
                let value = match (so.apparmor_unconfined, so.apparmor_profile.clone()) {
                    (true, _) => Some("unconfined".to_string()),
                    (false, p) => p,
                };
                let privileged = req.privileged;
                tokio::task::spawn_blocking(move || {
                    crate::container::apparmor::resolve(value.as_deref(), privileged)
                })
                .await
                .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
                .map_err(ContainerError::InvalidArgument)?
            },
        };
        // The profile is read now, once (its JSON goes in the config), and
        // one that does not parse fails the create.
        let mut security_config = security_config;
        let seccomp_opt = security_config.seccomp.clone();
        let mode = tokio::task::spawn_blocking(move || {
            crate::container::SeccompMode::from_security_opt(&seccomp_opt)
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
        .map_err(|e| ContainerError::InvalidArgument(e.to_string()))?;
        if let crate::container::SeccompMode::Custom(json) = mode {
            security_config.seccomp = json;
        }
        let sysctls = validate_sysctls(&req.sysctls, &req)?;
        crate::container::caps::build_capabilities_with_ambient(
            req.privileged,
            &req.cap_add,
            &req.cap_drop,
            &req.cap_ambient,
            true,
        )
        .map_err(ContainerError::InvalidArgument)?;

        let resources = req.resources.as_ref().map(|r| ResourceConfig {
            memory: r.memory,
            memory_swap: r.memory_swap,
            memory_reservation: r.memory_reservation,
            cpu_shares: r.cpu_shares,
            cpu_quota: r.cpu_quota,
            cpu_period: r.cpu_period,
            cpuset_cpus: r.cpuset_cpus.clone(),
            cpuset_mems: r.cpuset_mems.clone(),
            shm_size: r.shm_size,
            cgroup_conf: r.cgroup_conf.clone().map(|c| c.into_iter().collect()),
        });

        // `container:ID` and `ns:PATH` join a namespace: checked now, and
        // resolved again when the container starts (the target may restart,
        // and so may the daemon).
        let network_namespace_path = match (self.network_manager.engine(), &network_mode) {
            (Some(engine), NetworkMode::Container(target)) => {
                let joined = match self.db.get_container(target).await {
                    Ok(c) => c,
                    Err(velarx_types::DbError::NotFound(_)) => {
                        return Err(ContainerError::NotFound(target.to_string()));
                    }
                    Err(e) => return Err(e.into()),
                };
                // (a target that does not run has no namespace yet)
                if joined.state.is_alive() {
                    engine
                        .shared_netns(&network_mode)
                        .await?
                        .map(|p| p.spec_path())
                } else {
                    None
                }
            }
            (Some(engine), NetworkMode::Ns(_)) => engine
                .shared_netns(&network_mode)
                .await?
                .map(|p| p.spec_path()),
            (None, NetworkMode::Container(_) | NetworkMode::Ns(_)) => {
                // (no engine finds the namespace to join: the spec would get
                // a network of its own, and the container no word of it)
                return Err(ContainerError::InvalidArgument(format!(
                    "--network {} needs the network engine, which this engine does not run",
                    req.network_mode
                )));
            }
            _ => None,
        };

        // The networks: checked, the free host ports picked; the addresses
        // are allocated once the record exists.
        let net_plan = match self.network_manager.engine() {
            Some(engine) => Some(
                engine
                    .plan(&crate::network::engine::NetRequest {
                        name: req.name.clone().unwrap_or_default(),
                        network_mode: req.network_mode.clone(),
                        networks: req.networks.clone(),
                        ports: req
                            .ports
                            .iter()
                            .map(|p| {
                                velarx_wire::addr::PortSpec::single(
                                    &p.host_ip,
                                    p.host_port,
                                    p.container_port,
                                    &p.protocol,
                                )
                            })
                            .collect::<Result<_, _>>()
                            .map_err(|e| {
                                ContainerError::Network(
                                    velarx_netkernel::error::NetworkError::InvalidConfig(e),
                                )
                            })?,
                        ip: req.ip_address.clone(),
                        ip6: req.ip6_address.clone(),
                        mac: req.mac_address.clone(),
                        aliases: req.network_aliases.clone(),
                        implicit_aliases: std::iter::once(container_id.chars().take(12).collect())
                            .chain(Some(req.hostname.clone()))
                            .collect(),
                        annotations: req.annotations.clone().into_iter().collect(),
                        cni_annotations: req.cni_annotations.clone(),
                        cni_ip_ranges: req.cni_ip_ranges.clone(),
                    })
                    .await?,
            ),
            None => None,
        };
        // A shareable namespace is made by the network setup before the
        // runtime creates the container, which joins it (the monitor writes
        // the path the runtime finds it at).
        let network_namespace_path = match (&net_plan, self.network_manager.engine()) {
            (Some(p), Some(_)) if p.spec.shareable => Some(velarx_nsid::HELD.to_string()),
            _ => network_namespace_path,
        };

        // The cgroup of the container, by its `--cgroups` mode.
        let cgroups_path = self
            .container_cgroup(&req, &container_id)
            .map_err(ContainerError::InvalidArgument)?;

        let (log_driver, log_opts) = match &req.log_config {
            Some(lc) => (lc.driver.clone(), lc.config.clone().into_iter().collect()),
            None => (String::new(), HashMap::new()),
        };
        // the default is the one of now: a container keeps its driver
        let log_driver = if log_driver.is_empty() {
            self.containers_config.effective_log_driver().to_string()
        } else {
            log_driver
        };
        super::super::logs::validate_log_config(&log_driver, &log_opts)?;
        super::super::logs::allowed_log_path(
            &self.containers_config.log_path_allowlist,
            &log_opts,
        )?;
        let invalid = |m: String| {
            ContainerError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, m))
        };
        let Some(sdnotify) = crate::monitor::notify::SdNotify::parse(&req.sdnotify) else {
            return Err(invalid(format!(
                "unknown sdnotify mode `{}` (container, conmon, healthy, ignore)",
                req.sdnotify
            )));
        };
        if sdnotify == crate::monitor::notify::SdNotify::Healthy && req.healthcheck.is_none() {
            return Err(invalid(
                "--sdnotify=healthy needs a health check (--health-cmd)".into(),
            ));
        }
        // The monitor of a container the server starts is not in the cgroup
        // of the caller, whose service manager it must talk to, and its
        // output is not the caller's.
        if !self.caller_supervised {
            if sdnotify != crate::monitor::notify::SdNotify::Ignore {
                return Err(invalid(format!(
                    "--sdnotify={} needs the monitor to run in the caller's cgroup; \
                     the daemon's server cannot do that (run the container without the server)",
                    req.sdnotify
                )));
            }
            if log_driver == "passthrough" {
                return Err(invalid(
                    "--log-driver=passthrough writes to the caller's output; \
                     the daemon's server cannot do that (run the container without the server)"
                        .into(),
                ));
            }
        }
        // The HEALTHCHECK of the image unless one is given or none wanted
        // (a check without a command takes the image's, and the times it
        // does not give); podman's defaults complete the image's, a check
        // with its own command is kept as given
        let image_check = image_config
            .config
            .healthcheck
            .as_ref()
            .filter(|h| !req.no_healthcheck && !h.test.is_empty() && h.test[0] != "NONE");
        let pick = |own: u64, image: u64| if own == 0 { image } else { own };
        let healthcheck = match (&req.healthcheck, image_check) {
            (Some(h), Some(i)) if h.test.is_empty() => Some(
                Healthcheck {
                    test: i.test.clone(),
                    interval_ns: pick(h.interval_ns, i.interval),
                    timeout_ns: pick(h.timeout_ns, i.timeout),
                    start_period_ns: pick(h.start_period_ns, i.start_period),
                    retries: if h.retries == 0 { i.retries } else { h.retries },
                    start_interval_ns: pick(h.start_interval_ns, i.start_interval),
                    ..h.clone()
                }
                .completed(),
            ),
            (Some(h), _) if h.test.is_empty() => {
                if h.on_failure != OnFailure::None {
                    return Err(ContainerError::InvalidArgument(format!(
                        "cannot set on-failure action to {} without a health check",
                        h.on_failure.word()
                    )));
                }
                None
            }
            (Some(h), _) => Some(h.clone()),
            (None, Some(h)) => Some(
                Healthcheck {
                    test: h.test.clone(),
                    interval_ns: h.interval,
                    timeout_ns: h.timeout,
                    start_period_ns: h.start_period,
                    retries: h.retries,
                    start_interval_ns: h.start_interval,
                    ..Default::default()
                }
                .completed(),
            ),
            (None, None) => None,
        };
        if req.no_monitor && self.supervision.in_process.is_none() {
            return Err(ContainerError::InvalidArgument(
                "--no-monitor: the container is monitored by the process that runs it, \
                 which only `velarx run` in the foreground does"
                    .into(),
            ));
        }
        if let Some(h) = &healthcheck {
            match h.log_destination.as_str() {
                "" | "local" | "events_logger" => {}
                dir if Path::new(dir).is_absolute() && Path::new(dir).is_dir() => {}
                dir => {
                    return Err(ContainerError::InvalidArgument(format!(
                        "the health log destination `{dir}` is not local, events_logger or \
                         an absolute path of a directory"
                    )))
                }
            }
        }
        let stop_signal = match (
            req.stop_signal.as_str(),
            image_config.config.stop_signal.as_str(),
        ) {
            ("", "") if systemd => "SIGRTMIN+3".to_string(),
            ("", image) => image.to_string(),
            (given, _) => given.to_string(),
        };
        // the containers it needs, by id: they must exist
        let mut requires = Vec::new();
        for r in &req.requires {
            let rec = self.db.get_container(r).await.map_err(|_| {
                ContainerError::InvalidArgument(format!(
                    "`{r}` is not a valid container, cannot be used as a dependency"
                ))
            })?;
            if !requires.contains(&rec.id) {
                requires.push(rec.id);
            }
        }
        let joined_userns = matches!(userns_mode, UsernsMode::Container(_) | UsernsMode::Path(_));
        let mut options = self
            .create_options(&req, !uid_mappings.is_empty(), joined_userns, systemd)
            .await?;
        options.privileged = req.privileged;
        // the specs are read now, at each create
        let cdi_edits = self.cdi_edits(&req)?;
        if !stop_signal.is_empty() {
            options.annotations.insert(
                "org.opencontainers.image.stopSignal".into(),
                stop_signal.clone(),
            );
        }
        // podman's record of the options in the spec, what hooks and
        // inspect read
        for (on, key) in [
            (req.privileged, "privileged"),
            (req.auto_remove, "autoremove"),
            (req.auto_remove_image, "autoremove-image"),
            (req.init, "init"),
        ] {
            if on {
                options
                    .annotations
                    .insert(format!("io.podman.annotations.{key}"), "TRUE".into());
            }
        }
        if let Some(f) = req.cidfile.as_ref().filter(|f| !f.is_empty()) {
            options
                .annotations
                .insert("io.podman.annotations.cid-file".into(), f.clone());
        }
        options
            .annotations
            .extend(podman_security_annotations(&req.security_opts));
        let (runtime, runtime_name) = match req.runtime.as_deref().filter(|r| !r.is_empty()) {
            None => (None, None),
            Some(name) => {
                let path = self
                    .find_runtime(name)
                    .map_err(ContainerError::InvalidArgument)?;
                // (kept even when it is the runtime of this process: a
                // global --runtime makes it that one, and the later
                // commands of the container run with the default)
                (Some(path), Some(name.to_string()))
            }
        };
        let mut config = ContainerConfig {
            runtime,
            runtime_name,
            id: container_id.clone(),
            name: req.name.clone(),
            image: req.image.clone(),
            rootfs: rootfs_dir.clone(),
            command,
            entrypoint,
            working_dir,
            env,
            labels: super::bundle::container_labels(&image_config.config.labels, &req.labels),
            hostname,
            user: req.user.clone(),
            group_add: req.group_add.clone(),
            process_user: None,
            spec_user: None,
            umask,
            options,
            selinux: None,
            requires,
            mounts,
            read_only_rootfs: req.read_only_rootfs,
            privileged: req.privileged,
            cap_add: req.cap_add.clone(),
            cap_drop: req.cap_drop.clone(),
            cap_ambient: req.cap_ambient.clone(),
            groups_strict: req.groups_strict,
            userns_mode,
            userns: userns.mode.clone(),
            userns_path,
            uid_mappings: uid_mappings.clone(),
            gid_mappings: gid_mappings.clone(),
            tty: req.tty,
            stdin_open: req.stdin_open,
            security_opt: security_config,
            resources,
            // (the configured default only where the container has a cgroup
            // of its own: in that of its monitor it would limit the monitor;
            // not for the RUN containers of a build: buildah has none)
            pids_limit: req.pids_limit.or_else(|| {
                (cgroups_path.is_some()
                    && self.containers_config.pids_limit > 0
                    && !req.labels.contains_key(crate::services::build::BUILD_LABEL))
                .then_some(self.containers_config.pids_limit)
            }),
            oom_score_adj: req.oom_score_adj,
            sysctls,
            network_mode,
            networks: req.networks.clone(),
            network_namespace_path,
            stop_signal,
            log_driver,
            log_opts,
            timeout: req.timeout.filter(|&t| t > 0).map(u64::from),
            stop_timeout: req.stop_timeout,
            healthcheck,
            start_error: None,
            user_error: None,
            restart_policy: req.restart_policy.as_ref().map(|r| {
                velarx_wire::monitor::proto::RestartSettings {
                    policy: velarx_wire::monitor::proto::RestartPolicy::from_word(&r.name)
                        .unwrap_or_default(),
                    max_retries: r.maximum_retry_count,
                }
            }),
            sdnotify: req.sdnotify.clone(),
            cgroups: req.cgroups,
            cgroup_mode: req.cgroup_mode,
            no_monitor: req.no_monitor,
            cgroups_path,
            auto_remove: req.auto_remove,
            auto_remove_image: req.auto_remove_image,
            volatile: req.volatile,
            pid_file: req.pidfile.clone(),
            conmon_pid_file: req.conmon_pidfile.clone(),
            cid_file: req.cidfile.clone().filter(|f| !f.is_empty()),
            pinned: None,
        };
        // What only crun's annotations (`run.oci.*`) give: refused for a
        // runtime whose features do not allow them, which would ignore them.
        let crun_only = [
            (
                config.security_opt.seccomp_bpf.is_some(),
                "--security-opt seccomp-bpf",
            ),
            (
                crate::container::userspec::keep_groups(&req.group_add)?,
                "--group-add keep-groups",
            ),
        ];
        if let Some((_, what)) = crun_only.iter().find(|(asked, _)| *asked) {
            let runtime = config
                .runtime
                .as_deref()
                .unwrap_or(self.runtime.runtime_path());
            if !crate::container::has_crun_options(runtime) {
                return Err(ContainerError::InvalidArgument(format!(
                    "{what} needs an OCI runtime with crun's run.oci. annotations: the \
                     features of {} do not list them (crun and krun do)",
                    runtime.display()
                )));
            }
        }

        // The user, from the passwd and group files of the image (the root
        // file system is mounted by the monitor when the container starts).
        let (passwd, group) = match &rootfs_dir {
            Some(dir) => dir.users()?,
            None => self.image_users(&layers, &config)?,
        };
        let identity = keep_id_user.and_then(|(uid, gid)| host_identity(uid, gid));
        let identity = identity.as_ref().map(|(n, h)| (n.as_str(), h.as_str()));
        let with_hosts = if req.host_users.is_empty() {
            passwd.clone()
        } else {
            let host = fs::read("/etc/passwd")?;
            let mounts = &config.mounts;
            crate::container::userspec::with_host_users(
                &passwd,
                &host,
                &req.host_users,
                &config.working_dir,
                |home| {
                    let mut dir = home;
                    while dir != "/" && !dir.is_empty() {
                        if mounts.iter().any(|m| m.target == dir) {
                            return true;
                        }
                        dir = dir.rsplit_once('/').map_or("", |(parent, _)| parent);
                    }
                    false
                },
            )?
        };
        let (mut user, user_error) =
            resolve_container_user_later(&with_hosts, &group, &config, &req, identity)?;
        config.user_error = user_error;
        // keep-id: a volume mounted at the home of the user of the host (the
        // HOME of this process, as podman reads it) makes it the home of the
        // user in the container too
        if identity.is_some() && user.user.home.is_none() {
            if let Some(home) = std::env::var("HOME")
                .ok()
                .filter(|h| h.starts_with('/') && config.mounts.iter().any(|m| m.target == *h))
            {
                user.user.home = Some(home);
            }
        }
        if user.passwd.is_none() && with_hosts != passwd {
            user.passwd = Some(with_hosts);
        }

        // As podman: the PID or IPC namespace of the host is not separated
        let host_ns = req.pid_mode == NsMode::Host || req.ipc_mode == NsMode::Host;
        // and the processes of a container whose PID or IPC namespace is
        // joined are reachable with its label only
        let share = [&config.options.pid_ns, &config.options.ipc_ns]
            .iter()
            .find_map(|n| n.strip_prefix("container:"))
            .map(str::to_string)
            // the containers of a pod have the label of its infra container
            .or_else(|| req.selinux_share_with.clone());
        let (selinux, fresh_level) = self
            .selinux_config(
                &so,
                req.privileged,
                host_ns,
                share.as_deref(),
                req.preferred_selinux_level.as_deref(),
            )
            .await?;
        config.selinux = selinux;
        if systemd && !req.privileged {
            // systemd needs the init domain of the policy, as podman's
            // InitLabel: it manages cgroups, mounts and its own journal
            if let Some(s) = config.selinux.as_mut().filter(|s| !s.disable) {
                s.typ.get_or_insert_with(|| "container_init_t".into());
            }
        }

        let bundle_path = self.bundle_dir(&container_id);
        fs::create_dir_all(&bundle_path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            // (their requests, images of checkpoints, secrets' sources: the
            // engine's only)
            if let Some(parent) = bundle_path.parent() {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
            // the bundle is the base of a `directory` plan, which the
            // monitor refuses when its group or others can write it: a
            // umask of 002 (a user private group) must not make it so
            let mode = fs::metadata(&bundle_path)?.permissions().mode() & 0o7777;
            if mode & 0o022 != 0 {
                fs::set_permissions(&bundle_path, fs::Permissions::from_mode(mode & !0o022))?;
            }
        }
        // (the bundle and the writable layer of the container: what a create
        // that fails from here on removes)
        undo.writable = Some(self.writable(&container_id));
        if layers.is_empty() && rootfs_dir.is_none() {
            return Err(ContainerError::ImageNotFound(
                "Image has no layers".to_string(),
            ));
        }
        // the root file system from the images of the layers; with a user
        // namespace, its mapping (idmapped layers)
        let mapping =
            (!uid_mappings.is_empty()).then(|| self.translation(&uid_mappings, &gid_mappings));
        if rootfs_dir.is_none() {
            // what the driver cannot do of what the container asks is refused
            // before anything is made
            self.image_service
                .check_container_request(mapping.is_some(), false)?;
        }
        // an image named by its digest: the digest is the root of what an
        // enforced start verifies (what the container took from the image
        // is recorded with the container, below)
        if rootfs_dir.is_none() {
            config.pinned = pinned_digest(&req.image).map(|digest| PinnedImage {
                digest,
                taken: Default::default(),
            });
        }
        if config.security_opt.verity_enforce {
            self.image_service
                .check_verity_request(false, true)
                .map_err(|e| {
                    ContainerError::InvalidArgument(format!("--security-opt verity=enforce: {e}"))
                })?;
        }
        self.verity_off(&config)?;
        let enforce = self.digests_enforced(&config);
        if let (Some(why), Some(p)) = (enforce, &config.pinned) {
            self.image_service
                .verify_pinned(&req.image, &p.digest, why, &image, &layers)
                .await?;
        }
        if let (Some(why), Some(_)) = (enforce, &rootfs_dir) {
            return Err(ContainerError::InvalidArgument(format!(
                "{why}: --rootfs is a directory, not an image whose layers state fs-verity digests"
            )));
        }
        // (an image whose layers state none could never start: refused now,
        // and again at every start)
        let accepted = if enforce.is_some() {
            Some(self.image_service.create_digests(
                &image,
                &layers,
                config.security_opt.verity_enforce,
            )?)
        } else {
            None
        };
        // the writable layer of the container, from its image (a driver that
        // copies the layers copies them now, before the engine writes its
        // own files into the root file system)
        let root_plan = if rootfs_dir.is_none() {
            let ask = super::bundle::RootAsk {
                mapping: mapping.clone(),
                translate: self.translation(&uid_mappings, &gid_mappings),
                idmap_mount: crate::services::lifecycle::root_fd::may_idmap_mounts(
                    mapping.is_some(),
                ),
                label: crate::services::lifecycle::mount_label(&config),
                accepted,
                volatile: config.throw_away(),
            };
            self.make_writable(&container_id, &bundle_path, &image, &layers, id_maps, ask)
                .await?
        } else {
            None
        };
        // a writable root file system of an image gets the entries itself
        // (in a block: nothing of it is kept across the awaits below)
        {
            let view = (rootfs_dir.is_none()
                && !req.read_only_rootfs
                && (user.passwd.is_some()
                    || user.group.is_some()
                    || localtime.as_ref().is_some_and(|(zone, _)| zone != "local")))
            .then(|| self.image_view(&layers))
            .transpose()?;
            let translate = view
                .as_ref()
                .map(|_| self.translation(&uid_mappings, &gid_mappings));
            let root_fd = view
                .as_ref()
                .map(|_| self.storage().writable_root(&self.writable(&container_id)))
                .transpose()
                .map_err(|e| ContainerError::Io(e.into_io()))?;
            let root = view
                .as_ref()
                .zip(translate.as_ref())
                .zip(root_fd.as_ref())
                .map(|((view, translate), fd)| WritableRoot {
                    view: &**view,
                    translate,
                    root: std::os::fd::AsFd::as_fd(fd),
                });
            add_user_files(
                &mut config,
                &bundle_path,
                user,
                localtime
                    .as_ref()
                    .map(|(zone, data)| (zone.as_str(), data.as_slice())),
                root.as_ref(),
            )?;
        }
        // the image id as podman shows it: the digest of the config (a
        // container of a directory has the id of its pseudo-image)
        let image_id = if image.id == velarx_db::ROOTFS_IMAGE_ID {
            image.id.clone()
        } else {
            image.config_digest.hex()
        };
        add_containerenv(&mut config, &bundle_path, &req.image, &image_id)?;

        let rootfs_path = bundle_path.join("rootfs");
        fs::create_dir_all(&rootfs_path)?;

        velarx_base::trace::point("create composefs");
        // a --workdir the image lacks is not made (podman's), unless a
        // mount is there
        if !req.working_dir.is_empty() && rootfs_dir.is_none() {
            let view = self.image_view(&layers)?;
            // (podman makes the container, and its start says so)
            match check_workdir(
                &req.working_dir,
                &config,
                &req.tmpfs,
                Some(&*view),
                &config.id,
            ) {
                Err(ContainerError::InvalidArgument(why)) => config.start_error = Some(why),
                other => other?,
            }
        }
        if let Some(dir) = &rootfs_dir {
            self.setup_rootfs_dir(&container_id, &bundle_path, dir, id_maps)?;
        }
        velarx_base::trace::point("create rootfs");

        // Volumes: first use, owners, idmapped mounts, image mounts
        self.prepare_mounts(&mut config, &bundle_path, &layers)
            .await?;
        // `--mount type=artifact`: the files of the artifacts, read-only
        let artifacts = self.artifact_mounts(&req.mount, &layers, &bundle_path)?;
        if let (Some(why), false) = (enforce, artifacts.is_empty()) {
            return Err(ContainerError::InvalidArgument(format!(
                "{why}: --mount type=artifact mounts files of an artifact, which states no fs-verity digest to check"
            )));
        }
        config.mounts.extend(artifacts);
        // (a descriptor with the plan is the driver's for this one call: the
        // start asks again, the monitor uses a descriptor once)
        if let Some(m) = &root_plan {
            velarx_fuse::plan::write(
                &bundle_path,
                "",
                &crate::services::lifecycle::root_fd::plan_of(&m.plan, m.idmap, false),
            )?;
        }

        // The network providers make their interfaces ready, before the
        // spec is made: the interfaces are moved into the container with
        // netDevices, and the first name server is the container's.
        undo.providers.id = container_id.clone();
        let (provider_devices, provider_dns) = self
            .prepare_providers(
                &req,
                &config.network_mode,
                &container_id,
                &mut undo.providers.names,
            )
            .await?;

        if req.hosts_file.as_deref() == Some("image") && !req.no_hosts {
            let hosts = match &rootfs_dir {
                Some(dir) => dir.file("etc/hosts")?,
                None => self
                    .image_files(
                        &layers,
                        &self.translation(&config.uid_mappings, &config.gid_mappings),
                        &["etc/hosts"],
                    )?
                    .pop()
                    .unwrap_or_default(),
            };
            req.hosts_image = Some(String::from_utf8_lossy(&hosts).into_owned());
        }
        let inherited = self.inherited_etc(&req, !uid_mappings.is_empty()).await?;
        let etc_mounts = self.setup_etc_files(
            &bundle_path,
            &config,
            &req,
            provider_dns,
            net_plan.as_ref().map(|p| &p.etc),
            inherited,
        )?;
        if !uid_mappings.is_empty() {
            // They belong to the root of the container, which may edit them.
            if let (Some(u), Some(g)) = (
                velarx_base::idmap::to_parent(&uid_mappings, 0),
                velarx_base::idmap::to_parent(&gid_mappings, 0),
            ) {
                for m in &etc_mounts {
                    crate::services::volcopy::chown_path(Path::new(&m.source), u, g)?;
                }
            }
        }
        config.mounts.extend(etc_mounts);
        self.relabel_mounts(&config, &bundle_path)?;

        // the path the runtime is given for the root file system
        let spec_root = crate::userns::rootless::public_rootfs(
            &bundle_path,
            &container_id,
            &config.uid_mappings,
        )?
        .unwrap_or_else(|| rootfs_path.clone());
        let mut spec_value = self.runtime.generate_spec_json(&config, &spec_root)?;
        let spec_path = bundle_path.join("config.json");

        apply_mount_idmaps(&mut spec_value, &config.mounts);
        crate::cdi::apply(&mut spec_value, &cdi_edits, config.options.bind_devices);

        // The interfaces of the providers, with those CDI added
        add_net_devices(&mut spec_value, &provider_devices)?;

        // The OCI hooks of the hooks.d directories that apply.
        let hooks = crate::services::hooks::load(&crate::services::hooks::hook_dirs(
            &self.containers_config.hooks_dir,
        )?)
        .map_err(ContainerError::InvalidArgument)?;
        if !hooks.is_empty() {
            let has_bind_mounts = !req.volumes.is_empty()
                || !req.mount.is_empty()
                || !req.bind_mounts.is_empty()
                || !req.image_mounts.is_empty();
            let precreate =
                crate::services::hooks::inject(&mut spec_value, &hooks, has_bind_mounts);
            if !precreate.is_empty() {
                let (hooks_dir, mut v) = (bundle_path.clone(), spec_value);
                spec_value = tokio::task::spawn_blocking(move || {
                    crate::services::hooks::run_precreate(&precreate, &mut v, &hooks_dir).map(|_| v)
                })
                .await
                .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
                .map_err(ContainerError::InvalidArgument)?;
            }
        }

        crate::container::spec_file::write(&spec_path, &spec_value)?;
        velarx_base::trace::point("create spec");

        // Save container record first so it can be inspected/deleted even if start fails
        let now = chrono::Utc::now().to_rfc3339();
        // the variables of secrets are in the bundle's specification only:
        // not in the database, its inspect, a commit or a kube YAML
        let recorded = ContainerConfig {
            env: config
                .env
                .iter()
                .filter(|e| !req.secret_env.contains(e))
                .cloned()
                .collect(),
            ..config.clone()
        };
        let mut recorded = recorded;
        // (the user of the final specification, after the CDI edits and
        // the hooks: what the process runs as)
        recorded.spec_user = crate::container::SpecUser::of_spec(&spec_value);
        if let Some(p) = recorded.pinned.clone() {
            recorded.pinned = Some(PinnedImage {
                taken: crate::services::taken_of(&image_config, &recorded),
                ..p
            });
        }
        let record = ContainerRecord {
            id: container_id.clone(),
            name: req.name.clone(),
            image_id: image.id.clone(),
            config: serde_json::to_string(&recorded)?,
            state: RecordState::Created,
            created_at: now.clone(),
            ..Default::default()
        };

        // a level chosen here is judged by the insert: a create that chose
        // it at the same time may have been recorded first
        if fresh_level {
            self.db
                .insert_container_distinct(&record, crate::container::selinux::level_taken)
                .await?;
        } else {
            self.db.insert_container(&record).await?;
        }
        // what `restore --import` makes it again from: the secrets by
        // name, not their values
        let kept = req.without_secret_values(&self.secrets_dir_of(&container_id));
        if let Err(e) = super::super::crcheckpoint::save_create_request(
            &bundle_path,
            &kept,
            &req.resolved_secrets,
        ) {
            warn!("Cannot keep the request of {}: {}", container_id, e);
        }
        // The layers stay while the container does, whatever becomes of
        // the images.
        let mut used: Vec<velarx_db::LayerKey> = layers.iter().map(|l| l.key).collect();
        for m in config.mounts.iter().filter_map(|m| m.image.as_ref()) {
            if let Ok(img) = self.image_service.get(&m.image).await {
                used.extend(self.image_layers(&img).await?.into_iter().map(|l| l.key));
            }
        }
        self.db.set_container_layers(&container_id, used).await?;

        if let (Some(engine), Some(plan)) = (self.network_manager.engine(), &net_plan) {
            match engine.commit(&container_id, plan).await {
                Ok(ips) if !ips.is_empty() && !req.no_hosts => {
                    // The address is known once the record exists.
                    match self.hosts_content(&config, &req, Some(&plan.etc), &ips) {
                        Ok(content) => self.rewrite_hosts(&bundle_path, &content)?,
                        Err(e) => {
                            let _ = self.delete(&container_id, true).await;
                            return Err(e);
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    let _ = self.delete(&container_id, true).await;
                    return Err(e.into());
                }
            }
        }

        info!("Created container {}", container_id);
        Ok(container_id)
    }

    /// The layers of an image, the lowest first.
    /// The image a container is made of: the image of the store `req.image`
    /// names, or the pull in progress that has the name when that one is the
    /// more recent (a `pull --lazy` over an older image of the store makes
    /// `run --lazy` run the new one).  A container without `--lazy` does not
    /// run on a pull in progress: the pull is completed first, as fast as
    /// it goes, and the container runs from the store.  An image that is
    /// neither is the client's to pull (with its options: `--lazy` pulls
    /// lazily).
    async fn image_for_create(
        &self,
        req: &CreateContainerRequest,
    ) -> ContainerResult<(
        velarx_db::ImageRecord,
        Option<velarx_content::pull::staged::StagedPull>,
    )> {
        use velarx_types::ImageError;
        let images = &self.image_service;
        for _ in 0..2 {
            let stored = match images.get_with_tags(&req.image).await {
                Ok((image, _)) => Some(image),
                Err(ImageError::NotFound(_) | ImageError::Pulling(_)) => None,
                Err(ImageError::Invalid(why)) => return Err(ContainerError::InvalidArgument(why)),
                // (a store that cannot be read, or a prefix of several ids,
                // is told as it is: not as an image that is not there)
                Err(e) => return Err(e.into()),
            };
            let staged = images
                .staged_image(&req.image)
                .await?
                .map(|(_, _, pull)| pull);
            match (stored, staged) {
                (Some(image), Some(pull)) if !newer(&pull.started_at, &image.created_at) => {
                    return Ok((image, None))
                }
                (None, None) => return Err(ContainerError::ImageNotFound(req.image.clone())),
                (Some(image), None) => return Ok((image, None)),
                (_, Some(pull)) if req.lazy => return Ok((pull.image_record(), Some(pull))),
                (_, Some(pull)) => {
                    // run without --lazy: the pull is finished first
                    images.complete_staged(&pull.id).await?;
                    continue;
                }
            }
        }
        Err(ContainerError::ImageNotFound(req.image.clone()))
    }

    /// The layers of an image.
    pub async fn image_layers(
        &self,
        image: &velarx_db::ImageRecord,
    ) -> ContainerResult<Vec<LayerRecord>> {
        self.layers_of(image).await
    }

    /// The root file system of the image of `layers` as its containers see
    /// it, read a lookup at a time (a create reads its users, a working
    /// directory, the content of its volumes).  A view is shared while
    /// someone holds it (a create holds one for all its reads) and dropped
    /// with the last holder: for a driver that reads a mount of the image
    /// (`MountImage`) the mount goes with it.  An image of a layer that is
    /// missing or cannot be read is an error that names the layer and the
    /// remedy.
    pub fn image_view(
        &self,
        layers: &[LayerRecord],
    ) -> ContainerResult<Arc<dyn velarx_fuse::view::ImageTree>> {
        use std::sync::Weak;
        type Views = Vec<(String, Weak<dyn velarx_fuse::view::ImageTree>)>;
        static VIEWS: std::sync::Mutex<Views> = std::sync::Mutex::new(Vec::new());
        let key = layers
            .iter()
            .map(|l| l.key.to_string())
            .collect::<Vec<_>>()
            .join(",");
        {
            let mut views = VIEWS.lock().unwrap_or_else(|e| e.into_inner());
            views.retain(|(_, v)| v.strong_count() > 0);
            if let Some(view) = views
                .iter()
                .find(|(k, _)| *k == key)
                .and_then(|(_, v)| v.upgrade())
            {
                return Ok(view);
            }
        }
        let view = self.image_service.image_view("", layers)?;
        VIEWS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((key, Arc::downgrade(&view)));
        Ok(view)
    }

    /// Setup container networking based on network_mode and networks list
    pub(crate) async fn setup_container_network(
        &self,
        container_id: &str,
        pid: i32,
        config: &ContainerConfig,
    ) -> ContainerResult<()> {
        self.network_manager.begin(container_id);
        let modes = networks_to_set_up(config);

        info!(
            "Setting up {} network(s) for container {}: {:?}",
            modes.len(),
            container_id,
            modes.iter().map(|m| m.to_string()).collect::<Vec<_>>()
        );

        // The providers start their networks after the others
        let mut providers: Vec<String> = Vec::new();

        for mode in modes.iter() {
            if let NetworkMode::Ns(path) = mode {
                if !path.starts_with('/') {
                    return Err(ContainerError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Invalid network mode '{mode}': invalid network mode: the network \
                             namespace path in `{mode}` must be absolute"
                        ),
                    )));
                }
            }

            if let NetworkMode::Provider(name) = mode {
                providers.push(name.clone());
                continue;
            }

            // (nothing asked for is the default network, whichever it is)
            let named = if *mode == NetworkMode::Unset {
                "default".to_string()
            } else {
                mode.to_string()
            };
            self.network_manager
                .setup(container_id, mode, pid)
                .await
                .map_err(|e| match e {
                    // (typed, as the create says it)
                    crate::services::network::NetworkError::Setup(
                        n @ (velarx_netkernel::error::NetworkError::NoPasta { .. }
                        | velarx_netkernel::error::NetworkError::OldPasta { .. }),
                    ) => ContainerError::Network(n),
                    e => ContainerError::Io(std::io::Error::other(format!(
                        "Network setup failed for '{named}': {e}"
                    ))),
                })?;

            info!("Network '{named}' configured for container {container_id}");
        }

        if !providers.is_empty() {
            // A provider is not the way out when another network is
            let default_route = !modes.iter().any(|m| {
                matches!(
                    m,
                    NetworkMode::Pasta(None) | NetworkMode::Bridge(_) | NetworkMode::Host
                )
            });
            self.start_providers(container_id, pid as u32, &providers, default_route)
                .await?;
        }

        Ok(())
    }

    /// The providers `req` names, with their clients: an error for one that
    /// is not configured.
    fn providers_of<'a>(
        &self,
        network_mode: &'a NetworkMode,
        networks: &'a [String],
    ) -> ContainerResult<Vec<(&'a str, &crate::network::provider::ProviderClient)>> {
        velarx_netdetach::provider::names_of(network_mode, networks)
            .into_iter()
            .map(|name| {
                self.network_providers
                    .get(name)
                    .map(|client| (name, client))
                    .ok_or_else(|| {
                        ContainerError::Io(std::io::Error::new(
                            std::io::ErrorKind::NotConnected,
                            format!(
                                "--network provider:{name}: no [[network.providers]] has that \
                                 name (providers are used through the API server)"
                            ),
                        ))
                    })
            })
            .collect()
    }

    /// `Prepare` of each provider the request names: the interfaces to move
    /// into the container, and the name server of the first that has one.
    /// The providers that made its network are added to `prepared`: they
    /// are told to undo it when the create fails after all.
    async fn prepare_providers(
        &self,
        req: &CreateContainerRequest,
        network_mode: &NetworkMode,
        container_id: &str,
        prepared: &mut Vec<String>,
    ) -> ContainerResult<(
        Vec<crate::network::provider::Device>,
        Option<std::net::Ipv4Addr>,
    )> {
        let names: Vec<&str> = self
            .providers_of(network_mode, &req.networks)?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        // (the network was asked for: without it there is no container)
        self.network_providers
            .prepare(&names, container_id, prepared)
            .await
            .map_err(|(name, e)| {
                ContainerError::Io(std::io::Error::other(format!(
                    "--network provider:{name}: {e}"
                )))
            })
    }

    /// `Start` of each provider of the container, which runs as `pid`: each
    /// is given the network namespace of the process, opened once here.
    async fn start_providers(
        &self,
        container_id: &str,
        pid: u32,
        names: &[String],
        default_route: bool,
    ) -> ContainerResult<()> {
        // what the other containers know it by: its name, else the start of its id
        let name = match self.db.get_container(container_id).await {
            Ok(c) => c.name,
            Err(_) => None,
        }
        .unwrap_or_else(|| container_id[..12.min(container_id.len())].to_string());
        let netns = std::fs::File::open(format!("/proc/{pid}/ns/net")).map_err(|e| {
            ContainerError::Io(std::io::Error::new(
                e.kind(),
                format!("the network namespace of the container: {e}"),
            ))
        })?;
        for provider in names {
            let client = self.network_providers.get(provider).ok_or_else(|| {
                ContainerError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    format!("network provider {provider} is not configured"),
                ))
            })?;
            let netns = netns.try_clone().map_err(ContainerError::Io)?;
            client
                .start(container_id, &name, netns.into(), default_route)
                .await
                .map_err(|e| {
                    ContainerError::Io(std::io::Error::other(format!(
                        "Network provider {provider}: {e}"
                    )))
                })?;
            info!("Network provider {provider} started the network of container {container_id}");
        }
        Ok(())
    }
}

/// Add the interfaces of the network providers to the `netDevices` of the
/// spec, next to those CDI put there: a host interface both name is refused
/// (it can move into the container once).
fn add_net_devices(
    spec: &mut serde_json::Value,
    devices: &[crate::network::provider::Device],
) -> ContainerResult<()> {
    if devices.is_empty() {
        return Ok(());
    }
    if spec.get("linux").is_none() {
        spec["linux"] = serde_json::json!({});
    }
    let linux = &mut spec["linux"];
    if !linux.get("netDevices").is_some_and(|v| v.is_object()) {
        linux["netDevices"] = serde_json::json!({});
    }
    let Some(map) = linux["netDevices"].as_object_mut() else {
        return Ok(());
    };
    for d in devices {
        if map.contains_key(&d.host) {
            return Err(ContainerError::InvalidArgument(format!(
                "the interface {} of a network provider is also a CDI device",
                d.host
            )));
        }
        map.insert(d.host.clone(), serde_json::json!({ "name": d.container }));
    }
    info!("Added netDevices to OCI spec: {:?}", devices);
    Ok(())
}

/// The digest of an image reference that has one (`NAME@sha256:...`), as
/// the user typed it.
pub(super) fn pinned_digest(reference: &str) -> Option<velarx_types::digest::Digest> {
    reference
        .contains('@')
        .then(|| velarx_types::ImageReference::parse(reference).ok())
        .flatten()
        .and_then(|r| r.digest)
}

/// Whether the time `a` (RFC 3339) is after `b`.
fn newer(a: &str, b: &str) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(a),
        chrono::DateTime::parse_from_rfc3339(b),
    ) {
        (Ok(a), Ok(b)) => a > b,
        _ => a > b,
    }
}

/// The entrypoint and the command of the process of a container: those of
/// the request or of the image.  An entrypoint given drops the command of
/// the image; `[""]` (as `--entrypoint ""` sends it) drops the entrypoint of
/// the image.
fn process_args(
    req: &CreateContainerRequest,
    config: &velarx_types::OciImageConfig,
) -> (Vec<String>, Vec<String>) {
    let command = if !req.command.is_empty() {
        req.command.clone()
    } else if req.entrypoint.is_empty() {
        config.cmd.clone().unwrap_or_default()
    } else {
        Vec::new()
    };
    let entrypoint = match req.entrypoint.as_slice() {
        [] if req.reset_entrypoint => Vec::new(),
        [] => config.entrypoint.clone().unwrap_or_default(),
        [e] if e.is_empty() => Vec::new(),
        e => e.to_vec(),
    };
    (entrypoint, command)
}

#[cfg(test)]
mod net_device_tests {
    use super::*;
    use crate::network::provider::Device;

    fn device(host: &str, container: &str) -> Device {
        Device {
            host: host.into(),
            container: container.into(),
        }
    }

    /// The interfaces of a provider go next to the CDI ones, and one that
    /// both name is refused.
    #[test]
    fn provider_devices_are_added_to_the_cdi_ones() {
        let mut spec = serde_json::json!({"linux": {"netDevices": {"eth9": {"name": "cdi0"}}}});
        add_net_devices(&mut spec, &[device("veth1", "eth1")]).unwrap();
        assert_eq!(
            spec["linux"]["netDevices"],
            serde_json::json!({"eth9": {"name": "cdi0"}, "veth1": {"name": "eth1"}})
        );
        assert!(add_net_devices(&mut spec, &[device("eth9", "eth2")]).is_err());

        let mut bare = serde_json::json!({});
        add_net_devices(&mut bare, &[device("veth1", "eth1")]).unwrap();
        assert_eq!(bare["linux"]["netDevices"]["veth1"]["name"], "eth1");
        let mut untouched = serde_json::json!({});
        add_net_devices(&mut untouched, &[]).unwrap();
        assert_eq!(untouched, serde_json::json!({}));
    }
}

/// The networks a container is set up on: its list of networks, else its
/// network mode.  Nothing asked for stays unset: the default network is the
/// engine's to pick (pasta rootless, the default bridge as root), never a
/// bridge named here.
fn networks_to_set_up(config: &ContainerConfig) -> Vec<NetworkMode> {
    if !config.networks.is_empty() {
        config
            .networks
            .iter()
            .map(|n| NetworkMode::parse(n))
            .collect()
    } else {
        vec![config.network_mode.clone()]
    }
}

#[cfg(test)]
mod default_network_tests {
    use super::*;

    #[test]
    fn nothing_asked_for_stays_the_default_network() {
        let config = ContainerConfig::default();
        assert_eq!(networks_to_set_up(&config), vec![NetworkMode::Unset]);
    }

    #[test]
    fn a_bridge_asked_for_stays_a_bridge() {
        let mut config = ContainerConfig {
            network_mode: NetworkMode::Bridge(None),
            ..Default::default()
        };
        assert_eq!(networks_to_set_up(&config), vec![NetworkMode::Bridge(None)]);
        config.networks = vec!["pasta".into()];
        assert_eq!(networks_to_set_up(&config), vec![NetworkMode::Pasta(None)]);
    }
}

#[cfg(test)]
mod level_retry_tests {
    use super::*;
    use std::cell::Cell;

    fn taken() -> ContainerError {
        ContainerError::Database(velarx_types::DbError::LevelTaken("s0:c1,c2".into()))
    }

    /// A taken level is picked again, each failed attempt undone, until one
    /// is recorded.
    #[tokio::test]
    async fn a_taken_level_is_picked_again() {
        let (ran, undone) = (Cell::new(0), Cell::new(0));
        let result = retry_on_level_taken(|| async {
            ran.set(ran.get() + 1);
            if ran.get() <= 2 {
                undone.set(undone.get() + 1);
                return Err(taken());
            }
            Ok("id")
        })
        .await;
        assert_eq!(result.unwrap(), "id");
        assert_eq!((ran.get(), undone.get()), (3, 2));
    }

    /// When every attempt loses its level the create fails and says so.
    #[tokio::test]
    async fn the_attempts_run_out() {
        let ran = Cell::new(0);
        let result: ContainerResult<()> = retry_on_level_taken(|| async {
            ran.set(ran.get() + 1);
            Err(taken())
        })
        .await;
        assert_eq!(ran.get(), LEVEL_ATTEMPTS);
        let err = result.unwrap_err();
        assert!(matches!(err, ContainerError::LevelsTaken(LEVEL_ATTEMPTS)));
        assert!(err
            .to_string()
            .starts_with("cannot pick a free SELinux level"));
    }

    /// Any other error ends the create at once.
    #[tokio::test]
    async fn another_error_is_not_retried() {
        let ran = Cell::new(0);
        let result: ContainerResult<()> = retry_on_level_taken(|| async {
            ran.set(ran.get() + 1);
            Err(ContainerError::InvalidArgument("no".into()))
        })
        .await;
        assert_eq!(ran.get(), 1);
        assert!(matches!(result, Err(ContainerError::InvalidArgument(_))));
    }
}
