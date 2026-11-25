// SPDX-License-Identifier: Apache-2.0
use super::*;

/// The working directory given on the command line is in the image or on a
/// mount of the container, else podman's error.
pub(super) fn check_workdir(
    workdir: &str,
    config: &ContainerConfig,
    tmpfs: &[String],
    image: Option<&dyn velarx_fuse::view::ImageTree>,
    id: &str,
) -> ContainerResult<()> {
    let path = format!("/{}", workdir.trim_matches('/'));
    // (the runtime makes the directories of a mount, so a mount below the
    // working directory makes it too)
    let under = |target: &str| {
        let t = target.trim_end_matches('/');
        path == t || path.starts_with(&format!("{t}/")) || t.starts_with(&format!("{path}/"))
    };
    // (podman skips the check on the mounts it adds itself as well:
    // /dev, /proc, /sys and the files it makes)
    let engine_mount = ENGINE_MOUNTS
        .iter()
        .any(|t| path == *t || path.starts_with(&format!("{t}/")));
    if engine_mount
        || config.mounts.iter().any(|m| under(&m.target))
        || tmpfs
            .iter()
            .any(|t| under(t.split(':').next().unwrap_or_default()))
    {
        return Ok(());
    }
    let Some(tree) = image else {
        // (an image that cannot be read: the runtime will say)
        return Ok(());
    };
    match tree.resolve_following(&path).and_then(|n| tree.node(n)) {
        Some(n) if n.entry.entry_type != velarx_storage::TocEntryType::Dir => Err(
            ContainerError::InvalidArgument(workdir_not_a_directory(&path, id)),
        ),
        Some(_) => Ok(()),
        None => Err(ContainerError::InvalidArgument(workdir_missing(&path, id))),
    }
}

pub(super) fn workdir_missing(path: &str, id: &str) -> String {
    format!("workdir {path:?} does not exist on container {id}")
}

pub(super) fn workdir_not_a_directory(path: &str, id: &str) -> String {
    format!("workdir {path:?} exists on container {id}, but is not a directory")
}

/// The sysctls of a container, keys with dots: only those of the namespaces
/// the container owns (podman's list).
pub(super) fn validate_sysctls(
    sysctls: &std::collections::BTreeMap<String, String>,
    req: &CreateContainerRequest,
) -> ContainerResult<HashMap<String, String>> {
    const IPC: [&str; 8] = [
        "kernel.msgmax",
        "kernel.msgmnb",
        "kernel.msgmni",
        "kernel.sem",
        "kernel.shmall",
        "kernel.shmmax",
        "kernel.shmmni",
        "kernel.shm_rmid_forced",
    ];
    let host_net = req.has_network_mode(&NetworkMode::Host)
        || req.network_mode.is_joined()
        || req
            .networks
            .iter()
            .any(|n| NetworkMode::parse(n).is_joined());
    let host_ipc = req.ipc_mode.is_joined();
    let mut out = HashMap::new();
    for (k, v) in sysctls {
        let key = k.replace('/', ".");
        let err = |why: &str| ContainerError::InvalidArgument(format!("the sysctl `{key}` {why}"));
        if key.starts_with("net.") {
            if host_net {
                return Err(err(
                    "cannot be set in a network namespace the container does not own",
                ));
            }
        } else if key.starts_with("fs.mqueue.") || IPC.contains(&key.as_str()) {
            if host_ipc {
                return Err(err(
                    "cannot be set in an IPC namespace the container does not own",
                ));
            }
        } else {
            return Err(err("is not namespaced"));
        }
        out.insert(key, v.clone());
    }
    Ok(out)
}

/// A compiled seccomp filter (`--security-opt seccomp-bpf=PATH`, as
/// easyseccomp makes them): `struct sock_filter`s, base64 for crun's
/// `run.oci.seccomp_bpf_data` annotation.
pub(super) fn read_bpf_filter(path: &str) -> ContainerResult<String> {
    use base64::Engine;
    // BPF_MAXINSNS instructions of 8 bytes
    const MAX: u64 = 4096 * 8;
    let bad = |why: String| ContainerError::InvalidArgument(format!("seccomp-bpf `{path}`: {why}"));
    let data = crate::container::seccomp::read_regular_file(Path::new(path), MAX)
        .map_err(|e| bad(e.to_string()))?;
    if data.is_empty() || data.len() % 8 != 0 {
        return Err(bad(
            "not a BPF program (1 to 4096 instructions of 8 bytes)".into()
        ));
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(data))
}

/// The network mode that cannot take DNS settings of its own, when the
/// request has some: `none` has no resolver, and a container that shares the
/// network namespace of another (`container:ID`, the members of a pod) resolves
/// as that one.  Podman refuses both (`--pod P --dns X` it drops without a
/// word; here nothing is dropped).
pub(super) fn dns_conflict(req: &CreateContainerRequest) -> Option<&'static str> {
    if req.dns.is_empty() && req.dns_search.is_empty() && req.dns_options.is_empty() {
        None
    } else if req.has_network_mode(&NetworkMode::Off) {
        Some("none")
    } else if req.joins_network_of_container() {
        Some("container")
    } else {
        None
    }
}

/// Whether the state of the record is the one of the runtime; the
/// runtime's "created" is what `init` calls initialized.
/// The state the OCI runtime gives a container that the database does not
/// know: only a pause or a resume (made through the runtime).  An exit, a
/// creation or a start is recorded by the monitor's watcher with what goes
/// with it (the exit code and time, the pid), and a state read from the
/// runtime before it may land after it: written here, a stop would hide
/// the exit from its record (no died event) and a stale "created" would
/// undo a start.
pub(super) fn paused_or_resumed(
    record: RecordState,
    runtime: &crate::container::ContainerState,
) -> Option<RecordState> {
    use crate::container::ContainerState as Oci;
    match (record, runtime) {
        (RecordState::Running, Oci::Paused) => Some(RecordState::Paused),
        (RecordState::Paused, Oci::Running) => Some(RecordState::Running),
        _ => None,
    }
}

/// `-P`: a mapping to a free host port for every port the image or the
/// request exposes (`PORT[-END][/PROTO]`) that is not mapped already.
pub(super) fn publish_exposed<'a>(
    req: &mut CreateContainerRequest,
    image: impl Iterator<Item = &'a String>,
) -> ContainerResult<()> {
    let invalid = |e: &str| {
        ContainerError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid exposed port `{e}`"),
        ))
    };
    let exposed: Vec<String> = image.cloned().chain(req.expose.iter().cloned()).collect();
    let mut mapped: std::collections::HashSet<(u16, String)> = req
        .ports
        .iter()
        .map(|m| (m.container_port, m.protocol.clone()))
        .collect();
    for e in exposed {
        let (ports, proto) = e.split_once('/').unwrap_or((e.as_str(), "tcp"));
        let proto = if proto.is_empty() { "tcp" } else { proto };
        if proto == "sctp" {
            warn!("-P: {e} is not published: SCTP ports are not published");
            continue;
        }
        if !matches!(proto, "tcp" | "udp") {
            return Err(invalid(&e));
        }
        let port = |p: &str| p.trim().parse::<u16>().ok().filter(|p| *p > 0);
        let (lo, hi) = match ports.split_once('-') {
            Some((a, b)) => (port(a), port(b)),
            None => (port(ports), port(ports)),
        };
        let (Some(lo), Some(hi)) = (lo, hi) else {
            return Err(invalid(&e));
        };
        if lo > hi {
            return Err(invalid(&e));
        }
        for p in lo..=hi {
            if mapped.insert((p, proto.to_string())) {
                req.ports.push(PortMapping {
                    container_port: p,
                    host_port: None,
                    host_ip: String::new(),
                    protocol: proto.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// The OCI runtime a client asks for by `name`: a name of `[runtimes]`, or
/// the default one `default` (asked for with no name, its file name or its
/// path).  Nothing else: a client of a root server must not have it run a
/// binary of its choice, so neither a path nor a name in PATH is taken.
pub(super) fn client_runtime(
    name: &str,
    default: &Path,
    config: Option<&velarx_config::Config>,
) -> Result<PathBuf, String> {
    if name.is_empty() {
        return Ok(default.to_path_buf());
    }
    if let Some(found) = config.and_then(|c| c.configured_runtime(name)) {
        return found;
    }
    let default_name = default.file_name().unwrap_or_default().to_string_lossy();
    if Path::new(name) == default || default_name == name {
        return Ok(default.to_path_buf());
    }
    let mut known = vec![default_name.into_owned()];
    known.extend(config.iter().flat_map(|c| c.runtimes.keys().cloned()));
    Err(format!(
        "unknown OCI runtime {name:?}: the runtimes of this engine are {} (the \
         names of [runtimes] in its configuration)",
        known.join(", ")
    ))
}

impl ContainerService {
    /// A `--workdir` the image lacked, at the start: podman looks at each
    /// start, so what was copied into the container since the create
    /// counts.  Ok when the directory is there now, else why it is not.
    pub(crate) async fn workdir_now(
        &self,
        container: &velarx_db::ContainerRecord,
        config: &ContainerConfig,
    ) -> ContainerResult<Result<(), String>> {
        let path = format!("/{}", config.working_dir.trim_matches('/'));
        let image = self.db.get_image(&container.image_id).await?;
        let layers = self.image_layers(&image).await?;
        let tree = self.image_view(&layers)?;
        let digests: Vec<String> = layers.iter().map(|l| l.key.to_string()).collect();
        let translate = self.translation(&config.uid_mappings, &config.gid_mappings);
        let objects = self.image_service.objects();
        let view = self.storage().stopped_view(
            &self.writable(&container.id),
            super::super::imagecopy::TreeSource {
                tree: &*tree,
                layers: &digests,
                objects: &objects,
                verity: self.image_service.verity(),
                fetcher: None,
                translate: &translate,
            },
        );
        let Ok(view) = view else {
            return Ok(Err(workdir_missing(&path, &container.id)));
        };
        Ok(match view.stat(&path) {
            Ok((st, _)) if st.is_dir => Ok(()),
            Ok(_) => Err(workdir_not_a_directory(&path, &container.id)),
            Err(_) => Err(workdir_missing(&path, &container.id)),
        })
    }

    /// The merged tree of the layers that have a table of contents.
    /// The passwd and group files of the image of a container (empty when
    /// it has none), read from its table of contents: links are resolved
    /// in the image, never on the host.
    pub(super) fn image_users(
        &self,
        layers: &[LayerRecord],
        config: &ContainerConfig,
    ) -> ContainerResult<(Vec<u8>, Vec<u8>)> {
        let translate = self.translation(&config.uid_mappings, &config.gid_mappings);
        let mut files = self.image_files(layers, &translate, &["etc/passwd", "etc/group"])?;
        let group = files.pop().unwrap_or_default();
        Ok((files.pop().unwrap_or_default(), group))
    }

    /// Files of the image of a container (empty for one it lacks), read
    /// as `image_users` reads its files.
    pub(super) fn image_files(
        &self,
        layers: &[LayerRecord],
        translate: &velarx_fuse::IdTranslate,
        paths: &[&str],
    ) -> ContainerResult<Vec<Vec<u8>>> {
        let tree = self.image_view(layers)?;
        let layer_digests: Vec<String> = layers.iter().map(|l| l.key.to_string()).collect();
        let objects = self.image_service.objects();
        let source = crate::services::imagecopy::TreeSource {
            tree: &*tree,
            layers: &layer_digests,
            objects: &objects,
            verity: self.image_service.verity(),
            fetcher: Some(&*self.image_service),
            translate,
        };
        text_files(&source, paths)
    }

    /// The number of ids an image needs: one more than the highest owner
    /// of its files and than the ids of its `/etc/passwd` and `/etc/group`.
    pub(super) fn image_max_id(&self, layers: &[LayerRecord]) -> ContainerResult<u32> {
        let (uids, gids) = velarx_graph::objects::image_owners(layers);
        let from_files = uids
            .iter()
            .chain(&gids)
            .filter(|id| **id != 65534)
            .max()
            .map_or(0, |m| m.saturating_add(1));
        // (read back through the driver, as every read of the content of an
        // image is; an unreadable file counts for none)
        let files = self
            .image_files(layers, &Default::default(), &["etc/passwd", "etc/group"])
            .unwrap_or_default();
        let from_users = velarx_base::idmap::max_id_of_passwd_group(
            &files
                .first()
                .map(|f| String::from_utf8_lossy(f))
                .unwrap_or_default(),
            &files
                .get(1)
                .map(|f| String::from_utf8_lossy(f))
                .unwrap_or_default(),
        );
        Ok(from_files.max(from_users))
    }

    /// The SELinux settings of a new container: `label=` and, when SELinux
    /// is enabled and the container is confined, a level no other
    /// container has.  The second of the pair says that the level was
    /// chosen here (not given by the user, not the one of a target): it is
    /// only a choice until the container is recorded, where it is checked
    /// again (`insert_container_distinct`), for another create may have
    /// chosen it meanwhile.
    pub(super) async fn selinux_config(
        &self,
        so: &SecurityOptions,
        privileged: bool,
        host_ns: bool,
        share_with: Option<&str>,
        preferred: Option<&str>,
    ) -> ContainerResult<(Option<crate::container::selinux::SelinuxConfig>, bool)> {
        use crate::container::selinux;
        // an explicit level, label=files, label=disable or the namespaces of the
        // host win
        let own = so.selinux_level.is_some()
            || so.selinux_files
            || so.selinux_label.as_deref() == Some("disable")
            || host_ns;
        let mut shared_level = None;
        if let Some(target) = share_with.filter(|_| !own) {
            // the settings of the target, as podman shares the label
            let rec = self.db.get_container(target).await?;
            let theirs: ContainerConfig = serde_json::from_str(&rec.config)?;
            match theirs.selinux {
                // a privileged target is not confined: the container is, with
                // the level of the target's files (or one of its own)
                Some(t) if !t.disable && t.level.is_none() => shared_level = t.file_level,
                theirs => return Ok((theirs, false)),
            }
        }
        let mut s = selinux::SelinuxConfig {
            disable: so.selinux_label.as_deref() == Some("disable") || host_ns,
            user: so.selinux_user.clone(),
            role: so.selinux_role.clone(),
            typ: so.selinux_type.clone(),
            filetype: so.selinux_filetype.clone(),
            level: so
                .selinux_level
                .clone()
                .or(shared_level.filter(|_| !privileged)),
            files: so.selinux_files,
            file_level: None,
        };
        s.validate().map_err(ContainerError::InvalidArgument)?;
        if s.disable || !selinux::enabled() {
            return Ok((Some(s).filter(|s| s.disable), false));
        }
        // the level of the process of a confined container, of the files of a
        // privileged one that asks for them labelled
        let needs_level = s.level.is_none() && (!privileged || s.files);
        if needs_level {
            let used = self.db.container_selinux_levels().await?;
            let level = match preferred {
                Some(p) if !used.iter().any(|u| selinux::levels_overlap(p, u)) => p.to_string(),
                _ => selinux::allocate_level(&used).map_err(ContainerError::InvalidArgument)?,
            };
            if privileged {
                s.file_level = Some(level);
            } else {
                s.level = Some(level);
            }
        }
        Ok((Some(s), needs_level))
    }

    /// The namespace `kind` (`pid`, `ipc`...) of `--pid` and the like:
    /// private (empty), `host`, `container:ID` (its path) or `ns:PATH`.
    /// The namespace of a container that has the host's is the host's for a
    /// rootless engine, which cannot join the host's namespace.
    pub(super) async fn ns_mode(
        &self,
        kind: &str,
        mode: &NsMode,
        rootless: bool,
    ) -> ContainerResult<String> {
        match mode {
            NsMode::Default | NsMode::Private | NsMode::Shareable => Ok(String::new()),
            NsMode::Host => Ok("host".into()),
            NsMode::Ns(path) => Ok(path.clone()),
            // resolved at each start: the process of the target changes
            NsMode::Container(target) => {
                let rec = self
                    .db
                    .get_container(target)
                    .await
                    .map_err(|_| ContainerError::NotFound(target.to_string()))?;
                let o = serde_json::from_str::<ContainerConfig>(&rec.config)
                    .unwrap_or_default()
                    .options;
                let theirs = match kind {
                    "pid" => o.pid_ns,
                    "ipc" => o.ipc_ns,
                    "uts" => o.uts_ns,
                    _ => o.cgroup_ns,
                };
                if rootless && theirs == "host" {
                    return Ok("host".into());
                }
                Ok(format!("container:{}", rec.id))
            }
            // (`none` is for the IPC namespace only; `pod` is for a member
            // of a pod that shares the namespace, which joins its infra's)
            NsMode::Off | NsMode::Pod => Err(ContainerError::InvalidArgument(format!(
                "invalid {kind} namespace mode `{mode}`"
            ))),
        }
    }

    /// The network a request joins (`container:ID`), in its mode and its
    /// list of networks, named by the id of the container, as the other
    /// namespaces are: a rename or a new container of the same name does
    /// not change what it joins and starts first.  A target that does not
    /// exist is left to the create.
    pub(super) async fn resolve_joined_network(
        &self,
        req: &mut CreateContainerRequest,
    ) -> ContainerResult<()> {
        let NetworkMode::Container(target) = &req.network_mode else {
            return Ok(());
        };
        let Ok(rec) = self.db.get_container(target).await else {
            return Ok(());
        };
        let joined = NetworkMode::Container(rec.id);
        for n in &mut req.networks {
            if NetworkMode::parse(n) == req.network_mode {
                *n = joined.to_string();
            }
        }
        req.network_mode = joined;
        Ok(())
    }

    /// The IPC namespace of `--ipc` as [`Self::ns_mode`] has it, and as
    /// podman: `none` is a namespace of its own (without /dev/shm), and the
    /// IPC namespace of a container that is `private` cannot be joined.
    async fn ipc_mode(&self, mode: &NsMode, rootless: bool) -> ContainerResult<String> {
        if *mode == NsMode::Off {
            return Ok(String::new());
        }
        let ns = self.ns_mode("ipc", mode, rootless).await?;
        let Some(target) = ns.strip_prefix("container:") else {
            return Ok(ns);
        };
        let rec = self.db.get_container(target).await?;
        let config: ContainerConfig = serde_json::from_str(&rec.config).unwrap_or_default();
        let o = &config.options;
        if o.ipc_ns.is_empty() && !o.shm_shareable && !o.no_shm {
            return Err(ContainerError::InvalidArgument(format!(
                "joining IPC of container {} is not allowed: non-shareable IPC (hint: use \
                 IpcMode:shareable for the donor container)",
                rec.id
            )));
        }
        Ok(ns)
    }

    /// The edits of the CDI devices of `--device vendor.com/class=name`
    /// (the devices that are not a path), from the spec directories of the
    /// configuration (`[containers] cdi_spec_dirs`).
    pub(super) fn cdi_edits(
        &self,
        req: &CreateContainerRequest,
    ) -> ContainerResult<crate::cdi::Edits> {
        let names: Vec<String> = req
            .devices
            .iter()
            .filter(|d| !d.path_on_host.starts_with('/'))
            .map(|d| d.path_on_host.clone())
            .collect();
        if names.is_empty() {
            return Ok(Default::default());
        }
        let dirs = crate::cdi::spec_dirs(&self.containers_config.cdi_spec_dirs);
        crate::cdi::resolve(&names, &dirs).map_err(ContainerError::InvalidArgument)
    }

    /// The create options that shape the spec, checked; `own_userns`: the
    /// container has a user namespace of its own (devices are bind mounted).
    pub(super) async fn create_options(
        &self,
        req: &CreateContainerRequest,
        own_userns: bool,
        joined_userns: bool,
        systemd: bool,
    ) -> ContainerResult<velarx_wire::options::CreateOptions> {
        use velarx_wire::options as o;
        let inv = ContainerError::InvalidArgument;
        let rootless = crate::userns::rootless::in_user_namespace()?;
        let mut out = o::CreateOptions {
            annotations: req.annotations.clone().into_iter().collect(),
            bind_devices: rootless || own_userns,
            oom_kill_disable: req.oom_kill_disable,
            read_only_tmpfs: req.read_only_rootfs && !req.no_read_only_tmpfs,
            systemd,
            systemd_tmpfs_size: req.shm_size_systemd,
            ..Default::default()
        };
        for u in &req.ulimits {
            out.rlimits
                .push(o::rlimit(&u.name, u.soft, u.hard).map_err(inv)?);
        }
        if let Some(adj) = req.oom_score_adj {
            if velarx_limit_core::oom_score_adj(i64::from(adj)).is_none() {
                return Err(inv(format!("invalid oom score adjustment {adj}")));
            }
        }
        for d in req
            .devices
            .iter()
            .filter(|d| d.path_on_host.starts_with('/'))
        {
            let (host, path) = (&d.path_on_host, &d.path_in_container);
            let path = if path.is_empty() { host } else { path };
            let access = if d.cgroup_permissions.is_empty() {
                "rwm"
            } else {
                &d.cgroup_permissions
            };
            out.devices
                .extend(o::resolve_device(host, path, access).map_err(inv)?);
        }
        if req.privileged {
            // no device cgroup: every device is allowed
            out.devices
                .extend(o::privileged_devices(out.bind_devices, systemd));
        }
        if !req.device_cgroup_rules.is_empty() && (velarx_base::conf::rootless()? || own_userns) {
            return Err(inv(
                "device cgroup rules are not supported in rootless mode or in a user namespace"
                    .into(),
            ));
        }
        for r in &req.device_cgroup_rules {
            out.device_rules.push(o::parse_device_rule(r).map_err(inv)?);
        }
        out.pid_ns = self.ns_mode("pid", &req.pid_mode, rootless).await?;
        out.ipc_ns = self.ipc_mode(&req.ipc_mode, rootless).await?;
        // (shareable is the default: any container's /dev/shm can be
        // joined with --ipc container:ID; `none` has no /dev/shm at all)
        out.shm_shareable = matches!(req.ipc_mode, NsMode::Default | NsMode::Shareable);
        out.no_shm = req.ipc_mode == NsMode::Off;
        // procfs and mqueue are mounted by the owner of their namespace: a
        // user namespace of its own cannot join those of another one
        if own_userns && !joined_userns {
            for (kind, ns) in [("pid", &out.pid_ns), ("ipc", &out.ipc_ns)] {
                if !ns.is_empty() && ns != "host" {
                    return Err(inv(format!(
                        "a container with a user namespace of its own cannot join a {kind} \
                         namespace: join the user namespace of the target as well (--userns container:ID)"
                    )));
                }
            }
        }
        out.uts_ns = self.ns_mode("uts", &req.uts_mode, rootless).await?;
        out.cgroup_ns = self.ns_mode("cgroup", &req.cgroupns_mode, rootless).await?;
        // The restarts the monitor makes join the namespaces the first run
        // joined (it keeps them open: monitor::restart).
        out.personality = req
            .personality
            .as_deref()
            .map(o::parse_personality)
            .transpose()
            .map_err(inv)?;
        out.rdt_class = req.rdt_class.clone();
        if out.rdt_class.as_deref() == Some("") {
            return Err(inv(
                "--rdt-class needs the name of a class of service".into()
            ));
        }
        out.rootfs_propagation = req
            .rootfs_propagation
            .as_deref()
            .map(o::parse_propagation)
            .transpose()
            .map_err(inv)?;
        let res = req.resources.as_ref();
        out.shm_size = req.shm_size.or(res.and_then(|r| r.shm_size));
        if out.shm_size == Some(0) {
            return Err(inv("the size of /dev/shm must be positive".into()));
        }
        if let Some(r) = res {
            out.blkio_weight = r.blkio_weight;
            if let Some(w) = r.blkio_weight {
                if !(10..=1000).contains(&w) {
                    return Err(inv(format!("invalid block IO weight {w}: 10 to 1000")));
                }
            }
            let throttles = |list: &[ThrottleDevice], one: &Option<String>, iops: bool| {
                let mut v = Vec::new();
                for t in list {
                    v.push(o::throttle(&t.path, t.rate)?);
                }
                if let Some(s) = one {
                    v.push(o::parse_throttle(s, iops)?);
                }
                Ok::<_, String>(v)
            };
            out.read_bps =
                throttles(&r.blkio_device_read_bps, &r.device_read_bps, false).map_err(inv)?;
            out.write_bps =
                throttles(&r.blkio_device_write_bps, &r.device_write_bps, false).map_err(inv)?;
            out.read_iops =
                throttles(&r.blkio_device_read_iops, &r.device_read_iops, true).map_err(inv)?;
            out.write_iops =
                throttles(&r.blkio_device_write_iops, &r.device_write_iops, true).map_err(inv)?;
            for d in &r.blkio_weight_device {
                out.weight_devices.push(
                    o::weight_device(&d.path, d.device.map(|n| (n.major, n.minor)), d.weight)
                        .map_err(inv)?,
                );
            }
            out.unified = r
                .cgroup_conf
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            for h in &r.hugepage_limits {
                out.hugepages
                    .push(o::hugepage_limit(&h.page_size, h.limit).map_err(inv)?);
            }
        }
        Ok(out)
    }

    /// The user namespace of a running container to join: the id of the
    /// container, the path of the namespace and its mappings.
    pub(super) async fn userns_of_container(
        &self,
        target: &str,
    ) -> ContainerResult<(String, String, Vec<IdMapping>, Vec<IdMapping>)> {
        let record =
            self.db.get_container(target).await.map_err(|_| {
                ContainerError::NotFound(format!("container {target} for --userns"))
            })?;
        let config: ContainerConfig = serde_json::from_str(&record.config)?;
        if config.userns_mode == UsernsMode::Host {
            return Err(ContainerError::Runtime(
                crate::container::RuntimeError::Runtime(format!(
                    "container {target} has no user namespace of its own to join"
                )),
            ));
        }
        // The namespace is that of the target's process when the container
        // starts (the daemon puts it in the spec then); its mappings are
        // known from its record, running or not.
        let path = match (record.state, record.pid) {
            (RecordState::Running, Some(pid)) => format!("/proc/{pid}/ns/user"),
            _ if !config.uid_mappings.is_empty() => "/proc/self/ns/user".to_string(),
            _ => {
                return Err(ContainerError::NotRunning(format!(
                    "Target container {target} is not running (required for --userns=container:ID)"
                )))
            }
        };
        Ok((record.id, path, config.uid_mappings, config.gid_mappings))
    }
}

/// The files `paths` of the image `source` reads (empty for one it lacks),
/// each read up to one byte more than 16 MiB: a larger one, and one that
/// is no regular file, is an error that names it.
fn text_files(
    source: &crate::services::imagecopy::TreeSource<'_>,
    paths: &[&str],
) -> ContainerResult<Vec<Vec<u8>>> {
    const MAX: u64 = 16 << 20;
    paths
        .iter()
        .map(|path| match source.read_file(path, MAX + 1)? {
            Some(b) if b.len() as u64 > MAX => Err(ContainerError::InvalidArgument(format!(
                "/{path} of the image is larger than 16 MiB"
            ))),
            Some(b) => Ok(b),
            None => Ok(Vec::new()),
        })
        .collect()
}

#[cfg(test)]
mod text_file_tests {
    use super::*;

    /// The files a create reads of an image read from a mount: a
    /// `/etc/passwd` of 64 MiB is refused naming it (one byte past the limit
    /// is read, not the file), one of 16 MiB is read, a FIFO is refused naming
    /// it, a missing file is nothing.
    #[test]
    fn a_text_file_of_a_mounted_image_is_read_up_to_16_mib() {
        struct NoObjects;
        impl velarx_storage::ObjectOpener for NoObjects {
            fn object_file(&self, _: &str, _: u64) -> std::io::Result<std::fs::File> {
                Err(std::io::Error::other("the files are read from the mount"))
            }
        }
        let image = tempfile::tempdir().unwrap();
        let etc = image.path().join("etc");
        std::fs::create_dir(&etc).unwrap();
        std::fs::File::create(etc.join("passwd"))
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        std::fs::File::create(etc.join("group"))
            .unwrap()
            .set_len(16 << 20)
            .unwrap();
        rustix::fs::mkfifoat(rustix::fs::CWD, etc.join("shadow"), rustix::fs::Mode::RUSR).unwrap();
        let root = rustix::fs::open(
            image.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let tree = velarx_fuse::MountedImage::new(root).unwrap();
        let translate = velarx_fuse::IdTranslate::default();
        let source = crate::services::imagecopy::TreeSource {
            tree: &tree,
            layers: &[],
            objects: &NoObjects,
            verity: velarx_storage::VerityMode::Off,
            fetcher: None,
            translate: &translate,
        };
        let err = text_files(&source, &["etc/passwd"]).unwrap_err();
        assert!(
            err.to_string()
                .contains("/etc/passwd of the image is larger than 16 MiB"),
            "{err}"
        );
        let files = text_files(&source, &["etc/group", "etc/none"]).unwrap();
        assert_eq!(files[0].len(), 16 << 20);
        assert!(files[1].is_empty());
        let err = text_files(&source, &["etc/shadow"]).unwrap_err();
        assert!(
            err.to_string()
                .contains("/etc/shadow of the image is not a regular file"),
            "{err}"
        );
    }
}
