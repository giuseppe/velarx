// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn bundle_file_mount(
    bundle_path: &Path,
    name: &str,
    content: &[u8],
    dest: &str,
    ro: bool,
) -> ContainerResult<MountConfig> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = bundle_path.join(name);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(content)?;
    let mut options = vec!["rbind".to_string(), "rprivate".to_string()];
    if ro {
        options.push("ro".to_string());
    }
    Ok(MountConfig {
        source: path.to_string_lossy().into_owned(),
        target: dest.to_string(),
        mount_type: Some("bind".to_string()),
        options,
        engine: true,
        ..Default::default()
    })
}

/// [`bundle_file_mount`] of a file that is the donor's: the file of the
/// container whose network namespace this one joins (a pod's infra
/// container) is linked into the bundle, so that a change of it in place
/// (the engine's, or the container's) is seen by both, and it stays when the
/// donor's bundle goes.  `None` when it cannot be linked (another file
/// system): the caller copies it.
pub(super) fn linked_file_mount(
    bundle_path: &Path,
    name: &str,
    donor: &Path,
    dest: &str,
) -> Option<MountConfig> {
    let path = bundle_path.join(name);
    let _ = fs::remove_file(&path);
    fs::hard_link(donor, &path).ok()?;
    Some(MountConfig {
        source: path.to_string_lossy().into_owned(),
        target: dest.to_string(),
        mount_type: Some("bind".to_string()),
        options: vec!["rbind".to_string(), "rprivate".to_string()],
        engine: true,
        ..Default::default()
    })
}

/// The idmapped mounts: the OCI mount has `uidMappings` and `gidMappings`,
/// which the typed spec does not know.
pub(super) fn apply_mount_idmaps(spec: &mut serde_json::Value, mounts: &[MountConfig]) {
    let Some(list) = spec.get_mut("mounts").and_then(|m| m.as_array_mut()) else {
        return;
    };
    let map = |maps: &[IdMapping]| {
        serde_json::Value::Array(
            maps.iter()
                .map(|m| {
                    serde_json::json!({
                        "containerID": m.container_id,
                        "hostID": m.host_id,
                        "size": m.size,
                    })
                })
                .collect(),
        )
    };
    for m in mounts.iter().filter(|m| !m.uid_mappings.is_empty()) {
        let found = list
            .iter_mut()
            .rev()
            .find(|o| o.get("destination").and_then(|d| d.as_str()) == Some(m.target.as_str()));
        if let Some(o) = found {
            o["uidMappings"] = map(&m.uid_mappings);
            o["gidMappings"] = map(&m.gid_mappings);
        }
    }
}

/// What two mounts on one destination must share to be one: everything,
/// but the options of a named volume (`-v V:/x -v V:/x:ro` is one mount).
pub(super) fn same_mount(
    m: &crate::container::MountConfig,
) -> serde_json::Result<serde_json::Value> {
    let mut same = serde_json::to_value(m)?;
    if m.volume.is_some() {
        if let Some(o) = same.as_object_mut() {
            o.remove("options");
        }
    }
    Ok(same)
}

/// The host paths a pattern names, sorted (a component at a time, as Go's
/// `filepath.Glob` that podman uses: a `*` matches a name that starts with a
/// dot too); those of a relative pattern from the current directory.
fn glob_paths(pattern: &str) -> std::io::Result<Vec<String>> {
    let mut found = vec![if pattern.starts_with('/') {
        "/".to_string()
    } else {
        String::new()
    }];
    for component in pattern.split('/').filter(|c| !c.is_empty()) {
        let mut next = Vec::new();
        for base in &found {
            if !velarx_wire::parse::has_glob(component) {
                let path = format!("{base}{component}");
                if Path::new(&path).symlink_metadata().is_ok() {
                    next.push(format!("{path}/"));
                }
                continue;
            }
            let dir = if base.is_empty() { "." } else { base.as_str() };
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            for entry in entries {
                let name = entry?.file_name().to_string_lossy().into_owned();
                if velarx_wire::parse::fnmatch(component, &name) {
                    next.push(format!("{base}{name}/"));
                }
            }
        }
        found = next;
    }
    let mut paths = Vec::new();
    for p in found {
        let p = p.trim_end_matches('/');
        if !p.is_empty() {
            paths.push(std::path::absolute(p)?.display().to_string());
        }
    }
    paths.sort();
    Ok(paths)
}

/// The `--mount type=bind` arguments of a `--mount type=glob`: one for each
/// path the source pattern names, mounted at the destination (the path itself
/// without one) under its own name, with the other options; `None` for a
/// mount of another type.
fn expand_glob_mount(arg: &str) -> ContainerResult<Option<Vec<String>>> {
    let parts: Vec<&str> = arg.split(',').filter(|p| !p.is_empty()).collect();
    if !parts.contains(&"type=glob") {
        return Ok(None);
    }
    let (mut source, mut target) = (None, None);
    let mut options = Vec::new();
    for part in parts {
        match part.split_once('=') {
            Some(("type", _)) => {}
            Some(("source" | "src", v)) if source.is_none() => source = Some(v),
            Some(("target" | "dst" | "dest" | "destination", v)) if target.is_none() => {
                target = Some(v)
            }
            _ => options.push(part),
        }
    }
    let source = source.unwrap_or_default();
    let matches = if source.is_empty() {
        Vec::new()
    } else {
        glob_paths(source)?
    };
    if matches.is_empty() {
        return Err(ContainerError::InvalidArgument(format!(
            "no file paths matching glob {source:?}"
        )));
    }
    let options = options.join(",");
    Ok(Some(
        matches
            .iter()
            .map(|path| {
                let dest = match target {
                    None => path.clone(),
                    Some(t) => {
                        let name = path.rsplit('/').next().unwrap_or(path);
                        format!("{}/{name}", t.trim_end_matches('/'))
                    }
                };
                format!("type=bind,source={path},target={dest},{options}")
            })
            .collect(),
    ))
}

impl ContainerService {
    /// The mounts of a new container: those already worked out, `-v`,
    /// `--mount`, `--tmpfs`, and the volumes of the image that nothing else
    /// mounts.  Named volumes are created as needed (`new_volumes` collects
    /// them, to be removed if the container is not created; an anonymous
    /// one says it was made for `container_id`).
    pub(super) async fn gather_mounts(
        &self,
        req: &CreateContainerRequest,
        container_id: &str,
        image_volumes: &HashMap<String, serde_json::Value>,
        new_volumes: &mut Vec<String>,
    ) -> ContainerResult<Vec<MountConfig>> {
        let mut mounts = req.mounts.clone();
        let mut specs = Vec::new();
        for v in &req.volumes {
            specs.push(MountSpec::parse_volume_arg(v)?);
        }
        let mut mount_targets = Vec::new();
        for m in &req.mount {
            // (the artifacts are mounted once the image is known: `artifact_mounts`)
            if crate::services::artifact::parse_artifact_mount(m)
                .map_err(|e| ContainerError::InvalidArgument(e.to_string()))?
                .is_some()
            {
                continue;
            }
            let args = expand_glob_mount(m)?.unwrap_or_else(|| vec![m.clone()]);
            for m in &args {
                let spec = MountSpec::parse_mount_arg(m)?;
                // (podman merges only -v: two --mount on one destination are
                // refused, whatever their options)
                let target = crate::services::clean_target(&spec.target)?;
                if mount_targets.contains(&target) {
                    return Err(ContainerError::InvalidArgument(format!(
                        "{target}: duplicate mount destination"
                    )));
                }
                mount_targets.push(target);
                specs.push(spec);
            }
        }
        for m in &req.bind_mounts {
            specs.push(MountSpec::bind(&m.source, &m.target, &m.options)?);
        }
        for m in &req.image_mounts {
            let spec = MountSpec::image(&m.image, &m.target, m.subpath.as_deref())?;
            // (as a `--mount`: one destination, one mount)
            if mount_targets.contains(&spec.target) {
                return Err(ContainerError::InvalidArgument(format!(
                    "{}: duplicate mount destination",
                    spec.target
                )));
            }
            mount_targets.push(spec.target.clone());
            specs.push(spec);
        }
        for t in &req.tmpfs {
            specs.push(MountSpec::parse_tmpfs_arg(t)?);
        }
        for spec in specs {
            let (cfg, created) = self
                .volume_service
                .resolve_mount_new(spec, Some(container_id))
                .await?;
            if let (true, Some(name)) = (created, &cfg.volume) {
                new_volumes.push(name.clone());
            }
            mounts.push(cfg);
        }

        let mode = match req.image_volume.as_str() {
            "" | "bind" => "bind",
            m @ ("tmpfs" | "ignore") => m,
            m => {
                return Err(ContainerError::Volume(VolumeError::Parse(format!(
                    "invalid image volume mode `{m}`: bind, tmpfs or ignore"
                ))))
            }
        };
        let mut wanted: Vec<&String> = image_volumes.keys().collect();
        wanted.sort();
        for path in wanted {
            let target = crate::services::clean_target(path)?;
            if mode == "ignore" || mounts.iter().any(|m| m.target == target) {
                continue;
            }
            let arg = if mode == "tmpfs" {
                format!("type=tmpfs,target={target}")
            } else {
                target
            };
            let spec = if mode == "tmpfs" {
                MountSpec::parse_mount_arg(&arg)?
            } else {
                MountSpec::parse_volume_arg(&arg)?
            };
            let (cfg, created) = self
                .volume_service
                .resolve_mount_new(spec, Some(container_id))
                .await?;
            if let (true, Some(name)) = (created, &cfg.volume) {
                new_volumes.push(name.clone());
            }
            mounts.push(cfg);
        }

        // The volumes made for the container take its file type
        // (`label=filetype:TYPE`), as podman labels them: those it made
        // (or the API made for it) that no container used yet.
        let mut so = req.security_opt.clone();
        for o in &req.security_opts {
            // (one that is not valid is refused with the others, later)
            let _ = so.apply(o);
        }
        if let Some(ft) = so
            .selinux_filetype
            .as_deref()
            .filter(|_| crate::container::selinux::enabled())
        {
            let c = crate::container::selinux::Contexts::host();
            let label = format!("{}:{}:{ft}:s0", c.file_user, c.file_role);
            for name in mounts.iter().filter_map(|m| m.volume.as_ref()) {
                let v = self.volume_service.get(name).await?;
                let fresh = new_volumes.contains(name)
                    || (v.state.needs_copy_up
                        && !v.state.copied_up
                        && self.volume_service.users(name).await?.is_empty());
                if fresh {
                    crate::container::selinux::relabel_path(&v.mountpoint, &label, &[])?;
                }
            }
        }

        // (as podman: the same mount twice on a destination is one, a named
        // volume twice is one whatever its options, the first ones; two
        // sources, or a bind or tmpfs with other options, are refused)
        let mut seen: HashMap<String, serde_json::Value> = HashMap::new();
        let mut kept = Vec::with_capacity(mounts.len());
        for m in mounts {
            let same = same_mount(&m)?;
            match seen.get(&m.target) {
                Some(first) if *first == same => continue,
                Some(_) => {
                    return Err(ContainerError::InvalidArgument(format!(
                        "{}: duplicate mount destination",
                        m.target
                    )))
                }
                None => {
                    seen.insert(m.target.clone(), same);
                }
            }
            kept.push(m);
        }
        let mut mounts = kept;
        let judging = if mounts.iter().any(|m| m.image.is_some()) {
            self.signature_judging(&req.security_opt, &req.security_opts)?
        } else {
            SignatureJudging::Policy
        };
        for m in &mut mounts {
            if let Some(i) = m.image.as_mut() {
                let (image, tags) = self
                    .image_service
                    .get_with_tags(&i.image)
                    .await
                    .map_err(|_| ContainerError::ImageNotFound(i.image.clone()))?;
                // an image mounted is judged as the image of the container
                self.image_service
                    .verify_stored(&i.image, &image, &tags, judging)
                    .await?;
                i.digest = super::create::pinned_digest(&i.image).map(|d| d.to_string());
                i.image = image.id;
            }
        }
        Ok(mounts)
    }

    /// What the mounts need from the root file system once it is mounted:
    /// the first use of the volumes (copy-up, owner), `U`, idmapped mounts,
    /// image mounts and sub paths.
    pub(super) async fn prepare_mounts(
        &self,
        config: &mut ContainerConfig,
        bundle: &Path,
        layers: &[LayerRecord],
    ) -> ContainerResult<()> {
        use crate::services::volcopy;
        use velarx_base::idmap;
        if config.mounts.is_empty() {
            return Ok(());
        }
        let io_err = |m: String| ContainerError::Io(std::io::Error::other(m));
        // The root file system is mounted by the monitor when the container
        // starts: the volumes read the image from the images of its layers.
        let mut merged: Option<Arc<dyn velarx_fuse::view::ImageTree>> = None;
        let layer_digests: Vec<String> = layers.iter().map(|l| l.key.to_string()).collect();
        let translate = self.translation(&config.uid_mappings, &config.gid_mappings);
        // The user matters to the volumes that get an owner and to `U`.
        let (uid, gid) = config
            .process_user
            .as_ref()
            .map_or((0, 0), |u| (u.uid, u.gid));
        let own_ns = !config.uid_mappings.is_empty();
        // The ids the process has outside of the user namespace.
        let host_of = |maps: &[IdMapping], id: u32, what: &str| -> ContainerResult<u32> {
            if !own_ns {
                return Ok(id);
            }
            idmap::to_parent(maps, id).ok_or_else(|| {
                io_err(format!(
                    "the {what} {id} of the user is not mapped in the user namespace"
                ))
            })
        };
        let (host_uid, host_gid) = (
            host_of(&config.uid_mappings, uid, "uid")?,
            host_of(&config.gid_mappings, gid, "gid")?,
        );

        let mut image_index = 0;
        // the image mounts the driver hands over as mount descriptors
        let mut mount_fds = 0usize;
        let mut overlay_index = 0;
        let mut subpath_index = 0;
        // (read before the mounts are borrowed)
        let enforced = self.digests_enforced(config);
        let label = crate::services::lifecycle::mount_label(config);
        {
            for m in config.mounts.iter_mut() {
                if let Some(velarx_wire::request::Owner { uid: u, gid: g }) = m.secret_owner {
                    // only a file the engine wrote for this container
                    let file = PathBuf::from(&m.source);
                    let ours = file.parent() == Some(self.secrets_dir_of(&config.id).as_path());
                    if !ours {
                        return Err(io_err(format!(
                            "{} is not a secret of the container",
                            m.source
                        )));
                    }
                    let (hu, hg) = (
                        host_of(&config.uid_mappings, u, "uid")?,
                        host_of(&config.gid_mappings, g, "gid")?,
                    );
                    rustix::fs::chownat(
                        rustix::fs::CWD,
                        &file,
                        Some(rustix::fs::Uid::from_raw(hu)),
                        Some(rustix::fs::Gid::from_raw(hg)),
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .map_err(|e| io_err(format!("the owner of the secret {}: {e}", m.target)))?;
                    continue;
                }
                if let Some(ov) = m.overlay.as_mut() {
                    // The monitor mounts the overlay at `bundle/ovol/N` when
                    // the container starts: that is the source of the mount.
                    let lower = PathBuf::from(&m.source);
                    if !lower.is_dir() {
                        return Err(io_err(format!(
                            "the lower directory {} of the overlay volume is not a directory",
                            lower.display()
                        )));
                    }
                    ov.owner = Some(velarx_wire::request::Owner {
                        uid: host_of(&config.uid_mappings, 0, "uid")?,
                        gid: host_of(&config.gid_mappings, 0, "gid")?,
                    });
                    ov.lower = Some(m.source.clone());
                    let merged = bundle.join("ovol").join(overlay_index.to_string());
                    fs::create_dir_all(&merged)?;
                    m.source = merged.to_string_lossy().into_owned();
                    overlay_index += 1;
                    continue;
                }
                if m.subpath.is_some() && m.volume.is_none() {
                    return Err(io_err(format!(
                        "the mount at {} has a subpath but no volume",
                        m.target
                    )));
                }
                if let Some(opt) = m.idmap.clone() {
                    if !own_ns {
                        return Err(io_err(format!(
                            "the idmap option of {} needs a user namespace (--userns or --uidmap)",
                            m.target
                        )));
                    }
                    let (u, g) =
                        idmap::parse_mount_idmap(&opt, &config.uid_mappings, &config.gid_mappings)
                            .map_err(|e| io_err(e.to_string()))?;
                    idmap::validate(&u).map_err(|e| io_err(e.to_string()))?;
                    idmap::validate(&g).map_err(|e| io_err(e.to_string()))?;
                    (m.uid_mappings, m.gid_mappings) = (u, g);
                }
                let idmapped = m.idmap.is_some();
                // the owner as the volume stores it
                let (set_uid, set_gid) = if idmapped {
                    (uid, gid)
                } else {
                    (host_uid, host_gid)
                };

                if let Some(image) = m.image.clone() {
                    if image.rw {
                        return Err(io_err(
                            "read-write image mounts are not supported yet".into(),
                        ));
                    }
                    let record = self
                        .image_service
                        .get(&image.image)
                        .await
                        .map_err(|_| ContainerError::ImageNotFound(image.image.clone()))?;
                    let layers = self.image_layers(&record).await?;
                    if let (Some(why), Some(d)) = (enforced, &image.digest) {
                        self.image_service
                            .verify_pinned(
                                &format!("--mount type=image,source=@{d}"),
                                &d.parse::<velarx_types::digest::Digest>().map_err(|e| {
                                    ContainerError::InvalidArgument(format!(
                                        "{d}: not a digest: {e}"
                                    ))
                                })?,
                                why,
                                &record,
                                &layers,
                            )
                            .await?;
                    }
                    // (as for the image of the container: refused now, and
                    // again at every start)
                    let accepted = if enforced.is_some() {
                        Some(
                            self.image_service
                                .create_digests(
                                    &record,
                                    &layers,
                                    config.security_opt.verity_enforce,
                                )
                                .map_err(|e| {
                                    let source = match &image.digest {
                                        Some(digest) => format!("@{digest}"),
                                        None => record.id[..record.id.len().min(12)].to_string(),
                                    };
                                    ContainerError::InvalidArgument(format!(
                                        "--mount type=image,source={source}: {e}"
                                    ))
                                })?,
                        )
                    } else {
                        None
                    };
                    // with the mapping of the container (idmapped)
                    let mapping = own_ns
                        .then(|| self.translation(&config.uid_mappings, &config.gid_mappings));
                    // (how the owners are shown: the driver refuses owners
                    // outside it at the create already, as at each start)
                    let translate = self.translation(&config.uid_mappings, &config.gid_mappings);
                    // what the driver cannot do is refused before anything is
                    // made (a driver without image mounts, a user namespace
                    // it cannot show the ids of)
                    self.image_service
                        .check_container_request(own_ns, true)
                        .map_err(|e| {
                            ContainerError::InvalidArgument(format!("--mount type=image: {e}"))
                        })?;
                    let container = crate::storage_driver::Writable::new(&config.id, bundle);
                    let mount = velarx_graph::MountRequest {
                        container: &container,
                        purpose: velarx_graph::Purpose::Volume {
                            index: image_index as u32,
                        },
                        image: &record,
                        layers: &layers,
                        mapping: mapping.as_ref(),
                        translate: Some(&translate),
                        idmap_mount: crate::services::lifecycle::root_fd::may_idmap_mounts(own_ns),
                        label: label.as_deref(),
                        verity: match &accepted {
                            Some(accepted) => velarx_graph::VerityAsk::Enforce {
                                accepted,
                                chain: None,
                            },
                            None => velarx_graph::VerityAsk::Off,
                        },
                        volatile: false,
                    };
                    // what the driver keeps for this container's mount, and
                    // the plan as the monitor reads it: no descriptor is made
                    // here, the start asks for them and numbers them
                    let planned = self.image_service.image_volume_create(&mount).await?;
                    crate::services::lifecycle::root_fd::require_volume_label(
                        self.storage().name(),
                        &planned,
                        label.as_deref(),
                    )?;
                    crate::services::lifecycle::root_fd::count_volume_fd(
                        self.storage().name(),
                        &planned,
                        &mut mount_fds,
                    )?;
                    let cm = crate::services::lifecycle::root_fd::plan_of(
                        &planned.plan,
                        planned.idmap,
                        false,
                    );
                    m.source = self
                        .prepare_image_mount(image_index, &image, &layers, bundle)?
                        .to_string_lossy()
                        .to_string();
                    velarx_fuse::plan::write(
                        &bundle.join("imagevol"),
                        &format!("{image_index}."),
                        &cm,
                    )?;
                    image_index += 1;
                    continue;
                }

                if let Some(name) = m.volume.clone() {
                    let vol = self.volume_service.get(&name).await?;
                    let subpath = m.subpath.clone();
                    let nocopy =
                        m.nocopy || vol.options.keys().any(|k| k.eq_ignore_ascii_case("nocopy"));
                    let (undo_u, undo_g) = (m.uid_mappings.clone(), m.gid_mappings.clone());
                    let (mountpoint, target, state, chown_u) = (
                        vol.mountpoint.clone(),
                        m.target.clone(),
                        vol.state.clone(),
                        m.chown,
                    );
                    // (a container made from a directory reads that one)
                    let rootfs_path = config.rootfs.as_ref().map(|d| d.path.clone());
                    let tree = match (&rootfs_path, &merged) {
                        (Some(_), _) => None,
                        (None, Some(t)) => Some(t.clone()),
                        (None, None) => {
                            let t = self.image_view(layers)?;
                            merged = Some(t.clone());
                            Some(t)
                        }
                    };
                    let layer_digests = layer_digests.clone();
                    let (objects, verity, fetcher, translate) = (
                        self.image_service.objects(),
                        self.image_service.verity(),
                        self.image_service.clone(),
                        translate.clone(),
                    );
                    let sub = subpath.clone();
                    let (chown_uid, chown_gid) = (host_uid, host_gid);
                    let new_state = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
                        let vol_fd = volcopy::open_dir(&mountpoint)?;
                        // a sub path is looked up inside the volume: the
                        // copy-up and the owner go to that directory (the
                        // monitor looks it up again when it mounts it)
                        let vol_fd = match &sub {
                            None => vol_fd,
                            Some(sub) => volcopy::open_dir_in_root(vol_fd.as_fd(), sub)?
                                .ok_or_else(|| {
                                    std::io::Error::other(format!(
                                        "the volume has no directory {sub}"
                                    ))
                                })?,
                        };
                        // U: the directory that is mounted, through the
                        // descriptor that was looked up inside the volume
                        if chown_u && sub.is_some() {
                            volcopy::chown_tree(&vol_fd, chown_uid, chown_gid)?;
                        }
                        let (root_fd, tree_source, fd_source);
                        let source: &dyn volcopy::ImageSource = match (&rootfs_path, &tree) {
                            (Some(path), _) => {
                                root_fd = volcopy::open_dir(path)?;
                                fd_source = volcopy::FdSource(root_fd.as_fd());
                                &fd_source
                            }
                            (None, Some(tree)) => {
                                tree_source = crate::services::imagecopy::TreeSource {
                                    tree: &**tree,
                                    layers: &layer_digests,
                                    objects: &objects,
                                    verity,
                                    fetcher: Some(&*fetcher),
                                    translate: &translate,
                                };
                                &tree_source
                            }
                            (None, None) => unreachable!("an image has a tree"),
                        };
                        volcopy::first_use(
                            &volcopy::FirstUse {
                                source,
                                volume: vol_fd.as_fd(),
                                target: &target,
                                copy_up: !nocopy,
                                owner: Some((set_uid, set_gid)),
                                follow_image: !chown_u,
                                undo: (!undo_u.is_empty()).then_some((&undo_u[..], &undo_g[..])),
                            },
                            state,
                        )
                    })
                    .await
                    .map_err(|e| io_err(e.to_string()))??;
                    // the state is the volume's, not of a directory of it
                    if new_state != vol.state && subpath.is_none() {
                        self.volume_service.set_state(&name, &new_state).await?;
                    }
                    if subpath.is_some() {
                        // the monitor mounts the directory at
                        // `bundle/subvol/N`, the source of the mount
                        m.subpath_root = Some(vol.mountpoint.to_string_lossy().into_owned());
                        let at = bundle.join("subvol").join(subpath_index.to_string());
                        fs::create_dir_all(&at)?;
                        m.source = at.to_string_lossy().into_owned();
                        subpath_index += 1;
                    }
                }

                // (a sub path of a volume was given its owner above)
                if m.chown && m.subpath.is_none() {
                    match m.mount_type.as_deref() {
                        Some("tmpfs") => {
                            m.options.push(format!("uid={uid}"));
                            m.options.push(format!("gid={gid}"));
                        }
                        _ => {
                            let source = PathBuf::from(&m.source);
                            if m.volume.is_none() && !volcopy::chown_allowed(&source) {
                                return Err(io_err(format!(
                                    "the U option is refused for {}: it is a system directory",
                                    source.display()
                                )));
                            }
                            tokio::task::spawn_blocking(move || {
                                volcopy::chown_path(&source, host_uid, host_gid)
                            })
                            .await
                            .map_err(|e| io_err(e.to_string()))??;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// `U` at every start but the first (podman's ChangeHostPathOwnership):
    /// what was given back to someone else since is recursively given to the
    /// user again, when the directory (or file) mounted has another owner.
    pub(crate) async fn chown_mounts_again(&self, config: &ContainerConfig) -> ContainerResult<()> {
        use crate::services::volcopy;
        let io_err = |m: String| ContainerError::Io(std::io::Error::other(m));
        let todo: Vec<_> = config
            .mounts
            .iter()
            .filter(|m| m.chown && m.mount_type.as_deref() != Some("tmpfs"))
            .collect();
        if todo.is_empty() {
            return Ok(());
        }
        let (uid, gid) = config
            .process_user
            .as_ref()
            .map_or((0, 0), |u| (u.uid, u.gid));
        let host = |maps: &[IdMapping], id: u32| -> ContainerResult<u32> {
            if config.uid_mappings.is_empty() {
                return Ok(id);
            }
            velarx_base::idmap::to_parent(maps, id).ok_or_else(|| {
                io_err(format!(
                    "the id {id} of the user is not mapped in the user namespace"
                ))
            })
        };
        let (host_uid, host_gid) = (
            host(&config.uid_mappings, uid)?,
            host(&config.gid_mappings, gid)?,
        );
        for m in todo {
            let (source, root, sub) = (
                PathBuf::from(&m.source),
                m.subpath_root.clone().map(PathBuf::from),
                m.subpath.clone(),
            );
            tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                use std::os::unix::fs::MetadataExt;
                // a sub path is looked up inside the volume again
                if let (Some(root), Some(sub)) = (root, sub) {
                    let vol = volcopy::open_dir(&root)?;
                    let Some(dir) = volcopy::open_dir_in_root(vol.as_fd(), &sub)? else {
                        return Ok(());
                    };
                    let st = rustix::fs::fstat(&dir)?;
                    if (st.st_uid, st.st_gid) != (host_uid, host_gid) {
                        volcopy::chown_tree(&dir, host_uid, host_gid)?;
                    }
                    return Ok(());
                }
                // (a source that is gone is the runtime's to report)
                let Ok(st) = std::fs::symlink_metadata(&source) else {
                    return Ok(());
                };
                if (st.uid(), st.gid()) != (host_uid, host_gid) {
                    volcopy::chown_path(&source, host_uid, host_gid)?;
                }
                Ok(())
            })
            .await
            .map_err(|e| io_err(e.to_string()))??;
        }
        Ok(())
    }

    /// An image to mount in a container: the monitor mounts the images of its
    /// layers (with the ids of the container) and binds it where the OCI
    /// mount expects it, `bundle/imagevol/N`.
    pub(super) fn prepare_image_mount(
        &self,
        index: usize,
        image: &crate::container::ImageMountConfig,
        layers: &[LayerRecord],
        bundle: &Path,
    ) -> ContainerResult<PathBuf> {
        let io_err = |m: String| ContainerError::Io(std::io::Error::other(m));
        if let Some(sub) = &image.subpath {
            // The monitor resolves it inside the image again; this tells the
            // user now.
            let tree = self.image_view(layers)?;
            let is_dir = tree
                .resolve(sub.trim_start_matches('/'))
                .and_then(|n| tree.node(n))
                .is_some_and(|n| n.entry.entry_type == velarx_storage::TocEntryType::Dir);
            if !is_dir {
                return Err(io_err(format!("the image has no directory {sub}")));
            }
        }
        let dir = bundle.join("imagevol");
        fs::create_dir_all(dir.join(index.to_string()))?;
        Ok(dir.join(index.to_string()))
    }

    pub(super) async fn layers_of(
        &self,
        image: &velarx_db::ImageRecord,
    ) -> ContainerResult<Vec<LayerRecord>> {
        // (an image being pulled has its layers in the staging area, those
        // the store has already in the store)
        let layers = if image.is_lazy {
            self.image_service.staged_layers(&image.id).await?
        } else {
            self.db.get_image_layers(&image.id).await?
        };
        Ok(layers)
    }

    /// The mounts of the `--mount type=artifact` of `args`: each file of an
    /// artifact of the store bound read-only (it is the blob of the store,
    /// named by its digest), where podman puts it: on `dst` if it is a file
    /// of the image or is not in it (one file), else in the directory.
    pub(super) fn artifact_mounts(
        &self,
        args: &[String],
        layers: &[LayerRecord],
        bundle: &Path,
    ) -> ContainerResult<Vec<MountConfig>> {
        use crate::services::artifact::{mount_targets, parse_artifact_mount, ArtifactStore};
        let invalid = |e: crate::services::artifact::ArtifactError| {
            ContainerError::InvalidArgument(e.to_string())
        };
        let mut specs = Vec::new();
        for a in args {
            if let Some(spec) = parse_artifact_mount(a).map_err(invalid)? {
                specs.push(spec);
            }
        }
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let store = ArtifactStore::open(&self.root_dir.join("artifacts")).map_err(invalid)?;
        let tree = self.image_view(layers)?;
        // The blobs are linked in the bundle, which the container can
        // reach (the store is the user's, it may not be); a copy on
        // another file system.
        let dir = bundle.join("artifacts");
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o755)
                .recursive(true)
                .create(&dir)?;
        }
        let mut n = 0;
        let mut out = Vec::new();
        for spec in specs {
            let artifact = store.get(&spec.source).map_err(invalid)?;
            let blobs = store
                .blob_paths(&artifact, &spec.filter())
                .map_err(invalid)?;
            let dest_is_dir = tree.resolve_following(&spec.dest).and_then(|n| {
                tree.node(n)
                    .map(|n| matches!(n.entry.entry_type, velarx_storage::TocEntryType::Dir))
            });
            for (source, target) in mount_targets(&spec, &blobs, dest_is_dir).map_err(invalid)? {
                let linked = dir.join(n.to_string());
                n += 1;
                if std::fs::hard_link(&source, &linked).is_err() {
                    velarx_storage::copy_path(&source, &linked)?;
                }
                out.push(MountConfig {
                    source: linked.to_string_lossy().into_owned(),
                    target,
                    mount_type: Some("bind".to_string()),
                    // read-only: the source is the blob of the store
                    options: vec!["bind".into(), "ro".into()],
                    ..Default::default()
                });
            }
        }
        Ok(out)
    }

    /// Relabel what the container mounts: the files of its bundle and its
    /// secrets with its own label, the `:z` sources with the shared one, the
    /// `:Z` ones with its own.
    pub(super) fn relabel_mounts(
        &self,
        config: &ContainerConfig,
        bundle_path: &Path,
    ) -> ContainerResult<()> {
        use crate::container::selinux;
        let Some(s) = config.selinux.as_ref().filter(|_| selinux::enabled()) else {
            return Ok(());
        };
        let (_, Some(label)) = selinux::labels(s, config.privileged, selinux::Contexts::host())
        else {
            return Ok(());
        };
        let engine = [self.state_dir.clone(), self.root_dir.clone()];
        let secrets = self.secrets_dir();
        let fail = |src: &str, e: std::io::Error| {
            ContainerError::InvalidArgument(format!("cannot relabel {src}: {e}"))
        };
        for m in &config.mounts {
            let src = Path::new(&m.source);
            let own = src.starts_with(bundle_path) || src.starts_with(&secrets);
            let target = match (m.relabel.as_deref(), own) {
                (_, true) => Some(label.clone()),
                (Some("z"), _) => selinux::shared_label(&label),
                (Some("Z"), _) => Some(label.clone()),
                _ => None,
            };
            let Some(l) = target else { continue };
            // a named volume is in the directory of the engine
            let forbidden: &[std::path::PathBuf] = if own || m.volume.is_some() {
                &[]
            } else {
                &engine
            };
            selinux::relabel_path(src, &l, forbidden).map_err(|e| fail(&m.source, e))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod glob_tests {
    use super::*;

    #[test]
    fn a_glob_mount_is_a_bind_mount_of_each_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().display().to_string();
        for f in ["v1a", "v1b", "v2", ".v1hidden"] {
            fs::write(dir.path().join(f), "").unwrap();
        }
        let found = glob_paths(&format!("{root}/v1*")).unwrap();
        assert_eq!(found, [format!("{root}/v1a"), format!("{root}/v1b")]);
        assert!(glob_paths(&format!("{root}/v3*")).unwrap().is_empty());
        assert_eq!(
            glob_paths(&format!("{root}/.v?hidden")).unwrap(),
            [format!("{root}/.v1hidden")]
        );
        // (as Go's: a star matches a dot)
        assert_eq!(glob_paths(&format!("{root}/*")).unwrap().len(), 4);

        let mounts = expand_glob_mount(&format!("type=glob,src={root}/v1*,ro"))
            .unwrap()
            .unwrap();
        assert_eq!(
            mounts,
            [
                format!("type=bind,source={root}/v1a,target={root}/v1a,ro"),
                format!("type=bind,source={root}/v1b,target={root}/v1b,ro"),
            ]
        );
        let under = expand_glob_mount(&format!("type=glob,source={root}/v2,destination=/d/"))
            .unwrap()
            .unwrap();
        assert_eq!(under, [format!("type=bind,source={root}/v2,target=/d/v2,")]);
        assert!(expand_glob_mount("type=bind,src=/a,dst=/b")
            .unwrap()
            .is_none());
        let none = expand_glob_mount(&format!("type=glob,src={root}/zz*")).unwrap_err();
        assert!(
            none.to_string().contains("no file paths matching glob"),
            "{none}"
        );
        let none = expand_glob_mount("type=glob,dst=/d").unwrap_err();
        assert_eq!(none.to_string(), "no file paths matching glob \"\"");
    }
}
