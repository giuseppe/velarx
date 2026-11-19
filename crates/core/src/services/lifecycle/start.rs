// SPDX-License-Identifier: Apache-2.0
use super::root_fd;
use super::*;
use crate::services::SignatureJudging;
use velarx_db::RecordState;
use velarx_types::digest::Digest;
use velarx_wire::chain::Chain;
use velarx_wire::request::{CgroupsMode, NetworkMode};

/// Who asks for a start of a container.  The digests of the images are
/// checked against what the user typed on the command that starts: the
/// engine takes none from a row of its store.
#[derive(Debug, Clone)]
pub enum StartCheck {
    /// A command of a user, with the digests (`sha256:...`) typed on it: of
    /// the image of the container, and of the images mounted in it.
    /// `option`: they were given by `--verify-image` (the `verify_image` of
    /// the REST start), not found in the references of a `run`: they are
    /// refused, by name, for a container whose digests are not enforced,
    /// and each must be the digest of an image the container was made from.
    User { digests: Vec<Digest>, option: bool },
    /// A command of a user that starts the containers of a pod (`pod
    /// start`, a play of Kubernetes YAML): the digests typed on it are for all the
    /// containers, each takes those that name its images.  Whether every
    /// digest names an image that starts, and every enforced image a digest,
    /// is [`ContainerService::check_pod_digests`], before the first
    /// container starts.
    Pod { digests: Vec<Digest> },
    /// No command line: the engine starts it (the restart policy, a
    /// dependency, a pod, the CRI, the start at boot).  The digests of the
    /// record of the container are all there is to check against, and a
    /// writer of the store can change them.
    Engine,
}

impl StartCheck {
    /// The digests a user typed on the command that starts (none: a start of
    /// the engine).
    pub fn typed(&self) -> &[Digest] {
        match self {
            StartCheck::User { digests, .. } | StartCheck::Pod { digests } => digests,
            StartCheck::Engine => &[],
        }
    }

    /// Refuse the digests typed for a start that checks nothing: the
    /// container `name` runs, or its monitor holds file systems it mounted
    /// before (`why`), so they would not be compared with anything.
    pub fn refuse_unchecked(&self, name: &str, why: &str) -> ContainerResult<()> {
        match self.typed() {
            [] => Ok(()),
            [first, ..] => Err(ContainerError::InvalidArgument(format!(
                "container {name}: --verify-image {}: {why}: nothing would be checked now; stop it, then start it with --verify-image",
                first
            ))),
        }
    }

    /// [`Self::refuse_unchecked`] for a container that runs: not for a
    /// member of a pod, which is not started and has no digest to be held
    /// to (the digests are for the members that start).
    pub fn refuse_running(&self, name: &str, why: &str) -> ContainerResult<()> {
        match self {
            StartCheck::Pod { .. } => Ok(()),
            _ => self.refuse_unchecked(name, why),
        }
    }
}

/// The restart by its policy of a run of a container that ended
/// ([`ContainerService::start_checked`]).
pub(super) struct PolicyRestart {
    /// When the run that ended started (the record's `started_at`)
    pub run: Option<String>,
    /// The restarts with this one
    pub count: u32,
}

/// The lock of the start of a container, until it is dropped.
pub struct StartLock {
    _file: std::fs::File,
}

/// Point the namespaces of the spec at SPEC_PATH whose kind PATHS names at
/// the path given there.
fn set_namespace_paths(spec_path: &Path, paths: &[(&str, String)]) -> io::Result<()> {
    let mut spec: serde_json::Value = serde_json::from_slice(&std::fs::read(spec_path)?)?;
    if let Some(list) = spec["linux"]["namespaces"].as_array_mut() {
        for ns in list.iter_mut() {
            if let Some((_, path)) = paths.iter().find(|(k, _)| ns["type"] == *k) {
                ns["path"] = serde_json::json!(path);
            }
        }
    }
    crate::container::spec_file::write(spec_path, &spec)
}

/// Make the tmpfs on /dev/shm of the spec at SPEC_PATH a bind of DIR (the
/// spec stays as it is without one).
fn bind_shm(spec_path: &Path, dir: &Path) -> io::Result<()> {
    let mut spec: serde_json::Value = serde_json::from_slice(&std::fs::read(spec_path)?)?;
    let Some(mount) = spec["mounts"]
        .as_array_mut()
        .and_then(|m| m.iter_mut().find(|m| m["destination"] == "/dev/shm"))
        .filter(|m| m["type"] == "tmpfs")
    else {
        return Ok(());
    };
    *mount = serde_json::json!({"destination": "/dev/shm", "type": "bind",
        "source": dir, "options": ["rbind", "nosuid", "noexec", "nodev"]});
    crate::container::spec_file::write(spec_path, &spec)
}

/// Where each chain of `mc` broke if the configuration of the monitor, which
/// hands it the digests of the layers, was not `written`.
fn say_unwritten(mc: &MonitorConfig, written: &io::Result<()>) {
    let (Some(image), Err(_)) = (mc.image.as_ref(), written) else {
        return;
    };
    let root = image.chain.as_ref().map(|p| (String::new(), p));
    let mounts = image.image_mounts.iter().filter_map(|v| {
        let plan = v.chain.as_ref()?;
        Some((format!("image mount {}: ", v.destination), plan))
    });
    for (scope, plan) in root.into_iter().chain(mounts) {
        Chain::resume(&scope, plan.total, plan.done, &[], &[]).broken(|| {
            (
                velarx_wire::monitor::proto::CONFIG_FILE.to_string(),
                "written".into(),
                "error".into(),
            )
        });
    }
}

/// What the monitor goes on from, if the debug log follows the chain: the
/// links the engine checked.
fn plan_of(chain: &Chain) -> Option<crate::monitor::config::ChainPlan> {
    chain.is_on().then(|| crate::monitor::config::ChainPlan {
        total: chain.total(),
        done: chain.done(),
        trail: chain.trail(),
        layers: chain.layers(),
        fuse_layers: chain.fuse_layers(),
    })
}

/// What enforces the digests of the mounts the driver handed over, in the
/// configuration of the monitor, and the chain of trust each driver measured
/// the layers of (the links it said): the monitor goes on from them, checks
/// the mount it attaches and closes the chain.
fn say_enforced(
    image: &mut crate::monitor::config::ImageConfig,
    accepted: &root_fd::Accepted,
    chains: &mut dyn Iterator<Item = Option<Chain>>,
) {
    if let Some(e) = &accepted.root {
        image.verity = e.verity;
        if let Some(chain) = chains.next().flatten() {
            image.chain = plan_of(&chain);
        }
    }
    for (volume, e) in image.image_mounts.iter_mut().zip(&accepted.volumes) {
        volume.verity = e.verity;
        if let Some(chain) = chains.next().flatten() {
            volume.chain = plan_of(&chain);
        }
    }
}

/// The signature policy accepted the manifest of `image` at this start
/// (`judging`: how it was judged), in the debug log of the chain of trust,
/// whose links read the same bytes.
fn say_signature(
    scope: impl FnOnce() -> String,
    judging: SignatureJudging,
    image: &velarx_db::ImageRecord,
) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let mode = match judging {
        SignatureJudging::Require(_) => "require",
        _ => "check",
    };
    tracing::debug!(
        "verity chain: {}signature {mode} -> {} manifest",
        scope(),
        image.manifest_digest
    );
}

/// How long the log of the monitor in `dir` is now.
fn monitor_log_len(dir: &Path) -> u64 {
    std::fs::metadata(dir.join(velarx_wire::monitor::proto::LOG_FILE)).map_or(0, |m| m.len())
}

/// The lines of the chain of trust (`verity chain:`) the monitor of `dir`
/// wrote to its log from offset `from` on, in the debug log of the engine:
/// the monitor does the checks of the layer images and the mount, and its
/// log is not the user's.
fn repeat_chain_lines(dir: &Path, from: u64) {
    use std::io::{Read, Seek};
    // (a start says a few lines per layer)
    const MAX: u64 = 1 << 20;
    let mut text = Vec::new();
    let read =
        std::fs::File::open(dir.join(velarx_wire::monitor::proto::LOG_FILE)).and_then(|mut f| {
            f.seek(std::io::SeekFrom::Start(from))?;
            f.take(MAX).read_to_end(&mut text)
        });
    if let Err(e) = read {
        tracing::debug!("the log of the monitor cannot be read: {e}");
        return;
    }
    for line in String::from_utf8_lossy(&text).lines() {
        if let Some(at) = line.find("verity chain: ") {
            tracing::debug!("{}", &line[at..]);
        }
    }
}

/// The digests typed on `--verify-image` (the `verify_image` of a start),
/// which are the texts of the request until here.
pub fn verify_image_digests(texts: &[String]) -> ContainerResult<Vec<Digest>> {
    texts
        .iter()
        .map(|d| {
            d.parse().map_err(|_| {
                ContainerError::InvalidArgument(format!(
                    "--verify-image {}: not a digest (sha256:<64 lowercase hex digits> or sha512:<128 lowercase hex digits>)",
                    velarx_types::printable(d)
                ))
            })
        })
        .collect()
}

/// The digest a stored record names (none: a tag): a text that is no digest
/// is a record the store has been modified in.
fn stored_digest(text: Option<&str>) -> ContainerResult<Option<Digest>> {
    text.map(|d| {
        d.parse().map_err(|e| {
            ContainerError::InvalidArgument(format!(
                "the container's record names the digest {}: not a digest: {e}; the store was modified",
                velarx_types::printable(d)
            ))
        })
    })
    .transpose()
}

/// An image a container of a pod starts from, for [`pod_digests_refusal`].
#[derive(Debug, Clone)]
pub struct MemberImage {
    pub container: String,
    /// How the container names it (the image, or the image mount)
    pub reference: String,
    /// The digest the container was made from (none: a tag)
    pub digest: Option<Digest>,
    /// Why its digests are enforced (none: they are not)
    pub enforced: Option<&'static str>,
}

/// Why the digests `typed` do not fit the images of the containers a pod
/// starts, if they do not: every enforced image made from a digest is named
/// by one, and with `option` (`--verify-image`, not the references of a
/// play) each is the digest of an enforced image, as `start --verify-image`
/// holds one container to.  This only decides what to refuse by name before
/// the first container starts: each start hashes its images against the
/// digests typed, whatever the records say.
pub fn pod_digests_refusal(
    images: &[MemberImage],
    typed: &[Digest],
    option: bool,
) -> Option<String> {
    if option && !typed.is_empty() && images.iter().all(|i| i.enforced.is_none()) {
        return Some("--verify-image: the digests of the images of the containers that start are not enforced (--security-opt verity=enforce, [storage] composefs_digests = \"require\"): nothing holds the files to a digest".to_string());
    }
    for image in images {
        let (Some(why), Some(digest)) = (image.enforced, &image.digest) else {
            continue;
        };
        if !typed.contains(digest) {
            return Some(format!(
                "container {}: {}: the container was made from the digest {digest}, and the command gives none to hold its image to: pass --verify-image {digest} ({why})",
                image.container, image.reference
            ));
        }
    }
    if option {
        let held = |d: &Digest| {
            images
                .iter()
                .any(|i| i.enforced.is_some() && i.digest.as_ref() == Some(d))
        };
        if let Some(unused) = typed.iter().find(|d| !held(d)) {
            let made: Vec<String> = images
                .iter()
                .filter_map(|i| i.digest.as_ref().map(Digest::to_string))
                .collect();
            let made = if made.is_empty() {
                "they were made from no digest".to_string()
            } else {
                format!("they were made from {}", made.join(", "))
            };
            return Some(format!(
                "--verify-image {unused}: no image of the containers that start is held to it ({made})"
            ));
        }
    }
    None
}

/// What a check of an image against a digest is about: the image and its
/// layers, and how the debug log names the check.
#[derive(Clone, Copy)]
struct VerifyCtx<'a> {
    reference: &'a str,
    why: &'a str,
    image: &'a velarx_db::ImageRecord,
    layers: &'a [velarx_db::LayerRecord],
    /// The label of its lines in the debug log.
    scope: &'a str,
    /// The settings of the container the chain of the check counts.
    settings: usize,
}

impl ContainerService {
    /// This engine's command line up to its command (`velarx --config
    /// PATH`): what units run (generate systemd).
    pub fn engine_command(&self) -> Option<Vec<std::ffi::OsString>> {
        self.supervision.engine_command.clone()
    }

    /// The run directory of the monitor of a container.
    pub fn mon_dir(&self, id: &str) -> PathBuf {
        self.state_dir.join("mon").join(&id[..id.len().min(12)])
    }

    /// The log file of a container with the `k8s-file` driver.
    pub fn log_file(&self, id: &str) -> PathBuf {
        self.log_dir(id).join("container.log")
    }

    /// Whether the container is created without a session keyring of its
    /// own (`[containers] keyring = false`): refused when its runtime has no
    /// such option.  The RUN containers of a build do not read the setting
    /// (as buildah): rootless they have no keyring of their own when the
    /// runtime has the option (a default, not something asked for: a
    /// runtime without it makes them one), as root ones always have.
    fn no_new_keyring(&self, runtime: &Path, config: &ContainerConfig) -> ContainerResult<bool> {
        if config
            .labels
            .contains_key(crate::services::build::BUILD_LABEL)
        {
            return Ok(
                velarx_base::conf::rootless()? && crate::container::has_no_new_keyring(runtime)
            );
        }
        if self.containers_config.keyring {
            return Ok(false);
        }
        if !crate::container::has_no_new_keyring(runtime) {
            return Err(ContainerError::InvalidArgument(format!(
                "no session keyring of its own ([containers] keyring = false) \
                 needs an OCI runtime with `create --no-new-keyring` (crun, krun, runc and youki \
                 have it): {} has not",
                runtime.display()
            )));
        }
        Ok(true)
    }

    pub(crate) fn monitor_config(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> ContainerResult<MonitorConfig> {
        let short = &container.id[..container.id.len().min(12)];
        let runtime = self.runtime_for(config);
        if config.runtime.is_some() && !runtime.runtime_path().is_file() {
            return Err(ContainerError::InvalidArgument(format!(
                "the OCI runtime of the container ({}) is not there anymore: {}",
                config.runtime_name.as_deref().unwrap_or_default(),
                runtime.runtime_path().display()
            )));
        }
        let console_socket = config
            .tty
            .then(|| self.state_dir.join("mon").join(format!("{short}.console")));
        let bundle = self.bundle_dir(&container.id);
        let image = self.image_config(container, config)?;
        let mc = MonitorConfig {
            auto_remove: config.auto_remove,
            id: container.id.clone(),
            public_rootfs: crate::userns::rootless::public_rootfs(
                &bundle,
                &container.id,
                &config.uid_mappings,
            )?,
            runtime: runtime.runtime_path().to_path_buf(),
            runtime_args: super::super::cgroups_mode::runtime_args_for(
                runtime.args(),
                config.cgroups,
                config.cgroups_path.as_deref(),
                runtime.runtime_path(),
            ),
            runtime_root: self.runtime.state_dir().to_path_buf(),
            open_files: velarx_base::hardening::original_open_files(),
            no_new_keyring: self.no_new_keyring(runtime.runtime_path(), config)?,
            create_config: crate::container::has_crun_options(runtime.runtime_path()),
            bundle: self.bundle_dir(&container.id),
            tty: config.tty,
            group_add: config.group_add.clone(),
            groups_strict: config.groups_strict,
            env_has_home: config.env.iter().any(|e| e.starts_with("HOME=")),
            stdin_open: config.stdin_open,
            console_socket,
            log: self.log_config_of(container, config),
            drain_ms: self.containers_config.output_drain_ms,
            client_stall_ms: self
                .containers_config
                .client_stall_secs
                .saturating_mul(1000),
            timeout_secs: config.timeout,
            health: health_config(config),
            stop_signal: stop_settings(config).0,
            stop_timeout_secs: u64::from(stop_settings(config).1),
            restart: crate::monitor::restart::RestartConfig {
                policy: config.restart_policy.clone(),
                count: 0,
            },
            sdnotify: crate::monitor::notify::SdNotify::parse(&config.sdnotify).ok_or_else(
                || {
                    ContainerError::InvalidArgument(format!(
                        "the container has an invalid sdnotify mode `{}`",
                        config.sdnotify
                    ))
                },
            )?,
            image,
            hold_ports: Vec::new(),
            settle: None,
            // The monitor of a unit's container is the unit's main process.
            leave_parent: self.supervision.notify_socket.is_some(),
            // (set by `create_in_monitor_with`: the descriptors it passes)
            fds: Default::default(),
            preserve_holes: self.supervision.preserve_holes.clone(),
            notify_label: notify_label(config),
            private_mounts: !mounts_reach_the_host(config),
            pid_file: config.pid_file.as_ref().map(PathBuf::from),
            monitor_pid_file: config.conmon_pid_file.as_ref().map(PathBuf::from),
        };
        Ok(mc)
    }

    /// Why the fs-verity digests of the manifests are enforced for the
    /// container, if they are: the node's `[storage] composefs_digests =
    /// "require"` or the container's `--security-opt verity=enforce`.
    pub fn digests_enforced(&self, config: &ContainerConfig) -> Option<&'static str> {
        use velarx_config::ComposefsDigests;
        // (a driver that checks the digests at pull only enforces nothing at a
        // start; a request to enforce was refused at the start of the engine
        // and at the create of the container unless best effort is said)
        if self.image_service.verity_pull_only() {
            return None;
        }
        match (
            self.image_service.composefs_digests(),
            config.security_opt.verity_enforce,
        ) {
            (ComposefsDigests::Require, _) => Some("[storage] composefs_digests is \"require\""),
            (_, true) => Some("--security-opt verity=enforce"),
            _ => None,
        }
    }

    /// The images the containers `records` start from, which `typed` must
    /// fit (see [`pod_digests_refusal`]): refused by name before the first
    /// of them starts.  The digests recorded only say which to ask for.
    pub fn check_pod_digests(
        &self,
        records: &[ContainerRecord],
        typed: &[Digest],
        option: bool,
    ) -> ContainerResult<()> {
        let mut images = Vec::new();
        for record in records {
            let config: ContainerConfig = serde_json::from_str(&record.config)?;
            let container = config.name.clone().unwrap_or_else(|| record.id.clone());
            let enforced = self.digests_enforced(&config);
            images.push(MemberImage {
                container: container.clone(),
                reference: config.image.clone(),
                digest: config.pinned.as_ref().map(|p| p.digest),
                enforced,
            });
            for m in &config.mounts {
                if let Some(image) = &m.image {
                    images.push(MemberImage {
                        container: container.clone(),
                        reference: format!("--mount type=image,source={}", image.image),
                        digest: stored_digest(image.digest.as_deref())?,
                        enforced,
                    });
                }
            }
        }
        match pod_digests_refusal(&images, typed, option) {
            Some(why) => Err(ContainerError::InvalidArgument(why)),
            None => Ok(()),
        }
    }

    /// The check at every start of what the monitor will mount, before it
    /// is spawned: the stored manifest of the image of the container, and
    /// of each image mounted in it, is the one its id names and agrees with
    /// the records of the layers; the fs-verity digests that the monitor
    /// holds the EROFS images against come from that manifest, into the
    /// monitor's own configuration (the tmpfs of the run directory), never
    /// from the bundle.  A restart by the monitor (restart policy, health
    /// checks) keeps the file systems it mounted and checks nothing again.
    async fn verify_start_chain(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
        mc: &mut MonitorConfig,
        check: &StartCheck,
        judged: &[(String, velarx_db::ImageRecord)],
    ) -> ContainerResult<()> {
        let name = config.name.as_deref().unwrap_or(&container.id);
        let enforced = self.digests_enforced(config);
        // (none: a start of the engine, which has only the record to go by)
        let (user, option) = match check {
            StartCheck::User { digests, option } => (Some(digests.as_slice()), *option),
            StartCheck::Pod { digests } => (Some(digests.as_slice()), false),
            StartCheck::Engine => (None, false),
        };
        let typed = user.unwrap_or_default();
        if enforced.is_none() && mc.image.is_some() {
            tracing::debug!("verity chain: OFF");
        }
        if option && !typed.is_empty() && enforced.is_none() {
            return Err(ContainerError::InvalidArgument(format!(
                "container {name}: --verify-image: the digests of its images are not enforced (--security-opt verity=enforce, [storage] composefs_digests = \"require\"): nothing holds the files to a digest"
            )));
        }
        // (enforced, the root file system must be the one made from the
        // layers: without the bundle's file the monitor would mount none
        // and the container would run on whatever its directory holds)
        if let Some(why) = enforced {
            if !mc
                .image
                .as_ref()
                .is_some_and(|i| i.mount_rootfs && i.rootfs_dir.is_none())
            {
                return Err(ContainerError::InvalidArgument(format!(
                    "container {name}: {why}: its root file system is not made from the layers of its image (the bundle has no {}, or the container has a --rootfs directory): the store was modified",
                    velarx_fuse::plan::FILE
                )));
            }
        }
        // (a container of an image has the plan of its root file system in
        // its bundle from its create on: without it the runtime would run
        // the container on the empty directory of the bundle)
        if config.rootfs.is_none()
            && !velarx_fuse::plan::file(&self.bundle_dir(&container.id), "").exists()
        {
            return Err(ContainerError::InvalidArgument(format!(
                "container {name}: its bundle has no {}, the plan of its root file system: the container was made by another version of Velarx or the store was modified; remove it and create it again",
                velarx_fuse::plan::FILE
            )));
        }
        // (the check of the create, again: the node's `require` may have been
        // set since)
        if let Some(why) = enforced {
            let artifacts = self.bundle_dir(&container.id).join("artifacts");
            if config
                .mounts
                .iter()
                .any(|m| Path::new(&m.source).starts_with(&artifacts))
            {
                return Err(ContainerError::InvalidArgument(format!(
                    "container {name}: {why}: --mount type=artifact mounts files of an artifact, which states no fs-verity digest to check"
                )));
            }
        }
        let Some(image) = mc.image.as_mut() else {
            return Ok(());
        };
        let flag = config.security_opt.verity_enforce;
        let refuse = |e: velarx_types::ImageError| {
            ContainerError::InvalidArgument(format!("container {name}: {e}"))
        };
        image.enforce = enforced.is_some();
        // (the digests typed that verified an image of the container)
        let mut used: Vec<Digest> = Vec::new();
        let mut chain = Chain::off();
        if image.mount_rootfs {
            let record = self.image_of_start(judged, &container.image_id).await?;
            let layers = self.image_layers(&record).await?;
            if let Some(why) = enforced {
                // The chain starts from a digest the user typed on the
                // command that starts the container; the record of the
                // container only says which one to ask for.
                let record_digest = config.pinned.as_ref().map(|p| p.digest);
                let ctx = VerifyCtx {
                    reference: &config.image,
                    why,
                    image: &record,
                    layers: &layers,
                    scope: "",
                    settings: usize::from(config.pinned.is_some()) + 1,
                };
                let verified = self
                    .verify_root(user, record_digest, &ctx)
                    .await
                    .map_err(refuse)?;
                let (c, verified) = verified;
                chain = c;
                let verified = verified.map(|(v, digest)| {
                    used.push(digest);
                    v
                });
                if let (Some(v), Some(pinned)) = (&verified, &config.pinned) {
                    crate::services::check_taken(
                        &config.image,
                        why,
                        &pinned.taken,
                        &v.config,
                        config,
                        &chain,
                    )
                    .map_err(refuse)?;
                    chain.link(|| format!("{} config -> settings", v.manifest.config.digest));
                }
                if verified.is_some() {
                    let spec = self.bundle_dir(&container.id).join("config.json");
                    let spec: serde_json::Value = std::fs::read(&spec)
                        .map_err(ContainerError::from)
                        .and_then(|b| serde_json::from_slice(&b).map_err(ContainerError::from))
                        .inspect_err(|_| {
                            chain.broken(|| {
                                ("spec process".into(), "config.json".into(), "error".into())
                            })
                        })?;
                    crate::services::check_spec(&config.image, why, &spec, config, &chain)
                        .map_err(refuse)?;
                    chain.link(|| "settings -> spec process".to_string());
                }
            }
            self.image_service
                .start_digests_in(&record, &layers, flag, &chain)
                .map_err(refuse)?;
            image.chain = plan_of(&chain);
        }
        let volumes = config
            .mounts
            .iter()
            .filter_map(|m| Some((m, m.image.as_ref()?)));
        for (volume, (mount, mounted)) in image.image_mounts.iter_mut().zip(volumes) {
            // (the label of its lines in the debug log)
            let scope = match enforced.is_some() && tracing::enabled!(tracing::Level::DEBUG) {
                true => format!("image mount {}: ", mount.target),
                false => String::new(),
            };
            let mut chain = Chain::off();
            let record = self.image_of_start(judged, &mounted.image).await?;
            let layers = self.image_layers(&record).await?;
            let reference = match &mounted.digest {
                Some(digest) => format!("--mount type=image,source=@{digest}"),
                None => format!(
                    "--mount type=image,source={}",
                    &record.id[..record.id.len().min(12)]
                ),
            };
            if let Some(why) = enforced {
                let ctx = VerifyCtx {
                    reference: &reference,
                    why,
                    image: &record,
                    layers: &layers,
                    scope: &scope,
                    settings: 0,
                };
                let (c, verified) = self
                    .verify_root(user, stored_digest(mounted.digest.as_deref())?, &ctx)
                    .await
                    .map_err(refuse)?;
                chain = c;
                if let Some((_, digest)) = verified {
                    used.push(digest);
                }
            }
            self.image_service
                .start_digests_in(&record, &layers, flag, &chain)
                .map_err(|e| {
                    refuse(velarx_types::ImageError::Invalid(format!(
                        "{reference}: {e}"
                    )))
                })?;
            volume.chain = plan_of(&chain);
        }
        // (a digest given for no image of the container is an option that is
        // not honoured: a typo, another container's, or a record that no
        // longer says the container was made from a digest)
        if let Some(unused) = typed.iter().find(|d| option && !used.contains(d)) {
            let made: Vec<String> = config
                .pinned
                .iter()
                .map(|p| p.digest.to_string())
                .chain(
                    config
                        .mounts
                        .iter()
                        .filter_map(|m| m.image.as_ref()?.digest.clone()),
                )
                .collect();
            let made = if made.is_empty() {
                "it was made from no digest".to_string()
            } else {
                format!("it was made from {}", made.join(", "))
            };
            return Err(ContainerError::InvalidArgument(format!(
                "container {name}: --verify-image {unused}: no image of the container is held to it ({made})"
            )));
        }
        Ok(())
    }

    /// Hold the stored image to the digest of its reference: the image and
    /// the digest it hashes back to.  `recorded`: the digest the container was
    /// made from (none: a tag, which resolves in the store and has nothing to
    /// verify).  `typed`: the digests on the command of a user that starts it
    /// (none: a start of the engine, which has only the record to go by); if
    /// the container was made from a digest and the command gives none (or
    /// not the right one) the start is refused, whatever the record says.
    async fn verify_root(
        &self,
        typed: Option<&[Digest]>,
        recorded: Option<Digest>,
        ctx: &VerifyCtx<'_>,
    ) -> velarx_types::ImageResult<(Chain, Option<(crate::services::Verified, Digest)>)> {
        let VerifyCtx {
            reference,
            why,
            image,
            layers,
            scope,
            ..
        } = *ctx;
        // (made from a tag: it resolves in the store, nothing to verify)
        let Some(recorded) = recorded else {
            let chain = Chain::new(scope, crate::services::links_of_tag(layers.len()));
            chain.link(|| format!("root NONE {}", image.manifest_digest));
            chain.add(|| image.manifest_digest.to_string());
            return Ok((chain, None));
        };
        let digests: Vec<Digest> = match typed {
            None => vec![recorded],
            Some([]) => {
                return Err(velarx_types::ImageError::Invalid(format!(
                    "{reference}: the container was made from the digest {recorded}, and the command gives none to hold its image to: pass --verify-image {recorded} ({why})"
                )));
            }
            Some(typed) => typed.to_vec(),
        };
        // (with several digests typed, those of the other images of the
        // command do not verify this one: the chain of the one that does is
        // said, or of the first if none does, the one of the error)
        let quiet = digests.len() > 1;
        let mut errors = Vec::new();
        let mut first_chain = None;
        for digest in digests.iter().copied() {
            let (chain, verified) = self.verify_one(typed.is_some(), digest, ctx, quiet).await?;
            match verified {
                Ok(v) => {
                    chain.speak();
                    return Ok((chain, Some((v, digest))));
                }
                Err(e) => {
                    first_chain.get_or_insert(chain);
                    errors.push(e)
                }
            }
        }
        if let Some(chain) = first_chain {
            chain.speak();
        }
        // (a command that gives a digest for another image of the command
        // does not make a container made from a digest start without its own)
        let first = errors.swap_remove(0);
        Err(if typed.is_some() && !digests.contains(&recorded) {
            velarx_types::ImageError::Invalid(format!(
                "{first}; the container was made from {recorded}, which the command does not give"
            ))
        } else {
            first
        })
    }

    /// [`verify_root`] from `digest`, typed or (not `typed`) recorded, on a
    /// chain of its own that the debug log says, or (`held`) keeps until it
    /// speaks: the error of
    /// the store (the indexes cannot be read), or the chain and the result
    /// of the check.
    async fn verify_one(
        &self,
        typed: bool,
        root: Digest,
        ctx: &VerifyCtx<'_>,
        held: bool,
    ) -> velarx_types::ImageResult<(Chain, velarx_types::ImageResult<crate::services::Verified>)>
    {
        let VerifyCtx {
            reference,
            why,
            image,
            layers,
            scope,
            settings,
        } = *ctx;
        let indexes = self.image_service.pinned_indexes(&root, image).await;
        let indirect = indexes.as_ref().map_or(0, |indexes| {
            crate::services::index_links(&root, &image.manifest_digest, indexes)
        });
        let chain = Chain::new(
            scope,
            crate::services::links(indirect, settings, layers.len()),
        );
        let chain = if held { chain.held_back() } else { chain };
        match typed {
            true => chain.link(|| format!("root typed {root}")),
            false => chain.link(|| format!("root RECORDED {root}")),
        }
        chain.add(|| root.to_string());
        let indexes = indexes
            .inspect_err(|_| chain.broken(|| ("index".into(), root.to_string(), "error".into())))?;
        let verified =
            crate::services::verify(reference, &root, why, image, layers, &indexes, &chain);
        Ok((chain, verified))
    }

    /// What the monitor serves and mounts: the root file system of the
    /// container and the images mounted in it.
    pub(super) fn image_config(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> ContainerResult<Option<crate::monitor::config::ImageConfig>> {
        let bundle = self.bundle_dir(&container.id);
        let writable = self.writable_paths(&container.id);
        let spec = velarx_fuse::plan::file(&bundle, "");
        let mount_rootfs = spec.exists();
        let image_mounts: Vec<_> = config
            .mounts
            .iter()
            .filter_map(|m| m.image.as_ref().map(|i| (m, i)))
            .enumerate()
            .map(|(n, (m, i))| crate::monitor::config::ImageVolume {
                spec: velarx_fuse::plan::file(&bundle.join("imagevol"), &format!("{n}.")),
                subpath: i.subpath.clone(),
                target: std::path::PathBuf::from(&m.source),
                destination: m.target.clone(),
                chain: None,
                verity: Default::default(),
            })
            .collect();
        let overlay_volumes: Vec<_> = config
            .mounts
            .iter()
            .filter_map(|m| {
                let ov = m.overlay.as_ref()?;
                let lower = ov.lower.as_ref()?;
                let target = std::path::PathBuf::from(&m.source);
                let (upper, work, discard) = match (&ov.upperdir, &ov.workdir) {
                    (Some(u), Some(w)) => (u.into(), w.into(), false),
                    // next to the mount point, in the bundle
                    _ => (
                        target.with_extension("upper"),
                        target.with_extension("work"),
                        true,
                    ),
                };
                Some(crate::monitor::config::OverlayVolume {
                    lower: lower.into(),
                    upper,
                    work,
                    target,
                    discard,
                    owner: ov.owner.map(|o| (o.uid, o.gid)),
                })
            })
            .collect();
        let subpath_volumes: Vec<_> = config
            .mounts
            .iter()
            .filter_map(|m| {
                Some(crate::monitor::config::SubpathVolume {
                    volume: m.subpath_root.as_ref()?.into(),
                    subpath: m.subpath.clone()?,
                    target: m.source.clone().into(),
                })
            })
            .collect();
        let rootfs_dir = config
            .rootfs
            .as_ref()
            .map(|d| crate::monitor::config::RootfsMount {
                path: d.path.clone(),
                overlay: d.overlay,
                uid_mappings: d.uid_mappings.clone(),
                gid_mappings: d.gid_mappings.clone(),
            });
        if !mount_rootfs
            && rootfs_dir.is_none()
            && image_mounts.is_empty()
            && overlay_volumes.is_empty()
            && subpath_volumes.is_empty()
        {
            return Ok(None);
        }
        // (an engine without monitors of its own, the unit tests, makes no
        // image file system)
        if self.monitor_env.is_none() {
            return Ok(None);
        }
        Ok(Some(crate::monitor::config::ImageConfig {
            spec,
            overlay: writable.upper.parent().unwrap_or(&bundle).to_path_buf(),
            upper: Some(writable.upper),
            work: writable.work,
            rootfs: bundle.join("rootfs"),
            mount_rootfs,
            enforce: false,
            debug: tracing::enabled!(tracing::Level::DEBUG),
            chain: None,
            verity: Default::default(),
            rootfs_dir,
            translate: Some(self.translation(&config.uid_mappings, &config.gid_mappings)),
            // (wherever the monitor is: its scope, `split`'s runtime cgroup,
            // or where it was started for `no-conmon`; `disabled` touches none)
            servers_in_cgroup: config.cgroups != CgroupsMode::Disabled,
            userxattr: crate::userns::rootless::in_user_namespace()?,
            mount_label: mount_label(config),
            image_mounts,
            overlay_volumes,
            subpath_volumes,
        }))
    }

    /// Wait until the monitor of a previous run is gone.
    pub(super) async fn wait_monitor_gone(&self, dir: &Path) -> ContainerResult<()> {
        // (by its lock: one that is ending removed its socket already, and
        // the next monitor of the directory cannot take the lock until it
        // is gone; by its socket, one of another version, which takes none)
        let dir = dir.to_path_buf();
        let monitor = tokio::task::spawn_blocking(move || match monitor_alive(&dir) {
            Some(m) => Ok(m.pidfd),
            None => client::monitor_pid(&dir).and_then(velarx_sys::pidfd::open),
        })
        .await
        .map_err(|e| io_error(io::Error::other(e)))?;
        // (neither: no monitor)
        let pidfd = match monitor {
            Ok(pidfd) => pidfd,
            Err(e) if no_monitor(&e) => return Ok(()),
            Err(e) => return Err(io_error(e)),
        };
        tokio::time::timeout(Duration::from_secs(20), ended(pidfd))
            .await
            .map_err(|_| {
                io_error(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the monitor of the last run does not end",
                ))
            })?
            .map_err(io_error)
    }

    /// Put the namespaces of the containers this one joins in its spec,
    /// those of their processes of now (a restarted target has another
    /// process, a pid can be reused): each process is pinned by a pidfd and
    /// checked to be its container's.  The pidfds, to check that the targets
    /// still run once the container is in their namespaces.
    pub(super) async fn join_namespaces(
        &self,
        bundle: &Path,
        config: &ContainerConfig,
    ) -> ContainerResult<Vec<(String, std::os::fd::OwnedFd)>> {
        let o = &config.options;
        let mut joined: Vec<(&str, &str)> = [
            ("pid", &o.pid_ns),
            ("ipc", &o.ipc_ns),
            ("uts", &o.uts_ns),
            ("cgroup", &o.cgroup_ns),
        ]
        .into_iter()
        .filter_map(|(kind, ns)| ns.strip_prefix("container:").map(|t| (kind, t)))
        .collect();
        // --userns container:ID (the members of a pod with a user namespace)
        if let crate::container::UsernsMode::Container(target) = &config.userns_mode {
            joined.push(("user", target));
        }
        if joined.is_empty() {
            return Ok(Vec::new());
        }
        let mut pins = Vec::new();
        let mut paths = Vec::new();
        for (kind, target) in joined {
            let rec = self
                .db
                .get_container(target)
                .await
                .map_err(|_| ContainerError::NotFound(target.to_string()))?;
            let pid = match (rec.state, rec.pid) {
                (RecordState::Running, Some(pid)) if pid > 0 => pid,
                _ => {
                    return Err(ContainerError::NotRunning(format!(
                        "{target} (the container joins its {kind} namespace)"
                    )))
                }
            };
            // how the root of the target was made: a bound `--rootfs`, else an overlay
            let rootfs = super::super::container::stored_config(&rec)?.rootfs;
            let (driver, writable) = (self.storage().clone(), self.writable(&rec.id));
            let mon_dir = self.mon_dir(&rec.id);
            let pidfd = tokio::task::spawn_blocking(move || {
                super::super::procpin::pin_container_process(
                    pid,
                    super::super::procpin::ContainerRoot::of(
                        rootfs.as_ref(),
                        &*driver,
                        &writable,
                        &mon_dir,
                    ),
                )
            })
            .await
            .map_err(|e| ContainerError::Io(io::Error::other(e)))?
            .map_err(|e| ContainerError::NotRunning(format!("{target}: {e}")))?;
            paths.push((kind, format!("/proc/{pid}/ns/{kind}")));
            pins.push((target.to_string(), pidfd));
        }
        set_namespace_paths(&bundle.join("config.json"), &paths)?;
        Ok(pins)
    }

    /// /dev/shm of the containers of an IPC namespace, as podman shares it:
    /// a container that is `shareable` (the default, the infra container of a
    /// pod) has a tmpfs of the engine there, and the ones that join its IPC
    /// namespace (`--ipc container:ID`, the members of the pod, and the
    /// containers that join those) bind the same; those that join a container
    /// with the IPC namespace of the host bind the host's.  A target without
    /// one (`--ipc none`, or where the engine could not mount it) leaves the
    /// member its own tmpfs.
    pub(super) async fn share_shm(
        &self,
        bundle: &Path,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> ContainerResult<ShmMount> {
        let o = &config.options;
        let mut mounted = ShmMount(None);
        let dir = match o.ipc_ns.strip_prefix("container:") {
            Some(target) => {
                // (the container whose /dev/shm the target has)
                let mut owner = target.to_string();
                for _ in 0..16 {
                    let Ok(rec) = self.db.get_container(&owner).await else {
                        break;
                    };
                    let theirs = super::super::container::stored_config(&rec)?;
                    match theirs.options.ipc_ns.as_str() {
                        "host" => {
                            owner.clear();
                            break;
                        }
                        ns => match ns.strip_prefix("container:") {
                            Some(next) => owner = next.to_string(),
                            None => break,
                        },
                    }
                }
                let dir = if owner.is_empty() {
                    PathBuf::from("/dev/shm")
                } else {
                    self.mon_dir(&owner).join("shm")
                };
                if !dir.is_dir() {
                    return Ok(mounted);
                }
                dir
            }
            None if o.shm_shareable && o.ipc_ns.is_empty() => {
                let dir = self.mon_dir(&container.id).join("shm");
                if !make_shm_dir(&dir, config)? {
                    return Ok(mounted);
                }
                mounted.0 = Some(dir.clone());
                dir
            }
            None => return Ok(mounted),
        };
        bind_shm(&bundle.join("config.json"), &dir)?;
        Ok(mounted)
    }

    /// Start a monitor for the container, which creates it with the
    /// runtime, set up its network, then start it.  With `attach` the
    /// monitor waits for a client to attach before it starts the container.
    /// A container that `init` created is started by its monitor.
    pub async fn start_with(self: &Arc<Self>, id: &str, attach: bool) -> ContainerResult<PathBuf> {
        self.start_as(id, attach, &StartCheck::Engine).await
    }

    /// [`Self::start_with`] for the start `check` says: a command of a user
    /// (with the digests typed on it) or the engine's own.
    pub async fn start_as(
        self: &Arc<Self>,
        id: &str,
        attach: bool,
        check: &StartCheck,
    ) -> ContainerResult<PathBuf> {
        self.start_checked(id, attach, None, check)
            .await?
            .ok_or_else(|| io_error(io::Error::other("the start was not made")))
    }

    /// [`Self::start_with`]; with `restart`, the start of the restart policy
    /// of a run that ended: nothing (`None`) when, under the lock of the
    /// start, the container was stopped by a user or started since.  Else
    /// the restart is counted before the monitor takes the count on.
    pub(super) async fn start_checked(
        self: &Arc<Self>,
        id: &str,
        attach: bool,
        restart: Option<&PolicyRestart>,
        check: &StartCheck,
    ) -> ContainerResult<Option<PathBuf>> {
        let container = self.db.get_container(id).await?;
        // A container said to run whose monitor is gone without a word (it
        // was killed, the monitor itself too) gets what the monitor would
        // have given it first: else it could never be started again.
        if container.state.is_alive() {
            self.reconcile(&container.id).await?;
        }
        // One start of a container at a time, whatever process asks: the
        // second finds the container running (or its start failed).
        let _lock = self.start_lock(&container.id).await?;
        let container = self.db.get_container(&container.id).await?;
        let name = container.name.as_deref().unwrap_or(&container.id);
        if container.state == RecordState::Running {
            check.refuse_running(
                name,
                "it runs, on the file systems its monitor mounted when it started",
            )?;
            return Err(ContainerError::AlreadyRunning(id.to_string()));
        }
        if let Some(restart) = restart {
            let ext = self.db.get_container_ext(&container.id).await?;
            if ext.stopped_by_user
                || !container.state.has_ended()
                || container.started_at != restart.run
            {
                return Ok(None);
            }
            let count = restart.count;
            self.update_ext(&container.id, move |e| e.restart_count = count)
                .await?;
        }
        let mut config: ContainerConfig = serde_json::from_str(&container.config)?;
        if let Some(why) = &config.user_error {
            return Err(ContainerError::not_started(why.clone()));
        }
        if config.start_error.is_some() {
            if let Err(why) = self.workdir_now(&container, &config).await? {
                return Err(ContainerError::not_started(why));
            }
            config.start_error = None;
        }
        let dir = self.mon_dir(&container.id);
        if self.start_restarting(&container.id, &dir, check).await? {
            return Ok(Some(dir));
        }
        self.start_dependencies(&config).await?;
        if self.checkpoint_record(&container.id).restore_on_start {
            info!(
                "Restoring container {} from its staged checkpoint",
                container.id
            );
            self.restore_in_place_locked(&container.id, &Default::default(), check)
                .await?;
            return Ok(Some(dir));
        }
        info!("Starting container {}", container.id);
        if container.state == RecordState::Initialized {
            if self.monitor_created(&dir).await {
                check.refuse_unchecked(
                    name,
                    "it was initialized (`container init`, or a client attached to it before its start): its monitor mounted its file systems then",
                )?;
                let pid = container.pid.unwrap_or(0);
                return self
                    .start_created(&container, dir, None, pid, attach)
                    .await
                    .map(Some);
            }
            warn!(
                "The monitor of the initialized container {} is gone",
                container.id
            );
        }
        let (events, pid) = self
            .create_in_monitor(&container, &config, &dir, check)
            .await?;
        self.notify_action(&container, "init", Vec::new());
        self.start_created(&container, dir, Some(events), pid, attach)
            .await
            .map(Some)
    }

    /// How the signature policy judges the images of the container at a
    /// start, if it does: `require` by the configuration of now or by the
    /// request that made it, `check` by the request.  A container made
    /// with neither was judged at its create only.
    fn signature_judged(&self, config: &ContainerConfig) -> Option<SignatureJudging> {
        if self.containers_config.image_signature == "require" {
            Some(SignatureJudging::Require(
                "[containers] image_signature is \"require\"",
            ))
        } else if config.security_opt.signature_require {
            Some(SignatureJudging::Require(
                "--security-opt signature=require",
            ))
        } else if config.security_opt.signature_check {
            Some(SignatureJudging::Check)
        } else {
            None
        }
    }

    /// A container whose signature is required (by the configuration of now
    /// or by the request that made it) starts only while its image, and
    /// every image mounted in it, has a valid signature for every name it
    /// has; one made with `signature=check` only while the signature policy
    /// of now accepts them, `reject` included.  The images judged, by the id they were read by: the chain of
    /// the start reads the same records, not the store again.
    async fn verify_image_at_start(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> ContainerResult<Vec<(String, velarx_db::ImageRecord)>> {
        let mut judged = Vec::new();
        let Some(judging) = self.signature_judged(config) else {
            return Ok(judged);
        };
        // (a `--rootfs` directory is no image: nothing to judge)
        if config.rootfs.is_none() {
            let (image, tags, staged) = self.image_service.get_for_run(&container.image_id).await?;
            match &staged {
                Some(pull) => {
                    self.image_service
                        .verify_staged(&config.image, pull, judging)
                        .await?
                }
                None => {
                    self.image_service
                        .verify_stored(&config.image, &image, &tags, judging)
                        .await?
                }
            }
            say_signature(String::new, judging, &image);
            judged.push((container.image_id.clone(), image));
        }
        // the images mounted in it (`--mount type=image`), by the id the
        // create resolved
        for (m, i) in config
            .mounts
            .iter()
            .filter_map(|m| Some((m, m.image.as_ref()?)))
        {
            let (image, tags) = self.image_service.get_with_tags(&i.image).await?;
            self.image_service
                .verify_stored(&i.image, &image, &tags, judging)
                .await?;
            say_signature(|| format!("image mount {}: ", m.target), judging, &image);
            judged.push((i.image.clone(), image));
        }
        Ok(judged)
    }

    /// The image `id` as the signature check of the start read it
    /// (`judged`), else from the store.
    async fn image_of_start(
        &self,
        judged: &[(String, velarx_db::ImageRecord)],
        id: &str,
    ) -> ContainerResult<velarx_db::ImageRecord> {
        match judged.iter().find(|(i, _)| i == id) {
            Some((_, image)) => Ok(image.clone()),
            None => Ok(self.image_service.get_for_run(id).await?.0),
        }
    }

    /// The root file system and the images mounted in the container for this
    /// start of the monitor, asked of the driver in one call
    /// ([`velarx_graph::StorageDriver::mounts`]: the only source of mount
    /// descriptors), and the descriptors to pass.  The monitor uses a
    /// descriptor once, so every start asks the driver again: a start after a
    /// stop, a restore, an engine that was restarted (it has only the plan
    /// files of the bundle).
    ///
    /// The root is asked for when its plan is a mount of the driver
    /// (`RootfsPlan::MountFd`: the descriptor); never for a `--rootfs`.
    /// **The image mounts are always asked for**, whatever the root is
    /// (`--rootfs` or a directory root as well as a mount): each plan file of
    /// `imagevol` is written again from the answer, so the monitor never reads
    /// one of an earlier start.
    async fn fresh_mounts(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
        judged: &[(String, velarx_db::ImageRecord)],
        monitor: &mut MonitorConfig,
    ) -> ContainerResult<Vec<Arc<OwnedFd>>> {
        use velarx_graph::Purpose;
        let bundle = self.bundle_dir(&container.id);
        let image_mounts: Vec<_> = config
            .mounts
            .iter()
            .filter_map(|m| m.image.as_ref())
            .enumerate()
            .collect();
        let Some(needs) = root_fd::needs(&bundle, config.rootfs.is_none(), image_mounts.len())?
        else {
            return Ok(Vec::new());
        };
        let ask_root = needs.expects_fd;
        // the images and their layers, the image of the root first
        let mut images = Vec::new();
        if ask_root {
            let (record, _, _) = self.image_service.get_for_run(&container.image_id).await?;
            let layers = self.image_layers(&record).await?;
            images.push((record, layers));
        }
        for (_, mounted) in &image_mounts {
            let record = self.image_of_start(judged, &mounted.image).await?;
            let layers = self.image_layers(&record).await?;
            images.push((record, layers));
        }
        let own_ns = !config.uid_mappings.is_empty();
        let mapping = own_ns.then(|| self.translation(&config.uid_mappings, &config.gid_mappings));
        // the digests each image accepts, when they are enforced
        let accepted: Vec<Option<Vec<Vec<String>>>> = if self.digests_enforced(config).is_some() {
            let mut lists = Vec::with_capacity(images.len());
            for (record, layers) in &images {
                let (l, _) = self.image_service.start_digests(
                    record,
                    layers,
                    config.security_opt.verity_enforce,
                )?;
                lists.push(Some(l));
            }
            lists
        } else {
            images.iter().map(|_| None).collect()
        };
        let label = mount_label(config);
        let writable = self.writable(&container.id);
        let translate = self.translation(&config.uid_mappings, &config.gid_mappings);
        let ask = MountAsk {
            container: &writable,
            mapping: mapping.as_ref(),
            translate: Some(&translate),
            idmap_mount: root_fd::may_idmap_mounts(own_ns),
            label: label.as_deref(),
            volatile: config.throw_away(),
        };
        // the chain of trust of each image, from where the engine's checks
        // left it (the driver says the links of the layers it measures)
        let image_config = monitor.image.as_ref();
        let chains: Vec<Option<Chain>> = ask_root
            .then(|| (String::new(), image_config.and_then(|i| i.chain.as_ref())))
            .into_iter()
            .chain(image_mounts.iter().map(|(n, _)| {
                let volume = image_config.and_then(|i| i.image_mounts.get(*n));
                (
                    format!(
                        "image mount {}: ",
                        volume.map_or(String::new(), |v| v.destination.clone())
                    ),
                    volume.and_then(|v| v.chain.as_ref()),
                )
            }))
            .map(|(scope, plan)| {
                plan.map(|p| Chain::resume(&scope, p.total, p.done, &p.trail, &p.layers))
            })
            .collect();
        let mut images = images
            .iter()
            .zip(&accepted)
            .zip(&chains)
            .map(|((img, acc), chain)| (img, acc.as_deref().map(|a| (a, chain.as_ref()))));
        let root = ask_root.then(|| {
            let (img, acc) = images.next().expect("the root's image");
            ask.mount(Purpose::Root, img, acc)
        });
        let volumes: Vec<_> = image_mounts
            .iter()
            .zip(images)
            .map(|((n, _), (img, acc))| ask.mount(Purpose::Volume { index: *n as u32 }, img, acc))
            .collect();
        let accepted = root_fd::start_mounts(
            &**self.image_service.storage(),
            &bundle,
            &writable,
            root.map(|r| (r, ask_root)),
            volumes,
        )?;
        if let Some(image) = monitor.image.as_mut() {
            say_enforced(image, &accepted, &mut chains.into_iter());
        }
        Ok(accepted.fds)
    }

    /// Create the container with the runtime, in a monitor that waits to
    /// start it (podman's init): the state is `initialized`.  Only a
    /// container that is not running nor created can be.
    pub async fn init(self: &Arc<Self>, id: &str) -> ContainerResult<()> {
        self.init_with(id, true).await
    }

    /// `init`, with the event of it (`announce`) or without: a container
    /// that a client attaches to before it starts is made in the runtime so
    /// that its monitor is there, which is no event of podman's.
    pub async fn init_with(self: &Arc<Self>, id: &str, announce: bool) -> ContainerResult<()> {
        let container = self.db.get_container(id).await?;
        // (a start, a removal or another init of it in the meantime)
        let _lock = self.start_lock(&container.id).await?;
        let container = self.db.get_container(&container.id).await?;
        if !(container.state == RecordState::Created || container.state.has_ended()) {
            return Err(ContainerError::InvalidArgument(format!(
                "container {} has already been created in runtime",
                container.id
            )));
        }
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        let dir = self.mon_dir(&container.id);
        info!("Initializing container {}", container.id);
        let (events, pid) = self
            .create_in_monitor(&container, &config, &dir, &StartCheck::Engine)
            .await?;
        if let Err(e) = self
            .db
            .update_container_state(
                &container.id,
                RecordState::Initialized,
                Some(pid),
                None,
                None,
                None,
            )
            .await
        {
            let quit_dir = dir.clone();
            let _ = tokio::task::spawn_blocking(move || client::quit(&quit_dir)).await;
            self.release_network(&container).await;
            return Err(e.into());
        }
        self.observe_started(&container.id, events);
        if announce {
            self.notify_action(&container, "init", Vec::new());
        }
        Ok(())
    }

    /// Whether the monitor in `dir` holds a container it did not start.
    pub(super) async fn monitor_created(&self, dir: &Path) -> bool {
        let dir = dir.to_path_buf();
        matches!(
            tokio::task::spawn_blocking(move || client::status(&dir)).await,
            Ok(Ok(s)) if s.state == velarx_wire::monitor::proto::RunState::Created
        )
    }

    /// Spawn the monitor of the container, which creates it with the
    /// runtime, and set up its network: the events of the monitor and the
    /// pid of the container.
    pub(super) async fn create_in_monitor(
        self: &Arc<Self>,
        container: &velarx_db::ContainerRecord,
        config: &ContainerConfig,
        dir: &Path,
        check: &StartCheck,
    ) -> ContainerResult<(MonitorConn, i32)> {
        match self
            .create_in_monitor_with(container, config, dir, None, check)
            .await
        {
            // (the monitor could not make the root file system: when an
            // image of its plan is gone, the layer is marked incomplete and
            // the error says to pull the image again; the failure path only)
            Err(e) => Err(self.damaged_root(container, config).await.unwrap_or(e)),
            ok => ok,
        }
    }

    /// After a start that failed: the error of a root the driver mounts
    /// whose layer lost its EROFS image, if there is one.
    async fn damaged_root(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> Option<ContainerError> {
        use velarx_fuse::plan::RootfsPlan;
        let bundle = self.bundle_dir(&container.id);
        if config.rootfs.is_some() {
            return None;
        }
        // (a mount the driver makes names no image: the images of the
        // layers are looked at, the driver's quick check)
        if !matches!(
            velarx_fuse::plan::read(&bundle, ""),
            Ok(Some(RootfsPlan::MountFd(_)))
        ) {
            return None;
        }
        let (record, _, _) = self
            .image_service
            .get_for_run(&container.image_id)
            .await
            .ok()?;
        let layers = self.image_layers(&record).await.ok()?;
        self.image_service
            .find_damage(&record, &layers)
            .await
            .map(Into::into)
    }

    /// After a create that failed with a storage error: the error of the
    /// image `name` when a layer of it lost its EROFS image.
    pub(in crate::services) async fn damaged_image(&self, name: &str) -> Option<ContainerError> {
        let record = self.image_service.get(name).await.ok()?;
        let layers = self.image_layers(&record).await.ok()?;
        self.image_service
            .find_damage(&record, &layers)
            .await
            .map(Into::into)
    }

    /// The same; with `restore` the monitor restores the checkpoint instead
    /// of creating the container, which then runs (its network is the one
    /// CRIU restored).
    pub(in crate::services) async fn create_in_monitor_with(
        self: &Arc<Self>,
        container: &velarx_db::ContainerRecord,
        config: &ContainerConfig,
        dir: &Path,
        restore: Option<velarx_wire::monitor::client::Restore>,
        check: &StartCheck,
    ) -> ContainerResult<(MonitorConn, i32)> {
        let judged = self.verify_image_at_start(container, config).await?;
        let bundle_path = self.bundle_dir(&container.id);
        self.chown_mounts_again(config).await?;
        if !bundle_path.join("config.json").exists() {
            return Err(ContainerError::NotFound(format!(
                "the bundle of {}",
                container.id
            )));
        }

        if config.security_opt.apparmor_profile.as_deref()
            == Some(crate::container::apparmor::DEFAULT_PROFILE)
        {
            tokio::task::spawn_blocking(crate::container::apparmor::ensure_default_loaded)
                .await
                .map_err(|e| ContainerError::Io(io::Error::other(e)))?
                .map_err(|e| ContainerError::Runtime(crate::container::RuntimeError::Runtime(e)))?;
        }

        // The namespaces of other containers (`--pid container:ID`...), as
        // they are now: their processes stay pinned until the container
        // exists in them.
        let pins = self.join_namespaces(&bundle_path, config).await?;
        // (released when the container is not made: no exit says so)
        let shm = self.share_shm(&bundle_path, container, config).await?;

        // The network namespace of a container the engine sets the network
        // up for is made (a shareable one from the pool or new, or the one of
        // pasta, bridge networks, CNI) before the runtime creates the
        // container in it: this engine holds its descriptor, the monitor
        // inherits it, and the spec joins it as `/proc/PID/fd/N` of the
        // monitor.  `container:ID` joins what the target has now (its
        // descriptor, opened), `ns:PATH` the file.
        // Whatever fails from here until the container exists gives the
        // network set up back (the namespace, the pasta of it).
        let network: ContainerResult<Option<velarx_netkernel::netns::Netns>> = async {
            let Some(engine) = self.network_manager.engine() else {
                return Ok(None);
            };
            let spec_file = bundle_path.join("config.json");
            // A pooled namespace comes with its own address.
            // (a holder of the rootless network namespace started for a
            // container without cgroups stays in the caller's cgroup)
            let disabled = config.cgroups == CgroupsMode::Disabled;
            let mut prepared = crate::network::rootless_netns::in_caller_cgroup(
                disabled,
                engine.prepare(&container.id),
            )
            .await?;
            // A checkpoint of a container in a network namespace of the
            // engine does not hold that namespace: the processes are
            // restored into one set up again.
            let own_netns = config.uid_mappings.is_empty();
            if own_netns && prepared.is_none() {
                prepared = crate::network::rootless_netns::in_caller_cgroup(
                    disabled,
                    engine.prepare_own(&container.id),
                )
                .await?;
            }
            if let Some(ip) = prepared
                .as_ref()
                .and_then(|s| s.interfaces.first())
                .and_then(|i| i.ip)
            {
                self.update_hosts_address(&bundle_path, &config.hostname, &ip.to_string())?;
            }
            let netns = match engine.shared_netns(&config.network_mode).await? {
                Some(crate::network::engine::Shared::Path(path)) => {
                    velarx_runtime::network::spec_netns::set_spec_netns(&spec_file, &path)?;
                    None
                }
                Some(crate::network::engine::Shared::Held(ns)) => Some(ns),
                None if prepared.is_some() => engine.held(&container.id),
                // the network is set up in a namespace of its own (for a
                // container in the user namespace of the engine: one in a
                // user namespace of its own needs the network namespace to
                // be its own, to set the sysctls)
                None if own_netns => engine.prepare_netns(&container.id).await?,
                None => None,
            };
            Ok(netns)
        }
        .await;
        let netns = match network {
            Ok(netns) => netns,
            Err(e) => {
                self.release_network(container).await;
                return Err(e);
            }
        };

        // Whatever fails until the container exists gives the network
        // `prepare` set up back.
        let created: ContainerResult<(MonitorConn, i32)> = async {
            std::fs::create_dir_all(dir)?;
            self.wait_monitor_gone(dir).await?;
            let mut mc = self.monitor_config(container, config)?;
            mc.settle = Some(self.settle_plan(container, config).await);
            // the chain of trust first: a refusal names the image (or the
            // `--mount`) it is about, and nothing is mounted for it
            self.verify_start_chain(container, config, &mut mc, check, &judged)
                .await?;
            // the root file system and the image mounts: the driver's answer
            // for this start, and the descriptors of the mounts (the monitor
            // uses each once)
            let rootfs_fds = self
                .fresh_mounts(container, config, &judged, &mut mc)
                .await?;
            let health_log_dir = open_health_log_dir(config).map(Arc::new);
            // (a rootless engine: the namespace of the bridge networks, which
            // the monitor holds)
            let bridge_netns = match self.network_manager.engine() {
                Some(engine) => engine.bridge_netns_for(&container.id).await?.map(Arc::new),
                None => None,
            };
            mc.fds = velarx_base::spawn::InheritedFds::layout(
                self.supervision.listen_fds.len(),
                rootfs_fds.len(),
                netns.is_some(),
                health_log_dir.is_some(),
                bridge_netns.is_some(),
            );
            // (where the monitor has the namespace: after the descriptors
            // for the container and the mounts, from 4)
            let netns_number = mc.fds.netns.unwrap_or_default();
            mc.restart.count = self
                .db
                .get_container_ext(&container.id)
                .await?
                .restart_count;
            if let Some(engine) = self.network_manager.engine() {
                mc.hold_ports = engine.held_ports(&container.id).await?;
            }
            if let Some(parent) = mc.log.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // (the monitor's lines of the chain follow those of the log of
            // a start before this one)
            let chain_from = (mc.image.as_ref().is_some_and(|i| i.debug && i.enforce))
                .then(|| monitor_log_len(dir));
            let written = mc.write(dir);
            say_unwritten(&mc, &written);
            written?;
            self.prepare_notify_dir(&container.id, config)?;

            // The monitor takes no service manager from the server, and the
            // output of a container is the caller's only where there is one.
            let opts = velarx_base::spawn::SpawnOptions {
                notify_socket: self.supervision.notify_socket.clone(),
                preserve_fds: self.supervision.listen_fds.clone(),
                env: crate::userns::rootless::marker_env(),
                rootfs_fds,
                netns: netns.as_ref().map(|n| n.shared()),
                health_log_dir,
                bridge_netns,
                stdio: if mc.log.driver == crate::monitor::config::LogDriver::Passthrough {
                    warn_withheld_output(config);
                    velarx_base::spawn::StdioPolicy::Inherit
                } else {
                    Default::default()
                },
                ..Default::default()
            };
            // A container of a pod with limits in a systemd slice: the slice
            // is there with its limits before the runtime asks for the scope
            // (the manager would make it without them).
            if let Some(path) = config
                .cgroups_path
                .as_deref()
                .filter(|p| crate::services::cgroups_mode::is_systemd_path(p))
            {
                let (slices, path) = (self.pod_slices.clone(), path.to_string());
                tokio::task::spawn_blocking(move || slices.ensure(&path))
                    .await
                    .map_err(io::Error::other)
                    .and_then(|r| r.map_err(io::Error::other))
                    .map_err(io_error)?;
            }
            // The scope of a container with no limits (`services::scope`,
            // the table of `cgroups_mode`): asked for by the command at its
            // beginning, or now.  It is there before the runtime makes the
            // container in it, and the holder it was made around ends when
            // the container is made (`scope_dirs` is dropped).  Without it
            // the start fails: the runtime would make the cgroup by hand in
            // a slice of the manager.
            let scope_dirs = match config
                .cgroups_path
                .as_deref()
                .and_then(crate::services::cgroups_mode::engine_scope_dir)
            {
                Some(scope_dir) => {
                    let id = container.id.clone();
                    let leftover = std::path::Path::new(crate::services::cgroups_mode::CGROUP_FS)
                        .join(scope_dir.trim_start_matches('/'));
                    let made = tokio::task::spawn_blocking(move || {
                        match super::super::scope::take(&id) {
                            Some(p) => Ok(p),
                            None => {
                                super::super::scope::remove_leftovers(&leftover);
                                super::super::scope::begin(&id)
                            }
                        }
                        .and_then(super::super::scope::Pending::wait)
                    })
                    .await
                    .map_err(io::Error::other)
                    .and_then(|r| r)
                    .map_err(|e| {
                        io_error(io::Error::new(
                            e.kind(),
                            format!(
                                "cannot make the systemd scope velarx-{}.scope of the container \
                                 (--cgroups=disabled starts it without cgroups): {e}",
                                container.id
                            ),
                        ))
                    })?;
                    Some(made)
                }
                None => None,
            };
            // `run --no-monitor`: the process this engine split from is the
            // monitor of the container it runs (once).
            let mut moved = None;
            let handed = match (&self.supervision.in_process, config.no_monitor) {
                (Some(handoff), true) => handoff.monitor(dir, &opts).map_err(io_error)?,
                _ => None,
            };
            let monitor_pid: Option<u32>;
            // (a monitor of its own has the descriptor at a number the
            // engine knows; the one of the process that was split off has
            // it where it received it)
            let own_monitor: bool;
            let daemon_end = match handed {
                Some(daemon_end) => {
                    let daemon_end =
                        MonitorConn::boot(daemon_end, restore.as_ref()).map_err(io_error)?;
                    let monitor =
                        rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get());
                    monitor_pid = Some(monitor as u32);
                    own_monitor = false;
                    if let Err(e) = std::fs::write(dir.join(MONITOR_PID_FILE), monitor.to_string())
                    {
                        debug!(
                            "Cannot write the pid of the monitor of {}: {}",
                            container.id, e
                        );
                    }
                    daemon_end
                }
                None => {
                    let (daemon_end, monitor_end) =
                        std::os::unix::net::UnixStream::pair().map_err(io_error)?;
                    // (its first call is there before the monitor starts)
                    let daemon_end =
                        MonitorConn::boot(daemon_end, restore.as_ref()).map_err(io_error)?;
                    // The engine of a command is no server: the monitor of a
                    // container it leaves running must not die with the
                    // scope of its caller (podman's libpod-conmon scope): it
                    // starts in `monitor` of the container's scope (`no-conmon`: it stays where it is).
                    // The server's container has `monitor` next to its
                    // `container` (`CgroupManager`); the file says which
                    // cgroups go with the container's files.
                    // (a systemd scope of `cgroup_manager = "systemd"` is the manager's)
                    let server_monitor = match (&self.cgroup_manager, &config.cgroups_path) {
                        (Some(cm), Some(path))
                            if !self.caller_supervised
                                && !crate::services::cgroups_mode::is_systemd_path(path)
                                && crate::services::cgroups_mode::engine_scope_dir(path)
                                    .is_none() =>
                        {
                            match cm.prepare_container(path) {
                                Ok(monitor) => {
                                    if let Err(e) = std::fs::write(dir.join(CGROUP_FILE), path) {
                                        warn!(
                                            "The cgroup of {} was not recorded: {e}",
                                            container.id
                                        );
                                    }
                                    if let Some(s) = mc.settle.as_mut() {
                                        s.cgroup = cm.plan_of(path);
                                    }
                                    Some(monitor)
                                }
                                Err(e) => {
                                    warn!("No cgroup for the monitor of {}: {e}", container.id);
                                    None
                                }
                            }
                        }
                        _ => None,
                    };
                    let own_cgroup = scope_dirs
                        .as_ref()
                        .map(|d| d.monitor.clone())
                        .or(server_monitor)
                        .filter(|_| {
                            matches!(
                                config.cgroups,
                                CgroupsMode::Unset | CgroupsMode::Enabled | CgroupsMode::Split
                            )
                        });
                    let opts = velarx_base::spawn::SpawnOptions {
                        // (the mode first: a container without a scope
                        // does not ask the manager; the server's monitor of
                        // `--cgroups=scope` leaves the server's unit too)
                        scope: (crate::services::cgroups_mode::monitor_needs_scope(
                            config.cgroups,
                            config.cgroups_path.as_deref(),
                        ) && if self.caller_supervised {
                            self.supervision.systemd_cgroups.get()?
                        } else {
                            config.cgroup_mode == Some(velarx_wire::request::CgroupMode::Scope)
                        } && crate::services::cgroups_mode::scope_manager_answers()?)
                        .then(|| crate::services::cgroups_mode::monitor_scope(&container.id)),
                        ..opts
                    };
                    let cmd = velarx_base::spawn::command(
                        &velarx_base::spawn::binary(),
                        dir,
                        std::os::fd::AsFd::as_fd(&monitor_end),
                        &opts,
                    )
                    .map_err(io_error)?;
                    // A process that moves to a new cgroup afterwards waits
                    // for a grace period of the kernel (5-10 ms of every
                    // start), which one made in it does not: `Command`
                    // cannot do that, so the monitor of a container with
                    // cgroups of the engine starts through `clone3`.
                    let into = own_cgroup.as_deref().and_then(|cg| {
                        velarx_base::spawn::spawn_in_cgroup(
                            &cmd,
                            std::os::fd::AsFd::as_fd(&monitor_end),
                            &opts,
                            cg,
                        )
                        .map_err(|e| debug!("Cannot start the monitor in {}: {e}", cg.display()))
                        .ok()
                    });
                    let (pid, child) = match into {
                        Some(pid) => (Some(pid), None),
                        None => {
                            let c = tokio::process::Command::from(cmd)
                                .spawn()
                                .map_err(io_error)?;
                            let pid = c.id();
                            // (the kernel refused: into it afterwards, while
                            // the container is made)
                            if let (Some(pid), Some(cg)) = (pid, own_cgroup) {
                                moved = Some(tokio::task::spawn_blocking(move || {
                                    if let Err(e) =
                                        std::fs::write(cg.join("cgroup.procs"), pid.to_string())
                                    {
                                        warn!(
                                            "Cannot move the monitor {pid} to {}: {e}",
                                            cg.display()
                                        );
                                    }
                                }));
                            }
                            (pid, Some(c))
                        }
                    };
                    drop(monitor_end);
                    monitor_pid = pid;
                    own_monitor = true;
                    // What podman calls the ConmonPidFile
                    if let Some(pid) = pid {
                        // it outlives the engine that started it: the next
                        // command joins the namespaces through it
                        let _ = tokio::task::spawn_blocking(move || {
                            velarx_nsid::tree::register_holder(pid, "monitor")
                        })
                        .await;
                        if let Err(e) = std::fs::write(dir.join(MONITOR_PID_FILE), pid.to_string())
                        {
                            debug!(
                                "Cannot write the pid of the monitor of {}: {}",
                                container.id, e
                            );
                        }
                    }
                    tokio::spawn(async move {
                        match child {
                            Some(mut child) => {
                                let _ = child.wait().await;
                            }
                            None => {
                                if let Some(pid) = pid {
                                    reap(pid).await;
                                }
                            }
                        }
                    });
                    daemon_end
                }
            };

            // The monitor holds the namespace of the container: it is a
            // holder of it, and a pasta starts on the monitor's descriptor
            // while the runtime creates the container.  A monitor that
            // leaves its parent (a unit's) has its pid for good only once
            // it created the container: it is known after that.
            if let (Some(engine), Some(monitor), false) =
                (self.network_manager.engine(), monitor_pid, mc.leave_parent)
            {
                engine.monitor_started(&container.id, monitor as i32);
                if own_monitor && netns.is_some() {
                    engine
                        .start_pasta(&container.id, monitor, netns_number)
                        .await
                        .map_err(|e| ContainerError::Io(io::Error::other(e.to_string())))?;
                }
            }
            let mut events = daemon_end;
            velarx_base::trace::point("start monitor spawned");
            let first = tokio::time::timeout(
                CREATE_TIMEOUT,
                events.next::<velarx_wire::monitor::iface::Subscribed>(),
            )
            .await
            .map_err(|_| {
                io_error(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the monitor did not answer",
                ))
            })?;
            velarx_base::trace::point("start created");
            // (the monitor mounted the image, or failed to: what it checked)
            if let Some(from) = chain_from {
                repeat_chain_lines(dir, from);
            }
            if let Some(moved) = moved {
                let _ = moved.await;
            }
            let status = match first {
                Ok(Some(r)) => r.parameters.status,
                Ok(None) => {
                    // (what it leaves is gone when the command returns)
                    drop(events);
                    let _ = self.wait_monitor_gone(dir).await;
                    return Err(io_error(io::Error::other(
                        "the monitor ended before it created the container",
                    )));
                }
                Err(e) => {
                    let why = match client::monitor_error(&e) {
                        Some(client::MonitorError::Remote { reason, .. }) => reason.clone(),
                        _ => e.to_string(),
                    };
                    // (the monitor that refused cleans up and ends: nothing
                    // of it is left when the command returns)
                    drop(events);
                    let _ = self.wait_monitor_gone(dir).await;
                    let name = self.runtime_for(config).name();
                    return Err(ContainerError::Runtime(crate::container::not_started_for(
                        &name, &why,
                    )));
                }
            };
            let pid = status.as_ref().and_then(|s| s.pid).unwrap_or(0);
            // (the monitor that left its parent wrote its own pid before it
            // answered)
            if let (Some(engine), true) = (self.network_manager.engine(), mc.leave_parent) {
                if let Some(monitor) = std::fs::read_to_string(dir.join(MONITOR_PID_FILE))
                    .ok()
                    .and_then(|p| p.trim().parse().ok())
                {
                    engine.monitor_started(&container.id, monitor);
                }
            }
            // a target that exited may have left its pid to another process
            for (target, pidfd) in &pins {
                if !super::super::procpin::pidfd_alive(pidfd).unwrap_or(false) {
                    let quit_dir = dir.to_path_buf();
                    let _ = tokio::task::spawn_blocking(move || client::quit(&quit_dir)).await;
                    return Err(ContainerError::NotRunning(format!(
                        "{target}, whose namespaces the container joins, exited"
                    )));
                }
            }
            // (the container is made: the holder of its scope ends)
            drop(scope_dirs);
            Ok((events, pid))
        }
        .await;
        let (events, pid) = match created {
            Ok(v) => v,
            Err(e) => {
                self.release_network(container).await;
                return Err(e);
            }
        };

        // The network between the creation and the start.
        tracing::trace!("Container networks: {:?}, pid: {}", config.networks, pid);
        if pid > 0 && !super::super::container::config_has_network_mode(config, &NetworkMode::Host)
        {
            velarx_base::trace::point("start network");
            let networked = crate::network::rootless_netns::in_caller_cgroup(
                config.cgroups == CgroupsMode::Disabled,
                self.setup_container_network(&container.id, pid, config),
            )
            .await;
            velarx_base::trace::point("start network set up");
            if let Err(e) = networked {
                // No container without the network it asked for: the
                // monitor deletes the created container and exits.
                let quit_dir = dir.to_path_buf();
                let _ = tokio::task::spawn_blocking(move || client::quit(&quit_dir)).await;
                self.release_network(container).await;
                return Err(e);
            }
        }

        self.update_ext(&container.id, move |e| {
            e.oom_killed = false;
            e.timed_out = false;
            e.health = None;
            e.stopped_by_user = false;
        })
        .await?;

        shm.keep();
        Ok((events, pid))
    }

    /// Tell the monitor to start the container it created; `events` are
    /// those of the monitor when nothing follows them yet.
    pub(super) async fn start_created(
        self: &Arc<Self>,
        container: &velarx_db::ContainerRecord,
        dir: PathBuf,
        events: Option<MonitorConn>,
        pid: i32,
        attach: bool,
    ) -> ContainerResult<PathBuf> {
        let wait_ms = if attach {
            ATTACH_WAIT.as_millis() as u64
        } else {
            0
        };
        let call_dir = dir.clone();
        let started = tokio::task::spawn_blocking(move || client::start(&call_dir, wait_ms))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?;
        velarx_base::trace::point("start started");
        let started = match started {
            Ok(status) => status,
            Err(e)
                if client::monitor_error(&e)
                    .is_some_and(|m| matches!(m, client::MonitorError::Remote { .. })) =>
            {
                let why = match client::monitor_error(&e) {
                    Some(client::MonitorError::Remote { reason, .. }) => reason.clone(),
                    _ => "the container did not start".into(),
                };
                if let Some(events) = events {
                    self.observe_started(&container.id, events);
                }
                let name = self.runtime_for_record(container)?.name();
                return Err(ContainerError::Runtime(crate::container::not_started_for(
                    &name, &why,
                )));
            }
            Err(e) => {
                self.release_network(container).await;
                return Err(io_error(e));
            }
        };
        let started_at = started
            .as_ref()
            .and_then(|s| s.started_ns)
            .map(rfc3339)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        self.db
            .update_container_state(
                &container.id,
                RecordState::Running,
                Some(pid),
                Some(started_at),
                None,
                None,
            )
            .await?;
        if let Some(events) = events {
            self.observe_started(&container.id, events);
        }
        info!("Started container {} with PID {}", container.id, pid);
        self.notify_action(container, "start", Vec::new());
        Ok(dir)
    }

    /// Tell what a user did to the container (the events of every API).
    pub(crate) fn notify_action(
        &self,
        container: &ContainerRecord,
        action: &'static str,
        attributes: Vec<(String, String)>,
    ) {
        let (image, mut labels) = event_details(container);
        labels.extend(attributes);
        let _ = self.lifecycle.notices.send(ContainerNotice::Action {
            id: container.id.clone(),
            name: container.name.clone().unwrap_or_default(),
            image,
            action,
            attributes: labels,
        });
    }

    /// The same, for the container `id` of the database.
    pub async fn notify_action_of(
        &self,
        id: &str,
        action: &'static str,
        attributes: Vec<(String, String)>,
    ) {
        if let Ok(c) = self.db.get_container(id).await {
            self.notify_action(&c, action, attributes);
        }
    }

    pub async fn start(self: &Arc<Self>, id: &str) -> ContainerResult<()> {
        self.start_with(id, false).await.map(|_| ())
    }

    /// [`Self::start`] for the start `check` says.
    pub async fn start_checking(
        self: &Arc<Self>,
        id: &str,
        check: &StartCheck,
    ) -> ContainerResult<()> {
        self.start_as(id, false, check).await.map(|_| ())
    }

    /// The monitor this process started is observed when this process is
    /// one that observes (the engine service); else its connection ends
    /// here.
    fn observe_started(self: &Arc<Self>, id: &str, events: MonitorConn) {
        if self.supervision.observe {
            self.watch_monitor(id.to_string(), events);
        }
    }

    /// Observe the events of a monitor in a task of its own.  The monitor
    /// records them; this only tells this process's clients, and finds the
    /// monitor that ends without a word.
    pub(in crate::services) fn watch_monitor(
        self: &Arc<Self>,
        id: String,
        mut events: MonitorConn,
    ) {
        let svc = Arc::clone(self);
        let key = id.clone();
        let task = tokio::spawn(async move {
            let _end = svc.lifecycle.followed_end(&id);
            // (a hang up, or what is no reply, ends it)
            while let Ok(Some(r)) = events
                .next::<velarx_wire::monitor::iface::Subscribed>()
                .await
            {
                if let Some(event) = r.parameters.event.and_then(|e| e.into_event()) {
                    // (the monitor records what it says itself)
                    if let Err(e) = svc.observe_event(&id, event).await {
                        warn!("Cannot tell of an event of container {}: {}", id, e);
                    }
                }
            }
            svc.look_after_monitor_gone(&id).await;
        });
        self.lifecycle.watch(&key, task.abort_handle());
    }

    /// The lock of the start of a container, held while it is started and
    /// while what the monitor says is recorded: a file of the monitors'
    /// directory, locked with `flock` (released when the process ends).
    pub(in crate::services) async fn start_lock(&self, id: &str) -> ContainerResult<StartLock> {
        let _file = self.mon_lock(self.start_lock_file(id)).await?;
        Ok(StartLock { _file })
    }

    /// The lock file `path` of the monitors' directory, taken with `flock`.
    pub(super) async fn mon_lock(&self, path: PathBuf) -> ContainerResult<std::fs::File> {
        crate::off_thread(move || velarx_runtime::settle::lock::exclusive(&path))
            .await
            .map_err(io_error)
    }

    /// The lock file of the container `id` with the extension `ext`.
    pub(super) fn mon_lock_file(&self, id: &str, ext: &str) -> PathBuf {
        self.state_dir
            .join("mon")
            .join(format!("{}.{ext}", &id[..id.len().min(12)]))
    }

    /// The lock of a change of the configuration and the bundle of a
    /// container (`update`): the lock of its start, so that a start, the
    /// record of its exit and another change wait for it, and the change
    /// knows whether the container runs.
    pub async fn change_lock(&self, id: &str) -> ContainerResult<StartLock> {
        self.start_lock(id).await
    }

    /// The file of the lock of the start of a container.
    pub(in crate::services) fn start_lock_file(&self, id: &str) -> PathBuf {
        self.mon_lock_file(id, "lock")
    }

    /// A start while the monitor waits to restart the container: the
    /// monitor starts it now, on the file systems it mounted (`check` gives
    /// no digest to hold them to).  Whether there was such a monitor.
    pub(super) async fn start_restarting(
        &self,
        id: &str,
        dir: &Path,
        check: &StartCheck,
    ) -> ContainerResult<bool> {
        let status_dir = dir.to_path_buf();
        let status = tokio::task::spawn_blocking(move || client::status(&status_dir))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?;
        let Ok(status) = status else {
            return Ok(false);
        };
        if status.restarting.is_none() {
            // its restart policy started it again, and the record does not
            // say so yet: a second monitor would find it in the runtime
            if status.state == RunState::Running && status.exit.is_none() {
                check.refuse_running(
                    id,
                    "it runs, on the file systems its monitor mounted when it started",
                )?;
                return Err(ContainerError::AlreadyRunning(id.to_string()));
            }
            return Ok(false);
        }
        check.refuse_unchecked(
            id,
            "its monitor waits to restart it (restart policy), on the file systems it mounted when it started",
        )?;
        info!("Starting container {} now, its restart was waiting", id);
        let start_dir = dir.to_path_buf();
        let reply = tokio::task::spawn_blocking(move || client::start(&start_dir, 0))
            .await
            .map_err(|e| io_error(io::Error::other(e)))?;
        let status = match reply {
            Ok(s) => s,
            Err(e) => {
                return Err(match client::monitor_error(&e) {
                    Some(client::MonitorError::Remote { reason, .. }) => ContainerError::Runtime(
                        crate::container::RuntimeError::Runtime(reason.clone()),
                    ),
                    _ => io_error(e),
                })
            }
        };
        // (the monitor records the restart itself)
        let _ = status;
        Ok(true)
    }
}

/// The directory of the /dev/shm of a shareable container: a tmpfs of the
/// size of the container's `--shm-size`, with the label of the container's
/// files (it goes with [`release_shm_dir`] when the container exits).
/// False where the engine cannot mount one: the container keeps the tmpfs
/// the runtime mounts, and nobody shares it.
fn make_shm_dir(dir: &Path, config: &ContainerConfig) -> ContainerResult<bool> {
    use crate::container::selinux;
    use std::os::unix::fs::PermissionsExt;
    velarx_runtime::settle::mounts::detach_mounts_below(dir);
    let _ = velarx_base::tree::remove_dir_all_confined(dir);
    std::fs::create_dir_all(dir)?;
    let size = config.options.shm_size.unwrap_or(64 << 20);
    let mounted = rustix::mount::mount(
        "shm",
        dir,
        "tmpfs",
        rustix::mount::MountFlags::NOSUID
            | rustix::mount::MountFlags::NODEV
            | rustix::mount::MountFlags::NOEXEC,
        std::ffi::CString::new(format!("mode=1777,size={}k", size.div_ceil(1024)))
            .ok()
            .as_deref(),
    );
    if let Err(e) = mounted {
        tracing::debug!("cannot mount the /dev/shm of the container at {dir:?}: {e}");
        let _ = std::fs::remove_dir(dir);
        return Ok(false);
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o1777))?;
    let Some(s) = config.selinux.as_ref().filter(|_| selinux::enabled()) else {
        return Ok(true);
    };
    if let (_, Some(label)) = selinux::labels(s, config.privileged, selinux::Contexts::host()) {
        selinux::relabel_path(dir, &label, &[]).map_err(|e| {
            ContainerError::InvalidArgument(format!("cannot relabel {}: {e}", dir.display()))
        })?;
    }
    Ok(true)
}

/// The /dev/shm a start mounted for its container: it goes when the start
/// fails before the container is made (then no exit is recorded).
pub(super) struct ShmMount(Option<PathBuf>);

impl ShmMount {
    /// The container was made: its exit releases it.
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for ShmMount {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            velarx_runtime::settle::mounts::release_shm_dir(&dir);
        }
    }
}

/// What every mount of a container's start is asked with.
struct MountAsk<'a> {
    container: &'a velarx_graph::Writable,
    mapping: Option<&'a velarx_fuse::IdTranslate>,
    /// How the owners are shown by a driver that serves the files
    translate: Option<&'a velarx_fuse::IdTranslate>,
    /// (a container with no user namespace of its own has no mapping to put on
    /// a mount: the identity of the granted ids is never one)
    idmap_mount: bool,
    label: Option<&'a str>,
    volatile: bool,
}

impl MountAsk<'_> {
    fn mount<'b>(
        &'b self,
        purpose: velarx_graph::Purpose,
        (image, layers): &'b (velarx_db::ImageRecord, Vec<velarx_db::LayerRecord>),
        accepted: Option<(&'b [Vec<String>], Option<&'b Chain>)>,
    ) -> velarx_graph::MountRequest<'b> {
        velarx_graph::MountRequest {
            container: self.container,
            purpose,
            image,
            layers,
            mapping: self.mapping,
            translate: self.translate,
            idmap_mount: self.idmap_mount,
            label: self.label,
            verity: match accepted {
                Some((accepted, chain)) => velarx_graph::VerityAsk::Enforce { accepted, chain },
                None => velarx_graph::VerityAsk::Off,
            },
            volatile: self.volatile && matches!(purpose, velarx_graph::Purpose::Root),
        }
    }
}

/// The SELinux context of the mounts of a container, when it has one.
pub(in crate::services) fn mount_label(config: &ContainerConfig) -> Option<String> {
    config
        .selinux
        .as_ref()
        .filter(|_| crate::container::selinux::enabled())
        .and_then(|s| {
            use crate::container::selinux;
            selinux::labels(s, config.privileged, selinux::Contexts::host()).1
        })
}

#[cfg(test)]
mod tests {
    use super::{bind_shm, set_namespace_paths, StartCheck};
    use velarx_types::digest::Digest;

    /// A spec with the keys sorted, `linux` (with the
    /// `args` of its seccomp rules) before `process`.
    fn sorted_spec(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"linux": {"namespaces": [{"type": "pid"}, {"type": "ipc"}],
                "seccomp": {"syscalls": [{"names": ["read"], "args": [{"index": 0}]}]}},
                "mounts": [{"destination": "/dev/shm", "type": "tmpfs", "source": "shm"}],
                "ociVersion": "1.0.0", "process": {"args": ["true"]}}"#,
        )
        .unwrap();
        path
    }

    /// The first `args` of the text (what the init of a krun VM runs) is the
    /// command of the process.
    fn first_args_is_the_command(path: &std::path::Path) {
        let text = std::fs::read_to_string(path).unwrap();
        let args = text.find("\"args\"").unwrap();
        assert!(text.find("\"process\"").unwrap() < args, "{text}");
        assert!(args < text.find("\"linux\"").unwrap(), "{text}");
    }

    /// A digest typed for a start that mounts nothing is refused by name;
    /// a start without one, or of the engine, goes on.
    #[test]
    fn a_digest_typed_for_a_start_that_checks_nothing_is_refused() {
        let why = "it runs";
        StartCheck::Engine.refuse_unchecked("c", why).unwrap();
        let none = StartCheck::User {
            digests: Vec::new(),
            option: true,
        };
        none.refuse_unchecked("c", why).unwrap();
        let typed = StartCheck::User {
            digests: vec![digest_of('a')],
            option: true,
        };
        let e = typed.refuse_unchecked("c", why).unwrap_err().to_string();
        assert!(
            e.contains("container c: --verify-image sha256:aaaa")
                && e.contains("it runs: nothing would be checked now"),
            "{e}"
        );
    }

    fn digest_of(c: char) -> Digest {
        format!("sha256:{}", c.to_string().repeat(64))
            .parse()
            .unwrap()
    }

    fn member(container: &str, digest: Option<&Digest>, enforced: bool) -> super::MemberImage {
        super::MemberImage {
            container: container.to_string(),
            reference: format!("img-{container}"),
            digest: digest.copied(),
            enforced: enforced.then_some("--security-opt verity=enforce"),
        }
    }

    /// The digests typed on a pod start fit the images of its members: each
    /// enforced image made from a digest is named, each digest names one,
    /// both refused by name before the first member starts.
    #[test]
    fn the_digests_typed_for_a_pod_are_matched_to_the_images_of_its_members() {
        let (a, b, c) = (digest_of('a'), digest_of('b'), digest_of('c'));
        let images = [
            member("web", Some(&a), true),
            member("db", Some(&b), true),
            member("tag", None, true),
            member("loose", Some(&c), false),
        ];
        // both named: starts (the member made from a tag and the one not
        // enforced need none)
        assert_eq!(super::pod_digests_refusal(&images, &[a, b], true), None);
        // one missing: refused naming the container and its image
        let e = super::pod_digests_refusal(&images, std::slice::from_ref(&a), true).unwrap();
        assert!(
            e.contains("container db: img-db: the container was made from the digest sha256:bbbb")
                && e.contains(&format!("pass --verify-image {b}")),
            "{e}"
        );
        // none: the first is named
        let e = super::pod_digests_refusal(&images, &[], true).unwrap();
        assert!(e.contains("container web: img-web"), "{e}");
        // a digest of no image, and one of an image that is not enforced
        for stray in [digest_of('d'), c] {
            let typed = [a, b, stray];
            let e = super::pod_digests_refusal(&images, &typed, true).unwrap();
            assert!(
                e.contains(&format!(
                    "--verify-image {stray}: no image of the containers that start is held to it"
                )),
                "{e}"
            );
        }
        // nothing enforced: the option is refused, the references of a play
        // are not
        let loose = [member("loose", Some(&c), false)];
        let e = super::pod_digests_refusal(&loose, std::slice::from_ref(&c), true).unwrap();
        assert!(e.contains("not enforced"), "{e}");
        assert_eq!(super::pod_digests_refusal(&loose, &[c], false), None);
        // not a digest: refused where the texts of the request are typed
        let e = super::verify_image_digests(&["sha256:AB".to_string()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("--verify-image sha256:AB: not a digest"), "{e}");
        assert_eq!(
            super::verify_image_digests(&[format!("sha256:{}", "a".repeat(64))]).unwrap(),
            [a]
        );
        // a play: the digests of the references need not name an enforced
        // image, but an enforced one made from a digest must be named
        assert_eq!(
            super::pod_digests_refusal(&images, &[a, b, digest_of('e')], false),
            None
        );
        let e = super::pod_digests_refusal(&images, &[a], false).unwrap();
        assert!(e.contains("container db"), "{e}");
    }

    /// A member of a pod that runs is not started, so the digests typed are
    /// not refused for it; a user's start of one container still refuses them.
    #[test]
    fn a_member_that_runs_does_not_refuse_the_digests_of_the_pod() {
        let pod = StartCheck::Pod {
            digests: vec![digest_of('a')],
        };
        pod.refuse_running("c", "it runs").unwrap();
        assert!(pod.refuse_unchecked("c", "it was initialized").is_err());
        let user = StartCheck::User {
            digests: pod.typed().to_vec(),
            option: true,
        };
        assert!(user.refuse_running("c", "it runs").is_err());
    }

    #[test]
    fn the_namespaces_joined_at_start_keep_the_process_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = sorted_spec(dir.path());
        set_namespace_paths(&path, &[("ipc", "/proc/7/ns/ipc".to_string())]).unwrap();
        first_args_is_the_command(&path);
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(spec["linux"]["namespaces"][1]["path"], "/proc/7/ns/ipc");
        assert!(spec["linux"]["namespaces"][0].get("path").is_none());
    }

    #[test]
    fn the_shared_shm_keeps_the_process_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = sorted_spec(dir.path());
        bind_shm(&path, std::path::Path::new("/run/x/shm")).unwrap();
        first_args_is_the_command(&path);
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(spec["mounts"][0]["type"], "bind");
        assert_eq!(spec["mounts"][0]["source"], "/run/x/shm");
        // (a bind already: the spec is not written again)
        let before = std::fs::read(&path).unwrap();
        bind_shm(&path, std::path::Path::new("/run/y/shm")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
