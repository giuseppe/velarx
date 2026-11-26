// SPDX-License-Identifier: Apache-2.0
//! RUN: its flags (`--mount`, `--network`, `--security`), its
//! here-documents, the container it runs in and the commit of what it
//! changed.
//!
//! The mounts are mounts of the RUN container: a bind of the context (or
//! of a named directory context), read-only unless `rw` (then an overlay
//! whose writes are discarded); a read-only image mount of a directory of a
//! stage or an image (a file, or `rw`: a copy, discarded); a cache
//! directory of the store (`build-cache/`, next to the build's work
//! directory), locked as `sharing` says; a tmpfs; a secret file in a
//! directory of the build in the state directory (a tmpfs), removed after
//! the step, or a variable; a socket the engine serves that forwards each
//! connection to an agent of the client.  None of them is in the layer.

use super::runmount::{Kind, RunMount, Sharing};
use super::*;
use crate::container::MountConfig;
use crate::services::volume::{MountSpec, MountType, VolumeMountOptions};

/// What the mounts of a RUN step hold until it ends.
#[derive(Default)]
struct StepMounts {
    configs: Vec<MountConfig>,
    /// Variables the mounts set (`SSH_AUTH_SOCK`).
    env: Vec<String>,
    /// The variables of secrets (`env=`): never in a key or a log.
    secret_env: Vec<String>,
    /// Files and directories to give to these ids of the container once
    /// its mappings are known.
    owners: Vec<(PathBuf, u32, u32)>,
    /// Removed after the step.
    scratch: Vec<PathBuf>,
    /// The locks of the cache directories.
    locks: Vec<OwnedFd>,
    /// The servers of the agent sockets.
    agents: Vec<tokio::task::JoinHandle<()>>,
    /// The scratch space the copies hold.
    space: Option<Reservation>,
    /// When the step began to read its sources (see
    /// `CopyJob::unchanged_since`).
    since: Option<(i64, i64)>,
    /// A source copied for the step changed since: the step is not recorded
    /// under the key its digests made.
    changed: bool,
}

impl Drop for StepMounts {
    fn drop(&mut self) {
        for a in &self.agents {
            a.abort();
        }
        for p in &self.scratch {
            match std::fs::symlink_metadata(p) {
                Ok(m) if m.is_dir() => remove_dir(p),
                Ok(_) => {
                    let _ = std::fs::remove_file(p);
                }
                Err(_) => {}
            }
        }
    }
}

/// The container of a running step: known to the service until the step
/// ends.
pub(super) struct StepId<'a>(&'a BuildService, String);

impl<'a> StepId<'a> {
    /// A new step, known to `svc` from now on.
    pub(super) fn new(svc: &'a BuildService) -> Self {
        let id = crate::services::new_id();
        svc.steps().insert(id.clone());
        Self(svc, id)
    }

    pub(super) fn id(&self) -> &str {
        &self.1
    }
}

impl Drop for StepId<'_> {
    fn drop(&mut self) {
        self.0.steps().remove(&self.1);
    }
}

/// Where the source of a bind or cache mount is.
enum Root {
    /// A directory: the context, a named context.
    Dir(DirRoot),
    /// An image (a stage's, a named context's, or one pulled).
    Image(String),
}

/// A directory the sources of mounts are looked up in.
struct DirRoot {
    /// The directory, held open.
    fd: OwnedFd,
    /// It is the context of the build (its ignore file applies to the
    /// mounts).
    context: bool,
    /// Where the engine has it, when it opened it by name (an extracted,
    /// cloned or downloaded context, a named directory, podman's `local_dir`):
    /// a source below it is mounted where it is.  None for a directory a
    /// client sent as a descriptor, which may be a mount of the client's
    /// mount namespace: the kernel does not clone that for the runtime (a
    /// `/proc/self/fd/N` source fails the same way), so a source below it is
    /// copied for the step, as a directory of an image is.
    path: Option<PathBuf>,
}

/// `rel` inside `root`, no link followed out of it: the path it is (no
/// link in it).  `create`: the directories that are missing are made.
fn resolve_in(root: &Path, rel: &str, create: bool) -> std::io::Result<PathBuf> {
    let root_fd = open_path_dir(root)?;
    let root_real = std::fs::read_link(velarx_sys::fd::proc_path(&root_fd))?;
    let open = |p: &Path| {
        velarx_sys::fs::openat2_retry(
            root_fd.as_fd(),
            p,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            IN_ROOT,
        )
    };
    // the path so far, relative to the root, without links
    let mut so_far = PathBuf::new();
    let mut fd = open(Path::new("."))?;
    for c in rel.split('/').filter(|c| !c.is_empty() && *c != ".") {
        let next = so_far.join(c);
        fd = match open(&next) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) if create => {
                let dir = velarx_sys::fs::openat2_retry(
                    root_fd.as_fd(),
                    so_far.as_path().join(".").as_path(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    IN_ROOT,
                )?;
                match rustix::fs::mkdirat(&dir, c, Mode::from_raw_mode(0o755)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                // (a link to nowhere is still nowhere)
                open(&next)?
            }
            Err(e) => return Err(e.into()),
        };
        let real = std::fs::read_link(velarx_sys::fd::proc_path(&fd))?;
        so_far = real
            .strip_prefix(&root_real)
            .map_err(|_| std::io::Error::other(format!("`{rel}` is not inside its root")))?
            .to_path_buf();
    }
    let real = std::fs::read_link(velarx_sys::fd::proc_path(&fd))?;
    if !real.starts_with(&root_real) {
        return Err(std::io::Error::other(format!(
            "`{rel}` is not inside its root"
        )));
    }
    Ok(real)
}

/// The mount the container service makes of `spec`.
pub(super) fn mount_config(spec: MountSpec) -> BuildResult<MountConfig> {
    spec.to_mount_config(Path::new(""))
        .map_err(|e| BuildError::Parse(e.to_string()))
}

/// A socket listening at `path` for the agent of a RUN step: under
/// SELinux of the context of the containers' processes, which they may
/// connect to (buildah's agent socket has the label of its containers).
fn agent_listener(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    use crate::container::selinux;
    let label = selinux::enabled().then(|| {
        let c = selinux::Contexts::host();
        format!("{}:{}:{}:s0", c.user, c.role, c.typ)
    });
    // (the context of the sockets this thread makes: no await until it is
    // put back by an empty write)
    let attr = "/proc/thread-self/attr/sockcreate";
    if let Some(l) = &label {
        std::fs::write(attr, l)?;
    }
    let listener = std::os::unix::net::UnixListener::bind(path);
    if label.is_some() {
        std::fs::OpenOptions::new()
            .write(true)
            .open(attr)
            .and_then(|mut f| std::io::Write::write(&mut f, &[]))?;
    }
    let listener = listener?;
    listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(listener)
}

pub(super) fn bind_of(source: &Path, target: &str, rw: bool, m: Option<&RunMount>) -> MountSpec {
    let mut options = VolumeMountOptions {
        read_only: !rw,
        ..Default::default()
    };
    if let Some(m) = m {
        for o in &m.options {
            match o.as_str() {
                "bind" => options.non_recursive = true,
                p if crate::services::volume::BindPropagation::parse(p).is_some() => {
                    options.propagation =
                        crate::services::volume::BindPropagation::parse(p).unwrap_or_default()
                }
                o => options.extra.push(o.to_string()),
            }
        }
        options.selinux_relabel = match m.relabel.as_deref() {
            Some("z") => Some(crate::services::volume::SelinuxRelabel::Shared),
            Some("Z") => Some(crate::services::volume::SelinuxRelabel::Private),
            _ => None,
        };
    }
    MountSpec {
        mount_type: MountType::Bind,
        source: Some(source.to_string_lossy().into_owned()),
        target: target.to_string(),
        options,
    }
}

/// Give `path` to the ids `uid:gid` of a container with these mappings
/// (none: the ids of the engine's namespace).
fn give_to(
    path: &Path,
    uid: u32,
    gid: u32,
    uid_maps: &[velarx_proto::pod::IdMapping],
    gid_maps: &[velarx_proto::pod::IdMapping],
) -> std::io::Result<()> {
    let host = |maps: &[velarx_proto::pod::IdMapping], id: u32, what: &str| {
        if maps.is_empty() {
            return Ok(id);
        }
        velarx_base::idmap::to_parent(maps, id).ok_or_else(|| {
            std::io::Error::other(format!(
                "the {what} {id} is not mapped in the user namespace of the build"
            ))
        })
    };
    rustix::fs::chownat(
        rustix::fs::CWD,
        path,
        Some(rustix::fs::Uid::from_raw(host(uid_maps, uid, "uid")?)),
        Some(rustix::fs::Gid::from_raw(host(gid_maps, gid, "gid")?)),
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )?;
    Ok(())
}

/// The lock of a cache directory, taken as `exclusive` says; `wait`: until
/// it is free, else `None` when it is held.
fn lock_file(path: &Path, exclusive: bool, wait: bool) -> std::io::Result<Option<OwnedFd>> {
    use rustix::fs::FlockOperation as Op;
    let fd = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )?;
    let op = match (exclusive, wait) {
        (true, true) => Op::LockExclusive,
        (true, false) => Op::NonBlockingLockExclusive,
        (false, true) => Op::LockShared,
        (false, false) => Op::NonBlockingLockShared,
    };
    match velarx_sys::flock::flock_retrying(&fd, op) {
        Ok(()) => Ok(Some(fd)),
        Err(e) if !wait && e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove the cache directories of RUN --mount=type=cache nothing uses:
/// the bytes they took.
pub fn prune_cache_mounts(dir: &Path) -> std::io::Result<u64> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut freed = 0;
    for e in entries {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".lock") || !e.file_type()?.is_dir() {
            continue;
        }
        let Some(_lock) = lock_file(&dir.join(format!("{name}.lock")), true, false)? else {
            continue;
        };
        freed += disk_usage(&e.path()).unwrap_or(0);
        remove_dir(&e.path());
        let _ = std::fs::remove_file(dir.join(format!("{name}.lock")));
    }
    Ok(freed)
}

/// Forward each connection to `sock` to a new connection of the agent `id`
/// of the client.
async fn serve_agent(listener: tokio::net::UnixListener, agents: Arc<dyn AgentSource>, id: String) {
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            return;
        };
        let (agents, id) = (agents.clone(), id.clone());
        tokio::spawn(async move {
            let upstream = match agents.connect(&id).await {
                Ok(fd) => fd,
                Err(e) => {
                    warn!("No connection to the ssh agent {id} of the build: {e}");
                    return;
                }
            };
            let upstream = std::os::unix::net::UnixStream::from(upstream);
            let upstream = upstream
                .set_nonblocking(true)
                .and_then(|()| tokio::net::UnixStream::from_std(upstream));
            match upstream {
                Ok(mut up) => {
                    let _ = tokio::io::copy_bidirectional(&mut conn, &mut up).await;
                }
                Err(e) => warn!("The ssh agent {id} of the build: {e}"),
            }
        });
    }
}

impl Build<'_> {
    /// Under SELinux, give the files the build made for the mounts of a
    /// RUN step (its secrets, agent sockets, copies, caches and the context
    /// it received) the label containers share, as buildah's are, so that
    /// the step can read them.  A source that `z` or `Z` names is
    /// relabeled when the container is made, one of the user's never.
    fn label_sources(&self, configs: &[MountConfig], i: &Instr) -> BuildResult<()> {
        use crate::container::selinux;
        if !selinux::enabled() {
            return Ok(());
        }
        let c = selinux::Contexts::host();
        let label = format!("{}:{}:{}:s0", c.file_user, c.file_role, c.file_type);
        let run = self.svc.container_service.state_dir.join("build");
        let own = [
            self.svc.work_dir.as_path(),
            self.svc.cache_dir.as_path(),
            run.as_path(),
        ];
        for m in configs {
            let src = Path::new(&m.source);
            if m.relabel.is_some() || m.image.is_some() || !own.iter().any(|d| src.starts_with(d)) {
                continue;
            }
            selinux::relabel_path(src, &label, &[])
                .map_err(|e| step_error(i, format!("cannot relabel {}: {e}", m.source)))?;
        }
        Ok(())
    }

    /// The directory of the build in the state directory (a tmpfs): its
    /// secrets and agent sockets.
    fn run_dir(&mut self) -> BuildResult<PathBuf> {
        if self.run_dir.is_none() {
            let parent = self.svc.container_service.state_dir.join("build");
            private_dir(&parent)?;
            self.run_dir = Some(tempfile::Builder::new().prefix("b").tempdir_in(&parent)?);
        }
        Ok(self
            .run_dir
            .as_ref()
            .map(|d| d.path().to_path_buf())
            .unwrap_or_default())
    }

    /// Where the source of `from` is: a named context, a stage, an image.
    async fn root_of(&self, st: &StageState, from: Option<&str>) -> BuildResult<Root> {
        let Some(from) = from else {
            return Ok(Root::Dir(DirRoot {
                fd: self.ctx.fd()?,
                context: true,
                path: self.ctx.path.clone(),
            }));
        };
        Ok(match self.opts.contexts.get(from) {
            Some(NamedContext::Dir(d)) => Root::Dir(DirRoot {
                fd: open_path_dir(d)?,
                context: false,
                path: Some(d.clone()),
            }),
            Some(NamedContext::Image(i)) => {
                Root::Image(self.ensure_image(i, self.opts.platform.as_deref()).await?)
            }
            None => match self.stage_image(from, st.index) {
                Some(id) => Root::Image(id),
                None => Root::Image(
                    self.ensure_image(from, self.opts.platform.as_deref())
                        .await?,
                ),
            },
        })
    }

    /// Whether `path` is a directory of the image `id`.
    async fn image_dir(&self, id: &str, path: &str) -> BuildResult<bool> {
        let rec = self.svc.image_service.get(id).await?;
        let tocs = self.svc.image_service.layer_tocs(&rec).await?;
        let refs: Vec<&Toc> = tocs.iter().collect();
        let tree = MergedTree::build(&refs).map_err(BuildError::Parse)?;
        if path.is_empty() {
            return Ok(true);
        }
        Ok(tree
            .resolve(path)
            .and_then(|n| tree.node(n))
            .is_some_and(|n| n.entry.entry_type == TocEntryType::Dir))
    }

    /// A copy of `source` of the image `id` in a scratch directory: the
    /// path of the copy (the directory, or the file in it).
    async fn copy_of_image(
        &mut self,
        id: &str,
        source: &str,
        i: &Instr,
        mounts: &mut StepMounts,
    ) -> BuildResult<PathBuf> {
        let dir = self.new_dir("mount")?;
        mounts.scratch.push(dir.clone());
        let src = format!("/{source}");
        let (job, from, end) = self
            .image_sources(
                id,
                std::slice::from_ref(&src),
                ImageDest {
                    dst: "/",
                    dest_dir: true,
                    chown: None,
                    chmod: None,
                    parents: false,
                    excludes: &[],
                },
                i,
            )
            .await?;
        let space = mounts
            .space
            .get_or_insert_with(|| self.svc.scratch.reservation());
        let job = CopyJob {
            limits: self.svc.job_limits(space)?,
            ..job
        };
        self.svc
            .runner
            .run(job, &dir, from, &self.cancel)
            .await
            .map_err(|e| self.failed(i, e))?;
        end.check(i)?;
        space.set(disk_usage(&dir)?)?;
        let base = source.rsplit('/').next().unwrap_or_default();
        let file = dir.join(base);
        Ok(if !source.is_empty() && !file.is_dir() && file.exists() {
            file
        } else {
            dir
        })
    }

    /// What a mount adds to the key of the step: never the value of a
    /// secret or what an agent holds.
    async fn mount_key(&self, m: &RunMount, root: Option<&Root>) -> BuildResult<Value> {
        let mut key = serde_json::to_value(m)?;
        match (m.kind, root) {
            (Kind::Bind, Some(Root::Dir(root))) => {
                // the files the step sees, as COPY digests them
                let ignore = if root.context {
                    self.ignore.lines()
                } else {
                    Vec::new()
                };
                let job = CopyJob {
                    items: vec![Item {
                        src: if m.source.is_empty() {
                            ".".into()
                        } else {
                            m.source.clone()
                        },
                        dst: "/".into(),
                        dest_dir: true,
                        ..Default::default()
                    }],
                    ignore,
                    ..CopyJob::new(Source::Context)
                };
                let scratch = self.work.path().join("digest");
                let _ = std::fs::create_dir(&scratch);
                let digest = self
                    .svc
                    .runner
                    .digest(
                        job,
                        &scratch,
                        JobSource::Fd(root.fd.try_clone()?),
                        &self.cancel,
                    )
                    .await
                    .map_err(|e| {
                        BuildError::StepFailed(format!(
                            "the source of the mount at {}: {e}",
                            m.target
                        ))
                    })?;
                key["files"] = json!(digest);
            }
            (_, Some(Root::Image(id))) => key["image"] = json!(id),
            (Kind::Secret, _) => {
                key["present"] = json!(self
                    .opts
                    .secrets
                    .contains_key(m.id.as_deref().unwrap_or("")))
            }
            (Kind::Ssh, _) => {
                key["present"] = json!(self
                    .opts
                    .agents
                    .as_ref()
                    .is_some_and(|a| a.ids().iter().any(|i| Some(i.as_str()) == m.id.as_deref())))
            }
            _ => {}
        }
        Ok(key)
    }

    /// Make the mount `m` (its source `root`) for the step.
    async fn add_mount(
        &mut self,
        m: &RunMount,
        root: Option<Root>,
        i: &Instr,
        mounts: &mut StepMounts,
        ssh_mounted: &mut bool,
    ) -> BuildResult<()> {
        let step =
            |e: &dyn std::fmt::Display| step_error(i, format!("the mount at {}: {e}", m.target));
        match m.kind {
            Kind::Bind => {
                let spec = match root {
                    Some(Root::Dir(dir)) => {
                        let src = self.source_in(&dir, &m.source, i, mounts).await?;
                        if m.rw && src.is_dir() {
                            let mut spec = bind_of(&src, &m.target, true, Some(m));
                            spec.options.overlay = true;
                            spec
                        } else if m.rw {
                            let copy = self.new_dir("mount")?;
                            mounts.scratch.push(copy.clone());
                            let file = copy.join("file");
                            let (from, to) = (src.clone(), file.clone());
                            crate::off_thread(move || velarx_storage::copy_path(&from, &to))
                                .await
                                .map_err(|e| step(&e))?;
                            bind_of(&file, &m.target, true, Some(m))
                        } else {
                            bind_of(&src, &m.target, false, Some(m))
                        }
                    }
                    Some(Root::Image(id)) => {
                        if !m.rw && self.image_dir(&id, &m.source).await? {
                            MountSpec {
                                mount_type: MountType::Image,
                                source: Some(id),
                                target: m.target.clone(),
                                options: VolumeMountOptions {
                                    subpath: (!m.source.is_empty()).then(|| m.source.clone()),
                                    ..Default::default()
                                },
                            }
                        } else {
                            let copy = self.copy_of_image(&id, &m.source, i, mounts).await?;
                            bind_of(&copy, &m.target, m.rw, Some(m))
                        }
                    }
                    None => return Err(step(&"no source")),
                };
                mounts.configs.push(mount_config(spec)?);
            }
            Kind::Cache => {
                let source = match root {
                    // seeded from a stage or a context: a copy, discarded
                    Some(Root::Image(id)) => self.copy_of_image(&id, &m.source, i, mounts).await?,
                    Some(Root::Dir(dir)) => {
                        let src = self.source_in(&dir, &m.source, i, mounts).await?;
                        let mut spec = bind_of(&src, &m.target, m.rw, Some(m));
                        spec.options.overlay = src.is_dir();
                        mounts.configs.push(mount_config(spec)?);
                        return Ok(());
                    }
                    None => {
                        let parent = self.svc.cache_dir.clone();
                        private_dir(&parent)?;
                        let name = m.cache_name();
                        let lock = parent.join(format!("{name}.lock"));
                        // (a `source` in the directory is resolved here and
                        // mounted by its path by the runtime: no other step
                        // may change the directory in between, so it is held
                        // alone)
                        let (exclusive, wait) = match m.sharing {
                            Sharing::Shared if m.source.is_empty() => (false, true),
                            Sharing::Shared | Sharing::Locked => (true, true),
                            Sharing::Private => (true, false),
                        };
                        let held =
                            tokio::task::spawn_blocking(move || lock_file(&lock, exclusive, wait))
                                .await
                                .map_err(std::io::Error::other)??;
                        let dir = match held {
                            Some(fd) => {
                                mounts.locks.push(fd);
                                parent.join(&name)
                            }
                            // (in use by another step: one of its own)
                            None => {
                                let d = self.new_dir("cache")?;
                                mounts.scratch.push(d.clone());
                                std::fs::remove_dir(&d)?;
                                d
                            }
                        };
                        if !dir.exists() {
                            std::fs::create_dir(&dir)?;
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(
                                &dir,
                                std::fs::Permissions::from_mode(m.mode.unwrap_or(0o755)),
                            )?;
                            mounts.owners.push((dir.clone(), m.uid, m.gid));
                        }
                        let src = resolve_in(&dir, &m.source, true).map_err(|e| step(&e))?;
                        if src != dir && !m.source.is_empty() {
                            mounts.owners.push((src.clone(), m.uid, m.gid));
                        }
                        src
                    }
                };
                mounts
                    .configs
                    .push(mount_config(bind_of(&source, &m.target, m.rw, Some(m)))?);
            }
            Kind::Tmpfs => {
                let mut options = VolumeMountOptions::default();
                options.extra = m.options.clone();
                options.read_only = m.options.iter().any(|o| o == "ro");
                options.extra.retain(|o| o != "ro");
                if !options.extra.iter().any(|o| o == "noexec") {
                    options.extra.push("exec".into());
                }
                if let Some(s) = &m.size {
                    options.tmpfs.push(format!("size={s}"));
                }
                if let Some(mode) = m.tmpfs_mode {
                    options.tmpfs.push(format!("mode={mode:o}"));
                }
                mounts.configs.push(mount_config(MountSpec {
                    mount_type: MountType::Tmpfs,
                    source: None,
                    target: m.target.clone(),
                    options,
                })?);
            }
            Kind::Secret => {
                let id = m.id.clone().unwrap_or_default();
                let Some(value) = self.opts.secrets.get(&id).cloned() else {
                    if m.required {
                        return Err(step_error(
                            i,
                            format!("secret required but no secret with id {id:?} found"),
                        ));
                    }
                    return Ok(());
                };
                if let Some(var) = &m.env {
                    mounts
                        .secret_env
                        .push(format!("{var}={}", String::from_utf8_lossy(&value.0)));
                    if !m.target_given {
                        return Ok(());
                    }
                }
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let dir = self.run_dir()?;
                self.seq += 1;
                let file = dir.join(format!("s{}", self.seq));
                mounts.scratch.push(file.clone());
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(m.mode.unwrap_or(0o400))
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&file)?
                    .write_all(&value.0)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &file,
                    std::fs::Permissions::from_mode(m.mode.unwrap_or(0o400)),
                )?;
                mounts.owners.push((file.clone(), m.uid, m.gid));
                mounts
                    .configs
                    .push(mount_config(bind_of(&file, &m.target, false, None))?);
            }
            Kind::Ssh => {
                let id = m.id.clone().unwrap_or_default();
                let agents = self.opts.agents.clone().filter(|a| a.ids().contains(&id));
                let Some(agents) = agents else {
                    if m.required {
                        return Err(step_error(
                            i,
                            format!("ssh required but no ssh with id {id} found"),
                        ));
                    }
                    return Ok(());
                };
                let dir = self.run_dir()?;
                self.seq += 1;
                let sock = dir.join(format!("a{}", self.seq));
                let listener = agent_listener(&sock).map_err(|e| step(&e))?;
                mounts.scratch.push(sock.clone());
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    &sock,
                    std::fs::Permissions::from_mode(m.mode.unwrap_or(0o600)),
                )?;
                mounts.owners.push((sock.clone(), m.uid, m.gid));
                mounts
                    .agents
                    .push(tokio::spawn(serve_agent(listener, agents, id)));
                mounts
                    .configs
                    .push(mount_config(bind_of(&sock, &m.target, true, None))?);
                if !*ssh_mounted {
                    *ssh_mounted = true;
                    mounts.env.push(format!("SSH_AUTH_SOCK={}", m.target));
                }
            }
        }
        Ok(())
    }

    /// The source `source` of a mount below the directory `root`, links
    /// resolved inside it, none followed out of it: where it is when the
    /// engine opened the directory by name, else a copy of it made for the
    /// step by the confined worker (what the step sees is what the tree has
    /// when the step starts, and the copy is removed after it: the client's
    /// tree is never written, and holds no mount of the step).
    async fn source_in(
        &mut self,
        root: &DirRoot,
        source: &str,
        i: &Instr,
        mounts: &mut StepMounts,
    ) -> BuildResult<PathBuf> {
        let step = |e: &dyn std::fmt::Display| step_error(i, format!("the mount of {source}: {e}"));
        if let Some(path) = &root.path {
            return resolve_in(path, source, false).map_err(|e| step(&e));
        }
        let rel = context_relative(source).map_err(|e| step(&e))?;
        let dir = self.new_dir("mount")?;
        mounts.scratch.push(dir.clone());
        let space = mounts
            .space
            .get_or_insert_with(|| self.svc.scratch.reservation());
        let (src, changed) = self
            .copy_from_dir(&root.fd, &rel, &dir, mounts.since, space)
            .await
            .map_err(|e| step(&e))?;
        mounts.changed |= changed;
        Ok(src)
    }

    /// Copy `rel` of the directory `root` (a path in it, links resolved
    /// inside it, `""` the whole tree) into the empty directory `dir`, in the
    /// confined worker, as COPY copies from a context (no link followed out
    /// of it, the owner the worker's), within `space`: where the copy of
    /// `rel` is (`dir`, or the file in it), and whether a node copied
    /// changed since `since` (see `CopyJob::unchanged_since`).
    pub(super) async fn copy_from_dir(
        &self,
        root: &OwnedFd,
        rel: &str,
        dir: &Path,
        since: Option<(i64, i64)>,
        space: &mut Reservation,
    ) -> BuildResult<(PathBuf, bool)> {
        use rustix::fs::{FileType, Mode, OFlags};
        let is_dir = rel.is_empty() || {
            let node = velarx_sys::fs::openat2_retry(
                root.as_fd(),
                rel,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                IN_ROOT,
            )
            .map_err(std::io::Error::from)?;
            FileType::from_raw_mode(
                rustix::fs::fstat(&node)
                    .map_err(std::io::Error::from)?
                    .st_mode,
            ) == FileType::Directory
        };
        // (a directory's content goes to `dir`, a file is `dir/file`: no
        // name of the tree decides what is mounted)
        let job = CopyJob {
            items: vec![Item {
                src: if rel.is_empty() {
                    ".".into()
                } else {
                    rel.into()
                },
                dst: if is_dir { "/".into() } else { "/file".into() },
                dest_dir: is_dir,
                ..Default::default()
            }],
            limits: self.svc.job_limits(space)?,
            unchanged_since: since,
            ..CopyJob::new(Source::Context)
        };
        let changed = self
            .svc
            .runner
            .run(job, dir, JobSource::Fd(root.try_clone()?), &self.cancel)
            .await?;
        space.set(disk_usage(dir)?)?;
        Ok((
            if is_dir {
                dir.to_path_buf()
            } else {
                dir.join("file")
            },
            changed,
        ))
    }

    /// The command of a RUN: its here-documents as BuildKit runs them (one
    /// alone is the script: a file executed when it starts with `#!`, else
    /// the shell's command; with other words the shell reads them).
    fn run_argv(
        &mut self,
        st: &StageState,
        i: &Instr,
        mounts: &mut StepMounts,
    ) -> BuildResult<Vec<String>> {
        if i.json.is_some() || i.heredocs.is_empty() {
            return Ok(st.argv(i));
        }
        let mut argv = st.shell.clone();
        if let Some(h) = i.only_heredoc() {
            let content = h.content();
            if !content.starts_with("#!") {
                argv.push(content);
                return Ok(argv);
            }
            use std::os::unix::fs::PermissionsExt;
            let dir = self.new_dir("pipes")?;
            mounts.scratch.push(dir.clone());
            let name = h.file_name();
            std::fs::write(dir.join(&name), content.as_bytes())?;
            std::fs::set_permissions(dir.join(&name), std::fs::Permissions::from_mode(0o755))?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
            mounts
                .configs
                .push(mount_config(bind_of(&dir, "/dev/pipes", false, None))?);
            return Ok(vec![format!("/dev/pipes/{name}")]);
        }
        let mut full = i.args.clone();
        for h in &i.heredocs {
            full.push('\n');
            full.push_str(&h.body);
            full.push_str(&h.name);
        }
        argv.push(full);
        Ok(argv)
    }

    pub(super) async fn run_step(&mut self, st: &mut StageState, i: &Instr) -> BuildResult<()> {
        i.check_flags(&["mount", "network", "security"])
            .map_err(BuildError::Parse)?;
        let image = st
            .image
            .clone()
            .ok_or_else(|| step_error(i, "RUN in a stage without a base image"))?;
        // (the network of the build, or the step's: none or the host's)
        let network = match i.flag("network") {
            None | Some("default") => self.opts.network.as_deref().map(NetworkMode::parse),
            Some("none") => Some(NetworkMode::Off),
            Some("host") => Some(NetworkMode::Host),
            Some(n) => {
                return Err(step_error(
                    i,
                    format!("invalid --network `{n}`: default, none or host"),
                ))
            }
        };
        self.svc
            .require(&self.opts.allow, &entitlement::instruction_needs(i))?;
        let insecure = match i.flag("security") {
            None | Some("sandbox") => false,
            Some("insecure") => true,
            Some(s) => {
                return Err(step_error(
                    i,
                    format!("invalid --security `{s}`: sandbox or insecure"),
                ))
            }
        };
        let esc = self.file.escape;
        let mut specs = Vec::new();
        let mut ssh_index = 0;
        for f in i.flags.iter().filter_map(|f| f.strip_prefix("--mount=")) {
            let f = parse::expand(f, esc, &|n| st.lookup(n)).map_err(|e| step_error(i, e))?;
            let m = RunMount::parse(&f, &st.workdir, ssh_index).map_err(|e| step_error(i, e))?;
            if m.kind == Kind::Ssh {
                ssh_index += 1;
            }
            if specs
                .iter()
                .any(|(o, _): &(RunMount, _)| o.target == m.target)
            {
                return Err(step_error(
                    i,
                    format!("{}: duplicate mount destination", m.target),
                ));
            }
            let root = match m.kind {
                Kind::Bind => Some(self.root_of(st, m.from.as_deref()).await?),
                Kind::Cache if m.from.is_some() => Some(self.root_of(st, m.from.as_deref()).await?),
                _ => None,
            };
            specs.push((m, root));
        }
        let mut mounts = StepMounts::default();
        // (before the digests of the mounts' sources)
        mounts.since = Some(change_horizon());
        let argv = self.run_argv(st, i, &mut mounts)?;
        let (entry, cmd) = argv
            .split_first()
            .ok_or_else(|| step_error(i, "RUN requires a command"))?;
        let mut env: Vec<String> = st
            .args
            .iter()
            .filter(|(k, v)| v.is_some() && !st.env.iter().any(|(e, _)| e == k))
            .map(|(k, v)| format!("{k}={}", v.as_deref().unwrap_or_default()))
            .collect();
        env.extend(st.env.iter().map(|(k, v)| format!("{k}={v}")));
        let mut mount_keys = Vec::new();
        if self.caching(st) {
            for (m, root) in &specs {
                mount_keys.push(self.mount_key(m, root.as_ref()).await?);
            }
        }
        let key = self.cache_key(
            st,
            &i.raw_text(),
            json!({
                "run": argv,
                "env": env,
                "workdir": st.workdir,
                "user": st.user,
                "network": network,
                "insecure": insecure,
                "options": self.opts.run,
                "compat_volumes": self.opts.flags.compat_volumes,
                "mounts": mount_keys,
            }),
        )?;
        if self.use_cache(st, &key).await? {
            return Ok(());
        }
        let mut ssh_mounted = false;
        let mut targets = Vec::new();
        for (m, root) in specs {
            self.add_mount(&m, root, i, &mut mounts, &mut ssh_mounted)
                .await?;
            targets.push(m.target.clone());
        }
        targets.extend(mounts.configs.iter().map(|c| c.target.clone()));
        // (the targets of `--volume` are not changes of the step either)
        targets.extend(
            self.opts
                .run
                .volumes
                .iter()
                .filter_map(|v| v.split(':').nth(1))
                .map(velarx_wire::cp::clean_path),
        );
        env.extend(mounts.env.iter().cloned());
        // (`--http-proxy`: for the step only, as the secrets)
        env.extend(
            self.opts
                .flags
                .proxy_env
                .iter()
                .filter(|p| {
                    !env.iter()
                        .any(|e| e.split_once('=').map(|(n, _)| n) == Some(p.name.as_str()))
                })
                .map(|p| format!("{}={}", p.name, p.value))
                .collect::<Vec<_>>(),
        );
        env.extend(mounts.secret_env.iter().cloned());
        // (known to the build before the container exists: a prune of the
        // build containers leaves it)
        self.label_sources(&mounts.configs, i)?;
        let mut volumes = self.opts.run.volumes.clone();
        if self.opts.flags.compat_volumes {
            // (the VOLUMEs of the stage that are not committed yet: the
            // image of the step does not have them)
            for e in st.pending() {
                if let ConfigEdit::Merge(k, paths) = e {
                    if k == "Volumes" {
                        volumes.extend(paths.keys().cloned());
                    }
                }
            }
        }
        let step = StepId::new(self.svc);
        let req = CreateContainerRequest {
            image,
            entrypoint: vec![entry.clone()],
            command: cmd.to_vec(),
            env,
            secret_env: mounts.secret_env.clone(),
            working_dir: st.workdir.clone(),
            // USER: a name, uid or uid:gid resolved in the current image;
            // no passwd or group entry is made for a user it lacks (buildah).
            user: st.user.clone(),
            no_passwd: true,
            stdin_open: self.opts.stdin.is_some(),
            network_mode: network.unwrap_or_default(),
            privileged: insecure,
            id: Some(step.id().to_string()),
            // (buildah's working container is volatile, committed or not:
            // the upper layer is read through the page cache at the end of
            // the step, and a crashed build is over)
            volatile: true,
            labels: [(BUILD_LABEL.to_string(), std::process::id().to_string())].into(),
            mounts: std::mem::take(&mut mounts.configs),
            volumes,
            // (buildah's default: the step sees the directory of the
            // image and keeps what it writes there)
            image_volume: if self.opts.flags.compat_volumes {
                String::new()
            } else {
                "ignore".into()
            },
            add_hosts: self.opts.run.add_hosts.clone(),
            dns: self.opts.run.dns.clone(),
            dns_search: self.opts.run.dns_search.clone(),
            dns_options: self.opts.run.dns_options.clone(),
            cap_add: self.opts.run.cap_add.clone(),
            cap_drop: self.opts.run.cap_drop.clone(),
            security_opts: self.opts.run.security_opts.clone(),
            ulimits: self.opts.run.ulimits.clone(),
            devices: self.opts.run.devices.clone(),
            shm_size: self.opts.run.shm_size,
            group_add: self.opts.run.group_add.clone(),
            no_hosts: self.opts.run.no_hosts,
            no_hostname: self.opts.run.no_hostname,
            resources: self.opts.run.resources.clone(),
            cgroup_parent: self.opts.run.cgroup_parent.clone(),
            ipc_mode: self.opts.run.ipc.clone(),
            pid_mode: self.opts.run.pid.clone(),
            uts_mode: self.opts.run.uts.clone(),
            cgroupns_mode: self.opts.run.cgroupns.clone(),
            userns_mode: self.opts.run.userns.clone(),
            uidmap: self.opts.run.uidmap.clone(),
            gidmap: self.opts.run.gidmap.clone(),
            subuidname: self.opts.run.subuidname.clone(),
            subgidname: self.opts.run.subgidname.clone(),
            ..CreateContainerRequest::default()
        };
        let cs = self.svc.container_service.clone();
        let id = cs.create(req).await?;
        let result = match self.give_owners(&id, &mounts).await {
            Ok(()) => self.run_container(&id).await,
            Err(e) => Err(e),
        };
        let committed = match result {
            Ok(0) => match cs.writable_diff(&id).await {
                Ok((diff, mut walk)) => {
                    walk.exclude.extend(targets);
                    walk.root = velarx_content::layer::dirtar::Root::Changed;
                    // (for a driver whose layer is not an upper directory this
                    // extracts the tar of the changes: off the async thread)
                    let squash = match (&diff, &st.squash_dir) {
                        (Some(d), Some(_)) => {
                            let (d, walk, scratch) =
                                (d.clone(), walk.clone(), self.work.path().to_path_buf());
                            tokio::task::spawn_blocking(move || d.directory(&walk, &scratch))
                                .await
                                .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
                                .map(Some)
                        }
                        _ => Ok(None),
                    };
                    match squash {
                        Err(e) => Err(e.into()),
                        Ok(squash) => self
                            .commit(
                                st,
                                &i.text(),
                                diff.map(Changes::Writable),
                                walk.clone(),
                                (!mounts.changed).then_some(&key),
                            )
                            .await
                            .and_then(|()| match (st.squash_dir.clone(), &squash) {
                                (Some(sq), Some(up)) => self.merge_squash(&up.path, &sq, &up.walk),
                                _ => Ok(()),
                            }),
                    }
                }
                Err(e) => Err(e.into()),
            },
            Ok(code) => Err(step_error(
                i,
                format!("`{}` failed with exit code {code}", i.args),
            )),
            Err(e) => Err(e),
        };
        if let Err(e) = cs.delete(&id, true).await {
            warn!("Cannot remove the build container {id}: {e}");
        }
        drop(mounts);
        committed
    }

    /// The files of the mounts get the ids of the container.
    async fn give_owners(&self, id: &str, mounts: &StepMounts) -> BuildResult<()> {
        if mounts.owners.is_empty() {
            return Ok(());
        }
        let rec = self.svc.container_service.inspect(id).await?;
        let cfg: crate::container::ContainerConfig = serde_json::from_str(&rec.config)?;
        for (path, uid, gid) in &mounts.owners {
            give_to(path, *uid, *gid, &cfg.uid_mappings, &cfg.gid_mappings)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_resolved_inside_their_root() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("root");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("out")).unwrap();
        std::os::unix::fs::symlink("../../..", root.join("a/up")).unwrap();
        let real = root.canonicalize().unwrap();
        assert_eq!(resolve_in(&root, "a/b", false).unwrap(), real.join("a/b"));
        assert_eq!(resolve_in(&root, "", false).unwrap(), real);
        // links resolve inside the root
        assert_eq!(resolve_in(&root, "a/up", false).unwrap(), real);
        assert!(resolve_in(&root, "out", false).is_err());
        assert!(resolve_in(&root, "nope", false).is_err());
        assert_eq!(
            resolve_in(&root, "a/up/new/dir", true).unwrap(),
            real.join("new/dir")
        );
        assert!(real.join("new/dir").is_dir());
    }

    /// (in a process of its own: a program another test starts holds a copy
    /// of the lock until it is executed, so a lock that was dropped would
    /// still be taken for a moment)
    #[test]
    fn cache_locks_and_prune() {
        velarx_base::testing::in_child(|| {
            let d = tempfile::tempdir().unwrap();
            let lock = d.path().join("x.lock");
            let shared = lock_file(&lock, false, true).unwrap().unwrap();
            assert!(lock_file(&lock, false, false).unwrap().is_some());
            assert!(lock_file(&lock, true, false).unwrap().is_none());
            std::fs::create_dir_all(d.path().join("x/sub")).unwrap();
            std::fs::write(d.path().join("x/sub/f"), vec![0u8; 8192]).unwrap();
            std::fs::create_dir(d.path().join("y")).unwrap();
            // the one in use stays
            prune_cache_mounts(d.path()).unwrap();
            assert!(d.path().join("x/sub/f").exists());
            assert!(!d.path().join("y").exists());
            drop(shared);
            assert!(prune_cache_mounts(d.path()).unwrap() >= 8192);
            assert!(!d.path().join("x").exists());
            assert_eq!(prune_cache_mounts(&d.path().join("none")).unwrap(), 0);
        });
    }
}
