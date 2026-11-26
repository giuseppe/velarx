// SPDX-License-Identifier: Apache-2.0
//! Builds from a Containerfile.
//!
//! Every RUN, COPY and ADD is a commit: RUN runs in a container of the
//! current image through the container service and its upper directory is
//! committed; COPY and ADD fill a new directory in a confined worker
//! (`worker`), which is committed on top of the current image.  The other
//! instructions change the configuration, committed with the next layer
//! (or at the end of the stage).  Each commit is an image.  With `layers`
//! (the default) the intermediate images stay, recorded in the build cache
//! by their parent and the key of their step (what the commit is made of:
//! the command and its environment, or the digest of the files copied), and
//! a step whose key is there on the same parent takes the image; without,
//! they are removed at the end.  `--squash` merges the changes of the last
//! stage into one layer on top of its base (and does not use the cache);
//! `--squash-all` replaces the image of the last stage by one whose only
//! layer is its merged tree (the steps use the cache).

pub mod copy;
pub mod entitlement;
pub mod external;
pub mod git;
mod helper;
mod policy;
mod remote;
mod run;
mod runmount;
mod sbom;
mod squash;
pub mod worker;

use crate::services::{
    Cancel, Changes, CommitOptions, ConfigEdit, ContainerError, ContainerService,
    CreateContainerRequest, ImageService, PullOptions, TransferProgress,
};
use copy::{CopyJob, Item, ParentDir, Source};
pub use run::prune_cache_mounts;
use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{info, warn};
use velarx_content::layer::dirtar;
use velarx_fuse::MergedTree;
use velarx_storage::{Toc, TocEntryType};
use velarx_types::digest::{Algorithm, Digest, DigestWriter};
use velarx_types::ImageError;
pub use velarx_wire::parse::{Containerfile, Ignore, Instr};
use velarx_wire::request::NetworkMode;
use velarx_wire::{parse, redact};
use worker::{JobSource, Runner};

#[derive(Error, Debug)]
pub enum BuildError {
    #[error("{0}")]
    Parse(String),
    #[error("{0}")]
    StepFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("image error: {0}")]
    Image(#[from] ImageError),
    #[error("container error: {0}")]
    Container(#[from] ContainerError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the build was cancelled")]
    Cancelled,
}

pub type BuildResult<T> = Result<T, BuildError>;

/// What a build tells as it goes.
#[derive(Debug, Clone)]
pub enum BuildProgress {
    Started {
        total_steps: usize,
    },
    /// `instruction` is the line to show (`[1/2] STEP 1/5: FROM alpine`).
    StepStarted {
        step: usize,
        instruction: String,
    },
    /// What the build says of a step (`COMMIT`, `--> ID`): buildah's
    /// standard output, which `--quiet` leaves out.
    StepOutput {
        step: usize,
        output: String,
    },
    /// What a RUN writes, on the stream it writes it to (`--quiet` keeps it).
    RunOutput {
        step: usize,
        stderr: bool,
        output: String,
    },
    /// The pulls of the bases: buildah's report writer, the standard error
    /// (nothing with `--quiet`).
    Report {
        output: String,
    },
    StepCompleted {
        step: usize,
    },
    /// The build for a platform of several starts (`os/arch[/variant]`).
    Platform {
        platform: String,
    },
    /// A blob the step pulls, writes or stores.
    Blob(TransferProgress),
    Completed {
        image_id: String,
    },
    Error {
        message: String,
    },
}

/// The build context: a directory, and the Containerfile.
///
/// The directory is held open and the build reads the tree through that
/// descriptor, never through a path: COPY and ADD and their digests (in the
/// confined worker), the Containerfile and the ignore files, so what a
/// context is does not change when the path it was opened by is renamed or
/// replaced.  Nothing copies it: the build reads the tree as it is when a
/// step reads it (a file that changes while the build runs is read as it is
/// then).  The digest a COPY step is looked up in the cache by is taken
/// before it copies: a copy that finds a node it copied changed since (its
/// ctime, see `CopyJob::unchanged_since`) records the step under the digest
/// of what it copied instead, and a RUN step whose mount source copied from
/// the context changed so is not recorded in the cache.  The sources of the mounts of RUN and the SBOM scan are mounted
/// where the engine has the directory (`path`), and copied for the step when
/// it has none (see `run::DirRoot`).
#[derive(Debug, Clone)]
pub struct BuildContext {
    root: Arc<OwnedFd>,
    /// Where the directory is when the engine made it or was told its name
    /// (an extracted, cloned or downloaded context, podman's `local_dir`):
    /// the mounts of a step bind it there, and SELinux labels what the build
    /// owns.  A directory the client sent as a descriptor has none: it may be
    /// a mount of the client's mount namespace, and nothing of it is mounted
    /// or relabeled.
    path: Option<PathBuf>,
    /// Relative to the context; `Containerfile` or `Dockerfile` if none.
    pub containerfile: Option<PathBuf>,
    /// A Containerfile that is not in the context (`-f` outside of it):
    /// its text, never one of the files COPY sees.
    pub containerfile_text: Option<String>,
    /// The ignore file a client added with that Containerfile
    /// (`<name>.dockerignore`, taken out with it): the one it applied.
    ignore_text: Option<String>,
}

const IN_ROOT: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS);

impl BuildContext {
    /// The directory `dir` of the engine's host, opened now.
    pub fn new(dir: &Path, containerfile: Option<&Path>) -> BuildResult<Self> {
        let root = open_path_dir(dir).map_err(|_| {
            BuildError::Parse(format!(
                "the build context {} is not a directory",
                redact::urls(&dir.display().to_string())
            ))
        })?;
        Ok(Self {
            root: Arc::new(root),
            path: Some(dir.to_path_buf()),
            containerfile: containerfile.map(Path::to_path_buf),
            containerfile_text: None,
            ignore_text: None,
        })
    }

    /// The directory the descriptor `dir` is, which a client opened and
    /// sent.
    pub fn from_fd(dir: OwnedFd, containerfile: Option<&Path>) -> BuildResult<Self> {
        let root = rustix::fs::openat(
            &dir,
            ".",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BuildError::Parse("the build context is not a directory".into()))?;
        Ok(Self {
            root: Arc::new(root),
            path: None,
            containerfile: containerfile.map(Path::to_path_buf),
            containerfile_text: None,
            ignore_text: None,
        })
    }

    /// A descriptor of the directory of the context for a job or a mount.
    fn fd(&self) -> std::io::Result<OwnedFd> {
        self.root.try_clone()
    }

    /// Read a file of the context, links resolved in it.
    fn read(&self, name: &Path, max: u64) -> std::io::Result<Option<String>> {
        let fd = match velarx_sys::fs::open_in_root(self.root.as_fd(), name, ResolveFlags::empty())
        {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let st = rustix::fs::fstat(&fd)?;
        if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
            return Err(std::io::Error::other(format!(
                "`{}` is not a file",
                name.display()
            )));
        }
        if st.st_size as u64 > max {
            return Err(std::io::Error::other(format!(
                "`{}` is too large",
                name.display()
            )));
        }
        let mut s = String::new();
        std::fs::File::from(fd).take(max).read_to_string(&mut s)?;
        Ok(Some(s))
    }

    /// The Containerfile is a file a client added to the context: read it
    /// and remove it, COPY does not see it.
    pub fn take_containerfile(mut self) -> BuildResult<Self> {
        let name = self
            .containerfile
            .clone()
            .ok_or_else(|| BuildError::Parse("no Containerfile was named".into()))?;
        // A name at the top of the context: nothing on the way to follow.
        if name.components().count() != 1
            || !matches!(
                name.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(BuildError::Parse(format!(
                "the added Containerfile `{}` is not at the top of the context",
                name.display()
            )));
        }
        let text = self.containerfile()?;
        let root = &self.root;
        rustix::fs::unlinkat(root, &name, rustix::fs::AtFlags::empty())
            .map_err(std::io::Error::from)?;
        self.containerfile_text = Some(text);
        // (the ignore file the client applied, when it is not the one the
        // context has: `--ignorefile`, that of a Containerfile outside)
        let mut companion = name.into_os_string();
        companion.push(".dockerignore");
        let companion = PathBuf::from(companion);
        if let Some(text) = self.read(&companion, parse::MAX_FILE)? {
            rustix::fs::unlinkat(root, &companion, rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
            self.ignore_text = Some(text);
        }
        Ok(self)
    }

    /// `--ignorefile`: the file `name` of the context is the ignore file,
    /// the context's own are not read.
    pub fn with_ignore_file(mut self, name: &Path) -> BuildResult<Self> {
        let text = self.read(name, parse::MAX_FILE)?.ok_or_else(|| {
            BuildError::Parse(format!(
                "the ignore file {} is not in the context",
                name.display()
            ))
        })?;
        self.ignore_text = Some(text);
        Ok(self)
    }

    fn containerfile(&self) -> BuildResult<String> {
        if let Some(text) = &self.containerfile_text {
            return Ok(text.clone());
        }
        let names: Vec<PathBuf> = match &self.containerfile {
            Some(p) => vec![p.clone()],
            None => vec!["Containerfile".into(), "Dockerfile".into()],
        };
        for n in &names {
            if let Some(s) = self.read(n, parse::MAX_FILE)? {
                return Ok(s);
            }
        }
        Err(BuildError::Parse(format!(
            "no Containerfile or Dockerfile in the build context ({})",
            names
                .iter()
                .map(|n| n.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    /// The ignore file the client added, else that of the Containerfile
    /// (`<file>.dockerignore` before `<file>.containerignore`), else the
    /// context's, as buildah's.
    fn ignore(&self) -> BuildResult<Ignore> {
        if let Some(text) = &self.ignore_text {
            return Ok(Ignore::parse(text));
        }
        // (with no name, the Containerfile is the first of the two the
        // context has: the other one's ignore file is not its)
        let file: Option<String> = match &self.containerfile {
            Some(p) => Some(p.display().to_string()),
            // (one of a URL: no file of the context)
            None if self.containerfile_text.is_some() => None,
            None => {
                let mut found = None;
                for n in ["Containerfile", "Dockerfile"] {
                    if self.read(Path::new(n), parse::MAX_FILE)?.is_some() {
                        found = Some(n.to_string());
                        break;
                    }
                }
                found
            }
        };
        let names: Vec<String> = file
            .iter()
            .flat_map(|f| [format!("{f}.dockerignore"), format!("{f}.containerignore")])
            .chain([".containerignore".to_string(), ".dockerignore".to_string()])
            .collect();
        for n in &names {
            if let Some(s) = self.read(Path::new(n), parse::MAX_FILE)? {
                return Ok(Ignore::parse(&s));
            }
        }
        Ok(Ignore::default())
    }
}

/// Where a build gets the credentials of the registries it reaches, one
/// request for the endpoints of each reference it pulls: the client keeps
/// its auth file and gives only these entries.
#[async_trait::async_trait]
pub trait CredentialSource: std::fmt::Debug + Send + Sync {
    /// The entries for `scopes` (`registry` or `registry/repository`).
    async fn credentials(
        &self,
        scopes: &[String],
    ) -> Result<std::collections::BTreeMap<String, velarx_registry::Credentials>, String>;
}

/// `access` with what `source` has for the endpoints of `reference`.
async fn access_for(
    images: &ImageService,
    access: &velarx_registry::auth::RegistryAccess,
    source: Option<&Arc<dyn CredentialSource>>,
    reference: &str,
    push: bool,
) -> BuildResult<velarx_registry::auth::RegistryAccess> {
    let mut access = access.clone();
    let Some(source) = source else {
        return Ok(access);
    };
    let scopes = images.reference_credential_scopes(reference, push)?;
    if scopes.is_empty() {
        return Ok(access);
    }
    let asked = source
        .credentials(&scopes)
        .await
        .map_err(|e| BuildError::Parse(format!("credentials for {reference}: {e}")))?;
    access.auths.extend(only_asked(&scopes, asked));
    Ok(access)
}

/// The stage `name` (or index) among the first `before` of `stages`.
fn stage_before(stages: &[velarx_wire::parse::Stage], name: &str, before: usize) -> Option<usize> {
    stages[..before]
        .iter()
        .position(|s| {
            s.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
        .or_else(|| name.parse::<usize>().ok().filter(|i| *i < before))
}

/// What a client answered for `scopes`, and nothing else: one that sends
/// more does not widen what the build takes.
fn only_asked(
    scopes: &[String],
    answer: std::collections::BTreeMap<String, velarx_registry::Credentials>,
) -> impl Iterator<Item = (String, velarx_registry::Credentials)> + '_ {
    answer.into_iter().filter(|(key, _)| {
        scopes
            .iter()
            .any(|s| velarx_registry::auth::normalize_auth_key(s) == *key)
    })
}

/// How to build.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub tags: Vec<String>,
    pub build_args: HashMap<String, String>,
    pub labels: HashMap<String, String>,
    /// Do not take images from the build cache.
    pub no_cache: bool,
    /// Keep the intermediate images and record them in the build cache.
    pub layers: bool,
    pub target: Option<String>,
    /// `os/arch[/variant]`, several separated by commas: a build for each.
    pub platform: Option<String>,
    /// The manifest list the images are added to (created if missing): the
    /// build gives its id.
    pub manifest: Option<String>,
    /// A build for each platform all the base images have (their registries
    /// say), instead of `platform`.
    pub all_platforms: bool,
    /// The named contexts of `--build-context` (COPY --from=NAME, FROM NAME).
    pub contexts: HashMap<String, NamedContext>,
    pub squash: bool,
    /// `--squash-all`: the final image has one layer, the merged tree of
    /// all its layers, the base image's too.
    pub squash_all: bool,
    /// The network of the RUN containers.
    pub network: Option<String>,
    /// The entitlements the request allows (`build --allow`).
    pub allow: entitlement::Allow,
    /// `--digest`: `sha256` or `sha512`, the algorithm of every digest of
    /// the built image (the layers, the configuration, the manifest); none:
    /// `[build] digest`.
    pub digest: Option<String>,
    pub tls_verify: bool,
    /// What the RUN containers take from the command line.
    pub run: velarx_wire::request::BuildRun,
    /// `--env`: variables of the final image.
    pub env: Vec<(String, String)>,
    /// `--unsetenv`: variables the final image does not have.
    pub unset_env: Vec<String>,
    /// `--unsetlabel`: labels of the base image the final image does not have.
    pub unset_labels: Vec<String>,
    /// When the base images are pulled.
    pub pull: PullPolicy,
    /// Credentials and certificates for every registry the build pulls
    /// from (podman applies `--creds` to all of them too).
    pub access: velarx_registry::auth::RegistryAccess,
    /// The credentials of the auth file of the client, asked for each
    /// reference the build pulls.
    pub credentials: Option<Arc<dyn CredentialSource>>,
    /// `--secret`: the values of the secrets of `RUN --mount=type=secret`,
    /// by id.
    pub secrets: HashMap<String, SecretValue>,
    /// `--ssh`: the agents of the client for `RUN --mount=type=ssh`.
    pub agents: Option<Arc<dyn AgentSource>>,
    /// `--stdin`: the standard input of the client, which the RUN steps
    /// read (none: they read nothing).
    pub stdin: Option<Arc<std::os::fd::OwnedFd>>,
    /// `--from`, `--retry`, the times, `--omit-history`,
    /// `--inherit-labels`, `--skip-unused-stages`, `--cache-ttl`.
    pub flags: velarx_wire::buildopts::BuildFlags,
}

/// The value of a build secret: never printed, never in a key or a layer.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretValue(pub Vec<u8>);

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The largest value of a build secret (BuildKit's limit).
pub const MAX_BUILD_SECRET: usize = 500 * 1024;

/// The ssh agents of a build's client: each connection of a RUN step to
/// one is a new connection of the client to its agent.
#[async_trait::async_trait]
pub trait AgentSource: std::fmt::Debug + Send + Sync {
    /// The ids of the agents (`--ssh ID`).
    fn ids(&self) -> Vec<String>;
    /// A new connection to the agent `id`.
    async fn connect(&self, id: &str) -> std::io::Result<OwnedFd>;
}

/// A named context of a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamedContext {
    /// A directory of the daemon's host.
    Dir(PathBuf),
    /// An image (`docker-image://` or podman's `image:`).
    Image(String),
}

/// When a build pulls its base images.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PullPolicy {
    /// When the store does not have them.
    #[default]
    Missing,
    /// Every time.
    Always,
    /// When the registry serves another image than the store has (the one
    /// of the store when it cannot be asked).
    Newer,
    /// Never: they must be in the store.
    Never,
}

impl PullPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "missing" | "ifmissing" | "notpresent" => Some(Self::Missing),
            "always" | "true" => Some(Self::Always),
            "newer" | "ifnewer" => Some(Self::Newer),
            "never" | "false" => Some(Self::Never),
            _ => None,
        }
    }
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            tags: Vec::new(),
            build_args: HashMap::new(),
            labels: HashMap::new(),
            no_cache: false,
            layers: true,
            target: None,
            platform: None,
            manifest: None,
            all_platforms: false,
            contexts: HashMap::new(),
            squash: false,
            squash_all: false,
            network: None,
            allow: Default::default(),
            digest: None,
            tls_verify: true,
            run: Default::default(),
            env: Vec::new(),
            unset_env: Vec::new(),
            unset_labels: Vec::new(),
            pull: PullPolicy::Missing,
            access: Default::default(),
            credentials: None,
            secrets: HashMap::new(),
            agents: None,
            stdin: None,
            flags: Default::default(),
        }
    }
}

/// The limits of the builds.
#[derive(Debug, Clone)]
pub struct BuildSettings {
    /// What one COPY, ADD or context extraction may write.
    pub limits: copy::Limits,
    /// A copy worker that runs longer is killed.
    pub worker_timeout: std::time::Duration,
    /// Builds that run at the same time.
    pub max_concurrent: usize,
    /// Builds that run or wait at the same time: each holds its context
    /// and its connection until it ends.
    pub max_pending: usize,
    /// Bytes of scratch space of all the builds together.
    pub max_scratch: u64,
    /// The entitlements builds may be allowed (`[build]
    /// insecure_entitlements`).
    pub entitlements: Vec<velarx_base::entitlement::Entitlement>,
}

impl Default for BuildSettings {
    fn default() -> Self {
        Self {
            limits: copy::Limits::default(),
            worker_timeout: std::time::Duration::from_secs(3600),
            max_concurrent: 4,
            max_pending: 16,
            max_scratch: 100 << 30,
            entitlements: Vec::new(),
        }
    }
}

fn admit_to(pending: &Arc<std::sync::atomic::AtomicUsize>, max: usize) -> Option<Admission> {
    use std::sync::atomic::Ordering::SeqCst;
    pending
        .try_update(SeqCst, SeqCst, |n| (n < max).then_some(n + 1))
        .ok()?;
    Some(Admission(pending.clone()))
}

/// The end of the thread that archives sources of an image: its error after
/// the item list was sent.
struct ArchiveEnd(std::sync::mpsc::Receiver<std::io::Result<Vec<Item>>>);

impl ArchiveEnd {
    /// Fails the step when the archive stopped on an error: the worker saw
    /// a tar that ended cleanly, without the sources that were left.  (A
    /// write the closed pipe refused is not one: the worker stops reading
    /// at the end of the tar, before the rest of its end block.)
    fn check(self, i: &Instr) -> BuildResult<()> {
        match self.0.recv() {
            Ok(Err(e)) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(step_error(i, e)),
            _ => Ok(()),
        }
    }
}

/// The options of a layer of files put on `tree`: it has the root of the
/// tree when that is not a plain one, as a layer without one would give
/// the image a plain root.
fn files_onto(tree: &MergedTree) -> dirtar::Options {
    dirtar::Options {
        root: dirtar::Root::Changed,
        below: tree
            .node(velarx_fuse::ROOT)
            .map(|n| Arc::new(n.entry.clone())),
        ..Default::default()
    }
}

/// Where the sources taken from an image go, and what they are given.
struct ImageDest<'a> {
    dst: &'a str,
    dest_dir: bool,
    chown: Option<(u32, u32)>,
    chmod: Option<u32>,
    /// `COPY --parents`
    parents: bool,
    /// `--exclude`
    excludes: &'a [String],
}

/// A place among the builds that run or wait ([`BuildService::admit`]).
#[derive(Debug)]
pub struct Admission(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The scratch space of the builds: what is reserved of it.
#[derive(Debug, Clone)]
pub struct Scratch {
    used: Arc<std::sync::atomic::AtomicU64>,
    max: u64,
}

/// Bytes of scratch space held until dropped.
#[derive(Debug)]
pub struct Reservation {
    scratch: Scratch,
    amount: u64,
}

fn scratch_full() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::StorageFull,
        "the scratch space of the builds is exhausted ([build] max_scratch_gib)",
    )
}

impl Scratch {
    pub fn new(max: u64) -> Self {
        Self {
            used: Default::default(),
            max,
        }
    }

    /// Nothing reserved yet.
    pub fn reservation(&self) -> Reservation {
        Reservation {
            scratch: self.clone(),
            amount: 0,
        }
    }

    fn available(&self) -> u64 {
        self.max
            .saturating_sub(self.used.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl Reservation {
    /// Hold `n` bytes more.
    pub fn grow(&mut self, n: u64) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        let used = &self.scratch.used;
        let mut cur = used.load(Ordering::Relaxed);
        loop {
            let new = cur.checked_add(n).filter(|v| *v <= self.scratch.max);
            let Some(new) = new else {
                return Err(scratch_full());
            };
            match used.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        self.amount += n;
        Ok(())
    }

    /// Hold `n` bytes: more (if there is room) or less.
    pub fn set(&mut self, n: u64) -> std::io::Result<()> {
        if n >= self.amount {
            return self.grow(n - self.amount);
        }
        self.scratch
            .used
            .fetch_sub(self.amount - n, std::sync::atomic::Ordering::AcqRel);
        self.amount = n;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.scratch
            .used
            .fetch_sub(self.amount, std::sync::atomic::Ordering::AcqRel);
    }
}

/// The time from which a copy notices a change of a file of a context
/// (`CopyJob::unchanged_since`), taken before the digest of what it copies:
/// now, less two seconds for the file systems whose times are coarser than
/// the clock (a file changed just before is taken as changed, which only
/// keys its step by what was copied).
pub(crate) fn change_horizon() -> (i64, i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (now.as_secs() as i64 - 2, i64::from(now.subsec_nanos()))
}

/// The space the files below `dir` take, nothing followed.
fn disk_usage(dir: &Path) -> std::io::Result<u64> {
    let u = velarx_base::tree::usage(dir, &velarx_base::tree::Measure::default())?;
    Ok(u.blocks.saturating_mul(512))
}

/// The network of the RUN containers: any mode of `run --network` that
/// does not name another container, a pod or a provider: the build has
/// none.
fn build_network(mode: Option<&str>) -> BuildResult<Option<NetworkMode>> {
    match NetworkMode::parse(mode.unwrap_or("")) {
        NetworkMode::Unset | NetworkMode::Default | NetworkMode::Private => Ok(None),
        NetworkMode::Pod | NetworkMode::Container(_) | NetworkMode::Provider(_) => {
            Err(BuildError::Parse(format!(
                "unsupported network `{}` for a build",
                mode.unwrap_or("")
            )))
        }
        m => Ok(Some(m)),
    }
}

/// Whether the process `pid` exists (a process of another user too).
fn process_alive(pid: i32) -> bool {
    // 0 and below would name a process group.
    if pid <= 0 {
        return false;
    }
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return false;
    };
    match rustix::process::test_kill_process(pid) {
        Ok(()) => true,
        Err(e) => e == rustix::io::Errno::PERM,
    }
}

/// Create `dir` and its parents for this user only.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// A directory of a context sent by a client and the scratch space it
/// holds.
pub struct ContextDir {
    dir: tempfile::TempDir,
    pub reservation: Reservation,
}

impl ContextDir {
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// Builds images.
pub struct BuildService {
    image_service: Arc<ImageService>,
    container_service: Arc<ContainerService>,
    work_dir: PathBuf,
    runner: Runner,
    limits: copy::Limits,
    builds: tokio::sync::Semaphore,
    /// The builds that run or wait, and the most there may be.
    pending: Arc<std::sync::atomic::AtomicUsize>,
    max_pending: usize,
    /// The entitlements the configuration enables.
    entitlements: Vec<velarx_base::entitlement::Entitlement>,
    scratch: Scratch,
    /// The downloads of ADD.
    fetcher: velarx_content::pull::net::origin::OriginUrls,
    /// The directories of RUN --mount=type=cache, which stay between
    /// builds: next to `work_dir`.
    cache_dir: PathBuf,
    /// The containers of the RUN steps that run (their ids are chosen
    /// before they are made): [`BuildService::prune_containers`] leaves
    /// them.
    steps: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Asks every build to stop: the engine ends ([`BuildService::stop_all`]).
    stopping: tokio::sync::watch::Sender<bool>,
    /// The builds that run (or wait for their turn).
    running: tokio::sync::watch::Sender<usize>,
}

/// One of the builds [`BuildService::stop_all`] waits for.
struct Running<'a>(&'a tokio::sync::watch::Sender<usize>);

impl<'a> Running<'a> {
    fn new(count: &'a tokio::sync::watch::Sender<usize>) -> Self {
        count.send_modify(|n| *n += 1);
        Self(count)
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n -= 1);
    }
}

/// The annotation of the time of the built image.
const CREATED_ANNOTATION: &str = "org.opencontainers.image.created";
/// The annotation that names the base of the built image.
const BASE_NAME_ANNOTATION: &str = "org.opencontainers.image.base.name";

/// The name of the base `from` (the image `id`) in the annotations of the
/// built image: fully qualified, none when FROM gives its id (buildah
/// leaves the name out for a reference that is not qualified).
fn base_name(from: &str, id: &str) -> Option<String> {
    if from.len() >= 3 && id.starts_with(from) && from.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let Ok(r) = velarx_types::ImageReference::parse(from) else {
        return Some(from.to_string());
    };
    let name = format!("{}/{}", r.registry, r.repository);
    Some(match (&r.digest, &r.tag) {
        (Some(d), _) => format!("{name}@{d}"),
        (None, Some(t)) => format!("{name}:{t}"),
        (None, None) => name,
    })
}

/// The label of the containers a build makes (its RUN steps, the export
/// of `--output`): the pid of the process that makes them.
pub const BUILD_LABEL: &str = "io.velarx.build";

/// The name of the image of the step `key` on `parent` in the repository
/// of `--cache-from` and `--cache-to`: the tag is made of both.
fn cache_reference(repository: &str, parent: &str, key: &str) -> BuildResult<String> {
    let repository =
        velarx_types::transport::ImageLocation::local(repository, "a cache repository")
            .map_err(|e| BuildError::Parse(e.to_string()))?;
    let id = Digest::of(Algorithm::Sha256, format!("{parent}\n{key}").as_bytes()).to_string();
    Ok(format!(
        "{}:{}",
        repository,
        velarx_types::digest::without_algorithm(&id)
    ))
}

/// The label of the images a build makes that names the builder.
const IDENTITY_LABEL: &str = "io.velarx.version";

/// Where the build is: the steps, the images.
struct Build<'a> {
    svc: &'a BuildService,
    ctx: &'a BuildContext,
    opts: &'a BuildOptions,
    out: Option<mpsc::Sender<BuildProgress>>,
    cancel: Cancel,
    file: Containerfile,
    ignore: Ignore,
    /// The algorithm of the digests of everything the build makes.
    digest: Algorithm,
    global_args: Vec<(String, Option<String>)>,
    stage_images: Vec<Option<String>>,
    /// The bases of the stages built, for a stage FROM one of them.
    stage_bases: Vec<BaseOf>,
    intermediates: Vec<String>,
    /// The intermediate images recorded in the build cache: they stay.
    cached: std::collections::HashSet<String>,
    step: usize,
    work: tempfile::TempDir,
    seq: usize,
    /// Keeps the intermediate images from a prune until the build ends.
    hold: Option<velarx_content::pull::holds::Hold>,
    /// The name of the hold (the stages that run at the same time use it).
    hold_name: Option<String>,
    /// The scratch space of the --squash directory.
    squash_space: Reservation,
    /// The platform the build is for, if one was asked.
    platform: Option<velarx_registry::target::Platform>,
    /// The secrets and agent sockets of the RUN steps, in the state
    /// directory (a tmpfs).
    run_dir: Option<tempfile::TempDir>,
    /// The stage of the built image.
    target: usize,
    /// `--source-policy-file`.
    policy: Option<Arc<policy::SourcePolicy>>,
}

/// What a stage that was built next to others leaves to the build.
struct Left {
    base: BaseOf,
    intermediates: Vec<String>,
    cached: std::collections::HashSet<String>,
}

/// The base of a stage, as the annotations of the built image have it.
#[derive(Clone, Debug, Default)]
struct BaseOf {
    /// Its fully qualified name (empty for scratch; none for an image
    /// FROM names by its id, as buildah's for a short name).
    name: Option<String>,
    /// The digest of its manifest (empty for scratch).
    digest: String,
    /// Its annotations, its `os.features`.
    annotations: std::collections::BTreeMap<String, String>,
    os_features: Vec<String>,
    /// The arguments the stage declared: a stage FROM it has them, as
    /// buildah's (none for an image).
    args: Vec<(String, Option<String>)>,
}

/// The state of the stage being built.
struct StageState {
    index: usize,
    image: Option<String>,
    base_image: Option<String>,
    /// All the configuration changes of the stage (for `--squash`); those
    /// from `committed` on are not committed yet.
    edits: Vec<ConfigEdit>,
    committed: usize,
    author: Option<String>,
    env: Vec<(String, String)>,
    args: Vec<(String, Option<String>)>,
    shell: Vec<String>,
    workdir: String,
    user: String,
    cmd_set: bool,
    onbuild: Vec<Value>,
    squash_dir: Option<PathBuf>,
    base: BaseOf,
    /// The step being built makes the image the build names (the last one
    /// of the target stage, given a name): it is not an intermediate image.
    named: bool,
    /// The next commit (or image of the build cache) is the image of the
    /// build: buildah's `COMMIT name` comes before it.
    last_commit: bool,
    /// The `--layer-label` labels the current image has that are not labels
    /// of the stage (an intermediate image has those it has no value for).
    layer_added: Vec<String>,
}

/// The value of an argument among `vars`: none when it is not declared or has
/// no value.
fn lookup(vars: &[(String, Option<String>)]) -> impl Fn(&str) -> Option<String> + '_ {
    move |name| {
        vars.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| v.clone())
    }
}

fn set_kv<V>(list: &mut Vec<(String, V)>, key: &str, value: V) {
    match list.iter_mut().find(|(k, _)| k == key) {
        Some(e) => e.1 = value,
        None => list.push((key.to_string(), value)),
    }
}

impl StageState {
    fn lookup(&self, name: &str) -> Option<String> {
        self.env
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .or_else(|| {
                self.args
                    .iter()
                    .find(|(k, _)| k == name)
                    .and_then(|(_, v)| v.clone())
            })
    }

    fn edit(&mut self, e: ConfigEdit) {
        self.edits.push(e);
    }

    /// The changes not committed yet.
    fn pending(&self) -> &[ConfigEdit] {
        &self.edits[self.committed..]
    }

    /// The command of RUN, CMD and ENTRYPOINT.
    fn argv(&self, i: &Instr) -> Vec<String> {
        match &i.json {
            Some(v) => v.clone(),
            None => {
                let mut v = self.shell.clone();
                v.push(i.args.clone());
                v
            }
        }
    }
}

/// The `created_by` of the history entry of a step, as buildah writes it:
/// `/bin/sh -c COMMAND` for RUN, `/bin/sh -c #(nop) INSTRUCTION` for the
/// others; without the values of the build arguments, which would be
/// published with the image, and the digest of what a COPY copied.
fn created_by(i: &Instr) -> String {
    let text = i.text();
    match text.strip_prefix("RUN ") {
        Some(command) => format!("/bin/sh -c {command}"),
        None => format!("/bin/sh -c #(nop) {text}"),
    }
}

fn step_error(i: &Instr, e: impl std::fmt::Display) -> BuildError {
    // as podman's
    BuildError::StepFailed(redact::urls(&format!(
        "building at STEP \"{}\": {e}",
        i.text()
    )))
}

/// A duration flag of HEALTHCHECK in nanoseconds: a Go duration, and an
/// empty value is 0 (not set), as buildah and Docker read `--interval=`.
fn health_duration_ns(v: &str) -> Option<i64> {
    if v.is_empty() {
        return Some(0);
    }
    velarx_proto::duration::parse_go_duration_ns(v)
}

impl BuildService {
    /// `work_dir`: where the contexts and the layers of the steps are
    /// written (on the disk of the store, not a tmpfs); `worker`: the binary
    /// that runs the copies confined (this one again in the daemon), none
    /// runs them in this process.
    ///
    /// Each process has a directory of its own below `work_dir` (the API
    /// server and the engines of systemd units share the store); what the
    /// processes that are gone left there is removed: contexts can hold
    /// secrets and set-id files.
    pub fn new(
        image_service: Arc<ImageService>,
        container_service: Arc<ContainerService>,
        work_dir: PathBuf,
        worker: Option<PathBuf>,
        settings: BuildSettings,
    ) -> std::io::Result<Self> {
        private_dir(&work_dir)?;
        let mine = std::process::id();
        for e in std::fs::read_dir(&work_dir)? {
            let e = e?;
            let owner = e
                .file_name()
                .to_str()
                .and_then(|n| n.strip_prefix('p'))
                .and_then(|p| p.parse::<i32>().ok());
            // A directory of a live process is in use; anything else is a
            // leftover.
            if owner.is_some_and(|p| p as u32 != mine && process_alive(p)) {
                continue;
            }
            let path = e.path();
            let removed = match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => velarx_base::tree::remove_dir_all_confined(&path),
                Ok(_) => std::fs::remove_file(&path),
                Err(e) => Err(e),
            };
            // (another process that starts, or the one that ends, removes it
            // at the same time)
            if let Err(e) = removed.or_else(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(e),
            }) {
                warn!("Cannot remove {}: {e}", path.display());
            }
        }
        let cache_dir = work_dir.with_file_name("build-cache");
        let work_dir = work_dir.join(format!("p{mine}"));
        private_dir(&work_dir)?;
        // (the downloads of the builds are the registry fetcher's)
        let fetcher = image_service
            .url_fetcher()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self {
            cache_dir,
            steps: Default::default(),
            image_service,
            container_service,
            work_dir,
            fetcher,
            runner: Runner {
                exe: worker,
                timeout: settings.worker_timeout,
            },
            limits: settings.limits,
            builds: tokio::sync::Semaphore::new(settings.max_concurrent.max(1)),
            pending: Arc::default(),
            max_pending: settings.max_pending.max(settings.max_concurrent).max(1),
            scratch: Scratch::new(settings.max_scratch),
            entitlements: settings.entitlements,
            stopping: tokio::sync::watch::channel(false).0,
            running: tokio::sync::watch::channel(0).0,
        })
    }

    /// Stop every build, as one asked to stop is (its RUN container killed,
    /// its containers and intermediate images removed), and wait up to
    /// `limit` for them to end: how many did not.  The builds that come
    /// later stop at once.
    pub async fn stop_all(&self, limit: std::time::Duration) -> usize {
        self.stopping.send_replace(true);
        let mut running = self.running.subscribe();
        let _ = tokio::time::timeout(limit, running.wait_for(|n| *n == 0)).await;
        let left = *running.borrow();
        left
    }

    /// Whether the build may have `needs` (`entitlement::check`).
    fn require(
        &self,
        allow: &entitlement::Allow,
        needs: &[(velarx_base::entitlement::Entitlement, String)],
    ) -> BuildResult<()> {
        entitlement::check(&self.entitlements, allow, needs).map_err(BuildError::Parse)
    }

    /// Room for one more build, taken before its context is read and kept
    /// until it ends; `None` when as many run or wait as the limit says.
    pub fn admit(&self) -> Option<Admission> {
        admit_to(&self.pending, self.max_pending)
    }

    /// The limits of a job that may use what is left of `reservation`'s
    /// scratch space: the space is reserved.
    fn job_limits(&self, reservation: &mut Reservation) -> std::io::Result<copy::Limits> {
        let room = self.limits.max_bytes.min(self.scratch.available());
        if room == 0 {
            return Err(scratch_full());
        }
        reservation.grow(room)?;
        Ok(copy::Limits {
            max_bytes: room,
            ..self.limits
        })
    }

    /// Extract the context a client sent (a tar, maybe compressed) into the
    /// empty directory `dir`, in a worker.
    pub async fn unpack_context(
        &self,
        archive: std::fs::File,
        ctx: &mut ContextDir,
        dir: &Path,
    ) -> BuildResult<()> {
        let job = CopyJob {
            limits: self.job_limits(&mut ctx.reservation)?,
            ..CopyJob::new(Source::Unpack)
        };
        let r = self
            .runner
            .run(
                job,
                dir,
                JobSource::Stream(OwnedFd::from(archive)),
                &Cancel::default(),
            )
            .await
            .map(drop)
            .map_err(|e| BuildError::Parse(format!("invalid build context: {e}")));
        // The archive is gone (unlinked, closed): what is left is the
        // extracted context.
        ctx.reservation.set(disk_usage(dir)?)?;
        r
    }

    /// Clone the git repository `source` into the empty directory `dir`
    /// (a remote context), in the confined helper; the subdirectory it
    /// names is the context, its components no links.
    pub async fn clone_context(&self, source: &git::GitSource, dir: &Path) -> BuildResult<PathBuf> {
        let exe = self.runner.exe.clone().ok_or_else(|| {
            BuildError::Parse("a git context needs the confined helper of the daemon".into())
        })?;
        let (g, d, limits, timeout) = (
            source.clone(),
            dir.to_path_buf(),
            self.limits,
            self.runner.timeout,
        );
        helper::stoppable(&Cancel::default(), move |stop| {
            git::clone(&exe, &g, &d, &limits, timeout, stop)
        })
        .await
        .map_err(|e| BuildError::StepFailed(e.to_string()))?;
        remote::subdir(dir, &source.subdir)
    }

    /// Remove the directories of RUN --mount=type=cache no step uses: the
    /// bytes they took.
    pub fn prune_cache_mounts(&self) -> std::io::Result<u64> {
        prune_cache_mounts(&self.cache_dir)
    }

    /// Remove the containers of builds that are gone (`system prune
    /// --build`): those of a process that ended (a build killed with its
    /// engine or its command), and this process's own that no step runs.
    pub async fn prune_containers(&self) -> BuildResult<Vec<String>> {
        let me = std::process::id() as i32;
        let mut removed = Vec::new();
        for c in self.container_service.list(true).await? {
            let Ok(cfg) = serde_json::from_str::<crate::container::ContainerConfig>(&c.config)
            else {
                continue;
            };
            let Some(owner) = cfg.labels.get(BUILD_LABEL) else {
                continue;
            };
            let pid = owner.parse::<i32>().unwrap_or(0);
            let used = if pid == me {
                self.step_running(&c.id)
            } else {
                process_alive(pid)
            };
            if used {
                continue;
            }
            match self.container_service.delete(&c.id, true).await {
                Ok(()) => removed.push(c.id),
                Err(e) => warn!("Cannot remove the build container {}: {e}", c.id),
            }
        }
        Ok(removed)
    }

    fn steps(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.steps.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn step_running(&self, id: &str) -> bool {
        self.steps().contains(id)
    }

    /// A directory for a context a client sends (this user's only).
    pub fn context_dir(&self) -> std::io::Result<ContextDir> {
        let dir = self.work_dir.join("contexts");
        private_dir(&dir)?;
        Ok(ContextDir {
            dir: tempfile::Builder::new()
                .prefix("context-")
                .tempdir_in(&dir)?,
            reservation: self.scratch.reservation(),
        })
    }

    /// Build the image, an image for each platform of `opts.platform`, and
    /// add them to the list `opts.manifest`: the id of the image (of the
    /// first one), or of the list.
    pub async fn build(
        &self,
        ctx: &BuildContext,
        opts: &BuildOptions,
        out: Option<mpsc::Sender<BuildProgress>>,
        cancel: Cancel,
    ) -> BuildResult<String> {
        let _running = Running::new(&self.running);
        let cancel = cancel.or(&Cancel::on(self.stopping.subscribe()));
        if cancel.asked() {
            return Err(BuildError::Cancelled);
        }
        let mut platforms = Vec::new();
        for p in opts
            .platform
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            let platform =
                velarx_registry::target::Platform::parse(p).map_err(BuildError::Parse)?;
            if !platforms.contains(&platform) {
                platforms.push(platform);
            }
        }
        if opts.all_platforms {
            platforms = self.platforms_of_bases(ctx, opts).await?;
            let shown: Vec<String> = platforms.iter().map(ToString::to_string).collect();
            if let Some(tx) = &out {
                let _ = tx
                    .send(BuildProgress::StepOutput {
                        step: 0,
                        output: format!("Building for {}\n", shown.join(", ")),
                    })
                    .await;
            }
        }
        let manifest = opts.manifest.as_deref().filter(|m| !m.is_empty());
        if let Some(m) = manifest {
            // A name of an image is not taken from it.
            if self.image_service.manifest_lookup(m).await?.is_none()
                && self.image_service.get(m).await.is_ok()
            {
                return Err(BuildError::Parse(format!(
                    "{m} is an image, not a manifest list"
                )));
            }
        }
        if platforms.len() <= 1 && manifest.is_none() {
            return self.build_one(ctx, opts, out, true, cancel).await;
        }
        let mut built = Vec::new();
        for platform in &platforms {
            let one = BuildOptions {
                platform: Some(platform.to_string()),
                ..opts.clone()
            };
            if let Some(tx) = &out {
                let _ = tx
                    .send(BuildProgress::Platform {
                        platform: platform.to_string(),
                    })
                    .await;
            }
            let id = self
                .build_one(ctx, &one, out.clone(), false, cancel.clone())
                .await?;
            if let Some(tx) = &out {
                let _ = tx
                    .send(BuildProgress::StepOutput {
                        step: 0,
                        output: format!("{id}\n"),
                    })
                    .await;
            }
            built.push((id, Some(platform)));
        }
        if platforms.is_empty() {
            built.push((
                self.build_one(ctx, opts, out.clone(), false, cancel.clone())
                    .await?,
                None,
            ));
        }
        let Some(name) = manifest else {
            let id = built.swap_remove(0).0;
            if let Some(tx) = &out {
                let _ = tx
                    .send(BuildProgress::Completed {
                        image_id: id.clone(),
                    })
                    .await;
            }
            return Ok(id);
        };
        let svc = &self.image_service;
        let list = match svc.manifest_lookup(name).await? {
            Some(list) => list.id,
            None => {
                svc.manifest_create(
                    name,
                    &[],
                    &crate::services::AddOptions::default(),
                    &Default::default(),
                    true,
                    Some(svc.creation_algorithm(opts.digest.as_deref())?.name()),
                )
                .await?
            }
        };
        for (id, platform) in built {
            let add = crate::services::AddOptions {
                instance: crate::services::InstanceOptions {
                    os: platform.map(|p| p.os.clone()),
                    arch: platform.map(|p| p.arch.clone()),
                    variant: platform.and_then(|p| p.variant.clone()),
                    ..Default::default()
                },
                ..Default::default()
            };
            svc.manifest_add(&list, &[format!("containers-storage:{id}")], &add)
                .await?;
        }
        if let Some(tx) = &out {
            let _ = tx
                .send(BuildProgress::StepOutput {
                    step: 0,
                    output: format!("--> added to the manifest list {name}\n"),
                })
                .await;
            let _ = tx
                .send(BuildProgress::Completed {
                    image_id: list.clone(),
                })
                .await;
        }
        Ok(list)
    }

    /// The platforms every base image of the Containerfile has, from the
    /// indexes their registries serve (buildah's --all-platforms): an
    /// error if a base is not an index or they have none in common.
    async fn platforms_of_bases(
        &self,
        ctx: &BuildContext,
        opts: &BuildOptions,
    ) -> BuildResult<Vec<velarx_registry::target::Platform>> {
        let file = Containerfile::parse(&ctx.containerfile()?).map_err(BuildError::Parse)?;
        let bases = base_images(&file, &opts.build_args, None, opts.flags.from.as_deref())?;
        if bases.is_empty() {
            return Err(BuildError::Parse(
                "--all-platforms: the build uses no base image but scratch".into(),
            ));
        }
        let policy = source_policy(opts)?;
        let mut common: Option<Vec<String>> = None;
        for base in &bases {
            // FROM a named context: its image.
            let base = match opts.contexts.get(base) {
                Some(NamedContext::Image(image)) => image,
                _ => base,
            };
            let base = &judge(
                policy.as_deref(),
                &self.image_service,
                base,
                "the base image",
            )
            .await?;
            let access = access_for(
                &self.image_service,
                &opts.access,
                opts.credentials.as_ref(),
                base,
                false,
            )
            .await?;
            let index = self
                .image_service
                .remote_manifest(base, opts.tls_verify, &access)
                .await?;
            let Some(instances) = index["manifests"].as_array() else {
                return Err(BuildError::Parse(format!(
                    "--all-platforms: the base image {base} is not a manifest list"
                )));
            };
            let mut these: Vec<String> = instances
                .iter()
                .filter_map(index_platform)
                .map(|p| p.to_string())
                .collect();
            these.sort();
            these.dedup();
            common = Some(match common {
                None => these,
                Some(c) => c.into_iter().filter(|p| these.contains(p)).collect(),
            });
        }
        let common = common.unwrap_or_default();
        if common.is_empty() {
            return Err(BuildError::Parse(
                "--all-platforms: the base images have no platform in common".into(),
            ));
        }
        common
            .iter()
            .map(|p| velarx_registry::target::Platform::parse(p).map_err(BuildError::Parse))
            .collect()
    }

    /// One build; `complete`: its end is the end of the whole (it is told).
    async fn build_one(
        &self,
        ctx: &BuildContext,
        opts: &BuildOptions,
        out: Option<mpsc::Sender<BuildProgress>>,
        complete: bool,
        cancel: Cancel,
    ) -> BuildResult<String> {
        let text = ctx.containerfile()?;
        let file = Containerfile::parse(&text).map_err(BuildError::Parse)?;
        let digest = self
            .image_service
            .creation_algorithm(opts.digest.as_deref())?;
        // (before the first step: a store that cannot take it fails here)
        self.image_service.check_digest_algorithm(digest)?;
        for (i, s) in file.stages.iter().enumerate() {
            if let Some(n) = &s.name {
                if file.stages[..i]
                    .iter()
                    .any(|o| o.name.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(n)))
                {
                    return Err(BuildError::Parse(format!("duplicate stage name `{n}`")));
                }
            }
        }
        let target = match &opts.target {
            None => file.stages.len() - 1,
            Some(t) => stage_before(&file.stages, t, file.stages.len()).ok_or_else(|| {
                BuildError::Parse(format!("the target stage `{t}` does not exist"))
            })?,
        };
        let platform = opts
            .platform
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(velarx_registry::target::Platform::parse)
            .transpose()
            .map_err(BuildError::Parse)?;
        let policy = source_policy(opts)?;
        let opts = &BuildOptions {
            network: build_network(opts.network.as_deref())?.map(|m| m.to_string()),
            ..opts.clone()
        };
        // (a build asked to stop while it waits for its turn never starts)
        let _running = cancel
            .unless(self.builds.acquire())
            .await
            .ok_or(BuildError::Cancelled)?
            .map_err(|e| BuildError::Parse(e.to_string()))?;
        private_dir(&self.work_dir)?;
        let n_steps = file.stages[..=target]
            .iter()
            .map(|s| 1 + s.instrs.len())
            .sum();
        let mut b = Build {
            svc: self,
            ctx,
            opts,
            out,
            cancel,
            ignore: ctx.ignore()?,
            digest,
            global_args: platform_args(platform.as_ref(), &opts.build_args),
            stage_images: vec![None; file.stages.len()],
            stage_bases: vec![BaseOf::default(); file.stages.len()],
            intermediates: Vec::new(),
            cached: Default::default(),
            step: 0,
            work: tempfile::Builder::new()
                .prefix("build-")
                .tempdir_in(&self.work_dir)?,
            seq: 0,
            hold: None,
            hold_name: None,
            squash_space: self.scratch.reservation(),
            platform,
            file,
            run_dir: None,
            target,
            policy,
        };
        let needed = b.plan(target)?;
        let hold = self.image_service.hold_build()?;
        b.hold_name = Some(hold.name().to_string());
        b.hold = Some(hold);
        b.send(BuildProgress::Started {
            total_steps: n_steps,
        })
        .await;
        let result = b.run(target, &needed).await;
        let keep = result.as_ref().ok().cloned();
        b.cleanup(keep.as_deref()).await;
        match result {
            Ok(id) => {
                if complete {
                    b.send(BuildProgress::Completed {
                        image_id: id.clone(),
                    })
                    .await;
                }
                Ok(id)
            }
            Err(e) => {
                b.send(BuildProgress::Error {
                    message: e.to_string(),
                })
                .await;
                Err(e)
            }
        }
    }
}

impl<'a> Build<'a> {
    async fn send(&self, p: BuildProgress) {
        if let Some(tx) = &self.out {
            let _ = tx.send(p).await;
        }
    }

    /// Where the blobs of a step send their progress: to the build's
    /// listener, if it has one.  The task ends when every sender is gone,
    /// with all that was sent forwarded.
    fn blobs(&self) -> (mpsc::Sender<TransferProgress>, tokio::task::JoinHandle<()>) {
        let out = self.out.clone();
        let (tx, mut rx) = mpsc::channel::<TransferProgress>(16);
        let forwarded = tokio::spawn(async move {
            while let Some(p) = rx.recv().await {
                if let Some(out) = &out {
                    let _ = out.send(BuildProgress::Blob(p)).await;
                }
            }
        });
        (tx, forwarded)
    }

    async fn say(&self, text: String) {
        self.send(BuildProgress::StepOutput {
            step: self.step,
            output: redact::urls(&text),
        })
        .await;
    }

    async fn run_output(&self, stderr: bool, data: &[u8]) {
        self.send(BuildProgress::RunOutput {
            step: self.step,
            stderr,
            output: String::from_utf8_lossy(data).into_owned(),
        })
        .await;
    }

    /// ARG: the arguments it declares, each with the value of the build
    /// argument, else of the platform argument (`TARGETARCH`: a default does
    /// not change it, as buildah's), else the default, else (for an argument
    /// declared again) its value among `outer`.
    fn declare_args(
        &self,
        i: &Instr,
        lookup: parse::Lookup<'_>,
        outer: &[(String, Option<String>)],
    ) -> BuildResult<Vec<(String, Option<String>)>> {
        let words =
            parse::split_words(&i.args, self.file.escape, lookup).map_err(|e| step_error(i, e))?;
        if words.is_empty() {
            return Err(step_error(i, "ARG requires an argument"));
        }
        let mut declared = Vec::with_capacity(words.len());
        for w in words {
            let (name, default) = match w.split_once('=') {
                Some((n, d)) => (n.to_string(), Some(d.to_string())),
                None => (w.clone(), None),
            };
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(step_error(i, format!("invalid argument name `{name}`")));
            }
            let value = self
                .opts
                .build_args
                .get(&name)
                .cloned()
                // (`--source-date-epoch` is the value of its argument)
                .or_else(|| {
                    (name == "SOURCE_DATE_EPOCH")
                        .then(|| self.opts.flags.source_date_epoch.map(|t| t.to_string()))
                        .flatten()
                })
                .or_else(|| {
                    self::lookup(&platform_args(
                        self.platform.as_ref(),
                        &self.opts.build_args,
                    ))(&name)
                })
                .or(default)
                .or_else(|| self::lookup(outer)(&name));
            declared.push((name, value));
        }
        Ok(declared)
    }

    /// The error of step `i` that failed with `e`: the cancellation, when
    /// that is what stopped it.
    fn failed(&self, i: &Instr, e: impl std::fmt::Display) -> BuildError {
        if self.cancel.asked() {
            BuildError::Cancelled
        } else {
            step_error(i, e)
        }
    }

    /// `e`, or the cancellation when that is what stopped the operation.
    fn stopped(&self, e: impl Into<BuildError>) -> BuildError {
        if self.cancel.asked() {
            BuildError::Cancelled
        } else {
            e.into()
        }
    }

    /// Before the first step: the global arguments, the stages the build
    /// makes, and whether it may have the entitlements they need.
    fn plan(&mut self, target: usize) -> BuildResult<Vec<bool>> {
        for i in &self.file.global_args {
            // (a global argument declared again has no outer value)
            let declared = self.declare_args(i, &lookup(&self.global_args), &[])?;
            for (name, value) in declared {
                set_kv(&mut self.global_args, &name, value);
            }
        }
        let needed = self.needed_stages(target);
        self.svc.require(
            &self.opts.allow,
            &entitlement::needs(&self.file, &needed[..=target], self.opts.network.as_deref()),
        )?;
        Ok(needed)
    }

    /// A build of the stage `index` that runs next to others: it has the
    /// images of the stages built so far, and numbers its steps from
    /// `step`.  What it says goes to `out`; `cancel` stops it.
    fn fork(
        &self,
        step: usize,
        out: mpsc::Sender<BuildProgress>,
        cancel: Cancel,
    ) -> BuildResult<Build<'a>> {
        Ok(Build {
            svc: self.svc,
            ctx: self.ctx,
            opts: self.opts,
            out: Some(out),
            cancel,
            file: self.file.clone(),
            ignore: self.ctx.ignore()?,
            digest: self.digest,
            global_args: self.global_args.clone(),
            stage_images: self.stage_images.clone(),
            stage_bases: self.stage_bases.clone(),
            intermediates: Vec::new(),
            cached: Default::default(),
            step,
            work: tempfile::Builder::new()
                .prefix("stage-")
                .tempdir_in(self.work.path())?,
            seq: 0,
            hold: None,
            hold_name: self.hold_name.clone(),
            squash_space: self.svc.scratch.reservation(),
            platform: self.platform.clone(),
            run_dir: None,
            target: self.target,
            policy: self.policy.clone(),
        })
    }

    /// The stages the target needs, `jobs` of them at the same time as
    /// their dependencies allow (`--jobs`).  A stage numbers its steps as it
    /// would build alone after the stages before it; what a stage says is
    /// held back until the stages before it have said theirs, so that the
    /// log is the one of a build one stage after the other.  The first
    /// stage that fails stops the others.
    async fn run_stages_together(
        &mut self,
        target: usize,
        needed: &[bool],
        jobs: usize,
    ) -> BuildResult<()> {
        use futures::stream::{FuturesUnordered, StreamExt};
        let stages: Vec<usize> = (0..=target).filter(|i| needed[*i]).collect();
        let mut first_step = vec![0; target + 1];
        let mut steps = 0;
        for i in &stages {
            first_step[*i] = steps;
            steps += 1 + self.file.stages[*i].instrs.len();
        }
        let deps: Vec<Vec<usize>> = (0..=target).map(|i| self.dependencies(i)).collect();
        let mut done = vec![false; target + 1];
        let mut started = vec![false; target + 1];
        let mut flushed = vec![false; target + 1];
        let mut said: Vec<Option<mpsc::Receiver<BuildProgress>>> =
            (0..=target).map(|_| None).collect();
        let mut running = FuturesUnordered::new();
        let mut failed: Option<BuildError> = None;
        let (stop, stopped) = Cancel::new();
        let cancel = self.cancel.or(&stopped);
        loop {
            // the stages whose dependencies are built, in order
            for &i in &stages {
                if failed.is_some() || running.len() >= jobs {
                    break;
                }
                if started[i] || !deps[i].iter().all(|d| done[*d] || !needed[*d]) {
                    continue;
                }
                started[i] = true;
                let (tx, rx) = mpsc::channel(256);
                said[i] = Some(rx);
                let child = self.fork(first_step[i], tx, cancel.clone())?;
                running.push(Self::stage_apart(child, i, i == target));
            }
            if running.is_empty() {
                break;
            }
            // the first stage whose output is not out speaks as it goes
            let speaker = stages.iter().copied().find(|i| !flushed[*i]);
            let voice = speaker.and_then(|i| said[i].as_mut());
            let (finished, spoken) = tokio::select! {
                f = running.next() => (f, None),
                p = async {
                    match voice {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => (None, p),
            };
            if let Some(p) = spoken {
                self.send(p).await;
            }
            if let Some((i, result, left)) = finished {
                done[i] = true;
                self.intermediates.extend(left.intermediates);
                self.cached.extend(left.cached);
                match result {
                    Ok(id) => {
                        self.stage_images[i] = Some(id);
                        self.stage_bases[i] = left.base;
                    }
                    Err(e) => {
                        failed.get_or_insert(e);
                        let _ = stop.send(true);
                    }
                }
                // what the stages that are done have said, in order
                while let Some(i) = stages.iter().copied().find(|i| !flushed[*i]) {
                    if !done[i] {
                        break;
                    }
                    if let Some(mut rx) = said[i].take() {
                        while let Some(p) = rx.recv().await {
                            self.send(p).await;
                        }
                    }
                    flushed[i] = true;
                }
            }
        }
        // what the stages that did not speak have said
        for rx in said.iter_mut().flatten() {
            while let Some(p) = rx.recv().await {
                self.send(p).await;
            }
        }
        match failed {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Build the stage `index` of `child`, and say what it leaves.
    async fn stage_apart(
        mut child: Build<'a>,
        index: usize,
        last: bool,
    ) -> (usize, BuildResult<String>, Left) {
        let result = child.stage(index, last).await;
        let left = Left {
            base: std::mem::take(&mut child.stage_bases[index]),
            intermediates: std::mem::take(&mut child.intermediates),
            cached: std::mem::take(&mut child.cached),
        };
        (index, result, left)
    }

    async fn run(&mut self, target: usize, needed: &[bool]) -> BuildResult<String> {
        // (`--jobs`: 0 is as many as there are)
        let jobs = match self.opts.flags.jobs {
            0 => usize::MAX,
            n => n as usize,
        };
        if jobs > 1 && needed.iter().filter(|n| **n).count() > 1 {
            self.run_stages_together(target, needed, jobs).await?;
        } else {
            for (index, _) in needed
                .iter()
                .enumerate()
                .take(target + 1)
                .filter(|(_, n)| **n)
            {
                let id = self.stage(index, index == target).await?;
                self.stage_images[index] = Some(id);
            }
        }
        let id = self.stage_images[target]
            .clone()
            .ok_or_else(|| BuildError::Parse("the target stage was not built".into()))?;
        let id = self.sbom(id).await?;
        for t in &self.opts.tags {
            let name = self.svc.image_service.tag_local(&id, t).await?;
            self.say(format!("Successfully tagged {name}\n")).await;
        }
        Ok(id)
    }

    /// The stages the build makes: those the target uses (FROM, COPY
    /// --from, RUN --mount from=, transitively), or with
    /// `--skip-unused-stages=false` all of them up to it.  A reference
    /// with a variable may name any stage before.
    fn needed_stages(&self, target: usize) -> Vec<bool> {
        let n = self.file.stages.len();
        let mut need = vec![!self.opts.flags.skip_unused_stages; n];
        need[target] = true;
        for i in (0..=target).rev() {
            if !need[i] {
                continue;
            }
            for j in self.dependencies(i) {
                need[j] = true;
            }
        }
        need
    }

    /// The stages before `i` that it uses (FROM, COPY --from, RUN --mount
    /// from=); a reference with a variable may name any of them.
    fn dependencies(&self, i: usize) -> Vec<usize> {
        let lookup = lookup(&self.global_args);
        let stages = &self.file.stages;
        let s = &stages[i];
        let mut refs =
            vec![parse::expand(&s.base, self.file.escape, &lookup)
                .unwrap_or_else(|_| s.base.clone())];
        for instr in &s.instrs {
            for f in &instr.flags {
                if let Some(v) = f.strip_prefix("--from=") {
                    refs.push(v.to_string());
                }
                if let Some(m) = f.strip_prefix("--mount=") {
                    refs.extend(
                        m.split(',')
                            .filter_map(|kv| kv.strip_prefix("from="))
                            .map(str::to_string),
                    );
                }
            }
        }
        let mut found = Vec::new();
        for r in refs {
            if r.contains('$') {
                return (0..i).collect();
            }
            found.extend(stage_before(stages, &r, i));
        }
        found
    }

    /// The image of the stage `name` (or index) built before `before`.
    fn stage_image(&self, name: &str, before: usize) -> Option<String> {
        self.stage_index(name, before)
            .and_then(|i| self.stage_images[i].clone())
    }

    /// The stage `name` (or index) before `before`.
    fn stage_index(&self, name: &str, before: usize) -> Option<usize> {
        stage_before(&self.file.stages, name, before)
    }

    /// `--source-policy-file`: the image `reference` that the build is
    /// about to pull or use from the store (`what`: a base, the image of a
    /// `COPY --from` or of a `RUN --mount from`, directly or through a
    /// named context), as the policy has it.  A short name is decided,
    /// and then pulled, by the one name it stands for.
    async fn judged(&self, reference: &str, what: &str) -> BuildResult<String> {
        judge(
            self.policy.as_deref(),
            &self.svc.image_service,
            reference,
            what,
        )
        .await
    }

    /// The credentials the build has for the registry of `reference`.
    async fn access_of(
        &self,
        reference: &str,
    ) -> BuildResult<velarx_registry::auth::RegistryAccess> {
        access_for(
            &self.svc.image_service,
            &self.opts.access,
            self.opts.credentials.as_ref(),
            reference,
            false,
        )
        .await
    }

    /// The id of the image `reference` (pulled if the store has not the one
    /// asked), pinned by the hold of the build: a prune leaves it alone as
    /// long as the build runs.
    async fn ensure_image(&self, reference: &str, platform: Option<&str>) -> BuildResult<String> {
        let id = self.pull_missing(reference, platform).await?;
        let Some(hold) = &self.hold_name else {
            return Ok(id);
        };
        match self.svc.image_service.pin_image(hold, id.clone()).await? {
            Some(id) => Ok(id),
            None => Err(ImageError::NotFound(format!(
                "the image {reference} ({id:.12}) was removed before the build could hold it: \
                 run the build again"
            ))
            .into()),
        }
    }

    async fn pull_missing(&self, reference: &str, platform: Option<&str>) -> BuildResult<String> {
        let reference = velarx_types::transport::ImageLocation::local(reference, "FROM")
            .map_err(|e| BuildError::Parse(e.to_string()))?;
        let reference = reference.as_str();
        let wanted = platform
            .map(velarx_registry::target::Platform::parse)
            .transpose()
            .map_err(BuildError::Parse)?;
        let mut access = None;
        if self.opts.pull != PullPolicy::Always {
            match self.svc.image_service.get(reference).await {
                // An image for another platform is not the one asked: pulled
                // again.
                Ok(image) if platform_matches(&image, wanted.as_ref()) => {
                    if self.opts.pull != PullPolicy::Newer {
                        return Ok(image.id);
                    }
                    let a = self.access_of(reference).await?;
                    let options = PullOptions {
                        tls_verify: self.opts.tls_verify,
                        platform: platform.map(str::to_string),
                        access: a.clone(),
                        sources: None,
                    };
                    let remote = self
                        .svc
                        .image_service
                        .remote_digest(reference, &options)
                        .await;
                    // (not reachable: the image of the store)
                    if !remote.is_ok_and(|d| d != image.manifest_digest) {
                        return Ok(image.id);
                    }
                    access = Some(a);
                }
                Ok(_) if self.opts.pull == PullPolicy::Never => {
                    return Err(BuildError::Parse(format!(
                        "{reference} is not for the platform {} in the store and the pull policy is never",
                        platform.unwrap_or_default()
                    )))
                }
                Ok(_) => {}
                Err(_) if self.opts.pull == PullPolicy::Never => {
                    return Err(BuildError::Parse(format!(
                        "creating build container: {reference}: image not known"
                    )))
                }
                Err(_) => {}
            }
        }
        self.send(BuildProgress::Report {
            output: format!("Pulling {reference}\n"),
        })
        .await;
        let access = match access {
            Some(a) => a,
            None => self.access_of(reference).await?,
        };
        let opts = PullOptions {
            tls_verify: self.opts.tls_verify,
            platform: platform.map(str::to_string),
            access,
            sources: None,
        };
        // `--retry` (podman sends 3 by default)
        let pulled = self
            .cancel
            .unless(super::retried(
                &self.opts.flags.retry,
                || async {
                    let (tx, forwarded) = self.blobs();
                    // (a pull that is dropped leaves nothing: its files are in
                    // the staging area until it is done, and its hold goes
                    // with it)
                    let r = self
                        .svc
                        .image_service
                        .pull_with(reference, false, &opts, tx)
                        .await;
                    // what the pull reported comes before what the build says
                    // next
                    let _ = forwarded.await;
                    r
                },
                |e, a| async move {
                    self.send(BuildProgress::Report {
                        output: redact::urls(&format!("{}\n", a.note(&e))),
                    })
                    .await;
                },
            ))
            .await;
        match pulled {
            Some(Ok(image)) => Ok(image.id),
            Some(Err(e)) => Err(e.into()),
            None => Err(BuildError::Cancelled),
        }
    }

    async fn stage(&mut self, index: usize, last: bool) -> BuildResult<String> {
        let stage = self.file.stages[index].clone();
        let base = parse::expand(&stage.base, self.file.escape, &lookup(&self.global_args))
            .map_err(BuildError::Parse)?;
        self.step += 1;
        // As buildah numbers them: the steps of the stage, the stage when
        // there are several.
        let prefix = if self.file.stages.len() > 1 {
            format!("[{}/{}] ", index + 1, self.file.stages.len())
        } else {
            String::new()
        };
        let stage_steps = stage.instrs.len() + 1;
        let header = format!(
            "{prefix}STEP 1/{stage_steps}: FROM {base}{}",
            stage
                .name
                .as_deref()
                .map(|n| format!(" AS {n}"))
                .unwrap_or_default()
        );
        self.send(BuildProgress::StepStarted {
            step: self.step,
            instruction: header,
        })
        .await;
        // `--from`: the base of the first stage
        let base = match (&self.opts.flags.from, index) {
            (Some(from), 0) => from.clone(),
            _ => base,
        };
        // FROM a named context: its image.
        let mut base = match self.opts.contexts.get(&base) {
            Some(NamedContext::Image(image)) => image.clone(),
            Some(NamedContext::Dir(_)) => {
                return Err(BuildError::Parse(format!(
                    "the build context {base} is not an image, it cannot be used for FROM"
                )))
            }
            None => base,
        };
        let image = if base == "scratch" {
            None
        } else {
            match self.stage_image(&base, index) {
                Some(id) => Some(id),
                None => {
                    base = self.judged(&base, "the base image").await?;
                    let platform = stage
                        .platform
                        .as_deref()
                        .map(|p| parse::expand(p, self.file.escape, &lookup(&self.global_args)))
                        .transpose()
                        .map_err(BuildError::Parse)?
                        .or_else(|| self.opts.platform.clone());
                    Some(self.ensure_image(&base, platform.as_deref()).await?)
                }
            }
        };
        let mut st = StageState {
            index,
            base_image: image.clone(),
            image,
            edits: Vec::new(),
            committed: 0,
            author: None,
            env: Vec::new(),
            args: Vec::new(),
            shell: vec!["/bin/sh".into(), "-c".into()],
            workdir: String::new(),
            user: String::new(),
            cmd_set: false,
            onbuild: Vec::new(),
            squash_dir: None,
            base: BaseOf {
                name: Some(String::new()),
                ..Default::default()
            },
            named: false,
            last_commit: false,
            layer_added: Vec::new(),
        };
        let mut triggers = Vec::new();
        if let Some(id) = &st.image {
            let rec = self.svc.image_service.get(id).await?;
            let cfg: Value = serde_json::from_str(&rec.config)?;
            st.base = match self.stage_index(&base, index) {
                // (FROM a stage: its base, as buildah's)
                Some(i) => self.stage_bases[i].clone(),
                None => BaseOf {
                    name: base_name(&base, id),
                    digest: rec.manifest_digest.to_string(),
                    annotations: serde_json::from_str::<Value>(&rec.manifest)
                        .ok()
                        .and_then(|m| m["annotations"].as_object().cloned())
                        .into_iter()
                        .flatten()
                        // (the merged EROFS of the base is not the image's)
                        .filter(|(k, _)| !crate::services::image::is_merged_annotation(k))
                        .filter_map(|(k, v)| Some((k, v.as_str()?.to_string())))
                        .collect(),
                    os_features: cfg["os.features"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|f| Some(f.as_str()?.to_string()))
                        .collect(),
                    args: Vec::new(),
                },
            };
            st.args = st.base.args.clone();
            let c = &cfg["config"];
            for e in c["Env"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if let Some((k, v)) = e.split_once('=') {
                    set_kv(&mut st.env, k, v.to_string());
                }
            }
            st.workdir = c["WorkingDir"].as_str().unwrap_or_default().to_string();
            st.user = c["User"].as_str().unwrap_or_default().to_string();
            if let Some(shell) = c["Shell"].as_array().filter(|a| !a.is_empty()) {
                st.shell = shell
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }
            for t in c["OnBuild"].as_array().into_iter().flatten() {
                let text = t.as_str().ok_or_else(|| {
                    BuildError::Parse(
                        "the base image has an ONBUILD trigger that is not a string".into(),
                    )
                })?;
                triggers.push(
                    self.file.trigger(text, stage.line).map_err(|e| {
                        BuildError::Parse(format!("ONBUILD of the base image: {e}"))
                    })?,
                );
            }
        }
        if !self.opts.flags.inherit_labels && st.image.is_some() {
            st.edit(ConfigEdit::Unset("Labels".into()));
        }
        // (a LABEL and `--label` keep it, `--unsetlabel` removes it: as
        // buildah's)
        if self.opts.flags.identity() {
            st.edit(ConfigEdit::Merge(
                "Labels".into(),
                [(IDENTITY_LABEL.to_string(), json!(env!("CARGO_PKG_VERSION")))]
                    .into_iter()
                    .collect(),
            ));
        }
        // `--stage-labels`: the name of the stage and its base, the image
        // of the stage a stage is FROM
        if self.opts.flags.stage_labels && !stage.instrs.is_empty() {
            let name = stage.name.clone().unwrap_or_else(|| index.to_string());
            let from = match self.stage_image(&base, index) {
                Some(id) => self.svc.image_service.get(&id).await?.config_digest.hex(),
                None => base.clone(),
            };
            st.edit(ConfigEdit::Merge(
                "Labels".into(),
                [
                    ("io.buildah.stage.name".to_string(), json!(name)),
                    ("io.buildah.stage.base".to_string(), json!(from)),
                ]
                .into_iter()
                .collect(),
            ));
        }
        // `--env`: every stage, its RUN steps too; an ENV of the
        // Containerfile wins (as buildah)
        if !self.opts.env.is_empty() {
            for (k, v) in &self.opts.env {
                set_kv(&mut st.env, k, v.clone());
            }
            st.edit(ConfigEdit::Env(self.opts.env.clone()));
        }
        if !triggers.is_empty() {
            // The triggers run once: the image of this stage has none of them.
            st.edit(ConfigEdit::Unset("OnBuild".into()));
            self.say(format!("--> Executing {} build triggers\n", triggers.len()))
                .await;
            for i in &triggers {
                self.say(format!("--> ONBUILD {}\n", i.text())).await;
                self.instruction(&mut st, i).await?;
            }
        }
        if last && self.opts.squash && !self.opts.squash_all {
            let dir = self.new_dir("squash")?;
            st.squash_dir = Some(dir);
        }

        // (as buildah: the image of a build without a name is an
        // intermediate one too)
        let named = last && (!self.opts.tags.is_empty() || self.opts.manifest.is_some());
        // (the options that edit the built image make a commit of their own
        // after the last step, as do --squash and MAINTAINER)
        let edits_after = !self.opts.unset_env.is_empty()
            || !self.opts.labels.is_empty()
            || !self.opts.unset_labels.is_empty();
        for (n, i) in stage.instrs.iter().enumerate() {
            st.named = named && n + 1 == stage.instrs.len();
            st.last_commit = last
                && n + 1 == stage.instrs.len()
                && !edits_after
                && st.squash_dir.is_none()
                && st.author.is_none();
            self.step += 1;
            let header = format!("{prefix}STEP {}/{stage_steps}: {}", n + 2, i.text());
            self.send(BuildProgress::StepStarted {
                step: self.step,
                instruction: header,
            })
            .await;
            self.instruction(&mut st, i).await?;
            self.send(BuildProgress::StepCompleted { step: self.step })
                .await;
        }

        st.named = named;
        st.last_commit = last;
        if last && !self.opts.unset_env.is_empty() {
            st.edit(ConfigEdit::UnsetEnv(self.opts.unset_env.clone()));
        }
        if last && !self.opts.labels.is_empty() {
            let mut labels: Vec<_> = self.opts.labels.iter().collect();
            labels.sort();
            let mut labels = labels
                .into_iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect();
            self.keep_identity(&mut labels);
            st.edit(ConfigEdit::Merge("Labels".into(), labels));
        }
        // (`--unsetlabel` wins over `--label`, as buildah's)
        if last && !self.opts.unset_labels.is_empty() {
            st.edit(ConfigEdit::Remove(
                "Labels".into(),
                self.opts.unset_labels.clone(),
            ));
        }
        if let Some(dir) = st.squash_dir.clone() {
            // One layer of all the changes on the base of the stage, with
            // the root the stage has now.
            let tocs = match &st.image {
                Some(id) => {
                    let rec = self.svc.image_service.get(id).await?;
                    self.svc.image_service.layer_tocs(&rec).await?
                }
                None => Vec::new(),
            };
            let refs: Vec<&Toc> = tocs.iter().collect();
            let tree = MergedTree::build(&refs).map_err(BuildError::Parse)?;
            st.image = st.base_image.clone();
            st.layer_added.clear();
            st.committed = 0;
            self.commit(
                &mut st,
                "velarx build --squash",
                Some(Changes::Dir(dir)),
                files_onto(&tree),
                None,
            )
            .await?;
        } else if !st.pending().is_empty()
            || st.image.is_none()
            || st.author.is_some()
            // The built image is a new one, as podman's (never the base,
            // which a removal of the built name would untag only).
            || (last && st.image == st.base_image)
        {
            let key = self.cache_key(&st, "velarx build", json!("config"))?;
            if !self.use_cache(&mut st, &key).await? {
                // (a stage from scratch with nothing in it: an empty layer)
                let empty = if st.image.is_none() {
                    Some(self.new_dir("empty")?)
                } else {
                    None
                };
                self.commit(
                    &mut st,
                    "velarx build",
                    empty.map(Changes::Dir),
                    dirtar::Options::default(),
                    Some(&key),
                )
                .await?;
            }
        }
        if last && self.opts.squash_all {
            self.squash_all(&mut st).await?;
        }
        st.base.args = st.args;
        self.stage_bases[index] = st.base;
        let id = st
            .image
            .ok_or_else(|| BuildError::Parse(format!("the stage {index} has no content")))?;
        if self.opts.flags.save_stages {
            self.cached.insert(id.clone());
        }
        Ok(id)
    }

    /// The identity label wins over a LABEL of the Containerfile and over
    /// `--label` (as buildah's): those keep its value.
    fn keep_identity(&self, labels: &mut Map<String, Value>) {
        if let (true, Some(v)) = (self.opts.flags.identity(), labels.get_mut(IDENTITY_LABEL)) {
            *v = json!(env!("CARGO_PKG_VERSION"));
        }
    }

    /// The annotations of the manifest of the built image, as buildah's:
    /// those of the base with its name and digest (`--inherit-annotations`),
    /// the time of the image (`--created-annotation`), then `--annotation`
    /// and `--unsetannotation`.
    fn annotations(&self, st: &StageState) -> std::collections::BTreeMap<String, String> {
        let flags = &self.opts.flags;
        let mut a = std::collections::BTreeMap::new();
        if flags.inherit_annotations {
            a = st.base.annotations.clone();
            match &st.base.name {
                Some(name) => a.insert(BASE_NAME_ANNOTATION.into(), name.clone()),
                None => a.remove(BASE_NAME_ANNOTATION),
            };
            a.insert(
                "org.opencontainers.image.base.digest".into(),
                st.base.digest.clone(),
            );
        }
        if flags.created_annotation {
            // (its value is not in the key: the build cache has the image
            // of the first build that made it, as buildah's)
            a.insert(CREATED_ANNOTATION.into(), String::new());
        }
        for p in &flags.annotations {
            a.insert(p.name.clone(), p.value.clone());
        }
        for k in &flags.unset_annotations {
            a.remove(k);
        }
        a
    }

    /// What the images of the stage of the built image have: the
    /// annotations of their manifest, the time left empty, and the fields
    /// `--os-version` and `--os-feature` of their configuration.
    #[allow(clippy::type_complexity)]
    fn final_manifest(
        &self,
        st: &StageState,
    ) -> Option<(
        std::collections::BTreeMap<String, String>,
        Vec<(String, Value)>,
    )> {
        if st.index != self.target {
            return None;
        }
        let flags = &self.opts.flags;
        let mut root = Vec::new();
        if let Some(v) = &flags.os_version {
            root.push(("os.version".to_string(), json!(v)));
        }
        if !flags.os_features.is_empty() {
            // (those of the base, as buildah's: FEATURE- removes one)
            let mut features = st.base.os_features.clone();
            for f in &flags.os_features {
                match f.strip_suffix('-') {
                    Some(gone) => features.retain(|o| o != gone),
                    None if !features.contains(f) => features.push(f.clone()),
                    None => {}
                }
            }
            root.push((
                "os.features".to_string(),
                if features.is_empty() {
                    Value::Null
                } else {
                    json!(features)
                },
            ));
        }
        Some((self.annotations(st), root))
    }

    /// The annotations and the configuration fields of an image the stage
    /// commits ([`Build::final_manifest`]), the time set.
    fn final_commit(&self, st: &StageState, opts: &mut CommitOptions) {
        let Some((mut annotations, root)) = self.final_manifest(st) else {
            return;
        };
        if let Some(created) = annotations.get_mut(CREATED_ANNOTATION) {
            // (the time of the configuration, as buildah's)
            let time = opts.created.get_or_insert_with(|| {
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
            });
            *created = time.clone();
        }
        opts.annotations = annotations.into_iter().collect();
        opts.config_root = root;
    }

    /// Replace the image of the stage by one whose only layer is the merged
    /// tree of all its layers (the steps ran with the build cache).
    async fn squash_all(&mut self, st: &mut StageState) -> BuildResult<()> {
        let image = st
            .image
            .clone()
            .ok_or_else(|| BuildError::Parse("nothing to squash".into()))?;
        let (progress, forwarded) = self.blobs();
        let mut opts = CommitOptions {
            created_by: "velarx build --squash-all".into(),
            author: st.author.clone(),
            digest: Some(self.digest),
            hold: self.hold_name.clone(),
            platform: self.platform.clone(),
            progress: Some(progress),
            squash_all: true,
            created: self.created(),
            omit_history: self.opts.flags.omit_history,
            cancel: self.cancel.clone(),
            ..CommitOptions::default()
        };
        self.final_commit(st, &mut opts);
        let id = self
            .svc
            .image_service
            .commit_dir(Some(&image), None, &opts)
            .await;
        drop(opts);
        let _ = forwarded.await;
        let id = id.map_err(|e| self.stopped(e))?;
        self.say(format!("--> {}\n", &id[..12.min(id.len())])).await;
        self.intermediates.push(id.clone());
        st.image = Some(id);
        Ok(())
    }

    /// Download `url` into the new directory `dir` (a file named after the
    /// URL, mode 0600, the time of its Last-Modified as Docker does), at
    /// most what a copy may write, checked against `checksum`
    /// (`sha256:HEX` or `sha512:HEX`) if given.  Returns the name of the file.
    async fn download(
        &self,
        url: &str,
        dir: &Path,
        checksum: Option<&str>,
    ) -> Result<String, String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if !is_url(url) {
            return Err(format!("unsupported URL `{}`", redact::urls(url)));
        }
        let name = url_file_name(url)?;
        let want: Option<Digest> = checksum
            .map(|c| {
                c.parse()
                    .map_err(|e| format!("invalid --checksum `{c}`: {e}"))
            })
            .transpose()?;
        self.say(format!("Downloading {}\n", redact::urls(url)))
            .await;
        // The request and the bytes of the server: in a confined worker
        // when the pulls are confined, the daemon only stores the body.
        std::fs::create_dir(dir).map_err(|e| e.to_string())?;
        let path = dir.join(&name);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let mut out = std::io::BufWriter::new(&file);
        let mut hasher = DigestWriter::new(want.map_or(Algorithm::Sha256, |w| w.alg()));
        let limit = self.svc.limits.max_bytes;
        let cancel = self.cancel.clone();
        let fetched = cancel
            .unless(self.svc.fetcher.fetch(url, limit, &mut |chunk| {
                cancel.check()?;
                hasher.update(chunk);
                out.write_all(chunk)
            }))
            .await
            .ok_or_else(|| Cancel::error().to_string())?
            .map_err(|e| match e {
                velarx_content::pull::net::origin::UrlError::TooLarge(_) => redact::urls(&format!(
                    "{url} is larger than a copy may write ({limit} bytes)"
                )),
                e => redact::urls(&format!("downloading {url}: {e}")),
            })?;
        let modified = fetched
            .last_modified
            .as_deref()
            .and_then(|v| chrono::DateTime::parse_from_rfc2822(v).ok())
            .map(|t| std::time::SystemTime::from(t.with_timezone(&chrono::Utc)));
        out.flush().map_err(|e| e.to_string())?;
        drop(out);
        if let Some(want) = want {
            let got = hasher.finalize();
            if got != want {
                return Err(redact::urls(&format!(
                    "{url}: checksum {got} is not {want}"
                )));
            }
        }
        if let Some(t) = modified {
            file.set_modified(t).map_err(|e| e.to_string())?;
        }
        Ok(name)
    }

    /// Clone `g` into the empty directory `dir`, without its `.git` unless
    /// `keep_git_dir`.
    async fn clone_git(
        &self,
        g: &git::GitSource,
        dir: &Path,
        keep_git_dir: bool,
    ) -> Result<(), String> {
        let Some(exe) = self.svc.runner.exe.clone() else {
            return Err("ADD of a git repository needs the confined helper of the daemon".into());
        };
        self.say(format!("Cloning {} ({})\n", g.url, g.reference))
            .await;
        let (g2, d, limits, timeout) = (
            g.clone(),
            dir.to_path_buf(),
            self.svc.limits,
            self.svc.runner.timeout,
        );
        helper::stoppable(&self.cancel, move |stop| {
            git::clone(&exe, &g2, &d, &limits, timeout, stop)
        })
        .await
        .map_err(|e| e.to_string())?;
        // (the remove and the walk of the clone off the async threads)
        let root = dir.to_path_buf();
        let used = crate::off_thread(move || {
            if !keep_git_dir {
                match velarx_base::tree::remove_dir_all(root.join(".git")) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(std::io::Error::other(format!("removing .git: {e}"))),
                }
            }
            disk_usage(&root)
        })
        .await
        .map_err(|e| e.to_string())?;
        if used > self.svc.limits.max_bytes {
            return Err(format!(
                "the clone of {} is larger than a copy may write ({} bytes)",
                redact::urls(&g.url),
                self.svc.limits.max_bytes
            ));
        }
        Ok(())
    }

    async fn instruction(&mut self, st: &mut StageState, i: &Instr) -> BuildResult<()> {
        if self.cancel.asked() {
            return Err(BuildError::Cancelled);
        }
        match i.keyword.as_str() {
            "RUN" => self.run_step(st, i).await,
            "COPY" | "ADD" => self.copy_step(st, i).await,
            _ => self.metadata(st, i).await,
        }
    }

    /// The time of the image and its history (`--timestamp`,
    /// `--source-date-epoch`); none: the time of each commit.
    fn created(&self) -> Option<String> {
        self.opts
            .flags
            .timestamp
            .or(self.opts.flags.source_date_epoch)
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }

    /// The times of the files of the new layers.
    fn mtime(&self) -> dirtar::Mtime {
        match (self.opts.flags.timestamp, self.opts.flags.source_date_epoch) {
            (Some(t), _) => dirtar::Mtime::Fixed(t),
            (None, Some(e)) if self.opts.flags.rewrite_timestamp => dirtar::Mtime::Clamp(e),
            _ => dirtar::Mtime::Keep,
        }
    }

    fn new_dir(&mut self, what: &str) -> BuildResult<PathBuf> {
        self.seq += 1;
        let dir = self.work.path().join(format!("{what}-{}", self.seq));
        std::fs::create_dir(&dir)?;
        Ok(dir)
    }

    /// Whether the steps of this stage are recorded in the build cache:
    /// not without `layers`, nor in a stage that is squashed (its steps run
    /// to fill the squashed layer).
    fn caching(&self, st: &StageState) -> bool {
        self.opts.layers && st.squash_dir.is_none()
    }

    /// The changes of the labels the commit of a step makes for
    /// `--layer-label`, as buildah: an intermediate image has the layer
    /// labels the stage has no value for, the image the build names has
    /// none of them.  The edits that go before and after those of the step,
    /// and the labels the image then has from `--layer-label`.
    async fn layer_label_edits(
        &self,
        st: &StageState,
    ) -> BuildResult<(Vec<ConfigEdit>, Vec<ConfigEdit>, Vec<String>)> {
        let flags = &self.opts.flags.layer_labels;
        if flags.is_empty() {
            return Ok((Vec::new(), Vec::new(), Vec::new()));
        }
        let before: Vec<ConfigEdit> = (!st.layer_added.is_empty())
            .then(|| ConfigEdit::Remove("Labels".into(), st.layer_added.clone()))
            .into_iter()
            .collect();
        if st.named {
            return Ok((before, Vec::new(), Vec::new()));
        }
        // The labels of the stage once the step is committed.
        let mut config = serde_json::Map::new();
        if let Some(id) = &st.image {
            let image: Value = serde_json::from_str(&self.svc.image_service.get(id).await?.config)?;
            if let Some(labels) = image["config"].get("Labels") {
                config.insert("Labels".into(), labels.clone());
            }
        }
        for e in before.iter().chain(st.pending()) {
            e.apply(&mut config);
        }
        let mut added = serde_json::Map::new();
        for l in flags {
            if config.get("Labels").and_then(|c| c.get(&l.name)).is_none() {
                added.insert(l.name.clone(), json!(l.value));
            }
        }
        let keys = added.keys().cloned().collect();
        let after = (!added.is_empty())
            .then(|| ConfigEdit::Merge("Labels".into(), added))
            .into_iter()
            .collect();
        Ok((before, after, keys))
    }

    /// The key of a step in the build cache: what its commit is made of,
    /// `step` being what the step itself ran or copied.
    fn cache_key(&self, st: &StageState, created_by: &str, step: Value) -> BuildResult<String> {
        // (version 2: the layers are canonical tars, the images cached
        // before are not what a build makes now)
        let mut key = json!({
            "version": 2,
            "created_by": created_by,
            "edits": st.pending(),
            "author": st.author,
            "platform": self.platform.as_ref().map(ToString::to_string),
            "time": [self.opts.flags.timestamp, self.opts.flags.source_date_epoch],
            "rewrite_timestamp": self.opts.flags.rewrite_timestamp,
            "omit_history": self.opts.flags.omit_history,
            "manifest": self.final_manifest(st),
            "layer_labels": (!self.opts.flags.layer_labels.is_empty())
                .then(|| json!([self.opts.flags.layer_labels, st.named, st.layer_added])),
            "step": step,
        });
        // (an image of sha512 is another image than the one of sha256; the
        // keys of sha256 builds stay what they were)
        if self.digest != Algorithm::Sha256 {
            key["digest"] = json!(self.digest.name());
        }
        // (the key is no digest of an image: SHA-256, whatever the build makes)
        Ok(Digest::of(Algorithm::Sha256, &serde_json::to_vec(&key)?).to_string())
    }

    /// Take the image the build cache has for the step `key` on the
    /// current image as the next image of the stage, if it has one.
    async fn use_cache(&mut self, st: &mut StageState, key: &str) -> BuildResult<bool> {
        let Some(id) = self.cached_image(st, key).await? else {
            return Ok(false);
        };
        self.say(format!("--> Using cache {id}\n")).await;
        self.say_commit(st).await;
        self.say(format!("--> {}\n", &id[..12.min(id.len())])).await;
        st.layer_added = self.layer_label_edits(st).await?.2;
        st.committed = st.edits.len();
        st.image = Some(id);
        Ok(true)
    }

    /// The image the build cache has for the step `key` on the current
    /// image, if it may be used.
    async fn cached_image(&self, st: &StageState, key: &str) -> BuildResult<Option<String>> {
        if self.opts.no_cache || !self.caching(st) {
            return Ok(None);
        }
        let Some(hold) = self.hold_name.clone() else {
            return Ok(None);
        };
        let parent = st.image.as_deref().unwrap_or(velarx_db::BUILD_SCRATCH);
        let local = self
            .svc
            .image_service
            .build_cache_get(parent, key, &hold)
            .await?;
        let id = match local {
            Some(id) => id,
            None => match self.pull_cached(parent, key, &hold).await? {
                Some(id) => id,
                None => return Ok(None),
            },
        };
        if let Some(ttl) = self.opts.flags.cache_ttl() {
            let made = self.svc.image_service.get(&id).await?.created_at;
            let fresh = chrono::DateTime::parse_from_rfc3339(&made)
                .ok()
                .and_then(|t| {
                    (chrono::Utc::now() - t.with_timezone(&chrono::Utc))
                        .to_std()
                        .ok()
                })
                .is_some_and(|age| age <= ttl);
            if !fresh {
                return Ok(None);
            }
        }
        Ok(Some(id))
    }

    /// The image a `--cache-from` repository has for the step `key` on
    /// `parent`, if one has: pulled and recorded in the build cache.  A
    /// repository without it, or that cannot be reached, is no cache.
    async fn pull_cached(
        &self,
        parent: &str,
        key: &str,
        hold: &str,
    ) -> BuildResult<Option<String>> {
        let images = &self.svc.image_service;
        for repository in &self.opts.flags.cache_from {
            let reference = cache_reference(repository, parent, key)?;
            let access = access_for(
                images,
                &self.opts.access,
                self.opts.credentials.as_ref(),
                &reference,
                false,
            )
            .await?;
            let opts = PullOptions {
                tls_verify: self.opts.tls_verify,
                platform: self.platform.as_ref().map(ToString::to_string),
                access,
                sources: None,
            };
            let (tx, forwarded) = self.blobs();
            let pulled = self
                .cancel
                .unless(images.pull_with(&reference, false, &opts, tx))
                .await;
            let _ = forwarded.await;
            let image = match pulled {
                Some(Ok(image)) => image,
                Some(Err(e)) => {
                    info!("No cache image {reference}: {e}");
                    continue;
                }
                None => return Err(BuildError::Cancelled),
            };
            if !self.continues(parent, &image.id).await? {
                warn!("The cache image {reference} is not a step on the image {parent}");
                continue;
            }
            images.build_cache_put(parent, key, &image.id).await?;
            if let Some(id) = images.build_cache_get(parent, key, hold).await? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Whether the layers of the image `child` are those of `parent` and
    /// more.
    async fn continues(&self, parent: &str, child: &str) -> BuildResult<bool> {
        let diff_ids = |config: &str| -> Vec<String> {
            serde_json::from_str::<Value>(config)
                .ok()
                .and_then(|c| {
                    c["rootfs"]["diff_ids"].as_array().map(|a| {
                        a.iter()
                            .filter_map(|d| d.as_str().map(str::to_string))
                            .collect()
                    })
                })
                .unwrap_or_default()
        };
        let images = &self.svc.image_service;
        let have = if parent == velarx_db::BUILD_SCRATCH {
            Vec::new()
        } else {
            diff_ids(&images.get(parent).await?.config)
        };
        let layers = diff_ids(&images.get(child).await?.config);
        Ok(layers.len() > have.len() && layers.starts_with(&have))
    }

    /// Push the image `id` of the step `key` on `parent` to the
    /// repositories of `--cache-to`.
    async fn push_cached(&self, parent: &str, key: &str, id: &str) -> BuildResult<()> {
        for repository in &self.opts.flags.cache_to {
            let reference = cache_reference(repository, parent, key)?;
            let access = access_for(
                &self.svc.image_service,
                &self.opts.access,
                self.opts.credentials.as_ref(),
                &reference,
                true,
            )
            .await?;
            let opts = crate::services::PushOptions {
                tls_verify: self.opts.tls_verify,
                access,
                destination: Some(reference.clone()),
                ..Default::default()
            };
            self.cancel
                .unless(self.svc.image_service.push_with(id, &opts))
                .await
                .ok_or(BuildError::Cancelled)?
                .map_err(|e| {
                    BuildError::StepFailed(redact::urls(&format!(
                        "pushing the cache image {reference}: {e}"
                    )))
                })?;
        }
        Ok(())
    }

    /// Commit `changes` (none: the configuration only) as the next image of
    /// the stage, recorded in the build cache with `key`.
    async fn commit(
        &mut self,
        st: &mut StageState,
        created_by: &str,
        changes: Option<Changes>,
        walk: dirtar::Options,
        key: Option<&str>,
    ) -> BuildResult<()> {
        let parent = st
            .image
            .clone()
            .unwrap_or_else(|| velarx_db::BUILD_SCRATCH.to_string());
        let (progress, forwarded) = self.blobs();
        let mut walk = walk;
        walk.mtime = self.mtime();
        let (mut edits, after, added) = self.layer_label_edits(st).await?;
        st.layer_added = added;
        edits.extend_from_slice(st.pending());
        st.committed = st.edits.len();
        edits.extend(after);
        let mut opts = CommitOptions {
            edits,
            author: st.author.clone(),
            created_by: created_by.to_string(),
            digest: Some(self.digest),
            walk,
            created: self.created(),
            omit_history: self.opts.flags.omit_history,
            hold: self.hold_name.clone(),
            platform: self.platform.clone(),
            progress: Some(progress),
            cancel: self.cancel.clone(),
            ..CommitOptions::default()
        };
        self.final_commit(st, &mut opts);
        let id = self
            .svc
            .image_service
            .commit_changes(st.image.as_deref(), changes, &opts)
            .await;
        drop(opts);
        let _ = forwarded.await;
        let id = id.map_err(|e| self.stopped(e))?;
        self.say_commit(st).await;
        self.say(format!("--> {}\n", &id[..12.min(id.len())])).await;
        self.intermediates.push(id.clone());
        if let Some(key) = key.filter(|_| self.caching(st)) {
            self.svc
                .image_service
                .build_cache_put(&parent, key, &id)
                .await?;
            self.cached.insert(id.clone());
            self.push_cached(&parent, key, &id).await?;
        }
        st.image = Some(id);
        Ok(())
    }

    /// buildah's `COMMIT name` (the first name as given) before the id of
    /// the image of the build, after the progress of its commit: the
    /// output ends as buildah's.
    async fn say_commit(&mut self, st: &mut StageState) {
        if std::mem::take(&mut st.last_commit) {
            let name = self.opts.tags.first().map(|t| format!(" {t}"));
            self.say(format!("COMMIT{}\n", name.unwrap_or_default()))
                .await;
        }
    }

    async fn metadata(&mut self, st: &mut StageState, i: &Instr) -> BuildResult<()> {
        let esc = self.file.escape;
        let words = |st: &StageState| -> BuildResult<Vec<String>> {
            match &i.json {
                Some(v) => Ok(v.clone()),
                None => parse::split_words(&i.args, esc, &|n| st.lookup(n))
                    .map_err(|e| step_error(i, e)),
            }
        };
        let expand = |st: &StageState| {
            parse::expand(&i.args, esc, &|n| st.lookup(n)).map_err(|e| step_error(i, e))
        };
        match i.keyword.as_str() {
            "ENV" => {
                let w = words(st)?;
                let first = w
                    .first()
                    .ok_or_else(|| step_error(i, "ENV requires arguments"))?;
                let mut vars = Vec::new();
                if !first.contains('=') {
                    // ENV KEY value with spaces
                    let rest = i.args.trim_start()[i
                        .args
                        .trim_start()
                        .find(char::is_whitespace)
                        .unwrap_or(i.args.trim_start().len())..]
                        .trim_start();
                    let value = parse::expand(rest, esc, &|n| st.lookup(n))
                        .map_err(|e| step_error(i, e))?;
                    vars.push((first.clone(), value));
                } else {
                    for kv in &w {
                        match kv.split_once('=') {
                            Some((k, v)) if !k.is_empty() => {
                                vars.push((k.to_string(), v.to_string()))
                            }
                            _ => return Err(step_error(i, format!("invalid ENV `{kv}`"))),
                        }
                    }
                }
                for (k, v) in &vars {
                    set_kv(&mut st.env, k, v.clone());
                }
                st.edit(ConfigEdit::Env(vars));
            }
            "ARG" => {
                for (name, value) in self.declare_args(i, &|n| st.lookup(n), &self.global_args)? {
                    set_kv(&mut st.args, &name, value);
                }
            }
            "WORKDIR" => {
                let v = expand(st)?;
                if v.is_empty() {
                    return Err(step_error(i, "WORKDIR requires an argument"));
                }
                let joined = if v.starts_with('/') {
                    v
                } else {
                    format!("{}/{v}", st.workdir)
                };
                st.workdir = velarx_wire::cp::clean_path(&joined);
                let w = st.workdir.clone();
                st.edit(ConfigEdit::Set("WorkingDir".into(), json!(w)));
                // (made owned by the USER of now, as buildah's: root when
                // the image does not know it)
                let owner = match st.user.as_str() {
                    "" => None,
                    user => self.chown_of(st, user).await.ok(),
                };
                self.make_dirs(st, i, &[w], owner).await?;
            }
            "USER" => {
                let v = expand(st)?;
                if v.is_empty() {
                    return Err(step_error(i, "USER requires an argument"));
                }
                st.user = v.clone();
                st.edit(ConfigEdit::Set("User".into(), json!(v)));
            }
            "STOPSIGNAL" => {
                let v = expand(st)?;
                if v.is_empty() {
                    return Err(step_error(i, "STOPSIGNAL requires an argument"));
                }
                if crate::services::lifecycle::parse_signal(&v).is_none() {
                    return Err(step_error(i, format!("invalid signal `{v}`")));
                }
                st.edit(ConfigEdit::Set("StopSignal".into(), json!(v)));
            }
            "SHELL" => {
                let shell = i
                    .json
                    .clone()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| step_error(i, "SHELL requires a JSON array"))?;
                st.shell = shell.clone();
                st.edit(ConfigEdit::Set("Shell".into(), json!(shell)));
            }
            "CMD" => {
                st.cmd_set = true;
                let argv = st.argv(i);
                st.edit(ConfigEdit::Set("Cmd".into(), json!(argv)));
            }
            "ENTRYPOINT" => {
                let argv = st.argv(i);
                st.edit(ConfigEdit::Set("Entrypoint".into(), json!(argv)));
                // ENTRYPOINT resets the CMD of the base image.
                if !st.cmd_set {
                    st.edit(ConfigEdit::Unset("Cmd".into()));
                }
            }
            "LABEL" => {
                let mut labels = Map::new();
                for w in words(st)? {
                    match w.split_once('=') {
                        Some((k, v)) if !k.is_empty() => {
                            labels.insert(k.to_string(), json!(v));
                        }
                        _ => return Err(step_error(i, format!("invalid LABEL `{w}`"))),
                    }
                }
                self.keep_identity(&mut labels);
                st.edit(ConfigEdit::Merge("Labels".into(), labels));
            }
            "EXPOSE" => {
                let mut ports = Map::new();
                for w in words(st)? {
                    let (port, proto) = w.split_once('/').unwrap_or((&w, "tcp"));
                    let valid = port.split('-').all(|p| p.parse::<u16>().is_ok())
                        && matches!(proto.to_ascii_lowercase().as_str(), "tcp" | "udp" | "sctp");
                    if !valid {
                        return Err(step_error(i, format!("invalid port `{w}`")));
                    }
                    ports.insert(format!("{port}/{}", proto.to_ascii_lowercase()), json!({}));
                }
                st.edit(ConfigEdit::Merge("ExposedPorts".into(), ports));
            }
            "VOLUME" => {
                let vols: Map<String, Value> = words(st)?
                    .into_iter()
                    .filter(|v| !v.is_empty())
                    .map(|v| (v, json!({})))
                    .collect();
                if vols.is_empty() {
                    return Err(step_error(i, "VOLUME requires an argument"));
                }
                let paths: Vec<String> = vols.keys().cloned().collect();
                st.edit(ConfigEdit::Merge("Volumes".into(), vols));
                self.make_dirs(st, i, &paths, None).await?;
            }
            "MAINTAINER" => st.author = Some(i.args.clone()),
            "HEALTHCHECK" => {
                let hc = self.healthcheck(i)?;
                st.edit(ConfigEdit::Set("Healthcheck".into(), hc));
            }
            "ONBUILD" => {
                st.onbuild.push(json!(i.args));
                let list = st.onbuild.clone();
                st.edit(ConfigEdit::Set("OnBuild".into(), Value::Array(list)));
            }
            other => {
                self.say(format!("WARNING: {other} is not supported, ignored\n"))
                    .await;
            }
        }
        Ok(())
    }

    /// The directories VOLUME or WORKDIR names that the image lacks are
    /// made in a layer, mode 0755 and owned by `owner` (else root), with the
    /// attributes the image has for their parents: a RUN step finds them,
    /// whether it mounts the volumes or not.
    async fn make_dirs(
        &mut self,
        st: &mut StageState,
        i: &Instr,
        paths: &[String],
        owner: Option<(u32, u32)>,
    ) -> BuildResult<()> {
        let tocs = match &st.image {
            Some(id) => {
                let rec = self.svc.image_service.get(id).await?;
                self.svc.image_service.layer_tocs(&rec).await?
            }
            None => Vec::new(),
        };
        let refs: Vec<&Toc> = tocs.iter().collect();
        let tree = MergedTree::build(&refs).map_err(BuildError::Parse)?;
        let mut missing: Vec<String> = Vec::new();
        for p in paths {
            let abs = if p.starts_with('/') {
                p.clone()
            } else {
                format!("{}/{p}", st.workdir)
            };
            let (resolved, node) = resolve_in_tree(&tree, &velarx_wire::cp::clean_path(&abs))
                .map_err(|e| step_error(i, e))?;
            if node.is_none() && !missing.contains(&resolved) {
                missing.push(resolved);
            }
        }
        if missing.is_empty() {
            return Ok(());
        }
        let source = self.new_dir("volume")?;
        let upper = self.new_dir("upper")?;
        let result = async {
            let mut job = CopyJob::new(Source::Context);
            job.chown = owner;
            job.chmod = Some(0o755);
            for (n, dir) in missing.iter().enumerate() {
                std::fs::create_dir(source.join(n.to_string()))?;
                job.items.push(Item {
                    src: n.to_string(),
                    dst: dir.clone(),
                    dest_dir: false,
                    ..Default::default()
                });
            }
            job.parents = Self::parents(&tree, &missing);
            let mut space = self.svc.scratch.reservation();
            job.limits = self.svc.job_limits(&mut space)?;
            self.svc
                .runner
                .run(job, &upper, JobSource::Dir(source.clone()), &self.cancel)
                .await
                .map_err(|e| self.failed(i, e))?;
            self.commit_copy(st, i, &upper, None, &tree).await?;
            match st.squash_dir.clone() {
                Some(sq) => self.merge_squash(&upper, &sq, &dirtar::Options::default()),
                None => Ok(()),
            }
        }
        .await;
        remove_dir(&source);
        remove_dir(&upper);
        result
    }

    fn healthcheck(&self, i: &Instr) -> BuildResult<Value> {
        i.check_flags(&[
            "interval",
            "timeout",
            "start-period",
            "start-interval",
            "retries",
        ])
        .map_err(BuildError::Parse)?;
        if i.args.trim().eq_ignore_ascii_case("NONE") {
            return Ok(json!({"Test": ["NONE"]}));
        }
        let rest = i.args.trim_start();
        let Some(cmd) = rest
            .get(..3)
            .filter(|k| k.eq_ignore_ascii_case("CMD"))
            .map(|_| rest[3..].trim_start())
        else {
            return Err(step_error(i, "HEALTHCHECK requires NONE or CMD"));
        };
        let test = match parse::json_array(cmd) {
            Some(mut v) => {
                v.insert(0, "CMD".into());
                v
            }
            None => vec!["CMD-SHELL".into(), cmd.to_string()],
        };
        let mut hc = Map::new();
        hc.insert("Test".into(), json!(test));
        for (flag, key) in [
            ("interval", "Interval"),
            ("timeout", "Timeout"),
            ("start-period", "StartPeriod"),
            ("start-interval", "StartInterval"),
        ] {
            if let Some(v) = i.flag(flag) {
                let ns = health_duration_ns(v)
                    .ok_or_else(|| step_error(i, format!("invalid --{flag} `{v}`")))?;
                hc.insert(key.into(), json!(ns));
            }
        }
        if let Some(r) = i.flag("retries") {
            let n: u32 = r
                .parse()
                .map_err(|_| step_error(i, format!("invalid --retries `{r}`")))?;
            hc.insert("Retries".into(), json!(n));
        }
        Ok(Value::Object(hc))
    }

    /// Start a container, show its output, wait for it to end.
    async fn run_container(&self, id: &str) -> BuildResult<i32> {
        /// What the thread reading the standard input of the client tells.
        type Chunks = tokio::sync::mpsc::Receiver<Vec<u8>>;
        /// The standard input of the client, read in a thread of its own
        /// that waits for it to be readable (the descriptor is the client's,
        /// shared with its other processes: it is never made non-blocking)
        /// and stops when the step is over: the second is its owner.
        fn read_input(
            fd: Arc<std::os::fd::OwnedFd>,
        ) -> std::io::Result<(Chunks, std::os::fd::OwnedFd)> {
            use rustix::event::{poll, PollFd, PollFlags};
            let (stop_read, stop_write) =
                rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            std::thread::Builder::new()
                .name("build-stdin".into())
                .spawn(move || loop {
                    let mut fds = [
                        PollFd::new(&*fd, PollFlags::IN),
                        PollFd::new(&stop_read, PollFlags::IN),
                    ];
                    match poll(&mut fds, None) {
                        Err(rustix::io::Errno::INTR) => continue,
                        Err(_) => return,
                        Ok(_) => {}
                    }
                    if !fds[1].revents().is_empty() {
                        return;
                    }
                    let mut buf = vec![0u8; 8192];
                    match rustix::io::read(&*fd, &mut buf) {
                        Ok(n) if n > 0 => {
                            buf.truncate(n);
                            if tx.blocking_send(buf).is_err() {
                                return;
                            }
                        }
                        Err(rustix::io::Errno::INTR | rustix::io::Errno::AGAIN) => {}
                        _ => return,
                    }
                })?;
            Ok((rx, stop_write))
        }

        use crate::services::AttachEvent;
        let cs = &self.svc.container_service;
        let dir = cs.start_with(id, true).await?;
        let mut stream = cs
            .attach_stream(
                &dir,
                &velarx_wire::monitor::proto::Attach {
                    start: true,
                    stdin: self.opts.stdin.is_some(),
                    ..Default::default()
                },
            )
            .await?;
        // the standard input of the client, read while the step runs
        let (mut input_rx, _input_stop) = match &self.opts.stdin {
            Some(fd) => {
                let (rx, stop) = read_input(fd.clone())?;
                (Some(rx), Some(stop))
            }
            None => (None, None),
        };
        let mut pipe = stream.input();
        let mut cancel = self.cancel.clone();
        let mut killed = false;
        let code = loop {
            if pipe.take_end() {
                let _ = stream.eof().await;
            }
            let event = tokio::select! {
                e = stream.next() => e,
                r = pipe.flush(), if !pipe.is_empty() => {
                    // the step takes no more input
                    if r.is_err() {
                        input_rx = None;
                    }
                    continue;
                }
                chunk = async {
                    match input_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                }, if pipe.is_empty() => {
                    match chunk {
                        Some(data) => pipe.queue(&data),
                        None => {
                            input_rx = None;
                            pipe.end();
                        }
                    }
                    continue;
                }
                () = cancel.wait(), if !killed => {
                    killed = true;
                    if let Err(e) = cs.kill(id, "SIGKILL").await {
                        warn!("Cannot kill the build container {id}: {e}");
                    }
                    continue;
                }
            };
            match event {
                Ok(Some(AttachEvent::Stdout(d))) => self.run_output(false, &d).await,
                Ok(Some(AttachEvent::Stderr(d))) => self.run_output(true, &d).await,
                Ok(Some(AttachEvent::Exit(code))) => break code,
                Ok(None) | Err(_) => break cs.wait(id).await?,
            }
        };
        // The container is stopped (its root file system unmounted) before
        // its upper directory is read.
        let _ = cs.wait(id).await?;
        if killed {
            return Err(BuildError::Cancelled);
        }
        Ok(code)
    }

    /// The owner of `--chown`: numbers, or names of the current image.
    async fn chown_of(&self, st: &StageState, spec: &str) -> BuildResult<(u32, u32)> {
        let image = st.image.clone();
        let tocs = match &image {
            Some(id) => {
                let rec = self.svc.image_service.get(id).await?;
                self.svc.image_service.layer_tocs(&rec).await?
            }
            None => Vec::new(),
        };
        let store = self.svc.image_service.clone();
        let spec = spec.to_string();
        tokio::task::spawn_blocking(move || {
            with_image_view(&tocs, &store, |_, view| {
                velarx_wire::cp::user_of(&spec, |p| view.read_file(p, velarx_wire::cp::MAX_ID_FILE))
            })
        })
        .await
        .map_err(std::io::Error::other)?
        .map_err(|e| BuildError::StepFailed(format!("--chown: {e}")))
    }

    /// The attributes the current image has for the directories on the way
    /// to `paths`.
    fn parents(tree: &MergedTree, paths: &[String]) -> Vec<ParentDir> {
        let mut out: Vec<ParentDir> = Vec::new();
        for p in paths {
            let mut node = velarx_fuse::ROOT;
            let mut so_far = String::new();
            for c in p.split('/').filter(|c| !c.is_empty()) {
                let Some(n) = tree.lookup(node, c) else { break };
                let Some(e) = tree.node(n).map(|n| &n.entry) else {
                    break;
                };
                if e.entry_type != TocEntryType::Dir {
                    break;
                }
                so_far.push('/');
                so_far.push_str(c);
                if !out.iter().any(|d| d.path == so_far) {
                    out.push(ParentDir {
                        path: so_far.clone(),
                        mode: e.mode & 0o7777,
                        uid: e.uid,
                        gid: e.gid,
                        mtime: crate::services::imagecopy::mtime(e).tv_sec,
                    });
                }
                node = n;
            }
        }
        out
    }

    async fn copy_step(&mut self, st: &mut StageState, i: &Instr) -> BuildResult<()> {
        let add = i.keyword == "ADD";
        if add
            && i.flags
                .iter()
                .any(|f| f == "--parents" || f.starts_with("--parents="))
        {
            return Err(step_error(
                i,
                "ADD only supports the --chmod=<permissions>, --chown=<uid:gid>, --checksum=<checksum>, --link, --keep-git-dir, and --exclude=<pattern> flags",
            ));
        }
        // (`--link` is accepted and changes nothing: the layer of a COPY
        // holds the files it copies and their parent directories only,
        // never the content of the base, and the build cache keeps a step
        // with the image it follows.  Unlike BuildKit, the symbolic links
        // of the base on the way to the destination are followed.)
        let allowed: &[&str] = if add {
            &[
                "chown",
                "chmod",
                "link",
                "checksum",
                "keep-git-dir",
                "exclude",
            ]
        } else {
            &["from", "chown", "chmod", "link", "parents", "exclude"]
        };
        i.check_flags(allowed).map_err(BuildError::Parse)?;
        let esc = self.file.escape;
        let parents_flag = i.flag_bool("parents").map_err(BuildError::Parse)?;
        let excludes: Vec<String> = i
            .flag_values("exclude")
            .into_iter()
            .map(|e| parse::expand(e, esc, &|n| st.lookup(n)))
            .collect::<Result<_, _>>()
            .map_err(|e| step_error(i, e))?;
        let words: Vec<String> = match &i.json {
            Some(v) => v
                .iter()
                .map(|w| parse::expand(w, esc, &|n| st.lookup(n)))
                .collect::<Result<_, _>>(),
            None => parse::split_words(&i.args, esc, &|n| st.lookup(n)),
        }
        .map_err(|e| step_error(i, e))?;
        let Some((dest, sources)) = words.split_last().filter(|(_, s)| !s.is_empty()) else {
            return Err(step_error(
                i,
                format!("{} requires a source and a destination", i.keyword),
            ));
        };
        if dest.is_empty() {
            return Err(step_error(i, "empty destination"));
        }
        let flag = |name: &str| -> BuildResult<Option<String>> {
            i.flag(name)
                .map(|v| parse::expand(v, esc, &|n| st.lookup(n)))
                .transpose()
                .map_err(|e| step_error(i, e))
        };
        let chown = match flag("chown")? {
            Some(spec) => Some(self.chown_of(st, &spec).await?),
            None => None,
        };
        let chmod = match flag("chmod")? {
            Some(m) => Some(
                u32::from_str_radix(&m, 8)
                    .ok()
                    .filter(|m| *m <= 0o7777)
                    .ok_or_else(|| step_error(i, format!("invalid --chmod `{m}`")))?,
            ),
            None => None,
        };
        let joined = if dest.starts_with('/') {
            dest.clone()
        } else {
            format!("{}/{dest}", st.workdir)
        };
        // The current image: the links on the way to the destination and
        // the attributes of its directories.
        let tocs = match &st.image {
            Some(id) => {
                let rec = self.svc.image_service.get(id).await?;
                self.svc.image_service.layer_tocs(&rec).await?
            }
            None => Vec::new(),
        };
        let refs: Vec<&Toc> = tocs.iter().collect();
        let tree = MergedTree::build(&refs).map_err(BuildError::Parse)?;
        // `.`, `x/` or a directory of the image: the sources go into it.
        let named_dir = dest.ends_with('/')
            || dest == "."
            || dest == ".."
            || dest.ends_with("/.")
            || dest.ends_with("/..");
        let (dst, is_dir) = resolve_dest(&tree, &velarx_wire::cp::clean_path(&joined))
            .map_err(|e| step_error(i, e))?;
        let dest_dir = named_dir || is_dir || sources.len() > 1 || dst == "/";
        // (buildah: a destination that is no directory gets the file as it
        // is, but not with --parents)
        if parents_flag && !is_dir && is_file_in_tree(&tree, &dst) {
            return Err(step_error(
                i,
                format!("destination {dest} already exists but is not a directory"),
            ));
        }
        let parents = parents_flag && dest_dir;
        let pivot_of = |s: &str| -> Option<usize> { parents.then(|| pivot(s)) };

        // The here-documents: files of their own.
        let (docs, sources): (Vec<&String>, Vec<&String>) = sources
            .iter()
            .partition(|s| i.heredocs.iter().any(|_| i.heredoc_of(s).is_some()));
        let sources: Vec<String> = sources.into_iter().cloned().collect();
        let sources = sources.as_slice();
        if !docs.is_empty() && i.flag("from").is_some() {
            return Err(step_error(
                i,
                "here-documents cannot be copied --from a stage",
            ));
        }
        let mut heredoc_dir = None;
        let mut heredoc_items = Vec::new();
        for d in &docs {
            let h = i
                .heredoc_of(d)
                .ok_or_else(|| step_error(i, format!("no here-document {d}")))?;
            let content = if h.expand {
                parse::expand(&h.content(), esc, &|n| st.lookup(n)).map_err(|e| step_error(i, e))?
            } else {
                h.content()
            };
            let dir = match &heredoc_dir {
                Some(d) => d,
                None => heredoc_dir.insert(self.new_dir("heredoc")?),
            };
            let name = h.file_name();
            std::fs::write(dir.join(&name), content.as_bytes())?;
            heredoc_items.push(Item {
                src: name,
                dst: dst.clone(),
                dest_dir,
                ..Default::default()
            });
        }

        // The git repositories (ADD), apart from the URLs.
        let mut gits = Vec::new();
        for s in sources {
            match git::parse(s) {
                Some(Ok(g)) if add => gits.push(g),
                Some(Ok(_)) => return Err(step_error(i, "COPY of a git repository: use ADD")),
                Some(Err(e)) => return Err(step_error(i, e)),
                None => {}
            }
        }
        let is_git = |s: &str| git::parse(s).is_some();
        let is_url = |s: &str| is_url(s) && !is_git(s);
        let keep_git_dir = match flag("keep-git-dir")?.as_deref() {
            None | Some("false") => false,
            Some("" | "true") => true,
            Some(v) => return Err(step_error(i, format!("invalid --keep-git-dir `{v}`"))),
        };
        let checksum = flag("checksum")?;
        let checksum = checksum.as_deref();
        if checksum.is_some() && !sources.iter().all(|s| is_url(s)) {
            return Err(step_error(
                i,
                "--checksum is only for sources that are URLs",
            ));
        }
        let upper = self.new_dir("upper")?;
        let mut jobs = Vec::new();
        let mut downloads = None;
        let mut clones = Vec::new();
        let mut from_image = None;
        match i.flag("from") {
            None => {
                // ADD of git repositories: cloned in the confined helper,
                // their content (or the subdirectory named) copied.
                for g in gits {
                    let dir = self.new_dir("git")?;
                    clones.push(dir.clone());
                    self.clone_git(&g, &dir, keep_git_dir)
                        .await
                        .map_err(|e| self.failed(i, e))?;
                    let job = CopyJob {
                        source: Source::Context,
                        parents: Vec::new(),
                        items: vec![Item {
                            src: g.subdir.clone(),
                            dst: dst.clone(),
                            dest_dir: true,
                            ..Default::default()
                        }],
                        chown,
                        chmod,
                        ignore: Vec::new(),
                        add: false,
                        limits: self.svc.limits,
                        digest: false,
                        unchanged_since: None,
                    };
                    jobs.push((job, JobSource::Dir(dir)));
                }
                // ADD of URLs: downloaded here, copied as they are.
                let urls: Vec<&String> = sources.iter().filter(|s| is_url(s)).collect();
                if !urls.is_empty() {
                    if !add {
                        return Err(step_error(i, "source can't be a URL for COPY: use ADD"));
                    }
                    let dir = self.new_dir("download")?;
                    downloads = Some(dir.clone());
                    let mut items = Vec::new();
                    for (n, url) in urls.iter().enumerate() {
                        let name = self
                            .download(url, &dir.join(n.to_string()), checksum)
                            .await
                            .map_err(|e| self.failed(i, e))?;
                        items.push(Item {
                            src: format!("{n}/{name}"),
                            dst: dst.clone(),
                            dest_dir,
                            ..Default::default()
                        });
                    }
                    let job = CopyJob {
                        source: Source::Context,
                        parents: Vec::new(),
                        items,
                        chown,
                        chmod,
                        ignore: Vec::new(),
                        add: false,
                        limits: self.svc.limits,
                        digest: false,
                        unchanged_since: None,
                    };
                    jobs.push((job, JobSource::Dir(dir)));
                }
                let mut items = Vec::new();
                for s in sources.iter().filter(|s| !is_url(s) && !is_git(s)) {
                    if s.contains("://") {
                        return Err(step_error(
                            i,
                            format!("{} from a `{s}` URL is not supported", i.keyword),
                        ));
                    }
                    items.push(Item {
                        src: context_relative(s).map_err(|e| step_error(i, e))?,
                        dst: dst.clone(),
                        dest_dir,
                        pivot: pivot_of(s),
                        ..Default::default()
                    });
                }
                if let Some(dir) = &heredoc_dir {
                    let job = CopyJob {
                        source: Source::Context,
                        parents: Vec::new(),
                        items: std::mem::take(&mut heredoc_items),
                        chown,
                        chmod,
                        ignore: Vec::new(),
                        add: false,
                        limits: self.svc.limits,
                        digest: false,
                        unchanged_since: None,
                    };
                    jobs.push((job, JobSource::Dir(dir.clone())));
                }
                if !items.is_empty() {
                    let job = CopyJob {
                        source: Source::Context,
                        parents: Vec::new(),
                        items,
                        chown,
                        chmod,
                        ignore: self
                            .ignore
                            .lines()
                            .into_iter()
                            .chain(excludes.clone())
                            .collect(),
                        add,
                        limits: self.svc.limits,
                        digest: false,
                        unchanged_since: None,
                    };
                    jobs.push((job, JobSource::Fd(self.ctx.fd()?)));
                }
            }
            Some(from) => {
                let from =
                    parse::expand(from, esc, &|n| st.lookup(n)).map_err(|e| step_error(i, e))?;
                // A named context of the build: a directory, or an image.
                let from = match self.opts.contexts.get(&from) {
                    Some(NamedContext::Dir(dir)) => {
                        let mut items = Vec::new();
                        for s in sources {
                            items.push(Item {
                                src: context_relative(s).map_err(|e| step_error(i, e))?,
                                dst: dst.clone(),
                                dest_dir,
                                pivot: pivot_of(s),
                                ..Default::default()
                            });
                        }
                        let job = CopyJob {
                            source: Source::Context,
                            parents: Vec::new(),
                            items,
                            chown,
                            chmod,
                            ignore: excludes.clone(),
                            add,
                            limits: self.svc.limits,
                            digest: false,
                            unchanged_since: None,
                        };
                        jobs.push((job, JobSource::Dir(dir.clone())));
                        None
                    }
                    Some(NamedContext::Image(image)) => Some(image.clone()),
                    None => Some(from),
                };
                if let Some(from) = from {
                    let image = match self.stage_image(&from, st.index) {
                        Some(id) => id,
                        None => {
                            let from = self.judged(&from, "the COPY --from image").await?;
                            self.ensure_image(&from, self.opts.platform.as_deref())
                                .await?
                        }
                    };
                    // Read once the cache was asked: its files are not
                    // read for a step it has.
                    from_image = Some(image);
                }
            }
        };
        // The files of a context have a digest before they are copied, an
        // image is its manifest's: a step the cache has is not copied at
        // all.
        let mut key = None;
        let from_dirs = jobs
            .iter()
            .all(|(j, s)| j.source == Source::Context && s.is_tree());
        // (taken before the digests: a file changed from then on and copied
        // makes the copy say so, see below)
        let since = change_horizon();
        if self.caching(st) && from_dirs {
            let mut parts = Vec::new();
            if let Some(image) = &from_image {
                let rec = match self.svc.image_service.get(image).await {
                    Ok(rec) => rec,
                    Err(e) => {
                        cleanup_copy(&upper, downloads.as_deref(), &clones);
                        return Err(e.into());
                    }
                };
                parts.push(json!({
                    "image": rec.manifest_digest,
                    "sources": sources,
                    "dst": dst,
                    "dest_dir": dest_dir,
                    "chown": chown,
                    "chmod": chmod,
                }));
            }
            for (job, source) in &jobs {
                let paths = item_paths(job);
                let job = CopyJob {
                    parents: Self::parents(&tree, &paths),
                    limits: copy::Limits::default(),
                    ..job.clone()
                };
                let digest = self
                    .svc
                    .runner
                    .digest(job.clone(), &upper, source.duplicate()?, &self.cancel)
                    .await
                    .map_err(|e| self.failed(i, e));
                let digest = match digest {
                    Ok(d) => d,
                    Err(e) => {
                        cleanup_copy(&upper, downloads.as_deref(), &clones);
                        return Err(e);
                    }
                };
                parts.push(json!({ "job": job, "digest": digest }));
            }
            let k = self.cache_key(st, &i.raw_text(), json!({ "sources": parts }))?;
            if self.use_cache(st, &k).await? {
                cleanup_copy(&upper, downloads.as_deref(), &clones);
                return Ok(());
            }
            key = Some(k);
        }
        let mut archive_end = None;
        if let Some(image) = &from_image {
            match self
                .image_sources(
                    image,
                    sources,
                    ImageDest {
                        dst: &dst,
                        dest_dir,
                        chown,
                        chmod,
                        parents,
                        excludes: &excludes,
                    },
                    i,
                )
                .await
            {
                Ok((job, source, end)) => {
                    jobs.push((job, source));
                    archive_end = Some(end);
                }
                Err(e) => {
                    cleanup_copy(&upper, downloads.as_deref(), &clones);
                    return Err(e);
                }
            }
        }
        let mut space = self.svc.scratch.reservation();
        let mut ran = Ok(());
        for (job, source) in jobs {
            let paths = item_paths(&job);
            let job = CopyJob {
                parents: Self::parents(&tree, &paths),
                limits: self.svc.job_limits(&mut space)?,
                unchanged_since: key.is_some().then_some(since),
                ..job
            };
            ran = match self.svc.runner.run(job, &upper, source, &self.cancel).await {
                // A file of the context changed between its digest and its
                // copy: what was copied is not what the key says, and is
                // recorded under the digest of what it is.
                Ok(true) => {
                    key = None;
                    Ok(())
                }
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            };
            space.set(disk_usage(&upper)?)?;
            if ran.is_err() {
                break;
            }
        }
        if let Some(d) = &downloads {
            remove_dir(d);
        }
        if let Some(d) = &heredoc_dir {
            remove_dir(d);
        }
        for d in &clones {
            remove_dir(d);
        }
        let ran = ran
            .map_err(|e| self.failed(i, e))
            .and_then(|()| archive_end.map_or(Ok(()), |end| end.check(i)));
        let r = match ran {
            Ok(()) => {
                space.set(disk_usage(&upper)?)?;
                let r = self.commit_copy(st, i, &upper, key, &tree).await;
                match (st.squash_dir.clone(), r) {
                    (Some(sq), Ok(())) => {
                        self.merge_squash(&upper, &sq, &dirtar::Options::default())
                    }
                    (_, r) => r,
                }
            }
            Err(e) => Err(e),
        };
        remove_dir(&upper);
        drop(space);
        r
    }

    /// Commit what a COPY or ADD put in `upper`, or take the image of the
    /// build cache for the same files on the same image.  `key`: the key
    /// of the step, known before the copy; `tree`: the files it was copied
    /// into.
    async fn commit_copy(
        &mut self,
        st: &mut StageState,
        i: &Instr,
        upper: &Path,
        key: Option<String>,
        tree: &MergedTree,
    ) -> BuildResult<()> {
        let key = if key.is_some() {
            key
        } else if self.caching(st) {
            let dir = upper.to_path_buf();
            let files = tokio::task::spawn_blocking(move || tree_digest(&dir))
                .await
                .map_err(std::io::Error::other)??;
            let key = self.cache_key(st, &i.raw_text(), json!({ "files": files }))?;
            if self.use_cache(st, &key).await? {
                return Ok(());
            }
            Some(key)
        } else {
            None
        };
        self.commit(
            st,
            &created_by(i),
            Some(Changes::Dir(upper.to_path_buf())),
            files_onto(tree),
            key.as_deref(),
        )
        .await
    }

    /// Merge an upper directory into the --squash directory, whose space
    /// is counted.
    fn merge_squash(
        &mut self,
        upper: &Path,
        squash: &Path,
        walk: &dirtar::Options,
    ) -> BuildResult<()> {
        squash::merge(upper, squash, walk)?;
        self.squash_space.set(disk_usage(squash)?)?;
        Ok(())
    }

    /// The tar stream of the sources in the image `image`, for the worker.
    /// The error of the archive after its item list is told by the third
    /// value, which the caller asks once the worker is done: the stream
    /// alone ends as a clean one.
    async fn image_sources(
        &self,
        image: &str,
        sources: &[String],
        dest: ImageDest<'_>,
        i: &Instr,
    ) -> BuildResult<(CopyJob, JobSource, ArchiveEnd)> {
        let ImageDest {
            dst,
            dest_dir,
            chown,
            chmod,
            parents,
            excludes,
        } = dest;
        // The files of the image stay in the store while they are read: the
        // lock is taken before the image is looked at, not after (a removal
        // in between would take the files).
        let lock = self.svc.image_service.lock_store().await?;
        let rec = self.svc.image_service.get(image).await?;
        let tocs = self.svc.image_service.layer_tocs(&rec).await?;
        let store = self.svc.image_service.clone();
        let patterns: Vec<String> = sources.to_vec();
        let pivots: Vec<usize> = patterns.iter().map(|p| pivot(p)).collect();
        // Check the sources first: a missing one is an error of the step.
        let (tx_items, rx_items) = std::sync::mpsc::channel::<std::io::Result<Vec<Item>>>();
        let (reader, writer) = std::io::pipe()?;
        let dst = dst.to_string();
        std::thread::Builder::new()
            .name("build-from".into())
            .spawn(move || {
                let _lock = lock;
                let r = with_image_view(&tocs, &store, |tree, view| {
                    // The globs, matched in the image.
                    let mut sources = Vec::new();
                    let mut source_pivots = Vec::new();
                    for (p, pivot) in patterns.iter().zip(&pivots) {
                        if !parse::has_glob(p) {
                            sources.push(velarx_wire::cp::clean_path(p));
                            source_pivots.push(*pivot);
                            continue;
                        }
                        let found = glob_in_tree(tree, p).map_err(std::io::Error::other)?;
                        if found.is_empty() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                format!("`{p}`: no such file or directory"),
                            ));
                        }
                        source_pivots.extend(std::iter::repeat_n(*pivot, found.len()));
                        sources.extend(found);
                    }
                    let several = sources.len() > 1;
                    let mut items = Vec::new();
                    for (s, pivot) in sources.iter().zip(&source_pivots) {
                        let (stat, _) = view
                            .stat(s)
                            .map_err(|e| std::io::Error::new(e.kind(), format!("`{s}`: {e}")))?;
                        let base = s
                            .trim_end_matches('/')
                            .rsplit('/')
                            .next()
                            .unwrap_or_default();
                        let kept: Vec<&str> = s
                            .split('/')
                            .filter(|c| !c.is_empty())
                            .skip(*pivot)
                            .collect();
                        let target = if parents && !kept.is_empty() {
                            velarx_wire::cp::clean_path(&format!("{dst}/{}", kept.join("/")))
                        } else if stat.is_dir || !(dest_dir || several) {
                            dst.clone()
                        } else {
                            velarx_wire::cp::clean_path(&format!("{dst}/{base}"))
                        };
                        items.push(Item {
                            src: s.clone(),
                            dst: target,
                            dest_dir: false,
                            origin: s.trim_start_matches('/').to_string(),
                            ..Default::default()
                        });
                    }
                    let _ = tx_items.send(Ok(items));
                    let mut b = tar::Builder::new(std::io::BufWriter::new(writer));
                    for (n, s) in sources.iter().enumerate() {
                        view.archive(
                            &mut b,
                            s,
                            Path::new(&n.to_string()),
                            false,
                            &velarx_wire::cp::IdMaps::default(),
                        )?;
                    }
                    b.into_inner()?;
                    Ok(())
                });
                if let Err(e) = r {
                    let _ = tx_items.send(Err(e));
                }
            })?;
        let items = rx_items
            .recv()
            .map_err(|_| step_error(i, "the sources could not be read"))?
            .map_err(|e| step_error(i, e))?;
        let job = CopyJob {
            source: Source::Tar,
            items,
            chown,
            chmod,
            parents: Vec::new(),
            ignore: excludes.to_vec(),
            add: false,
            limits: self.svc.limits,
            digest: false,
            unchanged_since: None,
        };
        Ok((
            job,
            JobSource::Stream(OwnedFd::from(reader)),
            ArchiveEnd(rx_items),
        ))
    }

    async fn cleanup(&mut self, keep: Option<&str>) {
        for id in std::mem::take(&mut self.intermediates) {
            if Some(id.as_str()) == keep || self.cached.contains(&id) {
                continue;
            }
            if let Err(e) = self.svc.image_service.remove(&id, true).await {
                warn!("Cannot remove the intermediate image {id}: {e}");
            }
        }
        drop(self.hold.take());
        info!("Build in {} done", self.work.path().display());
    }
}

/// Whether the image is for `platform` (any if none).
fn platform_matches(
    image: &velarx_db::ImageRecord,
    platform: Option<&velarx_registry::target::Platform>,
) -> bool {
    let Some(platform) = platform else {
        return true;
    };
    let Ok(config) = serde_json::from_str::<Value>(&image.config) else {
        return false;
    };
    let field = |k: &str| config.get(k).and_then(Value::as_str);
    platform.matches(
        field("os").unwrap_or("linux"),
        field("architecture").unwrap_or(""),
        field("variant"),
    )
}

/// The platform arguments every build has (`FROM --platform=$BUILDPLATFORM`,
/// `ARG TARGETARCH`): of the platform the image is for (the build's
/// platform, else the host's) and of the host; a `--build-arg` of a name
/// overrides it.
fn platform_args(
    target: Option<&velarx_registry::target::Platform>,
    build_args: &HashMap<String, String>,
) -> Vec<(String, Option<String>)> {
    use velarx_registry::target::Platform;
    let host = Platform::host();
    let mut out = Vec::new();
    for (prefix, p) in [("TARGET", target.unwrap_or(&host)), ("BUILD", &host)] {
        let variant = p.variant.clone().unwrap_or_default();
        let all = [
            ("PLATFORM", p.to_string()),
            ("OS", p.os.clone()),
            ("ARCH", p.arch.clone()),
            ("VARIANT", variant),
        ];
        for (suffix, value) in all {
            let name = format!("{prefix}{suffix}");
            let value = build_args.get(&name).cloned().unwrap_or(value);
            out.push((name, Some(value)));
        }
    }
    out
}

/// The base images of the stages (not scratch, not an earlier stage), the
/// global arguments expanded as the build expands them; `from` (`--from`)
/// is the base of the first stage.
fn base_images(
    file: &Containerfile,
    build_args: &HashMap<String, String>,
    platform: Option<&velarx_registry::target::Platform>,
    from: Option<&str>,
) -> BuildResult<Vec<String>> {
    let predefined = platform_args(platform, build_args);
    let mut globals = predefined.clone();
    for i in &file.global_args {
        let words = parse::split_words(&i.args, file.escape, &lookup(&globals));
        for w in words.map_err(BuildError::Parse)? {
            let (name, default) = match w.split_once('=') {
                Some((n, d)) => (n.to_string(), Some(d.to_string())),
                None => (w.clone(), None),
            };
            let value = build_args
                .get(&name)
                .cloned()
                .or_else(|| lookup(&predefined)(&name))
                .or(default);
            set_kv(&mut globals, &name, value);
        }
    }
    let lookup = lookup(&globals);
    let mut out: Vec<String> = Vec::new();
    for (i, stage) in file.stages.iter().enumerate() {
        let base = match (from, i) {
            // `--from`: the base of the first stage
            (Some(from), 0) => from.to_string(),
            _ => parse::expand(&stage.base, file.escape, &lookup).map_err(BuildError::Parse)?,
        };
        let earlier = stage_before(&file.stages, &base, i).is_some();
        if base != "scratch" && !earlier && !out.contains(&base) {
            out.push(base);
        }
    }
    Ok(out)
}

/// `--source-policy-file`, read.
fn source_policy(opts: &BuildOptions) -> BuildResult<Option<Arc<policy::SourcePolicy>>> {
    Ok(opts
        .flags
        .source_policy
        .as_deref()
        .map(policy::SourcePolicy::parse)
        .transpose()
        .map_err(BuildError::Parse)?
        .map(Arc::new))
}

/// The image `reference` as the source `policy` has it, an error if it is
/// denied; `what` says what the build takes it for.  A short name is
/// decided, and then pulled, by the one name it stands for.
async fn judge(
    policy: Option<&policy::SourcePolicy>,
    images: &ImageService,
    reference: &str,
    what: &str,
) -> BuildResult<String> {
    let Some(policy) = policy else {
        return Ok(reference.to_string());
    };
    let name = images.qualify(reference).await?;
    match policy.decide(&name) {
        policy::Decision::Keep => Ok(name),
        policy::Decision::Convert(to) => Ok(to),
        policy::Decision::Deny(rule) => Err(BuildError::Parse(format!(
            "{what} {name} is denied by the source policy: {rule}"
        ))),
    }
}

/// The platform of an instance of an index, as --all-platforms takes it:
/// none for an artifact, an unknown OS or an architecture Go does not
/// know; arm64/v8 is arm64, arm is arm/v7.
fn index_platform(instance: &Value) -> Option<velarx_registry::target::Platform> {
    const ARCHES: [&str; 24] = [
        "386",
        "amd64",
        "amd64p32",
        "arm",
        "armbe",
        "arm64",
        "arm64be",
        "loong64",
        "mips",
        "mipsle",
        "mips64",
        "mips64le",
        "mips64p32",
        "mips64p32le",
        "ppc",
        "ppc64",
        "ppc64le",
        "riscv",
        "riscv64",
        "s390",
        "s390x",
        "sparc",
        "sparc64",
        "wasm",
    ];
    if instance["artifactType"]
        .as_str()
        .is_some_and(|a| !a.is_empty())
    {
        return None;
    }
    let p = instance.get("platform")?;
    let os = p["os"]
        .as_str()
        .filter(|o| !o.is_empty() && *o != "unknown")?;
    let arch = p["architecture"].as_str().filter(|a| !a.is_empty())?;
    let mut platform = velarx_registry::target::Platform::parse(&format!("{os}/{arch}")).ok()?;
    if !ARCHES.contains(&platform.arch.as_str()) {
        return None;
    }
    platform.variant = p["variant"]
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    match (platform.arch.as_str(), platform.variant.as_deref()) {
        ("arm64", Some("v8")) => platform.variant = None,
        ("arm", None) => platform.variant = Some("v7".into()),
        _ => {}
    }
    Some(platform)
}

/// The paths of the image `pattern` matches, sorted: its glob components
/// are matched against the names of the directories, resolved in the image
/// (links followed in it).
fn glob_in_tree(tree: &MergedTree, pattern: &str) -> Result<Vec<String>, String> {
    const MAX_MATCHES: usize = 100_000;
    let mut found = vec![String::new()];
    for c in pattern.split('/').filter(|c| !c.is_empty() && *c != ".") {
        if c == ".." {
            return Err(format!("`{pattern}` goes up"));
        }
        if !parse::has_glob(c) {
            for p in &mut found {
                p.push('/');
                p.push_str(c);
            }
            continue;
        }
        let mut next = Vec::new();
        for p in &found {
            let path = if p.is_empty() { "/" } else { p.as_str() };
            let Ok((_, Some(node))) = resolve_in_tree(tree, path) else {
                continue;
            };
            let Some(n) = tree.node(node) else { continue };
            if n.entry.entry_type != TocEntryType::Dir {
                continue;
            }
            for name in n.children.keys().filter(|name| parse::fnmatch(c, name)) {
                next.push(format!("{p}/{name}"));
                if next.len() > MAX_MATCHES {
                    return Err(format!("`{pattern}` matches too many files"));
                }
            }
        }
        found = next;
    }
    found.sort();
    Ok(found)
}

/// The destinations of the items of a job, and for `--parents` the leading
/// components of their sources that no glob changes: the directories the
/// copy may have to make.
fn item_paths(job: &CopyJob) -> Vec<String> {
    job.items
        .iter()
        .map(|i| match i.pivot {
            Some(pivot) => {
                let kept: Vec<&str> = i
                    .src
                    .split('/')
                    .filter(|c| !c.is_empty())
                    .skip(pivot)
                    .take_while(|c| !parse::has_glob(c))
                    .collect();
                velarx_wire::cp::clean_path(&format!("{}/{}", i.dst, kept.join("/")))
            }
            None => i.dst.clone(),
        })
        .collect()
}

/// `COPY --parents`: the number of components of the source before its
/// first `/./` (the path is kept from there), none when it has no mark.
fn pivot(source: &str) -> usize {
    let mut n = 0;
    for (i, c) in source.split('/').enumerate() {
        match c {
            "" => {}
            "." if i > 0 => return n,
            "." => {}
            _ => n += 1,
        }
    }
    0
}

/// A source of COPY as a path of its context, never above it.
fn context_relative(s: &str) -> Result<String, String> {
    let mut rel = Vec::new();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(format!("`{s}` is outside of the build context")),
            c => rel.push(c),
        }
    }
    Ok(rel.join("/"))
}

/// A source of ADD to download.
fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// The name of the file a URL gives (the last component of its path, without
/// the query and the fragment, percent-decoded).  The engine derives it
/// itself: it is a name in the build's directory, and what the fetcher sends
/// is not trusted for that.  An error for an empty one, `.`, `..`, or one
/// with a `/` or a NUL.
fn url_file_name(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| format!("unsupported URL `{}`", redact::urls(url)))?;
    let rest = rest.split(['#', '?']).next().unwrap_or_default();
    let path = rest.find('/').map_or("", |i| &rest[i..]);
    let last = path.rsplit('/').next().unwrap_or_default();
    let name = percent_encoding::percent_decode_str(last)
        .decode_utf8()
        .map_err(|e| format!("invalid file name in {}: {e}", redact::urls(url)))?
        .into_owned();
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(format!(
            "cannot determine a file name from {}",
            redact::urls(url)
        ));
    }
    Ok(name)
}

/// The digest of the files below `dir` as a layer has them (names, types,
/// owners, modes, link targets, xattrs, contents), but not their times: a
/// COPY of the same files on the same image is the same step even if a
/// directory it made is newer.
fn tree_digest(dir: &Path) -> std::io::Result<String> {
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let (reader, pipe) = std::io::pipe()?;
    let walker = std::thread::Builder::new()
        .name("build-digest".into())
        .spawn(move || -> std::io::Result<()> {
            let out = std::io::BufWriter::with_capacity(256 * 1024, pipe);
            dirtar::write(fd.as_fd(), &dirtar::Options::default(), out)
        })?;
    let hashed = tar_digest(std::io::BufReader::with_capacity(256 * 1024, reader));
    let walked = walker
        .join()
        .map_err(|_| std::io::Error::other("the walk of the directory panicked"))?;
    match (walked, hashed) {
        (Ok(()), r) => r,
        // The reader stopped: its error says why.
        (Err(e), Err(r)) if e.kind() == std::io::ErrorKind::BrokenPipe => Err(r),
        (Err(e), _) => Err(e),
    }
}

/// The digest of the entries of the tar stream `reader` (see
/// [`tree_digest`]).  The stream is read to its end: the archive ends at
/// its first zero block, but the writer still writes the second one and
/// its padding, which a reader that stopped there would leave it to write
/// into a closed pipe (a pipe smaller than what is left, as the kernel
/// makes them once the user has many, fails it with `BrokenPipe`).
fn tar_digest(reader: impl std::io::Read) -> std::io::Result<String> {
    let mut h = DigestWriter::new(Algorithm::Sha256);
    let mut archive = tar::Archive::new(reader);
    {
        let mut buf = vec![0u8; 64 * 1024];
        for entry in archive.entries()? {
            let mut e = entry?;
            let hd = e.header().clone();
            // Each field with its length: no two trees hash the same.
            let mut field = |b: &[u8]| {
                h.update(&(b.len() as u64).to_le_bytes());
                h.update(b);
            };
            field(&e.path_bytes());
            field(&[hd.entry_type().as_byte()]);
            field(&hd.mode()?.to_le_bytes());
            field(&hd.uid()?.to_le_bytes());
            field(&hd.gid()?.to_le_bytes());
            field(&e.link_name_bytes().unwrap_or_default());
            if matches!(
                hd.entry_type(),
                tar::EntryType::Block | tar::EntryType::Char
            ) {
                field(&hd.device_major()?.unwrap_or(0).to_le_bytes());
                field(&hd.device_minor()?.unwrap_or(0).to_le_bytes());
            }
            if let Some(exts) = e.pax_extensions()? {
                for ext in exts {
                    let ext = ext?;
                    field(ext.key_bytes());
                    field(ext.value_bytes());
                }
            }
            field(&e.size().to_le_bytes());
            loop {
                let n = e.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
            }
        }
    }
    std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
    Ok(h.finalize().to_string())
}

/// The node of a clean absolute path in the image, links followed
/// (absolute ones from the root of the image, `..` stopping there), and
/// the path it resolves to; `None` for the node of a path that does not
/// exist (its missing components are kept as they are).
fn resolve_in_tree(tree: &MergedTree, path: &str) -> Result<(String, Option<usize>), String> {
    const MAX_LINKS: usize = 40;
    let mut todo: Vec<String> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .map(str::to_string)
        .rev()
        .collect();
    // The components so far and their nodes (`None` past a missing one).
    let mut stack: Vec<(String, Option<usize>)> = Vec::new();
    let mut links = 0;
    while let Some(c) = todo.pop() {
        if c == ".." {
            stack.pop();
            continue;
        }
        let parent = match stack.last() {
            None => Some(velarx_fuse::ROOT),
            Some((_, n)) => *n,
        };
        let Some(node) = parent.and_then(|p| tree.lookup(p, &c)) else {
            stack.push((c, None));
            continue;
        };
        let entry = tree.node(node).map(|n| &n.entry);
        match entry {
            Some(e) if e.entry_type == TocEntryType::Symlink => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(format!("too many links to resolve `{path}`"));
                }
                let target = e.link_name.clone().unwrap_or_default();
                if target.starts_with('/') {
                    stack.clear();
                }
                todo.extend(
                    target
                        .split('/')
                        .filter(|c| !c.is_empty() && *c != ".")
                        .map(str::to_string)
                        .rev(),
                );
            }
            _ => stack.push((c, Some(node))),
        }
    }
    let resolved = format!(
        "/{}",
        stack
            .iter()
            .map(|(c, _)| c.as_str())
            .collect::<Vec<_>>()
            .join("/")
    );
    let node = match stack.last() {
        None => Some(velarx_fuse::ROOT),
        Some((_, n)) => *n,
    };
    Ok((resolved, node))
}

/// Where a COPY writes `dst` in the image: its parents resolved (a link on
/// the way is followed, not replaced), and whether it is a directory.  The
/// last component is followed only to a directory: a link to a file is
/// replaced, as a file is.
/// Whether `path` is in the image and no directory.
fn is_file_in_tree(tree: &MergedTree, path: &str) -> bool {
    resolve_in_tree(tree, path)
        .ok()
        .and_then(|(_, n)| n)
        .and_then(|n| tree.node(n))
        .is_some_and(|n| n.entry.entry_type != TocEntryType::Dir)
}

fn resolve_dest(tree: &MergedTree, dst: &str) -> Result<(String, bool), String> {
    let is_dir = |n: Option<usize>| {
        n.and_then(|n| tree.node(n))
            .is_some_and(|n| n.entry.entry_type == TocEntryType::Dir)
    };
    let Some((parent, name)) = dst.rsplit_once('/').filter(|(_, n)| !n.is_empty()) else {
        return Ok(("/".into(), true));
    };
    let (parent, parent_node) =
        resolve_in_tree(tree, if parent.is_empty() { "/" } else { parent })?;
    let literal = velarx_wire::cp::clean_path(&format!("{parent}/{name}"));
    let Some(node) = parent_node.and_then(|p| tree.lookup(p, name)) else {
        return Ok((literal, false));
    };
    match tree.node(node).map(|n| n.entry.entry_type) {
        Some(TocEntryType::Dir) => Ok((literal, true)),
        Some(TocEntryType::Symlink) => {
            let (target, target_node) = resolve_in_tree(tree, &literal)?;
            if is_dir(target_node) {
                Ok((target, true))
            } else {
                Ok((literal, false))
            }
        }
        _ => Ok((literal, false)),
    }
}

/// `f` with the files of the image of the layers `tocs`, as a stopped
/// container without changes has them.
fn with_image_view<T>(
    tocs: &[Toc],
    store: &crate::services::ImageService,
    f: impl FnOnce(&MergedTree, &crate::services::cpview::StoppedView<'_>) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let refs: Vec<&Toc> = tocs.iter().collect();
    let tree = MergedTree::build(&refs).map_err(std::io::Error::other)?;
    // (the files are read through the images of the layers, as a container
    // reads them)
    let images = tocs
        .iter()
        .map(|t| {
            velarx_fuse::layer_erofs::layer_image(&t.entries)
                .and_then(|b| velarx_fuse::erofs_tree::Layer::open(Box::new(b.image)))
                .map_err(std::io::Error::other)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let image = velarx_fuse::view::ImageView::new(images);
    let empty = tempfile::tempdir()?;
    let layers: Vec<String> = Vec::new();
    let translate = velarx_fuse::IdTranslate::default();
    let objects = store.objects();
    let view = crate::services::cpview::StoppedView::overlay(
        open_path_dir(empty.path())?,
        crate::services::imagecopy::TreeSource {
            tree: &image,
            layers: &layers,
            objects: &objects,
            verity: store.verity(),
            fetcher: None,
            translate: &translate,
        },
    );
    f(&tree, &view)
}

fn open_path_dir(p: &Path) -> std::io::Result<OwnedFd> {
    Ok(rustix::fs::openat(
        rustix::fs::CWD,
        p,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

fn remove_dir(p: &Path) {
    if let Err(e) = velarx_base::tree::remove_dir_all_confined(p) {
        warn!("Cannot remove {}: {e}", p.display());
    }
}

/// Remove the directories of a COPY or ADD step.
fn cleanup_copy(upper: &Path, downloads: Option<&Path>, clones: &[PathBuf]) {
    remove_dir(upper);
    if let Some(d) = downloads {
        remove_dir(d);
    }
    for d in clones {
        remove_dir(d);
    }
}

#[cfg(test)]
mod tests {
    /// The duration flags of HEALTHCHECK: Go's durations, `0`, and an empty
    /// value that leaves the field unset (0), as buildah reads it.
    #[test]
    fn a_healthcheck_duration_is_a_go_duration_and_empty_is_unset() {
        assert_eq!(super::health_duration_ns("1m30s"), Some(90_000_000_000));
        assert_eq!(super::health_duration_ns("0"), Some(0));
        assert_eq!(super::health_duration_ns(""), Some(0));
        for bad in ["30", "1d", "-1s", "s"] {
            assert_eq!(super::health_duration_ns(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_disk_a_scratch_directory_uses_is_the_blocks_of_what_is_below_it() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/f"), vec![1u8; 64 << 10]).unwrap();
        let used = super::disk_usage(d.path()).unwrap();
        assert!(used >= 64 << 10, "{used}");
        assert!(super::disk_usage(&d.path().join("nothing")).is_err());
    }

    #[test]
    fn a_cache_image_is_named_by_its_parent_and_its_step() {
        let a =
            super::cache_reference("localhost:5000/cache/app", "sha256:p1", "sha256:k1").unwrap();
        let (repository, tag) = a.rsplit_once(':').unwrap();
        assert_eq!(repository, "localhost:5000/cache/app");
        assert_eq!(tag.len(), 64);
        assert!(tag.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            a,
            super::cache_reference("localhost:5000/cache/app", "sha256:p1", "sha256:k1").unwrap()
        );
        for other in [("sha256:p2", "sha256:k1"), ("sha256:p1", "sha256:k2")] {
            let b = super::cache_reference("localhost:5000/cache/app", other.0, other.1).unwrap();
            assert_ne!(a, b);
        }
        assert!(super::cache_reference("oci-archive:/tmp/x", "p", "k").is_err());
    }

    #[test]
    fn a_client_answer_is_cut_to_the_endpoints_asked() {
        use velarx_registry::Credentials;
        let scopes = vec!["r.io".to_string(), "s.io/app/".to_string()];
        let mut answer = std::collections::BTreeMap::new();
        for key in ["r.io", "s.io/app", "other.io", "r.io/more"] {
            answer.insert(key.to_string(), Credentials::basic("u", "p"));
        }
        let kept: Vec<String> = super::only_asked(&scopes, answer).map(|(k, _)| k).collect();
        assert_eq!(kept, ["r.io", "s.io/app"]);
    }

    #[test]
    fn builds_above_the_limit_are_refused_until_one_ends() {
        let pending = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a = super::admit_to(&pending, 2).unwrap();
        let _b = super::admit_to(&pending, 2).unwrap();
        assert!(super::admit_to(&pending, 2).is_none());
        // a refused build holds no place
        drop(a);
        let _c = super::admit_to(&pending, 2).expect("the place of the build that ended");
        assert!(super::admit_to(&pending, 2).is_none());
    }

    use super::*;
    use velarx_storage::TocEntry;

    /// The policy judges a reference as one function for every place the
    /// build reads an image, the platform lists of the bases included.
    #[tokio::test]
    async fn a_policy_denies_or_converts_a_reference_before_it_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let images = ImageService::new(
            velarx_db::Database::open_in_memory().await.unwrap(),
            Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap()),
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        let policy = policy::SourcePolicy::parse(
            r#"{"rules": [
              {"action": "DENY", "selector": {"identifier": "docker-image://r.io/denied:1"}},
              {"action": "CONVERT", "selector": {"identifier": "docker-image://r.io/old:1"},
               "updates": {"identifier": "docker-image://r.io/new:1"}}
            ]}"#,
        )
        .unwrap();
        let judged = |r: &'static str| judge(Some(&policy), &images, r, "the base image");
        let denied = judged("r.io/denied:1").await.unwrap_err().to_string();
        assert!(
            denied.contains(
                "the base image r.io/denied:1 is denied by the source policy: matched rule 0"
            ),
            "{denied}"
        );
        assert_eq!(judged("r.io/old:1").await.unwrap(), "r.io/new:1");
        assert_eq!(judged("r.io/other:1").await.unwrap(), "r.io/other:1");
        let none = judge(None, &images, "r.io/denied:1", "the base image");
        assert_eq!(none.await.unwrap(), "r.io/denied:1");
    }

    #[test]
    fn test_platforms_and_bases_of_all_platforms() {
        let p = |v: Value| index_platform(&v).map(|p| p.to_string());
        let inst = |os: &str, arch: &str, variant: &str| json!({"platform": {"os": os, "architecture": arch, "variant": variant}});
        assert_eq!(
            p(inst("linux", "arm64", "v8")).as_deref(),
            Some("linux/arm64")
        );
        assert_eq!(p(inst("linux", "arm", "")).as_deref(), Some("linux/arm/v7"));
        assert_eq!(
            p(inst("linux", "x86_64", "")).as_deref(),
            Some("linux/amd64")
        );
        assert_eq!(p(inst("unknown", "amd64", "")), None);
        assert_eq!(p(inst("linux", "z80", "")), None);
        assert_eq!(p(json!({"digest": "x"})), None);
        let mut artifact = inst("linux", "amd64", "");
        artifact["artifactType"] = json!("application/x");
        assert_eq!(p(artifact), None);

        let f = Containerfile::parse(
            "ARG BASE=a:1\nFROM $BASE AS one\nFROM scratch\nFROM one\nFROM 0\nFROM b\nFROM a:1\n",
        )
        .unwrap();
        assert_eq!(
            base_images(&f, &HashMap::new(), None, None).unwrap(),
            ["a:1", "b"]
        );
        let args = HashMap::from([("BASE".to_string(), "c".to_string())]);
        assert_eq!(
            base_images(&f, &args, None, None).unwrap(),
            ["c", "b", "a:1"]
        );
        // (`--from` is the base of the first stage)
        assert_eq!(
            base_images(&f, &HashMap::new(), None, Some("d")).unwrap(),
            ["d", "b", "a:1"]
        );
    }

    #[test]
    fn test_the_platform_arguments() {
        use velarx_registry::target::Platform;
        let get = |args: &[(String, Option<String>)], n: &str| lookup(args)(n);
        let target = Platform::parse("linux/arm64/v8").unwrap();
        let args = platform_args(Some(&target), &HashMap::new());
        assert_eq!(get(&args, "TARGETPLATFORM").unwrap(), "linux/arm64/v8");
        assert_eq!(get(&args, "TARGETOS").unwrap(), "linux");
        assert_eq!(get(&args, "TARGETARCH").unwrap(), "arm64");
        assert_eq!(get(&args, "TARGETVARIANT").unwrap(), "v8");
        let host = Platform::host();
        assert_eq!(get(&args, "BUILDARCH").unwrap(), host.arch);
        assert_eq!(get(&args, "BUILDPLATFORM").unwrap(), host.to_string());
        // (none asked: the host's; a build argument wins)
        let over = HashMap::from([("TARGETOS".to_string(), "freebsd".to_string())]);
        let args = platform_args(None, &over);
        assert_eq!(get(&args, "TARGETARCH").unwrap(), host.arch);
        assert_eq!(get(&args, "TARGETOS").unwrap(), "freebsd");
        // (a base image may use them)
        let f = Containerfile::parse("FROM img-$TARGETARCH\n").unwrap();
        assert_eq!(
            base_images(&f, &HashMap::new(), Some(&target), None).unwrap(),
            ["img-arm64"]
        );
    }

    #[test]
    fn test_the_file_name_of_a_url() {
        let name = |u: &str| url_file_name(u);
        assert_eq!(name("http://h/a/b.tar.gz?x=1").unwrap(), "b.tar.gz");
        assert_eq!(name("http://h/a/b.tar.gz#frag/x").unwrap(), "b.tar.gz");
        assert_eq!(name("https://h/a%20b").unwrap(), "a b");
        assert_eq!(name("http://h/a/../../etc/passwd").unwrap(), "passwd");
        assert_eq!(name("http://h:80/x?a=/b/c").unwrap(), "x");
        for bad in [
            "http://h/",
            "http://h",
            "http://h/a/",
            "http://h/a%2Fb",
            "http://h/a/%2e%2e%2f",
            "http://h/%2e%2e%2f",
            "http://h/%2E%2E%2F%2E%2E%2Fx",
            "http://h/a%2F..%2F..%2Fx",
            "http://h/..",
            "http://h/a/..",
            "http://h/%2e%2e",
            "http://h/.",
            "http://h/a%00b",
            "http://h/%ff",
            "http://h?x=/y/z",
            "http://h/?name=x",
            "http://h/#/x",
            "ftp://h/x",
            "file:///etc/passwd",
        ] {
            assert!(name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_a_source_url() {
        assert!(is_url("https://h/x") && !is_url("git://h/x") && !is_url("x"));
    }

    #[test]
    fn test_the_digest_of_copied_files_ignores_their_times() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        std::fs::create_dir(dir.join("app")).unwrap();
        std::fs::write(dir.join("app/f"), b"one\n").unwrap();
        std::os::unix::fs::symlink("f", dir.join("app/l")).unwrap();
        let first = tree_digest(dir).unwrap();
        assert!(first.starts_with("sha256:"));
        let old = std::fs::File::open(dir.join("app")).unwrap();
        old.set_modified(std::time::SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(tree_digest(dir).unwrap(), first, "mtime");
        std::fs::set_permissions(dir.join("app/f"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let mode = tree_digest(dir).unwrap();
        assert_ne!(mode, first, "mode");
        std::fs::write(dir.join("app/f"), b"two\n").unwrap();
        let content = tree_digest(dir).unwrap();
        assert_ne!(content, mode, "content");
        std::fs::rename(dir.join("app/f"), dir.join("app/g")).unwrap();
        assert_ne!(tree_digest(dir).unwrap(), content, "name");
    }

    /// The digest takes the whole stream, past the end of the archive: the
    /// walk that writes it never writes into a closed pipe.
    #[test]
    fn test_the_digest_of_a_tar_reads_it_to_its_end() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), vec![7u8; 3000]).unwrap();
        let fd =
            rustix::fs::open(d.path(), OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let mut tar = Vec::new();
        dirtar::write(fd.as_fd(), &dirtar::Options::default(), &mut tar).unwrap();
        let mut stream = std::io::Cursor::new(&tar);
        let digest = tar_digest(&mut stream).unwrap();
        assert_eq!(stream.position(), tar.len() as u64);
        assert_eq!(digest, tree_digest(d.path()).unwrap());
    }

    fn tree(entries: &[(&str, Option<&str>)]) -> MergedTree {
        let entries: Vec<TocEntry> = entries
            .iter()
            .map(|(name, link)| {
                let mut e = velarx_fuse::dir_entry(name);
                if let Some(l) = link {
                    e.entry_type = TocEntryType::Symlink;
                    e.link_name = Some(l.to_string());
                } else if name.ends_with(".txt") {
                    e.entry_type = TocEntryType::Reg;
                }
                e
            })
            .collect();
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        MergedTree::build(&[&toc]).unwrap()
    }

    #[test]
    fn test_globs_in_an_image() {
        let t = tree(&[
            ("app", None),
            ("app/a.txt", None),
            ("app/b.txt", None),
            ("app/sub", None),
            ("app/sub/c.txt", None),
            ("link", Some("/app")),
            ("top.txt", None),
        ]);
        assert_eq!(
            glob_in_tree(&t, "app/*.txt").unwrap(),
            ["/app/a.txt", "/app/b.txt"]
        );
        assert_eq!(
            glob_in_tree(&t, "/*/sub/?.txt").unwrap(),
            ["/app/sub/c.txt", "/link/sub/c.txt"]
        );
        // A link to a directory is followed in the image.
        assert_eq!(glob_in_tree(&t, "link/[b]*").unwrap(), ["/link/b.txt"]);
        assert_eq!(glob_in_tree(&t, "*.txt").unwrap(), ["/top.txt"]);
        assert!(glob_in_tree(&t, "app/*.none").unwrap().is_empty());
        assert!(glob_in_tree(&t, "../*").is_err());
    }

    #[test]
    fn test_network_modes() {
        assert_eq!(build_network(None).unwrap(), None);
        assert_eq!(build_network(Some("private")).unwrap(), None);
        assert_eq!(build_network(Some("none")).unwrap(), Some(NetworkMode::Off));
        assert_eq!(
            build_network(Some("mynet")).unwrap(),
            Some(NetworkMode::Network("mynet".into()))
        );
        assert_eq!(
            build_network(Some("ns:/proc/1/ns/net")).unwrap(),
            Some(NetworkMode::Ns("/proc/1/ns/net".into()))
        );
        assert_eq!(
            build_network(Some("pasta:-T,80")).unwrap(),
            Some(NetworkMode::Pasta(Some("-T,80".into())))
        );
        assert_eq!(
            build_network(Some("pasta")).unwrap(),
            Some(NetworkMode::Pasta(None))
        );
        for bad in ["container:abc", "pod", "provider:x"] {
            assert!(build_network(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_scratch_reservations() {
        let s = Scratch::new(100);
        let mut a = s.reservation();
        a.grow(60).unwrap();
        let mut b = s.reservation();
        assert!(b.grow(41).is_err());
        b.grow(40).unwrap();
        a.set(10).unwrap();
        assert_eq!(s.available(), 50);
        drop(b);
        assert_eq!(s.available(), 90);
        drop(a);
        assert_eq!(s.available(), 100);
    }

    #[test]
    fn test_live_processes() {
        assert!(process_alive(std::process::id() as i32));
        assert!(!process_alive(0));
        assert!(!process_alive(-1));
    }

    #[test]
    fn test_private_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("build/contexts");
        private_dir(&dir).unwrap();
        for p in [d.path().join("build"), dir] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", p.display());
        }
    }

    #[test]
    fn test_destinations_follow_the_links_of_the_image() {
        let t = tree(&[
            ("usr", None),
            ("usr/lib", None),
            ("lib", Some("usr/lib")),
            ("run", None),
            ("var", None),
            ("var/run", Some("../run")),
            ("app", None),
            ("app/file.txt", None),
            ("tolib", Some("/usr/lib")),
            ("tofile", Some("app/file.txt")),
            ("loop", Some("loop")),
            ("escape", Some("../../../../etc")),
        ]);
        let r = |p: &str| resolve_dest(&t, p).unwrap();
        assert_eq!(r("/lib/foo"), ("/usr/lib/foo".into(), false));
        assert_eq!(r("/var/run/x"), ("/run/x".into(), false));
        assert_eq!(r("/app"), ("/app".into(), true));
        assert_eq!(r("/app/file.txt"), ("/app/file.txt".into(), false));
        // A link to a directory is followed, a link to a file replaced.
        assert_eq!(r("/tolib"), ("/usr/lib".into(), true));
        assert_eq!(r("/tofile"), ("/tofile".into(), false));
        assert_eq!(r("/new/dir/x"), ("/new/dir/x".into(), false));
        assert_eq!(r("/"), ("/".into(), true));
        // `..` stops at the root of the image.
        assert_eq!(r("/escape/x"), ("/etc/x".into(), false));
        assert!(resolve_dest(&t, "/loop/x").is_err());
    }

    #[test]
    fn test_a_file_is_no_destination_of_parents() {
        let t = tree(&[
            ("app", None),
            ("app/file.txt", None),
            ("tofile", Some("app/file.txt")),
        ]);
        assert!(is_file_in_tree(&t, "/app/file.txt"));
        assert!(is_file_in_tree(&t, "/tofile"));
        assert!(!is_file_in_tree(&t, "/app"));
        assert!(!is_file_in_tree(&t, "/missing"));
    }
}
