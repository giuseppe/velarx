// SPDX-License-Identifier: Apache-2.0
//! The engine's side of a pull that a fetcher brings in: the
//! scope of the pull (`Open`), one staging directory per layer
//! (`staging/layers/<stem>`, held by the lease `staging/meta/<stem>/lease`),
//! the table of contents of a layer by `Probe` and the files the store lacks
//! by `Layer` and `Fetch`.  Each file a fetcher says it staged is opened
//! beneath the layer's staging directory and given to the pull's session,
//! which the replay of the tar-split then checks against the diff id as it
//! checks every file of the layer: nothing a fetcher wrote is believed.
//! A lazy pull's files stay in the staging of their layer
//! (`StagedFetch::stage_files`), where its containers find them and its
//! commit links them; the staging of a layer a lazy pull staged
//! (`meta/<stem>/layer.json`) is never removed by an eager pull or the sweep.

use super::chunked::{self, Intake};
use super::sink::Sink;
use crate::fetcher::fetch::{Blob, EventKind, FetchEvent, Probed, Reuse, TocSource, Urgency};
use crate::fetcher::fetch_client::{files_at, CallError, FetchConn, Scoping, Unpacking};
use crate::stager::staged_rel;
use rustix::fs::{FlockOperation, Mode, OFlags, ResolveFlags};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::debug;
use velarx_proto::transfer::{next, Failure, FailureClass, Step};
use velarx_storage::{Toc, TocEntryType};
use velarx_types::digest::Digest;
use velarx_types::{ImageError, ImageResult, OciDescriptor};

pub use crate::pull::staged::{LAYERS, META};

/// Calls of `Fetch` a layer has in flight at once.
const FETCHES_AT_ONCE: usize = 4;

fn fetcher_error(party: &str, e: CallError) -> ImageError {
    use crate::fetcher::fetch::FetcherError;
    let (class, reason) = match e {
        CallError::Fetcher(FetcherError::Failed { failure }) => (failure.class, failure.reason),
        e => (FailureClass::Transient, e.to_string()),
    };
    ImageError::transfer(party, class, reason)
}

/// What a `failed` event of the fetcher `party` is, as an error, and what the
/// walk does with it.
fn failed_event(party: &str, is_origin: bool, event: &FetchEvent) -> (ImageError, Step) {
    let failure = event.failure.clone().unwrap_or_else(|| Failure {
        class: FailureClass::Failed,
        reason: "failed".into(),
    });
    failure_step(party, is_origin, failure)
}

/// What a failure of the fetcher `party` is, as an error, and what the walk
/// does with it.
fn failure_step(party: &str, is_origin: bool, failure: Failure) -> (ImageError, Step) {
    let step = next(failure.class, is_origin);
    (
        ImageError::transfer(party, failure.class, failure.reason),
        step,
    )
}

/// What a fetcher that did not bring what it claims did: `Contradicted`
/// (what the checks of a staged file and of a table of contents say) is that
/// fetcher's, and nobody else is asked.
fn by(party: &str, object: &str, e: ImageError) -> ImageError {
    match e {
        ImageError::Contradicted(why) => {
            ImageError::transfer_of(party, object.to_string(), FailureClass::Invalid, why)
        }
        e => e,
    }
}

/// The per-call connections this process has open to fetchers, at most:
/// below the limit a fetcher keeps for one client (`[services]
/// max_per_client`), so a busy engine waits for one of its own calls
/// instead of being refused.
const CONNECTIONS: usize = 128;

pub(crate) static CONNECTED: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(CONNECTIONS)));

/// Whether the layer of `stem` is staged by a lazy pull (`meta/<stem>/layer.json`):
/// its staging is the lazy pull's, kept when a fetch into it ends.
fn lazily_staged(root: &Path, stem: &str) -> bool {
    root.join(META).join(stem).join("layer.json").is_file()
}

/// A fetcher of `[pull] sources` other than the registry fetcher (a socket
/// of `[[sources.external]]`), as the engine connected to it.
pub struct Link {
    /// Its name in `[pull] sources`
    pub name: String,
    pub conn: FetchConn,
    /// How long it may be silent in a call (`idle_timeout_secs`)
    pub idle: std::time::Duration,
}

/// How long the registry fetcher may be silent in a call.
pub const REGISTRY_IDLE: std::time::Duration = std::time::Duration::from_secs(120);

/// One fetcher of the list of a pull: the connection that has its scope.
struct Fetcher {
    name: String,
    /// Calls with replies to come go on connections it gives
    control: tokio::sync::Mutex<FetchConn>,
    /// How long it may be silent in a call
    idle: std::time::Duration,
    max_objects: usize,
    /// It announces `reuse`: it is given the chunks of the store
    reuse: bool,
    /// It announces `origin`: it reaches the origin of a layer, and is
    /// given its blob
    origin: bool,
    /// It announces `handover`: it hands the small files it fetches over as
    /// descriptors when the pull keeps them in the engine
    handover: bool,
    /// Its connection failed (the peer restarted, the socket went): the
    /// scope it was given is gone with it
    lost: std::sync::atomic::AtomicBool,
}

/// What one call learnt of the fetchers of the list: the breaker.  One
/// whose connection failed is not asked again by this call, and by no
/// other: a fetcher that failed once (a peer that was away) is asked again
/// by the next call of a service that lives on.
struct Breaker {
    broken: Vec<std::sync::atomic::AtomicBool>,
    /// Why each tripped
    why: Vec<Mutex<Option<String>>>,
}

impl Breaker {
    fn new(fetchers: usize) -> Self {
        Self {
            broken: (0..fetchers).map(|_| Default::default()).collect(),
            why: (0..fetchers).map(|_| Mutex::default()).collect(),
        }
    }

    fn usable(&self, at: usize) -> bool {
        !self.broken[at].load(std::sync::atomic::Ordering::Relaxed)
    }

    fn trip(&self, at: usize, fetcher: &Fetcher, e: &CallError) {
        // (no connection for now is not a fetcher that failed)
        if matches!(
            e,
            CallError::Fetcher(crate::fetcher::fetch::FetcherError::Busy { .. })
        ) {
            return;
        }
        if matches!(e, CallError::Io(_)) {
            fetcher
                .lost
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.distrust(at, fetcher, &e.to_string());
    }

    /// `fetcher` said what is not so (a file staged that is not): it is
    /// not asked again by this call.
    fn distrust(&self, at: usize, fetcher: &Fetcher, why: &str) {
        debug!(
            "The fetcher {} is not asked again by this call: {why}",
            fetcher.name
        );
        self.broken[at].store(true, std::sync::atomic::Ordering::Relaxed);
        self.why[at]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(|| why.to_string());
    }
}

impl Fetcher {
    /// A connection for one call, and the place of it among those of the
    /// process ([`CONNECTIONS`]): held while the connection is used.  The
    /// fetcher is silent for its idle time at most, as in a call.
    async fn connection(
        &self,
    ) -> Result<(FetchConn, tokio::sync::OwnedSemaphorePermit), CallError> {
        let permit = CONNECTED
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| CallError::Protocol(e.to_string()))?;
        let mut control = self.control.lock().await;
        let conn = crate::idle::within(self.idle, control.connect()).await?;
        Ok((conn, permit))
    }
}

/// Whether the error of a call ends the walk: the fetcher refused the
/// request itself (it is wrong for every fetcher), not what it lacks.
fn refused(e: &CallError) -> bool {
    use crate::fetcher::fetch::FetcherError as F;
    matches!(
        e,
        CallError::Fetcher(F::Refused { .. } | F::InvalidArgument { .. } | F::BadStaging { .. })
    )
}

/// The reuse hints of a fetch: for each file asked for (its content key),
/// the chunks of it the store holds.  The fetcher is never given a file of
/// the store: the engine copies the bytes of exactly those chunks into ONE
/// file with no name in the staging of the layer (a reflink where the file
/// system has them), which it hands read-only.  Only a fetcher that
/// announces the word `reuse` is given it.
#[derive(Default)]
pub struct Reuses {
    /// chunk sha256, offset in `file`, size
    by_key: HashMap<String, Vec<(String, u64, u64)>>,
    /// The chunks, written; then the same file opened read-only
    file: Option<File>,
    len: u64,
}

impl Reuses {
    /// The chunk `chunk` of the file `key` is `size` bytes at `offset` of
    /// `from` (a file of the store): copied into the file of the hints,
    /// made in the staging directory `dir` of the layer on first use.
    pub fn hint(
        &mut self,
        dir: &File,
        key: &str,
        chunk: String,
        from: &File,
        (offset, size): (u64, u64),
    ) -> io::Result<()> {
        if self.file.is_none() {
            self.file = Some(super::unnamed::unnamed_file_at(dir)?);
        }
        let to = self.file.as_ref().expect("made above");
        let (mut off_in, mut off_out, mut left) = (offset, self.len, size);
        while left > 0 {
            let n = rustix::fs::copy_file_range(
                from,
                Some(&mut off_in),
                to,
                Some(&mut off_out),
                usize::try_from(left).unwrap_or(usize::MAX),
            )?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "a chunk of the store ends early",
                ));
            }
            left -= n as u64;
        }
        self.by_key
            .entry(key.to_string())
            .or_default()
            .push((chunk, self.len, size));
        self.len += size;
        Ok(())
    }

    /// The hints are complete: the file is handed read-only from now on.
    pub fn sealed(mut self) -> io::Result<Self> {
        if let Some(file) = self.file.take() {
            file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o400))?;
            self.file = Some(velarx_sys::fd::reopen_read_only(&file)?);
        }
        Ok(self)
    }

    /// The hints of the files `keys` and the one descriptor they name.
    fn of(&self, keys: &[String]) -> io::Result<(Vec<Reuse>, Vec<OwnedFd>)> {
        let hints: Vec<Reuse> = keys
            .iter()
            .filter_map(|k| self.by_key.get(k))
            .flatten()
            .map(|(chunk, offset, size)| Reuse {
                chunk: chunk.clone(),
                fd: 0,
                offset: *offset,
                length: *size,
            })
            .collect();
        match (&self.file, hints.is_empty()) {
            (Some(file), false) => Ok((hints, vec![OwnedFd::from(file.try_clone()?)])),
            _ => Ok((Vec::new(), Vec::new())),
        }
    }
}

/// The device and inode of a staging directory.
type StagingId = (u64, u64);

/// A pull through the engine's ordered list of fetchers: the scope each
/// was given (each its own; the credentials only to the registry
/// fetcher), and the layers the engine told them of.  The engine walks the
/// list for every request: a fetcher answers only for itself, and what it
/// does not have (`unavailable`) or could not bring (`failed`) is asked of
/// the next; a request it refuses ends the walk.
pub struct StagedFetch {
    /// The store has fs-verity: every fetcher seals what it stages, so a
    /// file the kernel does not measure is not what it says
    verity: bool,
    /// The fetcher that staged each file of a lazy layer, by the digest of
    /// the layer's blob and the key: what the failure of the completion names
    placed: Mutex<HashMap<(String, String), String>>,
    /// In the order of `[pull] sources`
    fetchers: Vec<Fetcher>,
    /// The place of the origin (the registry fetcher) in `fetchers`: none
    /// when `registry` is not one of the sources
    origin: Option<usize>,
    /// `<store>/staging`
    root: PathBuf,
    /// The layers of the manifest of the image, in order, as the engine
    /// hashed it
    blobs: Vec<Blob>,
    /// The digests of the layers of the manifest, in order
    layers: Vec<Digest>,
    /// The most objects of a `Fetch` that every fetcher takes
    max_objects: usize,
    /// The layers each fetcher was told of (the place in `fetchers`), by
    /// the blob, with the staging directory it was given (device and
    /// inode): a staging made again since (the layer was committed and
    /// removed, and is fetched anew) is told again, or the fetchers would
    /// write into the removed one
    told: Mutex<HashMap<String, Vec<Option<StagingId>>>>,
    /// The layers the fetchers were asked about (`Probe`) since they were
    /// last forgotten: what a fetcher keeps for a blob it read to answer
    /// goes with `Forget`, told or not
    probed: Mutex<std::collections::HashSet<String>>,
    /// Held while a layer is told: a second walk of the layer, at the same
    /// time, waits for the `Layer` call of the first, not for nothing
    telling: tokio::sync::Mutex<()>,
    /// The fetchers but the origin whose `Layer` failed (the place in
    /// `fetchers`): not asked again by this pull, so that no call waits for
    /// one that is silent
    unwilling: Vec<std::sync::atomic::AtomicBool>,
    /// The staging of each layer that is open, by its name: a layer that is
    /// opened twice while it is open is one staging (whoever drops the
    /// last takes it away)
    open: Arc<Mutex<HashMap<String, std::sync::Weak<LayerStaging>>>>,
}

impl StagedFetch {
    /// The scope of the fetchers of `links`, in order, with nothing but the
    /// verity of the store: one that is not there or refuses it is left out.
    async fn open_links(links: Vec<Link>, verity: bool) -> Vec<Fetcher> {
        let mut fetchers = Vec::new();
        for Link {
            name,
            mut conn,
            idle,
        } in links
        {
            let opened = async {
                let info = conn.get_info().await?;
                conn.open(Scoping {
                    verity,
                    source: None,
                    tls_verify: None,
                    target: None,
                    access: None,
                    idle,
                    requires: &["objects".to_string()],
                })
                .await?;
                Ok::<_, CallError>(info)
            };
            match crate::idle::within(idle, opened).await {
                Ok(info) => fetchers.push(Fetcher {
                    name,
                    control: tokio::sync::Mutex::new(conn),
                    idle,
                    max_objects: info.limit("max_objects").unwrap_or(1).max(1) as usize,
                    reuse: info.can("reuse"),
                    origin: info.can("origin"),
                    handover: info.can("handover"),
                    lost: Default::default(),
                }),
                Err(e) => debug!("The fetcher {name} is left out of the pull: {e}"),
            }
        }
        fetchers
    }

    /// Open the scope of a pull of `manifest` on each fetcher, in order:
    /// on those of `before` and `after` with nothing but the verity of the
    /// store, on the registry fetcher `end` between them (none: `registry`
    /// is not one of the sources) with the repository and the credentials
    /// `access` (the JSON of a `RegistryAccess`, in a sealed memory file).
    /// A fetcher of `before` or `after` that is not there or refuses the
    /// scope is left out.
    #[allow(clippy::type_complexity)]
    pub async fn open(
        (before, end, after): (Vec<Link>, Option<FetchConn>, Vec<Link>),
        root: &Path,
        verity: bool,
        (repository, tls_verify): (&str, bool),
        access: Option<&[u8]>,
        manifest: &[u8],
    ) -> ImageResult<Arc<Self>> {
        let mut fetchers = Self::open_links(before, verity).await;
        let mut origin = None;
        if let Some(mut end) = end {
            let info = end
                .get_info()
                .await
                .map_err(|e| fetcher_error("registry", e))?;
            let access = access
                .map(velarx_base::sealed::sealed_memory)
                .transpose()
                .map_err(ImageError::Io)?;
            let requires = vec!["objects".to_string(), "metadata".to_string()];
            end.open(Scoping {
                verity,
                source: Some(repository),
                tls_verify: Some(tls_verify),
                target: None,
                access,
                idle: REGISTRY_IDLE,
                requires: &requires,
            })
            .await
            .map_err(|e| fetcher_error("registry", e))?;
            origin = Some(fetchers.len());
            fetchers.push(Fetcher {
                name: "registry".into(),
                control: tokio::sync::Mutex::new(end),
                idle: REGISTRY_IDLE,
                max_objects: info.limit("max_objects").unwrap_or(1).max(1) as usize,
                reuse: info.can("reuse"),
                origin: info.can("origin"),
                handover: info.can("handover"),
                lost: Default::default(),
            });
        }
        fetchers.extend(Self::open_links(after, verity).await);
        Self::assemble(fetchers, origin, root, verity, manifest)
    }

    /// [`StagedFetch::open`] for a pull whose origin is a path: `end` is a
    /// connection of the origin process that has its scope already
    /// (`Connect`), the name of its fetcher is `name`.
    pub async fn open_scoped(
        before: Vec<Link>,
        mut end: FetchConn,
        name: &str,
        root: &Path,
        verity: bool,
        manifest: &[u8],
    ) -> ImageResult<Arc<Self>> {
        let mut fetchers = Self::open_links(before, verity).await;
        let info = end.get_info().await.map_err(|e| fetcher_error(name, e))?;
        let origin = Some(fetchers.len());
        fetchers.push(Fetcher {
            name: name.into(),
            control: tokio::sync::Mutex::new(end),
            idle: REGISTRY_IDLE,
            max_objects: info.limit("max_objects").unwrap_or(1).max(1) as usize,
            reuse: info.can("reuse"),
            origin: info.can("origin"),
            handover: info.can("handover"),
            lost: Default::default(),
        });
        Self::assemble(fetchers, origin, root, verity, manifest)
    }

    /// The pull of `manifest` over the fetchers once they are open.
    fn assemble(
        fetchers: Vec<Fetcher>,
        origin: Option<usize>,
        root: &Path,
        verity: bool,
        manifest: &[u8],
    ) -> ImageResult<Arc<Self>> {
        let max_objects = fetchers.iter().map(|f| f.max_objects).min().unwrap_or(1);
        let unwilling = fetchers.iter().map(|_| Default::default()).collect();
        let parsed: velarx_types::OciManifest = serde_json::from_slice(manifest)?;
        Ok(Arc::new(Self {
            verity,
            placed: Mutex::default(),
            fetchers,
            origin,
            root: root.to_path_buf(),
            blobs: parsed
                .layers
                .iter()
                .map(|l| Blob {
                    digest: l.digest.to_string(),
                    size: u64::try_from(l.size).unwrap_or(0),
                    media_type: l.media_type.clone(),
                    annotations: (!l.annotations.is_empty()).then(|| {
                        l.annotations
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    }),
                })
                .collect(),
            layers: parsed.layers.iter().map(|l| l.digest).collect(),
            max_objects,
            told: Mutex::default(),
            probed: Mutex::default(),
            telling: tokio::sync::Mutex::default(),
            unwilling,
            open: Arc::default(),
        }))
    }

    /// Whether the fetcher at `at` is left out of the pull: a `Layer` of it
    /// failed.
    fn unwilling(&self, at: usize) -> bool {
        self.unwilling[at].load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A connection of a fetcher failed: its scope is gone with it (a peer
    /// that restarted), and this pull is to be opened again.
    pub fn stale(&self) -> bool {
        self.fetchers
            .iter()
            .any(|f| f.lost.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// The names of the fetchers of the pull, in the order they are asked.
    pub fn sources(&self) -> Vec<&str> {
        self.fetchers.iter().map(|f| f.name.as_str()).collect()
    }

    /// The compressed table of contents and tar-split of `layer` as the
    /// fetchers found them (for the caller to verify against the descriptor),
    /// or none when it has no table of contents for it.  `again`: the index
    /// the last probe carried for it was wrong.
    pub async fn probe(
        &self,
        layer: &OciDescriptor,
        again: bool,
    ) -> ImageResult<Option<(Vec<u8>, Vec<u8>)>> {
        let Some(at) = self.layers.iter().position(|d| *d == layer.digest) else {
            return Err(ImageError::Layer(format!(
                "{} is not a layer of the image",
                layer.digest
            )));
        };
        let at = at as u32;
        let mut found = None;
        for (reply, metadata) in self.probe_all(&[at], again).await? {
            if reply.layer == at {
                found = metadata;
            }
        }
        Ok(found)
    }

    /// What the fetchers can do for the layers at `at` of the manifest: the
    /// list walked with one `Probe` for each fetcher, a layer asked of the
    /// next while none brought its table of contents or can unpack it; a
    /// reply for each layer, once, with the table of contents and the
    /// tar-split it carries.  A layer nobody answered is `none`,
    /// `unreachable`.  `again`: [`StagedFetch::probe`].
    #[allow(clippy::type_complexity)]
    pub async fn probe_all(
        &self,
        at: &[u32],
        again: bool,
    ) -> ImageResult<Vec<(Probed, Option<(Vec<u8>, Vec<u8>)>)>> {
        self.probed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(
                at.iter()
                    .filter_map(|i| self.layers.get(*i as usize))
                    .map(Digest::to_string),
            );
        let mut found: Vec<(Probed, Option<(Vec<u8>, Vec<u8>)>)> = Vec::new();
        let mut left: Vec<u32> = at.to_vec();
        let breaker = Breaker::new(self.fetchers.len());
        for (fetcher_at, fetcher) in self.fetchers.iter().enumerate() {
            if !breaker.usable(fetcher_at) || self.unwilling(fetcher_at) {
                continue;
            }
            if left.is_empty() {
                break;
            }
            let answered = match self.probe_one(fetcher, &left, again).await {
                Ok(a) => a,
                Err(e) if refused(&e) => return Err(fetcher_error(&fetcher.name, e)),
                Err(e) => {
                    breaker.trip(fetcher_at, fetcher, &e);
                    continue;
                }
            };
            // (what it sent that cannot be read: it is not asked again)
            let answered = match answered {
                Ok(a) => a,
                Err(e) => {
                    breaker.distrust(fetcher_at, fetcher, &e.to_string());
                    continue;
                }
            };
            for (reply, metadata) in answered {
                // (the last word on a layer is the best one heard: a
                // fetcher that cannot reach it leaves it to the next)
                if reply.toc == TocSource::None {
                    found.retain(|(r, _)| r.layer != reply.layer);
                    found.push((reply, None));
                    continue;
                }
                left.retain(|l| *l != reply.layer);
                found.retain(|(r, _)| r.layer != reply.layer);
                found.push((reply, metadata));
            }
        }
        for layer in at {
            if !found.iter().any(|(r, _)| r.layer == *layer) {
                let reply = Probed {
                    layer: *layer,
                    toc: TocSource::None,
                    on_demand: false,
                    reason: Some(crate::fetcher::fetch::NotLazy::Unreachable),
                    toc_file: None,
                    tarsplit_file: None,
                };
                found.push((reply, None));
            }
        }
        Ok(found)
    }

    /// One `Probe` of `fetcher`: the replies for the layers of `at`, once
    /// each (the outer error: the call; the inner one: what it sent).
    #[allow(clippy::type_complexity)]
    async fn probe_one(
        &self,
        fetcher: &Fetcher,
        at: &[u32],
        again: bool,
    ) -> Result<ImageResult<Vec<(Probed, Option<(Vec<u8>, Vec<u8>)>)>>, CallError> {
        // (the call carries the layers asked for, in order: a reply names
        // its layer by its position in the call)
        let asked: Vec<Blob> = at
            .iter()
            .filter_map(|i| self.blobs.get(*i as usize).cloned())
            .collect();
        let (mut conn, _connected) = fetcher.connection().await?;
        let mut replies = crate::idle::within(fetcher.idle, conn.probe(&asked, again)).await?;
        let mut found: Vec<(Probed, Option<(Vec<u8>, Vec<u8>)>)> = Vec::new();
        while let Some((mut reply, fds)) =
            crate::idle::within(fetcher.idle, replies.probed()).await?
        {
            let Some(&position) = at.get(reply.layer as usize) else {
                continue;
            };
            reply.layer = position;
            if found.iter().any(|(r, _)| r.layer == reply.layer) {
                continue;
            }
            if reply.toc != TocSource::Carried {
                found.push((reply, None));
                continue;
            }
            let mut files = fds.into_iter().map(Some).collect::<Vec<_>>();
            let mut take = |at: Option<u32>| {
                at.and_then(|at| files.get_mut(at as usize)?.take())
                    .map(File::from)
            };
            // (a canonical layer has no tar-split)
            let toc = take(reply.toc_file);
            let ts = take(reply.tarsplit_file);
            let (Some(toc), true) = (toc, ts.is_some() == reply.tarsplit_file.is_some()) else {
                return Ok(Err(ImageError::transfer(
                    &fetcher.name,
                    FailureClass::Invalid,
                    "a table of contents without its files",
                )));
            };
            let max = super::chunked::MAX_METADATA_COMPRESSED;
            let read = |file: File| {
                velarx_base::sealed::read_sealed_whole(&file, max).map_err(|w| {
                    ImageError::transfer(
                        &fetcher.name,
                        FailureClass::Invalid,
                        format!("the metadata of the layer {w}"),
                    )
                })
            };
            let metadata = match (read(toc), ts.map_or(Ok(Vec::new()), read)) {
                (Ok(t), Ok(m)) => (t, m),
                (Err(e), _) | (_, Err(e)) => return Ok(Err(e)),
            };
            found.push((reply, Some(metadata)));
        }
        Ok(Ok(found))
    }

    /// The staging of `layer`, open, for an eager pull: the engine holds
    /// the lease of the layer (`meta/<stem>/lease`, taken with the lock of
    /// the layer before it planned what the store lacks, and let go once
    /// the layer is recorded), so that another engine that pulls the layer
    /// waits for it and finds the layer in the store.  The staging goes
    /// with the result, unless a lazy pull keeps the layer.
    pub async fn open_layer(&self, layer: &OciDescriptor) -> ImageResult<Arc<LayerStaging>> {
        self.open_layer_as(velarx_types::LayerKey::expected(layer))
            .await
    }

    /// [`StagedFetch::open_layer`] for the layer `key`: a layer
    /// with no table of contents is the layer of its blob, whose staging is
    /// not the one of a table (two blobs may have one table).
    pub async fn open_layer_as(
        &self,
        key: velarx_types::LayerKey,
    ) -> ImageResult<Arc<LayerStaging>> {
        let stem = key.file_stem();
        let root = self.root.clone();
        let open = self.open.clone();
        tokio::task::spawn_blocking(move || {
            // (looked up and made under one lock: a staging that is made
            // twice would be removed by the drop of the second)
            let mut open = open.lock().unwrap_or_else(|e| e.into_inner());
            open.retain(|_, w| w.strong_count() > 0);
            if let Some(there) = open.get(&stem).and_then(std::sync::Weak::upgrade) {
                return Ok(there);
            }
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            let path = root.join(LAYERS).join(&stem);
            builder.create(&path)?;
            let dir = File::open(&path)?;
            let keep = lazily_staged(&root, &stem);
            let made = Arc::new(LayerStaging {
                root,
                stem: stem.clone(),
                keep,
                dir,
                placed: Mutex::default(),
            });
            open.insert(stem, Arc::downgrade(&made));
            Ok::<_, ImageError>(made)
        })
        .await
        .map_err(|e| ImageError::Layer(format!("the staging of a layer: {e}")))?
    }

    /// Bring the files `keys` of `layer` (whose verified table of contents
    /// is `toc`) into its staging directory `staging` and give each to
    /// `sink`.  `progress` gets the compressed bytes fetched so far.  The
    /// staging of the layer is removed with `staging` once every file is
    /// given (unless a lazy pull staged the layer: then it is that pull's
    /// and stays); a failure leaves nothing of this call.
    pub async fn fetch_files(
        &self,
        staging: &Arc<LayerStaging>,
        layer: &OciDescriptor,
        toc: &Toc,
        (keys, reuse): (Vec<String>, &Reuses),
        (sink, taking): (&Arc<dyn Sink>, &Arc<tokio::sync::Semaphore>),
        progress: &(dyn Fn(u64) + Send + Sync),
    ) -> ImageResult<Walked> {
        self.walk(
            layer,
            toc,
            (keys, reuse),
            &staging.dir,
            Some((sink, staging, taking)),
            (Urgency::Wait, true),
            (progress, &|_| {}),
        )
        .await
    }

    /// [`StagedFetch::fetch_files`] of the fetchers before the origin
    /// only: the origin is not told of the layer, and what no other
    /// fetcher has is an error.  `toc` is a claim of one of them (the
    /// origin could not read ranges of the blob at its offsets).
    pub async fn fetch_from_sources(
        &self,
        staging: &Arc<LayerStaging>,
        layer: &OciDescriptor,
        toc: &Toc,
        keys: Vec<String>,
        (sink, taking): (&Arc<dyn Sink>, &Arc<tokio::sync::Semaphore>),
        progress: &(dyn Fn(u64) + Send + Sync),
    ) -> ImageResult<Walked> {
        self.walk(
            layer,
            toc,
            (keys, &Reuses::default()),
            &staging.dir,
            Some((sink, staging, taking)),
            (Urgency::Wait, false),
            (progress, &|_| {}),
        )
        .await
    }

    /// Bring the files `keys` of `layer` (whose verified table of contents
    /// is `toc`) into the staging directory of the layer of `stem` and leave
    /// them there, named as the object contract says: the staging of a lazy
    /// pull.  The caller holds the lease of the layer.  `staged` is told
    /// the key of each file as soon as it is staged (a miss waits for its
    /// file, not for the batch).  Returns the compressed bytes fetched.
    pub async fn stage_files(
        &self,
        stem: &str,
        layer: &OciDescriptor,
        toc: &Toc,
        keys: Vec<String>,
        (urgency, staged): (Urgency, &(dyn Fn(&str) + Send + Sync)),
    ) -> ImageResult<Walked> {
        let dir = self.root.join(LAYERS).join(stem);
        let opened = dir.clone();
        let dir = tokio::task::spawn_blocking(move || {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(&opened)?;
            File::open(&opened)
        })
        .await
        .map_err(|e| ImageError::Layer(format!("the staging of a layer: {e}")))?
        .map_err(|e| ImageError::Layer(format!("the staging {}: {e}", dir.display())))?;
        self.walk(
            layer,
            toc,
            (keys, &Reuses::default()),
            &dir,
            None,
            (urgency, true),
            (&|_| {}, staged),
        )
        .await
    }

    /// Tell the fetchers of `layer` once, then walk the list for the files
    /// `keys` in batches: each staged file is given to the sink (and its
    /// name taken away from the staging unless it is `kept`), or left where
    /// it is staged.  The origin only `with_origin`.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    async fn walk(
        &self,
        layer: &OciDescriptor,
        toc: &Toc,
        (keys, reuse): (Vec<String>, &Reuses),
        dir: &File,
        sink: Option<Eager<'_>>,
        (urgency, with_origin): (Urgency, bool),
        (progress, staged): (&(dyn Fn(u64) + Send + Sync), &(dyn Fn(&str) + Send + Sync)),
    ) -> ImageResult<Walked> {
        let name = layer.digest.to_string();
        let breaker = Breaker::new(self.fetchers.len());
        self.tell(layer, (dir, Some(toc)), &breaker, with_origin)
            .await?;
        // (the names the files of a session are staged by: a lazy pull's
        // files stay where they are staged, and a table of 120,000 entries
        // is not walked for each group of files it asks for)
        let names: std::collections::HashMap<String, String> = match sink {
            Some(_) => toc
                .entries
                .iter()
                .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0 && e.verity().is_some())
                .filter_map(|e| Some((e.content_key()?, e.name.clone())))
                .collect(),
            None => Default::default(),
        };
        let bytes = std::sync::atomic::AtomicU64::new(0);
        let sourced = Sourced {
            each: self.fetchers.iter().map(|_| Default::default()).collect(),
        };
        {
            use futures::{StreamExt, TryStreamExt};
            let (names, bytes, name) = (&names, &bytes, name.as_str());
            let (sourced, breaker) = (&sourced, &breaker);
            let batches: Vec<Vec<String>> = keys
                .chunks(self.max_objects)
                .map(<[String]>::to_vec)
                .collect();
            futures::stream::iter(batches)
                .map(|batch: Vec<String>| async move {
                    let counts = Counts {
                        bytes,
                        progress,
                        sourced,
                        staged,
                        breaker,
                        with_origin,
                    };
                    self.fetch_batch(name, (&batch, reuse), dir, names, sink, urgency, counts)
                        .await
                })
                .buffer_unordered(FETCHES_AT_ONCE)
                .try_collect::<Vec<()>>()
                .await?;
        }
        Ok(Walked {
            bytes: bytes.into_inner(),
            sources: self
                .fetchers
                .iter()
                .zip(sourced.each)
                .enumerate()
                .filter(|(at, _)| Some(*at) != self.origin)
                .map(
                    |(_, (f, (bytes, files)))| velarx_proto::workload::BySource {
                        name: f.name.clone(),
                        bytes: bytes.into_inner(),
                        files: files.into_inner(),
                    },
                )
                .collect(),
        })
    }

    /// The name of the last fetcher of the pull: the party of what no
    /// fetcher had.
    fn last_name(&self) -> &str {
        self.fetchers.last().map_or("registry", |f| f.name.as_str())
    }

    /// The fetcher that staged the file `key` of the lazy layer whose blob is
    /// `layer`, when this process's walk did.
    pub fn staged_by(&self, layer: &str, key: &str) -> Option<String> {
        self.placed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(layer.to_string(), key.to_string()))
            .cloned()
    }

    /// The staging of the layer whose blob is `layer` went (committed,
    /// removed): its fetchers forget it (`Cancel`), and it is told again
    /// when it is fetched anew.  What a fetcher answers is of no matter.
    pub async fn forget(&self, layer: &str) {
        self.placed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(l, _), _| l != layer);
        let told = self
            .told
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(layer)
            .is_some();
        let probed = self
            .probed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(layer);
        if !told && !probed {
            return;
        }
        for (at, fetcher) in self.fetchers.iter().enumerate() {
            if self.unwilling(at) {
                continue;
            }
            let mut control = fetcher.control.lock().await;
            if let Err(e) = crate::idle::within(fetcher.idle, control.forget(layer)).await {
                debug!("The fetcher {} keeps the layer {layer}: {e}", fetcher.name);
            }
        }
    }

    /// A fetcher refused a request for `layer`: that it was not told of it
    /// is the engine's state, not the request's fault.  It is not asked
    /// again by this call and told again by the next, and the walk goes on.
    fn untell(&self, layer: &str, at: usize, e: &CallError) {
        if !refused(e) {
            return;
        }
        if let Some(slot) = self
            .told
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(layer)
            .and_then(|known| known.get_mut(at))
        {
            *slot = None;
        }
    }

    /// Tell the fetchers of `layer` (whose verified table of contents is
    /// `toc`, if it has one) and its staging directory `dir`, once; the
    /// origin only `with_origin`.
    async fn tell(
        &self,
        layer: &OciDescriptor,
        (dir, toc): (&File, Option<&Toc>),
        breaker: &Breaker,
        with_origin: bool,
    ) -> ImageResult<()> {
        let _telling = self.telling.lock().await;
        for (i, fetcher) in self.fetchers.iter().enumerate() {
            if self.unwilling(i) {
                breaker.distrust(i, fetcher, "a layer it was told of failed");
            }
        }
        let name = layer.digest.to_string();
        let staging = dir.metadata().map(|m| (m.dev(), m.ino()))?;
        let missed: Vec<bool> = {
            let told = self.told.lock().unwrap_or_else(|e| e.into_inner());
            let known = told.get(&name);
            (0..self.fetchers.len())
                .map(|i| known.and_then(|k| k.get(i).copied().flatten()) != Some(staging))
                .collect()
        };
        if missed.iter().any(|m| *m) {
            let toc_fd = match toc {
                Some(toc) => Some(
                    velarx_base::sealed::sealed_memory(&serde_json::to_vec(toc)?)
                        .map_err(ImageError::Io)?,
                ),
                None => None,
            };
            let described = Blob {
                digest: name.clone(),
                size: u64::try_from(layer.size).unwrap_or(0),
                media_type: layer.media_type.clone(),
                annotations: (!layer.annotations.is_empty()).then(|| {
                    layer
                        .annotations
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                }),
            };
            // (every fetcher is told, by the engine: the blob only to the
            // registry fetcher)
            for (i, fetcher) in self.fetchers.iter().enumerate() {
                if !missed[i] || !breaker.usable(i) || (!with_origin && Some(i) == self.origin) {
                    continue;
                }
                let toc = toc_fd
                    .as_ref()
                    .map(OwnedFd::try_clone)
                    .transpose()
                    .map_err(ImageError::Io)?;
                // (the blob of the layer only to a fetcher that reaches an
                // origin: the word `origin`)
                let blob = fetcher.origin.then_some(&described);
                let said = {
                    let mut control = fetcher.control.lock().await;
                    crate::idle::within(fetcher.idle, control.layer(&name, blob, dir, toc)).await
                };
                match said {
                    Ok(()) => {
                        let mut told = self.told.lock().unwrap_or_else(|e| e.into_inner());
                        let known = told.entry(name.clone()).or_default();
                        known.resize(self.fetchers.len(), None);
                        known[i] = Some(staging);
                    }
                    // (one that cannot take the layer, whatever it says, is
                    // not asked for it by this walk, and by no call of the
                    // pull unless it is the origin)
                    Err(e) => {
                        if Some(i) != self.origin {
                            self.unwilling[i].store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                        breaker.distrust(i, fetcher, &e.to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// Bring the whole of `layer`, which has no table of contents, from the
    /// origin: it unpacks the layer, the files it hands over go to `intake`
    /// as they come, and the table of contents it claims and the tar-split
    /// are read from the staging `staging` at the end.  Nothing of it is
    /// believed: the caller recreates the stream from the tar-split and the
    /// files and checks it.
    pub async fn fetch_whole(
        &self,
        staging: &LayerStaging,
        layer: &OciDescriptor,
        progress: &(dyn Fn(u64) + Send + Sync),
        intake: &Intake,
    ) -> ImageResult<Whole> {
        use crate::fetcher::fetch::{TARSPLIT, TOC_CLAIM};
        let name = layer.digest.to_string();
        let breaker = Breaker::new(self.fetchers.len());
        self.tell(layer, (&staging.dir, None), &breaker, true)
            .await?;
        let Some(at) = self.origin else {
            return Err(ImageError::transfer_of(
                self.last_name(),
                name,
                FailureClass::Unavailable,
                "no source has a table of contents of the layer, and `registry` is not one of them",
            ));
        };
        let fetcher = &self.fetchers[at];
        let mut bytes = 0u64;
        let mut fatal: Option<ImageError> = None;
        let walked = async {
            let (mut conn, _connected) = fetcher.connection().await?;
            let mut replies =
                crate::idle::within(fetcher.idle, conn.unpack(&name, Urgency::Wait)).await?;
            loop {
                match crate::idle::within(fetcher.idle, replies.unpacking()).await {
                    // (cumulative bytes of the blob; a beat repeats what was
                    // said or says none)
                    Ok(Some(Unpacking::Bytes(said))) => {
                        bytes = bytes.max(said);
                        progress(bytes);
                    }
                    Ok(Some(Unpacking::Files(files))) => {
                        // (a file that cannot be taken in is the engine's
                        // failure, not the fetcher's)
                        for file in files {
                            if let Err(e) = intake.give(file).await {
                                fatal.get_or_insert(e.into());
                                break;
                            }
                        }
                        if fatal.is_some() {
                            break;
                        }
                    }
                    // (the last reply: the names are given)
                    Ok(None) => break,
                    Err(CallError::Fetcher(crate::fetcher::fetch::FetcherError::Failed {
                        failure: said,
                    })) => {
                        fatal.get_or_insert(failure_step(&fetcher.name, true, said).0);
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok::<_, CallError>(())
        };
        let walked = walked.await;
        if let Some(e) = fatal.take() {
            return Err(e);
        }
        if let Err(e) = walked {
            self.untell(&name, at, &e);
            return Err(fetcher_error(&fetcher.name, e));
        }
        let (dir, indexer) = (staging.dir.try_clone()?, fetcher.name.clone());
        tokio::task::spawn_blocking(move || {
            let claim = read_beneath(&dir, TOC_CLAIM, super::chunked::MAX_TOC_JSON)
                .map_err(|e| by(&indexer, &name, e))?;
            let tarsplit = read_beneath(&dir, TARSPLIT, super::chunked::MAX_METADATA_COMPRESSED)
                .map_err(|e| by(&indexer, &name, e))?;
            let toc: Toc = serde_json::from_slice(&claim).map_err(|e| {
                ImageError::transfer_of(
                    &indexer,
                    name.clone(),
                    FailureClass::Invalid,
                    format!("the table of contents it made: {e}"),
                )
            })?;
            if let Some(problem) = crate::pull::entry::toc_problem(&toc.entries) {
                return Err(ImageError::transfer_of(
                    &indexer,
                    name,
                    FailureClass::Invalid,
                    problem,
                ));
            }
            Ok::<_, ImageError>(Whole {
                toc,
                tarsplit,
                bytes,
            })
        })
        .await
        .map_err(|e| ImageError::Layer(format!("the files of a layer: {e}")))?
    }

    /// One batch of files of `layer`: the list walked, each fetcher asked
    /// for what the ones before it did not stage; every file is given once.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_batch(
        &self,
        layer: &str,
        (batch, reuse): (&[String], &Reuses),
        dir: &File,
        names: &std::collections::HashMap<String, String>,
        sink: Option<Eager<'_>>,
        urgency: Urgency,
        counts: Counts<'_>,
    ) -> ImageResult<()> {
        let Counts {
            bytes,
            progress,
            sourced,
            staged,
            breaker,
            with_origin,
        } = counts;
        let mut given = vec![false; batch.len()];
        let mut failure: Option<ImageError> = None;
        let mut fatal: Option<ImageError> = None;
        let last = self.fetchers.len().saturating_sub(1);
        for (at, fetcher) in self
            .fetchers
            .iter()
            .enumerate()
            .filter(|(at, _)| breaker.usable(*at) && (with_origin || Some(*at) != self.origin))
        {
            let left: Vec<usize> = (0..batch.len()).filter(|i| !given[*i]).collect();
            if left.is_empty() {
                break;
            }
            let asked: Vec<String> = left.iter().map(|i| batch[*i].clone()).collect();
            // (the bytes of each object so far, by its place in `asked`)
            let mut moved: HashMap<u32, u64> = HashMap::new();
            // (a file is given: the pull knows it, and what a fetcher other
            // than the registry fetcher brought is counted)
            let mark = |given: &mut [bool], i: usize| {
                given[i] = true;
                staged(&batch[i]);
                if Some(at) != self.origin {
                    use std::sync::atomic::Ordering::Relaxed;
                    sourced.each[at].1.fetch_add(1, Relaxed);
                }
            };
            // (a file handed over was taken in, or not)
            let landed = |done: Result<(usize, ImageResult<()>), tokio::task::JoinError>,
                          given: &mut [bool]| {
                let (i, taken) = match done {
                    Ok(done) => done,
                    Err(e) => {
                        return Some(Said::Failed(ImageError::Layer(format!(
                            "a handed over file: {e}"
                        ))))
                    }
                };
                match taken {
                    Ok(()) => {
                        if let Some((_, layer, _)) = sink {
                            layer.placed_by(&batch[i], &fetcher.name);
                        }
                        mark(given, i);
                        None
                    }
                    Err(e @ (ImageError::Contradicted(_) | ImageError::Layer(_))) => {
                        Some(Said::Lied(format!("{}: {e}", batch[i])))
                    }
                    Err(e) => Some(Said::Failed(e)),
                }
            };
            // (the copies of the files it hands over are files of the pull's
            // session; the files of a storage driver are written at the
            // places it chose)
            let handover =
                fetcher.handover && sink.is_some_and(|(sink, ..)| sink.clone().session().is_some());
            // (the files handed over are taken in beside the call)
            let mut taken = tokio::task::JoinSet::new();
            let walked = async {
                let (mut conn, _connected) = fetcher.connection().await?;
                let (hints, sources) = if fetcher.reuse {
                    reuse.of(&asked)?
                } else {
                    (Vec::new(), Vec::new())
                };
                let mut replies = crate::idle::within(
                    fetcher.idle,
                    conn.fetch(layer, &asked, urgency, (&hints, sources), handover),
                )
                .await?;
                while let Some((event, fds)) =
                    crate::idle::within(fetcher.idle, replies.event()).await?
                {
                    match event.kind {
                        EventKind::Staged if event.files.is_some() => {
                            let (Some((sink, _, taking)), Some(places), true) =
                                (sink, &event.files, handover)
                            else {
                                return Ok(Said::Lied(
                                    "a file handed over to a call that did not ask".into(),
                                ));
                            };
                            let files = match files_at(places, fds) {
                                Ok(files) if files.len() == event.objects.len() => files,
                                Ok(_) => {
                                    return Ok(Said::Lied(
                                        "a file for each object is not what it handed over".into(),
                                    ))
                                }
                                Err(e) => return Ok(Said::Lied(e.to_string())),
                            };
                            for (j, file) in event.objects.iter().zip(files) {
                                let Some(&i) = left.get(*j as usize) else {
                                    return Ok(Said::Lied(
                                        "an event for a file that was not asked".into(),
                                    ));
                                };
                                if given[i] {
                                    continue;
                                }
                                let key = batch[i].clone();
                                let name = names.get(&key).cloned();
                                let sink = sink.clone();
                                let permit = taking.clone().acquire_owned().await.map_err(|e| {
                                    CallError::Protocol(format!("the files taken in: {e}"))
                                })?;
                                taken.spawn_blocking(move || {
                                    let taken =
                                        chunked::take_handed(file, (&key, name.as_deref()), &sink);
                                    drop(permit);
                                    (i, taken)
                                });
                            }
                            while let Some(done) = taken.try_join_next() {
                                if let Some(said) = landed(done, &mut given) {
                                    return Ok(said);
                                }
                            }
                        }
                        EventKind::Staged => {
                            for j in event.objects {
                                let Some(&i) = left.get(j as usize) else {
                                    return Ok(Said::Lied(
                                        "an event for a file that was not asked".into(),
                                    ));
                                };
                                if given[i] {
                                    continue;
                                }
                                // (what a fetcher says is staged is not
                                // believed: the file is there, a plain file
                                // of the staging, and what the sink makes of
                                // it is its own to say; a fetcher that is
                                // wrong fails the pull)
                                match sink {
                                    // (a lazy pull's file stays where it is
                                    // staged, named as the contract says)
                                    None => {
                                        let (dir, key) = (dir.try_clone()?, batch[i].clone());
                                        let verity = self.verity;
                                        let checked = tokio::task::spawn_blocking(move || {
                                            check_staged(&dir, &key, verity)
                                                .and_then(|file| lazy_read_only(&file))
                                        })
                                        .await
                                        .map_err(|e| {
                                            ImageError::Layer(format!("a staged file: {e}"))
                                        })
                                        .and_then(|r| r);
                                        if let Err(e) = checked {
                                            return Ok(Said::Lied(format!("{}: {e}", batch[i])));
                                        }
                                        self.placed
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .insert(
                                                (layer.to_string(), batch[i].clone()),
                                                fetcher.name.clone(),
                                            );
                                    }
                                    Some((sink, layer, _)) => {
                                        let key = batch[i].clone();
                                        let (layer, sink) = (layer.clone(), sink.clone());
                                        let name = names.get(&key).cloned();
                                        let verity = self.verity;
                                        let placed = (layer.clone(), key.clone());
                                        let gave = tokio::task::spawn_blocking(move || {
                                            give(&layer, &key, name.as_deref(), &sink, verity)
                                        })
                                        .await
                                        .map_err(|e| {
                                            ImageError::Layer(format!("a staged file: {e}"))
                                        })
                                        .and_then(|r| r);
                                        match gave {
                                            Ok(()) => placed.0.placed_by(&placed.1, &fetcher.name),
                                            Err(
                                                e @ (ImageError::Contradicted(_)
                                                | ImageError::Layer(_)),
                                            ) => {
                                                return Ok(Said::Lied(format!(
                                                    "{}: {e}",
                                                    batch[i]
                                                )));
                                            }
                                            Err(e) => return Ok(Said::Failed(e)),
                                        }
                                    }
                                }
                                mark(&mut given, i);
                            }
                        }
                        // (what the registry fetcher fetched, and what the
                        // fetchers before it brought)
                        EventKind::Progress => {
                            use std::sync::atomic::Ordering::Relaxed;
                            // (the bytes of one object so far: what is new
                            // since the last event of it; a beat with no
                            // object adds none)
                            let [object] = event.objects[..] else {
                                continue;
                            };
                            let so_far = event.bytes.unwrap_or(0);
                            let n =
                                so_far.saturating_sub(moved.insert(object, so_far).unwrap_or(0));
                            let counter = if Some(at) == self.origin {
                                bytes
                            } else {
                                &sourced.each[at].0
                            };
                            // (the number is the fetcher's: no wrap)
                            let _ =
                                counter.try_update(Relaxed, Relaxed, |c| Some(c.saturating_add(n)));
                            progress(
                                bytes.load(Relaxed)
                                    + sourced.each.iter().map(|e| e.0.load(Relaxed)).sum::<u64>(),
                            );
                        }
                        // (the next fetcher is asked for them)
                        EventKind::Failed => {
                            let (err, step) = failed_event(&fetcher.name, at == last, &event);
                            match step {
                                Step::Next => failure = Some(err),
                                // (the call is read to its end: the fetcher
                                // has stopped writing when the pull fails)
                                Step::Fail => {
                                    fatal.get_or_insert(err);
                                }
                            }
                        }
                        EventKind::Unavailable | EventKind::Unknown => {}
                    }
                }
                while let Some(done) = taken.join_next().await {
                    if let Some(said) = landed(done, &mut given) {
                        return Ok(said);
                    }
                }
                Ok::<_, CallError>(Said::Fine)
            };
            let walked = walked.await;
            // (a call that failed leaves no file being taken in)
            while taken.join_next().await.is_some() {}
            // (what a fetcher other than the registry fetcher sent of a file
            // it did not stage is thrown away: not counted as brought by it)
            if Some(at) != self.origin {
                let lost: u64 = moved
                    .iter()
                    .filter(|(j, _)| left.get(**j as usize).is_none_or(|i| !given[*i]))
                    .map(|(_, n)| *n)
                    .fold(0, u64::saturating_add);
                let _ = sourced.each[at].0.try_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |c| Some(c.saturating_sub(lost)),
                );
            }
            if let Some(e) = fatal.take() {
                return Err(e);
            }
            match walked {
                Ok(Said::Fine) => {}
                Ok(Said::Failed(e)) => return Err(e),
                // (the transfer was complete and the file is not: the pull
                // fails, no other fetcher is asked)
                Ok(Said::Lied(why)) => {
                    return Err(ImageError::transfer(
                        &fetcher.name,
                        FailureClass::Invalid,
                        format!("it staged {why}"),
                    ))
                }
                Err(e) if refused(&e) && at == last => return Err(fetcher_error(&fetcher.name, e)),
                Err(e) => {
                    self.untell(layer, at, &e);
                    breaker.trip(at, fetcher, &e);
                    // (the cause, when no other fetcher brings the files)
                    failure.get_or_insert_with(|| fetcher_error(&fetcher.name, e));
                }
            }
        }
        match given.iter().position(|g| !g) {
            None => Ok(()),
            Some(i) => Err(failure.unwrap_or_else(|| {
                let broken: Vec<String> = self
                    .fetchers
                    .iter()
                    .zip(&breaker.why)
                    .filter_map(|(f, why)| {
                        let why = why.lock().unwrap_or_else(|e| e.into_inner()).clone()?;
                        Some(format!("{}: {why}", f.name))
                    })
                    .collect();
                match broken.is_empty() {
                    // (every fetcher answered: it has not; only the origin's
                    // own `not_found`, a failed event, says it does not exist)
                    true => ImageError::transfer_of(
                        self.last_name(),
                        batch[i].clone(),
                        FailureClass::Unavailable,
                        "no fetcher has it",
                    ),
                    false => ImageError::transfer_of(
                        self.last_name(),
                        batch[i].clone(),
                        FailureClass::Transient,
                        format!("no fetcher has it (not asked: {})", broken.join("; ")),
                    ),
                }
            })),
        }
    }
}

/// Where the files of an eager pull go: its sink, the staging of the layer,
/// and the permits for the files taken in at once.
type Eager<'a> = (
    &'a Arc<dyn Sink>,
    &'a Arc<LayerStaging>,
    &'a Arc<tokio::sync::Semaphore>,
);

/// How a fetcher's reply to a request for files ended.
enum Said {
    Fine,
    /// What it said is not so (a file staged that is not there, not a plain
    /// file, or that the sink refuses as wrong): the pull fails, naming the
    /// fetcher and the file
    Lied(String),
    /// What the engine could not do with it: the pull fails
    Failed(ImageError),
}

/// What a walk of the list for the files of a layer brought.
#[derive(Debug, Default, Clone)]
pub struct Walked {
    /// The compressed bytes the registry fetcher said it fetched
    pub bytes: u64,
    /// What the other fetchers brought (the compressed bytes they said
    /// they fetched, the files they staged), by name, in the order of the
    /// walk
    pub sources: Vec<velarx_proto::workload::BySource>,
}

impl Walked {
    /// What another walk brought, counted in.
    pub fn add(&mut self, other: Walked) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        for s in other.sources {
            match self.sources.iter_mut().find(|m| m.name == s.name) {
                Some(m) => {
                    m.bytes = m.bytes.saturating_add(s.bytes);
                    m.files += s.files;
                }
                None => self.sources.push(s),
            }
        }
    }
}

#[derive(Default)]
struct Sourced {
    /// The bytes and files of each fetcher but the registry fetcher, by its
    /// place in the list
    each: Vec<(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicU64)>,
}

/// What the batches of a walk count in.
#[derive(Clone, Copy)]
struct Counts<'a> {
    bytes: &'a std::sync::atomic::AtomicU64,
    progress: &'a (dyn Fn(u64) + Send + Sync),
    sourced: &'a Sourced,
    /// Told the key of each file as soon as it is staged
    staged: &'a (dyn Fn(&str) + Send + Sync),
    breaker: &'a Breaker,
    /// The origin is asked too
    with_origin: bool,
}

/// A layer the origin unpacked whole, as [`StagedFetch::fetch_whole`] took
/// it: its files went to the intake.
pub struct Whole {
    /// The table of contents the origin claims
    pub toc: Toc,
    /// The compressed tar-split
    pub tarsplit: Vec<u8>,
    /// The compressed bytes fetched
    pub bytes: u64,
}

/// The staging of a layer, removed when it is dropped, before its lease is
/// let go.
/// The staging of a layer of an eager pull, open
/// ([`StagedFetch::open_layer`]).  Whatever the end of the fetches, also a
/// cancel, what is staged goes with it (it is the session's, or of a pull
/// that failed), unless a lazy pull keeps the layer; a process that dies
/// leaves it to the collector, [`sweep`].
pub struct LayerStaging {
    root: PathBuf,
    stem: String,
    /// A lazy pull staged the layer: its staging stays
    keep: bool,
    dir: File,
    /// The fetcher that staged each file, by key
    placed: Mutex<HashMap<String, String>>,
}

impl LayerStaging {
    /// The staging of the layer `stem` below `root`, made now.
    #[cfg(test)]
    pub(crate) fn made_for_test(root: &Path, stem: &str) -> Arc<Self> {
        let path = root.join(LAYERS).join(stem);
        std::fs::create_dir_all(&path).unwrap();
        Arc::new(Self {
            root: root.to_path_buf(),
            stem: stem.to_string(),
            keep: false,
            dir: File::open(&path).unwrap(),
            placed: Mutex::default(),
        })
    }

    /// The fetcher `name` staged the file `key`.
    pub fn placed_by(&self, key: &str, name: &str) {
        self.placed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), name.to_string());
    }

    /// The fetcher that staged the file `key` (the commit's failure names it).
    pub fn staged_by(&self, key: &str) -> Option<String> {
        self.placed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    /// The path of the staging directory of the layer.
    pub fn path(&self) -> PathBuf {
        self.root.join(LAYERS).join(&self.stem)
    }

    /// A lazy pull staged the layer: its staging stays whoever is done with
    /// it, and the files in it are where its containers find them.
    pub fn kept(&self) -> bool {
        self.keep
    }

    /// The directory of the staged files of the layer (the one the commit
    /// names the files of by `ab/cdef...`).
    pub fn files(&self) -> PathBuf {
        self.path().join("files")
    }

    /// Take the name of the staged file of `key` away.
    pub fn forget_name(&self, key: &str) {
        reject_staged(&self.dir, key);
    }

    /// The staging directory of the layer.
    pub fn dir(&self) -> &File {
        &self.dir
    }
}

impl Drop for LayerStaging {
    fn drop(&mut self) {
        // (a lazy pull of another process may have adopted the layer since
        // it was opened)
        if self.keep || lazily_staged(&self.root, &self.stem) {
            return;
        }
        let path = self.root.join(LAYERS).join(&self.stem);
        if let Err(e) = velarx_base::tree::remove_dir_all(&path) {
            if e.kind() != io::ErrorKind::NotFound {
                debug!("The staging {}: {e}", path.display());
            }
        }
    }
}

/// Remove the staging of the layers that no process stages any more (their
/// lease is not held: the process died) and no lazy pull keeps; the number
/// removed.
pub fn sweep(root: &Path) -> io::Result<usize> {
    let mut removed = 0;
    let stems: std::collections::BTreeSet<std::ffi::OsString> = [LAYERS, META]
        .iter()
        .filter_map(|d| std::fs::read_dir(root.join(d)).ok())
        .flat_map(|d| d.flatten().map(|e| e.file_name()))
        .collect();
    for stem in stems {
        let lease = std::fs::File::open(root.join(META).join(&stem).join("lease"));
        let free = match &lease {
            Ok(f) => rustix::fs::flock(f, FlockOperation::NonBlockingLockExclusive).is_ok(),
            Err(e) => e.kind() == io::ErrorKind::NotFound,
        };
        if !free || lazily_staged(root, &stem.to_string_lossy()) {
            continue;
        }
        for dir in [LAYERS, META] {
            match velarx_base::tree::remove_dir_all(root.join(dir).join(&stem)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        removed += 1;
    }
    Ok(removed)
}

/// Give the staged file of `key` to `sink`: the sink commits it where it is
/// staged (a session) or takes the bytes and the name goes (the staging of a
/// lazy pull, whose containers find the file there, keeps it).
fn give(
    layer: &Arc<LayerStaging>,
    key: &str,
    name: Option<&str>,
    sink: &Arc<dyn Sink>,
    verity: bool,
) -> ImageResult<()> {
    // (measured, not believed: what the kernel does not measure is read by
    // the replay or the commit, once)
    let file = check_staged(&layer.dir, key, verity)?;
    sink.adopt_staged(layer, &file, key, name)?;
    Ok(())
}

/// A fetcher staged a file that is not what its name says: the name goes,
/// or the next fetcher would find "a name that exists is success" and say
/// `staged` of the same bad file.
fn reject_staged(dir: &File, key: &str) {
    if let Some(rel) = staged_rel(key) {
        let _ = rustix::fs::unlinkat(dir, rel.as_str(), rustix::fs::AtFlags::empty());
    }
}

/// The staged file of `key`, opened, and measured against its name: an
/// fs-verity key by the digest the kernel measures, when it measures one.
/// What the kernel does not measure is not read here: the commit checks it,
/// in the one pass that copies it (or the replay that read it does), so a
/// file is never hashed twice.  Where the store has fs-verity (`verity`)
/// every fetcher seals what it stages, so a file of an fs-verity key that the
/// kernel does not measure is not what the fetcher says.  A file that is not
/// what its name says loses the name.
fn check_staged(dir: &File, key: &str, verity: bool) -> ImageResult<File> {
    let checked = open_staged(dir, key).and_then(|file| {
        let want = Digest::parse_key(key)
            .map_err(|_| ImageError::Layer(format!("{key} is not the digest of a file")))?;
        let measured = want
            .is_fsverity()
            .then(|| kernel_object(&file, want.alg()))
            .flatten();
        if verity && want.is_fsverity() && measured.is_none() {
            return Err(ImageError::Contradicted(format!(
                "the staged file {key} has no fs-verity, which the store asks of it"
            )));
        }
        match is_named_by(&want, measured.as_deref()) {
            true => Ok(file),
            false => Err(ImageError::Contradicted(format!(
                "the staged file {key} is not what its name says"
            ))),
        }
    });
    if checked.is_err() {
        reject_staged(dir, key);
    }
    checked
}

/// A file a lazy pull keeps where it is staged is made read-only by the
/// engine (no fetcher can change the mode afterwards: its seccomp list has no
/// `chmod`); one an eager pull gives to its session is made so by the commit,
/// which may enable fs-verity on it first (that needs write permission).
fn lazy_read_only(file: &File) -> ImageResult<()> {
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o444))
        .map_err(ImageError::from)
}

/// Whether a file with the kernel's measure `measured` (none: the kernel
/// does not measure it) may be the file named `want`.
fn is_named_by(want: &Digest, measured: Option<&str>) -> bool {
    measured.is_none_or(|m| Digest::parse_key(m).ok().as_ref() == Some(want))
}

/// The staged file of `key`, opened beneath the layer's staging directory:
/// a regular file of this user with one name, nothing a fetcher could point
/// elsewhere.
pub(crate) fn open_staged(dir: &File, key: &str) -> ImageResult<File> {
    let rel = staged_rel(key)
        .ok_or_else(|| ImageError::Layer(format!("{key} is not the digest of a file")))?;
    open_beneath(dir, &rel, key)
}

/// The object of the store a staged file is, as the kernel measures it
/// when the fetcher enabled fs-verity.
fn kernel_object(file: &File, alg: velarx_types::digest::Algorithm) -> Option<String> {
    velarx_storage::measure_file(file)
        .ok()
        .and_then(|m| m.object().map(|o| o.to_string()))
        .filter(|o| object_alg(o) == Some(alg))
}

/// The algorithm of an object's name.
fn object_alg(object: &str) -> Option<velarx_types::digest::Algorithm> {
    Digest::parse_fsverity(object).ok().map(|d| d.alg())
}

/// The bytes of the file `rel` of the layer's staging directory, at most
/// `max`.
fn read_beneath(dir: &File, rel: &str, max: u64) -> ImageResult<Vec<u8>> {
    use std::io::Read;
    let file = open_beneath(dir, rel, rel)?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(ImageError::Contradicted(format!(
            "the {rel} a fetcher made is larger than {max} bytes"
        )));
    }
    Ok(bytes)
}

/// The file `rel` beneath the staging directory `dir`, as [`open_staged`]
/// opens it.
fn open_beneath(dir: &File, rel: &str, key: &str) -> ImageResult<File> {
    let fd = velarx_sys::fs::openat2_retry(
        dir.as_fd(),
        rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(|e| ImageError::Layer(format!("the staged file {key}: {e}")))?;
    let file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.file_type().is_file()
        || meta.nlink() != 1
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ImageError::Layer(format!(
            "the staged file {key} is not a plain file of the staging"
        )));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::Limits;
    use crate::fetcher::fetch::{FetchEvent as Event, FetcherError, NotLazy, MAX_FDS};
    use crate::serve_fetch::{Described, LocalFetcher, Out, Scope, StagingFetcher};
    use async_trait::async_trait;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A call whose future is dropped before its replies came (a pull that
    /// ends while one of its layers probes) leaves the connection usable:
    /// the next call reads and drops what was left, and is answered.
    #[tokio::test]
    async fn a_dropped_call_leaves_the_connection_usable() {
        let f = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let mut conn = FetchConn::new(f.connect().unwrap()).unwrap();
        conn.open(Scoping::bare(REGISTRY_IDLE)).await.unwrap();
        // (dropped before any reply is read)
        let call = conn.get_manifest("latest", 100);
        let polled = futures::FutureExt::now_or_never(Box::pin(call));
        assert!(polled.is_none(), "the reply came at once");
        let info = conn.get_info().await.unwrap();
        assert_eq!(info.proto, crate::fetcher::fetch::PROTO);
    }

    /// A fetcher is handed only the bytes of the chunks it may reuse, in a
    /// file of the engine, read-only: never the file of the store they are
    /// in.
    #[test]
    fn the_reuse_hints_hand_only_the_chunks() {
        use std::os::unix::fs::FileExt;
        let (store, staging) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let object = store.path().join("object");
        std::fs::write(&object, b"0123456789abcdefghij").unwrap();
        let (from, dir) = (
            File::open(&object).unwrap(),
            File::open(staging.path()).unwrap(),
        );
        let mut reuse = Reuses::default();
        reuse
            .hint(&dir, "sha256:f", "sha256:c1".into(), &from, (2, 3))
            .unwrap();
        reuse
            .hint(&dir, "sha256:f", "sha256:c2".into(), &from, (10, 4))
            .unwrap();
        let reuse = reuse.sealed().unwrap();
        let (hints, fds) = reuse.of(&["sha256:f".to_string()]).unwrap();
        assert_eq!(fds.len(), 1);
        let file = File::from(fds.into_iter().next().unwrap());
        assert_eq!(file.metadata().unwrap().len(), 7, "only the chunks");
        let mut got = vec![0u8; 4];
        file.read_exact_at(&mut got, hints[1].offset).unwrap();
        assert_eq!(&got, b"abcd");
        assert!(file.write_at(b"x", 0).is_err(), "read-only");
        // (nothing of it is named in the staging)
        assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 0);
        // a file with no hints is given no descriptor
        assert!(reuse.of(&["sha256:g".to_string()]).unwrap().1.is_empty());
    }

    /// A fetcher that has the tables of the layers `has` (as `unpack`, which
    /// needs no file), says nothing of the others but `none`, and refuses a
    /// probe when `refuse`.
    struct Probes {
        has: Vec<u32>,
        refuse: bool,
    }

    #[async_trait]
    impl StagingFetcher for Probes {
        fn described(&self) -> Described {
            Described {
                name: "probed".into(),
                capabilities: vec!["objects".into(), "metadata".into()],
                max_objects: 8,
            }
        }

        async fn probe(
            &self,
            _scope: &Scope,
            layers: Vec<Blob>,
            _again: bool,
            out: &Out<Probed>,
        ) -> Result<(), FetcherError> {
            if self.refuse {
                return Err(FetcherError::Refused {
                    reason: "no".into(),
                });
            }
            for (at, blob) in layers.iter().enumerate() {
                // (the layers of the manifest below are named by their position)
                let wanted = u32::from_str_radix(&blob.digest[7..], 16).unwrap();
                let has = self.has.contains(&wanted);
                let reply = Probed {
                    layer: at as u32,
                    toc: if has {
                        TocSource::Unpack
                    } else {
                        TocSource::None
                    },
                    on_demand: has,
                    reason: (!has).then_some(NotLazy::Unreachable),
                    toc_file: None,
                    tarsplit_file: None,
                };
                if out.send(reply).await.is_err() {
                    break;
                }
            }
            Ok(())
        }
    }

    /// A manifest of four layers, whose digests are their numbers.
    fn manifest() -> Vec<u8> {
        let layers: Vec<String> = (0..4)
            .map(|i| {
                format!(
                    r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{i:064x}","size":1}}"#
                )
            })
            .collect();
        format!(
            r#"{{"schemaVersion":2,"config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":2}},"layers":[{}]}}"#,
            layers.join(",")
        )
        .into_bytes()
    }

    fn local(has: &[u32], refuse: bool) -> LocalFetcher {
        let api = Arc::new(Probes {
            has: has.to_vec(),
            refuse,
        });
        LocalFetcher::start(api, Limits::default()).unwrap()
    }

    async fn pull(before: &[(&str, &LocalFetcher)], end: &LocalFetcher) -> Arc<StagedFetch> {
        let links = before
            .iter()
            .map(|(name, f)| Link {
                name: name.to_string(),
                conn: FetchConn::new(f.connect().unwrap()).unwrap(),
                idle: REGISTRY_IDLE,
            })
            .collect();
        let staging = tempfile::tempdir().unwrap();
        StagedFetch::open(
            (
                links,
                Some(FetchConn::new(end.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            staging.path(),
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap()
    }

    /// The engine walks its list: each layer is answered once, by the first
    /// fetcher that has it; what nobody has is `none`, `unreachable`.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_layer_is_asked_of_the_next_fetcher_until_one_has_it() {
        let peers = local(&[0], false);
        let cache = local(&[1], false);
        let registry = local(&[1, 2], false);
        let staged = pull(&[("peers", &peers), ("cache", &cache)], &registry).await;
        assert_eq!(staged.sources(), ["peers", "cache", "registry"]);
        let mut got: Vec<(u32, TocSource)> = staged
            .probe_all(&[0, 1, 2, 3], false)
            .await
            .unwrap()
            .into_iter()
            .map(|(r, _)| (r.layer, r.toc))
            .collect();
        got.sort_by_key(|g| g.0);
        assert_eq!(
            got,
            [
                (0, TocSource::Unpack),
                (1, TocSource::Unpack),
                (2, TocSource::Unpack),
                (3, TocSource::None)
            ]
        );
    }

    /// The list is walked as given: the registry fetcher where the sources
    /// have it, or nowhere.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_registry_fetcher_is_where_the_sources_have_it() {
        let (peers, cache, registry) = (local(&[0], false), local(&[1], false), local(&[2], false));
        let link = |name: &str, f: &LocalFetcher| Link {
            name: name.to_string(),
            conn: FetchConn::new(f.connect().unwrap()).unwrap(),
            idle: REGISTRY_IDLE,
        };
        let staging = tempfile::tempdir().unwrap();
        for end in [Some(&registry), None] {
            let staged = StagedFetch::open(
                (
                    vec![link("peers", &peers)],
                    end.map(|f| FetchConn::new(f.connect().unwrap()).unwrap()),
                    vec![link("cache", &cache)],
                ),
                staging.path(),
                false,
                ("localhost/a", true),
                Some(b"{}"),
                &manifest(),
            )
            .await
            .unwrap();
            let mut answered: Vec<u32> = staged
                .probe_all(&[0, 1, 2], false)
                .await
                .unwrap()
                .into_iter()
                .filter(|(r, _)| r.toc != TocSource::None)
                .map(|(r, _)| r.layer)
                .collect();
            answered.sort();
            match end {
                Some(_) => {
                    assert_eq!(staged.sources(), ["peers", "registry", "cache"]);
                    assert_eq!(answered, [0, 1, 2]);
                }
                None => {
                    assert_eq!(staged.sources(), ["peers", "cache"]);
                    assert_eq!(answered, [0, 1]);
                }
            }
        }
    }

    /// A fetcher whose connection fails (a peer that restarted: its scope
    /// went with it) makes the list stale, so that a service that caches
    /// the list opens it anew; one that answers does not.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_connection_that_fails_makes_the_list_stale() {
        let peers = local(&[0], false);
        let registry = local(&[0], false);
        let staged = pull(&[("peers", &peers)], &registry).await;
        assert!(!staged.stale());
        staged.probe_all(&[0], false).await.unwrap();
        assert!(!staged.stale());
        drop(peers);
        staged.probe_all(&[0], false).await.unwrap();
        assert!(staged.stale(), "the peer is gone");
    }

    /// A fetcher that refuses the request ends the walk: the request is
    /// wrong for every fetcher.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refusal_ends_the_walk() {
        let peers = local(&[], true);
        let registry = local(&[0], false);
        let staged = pull(&[("peers", &peers)], &registry).await;
        assert!(staged.probe_all(&[0], false).await.is_err());
    }

    /// Stage each file of `call` where the contract has it, with the bytes
    /// its name says (`wrong`: other bytes).
    async fn stage_all(
        layer: &crate::serve_fetch::LayerScope,
        call: &crate::serve_fetch::FetchCall,
        out: &Out<Event>,
        wrong: bool,
    ) -> Result<(), FetcherError> {
        use std::io::Write;
        let failed = |e: rustix::io::Errno| FetcherError::failed(e.to_string());
        for name in &call.objects {
            let rel = crate::stager::staged_rel(name).unwrap();
            let (dir, _) = rel.rsplit_once('/').unwrap();
            for part in ["files", dir] {
                match rustix::fs::mkdirat(&layer.staging, part, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(e) => return Err(failed(e)),
                }
            }
            let file = rustix::fs::openat(
                &layer.staging,
                rel.as_str(),
                OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(failed)?;
            // (what the name says it is)
            let body = (0..=255u8)
                .map(body_of)
                .find(|b| &key_text(b) == name)
                .unwrap_or_default();
            let body = if wrong { b"not it".to_vec() } else { body };
            std::fs::File::from(file)
                .write_all(&body)
                .map_err(|e| FetcherError::failed(e.to_string()))?;
        }
        say_staged(call, out).await
    }

    /// The bytes of the test file `n`, and its key: the hash of them.
    fn body_of(n: u8) -> Vec<u8> {
        vec![n; 5]
    }

    fn key_text(body: &[u8]) -> String {
        Digest::of(velarx_types::digest::Algorithm::Sha256, body).to_string()
    }

    fn key_of(n: u8) -> String {
        key_text(&body_of(n))
    }

    /// Say that every file of `call` is staged.
    async fn say_staged(
        call: &crate::serve_fetch::FetchCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let staged = Event {
            objects: (0..call.objects.len() as u32).collect(),
            ..Event::of(EventKind::Staged)
        };
        out.send(staged)
            .await
            .map_err(|_| FetcherError::failed("gone"))
    }

    fn described_for_tests() -> Described {
        Described {
            name: "stages".into(),
            capabilities: vec!["objects".into(), "metadata".into()],
            max_objects: 8,
        }
    }

    /// A fetcher that stages every file it is asked for as an empty file
    /// named after it, in the staging directory it was told of.
    struct Stages;

    #[async_trait]
    impl StagingFetcher for Stages {
        fn described(&self) -> Described {
            described_for_tests()
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            layer: &crate::serve_fetch::LayerScope,
            call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            stage_all(layer, &call, out, false).await
        }
    }

    /// A fetcher that says every file is staged and stages none.
    struct Lies;

    #[async_trait]
    impl StagingFetcher for Lies {
        fn described(&self) -> Described {
            described_for_tests()
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            _layer: &crate::serve_fetch::LayerScope,
            call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            say_staged(&call, out).await
        }
    }

    /// A fetcher whose first fetch fails (a peer that was away) and the
    /// next ones stage; the number of fetches it was asked for.
    #[derive(Default)]
    struct Flaky(std::sync::atomic::AtomicUsize);

    #[async_trait]
    impl StagingFetcher for Flaky {
        fn described(&self) -> Described {
            described_for_tests()
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            layer: &crate::serve_fetch::LayerScope,
            call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return Err(FetcherError::failed("away"));
            }
            stage_all(layer, &call, out, false).await
        }
    }

    /// A fetcher that stops (its thread is stuck) and sends not even a beat.
    struct Wedged;

    #[async_trait]
    impl StagingFetcher for Wedged {
        fn described(&self) -> Described {
            described_for_tests()
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            layer: &crate::serve_fetch::LayerScope,
            call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            // (the thread of this call does not return to the runtime)
            std::thread::sleep(std::time::Duration::from_secs(3));
            stage_all(layer, &call, out, false).await
        }
    }

    /// A fetcher that says nothing for its idle time is that party failed,
    /// as transient: the next fetcher stages the file.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_that_stays_silent_is_left_for_the_next_fetcher() {
        let root = tempfile::tempdir().unwrap();
        let (staged, _keep) = walk_idle(
            vec![("wedged", Arc::new(Wedged))],
            Arc::new(Stages),
            root.path(),
            std::time::Duration::from_millis(400),
        )
        .await;
        let (desc, toc) = layer_and_toc();
        staged
            .stage_files(
                "stem",
                &desc,
                &toc,
                vec![key_of(1)],
                (Urgency::OnDemand, &|_| {}),
            )
            .await
            .unwrap();
    }

    /// A connection to `f` through a relay that passes nothing more, either
    /// way, once `mute` is set: a fetcher that takes calls and never answers.
    fn muted(f: &LocalFetcher, mute: Arc<AtomicBool>) -> FetchConn {
        use std::io::{Read, Write};
        let theirs = f.connect().unwrap();
        let (ours, relay) = std::os::unix::net::UnixStream::pair().unwrap();
        for (mut from, mut to) in [
            (relay.try_clone().unwrap(), theirs.try_clone().unwrap()),
            (theirs, relay),
        ] {
            let mute = mute.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n @ 1..) = from.read(&mut buf) {
                    if !mute.load(Ordering::SeqCst) && to.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
        FetchConn::new(ours).unwrap()
    }

    /// A fetcher that never answers is left out of the pull when it opens.
    #[tokio::test]
    async fn a_fetcher_that_never_answers_is_left_out() {
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let registry = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let link = Link {
            name: "peers".into(),
            conn: FetchConn::new(ours).unwrap(),
            idle: std::time::Duration::from_millis(200),
        };
        let staged = StagedFetch::open(
            (
                vec![link],
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            root.path(),
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap();
        assert_eq!(staged.sources(), ["registry"]);
    }

    /// A fetcher that stops answering in a pull is waited for once, for its
    /// idle time: the walks after it leave it out, and a probe does not wait
    /// for the reply it still owes.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_that_stops_answering_is_waited_for_once() {
        let idle = std::time::Duration::from_millis(300);
        let peers = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let registry = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let mute = Arc::new(AtomicBool::new(false));
        let root = tempfile::tempdir().unwrap();
        let link = Link {
            name: "peers".into(),
            conn: muted(&peers, mute.clone()),
            idle,
        };
        let staged = StagedFetch::open(
            (
                vec![link],
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            root.path(),
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap();
        assert_eq!(staged.sources(), ["peers", "registry"]);
        mute.store(true, Ordering::SeqCst);
        let (desc, toc) = layer_and_toc();
        for (n, most) in [(1, None), (2, Some(idle))] {
            let started = std::time::Instant::now();
            staged
                .stage_files(
                    "stem",
                    &desc,
                    &toc,
                    vec![key_of(n)],
                    (Urgency::OnDemand, &|_| {}),
                )
                .await
                .unwrap();
            if let Some(most) = most {
                assert!(started.elapsed() < most, "{:?}", started.elapsed());
            }
        }
        let probed = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            staged.probe_all(&[0], false),
        )
        .await;
        assert!(probed.is_ok(), "the probe waits for the silent fetcher");
    }

    /// A fetcher after the origin, the last of the list, that cannot take
    /// a layer is left out: the origin brings the files.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_last_fetcher_that_fails_a_layer_is_left_out() {
        let after = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let registry = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let mute = Arc::new(AtomicBool::new(false));
        let root = tempfile::tempdir().unwrap();
        let link = Link {
            name: "after".into(),
            conn: muted(&after, mute.clone()),
            idle: std::time::Duration::from_millis(200),
        };
        let staged = StagedFetch::open(
            (
                Vec::new(),
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                vec![link],
            ),
            root.path(),
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap();
        assert_eq!(staged.sources(), ["registry", "after"]);
        mute.store(true, Ordering::SeqCst);
        let (desc, toc) = layer_and_toc();
        staged
            .stage_files(
                "stem",
                &desc,
                &toc,
                vec![key_of(1)],
                (Urgency::OnDemand, &|_| {}),
            )
            .await
            .unwrap();
    }

    /// A layer whose staging was removed (committed) and is fetched again is
    /// told again: the files go into the new staging, not the removed one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_staging_made_again_is_told_again() {
        let registry = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let staged = StagedFetch::open(
            (
                Vec::new(),
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            root.path(),
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap();
        let desc: OciDescriptor = serde_json::from_str(
            r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar+zstd","digest":"sha256:5555555555555555555555555555555555555555555555555555555555555555","size":1}"#,
        )
        .unwrap();
        let toc = Toc {
            version: 1,
            entries: Vec::new(),
            tar_split_digest: None,
        };
        let dir = root.path().join(LAYERS).join("stem");
        let (first, second) = (key_of(1), key_of(2));
        for name in [first.as_str(), second.as_str()] {
            staged
                .stage_files(
                    "stem",
                    &desc,
                    &toc,
                    vec![name.into()],
                    (Urgency::OnDemand, &|_| {}),
                )
                .await
                .unwrap();
            assert!(
                dir.join(crate::stager::staged_rel(name).unwrap()).exists(),
                "{name} is in the staging of now"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Each fetch of files of a lazy layer costs what the files cost, not
    /// what the table of the layer does: a completion asks for a layer of
    /// many files in many groups (250 groups of a table of 20,000 entries
    /// took 24 s when each walked it, debug build).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetch_of_a_lazy_layer_does_not_walk_its_table() {
        let registry = LocalFetcher::start(Arc::new(Stages), Limits::default()).unwrap();
        let root = tempfile::tempdir().unwrap();
        let staged = StagedFetch::open(
            (
                Vec::new(),
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            root.path(),
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap();
        let (desc, _) = layer_and_toc();
        let entries: Vec<serde_json::Value> = (0..20_000)
            .map(|i| {
                serde_json::json!({
                    "name": format!("f{i}"),
                    "type": "reg",
                    "size": 10,
                    "fsverity": format!("sha256-12:{i:064x}"),
                })
            })
            .collect();
        let toc: Toc =
            serde_json::from_value(serde_json::json!({"version": 1, "entries": entries})).unwrap();
        let started = std::time::Instant::now();
        for n in 0..250 {
            staged
                .stage_files(
                    "stem",
                    &desc,
                    &toc,
                    vec![key_of(n)],
                    (Urgency::OnDemand, &|_| {}),
                )
                .await
                .unwrap();
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// A fetcher that is gone is left out (its breaker), and the next one
    /// answers.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_that_is_gone_is_skipped() {
        let peers = local(&[0], false);
        let registry = local(&[0], false);
        let staged = pull(&[("peers", &peers)], &registry).await;
        drop(peers);
        let got = staged.probe_all(&[0], false).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.toc, TocSource::Unpack);
    }

    fn layer_and_toc() -> (OciDescriptor, Toc) {
        let desc: OciDescriptor = serde_json::from_str(
            r#"{"mediaType":"application/vnd.oci.image.layer.v1.tar+zstd","digest":"sha256:5555555555555555555555555555555555555555555555555555555555555555","size":1}"#,
        )
        .unwrap();
        let toc = Toc {
            version: 1,
            entries: Vec::new(),
            tar_split_digest: None,
        };
        (desc, toc)
    }

    async fn walk_of(
        before: Vec<(&str, Arc<dyn StagingFetcher>)>,
        end: Arc<dyn StagingFetcher>,
        root: &Path,
    ) -> (Arc<StagedFetch>, Vec<LocalFetcher>) {
        walk_idle(before, end, root, REGISTRY_IDLE).await
    }

    /// [`walk_of`], the fetchers of `before` silent for at most `idle`.
    async fn walk_idle(
        before: Vec<(&str, Arc<dyn StagingFetcher>)>,
        end: Arc<dyn StagingFetcher>,
        root: &Path,
        idle: std::time::Duration,
    ) -> (Arc<StagedFetch>, Vec<LocalFetcher>) {
        let mut keep = Vec::new();
        let mut links = Vec::new();
        for (name, api) in before {
            let f = LocalFetcher::start(api, Limits::default()).unwrap();
            links.push(Link {
                name: name.into(),
                conn: FetchConn::new(f.connect().unwrap()).unwrap(),
                idle,
            });
            keep.push(f);
        }
        let registry = LocalFetcher::start(end, Limits::default()).unwrap();
        let staged = StagedFetch::open(
            (
                links,
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            root,
            false,
            ("localhost/a", true),
            Some(b"{}"),
            &manifest(),
        )
        .await
        .unwrap();
        keep.push(registry);
        (staged, keep)
    }

    /// A fetcher that stages other bytes than its names say.
    struct Wrong;

    #[async_trait]
    impl StagingFetcher for Wrong {
        fn described(&self) -> Described {
            described_for_tests()
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            layer: &crate::serve_fetch::LayerScope,
            call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            stage_all(layer, &call, out, true).await
        }
    }

    /// A pull whose files wait in a session (an eager pull) and the sink of
    /// it, on a store with no fs-verity.
    fn eager(root: &Path) -> (Arc<crate::pull::session::Session>, Arc<dyn Sink>) {
        let store = Arc::new(velarx_storage::FileStore::new(root.join("objects")).unwrap());
        let session = crate::pull::session::Session::create(root, store).unwrap();
        let sink: Arc<dyn Sink> = session.clone();
        (session, sink)
    }

    /// The first fetcher of a walk that stages as `Stages`, then a walk of
    /// the file `n` into a session: the walk's result and the session.
    async fn eager_walk(
        before: Arc<dyn StagingFetcher>,
        n: u8,
        root: &Path,
    ) -> (
        ImageResult<Walked>,
        Arc<crate::pull::session::Session>,
        String,
        Vec<LocalFetcher>,
    ) {
        let (staged, keep) = walk_of(vec![("first", before)], Arc::new(Stages), root).await;
        let (desc, toc) = layer_and_toc();
        let name = key_of(n);
        let (session, sink) = eager(root);
        let layer = staged.open_layer(&desc).await.unwrap();
        let walked = staged
            .fetch_files(
                &layer,
                &desc,
                &toc,
                (vec![name.clone()], &Reuses::default()),
                (&sink, &Arc::new(tokio::sync::Semaphore::new(2))),
                &|_| {},
            )
            .await;
        (walked, session, name, keep)
    }

    /// A fetcher that says a file is staged and did not stage it has
    /// finished a transfer with a file that is not there: the pull fails,
    /// naming the fetcher and the file, and no other fetcher is asked.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_said_to_be_staged_that_is_not_fails_the_pull_naming_the_fetcher() {
        let root = tempfile::tempdir().unwrap();
        let (walked, session, name, _keep) = eager_walk(Arc::new(Lies), 1, root.path()).await;
        let e = walked.unwrap_err().to_string();
        assert!(e.contains("first") && e.contains(&name), "{e}");
        assert!(!session.has_staged(&name));
        assert!(session.commit(None).unwrap().is_empty());
    }

    /// A fetcher that stages other bytes than its name says: the commit (the
    /// one pass that reads a file the kernel does not measure) refuses it,
    /// the pull fails naming the fetcher and the file, the next fetcher is
    /// not asked, and nothing is named in the store.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_staged_with_wrong_bytes_fails_the_pull_naming_the_fetcher() {
        let root = tempfile::tempdir().unwrap();
        let (walked, session, name, _keep) = eager_walk(Arc::new(Wrong), 3, root.path()).await;
        walked.unwrap();
        let e = session.commit(None).unwrap_err().to_string();
        assert!(e.contains("first") && e.contains(&name), "{e}");
        assert!(!session.store().contains_local(&name));
        assert!(!has_objects(root.path()), "nothing is named in the store");
    }

    /// A fetcher that took away the file it staged: the same.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_taken_away_after_it_was_staged_fails_the_pull_naming_the_fetcher() {
        let root = tempfile::tempdir().unwrap();
        let (walked, session, name, _keep) = eager_walk(Arc::new(Stages), 4, root.path()).await;
        walked.unwrap();
        let rel = staged_rel(&name).unwrap();
        for entry in std::fs::read_dir(root.path().join(LAYERS)).unwrap() {
            let _ = std::fs::remove_file(entry.unwrap().path().join(&rel));
        }
        let e = session.commit(None).unwrap_err().to_string();
        assert!(e.contains("first") && e.contains(&name), "{e}");
        assert!(!has_objects(root.path()), "nothing is named in the store");
    }

    /// A fetcher that hands over the files it is asked for as descriptors of
    /// one event, the bytes they are named by or, with `wrong`, others, and
    /// with `short`, one descriptor less than the objects and with `extra`
    /// that many descriptors more.  With `silent` it does not announce
    /// `handover`; `asked` is whether it was called with it.
    #[derive(Default)]
    struct HandsOver {
        wrong: bool,
        short: bool,
        extra: usize,
        silent: bool,
        asked: AtomicBool,
    }

    #[async_trait]
    impl StagingFetcher for HandsOver {
        fn described(&self) -> Described {
            let mut capabilities = vec!["objects".into(), "metadata".into()];
            if !self.silent {
                capabilities.push("handover".into());
            }
            Described {
                capabilities,
                ..described_for_tests()
            }
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            _layer: &crate::serve_fetch::LayerScope,
            call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            self.asked.store(call.handover, Ordering::Relaxed);
            let mut files: Vec<OwnedFd> = call
                .objects
                .iter()
                .map(|name| {
                    let body = (0..=255u8)
                        .map(body_of)
                        .find(|b| &key_text(b) == name)
                        .unwrap_or_default();
                    in_memory(if self.wrong { b"not it" } else { &body })
                })
                .collect();
            let objects: Vec<u32> = (0..files.len() as u32).collect();
            if self.short {
                files.pop();
            }
            let places = (0..files.len() as u32).collect();
            files.extend((0..self.extra).map(|_| in_memory(b"more")));
            let event = Event {
                files: Some(places),
                objects,
                ..Event::of(EventKind::Staged)
            };
            out.send_with(event, files)
                .await
                .map_err(|_| FetcherError::failed("gone"))
        }
    }

    /// The files a fetcher hands over are copied by the engine, known by
    /// the digest of the bytes it read, and named nowhere in the staging of
    /// the layer: the commit names them in the store.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_files_a_fetcher_hands_over_are_taken_in_and_committed() {
        let root = tempfile::tempdir().unwrap();
        let handing = Arc::new(HandsOver::default());
        let (walked, session, name, _keep) = eager_walk(handing, 5, root.path()).await;
        walked.unwrap();
        assert!(session.has_staged(&name));
        let rel = staged_rel(&name).unwrap();
        for entry in std::fs::read_dir(root.path().join(LAYERS)).unwrap() {
            assert!(!entry.unwrap().path().join(&rel).exists());
        }
        let committed = session.commit(None).unwrap();
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].digest, name);
        assert!(session.store().contains_local(&committed[0].object.verity));
    }

    /// A fetcher that hands over other bytes than the name says: the pull
    /// fails naming the fetcher and the file, and nothing is staged.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_handed_over_with_wrong_bytes_fails_the_pull_naming_the_fetcher() {
        let root = tempfile::tempdir().unwrap();
        let handing = Arc::new(HandsOver {
            wrong: true,
            ..Default::default()
        });
        let (walked, session, name, _keep) = eager_walk(handing, 6, root.path()).await;
        let e = walked.unwrap_err().to_string();
        assert!(e.contains("first") && e.contains(&name), "{e}");
        assert!(!session.has_staged(&name));
        assert!(!has_objects(root.path()), "nothing is named in the store");
    }

    /// An event of files with fewer descriptors than objects is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_event_that_hands_over_fewer_files_than_objects_fails_the_pull() {
        let root = tempfile::tempdir().unwrap();
        let handing = Arc::new(HandsOver {
            short: true,
            ..Default::default()
        });
        let (walked, session, name, _keep) = eager_walk(handing, 7, root.path()).await;
        let e = walked.unwrap_err().to_string();
        assert!(e.contains("first"), "{e}");
        assert!(!session.has_staged(&name));
    }

    /// A fetcher that does not announce `handover` is not called with it, and
    /// files it hands over all the same are refused: the engine takes the
    /// descriptors of the calls that asked for them.
    #[tokio::test(flavor = "multi_thread")]
    async fn files_handed_over_to_a_call_that_did_not_ask_fail_the_pull() {
        let root = tempfile::tempdir().unwrap();
        let handing = Arc::new(HandsOver {
            silent: true,
            ..Default::default()
        });
        let (walked, session, name, _keep) = eager_walk(handing.clone(), 8, root.path()).await;
        assert!(!handing.asked.load(Ordering::Relaxed));
        let e = walked.unwrap_err().to_string();
        assert!(e.contains("first") && e.contains("did not ask"), "{e}");
        assert!(!session.has_staged(&name));
    }

    /// A message has at most 16 descriptors, as the interface says: an event
    /// with more is refused, though it names only the ones it needs.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_event_with_more_descriptors_than_a_message_has_fails_the_pull() {
        let root = tempfile::tempdir().unwrap();
        let handing = Arc::new(HandsOver {
            extra: MAX_FDS,
            ..Default::default()
        });
        let (walked, session, name, _keep) = eager_walk(handing, 9, root.path()).await;
        let e = walked.unwrap_err().to_string();
        assert!(e.contains("first"), "{e}");
        assert!(!session.has_staged(&name));
    }

    /// Whether the store under `root` has a file.
    fn has_objects(root: &Path) -> bool {
        fn files(dir: &Path) -> bool {
            std::fs::read_dir(dir)
                .is_ok_and(|d| d.flatten().any(|e| e.path().is_file() || files(&e.path())))
        }
        files(&root.join("objects"))
    }

    /// A fetcher that fails to transfer (a peer that was away) is skipped:
    /// the next fetcher of the list stages the file.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_that_fails_leaves_the_file_to_the_next_fetcher() {
        let root = tempfile::tempdir().unwrap();
        let (walked, session, name, _keep) =
            eager_walk(Arc::new(Flaky::default()), 2, root.path()).await;
        walked.unwrap();
        assert!(session.has_staged(&name));
    }

    /// A fetcher that failed is left out of that call only: the next call
    /// of the same walker asks it again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_that_failed_is_asked_again_by_the_next_call() {
        let root = tempfile::tempdir().unwrap();
        let flaky = Arc::new(Flaky::default());
        let (staged, _keep) = walk_of(
            vec![("peers", flaky.clone())],
            Arc::new(Stages),
            root.path(),
        )
        .await;
        let (desc, toc) = layer_and_toc();
        for n in 1..=2 {
            staged
                .stage_files(
                    "stem",
                    &desc,
                    &toc,
                    vec![key_of(n)],
                    (Urgency::OnDemand, &|_| {}),
                )
                .await
                .unwrap();
        }
        assert_eq!(flaky.0.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// The file of an fs-verity key is the one the kernel measures to be
    /// that digest; what the kernel does not measure is left to the commit
    /// (which reads it once), and a measure of another digest is refused.
    #[test]
    fn a_staged_file_of_an_fsverity_key_is_accepted_only_by_its_measure() {
        let alg = velarx_types::digest::Algorithm::Sha256;
        let object = |body: &[u8]| velarx_storage::fsverity_digest_of(alg, body);
        let key = Digest::parse_key(&object(b"measured bytes")).unwrap();
        assert!(is_named_by(&key, Some(&object(b"measured bytes"))));
        assert!(!is_named_by(&key, Some(&object(b"other bytes"))));
        assert!(is_named_by(&key, None));
        // (the file of a plain directory is not measured, nor read here)
        let dir = tempfile::tempdir().unwrap();
        let root = File::open(dir.path()).unwrap();
        let rel = staged_rel(&key.to_string()).unwrap();
        std::fs::create_dir_all(dir.path().join(&rel).parent().unwrap()).unwrap();
        std::fs::write(dir.path().join(&rel), b"other bytes").unwrap();
        check_staged(&root, &key.to_string(), false).unwrap();
        assert!(dir.path().join(&rel).exists());
        // (the mode is the commit's to make: it may enable fs-verity first,
        // which needs write permission)
        assert_eq!(
            std::fs::metadata(dir.path().join(&rel)).unwrap().mode() & 0o222,
            0o200
        );
        // (where the store has fs-verity every fetcher seals what it
        // stages: an unsealed file is not what the fetcher says, and loses
        // its name)
        assert!(matches!(
            check_staged(&root, &key.to_string(), true),
            Err(ImageError::Contradicted(_))
        ));
        assert!(!dir.path().join(&rel).exists());
    }

    /// A fetcher that does not know the layer any more (it was told, and
    /// lost it) refuses the request: that is the engine's state, not the
    /// request's fault; the walk goes on to the registry fetcher, and the
    /// fetcher is told again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fetcher_that_lost_the_layer_does_not_end_the_walk() {
        let root = tempfile::tempdir().unwrap();
        let (staged, _keep) = walk_of(
            vec![("peers", Arc::new(Stages))],
            Arc::new(Stages),
            root.path(),
        )
        .await;
        let (desc, toc) = layer_and_toc();
        let layer = desc.digest.to_string();
        staged
            .stage_files(
                "stem",
                &desc,
                &toc,
                vec![key_of(1)],
                (Urgency::OnDemand, &|_| {}),
            )
            .await
            .unwrap();
        staged.fetchers[0]
            .control
            .lock()
            .await
            .forget(&layer)
            .await
            .unwrap();
        staged
            .stage_files(
                "stem",
                &desc,
                &toc,
                vec![key_of(2)],
                (Urgency::OnDemand, &|_| {}),
            )
            .await
            .unwrap();
        // (told again by the next call)
        staged
            .stage_files(
                "stem",
                &desc,
                &toc,
                vec![key_of(4)],
                (Urgency::OnDemand, &|_| {}),
            )
            .await
            .unwrap();
        let told = staged.told.lock().unwrap();
        assert!(told[&layer][0].is_some(), "the fetcher was told again");
    }

    /// A fetcher that sends some bytes of the first file it is asked for
    /// and fails before it stages it (a peer whose service died).
    struct SendsAndDies;

    #[async_trait]
    impl StagingFetcher for SendsAndDies {
        fn described(&self) -> Described {
            described_for_tests()
        }

        async fn fetch(
            &self,
            _scope: &Scope,
            _layer: &crate::serve_fetch::LayerScope,
            _call: crate::serve_fetch::FetchCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            let sent = Event {
                objects: vec![0],
                bytes: Some(1000),
                ..Event::of(EventKind::Progress)
            };
            out.send(sent)
                .await
                .map_err(|_| FetcherError::failed("gone"))?;
            Err(FetcherError::failed("died"))
        }
    }

    /// The bytes a fetcher sent of a file it did not stage are thrown away:
    /// they are not counted as brought by it (the file came from the next
    /// fetcher).
    #[tokio::test(flavor = "multi_thread")]
    async fn the_bytes_of_a_file_a_fetcher_did_not_stage_are_not_counted() {
        let root = tempfile::tempdir().unwrap();
        let (staged, _keep) = walk_of(
            vec![("peers", Arc::new(SendsAndDies))],
            Arc::new(Stages),
            root.path(),
        )
        .await;
        let (desc, toc) = layer_and_toc();
        let walked = staged
            .stage_files(
                "stem",
                &desc,
                &toc,
                vec![key_of(1)],
                (Urgency::OnDemand, &|_| {}),
            )
            .await
            .unwrap();
        let peers = walked.sources.iter().find(|s| s.name == "peers").unwrap();
        assert_eq!((peers.bytes, peers.files), (0, 0), "{walked:?}");
    }

    /// A file in memory that holds `bytes`.
    fn in_memory(bytes: &[u8]) -> OwnedFd {
        use std::io::Write;
        let fd = rustix::fs::memfd_create(
            "file",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .unwrap();
        File::from(fd.try_clone().unwrap())
            .write_all(bytes)
            .unwrap();
        fd
    }

    /// A fetcher that unpacks a layer of an empty table of contents and hands
    /// over the descriptors `give` makes, and says that the descriptors of
    /// its message are the positions `at`.
    struct Hands {
        give: fn() -> Vec<OwnedFd>,
        at: Vec<u32>,
    }

    #[async_trait]
    impl StagingFetcher for Hands {
        fn described(&self) -> Described {
            Described {
                name: "hands".into(),
                capabilities: vec!["objects".into(), "metadata".into(), "unpack".into()],
                max_objects: 8,
            }
        }

        async fn unpack(
            &self,
            _scope: &Scope,
            layer: &crate::serve_fetch::LayerScope,
            _call: crate::serve_fetch::UnpackCall,
            out: &Out<Event>,
        ) -> Result<(), FetcherError> {
            let event = Event {
                objects: self.at.clone(),
                ..Event::of(EventKind::Staged)
            };
            out.send_with(event, (self.give)())
                .await
                .map_err(|_| FetcherError::failed("gone"))?;
            let toc = Toc {
                version: 1,
                entries: Vec::new(),
                tar_split_digest: None,
            };
            crate::unpack::put_claim(&layer.staging, &toc, b"split")
                .map_err(|e| FetcherError::failed(e.to_string()))
        }
    }

    /// An intake into the session of a new store, of the layer of
    /// [`layer_and_toc`], and its staging.
    async fn intake_of(
        staged: &StagedFetch,
        root: &Path,
    ) -> (Intake, Arc<LayerStaging>, OciDescriptor) {
        let store = Arc::new(velarx_storage::FileStore::new(root.join("files")).unwrap());
        let session = crate::pull::session::Session::create(&root.join("session"), store).unwrap();
        let intake = Intake::new(session, velarx_types::digest::Algorithm::Sha256, 2);
        let (desc, _) = layer_and_toc();
        let staging = staged
            .open_layer_as(velarx_types::LayerKey::Whole(desc.digest))
            .await
            .unwrap();
        (intake, staging, desc)
    }

    /// The files an unpack hands over in its replies are taken in by the
    /// intake, each known by the digest of its content, and the claim is read
    /// from the staging once the last reply says the names are given.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_files_an_unpack_hands_over_are_taken_in() {
        let root = tempfile::tempdir().unwrap();
        let hands = Hands {
            give: || vec![in_memory(b"one"), in_memory(b"two")],
            at: vec![0, 1],
        };
        let (staged, _keep) = walk_of(vec![], Arc::new(hands), root.path()).await;
        let (intake, staging, desc) = intake_of(&staged, root.path()).await;
        let whole = staged
            .fetch_whole(&staging, &desc, &|_| {}, &intake)
            .await
            .unwrap();
        assert_eq!(whole.tarsplit, b"split");
        let taken = intake.finish().await.unwrap();
        let mut keys: Vec<_> = taken.keys().cloned().collect();
        keys.sort();
        let mut want: Vec<_> = [&b"one"[..], b"two"]
            .iter()
            .map(|b| Digest::of(velarx_types::digest::Algorithm::Sha256, b).to_string())
            .collect();
        want.sort();
        assert_eq!(keys, want);
    }

    /// A reply that names a descriptor it does not carry is a fetcher that
    /// broke the protocol: the layer is not unpacked.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_that_names_a_descriptor_it_lacks_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let hands = Hands {
            give: || vec![in_memory(b"one")],
            at: vec![0, 1],
        };
        let (staged, _keep) = walk_of(vec![], Arc::new(hands), root.path()).await;
        let (intake, staging, desc) = intake_of(&staged, root.path()).await;
        let e = staged
            .fetch_whole(&staging, &desc, &|_| {}, &intake)
            .await
            .err()
            .expect("a refusal");
        assert!(e.to_string().contains("descriptor"), "{e}");
    }

    /// A descriptor that is not a regular file open for reading (a pipe, whose
    /// read would wait forever, a descriptor of `O_PATH`, a write-only one) is
    /// a fetcher that broke the protocol: nothing of it is read, and the layer
    /// is not unpacked.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_descriptor_that_is_not_a_readable_regular_file_is_refused() {
        let pipe: fn() -> Vec<OwnedFd> = || {
            let (read, write) = rustix::pipe::pipe().unwrap();
            // (the end that writes stays open: a read would wait)
            std::mem::forget(write);
            vec![read]
        };
        let path: fn() -> Vec<OwnedFd> = || {
            let fd = in_memory(b"one");
            let proc = velarx_sys::fd::proc_path(&fd);
            vec![rustix::fs::open(&proc, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap()]
        };
        let write_only: fn() -> Vec<OwnedFd> = || {
            let fd = in_memory(b"one");
            let proc = velarx_sys::fd::proc_path(&fd);
            vec![rustix::fs::open(&proc, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty()).unwrap()]
        };
        for give in [pipe, path, write_only] {
            let root = tempfile::tempdir().unwrap();
            let hands = Hands { give, at: vec![0] };
            let (staged, _keep) = walk_of(vec![], Arc::new(hands), root.path()).await;
            let (intake, staging, desc) = intake_of(&staged, root.path()).await;
            let e = staged
                .fetch_whole(&staging, &desc, &|_| {}, &intake)
                .await
                .err()
                .expect("a refusal");
            assert!(
                e.to_string()
                    .contains("not a regular file open for reading"),
                "{e}"
            );
            assert!(intake.finish().await.unwrap().is_empty());
        }
    }
}
