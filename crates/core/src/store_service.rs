// SPDX-License-Identifier: Apache-2.0
//! The store service: the content of the store, by digest, for the
//! processes that give it to others (the service of a peer source), over varlink
//! (`org.velarx.Store`).
//!
//! The service owns the database and the objects; a client opens neither.
//! It asks for content by its sha256 and gets read-only descriptors of the
//! files that hold it, beside the reply, for what may be given to peers:
//! the files and chunks of the layers that `shared_layers` lists as proven.
//! What is private, or not in the store, simply has no descriptor.
//!
//! * `GetInfo`: the version of the protocol (a client refuses another) and
//!   the most digests a `Lookup` may carry ([`MAX_LOOKUP`]).
//! * `Lookup`: up to [`MAX_LOOKUP`] digests; for each one that may be
//!   given, a descriptor (an index into the descriptors of the reply), an
//!   offset and a length.  The descriptors are opened read-only.
//! * `Index`: the index of a shareable layer ([`velarx_content::pull::index`]) in a
//!   file with no name, read-only.
//! * `Profile`: the startup profile of an image, the file of the store
//!   itself, read-only.
//! * `ImageList` (one a reply, `more`), `ImageInspect`: the images the
//!   store has that may be given
//!   to peers ([`ImageInfo`]: the digests of the manifest, the
//!   configuration and the layers, the size, and whether the image is
//!   `complete`: a lazy image is listed as partial until its completion
//!   proved its layers).  Names are given only when the configuration says
//!   (`[pull] share_image_names`); builds, commits, loads and local tags
//!   are not the service's to tell.
//! * `Subscribe` (streamed, `more`): the shareable layers and images, a
//!   snapshot first, then what is added (an image added again is one that
//!   changed: it became complete) and removed.  The service watches
//!   the database (each commit of any process tells, once it is
//!   published) and the shares of checkpoints, so what any process commits
//!   is seen: no daemon is needed.
//!
//! The service runs in a process of its own (`velarx store-service`),
//! started by systemd with a socket (`LISTEN_FDS`), or on demand by a
//! client ([`start_if_absent`]) that passes it the listening socket as
//! descriptor 3; one instance serves a store (who binds the socket checks
//! under a lock that nothing answers on it), and it leaves after it was
//! idle, taking the socket it was given away first.  `velarx system
//! service` serves it in its own process instead ([`spawn_thread`]).

pub(crate) mod chunk_provider;
use crate::services::checkpoint::SharedCheckpoints;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, warn};
use velarx_config::Config;
use velarx_content::activation::{self, IdleExit};
use velarx_db::Database;
use velarx_proto::info::Info;
use velarx_storage::{ChunkFile, FileStore};
use zlink::{introspect, Reply};

/// The varlink interface.
pub const INTERFACE: &str = "org.velarx.Store";

/// The version of the protocol: a client refuses another one.
pub const PROTO: u32 = 1;

/// The most digests a `Lookup` carries: the files of one wave of such
/// a service, opened in one round trip.
pub const MAX_LOOKUP: usize = 8;

/// The longest reference `ImageInspect` takes.
const MAX_REFERENCE: usize = 512;

/// The fewest digits of an id that `ImageInspect` takes for the start of one.
const MIN_ID_PREFIX: usize = 12;

/// The changes kept for a subscriber that does not read; one that falls
/// further behind gets a snapshot again.
const CHANGES_KEPT: usize = 64;

/// What a client wants: the sha256 of a file or a chunk, and its size if
/// it knows it (an item of another size is not given).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct Want {
    /// `sha256:` and 64 lowercase hex digits, or `sha512:` and 128
    pub digest: String,
    /// The size the client expects, in bytes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// The answer for one digest: its bytes are `length` bytes from `offset` of
/// the file `fd`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct Item {
    /// The digest asked for
    pub digest: String,
    /// The position of its file among the descriptors of the reply; absent
    /// when it is not given
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<u32>,
    /// Where its bytes begin in the file
    #[serde(default)]
    pub offset: u64,
    /// How many bytes it has
    #[serde(default)]
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct LookupReply {
    /// One for each digest asked, in order
    pub items: Vec<Item>,
}

/// The index of a layer: a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct IndexReply {
    /// The position of the file among the descriptors of the reply
    pub fd: u32,
}

/// The startup profile of an image: a file of digests, one a line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ProfileReply {
    /// The position of the file among the descriptors of the reply
    pub file: u32,
}

/// An image that may be announced: the digests of what it is made of, and
/// the names a shared pull gave it when the configuration shares them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::CustomType)]
pub struct ImageInfo {
    /// Its id (the digest of its manifest without its algorithm: 64 hex
    /// digits for a sha256, 128 for a sha512)
    pub id: String,
    /// The digest of its manifest
    pub manifest_digest: String,
    /// The digest of its configuration
    pub config_digest: String,
    /// `repository:tag`; empty unless the names are shared
    pub tags: Vec<String>,
    /// `repository@manifest digest`; empty unless the names are shared
    pub repo_digests: Vec<String>,
    /// The layers, in order, by their keys (`sha256:<hex>`, the blob of a
    /// layer pulled whole; `toc:sha256:<hex>`, the TOC of a layer pulled
    /// through it: never one for the other): each one's index is asked of
    /// the service by it (`Index`), its files by theirs (`Lookup`)
    pub layers: Vec<String>,
    /// The sizes of the layers, together
    pub size: u64,
    /// When it was made, as its configuration says (RFC 3339)
    pub created_at: String,
    /// Every layer is proven and every file is in the store: the image is
    /// given whole.  False for a lazy image, until its completion.
    pub complete: bool,
}

/// A reply of `ImageList`: an image, none in the only reply of an empty
/// list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ImageListed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageInfo>,
}

/// What `ImageInspect` answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct ImageReply {
    pub image: ImageInfo,
}

/// What the store may announce to peers: the content digests, the layers and
/// the images that may be shared.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Announcement {
    /// Chunk or file digests
    #[serde(default)]
    pub content: Vec<String>,
    /// Layer digests
    #[serde(default)]
    pub layers: Vec<String>,
    /// Images
    #[serde(default)]
    pub images: Vec<ImageInfo>,
}

impl Announcement {
    /// The layers and images in the database.  `names`: the images carry
    /// the names a shared pull gave them.
    pub async fn from_database(
        db: &velarx_db::Database,
        names: bool,
    ) -> Result<Self, velarx_types::DbError> {
        // only what may be given to peers: the layers of public pulls, and
        // the images all of whose layers are (see below for the names)
        let shared = db.shareable_layers().await?;
        let public = db.public_layers().await?;
        // (a layer is announced by its key and by the blob it was pulled
        // for: a node that pulls the layer names it by its blob, and the
        // key of a layer pulled through its table of contents is the
        // digest of the table)
        let blobs = db.layer_blobs().await?;
        let mut layers: Vec<String> = Vec::new();
        for key in db.get_all_layer_digests().await? {
            if !shared.contains(&key) {
                continue;
            }
            let blob = blobs
                .get(&key)
                .filter(|b| velarx_db::LayerKey::parse(b).is_some());
            layers.extend(blob.cloned());
            layers.push(key.to_string());
        }
        layers.sort();
        layers.dedup();
        // only images a pull that may be shared recorded, under the names
        // that pull gave them: not a local tag, not a commit, not a
        // private repository
        let named = db.shared_images().await?;
        let mut images = Vec::new();
        for img in db.list_images().await? {
            let Some(allowed) = named.get(&img.id) else {
                continue;
            };
            let manifest: serde_json::Value =
                serde_json::from_str(&img.manifest).unwrap_or_default();
            let manifest_layers = manifest
                .get("layers")
                .and_then(|l| l.as_array())
                .cloned()
                .unwrap_or_default();
            // (its layers as the store has them: a layer of a TOC is not
            // the layer of its blob)
            let keys: Vec<velarx_db::LayerKey> = db
                .get_image_layers_without_toc(&img.id)
                .await?
                .into_iter()
                .map(|l| l.key)
                .collect();
            if keys.is_empty() || !keys.iter().all(|k| public.contains(k)) {
                continue;
            }
            // (an image with a layer that may not be given is not the
            // store's to list)
            if !keys.iter().all(|k| shared.contains(k)) {
                continue;
            }
            let layers: Vec<String> = keys.iter().map(ToString::to_string).collect();
            let (tags, repo_digests) = match names {
                true => {
                    let tags: Vec<(String, String)> = db
                        .get_tags_for_image(&img.id)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .map(|t| (t.repository, t.tag))
                        .filter(|name| allowed.contains(name))
                        .collect();
                    let mut repos: Vec<String> = tags
                        .iter()
                        .map(|(r, _)| format!("{r}@{}", img.manifest_digest))
                        .collect();
                    repos.sort();
                    repos.dedup();
                    (
                        tags.into_iter().map(|(r, t)| format!("{r}:{t}")).collect(),
                        repos,
                    )
                }
                false => (Vec::new(), Vec::new()),
            };
            let size = manifest_layers
                .iter()
                .filter_map(|l| l.get("size").and_then(|s| s.as_u64()))
                .sum();

            images.push(ImageInfo {
                id: img.id.clone(),
                manifest_digest: img.manifest_digest.to_string(),
                config_digest: img.config_digest.to_string(),
                tags,
                repo_digests,
                layers,
                size,
                created_at: img.created_at.clone(),
                // (the store holds only complete images)
                complete: true,
            });
        }
        Ok(Self {
            content: Vec::new(),
            layers,
            images,
        })
    }
}

/// What a change of `Subscribe` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[serde(rename_all = "lowercase")]
#[zlink(rename_all = "lowercase")]
pub enum ChangeKind {
    /// Everything that may be announced (the first change of a stream, and
    /// again after the subscriber fell behind)
    Snapshot,
    /// New layers and content, and the images that are new or changed (an
    /// image that became complete is one of them: take it as it is now)
    Added,
    /// What is not there any more (an image by its id)
    Removed,
}

/// What may be announced, or what changed in it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, introspect::Type)]
pub struct Change {
    pub kind: ChangeKind,
    /// The digests of layers
    pub layers: Vec<String>,
    /// The images (with `removed`, only their `id` is meaningful)
    pub images: Vec<ImageInfo>,
    /// Digests of content announced by itself: the pieces and manifests of
    /// the checkpoints this node shares
    #[serde(default)]
    pub content: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, zlink::ReplyError, introspect::ReplyError)]
#[zlink(interface = "org.velarx.Store")]
pub enum StoreError {
    /// A request the service does not take: too many digests, a digest
    /// that is not `sha256:` and 64 lowercase hex digits or `sha512:` and
    /// 128
    InvalidArgument { reason: String },
    /// The store cannot answer now (its database)
    Unavailable { reason: String },
    /// The store has nothing to give: no such image, or one that is not for
    /// the peers; for `Index` and `Profile`: no file, because the layer or
    /// the image is not shareable, the store has none for it, or it is
    /// larger than `max`
    NotFound { reason: String },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgument { reason } => write!(f, "invalid argument: {reason}"),
            Self::Unavailable { reason } => write!(f, "store unavailable: {reason}"),
            Self::NotFound { reason } => write!(f, "not found: {reason}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// What a call that has nothing to give answers: the layer or the image is
/// not shareable, the store has none for it, or it is larger than `max`.
fn none_to_give(what: &str, of: &str) -> StoreError {
    StoreError::NotFound {
        reason: format!("no {what} to give for {:?}", short(of)),
    }
}

/// What may be announced now: the shareable layers and images.
#[derive(Debug, Clone, Default, PartialEq)]
struct Shared {
    layers: Vec<String>,
    images: Vec<ImageInfo>,
    content: Vec<String>,
}

impl Shared {
    fn of(a: Announcement) -> Self {
        Self {
            layers: a.layers,
            images: a.images,
            content: a.content,
        }
    }

    fn snapshot(&self) -> Change {
        Change {
            kind: ChangeKind::Snapshot,
            layers: self.layers.clone(),
            images: self.images.clone(),
            content: self.content.clone(),
        }
    }

    /// What `self` adds to `before` and what it removes from it.
    fn diff(&self, before: &Shared) -> (Option<Change>, Option<Change>) {
        let old: HashSet<&String> = before.layers.iter().collect();
        let new: HashSet<&String> = self.layers.iter().collect();
        let old_content: HashSet<&String> = before.content.iter().collect();
        let new_content: HashSet<&String> = self.content.iter().collect();
        // (an image is the same by its id, and changed if it is not equal)
        let image_in = |list: &[ImageInfo], i: &ImageInfo| list.iter().any(|o| o == i);
        let image_has = |list: &[ImageInfo], i: &ImageInfo| list.iter().any(|o| o.id == i.id);
        let added = Change {
            kind: ChangeKind::Added,
            layers: self
                .layers
                .iter()
                .filter(|l| !old.contains(l))
                .cloned()
                .collect(),
            images: self
                .images
                .iter()
                .filter(|i| !image_in(&before.images, i))
                .cloned()
                .collect(),
            content: self
                .content
                .iter()
                .filter(|c| !old_content.contains(c))
                .cloned()
                .collect(),
        };
        let removed = Change {
            kind: ChangeKind::Removed,
            layers: before
                .layers
                .iter()
                .filter(|l| !new.contains(l))
                .cloned()
                .collect(),
            images: before
                .images
                .iter()
                .filter(|i| !image_has(&self.images, i))
                .cloned()
                .collect(),
            content: before
                .content
                .iter()
                .filter(|c| !new_content.contains(c))
                .cloned()
                .collect(),
        };
        let some = |c: Change| {
            (!c.layers.is_empty() || !c.images.is_empty() || !c.content.is_empty()).then_some(c)
        };
        (some(added), some(removed))
    }
}

impl Inner {
    /// What serves the files and chunks to peers, when the driver says it
    /// serves content (`Capabilities::serve_content`): nothing otherwise.
    fn chunks(&self) -> Option<&chunk_provider::StorageChunkProvider> {
        self.serves_content.then_some(&*self.chunks)
    }
}

struct Inner {
    db: Database,
    /// Whether the storage driver of the store says it serves content: peers
    /// are served only then
    serves_content: bool,
    /// What serves the files of the store to peers (the layout of the
    /// objects is composefs's whatever the driver is), when the driver serves
    /// content
    chunks: Arc<chunk_provider::StorageChunkProvider>,
    /// The objects of the store, next to which the startup profiles of the
    /// images are
    objects: PathBuf,
    /// The checkpoints this node shares
    checkpoints: Option<Arc<SharedCheckpoints>>,
    /// Whether the images carry the names a shared pull gave them
    names: bool,
    /// One look at the database at a time: a look that is older than
    /// another never replaces it
    looking: tokio::sync::Mutex<()>,
    shared: Mutex<Shared>,
    changes: broadcast::Sender<Change>,
}

/// The service: what the store has, for the connections of one process.
#[derive(Clone)]
pub struct StoreService {
    inner: Arc<Inner>,
}

impl StoreService {
    /// The service of the store of `config`, with a connection of its own
    /// to the database (so that it sees what the other connections of its
    /// process commit as well).
    pub async fn open(config: &Config) -> io::Result<Self> {
        // (a store nothing has used yet, without a daemon: an empty one)
        std::fs::create_dir_all(&config.storage.root)?;
        let db = Database::open_store(&config.storage)
            .await
            .map_err(io::Error::other)?;
        let files = Arc::new(config.storage.file_store().map_err(io::Error::other)?);
        // (read once, and again when the shares change: this service sees
        // them change)
        let checkpoints = SharedCheckpoints::new(&config.storage.root)?.cached();
        // (the driver the store was made with: what it serves is its own)
        let kind = match db.recorded_driver().await {
            Ok(recorded) => config.storage.resolve_driver(&recorded).ok(),
            Err(_) => None,
        }
        .unwrap_or_else(|| config.storage.driver_kind());
        Self::build(
            db,
            files,
            Some(Arc::new(checkpoints)),
            config.pull.share_image_names,
            kind,
        )
        .await
    }

    /// The service of `db` and `files`, which gives no names of images.
    pub async fn new(db: Database, files: Arc<FileStore>) -> io::Result<Self> {
        Self::build(
            db,
            files,
            None,
            false,
            velarx_config::StorageDriverKind::DEFAULT,
        )
        .await
    }

    /// The service of `db` and `files`, which gives the names of the images
    /// that a shared pull recorded.
    pub async fn with_names(db: Database, files: Arc<FileStore>) -> io::Result<Self> {
        Self::build(
            db,
            files,
            None,
            true,
            velarx_config::StorageDriverKind::DEFAULT,
        )
        .await
    }

    /// The service of `db` and `files`, which also gives the pieces of the
    /// checkpoints that `checkpoints` shares, and announces them.
    pub async fn with_checkpoints(
        db: Database,
        files: Arc<FileStore>,
        checkpoints: Arc<SharedCheckpoints>,
    ) -> io::Result<Self> {
        Self::build(
            db,
            files,
            Some(checkpoints),
            false,
            velarx_config::StorageDriverKind::DEFAULT,
        )
        .await
    }

    async fn build(
        db: Database,
        files: Arc<FileStore>,
        checkpoints: Option<Arc<SharedCheckpoints>>,
        names: bool,
        kind: velarx_config::StorageDriverKind,
    ) -> io::Result<Self> {
        let objects = files.root().to_path_buf();
        let chunks = Arc::new(chunk_provider::StorageChunkProvider::new(
            files.clone(),
            db.clone(),
        ));
        // (the driver of another process, `varlink`, serves nothing: the
        // engine has no files of its own to name the chunks by)
        let serves_content =
            crate::storage_driver::local_capabilities(kind).is_some_and(|c| c.serve_content);
        let shared = Shared::of(announcement(&db, checkpoints.as_ref(), names).await?);
        let (changes, _) = broadcast::channel(CHANGES_KEPT);
        Ok(Self {
            inner: Arc::new(Inner {
                db,
                serves_content,
                chunks,
                objects,
                checkpoints,
                names,
                looking: tokio::sync::Mutex::new(()),
                shared: Mutex::new(shared),
                changes,
            }),
        })
    }

    /// Look at the database again: what may be announced, and what changed
    /// since the last time (sent to the subscribers).  Returns whether
    /// anything changed.
    pub async fn refresh(&self) -> io::Result<bool> {
        let _look = self.inner.looking.lock().await;
        let now = Shared::of(
            announcement(
                &self.inner.db,
                self.inner.checkpoints.as_ref(),
                self.inner.names,
            )
            .await?,
        );
        // (sent under the lock: a subscriber takes its snapshot and joins
        // under it too, so it misses no change and gets none twice)
        let mut shared = self.inner.shared.lock().unwrap_or_else(|e| e.into_inner());
        let (added, removed) = now.diff(&shared);
        *shared = now;
        let changed = added.is_some() || removed.is_some();
        for change in [removed, added].into_iter().flatten() {
            // (nobody listening is not an error)
            let _ = self.inner.changes.send(change);
        }
        Ok(changed)
    }

    /// Watch the store, until the task is dropped: each time a process
    /// commits to the database (it tells once the commit is published, see
    /// [`velarx_db::ChangeWatch`]) or the records of the shared checkpoints
    /// change (inotify on their directory), [`Self::refresh`].  No timer.
    /// The changes that come while a scan runs are read together after it,
    /// so a burst of writes costs a few scans, not one for each.
    ///
    /// Returns when there is nothing to watch.  An error: the changes can
    /// no longer be followed (a directory that went away, a lost watch), and
    /// whoever serves has to leave, to be started again.
    pub async fn watch(self) -> io::Result<()> {
        self.watch_observed(&Unobserved).await
    }

    /// [`Self::watch`], reporting its progress to `observer`.
    async fn watch_observed<O: WatchObserver>(self, observer: &O) -> io::Result<()> {
        // (a database in memory has no other process to watch)
        let mut commits = if self.inner.db.path().is_some() {
            let watch =
                self.inner.db.watch_changes().map_err(|e| {
                    io::Error::new(e.kind(), format!("cannot watch the store: {e}"))
                })?;
            Some(watch)
        } else {
            None
        };
        let shares = self
            .inner
            .checkpoints
            .as_ref()
            .map(|c| c.shares_dir().to_path_buf());
        let mut writes = shares
            .as_deref()
            .map(ShareWrites::new)
            .transpose()
            .map_err(|e| io::Error::new(e.kind(), format!("cannot watch the store: {e}")))?;
        if commits.is_none() && writes.is_none() {
            return Ok(());
        }
        // (what changed between the snapshot the service was made with and
        // these watches: looked at once they are there)
        if let Some(checkpoints) = &self.inner.checkpoints {
            checkpoints.invalidate();
        }
        loop {
            observer.scanning();
            if let Err(e) = self.refresh().await {
                debug!("store service: what may be announced: {e}");
            }
            observer.idle();
            let lost = |e: io::Error| {
                io::Error::new(e.kind(), format!("the changes of the store are lost: {e}"))
            };
            tokio::select! {
                changed = async {
                    match commits.as_mut() {
                        Some(c) => c.changed().await,
                        None => std::future::pending().await,
                    }
                } => changed.map_err(lost)?,
                shares = async {
                    match writes.as_mut() {
                        Some(w) => w.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    shares.map_err(lost)?;
                    // (the records on the disk are not the ones that were read)
                    if let Some(checkpoints) = &self.inner.checkpoints {
                        checkpoints.invalidate();
                    }
                }
            }
        }
    }

    /// The images that may be given, as the store has them now (what any
    /// process committed is in them).
    pub async fn images_now(&self) -> Result<Vec<ImageInfo>, StoreError> {
        let unavailable = |e: io::Error| StoreError::Unavailable {
            reason: e.to_string(),
        };
        self.refresh().await.map_err(unavailable)?;
        let shared = self.inner.shared.lock().unwrap_or_else(|e| e.into_inner());
        Ok(shared.images.clone())
    }

    /// The image `image` names: its id (or the start of it, twelve digits
    /// or more), its manifest digest, and, when the names are given, one of
    /// its names or `repository@digest`.
    pub async fn image_by(&self, image: &str) -> Result<ImageInfo, StoreError> {
        if image.is_empty() || image.len() > MAX_REFERENCE {
            return Err(StoreError::InvalidArgument {
                reason: format!("not an image: {:?}", short(image)),
            });
        }
        let images = self.images_now().await?;
        let by = |matches: &dyn Fn(&ImageInfo) -> bool| -> Vec<&ImageInfo> {
            images.iter().filter(|i| matches(i)).collect()
        };
        let mut found = by(&|i| i.id == image || i.manifest_digest == image);
        if found.is_empty() {
            found = by(&|i| i.tags.iter().chain(&i.repo_digests).any(|n| n == image));
        }
        let hex = velarx_types::digest::without_algorithm(image);
        // (`sha256:` or `sha512:` in front: an id of that algorithm's length)
        let id_len = image
            .strip_suffix(hex)
            .and_then(|alg| alg.strip_suffix(':'))
            .and_then(|alg| velarx_types::digest::Algorithm::from_name(alg).ok())
            .map(|alg| alg.len() * 2);
        if found.is_empty()
            && hex.len() >= MIN_ID_PREFIX
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            found = by(&|i| i.id.starts_with(hex) && id_len.is_none_or(|n| i.id.len() == n));
        }
        match found.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(StoreError::NotFound {
                reason: format!("no image {:?} for the peers", short(image)),
            }),
            _ => Err(StoreError::InvalidArgument {
                reason: format!("{:?} names more than one image", short(image)),
            }),
        }
    }

    /// What may be announced now, and the changes that follow it.
    fn join(&self) -> (Change, broadcast::Receiver<Change>) {
        let shared = self.inner.shared.lock().unwrap_or_else(|e| e.into_inner());
        (shared.snapshot(), self.inner.changes.subscribe())
    }

    /// The answers to `wants`, and their descriptors.
    pub async fn lookup_items(
        &self,
        wants: &[Want],
    ) -> Result<(Vec<Item>, Vec<OwnedFd>), StoreError> {
        if wants.len() > MAX_LOOKUP {
            return Err(StoreError::InvalidArgument {
                reason: format!("at most {MAX_LOOKUP} digests in a lookup"),
            });
        }
        if let Some(w) = wants
            .iter()
            .find(|w| velarx_types::digest::Digest::parse_key(&w.digest).is_err())
        {
            return Err(StoreError::InvalidArgument {
                reason: format!("not a digest: {:?}", short(&w.digest)),
            });
        }
        let digests: Vec<String> = wants.iter().map(|w| w.digest.clone()).collect();
        let shareable = self
            .inner
            .db
            .are_contents_shareable(&digests)
            .await
            .map_err(|e| StoreError::Unavailable {
                reason: e.to_string(),
            })?;
        let opened = futures::future::join_all(wants.iter().enumerate().map(|(i, want)| {
            let shareable = shareable.get(i).copied().unwrap_or(false);
            async move {
                let found = match shareable {
                    true => match self.inner.chunks() {
                        Some(chunks) => chunks.open(&want.digest).await,
                        None => None,
                    },
                    // (not the store's: a piece of a checkpoint this node shares)
                    false => self.piece(&want.digest).await,
                };
                found.filter(|f| want.size.is_none_or(|size| size == f.len))
            }
        }))
        .await;
        let mut items = Vec::with_capacity(wants.len());
        let mut fds = Vec::new();
        for (want, found) in wants.iter().zip(opened) {
            let mut item = Item {
                digest: want.digest.clone(),
                fd: None,
                offset: 0,
                length: 0,
            };
            if let Some(chunk) = found {
                item.fd = Some(fds.len() as u32);
                item.offset = chunk.offset;
                item.length = chunk.len;
                fds.push(OwnedFd::from(chunk.file));
            }
            items.push(item);
        }
        Ok((items, fds))
    }

    /// The file of a piece or a manifest of a checkpoint this node shares.
    async fn piece(&self, digest: &str) -> Option<ChunkFile> {
        let shared = self.inner.checkpoints.clone()?;
        let digest = digest.to_string();
        let (file, len) = tokio::task::spawn_blocking(move || shared.open(&digest))
            .await
            .ok()??;
        Some(ChunkFile {
            file,
            offset: 0,
            len,
        })
    }

    /// The startup profile of the image `image` (`sha256:` and its id): the
    /// file of the store, opened read-only, if every layer of the image may
    /// be given, it is a profile, and it is at most `max` bytes.
    pub async fn profile_of(
        &self,
        image: &str,
        max: u64,
    ) -> Result<Option<(OwnedFd, u64)>, StoreError> {
        let Ok(digest) = image.parse::<velarx_types::digest::Digest>() else {
            return Err(StoreError::InvalidArgument {
                reason: format!("not a digest: {:?}", short(image)),
            });
        };
        let id = digest.hex();
        let id = id.as_str();
        let db = &self.inner.db;
        let unavailable = |e: velarx_types::DbError| StoreError::Unavailable {
            reason: e.to_string(),
        };
        // (an image no shareable pull recorded, as a commit that adds no
        // layer to a public base, is not given whatever its layers are)
        if !db.is_image_shared(id).await.map_err(unavailable)? {
            return Ok(None);
        }
        let layers = db.get_image_layers(id).await.map_err(unavailable)?;
        if layers.is_empty() {
            return Ok(None);
        }
        for layer in &layers {
            if !db
                .is_layer_shareable(&layer.key)
                .await
                .map_err(unavailable)?
            {
                return Ok(None);
            }
        }
        let (objects, id) = (self.inner.objects.clone(), id.to_string());
        let max = max.min(velarx_content::fetcher::fetch::PROFILE_MAX_BYTES);
        tokio::task::spawn_blocking(move || {
            let (file, length) = read_profile(&objects, &id)?;
            (length <= max).then(|| (OwnedFd::from(file), length))
        })
        .await
        .map_err(|e| StoreError::Unavailable {
            reason: e.to_string(),
        })
    }

    /// The index of the layer `layer` (its key: the layer of a TOC is not
    /// the one of its blob) in a file with no name, opened read-only, if it
    /// may be given and is at most `max` bytes.
    pub async fn index_of(
        &self,
        layer: &str,
        max: u64,
    ) -> Result<Option<(OwnedFd, u64)>, StoreError> {
        let Some(layer) = velarx_db::LayerKey::parse(layer) else {
            return Err(StoreError::InvalidArgument {
                reason: format!("not a layer: {:?}", short(layer)),
            });
        };
        let layer = &layer;
        let db = &self.inner.db;
        let unavailable = |e: velarx_types::DbError| StoreError::Unavailable {
            reason: e.to_string(),
        };
        // a layer that may be private is not described to anyone
        if !db.is_layer_shareable(layer).await.map_err(unavailable)? {
            return Ok(None);
        }
        let Ok(record) = db.get_layer(layer).await else {
            return Ok(None);
        };
        let Some(toc) = record.toc else {
            return Ok(None);
        };
        let Some(tarsplit) = db.get_layer_tarsplit(layer).await.map_err(unavailable)? else {
            return Ok(None);
        };
        let objects = self.inner.objects.clone();
        tokio::task::spawn_blocking(move || {
            let index = velarx_content::pull::index::encode(toc.as_bytes(), &tarsplit)?;
            if index.len() as u64 > max {
                return None;
            }
            let fd = velarx_content::pull::unnamed::read_only_unnamed(&objects, &index)
                .map_err(|e| warn!("store service: cannot hold an index: {e}"))
                .ok()?;
            Some((fd, index.len() as u64))
        })
        .await
        .map_err(|e| StoreError::Unavailable {
            reason: e.to_string(),
        })
    }

    /// The changes of what may be announced, a snapshot first.
    fn changes(&self, more: bool) -> Pin<Box<dyn Stream<Item = Reply<Change>> + Send>> {
        let (first, rx) = self.join();
        if !more {
            return Box::pin(futures::stream::once(async move {
                Reply::new(Some(first)).set_continues(Some(false))
            }));
        }
        let this = self.clone();
        let rest = futures::stream::unfold((rx, this), |(mut rx, this)| async move {
            let change = match rx.recv().await {
                Ok(change) => change,
                // fell behind: everything again, and the changes after it
                // (not the older ones still kept)
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let (snapshot, fresh) = this.join();
                    rx = fresh;
                    snapshot
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            };
            Some((
                Reply::new(Some(change)).set_continues(Some(true)),
                (rx, this),
            ))
        });
        let first = Reply::new(Some(first)).set_continues(Some(true));
        Box::pin(futures::StreamExt::chain(
            futures::stream::once(async move { first }),
            rest,
        ))
    }
}

/// What may be announced: the shareable layers and images of the database,
/// and the manifests and pieces of the shared checkpoints (announced as the
/// layers are, and by their digests).
async fn announcement(
    db: &Database,
    checkpoints: Option<&Arc<SharedCheckpoints>>,
    names: bool,
) -> io::Result<Announcement> {
    let mut a = Announcement::from_database(db, names)
        .await
        .map_err(io::Error::other)?;
    if let Some(shared) = checkpoints.cloned() {
        let (manifests, digests) = tokio::task::spawn_blocking(move || shared.announced())
            .await
            .map_err(io::Error::other)?;
        a.layers.extend(manifests);
        a.content.extend(digests);
    }
    Ok(a)
}

/// The changes of the directory of the shared checkpoints (a share is a
/// record renamed into place, an unshare removes it): inotify.
struct ShareWrites {
    fd: tokio::io::unix::AsyncFd<OwnedFd>,
}

/// What the watch of the store reports of its progress, to whoever watches
/// the watcher.
trait WatchObserver {
    /// The watcher has read every event and waits for more.
    fn idle(&self) {}
    /// The watcher scans the store for what may be announced.
    fn scanning(&self) {}
}

/// Nobody looks.
struct Unobserved;

impl WatchObserver for Unobserved {}

impl ShareWrites {
    /// Watch the directory `shares`.
    fn new(shares: &Path) -> io::Result<Self> {
        use rustix::fs::inotify::{self, WatchFlags};
        let fd = velarx_sys::watch::inotify_init()?;
        inotify::add_watch(
            &fd,
            shares,
            WatchFlags::DELETE_SELF
                | WatchFlags::MOVE_SELF
                | WatchFlags::CREATE
                | WatchFlags::MOVED_TO
                | WatchFlags::MOVED_FROM
                | WatchFlags::DELETE,
        )?;
        Ok(Self {
            fd: velarx_sys::fd::register(
                fd,
                tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
            )?,
        })
    }

    /// Until a share changed.
    async fn next(&mut self) -> io::Result<()> {
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 4096];
        loop {
            let mut guard = self.fd.readable().await?;
            let mut written = false;
            let mut reader = rustix::fs::inotify::Reader::new(guard.get_inner(), &mut buf);
            loop {
                match reader.next() {
                    Ok(event) => {
                        use rustix::fs::inotify::ReadFlags;
                        // (the watch ended: the directory was removed, moved
                        // or unmounted; nothing will be reported again)
                        if event.events().intersects(
                            ReadFlags::IGNORED
                                | ReadFlags::DELETE_SELF
                                | ReadFlags::MOVE_SELF
                                | ReadFlags::UNMOUNT,
                        ) {
                            return Err(io::Error::other("a watched directory is gone"));
                        }
                        // (events were lost: any of them may be ours)
                        written |= event.events().contains(ReadFlags::QUEUE_OVERFLOW)
                            // (not the work of a share in progress)
                            || event
                                .file_name()
                                .is_some_and(|n| !n.to_bytes().starts_with(b".tmp-"));
                    }
                    Err(rustix::io::Errno::AGAIN) => {
                        guard.clear_ready();
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if written {
                return Ok(());
            }
        }
    }
}

/// The startup profile of the image `id` next to its record, when it is one:
/// the file, and the number of bytes that were checked.
#[cfg(feature = "fuse")]
fn read_profile(objects: &Path, id: &str) -> Option<(std::fs::File, u64)> {
    use velarx_fuse::{composefs, profile};
    let path = composefs::profile_path(objects, id);
    let file = std::fs::File::open(path).ok()?;
    let text = profile::read_from(&file)?;
    (!profile::parse(&text, usize::MAX).is_empty()).then_some((file, text.len() as u64))
}

#[cfg(not(feature = "fuse"))]
fn read_profile(_: &Path, _: &str) -> Option<(std::fs::File, u64)> {
    None
}

/// A short form of what a client sent, for an error.
fn short(s: &str) -> String {
    s.chars().take(80).collect()
}

mod service {
    #![allow(missing_docs)]
    use super::*;

    #[zlink::service(
        interface = "org.velarx.Store",
        description = |_| velarx_proto::interfaces::store(),
        vendor = "org.velarx",
        product = "velarx",
        version = env!("CARGO_PKG_VERSION"),
        url = env!("CARGO_PKG_HOMEPAGE"),
        types = [Want, Item, ImageInfo, ChangeKind]
    )]
    impl StoreService {
        /// Who serves this interface and what it can do.  The first call of a
        /// connection; a client refuses a `proto` other than its own.
        async fn get_info(&self) -> Info {
            Info {
                name: "store".into(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                proto: PROTO,
                limits: [("max_lookup".to_string(), MAX_LOOKUP as u64)].into(),
                ..Info::default()
            }
        }

        /// The images that may be given to peers, complete or not, one a
        /// reply.
        #[zlink(more)]
        async fn image_list(
            &self,
            more: bool,
        ) -> impl Stream<Item = Result<Reply<ImageListed>, StoreError>> + Unpin {
            let listed = if more {
                self.images_now().await
            } else {
                Err(StoreError::InvalidArgument {
                    reason: "ImageList answers one image a reply: call it with more".into(),
                })
            };
            image_replies(listed)
        }

        /// One image, by id, manifest digest or name.
        async fn image_inspect(&self, image: String) -> Result<ImageReply, StoreError> {
            Ok(ImageReply {
                image: self.image_by(&image).await?,
            })
        }

        /// Read-only descriptors of the files that hold `wants`, for those
        /// that may be given to peers.
        #[zlink(return_fds)]
        async fn lookup(
            &self,
            wants: Vec<Want>,
        ) -> (Result<LookupReply, StoreError>, Vec<OwnedFd>) {
            match self.lookup_items(&wants).await {
                Ok((items, fds)) => (Ok(LookupReply { items }), fds),
                Err(e) => (Err(e), Vec::new()),
            }
        }

        /// The index of a shareable layer, in a file with no name.
        #[zlink(return_fds)]
        async fn index(
            &self,
            layer: String,
            max: u64,
        ) -> (Result<IndexReply, StoreError>, Vec<OwnedFd>) {
            match self.index_of(&layer, max).await {
                Ok(Some((fd, _))) => (Ok(IndexReply { fd: 0 }), vec![fd]),
                Ok(None) => (Err(none_to_give("index", &layer)), Vec::new()),
                Err(e) => (Err(e), Vec::new()),
            }
        }

        /// The startup profile of an image: the file of the store.
        #[zlink(return_fds)]
        async fn profile(
            &self,
            image: String,
            max: u64,
        ) -> (Result<ProfileReply, StoreError>, Vec<OwnedFd>) {
            match self.profile_of(&image, max).await {
                Ok(Some((fd, _))) => (Ok(ProfileReply { file: 0 }), vec![fd]),
                Ok(None) => (Err(none_to_give("profile", &image)), Vec::new()),
                Err(e) => (Err(e), Vec::new()),
            }
        }

        /// What may be announced, then what changes in it, called with
        /// `more`: a `snapshot`, then `added` and `removed` as the store
        /// changes, until the client closes the connection.
        #[zlink(more)]
        async fn subscribe(&self, more: bool) -> impl Stream<Item = Reply<Change>> + Unpin {
            self.changes(more)
        }
    }

    /// The interface as the macro described it (the binary serves the file).
    #[cfg(test)]
    pub(super) fn description() -> String {
        format!("{}", __StoreService_INTERFACE_0)
    }
}

/// The text of the interface definition (`interfaces/org.velarx.Store.varlink`),
/// made from the types and the methods above.
#[cfg(test)]
pub fn definition() -> String {
    format!(
        "# SPDX-License-Identifier: Apache-2.0\n\
         #\n\
         # The interface org.velarx.Store: what the store of a node may give to the\n\
         # other nodes, served on services/store.sock to the fetchers of the node\n\
         # that serve its peers.  Generated from the Rust types\n\
         # (crates/core/src/store_service.rs) by the test\n\
         # `store_service::tests::the_interface_file_is_current`:\n\
         # VELARX_WRITE_INTERFACES=1 cargo test -p velarx-core --lib store_service writes it.\n\
         #\n\
         # A client calls GetInfo on each connection and refuses a `proto` other than its\n\
         # own ({PROTO}).  Only what shareable pulls stored is given (the layers of\n\
         # public pulls, and the images whose layers are all public); the files cross as\n\
         # read-only descriptors in the SCM_RIGHTS of the reply, named in the JSON by\n\
         # their position, and a client checks every byte it reads from them.\n\
         # Who may call: a peer of the same user or root (SO_PEERCRED); any\n\
         # accepted peer may make every call.\n\
         \n{}\n",
        service::description()
    )
}

/// The replies of `ImageList`: one image each, the last with `continues:
/// false`; an empty list is one reply without an image.
fn image_replies(
    listed: Result<Vec<ImageInfo>, StoreError>,
) -> impl Stream<Item = Result<Reply<ImageListed>, StoreError>> + Unpin + Send {
    let replies = match listed {
        Err(e) => vec![Err(e)],
        Ok(list) if list.is_empty() => vec![Ok(
            Reply::new(Some(ImageListed { image: None })).set_continues(Some(false))
        )],
        Ok(list) => {
            let last = list.len() - 1;
            list.into_iter()
                .enumerate()
                .map(|(i, image)| {
                    Ok(Reply::new(Some(ImageListed { image: Some(image) }))
                        .set_continues(Some(i < last)))
                })
                .collect()
        }
    };
    futures::stream::iter(replies)
}

/// The images of `ImageList`, all of them.  (A call of its own, not the
/// proxy's: the future is `Send`.)
pub async fn image_list(
    conn: &mut zlink::Connection<zlink::tokio::unix::Stream>,
) -> io::Result<Vec<ImageInfo>> {
    #[derive(Serialize, Debug)]
    struct ImageList {
        method: &'static str,
    }
    let call = zlink::Call::new(ImageList {
        method: "org.velarx.Store.ImageList",
    })
    .set_more(true);
    let other = |e: zlink::Error| io::Error::other(e.to_string());
    conn.send_call(&call, Vec::new()).await.map_err(other)?;
    let mut out = Vec::new();
    loop {
        let (reply, _) = conn
            .read_mut()
            .receive_reply::<ImageListed, StoreError>()
            .await
            .map_err(other)?;
        let reply = reply.map_err(io::Error::other)?;
        let more = reply.continues() == Some(true);
        if let Some(listed) = reply.into_parameters() {
            out.extend(listed.image);
        }
        if !more {
            return Ok(out);
        }
    }
}

/// The client side of the interface.
#[zlink::proxy("org.velarx.Store")]
pub trait StoreProxy {
    async fn get_info(&mut self) -> zlink::Result<Result<Info, StoreError>>;
    #[zlink(more)]
    async fn image_list(
        &mut self,
    ) -> zlink::Result<impl Stream<Item = zlink::Result<Result<ImageListed, StoreError>>>>;
    async fn image_inspect(&mut self, image: &str)
        -> zlink::Result<Result<ImageReply, StoreError>>;
    #[zlink(return_fds)]
    async fn lookup(
        &mut self,
        wants: Vec<Want>,
    ) -> zlink::Result<(Result<LookupReply, StoreError>, Vec<OwnedFd>)>;
    #[zlink(return_fds)]
    async fn index(
        &mut self,
        layer: &str,
        max: u64,
    ) -> zlink::Result<(Result<IndexReply, StoreError>, Vec<OwnedFd>)>;
    #[zlink(return_fds)]
    async fn profile(
        &mut self,
        image: &str,
        max: u64,
    ) -> zlink::Result<(Result<ProfileReply, StoreError>, Vec<OwnedFd>)>;
    #[zlink(more)]
    async fn subscribe(
        &mut self,
    ) -> zlink::Result<impl Stream<Item = zlink::Result<Result<Change, StoreError>>>>;
}

/// The socket of the store service of `config`.
pub fn socket_path(config: &Config) -> PathBuf {
    config.services_dir().join("store.sock")
}

/// Serve `service` on `listener`, for good with no `idle`.  Each connection
/// has a server of its own, so that a slow call of one does not hold the
/// others.  The caller runs this in a `LocalSet` (the servers of zlink are
/// not `Send`).
///
/// Fails when the changes of the store cannot be followed any more (see
/// [`StoreService::watch`]): announcements would stop for good, so the
/// service ends and is started again.
pub async fn serve(
    listener: tokio::net::UnixListener,
    service: StoreService,
    idle: Option<IdleExit>,
    trusted: fn(u32) -> bool,
    limits: activation::Limits,
) -> io::Result<()> {
    let mut watcher = tokio::spawn(service.clone().watch());
    let serving =
        activation::serve_varlink(listener, idle, trusted, limits, "store service", service);
    tokio::pin!(serving);
    let result = tokio::select! {
        () = &mut serving => Ok(()),
        watched = &mut watcher => match watched.map_err(io::Error::other).and_then(|r| r) {
            Err(e) => Err(e),
            // (nothing to watch: serves on)
            Ok(()) => {
                serving.await;
                Ok(())
            }
        },
    };
    watcher.abort();
    result
}

/// Serve on a runtime of this thread (current thread, with a `LocalSet`).
pub fn run_blocking(
    config: &Config,
    listener: std::os::unix::net::UnixListener,
    idle: Option<IdleExit>,
) -> io::Result<()> {
    run_until(
        config,
        listener,
        idle,
        &tokio::sync::watch::channel(false).1,
    )
}

/// [`run_blocking`] until `stop` says true: Ok then, and nothing of the
/// store is made (opened, created again) when it said so already.
fn run_until(
    config: &Config,
    listener: std::os::unix::net::UnixListener,
    idle: Option<IdleExit>,
    stop: &tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let local = tokio::task::LocalSet::new();
    let mut stop = stop.clone();
    local.block_on(&runtime, async move {
        if *stop.borrow() {
            return Ok(());
        }
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        let service = StoreService::open(config).await?;
        let limits = activation::Limits::of(&config.services);
        let serving = serve(
            listener,
            service,
            idle,
            velarx_base::ipc::trusted_uid,
            limits,
        );
        tokio::select! {
            served = serving => served,
            // (a sender that is gone, a detached service, never says stop)
            _ = async {
                if stop.wait_for(|stopped| *stopped).await.is_err() {
                    std::future::pending::<()>().await;
                }
            } => Ok(()),
        }
    })
}

/// The store service a process serves in a thread of its own
/// ([`spawn_thread`]).  Dropped, it stops the service and waits for the
/// thread: nothing of it is left running, or makes the directory of the
/// store again.  [`ServiceThread::detach`] lets it run for as long as the
/// process does.
pub struct ServiceThread {
    stop: Option<tokio::sync::watch::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ServiceThread {
    /// Serve for as long as the process lives.
    pub fn detach(mut self) {
        // (the service takes a stop sender that is gone for "never")
        self.stop = None;
        self.thread = None;
    }
}

impl Drop for ServiceThread {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send_replace(true);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serve the store service from this process, in a thread of its own
/// (`velarx varlink`), when no other instance serves the store: None then.
pub fn spawn_thread(config: &Config) -> io::Result<Option<ServiceThread>> {
    let socket = socket_path(config);
    let listener = match activation::connect_or_bind(&socket)? {
        Ok(_) => {
            debug!("store service: another process serves {}", socket.display());
            return Ok(None);
        }
        Err(listener) => listener,
    };
    let config = config.clone();
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let thread = std::thread::Builder::new()
        .name("store-service".into())
        .spawn(move || {
            let result = serve_again(RESTARTS, |_| {
                run_until(&config, listener.try_clone()?, None, &stopped)
            });
            if let Err(e) = result {
                warn!("store service: {e}: it stays down until the daemon restarts");
            }
        })?;
    Ok(Some(ServiceThread {
        stop: Some(stop),
        thread: Some(thread),
    }))
}

/// How many times the service of a daemon is started again after it lost
/// the store.
const RESTARTS: usize = 3;

/// Run `serve` until it ends well, or has failed `restarts` times more than
/// it was started again (a standalone service ends and its unit starts it
/// again; this thread cannot end the daemon, so it starts the service again
/// itself, with the directory of the store made again): the last error.
fn serve_again(restarts: usize, mut serve: impl FnMut(usize) -> io::Result<()>) -> io::Result<()> {
    let mut attempt = 0;
    loop {
        match serve(attempt) {
            Ok(()) => return Ok(()),
            Err(e) if attempt >= restarts => return Err(e),
            Err(e) => {
                warn!("store service: {e}: starting it again");
                attempt += 1;
            }
        }
    }
}

/// `velarx store-service [--config PATH] [--listen-fd N] [--idle-exit SECS]`:
/// serve the store of the configuration.  The socket comes from systemd
/// (`LISTEN_FDS`), from `--listen-fd` (a client that started this and bound
/// it), or is bound here unless another instance serves it.
pub fn main(
    args: impl Iterator<Item = std::ffi::OsString>,
    startup: &velarx_sys::fd::Startup,
) -> anyhow::Result<()> {
    let mut config_path = velarx_config::DefaultDirs::current()?.config_file;
    let mut listen_fd: Option<i32> = None;
    let mut idle: Option<Duration> = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| anyhow::anyhow!("{} needs a value", arg.to_string_lossy()))
        };
        match arg.to_str() {
            Some("--config") => config_path = PathBuf::from(value()?),
            Some("--listen-fd") => listen_fd = Some(value()?.to_string_lossy().parse()?),
            Some("--idle-exit") => {
                let secs: u64 = value()?.to_string_lossy().parse()?;
                idle = (secs > 0).then(|| Duration::from_secs(secs));
            }
            _ => anyhow::bail!("unknown argument {}", arg.to_string_lossy()),
        }
    }
    let inherited = activation::Inherited::take(startup, listen_fd)?;
    velarx_wire::logging::init("warn", "text");
    let config = Config::load_or_default(&config_path)?;
    let socket = socket_path(&config);
    let (listener, ours) = activation::listener_for(&socket, inherited)
        .map_err(|e| anyhow::anyhow!("the store service: {e}"))?;
    debug!("store service on {}", socket.display());
    let idle = idle.map(|after| IdleExit {
        after,
        socket: ours.then(|| socket.clone()),
        last: false,
        lock: None,
    });
    Ok(run_blocking(&config, listener, idle)?)
}

/// The idle time of a service a client starts, usually.
pub const STARTED_IDLE: Duration = Duration::from_secs(60);

/// The command that runs the store service for `config_path`, with the
/// socket passed as descriptor 3 (see [`activation::start`]); it leaves
/// after `idle` without a connection, never with none.
pub fn start_command(
    exe: &Path,
    config_path: &Path,
    idle: Option<Duration>,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("store-service")
        .arg("--config")
        .arg(config_path)
        .arg("--listen-fd")
        .arg("3")
        .arg("--idle-exit")
        .arg(idle.map_or(0, |i| i.as_secs().max(1)).to_string());
    cmd
}

/// Start the store service of `config` if nothing serves it, for a process
/// that cannot start one once it confined itself.  The service lives as long
/// as the calling process (it is told to leave when it ends), and leaves
/// after `idle` without a connection.  Call it from the main thread of the
/// process, which the service is tied to (the parent-death signal follows
/// the thread that forked), before any other thread exists: the process
/// started, if one was, is the caller's to reap, from a thread started
/// after the process confined itself.
pub fn start_if_absent(
    config: &Config,
    config_path: &Path,
    exe: &Path,
    idle: Option<Duration>,
) -> io::Result<Option<std::process::Child>> {
    let socket = socket_path(config);
    let mut cmd = start_command(exe, config_path, idle);
    let parent = rustix::process::getpid();
    velarx_sys::spawn::pre_exec(&mut cmd, move |_| {
        rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::TERM))?;
        // (the parent ended before the signal was asked for)
        if rustix::process::getppid() != Some(parent) {
            velarx_sys::process::exit_now(0);
        }
        Ok(())
    });
    activation::start(&socket, cmd, std::process::Stdio::inherit()).map(|(_, child)| child)
}

/// A connection to the service on `socket`, checked to be served by a
/// trusted user of this protocol (its `GetInfo`).
pub async fn connect(socket: &Path) -> io::Result<zlink::Connection<zlink::tokio::unix::Stream>> {
    let mut conn = activation::connect(socket).await?;
    let info = conn
        .get_info()
        .await
        .map_err(|e| io::Error::other(e.to_string()))?
        .map_err(io::Error::other)?;
    velarx_proto::info::check("org.velarx.Store", &info, PROTO).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the store service on {}: {e}", socket.display()),
        )
    })?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text a service sends for `GetInterfaceDescription` (the file,
    /// embedded) is what the descriptors of the types and methods say.
    #[test]
    fn the_description_served_is_what_the_types_say() {
        assert_eq!(velarx_proto::interfaces::store(), service::description());
    }

    /// The file is made from the types: when they change it changes.
    /// `VELARX_WRITE_INTERFACES=1` writes it.
    #[test]
    fn the_interface_file_is_current() {
        let text = definition();
        velarx_base::testing::assert_interface_file("org.velarx.Store.varlink", &text);
        assert!(
            text.contains("\tsnapshot,"),
            "the enum values as the wire has them"
        );
    }

    fn image(id: &str, layers: &[&str]) -> ImageInfo {
        ImageInfo {
            id: id.into(),
            manifest_digest: format!("sha256:{id}"),
            config_digest: String::new(),
            tags: vec![],
            repo_digests: vec![],
            layers: layers.iter().map(|s| s.to_string()).collect(),
            size: 1,
            created_at: String::new(),
            complete: true,
        }
    }

    #[test]
    fn the_diff_tells_what_was_added_and_removed() {
        let before = Shared {
            layers: vec!["a".into(), "b".into()],
            images: vec![image("1", &["a"])],
            content: vec!["x".into(), "y".into()],
        };
        let after = Shared {
            layers: vec!["b".into(), "c".into()],
            images: vec![image("2", &["c"])],
            content: vec!["y".into(), "z".into()],
        };
        let (added, removed) = after.diff(&before);
        let added = added.unwrap();
        let removed = removed.unwrap();
        assert_eq!(added.kind, ChangeKind::Added);
        assert_eq!(added.layers, vec!["c".to_string()]);
        assert_eq!(added.images, vec![image("2", &["c"])]);
        assert_eq!(added.content, vec!["z".to_string()]);
        assert_eq!(removed.kind, ChangeKind::Removed);
        assert_eq!(removed.layers, vec!["a".to_string()]);
        assert_eq!(removed.images, vec![image("1", &["a"])]);
        assert_eq!(removed.content, vec!["x".to_string()]);
        assert_eq!(after.diff(&after), (None, None));
    }

    /// An image that becomes complete is told as added again, as it is
    /// now: not as removed.
    #[test]
    fn an_image_that_changes_is_added_again_and_not_removed() {
        let partial = ImageInfo {
            complete: false,
            ..image("1", &["a"])
        };
        let before = Shared {
            images: vec![partial.clone()],
            ..Shared::default()
        };
        let after = Shared {
            images: vec![image("1", &["a"])],
            ..Shared::default()
        };
        let (added, removed) = after.diff(&before);
        assert_eq!(added.unwrap().images, vec![image("1", &["a"])]);
        assert_eq!(removed, None);
        let (added, removed) = Shared::default().diff(&after);
        assert_eq!(added, None);
        assert_eq!(removed.unwrap().images, vec![image("1", &["a"])]);
    }

    #[test]
    fn the_lock_is_next_to_the_socket() {
        assert_eq!(
            activation::lock_path(Path::new("/run/x/store.sock")),
            PathBuf::from("/run/x/store.sock.lock")
        );
    }

    /// What the test counts of the watcher.
    struct Seen {
        scans: std::sync::atomic::AtomicUsize,
        idle: tokio::sync::watch::Sender<()>,
    }

    impl WatchObserver for Seen {
        fn idle(&self) {
            self.idle.send_replace(());
        }
        fn scanning(&self) {
            self.scans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A burst of commits by another connection is followed by a few scans
    /// of the store, not one for each: what comes while the watcher is busy
    /// is read together.
    #[tokio::test]
    async fn a_burst_of_commits_costs_few_scans() {
        const BURST: usize = 60;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite");
        let reader = Database::open(&db_path).await.unwrap();
        let files = Arc::new(FileStore::new(dir.path().join("files")).unwrap());
        let service = StoreService::new(reader, files).await.unwrap();
        let seen = Arc::new(Seen {
            scans: std::sync::atomic::AtomicUsize::new(0),
            idle: tokio::sync::watch::channel(()).0,
        });
        let observer = seen.clone();
        let watching = service.clone();
        let watcher = tokio::spawn(async move { watching.watch_observed(&*observer).await });
        let mut idle = seen.idle.subscribe();
        let scans = || seen.scans.load(std::sync::atomic::Ordering::SeqCst);
        // (the watcher has made its first look and waits for events)
        idle.changed().await.unwrap();
        let first = scans();

        // (the runtime is blocked while the commits are made: the watcher
        // sees the whole burst at once)
        let writer = Database::open(&db_path).await.unwrap();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    for n in 0..BURST {
                        writer
                            .store_setting(&format!("burst{n}"), "v")
                            .await
                            .unwrap();
                    }
                })
        })
        .join()
        .unwrap();
        // (it has read every event of the burst, and scanned for them)
        idle.changed().await.unwrap();
        let n = scans() - first;
        assert!(
            (1..=3).contains(&n),
            "{n} scans for {BURST} commits, a few expected"
        );
        watcher.abort();
    }

    /// A watched directory that goes away ends the watch with an error (the
    /// service leaves and is started again), instead of announcing nothing
    /// for good.
    #[test]
    fn a_service_that_lost_the_store_is_started_again_a_few_times() {
        let mut starts = Vec::new();
        let r = serve_again(2, |n| {
            starts.push(n);
            Err(io::Error::other("lost"))
        });
        assert!(r.is_err());
        assert_eq!(starts, [0, 1, 2], "started, and again twice");
        let mut starts = 0;
        let r = serve_again(2, |n| {
            starts += 1;
            if n < 1 {
                Err(io::Error::other("lost"))
            } else {
                Ok(())
            }
        });
        assert!(r.is_ok());
        assert_eq!(starts, 2);
    }

    #[tokio::test]
    async fn a_lost_watch_ends_the_service() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let dir = tempfile::tempdir().unwrap();
                let db_path = dir.path().join("db.sqlite");
                let db = Database::open(&db_path).await.unwrap();
                let files = Arc::new(FileStore::new(dir.path().join("files")).unwrap());
                let shared = Arc::new(SharedCheckpoints::new(dir.path()).unwrap());
                let shares = shared.shares_dir().to_path_buf();
                let service = StoreService::with_checkpoints(db, files, shared)
                    .await
                    .unwrap();
                let socket = dir.path().join("store.sock");
                let listener = tokio::net::UnixListener::bind(&socket).unwrap();
                let serving = tokio::task::spawn_local(serve(
                    listener,
                    service,
                    None,
                    |_| true,
                    activation::Limits::default(),
                ));
                tokio::task::yield_now().await;
                std::fs::remove_dir_all(&shares).unwrap();
                let ended = tokio::time::timeout(Duration::from_secs(10), serving)
                    .await
                    .expect("the service ended")
                    .unwrap();
                assert!(ended.is_err(), "ended with an error: {ended:?}");
            })
            .await;
    }
}
