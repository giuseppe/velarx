// SPDX-License-Identifier: Apache-2.0
//! Image pulls on top of the pull engine (`velarx_content::pull`).

use super::seal;
use super::*;
use async_trait::async_trait;
use std::collections::HashSet;
use velarx_content::pull::holds::{self, Hold};
use velarx_content::pull::net::Net;
use velarx_content::pull::{self, layer_commit, LayerDone, Limits};
use velarx_db::{BlobSource, ImageRecord, ImageTag, LayerKey, LayerReach, PullCommit};
use velarx_graph::feed::{
    CheckId, Checked, ContentFeed, FeedLayer, Identities, Incoming as DriverIncoming, LayerIndex,
    PullFeed, Pulled, Settled, Settlement, Verdict,
};
use velarx_graph::LayerRef;
use velarx_proto::workload::{SOURCE_REGISTRY, SOURCE_STORE};
use velarx_registry::target::Platform;
use velarx_types::digest::Digest;

/// Progress is reported when at least this many bytes arrived since the last
/// report of the layer.
const PROGRESS_STEP: u64 = 256 * 1024;

/// The engine's side of a pull as a storage driver sees it: the pull code
/// ([`ContentFeed`]), and what the engine holds for the pull while it runs
/// (the hold that pins the layers, the store for the commit).
struct EngineFeed {
    inner: ContentFeed,
    staging_dir: std::path::PathBuf,
    expected: Vec<LayerKey>,
    /// The store, held from the check of what it has to the hold
    store: std::sync::Mutex<Option<velarx_storage::StorageLock>>,
    /// The hold of the pull, taken when the driver opens it
    hold: std::sync::Mutex<Option<Hold>>,
    /// The store, held from the commit of the files to the record of the
    /// image (until the feed is dropped)
    commit_lock: std::sync::Mutex<Option<velarx_storage::StorageLock>>,
}

#[async_trait]
impl PullFeed for EngineFeed {
    async fn begin(&self, into: &Arc<dyn DriverIncoming>) -> ImageResult<()> {
        self.inner.begin(into).await?;
        // (the layers stored are pinned by the hold, the files fetched by
        // the live hold of the staging: the session of a driver of this
        // process is the hold, one that has its files elsewhere has none)
        let id = into.pull_id();
        let name = if id.starts_with("pull-") {
            id
        } else {
            format!("pull-{id}")
        };
        // (a name that is no hold name would make a hold no look finds)
        if !holds::is_hold_name(&name) {
            return Err(ImageError::Storage(format!(
                "the pull {name:?} has no name a hold can have"
            )));
        }
        let hold = Hold::join_or_create(&self.staging_dir, &name)?;
        hold.pin(holds::LAYER, &self.expected)?;
        *self.hold.lock().unwrap_or_else(|e| e.into_inner()) = Some(hold);
        // (a removal of another image, or a collection, would wait for every
        // pull in progress if the lock were held through the download)
        drop(self.store.lock().unwrap_or_else(|e| e.into_inner()).take());
        Ok(())
    }

    fn parallel(&self) -> usize {
        self.inner.parallel()
    }

    fn is_lazy(&self) -> bool {
        self.inner.is_lazy()
    }

    async fn why_not_lazy(&self, layer: &FeedLayer) -> ImageResult<Option<String>> {
        self.inner.why_not_lazy(layer).await
    }

    async fn index(&self, layer: &FeedLayer) -> ImageResult<Option<LayerIndex>> {
        self.inner.index(layer).await
    }

    async fn fetch(
        &self,
        layer: &FeedLayer,
        into: &Arc<dyn DriverIncoming>,
    ) -> ImageResult<LayerDone> {
        self.inner.fetch(layer, into).await
    }

    fn release(&self, layer: &FeedLayer) {
        self.inner.release(layer)
    }

    async fn finish(&self) -> ImageResult<()> {
        self.inner.finish().await?;
        let lock = StorageLock::shared(&StorageLock::path_of_staging(&self.staging_dir))
            .await
            .map_err(|e| ImageError::Storage(format!("cannot lock the store: {e}")))?;
        *self.commit_lock.lock().unwrap_or_else(|e| e.into_inner()) = Some(lock);
        Ok(())
    }

    fn end(&self) {
        self.inner.end()
    }
}

/// Drops what an [`EngineFeed`] holds for its pull (the hold, the locks of
/// the store) when the install that made it ends, whatever the way.
struct LetGo<'a>(&'a EngineFeed);

impl Drop for LetGo<'_> {
    fn drop(&mut self) {
        let f = self.0;
        drop(f.hold.lock().unwrap_or_else(|e| e.into_inner()).take());
        drop(f.store.lock().unwrap_or_else(|e| e.into_inner()).take());
        drop(
            f.commit_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
        );
    }
}

fn progress(
    tx: &mpsc::Sender<TransferProgress>,
    layer: &OciDescriptor,
    status: &str,
    current: u64,
    complete: bool,
) {
    tx.report(TransferProgress {
        subject: meter::Subject::Digest(layer.digest),
        status: status.to_string(),
        current_bytes: current,
        total_bytes: layer.size.max(0) as u64,
        complete,
    });
}

fn utf8(bytes: &[u8], what: &str) -> ImageResult<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| ImageError::Manifest(format!("the {what} is not UTF-8")))
}

/// What a manifest is asked for: its digest, or the tag when the digest is
/// not one the registry addresses manifests by (`NAME:TAG@sha512:D`), else
/// the tag.
pub(crate) fn manifest_reference(image_ref: &ImageReference) -> String {
    match (&image_ref.locator_tag, &image_ref.digest, &image_ref.tag) {
        (Some(tag), _, _) | (None, None, Some(tag)) => tag.clone(),
        (None, Some(digest), _) => digest.to_string(),
        (None, None, None) => "latest".into(),
    }
}

/// The names a pull gives the image it brings.
#[derive(Clone, Copy)]
pub(super) struct PullNames<'a> {
    pub tags: &'a [ImageTag],
    pub digest_names: &'a [(String, Digest)],
}

/// The layers a pull is fetching, held until the pull has recorded them: a
/// second pull of the same layers waits for the first and finds them stored.
/// In this process by a lock of each layer; across the engines of the store
/// (every command is one) by the lease of the layer's staging
/// (`staging/meta/<stem>/lease`, `flock`), which the kernel gives the next
/// one when the holder lets go or dies.
pub(super) struct LayerLocks {
    held: Vec<(Digest, tokio::sync::OwnedMutexGuard<()>)>,
    all: Arc<LayerLockMap>,
    /// The leases, shared with the open stagings of their layers
    leases: Vec<Arc<velarx_content::pull::staged::LayerLease>>,
    area: velarx_content::pull::staged::Staging,
}

/// The lock of each layer some pull is fetching.  The map is held for the
/// time of a lookup or an insertion, never across an await.
pub(super) type LayerLockMap = std::sync::Mutex<HashMap<Digest, Arc<tokio::sync::Mutex<()>>>>;

impl Drop for LayerLocks {
    fn drop(&mut self) {
        for (key, guard) in self.held.drain(..) {
            drop(guard);
            // Nobody else waits for it: forget the lock.
            let mut all = self.all.lock().unwrap_or_else(|e| e.into_inner());
            if all.get(&key).is_some_and(|m| Arc::strong_count(m) == 1) {
                all.remove(&key);
            }
        }
    }
}

/// How the engine pulls an image.
#[derive(Debug, Clone, Default)]
pub(super) struct EngineOptions {
    /// Fetch only the metadata of the layers that allow it.
    pub lazy: bool,
    /// The names of the fetchers of the pull, in the order they are asked,
    /// as given ([`ImageService::sources_of`]); none: `[pull] sources`
    pub sources: Option<Vec<String>>,
    /// How the registry is reached: with TLS verification or not, with
    /// credentials and certificates of the request or not.
    pub reach: LayerReach,
    /// The platform asked for; by default the one of the host.
    pub platform: Option<Platform>,
    /// What the layers of the pull are made with, as
    /// [`PullOptions::inline_threshold`] says
    pub inline_threshold: Option<i64>,
}

/// An image to install: its manifest and configuration as they were
/// received, and where its layers are.
pub(super) struct Incoming {
    pub manifest: OciManifest,
    pub manifest_bytes: Bytes,
    pub manifest_digest: Digest,
    pub config: OciConfig,
    pub config_bytes: Bytes,
    /// The origin that unpacks the layers of a pull of a path or a
    /// transport
    pub via: Option<super::pull_origin::Via>,
    /// The layers a build made (with no blob to read): their files are
    /// moved into the pull's session and committed with it
    pub made: Vec<Arc<velarx_content::pull::Made>>,
    /// The reference the layers can be fetched from again, if any.
    pub registry_ref: Option<String>,
    pub tags: Vec<ImageTag>,
    /// The (repository, digest) names of a pull by digest.
    pub digest_names: Vec<(String, Digest)>,
    /// Fetch only the metadata of the layers that allow it.
    pub lazy: bool,
    /// The fetchers of a pull from a registry, as
    /// [`EngineOptions::sources`] says
    pub sources: Option<Vec<String>>,
    /// What its layers are made with: the pull's own, else the
    /// configured one ([`ImageService::inline_threshold`])
    pub inline_threshold: Option<i64>,
    /// How the registry is reached, to fetch files later.
    pub reach: LayerReach,
    /// An image made here: the manifest gets the digest of its merged
    /// EROFS (`seal`), and so its id.
    pub seal: bool,
    /// An image made here (a commit, an import): the manifest states the
    /// digest of the EROFS image of each layer, which is not checked.
    pub states: bool,
    /// The hold (by its name) that pins the image before it is recorded.
    pub hold: Option<String>,
    /// How the image was pulled and the signatures found, recorded with the
    /// image (a lazy pull's: the staging area keeps them until the image is
    /// committed).
    pub pulled: Vec<(String, Vec<u8>)>,
    /// The indexes that led to the manifest, by digest, kept once the store
    /// is locked for the pull ([`ImageService::keep_indexes`]).
    pub indexes: Vec<(Digest, Bytes)>,
    /// The credentials and certificates the layers are fetched with (a pull
    /// from a registry)
    pub access: Option<velarx_registry::auth::RegistryAccess>,
    /// Of the layers of the manifest, by index, those that are layers of the
    /// store already, by their key (the layers of the parent of a commit,
    /// whatever route their pull took); the others are looked up by the key
    /// their descriptor asks for ([`LayerKey::expected`]).
    pub recorded: Vec<LayerKey>,
}

/// The most layers a mount of the driver takes for an image of the pull
/// (`Capabilities::max_image_layers`), and why.
#[derive(Clone, Copy)]
struct Mountable {
    limit: usize,
    overlay: usize,
    stores: usize,
    lazy: bool,
}

impl ImageService {
    /// Check what the registry sent before using it: the digests name files
    /// of the store and the layers must match the configuration.
    fn check_image(
        image: &str,
        manifest: &OciManifest,
        config: &OciConfig,
        pull: &velarx_config::PullConfig,
        mountable: Option<Mountable>,
    ) -> ImageResult<()> {
        if let Some(m) = mountable.filter(|m| manifest.layers.len() > m.limit) {
            return Err(ImageError::TooManyLayers {
                image: image.to_string(),
                layers: manifest.layers.len(),
                limit: m.limit,
                overlay: m.overlay,
                stores: m.stores,
                lazy: m.lazy,
            });
        }
        // (the mount holds descriptors for the layers, and the process may
        // not be allowed that many: refused before anything is fetched, as
        // the layers are)
        if mountable.is_some() {
            let needed = velarx_base::hardening::open_files_needed(manifest.layers.len());
            if let Err(e) = velarx_base::hardening::check_open_files(needed) {
                return Err(ImageError::NoOpenFiles {
                    image: image.to_string(),
                    layers: manifest.layers.len(),
                    needed,
                    hard: e.hard.unwrap_or(0),
                });
            }
        }
        // (a blob that inflates to more than the limit is refused whatever
        // it is: a registry that announces more is not asked for anything)
        let max_blob = pull.max_layer_gib.max(1).saturating_mul(1 << 30);
        let max_blob = max_blob.saturating_add(max_blob / 64);
        if let Some(layer) = manifest
            .layers
            .iter()
            .find(|l| l.size > 0 && l.size as u64 > max_blob)
        {
            return Err(ImageError::Manifest(format!(
                "the layer {} announces {} bytes, more than the {} GiB ([pull] max_layer_gib) a layer may inflate to",
                layer.digest, layer.size, pull.max_layer_gib.max(1)
            )));
        }
        if manifest.layers.len() != config.rootfs.diff_ids.len() {
            return Err(ImageError::Manifest(format!(
                "the manifest has {} layers, the configuration {} diff ids",
                manifest.layers.len(),
                config.rootfs.diff_ids.len()
            )));
        }
        for layer in &manifest.layers {
            if layer.size < 0 {
                return Err(ImageError::Manifest(format!(
                    "invalid layer `{}` in the manifest",
                    layer.digest
                )));
            }
        }
        // A layer listed twice has one diff id.
        let mut seen: HashMap<&Digest, &Digest> = HashMap::new();
        for (layer, diff_id) in manifest.layers.iter().zip(&config.rootfs.diff_ids) {
            if let Some(prev) = seen.insert(&layer.digest, diff_id) {
                if prev != diff_id {
                    return Err(ImageError::Manifest(format!(
                        "layer {} appears with two diff ids",
                        layer.digest
                    )));
                }
            }
        }
        Ok(())
    }

    /// Wait for the other pulls that are fetching these layers, and hold
    /// them.  The digests are taken in order, so that two pulls with layers
    /// in common cannot wait for each other.
    async fn lock_layers(&self, layers: &[&OciDescriptor], lease: bool) -> ImageResult<LayerLocks> {
        let mut digests: Vec<Digest> = layers.iter().map(|l| l.digest).collect();
        digests.sort_unstable();
        digests.dedup();
        let mut held = Vec::with_capacity(digests.len());
        for digest in digests {
            let lock = self
                .pulling
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(digest)
                .or_default()
                .clone();
            held.push((digest, lock.lock_owned().await));
        }
        let mut locks = LayerLocks {
            held,
            all: self.pulling.clone(),
            leases: Vec::new(),
            area: self.staging_area(),
        };
        if lease {
            let mut keys: Vec<LayerKey> = layers.iter().map(|l| LayerKey::expected(l)).collect();
            keys.sort_unstable_by_key(|k| k.file_stem());
            keys.dedup();
            for key in keys {
                let area = locks.area.clone();
                let file = tokio::task::spawn_blocking(move || area.lease_layer(&key))
                    .await
                    .map_err(|e| ImageError::Storage(e.to_string()))??;
                locks
                    .leases
                    .push(Arc::new(velarx_content::pull::staged::LayerLease::new(
                        locks.area.clone(),
                        key,
                        file,
                    )));
            }
        }
        Ok(locks)
    }

    /// Whether the store has the image of the manifest `digest`, with every
    /// layer of it.
    pub(super) async fn image_stored(&self, digest: &Digest) -> bool {
        match self.db.get_image_by_digest(digest).await {
            Ok(image) => self.layers_stored(&image).await,
            Err(_) => false,
        }
    }

    /// Whether every layer of a stored image is stored (complete, with what
    /// it is rebuilt as a stream from: push and archives need it); an image
    /// with a layer that is not is pulled again.
    async fn layers_stored(&self, image: &ImageRecord) -> bool {
        let Ok(layers) = self.db.get_image_layers(&image.id).await else {
            return false;
        };
        let Ok(config) = serde_json::from_str::<OciConfig>(&image.config) else {
            return false;
        };
        if layers.len() != config.rootfs.diff_ids.len() {
            return false;
        }
        let keys: Vec<LayerKey> = layers.into_iter().map(|l| l.key).collect();
        let stored = match self.stored_layers(&keys, &config).await {
            Ok(stored) => stored,
            Err(e) => {
                warn!(
                    "Cannot ask the storage driver for the layers of {}: {e}",
                    image.id
                );
                return false;
            }
        };
        let mut missing: Vec<LayerKey> = keys
            .into_iter()
            .zip(stored)
            .filter(|(_, ok)| !ok)
            .map(|(k, _)| k)
            .collect();
        missing.sort();
        missing.dedup();
        if missing.is_empty() {
            return true;
        }
        // A layer this store has no row of is a read-only store's: the image
        // is that store's, whose files it keeps (not the driver's to say).
        let own: HashSet<LayerKey> = match self.db.get_own_layer_states(&missing).await {
            Ok(states) => states.into_iter().map(|s| s.key).collect(),
            Err(_) => return false,
        };
        for key in missing {
            if own.contains(&key) || !matches!(self.db.get_layer_tarsplit(&key).await, Ok(Some(_)))
            {
                return false;
            }
        }
        true
    }

    /// For each layer of an image (`keys` are the keys the layers are looked
    /// up by, in the order of the manifest), whether it is stored and proven
    /// against the diff id of the configuration: one answer per position, in
    /// the order of `keys`.  A layer is found only under its own key: a layer
    /// of a TOC never stands for one pulled whole, nor the other way round.
    ///
    /// Whether a layer is in the store is the storage driver's answer
    /// ([`StorageDriver::has_layers`], one call, one answer per position): a
    /// layer it has is neither fetched nor looked at again, and a
    /// driver that is not the engine's files says so by key.  The engine's own
    /// check is of its index only: an image is recorded from the table of
    /// contents of each of its layers, so a layer the driver has but the
    /// database has no row of is pulled again (the driver then wants none of
    /// its files).
    pub(super) async fn stored_layers(
        &self,
        keys: &[LayerKey],
        config: &OciConfig,
    ) -> ImageResult<Vec<bool>> {
        let asked = layer_refs(keys, &config.rootfs.diff_ids);
        let have = per_position(asked.len(), self.storage.has_layers(&asked).await?)?;
        let mut held: Vec<LayerKey> = asked
            .iter()
            .zip(&have)
            .filter(|(_, h)| **h)
            .map(|(l, _)| l.key)
            .collect();
        held.sort();
        held.dedup();
        let indexed: HashSet<LayerKey> = if held.is_empty() {
            HashSet::new()
        } else {
            self.db
                .get_own_layer_states(&held)
                .await?
                .into_iter()
                .filter(|s| s.has_toc)
                .map(|s| s.key)
                .collect()
        };
        Ok(asked
            .into_iter()
            .zip(have)
            .map(|(l, h)| h && indexed.contains(&l.key))
            .collect())
    }

    /// Pull with the given registry client.
    pub async fn pull_with_client(
        &self,
        client: &Resolver,
        reference: &str,
        progress_tx: mpsc::Sender<TransferProgress>,
    ) -> ImageResult<PullResult> {
        self.policy_for(&ImageReference::parse(reference)?)?;
        self.pull_engine(client, reference, progress_tx, &EngineOptions::default())
            .await
    }

    /// Like `pull_with_client`, fetching only the metadata of the layers that
    /// allow it.
    pub async fn pull_lazy_with_client(
        &self,
        client: &Resolver,
        reference: &str,
        progress_tx: mpsc::Sender<TransferProgress>,
    ) -> ImageResult<PullResult> {
        self.policy_for(&ImageReference::parse(reference)?)?;
        self.pull_engine(
            client,
            reference,
            progress_tx,
            &EngineOptions {
                lazy: true,
                ..EngineOptions::default()
            },
        )
        .await
    }

    /// How a pull talks to the registries: through confined workers, or
    /// from this process.
    /// The digest of the manifest the registry serves for `reference` now
    /// (for the platform of an index), without pulling anything.
    pub async fn remote_digest(
        &self,
        reference: &str,
        options: &PullOptions,
    ) -> ImageResult<Digest> {
        let platform = options
            .platform
            .as_deref()
            .map(Platform::parse)
            .transpose()
            .map_err(ImageError::Manifest)?;
        let mut tried = Tried::default();
        for candidate in self.candidates(reference)? {
            let result = async {
                let image_ref = ImageReference::parse(&candidate)?;
                // nothing of the image is kept: `reject` refuses it
                self.policy_for(&image_ref)?;
                image_ref.validate()?;
                let net = self.inspect_net(&image_ref, options.tls_verify, &options.access)?;
                let (_, digest, _, _) = net
                    .manifest_raw(&image_ref, platform.as_ref(), None)
                    .await?;
                Ok::<_, ImageError>(digest)
            }
            .await;
            match result {
                Ok(d) => return Ok(d),
                Err(e) => tried.push(&candidate, e),
            }
        }
        Err(tried.into_error(reference))
    }

    /// What the registry serves for `reference`, without pulling it (the
    /// distribution endpoint): the media type, digest and size of the
    /// manifest or index, and the platforms it has.
    pub async fn remote_descriptor(
        &self,
        reference: &str,
        options: &PullOptions,
    ) -> ImageResult<RemoteDescriptor> {
        let mut tried = Tried::default();
        for candidate in self.candidates(reference)? {
            let result = async {
                let image_ref = ImageReference::parse(&candidate)?;
                image_ref.validate()?;
                // nothing of the image is kept: `reject` refuses it
                self.policy_for(&image_ref)?;
                image_ref.validate()?;
                let net = self.inspect_net(&image_ref, options.tls_verify, &options.access)?;
                let wanted = manifest_reference(&image_ref);
                let (body, mut digest) = net.manifest_top(&wanted).await?;
                if let Some(pinned) = &image_ref.digest {
                    velarx_registry::target::verify_digest(pinned, &body)?;
                    digest = *pinned;
                }
                let value: serde_json::Value = serde_json::from_slice(&body)?;
                let mut platforms = Vec::new();
                match value.get("manifests").and_then(|m| m.as_array()) {
                    Some(list) => {
                        for m in list {
                            if let Some(p) = m.get("platform") {
                                platforms.push(p.clone());
                            }
                        }
                    }
                    None => {
                        let manifest: OciManifest = serde_json::from_slice(&body)?;
                        let (config, _) = net.config_raw(&manifest.config).await?;
                        platforms.push(serde_json::json!({
                            "architecture": config.architecture,
                            "os": config.os,
                        }));
                    }
                }
                let media_type = value
                    .get("mediaType")
                    .and_then(|m| m.as_str())
                    .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                    .to_string();
                Ok::<_, ImageError>(RemoteDescriptor {
                    media_type,
                    digest,
                    size: body.len() as u64,
                    platforms,
                })
            }
            .await;
            match result {
                Ok(d) => return Ok(d),
                Err(e) => tried.push(&candidate, e),
            }
        }
        Err(tried.into_error(reference))
    }

    /// The names of the fetchers of a pull, in the order they are asked:
    /// `asked` (`--sources`) or `[pull] sources`, as written (by default
    /// `registry` alone).  A name that is not `registry` or of
    /// `[[sources.external]]` is refused before anything is fetched.
    pub(super) fn sources_of(&self, asked: Option<&[String]>) -> ImageResult<Vec<String>> {
        let names = asked.map_or_else(|| self.pull_config.sources.clone(), <[String]>::to_vec);
        for name in &names {
            if name != "registry" && !self.fetchers.iter().any(|f| f.name == *name) {
                return Err(ImageError::Invalid(format!(
                    "the sources {}: `{name}` is neither `registry` nor a fetcher of [[sources.external]]",
                    names.join(",")
                )));
            }
        }
        Ok(names)
    }

    /// The walker of a pull of the image of `manifest` from `repository`: the
    /// fetchers of `names` (none: `[pull] sources`), each in its own scope,
    /// in the engine's order, then the registry fetcher, which gets the credentials `access`.
    pub(super) async fn staged_fetch(
        &self,
        (repository, names): (&str, Option<&[String]>),
        tls_verify: bool,
        access: Option<&velarx_registry::auth::RegistryAccess>,
        manifest: &[u8],
    ) -> ImageResult<Arc<velarx_content::pull::staged_fetch::StagedFetch>> {
        use velarx_content::pull::staged_fetch::StagedFetch;
        let names = match names {
            Some(n) => n.to_vec(),
            None => self.sources_of(None)?,
        };
        let (first, rest) = split_at_registry(&names);
        let before = self.source_links(first).await;
        // (the registry fetcher process, when `registry` is one of the
        // sources: nothing of a pull is fetched by this one)
        let end = match rest {
            Some(_) => {
                let origin = self.origin()?;
                let conn = origin.connect().await.map_err(|e| {
                    ImageError::transfer(
                        "registry",
                        velarx_proto::transfer::FailureClass::Transient,
                        e.to_string(),
                    )
                })?;
                Some((conn, origin.idle()))
            }
            None => None,
        };
        let after = self.source_links(rest.unwrap_or_default()).await;
        let verity = self.fsverity != velarx_storage::VerityMode::Off
            && velarx_storage::probe(&self.staging_dir).is_ok();
        let access = access.map(serde_json::to_vec).transpose()?;
        let staged = StagedFetch::open(
            (before, end, after),
            &self.staging_dir,
            verity,
            (repository, tls_verify),
            access.as_deref(),
            manifest,
        )
        .await?;
        debug!("The fetchers of the pull: {}", staged.sources().join(", "));
        Ok(staged)
    }

    /// Connections to the fetchers of `names` but the registry fetcher, in
    /// their order: a fetcher of `[[sources.external]]` on its socket or
    /// started for the pull (`command`), or the fetcher of a `dir`, a
    /// confined process of its own for this connection.  A fetcher that
    /// cannot be reached is left out.
    pub(super) async fn source_links(
        &self,
        names: &[String],
    ) -> Vec<velarx_content::pull::staged_fetch::Link> {
        use velarx_content::pull::staged_fetch::Link;
        let mut links = Vec::new();
        for name in names.iter().filter(|n| *n != "registry") {
            let Some(def) = self.fetchers.iter().find(|f| f.name == *name) else {
                continue;
            };
            let conn = match &def.dir {
                Some(dir) => match self.origin() {
                    Ok(origin) => origin.connect_dir(name, dir).await,
                    Err(e) => Err(std::io::Error::other(e.to_string())),
                },
                None => velarx_content::list::connect_reach(&def.reach()).await,
            };
            match conn {
                Ok(conn) => links.push(Link {
                    name: name.clone(),
                    conn,
                    idle: std::time::Duration::from_secs(def.idle_timeout_secs),
                }),
                Err(e) => debug!("The fetcher {name} is left out: {e}"),
            }
        }
        links
    }

    /// The bytes of the blob `digest` of `size` bytes from the fetchers of
    /// `[pull] sources` but the registry (the pieces of a shared
    /// checkpoint), checked against its digest; none when nobody has it.
    pub async fn source_blob(&self, digest: &Digest, size: u64) -> Option<Vec<u8>> {
        let names = self.sources_of(None).ok()?;
        let name = digest.to_string();
        for mut link in self.source_links(&names).await {
            let blob = velarx_content::fetcher::fetch::Blob {
                digest: name.clone(),
                size,
                media_type: "application/octet-stream".into(),
                annotations: None,
            };
            // (a piece or a manifest of a checkpoint: small, and decrypted
            // whole)
            let Ok(file) = rustix::fs::memfd_create("blob", rustix::fs::MemfdFlags::CLOEXEC)
                .map(std::fs::File::from)
            else {
                return None;
            };
            let asked = async {
                let scope = velarx_content::fetcher::fetch_client::Scoping::bare(link.idle);
                velarx_content::idle::within(link.idle, link.conn.open(scope)).await?;
                link.conn.get_blob(&blob, &file, link.idle).await
            }
            .await;
            if asked.is_ok() {
                let read = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
                    use std::os::unix::fs::FileExt;
                    if file.metadata()?.len() != size {
                        return Err(std::io::Error::other("another size"));
                    }
                    let mut bytes =
                        vec![0u8; usize::try_from(size).map_err(std::io::Error::other)?];
                    file.read_exact_at(&mut bytes, 0)?;
                    Ok(bytes)
                })
                .await;
                if let Ok(Ok(bytes)) = read {
                    if Digest::of(digest.alg(), &bytes) == *digest {
                        return Some(bytes);
                    }
                }
            }
            debug!("The fetcher {}: {name} is not what it says", link.name);
        }
        None
    }

    /// The lazy layers of the pull of `manifest` (those the store lacks, as
    /// `stored` says), as the fetchers of `staged` found them (`Probe`)
    /// and the engine verified them; `ImageNotLazy` with every layer that
    /// cannot be lazy, before anything of the pull exists.  Once every layer
    /// is accepted, each is sent to `accepted` (its descriptor and its table
    /// as the layer has it).
    async fn accept_lazy(
        staged: &velarx_content::pull::staged_fetch::StagedFetch,
        manifest: &OciManifest,
        stored: &[bool],
        (image, max_tar): (&str, u64),
        db: &velarx_db::Database,
        accepted_tx: &futures::channel::mpsc::UnboundedSender<(OciDescriptor, bytes::Bytes)>,
    ) -> ImageResult<Accepted> {
        let missing: Vec<u32> = stored
            .iter()
            .enumerate()
            .filter(|(_, ok)| !**ok)
            .map(|(i, _)| i as u32)
            .collect();
        // (a layer with no table of contents is not lazy: the sources are
        // not asked for what they know of it)
        let mut tabled = Vec::new();
        for at in &missing {
            if pull::chunked::parse_info(&manifest.layers[*at as usize])?.is_some() {
                tabled.push(*at);
            }
        }
        // (a start needs the tables, not the tar-splits: those are the
        // completion's)
        let mut replies = staged
            .probe_all(&tabled, false, velarx_content::fetcher::fetch::Parts::Toc)
            .await?;
        velarx_base::trace::point("pull probed");
        let mut accepted = Accepted::default();
        let mut refused = Vec::new();
        let mut told = Vec::new();
        // (the layers are checked at once, and what the pull needs of each
        // is made as soon as its table is: the last does not wait for the
        // others)
        let answers = missing.into_iter().map(|at| {
            let layer = &manifest.layers[at as usize];
            let reply = replies
                .iter()
                .position(|(r, _)| r.layer == at)
                .map(|i| replies.swap_remove(i));
            async move {
                let answer = match reply {
                    Some((reply, metadata)) => {
                        pull::lazy::accept(layer, &reply, metadata, max_tar).await?
                    }
                    None => Err(velarx_proto::transfer::NotLazy::NoToc),
                };
                let made = match &answer {
                    Ok((_, lazy)) => Some(Self::made_of_table(layer, &lazy.toc, db).await?),
                    Err(_) => None,
                };
                Ok::<_, ImageError>((at, layer, answer, made))
            }
        });
        // (a file of the image has one size: in every table of it and in
        // the store)
        let mut listed: HashMap<String, u64> = HashMap::new();
        for (at, layer, answer, made) in
            futures::future::try_join_all(answers.collect::<Vec<_>>()).await?
        {
            if let Some(m) = made {
                let conflict = m
                    .files
                    .into_iter()
                    .find_map(|(digest, size)| {
                        let first = *listed.entry(digest.clone()).or_insert(size);
                        (first != size).then_some((digest, first, size))
                    })
                    .or(m.stored_conflict);
                if let Some((digest, held, size)) = conflict {
                    return Err(ImageError::Contradicted(format!(
                        "layer {}: its table of contents lists {digest} with {size} bytes, another table or the store has it with {held}",
                        layer.digest
                    )));
                }
                accepted.made.insert(m.key, (m.artifact, m.image));
            }
            match answer {
                Ok(f) => {
                    told.push((layer.clone(), f.1.toc_z.clone()));
                    accepted.found.insert(layer.digest.to_string(), f);
                }
                Err(reason) => refused.push(velarx_types::NotLazyLayer {
                    index: at,
                    digest: layer.digest.to_string(),
                    media_type: layer.media_type.clone(),
                    reason,
                }),
            }
        }
        velarx_base::trace::point("pull tocs verified");
        if !refused.is_empty() {
            return Err(ImageError::NotLazy {
                image: image.to_string(),
                layers: refused,
            });
        }
        // (the fetchers hear of the layers of a pull that is accepted:
        // nothing of one that is refused exists; nobody may listen, and
        // the pull tells nobody then)
        for layer in told {
            let _ = accepted_tx.unbounded_send(layer);
        }
        Ok(accepted)
    }

    /// What the pull of the lazy `layer` needs of its verified table `toc`,
    /// made at once: the identity and the EROFS image of the layer, and its
    /// files, with the first that the store has with another size.
    async fn made_of_table(
        layer: &OciDescriptor,
        toc: &Arc<velarx_storage::Toc>,
        db: &velarx_db::Database,
    ) -> ImageResult<MadeOfTable> {
        let key = LayerKey::expected(layer);
        let identity = tokio::task::spawn_blocking({
            let toc = toc.clone();
            move || storage::identity_of_table(&key, &toc)
        });
        let files: Vec<(String, u64)> = toc
            .entries
            .iter()
            .filter(|e| e.has_content())
            .filter_map(|e| Some((e.verity()?, e.size)))
            .collect();
        let stored_conflict = db.file_size_conflict(files.clone()).await?;
        let task = |e: tokio::task::JoinError| ImageError::Layer(format!("layer {key}: {e}"));
        let (key, artifact, image) = identity.await.map_err(task)??;
        Ok(MadeOfTable {
            key,
            artifact,
            image,
            files,
            stored_conflict,
        })
    }

    /// How a call about the repository `repository` (`registry/name`) of a
    /// registry reaches it through the fetcher.  The credentials of the
    /// command go to the fetcher in a file with no name; this process opens
    /// no connection.
    pub(super) fn remote_of(
        &self,
        repository: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<velarx_content::pull::net::origin::OriginRemote> {
        velarx_content::pull::net::origin::OriginRemote::new(
            self.origin()?.clone(),
            repository,
            tls_verify,
            access,
        )
    }

    /// How a pull, or a call that reads a manifest or a configuration of the
    /// remote registry without pulling it (`inspect --remote`, `manifest
    /// inspect`), reaches the registry: through the fetcher, with the
    /// credentials and certificates of the command in a sealed memory file.
    pub(super) fn inspect_net(
        &self,
        image_ref: &ImageReference,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Net> {
        let origin = self.origin()?;
        let name = image_ref.full_name();
        let access =
            velarx_content::fetcher::fetch_client::Access::new(access).map_err(ImageError::Io)?;
        Ok(Net::Origin(
            velarx_content::pull::net::origin::OriginNet::new(origin.clone(), name, tls_verify)
                .with_access(access),
        ))
    }

    /// An image of another platform than the one asked for is taken with
    /// podman's warning: the selection in an index fails for a platform it
    /// lacks, so this is a single image.
    pub(super) fn check_platform(
        config: &OciConfig,
        platform: &Platform,
        progress: &impl ProgressSink,
    ) {
        if platform.matches(&config.os, &config.architecture, None) {
            return;
        }
        let line = format!(
            "image platform ({}/{}) does not match the expected platform ({platform})",
            config.os, config.architecture
        );
        progress.report(TransferProgress::warning(&line));
    }

    /// An image that is stored is not fetched again: the names are added.
    pub(super) async fn already_stored(
        &self,
        manifest_digest: &Digest,
        manifest: &OciManifest,
        names: PullNames<'_>,
        platform: Option<(&Platform, &mpsc::Sender<TransferProgress>)>,
        start: std::time::Instant,
    ) -> ImageResult<Option<PullResult>> {
        let Ok(image) = self.db.get_image_by_digest(manifest_digest).await else {
            return Ok(None);
        };
        if !self.layers_stored(&image).await {
            return Ok(None);
        }
        // (the same rule as a pull that fetches: `require` may be newer than
        // the image; the layers are those the image records)
        let ours: Vec<Option<String>> = self
            .db
            .get_image_layers(&image.id)
            .await?
            .into_iter()
            .map(|l| l.erofs)
            .collect();
        seal::check_layers(manifest, &ours, self.composefs_digests())?;
        if let (Some((p, progress)), Ok(config)) =
            (platform, serde_json::from_str::<OciConfig>(&image.config))
        {
            Self::check_platform(&config, p, progress);
        }
        for tag in names.tags {
            self.db.insert_image_tag(tag).await?;
        }
        for (repository, digest) in names.digest_names {
            self.db
                .insert_image_digest_name(repository, digest, &image.id)
                .await?;
        }
        let mut stats = TransferStats {
            layers_cached: manifest.layers.len() as u64,
            duration_ms: start.elapsed().as_millis() as u64,
            ..TransferStats::default()
        };
        stats.add(
            SOURCE_STORE,
            manifest.layers.iter().map(|l| l.size.max(0) as u64).sum(),
            0,
        );
        Ok(Some(PullResult {
            id: image.id,
            stats,
        }))
    }

    /// Keep the bytes of the indexes that led to the manifest of a pull: an
    /// image named later by the digest of an index is verified from that
    /// index (a start hashes the bytes again).  Called once the image is in
    /// the store, staged, or the store is locked for the pull, so that the
    /// collection, which forgets the indexes that list no image, never sees
    /// them first.
    async fn keep_indexes(&self, indexes: &[(Digest, Bytes)]) -> ImageResult<()> {
        for (digest, bytes) in indexes {
            self.db.set_index(digest, &utf8(bytes, "index")?).await?;
        }
        Ok(())
    }

    /// A pull of an image whose pull is in progress joins it: its names and
    /// signatures are added to the staged ones, and an eager pull completes
    /// it (the files are not fetched a second time).  A pull that failed is
    /// not joined: it is discarded, as joining it would fail again on what
    /// it lacks, and the new pull starts over; unless a container is made on it, whose files its
    /// staging serves.  None: there is no such pull.
    async fn join_staged(
        &self,
        id: &str,
        names: PullNames<'_>,
        signed: &[(String, Vec<u8>)],
        (lazy, access): (bool, &velarx_registry::auth::RegistryAccess),
        start: std::time::Instant,
    ) -> ImageResult<Option<PullResult>> {
        use velarx_content::pull::staged as st;
        let area = self.staging_area();
        // (removed first, then read: a pull that another command discarded
        // meanwhile is not published again from what was read of it)
        if !self.containers_use(id).await? && area.remove_failed_pull(id)? {
            self.discard_unnamed_layers().await;
            return Ok(None);
        }
        let Some(there) = area.pull(id)? else {
            return Ok(None);
        };
        let again = st::StagedPull {
            tags: names
                .tags
                .iter()
                .map(|t| st::StagedTag {
                    repository: t.repository.clone(),
                    tag: t.tag.clone(),
                })
                .collect(),
            digest_names: names
                .digest_names
                .iter()
                .map(|(r, d)| (r.clone(), d.to_string()))
                .collect(),
            pulls: signed
                .iter()
                .map(|(reference, signatures)| st::StagedSignatures {
                    reference: reference.clone(),
                    signatures: signatures.clone(),
                })
                .collect(),
            started_at: st::now(),
            ..there
        };
        area.publish_pull(&again)?;
        let mut stats = if lazy {
            self.ensure_completer(id, access);
            TransferStats::default()
        } else {
            self.complete_waiting(id, access.clone()).await?
        };
        stats.duration_ms = start.elapsed().as_millis() as u64;
        Ok(Some(PullResult {
            id: id.to_string(),
            stats,
        }))
    }

    pub(super) async fn pull_engine(
        &self,
        client: &Resolver,
        reference: &str,
        progress_tx: mpsc::Sender<TransferProgress>,
        options: &EngineOptions,
    ) -> ImageResult<PullResult> {
        let EngineOptions {
            lazy,
            reach,
            ref platform,
            ref sources,
            inline_threshold,
        } = *options;
        // (an option the driver lacks is refused before anything is fetched)
        self.storage
            .capabilities()
            .refuse(
                self.storage.name(),
                &velarx_graph::negotiate::Ask {
                    lazy,
                    ..Default::default()
                },
            )
            .map_err(ImageError::from)?;
        let start = std::time::Instant::now();
        velarx_base::trace::point("pull start");
        // (the connections to the fetcher stay between the
        // calls of the pull, and go with it: it is not kept when the engine
        // pulls nothing; an origin that cannot be had fails the calls that
        // need it, below)
        let image_ref = ImageReference::parse(reference)?;
        info!(
            "{} image: {}",
            if lazy { "Lazy pulling" } else { "Pulling" },
            image_ref.full_name()
        );

        let requirements = self.policy_for(&image_ref)?;
        // (a tag is resolved by the sources of `[pull] names`: one that is
        // not the registry gives the digest it is signed for, and the pull
        // goes on by that digest; the image is still asked for by its tag,
        // which the signatures are judged for and the image is named by)
        let pinned = match (&image_ref.tag, &image_ref.digest) {
            (Some(_), None) => {
                let platform = platform.clone().unwrap_or_else(Platform::host);
                self.resolve_tag(&image_ref, &platform, &requirements)
                    .await?
            }
            _ => None,
        };
        let fetched_ref = ImageReference {
            digest: pinned.or(image_ref.digest),
            ..image_ref.clone()
        };
        let access = client.request_access().cloned().unwrap_or_default();
        let mut net = self.inspect_net(&image_ref, reach.tls_verify, &access)?;
        // (the sources are asked in their order; a digest vouches for the
        // manifest, and the manifest for the rest: what the fetchers have is
        // checked against them, and only the registry resolves a tag)
        if let Net::Origin(origin) = &net {
            use velarx_content::pull::net::origin::{MetadataSources, Source};
            let names = self.sources_of(sources.as_deref())?;
            let (first, rest) = split_at_registry(&names);
            let digest = fetched_ref.digest.is_some();
            let mut listed = Vec::new();
            if digest {
                let links = self.source_links(first).await;
                listed.push(Source::Fetchers(MetadataSources::open(links).await));
            }
            if let Some(rest) = rest {
                listed.push(Source::Registry);
                if digest {
                    let links = self.source_links(rest).await;
                    listed.push(Source::Fetchers(MetadataSources::open(links).await));
                }
            }
            net = Net::Origin(origin.clone().with_sources(listed));
        }
        // (the instance an index names is not asked of the registry when the
        // store has that very manifest, which is checked against its digest)
        let stored = |digest: &Digest| -> futures::future::BoxFuture<'_, Option<bytes::Bytes>> {
            let digest = *digest;
            Box::pin(async move {
                let image = self.db.get_image_by_digest(&digest).await.ok()?;
                Some(bytes::Bytes::from(image.manifest))
            })
        };
        let (manifest, manifest_digest, manifest_bytes, indexes) = net
            .manifest_raw(&fetched_ref, platform.as_ref(), Some(&stored))
            .await?;
        velarx_base::trace::point("pull manifest");
        // the policy, before anything else of the image is read
        let signatures = self
            .verify_signatures(
                &net,
                &image_ref,
                &manifest_digest,
                &manifest_bytes,
                &requirements,
            )
            .await?;
        // (recorded with the image: a pull that fails records nothing)
        let signed = vec![self.pull_record(&image_ref, &signatures)?];
        let image_id = self
            .db
            .image_id_for(&manifest_digest, &manifest_digest)
            .await?;
        let tags: Vec<ImageTag> = image_ref
            .tag
            .iter()
            .map(|t| ImageTag {
                repository: image_ref.name(),
                tag: t.clone(),
                image_id: image_id.clone(),
            })
            .collect();
        // (a pull by digest names the image `repository@digest`)
        let digest_names: Vec<(String, Digest)> = match (&image_ref.tag, &image_ref.digest) {
            (None, Some(d)) => vec![(image_ref.name(), *d)],
            _ => Vec::new(),
        };
        let names = PullNames {
            tags: &tags,
            digest_names: &digest_names,
        };

        // The configuration of a stored image is not fetched either.
        if let Some(done) = self
            .already_stored(
                &manifest_digest,
                &manifest,
                names,
                platform.as_ref().map(|p| (p, &progress_tx)),
                start,
            )
            .await?
        {
            self.keep_indexes(&indexes).await?;
            for (reference, signatures) in signed {
                self.db
                    .set_pulled_image(&manifest_digest, &reference, signatures)
                    .await?;
            }
            // Another name for an image the store has: its repository has
            // the blobs too.
            let sources = blob_sources(&manifest, Some(&image_ref.full_name()));
            if let Err(e) = self.db.add_blob_sources(sources).await {
                debug!("Cannot record where the blobs are: {e}");
            }
            // what clients show of an image they have: every layer is there
            for layer in &manifest.layers {
                let n = layer.size.max(0) as u64;
                progress(&progress_tx, layer, "exists", n, true);
            }
            return Ok(done);
        }

        // The pull of this image is in progress: this one joins it, and an
        // eager one waits for it.
        if let Some(done) = self
            .join_staged(&image_id, names, &signed, (lazy, &access), start)
            .await?
        {
            self.keep_indexes(&indexes).await?;
            for layer in &manifest.layers {
                let n = layer.size.max(0) as u64;
                progress(&progress_tx, layer, "exists", n, true);
            }
            return Ok(done);
        }

        let (config, config_bytes) = net.config_raw(&manifest.config).await?;
        if let Some(p) = platform {
            Self::check_platform(&config, p, &progress_tx);
        }
        let incoming = Incoming {
            manifest,
            manifest_bytes,
            manifest_digest,
            config,
            config_bytes,
            via: None,
            made: Vec::new(),
            registry_ref: Some(image_ref.full_name()),
            tags,
            digest_names,
            lazy,
            sources: sources.clone(),
            inline_threshold,
            reach,
            seal: false,
            states: false,
            hold: None,
            pulled: signed,
            indexes,
            access: Some(access.clone()),
            recorded: Vec::new(),
        };
        let result = self.install(net, incoming, progress_tx, start).await?;
        // a lazy pull goes on in the background, after the command that made
        // it (the pull is staged unless every layer was pulled whole)
        if lazy && self.staging_area().pull(&result.id)?.is_some() {
            self.ensure_completer(&result.id, &access);
        }
        Ok(result)
    }

    /// Fetch the layers of an image from `incoming.source`, check them
    /// against its configuration, and record the image.
    pub(super) async fn install(
        &self,
        net: Net,
        incoming: Incoming,
        progress_tx: mpsc::Sender<TransferProgress>,
        start: std::time::Instant,
    ) -> ImageResult<PullResult> {
        self.install_with(net, incoming, progress_tx, start).await
    }

    async fn install_with(
        &self,
        net: Net,
        incoming: Incoming,
        progress_tx: mpsc::Sender<TransferProgress>,
        start: std::time::Instant,
    ) -> ImageResult<PullResult> {
        let Incoming {
            mut manifest,
            mut manifest_bytes,
            mut manifest_digest,
            config,
            config_bytes,
            via,
            made,
            registry_ref,
            mut tags,
            digest_names,
            lazy,
            sources,
            inline_threshold,
            reach,
            seal,
            states,
            hold: image_hold,
            pulled,
            indexes,
            access,
            recorded,
        } = incoming;
        let started_at = chrono::Utc::now().to_rfc3339();
        let inline = inline_threshold.unwrap_or(self.inline_threshold);
        // (an image made here is named by the digest of its configuration,
        // which holds the diff ids of its layers whatever compression the
        // push gives them; one pulled by its manifest's)
        let config_digest = manifest.config.digest;
        let made_here = !made.is_empty();
        let named_by = move |manifest: Digest| if made_here { config_digest } else { manifest };
        let mut image_id = self
            .db
            .image_id_for(&manifest_digest, &named_by(manifest_digest))
            .await?;
        // (the data-only layers of the overlay: the objects of the stores,
        // and for a lazy image the files fetched for each layer)
        let stores = velarx_graph::objects::objects_dirs(&self.file_store).len();
        let caps = self.storage.capabilities();
        let image_name = registry_ref
            .clone()
            .unwrap_or_else(|| manifest_digest.to_string());
        Self::check_image(
            &image_name,
            &manifest,
            &config,
            &self.pull_config,
            caps.max_layers
                .zip(caps.max_image_layers(stores, lazy))
                .map(|(overlay, limit)| Mountable {
                    limit,
                    overlay,
                    stores,
                    lazy,
                }),
        )?;
        if lazy {
            // (its files are linked into the store, never copied)
            self.staging_area()
                .require_store_fs(self.file_store.root())
                .map_err(|e| ImageError::Storage(e.to_string()))?;
        }
        // the key each layer is looked up by: what the caller knows it is,
        // else what its descriptor asks for
        let expected: Vec<LayerKey> = manifest
            .layers
            .iter()
            .enumerate()
            .map(|(i, l)| {
                recorded
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| LayerKey::expected(l))
            })
            .collect();
        // What the store has stays until the hold below pins it: the lock is
        // held from the check to the hold and from the commit to the record,
        // not through the download (a removal or a collection would wait for
        // every pull); layers another pull fetches are waited for before it.
        // (a merged EROFS digest the layers cannot check: refused before any
        // layer, a lazy pull too)
        seal::check_statable(
            &manifest,
            &expected
                .iter()
                .map(|k| k.digest().alg())
                .collect::<Vec<_>>(),
        )?;
        let stored_before = self.stored_layers(&expected, &config).await?;
        let missing: Vec<&OciDescriptor> = manifest
            .layers
            .iter()
            .zip(&stored_before)
            .filter(|(_, ok)| !**ok)
            .map(|(l, _)| l)
            .collect();
        // (an eager pull of a registry fetches into the staging of each
        // layer, under its lease: another engine of the store that pulls
        // them now is waited for)
        let locks = self
            .lock_layers(&missing, !lazy && (registry_ref.is_some() || via.is_some()))
            .await?;
        let store = self.lock_store().await?;
        self.keep_indexes(&indexes).await?;
        let mut stored = self.stored_layers(&expected, &config).await?;
        if stored.iter().any(|ok| !ok) {
            if let Some(done) = self
                .already_stored(
                    &manifest_digest,
                    &manifest,
                    PullNames {
                        tags: &tags,
                        digest_names: &digest_names,
                    },
                    None,
                    start,
                )
                .await?
            {
                for (reference, signatures) in &pulled {
                    self.db
                        .set_pulled_image(&manifest_digest, reference, signatures.clone())
                        .await?;
                }
                return Ok(done);
            }
            stored = self.stored_layers(&expected, &config).await?;
        }

        let mut limits = Limits::from_config(&self.pull_config);
        // a blob written here from a directory is no bomb: a layer of
        // sparse files inflates far beyond any ratio
        if seal {
            limits.inflate_floor_bytes = limits.max_layer_bytes;
        }
        // The whole layer list of the image, in order, with the layers the
        // driver has marked as stored; the driver fetches the others, each
        // blob once (`feed::to_fetch`).
        let to_fetch = feed_layers(
            &manifest.layers,
            &config.rootfs.diff_ids,
            &expected,
            &stored,
        );
        let mut cached = 0u64;
        let mut started: HashSet<(&LayerKey, Digest)> = HashSet::new();
        for ((layer, key), ok) in manifest.layers.iter().zip(&expected).zip(&stored) {
            if started.insert((key, layer.digest)) && *ok {
                info!("Layer {} already exists", layer.digest);
                cached += 1;
                progress(
                    &progress_tx,
                    layer,
                    "exists",
                    layer.size.max(0) as u64,
                    true,
                );
            }
        }

        // The tables of contents of the layers of a pull from a registry
        // (`Probe`), the files of those of an eager pull, and the layers
        // without one (unpacked whole) come from the fetchers.
        let staged = match (&registry_ref, &via) {
            (_, Some(via)) => Some(
                self.staged_origin(via, sources.as_deref(), &manifest_bytes)
                    .await?,
            ),
            (Some(repository), _) => Some(
                self.staged_fetch(
                    (repository, sources.as_deref()),
                    reach.tls_verify,
                    access.as_ref(),
                    &manifest_bytes,
                )
                .await?,
            ),
            _ => None,
        };
        // (the staging of a layer keeps its lease, so that a thread that
        // outlives the pull cannot remove the staging of the next one)
        if let Some(staged) = &staged {
            staged.leased(&locks.leases);
        }
        // A lazy pull is accepted before anything of it exists, or refused
        // (`ImageNotLazy`): every layer the store lacks must have a table of
        // contents with the fs-verity digest of each file, which a fetcher
        // can serve on demand.  What the fetchers gave is what the pull keeps.
        // (a lazy layer fetches no file: its table is compared with what the
        // store has recorded of the files it lists, and with the other
        // layers of the image)
        // (the list of fetchers of the layers is opened while they are probed)
        let from = registry_ref.as_ref().filter(|_| lazy).map(|repository| {
            super::lazy_fetch::PulledFrom {
                repository: repository.clone(),
                reach,
                manifest: manifest_bytes.to_vec(),
            }
        });
        let (accepted_tx, accepted_rx) = futures::channel::mpsc::unbounded();
        let walker = from
            .as_ref()
            .map(|from| self.open_walker(from, accepted_rx));
        // (the profile of the image comes while the layers are probed)
        let profile = match &from {
            Some(_) => {
                let names = self.sources_of(sources.as_deref())?;
                let (this, id) = (self.clone(), image_id.clone());
                let (ask, asked) = futures::FutureExt::remote_handle(async move {
                    this.pull_profile(&id, &names).await
                });
                tokio::spawn(ask);
                Some(asked)
            }
            None => None,
        };
        let accepted = match (&staged, lazy) {
            (Some(staged), true) => {
                let image = registry_ref.clone().unwrap_or_default();
                Self::accept_lazy(
                    staged,
                    &manifest,
                    &stored,
                    (&image, limits.max_layer_bytes),
                    &self.db,
                    &accepted_tx,
                )
                .await?
            }
            _ => Accepted::default(),
        };
        drop(accepted_tx);
        let Accepted {
            found: lazy_found,
            made: made_early,
        } = accepted;
        // (the layers of a pull come from its fetchers, the ones a build made
        // are given)
        let content = match staged {
            Some(staged) => ContentFeed::new(net, self.db.clone(), limits).with_staged(staged),
            None => ContentFeed::made(self.db.clone(), limits, &made),
        }
        .with_lazy_found(lazy_found)
        .lazy(lazy)
        .with_progress(
            PROGRESS_STEP,
            {
                let tx = progress_tx.clone();
                Arc::new(move |layer: &FeedLayer, n: u64| {
                    progress(&tx, &layer.descriptor, "downloading", n, false)
                })
            },
            {
                let tx = progress_tx.clone();
                Arc::new(move |layer: &FeedLayer, _: &LayerDone| {
                    progress(
                        &tx,
                        &layer.descriptor,
                        "complete",
                        layer.descriptor.size.max(0) as u64,
                        true,
                    )
                })
            },
        );
        let feed = Arc::new(EngineFeed {
            inner: content,
            staging_dir: self.staging_dir.clone(),
            expected: expected.clone(),
            store: std::sync::Mutex::new(Some(store)),
            hold: std::sync::Mutex::new(None),
            commit_lock: std::sync::Mutex::new(None),
        });
        // (what the feed holds for the pull goes with this call, also when
        // it is cancelled: the tasks of the layers that hold the feed too
        // may end later, when the database is gone)
        let _let_go = LetGo(&feed);

        let (check, settled) = self.settled(Settling {
            manifest: &manifest,
            manifest_digest: &manifest_digest,
            expected: &expected,
            seal,
            states,
            inline,
            progress: &progress_tx,
            made: made_early,
        });

        let driver_feed: Arc<dyn PullFeed> = feed.clone();
        let driven = self.storage.pull(&driver_feed, &to_fetch, settled).await?;
        velarx_base::trace::point("pull erofs made");
        drop(driver_feed);
        let hold = feed
            .hold
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| ImageError::Storage("the pull took no hold".into()))?;
        let Pulled {
            layers: driven_layers,
            artifacts: recorded,
            verdict,
        } = driven;
        let Checked {
            layer_keys,
            merged_id,
            stored_erofs,
            ours: made,
            inlining,
        } = opened(&check, verdict, &driven_layers, &recorded)?;
        let done_layers: HashMap<LayerKey, LayerDone> =
            driven_layers.into_iter().map(|p| (p.key, p)).collect();
        debug!(
            "Layers pulled and their images made after {:?}",
            start.elapsed()
        );
        let mut restated = false;
        if states {
            for (l, k) in manifest.layers.iter_mut().zip(&layer_keys) {
                let erofs = made
                    .get(k)
                    .map(|m| m.image_digest.clone())
                    .or_else(|| stored_erofs.get(k).cloned().flatten());
                if let Some(erofs) = erofs {
                    let inline = match inlining.get(k) {
                        Some(i) => i.threshold,
                        None => self.db.get_layer(k).await?.inline,
                    };
                    let toc = done_layers.get(k).map(|d| d.toc.clone());
                    let erofs = self.stated_erofs(k, erofs, inline, toc).await?;
                    restated |= seal::state_layer(l, &erofs);
                }
            }
        }
        if let (true, Some((alg, id))) = (seal, merged_id) {
            // the manifest states it, and is the image's id (and no other
            // statement of a merged EROFS, which nothing here made)
            manifest
                .annotations
                .retain(|k, _| !seal::is_merged_annotation(k));
            manifest
                .annotations
                .insert(seal::merged_annotation(alg), id);
            restated = true;
        }
        if restated {
            let bytes = serde_json::to_vec(&manifest)?;
            manifest_digest = Digest::of(manifest_digest.alg(), &bytes);
            manifest_bytes = Bytes::from(bytes);
            image_id = self
                .db
                .image_id_for(&manifest_digest, &named_by(manifest_digest))
                .await?;
            for t in &mut tags {
                t.image_id = image_id.clone();
            }
        }
        // under the store lock, before it is recorded: no prune takes it
        if let Some(h) = &image_hold {
            holds::pin(&self.staging_dir.join(h), holds::IMAGE, [&image_id])?;
        }

        debug!("Files committed after {:?}", start.elapsed());
        let sealed = self.layers_sealed_now();
        let commits = done_layers
            .values()
            .filter(|d| !d.lazy)
            .map(|d| {
                layer_commit(d, registry_ref.as_deref())
                    .map(|c| super::storage::with_image(c, &made, &inlining, sealed))
            })
            .collect::<ImageResult<Vec<velarx_db::LayerCommit>>>()?;
        debug!("Rows prepared after {:?}", start.elapsed());
        let image = ImageRecord {
            id: image_id.clone(),
            manifest_digest,
            config_digest: manifest.config.digest,
            // The bytes the digests are of: push sends them back as they are.
            manifest: utf8(&manifest_bytes, "manifest")?,
            config: utf8(&config_bytes, "configuration")?,
            created_at: chrono::Utc::now().to_rfc3339(),
            is_lazy: false,
        };
        if done_layers.values().any(|d| d.lazy) {
            // The store holds only complete layers: the whole ones are
            // recorded now, the lazy ones wait in the staging area with the
            // image, which the store gets when its last layer is complete.
            self.db
                .commit_layers(commits, blob_sources(&manifest, registry_ref.as_deref()))
                .await?;
            velarx_base::trace::point("pull rows committed");
            // (the files a start reads are planned while the barrier waits)
            let set = from.zip(walker).map(|(from, walker)| {
                let layers = layer_keys
                    .iter()
                    .zip(&manifest.layers)
                    .filter_map(|(k, l)| Some((done_layers.get(k).filter(|d| d.lazy)?, l)))
                    .map(|(d, l)| {
                        // (the blob and the size the layer was staged with)
                        let desc = OciDescriptor {
                            digest: d.blob,
                            size: d.size,
                            ..l.clone()
                        };
                        Ok((d.key, desc, d.toc.clone(), d.toc_z.clone()))
                    })
                    .collect::<ImageResult<Vec<super::lazy_fetch::StartLayer>>>()?;
                let (tocs, config) = (layers.clone(), config.config.clone());
                let planned = tokio::task::spawn_blocking(move || {
                    super::lazy_fetch::plan_start_set(&tocs, &config, &[])
                });
                Ok::<_, ImageError>((from, layers, walker, planned))
            });
            let set = set.transpose()?;
            // (each with the EROFS image and the owners made of its table)
            let mut lazy = done_layers
                .values()
                .filter(|d| d.lazy)
                .map(|d| {
                    let m = made.get(&d.key).ok_or_else(|| {
                        ImageError::Layer(format!("no EROFS image was made for layer {}", d.key))
                    })?;
                    Ok((d.clone(), m.image_digest.clone(), m.owners.clone()))
                })
                .collect::<ImageResult<Vec<_>>>()?;
            lazy.sort_unstable_by_key(|(d, ..)| d.key.file_stem());
            let staged = velarx_content::pull::staged::StagedPull {
                id: image_id.clone(),
                manifest_digest: image.manifest_digest,
                config_digest: image.config_digest,
                manifest: image.manifest.clone(),
                config: image.config.clone(),
                layers: layer_keys.iter().map(|k| k.to_string()).collect(),
                tags: tags
                    .iter()
                    .map(|t| velarx_content::pull::staged::StagedTag {
                        repository: t.repository.clone(),
                        tag: t.tag.clone(),
                    })
                    .collect(),
                digest_names: digest_names
                    .iter()
                    .map(|(r, d)| (r.clone(), d.to_string()))
                    .collect(),
                pulls: pulled
                    .iter()
                    .map(
                        |(reference, signatures)| velarx_content::pull::staged::StagedSignatures {
                            reference: reference.clone(),
                            signatures: signatures.clone(),
                        },
                    )
                    .collect(),
                registry_ref: registry_ref.clone(),
                started_at: started_at.clone(),
            };
            // (a lease is waited for while another process holds it: not on
            // a worker of the runtime; the hold goes once the pull is
            // published, even when this pull is cancelled meanwhile)
            let (area, registry_ref) = (self.staging_area(), registry_ref.clone());
            tokio::task::spawn_blocking(move || -> ImageResult<()> {
                let mut barrier = velarx_content::pull::staged::Barrier::default();
                // (the barrier holds the leases of the layers until it
                // commits: taken in the order `lock_layers` takes them)
                for (d, erofs, owners) in &lazy {
                    pull::stage_layer(
                        &area,
                        &mut barrier,
                        d,
                        registry_ref.as_deref(),
                        reach,
                        (erofs, owners),
                    )?;
                }
                // the publish point: from here on the pull is visible, and
                // its layers are pinned by it
                area.publish_pull_after(&staged, barrier)?;
                drop(hold);
                Ok(())
            })
            .await
            .map_err(|e| ImageError::Storage(e.to_string()))??;
            velarx_base::trace::point("pull layers staged");
            if let Some((from, layers, walker, planned)) = set {
                let first = planned.await.unwrap_or_default();
                let first = (first, config.config.clone());
                self.fetch_start_set((layers, from), walker, first, profile)
                    .await;
            }
            debug!("Pull staged after {:?}", start.elapsed());
        } else {
            self.db
                .commit_pull(PullCommit {
                    layers: commits,
                    image,
                    image_layers: layer_keys.clone(),
                    sources: blob_sources(&manifest, registry_ref.as_deref()),
                    tags,
                    digest_names,
                    pulled,
                })
                .await?;
            drop(hold);

            debug!("Database updated after {:?}", start.elapsed());
        }
        // (what the origin brought is counted under its name)
        let origin = via.as_ref().map_or(SOURCE_REGISTRY, |v| v.party());
        let mut stats = TransferStats {
            layers_cached: cached,
            ..TransferStats::default()
        };
        for (layer, key) in manifest.layers.iter().zip(&layer_keys) {
            match done_layers.get(key) {
                Some(d) => {
                    let r = &d.report;
                    stats.add(origin, r.fetched_bytes, r.fetched_files);
                    stats.add(SOURCE_STORE, r.reused_bytes, r.reused_files);
                    for s in &r.sources {
                        stats.add(&s.name, s.bytes, s.files);
                    }
                    stats.layers.push(LayerStats {
                        digest: layer.digest.to_string(),
                        fetched_bytes: r.fetched_bytes,
                        deduplicated_bytes: r.reused_bytes,
                        fetched_files: r.fetched_files,
                        deduplicated_files: r.reused_files,
                        cached: false,
                    });
                }
                None => {
                    stats.add(SOURCE_STORE, layer.size.max(0) as u64, 0);
                    stats.layers.push(LayerStats {
                        digest: layer.digest.to_string(),
                        deduplicated_bytes: layer.size.max(0) as u64,
                        cached: true,
                        ..LayerStats::default()
                    });
                }
            }
        }
        stats.duration_ms = start.elapsed().as_millis() as u64;
        velarx_base::trace::point("pull end");
        info!(
            "Pull complete: {} fetched, {} deduplicated in {} ms",
            format_bytes(stats.from(origin).0),
            format_bytes(stats.from(SOURCE_STORE).0),
            stats.duration_ms
        );
        progress_tx.report(TransferProgress {
            subject: meter::Subject::Image,
            status: "complete".to_string(),
            current_bytes: 0,
            total_bytes: 0,
            complete: true,
        });
        Ok(PullResult {
            id: image_id,
            stats,
        })
    }
}

/// A manifest or an index of a registry.
#[derive(Debug, Clone)]
pub struct RemoteDescriptor {
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
    /// `{"architecture", "os", ...}` of each instance.
    pub platforms: Vec<serde_json::Value>,
}

/// The verdict a driver returned for a pull: it is of this check, of the layers
/// the driver pulled, and the driver recorded what the engine made, or it is
/// refused.
pub(super) fn opened(
    check: &CheckId,
    verdict: Verdict,
    pulled: &[LayerDone],
    recorded: &HashMap<LayerKey, velarx_graph::LayerArtifact>,
) -> ImageResult<Checked> {
    let checked = verdict.open(check).ok_or_else(|| {
        ImageError::Storage("the driver returned the verdict of another check".into())
    })?;
    let keys: Vec<&LayerKey> = pulled.iter().map(|p| &p.key).collect();
    storage::of_these_layers(&checked.ours, &keys)?;
    storage::agree(&checked.ours, recorded)?;
    Ok(checked)
}

/// What the engine's check of a pull ([`ImageService::settled`]) needs to
/// know of it.
pub(super) struct Settling<'a> {
    pub manifest: &'a OciManifest,
    pub manifest_digest: &'a Digest,
    /// The key each layer of the image is looked up by.
    pub expected: &'a [LayerKey],
    /// The pull makes a sealed image: its merged EROFS is stated, not checked.
    pub seal: bool,
    /// The pull states the digests of the EROFS images in the manifest.
    pub states: bool,
    /// The threshold the images of the layers are made with, unless a layer
    /// of the store is made again: that one keeps its own.
    pub inline: i64,
    pub progress: &'a mpsc::Sender<TransferProgress>,
    /// The identities and images already made, by layer (the lazy layers:
    /// made as their tables were checked); the others are made when the
    /// driver is done.
    pub made: Made,
}

/// The lazy layers [`ImageService::accept_lazy`] accepted, by blob digest,
/// with what was made of their tables by layer: their identities and EROFS
/// images.
#[derive(Default)]
struct Accepted {
    found: HashMap<String, pull::lazy::Found>,
    made: Made,
}

/// [`ImageService::made_of_table`].
struct MadeOfTable {
    key: LayerKey,
    artifact: crate::storage_driver::LayerArtifact,
    image: velarx_graph::MadeImage,
    files: Vec<(String, u64)>,
    stored_conflict: Option<(String, u64, u64)>,
}

/// What the image of a layer is made with: what its record says when it
/// has an image already (a layer fetched again is made as it was, the first
/// threshold wins and nothing is said), else `asked`.
fn threshold_of(record: Option<&velarx_db::LayerRecord>, asked: i64) -> i64 {
    record
        .filter(|r| r.erofs.is_some())
        .map_or(asked, |r| r.inline)
}

/// The files, by fs-verity digest, that the images hold and no layer of
/// the pull needs as an object: a file one layer holds and another one
/// (made with a smaller threshold) does not is an object.
fn held_files(
    pulled: &[LayerDone],
    inlining: &HashMap<LayerKey, velarx_graph::Inlining>,
) -> HashSet<String> {
    let needed: HashSet<&str> = pulled
        .iter()
        .filter(|p| !p.lazy)
        .flat_map(|p| {
            let own: HashSet<&str> = inlining
                .get(&p.key)
                .map(|i| i.files.iter().map(|f| f.digest.as_str()).collect())
                .unwrap_or_default();
            p.files
                .iter()
                .map(|f| f.digest.as_str())
                .filter(move |d| !own.contains(d))
        })
        .collect();
    inlining
        .values()
        .flat_map(|i| i.files.iter().map(|f| f.digest.clone()))
        .filter(|d| !needed.contains(d.as_str()))
        .collect()
}

/// The identity of layers and the EROFS image it was made from.
pub(super) type Made = HashMap<
    LayerKey,
    (
        crate::storage_driver::LayerArtifact,
        velarx_graph::MadeImage,
    ),
>;

impl ImageService {
    /// What the engine makes of the layers once the driver verified them,
    /// before it names any of them in its store:
    /// the merged EROFS of a complete image to check against the manifest or
    /// to state in it, the identity of each layer, and the digests the
    /// manifest states for them, checked before anything of the layers is
    /// written (nothing is left of a manifest that lies).  The check comes
    /// with the id its verdict is sealed with: the engine opens only the
    /// verdict it seals.
    pub(super) fn settled(&self, s: Settling<'_>) -> (CheckId, Settled) {
        let check = CheckId::fresh();
        let settled: Settled = {
            let check = check.clone();
            let (manifest, expected) = (s.manifest.clone(), s.expected.to_vec());
            let (seal, states, inline) = (s.seal, s.states, s.inline);
            let (db, mode) = (self.db.clone(), self.composefs_digests());
            let staging = self.staging_dir.clone();
            let (progress_tx, handle) = (s.progress.clone(), tokio::runtime::Handle::current());
            let manifest_alg = s.manifest_digest.alg();
            let mut early = s.made;
            Box::new(move |pulled: &mut Vec<LayerDone>, objects| {
                // (each layer of the image is under the key it was asked by)
                let layer_keys = expected;
                let done: HashMap<&LayerKey, &LayerDone> =
                    pulled.iter().map(|p| (&p.key, p)).collect();
                let stored = |d: &LayerKey| handle.block_on(db.get_layer(d));
                let merged = (seal || !seal::expected(&manifest)?.is_empty())
                    && !pulled.iter().any(|p| p.lazy);
                let mut merged_id = None;
                if merged {
                    let mut stored_tocs = HashMap::new();
                    for d in layer_keys.iter().filter(|d| !done.contains_key(*d)) {
                        if stored_tocs.contains_key(d) {
                            continue;
                        }
                        let toc = handle
                            .block_on(velarx_content::pull::stored::stored_toc(&db, d))?
                            .ok_or_else(|| {
                                ImageError::Layer(format!("layer {d} has no table of contents"))
                            })?;
                        stored_tocs.insert(*d, toc);
                    }
                    progress_tx.report(TransferProgress::phase("merging the layers (EROFS)"));
                    let tocs: Vec<&velarx_storage::Toc> = layer_keys
                        .iter()
                        .map(|d| done.get(d).map(|l| &*l.toc).or(stored_tocs.get(d)))
                        .collect::<Option<_>>()
                        .ok_or_else(|| ImageError::Layer("a layer has no TOC".into()))?;
                    let algs: Vec<Algorithm> =
                        layer_keys.iter().map(|k| k.digest().alg()).collect();
                    merged_id = seal::merged_erofs(
                        manifest_alg,
                        &algs,
                        &tocs,
                        objects,
                        (!seal).then_some(&manifest),
                    )?;
                }
                // the images of the layers, the store's from the commit on
                progress_tx.report(TransferProgress::phase(
                    "making the images of the layers (EROFS)",
                ));
                let mut stored_erofs: HashMap<LayerKey, Option<String>> = HashMap::new();
                for d in layer_keys.iter().filter(|d| !done.contains_key(*d)) {
                    if !stored_erofs.contains_key(d) {
                        stored_erofs.insert(*d, stored(d)?.erofs);
                    }
                }
                let (mut ours, mut images) = (HashMap::new(), HashMap::new());
                let mut tocs: Vec<(&LayerKey, &velarx_storage::Toc, i64)> = Vec::new();
                for p in pulled.iter() {
                    match early.remove(&p.key) {
                        Some((artifact, image)) => {
                            ours.insert(p.key, artifact);
                            images.insert(p.key, image);
                        }
                        None => {
                            let own = threshold_of(stored(&p.key).ok().as_ref(), inline);
                            tocs.push((&p.key, &*p.toc, own))
                        }
                    }
                }
                // (the content of a file an image holds: the staged file, or
                // the store's, by its fs-verity digest)
                let open = |d: &Digest| {
                    let path = objects(&d.to_string()).ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::NotFound, "not in the pull")
                    })?;
                    std::fs::File::open(path)
                };
                let (made, inlined) = storage::identities_of(&tocs, &open, &staging)?;
                ours.extend(made.artifacts);
                images.extend(made.images);
                let held = held_files(pulled, &inlined);
                if !states {
                    let theirs: Vec<Option<String>> = layer_keys
                        .iter()
                        .map(|k| {
                            ours.get(k)
                                .map(|a| a.image_digest.clone())
                                .or_else(|| stored_erofs.get(k).cloned().flatten())
                        })
                        .collect();
                    seal::check_layers(&manifest, &theirs, mode)?;
                }
                // (the driver records `identities` and returns `verdict` with
                // what it pulled; `ours` is the engine's copy of the
                // identities, which what the driver recorded is checked
                // against)
                Ok(Settlement {
                    held,
                    verdict: Verdict::sealed(
                        &check,
                        Checked {
                            layer_keys,
                            merged_id,
                            stored_erofs,
                            ours: ours.clone(),
                            inlining: inlined,
                        },
                    ),
                    identities: Identities {
                        artifacts: ours,
                        images,
                    },
                })
            })
        };
        (check, settled)
    }
}

/// The repository the blobs of a manifest were fetched from.
pub(super) fn blob_sources(manifest: &OciManifest, registry_ref: Option<&str>) -> Vec<BlobSource> {
    let Some(source) = registry_ref.and_then(|r| ImageReference::parse(r).ok()) else {
        return Vec::new();
    };
    std::iter::once(&manifest.config)
        .chain(&manifest.layers)
        .map(|d| BlobSource {
            digest: d.digest,
            registry: source.registry.clone(),
            repository: source.repository.clone(),
        })
        .collect()
}

/// The answer of a driver to `has_layers` about `asked` layers: one for each,
/// in order.  An answer of another length cannot be placed, and is refused
/// (no layer is taken as stored by a guess).
pub(super) fn per_position(asked: usize, have: Vec<bool>) -> ImageResult<Vec<bool>> {
    if have.len() != asked {
        return Err(ImageError::Storage(format!(
            "the storage driver answered for {} layers of the {asked} asked",
            have.len()
        )));
    }
    Ok(have)
}

/// The layers of an image as the engine asks the driver about them
/// ([`StorageDriver::has_layers`]): one per position of the image, in order,
/// with the key each is looked up by (`keys`), its diff id (`diff_ids`, those
/// of its configuration) and its chain id.  The same layer twice in an image
/// is asked twice: to a chain it is two layers.
pub(super) fn layer_refs(keys: &[LayerKey], diff_ids: &[Digest]) -> Vec<LayerRef> {
    keys.iter()
        .zip(diff_ids)
        .zip(velarx_types::chain_ids(diff_ids))
        .map(|((key, diff_id), chain_id)| LayerRef {
            key: *key,
            diff_id: *diff_id,
            chain_id,
        })
        .collect()
}

/// The layers of an image as the pull offers them to the driver
/// ([`StorageDriver::pull`]): all of them, in the order of the manifest, each
/// with its chain id and the chain id of the layer below it, and marked
/// `stored` for those the driver has (`stored`, one for each position, from
/// [`ImageService::stored_layers`]).
pub(super) fn feed_layers(
    descriptors: &[OciDescriptor],
    diff_ids: &[Digest],
    keys: &[LayerKey],
    stored: &[bool],
) -> Vec<FeedLayer> {
    let chains = velarx_types::chain_ids(diff_ids);
    descriptors
        .iter()
        .zip(diff_ids)
        .zip(keys)
        .zip(stored)
        .enumerate()
        .map(|(i, (((descriptor, diff_id), key), stored))| FeedLayer {
            key: *key,
            descriptor: descriptor.clone(),
            diff_id: *diff_id,
            chain_id: chains[i],
            parent: i.checked_sub(1).map(|p| chains[p]),
            stored: *stored,
        })
        .collect()
}

/// The sources before `registry` and those after it; none after when
/// `registry` is not one of them.
fn split_at_registry(names: &[String]) -> (&[String], Option<&[String]>) {
    match names.iter().position(|n| n == "registry") {
        Some(at) => (&names[..at], Some(&names[at + 1..])),
        None => (names, None),
    }
}

#[cfg(test)]
mod opened_tests {
    use super::*;

    fn nothing() -> Checked {
        Checked {
            layer_keys: Vec::new(),
            merged_id: None,
            stored_erofs: HashMap::new(),
            ours: HashMap::new(),
            inlining: HashMap::new(),
        }
    }

    /// The verdict a driver returns (of an eager pull, and of the completion
    /// of a lazy one) is opened only with the id of the check that sealed
    /// it.
    #[test]
    fn a_verdict_is_opened_only_with_the_id_of_its_check() {
        let check = CheckId::fresh();
        assert!(opened(
            &check,
            Verdict::sealed(&check, nothing()),
            &[],
            &HashMap::new()
        )
        .is_ok());
        let e = opened(
            &check,
            Verdict::sealed(&CheckId::fresh(), nothing()),
            &[],
            &HashMap::new(),
        )
        .err()
        .expect("the verdict of another check");
        assert!(e.to_string().contains("another check"), "{e}");
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    fn digest(text: &str) -> Digest {
        Digest::of(Algorithm::Sha256, text.as_bytes())
    }

    /// sha256 of "PARENT DIFF", from the formula of the image-spec, computed
    /// with `printf | sha256sum` outside this code.
    const A: &str = "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
    const B: &str = "sha256:3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d";
    const C: &str = "sha256:2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6";
    const AB: &str = "sha256:51c0c8ace48498d6f5fee6b0592cc06f2da0f3cbe09c5a34a97dce85c3889676";
    const ABC: &str = "sha256:2fce7f8ce91bcf0a1428b36e1024639fdbd9469eea762dba98aa749631885106";

    fn desc(blob: &Digest) -> OciDescriptor {
        OciDescriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            digest: *blob,
            size: 1,
            annotations: Default::default(),
        }
    }

    /// The engine hands a driver every layer of the image, in order, with the
    /// chain ids and parents of the OCI formula and the stored ones marked.
    #[test]
    fn the_feed_layers_are_the_whole_image_with_their_chains() {
        let diffs: Vec<Digest> = [A, B, C].iter().map(|d| d.parse().unwrap()).collect();
        let blobs: Vec<Digest> = (0..3).map(|n| digest(&format!("blob{n}"))).collect();
        let keys: Vec<LayerKey> = blobs.iter().map(|b| LayerKey::Whole(*b)).collect();
        let descs: Vec<OciDescriptor> = blobs.iter().map(desc).collect();
        // the base is stored, the rest is not
        let stored = [true, false, false];
        let layers = feed_layers(&descs, &diffs, &keys, &stored);
        assert_eq!(layers.len(), 3, "the stored layers are in the list");
        let chain: Vec<String> = layers.iter().map(|l| l.chain_id.to_string()).collect();
        assert_eq!(chain, [A, AB, ABC]);
        let parent: Vec<Option<String>> = layers
            .iter()
            .map(|l| l.parent.map(|p| p.to_string()))
            .collect();
        assert_eq!(parent, [None, Some(A.into()), Some(AB.into())]);
        assert_eq!(
            layers.iter().map(|l| l.stored).collect::<Vec<_>>(),
            [true, false, false]
        );
        assert_eq!(layers.iter().map(|l| l.key).collect::<Vec<_>>(), keys);
        assert!(layers.iter().zip(&diffs).all(|(l, d)| l.diff_id == *d));
    }

    /// The driver is asked about every position of the image, once each, in
    /// order, with the chain id of each: the same layer twice in an image is
    /// two questions (to a chain it is two layers).
    #[test]
    fn has_layers_is_asked_per_position() {
        let (a, b) = (digest("a"), digest("b"));
        let keys = [
            LayerKey::Whole(digest("ka")),
            LayerKey::Whole(digest("kb")),
            LayerKey::Whole(digest("ka")),
        ];
        let diffs = [a, b, a];
        let chains = velarx_types::chain_ids(&diffs);
        let asked = layer_refs(&keys, &diffs);
        assert_eq!(asked.len(), 3);
        assert_eq!(asked.iter().map(|l| l.key).collect::<Vec<_>>(), keys);
        assert_eq!(asked[0].key, asked[2].key);
        assert_ne!(asked[0].chain_id, asked[2].chain_id);
        assert_eq!(asked.iter().map(|l| l.chain_id).collect::<Vec<_>>(), chains);
    }

    /// An answer that is not one for each layer asked is refused: it cannot
    /// be placed, and no layer is taken as stored from it.
    #[test]
    fn an_answer_of_another_length_is_refused() {
        assert_eq!(per_position(2, vec![true, false]).unwrap(), [true, false]);
        assert!(per_position(0, vec![]).unwrap().is_empty());
        for have in [vec![true], vec![true, true, true], vec![]] {
            let e = per_position(2, have.clone()).unwrap_err();
            assert!(
                e.to_string().contains("answered for") && e.to_string().contains("of the 2 asked"),
                "{have:?}: {e}"
            );
        }
    }
}

#[cfg(test)]
mod stored_tests {
    use super::*;
    use velarx_db::LayerCommit;
    use velarx_types::digest::Algorithm;

    fn digest(text: &str) -> Digest {
        Digest::of(Algorithm::Sha256, text.as_bytes())
    }

    fn commit(n: u8, toc: &str, tarsplit: &[u8]) -> LayerCommit {
        LayerCommit {
            record: velarx_db::LayerRecord {
                stream_size: Some(0),
                inline: 0,
                key: LayerKey::Whole(digest(&format!("blob{n}"))),
                blob: None,
                diff_id: Some(digest(&format!("diff{n}"))),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                registry_ref: Some("example.com/image:1".into()),
                erofs: None,
                owners: None,
            },
            files: vec![],
            refs: vec![],
            chunks: vec![],
            toc_digest: digest(toc),
            tarsplit: Some(Digest::of(Algorithm::Sha256, tarsplit)),
            sealed: false,
            inlined: Vec::new(),
            blob_checked: false,
        }
    }

    /// The pull asks the storage driver which layers it has, and trusts
    /// that only for the layers the engine has an index of.
    #[tokio::test]
    async fn the_driver_says_which_layers_are_stored() {
        let tmp = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        db.commit_layers(
            vec![
                commit(1, "{}", b"ts"),
                commit(2, "{}", b"ts"),
                commit(3, "{}", b"ts"),
            ],
            vec![],
        )
        .await
        .unwrap();
        // 2 has no tar-split: pulled again
        db.mark_layer_incomplete(&commit(2, "{}", b"ts").record.key)
            .await
            .unwrap();
        // 3: the driver has it, the engine has no table of contents to
        // record an image from
        let third = commit(3, "{}", b"ts").record.key;
        db.conn()
            .call(move |c| {
                Ok(c.execute("UPDATE layers SET toc_digest = NULL WHERE id = ?1", [third])?)
            })
            .await
            .unwrap();
        let store = Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap());
        let service = ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        let keys: Vec<LayerKey> = (1..=4)
            .map(|n| LayerKey::Whole(digest(&format!("blob{n}"))))
            .collect();
        let mut config: OciConfig = serde_json::from_str(
            r#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#,
        )
        .unwrap();
        config.rootfs.diff_ids = (1..=4).map(|n| digest(&format!("diff{n}"))).collect();
        let stored = service.stored_layers(&keys, &config).await.unwrap();
        assert_eq!(stored, [true, false, false, false]);
        // the diff id of another image's layer is not the layer
        config.rootfs.diff_ids[0] = digest("another");
        let stored = service.stored_layers(&keys, &config).await.unwrap();
        assert!(!stored[0]);
        config.rootfs.diff_ids[0] = digest("diff1");
        // the answer is the driver's, not the engine's look at its rows: a
        // driver that has none of them (here: one that keeps its records
        // elsewhere) makes the pull fetch them, complete rows or not
        let mut service = service_of(&tmp).await;
        let stored = service.stored_layers(&keys, &config).await.unwrap();
        assert!(stored[0], "the driver of the same records has it");
        service.storage = storage_driver::open(
            DriverParts {
                db: velarx_db::Database::open_in_memory().await.unwrap(),
                store: service.file_store.clone(),
                staging_dir: service.staging_dir.clone(),
                fsverity: service.fsverity,
            },
            &service.driver_options(),
        );
        let stored = service.stored_layers(&keys, &config).await.unwrap();
        assert!(
            stored.iter().all(|ok| !ok),
            "a layer the driver does not have is not stored: {stored:?}"
        );
    }

    /// An engine whose database has layer 1 complete.
    async fn service_of(tmp: &tempfile::TempDir) -> ImageService {
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        db.commit_layers(vec![commit(1, "{}", b"ts")], vec![])
            .await
            .unwrap();
        let store = Arc::new(velarx_storage::FileStore::new(tmp.path().join("objects")).unwrap());
        ImageService::new(
            db,
            store,
            tmp.path().join("pulls"),
            velarx_storage::VerityMode::Off,
        )
        .unwrap()
    }

    /// A file the images hold is left out of the commit, unless a layer
    /// that does not hold it needs it as an object.
    #[test]
    fn a_file_a_layer_needs_as_an_object_is_not_left_out() {
        let id = |n: u8| format!("fsverity-sha256-12:{}", format!("{n:02x}").repeat(32));
        let layer = |n: u8, files: &[u8]| LayerDone {
            key: LayerKey::Whole(digest(&format!("blob{n}"))),
            blob: digest("blob"),
            diff_id: digest("diff"),
            size: 0,
            toc: Arc::new(velarx_storage::Toc {
                version: 1,
                entries: Vec::new(),
                tar_split_digest: None,
            }),
            files: files
                .iter()
                .map(|&f| velarx_content::pull::entry::FileUse {
                    digest: id(f),
                    size: 3,
                })
                .collect(),
            chunks: Vec::new(),
            report: Default::default(),
            tarsplit: Default::default(),
            toc_z: Default::default(),
            lazy: false,
            blob_checked: false,
            checked: Default::default(),
        };
        let holding = |files: &[u8]| velarx_graph::Inlining {
            threshold: 64,
            files: files
                .iter()
                .map(|&f| velarx_db::InlinedFile {
                    digest: id(f),
                    offset: 0,
                    size: 3,
                })
                .collect(),
        };
        let (a, b) = (layer(1, &[1, 2]), layer(2, &[2, 3]));
        // (a holds 1 and 2, b holds 3 only: 2 is an object of b)
        let inlining = HashMap::from([(a.key, holding(&[1, 2])), (b.key, holding(&[3]))]);
        assert_eq!(
            held_files(&[a, b], &inlining),
            HashSet::from([id(1), id(3)])
        );
    }

    /// The first threshold a layer is made with wins, silently: a layer with
    /// an image keeps its record's, one without takes the pull's.
    #[test]
    fn a_layer_with_an_image_keeps_the_threshold_it_was_made_with() {
        let mut record = commit(1, "{}", b"ts").record;
        record.inline = 64;
        assert_eq!(threshold_of(None, 4096), 4096);
        // (no image recorded: nothing was made with 64)
        assert_eq!(threshold_of(Some(&record), 4096), 4096);
        record.erofs = Some("sha256:a".into());
        assert_eq!(threshold_of(Some(&record), 4096), 64);
        record.inline = 0;
        assert_eq!(threshold_of(Some(&record), -1), 0);
    }

    /// The files the image of a layer holds are no objects of the layer:
    /// its record says the threshold and the extents, and its files and
    /// references leave them out.
    #[test]
    fn the_files_an_image_holds_are_not_the_objects_of_its_layer() {
        let file = |n: u8| velarx_db::FileRecord {
            digest: format!("fsverity-sha256-12:{}", format!("{n:02x}").repeat(32)),
            size: 3,
            created_at: "2026-01-01T00:00:00Z".into(),
            checked: false,
        };
        let mut c = commit(1, "{}", b"ts");
        c.files = vec![file(1), file(2)];
        c.refs = c.files.iter().map(|f| (f.digest.clone(), 1)).collect();
        let key = c.record.key;
        let held = velarx_db::InlinedFile {
            digest: file(1).digest,
            offset: 4096,
            size: 3,
        };
        let inlining = HashMap::from([(
            key,
            velarx_graph::Inlining {
                threshold: 64,
                files: vec![held.clone()],
            },
        )]);
        let made = HashMap::new();
        let c = super::storage::with_image(c, &made, &inlining, true);
        assert_eq!(c.record.inline, 64);
        assert_eq!(c.inlined, [held]);
        assert_eq!(
            c.files.iter().map(|f| &f.digest).collect::<Vec<_>>(),
            [&file(2).digest]
        );
        assert_eq!(c.refs, [(file(2).digest, 1)]);
        // (a layer the engine made no image for is as it was)
        let c = super::storage::with_image(commit(2, "{}", b"ts"), &made, &inlining, true);
        assert_eq!(c.record.inline, 0);
    }
}

#[cfg(test)]
mod sources_tests {
    use super::split_at_registry;

    #[test]
    fn the_sources_are_split_where_the_registry_is() {
        let names = |l: &[&str]| l.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let list = names(&["a", "registry", "b"]);
        assert_eq!(split_at_registry(&list), (&list[..1], Some(&list[2..])));
        let list = names(&["a", "b"]);
        assert_eq!(split_at_registry(&list), (&list[..], None));
    }
}
