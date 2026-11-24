// SPDX-License-Identifier: Apache-2.0
//! Images pulled lazily: files on demand, and the completion that commits
//! the layers once their files are staged.

use super::*;
use std::path::{Path, PathBuf};
use velarx_content::pull::commit::ImageStep;
use velarx_content::pull::staged::{StagedPull, Staging};
use velarx_content::pull::{layer_commit, LayerDone};
use velarx_db::LayerKey;
use velarx_fuse::LazyFileFetcher;
use velarx_registry::auth::RegistryAccess;

/// The files fetched together by the retrieval, at most.
const GROUP_FILES: usize = 64;
/// The bytes fetched together by the retrieval, at most (a bigger file is a
/// group of its own).
const GROUP_BYTES: u64 = 8 << 20;

/// How long a pull waits for the startup profile of its image from the
/// sources: a peer that has it answers in a round trip, and a pull is not
/// held longer for what is only a hint.
const PROFILE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// A staged layer of an image being completed, and what its proof needs.
#[derive(Clone)]
pub(super) struct LazyLayer {
    /// The layer of the store (its TOC)
    pub(super) key: LayerKey,
    desc: OciDescriptor,
    /// The diff id the configuration of the image claims for it
    diff_id: Digest,
    toc: Arc<Toc>,
    tarsplit: bytes::Bytes,
    /// The table as the registry sent it, recorded with the layer
    toc_z: bytes::Bytes,
    /// What the staging area says of it (`layer.json`)
    meta: velarx_content::pull::staged::StagedLayerMeta,
}

/// What a try of the completion of a pull works on: the layers the store
/// lacks and the groups of files to fetch for them.
pub(super) struct Plan {
    pub(super) pull: StagedPull,
    manifest: OciManifest,
    config: OciConfig,
    keys: Vec<LayerKey>,
    /// The layers the store lacks
    pub(super) layers: Arc<[LazyLayer]>,
    /// The groups, in the order they are fetched
    pub(super) groups: Vec<PlanGroup>,
    /// What the store and the staging had of the files already
    pub(super) reused: (u64, u64),
    /// The image is in the store already: only the names of the pull are
    /// added
    names_only: bool,
}

/// A group of files, fetched into the staging of a layer.
pub(super) struct PlanGroup {
    /// The layer it is fetched into (a content is fetched once, into the
    /// first layer that has it)
    pub(super) layer: usize,
    /// The layers that wait for its files
    pub(super) needed_by: Vec<usize>,
    pub(super) files: Vec<String>,
    pub(super) bytes: u64,
}

impl ImageService {
    /// The startup profile of the image of the pull `id` from the sources
    /// that have one: at most `max` digests of files, empty when nobody has
    /// one.  Only an order of files: what is fetched in it is checked as any
    /// file is.
    pub async fn peer_profile(&self, id: &str, max: usize) -> Vec<String> {
        let Ok(names) = self.sources_of(None) else {
            return Vec::new();
        };
        self.profile_from(id, &names, max).await
    }

    /// The startup profile of the image `id` for a pull that starts: the
    /// one this node recorded, else the one of the sources (the peers) if
    /// the settings ask them.  Empty when there is none.
    pub(super) async fn pull_profile(&self, id: &str, sources: &[String]) -> Vec<String> {
        let config = &self.pull_config;
        if config.lazy_profile_secs == 0 {
            return Vec::new();
        }
        let path = velarx_fuse::composefs::profile_path(self.file_store.root(), id);
        let max = config.lazy_profile_files;
        let local = tokio::task::spawn_blocking(move || velarx_fuse::profile::read(&path, max))
            .await
            .unwrap_or_default();
        if !local.is_empty() || !config.lazy_profile_peers {
            return local;
        }
        let asked = self.profile_from(id, sources, max);
        tokio::time::timeout(PROFILE_WAIT, asked)
            .await
            .unwrap_or_default()
    }

    /// The profile of the image `id` from the fetchers `sources`.
    async fn profile_from(&self, id: &str, names: &[String], max: usize) -> Vec<String> {
        let Ok(image) = velarx_types::digest::Digest::from_id(id) else {
            return Vec::new();
        };
        let (name, max_bytes) = (
            image.to_string(),
            velarx_content::fetcher::fetch::PROFILE_MAX_BYTES,
        );
        let mut text = None;
        for mut link in self.source_links(names).await {
            let got = velarx_content::idle::within(link.idle, async {
                link.conn
                    .open(velarx_content::fetcher::fetch_client::Scoping::bare(
                        link.idle,
                    ))
                    .await?;
                link.conn.get_profile(&name, max_bytes).await
            })
            .await;
            let Ok(file) = got else {
                continue;
            };
            let read = tokio::task::spawn_blocking(move || {
                velarx_base::sealed::read_sealed_whole(&file, max_bytes)
                    .map_err(std::io::Error::other)
            })
            .await;
            if let Ok(Ok(bytes)) = read {
                text = Some(bytes);
                break;
            }
        }
        let Some(text) = text else {
            return Vec::new();
        };
        let mut files = velarx_fuse::profile::parse(&text, max);
        files.retain(|d| velarx_content::pull::is_file_key(d));
        files.truncate(max);
        files
    }

    /// The staging area of lazy pulls of the store.
    pub fn staging_area(&self) -> Staging {
        Staging::new(&self.staging_dir)
    }

    /// Where the credentials of a completion of `reference` go
    /// (`registry/repository`, mirrors included): the endpoints of the
    /// staged layers that were pulled with credentials, which are not stored.
    pub async fn credential_scopes(&self, reference: &str) -> ImageResult<Vec<String>> {
        let mut scopes = std::collections::BTreeSet::new();
        let area = self.staging_area();
        let Some(entry) = area.find(reference) else {
            return Ok(Vec::new());
        };
        for key in entry.pull.layers.iter().filter_map(|k| LayerKey::parse(k)) {
            let Some(layer) = area.layer(&key)? else {
                continue;
            };
            if !layer.meta.reach.creds {
                continue;
            }
            let Some(registry_ref) = layer.meta.registry_ref.as_deref() else {
                continue;
            };
            let target = self
                .resolver
                .target(&ImageReference::parse(registry_ref)?)?;
            scopes.extend(target.credential_scopes());
        }
        Ok(scopes.into_iter().collect())
    }

    /// Where the credentials for `reference` go (`registry/repository`): for
    /// each reference it can mean (short names, the search registries), the
    /// mirrors and the registry of a pull, the registry alone of a push.
    pub fn reference_credential_scopes(
        &self,
        reference: &str,
        push: bool,
    ) -> ImageResult<Vec<String>> {
        // (a reference that means nothing is the operation's error to
        // report, which says it better)
        let mut scopes = std::collections::BTreeSet::new();
        for candidate in self.candidates(reference).unwrap_or_default() {
            let Ok(image_ref) = ImageReference::parse(&candidate) else {
                continue;
            };
            let target = if push {
                self.resolver.push_target(&image_ref)
            } else {
                self.resolver.target(&image_ref)
            };
            scopes.extend(target.into_iter().flat_map(|t| t.credential_scopes()));
        }
        Ok(scopes.into_iter().collect())
    }

    /// Finish the pull of `reference` in this process: fetch what its staged
    /// layers lack, commit each layer to the store as it is complete, and the
    /// image with the last.  Does nothing for an image the store has.
    pub async fn complete_image(&self, reference: &str) -> ImageResult<TransferStats> {
        self.complete_image_with(reference, RegistryAccess::default())
            .await
    }

    /// `complete_image`, with the credentials and certificates of the
    /// command: the layers that were pulled with such need them again (they
    /// are not stored), and their files are fetched by this process.
    pub async fn complete_image_with(
        &self,
        reference: &str,
        access: RegistryAccess,
    ) -> ImageResult<TransferStats> {
        match self.staging_area().find(reference) {
            Some(entry) => self.complete_waiting(&entry.pull.id, access).await,
            None => {
                // (an image of the store is complete; one that is not
                // known is an error)
                self.get(reference).await?;
                Ok(TransferStats::default())
            }
        }
    }

    /// The pull `id`, finished for a command that waits for it (a `run`
    /// without `--lazy`): with the parallelism the monitors have.
    pub async fn complete_staged(&self, id: &str) -> ImageResult<TransferStats> {
        self.complete_waiting(id, RegistryAccess::default()).await
    }

    /// What a try of the completion of the pull `id` works on, once the
    /// layers the store lacks are staged and proven against their tables
    /// (`access`: the credentials of the command).  None: the pull is gone.
    pub(super) async fn prepare(
        &self,
        id: &str,
        access: RegistryAccess,
    ) -> ImageResult<Option<Arc<Plan>>> {
        let area = self.staging_area();
        let Some(pull) = area.pull(id)? else {
            return Ok(None);
        };
        let manifest: OciManifest = serde_json::from_str(&pull.manifest)?;
        let driver_pulls = !self.storage.holds_objects();
        if self.image_stored(&pull.manifest_digest).await {
            // (committed by another process, by an earlier run of this one,
            // or pulled whole meanwhile: the names of the pull are its)
            return Ok(Some(Arc::new(Plan {
                config: serde_json::from_str(&pull.config)?,
                pull,
                manifest,
                keys: Vec::new(),
                layers: Vec::new().into(),
                groups: Vec::new(),
                reused: (0, 0),
                names_only: true,
            })));
        }
        let config: OciConfig = serde_json::from_str(&pull.config)?;
        if manifest.layers.len() != config.rootfs.diff_ids.len()
            || manifest.layers.len() != pull.layers.len()
        {
            return Err(ImageError::Manifest(
                "the layers, the diff ids and the staged layers differ".into(),
            ));
        }
        let keys: Vec<LayerKey> = pull
            .layers
            .iter()
            .map(|k| {
                LayerKey::parse(k)
                    .ok_or_else(|| ImageError::Layer(format!("{k:?} is no layer key")))
            })
            .collect::<ImageResult<_>>()?;
        // (a driver that keeps its own files gets the layers from the staging,
        // as a pull brings them, and the engine keeps every staged layer: the
        // containers made on the pull run on its files, the layers the
        // driver holds already too)
        // (the credentials of the command reach the tar-splits that the
        // start did without, fetched before the files)
        self.set_lazy_access(access);
        let layers: Arc<[LazyLayer]> = self
            .lazy_layers(&area, &manifest, &config, &keys, driver_pulls)
            .await?
            .into();
        let profile = velarx_fuse::profile::read(
            &velarx_fuse::composefs::profile_path(self.file_store.root(), id),
            self.pull_config.lazy_profile_files,
        );
        let (groups, reused) = self.plan_groups(&layers, profile).await?;
        Ok(Some(Arc::new(Plan {
            pull,
            manifest,
            config,
            keys,
            layers,
            groups,
            reused,
            names_only: false,
        })))
    }

    /// The pull, finished: the image of the store with the layers of the
    /// plan (the storage driver has pulled them).
    pub(super) async fn commit_planned_image(&self, plan: &Plan) -> ImageResult<()> {
        if plan.names_only {
            return self.commit_image(&plan.pull, &plan.manifest, None).await;
        }
        self.commit_image(&plan.pull, &plan.manifest, Some(&plan.keys))
            .await?;
        if !self.storage.holds_objects() {
            // (the image is the store's and the pull is gone: what the
            // containers made on the pull do not name is not needed)
            self.release_engine_copies(Some(&plan.keys)).await;
        }
        Ok(())
    }

    /// The staged layers of the image that the store lacks, each once, with
    /// what their proof needs.  A layer of the store must be the one the
    /// configuration of this image claims: the diff id it was proven
    /// against.
    async fn lazy_layers(
        &self,
        area: &Staging,
        manifest: &OciManifest,
        config: &OciConfig,
        keys: &[LayerKey],
        staged_too: bool,
    ) -> ImageResult<Vec<LazyLayer>> {
        // which of them the store has is the driver's answer, once for all
        let have = self.stored_layers(keys, config).await?;
        let mut layers = Vec::new();
        let mut replays = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (at, (((desc, diff_id), key), have)) in manifest
            .layers
            .iter()
            .zip(&config.rootfs.diff_ids)
            .zip(keys)
            .zip(&have)
            .enumerate()
        {
            // (`staged_too`: a layer the driver has and the pull staged is
            // the engine's to keep as well, for the containers made on the
            // pull; one it has and nothing staged was kept by the completion
            // that released it)
            if *have && !(staged_too && area.layer(key)?.is_some()) {
                // proven when it was committed, against this image's diff id
                continue;
            }
            // (a layer at two places is staged once)
            if !seen.insert(*key) {
                continue;
            }
            // (the layer the index has under this key was proven against
            // another diff id than this image's: the key is not this image's
            // layer)
            if let Ok(record) = self.db.get_own_layer(key).await {
                if !record.matches_diff_id(diff_id) {
                    return Err(ImageError::Contradicted(format!(
                        "layer {key} has the diff id {:?}, the image says {diff_id}",
                        record.diff_id
                    )));
                }
            }
            // (read whole: the completion of another image that shares the
            // layer may commit it and remove its staging meanwhile)
            let staged = area.layer(key).and_then(|staged| {
                staged
                    .map(|s| Ok((s.toc()?, s.tarsplit()?, s.toc_z()?, s.meta)))
                    .transpose()
            });
            let staged = match staged {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                staged => staged?,
            };
            let Some((toc, tarsplit, toc_z, meta)) = staged else {
                // (the completion of another image that shares the layer
                // committed it since: the driver has it now)
                if self.stored_layers(keys, config).await?[at] {
                    continue;
                }
                return Err(ImageError::Layer(format!(
                    "layer {key} is neither in the store nor staged: pull the image again"
                )));
            };
            let mut tarsplit = bytes::Bytes::from(tarsplit);
            if tarsplit.is_empty() && !toc.is_canonical() {
                tarsplit = self.lazy_tarsplit(key, &toc).await?;
            }
            let toc = Arc::new(toc);
            replays.push(tokio::task::spawn_blocking({
                let (toc, tarsplit, layer) = (toc.clone(), tarsplit.clone(), desc.digest);
                move || velarx_content::pull::lazy::replay(&toc, tarsplit, &layer)
            }));
            layers.push(LazyLayer {
                key: *key,
                desc: desc.clone(),
                diff_id: *diff_id,
                toc,
                tarsplit,
                toc_z: toc_z.into(),
                meta,
            });
        }
        // (what the pull staged was checked against the digests of the table;
        // that the tar-split says what the table says is checked before the
        // layers are committed)
        for replay in replays {
            replay
                .await
                .map_err(|e| ImageError::Layer(format!("the replay task: {e}")))??;
        }
        Ok(layers)
    }

    /// The groups of files to fetch for `layers`, in the order they are
    /// fetched (the files the startup `profile` names first, in its order),
    /// with the layers that wait for each, and the bytes and files the store
    /// and the staging had already.  What the stores hold is asked once for
    /// each content: the plan is of that snapshot.
    async fn plan_groups(
        &self,
        layers: &Arc<[LazyLayer]>,
        profile: Vec<String>,
    ) -> ImageResult<(Vec<PlanGroup>, (u64, u64))> {
        if layers.is_empty() {
            return Ok((Vec::new(), (0, 0)));
        }
        let staged = self.staged_files(layers)?;
        let (store, l) = (self.file_store.clone(), layers.clone());
        tokio::task::spawn_blocking(move || {
            // the contents get dense numbers, in the order of the tables
            let mut id_of: std::collections::HashMap<String, u32> = Default::default();
            let mut digests: Vec<String> = Vec::new();
            // (the bytes the first entry of a content takes in the blob)
            let mut blob: Vec<u64> = Vec::new();
            let mut tables: Vec<Vec<velarx_plan_core::File>> = Vec::new();
            for layer in l.iter() {
                let mut table = Vec::new();
                for e in layer
                    .toc
                    .entries
                    .iter()
                    .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
                {
                    let d = e.verity().ok_or_else(|| {
                        ImageError::Layer(format!(
                            "layer {}: `{}` has no fs-verity digest in the table",
                            layer.desc.digest, e.name
                        ))
                    })?;
                    let content = *id_of.entry(d.clone()).or_insert_with(|| {
                        digests.push(d);
                        blob.push(e.end_offset.saturating_sub(e.offset));
                        digests.len() as u32 - 1
                    });
                    table.push(velarx_plan_core::File {
                        content,
                        size: e.size,
                    });
                }
                tables.push(table);
            }
            let present: Vec<bool> = digests
                .iter()
                .map(|d| store.contains(d) || staged.iter().any(|s| s.get_path(d).is_some()))
                .collect();
            let mut reused: (u64, u64) = (0, 0);
            for (here, bytes) in present.iter().zip(&blob) {
                if *here {
                    reused = (reused.0.saturating_add(*bytes), reused.1 + 1);
                }
            }
            let profile: Vec<u32> = profile
                .iter()
                .filter_map(|d| id_of.get(d))
                .copied()
                .collect();
            let limits = velarx_plan_core::Limits {
                files: GROUP_FILES as u32,
                bytes: GROUP_BYTES,
            };
            let groups = velarx_plan_core::plan(&tables, &present, &profile, limits)
                .into_iter()
                .map(|g| PlanGroup {
                    layer: g.layer as usize,
                    needed_by: g.needed_by.iter().map(|&l| l as usize).collect(),
                    files: g
                        .files
                        .iter()
                        .map(|&c| digests[c as usize].clone())
                        .collect(),
                    bytes: g.bytes,
                })
                .collect();
            Ok::<_, ImageError>((groups, reused))
        })
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))?
    }

    /// The staged layers the driver lacks, pulled into it from the files of the
    /// staging (and the engine's own store): the pull of an eager image, with the
    /// engine's copy of each file in place of the registry's.  The driver asks
    /// for the files it lacks, the engine measures what it copies in the
    /// places the driver gave, reads each layer back from the driver to prove
    /// its diff id, checks the identities of the layers (the same check as
    /// the pull's, the manifest's statements too) and only then records the
    /// layers.  The driver publishes them with its `Commit`; the image is the
    /// caller's to commit.
    pub(super) async fn pull_staged(&self, plan: &Plan) -> ImageResult<()> {
        let Plan {
            pull,
            manifest,
            config,
            keys,
            layers,
            ..
        } = plan;
        if layers.is_empty() {
            return Ok(());
        }
        // The containers made on the pull are served by the engine's files
        // (the image server of the root, and the writable layer in the
        // bundle): the engine keeps them, as the objects of its store and the
        // images of the layers, whether or not a container is made on the
        // pull yet (one can be made until the pull is forgotten).  The staged
        // inodes are linked, not copied (each measured against its name
        // first); the rows of the layers name the files, so the collection
        // removes them with the image.  Before anything is recorded: a
        // completion that stops after this does it again, the same.
        let mut seen = std::collections::HashSet::new();
        let files = layers
            .iter()
            .flat_map(|l| l.toc.files())
            .filter(|d| seen.insert(d.clone()))
            .collect();
        self.link_files(layers, files, layers.iter().collect())
            .await?;
        self.require_covered(layers).await?;
        let stored = self.stored_layers(keys, config).await?;
        let to_fetch =
            super::pull::feed_layers(&manifest.layers, &config.rootfs.diff_ids, keys, &stored);
        let indexes = layers
            .iter()
            .map(|l| velarx_graph::LayerIndex {
                key: l.key,
                toc: l.toc.clone(),
                tarsplit: l.tarsplit.clone(),
                toc_z: l.toc_z.clone(),
            })
            .collect();
        // (the files are the engine's own objects now; one that is not, the
        // staging's)
        let content = velarx_graph::StoreContent(
            std::iter::once(self.file_store.clone())
                .chain(self.staged_files(layers)?)
                .collect(),
        );
        let feed: Arc<dyn velarx_graph::PullFeed> = Arc::new(velarx_graph::StagedFeed::new(
            indexes,
            Arc::new(content),
            self.pull_config.parallel_layers,
        ));
        let (progress, _) = mpsc::channel(1);
        let (check, settled) = self.settled(super::pull::Settling {
            manifest,
            manifest_digest: &pull.manifest_digest,
            expected: keys,
            seal: false,
            states: false,
            progress: &progress,
            made: Default::default(),
        });
        let velarx_graph::Pulled {
            layers: driven,
            artifacts: recorded,
            verdict,
        } = self.storage.pull(&feed, &to_fetch, settled).await?;
        drop(feed);
        let checked = super::pull::opened(&check, verdict, &driven, &recorded)?;
        for pulled in driven {
            let layer = layers.iter().find(|l| l.key == pulled.key).ok_or_else(|| {
                ImageError::Storage(format!(
                    "the storage driver pulled the layer {}, which the image does not stage",
                    pulled.key
                ))
            })?;
            let _one = self.commit_layer_lock(&layer.key).await?;
            let _store = self.lock_store().await?;
            if let Ok(record) = self.db.get_own_layer(&layer.key).await {
                if !record.matches_diff_id(&layer.diff_id) {
                    return Err(ImageError::Contradicted(format!(
                        "layer {} has the diff id {:?}, the image says {}",
                        layer.key, record.diff_id, layer.diff_id
                    )));
                }
            }
            // (the images containers run on while the layers are staged are
            // the ones the pull recorded: the driver's record of the layer
            // is the same)
            let made = checked.ours.get(&layer.key).ok_or_else(|| {
                ImageError::Storage(format!("no identity was made for layer {}", layer.key))
            })?;
            if made.image_digest != layer.meta.erofs {
                return Err(ImageError::Contradicted(format!(
                    "the EROFS image of layer {} is {}, the lazy pull recorded {}",
                    layer.key, made.image_digest, layer.meta.erofs
                )));
            }
            let mut commit = super::storage::with_image(
                layer_commit(&pulled, layer.meta.registry_ref.as_deref())?,
                &checked.ours,
            );
            (commit.record.blob, commit.record.size) =
                (layer.meta.blob.parse().ok(), layer.meta.size);
            self.db.commit_layers(vec![commit], Vec::new()).await?;
            debug!("Layer {} pulled into the storage driver", layer.key);
        }
        Ok(())
    }

    /// One layer into the store, once the staging (or the store) has all its
    /// files, in this order:
    ///
    /// 1. the files are written to the disk if `[storage] sync` says (one
    ///    `syncfs`: they are complete and sealed, nothing in progress is
    ///    synced) and then linked into `objects/` with the very inode;
    /// 2. the EROFS image of the layer is renamed into `composefs/` (inside
    ///    the same two barriers);
    /// 3. one transaction records the layer, with no diff id: nothing claims
    ///    the stream before a recreation of it checks one.
    ///
    /// The commit lock of the layer is exclusive across processes and the
    /// lock of the store is held shared from the first link to the end of
    /// the transaction, so a collection never removes what is linked and not
    /// yet referenced.  A layer that another process committed first is
    /// kept as it is, when it has this image's diff id.
    pub(super) async fn commit_layer(
        &self,
        layer: &LazyLayer,
        all: &[LazyLayer],
        chunks: Vec<velarx_db::ChunkLocation>,
    ) -> ImageResult<()> {
        // The files and the image of the layer are verified first, with no
        // lock held (the reads and hashes of the commit are all here): the
        // sections that follow only link, rename and sync.
        let verified = self
            .verify_files(all, layer.toc.files(), vec![layer])
            .await?;
        let one = self.commit_layer_lock(&layer.key).await?;
        let store = self.lock_store().await?;
        // The race check of this commit: under the commit lock of the layer,
        // the store says whether another process committed it first, as it
        // said when the layers were chosen.  A layer it has marked
        // incomplete is committed again.
        if let Some(state) = self.db.get_own_layer_states(&[layer.key]).await?.first() {
            if !state.matches_diff_id(&layer.diff_id) {
                return Err(ImageError::Contradicted(format!(
                    "layer {} has the diff id {:?}, the image says {}",
                    layer.key, state.diff_id, layer.diff_id
                )));
            }
            if state.is_stored_as(&layer.diff_id) {
                return Ok(());
            }
        }
        // (a staged layer is always one with a table of contents,
        // `LayerKey::expected` of a chunked descriptor: no other key has
        // files to link, and no stream is proven here)
        if !layer.key.is_toc() {
            return Err(ImageError::Storage(format!(
                "the staged layer {} has no table of contents",
                layer.key
            )));
        }
        // by its table: every file was measured against its entry, and
        // nothing claims the stream (no diff id) before a recreation of it
        // checks one
        let mut done = LayerDone {
            key: layer.key,
            blob: layer.desc.digest,
            diff_id: layer.diff_id,
            size: layer.desc.size,
            toc: layer.toc.clone(),
            files: Vec::new(),
            chunks,
            report: Default::default(),
            tarsplit: layer.tarsplit.clone(),
            toc_z: layer.toc_z.clone(),
            lazy: false,
            blob_checked: false,
            checked: Default::default(),
        };
        // (its files are written with the others, before the barrier that
        // makes them durable: the row that names the layer comes after it)
        let (linked, held) = self
            .link_verified(all, verified, vec![done.clone()], (store, one))
            .await?;
        // (a file the link refused, or that went meanwhile, is not fetched
        // here: the layer stays staged)
        let one: Arc<[LazyLayer]> = vec![layer.clone()].into();
        self.require_covered(&one).await?;
        let checked: std::collections::HashSet<String> = linked
            .iter()
            .filter(|o| o.checked)
            .map(|o| o.verity.clone())
            .collect();
        done.checked = checked;
        let mut commit = layer_commit(&done, layer.meta.registry_ref.as_deref())?;
        (commit.record.blob, commit.record.size) = (layer.meta.blob.parse().ok(), layer.meta.size);
        (commit.record.erofs, commit.record.owners) = (
            Some(layer.meta.erofs.clone()),
            Some(layer.meta.owners.clone()),
        );
        self.db.commit_layers(vec![commit], Vec::new()).await?;
        debug!("Layer {} committed to the store", layer.key);
        drop(held);
        Ok(())
    }

    /// Remove the staged layer: it is in the store now, which the pulls that
    /// name it find it in.  Under its lease, once the fetches into its
    /// staging end (of this process too: another completion may still
    /// fetch a file the store had from another layer); called with no lock
    /// of the commit held, which a holder of the lease may wait for.
    pub(super) async fn release_layer(&self, key: &LayerKey) {
        let (area, k) = (self.staging_area(), *key);
        let removed = tokio::task::spawn_blocking(move || area.remove_layer(&k)).await;
        self.forget_lazy(key).await;
        match removed {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("Cannot remove the staged layer {key}: {e}"),
            Err(e) => warn!("Cannot remove the staged layer {key}: {e}"),
        }
    }

    /// The image of the pull `read` (as it was read), once every layer of
    /// it is in the store: its record, names, signatures and the right to
    /// announce it, in one transaction, then the pull removed.  The names
    /// are the pull's as it is at the commit, read and removed under the
    /// lock a pull that joins it takes: none of a pull that joined meanwhile
    /// is lost.  A sealed manifest's merged EROFS is checked before.  No
    /// `keys`: the image is in the store already, the pull adds its names.
    async fn commit_image(
        &self,
        read: &StagedPull,
        manifest: &OciManifest,
        keys: Option<&[LayerKey]>,
    ) -> ImageResult<()> {
        let area = self.staging_area();
        let store = self.lock_store().await?;
        let layers = keys.unwrap_or_default();
        if keys.is_none() {
            // (still there: it was looked for before the lock)
            self.db.get_image_by_digest(&read.manifest_digest).await?;
        } else if self.storage.holds_objects() && !super::seal::expected(manifest)?.is_empty() {
            let tocs = velarx_content::pull::stored::stored_tocs(&self.db, layers).await?;
            let (store, want) = (self.file_store.clone(), manifest.clone());
            let alg = read.manifest_digest.alg();
            let algs: Vec<Algorithm> = layers.iter().map(|k| k.digest().alg()).collect();
            tokio::task::spawn_blocking(move || {
                let tocs: Vec<&Toc> = tocs.iter().collect();
                super::seal::merged_erofs(alg, &algs, &tocs, &|d| store.get_path(d), Some(&want))
                    .map(|_| ())
            })
            .await
            .map_err(|e| ImageError::Storage(e.to_string()))??;
        }
        let names = match area.lock_names(&read.id) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            other => other?,
        };
        let Some(pull) = area.pull(&read.id)? else {
            return Ok(());
        };
        let image = pull.image_record();
        let image = ImageRecord {
            created_at: chrono::Utc::now().to_rfc3339(),
            is_lazy: false,
            ..image
        };
        let tags: Vec<ImageTag> = pull
            .tags
            .iter()
            .map(|t| ImageTag {
                repository: t.repository.clone(),
                tag: t.tag.clone(),
                image_id: pull.id.clone(),
            })
            .collect();
        let digest_names = pull
            .digest_names
            .iter()
            .filter_map(|(r, d)| Some((r.clone(), d.parse().ok()?)))
            .collect();
        self.db
            .commit_staged_image(velarx_db::StagedImageCommit {
                pull: velarx_db::PullCommit {
                    layers: Vec::new(),
                    image,
                    image_layers: layers.to_vec(),
                    tags,
                    digest_names,
                    sources: super::pull::blob_sources(manifest, pull.registry_ref.as_deref()),
                    pulled: pull
                        .pulls
                        .iter()
                        .map(|p| (p.reference.clone(), p.signatures.clone()))
                        .collect(),
                },
                started_at: pull.started_at.clone(),
            })
            .await?;
        area.remove_pull(&pull.id)?;
        drop(names);
        drop(store);
        self.forget_pull(&pull).await;
        Ok(())
    }

    /// The pull is in the store: what the staging area kept of it goes (its
    /// startup profile is next to the records of the store from the start).
    async fn forget_pull(&self, pull: &StagedPull) {
        self.discard_pull(pull).await;
    }

    /// The files of the layers are in the store, or nothing more is done:
    /// no fetch is made behind the link, and the proof finds every file
    /// under its name in the store (after it).  It relies on the plan having
    /// refused a regular file without a digest: `files` has every file.
    async fn require_covered(&self, layers: &Arc<[LazyLayer]>) -> ImageResult<()> {
        let (store, l) = (self.file_store.clone(), layers.clone());
        let lacking = tokio::task::spawn_blocking(move || {
            // (a content is asked once, in the first layer that has it)
            let mut seen = std::collections::HashSet::new();
            for layer in l.iter() {
                let lacking: Vec<String> = layer
                    .toc
                    .files()
                    .into_iter()
                    .filter(|d| seen.insert(d.clone()) && !store.contains(d))
                    .collect();
                if let Some(first) = lacking.first() {
                    return Some((layer.key, lacking.len(), first.clone()));
                }
            }
            None
        })
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))?;
        if let Some((digest, n, file)) = lacking {
            return Err(ImageError::Storage(format!(
                "{n} files of layer {digest} are not in the store after the link \
                 ({file} is the first; a staged file is not what its name says, \
                 or went meanwhile): the layer stays staged"
            )));
        }
        Ok(())
    }

    /// The staging directories of the layers `layers`, as stores of the
    /// files staged in them.
    fn staged_files(&self, layers: &[LazyLayer]) -> ImageResult<Vec<Arc<FileStore>>> {
        let area = self.staging_area();
        layers
            .iter()
            .map(|l| {
                FileStore::new(area.layer_files(&l.key))
                    .map(Arc::new)
                    .map_err(|e| ImageError::Storage(e.to_string()))
            })
            .collect()
    }

    /// Give the staged files `digests` their names in the store, from the
    /// staging directories of `layers` (a content is staged once, in the
    /// first layer that has it), after the staging is written to the disk
    /// when `[storage] sync` says (the files are complete and sealed: one
    /// `syncfs`), each by a link of the same inode.  Returns the objects the
    /// kernel measured.  With `image`, the layer's staged EROFS image is
    /// renamed into the store in the same commit (the same bytes: the
    /// containers that run on the staged one keep their mounts), after it
    /// was checked against the digest the layer records.
    async fn link_files(
        &self,
        layers: &[LazyLayer],
        digests: Vec<String>,
        images: Vec<&LazyLayer>,
    ) -> ImageResult<Vec<velarx_storage::Object>> {
        let verified = self.verify_files(layers, digests, images).await?;
        let (objects, ()) = self.link_verified(layers, verified, Vec::new(), ()).await?;
        Ok(objects)
    }

    /// The staging phase of [`LazyEngine::link_files`]: every staged file
    /// and image is verified (once), with no lock held; the locked part
    /// ([`LazyEngine::link_verified`]) only links, renames and syncs.
    async fn verify_files(
        &self,
        layers: &[LazyLayer],
        digests: Vec<String>,
        images: Vec<&LazyLayer>,
    ) -> ImageResult<StagedFiles> {
        let store = self.file_store.clone();
        let fsverity = self.fsverity;
        let area = self.staging_area();
        let dirs: Vec<PathBuf> = layers.iter().map(|l| area.layer_files(&l.key)).collect();
        let objects = area.objects_stand_in();
        let wanted = wanted_by_staging(layers, digests);
        let images: Vec<StagedImageOf> = images
            .into_iter()
            .filter_map(|l| {
                let at = layers.iter().position(|o| o.key == l.key)?;
                Some((
                    at,
                    l.key.file_stem(),
                    l.key.digest().alg(),
                    l.meta.erofs.clone(),
                ))
            })
            .collect();
        tokio::task::spawn_blocking(move || {
            let verified = verify_staged(&dirs, &wanted, &store, fsverity, &images, &objects)?;
            Ok::<_, ImageError>(StagedFiles {
                dirs,
                wanted,
                images,
                objects,
                verified,
            })
        })
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))?
    }

    /// The locked part of [`LazyEngine::link_files`]: the locks `held` (of
    /// the commit) are those of the thread that links, they are let go when
    /// it ends whatever becomes of the caller, and given back with the
    /// result.
    async fn link_verified<H: Send + 'static>(
        &self,
        layers: &[LazyLayer],
        staged: StagedFiles,
        keep: Vec<LayerDone>,
        held: H,
    ) -> ImageResult<(Vec<velarx_storage::Object>, H)> {
        let store = self.file_store.clone();
        let (placed, held) = blocking_holding(held, move || {
            let StagedFiles {
                dirs,
                wanted,
                images,
                objects,
                verified,
            } = staged;
            place_staged(verified, &dirs, &wanted, &store, &images, &objects, &keep)
        })
        .await?;
        let (done, steps, refused) = placed?;
        // (a file that is gone, has wrong bytes or lacks the seal the store
        // asks for fails the completion, naming the fetcher that staged it)
        // (a file whose name is gone because another completion committed it
        // is in the store, and is no failure)
        let refused: Vec<Refused> = refused
            .into_iter()
            .filter(|r| !(r.why == GONE && self.file_store.contains(&r.key)))
            .collect();
        if let Some(Refused { at, key, why }) = refused.first() {
            let layer = &layers[*at].key;
            let by = self.lazy_fetcher_of(layer, key).await;
            return Err(ImageError::Contradicted(format!(
                "the file {key} of layer {layer}{}: {why}",
                by.map(|f| format!(", staged by the fetcher {f}"))
                    .unwrap_or_default()
            )));
        }
        for step in steps {
            match step {
                ImageStep::Moved => {}
                ImageStep::Wrong => {
                    return Err(ImageError::Contradicted(
                        "the staged EROFS image of the layer is not the one the pull recorded"
                            .into(),
                    ))
                }
                ImageStep::Missing => {
                    return Err(ImageError::Storage(
                        "the staged EROFS image of the layer is gone".into(),
                    ))
                }
            }
        }
        Ok((done, held))
    }

    /// Exclusive for the commit of one layer, across processes: held until
    /// the guard is dropped.
    async fn commit_layer_lock(&self, key: &LayerKey) -> ImageResult<velarx_sys::flock::Held> {
        let path = self
            .file_store
            .root()
            .with_file_name("locks")
            .join(format!("commit-layer-{}", key.file_stem()));
        tokio::task::spawn_blocking(move || {
            velarx_storage::locks::lock(&path, true)
                .map(|f| f.expect("a wait gives the lock or an error"))
        })
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))?
        .map_err(ImageError::Io)
    }
}

/// `work` on a blocking thread, which keeps `held` until it ends: a caller
/// that is dropped meanwhile (a cancel) does not let go of what `work`
/// needs held.  `held` is given back with the result.
async fn blocking_holding<H: Send + 'static, R: Send + 'static>(
    held: H,
    work: impl FnOnce() -> R + Send + 'static,
) -> ImageResult<(R, H)> {
    tokio::task::spawn_blocking(move || (work(), held))
        .await
        .map_err(|e| ImageError::Storage(e.to_string()))
}

/// The files `digests` split by the staging that holds each: a content is
/// staged once, in the first layer of `layers` that has it, and is asked of
/// that staging only (not of every one: no `openat2` of a file in a staging
/// that cannot have it, and no name removed from a staging of another layer).
fn wanted_by_staging(layers: &[LazyLayer], digests: Vec<String>) -> Vec<Vec<String>> {
    let owners: Vec<std::collections::HashSet<String>> = layers
        .iter()
        .map(|l| l.toc.files().into_iter().collect())
        .collect();
    let mut wanted: Vec<Vec<String>> = vec![Vec::new(); layers.len()];
    for digest in digests {
        if let Some(at) = owners.iter().position(|o| o.contains(&digest)) {
            wanted[at].push(digest);
        }
    }
    wanted
}

impl LazyFileFetcher for ImageService {
    fn fetch_file_blocking(
        &self,
        file_digest: &str,
        layer_digest: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<PathBuf, String> {
        // The caller is a FUSE thread: the work runs on the runtime of the
        // service and the thread waits for it.
        let (tx, rx) = std::sync::mpsc::channel();
        let this = self.clone();
        let (file_digest, layer_digest) = (file_digest.to_string(), layer_digest.to_string());
        let runtime = self
            .fuse_runtime
            .get()
            .map_err(|e| format!("cannot start the runtime of the fetches: {e}"))?;
        let task = runtime.spawn(async move {
            let result = match LayerKey::parse(&layer_digest) {
                Some(layer) => this
                    .fetch_lazy_file(&file_digest, &layer)
                    .await
                    .map_err(|e| e.to_string()),
                None => Err(format!("{layer_digest:?} is no layer")),
            };
            let _ = tx.send(result);
        });
        let received = match timeout {
            Some(timeout) => rx.recv_timeout(timeout),
            None => rx
                .recv()
                .map_err(|_| std::sync::mpsc::RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                task.abort();
                Err(format!(
                    "Fetch timed out after {:?}",
                    timeout.unwrap_or_default()
                ))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err("Fetch task was cancelled".to_string())
            }
        }
    }
}

/// Move the files of `files` (`ab/cdef...` by their fs-verity digest) into
/// the store, each one after its content was checked against its name; the
/// objects they are returned as are to be recorded.
///
/// A staged file that has fs-verity (the fetch enabled it, so nothing can
/// open it for writing any more) is checked through the descriptor it was
/// opened with, and that very inode gets the name of its object in the store
/// (the fs-verity digest the kernel measures), never over an object that is
/// there unless that one does not have the digest it is named by; its name in
/// the staging goes after.  Any other file (no fs-verity, or another file
/// system) is copied under no name, its fs-verity digest computed as it is
/// copied, and the copy is linked after the barrier; its name in the staging
/// goes too.
#[cfg(test)]
fn link_staged(
    files: &std::path::Path,
    store: &velarx_storage::FileStore,
    fsverity: velarx_storage::VerityMode,
) -> ImageResult<Vec<velarx_storage::Object>> {
    use velarx_storage::Object;
    let mut digests = Vec::new();
    if let Ok(prefixes) = std::fs::read_dir(files) {
        for prefix in prefixes.flatten() {
            let Ok(entries) = std::fs::read_dir(prefix.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let rel = format!(
                    "{}/{}",
                    prefix.file_name().to_string_lossy(),
                    entry.file_name().to_string_lossy()
                );
                if let Some(named) = Object::from_rel(std::path::Path::new(&rel)) {
                    digests.push(named.verity);
                }
            }
        }
    }
    Ok(commit_staged(
        &[files.to_path_buf()],
        &[digests],
        store,
        fsverity,
        &[],
        Path::new(""),
    )?
    .0)
}

/// The files of some staging directories, verified, waiting for their names.
struct StagedFiles {
    dirs: Vec<PathBuf>,
    wanted: Vec<Vec<String>>,
    images: Vec<StagedImageOf>,
    objects: PathBuf,
    verified: velarx_content::pull::commit::Verified,
}

/// The image of a layer given to [`commit_staged`]: the index of its staging
/// in the call, its name, its algorithm, its recorded digest.
type StagedImageOf = (usize, String, velarx_types::digest::Algorithm, String);

/// The commit of the files `wanted` (fs-verity digests; the files of
/// `dirs[i]` are `wanted[i]`: a content is staged once, in the first layer
/// that has it, and is asked of that staging only): checked and linked by
/// `velarx_content::pull::commit::commit_layer`, the one routine that gives a
/// staged file its name in the store.  The objects in the store are returned;
/// one that is not there is the caller's to find.
#[cfg(test)]
fn commit_staged(
    dirs: &[PathBuf],
    wanted: &[Vec<String>],
    store: &velarx_storage::FileStore,
    fsverity: velarx_storage::VerityMode,
    images: &[StagedImageOf],
    objects: &Path,
) -> ImageResult<Placed> {
    let verified = verify_staged(dirs, wanted, store, fsverity, images, objects)?;
    place_staged(verified, dirs, wanted, store, images, objects, &[])
}

/// The staging phase of [`commit_staged`]: every file is checked and
/// verified, once, and the staged images against what the layers recorded.
/// No lock is needed, and none is held by the caller: the reads and hashes
/// of a commit are all here.
fn verify_staged(
    dirs: &[PathBuf],
    wanted: &[Vec<String>],
    store: &velarx_storage::FileStore,
    fsverity: velarx_storage::VerityMode,
    images: &[StagedImageOf],
    objects: &Path,
) -> ImageResult<velarx_content::pull::commit::Verified> {
    let stagings = stagings_of(dirs, wanted, images, objects);
    velarx_content::pull::commit::verify_layers(&stagings, store, fsverity.manager().as_ref())
        .map_err(|e| ImageError::Storage(e.to_string()))
}

/// The staging directories of a commit.
fn stagings_of<'a>(
    dirs: &'a [PathBuf],
    wanted: &[Vec<String>],
    images: &'a [StagedImageOf],
    objects: &'a Path,
) -> Vec<velarx_content::pull::commit::Staging<'a>> {
    use velarx_content::pull::commit::{StagedImage, Staging, Want};
    dirs.iter()
        .enumerate()
        .map(|(i, dir)| Staging {
            dir,
            wants: wanted[i]
                .iter()
                .filter_map(|d| velarx_types::digest::Digest::parse_fsverity(d).ok())
                .map(|digest| Want::by_verity(&digest, None))
                .collect(),
            image: images
                .iter()
                .find(|(at, ..)| *at == i)
                .map(|(_, stem, alg, recorded)| StagedImage {
                    objects,
                    stem,
                    alg: *alg,
                    recorded,
                }),
        })
        .collect()
}

/// What [`place_staged`] did: the objects in the store, the steps of the
/// images, the files it refused, and the files the store had already.
type Placed = (Vec<velarx_storage::Object>, Vec<ImageStep>, Vec<Refused>);

/// The locked phase of [`commit_staged`]: the names, and nothing that reads,
/// hashes or copies.
fn place_staged(
    verified: velarx_content::pull::commit::Verified,
    dirs: &[PathBuf],
    wanted: &[Vec<String>],
    store: &velarx_storage::FileStore,
    images: &[StagedImageOf],
    objects: &Path,
    keep: &[LayerDone],
) -> ImageResult<Placed> {
    use velarx_content::pull::commit::{commit_verified, Refusal};
    let stagings = stagings_of(dirs, wanted, images, objects);
    // (the files of the layers are written between the links and the barrier
    // of the store, as the images are)
    let mut write = |_: &[velarx_content::pull::commit::Linked]| {
        for done in keep {
            done.write_files(velarx_db::layer_files::root_of(store.root()))?;
        }
        Ok(!keep.is_empty())
    };
    let linked = commit_verified(&stagings, verified, store, Some(&mut write))
        .map_err(|e| ImageError::Storage(e.to_string()))?;
    let steps = linked.iter().filter_map(|l| l.image.clone()).collect();
    // (the files of fetchers the commit refused)
    let refused = linked
        .iter()
        .enumerate()
        .flat_map(|(at, l)| {
            let wants = &stagings[at].wants;
            l.refused.iter().map(move |(i, why)| Refused {
                at,
                key: wants[*i].key.clone(),
                why: match why {
                    Refusal::Missing => GONE.to_string(),
                    Refusal::Wrong(why) => why.clone(),
                },
            })
        })
        .collect();
    let mut seen = std::collections::HashSet::new();
    Ok((
        linked
            .into_iter()
            .flat_map(|l| l.objects)
            .map(|(_, o)| o)
            .filter(|o| seen.insert(o.verity.clone()))
            .collect(),
        steps,
        refused,
    ))
}

/// Why the commit refused a file whose staged name is not there.
const GONE: &str = "it is gone";

/// A file a fetcher staged that the commit refused: the place of its layer
/// among the staging directories, its key, and why.
struct Refused {
    at: usize,
    key: String,
    why: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use velarx_content::fetcher::fetch::Urgency;

    /// The locks of a commit are let go when the thread that links ends, not
    /// when the task that waits for it is dropped.
    #[tokio::test]
    async fn the_locks_of_a_commit_outlive_a_cancelled_task() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("commit-layer");
        let held = velarx_storage::locks::lock(&path, true).unwrap().unwrap();
        let (started_tx, started) = std::sync::mpsc::channel();
        let (end_tx, end) = std::sync::mpsc::channel::<()>();
        let task = tokio::spawn(blocking_holding(held, move || {
            started_tx.send(()).unwrap();
            end.recv().unwrap();
        }));
        tokio::task::spawn_blocking(move || started.recv().unwrap())
            .await
            .unwrap();
        task.abort();
        let _ = task.await;
        assert!(velarx_storage::locks::lock(&path, false).unwrap().is_none());
        end_tx.send(()).unwrap();
        let free = tokio::task::spawn_blocking(move || velarx_storage::locks::lock(&path, true))
            .await
            .unwrap();
        assert!(free.unwrap().is_some());
    }

    use velarx_storage::{FileStore, VerityMode};

    fn layer_of(files: &[(&str, &[u8])]) -> LazyLayer {
        let entries: Vec<serde_json::Value> = files
            .iter()
            .map(|(name, data)| {
                serde_json::json!({
                    "name": name,
                    "type": "reg",
                    "size": data.len(),
                    "fsverity": velarx_storage::toc_value(&velarx_storage::to_toc(&velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, data)).unwrap()),
                    "offset": 10,
                    "endOffset": 30,
                })
            })
            .collect();
        let toc: Toc =
            serde_json::from_value(serde_json::json!({"version": 1, "entries": entries})).unwrap();
        LazyLayer {
            key: LayerKey::Toc(format!("sha256:{}", "2".repeat(64)).parse().unwrap()),
            desc: OciDescriptor {
                media_type: String::new(),
                digest: format!("sha256:{}", "1".repeat(64)).parse().unwrap(),
                size: 0,
                annotations: Default::default(),
            },
            diff_id: Digest::empty(Algorithm::Sha256),
            toc: Arc::new(toc),
            tarsplit: bytes::Bytes::new(),
            meta: velarx_content::pull::staged::StagedLayerMeta {
                key: String::new(),
                blob: String::new(),
                size: 0,
                registry_ref: None,
                reach: Default::default(),
                erofs: String::new(),
                owners: String::new(),
                created_at: String::new(),
            },
            toc_z: bytes::Bytes::new(),
        }
    }

    /// A file two layers have is asked of the staging of the first, and the
    /// files only the second has of the second's.
    #[test]
    fn a_file_is_wanted_from_the_staging_of_the_first_layer_that_has_it() {
        let a = layer_of(&[("a", b"one"), ("shared", b"both")]);
        let mut b = layer_of(&[("shared", b"both"), ("c", b"three")]);
        b.key = LayerKey::Toc(format!("sha256:{}", "3".repeat(64)).parse().unwrap());
        let layers = [a, b];
        let id = |d: &[u8]| velarx_storage::fsverity_digest_of(Algorithm::Sha256, d);
        let mut seen = std::collections::HashSet::new();
        let all: Vec<String> = layers
            .iter()
            .flat_map(|l| l.toc.files())
            .filter(|d| seen.insert(d.clone()))
            .collect();
        let wanted = wanted_by_staging(&layers, all);
        let at =
            |i: usize| -> std::collections::HashSet<String> { wanted[i].iter().cloned().collect() };
        assert_eq!(
            at(0),
            [id(b"one"), id(b"both")].into_iter().collect(),
            "{wanted:?}"
        );
        assert_eq!(at(1), [id(b"three")].into_iter().collect());
        assert_eq!(wanted[0].len() + wanted[1].len(), 3);
    }

    fn stores() -> (tempfile::TempDir, Arc<FileStore>) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        (tmp, store)
    }

    /// A service with a staging area and an empty store.
    async fn planner() -> (tempfile::TempDir, ImageService, Arc<FileStore>) {
        let (tmp, store) = stores();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let service =
            ImageService::new(db, store.clone(), tmp.path().join("pulls"), VerityMode::Off)
                .unwrap();
        service.staging_area().create().unwrap();
        (tmp, service, store)
    }

    /// What the store and the staging have is not planned, and is counted
    /// once for each content with the bytes its first entry takes in the blob.
    #[tokio::test]
    async fn the_plan_leaves_out_what_the_store_or_the_staging_has() {
        let (_tmp, service, store) = planner().await;
        let layer = layer_of(&[
            ("a", b"in the store"),
            ("b", b"in the staging"),
            ("c", b"nowhere"),
            ("d", b"nowhere either"),
            ("e", b"in the store"),
        ]);
        let staging = FileStore::new(service.staging_area().layer_files(&layer.key)).unwrap();
        store.put(Algorithm::Sha256, b"in the store").unwrap();
        staging.put(Algorithm::Sha256, b"in the staging").unwrap();
        let layers: Arc<[LazyLayer]> = vec![layer].into();
        let (groups, reused) = service.plan_groups(&layers, Vec::new()).await.unwrap();
        let want = |d: &[u8]| velarx_storage::fsverity_digest_of(Algorithm::Sha256, d);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].files, [want(b"nowhere"), want(b"nowhere either")]);
        assert_eq!(groups[0].bytes, 7 + 14);
        assert_eq!(groups[0].needed_by, [0]);
        assert_eq!(reused, (40, 2));
    }

    /// A content two layers have is planned once, into the first, and the
    /// second waits for it; the profile names it, and what is no file.
    #[tokio::test]
    async fn a_content_is_planned_once_for_all_the_layers() {
        let (_tmp, service, _) = planner().await;
        let mut second = layer_of(&[("a", b"shared"), ("b", b"own")]);
        second.key = LayerKey::Toc(format!("sha256:{}", "3".repeat(64)).parse().unwrap());
        let layers: Arc<[LazyLayer]> = vec![layer_of(&[("a", b"shared")]), second].into();
        let want = |d: &[u8]| velarx_storage::fsverity_digest_of(Algorithm::Sha256, d);
        let profile = vec![want(b"own"), "../../x".to_string(), want(b"shared")];
        let (groups, _) = service.plan_groups(&layers, profile).await.unwrap();
        let got: Vec<_> = groups
            .iter()
            .map(|g| (g.layer, g.files.clone(), g.needed_by.clone()))
            .collect();
        assert_eq!(
            got,
            [
                (1, vec![want(b"own")], vec![1]),
                (0, vec![want(b"shared")], vec![0, 1])
            ]
        );
    }

    /// A regular file with no fs-verity digest in the table is an error of the
    /// plan, not a file left out.
    #[tokio::test]
    async fn a_file_without_a_digest_is_an_error_of_the_plan() {
        let (_tmp, service, _) = planner().await;
        let mut layer = layer_of(&[]);
        layer.toc = Arc::new(
            serde_json::from_value(serde_json::json!({"version": 1, "entries": [
                {"name": "f", "type": "reg", "size": 3}
            ]}))
            .unwrap(),
        );
        let layers: Arc<[LazyLayer]> = vec![layer].into();
        let err = service
            .plan_groups(&layers, Vec::new())
            .await
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("`f` has no fs-verity digest"),
            "{err}"
        );
    }

    /// The store does not have every file after the link: nothing is
    /// fetched to make up for it.
    #[tokio::test]
    async fn files_that_remain_uncovered_are_an_error() {
        let (tmp, store) = stores();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let service =
            ImageService::new(db, store.clone(), tmp.path().join("pulls"), VerityMode::Off)
                .unwrap();
        let layers: Arc<[LazyLayer]> =
            vec![layer_of(&[("a", b"in the staging"), ("b", b"nowhere")])].into();
        store
            .put(velarx_types::digest::Algorithm::Sha256, b"nowhere")
            .unwrap();
        let err = service.require_covered(&layers).await.unwrap_err();
        assert!(err.to_string().contains("after the link"), "{err}");
        store
            .put(velarx_types::digest::Algorithm::Sha256, b"in the staging")
            .unwrap();
        service.require_covered(&layers).await.unwrap();
    }

    /// A directory of a file system with fs-verity (VELARX_VERITY_DIR).
    fn verity_dir() -> Option<tempfile::TempDir> {
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return None;
        };
        Some(tempfile::tempdir_in(dir).unwrap())
    }

    fn objects_store(dir: std::path::PathBuf) -> FileStore {
        FileStore::new(dir).unwrap()
    }

    fn with_verity(path: &std::path::Path) {
        velarx_storage::FsVerityManager::with_config(velarx_storage::FsVerityConfig {
            required: true,
            ..Default::default()
        })
        .enable(path)
        .unwrap();
    }

    fn written(path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .write_all(b"evil")
    }

    #[test]
    fn staged_files_are_copied_when_they_have_no_verity() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let good = staging
            .put(velarx_types::digest::Algorithm::Sha256, b"a staged file")
            .unwrap();
        let known = staging
            .put(
                velarx_types::digest::Algorithm::Sha256,
                b"a file the store has",
            )
            .unwrap();
        store
            .put(
                velarx_types::digest::Algorithm::Sha256,
                b"a file the store has",
            )
            .unwrap();
        // a file that is not what its name says
        let bad = format!("fsverity-sha256-12:{}", "ab".repeat(32));
        let bad_path = staging.local_path(&bad).unwrap();
        std::fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
        std::fs::write(&bad_path, b"not that").unwrap();

        link_staged(&tmp.path().join("staging/files"), &store, VerityMode::Off).unwrap();
        let copy = store
            .get_path(&good)
            .expect("the staged file is in the store");
        assert_eq!(std::fs::read(&copy).unwrap(), b"a staged file");
        // a copy of its own (its pool name goes with the link: the file is
        // the store's)
        assert!(staging.get_path(&good).is_none());
        assert!(store.get_path(&bad).is_none(), "an unchecked file went in");
        // the store's own file is not replaced
        assert!(staging.get_path(&known).is_none());
        assert_eq!(
            std::fs::read(store.get_path(&known).unwrap()).unwrap(),
            b"a file the store has"
        );
        // again: nothing to do
        link_staged(&tmp.path().join("staging/files"), &store, VerityMode::Off).unwrap();
    }

    /// Where fs-verity is required a file without it takes no name in the
    /// store: a file system that cannot have it is an error, and the file
    /// stays in the pool.
    #[test]
    fn a_required_fs_verity_that_cannot_be_enabled_gives_no_name() {
        let tmp = tempfile::tempdir_in("/dev/shm").unwrap();
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let digest = staging
            .put(velarx_types::digest::Algorithm::Sha256, b"a staged file")
            .unwrap();
        let err = link_staged(
            &tmp.path().join("staging/files"),
            &store,
            VerityMode::Require,
        )
        .unwrap_err();
        assert!(err.to_string().contains("fs-verity is required"), "{err}");
        assert!(!store.contains_local(&digest));
        assert!(staging.get_path(&digest).is_some());
        // without the requirement the file takes its name
        link_staged(&tmp.path().join("staging/files"), &store, VerityMode::On).unwrap();
        assert!(store.contains_local(&digest));
    }

    #[test]
    fn a_committed_file_cannot_be_written_from_the_staging() {
        let Some(tmp) = verity_dir() else { return };
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let digest = staging
            .put(velarx_types::digest::Algorithm::Sha256, b"a staged file")
            .unwrap();
        let staged = staging.get_path(&digest).unwrap();
        with_verity(&staged);
        let reader = std::fs::File::open(&staged).unwrap();
        let ino = std::fs::metadata(&staged).unwrap().ino();

        let objects =
            link_staged(&tmp.path().join("staging/files"), &store, VerityMode::On).unwrap();
        let committed = store.get_path(&digest).unwrap();
        assert_eq!(std::fs::metadata(&committed).unwrap().ino(), ino);
        assert!(staging.get_path(&digest).is_none(), "the staging keeps it");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].verity, digest);
        // the kernel measures the digest it is named by
        assert!(objects[0].checked);
        assert_eq!(committed, store.object_path(&objects[0]));
        // the new name, and the descriptor from before (by /proc)
        let by_fd = velarx_sys::fd::proc_path(&reader);
        for path in [&by_fd, &committed] {
            let e = written(path).unwrap_err();
            assert!(
                matches!(
                    e.raw_os_error(),
                    Some(libc::EPERM | libc::EACCES | libc::ETXTBSY)
                ),
                "{path:?}: {e}"
            );
        }
        let mut ro = &reader;
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut ro, &mut content).unwrap();
        assert_eq!(content, b"a staged file");
        assert!(std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&committed)
            .is_err());
    }

    /// A staged file without fs-verity is copied, and the copy gets it:
    /// its object is the one the kernel measures, read-only.
    #[test]
    fn a_copy_gets_fs_verity() {
        let Some(tmp) = verity_dir() else { return };
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let digest = staging
            .put(
                velarx_types::digest::Algorithm::Sha256,
                b"a staged file without fs-verity",
            )
            .unwrap();
        let objects =
            link_staged(&tmp.path().join("staging/files"), &store, VerityMode::On).unwrap();
        assert_eq!(objects.len(), 1);
        assert!(objects[0].checked, "the copy has no fs-verity");
        let committed = store.get_path(&digest).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&committed).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o444);
    }

    /// A file with another name than the staging's is not what a fetcher
    /// was asked to stage: it is refused, and the store takes none of it.
    #[test]
    fn a_staged_file_with_another_name_is_refused() {
        let Some(tmp) = verity_dir() else { return };
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let digest = staging
            .put(
                velarx_types::digest::Algorithm::Sha256,
                b"a staged file with two names",
            )
            .unwrap();
        let staged = staging.get_path(&digest).unwrap();
        with_verity(&staged);
        let other = tmp.path().join("workers-name");
        std::fs::hard_link(&staged, &other).unwrap();
        let objects =
            link_staged(&tmp.path().join("staging/files"), &store, VerityMode::On).unwrap();
        assert!(objects.is_empty());
        assert!(store.get_path(&digest).is_none());
        assert_eq!(
            std::fs::read(&other).unwrap(),
            b"a staged file with two names"
        );
    }

    #[test]
    fn a_file_the_store_has_is_kept_and_the_staged_one_goes() {
        let Some(tmp) = verity_dir() else { return };
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let digest = staging
            .put(velarx_types::digest::Algorithm::Sha256, b"the same content")
            .unwrap();
        with_verity(&staging.get_path(&digest).unwrap());
        store
            .put(velarx_types::digest::Algorithm::Sha256, b"the same content")
            .unwrap();
        let before = std::fs::metadata(store.get_path(&digest).unwrap())
            .unwrap()
            .ino();
        assert_ne!(
            before,
            std::fs::metadata(staging.get_path(&digest).unwrap())
                .unwrap()
                .ino()
        );
        link_staged(&tmp.path().join("staging/files"), &store, VerityMode::On).unwrap();
        assert_eq!(
            std::fs::metadata(store.get_path(&digest).unwrap())
                .unwrap()
                .ino(),
            before
        );
        assert!(staging.get_path(&digest).is_none());
    }

    #[test]
    fn commits_of_the_same_files_in_parallel() {
        for verity in [false, true] {
            let tmp = if verity {
                let Some(tmp) = verity_dir() else { continue };
                tmp
            } else {
                tempfile::tempdir().unwrap()
            };
            let mode = if verity {
                VerityMode::On
            } else {
                VerityMode::Off
            };
            let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
            let store = objects_store(tmp.path().join("store/objects"));
            let mut contents = Vec::new();
            for i in 0..40 {
                let data = format!("file number {i}").repeat(i * 50 + 1);
                let digest = staging
                    .put(velarx_types::digest::Algorithm::Sha256, data.as_bytes())
                    .unwrap();
                if verity {
                    with_verity(&staging.get_path(&digest).unwrap());
                }
                contents.push((digest, data));
            }
            let files = tmp.path().join("staging/files");
            std::thread::scope(|s| {
                for _ in 0..8 {
                    s.spawn(|| {
                        link_staged(&files, &store, mode).unwrap();
                    });
                }
            });
            for (digest, data) in &contents {
                let path = store.get_path(digest).expect("committed");
                assert_eq!(std::fs::read(&path).unwrap(), data.as_bytes());
            }
            let leftovers = std::fs::read_dir(tmp.path().join("store/objects"))
                .unwrap()
                .flatten()
                .flat_map(|d| {
                    if d.path().is_dir() {
                        std::fs::read_dir(d.path()).unwrap().flatten().collect()
                    } else {
                        vec![d]
                    }
                })
                .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
                .count();
            assert_eq!(leftovers, 0, "temporary files are left");
        }
    }

    /// The completion of a lazy layer whose fetcher staged other bytes, or
    /// took the file away after it said `staged`: the transfer was complete
    /// and the file is not valid, so the completion fails naming the fetcher
    /// and the file, the next fetcher is not asked, and nothing is named in
    /// the store.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lazy_file_that_is_not_valid_fails_the_completion_naming_the_fetcher() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use velarx_content::fakes::{Fake, Stages};
        use velarx_content::fetcher::fetch_client::FetchConn;
        use velarx_content::pull::staged_fetch::{Link, StagedFetch};
        use velarx_content::serve_fetch::LocalFetcher;
        for removes in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let db = velarx_db::Database::open_in_memory().await.unwrap();
            let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
            let service =
                ImageService::new(db, store.clone(), tmp.path().join("pulls"), VerityMode::Off)
                    .unwrap();
            let area = service.staging_area();
            area.create().unwrap();
            let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"blob"));
            std::fs::create_dir_all(area.layer_dir(&key)).unwrap();
            std::fs::write(area.layer_dir(&key).join("layer.json"), b"{}").unwrap();
            let body = b"the file".to_vec();
            let file = velarx_storage::fsverity_digest_of(Algorithm::Sha256, &body);
            let file = Digest::parse_key(&file).unwrap().to_string();
            let toc: Toc = serde_json::from_value(serde_json::json!({
                "version": 1,
                "entries": [{
                    "name": "f", "type": "reg", "size": body.len(),
                    "fsverity": velarx_storage::toc_value(&velarx_storage::to_toc(
                        &velarx_storage::fsverity_digest_of(Algorithm::Sha256, &body)
                    ).unwrap()),
                }],
            }))
            .unwrap();
            let desc: OciDescriptor = serde_json::from_value(serde_json::json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
                "digest": Digest::of(Algorithm::Sha256, b"blob").to_string(),
                "size": 1,
            }))
            .unwrap();
            let (first_asked, end_asked) =
                (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            let first_how = if removes {
                Stages::Right
            } else {
                Stages::Wrong
            };
            let local = |how, asked: &Arc<AtomicUsize>| {
                LocalFetcher::start(
                    Arc::new(Fake::new(how, &file, &body, asked.clone())),
                    velarx_content::activation::Limits::default(),
                )
                .unwrap()
            };
            let (first, end) = (
                local(first_how, &first_asked),
                local(Stages::Right, &end_asked),
            );
            let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":2},"layers":[]}"#;
            let walker = StagedFetch::open(
                (
                    vec![Link {
                        name: "first".into(),
                        conn: FetchConn::new(first.connect().unwrap()).unwrap(),
                        idle: velarx_content::pull::staged_fetch::REGISTRY_IDLE,
                    }],
                    Some(FetchConn::new(end.connect().unwrap()).unwrap()),
                    Vec::new(),
                ),
                &service.staging_dir,
                false,
                ("localhost/a", true),
                Some(b"{}"),
                manifest,
            )
            .await
            .unwrap();
            service
                .with_lazy_walker(&key, (desc.clone(), toc.clone()), walker)
                .await;
            let layer = LazyLayer {
                key,
                desc: desc.clone(),
                diff_id: desc.digest,
                toc: Arc::new(toc),
                tarsplit: bytes::Bytes::new(),
                meta: velarx_content::pull::staged::StagedLayerMeta {
                    key: key.to_string(),
                    blob: desc.digest.to_string(),
                    size: 1,
                    registry_ref: None,
                    reach: velarx_db::LayerReach {
                        tls_verify: true,
                        creds: false,
                        certs: false,
                    },
                    erofs: String::new(),
                    owners: String::new(),
                    created_at: String::new(),
                },
                toc_z: bytes::Bytes::new(),
            };
            service
                .stage_lazy(&key, vec![file.clone()], Urgency::Background)
                .await
                .unwrap();
            if removes {
                let rel = velarx_content::stager::staged_rel(&file).unwrap();
                let rel = rel.strip_prefix("files/").unwrap();
                std::fs::remove_file(area.layer_files(&key).join(rel)).unwrap();
            }
            let e = service
                .link_files(std::slice::from_ref(&layer), vec![file.clone()], Vec::new())
                .await
                .unwrap_err();
            let e = e.to_string();
            assert!(
                e.contains("the fetcher first") && e.contains(&file),
                "removes {removes}: {e}"
            );
            assert!(!store.contains_local(&file), "removes {removes}");
            assert_eq!(
                (
                    first_asked.load(Ordering::SeqCst),
                    end_asked.load(Ordering::SeqCst)
                ),
                (1, 0),
                "the next fetcher is not asked: removes {removes}"
            );
        }
    }

    /// A miss of a lazy layer of many files finds the file in a map: the
    /// misses of a container that reads every file do not walk the table
    /// each (1,000 misses of a table of 20,000 files took 38 s when they
    /// did, debug build).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_miss_does_not_walk_the_table_of_its_layer() {
        use velarx_content::fakes::{Fake, Stages};
        use velarx_content::fetcher::fetch_client::FetchConn;
        use velarx_content::pull::staged_fetch::StagedFetch;
        use velarx_content::serve_fetch::LocalFetcher;
        const FILES: usize = 20_000;
        let tmp = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let service =
            ImageService::new(db, store, tmp.path().join("pulls"), VerityMode::Off).unwrap();
        let area = service.staging_area();
        area.create().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"blob"));
        std::fs::create_dir_all(area.layer_dir(&key)).unwrap();
        std::fs::write(area.layer_dir(&key).join("layer.json"), b"{}").unwrap();
        let entries: Vec<serde_json::Value> = (0..FILES)
            .map(|i| {
                serde_json::json!({
                    "name": format!("f{i}"),
                    "type": "reg",
                    "size": 100,
                    "fsverity": format!("sha256-12:{i:064x}"),
                })
            })
            .collect();
        let toc: Toc =
            serde_json::from_value(serde_json::json!({"version": 1, "entries": entries})).unwrap();
        let desc: OciDescriptor = serde_json::from_value(serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
            "digest": Digest::of(Algorithm::Sha256, b"blob").to_string(),
            "size": 1,
        }))
        .unwrap();
        let registry = LocalFetcher::start(
            Arc::new(Fake::new(Stages::Right, "", b"", Default::default())),
            velarx_content::activation::Limits::default(),
        )
        .unwrap();
        let manifest = br#"{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","size":2},"layers":[]}"#;
        let walker = StagedFetch::open(
            (
                Vec::new(),
                Some(FetchConn::new(registry.connect().unwrap()).unwrap()),
                Vec::new(),
            ),
            &service.staging_dir,
            false,
            ("localhost/a", true),
            Some(b"{}"),
            manifest,
        )
        .await
        .unwrap();
        service.with_lazy_walker(&key, (desc, toc), walker).await;
        let started = std::time::Instant::now();
        for i in (0..FILES).rev().take(1_000) {
            let file = format!("fsverity-sha256-12:{i:064x}");
            assert!(service.is_file_of_lazy_layer(&key, &file).await.unwrap());
        }
        let other = format!("fsverity-sha256-12:{:064x}", FILES);
        assert!(!service.is_file_of_lazy_layer(&key, &other).await.unwrap());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// The groups of a layer of many files ask the size of each file once
    /// and find it at once: the time does not grow with the square of the
    /// number of files.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_completion_of_a_layer_of_many_files_is_not_quadratic() {
        const FILES: usize = 6_000;
        let (_tmp, service, _) = planner().await;
        let mut layer = layer_of(&[]);
        let entries: Vec<serde_json::Value> = (0..FILES)
            .map(|i| {
                serde_json::json!({
                    "name": format!("f{i}"),
                    "type": "reg",
                    "size": 100,
                    "fsverity": format!("sha256-12:{i:064x}"),
                })
            })
            .collect();
        layer.toc = Arc::new(
            serde_json::from_value(serde_json::json!({"version": 1, "entries": entries})).unwrap(),
        );
        let layers: Arc<[LazyLayer]> = vec![layer].into();
        let profile: Vec<String> = (0..FILES)
            .map(|i| format!("fsverity-sha256-12:{i:064x}"))
            .collect();
        let started = std::time::Instant::now();
        let (groups, _) = service.plan_groups(&layers, profile).await.unwrap();
        let planned: std::collections::HashSet<&String> =
            groups.iter().flat_map(|g| &g.files).collect();
        assert_eq!(planned.len(), FILES, "each file is planned");
        assert_eq!(groups.iter().map(|g| g.files.len()).sum::<usize>(), FILES);
        assert!(groups.iter().all(|g| g.layer == 0 && g.needed_by == [0]));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// The profile a pull starts with is the one this node recorded (the
    /// sources are not asked then), none when the settings turn it off.
    #[tokio::test]
    async fn a_pull_starts_with_the_profile_this_node_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let mut service =
            ImageService::new(db, store.clone(), tmp.path().join("pulls"), VerityMode::Off)
                .unwrap();
        let id = "a".repeat(64);
        let path = velarx_fuse::composefs::profile_path(store.root(), &id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = format!("fsverity-sha256-12:{}", "b".repeat(64));
        std::fs::write(&path, format!(r#"{{"v":1,"files":["{file}"]}}"#)).unwrap();
        let names = ["peers".to_string()];
        assert_eq!(service.pull_profile(&id, &names).await, [file]);
        service.pull_config.lazy_profile_secs = 0;
        assert!(service.pull_profile(&id, &names).await.is_empty());
    }

    #[test]
    fn a_link_in_the_staging_is_not_committed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = objects_store(tmp.path().join("store/objects"));
        let data = b"what the link points to";
        let digest =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, data);
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, data).unwrap();
        let staged = tmp.path().join("staging/files");
        let path = FileStore::new(&staged)
            .unwrap()
            .local_path(&digest)
            .unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        link_staged(&staged, &store, VerityMode::Off).unwrap();
        assert!(!store.contains_local(&digest));
    }

    /// Which layers of a lazy image the store has is the storage driver's
    /// answer: a layer the engine's database has complete but the driver
    /// does not is to be completed from the staging (and here, where nothing
    /// is staged, it is an error, not a layer taken as stored).
    #[tokio::test]
    async fn the_layers_a_lazy_image_lacks_are_the_drivers_answer() {
        use crate::storage_driver::{self, DriverParts};
        let tmp = tempfile::tempdir().unwrap();
        let sha = |t: &str| Digest::of(Algorithm::Sha256, t.as_bytes());
        let key = LayerKey::Whole(sha("blob"));
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        db.commit_layers(
            vec![velarx_db::LayerCommit {
                record: velarx_db::LayerRecord {
                    stream_size: Some(0),
                    key,
                    blob: None,
                    diff_id: Some(sha("diff")),
                    other_diff_id: None,
                    size: 1,
                    status: "ready".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    registry_ref: None,
                    erofs: None,
                    owners: None,
                },
                files: vec![],
                refs: vec![],
                chunks: vec![],
                toc_digest: sha("{}"),
                tarsplit: Some(sha("ts")),
                blob_checked: false,
            }],
            vec![],
        )
        .await
        .unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let mut service =
            ImageService::new(db, store, tmp.path().join("pulls"), VerityMode::Off).unwrap();
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "", "digest": sha("config").to_string(), "size": 1},
            "layers": [{"mediaType": "", "digest": sha("blob").to_string(), "size": 1}],
        }))
        .unwrap();
        let mut config: OciConfig = serde_json::from_str(
            r#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#,
        )
        .unwrap();
        config.rootfs.diff_ids = vec![sha("diff")];
        let area = service.staging_area();
        let keys = [key];
        let lacking = service
            .lazy_layers(&area, &manifest, &config, &keys, false)
            .await
            .unwrap();
        assert!(lacking.is_empty(), "the driver has it");
        // a driver that keeps its records elsewhere and has none of them
        service.storage = storage_driver::open(
            service.storage_kind,
            DriverParts {
                db: velarx_db::Database::open_in_memory().await.unwrap(),
                store: service.file_store.clone(),
                staging_dir: service.staging_dir.clone(),
                fsverity: service.fsverity,
            },
            &service.driver_options(),
        )
        .unwrap();
        let e = service
            .lazy_layers(&area, &manifest, &config, &keys, false)
            .await
            .map(|l| l.len())
            .unwrap_err();
        assert!(
            e.to_string().contains("neither in the store nor staged"),
            "{e}"
        );
    }
    /// The completion replays the tar-split of each staged layer against its
    /// table before it commits any: a tar-split that describes another
    /// filesystem than the table the pull checked stops it.
    #[tokio::test]
    async fn a_staged_layer_whose_tar_split_contradicts_its_table_is_refused() {
        use velarx_content::pull::staged::{NewLayer, StagedLayerMeta};
        use velarx_content::pull::{tar::TarReader, tarsplit::Recorder};
        let tmp = tempfile::tempdir().unwrap();
        let sha = |t: &str| Digest::of(Algorithm::Sha256, t.as_bytes());
        let key = LayerKey::Toc(sha("toc"));
        let db = velarx_db::Database::open_in_memory().await.unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("objects")).unwrap());
        let service =
            ImageService::new(db, store, tmp.path().join("pulls"), VerityMode::Off).unwrap();
        // (a table of one file, a tar-split of an empty tar)
        let file = format!("sha256-12:{}", "cd".repeat(32));
        let toc = serde_json::json!({"version": 1, "entries": [
            {"name": "f", "type": "reg", "size": 4, "fsverity": file}
        ]});
        let mut r = TarReader::with_sink(&[0u8; 1024][..], Recorder::new().unwrap());
        while r.next_entry().unwrap().is_some() {}
        let tarsplit = r.finish().unwrap().1.finish().unwrap().compressed;
        let area = service.staging_area();
        area.publish_layer(&NewLayer {
            meta: StagedLayerMeta {
                key: key.to_string(),
                blob: sha("blob").to_string(),
                size: 4,
                registry_ref: None,
                reach: velarx_db::LayerReach::default(),
                erofs: "sha256:ee".into(),
                owners: "[[],[]]".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
            },
            tarsplit: &tarsplit,
            toc_z: &zstd::encode_all(toc.to_string().as_bytes(), 3).unwrap(),
        })
        .unwrap();
        let manifest: OciManifest = serde_json::from_value(serde_json::json!({
            "schemaVersion": 2,
            "config": {"mediaType": "", "digest": sha("config").to_string(), "size": 1},
            "layers": [{"mediaType": "", "digest": sha("blob").to_string(), "size": 1}],
        }))
        .unwrap();
        let mut config: OciConfig = serde_json::from_str(
            r#"{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}"#,
        )
        .unwrap();
        config.rootfs.diff_ids = vec![sha("diff")];
        let e = service
            .lazy_layers(&area, &manifest, &config, &[key], false)
            .await
            .map(|l| l.len())
            .unwrap_err();
        assert!(matches!(e, ImageError::Contradicted(_)), "{e}");
        assert!(e.to_string().contains("differ at `f`"), "{e}");
    }
}
