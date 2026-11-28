// SPDX-License-Identifier: Apache-2.0
//! The engine's side of the storage driver (`crate::storage_driver`): the
//! calls of the image service to it, with the errors of the driver turned
//! into the engine's, and what only the engine knows (the database, the lock
//! of the store, the checks of the manifests).

use super::*;
use crate::storage_driver::{LayerArtifact, MountRequest, MountsRequest, Planned};
use velarx_config::ComposefsDigests;
use velarx_content::pull::stored::{stored_toc, stored_tocs};
use velarx_db::{LayerKey, LayerRecord};
use velarx_fuse::layer_erofs::Inline;
use velarx_graph::{Identities, ImageBytes, Inlining, MadeImage};

/// The commit of a layer with the record of what the driver made of it:
/// its image and the files the image holds itself, which are no objects of
/// the layer.
pub(super) fn with_image(
    mut commit: velarx_db::LayerCommit,
    made: &HashMap<LayerKey, LayerArtifact>,
    inlining: &HashMap<LayerKey, Inlining>,
    sealed: bool,
) -> velarx_db::LayerCommit {
    let key = commit.record.key;
    if let Some(m) = made.get(&key) {
        commit.record.erofs = Some(m.image_digest.clone());
        commit.record.owners = Some(m.owners.clone());
        commit.sealed = sealed;
    }
    if let Some(i) = inlining.get(&key) {
        let held: std::collections::HashSet<&str> =
            i.files.iter().map(|f| f.digest.as_str()).collect();
        commit.files.retain(|f| !held.contains(f.digest.as_str()));
        commit.refs.retain(|(d, _)| !held.contains(d.as_str()));
        commit.record.inline = i.threshold;
        commit.inlined = i.files.clone();
    }
    commit
}

impl ImageService {
    /// The mode of `[storage] composefs_digests` of this node.
    pub fn composefs_digests(&self) -> ComposefsDigests {
        self.storage_options.digests
    }

    /// What a start of a container of `image` (with `layers`) checks of the
    /// stored manifest, and the fs-verity digests it gives the monitor, one
    /// list per layer (`seal::start_lists`), as `enforcing` says.
    pub fn start_digests(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
        enforcing: seal::Enforcing,
    ) -> ImageResult<Vec<Vec<String>>> {
        self.start_digests_in(image, layers, enforcing, &velarx_wire::chain::Chain::off())
    }

    /// The same, with the links it checks said by `chain`, the debug log of
    /// the chain of trust of the start.
    pub fn start_digests_in(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
        enforcing: seal::Enforcing,
        chain: &velarx_wire::chain::Chain,
    ) -> ImageResult<Vec<Vec<String>>> {
        seal::start_lists(
            &image.id,
            &image.manifest_digest,
            &image.manifest,
            layers,
            image.is_lazy,
            enforcing,
            chain,
        )
    }

    /// Seal the layers of the stored image `image_id` that were recorded
    /// without fs-verity (the store had none then) and whose
    /// EROFS image the kernel measures now with the canonical parameters as
    /// the digest recorded for it: one ioctl for each layer, no read.  A
    /// layer that does not measure so is never sealed, and stays held to
    /// nothing; an image that is not all in the store is left alone.
    pub async fn seal_measured(&self, image_id: &str) -> ImageResult<()> {
        if !self.layers_sealed_now() {
            return Ok(());
        }
        let image = self.db.get_image(image_id).await?;
        if image.is_lazy {
            return Ok(());
        }
        let objects = self.file_store.root().to_path_buf();
        for layer in self.db.get_image_layers(&image.id).await? {
            let Some(recorded) = layer.erofs.clone() else {
                continue;
            };
            if self.db.layers_sealed(&[layer.key]).await? {
                continue;
            }
            let path = velarx_fuse::composefs::layer_image_path(&objects, &layer.key.file_stem());
            let measured = tokio::task::spawn_blocking(move || {
                use std::os::unix::fs::OpenOptionsExt;
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)
                    .ok()?;
                velarx_fuse::composefs::measure_layer_image(&file, &path, &[recorded], true)
                    .ok()
                    .flatten()
            })
            .await
            .map_err(|e| ImageError::Layer(format!("the measure task: {e}")))?;
            if measured.is_some() {
                self.db.set_layer_sealed(&layer.key, true).await?;
            }
        }
        Ok(())
    }

    /// The check of a create whose digests are enforced (`container`: its
    /// `--security-opt verity=enforce`; the node's `require` too): the stored
    /// manifest of `image` states one for every layer, as every start checks
    /// again.  Whether the image is all in the store is the start's to check
    /// (a lazy image may be fetched whole before it).
    pub fn create_digests(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
        container: bool,
    ) -> ImageResult<Vec<Vec<String>>> {
        seal::start_lists(
            &image.id,
            &image.manifest_digest,
            &image.manifest,
            layers,
            false,
            self.enforcing(container),
            &velarx_wire::chain::Chain::off(),
        )
    }

    /// What the container asks of the driver that it cannot do is refused
    /// before anything is made for the container, with the driver named and
    /// what to do: a user namespace of its own (`userns`) and an image mounted
    /// in it (`image_volumes`), for an unprivileged engine or not.
    pub fn check_container_request(&self, userns: bool, image_volumes: bool) -> ImageResult<()> {
        self.storage
            .capabilities()
            .refuse(
                self.storage.name(),
                &velarx_graph::negotiate::Ask {
                    unprivileged: !velarx_base::ids::rootful().unwrap_or(false),
                    userns,
                    image_volumes,
                    ..Default::default()
                },
            )
            .map_err(ImageError::from)
    }

    /// What the node and the container (`--security-opt verity=enforce`) ask
    /// of the digests of the manifests.
    pub fn enforcing(&self, container: bool) -> seal::Enforcing {
        seal::Enforcing::of(
            self.verity_pull_only(),
            self.storage_options.digests,
            container,
        )
    }

    /// The root file system of the image as its containers see it, read
    /// from the images of its layers a lookup at a time.
    pub fn image_view(
        &self,
        image_id: &str,
        layers: &[LayerRecord],
    ) -> ImageResult<Arc<dyn velarx_fuse::view::ImageTree>> {
        Ok(self.storage.image_view(image_id, layers)?)
    }

    /// The mounts of a container, as the monitor mounts them
    /// ([`velarx_graph::StorageDriver::mounts`]): plans, and the descriptors
    /// of the mounts the driver hands over.  An image whose artifacts are
    /// missing is an error.
    pub fn mounts(&self, req: &MountsRequest<'_>) -> ImageResult<velarx_graph::Mounts> {
        Ok(self.storage.mounts(req)?)
    }

    /// Make what the driver keeps for the image mounted in a container
    /// (`--mount type=image`) when the container is created, and say what the
    /// mount will be ([`Planned`]: no descriptor is made).  A layer whose
    /// artifact is gone is marked incomplete and the error names the image
    /// (see [`ImageService::damaged`]).
    pub async fn image_volume_create(&self, req: &MountRequest<'_>) -> ImageResult<Planned> {
        match self.storage.image_volume_create(req) {
            Ok(p) => Ok(p),
            Err(e) => {
                self.damaged(req.image, req.layers, e).await?;
                // (the artifact came back while the lock was waited for)
                Ok(self.storage.image_volume_create(req)?)
            }
        }
    }

    /// The image `image` after something failed with it: whether a layer of
    /// it has lost its EROFS image, in which case the layer is marked
    /// incomplete and the error is the one that says so (see
    /// [`ImageService::damaged`]).  None when it has not.
    pub async fn find_damage(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
    ) -> Option<ImageError> {
        let (key, _) = self.lost_artifact(image, layers).await?;
        let error = velarx_graph::DriverError::missing(
            self.storage.name(),
            Some(&key),
            format!("the layer {key} has no EROFS image"),
            velarx_graph::Remedy::Repair,
        );
        self.damaged(image, layers, error).await.err()
    }

    /// The first layer of a complete image of the composefs driver whose
    /// image the driver's quick check does not find, with its problem.
    async fn lost_artifact(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
    ) -> Option<(LayerKey, velarx_graph::Problem)> {
        if image.is_lazy || self.storage.name() != crate::storage_driver::composefs::NAME {
            return None;
        }
        let problems = self.storage.check(image, layers, false).await.ok()?;
        problems
            .into_iter()
            .find(|p| p.kind == velarx_graph::ProblemKind::ArtifactMissing)
            .and_then(|p| p.layer.map(|k| (k, p)))
    }

    /// What a driver's error about the image `image` means.  When a layer of
    /// a complete image has lost its artifact (`Missing`, naming the layer),
    /// the layer is marked incomplete (`has_layers` stops reporting it, so
    /// the next pull of the image fetches it again; the objects and the other
    /// layers stay) and the error says the image is damaged.  Any other error
    /// is returned as it is, and so is a lazy image's and that of a layer
    /// made here, not pulled (`system check --repair` makes their
    /// artifacts).  Under the shared lock of the store,
    /// like the repair, and the layer is looked at again under it: `Ok` says
    /// the artifact is there after all.  Only the failure path comes here: a
    /// healthy create or start does nothing more.
    pub async fn damaged(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
        error: velarx_graph::DriverError,
    ) -> ImageResult<()> {
        if missing_layer(image, &error).is_none() {
            return Err(error.into());
        }
        let _shared = self.lock_store().await?;
        let Some((key, lost)) = self.lost_artifact(image, layers).await else {
            // (the artifact came back while the lock was waited for)
            return Ok(());
        };
        if let Some(held) = layers.iter().find(|l| l.key == key && l.inline != 0) {
            leave_inlined(held);
            return Err(ImageError::Storage(format!(
                "image {}: the layer {key}: {}; it holds files in its image: remove the image and pull it again",
                image.id, lost.message
            )));
        }
        // (a layer made here, by a commit, a build or a load, keeps its
        // tar-split: no pull brings it back, the repair makes its image)
        let marked = match self.db.mark_layer_incomplete(&key).await? {
            velarx_db::LayerMarking::NotPulled => {
                return Err(velarx_graph::DriverError::missing(
                    self.storage.name(),
                    Some(&key),
                    format!("image {}: the layer {key}: {}", image.id, lost.message),
                    velarx_graph::Remedy::Repair,
                )
                .into())
            }
            m => m == velarx_db::LayerMarking::Marked,
        };
        let name = match self.db.get_tags_for_image(&image.id).await {
            Ok(tags) if !tags.is_empty() => format!("{}:{}", tags[0].repository, tags[0].tag),
            _ => image.id.chars().take(12).collect(),
        };
        let what = "has no EROFS image";
        warn!(
            "Image {}: the layer {key} {what}: marked incomplete{}, the next pull of the image fetches it again",
            image.id,
            if marked { "" } else { " (not done: the layer is of a read-only store)" }
        );
        Err(ImageError::Storage(format!(
            "the image {name} is damaged (layer {key} {what}): pull it again"
        )))
    }

    /// The digest of the EROFS image of the layer `key` that a manifest
    /// written here states: `recorded`, the digest of the image the store
    /// has, unless the layer holds files in that image (`inline`), whose
    /// digest no other node makes: the one its table of contents alone
    /// makes, `toc` or the stored one.
    pub(super) async fn stated_erofs(
        &self,
        key: &LayerKey,
        recorded: String,
        inline: i64,
        toc: Option<Arc<Toc>>,
    ) -> ImageResult<String> {
        if inline == 0 {
            return Ok(recorded);
        }
        let toc = match toc {
            Some(toc) => toc,
            None => Arc::new(stored_toc(&self.db, key).await?.ok_or_else(|| {
                ImageError::Layer(format!("layer {key} has no table of contents"))
            })?),
        };
        let alg = key.digest().alg();
        tokio::task::spawn_blocking(move || {
            velarx_fuse::layer_erofs::layer_identity(alg, &toc.entries).map(|id| id.erofs)
        })
        .await
        .map_err(|e| ImageError::Layer(format!("the identity task: {e}")))?
        .map_err(|e| ImageError::Layer(format!("the identity of layer {key}: {e}")))
    }

    /// The digest of the merged image of the layers of the image `image_id`
    /// in `alg` (the algorithm of its manifest), made now when the store has
    /// every file of them (the image is not kept).  None for an image with a
    /// layer of another algorithm: a mixed image has none.
    pub(super) async fn merged_erofs_id(
        &self,
        image_id: &str,
        alg: Algorithm,
    ) -> ImageResult<Option<(Algorithm, String)>> {
        let mut tocs = Vec::new();
        // (a failed read of the layers is an error, not an image that has
        // no merged one)
        for l in self.db.get_image_layers(image_id).await? {
            if l.key.digest().alg() != alg {
                return Ok(None);
            }
            let Ok(Some(toc)) = stored_toc(&self.db, &l.key).await else {
                return Ok(None);
            };
            tocs.push(toc);
        }
        let store = self.file_store.clone();
        let id = tokio::task::spawn_blocking(move || {
            let tocs: Vec<&Toc> = tocs.iter().collect();
            velarx_fuse::canonical::image_of_store(alg, &tocs, &store)
                .ok()
                .map(|(_, id)| id)
        })
        .await
        .map_err(|e| ImageError::Layer(format!("the merged image task: {e}")))?;
        Ok(id.map(|id| (alg, id)))
    }

    /// What is wrong with what the driver made of the layers of `image`:
    /// each must be recorded, there, read-only and of the digest recorded;
    /// `full` reads them, compares them with what the tables of contents
    /// make, and checks the merged image a sealed manifest states.
    pub async fn image_problems(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
        full: bool,
    ) -> ImageResult<Vec<crate::storage_driver::Problem>> {
        Ok(self.storage.check(image, layers, full).await?)
    }

    /// The layer `key` as the tar stream of its diff id (in `alg`'s), read
    /// back by the engine from its tar-split and the objects of the store
    /// (push, save).  A layer that is not there is `Missing` with the remedy
    /// of pulling again.
    pub async fn open_layer(
        &self,
        key: &LayerKey,
        diff_id: &velarx_types::digest::Digest,
    ) -> velarx_graph::DriverResult<velarx_content::layer::reproduce::StoredLayer> {
        velarx_graph::objects::open_layer_expecting(self.storage.name(), &self.db, key, diff_id)
            .await
    }

    /// The layers of the image `image` as the engine names them to the
    /// driver: `layers` are its whole stack, in order.  The diff ids, and so
    /// the chain ids, are those of the image's configuration, as a pull
    /// computes them; the diff ids of the layers' records stand in when the
    /// configuration cannot be read or does not name every layer.
    pub(super) fn layer_refs(
        &self,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
    ) -> ImageResult<Vec<velarx_graph::LayerRef>> {
        let keys: Vec<LayerKey> = layers.iter().map(|l| l.key).collect();
        if let Ok(c) = serde_json::from_str::<OciConfig>(&image.config) {
            if c.rootfs.diff_ids.len() == layers.len() {
                return Ok(super::pull::layer_refs(&keys, &c.rootfs.diff_ids));
            }
        }
        // (a layer made here, by a commit, has its diff id)
        let diff_ids: Vec<_> = layers
            .iter()
            .map(|l| l.diff_id.unwrap_or(*l.key.digest()))
            .collect();
        Ok(super::pull::layer_refs(&keys, &diff_ids))
    }

    /// Make the artifacts of the staged layers of the pull `id` again from
    /// their tables of contents: they must be the ones the pull recorded.
    pub async fn remake_staged_images(&self, id: &str) -> ImageResult<()> {
        Ok(self.storage.remake_staged(id).await?)
    }

    /// Make the artifacts of the layers of `image_id` again from their
    /// tables of contents, and record them.
    pub async fn remake_image(&self, image_id: &str) -> ImageResult<()> {
        let image = self.db.get_image(image_id).await?;
        let layers = self.db.get_image_layers(image_id).await?;
        if let Some(held) = layers.iter().find(|l| l.inline != 0) {
            leave_inlined(held);
            return Err(ImageError::Storage(format!(
                "the layer {} holds files in its EROFS image, which cannot be made again from the table of contents",
                held.key
            )));
        }
        let tocs = stored_tocs(&self.db, &layers.iter().map(|l| l.key).collect::<Vec<_>>()).await?;
        let tocs: Vec<(LayerKey, Toc)> = layers.iter().map(|l| l.key).zip(tocs).collect();
        let _shared = self.lock_store().await?;
        let ours = identities(tocs).await?;
        let refs = self.layer_refs(&image, &layers)?;
        let theirs = self.storage.repair(&refs).await?;
        agree(&ours, &theirs)?;
        for (digest, m) in ours {
            self.db
                .set_layer_erofs(&digest, &m.image_digest, &m.owners)
                .await?;
            self.db
                .set_layer_sealed(&digest, self.layers_sealed_now())
                .await?;
        }
        Ok(())
    }
}

/// Say that `layer`, which holds files in its EROFS image, is left as it is:
/// nothing is fetched for it, and it stays recorded as it is.
fn leave_inlined(layer: &LayerRecord) {
    debug!(
        "Layer {} holds files in its EROFS image (inline threshold {}): it stays as it is, nothing is fetched for it; to make it again, with another threshold too, remove its image with `velarx rmi` and pull it again",
        layer.key, layer.inline
    );
}

/// The identity of each layer, made from its table of contents by the engine
/// (one thread for each layer): what the engine records, whatever the driver
/// says.
async fn identities(layers: Vec<(LayerKey, Toc)>) -> ImageResult<HashMap<LayerKey, LayerArtifact>> {
    tokio::task::spawn_blocking(move || {
        std::thread::scope(|s| {
            let handles: Vec<_> = layers
                .iter()
                .map(|(key, toc)| s.spawn(move || identity_of_table(key, toc)))
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    let (key, artifact, _) = h
                        .join()
                        .unwrap_or_else(|_| Err(ImageError::Layer("the making panicked".into())))?;
                    Ok((key, artifact))
                })
                .collect()
        })
    })
    .await
    .map_err(|e| ImageError::Layer(format!("the identity task: {e}")))?
}

/// The content of a file a layer image holds, by its fs-verity digest.
pub(super) type Open<'a> = &'a (dyn Fn(&Digest) -> std::io::Result<std::fs::File> + Sync);

/// The identity of each layer `(key, TOC, inline threshold)` and the EROFS
/// image it was made from (one thread for each layer; blocking): the images
/// go to the driver, which stores them as they are rather than build them
/// again.  `open` and `dir` are those of [`identity_of`].
pub(super) fn identities_of(
    layers: &[(&LayerKey, &Toc, i64)],
    open: Open<'_>,
    dir: &std::path::Path,
) -> ImageResult<(Identities, HashMap<LayerKey, Inlining>)> {
    std::thread::scope(|s| {
        let handles: Vec<_> = layers
            .iter()
            .map(|&(key, toc, threshold)| {
                s.spawn(move || identity_of(key, toc, &Inline { threshold, open }, dir))
            })
            .collect();
        let mut ids = Identities::default();
        let mut inlining = HashMap::new();
        for h in handles {
            let (key, artifact, image, inlined) = h
                .join()
                .unwrap_or_else(|_| Err(ImageError::Layer("the making panicked".into())))?;
            ids.artifacts.insert(key, artifact);
            ids.images.insert(key, image);
            inlining.insert(key, inlined);
        }
        Ok((ids, inlining))
    })
}

/// The identity of the layer `key` from its table of contents, the EROFS
/// image it was made from and the files the image holds itself, which
/// `inline` says and opens (blocking).  An image that holds none is made in
/// memory; one that holds files is written once to a file with no name in
/// `dir`, hashed as it is written: it can be as big as they are.
pub(super) fn identity_of(
    key: &LayerKey,
    toc: &Toc,
    inline: &Inline,
    dir: &std::path::Path,
) -> ImageResult<(LayerKey, LayerArtifact, MadeImage, Inlining)> {
    let threshold = inline.threshold;
    if threshold == 0 {
        let (key, artifact, image) = identity_of_table(key, toc)?;
        let none = Inlining {
            threshold,
            files: Vec::new(),
        };
        return Ok((key, artifact, image, none));
    }
    let fail = |e: String| ImageError::Layer(format!("the identity of layer {key}: {e}"));
    let alg = key.digest().alg();
    let file = velarx_content::pull::unnamed::unnamed_file(dir).map_err(|e| fail(e.to_string()))?;
    let mut hashed = Hashed {
        file: &file,
        hasher: velarx_storage::VerityHasher::new(alg),
    };
    let written = velarx_fuse::layer_erofs::write_layer_image(
        &toc.entries,
        inline,
        std::io::BufWriter::new(&mut hashed),
    )
    .map_err(fail)?;
    let erofs = Digest::parse_fsverity(&hashed.hasher.finish())
        .map_err(|e| fail(e.to_string()))?
        .plain();
    let artifact = LayerArtifact {
        image_digest: erofs,
        owners: serde_json::to_string(&written.owners).map_err(|e| fail(e.to_string()))?,
    };
    let files = written
        .extents
        .into_iter()
        .map(|e| velarx_db::InlinedFile {
            digest: e.digest.to_string(),
            offset: e.offset,
            size: e.size,
        })
        .collect();
    let image = MadeImage {
        image: ImageBytes::File(file),
        index: written.index,
    };
    Ok((*key, artifact, image, Inlining { threshold, files }))
}

/// The identity of the layer `key` from its table of contents alone, and
/// the EROFS image it was made from, in memory (blocking).
pub(super) fn identity_of_table(
    key: &LayerKey,
    toc: &Toc,
) -> ImageResult<(LayerKey, LayerArtifact, MadeImage)> {
    let fail = |e: String| ImageError::Layer(format!("the identity of layer {key}: {e}"));
    let image = velarx_fuse::layer_erofs::layer_image(&toc.entries).map_err(fail)?;
    let id = image.identity(key.digest().alg()).map_err(fail)?;
    let artifact = LayerArtifact {
        image_digest: id.erofs,
        owners: id.owners,
    };
    Ok((*key, artifact, image.into()))
}

/// A file that an image is written to, and the fs-verity hash of what is.
struct Hashed<'a> {
    file: &'a std::fs::File,
    hasher: velarx_storage::VerityHasher,
}

impl std::io::Write for Hashed<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(bytes)?;
        self.hasher.update(&bytes[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The artifacts a driver recorded must be the engine's identity: a driver
/// that says another is refused.
pub(super) fn agree(
    ours: &HashMap<LayerKey, LayerArtifact>,
    theirs: &HashMap<LayerKey, LayerArtifact>,
) -> ImageResult<()> {
    for (key, made) in theirs {
        if let Some(own) = ours.get(key) {
            if own != made {
                return Err(ImageError::Contradicted(format!(
                    "the storage driver records the layer {key} as (image {}, owners {}), \
                     its table of contents makes (image {}, owners {})",
                    made.image_digest, made.owners, own.image_digest, own.owners
                )));
            }
        }
    }
    Ok(())
}

/// The verdict a driver returned must be the check of the layers it pulled:
/// the identities in it are of exactly those layers (a verdict of another
/// pull, or one made up, is refused).
pub(super) fn of_these_layers(
    ours: &HashMap<LayerKey, LayerArtifact>,
    pulled: &[&LayerKey],
) -> ImageResult<()> {
    let keys: std::collections::HashSet<&LayerKey> = pulled.iter().copied().collect();
    if ours.len() == keys.len() && ours.keys().all(|k| keys.contains(k)) {
        Ok(())
    } else {
        Err(ImageError::Storage(
            "the check of the pull is not of the layers the driver pulled".into(),
        ))
    }
}

/// The layer a `Missing` error of a complete image of the composefs driver
/// names.
fn missing_layer(
    image: &velarx_db::ImageRecord,
    error: &velarx_graph::DriverError,
) -> Option<LayerKey> {
    match (&error.kind, &error.layer) {
        (velarx_graph::DriverErrorKind::Missing { .. }, Some(layer))
            if !image.is_lazy && error.driver == crate::storage_driver::composefs::NAME =>
        {
            LayerKey::parse(layer)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> LayerKey {
        LayerKey::Whole(
            format!("sha256:{}", format!("{n:02x}").repeat(32))
                .parse()
                .unwrap(),
        )
    }

    fn art(erofs: &str, owners: &str) -> LayerArtifact {
        LayerArtifact {
            image_digest: erofs.into(),
            owners: owners.into(),
        }
    }

    /// A driver's artifacts are compared with the engine's identity: the same
    /// (or none for a layer) is fine, another digest or other owners is
    /// refused, never taken.
    #[test]
    fn a_driver_that_records_another_identity_is_refused() {
        let ours: HashMap<LayerKey, LayerArtifact> = [
            (key(1), art("a", "[[0],[0]]")),
            (key(2), art("b", "[[1],[1]]")),
        ]
        .into();
        assert!(agree(&ours, &ours).is_ok());
        assert!(agree(&ours, &HashMap::new()).is_ok());
        let some: HashMap<_, _> = [(key(2), art("b", "[[1],[1]]"))].into();
        assert!(agree(&ours, &some).is_ok());
        let other_image: HashMap<_, _> = [(key(1), art("x", "[[0],[0]]"))].into();
        assert!(matches!(
            agree(&ours, &other_image),
            Err(ImageError::Contradicted(m)) if m.contains("image x")
        ));
        let other_owners: HashMap<_, _> = [(key(1), art("a", "[[5],[0]]"))].into();
        assert!(agree(&ours, &other_owners).is_err());
        // a layer the engine did not ask about is not its business
        let extra: HashMap<_, _> = [(key(9), art("z", "[[],[]]"))].into();
        assert!(agree(&ours, &extra).is_ok());
    }

    /// A verdict is of the layers the driver pulled: one that has more, fewer
    /// or other layers (the check of another pull, or none) is refused.
    #[test]
    fn a_verdict_of_other_layers_is_refused() {
        let ours: HashMap<LayerKey, LayerArtifact> = [
            (key(1), art("a", "[[0],[0]]")),
            (key(2), art("b", "[[1],[1]]")),
        ]
        .into();
        let (one, two, nine) = (key(1), key(2), key(9));
        assert!(of_these_layers(&ours, &[&one, &two]).is_ok());
        assert!(of_these_layers(&ours, &[&two, &one]).is_ok());
        // a verdict with no identity (a driver that ran no check)
        assert!(of_these_layers(&HashMap::new(), &[&one, &two]).is_err());
        // of fewer, of more, of other layers
        assert!(of_these_layers(&ours, &[&one]).is_err());
        assert!(of_these_layers(&ours, &[&one, &two, &nine]).is_err());
        assert!(of_these_layers(&ours, &[&one, &nine]).is_err());
    }
}
