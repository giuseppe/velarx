// SPDX-License-Identifier: Apache-2.0
//! The lazy phase of an image for a driver that is a program of its own.
//!
//! A storage service keeps complete layers.  An image pulled with `--lazy`
//! does not have them yet: the engine stages its tables of contents and makes
//! the EROFS images of its layers, and the containers of the image are served
//! by the engine's image server (a FUSE file system that fetches the files as
//! they are read, checked against the fs-verity digest of the table of
//! contents) with the writable layer in the bundle of the container, exactly
//! as for the `composefs` driver.  [`LazyPhase`] is that part: it wraps the
//! service and a `composefs` driver over the engine's own graph root, and
//! sends to the second one what concerns an image that is being pulled and
//! the containers made on it; everything else is the service's.  The service
//! sees nothing of the lazy phase: when the files are all in the pool of the
//! staging area the engine pulls the layers into the service as an eager pull
//! does, from the pool (`ImageService::complete_pull`).
//!
//! `lazy` is a capability the engine gives the service (the service does not
//! say it); a layer that cannot be served lazily (it is not a zstd:chunked
//! layer, or its table of contents gives no fs-verity digest for a file)
//! makes the pull fail before a byte of the image is staged.

use super::*;
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use std::sync::Arc;
use velarx_content::layer::dirtar::Change;
use velarx_content::layer::holes::HoleWrite;
use velarx_db::{ImageRecord, LayerKey, LayerRecord};
use velarx_fuse::view::ImageTree;
use velarx_graph::cpview::StoppedView;
use velarx_graph::feed::{to_fetch, Incoming as DriverIncoming, LayerIndex, PullFeed};
use velarx_graph::forward_storage_driver;
use velarx_types::{ImageError, ImageResult};

/// The directory of the graph root with the pins of the containers whose root
/// the engine serves.
const PINS: &str = "lazy-pins";

/// The service, and the `composefs` driver of the engine's own files that runs
/// an image while it is pulled.
pub struct LazyPhase {
    service: Arc<dyn StorageDriver>,
    local: Arc<ComposefsDriver>,
    caps: Capabilities,
    /// A file for each container whose root the engine serves, with the
    /// layers of its image: what the engine's copy is kept for.
    pins: std::path::PathBuf,
}

impl LazyPhase {
    pub fn new(service: Arc<dyn StorageDriver>, local: Arc<ComposefsDriver>) -> Self {
        let caps = Capabilities {
            lazy: true,
            ..service.capabilities().clone()
        };
        let pins = local.beside_objects(PINS);
        Self {
            service,
            local,
            caps,
            pins,
        }
    }

    /// The container `w` is served by the engine from now: the layers of its
    /// image are kept until it is removed.  Written (and made durable) before
    /// its writable layer is, under the shared lock of the store the create
    /// holds, so that a release, which holds it exclusive, sees every root
    /// that exists or is being made.
    fn pin(&self, w: &Writable, layers: &[LayerRecord]) -> DriverResult<()> {
        let path = self.pin_path(w)?;
        let write = || -> std::io::Result<()> {
            velarx_base::ipc::create_private_dirs(&self.pins)?;
            let mut text = String::new();
            for l in layers {
                text.push_str(&format!("{}\n", l.key));
            }
            // (a temporary name of the writer's own, `.<id>.<pid>.<n>.tmp`,
            // which a release takes away; the directory synced: the row of
            // the container is durable, its pin must be too)
            velarx_base::atomic_file::write_durable(&path, text.as_bytes(), 0o600)?;
            std::fs::File::open(&self.pins)?.sync_all()
        };
        write().map_err(|e| DriverError::io(self.service.name(), e))
    }

    /// The root of `w` is not the engine's any more (or never was).
    fn unpin(&self, w: &Writable) -> DriverResult<()> {
        // (a name that cannot be a pin has none)
        let Ok(path) = self.pin_path(w) else {
            return Ok(());
        };
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DriverError::io(self.service.name(), e)),
        }
    }

    fn pin_path(&self, w: &Writable) -> DriverResult<std::path::PathBuf> {
        let id = w.id();
        if id.is_empty() || id.starts_with('.') || id.contains(['/', '\0']) {
            return Err(DriverError::storage(
                self.service.name(),
                format!("{id:?} is no container id"),
            ));
        }
        Ok(self.pins.join(id))
    }

    /// Whether the container `w` has a pin (one that cannot be named has
    /// none).
    fn is_pinned(&self, w: &Writable) -> bool {
        self.pin_path(w).is_ok_and(|p| p.exists())
    }

    /// The layers the pins of the containers in `containers` name.  A pin of
    /// a container that does not exist (a create that died) goes, and so does
    /// a temporary file of one; a pin that cannot be read is an error, which
    /// makes the release drop nothing.
    fn pinned(&self, containers: &[String]) -> DriverResult<std::collections::HashSet<LayerKey>> {
        let mut layers = std::collections::HashSet::new();
        let entries = match std::fs::read_dir(&self.pins) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(layers),
            Err(e) => return Err(DriverError::io(self.service.name(), e)),
        };
        let exist: std::collections::HashSet<&str> =
            containers.iter().map(String::as_str).collect();
        for entry in entries {
            let entry = entry.map_err(|e| DriverError::io(self.service.name(), e))?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") || !exist.contains(name.as_str()) {
                match std::fs::remove_file(&path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return Err(DriverError::io(self.service.name(), e))
                    }
                    _ => continue,
                }
            }
            let text = std::fs::read_to_string(&path).map_err(|e| {
                DriverError::io(
                    self.service.name(),
                    std::io::Error::new(e.kind(), format!("{}: {e}", path.display())),
                )
            })?;
            for line in text.lines() {
                layers.insert(LayerKey::parse(line).ok_or_else(|| {
                    DriverError::storage(
                        self.service.name(),
                        format!("{} names {line:?}, which is no layer key", path.display()),
                    )
                })?);
            }
        }
        Ok(layers)
    }

    /// The container was made on an image that was being pulled: its root and
    /// its writable layer are the engine's.
    fn is_local(&self, w: &Writable) -> bool {
        self.local.writable_exists(w).unwrap_or(false)
    }

    /// An error of the engine's side of the lazy phase is the driver's: the
    /// caller sees one driver.
    fn ours<T>(&self, r: DriverResult<T>) -> DriverResult<T> {
        r.map_err(|mut e| {
            e.driver = self.service.name().to_string();
            e
        })
    }

    fn of(&self, w: &Writable) -> &dyn StorageDriver {
        if self.is_local(w) {
            &*self.local
        } else {
            &*self.service
        }
    }

    fn refuses_volume(&self, req: &MountRequest<'_>) -> DriverError {
        DriverError::of(
            self.service.name(),
            DriverErrorKind::Unsupported,
            format!(
                "the image {} is being pulled lazily and the storage service {} does not serve an image mount (--mount type=image) of it yet: wait for the pull (`image complete`)",
                req.image.id,
                self.service.name()
            ),
        )
    }
}

/// The feed of a lazy pull that refuses, before it is begun, an image with a
/// layer the engine cannot serve lazily.
struct Checked {
    inner: Arc<dyn PullFeed>,
    layers: Vec<FeedLayer>,
    service: String,
}

impl Checked {
    async fn check(&self) -> ImageResult<()> {
        let refusals: Vec<Option<String>> = futures::stream::iter(self.layers.iter().cloned())
            .map(|layer| {
                let inner = self.inner.clone();
                async move {
                    Ok::<_, ImageError>(inner.why_not_lazy(&layer).await?.map(|why| {
                        format!(
                            "layer {} ({} bytes): {why}",
                            layer.descriptor.digest, layer.descriptor.size
                        )
                    }))
                }
            })
            .buffered(self.inner.parallel().max(1))
            .try_collect()
            .await?;
        match refusals.into_iter().flatten().next() {
            None => Ok(()),
            Some(layer) => Err(ImageError::Storage(format!(
                "the image cannot be pulled lazily with the storage service {}: {layer}.  A lazy image is run from the files of the engine while its layers are pulled into the service, which needs a zstd:chunked table of contents with the fs-verity digest of every file in every layer; pull the image without --lazy, or with an image pushed by `velarx image push` or `buildah ... --compression-format zstd:chunked`",
                self.service
            ))),
        }
    }
}

#[async_trait]
impl PullFeed for Checked {
    async fn begin(&self, into: &Arc<dyn DriverIncoming>) -> ImageResult<()> {
        self.inner.begin(into).await?;
        self.check().await
    }

    fn parallel(&self) -> usize {
        self.inner.parallel()
    }

    fn is_lazy(&self) -> bool {
        true
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
    ) -> ImageResult<velarx_content::pull::LayerDone> {
        let done = self.inner.fetch(layer, into).await?;
        // (a layer the feed pulled whole after all would be the engine's
        // alone, never the service's: no downgrade)
        if !done.lazy {
            return Err(ImageError::Storage(format!(
                "the layer {} of a lazy pull with the storage service {} was not staged lazily: pull the image without --lazy",
                layer.descriptor.digest, self.service
            )));
        }
        Ok(done)
    }

    fn release(&self, layer: &FeedLayer) {
        self.inner.release(layer)
    }

    async fn finish(&self) -> ImageResult<()> {
        self.inner.finish().await
    }

    fn end(&self) {
        self.inner.end()
    }
}

forward_storage_driver! {
    impl StorageDriver for LazyPhase {
        inner: service;
        forward: [name graph_name has_layers repair read_objects open_object objects_in_order holds_objects usage list_stores drop_store lock_unused_layers];

        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }

        fn status(&self) -> Vec<(String, String)> {
            let mut pairs = self.service.status();
            // (the engine's word, not the service's: it gave itself `lazy`)
            for (name, value) in &mut pairs {
                if name == "capabilities" {
                    *value = self.caps.summary();
                }
            }
            pairs.push((
                "lazy phase".into(),
                format!("the engine's {} files", self.local.name()),
            ));
            pairs
        }

        fn graph_data(&self, w: &Writable) -> Vec<(String, String)> {
            self.of(w).graph_data(w)
        }

        async fn pull(
            &self,
            feed: &Arc<dyn PullFeed>,
            layers: &[FeedLayer],
            settled: Settled,
        ) -> DriverResult<Pulled> {
            if !feed.is_lazy() {
                return self.service.pull(feed, layers, settled).await;
            }
            // (every layer is staged: the service's copy of a layer is not
            // something the engine's image server can read)
            let layers: Vec<FeedLayer> = layers
                .iter()
                .map(|l| FeedLayer {
                    stored: false,
                    ..l.clone()
                })
                .collect();
            let checked: Arc<dyn PullFeed> = Arc::new(Checked {
                inner: feed.clone(),
                layers: to_fetch(&layers).cloned().collect(),
                service: self.service.name().to_string(),
            });
            self.ours(self.local.pull(&checked, &layers, settled).await)
        }

        fn collect(&self, keep: &Keep) -> DriverResult<Collected> {
            // (the images of the layers the engine kept for the containers
            // made on a lazy pull are its own to sweep)
            let mut all = self.service.collect(keep)?;
            let local = self.ours(self.local.collect(keep))?;
            all.bytes_freed += local.bytes_freed;
            all.errors.extend(local.errors);
            Ok(all)
        }

        async fn release_engine_copies(
            &self,
            layers: &[LayerKey],
            held: &EngineHeld,
        ) -> DriverResult<Collected> {
            // (a pin that cannot be read: nothing is dropped)
            let mut keep = self.pinned(&held.containers)?;
            keep.extend(held.layers.iter().copied());
            self.ours(self.local.drop_layers(layers, &keep, &held.files).await)
        }

        async fn remake_staged(&self, pull: &str) -> DriverResult<()> {
            self.ours(self.local.remake_staged(pull).await)
        }

        fn remove_image(&self, image_id: &str) -> DriverResult<()> {
            self.ours(self.local.remove_image(image_id))?;
            self.service.remove_image(image_id)
        }

        fn image_volume_create(&self, req: &MountRequest<'_>) -> DriverResult<Planned> {
            if req.image.is_lazy {
                return Err(self.refuses_volume(req));
            }
            self.service.image_volume_create(req)
        }

        fn mounts(&self, req: &MountsRequest<'_>) -> DriverResult<Mounts> {
            if let Some(v) = req.volumes.iter().find(|v| v.image.is_lazy) {
                return Err(self.refuses_volume(v));
            }
            let Some(root) = req.root.as_ref().filter(|r| self.is_local(r.container) || r.image.is_lazy)
            else {
                return self.service.mounts(req);
            };
            let mut mounts = match self.local.mounts(&MountsRequest {
                root: Some(root.clone()),
                volumes: Vec::new(),
            }) {
                // (a root of the engine's on a completed image with no pin:
                // made by an engine built before the pins, so nothing held
                // the copy it runs on; no repair brings its files back)
                Err(e)
                    if matches!(e.kind, velarx_graph::DriverErrorKind::Missing { .. })
                        && !root.image.is_lazy
                        && !self.is_pinned(root.container) =>
                {
                    return Err(DriverError::missing(
                        self.service.name(),
                        None,
                        format!(
                            "the root of the container {} was served by the engine from its copy of a lazy image, which nothing held and which is gone (the container was made by an engine that kept no pin in {})",
                            root.container.id(),
                            self.pins.display()
                        ),
                        velarx_graph::Remedy::RecreateContainer,
                    ));
                }
                other => self.ours(other)?,
            };
            if !req.volumes.is_empty() {
                mounts.volumes = self
                    .service
                    .mounts(&MountsRequest {
                        root: None,
                        volumes: req.volumes.clone(),
                    })?
                    .volumes;
            }
            Ok(mounts)
        }

        fn image_view(
            &self,
            image_id: &str,
            layers: &[LayerRecord],
        ) -> DriverResult<Arc<dyn ImageTree>> {
            // (the images of the layers the engine made are the engine's to
            // read; a layer it has none for is the service's)
            self.local
                .image_view(image_id, layers)
                .or_else(|_| self.service.image_view(image_id, layers))
        }

        async fn leftovers(&self, grace: std::time::Duration) -> DriverResult<Vec<(std::path::PathBuf, String)>> {
            let mut all = self.service.leftovers(grace).await?;
            all.extend(self.ours(self.local.leftovers(grace).await)?);
            Ok(all)
        }

        async fn check(
            &self,
            image: &ImageRecord,
            layers: &[LayerRecord],
            full: bool,
        ) -> DriverResult<Vec<Problem>> {
            if image.is_lazy {
                return self.ours(self.local.check(image, layers, full).await);
            }
            self.service.check(image, layers, full).await
        }

        fn writable_create(
            &self,
            w: &Writable,
            owner: Option<(u32, u32)>,
            opts: &WritableOptions,
            base: Option<&MountRequest<'_>>,
        ) -> DriverResult<Option<Planned>> {
            match base {
                Some(b) if b.image.is_lazy => {
                    // (the pin first: whenever the writable layer is there,
                    // the layers it is served from are held)
                    self.pin(w, b.layers)?;
                    self.ours(self.local.writable_create(w, owner, opts, base))
                }
                _ => self.service.writable_create(w, owner, opts, base),
            }
        }

        fn writable_paths(&self, w: &Writable) -> WritablePaths {
            self.of(w).writable_paths(w)
        }

        fn writable_root(&self, w: &Writable) -> DriverResult<std::os::fd::OwnedFd> {
            self.ours(self.of(w).writable_root(w))
        }

        fn writable_size(&self, w: &Writable) -> DriverResult<u64> {
            self.ours(self.of(w).writable_size(w))
        }

        fn writable_remove(&self, w: &Writable) -> DriverResult<()> {
            self.ours(self.of(w).writable_remove(w))?;
            // (after the layer: a removal that stops between the two leaves a
            // pin of a container that has no root, which the next release
            // takes away)
            self.unpin(w)
        }

        fn writable_release(&self, w: &Writable) -> velarx_graph::WritableRelease {
            match self.of(w).writable_release(w) {
                velarx_graph::WritableRelease::Service {
                    socket,
                    timeout_secs,
                    store,
                    ..
                } => velarx_graph::WritableRelease::Service {
                    socket,
                    timeout_secs,
                    store,
                    pin: self.pin_path(w).ok(),
                },
                velarx_graph::WritableRelease::InBundle { .. } => {
                    velarx_graph::WritableRelease::InBundle {
                        pin: self.pin_path(w).ok(),
                    }
                }
            }
        }

        fn writable_exists(&self, w: &Writable) -> DriverResult<bool> {
            Ok(self.is_local(w) || self.service.writable_exists(w)?)
        }

        fn diff(
            &self,
            w: &Writable,
            lower: Option<Arc<dyn ImageTree>>,
            opts: &DiffOptions,
            out: &mut dyn HoleWrite,
        ) -> DriverResult<()> {
            self.ours(self.of(w).diff(w, lower, opts, out))
        }

        fn changes(
            &self,
            w: &Writable,
            lower: Option<Arc<dyn ImageTree>>,
            opts: &DiffOptions,
        ) -> DriverResult<Vec<(String, Change)>> {
            self.ours(self.of(w).changes(w, lower, opts))
        }

        fn apply(&self, w: &Writable, opts: &DiffOptions, tar: &mut dyn std::io::Read) -> DriverResult<()> {
            self.ours(self.of(w).apply(w, opts, tar))
        }

        fn stopped_view<'a>(
            &self,
            w: &Writable,
            image: TreeSource<'a>,
        ) -> DriverResult<StoppedView<'a>> {
            self.ours(self.of(w).stopped_view(w, image))
        }

        fn is_root_of(&self, w: &Writable, proc_dir: &std::path::Path) -> DriverResult<bool> {
            self.ours(self.of(w).is_root_of(w, proc_dir))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_graph::conformance::conformance_suite;
    use velarx_storage_client::VarlinkDriver;
    use velarx_storage_server::conformance::factory;

    /// The service behind the lazy phase, over the files of the subject.
    fn lazy(
        client: Arc<VarlinkDriver>,
        db: &velarx_db::Database,
        store: &Arc<velarx_storage::FileStore>,
        staging: &std::path::Path,
    ) -> Arc<dyn StorageDriver> {
        let dir = staging.parent().expect("a directory of the subject");
        let local = ComposefsDriver::new(
            db.clone(),
            store.clone(),
            staging.to_path_buf(),
            velarx_storage::VerityMode::Off,
            composefs::options_for_tests(dir),
        );
        Arc::new(LazyPhase::new(client, Arc::new(local)))
    }

    /// The engine's copy of a lazy image: the pins of the containers whose
    /// root the engine serves, and what a release drops.
    mod engine_copy {
        use super::*;
        use velarx_fuse::composefs as cfs;

        struct Copy {
            _dir: tempfile::TempDir,
            phase: LazyPhase,
            local: Arc<ComposefsDriver>,
            db: velarx_db::Database,
            store: Arc<velarx_storage::FileStore>,
        }

        async fn copy() -> Copy {
            let dir = tempfile::tempdir().unwrap();
            let db = velarx_db::Database::open(dir.path().join("db"))
                .await
                .unwrap();
            let store =
                Arc::new(velarx_storage::FileStore::new(dir.path().join("objects")).unwrap());
            let make = |name: &str| {
                let root = dir.path().join(name);
                std::fs::create_dir_all(&root).unwrap();
                ComposefsDriver::new(
                    db.clone(),
                    store.clone(),
                    root.join("staging"),
                    velarx_storage::VerityMode::Off,
                    composefs::options_for_tests(&root),
                )
            };
            // (any driver stands for the service: a release never asks it)
            let service: Arc<dyn StorageDriver> = Arc::new(make("service"));
            let local = Arc::new(make("local"));
            let phase = LazyPhase::new(service, local.clone());
            Copy {
                _dir: dir,
                phase,
                local,
                db,
                store,
            }
        }

        fn file(n: u32) -> String {
            format!("{n:064x}")
        }

        fn key(n: u32) -> LayerKey {
            LayerKey::Toc(format!("sha256:{n:064x}").parse().unwrap())
        }

        impl Copy {
            fn object(&self, n: u32) -> std::path::PathBuf {
                self.store
                    .local_path(&format!("fsverity-sha256-12:{}", file(n)))
                    .unwrap()
            }

            fn image(&self, n: u32) -> std::path::PathBuf {
                cfs::layer_image_path(self.store.root(), &key(n).file_stem())
            }

            fn index(&self, n: u32) -> std::path::PathBuf {
                cfs::layer_index_path(self.store.root(), &key(n).file_stem())
            }

            /// The layer `n` with the files `files` (named by number): its
            /// row, its objects and its image, as a completion leaves them.
            async fn layer(&self, n: u32, files: &[u32]) -> LayerRecord {
                let entries: Vec<serde_json::Value> = files
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "name": format!("f{f}"), "type": "reg", "size": 4,
                            "fsverity": format!("sha256-12:{}", file(*f)),
                        })
                    })
                    .collect();
                let toc = serde_json::json!({"version": 1, "entries": entries}).to_string();
                let record = LayerRecord {
                    stream_size: Some(0),
                    key: key(n),
                    blob: Some(format!("sha256:{:064x}", n + 1000).parse().unwrap()),
                    diff_id: None,
                    other_diff_id: None,
                    size: 1,
                    status: "ready".into(),
                    created_at: String::new(),
                    registry_ref: None,
                    erofs: Some("sha256:ee".into()),
                    owners: None,
                };
                self.db
                    .insert_layer_with_toc(&record, &zstd::encode_all(toc.as_bytes(), 3).unwrap())
                    .await
                    .unwrap();
                for f in files {
                    let path = self.object(*f);
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(path, b"data").unwrap();
                }
                for p in [self.image(n), self.index(n)] {
                    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                    std::fs::write(p, b"image").unwrap();
                }
                record
            }

            fn writable(&self, id: &str) -> Writable {
                Writable::new(
                    id,
                    self.store.root().parent().unwrap().join("bundles").join(id),
                )
            }

            async fn release(
                &self,
                layers: &[u32],
                containers: &[&str],
                pulling: &[u32],
                files: &[u32],
            ) -> DriverResult<Collected> {
                let layers: Vec<LayerKey> = layers.iter().map(|n| key(*n)).collect();
                self.phase
                    .release_engine_copies(
                        &layers,
                        &EngineHeld {
                            containers: containers.iter().map(|c| c.to_string()).collect(),
                            layers: pulling.iter().map(|n| key(*n)).collect(),
                            files: files
                                .iter()
                                .map(|f| format!("fsverity-sha256-12:{}", file(*f)))
                                .collect(),
                        },
                    )
                    .await
            }
        }

        const C1: &str = "c1";

        /// Nothing holds the copy: the objects go, then the index and the
        /// image; the row of the layer stays, as for an eager layer.
        #[tokio::test]
        async fn a_copy_nothing_holds_is_dropped() {
            let c = copy().await;
            c.layer(1, &[10, 11]).await;
            let out = c.release(&[1], &[], &[], &[]).await.unwrap();
            assert!(out.bytes_freed > 0 && out.errors.is_empty(), "{out:?}");
            assert!(!c.object(10).exists() && !c.object(11).exists());
            assert!(!c.image(1).exists() && !c.index(1).exists());
            assert!(c.db.get_own_layer(&key(1)).await.is_ok(), "the row stays");
        }

        /// A container whose root the engine serves holds the layers of its
        /// image as long as it exists; its removal lets them go.  (Mutation:
        /// a release that does not read the pins drops the copy under a
        /// running container and fails this test.)
        #[tokio::test]
        async fn a_container_the_engine_serves_holds_the_copy_until_it_is_removed() {
            let c = copy().await;
            let record = c.layer(1, &[10]).await;
            let w = c.writable(C1);
            c.phase.pin(&w, &[record]).unwrap();
            c.release(&[1], &[C1], &[], &[]).await.unwrap();
            assert!(
                c.object(10).exists() && c.image(1).exists(),
                "held by the pin"
            );
            c.phase.unpin(&w).unwrap();
            c.release(&[1], &[C1], &[], &[]).await.unwrap();
            assert!(
                !c.object(10).exists() && !c.image(1).exists(),
                "free after it"
            );
        }

        /// One of two containers is removed: the other still holds the copy.
        #[tokio::test]
        async fn the_last_of_the_containers_lets_the_copy_go() {
            let c = copy().await;
            let record = c.layer(1, &[10]).await;
            let (a, b) = (c.writable("a"), c.writable("b"));
            c.phase.pin(&a, std::slice::from_ref(&record)).unwrap();
            c.phase.pin(&b, &[record]).unwrap();
            c.phase.unpin(&a).unwrap();
            c.release(&[1], &["a", "b"], &[], &[]).await.unwrap();
            assert!(c.image(1).exists(), "b holds it");
            c.phase.unpin(&b).unwrap();
            c.release(&[1], &["a", "b"], &[], &[]).await.unwrap();
            assert!(!c.image(1).exists());
        }

        /// A pin of a container that does not exist (a create that died after
        /// the pin) holds nothing, and goes.
        #[tokio::test]
        async fn a_pin_of_a_container_that_does_not_exist_holds_nothing() {
            let c = copy().await;
            let record = c.layer(1, &[10]).await;
            let w = c.writable(C1);
            c.phase.pin(&w, &[record]).unwrap();
            c.release(&[1], &[], &[], &[]).await.unwrap();
            assert!(!c.image(1).exists() && !c.phase.pin_path(&w).unwrap().exists());
        }

        /// A pull in progress holds its layers (a container can still be made
        /// on them) and the files they name, a layer that no pull holds can
        /// go while a file of it stays.
        #[tokio::test]
        async fn a_pull_in_progress_holds_its_layers_and_files() {
            let c = copy().await;
            c.layer(1, &[10]).await;
            c.layer(2, &[20, 21]).await;
            c.release(&[1, 2], &[], &[1], &[21]).await.unwrap();
            assert!(
                c.image(1).exists() && c.object(10).exists(),
                "the pulled layer"
            );
            assert!(!c.image(2).exists(), "the other goes");
            assert!(c.object(21).exists(), "a file a pull names stays");
            assert!(!c.object(20).exists());
        }

        /// A file that a layer that stays names too stays.
        #[tokio::test]
        async fn a_file_of_a_layer_that_stays_is_not_dropped() {
            let c = copy().await;
            let record = c.layer(2, &[11, 12]).await;
            c.layer(1, &[10, 11]).await;
            c.phase.pin(&c.writable(C1), &[record]).unwrap();
            c.release(&[1, 2], &[C1], &[], &[]).await.unwrap();
            assert!(!c.image(1).exists() && !c.object(10).exists());
            assert!(c.object(11).exists(), "layer 2 names it");
            assert!(c.image(2).exists() && c.object(12).exists());
        }

        /// A pin that cannot be read holds everything: nothing is dropped and
        /// the release says why.
        #[tokio::test]
        async fn a_pin_that_cannot_be_read_drops_nothing() {
            let c = copy().await;
            c.layer(1, &[10]).await;
            std::fs::create_dir_all(&c.phase.pins).unwrap();
            std::fs::write(c.phase.pins.join(C1), "not a layer key\n").unwrap();
            let e = c.release(&[1], &[C1], &[], &[]).await.unwrap_err();
            assert!(e.to_string().contains("no layer key"), "{e}");
            assert!(c.object(10).exists() && c.image(1).exists());
        }

        /// A layer that stays whose table of contents cannot be read: the
        /// files it names are not known, so nothing is dropped.  (Mutation:
        /// a release that skips such a layer removes a file the pinned
        /// container reads.)
        #[tokio::test]
        async fn a_layer_that_stays_with_no_readable_toc_drops_nothing() {
            let c = copy().await;
            let mut kept = c.layer(1, &[10, 11]).await;
            kept.key = key(2);
            c.db.insert_layer_with_toc(&kept, &zstd::encode_all(&b"{"[..], 3).unwrap())
                .await
                .unwrap();
            c.phase.pin(&c.writable(C1), &[kept]).unwrap();
            let e = c.release(&[1], &[C1], &[], &[]).await.unwrap_err();
            assert!(e.to_string().contains("table of contents"), "{e}");
            assert!(c.object(10).exists() && c.object(11).exists() && c.image(1).exists());
        }

        /// A layer with no image of the engine's is not a copy the release
        /// made: its files stay (they are the collection's).
        #[tokio::test]
        async fn a_layer_with_no_image_of_the_engine_is_not_touched() {
            let c = copy().await;
            c.layer(1, &[10]).await;
            std::fs::remove_file(c.image(1)).unwrap();
            c.release(&[1], &[], &[], &[]).await.unwrap();
            assert!(c.object(10).exists());
        }

        /// The release stopped after any number of removals (the process
        /// killed between two): the next release finishes, and a third has
        /// nothing to do.  The image goes last, so a layer with files of the
        /// engine is always found again.
        #[tokio::test]
        async fn a_release_that_stopped_anywhere_is_finished_by_the_next() {
            // the removals of the release, in order: the objects, the index,
            // the image
            let steps = 4;
            for done in 0..=steps {
                let c = copy().await;
                c.layer(1, &[10, 11]).await;
                let order = [c.object(10), c.object(11), c.index(1), c.image(1)];
                for gone in &order[..done] {
                    std::fs::remove_file(gone).unwrap();
                }
                if done < steps {
                    assert!(c.image(1).exists(), "the image is the last to go");
                }
                let first = c.release(&[1], &[], &[], &[]).await.unwrap();
                assert!(first.errors.is_empty(), "stopped after {done}: {first:?}");
                for p in &order {
                    assert!(!p.exists(), "stopped after {done}: {} is left", p.display());
                }
                let again = c.release(&[1], &[], &[], &[]).await.unwrap();
                assert_eq!(again.bytes_freed, 0);
            }
        }

        /// An object that cannot be removed keeps the image of its layer: the
        /// image says that the layer has files of the engine, so the next
        /// release finds the layer again and finishes.
        #[tokio::test]
        async fn an_object_that_cannot_be_removed_keeps_the_image_that_finds_it_again() {
            let c = copy().await;
            c.layer(1, &[10, 11]).await;
            // (a directory in the place of an object: removing it fails)
            std::fs::remove_file(c.object(11)).unwrap();
            std::fs::create_dir_all(c.object(11).join("sub")).unwrap();
            let out = c.release(&[1], &[], &[], &[]).await.unwrap();
            assert!(!out.errors.is_empty(), "{out:?}");
            assert!(
                c.image(1).exists() && c.index(1).exists(),
                "the layer is found again"
            );
            std::fs::remove_dir_all(c.object(11)).unwrap();
            let out = c.release(&[1], &[], &[], &[]).await.unwrap();
            assert!(out.errors.is_empty(), "{out:?}");
            assert!(!c.image(1).exists() && !c.object(10).exists());
        }

        /// The names of the containers are file names: nothing else is a pin.
        #[tokio::test]
        async fn a_pin_has_the_name_of_a_container() {
            let c = copy().await;
            for bad in ["", ".", "..", "a/b", "../x", ".hidden"] {
                assert!(
                    c.phase.pin(&Writable::new(bad, "/nowhere"), &[]).is_err(),
                    "{bad:?}"
                );
            }
            // (and the layer first, the pin after, remove the pin of a
            // container that was never pinned: no error)
            c.phase.unpin(&c.writable("never")).unwrap();
        }

        /// The create of a container on a lazy image pins before the writable
        /// layer is made, and the removal of the layer takes the pin away.
        #[tokio::test]
        async fn the_writable_layer_of_a_lazy_root_is_pinned_and_unpinned() {
            let c = copy().await;
            let record = c.layer(1, &[10]).await;
            let w = c.writable(C1);
            let image = ImageRecord {
                id: "i".repeat(64),
                manifest_digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
                config_digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
                manifest: String::new(),
                config: String::new(),
                created_at: String::new(),
                is_lazy: true,
            };
            let layers = [record];
            let ask = MountRequest {
                container: &w,
                purpose: velarx_graph::Purpose::Root,
                image: &image,
                layers: &layers,
                mapping: None,
                translate: None,
                idmap_mount: false,
                label: None,
                verity: velarx_graph::VerityAsk::Off,
                volatile: false,
            };
            // (the plan of the root needs more than a test has; the layer
            // and its pin are made before it)
            let _ = c
                .phase
                .writable_create(&w, None, &WritableOptions::default(), Some(&ask));
            assert!(c.phase.pin_path(&w).unwrap().exists(), "pinned");
            assert!(c.local.writable_exists(&w).unwrap(), "the engine's layer");
            c.phase.writable_remove(&w).unwrap();
            assert!(!c.phase.pin_path(&w).unwrap().exists(), "unpinned");
            assert!(!c.local.writable_exists(&w).unwrap());
        }
    }

    /// The layers come as zstd:chunked blobs of a registry.
    mod chunked {
        use super::*;
        conformance_suite!(factory(true, lazy));
    }

    /// The layers come as archives read whole.
    mod whole {
        use super::*;
        conformance_suite!(factory(false, lazy));
    }
}
