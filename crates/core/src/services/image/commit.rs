// SPDX-License-Identifier: Apache-2.0
//! Images made of the changes in a directory on top of another image: the
//! commit of a container and the steps of a build.
//!
//! The changes (the writable layer of a container, read through its storage
//! driver, or a directory a build step filled) become a tar stream
//! (`StorageDriver::diff`, `layer::dirtar`), the layer writer compresses it
//! into a blob of the staging area, and the blob is installed like a layer
//! of an archive: decompressed, checked against its digest and diff id, and
//! stored with its tar-split.  The parent's layers are shared.

use super::archive::{archive_tag, local_reference};
use super::meter::{Meter, Subject};
use super::pull::Incoming;
use super::*;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use velarx_content::layer::dirtar;
use velarx_content::pull::net::Net;
use velarx_content::pull::stored::stored_tocs;

const MEDIA_TYPE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const MEDIA_TYPE_CONFIG: &str = "application/vnd.oci.image.config.v1+json";

/// An edit of the `config` object of an image configuration.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum ConfigEdit {
    /// Replace a setting (`Cmd`, `User`...).
    Set(String, Value),
    /// Remove a setting (an ENTRYPOINT resets the CMD of the base image).
    Unset(String),
    /// Add the keys of an object (`Labels`, `ExposedPorts`, `Volumes`).
    Merge(String, Map<String, Value>),
    /// Set environment variables, replacing the ones of the same name.
    Env(Vec<(String, String)>),
    /// Remove environment variables by name.
    UnsetEnv(Vec<String>),
    /// Remove keys of an object (`Labels`).
    Remove(String, Vec<String>),
}

impl ConfigEdit {
    pub(crate) fn apply(&self, c: &mut Map<String, Value>) {
        match self {
            Self::Set(k, v) => {
                c.insert(k.clone(), v.clone());
            }
            Self::Unset(k) => {
                c.remove(k);
            }
            Self::Merge(k, values) => {
                let entry = c.entry(k.clone()).or_insert_with(|| json!({}));
                if !entry.is_object() {
                    *entry = json!({});
                }
                if let Some(o) = entry.as_object_mut() {
                    for (key, value) in values {
                        o.insert(key.clone(), value.clone());
                    }
                }
            }
            Self::UnsetEnv(names) => {
                if let Some(env) = c.get_mut("Env").and_then(Value::as_array_mut) {
                    env.retain(|e| {
                        !e.as_str().is_some_and(|e| {
                            names.iter().any(|n| {
                                e.strip_prefix(n.as_str())
                                    .is_some_and(|r| r.starts_with('='))
                            })
                        })
                    });
                }
            }
            Self::Remove(k, keys) => {
                if let Some(o) = c.get_mut(k).and_then(Value::as_object_mut) {
                    for key in keys {
                        o.remove(key);
                    }
                }
            }
            Self::Env(vars) => {
                let entry = c.entry("Env").or_insert_with(|| json!([]));
                if !entry.is_array() {
                    *entry = json!([]);
                }
                let Some(env) = entry.as_array_mut() else {
                    return;
                };
                for (key, value) in vars {
                    let prefix = format!("{key}=");
                    let new = json!(format!("{key}={value}"));
                    match env
                        .iter_mut()
                        .find(|e| e.as_str().is_some_and(|e| e.starts_with(&prefix)))
                    {
                        Some(old) => *old = new,
                        None => env.push(new),
                    }
                }
            }
        }
    }
}

/// What goes in a committed image besides the files.
#[derive(Debug, Clone)]
pub struct CommitOptions {
    /// Edits of the configuration, applied first (the settings of the
    /// container, the instructions of a build).
    pub edits: Vec<ConfigEdit>,
    /// Dockerfile instructions (`--change`), applied after the edits.
    pub changes: Vec<String>,
    pub author: Option<String>,
    pub message: Option<String>,
    /// The `created_by` of the history entry.
    pub created_by: String,
    /// The algorithm of the digests the commit makes (layer blob, diff id,
    /// configuration, manifest, annotations).  None: that of the parent
    /// image, or SHA-256 without one.
    pub digest: Option<Algorithm>,
    /// The names to give the image (`localhost/` when they have no
    /// registry).
    pub names: Vec<String>,
    /// How the directory is read.
    pub walk: dirtar::Options,
    /// A lease that takes the new image before it is recorded (the
    /// intermediate images of a build: a prune does not remove them).
    pub lease: Option<String>,
    /// The platform of the image (that of the parent, or of this host,
    /// if none): what a build for a platform makes.
    pub platform: Option<velarx_registry::target::Platform>,
    /// Where the progress of the layer goes, if anyone watches.
    pub progress: Option<mpsc::Sender<TransferProgress>>,
    /// The layers of the parent are replaced by one layer of its merged
    /// tree with the directory applied (`build --squash-all`,
    /// `commit --squash`), and the history is the one entry of the new
    /// layer.
    pub squash_all: bool,
    /// The layer stops being made, with an error, once this is asked.
    pub cancel: crate::services::Cancel,
    /// The time of the image and of its history entry (RFC 3339); absent:
    /// the time of the commit.
    pub created: Option<String>,
    /// No history: the entries of the parent are dropped too.
    pub omit_history: bool,
    /// The annotations of the manifest.
    pub annotations: HashMap<String, String>,
    /// Fields of the configuration set at its top (`os.version`); null
    /// removes one.
    pub config_root: Vec<(String, Value)>,
}

impl Default for CommitOptions {
    fn default() -> Self {
        Self {
            edits: Vec::new(),
            changes: Vec::new(),
            author: None,
            message: None,
            created_by: "velarx commit".into(),
            digest: None,
            names: Vec::new(),
            walk: dirtar::Options::default(),
            lease: None,
            platform: None,
            progress: None,
            squash_all: false,
            cancel: Default::default(),
            created: None,
            omit_history: false,
            annotations: HashMap::new(),
            config_root: Vec::new(),
        }
    }
}

/// What the layer of a commit is made of.
#[derive(Clone)]
pub enum Changes {
    /// A directory of files (what a build step filled): read as it is, with
    /// the options of the commit.
    Dir(PathBuf),
    /// The writable layer of a container, read by its storage driver.
    Writable(crate::storage_driver::WritableDiff),
}

impl Changes {
    /// The directory of the changes and how to walk it, for what reads the
    /// changes as a directory (the squash: `commit --squash`); what it takes
    /// to make one goes to `scratch`.
    fn directory(
        &self,
        walk: &dirtar::Options,
        scratch: &Path,
    ) -> std::io::Result<crate::storage_driver::ChangesDir> {
        match self {
            Self::Dir(d) => Ok(crate::storage_driver::ChangesDir::of(
                d.clone(),
                walk.clone(),
            )),
            Self::Writable(w) => w.directory(walk, scratch),
        }
    }
}

/// A layer as it was made: its stream ingested in one pass, the files in a
/// spool, the diff id learned.  Not compressed: its blob is its stream.
struct Blob {
    made: velarx_content::pull::Made,
    size: u64,
}

/// What makes a layer in one walk, on a thread of its own: given where its
/// files are staged, the largest stream it may stand for and what is told
/// of the bytes of the stream, it gives the layer and the size of the
/// stream.
type Producer = Box<
    dyn FnOnce(
            &Arc<dyn velarx_content::pull::sink::Sink>,
            u64,
            velarx_content::pull::made::Observe<'_>,
        ) -> std::io::Result<(velarx_content::pull::stream::Ingested, u64)>
        + Send,
>;

/// What [`producer_of_tree`] makes the layer from.
struct SquashedTree<'a> {
    tree: Arc<velarx_fuse::MergedTree>,
    size: u64,
    objects: Arc<dyn velarx_storage::ObjectOpener>,
    changes: Option<Changes>,
    walk: &'a dirtar::Options,
    staging: &'a Path,
    alg: Algorithm,
    progress: Option<mpsc::Sender<TransferProgress>>,
}

/// What makes the layer of the merged tree of an image (`--squash-all`),
/// with the changes in a directory applied (`commit --squash`), its meter,
/// and what is kept until the layer is made (the directory, if one was made
/// for the changes: the squash reads the files from it).
fn producer_of_tree(
    squash: SquashedTree<'_>,
) -> std::io::Result<(Producer, Meter, Option<crate::storage_driver::ChangesDir>)> {
    use rustix::fs::{openat, Mode, OFlags};
    let SquashedTree {
        tree,
        size,
        objects,
        changes,
        walk,
        staging,
        alg,
        progress,
    } = squash;
    let dir = changes.map(|c| c.directory(walk, staging)).transpose()?;
    let upper = dir
        .as_ref()
        .map(|d| {
            let fd = openat(
                rustix::fs::CWD,
                &d.path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| {
                std::io::Error::new(e.kind(), format!("open {}: {e}", d.path.display()))
            })?;
            super::squash::Upper::record(fd, &d.walk)
        })
        .transpose()?;
    let size = size + upper.as_ref().map_or(Ok(0), |u| u.len())?;
    let meter = Meter::new(progress, Subject::Made("squashed layer"), "squashing", size);
    let produce: Producer = Box::new(move |sink, max, observe| {
        velarx_content::pull::made::from_walk(sink, alg, max, observe, |out| {
            super::squash::write_tree(&tree, &*objects, upper.as_ref(), out)
        })
    });
    Ok((produce, meter, dir))
}

impl ImageService {
    /// The layer of the changes: the directory is walked once, and that walk
    /// stages each file, builds the table of contents and learns the diff
    /// id (the tar stream it stands for is hashed as it goes, never made).
    async fn layer_of_changes(
        &self,
        changes: Changes,
        walk: &dirtar::Options,
        alg: Algorithm,
        meter: Meter,
        cancel: crate::services::Cancel,
    ) -> ImageResult<Blob> {
        let (walk, staging) = (walk.clone(), self.staging_dir.clone());
        let produce: Producer = Box::new(move |sink, max, observe| {
            let dir = changes.directory(&walk, &staging)?;
            let fd = rustix::fs::openat(
                rustix::fs::CWD,
                &dir.path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| {
                std::io::Error::new(e.kind(), format!("open {}: {e}", dir.path.display()))
            })?;
            velarx_content::pull::made::from_dir(
                rustix::fd::AsFd::as_fd(&fd),
                &dir.walk,
                sink,
                alg,
                max,
                observe,
            )
        });
        self.layer_made(produce, meter, cancel).await
    }

    /// The layer `produce` makes in one walk: its files staged in a session
    /// of the store, its table of contents, tar-split and diff id learned
    /// in the same pass.
    async fn layer_made(
        &self,
        produce: Producer,
        meter: Meter,
        cancel: crate::services::Cancel,
    ) -> ImageResult<Blob> {
        use velarx_content::pull::Limits;
        std::fs::create_dir_all(&self.staging_dir)?;
        let session = velarx_content::pull::session::Session::create(
            &self.staging_dir,
            self.file_store.clone(),
        )?;
        let max = Limits::from_config(&self.pull_config).max_layer_bytes;
        let sink: Arc<dyn velarx_content::pull::sink::Sink> = session.clone();
        let made = tokio::task::spawn_blocking(move || {
            let mut meter = meter;
            // (what makes the layer may walk the table of contents of an
            // image by recursion: the stack of a walk, not the default one)
            std::thread::scope(|scope| {
                std::thread::Builder::new()
                    .name("commit-walk".into())
                    .stack_size(velarx_base::walk::WALK_STACK)
                    .spawn_scoped(scope, || {
                        produce(
                            &sink,
                            max,
                            Box::new(|n| {
                                cancel.check()?;
                                meter.add(n);
                                Ok(())
                            }),
                        )
                        .map(|r| (r, meter))
                    })?
                    .join()
                    .map_err(|_| std::io::Error::other("the walk of the directory panicked"))?
            })
        })
        .await
        .map_err(|e| ImageError::Layer(e.to_string()))?
        .map_err(|e| ImageError::Layer(format!("cannot make the layer: {e}")))?;
        let ((ingested, size), meter) = made;
        meter.end(true);
        Ok(Blob {
            made: velarx_content::pull::Made { session, ingested },
            size,
        })
    }
}

/// The time stamps of the configuration.
fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// The configuration of the new image: the parent's (or an empty one), the
/// edits and changes, one more diff id and one more history entry.
pub(super) fn new_config(
    parent: Option<&str>,
    opts: &CommitOptions,
    diff_id: Option<&str>,
) -> ImageResult<Value> {
    let mut config: Value = match parent {
        Some(p) => serde_json::from_str(p)?,
        None => json!({
            "architecture": velarx_registry::target::host_arch(),
            "os": "linux",
            "config": {},
        }),
    };
    let root = config
        .as_object_mut()
        .ok_or_else(|| ImageError::Manifest("the configuration is not an object".into()))?;
    for (k, v) in &opts.config_root {
        if v.is_null() {
            root.remove(k);
        } else {
            root.insert(k.clone(), v.clone());
        }
    }
    let created = opts.created.clone().unwrap_or_else(now);
    root.insert("created".into(), json!(created));
    // Fields of the Docker format that describe another container.
    root.remove("container");
    root.remove("container_config");
    {
        let entry = root.entry("config").or_insert_with(|| json!({}));
        if !entry.is_object() {
            *entry = json!({});
        }
        if let Some(c) = entry.as_object_mut() {
            for edit in &opts.edits {
                edit.apply(c);
            }
        }
    }
    for change in &opts.changes {
        changes::apply(&mut config, change).map_err(ImageError::Manifest)?;
    }
    let root = config
        .as_object_mut()
        .ok_or_else(|| ImageError::Manifest("the configuration is not an object".into()))?;
    if let Some(author) = &opts.author {
        root.insert("author".into(), json!(author));
    }
    if let Some(p) = &opts.platform {
        root.insert("os".into(), json!(p.os));
        root.insert("architecture".into(), json!(p.arch));
        match &p.variant {
            Some(v) => root.insert("variant".into(), json!(v)),
            None => root.remove("variant"),
        };
    }

    if opts.squash_all {
        root.remove("history");
        root.remove("rootfs");
    }
    if opts.omit_history {
        root.remove("history");
    }
    let rootfs = root.entry("rootfs").or_insert_with(|| json!({}));
    if !rootfs.is_object() {
        *rootfs = json!({});
    }
    if let Some(r) = rootfs.as_object_mut() {
        r.insert("type".into(), json!("layers"));
        let ids = r.entry("diff_ids").or_insert_with(|| json!([]));
        if !ids.is_array() {
            *ids = json!([]);
        }
        if let (Some(ids), Some(d)) = (ids.as_array_mut(), diff_id) {
            ids.push(json!(d));
        }
    }

    let mut h = Map::new();
    h.insert("created".into(), json!(created));
    h.insert("created_by".into(), json!(opts.created_by));
    if let Some(a) = &opts.author {
        h.insert("author".into(), json!(a));
    }
    if let Some(m) = opts.message.as_ref().filter(|m| !m.is_empty()) {
        h.insert("comment".into(), json!(m));
    }
    if diff_id.is_none() {
        h.insert("empty_layer".into(), json!(true));
    }
    if opts.omit_history {
        return Ok(config);
    }
    let history = root.entry("history").or_insert_with(|| json!([]));
    if !history.is_array() {
        *history = json!([]);
    }
    if let Some(list) = history.as_array_mut() {
        list.push(Value::Object(h));
    }
    Ok(config)
}

impl ImageService {
    /// A lease named `name` of this process, which holds nothing yet.
    pub async fn take_lease(&self, name: &str) -> ImageResult<velarx_db::Lease> {
        Ok(velarx_db::Lease::take_items(&self.db, name, Vec::new()).await?)
    }

    /// The image the build cache has for a step of key `key` on `parent`
    /// (an image id, or [`velarx_db::BUILD_SCRATCH`]), taken by the lease
    /// `lease` first so that a prune leaves it alone.
    pub async fn build_cache_get(
        &self,
        parent: &str,
        key: &str,
        lease: &str,
    ) -> ImageResult<Option<String>> {
        let Some(id) = self.db.build_cache_get(parent, key).await? else {
            return Ok(None);
        };
        self.db
            .add_lease_items(
                lease,
                vec![(velarx_db::LEASE_IMAGE.to_string(), id.clone())],
            )
            .await?;
        // Removed before the lease took it: not in the cache any more.
        match self.db.get_image(&id).await {
            Ok(_) => Ok(Some(id)),
            _ => Ok(None),
        }
    }

    /// The image each image a build made was built on, by id
    /// ([`velarx_db::BUILD_SCRATCH`] for the ones built from scratch).
    pub async fn build_lineage(&self) -> ImageResult<std::collections::HashMap<String, String>> {
        Ok(self.db.build_lineage().await?)
    }

    /// The intermediate images of the builds: those without a name that
    /// other images were built on.
    pub async fn intermediate_images(&self) -> ImageResult<std::collections::HashSet<String>> {
        let mut out = std::collections::HashSet::new();
        for parent in self.db.build_lineage().await?.into_values() {
            if parent != velarx_db::BUILD_SCRATCH
                && !out.contains(&parent)
                && !self.db.image_is_named(&parent).await?
            {
                out.insert(parent);
            }
        }
        Ok(out)
    }

    /// Remove the images the builds made that nothing uses: without a
    /// name, a container, a build in progress or an image built on them.
    /// Returns their ids and the bytes of their layers.
    pub async fn prune_build_cache(&self) -> ImageResult<(Vec<String>, u64)> {
        let (mut deleted, mut space) = (Vec::new(), 0u64);
        loop {
            let lineage = self.db.build_lineage().await?;
            let parents: std::collections::HashSet<&String> = lineage.values().collect();
            let mut removed = false;
            for id in lineage.keys().filter(|id| !parents.contains(id)) {
                if self.db.image_is_named(id).await?
                    || self.db.image_has_containers(id).await?
                    || self.db.is_leased(velarx_db::LEASE_IMAGE, id).await?
                {
                    continue;
                }
                let size: i64 = self
                    .db
                    .get_image_layers(id)
                    .await?
                    .iter()
                    .map(|l| l.size)
                    .sum();
                self.remove(id, true).await?;
                deleted.push(id.clone());
                space += size.max(0) as u64;
                removed = true;
            }
            if !removed {
                return Ok((deleted, space));
            }
        }
    }

    /// Record the image a step of key `key` made on `parent`.
    pub async fn build_cache_put(&self, parent: &str, key: &str, id: &str) -> ImageResult<()> {
        Ok(self.db.build_cache_put(parent, key, id).await?)
    }

    /// Name an image; a name without a registry is `localhost/NAME`.
    pub async fn tag_local(&self, source: &str, name: &str) -> ImageResult<()> {
        let local = local_reference(name)?;
        ImageReference::parse(&local)?.validate()?;
        self.tag(source, &local).await
    }

    /// The merged tree of the layers of an image and the bytes of its
    /// regular files.
    async fn merged_tree_of(
        &self,
        image_id: &str,
    ) -> ImageResult<(Arc<velarx_fuse::MergedTree>, u64)> {
        let layers = self.db.get_image_layers(image_id).await?;
        let tocs = stored_tocs(&self.db, &layers.iter().map(|l| l.key).collect::<Vec<_>>()).await?;
        tokio::task::spawn_blocking(move || {
            let tree = velarx_fuse::MergedTree::build(&tocs.iter().collect::<Vec<_>>())
                .map_err(ImageError::Layer)?;
            let size = (0..tree.count())
                .filter_map(|i| tree.node(i))
                .filter(|n| n.entry.entry_type == TocEntryType::Reg)
                .map(|n| n.entry.size)
                .sum();
            Ok((Arc::new(tree), size))
        })
        .await
        .map_err(|e| ImageError::Layer(e.to_string()))?
    }

    /// Commit the changes in `dir` (none: the configuration only) on top of
    /// the image `parent` (none: an image of its own).  Returns the id of
    /// the new image.
    pub async fn commit_dir(
        &self,
        parent: Option<&str>,
        dir: Option<&Path>,
        opts: &CommitOptions,
    ) -> ImageResult<String> {
        self.commit_changes(parent, dir.map(|d| Changes::Dir(d.to_path_buf())), opts)
            .await
    }

    /// Commit the `changes` (none: the configuration only) on top of the
    /// image `parent` (none: an image of its own).  Returns the id of the new
    /// image.
    pub async fn commit_changes(
        &self,
        parent: Option<&str>,
        changes: Option<Changes>,
        opts: &CommitOptions,
    ) -> ImageResult<String> {
        // Nothing the commit reads or adds can be collected meanwhile.
        let _store = self.lock_store().await?;
        let mut names = Vec::new();
        for name in opts.names.iter().filter(|n| !n.is_empty()) {
            let local = local_reference(name)?;
            ImageReference::parse(&local)?.validate()?;
            names.push(local);
        }
        // The changes are checked before the directory is read.
        new_config(None, opts, None)?;
        let parent = match parent {
            Some(p) => Some(self.get(p).await?),
            None => None,
        };
        let alg = opts
            .digest
            .or_else(|| parent.as_ref().map(|p| p.manifest_digest.alg()))
            .unwrap_or(Algorithm::Sha256);
        self.check_digest_algorithm(alg)?;
        let mut layers = Vec::new();
        // the layers of the parent, as its record has them (a layer of a
        // TOC, or one of a blob that a pull of a labelled descriptor took
        // whole)
        let mut recorded = Vec::new();
        let mut tree = None;
        if let Some(image) = &parent {
            let manifest: OciManifest = serde_json::from_str(&image.manifest)?;
            let config: OciConfig = serde_json::from_str(&image.config)?;
            recorded = self
                .db
                .get_image_layers(&image.id)
                .await?
                .into_iter()
                .map(|l| l.key)
                .collect::<Vec<_>>();
            // The layers are shared: they must all be stored.
            let stored = self.stored_layers(&recorded, &config).await?;
            if recorded.len() != manifest.layers.len() || stored.iter().any(|ok| !ok) {
                return Err(ImageError::Layer(format!(
                    "the image {} is not complete: pull it again before committing on top of it",
                    image.id
                )));
            }
            if opts.squash_all {
                tree = Some(self.merged_tree_of(&image.id).await?);
                recorded.clear();
            } else {
                // (an image pulled in the Docker format is committed as OCI)
                layers = manifest.layers;
                for l in &mut layers {
                    l.media_type = velarx_types::docker::as_oci(&l.media_type).to_string();
                }
            }
        }

        let blob = match (changes, tree) {
            (changes, Some((tree, size))) => {
                let (objects, staging) = (Arc::new(self.objects()), self.staging_dir.clone());
                let (walk, progress, cancel) = (
                    opts.walk.clone(),
                    opts.progress.clone(),
                    opts.cancel.clone(),
                );
                let (produce, meter, dir) = tokio::task::spawn_blocking(move || {
                    producer_of_tree(SquashedTree {
                        tree,
                        size,
                        objects,
                        changes,
                        walk: &walk,
                        staging: &staging,
                        alg,
                        progress,
                    })
                })
                .await
                .map_err(|e| ImageError::Layer(e.to_string()))?
                .map_err(|e| ImageError::Layer(format!("cannot make the squashed layer: {e}")))?;
                let blob = self.layer_made(produce, meter, cancel).await;
                drop(dir);
                Some(blob?)
            }
            (Some(changes), None) => {
                let cancel = opts.cancel.clone();
                let walk = opts.walk.clone();
                let meter = Meter::new(
                    opts.progress.clone(),
                    Subject::Made("new layer"),
                    "streaming",
                    0,
                );
                Some(
                    self.layer_of_changes(changes, &walk, alg, meter, cancel)
                        .await?,
                )
            }
            (None, None) => None,
        };

        let new_diff_id = blob.as_ref().map(|b| b.made.ingested.diff_id.to_string());
        let config = new_config(
            parent.as_ref().map(|p| p.config.as_str()),
            opts,
            new_diff_id.as_deref(),
        )?;
        let config_bytes = serde_json::to_vec(&config)?;
        if layers.is_empty() && blob.is_none() {
            return Err(ImageError::Layer(
                "nothing to commit without a parent image and a directory".into(),
            ));
        }
        let mut made = Vec::new();
        if let Some(b) = blob {
            // (a layer that is not compressed: its blob is its stream)
            layers.push(OciDescriptor {
                media_type: velarx_content::archive::LAYER.to_string(),
                digest: b.made.ingested.diff_id,
                size: b.size as i64,
                annotations: HashMap::new(),
            });
            made.push(Arc::new(b.made));
        }
        let manifest = OciManifest {
            schema_version: 2,
            media_type: Some(MEDIA_TYPE_MANIFEST.into()),
            config: OciDescriptor {
                media_type: MEDIA_TYPE_CONFIG.into(),
                digest: Digest::of(alg, &config_bytes),
                size: config_bytes.len() as i64,
                annotations: HashMap::new(),
            },
            layers,
            annotations: opts.annotations.clone(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_digest = Digest::of(alg, &manifest_bytes);
        // the id of the image is the digest of its configuration: it holds
        // the diff ids, whatever the compression of the layers is when they
        // are pushed
        let image_id = self
            .db
            .image_id_for(&manifest_digest, &manifest.config.digest)
            .await?;
        let tags = names
            .iter()
            .filter_map(|n| archive_tag(n, &image_id).map(|(_, t)| t))
            .collect();
        let incoming = Incoming {
            config: serde_json::from_slice(&config_bytes)?,
            manifest,
            manifest_bytes: Bytes::from(manifest_bytes),
            manifest_digest,
            config_bytes: Bytes::from(config_bytes),
            source: None,
            via: None,
            made,
            registry_ref: None,
            tags,
            digest_names: Vec::new(),
            lazy: false,
            sources: None,
            reach: Default::default(),
            seal: true,
            states: true,
            // leased before it is recorded, under the store lock: there is
            // no time when a prune could take it
            lease: opts.lease.clone(),
            pulled: Vec::new(),
            indexes: Vec::new(),
            access: None,
            recorded,
        };
        let progress = match &opts.progress {
            Some(tx) => tx.clone(),
            None => {
                let (progress, mut rx) = mpsc::channel(8);
                tokio::spawn(async move { while rx.recv().await.is_some() {} });
                progress
            }
        };
        let net = Net::offline();
        let result = self
            .install(net, incoming, progress, std::time::Instant::now())
            .await?;
        Ok(result.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_config_keeps_the_parent_and_adds_a_layer() {
        let parent = r#"{"architecture":"amd64","os":"linux","container":"x",
            "config":{"Env":["PATH=/bin","A=1"],"Cmd":["sh"],"Labels":{"a":"1"}},
            "rootfs":{"type":"layers","diff_ids":["sha256:aa"]},
            "history":[{"created_by":"base"}]}"#;
        let opts = CommitOptions {
            edits: vec![
                ConfigEdit::Env(vec![("A".into(), "2".into()), ("B".into(), "x y".into())]),
                ConfigEdit::Merge(
                    "Labels".into(),
                    [("b".to_string(), json!("2"))].into_iter().collect(),
                ),
                ConfigEdit::Unset("Cmd".into()),
                ConfigEdit::Set("Entrypoint".into(), json!(["/bin/app"])),
            ],
            changes: vec!["USER 1000".into(), "EXPOSE 80".into()],
            author: Some("me".into()),
            message: Some("msg".into()),
            created_by: "test".into(),
            ..CommitOptions::default()
        };
        let c = new_config(Some(parent), &opts, Some("sha256:bb")).unwrap();
        assert_eq!(c["config"]["Env"], json!(["PATH=/bin", "A=2", "B=x y"]));
        assert_eq!(c["config"]["Labels"], json!({"a": "1", "b": "2"}));
        assert!(c["config"].get("Cmd").is_none());
        assert_eq!(c["config"]["Entrypoint"], json!(["/bin/app"]));
        assert_eq!(c["config"]["User"], json!("1000"));
        assert_eq!(c["config"]["ExposedPorts"], json!({"80/tcp": {}}));
        assert_eq!(c["author"], json!("me"));
        assert!(c.get("container").is_none());
        assert_eq!(c["rootfs"]["diff_ids"], json!(["sha256:aa", "sha256:bb"]));
        let h = c["history"].as_array().unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[1]["created_by"], json!("test"));
        assert_eq!(h[1]["comment"], json!("msg"));
        assert!(h[1].get("empty_layer").is_none());
        // The configuration only: an empty layer in the history.
        let c = new_config(Some(parent), &CommitOptions::default(), None).unwrap();
        assert_eq!(c["rootfs"]["diff_ids"], json!(["sha256:aa"]));
        assert_eq!(c["history"][1]["empty_layer"], json!(true));
        // A bad change is an error.
        let bad = CommitOptions {
            changes: vec!["FROB x".into()],
            ..CommitOptions::default()
        };
        assert!(new_config(Some(parent), &bad, None).is_err());
    }

    #[test]
    fn test_new_config_without_parent() {
        let c = new_config(None, &CommitOptions::default(), Some("sha256:cc")).unwrap();
        assert_eq!(c["os"], json!("linux"));
        assert_eq!(
            c["rootfs"],
            json!({"type": "layers", "diff_ids": ["sha256:cc"]})
        );
    }
}
