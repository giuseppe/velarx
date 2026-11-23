// SPDX-License-Identifier: Apache-2.0
//! `system check`: whether the images of the store are whole.
//!
//! Every image is looked at: its record, its layers and their tables of
//! contents, each file its layers name (it is in the objects, of the size
//! the table says and, unless the check is quick, of the content: its
//! fs-verity digest, which names it, recomputed, and the kernel's measure
//! where the file has fs-verity), and
//! its composefs image.  The store is looked at too: objects no row knows,
//! rows of files that are gone, temporary files, pull and container
//! staging directories of nothing, leases of pulls that died.
//!
//! The images are checked under the shared lock of the store, the oldest
//! checked first, as many as the timeout leaves time for.  A repair takes the
//! exclusive lock for what it removes in the store; it makes the composefs
//! images of an image again from the tables of contents and the objects,
//! and removes the images whose objects are damaged or gone (a pull brings
//! them back), unless a container uses them.

use crate::services::ImageService;
use crate::storage_driver::Leftovers;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};
use velarx_db::Database;
use velarx_proto::system::{
    CheckAction, CheckProblem, CheckRemovedContainer, CheckReport, CheckSpec,
};
use velarx_storage::{FileStore, Object, StorageLock, TocEntryType};
use velarx_types::OciManifest;

#[derive(Error, Debug)]
pub enum CheckError {
    #[error(transparent)]
    Database(#[from] velarx_types::DbError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Image(#[from] velarx_types::ImageError),
    #[error("{0}")]
    Other(String),
}

pub type CheckResult<T> = Result<T, CheckError>;

/// How long a file the store does not account for must be unchanged to be
/// taken for a leftover and not for the work of a process that is running.
pub(crate) const LEFTOVER_GRACE: Duration = Duration::from_secs(86400);

/// What a repair does about a finding.
#[derive(Debug, Clone)]
enum Fix {
    /// Nothing can be done here.
    None,
    RemoveFile(PathBuf),
    RemoveDir(PathBuf),
    /// Forget the rows of these files, which are not in the store.
    DropRows(Vec<String>),
    /// Make the composefs images of the image again.
    Remake,
    /// Make the images of the staged layers of the pull again.
    RemakeStaged(String),
    /// Finish the pull `id`: nothing completes it.
    Complete(String),
    ReleaseLease(String),
}

/// A problem, before the repair decides what to do about it.
#[derive(Debug, Clone)]
struct Finding {
    image: Option<String>,
    name: Option<String>,
    kind: &'static str,
    message: String,
    path: Option<PathBuf>,
    fix: Fix,
    /// The image cannot be repaired from what the store has: it needs a
    /// pull.
    damaged: bool,
}

impl Finding {
    fn of_store(kind: &'static str, message: impl Into<String>, path: Option<PathBuf>) -> Self {
        Self {
            image: None,
            name: None,
            kind,
            message: message.into(),
            path,
            fix: Fix::None,
            damaged: false,
        }
    }

    fn with(mut self, fix: Fix) -> Self {
        self.fix = fix;
        self
    }

    fn into_problem(self, action: CheckAction) -> CheckProblem {
        CheckProblem {
            image: self.image,
            name: self.name,
            kind: self.kind.to_string(),
            message: self.message,
            path: self.path.map(|p| p.display().to_string()),
            action,
        }
    }
}

/// What the check of one image found.
struct Checked {
    image: velarx_db::ImageRecord,
    layers: Vec<velarx_db::LayerRecord>,
    findings: Vec<Finding>,
}

/// What reading a file found wrong with it.
type Verdict = Vec<(&'static str, String)>;

/// What the check of a run shares between the images: the verdicts on the
/// files (a file of several images is read once).
#[derive(Default)]
struct Run {
    verdicts: HashMap<String, Verdict>,
    /// The files whose object is gone, which the findings of images say.
    missing: HashSet<String>,
    files_checked: usize,
    bytes_read: u64,
}

/// The consistency checker of a store.
pub struct CheckService {
    db: Database,
    images: Arc<ImageService>,
    store: Arc<FileStore>,
    staging: PathBuf,
    grace: Duration,
    containers: Option<Arc<crate::services::ContainerService>>,
}

impl CheckService {
    /// The checker of the store whose staging directory is `staging` (the
    /// lock is next to it).
    pub fn new(
        db: Database,
        images: Arc<ImageService>,
        store: Arc<FileStore>,
        staging: PathBuf,
    ) -> Self {
        Self {
            db,
            images,
            store,
            staging,
            grace: LEFTOVER_GRACE,
            containers: None,
        }
    }

    /// The service that removes the containers of a lossy repair.
    pub fn with_containers(mut self, containers: Arc<crate::services::ContainerService>) -> Self {
        self.containers = Some(containers);
        self
    }

    /// How long a file must be unchanged to be taken for a leftover.
    pub fn with_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    fn lock_path(&self) -> PathBuf {
        StorageLock::path_of_staging(&self.staging)
    }

    /// Check the store as `req` says.
    pub async fn check(&self, req: &CheckSpec) -> CheckResult<CheckReport> {
        let started = Instant::now();
        let deadline = req.timeout_ms.map(|ms| started + Duration::from_millis(ms));
        let full = !req.quick;
        let mut report = CheckReport::default();
        let mut run = Run::default();

        let shared = StorageLock::shared(&self.lock_path()).await?;
        let mut images = self.own_images().await?;
        let times = self.db.image_check_times().await?;
        images.sort_by_key(|i| times.get(&i.id).copied().unwrap_or(0));
        report.images_total = images.len() as u64;
        let mut checked = Vec::new();
        for image in images {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                report.images_unchecked += 1;
                continue;
            }
            match self.check_image(image, full, deadline, &mut run).await? {
                Some(c) => {
                    self.db
                        .set_image_checked(&c.image.id, chrono::Utc::now().timestamp())
                        .await?;
                    report.images_checked += 1;
                    checked.push(c);
                }
                None => report.images_unchecked += 1,
            }
        }
        report.files_checked = run.files_checked as u64;
        report.bytes_read = run.bytes_read;

        if !req.repair {
            let scan = self.scan_store(&run.missing).await?;
            drop(shared);
            for c in checked {
                report.problems.extend(
                    c.findings
                        .into_iter()
                        .map(|f| f.into_problem(CheckAction::None)),
                );
            }
            report.problems.extend(
                scan.findings
                    .into_iter()
                    .map(|f| f.into_problem(CheckAction::None)),
            );
            report.elapsed_ms = started.elapsed().as_millis() as u64;
            return Ok(report);
        }
        drop(shared);
        self.repair(checked, full, req.repair_lossy, &run, &mut report)
            .await?;
        report.elapsed_ms = started.elapsed().as_millis() as u64;
        Ok(report)
    }

    /// Remove the containers of a lossy repair (a running one stays: the
    /// image is then kept too).
    async fn remove_containers(&self, ids: &[String], report: &mut CheckReport) {
        let Some(service) = &self.containers else {
            return;
        };
        for id in ids {
            let name = match self.db.get_container(id).await {
                Ok(c) => c.name.unwrap_or_default(),
                Err(_) => String::new(),
            };
            match service.delete(id, false).await {
                Ok(()) => {
                    warn!("Removed the container {id} of a damaged image");
                    report.removed_containers.push(CheckRemovedContainer {
                        id: id.clone(),
                        name,
                    });
                }
                Err(e) => warn!("Cannot remove the container {id}: {e}"),
            }
        }
    }

    /// The images of this store, not those of a read-only one.
    async fn own_images(&self) -> CheckResult<Vec<velarx_db::ImageRecord>> {
        let mut own = Vec::new();
        for image in self.db.list_images().await? {
            if self.db.read_only_store_of(&image.id).await.is_none() {
                own.push(image);
            }
        }
        Ok(own)
    }

    /// Check one image; None when the deadline came before the end.
    async fn check_image(
        &self,
        image: velarx_db::ImageRecord,
        full: bool,
        deadline: Option<Instant>,
        run: &mut Run,
    ) -> CheckResult<Option<Checked>> {
        let name = self
            .db
            .get_tags_for_image(&image.id)
            .await
            .ok()
            .and_then(|t| t.first().map(|t| format!("{}:{}", t.repository, t.tag)));
        let mut findings = Vec::new();
        let mut add = |kind: &'static str,
                       message: String,
                       path: Option<PathBuf>,
                       fix: Fix,
                       damaged: bool| {
            findings.push(Finding {
                image: Some(image.id.clone()),
                name: name.clone(),
                kind,
                message,
                path,
                fix,
                damaged,
            });
        };

        let manifest = serde_json::from_str::<serde_json::Value>(&image.manifest);
        if let Err(e) = &manifest {
            add(
                "bad_manifest",
                format!("the manifest of the image does not parse: {e}"),
                None,
                Fix::None,
                true,
            );
        }
        if let Err(e) = serde_json::from_str::<serde_json::Value>(&image.config) {
            add(
                "bad_config",
                format!("the configuration of the image does not parse: {e}"),
                None,
                Fix::None,
                true,
            );
        }
        let layers = match self.db.get_image_layers(&image.id).await {
            Ok(layers) => {
                if let Some(listed) = manifest
                    .ok()
                    .and_then(|m| m.get("layers").and_then(|l| l.as_array()).map(|l| l.len()))
                {
                    if listed != layers.len() {
                        add(
                            "layer_count",
                            format!(
                                "the manifest lists {listed} layers, the image has {}",
                                layers.len()
                            ),
                            None,
                            Fix::None,
                            true,
                        );
                    }
                }
                layers
            }
            Err(e) => {
                add(
                    "bad_toc",
                    format!("the layers of the image cannot be read: {e}"),
                    None,
                    Fix::None,
                    true,
                );
                Vec::new()
            }
        };

        // each layer is the one of its descriptor, by the route that
        // verified it: its blob pulled whole, or the TOC the descriptor's
        // labels name (whatever blob names it); and says what proved it (a
        // diff id once verified, none while lazy)
        let descriptors = serde_json::from_str::<OciManifest>(&image.manifest)
            .map(|m| m.layers)
            .unwrap_or_default();
        for (i, (layer, desc)) in layers.iter().zip(&descriptors).enumerate() {
            let wrong = if !layer.key.stands_for(desc)
                || matches!(&layer.key, velarx_types::LayerKey::Whole(b) if layer.blob != Some(*b))
            {
                Some(format!(
                    "layer {i} is stored as {} (blob {}), its descriptor is {}{}",
                    layer.key,
                    short(&layer.blob.map(|b| b.to_string()).unwrap_or_default()),
                    desc.digest,
                    velarx_types::layer::chunked_checksum(desc)
                        .map(|t| format!(" of the TOC {t}"))
                        .unwrap_or_default()
                ))
            } else if layer.diff_id.is_none() && !layer.key.is_toc() {
                // (a layer of a table of contents has none until a
                // recreation of its stream checked one)
                Some(format!("layer {i} ({}) has no diff id", layer.key))
            } else {
                None
            };
            if let Some(message) = wrong {
                add("layer_identity_mismatch", message, None, Fix::None, true);
            }
        }

        // the files the layers name
        let mut files: BTreeMap<String, u64> = BTreeMap::new();
        for (i, layer) in layers.iter().enumerate() {
            let toc = match velarx_content::pull::stored::stored_toc(&self.db, &layer.key).await {
                Ok(Some(t)) => t,
                Ok(None) => {
                    add(
                        "toc_missing",
                        format!(
                            "layer {i} ({}) has no table of contents",
                            short_key(&layer.key)
                        ),
                        None,
                        Fix::None,
                        true,
                    );
                    continue;
                }
                Err(e) => {
                    add(
                        "bad_toc",
                        format!(
                            "the table of contents of layer {i} ({}) cannot be read: {e}",
                            short_key(&layer.key)
                        ),
                        None,
                        Fix::None,
                        true,
                    );
                    continue;
                }
            };
            for e in toc
                .entries
                .iter()
                .filter(|e| e.entry_type == TocEntryType::Reg)
            {
                if e.size == 0 {
                    continue;
                }
                let Some(d) = &e.verity() else {
                    add(
                        "bad_toc",
                        format!("`{}` of layer {i} has no fs-verity digest", e.name),
                        None,
                        Fix::None,
                        true,
                    );
                    continue;
                };
                let entry = files.entry(d.clone()).or_insert(e.size);
                if *entry != e.size {
                    add(
                        "bad_toc",
                        format!("{d} is listed with two sizes: {} and {}", entry, e.size),
                        None,
                        Fix::None,
                        true,
                    );
                }
            }
        }

        // (the objects of a driver of another process are its own: its check
        // reads them)
        if !self.images.storage().holds_objects() {
            files.clear();
        }
        let digests: Vec<String> = files.keys().cloned().collect();
        let rows = self.db.file_objects(digests).await?;
        let mut to_read = Vec::new();
        for (digest, size) in &files {
            run.files_checked += 1;
            let Some(object) = rows.get(digest) else {
                add(
                    "unmapped_file",
                    format!("{digest} has no object in the store"),
                    None,
                    Fix::None,
                    true,
                );
                continue;
            };
            let path = self.object_path(digest, object);
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    run.missing.insert(digest.clone());
                    add(
                        "object_missing",
                        format!("the object of {digest} is gone"),
                        Some(path),
                        Fix::None,
                        true,
                    );
                    continue;
                }
                Err(e) => {
                    add(
                        "unreadable_object",
                        format!("cannot stat the object of {digest}: {e}"),
                        Some(path),
                        Fix::None,
                        true,
                    );
                    continue;
                }
            };
            if !meta.is_file() {
                add(
                    "bad_object",
                    format!("the object of {digest} is not a regular file"),
                    Some(path),
                    Fix::None,
                    true,
                );
                continue;
            }
            if meta.len() != *size {
                add(
                    "wrong_size",
                    format!(
                        "the object of {digest} has {} bytes, its table says {size}",
                        meta.len()
                    ),
                    Some(path),
                    Fix::None,
                    true,
                );
                continue;
            }
            if full && !run.verdicts.contains_key(digest) {
                to_read.push((digest.clone(), object.clone(), path, meta.len()));
            } else if full {
                // (read for an image before: the same verdict)
                for (kind, message) in &run.verdicts[digest] {
                    add(
                        kind,
                        message.clone(),
                        Some(self.object_path(digest, object)),
                        Fix::None,
                        true,
                    );
                }
            }
        }

        if !to_read.is_empty() {
            let results = tokio::task::spawn_blocking(move || read_files(to_read, deadline))
                .await
                .map_err(|e| CheckError::Other(e.to_string()))?;
            let mut interrupted = false;
            for (digest, path, result) in results {
                let Some((bytes, verdict)) = result else {
                    interrupted = true;
                    continue;
                };
                run.bytes_read += bytes;
                for (kind, message) in &verdict {
                    add(kind, message.clone(), Some(path.clone()), Fix::None, true);
                }
                run.verdicts.insert(digest, verdict);
            }
            if interrupted {
                return Ok(None);
            }
        }

        match self.images.image_problems(&image, &layers, full).await {
            Ok(problems) => {
                let content_damaged = findings.iter().any(|f| f.damaged);
                for p in problems {
                    findings.push(Finding {
                        image: Some(image.id.clone()),
                        name: name.clone(),
                        kind: p.kind.as_str(),
                        message: p.message,
                        path: p.path,
                        // (made again once the objects are known to be whole)
                        fix: if p.repair { Fix::Remake } else { Fix::None },
                        damaged: content_damaged,
                    });
                }
            }
            Err(e) => findings.push(Finding {
                image: Some(image.id.clone()),
                name: name.clone(),
                kind: "artifact_unreadable",
                message: format!("cannot check the composefs image: {e}"),
                path: None,
                fix: Fix::Remake,
                damaged: false,
            }),
        }
        debug!("Image {}: {} problems", short(&image.id), findings.len());
        Ok(Some(Checked {
            image,
            layers,
            findings,
        }))
    }

    /// Where the object of a file is: the objects of this store, or those
    /// of a read-only one that has it.
    fn object_path(&self, digest: &str, object: &Object) -> PathBuf {
        let path = self.store.object_path(object);
        if path.exists() {
            return path;
        }
        self.store.find_additional(digest).unwrap_or(path)
    }

    /// The problems of the store itself: what no image accounts for.
    /// `named`: the files whose objects are gone and an image's findings say so.
    async fn scan_store(&self, named: &HashSet<String>) -> CheckResult<Scan> {
        let mut scan = Scan::default();
        let rows = self.db.all_file_objects().await?;
        let recorded: HashSet<String> = rows.values().map(|o| o.verity.clone()).collect();

        // rows of files that are gone (the objects of a driver of another
        // process are its own: the rows name them, the engine has none)
        let mut gone: Vec<(&String, PathBuf)> = if self.images.storage().holds_objects() {
            rows.iter()
                .map(|(d, o)| (d, self.store.object_path(o)))
                .filter(|(_, p)| std::fs::symlink_metadata(p).is_err())
                .collect()
        } else {
            Vec::new()
        };
        gone.sort();
        for (digest, path) in &gone {
            scan.rows.push((*digest).clone());
            if !named.contains(*digest) {
                scan.findings.push(
                    Finding::of_store(
                        "stale_row",
                        format!("{digest} is recorded and its object is gone"),
                        Some(path.clone()),
                    )
                    .with(Fix::DropRows(vec![(*digest).clone()])),
                );
            }
        }

        // the objects and the temporary files
        let grace = self.grace;
        let root = self.store.root().to_path_buf();
        let Leftovers { mut stray, orphans } = tokio::task::spawn_blocking(move || {
            velarx_graph::objects::objects(&root, &recorded, grace)
        })
        .await
        .map_err(|e| CheckError::Other(e.to_string()))?
        .map_err(|e| CheckError::Other(e.to_string()))?;
        stray.extend(
            self.images
                .storage()
                .leftovers(grace)
                .await
                .map_err(|e| CheckError::Other(e.to_string()))?,
        );
        stray.sort();
        for (path, why) in stray {
            scan.findings.push(
                Finding::of_store("stale_temp", why, Some(path.clone()))
                    .with(Fix::RemoveFile(path)),
            );
        }
        for path in orphans {
            scan.findings.push(
                Finding::of_store(
                    "orphan_object",
                    "an object no row of the database names",
                    Some(path.clone()),
                )
                .with(Fix::RemoveFile(path)),
            );
        }

        self.scan_staging(&mut scan).await?;
        Ok(scan)
    }

    /// The staging directories of pulls that died and of containers that
    /// are gone, and the leases of pulls that died.
    async fn scan_staging(&self, scan: &mut Scan) -> CheckResult<()> {
        use velarx_content::pull::session::Session;
        let (held, stale) = self.db.partition_leases().await?;
        let live: HashSet<String> = held.into_iter().map(|l| l.id).collect();
        for l in &stale {
            scan.findings.push(
                Finding::of_store(
                    "stale_lease",
                    format!("the lease {} of a pull that is gone (pid {})", l.id, l.pid),
                    None,
                )
                .with(Fix::ReleaseLease(l.id.clone())),
            );
        }
        if let Ok(entries) = std::fs::read_dir(&self.staging) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if Session::is_session_name(&name) && !live.contains(&name) {
                    scan.findings.push(
                        Finding::of_store(
                            "stale_staging",
                            "the staging directory of a pull that is gone",
                            Some(entry.path()),
                        )
                        .with(Fix::RemoveDir(entry.path())),
                    );
                }
            }
        }
        self.scan_lazy(scan).await?;
        Ok(())
    }

    /// The staging area of lazy pulls: pulls that are not what their names
    /// say, whose layers or images are damaged, that failed, or that nothing
    /// completes; staged files that their layer's table does not name or
    /// that are not what their names say.
    async fn scan_lazy(&self, scan: &mut Scan) -> CheckResult<()> {
        use velarx_content::pull::staged::{PullState, Staging};
        let area = Staging::new(&self.staging);
        if !area.exists() {
            return Ok(());
        }
        for entry in area.pulls() {
            let (id, pull) = (&entry.pull.id, &entry.pull);
            let named = pull
                .tags
                .first()
                .map(|t| format!("{}:{}", t.repository, t.tag));
            let mut add = |kind: &'static str, message: String, fix: Fix| {
                let mut f = Finding::of_store(kind, message, Some(area.image_dir(id))).with(fix);
                f.image = Some(id.clone());
                f.name = named.clone();
                scan.findings.push(f);
            };
            // what the directory and the file say of the image
            let hex = pull.manifest_digest.hex();
            if &hex != id
                || velarx_types::digest::Digest::of(
                    pull.manifest_digest.alg(),
                    pull.manifest.as_bytes(),
                ) != pull.manifest_digest
            {
                add(
                    "bad_staged_pull",
                    format!(
                        "the manifest of the pull {} is not the one its id names",
                        short(id)
                    ),
                    Fix::None,
                );
                continue;
            }
            match &entry.state.state {
                PullState::Failed { reason } => add(
                    "failed_pull",
                    format!(
                        "the pull of {} failed: {reason}: `velarx image complete {}` tries again",
                        named.as_deref().unwrap_or(&short(id)),
                        short(id)
                    ),
                    Fix::Complete(id.clone()),
                ),
                state if state.is_open() && !entry.completer_alive => add(
                    "stalled_pull",
                    format!(
                        "nothing completes the pull of {}: `velarx image complete {}`",
                        named.as_deref().unwrap_or(&short(id)),
                        short(id)
                    ),
                    Fix::Complete(id.clone()),
                ),
                _ => {}
            }
            // the layers: staged, or in the store
            let mut remake = false;
            for key in &pull.layers {
                let Some(key) = velarx_types::LayerKey::parse(key) else {
                    add(
                        "bad_staged_pull",
                        format!("{key:?} is no layer key"),
                        Fix::None,
                    );
                    continue;
                };
                match area.layer(&key) {
                    Ok(Some(layer)) => {
                        let erofs = velarx_fuse::composefs::layer_image_path(
                            &area.objects_stand_in(),
                            &key.file_stem(),
                        );
                        let toc_ok = layer.toc().is_ok();
                        if !toc_ok {
                            add(
                                "bad_toc",
                                format!(
                                    "the table of contents of the staged layer {} does not parse",
                                    short(&key.to_string())
                                ),
                                Fix::None,
                            );
                        } else if !erofs.is_file() {
                            remake = true;
                        }
                    }
                    Ok(None) => {
                        if !self.db.has_layer(&key).await? {
                            add(
                                "missing_layer",
                                format!(
                                    "layer {} of the pull is neither staged nor in the store",
                                    short(&key.to_string())
                                ),
                                Fix::None,
                            );
                        }
                    }
                    Err(e) => add(
                        "bad_staged_pull",
                        format!(
                            "the staged layer {} cannot be read: {e}",
                            short(&key.to_string())
                        ),
                        Fix::None,
                    ),
                }
            }
            if remake {
                add(
                    "artifact_missing",
                    "the EROFS image of a staged layer is not there".to_string(),
                    Fix::RemakeStaged(id.clone()),
                );
            }
        }
        // the staging of each staged layer: files its table does not name,
        // or that are not what their names say
        let staged: Vec<(std::collections::BTreeMap<String, u64>, std::path::PathBuf)> = area
            .layer_keys()
            .into_iter()
            .filter_map(|k| {
                let layer = area.layer(&k).ok()??;
                let toc = layer.toc().ok()?;
                let named = toc
                    .entries
                    .iter()
                    .filter_map(|e| Some((e.verity()?, e.size)))
                    .collect();
                Some((named, area.layer_files(&k)))
            })
            .collect();
        let found = tokio::task::spawn_blocking(move || {
            let mut found = Vec::new();
            for (named, dir) in staged {
                for prefix in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                    for f in std::fs::read_dir(prefix.path())
                        .into_iter()
                        .flatten()
                        .flatten()
                    {
                        let rel = format!(
                            "{}/{}",
                            prefix.file_name().to_string_lossy(),
                            f.file_name().to_string_lossy()
                        );
                        let Some(object) = Object::from_rel(Path::new(&rel)) else {
                            continue;
                        };
                        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
                        let want = named.get(&object.verity).copied();
                        found.push((object.verity, f.path(), size, want));
                    }
                }
            }
            found
        })
        .await
        .map_err(|e| CheckError::Other(e.to_string()))?;
        for (digest, path, size, want) in found {
            match want {
                None => scan.findings.push(
                    Finding::of_store(
                        "unwanted_staged_file",
                        format!(
                            "{digest} is in the staging of a layer whose table does not name it"
                        ),
                        Some(path.clone()),
                    )
                    .with(Fix::RemoveFile(path)),
                ),
                Some(want) if want != size => scan.findings.push(
                    Finding::of_store(
                        "wrong_size",
                        format!("the staged file {digest} has {size} bytes, its table says {want}"),
                        Some(path.clone()),
                    )
                    .with(Fix::RemoveFile(path)),
                ),
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// Repair what was found, as far as the store allows, and report it.
    async fn repair(
        &self,
        mut checked: Vec<Checked>,
        full: bool,
        lossy: bool,
        run: &Run,
        report: &mut CheckReport,
    ) -> CheckResult<()> {
        // composefs images of the images that are otherwise whole
        for c in checked.iter_mut() {
            let remake = c.findings.iter().any(|f| matches!(f.fix, Fix::Remake));
            if !remake || c.findings.iter().any(|f| f.damaged) {
                continue;
            }
            info!(
                "Making the composefs images of {} again",
                short(&c.image.id)
            );
            let left = match self.images.remake_image(&c.image.id).await {
                Ok(()) => self
                    .images
                    .image_problems(&c.image, &c.layers, full)
                    .await
                    .map(|p| {
                        p.iter()
                            .filter(|p| p.repair)
                            .map(|p| p.message.clone())
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_else(|e| e.to_string()),
                Err(e) => e.to_string(),
            };
            if !left.is_empty() {
                // what the objects cannot make again: they are not whole
                for f in c.findings.iter_mut() {
                    f.damaged = true;
                    f.message
                        .push_str(&format!(" (and cannot be made again: {left})"));
                }
            }
        }

        // the store, under the exclusive lock: nothing is being recorded
        let mut dropped: HashSet<String> = HashSet::new();
        let mut done_store = Vec::new();
        let mut completing: Vec<String> = Vec::new();
        {
            let _exclusive = StorageLock::exclusive(&self.lock_path()).await?;
            let scan = self.scan_store(&run.missing).await?;
            let mut rows: Vec<String> = scan.rows.clone();
            for c in &checked {
                for f in &c.findings {
                    if let Fix::DropRows(d) = &f.fix {
                        rows.extend(d.iter().cloned());
                    }
                }
            }
            rows.sort();
            rows.dedup();
            if !rows.is_empty() {
                // (looked at again: the object of a row may have come back)
                let present = self.db.file_objects(rows.clone()).await?;
                let gone: Vec<String> = rows
                    .into_iter()
                    .filter(|d| match present.get(d) {
                        Some(o) => std::fs::symlink_metadata(self.store.object_path(o)).is_err(),
                        None => true,
                    })
                    .collect();
                self.db.delete_files(gone.clone()).await?;
                dropped.extend(gone);
            }
            for f in scan.findings {
                let action = match &f.fix {
                    Fix::RemoveFile(p) => remove(|| std::fs::remove_file(p), p),
                    Fix::RemoveDir(p) => {
                        let dir = p.clone();
                        let removed =
                            crate::off_thread(move || velarx_base::tree::remove_dir_all(dir)).await;
                        remove(|| removed, p)
                    }
                    Fix::DropRows(d) => d.iter().all(|d| dropped.contains(d)),
                    Fix::ReleaseLease(id) => self.db.release_lease(id).await.is_ok(),
                    Fix::RemakeStaged(id) => self.images.remake_staged_images(id).await.is_ok(),
                    Fix::Complete(id) => {
                        completing.push(id.clone());
                        true
                    }
                    Fix::None | Fix::Remake => false,
                };
                done_store.push(f.into_problem(if action {
                    CheckAction::Repaired
                } else {
                    CheckAction::None
                }));
            }
        }
        report.problems.extend(done_store);
        // (the pulls nothing completes: with the lock of the store free)
        for id in completing {
            if let Err(e) = self.images.complete_staged(&id).await {
                warn!("Cannot complete the pull {}: {e}", short(&id));
            }
        }

        // the images
        for c in checked {
            if c.findings.is_empty() {
                continue;
            }
            let damaged = c.findings.iter().any(|f| f.damaged);
            let mut action = CheckAction::Repaired;
            let mut note = None;
            if damaged {
                let mut users = self.db.containers_using_image(&c.image.id).await?;
                if lossy && !users.is_empty() {
                    self.remove_containers(&users, report).await;
                    users = self.db.containers_using_image(&c.image.id).await?;
                }
                if !users.is_empty() {
                    action = CheckAction::ImageInUse;
                    note = Some(format!(
                        "image not removed: used by the container{} {}",
                        if users.len() > 1 { "s" } else { "" },
                        users
                            .iter()
                            .map(|u| short(u))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                } else {
                    match self.images.remove(&c.image.id, false).await {
                        Ok(_) => {
                            warn!("Removed the damaged image {}", c.image.id);
                            action = CheckAction::ImageRemoved;
                        }
                        Err(e) => {
                            action = CheckAction::None;
                            note = Some(format!("image not removed: {e}"));
                        }
                    }
                }
            }
            let mut problems: Vec<CheckProblem> = c
                .findings
                .into_iter()
                .map(|f| {
                    let a = if damaged {
                        action
                    } else {
                        match &f.fix {
                            Fix::DropRows(d) if d.iter().all(|d| dropped.contains(d)) => {
                                CheckAction::Repaired
                            }
                            Fix::Remake => CheckAction::Repaired,
                            _ => CheckAction::None,
                        }
                    };
                    f.into_problem(a)
                })
                .collect();
            if let (Some(note), Some(first)) = (note, problems.first_mut()) {
                first.message.push_str(&format!(" ({note})"));
            }
            report.problems.extend(problems);
        }
        Ok(())
    }
}

/// What the scan of the store found, and the rows to forget (all of them,
/// also those an image's findings name).
#[derive(Default)]
struct Scan {
    findings: Vec<Finding>,
    rows: Vec<String>,
}

fn remove(f: impl FnOnce() -> std::io::Result<()>, path: &Path) -> bool {
    match f() {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            warn!("Cannot remove {}: {e}", path.display());
            false
        }
    }
}

fn short(digest: &str) -> String {
    let d = velarx_types::digest::without_algorithm(digest);
    d[..12.min(d.len())].to_string()
}

/// A layer as the report names it: the short digest of its key, `toc:` in
/// front of a TOC.
fn short_key(key: &velarx_types::LayerKey) -> String {
    match key {
        velarx_types::LayerKey::Whole(d) => short(&d.to_string()),
        velarx_types::LayerKey::Toc(d) => format!("toc:{}", short(&d.to_string())),
    }
}

/// A file to judge: its digest, object, path and size.
type ToRead = (String, Object, PathBuf, u64);
/// A judged file: its digest, path and (bytes read, verdict).
type Judged = (String, PathBuf, Option<(u64, Verdict)>);

/// Read the files and judge them; None for a file the deadline came
/// before.  Returns the digest, the path and (bytes read, verdict).
fn read_files(files: Vec<ToRead>, deadline: Option<Instant>) -> Vec<Judged> {
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(4));
    let work = || {
        files
            .into_par_iter()
            .map(|(digest, object, path, size)| {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    return (digest, path, None);
                }
                let verdict = judge(&digest, &object, &path, size);
                (digest, path, Some((size, verdict)))
            })
            .collect()
    };
    match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
        Ok(pool) => pool.install(work),
        Err(_) => work(),
    }
}

/// Read the file and recompute its fs-verity digest, which must be the name
/// of the object, `digest` (and what the kernel measures, when the file has
/// fs-verity and blocks of 4096 bytes).
fn judge(digest: &str, object: &Object, path: &Path, size: u64) -> Verdict {
    use std::io::Read;
    let mut out = Verdict::new();
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            out.push((
                "unreadable_object",
                format!("cannot open the object of {digest}: {e}"),
            ));
            return out;
        }
    };
    let alg = object.alg();
    let mut verity = velarx_storage::VerityHasher::new(alg);
    let mut buf = vec![0u8; 256 * 1024];
    let mut read = 0u64;
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                verity.update(&buf[..n]);
                read += n as u64;
            }
            Err(e) => {
                out.push((
                    "unreadable_object",
                    format!("cannot read the object of {digest}: {e}"),
                ));
                return out;
            }
        }
    }
    if read != size {
        out.push((
            "wrong_size",
            format!("the object of {digest} has {read} bytes, its table says {size}"),
        ));
    }
    let computed = verity.finish();
    // (fs-verity of the other hash: the overlay that checks the object
    // against its name refuses it)
    if let Some(other) = velarx_storage::canonical_algorithm(&file).filter(|a| *a != alg) {
        out.push((
            "verity_mismatch",
            format!(
                "the object is named {} and has fs-verity with {}, not {}",
                object.verity,
                velarx_storage::FsVerityHashAlgorithm::of(other).label(),
                velarx_storage::FsVerityHashAlgorithm::of(alg).label()
            ),
        ));
        return out;
    }
    // (a file system of small blocks measures another digest)
    let measured = velarx_storage::measure_file(&file)
        .ok()
        .filter(|_| velarx_storage::canonical_digest(&file, alg))
        .and_then(|m| m.object())
        .map(|o| o.to_string());
    let sound = computed == digest && measured.as_ref().is_none_or(|m| *m == digest);
    if !sound {
        out.push((
            "verity_mismatch",
            format!(
                "the object is named {} and its fs-verity digest is {}",
                object.verity,
                measured.unwrap_or(computed)
            ),
        ));
    }
    out
}
