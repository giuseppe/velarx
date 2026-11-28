// SPDX-License-Identifier: Apache-2.0
//! Garbage collection of the store: mark and sweep under the exclusive lock
//! of the store ([`StorageLock`]), so it never runs while a pull or a fetch
//! holds it shared.  In order: the staging directories of pulls and builds
//! that died (nothing holds them), the
//! expired chunks, the layers no image uses and no pull pins, the files no
//! layer references (with their chunk locations), the files on disk the
//! database does not know, and the kept indexes that list no image.

use crate::storage_driver::{Keep, StorageDriver};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};
use velarx_config::StorageConfig;
use velarx_content::pull::holds;
use velarx_content::pull::staged::{PullState, Staging};
use velarx_db::Database;
use velarx_storage::{FileStore, Object, StorageLock};

#[derive(Error, Debug)]
pub enum GcError {
    #[error(transparent)]
    Database(#[from] velarx_types::DbError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Driver(#[from] velarx_graph::DriverError),
}

impl From<tokio_rusqlite::Error> for GcError {
    fn from(e: tokio_rusqlite::Error) -> Self {
        GcError::Database(velarx_types::DbError::Sqlite(e))
    }
}

pub type GcResult<T> = Result<T, GcError>;

/// Result of garbage collection
#[derive(Debug, Clone, Default, Serialize)]
pub struct GcReport {
    /// Number of unreferenced layers removed
    pub layers_removed: usize,
    /// Number of unreferenced files removed
    pub files_removed: usize,
    /// Staging directories of pulls that are gone, removed
    pub staging_removed: usize,
    /// The bytes the store freed: the objects (each file once, by its length
    /// on disk), the composefs images of the layers, the temporary files and
    /// the engine's copies, which is what `system df` counts under "Store
    /// space usage".  A layer row has no bytes of its own: what it names is
    /// counted as the files and the image it had.
    pub bytes_freed: u64,
    /// The size of the layers removed, each once, as the images that had
    /// them count it (`system df`, `image ls`): the uncompressed tar of the
    /// layer.  The space an image removal frees is this and the metadata of
    /// its record, not [`Self::bytes_freed`].
    pub layers_size: u64,
    /// Nothing was done: the store was in use and the collection was not
    /// asked to wait
    pub skipped: bool,
    /// Errors encountered (non-fatal)
    pub errors: Vec<String>,
    /// The staged layers of lazy pulls that were removed: the engine that
    /// runs the collection tells the fetchers of its pulls
    /// (`ImageService::forget_collected`)
    #[serde(skip)]
    pub staged_layers: Vec<velarx_types::LayerKey>,
}

impl GcReport {
    /// `n` bytes freed, never past the largest number (a report of a store
    /// of exabytes does not wrap).
    fn add_freed(&mut self, n: u64) {
        self.bytes_freed = self.bytes_freed.saturating_add(n);
    }

    /// A layer removed: its size as the images count it (a row that has none
    /// recorded, a negative number, counts for nothing).
    fn add_layer_size(&mut self, n: i64) {
        self.layers_size = self
            .layers_size
            .saturating_add(u64::try_from(n).unwrap_or(0));
    }
}

/// The layers no image and no container uses (what a pull in progress pins
/// is left out by the caller).
/// A container keeps the layers it was made from even when its image
/// was removed (`container_layers`).
const UNREFERENCED_LAYERS: &str = "SELECT l.id, l.stream_size FROM layers l
     WHERE NOT EXISTS (SELECT 1 FROM image_layers il WHERE il.layer_id = l.id)
       AND NOT EXISTS (SELECT 1 FROM container_layers cl WHERE cl.layer_id = l.id)";

/// Forget a layer (`?1`, its key): its files, and the repositories of its
/// blob when no other layer is of that blob (a layer of its TOC and one
/// pulled whole may be).  Its directory goes with the sweep of
/// [`GcService::collect_storage`], which every removal of layers ends in.
const FORGET_LAYER: [&str; 3] = [
    "DELETE FROM file_refs WHERE layer_id = ?1",
    "DELETE FROM blob_sources WHERE digest = (SELECT blob FROM layers WHERE id = ?1)
         AND NOT EXISTS (SELECT 1 FROM layers WHERE blob = blob_sources.digest AND id != ?1)",
    "DELETE FROM layers WHERE id = ?1",
];

/// The most files or layers one transaction of the collector removes: the
/// store is locked meanwhile, and a transaction per file costs a round trip
/// each.
const BATCH: usize = 2000;

/// Garbage collection options
#[derive(Debug, Clone)]
pub struct GcOptions {
    /// Only report what would be deleted, don't actually delete
    pub dry_run: bool,
    /// Delete unreferenced files
    pub collect_files: bool,
    /// Delete unreferenced layers
    pub collect_layers: bool,
    /// Wait for the pulls in progress; otherwise do nothing if there are
    pub wait: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            collect_files: true,
            collect_layers: true,
            wait: true,
        }
    }
}

/// Garbage collection service
pub struct GcService {
    db: Database,
    file_store: Arc<FileStore>,
    objects_dir: PathBuf,
    staging_dir: PathBuf,
    lock_path: PathBuf,
    /// What the driver holds (the images of the layers, the profiles) is
    /// collected by it.
    storage: Arc<dyn StorageDriver>,
}

impl GcService {
    pub fn new(
        db: Database,
        file_store: Arc<FileStore>,
        storage: &StorageConfig,
        driver: Arc<dyn StorageDriver>,
    ) -> Self {
        let staging_dir = storage.staging_dir();
        Self {
            storage: driver,
            db,
            objects_dir: file_store.root().to_path_buf(),
            file_store,
            staging_dir,
            lock_path: StorageLock::path(&storage.root),
        }
    }

    /// The collector of the store whose staging directory is `staging`, with
    /// the driver of the store.
    pub fn of_store(
        storage: Arc<dyn StorageDriver>,
        db: Database,
        file_store: Arc<FileStore>,
        staging: &std::path::Path,
    ) -> Self {
        Self {
            storage,
            db,
            objects_dir: file_store.root().to_path_buf(),
            file_store,
            staging_dir: staging.to_path_buf(),
            lock_path: StorageLock::path_of_staging(staging),
        }
    }

    /// The staging area of lazy pulls.
    fn staging(&self) -> Staging {
        Staging::new(&self.staging_dir)
    }

    /// The layers a pull in progress pins: the complete layers of a lazy
    /// pull (by its record), and those a live pull holds.
    /// A staging directory that cannot be read is an error: nothing is
    /// removed on a guess.
    fn pinned_layers(&self) -> GcResult<HashSet<String>> {
        let mut pinned: HashSet<String> = self.staging().pinned_layers().into_iter().collect();
        pinned.extend(holds::pinned(&self.staging_dir)?.layers);
        Ok(pinned)
    }

    /// After images were removed: remove the layers no image uses and no
    /// pull pins, then the files only those layers had.  Waits for the
    /// pulls and commits in progress (the exclusive lock of the store).
    pub async fn release_unused_layers(&self) -> GcResult<GcReport> {
        let _lock = StorageLock::exclusive(&self.lock_path).await?;
        let mut report = GcReport::default();
        let layers: Vec<(String, i64)> = self
            .db
            .conn()
            .call(|conn| {
                let mut stmt = conn.prepare(UNREFERENCED_LAYERS)?;
                let layers = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(layers)
            })
            .await?;
        let pinned = self.pinned_layers()?;
        let layers: Vec<(String, i64)> = layers
            .into_iter()
            .filter(|(d, _)| !pinned.contains(d))
            .collect();
        // (a layer a mount or a server uses stays; the others are held until
        // their rows and files are gone, so many at a time)
        for batch in self.unused_batches(layers) {
            let mut batch = batch?;
            self.release_layers(std::mem::take(&mut batch.unused), &mut report)
                .await?;
        }
        if report.layers_removed == 0 {
            return Ok(report);
        }
        // The images the driver kept of those layers go with them (it keeps
        // what the layers still in the database name).
        self.collect_storage(&mut report).await?;
        // (the rows of the layers leave free pages in the file)
        if let Err(e) = self.db.shrink().await {
            report
                .errors
                .push(format!("the database is not shrunk: {e}"));
        }
        info!(
            "Released {} layers and {} files of removed images",
            report.layers_removed, report.files_removed
        );
        Ok(report)
    }

    /// The rows of `layers` and their files, gone: the files of those layers,
    /// and the layers, in one transaction, then the files no other layer has.
    async fn release_layers(
        &self,
        layers: Vec<(String, i64)>,
        report: &mut GcReport,
    ) -> GcResult<()> {
        if layers.is_empty() {
            return Ok(());
        }
        let digests: Vec<String> = layers.iter().map(|(d, _)| d.clone()).collect();
        let files: Vec<String> = self
            .db
            .conn()
            .call(move |conn| {
                // a write transaction from the start: a read one that
                // writes after another process did fails (SQLITE_BUSY)
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut files = HashSet::new();
                for d in &digests {
                    let mut stmt =
                        tx.prepare("SELECT file_digest FROM file_refs WHERE layer_id = ?1")?;
                    for f in stmt.query_map([d], |row| row.get::<_, String>(0))? {
                        files.insert(f?);
                    }
                    drop(stmt);
                    for sql in FORGET_LAYER {
                        tx.execute(sql, [d])?;
                    }
                }
                tx.commit()?;
                Ok(files.into_iter().collect())
            })
            .await?;
        for (digest, size) in &layers {
            debug!("Released the layer {}", digest);
            report.layers_removed += 1;
            report.add_layer_size(*size);
        }
        self.remove_files_if_unused(files, report).await
    }

    /// Remove the files no layer references any more: their rows, in
    /// transactions of at most [`BATCH`] files (the store is locked meanwhile,
    /// and a transaction per file costs a round trip each), then the files.
    async fn remove_files_if_unused(
        &self,
        digests: Vec<String>,
        report: &mut GcReport,
    ) -> GcResult<()> {
        // A pull in progress (it holds a live hold, not the lock) may use
        // a file of the store that no layer of its image has, one it found
        // there for a file of its own: the files stay until no pull runs,
        // the next collection removes them.
        // (the files a pulling image's staged layers name stay: the store
        // may be where they are)
        let wanted = self.staging().wanted_files();
        let digests: Vec<String> = digests
            .into_iter()
            .filter(|d| !wanted.contains_key(d))
            .collect();
        if !digests.is_empty() && self.pull_in_progress()? {
            debug!(
                "{} unreferenced files kept: a pull is in progress",
                digests.len()
            );
            return Ok(());
        }
        for batch in digests.chunks(BATCH) {
            let mut paths: HashMap<String, Option<std::path::PathBuf>> = batch
                .iter()
                .map(|d| (d.clone(), self.file_store.local_path(d)))
                .collect();
            let digests: Vec<String> = batch.to_vec();
            let removed: Vec<(String, i64)> = self
                .db
                .conn()
                .call(move |conn| {
                    let tx =
                        conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                    let mut removed = Vec::new();
                    {
                        let mut used = tx.prepare(
                            "SELECT EXISTS (SELECT 1 FROM file_refs WHERE file_digest = ?1)",
                        )?;
                        let mut sized = tx.prepare("SELECT size FROM files WHERE digest = ?1")?;
                        let mut chunks =
                            tx.prepare("DELETE FROM chunk_locations WHERE file_digest = ?1")?;
                        let mut files = tx.prepare("DELETE FROM files WHERE digest = ?1")?;
                        for d in &digests {
                            if used.query_row([d], |row| row.get::<_, i64>(0))? != 0 {
                                continue;
                            }
                            let size: Option<i64> = sized.query_row([d], |row| row.get(0)).ok();
                            chunks.execute([d])?;
                            files.execute([d])?;
                            removed.push((d.clone(), size.unwrap_or(0)));
                        }
                    }
                    tx.commit()?;
                    Ok(removed)
                })
                .await?;
            for (digest, row_size) in removed {
                // (what the object took: its length, and nothing when the
                // object was gone already; the row's size for a store that
                // keeps its objects elsewhere)
                let mut size = row_size.max(0) as u64;
                if let Some(path) = paths.remove(&digest).flatten() {
                    size = 0;
                    match std::fs::symlink_metadata(&path)
                        .and_then(|m| std::fs::remove_file(&path).map(|()| m.len()))
                    {
                        Ok(len) => size = len,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => {
                            warn!("Failed to remove file {}: {}", digest, e);
                            report
                                .errors
                                .push(format!("Failed to remove file {digest}: {e}"));
                            continue;
                        }
                    }
                }
                debug!("Removed unreferenced file: {}", digest);
                report.files_removed += 1;
                report.add_freed(size);
            }
        }
        Ok(())
    }

    /// Run garbage collection with the specified options
    pub async fn collect(&self, options: GcOptions) -> GcResult<GcReport> {
        let mut report = GcReport::default();
        let lock = if options.wait {
            Some(StorageLock::exclusive(&self.lock_path).await?)
        } else {
            StorageLock::try_exclusive(&self.lock_path)?
        };
        let Some(_lock) = lock else {
            debug!("The store is in use: no garbage collection this time");
            report.skipped = true;
            return Ok(report);
        };

        info!(
            "Starting garbage collection (dry_run: {}, files: {}, layers: {})",
            options.dry_run, options.collect_files, options.collect_layers
        );

        if !options.dry_run {
            self.collect_stale_staging(&mut report).await?;
            self.collect_lazy_staging(&mut report).await?;
            let locks = self.file_store.root().with_file_name("locks");
            let removed = velarx_storage::locks::remove_unused(&locks);
            debug!("Removed {removed} lock files nothing held");
        }
        let mut would_go = HashSet::new();
        if options.collect_layers {
            would_go = self
                .collect_unreferenced_layers(&options, &mut report)
                .await?;
        }
        if options.collect_files {
            self.collect_unreferenced_files(&options, &mut report, &would_go)
                .await?;
        }

        if !options.dry_run {
            // The images the driver kept of the layers the store does not
            // have, those this collection removed included: they go with
            // them, not with the next collection.
            self.collect_storage(&mut report).await?;
            // (an index is kept for the images it lists, those of the staged
            // pulls included; a pull in progress has kept its
            // indexes and not recorded its image yet)
            if let Err(e) = self.collect_indexes().await {
                report.errors.push(format!("the kept indexes: {e}"));
            }
            // (the rows the collection removed leave free pages in the file)
            if let Err(e) = self.db.shrink().await {
                report
                    .errors
                    .push(format!("the database is not shrunk: {e}"));
            }
        }
        info!(
            "Garbage collection complete: {} layers, {} files, {} staging directories removed, {} bytes freed",
            report.layers_removed,
            report.files_removed,
            report.staging_removed,
            report.bytes_freed
        );
        Ok(report)
    }

    /// Forget the kept indexes that list no image of the store nor of a
    /// staged pull, unless a pull is in progress.
    async fn collect_indexes(&self) -> GcResult<()> {
        if self.pull_in_progress()? {
            return Ok(());
        }
        let staged = self
            .staging()
            .pulls()
            .into_iter()
            .map(|p| p.pull.manifest_digest)
            .collect();
        let n = self.db.forget_unlisted_indexes(staged).await?;
        debug!("Forgot {n} indexes that list no image");
        Ok(())
    }

    /// Whether a pull or a build is in progress: a process holds its hold.
    fn pull_in_progress(&self) -> GcResult<bool> {
        Ok(holds::any_live(&self.staging_dir)?)
    }

    /// Remove the staging of the layers whose stager died, and the holds
    /// nobody holds with what they staged (a pull is held from the birth of
    /// its directory; a leftover birth goes too).
    async fn collect_stale_staging(&self, report: &mut GcReport) -> GcResult<()> {
        let root = self.staging_dir.clone();
        match crate::off_thread(move || velarx_content::pull::staged_fetch::sweep(&root)).await {
            Ok(n) => report.staging_removed += n,
            Err(e) => report
                .errors
                .push(format!("cannot remove the staging of a layer: {e}")),
        }
        let root = self.staging_dir.clone();
        let (removed, errors) = crate::off_thread(move || Ok(holds::sweep(&root))).await?;
        report.staging_removed += removed;
        for e in errors {
            warn!("Cannot remove a stale hold: {e}");
            report
                .errors
                .push(format!("cannot remove a staging directory: {e}"));
        }
        Ok(())
    }

    /// The staging area of lazy pulls: pulls that are in the store, or were
    /// cancelled, and that nothing runs or holds; the staged layers (with
    /// their staging directories) no live pull names; what an interrupted
    /// publish left.
    /// A pull that is not committed is never removed because nobody holds
    /// it (one whose engine stopped is resumed; a reboot discards the pulls
    /// at the start of the next engine: `Staging::forget_earlier_boots`).
    async fn collect_lazy_staging(&self, report: &mut GcReport) -> GcResult<()> {
        let area = self.staging();
        if !area.exists() {
            return Ok(());
        }
        for entry in area.pulls() {
            let committed = self
                .db
                .get_image_by_digest(&entry.pull.manifest_digest)
                .await
                .is_ok();
            let cancelled = entry.state.state == PullState::Cancelled;
            if entry.completer_alive || !(committed || cancelled) {
                continue;
            }
            if !self
                .db
                .containers_using_image(&entry.pull.id)
                .await?
                .is_empty()
            {
                continue;
            }
            debug!("Removing the staging of the pull {}", entry.pull.id);
            match area.remove_pull(&entry.pull.id) {
                Ok(()) => report.staging_removed += 1,
                Err(e) => report.errors.push(format!(
                    "cannot remove the staging of the pull {}: {e}",
                    entry.pull.id
                )),
            }
        }
        // (one a process fetches into is left for the next collection)
        for key in area.unnamed_layers() {
            match area.remove_layer_unless_leased(&key) {
                Ok(true) => {
                    report.staging_removed += 1;
                    report.staged_layers.push(key);
                }
                Ok(false) => {}
                Err(e) => report
                    .errors
                    .push(format!("cannot remove the staged layer {key}: {e}")),
            }
        }
        // what a publish of a pull that died left
        if let Ok(entries) =
            std::fs::read_dir(area.root().join(velarx_content::pull::staged::PULLS))
        {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().starts_with(".new-") {
                    let path = e.path();
                    let shown = path.display().to_string();
                    match crate::off_thread(move || velarx_base::tree::remove_dir_all(path)).await {
                        Ok(()) => report.staging_removed += 1,
                        Err(e) => report
                            .errors
                            .push(format!("cannot remove the leftover {shown}: {e}")),
                    }
                }
            }
        }
        Ok(())
    }

    /// The layers of `layers` that nothing uses, a batch at a time
    /// ([`velarx_graph::unused::unused_batches`]): a layer whose image a
    /// mount or an image server holds stays (and so do its files, which the
    /// rows of the layer name), and the others are held until the caller
    /// drops their batch.  Not being able to tell is an error: nothing more
    /// is removed on a guess.
    fn unused_batches(
        &self,
        layers: Vec<(String, i64)>,
    ) -> impl Iterator<Item = GcResult<velarx_graph::unused::UnusedBatch<(String, i64)>>> + '_ {
        velarx_graph::unused::unused_batches(self.storage.as_ref(), layers, |(d, _)| {
            velarx_types::LayerKey::parse(d)
        })
        .map(|batch| {
            let batch = batch?;
            for (d, _) in &batch.in_use {
                debug!("The layer {d} is in use: it stays");
            }
            Ok(batch)
        })
    }

    /// What the object of the file `digest` takes in the store: its length
    /// (nothing if it is not there), the row's `size` where the store has no
    /// local objects.
    fn object_bytes(&self, digest: &str, row_size: i64) -> u64 {
        match self.file_store.local_path(digest) {
            Some(p) => std::fs::symlink_metadata(p).map_or(0, |m| m.len()),
            None => u64::try_from(row_size).unwrap_or(0),
        }
    }

    /// Remove the layers no image uses and no pull pins.  A dry run removes
    /// nothing and returns the layers it would remove, so that the files only
    /// they have are counted as the collection frees them.
    async fn collect_unreferenced_layers(
        &self,
        options: &GcOptions,
        report: &mut GcReport,
    ) -> GcResult<HashSet<String>> {
        let mut would_go = HashSet::new();
        debug!("Collecting unreferenced layers");
        let unreferenced: Vec<(String, i64)> = self
            .db
            .conn()
            .call(|conn| {
                let mut stmt = conn.prepare(UNREFERENCED_LAYERS)?;
                let layers = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(layers)
            })
            .await?;
        let pinned = self.pinned_layers()?;
        let unreferenced: Vec<(String, i64)> = unreferenced
            .into_iter()
            .filter(|(d, _)| !pinned.contains(d))
            .collect();
        // (a layer a mount or a server uses stays; the others are held until
        // their rows are gone, so many at a time)
        for batch in self.unused_batches(unreferenced) {
            let mut held = batch?;
            let batch = std::mem::take(&mut held.unused);
            if options.dry_run {
                for (digest, size) in &batch {
                    report.layers_removed += 1;
                    report.add_layer_size(*size);
                    would_go.insert(digest.clone());
                }
                continue;
            }
            if batch.is_empty() {
                continue;
            }
            let layers = batch.clone();
            let removed = self
                .db
                .conn()
                .call(move |conn| {
                    let tx =
                        conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                    for (d, _) in &layers {
                        for sql in FORGET_LAYER {
                            tx.execute(sql, [d])?;
                        }
                    }
                    tx.commit()?;
                    Ok(())
                })
                .await;
            if let Err(e) = removed {
                warn!("Failed to remove {} layers: {}", batch.len(), e);
                report
                    .errors
                    .push(format!("Failed to remove {} layers: {}", batch.len(), e));
                continue;
            }
            for (digest, size) in &batch {
                debug!("Removed unreferenced layer: {}", digest);
                report.layers_removed += 1;
                report.add_layer_size(*size);
            }
        }
        Ok(would_go)
    }

    /// The files the layers reference, and those the staged layers of the
    /// pulls in progress name: the store may have them already (a layer
    /// that shares them was committed), and the completion links the ones
    /// it has not.
    /// (without those of the layers `leaving`, which a dry run did not
    /// remove)
    async fn referenced_files(&self, leaving: &HashSet<String>) -> GcResult<HashSet<String>> {
        let leaving = leaving.clone();
        let mut digests = self
            .db
            .conn()
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT layer_id, file_digest FROM file_refs")?;
                let mut digests = HashSet::new();
                for row in stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })? {
                    let (layer, file) = row?;
                    if !leaving.contains(&layer) {
                        digests.insert(file);
                    }
                }
                Ok(digests)
            })
            .await?;
        digests.extend(self.staging().wanted_files().into_keys());
        Ok(digests)
    }

    /// Remove the files no layer references, their rows and their chunk
    /// locations, then the files on disk the database does not know.
    async fn collect_unreferenced_files(
        &self,
        options: &GcOptions,
        report: &mut GcReport,
        leaving: &HashSet<String>,
    ) -> GcResult<()> {
        debug!("Collecting unreferenced files");
        let referenced = self.referenced_files(leaving).await?;
        let all_files: Vec<(String, i64)> = self
            .db
            .conn()
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT digest, size FROM files")?;
                let files = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(files)
            })
            .await?;

        let mut unreferenced = Vec::new();
        // (a dry run counts what the collection would remove: nothing of
        // the files with a row while a pull runs, `remove_files_if_unused`)
        let pulling = options.dry_run && self.pull_in_progress()?;
        for (digest, size) in all_files {
            if referenced.contains(&digest) {
                continue;
            }
            if options.dry_run {
                if !pulling {
                    report.files_removed += 1;
                    report.add_freed(self.object_bytes(&digest, size));
                }
            } else {
                unreferenced.push(digest);
            }
        }
        self.remove_files_if_unused(unreferenced, report).await?;

        // the objects with no row (a pull that died after the commit):
        // a file whose row stays is kept, as the rows of the files no
        // layer references stay while a pull runs (it may use them)
        let mut keep = referenced;
        keep.extend(
            self.db
                .conn()
                .call(|conn| {
                    let mut stmt = conn.prepare("SELECT digest FROM files")?;
                    let rows = stmt
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                })
                .await?,
        );
        // (a row that names no object, as the rows of a store of another
        // velarx do, would leave its file to the scan: none is removed)
        match keep.iter().find(|d| Object::new(d, false).is_none()) {
            Some(d) => report.errors.push(format!(
                "the store records the file `{d}`, which is no fs-verity digest of an object \
                 (fsverity-sha256-12:HEX or fsverity-sha512-12:HEX): the files with no row are \
                 not removed (a store of another velarx: remove it)"
            )),
            None => self.collect_orphaned_files(report, &keep, options.dry_run)?,
        }
        Ok(())
    }

    /// Remove the images of the layers the store does not have any more,
    /// the startup profiles of the images it does not have, the files of
    /// the layers no row names, and what an interrupted pull left.
    async fn collect_storage(&self, report: &mut GcReport) -> GcResult<()> {
        let layers = self.db.layer_digests().await?;
        let named = layers
            .iter()
            .map(velarx_types::LayerKey::file_stem)
            .collect();
        report.add_freed(velarx_db::layer_files::sweep(
            velarx_db::layer_files::root_of(&self.objects_dir),
            &named,
        )?);
        let pulls = self.staging().pulls().into_iter().map(|p| p.pull.id);
        let image_records = self.db.list_images().await?;
        let images = image_records.into_iter().map(|i| i.id);
        // (the layers of the containers' images are in `layers`: an image a
        // container uses is never removed)
        let containers = self
            .db
            .list_containers(true)
            .await?
            .into_iter()
            .map(|c| c.id);
        let keep = Keep {
            layers,
            images: images.collect(),
            containers: containers.collect(),
            pulls: pulls.collect(),
            grace: crate::services::check::LEFTOVER_GRACE,
        };
        let out = self
            .storage
            .collect(&keep)
            .map_err(|e| GcError::Io(e.into_io()))?;
        report.add_freed(out.bytes_freed);
        report.errors.extend(out.errors);
        Ok(())
    }

    /// Remove the files of the store that no layer references: the objects
    /// whose fs-verity digest is not in `keep`, and the temporary files
    /// left by writers that died.  A dry run counts the objects and leaves
    /// the temporary files (whether a writer holds one is known only by
    /// taking its lock).
    fn collect_orphaned_files(
        &self,
        report: &mut GcReport,
        keep: &HashSet<String>,
        dry_run: bool,
    ) -> GcResult<()> {
        debug!("Scanning for orphaned files on disk");
        let prefixes = match std::fs::read_dir(&self.objects_dir) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for prefix_entry in prefixes {
            let prefix_entry = prefix_entry?;
            let meta = prefix_entry.metadata()?;
            if !meta.is_dir() {
                // a temporary file of the store itself (a commit that died)
                if dry_run {
                    continue;
                }
                if let Ok(Some(size)) = velarx_storage::remove_abandoned(&prefix_entry.path()) {
                    report.add_freed(size);
                }
                continue;
            }
            let prefix = prefix_entry.file_name().to_string_lossy().into_owned();
            for file_entry in std::fs::read_dir(prefix_entry.path())? {
                let file_entry = file_entry?;
                if !file_entry.file_type()?.is_file() {
                    continue;
                }
                let name = file_entry.file_name().to_string_lossy().into_owned();
                // (an object of either algorithm, by the digits of its name:
                // the same content under the other is another object)
                let object = Object::from_rel(std::path::Path::new(&format!("{prefix}/{name}")));
                let verity = object.map_or_else(String::new, |o| o.verity);
                let meta = file_entry.metadata()?;
                if !verity.is_empty() {
                    if keep.contains(&verity) {
                        continue;
                    }
                } else {
                    if dry_run {
                        continue;
                    }
                    // a temporary file: removed when no writer holds its
                    // lock (the writers that do not take the lock of the
                    // store lock their file)
                    match velarx_storage::remove_abandoned(&file_entry.path()) {
                        Ok(Some(size)) => {
                            debug!("Removed the temporary file {}", file_entry.path().display());
                            report.add_freed(size);
                        }
                        Ok(None) => {}
                        Err(e) => report.errors.push(format!(
                            "Failed to remove {}: {e}",
                            file_entry.path().display()
                        )),
                    }
                    continue;
                }
                if dry_run {
                    report.files_removed += 1;
                    report.add_freed(meta.len());
                    continue;
                }
                debug!("Removing orphaned file: {}", verity);
                match std::fs::remove_file(file_entry.path()) {
                    Ok(()) => {
                        report.files_removed += 1;
                        report.add_freed(meta.len());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        warn!("Failed to remove orphaned file {}: {}", verity, e);
                        report
                            .errors
                            .push(format!("Failed to remove orphaned file {}: {}", verity, e));
                    }
                }
            }
            // (empty when all went; else it stays)
            if !dry_run {
                let _ = std::fs::remove_dir(prefix_entry.path());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_driver::watching::Watching;
    use crate::storage_driver::{ComposefsDriver, StorageDriver};
    use velarx_db::{ContainerRecord, RecordState};

    /// A container is made in two steps that the engine keeps together, the
    /// root that the driver makes and the row of the database, under the
    /// shared lock of the store.  A collection that comes in between waits
    /// for the lock (or is skipped, if it does not wait): the driver is never
    /// told, between the two steps, that the container does not exist, and
    /// when it is told, the container is among those to keep.
    #[tokio::test]
    async fn a_collection_never_runs_between_the_root_and_the_row_of_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db")).await.unwrap();
        let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
        let staging = dir.path().join("staging");
        let inner: Arc<dyn StorageDriver> = Arc::new(ComposefsDriver::new(
            db.clone(),
            store.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
            crate::storage_driver::composefs::options_for_tests(&staging),
        ));
        let caps = inner.capabilities().clone();
        let watching = Arc::new(Watching::new(inner, caps));
        let gc = GcService::of_store(watching.clone(), db.clone(), store, &staging);
        let told = || watching.collected.lock().unwrap().clone();

        // the create: its shared lock, held from the first call to the driver
        // until the row is recorded
        let create = StorageLock::shared(&StorageLock::path_of_staging(&staging))
            .await
            .unwrap();
        let skipped = gc
            .collect(GcOptions {
                wait: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(skipped.skipped, "a collection does not run under a create");
        assert!(told().is_empty(), "the driver was told nothing");
        // one that waits is still waiting when the create ends
        let waiting = {
            let (db, staging, watching) = (db.clone(), staging.clone(), watching.clone());
            let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
            tokio::spawn(async move {
                GcService::of_store(watching, db, store, &staging)
                    .collect(GcOptions::default())
                    .await
            })
        };
        // (time for it to reach the lock: a task that never ran would prove
        // nothing)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!waiting.is_finished(), "it waits for the create");
        assert!(told().is_empty());

        // the row is recorded, then the lock goes
        let image = velarx_db::ImageRecord {
            id: "img".into(),
            manifest_digest: velarx_types::digest::Digest::empty(
                velarx_types::digest::Algorithm::Sha256,
            ),
            config_digest: velarx_types::digest::Digest::empty(
                velarx_types::digest::Algorithm::Sha256,
            ),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        };
        db.insert_image(&image).await.unwrap();
        db.insert_container(&ContainerRecord {
            id: "c1".into(),
            name: None,
            image_id: "img".into(),
            config: "{}".into(),
            state: RecordState::Created,
            ..Default::default()
        })
        .await
        .unwrap();
        drop(create);
        waiting.await.unwrap().unwrap();
        let told = told();
        assert_eq!(told.len(), 1, "told once, after the create");
        assert_eq!(told[0].containers, ["c1"], "and the container is kept");
        assert_eq!(told[0].grace, super::super::check::LEFTOVER_GRACE);
    }

    /// The rows of the layers an `rmi` releases do not stay in the file as
    /// free pages, and their files (the table of contents) go with them.
    #[tokio::test]
    async fn releasing_layers_removes_their_rows_and_their_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db")).await.unwrap();
        let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
        let staging = dir.path().join("staging");
        let driver: Arc<dyn StorageDriver> = Arc::new(ComposefsDriver::new(
            db.clone(),
            store.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
            crate::storage_driver::composefs::options_for_tests(&staging),
        ));
        let gc = GcService::of_store(driver, db.clone(), store, &staging);
        let digest: velarx_types::digest::Digest =
            format!("sha256:{}", "ab".repeat(32)).parse().unwrap();
        let key = velarx_types::LayerKey::Whole(digest);
        // (a table of contents of a big layer: a file of its directory)
        db.insert_layer_with_toc(
            dir.path(),
            &velarx_db::LayerRecord {
                stream_size: Some(0),
                inline: 0,
                key,
                blob: Some(digest),
                diff_id: Some(digest),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: String::new(),
                registry_ref: None,
                erofs: None,
                owners: None,
            },
            &vec![7u8; 1 << 20],
        )
        .await
        .unwrap();
        let files = velarx_db::layer_files::layer_dir(dir.path(), &key);
        assert!(files.is_dir());
        let report = gc.release_unused_layers().await.unwrap();
        assert_eq!(report.layers_removed, 1);
        assert!(!files.exists(), "the files of the layer stay");
        let free: i64 = db
            .conn()
            .call(|conn| Ok(conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(free, 0, "free pages stay in the file");
    }

    /// A collection removes the directories of the layers no row names (a
    /// pull that wrote its files and did not commit) and the temporary file
    /// of a writer that died, and leaves the files a row names; so does the
    /// sweep of a store nobody holds, which a busy store leaves alone.
    #[tokio::test]
    async fn a_collection_removes_the_layer_files_no_row_names() {
        use velarx_db::layer_files::{self, TOC};
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db")).await.unwrap();
        let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
        let staging = dir.path().join("staging");
        let driver: Arc<dyn StorageDriver> = Arc::new(ComposefsDriver::new(
            db.clone(),
            store.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
            crate::storage_driver::composefs::options_for_tests(&staging),
        ));
        let image = crate::services::ImageService::new(
            db.clone(),
            store.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
        )
        .unwrap();
        let gc = GcService::of_store(driver, db.clone(), store, &staging);
        let layer = |n: u8| {
            let d: velarx_types::digest::Digest =
                format!("sha256:{}", format!("{n:02x}").repeat(32))
                    .parse()
                    .unwrap();
            velarx_types::LayerKey::Whole(d)
        };
        let (named, orphan) = (layer(1), layer(2));
        let record = |key: velarx_types::LayerKey| velarx_db::LayerRecord {
            stream_size: Some(0),
            inline: 0,
            key,
            blob: Some(*key.digest()),
            diff_id: Some(*key.digest()),
            other_diff_id: None,
            size: 1,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs: None,
            owners: None,
        };
        db.insert_layer_with_toc(dir.path(), &record(named), b"table")
            .await
            .unwrap();
        let table = velarx_types::digest::Digest::of(named.digest().alg(), b"table");
        layer_files::write(dir.path(), &orphan, TOC, b"table").unwrap();
        // (what another store has, a read-only one, is not this store's)
        let other = tempfile::tempdir().unwrap();
        layer_files::write(other.path(), &orphan, TOC, b"table").unwrap();
        let temporary = layer_files::layers_dir(dir.path()).join(".tmpdead");
        std::fs::write(&temporary, b"half").unwrap();
        // a store that a pull holds is left alone
        let busy = StorageLock::shared(&StorageLock::path_of_staging(&staging))
            .await
            .unwrap();
        image.sweep_layer_files().await;
        assert!(layer_files::layer_dir(dir.path(), &orphan).exists());
        drop(busy);
        image.sweep_layer_files().await;
        assert!(layer_files::file(dir.path(), &named, TOC, &table).is_file());
        assert!(!layer_files::layer_dir(dir.path(), &orphan).exists());
        assert!(!temporary.exists());
        // and the collection does the same
        layer_files::write(dir.path(), &orphan, TOC, b"table").unwrap();
        let report = gc.collect(GcOptions::default()).await.unwrap();
        assert!(report.bytes_freed >= 5, "{report:?}");
        assert!(!layer_files::layer_dir(dir.path(), &orphan).exists());
        // (no image uses the layer: it goes with its row)
        assert!(!layer_files::layer_dir(dir.path(), &named).exists());
        assert!(layer_files::layer_dir(other.path(), &orphan).exists());
    }
}

/// What the report says it freed: each object once, by what it took, and the
/// layers by their size as the images count it.
#[cfg(test)]
mod layer_tests {
    use super::*;
    use crate::storage_driver::ComposefsDriver;
    use velarx_fuse::composefs as cfs;
    use velarx_graph::forward_storage_driver;

    struct Fixture {
        _dir: tempfile::TempDir,
        db: velarx_db::Database,
        store: Arc<FileStore>,
        gc: GcService,
        key: velarx_db::LayerKey,
    }

    /// A store with the layer `key` that no image uses: its row, its object
    /// and its image.
    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open(dir.path().join("db"))
            .await
            .unwrap();
        let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
        let staging = dir.path().join("staging");
        let driver = Arc::new(ComposefsDriver::new(
            db.clone(),
            store.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
            crate::storage_driver::composefs::options_for_tests(&staging),
        ));
        let gc = GcService::of_store(driver, db.clone(), store.clone(), &staging);
        let key = velarx_db::LayerKey::Toc(format!("sha256:{}", "ab".repeat(32)).parse().unwrap());
        let file = format!("sha256-12:{}", "cd".repeat(32));
        let toc = serde_json::json!({"version": 1, "entries": [
            {"name": "f", "type": "reg", "size": 4, "fsverity": file}
        ]});
        db.insert_layer_with_toc(
            dir.path(),
            &velarx_db::LayerRecord {
                stream_size: Some(0),
                inline: 0,
                key,
                blob: Some(format!("sha256:{}", "ef".repeat(32)).parse().unwrap()),
                diff_id: None,
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: String::new(),
                registry_ref: None,
                erofs: Some("sha256:ee".into()),
                owners: None,
            },
            &zstd::encode_all(toc.to_string().as_bytes(), 3).unwrap(),
        )
        .await
        .unwrap();
        let f = Fixture {
            _dir: dir,
            db,
            store,
            gc,
            key,
        };
        for p in [f.object(), f.image()] {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"data").unwrap();
        }
        f
    }

    impl Fixture {
        fn object(&self) -> std::path::PathBuf {
            self.store
                .local_path(&format!("fsverity-sha256-12:{}", "cd".repeat(32)))
                .unwrap()
        }

        fn image(&self) -> std::path::PathBuf {
            cfs::layer_image_path(self.store.root(), &self.key.file_stem())
        }
    }

    /// The staged layers a collection removes are reported: the engine that
    /// runs it tells the fetchers of its pulls to forget them.
    #[tokio::test]
    async fn a_collection_reports_the_staged_layers_it_removes() {
        use velarx_content::pull::staged::{NewLayer, StagedLayerMeta};
        let f = fixture().await;
        let key =
            velarx_types::LayerKey::Toc(format!("sha256:{}", "12".repeat(32)).parse().unwrap());
        let area = f.gc.staging();
        area.publish_layer(&NewLayer {
            meta: StagedLayerMeta {
                key: key.to_string(),
                blob: format!("sha256:{}", "34".repeat(32)),
                size: 1,
                registry_ref: None,
                reach: Default::default(),
                erofs: "sha256:ee".into(),
                owners: String::new(),
                created_at: String::new(),
            },
            tarsplit: b"",
            toc_z: b"",
        })
        .unwrap();
        assert_eq!(area.unnamed_layers(), [key]);
        let report = f.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!(report.staged_layers, [key]);
        assert!(area.unnamed_layers().is_empty());
    }

    /// A layer no row uses whose image a mount or a server holds open stays,
    /// with its row and its image, in the release after an `rmi` and in a
    /// collection (its dry run too); once nothing holds it, it goes.
    /// (in a process of its own: the lock is the open file's, which a
    /// process that another test forks shares until it runs its program,
    /// and would hold beyond the drop here)
    #[test]
    fn a_layer_whose_image_is_held_is_not_collected() {
        velarx_base::testing::in_child(|| {
            block_on(async {
                let f = fixture().await;
                let held = cfs::open_layer_image(&f.image()).unwrap();
                let dry = GcOptions {
                    dry_run: true,
                    ..Default::default()
                };
                assert_eq!(f.gc.collect(dry.clone()).await.unwrap().layers_removed, 0);
                let report = f.gc.release_unused_layers().await.unwrap();
                assert_eq!(report.layers_removed, 0);
                let report = f.gc.collect(GcOptions::default()).await.unwrap();
                assert_eq!(report.layers_removed, 0);
                assert!(report.errors.is_empty(), "{:?}", report.errors);
                assert_eq!(f.db.layer_digests().await.unwrap(), [f.key]);
                assert!(f.image().exists(), "the image stays");
                drop(held);
                assert_eq!(f.gc.collect(dry).await.unwrap().layers_removed, 1);
                let report = f.gc.collect(GcOptions::default()).await.unwrap();
                assert_eq!(report.layers_removed, 1);
                assert!(f.db.layer_digests().await.unwrap().is_empty());
                assert!(!f.image().exists());
            });
        });
    }

    /// The question is never answered by a guess: an image that cannot be
    /// opened for the lock (a link that loops, where it should be) is an
    /// error, and the collection removes nothing.
    #[tokio::test]
    async fn a_layer_that_cannot_be_asked_is_not_collected() {
        let f = fixture().await;
        std::fs::remove_file(f.image()).unwrap();
        std::os::unix::fs::symlink(f.image(), f.image()).unwrap();
        let e = f.gc.release_unused_layers().await.unwrap_err();
        assert!(matches!(e, GcError::Driver(_)), "{e}");
        let e = f.gc.collect(GcOptions::default()).await.unwrap_err();
        assert!(matches!(e, GcError::Driver(_)), "{e}");
        assert_eq!(f.db.layer_digests().await.unwrap(), [f.key]);
        assert!(f.object().exists());
    }

    /// A driver that tells how many layers it was asked to lock at most at
    /// once (a descriptor each, held until they are removed).
    struct Counting {
        inner: Arc<dyn StorageDriver>,
        most: std::sync::atomic::AtomicUsize,
    }

    forward_storage_driver! {
        impl StorageDriver for Counting {
            inner: inner;
            forward: [name graph_name capabilities graph_data status pull has_layers repair remake_staged read_objects open_object objects_in_order collect remove_image image_volume_create mounts image_view leftovers check writable_create writable_paths writable_root writable_size writable_remove writable_exists diff changes apply stopped_view is_root_of usage];
            fn lock_unused_layers(
                &self,
                layers: &[velarx_types::LayerKey],
            ) -> velarx_graph::DriverResult<velarx_graph::UnusedLayers> {
                self.most
                    .fetch_max(layers.len(), std::sync::atomic::Ordering::Relaxed);
                self.inner.lock_unused_layers(layers)
            }
        }
    }

    /// More unused layers than a shell allows open files are collected (and
    /// counted by a dry run), with at most [`LOCK_BATCH`] images held at once: the
    /// number of layers is never a reason to remove nothing.
    #[tokio::test]
    async fn many_layers_are_collected_with_a_few_held_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open(dir.path().join("db"))
            .await
            .unwrap();
        let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
        let staging = dir.path().join("staging");
        let counting = Arc::new(Counting {
            inner: Arc::new(ComposefsDriver::new(
                db.clone(),
                store.clone(),
                staging.clone(),
                velarx_storage::VerityMode::Off,
                crate::storage_driver::composefs::options_for_tests(&staging),
            )),
            most: Default::default(),
        });
        let gc = GcService::of_store(counting.clone(), db.clone(), store.clone(), &staging);
        let n = 1100;
        // (the release after an `rmi` first, then a collection)
        for round in 0..2 {
            for i in 0..n {
                add_layer(&db, &store, i).await;
            }
            let dry = GcOptions {
                dry_run: true,
                ..Default::default()
            };
            assert_eq!(gc.collect(dry).await.unwrap().layers_removed, n);
            let report = if round == 0 {
                gc.release_unused_layers().await.unwrap()
            } else {
                gc.collect(GcOptions::default()).await.unwrap()
            };
            assert_eq!(report.layers_removed, n);
            assert!(db.layer_digests().await.unwrap().is_empty());
        }
        let most = counting.most.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            most > 0 && most <= velarx_graph::unused::LOCK_BATCH,
            "{most}"
        );
    }

    /// The layer number `i`, ready, with its image in the store.
    async fn add_layer(db: &velarx_db::Database, store: &FileStore, i: usize) {
        let key = velarx_db::LayerKey::Toc(format!("sha256:{i:064x}").parse().unwrap());
        db.insert_layer(&velarx_db::LayerRecord {
            stream_size: Some(0),
            inline: 0,
            key,
            blob: Some(format!("sha256:{}", "ef".repeat(32)).parse().unwrap()),
            diff_id: None,
            other_diff_id: None,
            size: 1,
            status: "ready".into(),
            created_at: String::new(),
            registry_ref: None,
            erofs: None,
            owners: None,
        })
        .await
        .unwrap();
        let image = cfs::layer_image_path(store.root(), &key.file_stem());
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(image, b"image").unwrap();
    }

    /// More layers than the soft limit of open files, that a test runs
    /// under: `body` runs in a runtime of its own in a child process whose
    /// limit is [`FEW`] descriptors, which a collection that held the lock of
    /// every layer at once would exceed.
    const FEW: u64 = 400;
    const MANY: usize = 1100;

    fn with_few_descriptors(body: impl std::future::Future<Output = ()>) {
        let now = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(FEW),
                maximum: now.maximum,
            },
        )
        .unwrap();
        block_on(body);
    }

    /// `body` in a runtime of its own (a test in a child process).
    fn block_on(body: impl std::future::Future<Output = ()>) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(body);
    }

    /// The release after an `rmi` and the collection of more unused layers
    /// than the process may open files go in turns, and remove them all.
    #[test]
    fn collecting_more_layers_than_the_open_file_limit_goes_in_turns() {
        velarx_base::testing::in_child(|| {
            with_few_descriptors(async {
                let dir = tempfile::tempdir().unwrap();
                let db = velarx_db::Database::open(dir.path().join("db"))
                    .await
                    .unwrap();
                let store = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
                let staging = dir.path().join("staging");
                let driver = Arc::new(ComposefsDriver::new(
                    db.clone(),
                    store.clone(),
                    staging.clone(),
                    velarx_storage::VerityMode::Off,
                    crate::storage_driver::composefs::options_for_tests(&staging),
                ));
                let gc = GcService::of_store(driver, db.clone(), store.clone(), &staging);
                for round in 0..2 {
                    for i in 0..MANY {
                        add_layer(&db, &store, i).await;
                    }
                    let report = if round == 0 {
                        gc.release_unused_layers().await.unwrap()
                    } else {
                        gc.collect(GcOptions::default()).await.unwrap()
                    };
                    assert_eq!(report.layers_removed, MANY, "{:?}", report.errors);
                    assert!(db.layer_digests().await.unwrap().is_empty());
                }
            });
        });
    }
}

#[cfg(test)]
mod freed_tests {
    use super::*;
    use crate::storage_driver::ComposefsDriver;
    use velarx_fuse::composefs as cfs;

    struct Store {
        _dir: tempfile::TempDir,
        db: velarx_db::Database,
        files: Arc<FileStore>,
        staging: PathBuf,
        gc: GcService,
    }

    async fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let db = velarx_db::Database::open(dir.path().join("db"))
            .await
            .unwrap();
        let files = Arc::new(FileStore::new(dir.path().join("objects")).unwrap());
        let staging = dir.path().join("staging");
        let driver: Arc<dyn StorageDriver> = Arc::new(ComposefsDriver::new(
            db.clone(),
            files.clone(),
            staging.clone(),
            velarx_storage::VerityMode::Off,
            crate::storage_driver::composefs::options_for_tests(&staging),
        ));
        let gc = GcService::of_store(driver, db.clone(), files.clone(), &staging);
        Store {
            _dir: dir,
            db,
            files,
            staging,
            gc,
        }
    }

    fn name(n: u8) -> String {
        format!("fsverity-sha256-12:{}", format!("{n:02x}").repeat(32))
    }

    impl Store {
        /// The layer `n` with the files of `files` (number, bytes): their
        /// objects, rows and references; `stream` is its size as an image
        /// counts it, and the row says it has one byte of blob.  Its image
        /// is `image` bytes when it has one.
        async fn layer(
            &self,
            n: u8,
            stream: i64,
            files: &[(u8, usize)],
            image: usize,
        ) -> velarx_db::LayerKey {
            let key = velarx_db::LayerKey::Toc(
                format!("sha256:{}", format!("{n:02x}").repeat(32))
                    .parse()
                    .unwrap(),
            );
            self.db
                .insert_layer(&velarx_db::LayerRecord {
                    stream_size: Some(stream),
                    inline: 0,
                    key,
                    blob: Some(format!("sha256:{}", "ef".repeat(32)).parse().unwrap()),
                    diff_id: None,
                    other_diff_id: None,
                    size: 1,
                    status: "ready".into(),
                    created_at: String::new(),
                    registry_ref: None,
                    erofs: None,
                    owners: None,
                })
                .await
                .unwrap();
            for (f, bytes) in files {
                let digest = name(*f);
                let path = self.files.local_path(&digest).unwrap();
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, vec![7u8; *bytes]).unwrap();
                let (key, digest, bytes) = (key, digest, *bytes as i64);
                self.db
                    .conn()
                    .call(move |c| {
                        c.execute(
                            "INSERT OR IGNORE INTO files (digest, size, created_at) VALUES (?1, ?2, '')",
                            rusqlite::params![digest, bytes],
                        )?;
                        c.execute(
                            "INSERT INTO file_refs (layer_id, file_digest) VALUES (?1, ?2)",
                            rusqlite::params![key, digest],
                        )?;
                        Ok(())
                    })
                    .await
                    .unwrap();
            }
            if image > 0 {
                let path = cfs::layer_image_path(self.files.root(), &key.file_stem());
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, vec![1u8; image]).unwrap();
            }
            key
        }
    }

    /// A layer with N bytes of files is N bytes once: not N and the size of
    /// the layer (whatever its row says) on top, and the layer's size, as the
    /// images count it, is a number of its own.
    #[tokio::test]
    async fn a_layer_with_files_frees_their_bytes_once() {
        let s = store().await;
        s.layer(1, 5000, &[(1, 100), (2, 300)], 0).await;
        let dry =
            s.gc.collect(GcOptions {
                dry_run: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!((dry.bytes_freed, dry.layers_size), (400, 5000));
        let report = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!(report.bytes_freed, 400, "{report:?}");
        assert_eq!(
            (
                report.layers_removed,
                report.files_removed,
                report.layers_size
            ),
            (1, 2, 5000)
        );
        assert!(!s.files.contains(&name(1)));
        let again = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!((again.bytes_freed, again.layers_size), (0, 0));
    }

    /// A collection that removes a layer removes its composefs image with it
    /// and counts it, as the release after an image removal does: not the
    /// next collection.
    #[tokio::test]
    async fn a_collection_frees_the_image_of_a_layer_it_removes() {
        let s = store().await;
        let key = s.layer(1, 50, &[(1, 100)], 9).await;
        let image = cfs::layer_image_path(s.files.root(), &key.file_stem());
        let report = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!(report.bytes_freed, 100 + 9, "{report:?}");
        assert!(!image.exists());
        let again = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!(again.bytes_freed, 0, "{again:?}");
    }

    /// A dry run counts what the collection then frees: an object no row
    /// names (what a pull that died left) too, and nothing of the files
    /// with a row while a pull runs, which the collection keeps.
    #[tokio::test]
    async fn a_dry_run_counts_what_the_collection_frees() {
        let s = store().await;
        s.layer(1, 50, &[(1, 100)], 0).await;
        let orphan = s.files.local_path(&name(9)).unwrap();
        std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        std::fs::write(&orphan, [3u8; 70]).unwrap();
        let dry = GcOptions {
            dry_run: true,
            ..Default::default()
        };

        std::fs::create_dir_all(&s.staging).unwrap();
        let held = holds::Hold::create(&s.staging, "pull-0000cafe").unwrap();
        let pulling = s.gc.collect(dry.clone()).await.unwrap();
        assert_eq!(pulling.bytes_freed, 70, "{pulling:?}");
        assert!(orphan.exists());
        let report = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!(report.bytes_freed, pulling.bytes_freed, "{report:?}");
        assert!(s.files.contains(&name(1)) && !orphan.exists());
        drop(held);

        let predicted = s.gc.collect(dry).await.unwrap();
        assert_eq!(predicted.bytes_freed, 100, "{predicted:?}");
        let report = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!(report.bytes_freed, predicted.bytes_freed, "{report:?}");
    }

    /// The same for the release after an image removal, with the image of the
    /// layer counted once (the driver's) and a file two layers have.
    #[tokio::test]
    async fn releasing_layers_counts_a_shared_file_once() {
        let s = store().await;
        s.layer(1, 10, &[(1, 100), (2, 30)], 7).await;
        s.layer(2, 20, &[(1, 100), (3, 5)], 9).await;
        let report = s.gc.release_unused_layers().await.unwrap();
        // 100 + 30 + 5 of the files, 7 + 9 of the images, the shared 100
        // once
        assert_eq!(report.bytes_freed, 135 + 16, "{report:?}");
        assert_eq!((report.layers_removed, report.files_removed), (2, 3));
        assert_eq!(report.layers_size, 30);
    }

    /// A file whose object is gone frees nothing, one whose row says more
    /// than the object has frees what it has, and a layer row with a size
    /// that cannot be one counts for nothing: the numbers are what the store
    /// had, never negative.
    #[tokio::test]
    async fn the_numbers_are_what_the_store_had() {
        let s = store().await;
        s.layer(1, -5, &[(1, 100), (2, 40)], 0).await;
        let gone = s.files.local_path(&name(1)).unwrap();
        std::fs::remove_file(gone).unwrap();
        // the row of the second says more than the object has
        s.db.conn()
            .call(|c| {
                c.execute("UPDATE files SET size = 4000 WHERE digest = ?1", [name(2)])?;
                Ok(())
            })
            .await
            .unwrap();
        let dry =
            s.gc.collect(GcOptions {
                dry_run: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!((dry.bytes_freed, dry.layers_size), (40, 0));
        let report = s.gc.collect(GcOptions::default()).await.unwrap();
        assert_eq!((report.bytes_freed, report.layers_size), (40, 0));
    }

    #[test]
    fn a_report_never_wraps() {
        let mut r = GcReport {
            bytes_freed: u64::MAX - 1,
            layers_size: u64::MAX - 1,
            ..Default::default()
        };
        r.add_freed(10);
        r.add_layer_size(i64::MAX);
        r.add_layer_size(-1);
        assert_eq!((r.bytes_freed, r.layers_size), (u64::MAX, u64::MAX));
    }
}
