// SPDX-License-Identifier: Apache-2.0
mod build_cache;
mod changes;
pub use changes::ChangeWatch;
mod checks;
pub mod layer_files;
mod manifests;
pub mod namespaces;
mod schema;
mod staged;
mod stores;
pub mod sync;
pub mod volatile;
pub mod volumes;

pub mod container_ext;
pub use container_ext::ContainerExt;
pub mod network_ext;
pub use network_ext::{Ip6Choice, IpChoice};

use rusqlite::OptionalExtension as _;
use std::path::Path;
use std::sync::Arc;
use tokio_rusqlite::Connection;
use tracing::info;
use velarx_types::digest::Digest;
use velarx_types::{DbError, DbResult};

fn io_error(path: &Path, e: std::io::Error) -> DbError {
    DbError::Sqlite(tokio_rusqlite::Error::Other(
        format!("{}: {e}", path.display()).into(),
    ))
}

use velarx_storage::Object;

pub use build_cache::SCRATCH as BUILD_SCRATCH;
pub use manifests::ManifestListRecord;
pub use schema::*;
pub use staged::StagedImageCommit;

/// What a change of a container's state writes elsewhere (its event) while
/// the change is not committed yet.
pub type Announce = Box<dyn FnOnce() + Send>;

#[derive(Clone)]
pub struct Database {
    conn: Arc<Conn>,
    /// The file of the database (none in memory)
    path: Option<Arc<std::path::PathBuf>>,
    /// Where the files of its layers are read from (the directory of the
    /// database; none in memory), shared by the clones of the database
    /// ([`Database::with_layer_files`])
    files: Arc<std::sync::RwLock<Option<Arc<dyn layer_files::Source>>>>,
    /// The databases of the read-only stores under this one, whose
    /// images, layers and files are found when this one has not got them
    more: Arc<Vec<Database>>,
}

/// A container by its ID or its name (`?2`: the name without the `/` that
/// Docker shows): each term an index (an expression of `name`, such as
/// `'/' || name`, is a scan of every container, at every lookup).
const GET_CONTAINER: &str =
    "SELECT id, name, image_id, config, state, pid, created_at, started_at, finished_at, exit_code
     FROM containers WHERE id = ?1 OR name = ?1 OR name = ?2";

/// The image of the containers made from a directory (`--rootfs`), which is
/// not listed.
pub const ROOTFS_IMAGE_ID: &str = "-rootfs-";

/// How long a connection waits for the others.  Several processes share the
/// database (the API server, the engine run by a unit, monitors): a writer
/// waits for the others instead of failing with SQLITE_BUSY.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How many connections to the store this process has opened.  While one is
/// open, a new connection finds the index of the log in shared memory; the
/// first one of a process rebuilds it from the whole -wal file (milliseconds,
/// more as the log grows).  Counted for the trace: a command opens the store
/// cold once (`db open cold`, tests/perf/phases.py and
/// tests/e2e/bats/run-*.bats).
static KEPT: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

/// The connections of the stores this process opened (the engine's, the
/// service's), which `close_all` closes when the process ends.
static OPEN: std::sync::Mutex<Vec<std::sync::Weak<Conn>>> = std::sync::Mutex::new(Vec::new());

/// The process that registered `close_all` with the end of the process: a
/// child that forks from it and ends has no connection thread to ask.
static CLOSER: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// A connection to the store is opened: the trace point says whether it is
/// the first of the process.
/// The rows of `sql` for each of `keys`: its `{marks}` is the list of
/// their placeholders, one query for every 500 (far below the limit of the
/// variables of a statement), each row through `map`.
pub(crate) fn query_in<T>(
    conn: &rusqlite::Connection,
    sql: &str,
    keys: &[String],
    mut map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> rusqlite::Result<Vec<T>> {
    let mut out = Vec::new();
    for chunk in keys.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare(&sql.replace("{marks}", &marks))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(chunk), &mut map)?;
        for row in rows {
            out.push(row?);
        }
    }
    Ok(out)
}

fn trace_open() {
    let cold = KEPT.load(std::sync::atomic::Ordering::Relaxed) <= 0;
    velarx_base::trace::point(if cold { "db open cold" } else { "db open" });
}

/// Close the connections of the stores this process opened, for the end of
/// the process (`exit` skips the `Drop`s that would close them, and SQLite
/// leaves the log of a connection that does not close).
pub fn close_all() {
    let open: Vec<_> = std::mem::take(&mut *OPEN.lock().unwrap_or_else(|e| e.into_inner()))
        .into_iter()
        .filter_map(|c| c.upgrade())
        .collect();
    if open.is_empty() {
        return;
    }
    velarx_base::trace::point("db close");
    // (a thread: the process may end in a task of a runtime, which cannot
    // wait for another future)
    let _ = std::thread::Builder::new()
        .name("db-close".into())
        .spawn(move || {
            for conn in open {
                block_on(async { close_connection(&conn).await });
            }
        })
        .map(|t| t.join());
    velarx_base::trace::point("db closed");
}

/// The connection of a `Database`, which is closed, and waited for, when the
/// last handle of the database goes: the connection thread of
/// `tokio_rusqlite` closes at its own pace, and a process that ends before
/// it has done leaves the log of the store.
pub struct Conn {
    conn: Option<Connection>,
    /// Touched after each commit that changed rows (see `changes`); none
    /// for a database in memory or a read-only store
    changes: Option<Arc<changes::Changes>>,
    /// Whether it has a log to write back (not a database in memory, nor
    /// a read-only store opened immutable)
    file: bool,
    /// Whether it was closed (`close_connection`): what it answers from
    /// then on is the empty database that took its place
    closed: std::sync::atomic::AtomicBool,
}

impl Conn {
    fn new(conn: Connection, file: bool, changes: Option<changes::Changes>) -> Self {
        Self {
            conn: Some(conn),
            changes: changes.map(Arc::new),
            file,
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Conn {
    /// Run `function` on the connection.  When it changed rows (what it
    /// committed is published when it returns), the other processes are
    /// told, once and after the commit: every write of the database goes
    /// through here, so no writer has to remember to.  (A write that is
    /// rolled back tells too: whoever wakes looks and finds nothing new.)
    ///
    /// Rows changed in a transaction that the call leaves open are told by
    /// the call that ends it, never before its commit.
    pub async fn call<F, R>(&self, function: F) -> tokio_rusqlite::Result<R>
    where
        F: FnOnce(&mut rusqlite::Connection) -> tokio_rusqlite::Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let connection = self.raw();
        let Some(changes) = self.changes.clone() else {
            return connection.call(function).await;
        };
        connection
            .call(move |conn| {
                let before = conn.total_changes();
                volatile::call_begins();
                let result = function(conn);
                let changed = conn.total_changes().saturating_sub(before);
                volatile::call_ends(conn, i64::try_from(changed).unwrap_or(i64::MAX));
                changes.changed(changed != 0, conn.is_autocommit());
                result
            })
            .await
    }

    /// The connection itself, which tells nobody: for this module only
    /// (the close), every other call goes through [`Self::call`].
    fn raw(&self) -> &Connection {
        self.conn
            .as_ref()
            .expect("the connection is there until the drop")
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take().filter(|_| self.file) else {
            return;
        };
        // (a thread: this may be a task of a runtime, which cannot wait for
        // another future)
        let _ = std::thread::Builder::new()
            .name("db-close".into())
            .spawn(move || block_on(close_raw(&conn)))
            .map(|t| t.join());
    }
}

/// Wait for `future` on a runtime of its own.
fn block_on<F: std::future::Future>(future: F) -> Option<F::Output> {
    let rt = tokio::runtime::Builder::new_current_thread().build().ok()?;
    Some(rt.block_on(future))
}

/// Close `conn` (see `Database::close`).
async fn close_connection(conn: &Conn) -> tokio_rusqlite::Result<()> {
    conn.closed
        .store(true, std::sync::atomic::Ordering::Release);
    close_raw(conn.raw()).await
}

async fn close_raw(conn: &Connection) -> tokio_rusqlite::Result<()> {
    conn.call(|conn| {
        // (in memory: nothing to write back, and nothing left behind)
        if conn.path().is_none_or(str::is_empty) {
            return Ok(());
        }
        let open = std::mem::replace(conn, rusqlite::Connection::open_in_memory()?);
        // (a process that wrote only volatile rows leaves the log to the next
        // one, see `volatile`)
        volatile::before_close(&open);
        let path = open.path().map(std::path::PathBuf::from);
        open.close().map_err(|(_, e)| e)?;
        if let Some(path) = path {
            volatile::after_close(&path);
        }
        Ok(())
    })
    .await
}

extern "C" fn close_at_exit() {
    if CLOSER.get() == Some(&std::process::id()) {
        close_all();
    }
}

/// How many free pages one step of [`Database::shrink`] gives back.
const SHRINK_STEP: u32 = 1000;

/// The journal mode the database of `conn` is in after it was asked to be in
/// WAL: SQLite answers the mode it has, which is not WAL for a file system
/// that cannot share memory between the processes.
fn set_wal(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    check_wal(&mode)
}

/// Whether `mode` is the WAL the store needs.
fn check_wal(mode: &str) -> rusqlite::Result<()> {
    if mode.eq_ignore_ascii_case("wal") {
        return Ok(());
    }
    Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
        std::io::Error::other(format!(
            "the database is in the journal mode `{mode}`, not WAL: the processes of a store \
             share it through WAL (is the store on a file system that cannot map shared memory?)"
        )),
    )))
}

/// The value of `PRAGMA auto_vacuum` for INCREMENTAL.
const AUTO_VACUUM_INCREMENTAL: i64 = 2;

/// The settings of every connection to a store's database.  `file`: it is a
/// file (an in-memory database has no WAL).
fn apply_pragmas(conn: &rusqlite::Connection, file: bool, cache_kib: u32) -> rusqlite::Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // (first: a write of the pragmas below commits without a sync)
    conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
    if file {
        // (before the first table: the pages the rows free are given back
        // by `Database::shrink`, in steps.  Asked first: setting it is a
        // write of the header of the file, a commit at every open of every
        // command, which the next process's open of a store another one is
        // closing waited for)
        let mode: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
        if mode != AUTO_VACUUM_INCREMENTAL {
            conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL;")?;
            volatile::mark_durable();
        }
        set_wal(conn)?;
    }
    // Foreign keys for the CASCADE deletes.
    conn.execute_batch(&format!(
        "PRAGMA foreign_keys = ON;
         PRAGMA wal_autocheckpoint = {AUTOCHECKPOINT};
         PRAGMA cache_size = -{cache_kib};
         PRAGMA temp_store = MEMORY;"
    ))
}

/// The pages of the log after which a commit writes it back.
const AUTOCHECKPOINT: u32 = 1000;

/// The page cache of the connections of the engine, in KiB.
const CACHE_KIB: u32 = 64000;

impl Database {
    /// Watch the commits to the database, made by this process or another
    /// one (a container, an image, a layer, a manifest: whatever changed
    /// rows): look at them after making the watch, and again after each
    /// return.
    pub fn watch_changes(&self) -> std::io::Result<ChangeWatch> {
        ChangeWatch::new(
            self.path
                .as_deref()
                .zip(self.conn.changes.as_deref())
                .map(|(p, c)| (p.as_path(), c)),
        )
    }

    pub async fn open<P: AsRef<Path>>(path: P) -> DbResult<Self> {
        let path = path.as_ref().to_path_buf();
        trace_open();
        velarx_base::ipc::make_private_file(&path).map_err(|e| io_error(&path, e))?;
        let changes =
            changes::open(&path).map_err(|e| tokio_rusqlite::Error::Other(Box::new(e)))?;
        let conn = Connection::open(&path).await?;
        KEPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let conn = Arc::new(Conn::new(conn, true, Some(changes::Changes::new(changes))));
        {
            let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
            open.retain(|c| c.strong_count() > 0);
            open.push(Arc::downgrade(&conn));
        }
        CLOSER.get_or_init(|| {
            velarx_sys::process::at_exit(close_at_exit);
            std::process::id()
        });
        let db = Self {
            conn,
            files: layer_files::of_directory(path.parent()),
            path: Some(Arc::new(path)),
            more: Arc::new(Vec::new()),
        };
        db.init_pragmas().await?;
        db.init_schema().await?;
        // (the connection of the namespaces of the command closes now that
        // this one is open: this one writes the log back)
        volatile::release(db.path.as_deref().map(|p| p.as_path()));
        velarx_base::trace::point("db ready");
        Ok(db)
    }

    pub async fn open_in_memory() -> DbResult<Self> {
        let conn = Connection::open_in_memory().await?;
        let db = Self {
            conn: Arc::new(Conn::new(conn, false, None)),
            path: None,
            files: layer_files::of_directory(None),
            more: Arc::new(Vec::new()),
        };
        db.init_pragmas().await?;
        db.init_schema().await?;
        Ok(db)
    }

    async fn init_pragmas(&self) -> DbResult<()> {
        let file = self.path.is_some();
        self.conn
            .call(move |conn| {
                apply_pragmas(conn, file, CACHE_KIB)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn init_schema(&self) -> DbResult<()> {
        self.conn
            .call(|conn| schema::init(conn).map_err(|e| tokio_rusqlite::Error::Other(Box::new(e))))
            .await?;
        Ok(())
    }

    /// Get a reference to the underlying connection (for raw queries)
    pub fn conn(&self) -> &Conn {
        &self.conn
    }

    /// The size of the write-ahead log, 0 when there is none.
    pub fn wal_size(&self) -> u64 {
        let Some(path) = &self.path else {
            return 0;
        };
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        std::fs::metadata(wal).map(|m| m.len()).unwrap_or(0)
    }

    /// Write the log back to the database and truncate it when it grew past
    /// `limit` bytes (SQLite's own checkpoints never shrink the file, and
    /// cannot finish while readers keep old pages).  Whether it was done.
    pub async fn compact_wal(&self, limit: u64) -> DbResult<bool> {
        if self.wal_size() <= limit {
            return Ok(false);
        }
        self.checkpoint().await?;
        Ok(true)
    }

    /// Whether the database answers: a read of its schema.
    pub async fn ping(&self) -> DbResult<()> {
        self.conn
            .call(|conn| {
                conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Checkpoint the WAL file to main database (call periodically or at clean shutdown)
    pub async fn checkpoint(&self) -> DbResult<()> {
        self.conn
            .call(|conn| {
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Give the pages the removed rows freed back to the file system and
    /// empty the log: the file stays what its rows need.  The free pages go
    /// in steps of [`SHRINK_STEP`], each its own write, so that the other
    /// processes of the store are never held for long.
    /// A store made before its file had `auto_vacuum` keeps its free pages
    /// (they are used again by the next rows).
    pub async fn shrink(&self) -> DbResult<()> {
        let mut before = i64::MAX;
        loop {
            let left = self.shrink_step().await?;
            // (none left, or none given back: a file without auto_vacuum)
            if left == 0 || left >= before {
                break;
            }
            before = left;
        }
        self.checkpoint().await
    }

    /// Give back up to [`SHRINK_STEP`] free pages in one write; the pages
    /// still free.  The pragma gives a row, and frees a page, for each step
    /// of its statement: it is stepped to its end here (`execute_batch` steps
    /// a statement once, and gives back one page).
    async fn shrink_step(&self) -> DbResult<i64> {
        Ok(self
            .conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare(&format!("PRAGMA incremental_vacuum({SHRINK_STEP})"))?;
                let mut rows = stmt.query([])?;
                while rows.next()?.is_some() {}
                drop(rows);
                drop(stmt);
                Ok(conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?)
            })
            .await?)
    }

    /// Close the connection.  When it is the last one to the store, SQLite
    /// writes the log of the database back into it and removes the `-wal` and
    /// `-shm` files (a disk wait for the log, none when nothing was written);
    /// another process that has the store open leaves that to the one that
    /// closes last, and this does not wait for it.  The database of this
    /// handle, and of its clones, is empty from then on: the end of a
    /// process, not a pause.
    pub async fn close(&self) -> DbResult<()> {
        close_connection(&self.conn).await?;
        Ok(())
    }

    /// Stop the thread of the connection, as a connection that went away:
    /// every later call fails.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn stop(&self) -> DbResult<()> {
        self.conn.raw().clone().close().await?;
        Ok(())
    }

    /// Whether the database was closed, at the end of the process: a task
    /// that still runs finds it empty, and what it cannot read is not a
    /// fault of the store.
    pub fn is_closed(&self) -> bool {
        self.conn.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn insert_image(&self, image: &ImageRecord) -> DbResult<()> {
        let image = image.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(manifest_digest) DO NOTHING",
                    rusqlite::params![
                        image.id,
                        image.manifest_digest,
                        image.config_digest,
                        image.manifest,
                        image.config,
                        image.created_at,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_image_here(&self, id: &str) -> DbResult<ImageRecord> {
        let owned = id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, manifest_digest, config_digest, manifest, config, created_at
                     FROM images WHERE id = ?1",
                )?;
                let image = stmt.query_row([&owned], ImageRecord::from_row)?;
                Ok(image)
            })
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(format!("image {}", id))
                }
                _ => DbError::Sqlite(e),
            })
    }

    /// The id of the image of a manifest: the one it was recorded with, here
    /// or in a read-only store, or the whole hex of `new` for an image not
    /// stored yet (the manifest's own digest for an image that was pulled;
    /// the configuration's for one that was made here, whose manifest is
    /// only written when it is pushed).  An image keeps the id it was
    /// recorded with.  Two manifests of one configuration made here are given
    /// one id: the image of that configuration, which has the last one.
    pub async fn image_id_for(&self, manifest_digest: &Digest, new: &Digest) -> DbResult<String> {
        match self.get_image_by_digest(manifest_digest).await {
            Ok(image) => Ok(image.id),
            Err(DbError::NotFound(_)) => Ok(new.hex()),
            Err(e) => Err(e),
        }
    }

    async fn get_image_by_digest_here(&self, digest: &Digest) -> DbResult<ImageRecord> {
        let digest = *digest;
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, manifest_digest, config_digest, manifest, config, created_at
                     FROM images WHERE manifest_digest = ?1",
                )?;
                let image = stmt.query_row([&digest], ImageRecord::from_row)?;
                Ok(image)
            })
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(format!("image with digest {digest}"))
                }
                _ => DbError::Sqlite(e),
            })
    }

    async fn list_images_here(&self) -> DbResult<Vec<ImageRecord>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, manifest_digest, config_digest, manifest, config, created_at
                     FROM images WHERE id != '-rootfs-' ORDER BY created_at DESC",
                )?;
                let images = stmt
                    .query_map([], ImageRecord::from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(images)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn delete_image(&self, id: &str) -> DbResult<()> {
        let owned = id.to_string();
        self.conn
            .call(move |conn| delete_image(conn, &owned))
            .await
            .map_err(|e| refusal(e, || format!("image {}", id)))
    }

    /// Remove the name `repository:tag` (whatever image has it).
    pub async fn delete_image_tag(&self, repository: &str, tag: &str) -> DbResult<()> {
        let (repository, tag) = (repository.to_string(), tag.to_string());
        self.conn
            .call(move |c| delete_image_tag(c, &repository, &tag))
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn insert_image_tag(&self, tag: &ImageTag) -> DbResult<()> {
        // a name of this store names an image of this store
        self.import_image(&tag.image_id).await?;
        let tag = tag.clone();
        tracing::info!(
            "DB: Inserting tag {}:{} for image {}",
            tag.repository,
            tag.tag,
            tag.image_id
        );
        self.conn
            .call(move |conn| {
                // The name is the image's already and the last one it was
                // given: a write would change nothing and still cost its
                // syncs.
                let unchanged: bool = conn.query_row(
                    "SELECT EXISTS (SELECT 1 FROM image_tags
                                    WHERE repository = ?1 AND tag = ?2 AND image_id = ?3)
                        AND NOT EXISTS (SELECT 1 FROM manifest_list_names
                                        WHERE repository = ?1 AND tag = ?2)
                        AND COALESCE((SELECT repository = ?1 AND tag = ?2
                                      FROM image_name_history WHERE image_id = ?3
                                      ORDER BY rowid DESC LIMIT 1), 0)",
                    rusqlite::params![tag.repository, tag.tag, tag.image_id],
                    |r| r.get(0),
                )?;
                if unchanged {
                    return Ok(());
                }
                let tx = conn.transaction()?;
                // A name is an image's or a manifest list's.
                tx.execute(
                    "DELETE FROM manifest_list_names WHERE repository = ?1 AND tag = ?2",
                    rusqlite::params![tag.repository, tag.tag],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO image_tags (repository, tag, image_id)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![tag.repository, tag.tag, tag.image_id],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        tracing::info!("DB: Tag inserted successfully");
        Ok(())
    }

    async fn get_image_by_tag_here(&self, repository: &str, tag: &str) -> DbResult<ImageRecord> {
        let (owned_repo, owned_tag) = (repository.to_string(), tag.to_string());
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT i.id, i.manifest_digest, i.config_digest, i.manifest, i.config, i.created_at
                     FROM images i
                     JOIN image_tags t ON i.id = t.image_id
                     WHERE t.repository = ?1 AND t.tag = ?2",
                )?;
                let image = stmt.query_row([&owned_repo, &owned_tag], ImageRecord::from_row)?;
                Ok(image)
            })
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(format!("image {repository}:{tag}"))
                }
                _ => DbError::Sqlite(e),
            })
    }

    async fn get_tags_for_image_here(&self, image_id: &str) -> DbResult<Vec<ImageTag>> {
        let image_id = image_id.to_string();
        let image_id_for_log = image_id.clone();
        let result = self
            .conn
            .call(move |conn| image_tags(conn, &image_id))
            .await
            .map_err(DbError::Sqlite);

        if let Ok(ref tags) = result {
            tracing::debug!(
                "DB: Found {} tags for image {}",
                tags.len(),
                image_id_for_log
            );
        }
        result
    }

    /// Every name the image had, the last one given first (podman's
    /// NamesHistory); a name `repository@digest` has the tag `@digest`.
    pub async fn get_name_history(&self, image_id: &str) -> DbResult<Vec<ImageTag>> {
        let image_id = image_id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT repository, tag, image_id FROM image_name_history
                     WHERE image_id = ?1 ORDER BY rowid DESC",
                )?;
                let tags = stmt
                    .query_map([&image_id], |row| {
                        Ok(ImageTag {
                            repository: row.get(0)?,
                            tag: row.get(1)?,
                            image_id: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(tags)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The setting `key` of the store, recorded the first time: what it
    /// already was, or `value` now kept.
    pub async fn store_setting(&self, key: &str, value: &str) -> DbResult<String> {
        let (key, value) = (key.to_string(), value.to_string());
        self.conn
            .call(move |conn| store_setting(conn, &key, &value))
            .await
            .map_err(DbError::Sqlite)
    }

    /// Whether an image was removed whose layers were not released yet (a
    /// monitor removes the image of `--rmi` and cannot collect the layers).
    pub async fn gc_pending(&self) -> DbResult<bool> {
        self.conn.call(gc_pending).await.map_err(DbError::Sqlite)
    }

    /// Set or clear [`Self::gc_pending`].
    pub async fn set_gc_pending(&self, pending: bool) -> DbResult<()> {
        self.conn
            .call(move |conn| set_gc_pending(conn, pending))
            .await
            .map_err(DbError::Sqlite)
    }

    /// Keep the bytes of the index `digest` (a pull of an image by the
    /// digest of an index): a start that verifies the image from that digest
    /// hashes them again.  Bytes of one digest are always the same.
    pub async fn set_index(&self, digest: &Digest, bytes: &str) -> DbResult<()> {
        let (key, bytes) = (format!("index:{digest}"), bytes.to_string());
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO store_settings (key, value) VALUES (?1, ?2)",
                    rusqlite::params![key, bytes],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Forget the kept indexes that list no image of the store nor one of
    /// `staged` (the manifest digests of the pulls in progress), neither
    /// themselves nor through a kept index they list.  The number forgotten.
    pub async fn forget_unlisted_indexes(&self, staged: Vec<Digest>) -> DbResult<usize> {
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut indexes: Vec<(String, String)> = tx
                    .prepare("SELECT key, value FROM store_settings WHERE key LIKE 'index:%'")?
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                let mut listed: Vec<String> = tx
                    .prepare("SELECT manifest_digest FROM images")?
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?;
                listed.extend(staged.iter().map(Digest::to_string));
                // (an index that lists a listed digest is kept, and its own
                // digest is then listed: as deep as indexes go)
                while !listed.is_empty() {
                    let (kept, rest) = indexes
                        .into_iter()
                        .partition(|(_, v)| listed.iter().any(|d| v.contains(d.as_str())));
                    indexes = rest;
                    listed = kept
                        .into_iter()
                        .map(|(k, _): (String, String)| k["index:".len()..].to_string())
                        .collect();
                }
                for (key, _) in &indexes {
                    tx.execute("DELETE FROM store_settings WHERE key = ?1", [key])?;
                }
                tx.commit()?;
                Ok(indexes.len())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The bytes kept for the index `digest`, as stored (not checked).
    pub async fn index(&self, digest: &Digest) -> DbResult<Option<String>> {
        let key = format!("index:{digest}");
        self.conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT value FROM store_settings WHERE key = ?1")?;
                let mut rows = stmt.query([&key])?;
                Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn insert_layer(&self, layer: &LayerRecord) -> DbResult<()> {
        let layer = layer.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO layers (id, diff_id, size, created_at, registry_ref, blob, stream_size)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(id) DO NOTHING",
                    rusqlite::params![
                        layer.key,
                        layer.diff_id,
                        layer.size,
                        layer.created_at,
                        layer.registry_ref,
                        layer.blob,
                        layer.stream_size,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// [`Self::insert_layer`] of a layer whose table of contents is `toc_z`,
    /// a file written in the store `root` as a pull writes it (for the tests
    /// of what reads it).
    #[cfg(any(test, feature = "test-support"))]
    pub async fn insert_layer_with_toc(
        &self,
        root: &Path,
        layer: &LayerRecord,
        toc_z: &[u8],
    ) -> DbResult<()> {
        let digest = layer_files::write(root, &layer.key, layer_files::TOC, toc_z)
            .map_err(|e| io_error(&layer_files::layer_dir(root, &layer.key), e))?;
        self.insert_layer(layer).await?;
        let key = layer.key;
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE layers SET toc_digest = ?2 WHERE id = ?1",
                    rusqlite::params![key, digest],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_layer_here(&self, key: &LayerKey) -> DbResult<LayerRecord> {
        let key = *key;
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {} FROM layers l WHERE l.id = ?1",
                    LayerRecord::COLUMNS
                ))?;
                let layer = stmt.query_row([&key], LayerRecord::from_row)?;
                Ok(layer)
            })
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(format!("layer {key}"))
                }
                _ => DbError::Sqlite(e),
            })
    }

    /// Record the EROFS image of the layer `key`: its fs-verity digest
    /// and the owners of its files.
    pub async fn set_layer_erofs(&self, key: &LayerKey, erofs: &str, owners: &str) -> DbResult<()> {
        let (key, erofs, owners) = (*key, erofs.to_string(), owners.to_string());
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE layers SET erofs = ?2, owners = ?3 WHERE id = ?1",
                    rusqlite::params![key, erofs, owners],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Whether every layer of `keys` is sealed (`layers.sealed`: made with
    /// fs-verity).
    pub async fn layers_sealed(&self, keys: &[LayerKey]) -> DbResult<bool> {
        let keys = keys.to_vec();
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT coalesce(sealed, 0) FROM layers WHERE id = ?1")?;
                for key in &keys {
                    let sealed = stmt
                        .query_row([key], |r| r.get::<_, i64>(0))
                        .optional()?
                        .unwrap_or(0);
                    if sealed != 1 {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .await?)
    }

    /// Record whether the EROFS image of the layer `key` was made with
    /// fs-verity (`layers.sealed`): the value it has now, whatever the image
    /// made before had.
    pub async fn set_layer_sealed(&self, key: &LayerKey, sealed: bool) -> DbResult<()> {
        let key = *key;
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE layers SET sealed = ?2 WHERE id = ?1",
                    rusqlite::params![key, sealed],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Mark the layer `key` incomplete: its row says it has no tar-split, so
    /// the store no longer reports it as stored (a pull fetches it again, as
    /// a layer committed without one) and an image that has it stays
    /// recorded.  The record of its EROFS image stays: `system check
    /// --repair` makes the image again against it.  No file is removed (a
    /// pull that wrote one and commits after this would name a file that is
    /// gone): the collection removes them with the layer.  The other layers
    /// are not touched.  Only a layer pulled from a registry (`registry_ref`) is
    /// marked: the tar-split of a layer made here (a commit, a build, a load)
    /// is in no registry, and a pull could not bring it back.
    pub async fn mark_layer_incomplete(&self, key: &LayerKey) -> DbResult<LayerMarking> {
        let key = *key;
        Ok(self
            .conn
            .call(move |conn| {
                let changed = conn.execute(
                    "UPDATE layers SET tarsplit_digest = NULL WHERE id = ?1 AND registry_ref IS NOT NULL",
                    [&key],
                )?;
                if changed > 0 {
                    return Ok(LayerMarking::Marked);
                }
                let here: bool = conn.query_row(
                    "SELECT EXISTS (SELECT 1 FROM layers WHERE id = ?1)",
                    [&key],
                    |row| row.get(0),
                )?;
                Ok(if here {
                    LayerMarking::NotPulled
                } else {
                    LayerMarking::NotHere
                })
            })
            .await?)
    }

    /// This database with the files of its layers read from `source`: the
    /// storage driver that keeps them, or a directory (for the tests of a
    /// database in memory, and of a store made apart).  The clones of the
    /// database have it too.
    pub fn with_layer_files(self, source: Arc<dyn layer_files::Source>) -> Self {
        *self.files.write().unwrap_or_else(|e| e.into_inner()) = Some(source);
        self
    }

    /// The row of the layer `key` as far as its files go: the digests of its
    /// table of contents and of its tar-split.
    async fn layer_files_here(
        &self,
        key: &LayerKey,
    ) -> DbResult<Option<(Option<Digest>, Option<String>)>> {
        let key = *key;
        self.conn
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT toc_digest, tarsplit_digest FROM layers WHERE id = ?1",
                        [&key],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The digests of the files the row of the layer `key` names, of its
    /// table of contents and of its tar-split (none for a layer without one,
    /// or that is not complete); none for a layer with no row.  A storage
    /// service opens the files by them.
    pub async fn layer_file_digests(
        &self,
        key: &LayerKey,
    ) -> DbResult<Option<(Option<Digest>, Option<Digest>)>> {
        Ok(self
            .layer_files_here(key)
            .await?
            .map(|(toc, tarsplit)| (toc, tarsplit.and_then(|t| t.parse().ok()))))
    }

    /// The file `name` of the layer `key` once its digest is checked: the
    /// one of this store's source, or of a read-only store (an image of one
    /// has its rows copied here, not its files), whichever has the file with
    /// that digest.
    async fn read_layer_file(
        &self,
        key: &LayerKey,
        name: &'static str,
        expected: Digest,
    ) -> DbResult<Vec<u8>> {
        let key = *key;
        let sources: Vec<Arc<dyn layer_files::Source>> = std::iter::once(self)
            .chain(self.more.iter())
            .filter_map(|db| db.files.read().unwrap_or_else(|e| e.into_inner()).clone())
            .collect();
        tokio::task::spawn_blocking(move || {
            // (what the first source says if none has it)
            let mut first = None;
            for source in &sources {
                match source
                    .read(&key, name, &expected)
                    .and_then(|bytes| layer_files::checked(bytes, &expected))
                {
                    Ok(bytes) => return Ok(bytes),
                    Err(e) => {
                        first.get_or_insert(e);
                    }
                }
            }
            let e = first.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "the store has no files")
            });
            Err(DbError::Sqlite(tokio_rusqlite::Error::Other(
                format!("layer {key}: {name}: {e}").into(),
            )))
        })
        .await
        .map_err(|e| DbError::Sqlite(tokio_rusqlite::Error::Other(Box::new(e))))?
    }

    /// The compressed table of contents of a layer, if it has one (none for
    /// a layer with no row), checked against its digest (see `layer_files`).
    async fn get_layer_toc_z_here(&self, key: &LayerKey) -> DbResult<Option<Vec<u8>>> {
        let Some((Some(digest), _)) = self.layer_files_here(key).await? else {
            return Ok(None);
        };
        self.read_layer_file(key, layer_files::TOC, digest)
            .await
            .map(Some)
    }

    /// The compressed tar-split of a layer, if it has one: none for a layer
    /// that is not complete, empty for a layer that needs none, checked
    /// against its digest.
    async fn get_layer_tarsplit_here(&self, key: &LayerKey) -> DbResult<Option<Vec<u8>>> {
        let Some((_, tarsplit)) = self.layer_files_here(key).await? else {
            return Ok(None);
        };
        match tarsplit {
            None => Ok(None),
            Some(text) if text.is_empty() => Ok(Some(Vec::new())),
            Some(text) => {
                let digest = text.parse().map_err(|e| {
                    DbError::Sqlite(tokio_rusqlite::Error::Other(
                        format!("layer {key}: its tar-split digest {text:?}: {e}").into(),
                    ))
                })?;
                self.read_layer_file(key, layer_files::TARSPLIT, digest)
                    .await
                    .map(Some)
            }
        }
    }

    /// What the layers `keys` of this store (not the read-only ones) say of
    /// themselves, one query for every 500 keys: only the layers that have a
    /// row are returned.  Neither the table of contents nor the tar-split is
    /// read, only whether each is there.
    async fn get_layer_states_here(&self, keys: &[LayerKey]) -> DbResult<Vec<LayerState>> {
        let keys: Vec<String> = keys.iter().map(LayerKey::to_string).collect();
        self.conn
            .call(move |conn| {
                Ok(query_in(
                    conn,
                    "SELECT l.id, l.diff_id, l.diff_id_other, \
                     l.tarsplit_digest IS NOT NULL, l.toc_digest IS NOT NULL \
                     FROM layers l WHERE l.id IN ({marks})",
                    &keys,
                    |row| {
                        Ok(LayerState {
                            key: row.get(0)?,
                            diff_id: row.get(1)?,
                            other_diff_id: row.get(2)?,
                            has_tarsplit: row.get(3)?,
                            has_toc: row.get(4)?,
                        })
                    },
                )?)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn insert_image_layer(
        &self,
        image_id: &str,
        layer: &LayerKey,
        index: i32,
    ) -> DbResult<()> {
        info!("DB: insert_image_layer image={image_id} layer={layer} index={index}");
        let image_id = image_id.to_string();
        let layer_digest = layer.to_string();
        let result = self
            .conn
            .call(move |conn| {
                let rows = conn.execute(
                    "INSERT OR IGNORE INTO image_layers (image_id, layer_id, layer_index)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![image_id, layer_digest, index],
                )?;
                Ok(rows)
            })
            .await?;
        info!("DB: insert_image_layer result: {} rows affected", result);
        Ok(())
    }

    async fn get_image_layers_here(&self, image_id: &str) -> DbResult<Vec<LayerRecord>> {
        let image_id = image_id.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {} FROM layers l
                     JOIN image_layers il ON l.id = il.layer_id
                     WHERE il.image_id = ?1
                     ORDER BY il.layer_index",
                    LayerRecord::COLUMNS
                ))?;
                let layers = stmt
                    .query_map([&image_id], LayerRecord::from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(layers)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The blob of the descriptor each complete layer of this store (one with
    /// a tar-split) was pulled for, by the layer's key: the key of a layer
    /// pulled through its table of contents is not the digest of its blob,
    /// which is what a puller names the layer by.
    pub async fn layer_blobs(&self) -> DbResult<std::collections::HashMap<LayerKey, String>> {
        self.conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, blob FROM layers WHERE tarsplit_digest IS NOT NULL")?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<_, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The keys of every layer of this store, whatever its state.
    pub async fn layer_digests(&self) -> DbResult<Vec<LayerKey>> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT id FROM layers")?;
                let digests = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(digests)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// List all layers
    pub async fn list_layers(&self) -> DbResult<Vec<LayerRecord>> {
        self.conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare(&format!("SELECT {} FROM layers l", LayerRecord::COLUMNS))?;
                let layers = stmt
                    .query_map([], LayerRecord::from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(layers)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Get all file refs for a layer
    pub async fn get_layer_file_refs(&self, layer: &LayerKey) -> DbResult<Vec<FileRef>> {
        let layer_digest = layer.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT layer_id, file_digest, ref_count FROM file_refs WHERE layer_id = ?1",
                )?;
                let refs = stmt
                    .query_map([&layer_digest], |row| {
                        Ok(FileRef {
                            layer: row.get(0)?,
                            file_digest: row.get(1)?,
                            ref_count: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(refs)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// List all files
    pub async fn list_files(&self) -> DbResult<Vec<FileRecord>> {
        self.conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT digest, size, created_at, checked FROM files")?;
                let files = stmt
                    .query_map([], |row| {
                        Ok(FileRecord {
                            digest: row.get(0)?,
                            size: row.get(1)?,
                            created_at: row.get(2)?,
                            checked: row.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(files)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn insert_container(&self, container: &ContainerRecord) -> DbResult<()> {
        self.insert_container_in(container, None).await
    }

    /// Insert the container, but only if its SELinux level (`selinux_level`)
    /// is not `taken` by the level of a container there is: `taken(level,
    /// used)` is asked of each of the levels in use.  The check runs in the
    /// transaction that inserts (a write lock taken first), so two creations
    /// that chose their level before either was recorded cannot both keep
    /// it.  [`DbError::LevelTaken`] when it is taken.  For a level the
    /// engine allocated: one the user gave, or the one of a pod, is shared
    /// on purpose and goes through [`Database::insert_container`].
    pub async fn insert_container_distinct(
        &self,
        container: &ContainerRecord,
        taken: fn(&str, &str) -> bool,
    ) -> DbResult<()> {
        self.insert_container_in(container, Some(taken)).await
    }

    async fn insert_container_in(
        &self,
        container: &ContainerRecord,
        distinct: Option<fn(&str, &str) -> bool>,
    ) -> DbResult<()> {
        // the image of a container is an image of this store
        self.import_image(&container.image_id).await?;
        let container = container.clone();
        let (selinux_level, targets) = config_refs(&container.config);
        let removed = config_removes(&container.config);
        self.conn
            .call(move |conn| {
                volatile::run(conn, removed, |conn| {
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                if let (Some(taken), Some(level)) = (distinct, &selinux_level) {
                    let mut stmt = tx.prepare(
                        "SELECT selinux_level FROM containers WHERE selinux_level IS NOT NULL",
                    )?;
                    let used = stmt
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    if used.iter().any(|u| taken(level, u)) {
                        return Err(tokio_rusqlite::Error::Other(Box::new(LevelTaken(
                            level.clone(),
                        ))));
                    }
                }
                tx.execute(
                    "INSERT INTO containers (id, name, image_id, config, state, pid, created_at, started_at, finished_at, exit_code, selinux_level)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    rusqlite::params![
                        container.id,
                        container.name,
                        container.image_id,
                        container.config,
                        container.state,
                        container.pid,
                        container.created_at,
                        container.started_at,
                        container.finished_at,
                        container.exit_code,
                        selinux_level,
                    ],
                )?;
                for target in targets {
                    tx.execute(
                        "INSERT INTO container_deps (container_id, target) VALUES (?1, ?2)",
                        rusqlite::params![container.id, target],
                    )?;
                }
                tx.commit()?;
                Ok(())
                })
            })
            .await
            .map_err(|e| refusal(e, String::new))?;
        Ok(())
    }

    /// The container of this ID or name; `/NAME` is the name too, as
    /// Docker shows them and podman takes them.
    pub async fn get_container(&self, id: &str) -> DbResult<ContainerRecord> {
        let owned = id.to_string();
        self.conn
            .call(move |conn| get_container(conn, &owned))
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(format!("container {}", id))
                }
                _ => DbError::Sqlite(e),
            })
    }

    pub async fn list_containers(&self, all: bool) -> DbResult<Vec<ContainerRecord>> {
        self.conn
            .call(move |conn| list_containers(conn, all))
            .await
            .map_err(DbError::Sqlite)
    }

    /// The containers whose record says their processes are there (running
    /// or paused), as [`Self::list_containers`] orders them.
    pub async fn list_alive_containers(&self) -> DbResult<Vec<ContainerRecord>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, name, image_id, config, state, pid, created_at, started_at, finished_at, exit_code
                     FROM containers WHERE state IN ('running', 'paused') ORDER BY created_at DESC",
                )?;
                let containers = stmt
                    .query_map([], ContainerRecord::from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(containers)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Check if any containers reference the given image ID
    pub async fn image_has_containers(&self, image_id: &str) -> DbResult<bool> {
        let image_id = image_id.to_string();
        self.conn
            .call(move |conn| {
                let count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM containers WHERE image_id = ?1",
                    [&image_id],
                    |row| row.get(0),
                )?;
                Ok(count > 0)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Get container IDs that reference the given image ID
    pub async fn containers_using_image(&self, image_id: &str) -> DbResult<Vec<String>> {
        let image_id = image_id.to_string();
        self.conn
            .call(move |conn| containers_using_image(conn, &image_id))
            .await
            .map_err(DbError::Sqlite)
    }

    /// How many containers use each image (as [`Self::containers_using_image`]
    /// tells for one), for the images that have any: one scan of the
    /// containers for all of them.
    pub async fn container_counts_by_image(
        &self,
    ) -> DbResult<std::collections::HashMap<String, usize>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT image, count(*) FROM (
                         SELECT image_id AS image, id FROM containers
                         UNION
                         SELECT json_extract(m.value, '$.image.image'), c.id
                         FROM containers c, json_each(c.config, '$.mounts') m)
                     WHERE image IS NOT NULL GROUP BY image",
                )?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get::<_, usize>(1)?)))?;
                Ok(rows.collect::<rusqlite::Result<std::collections::HashMap<_, _>>>()?)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn update_container_state(
        &self,
        id: &str,
        state: RecordState,
        pid: Option<i32>,
        started_at: Option<String>,
        finished_at: Option<String>,
        exit_code: Option<i32>,
    ) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                update_container_state(conn, &id, state, pid, started_at, finished_at, exit_code)
            })
            .await?;
        Ok(())
    }

    /// A container that exited and starts again by its restart policy is
    /// stopped meanwhile; `announce` runs in the same transaction, before it
    /// is committed (see [`Self::record_container_exit_announcing`]).
    pub async fn record_container_restarting(
        &self,
        id: &str,
        finished_at: String,
        exit_code: i32,
        announce: Announce,
    ) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                record_container_restarting(conn, &id, &finished_at, exit_code, announce)
            })
            .await?;
        Ok(())
    }

    /// Record the exit of a container that is not stopped yet: true when
    /// this call did (the processes that follow the same container, a
    /// command and the engine service, both see the exit; the one that
    /// records it tells it).  With `started_at` the exit is the one of the
    /// run that started then: a container that started again since (its
    /// start is later) is left alone.  (The start a starter records may
    /// come a moment before the monitor's own, when the monitor waited for
    /// a client to start the container: that run's exit is still its own.)
    pub async fn record_container_exit(
        &self,
        id: &str,
        finished_at: String,
        exit_code: i32,
        started_at: Option<String>,
    ) -> DbResult<bool> {
        self.record_container_exit_announcing(
            id,
            finished_at,
            exit_code,
            started_at,
            false,
            Box::new(|| {}),
        )
        .await
    }

    /// [`Self::record_container_exit`] with `announce` run, when this call
    /// records the exit, in the same transaction before it is committed:
    /// whoever sees the container stopped sees what `announce` wrote (its
    /// `died` event).  `removal`: the container goes with its exit (`--rm`):
    /// the row says so ([`Self::removals_pending`]) until its removal is done
    /// or given up, so that a removal that was interrupted is finished by
    /// the next process that opens the store.
    pub async fn record_container_exit_announcing(
        &self,
        id: &str,
        finished_at: String,
        exit_code: i32,
        started_at: Option<String>,
        removal: bool,
        announce: Announce,
    ) -> DbResult<bool> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                record_container_exit_announcing(
                    conn,
                    &id,
                    &finished_at,
                    exit_code,
                    started_at.as_deref(),
                    removal,
                    announce,
                )
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The containers that went with their exit (`--rm`) whose removal was
    /// not done: its process ended before it did (a killed monitor).  One
    /// read of a partial index, empty when nothing was interrupted.
    pub async fn removals_pending(&self) -> DbResult<Vec<String>> {
        self.conn
            .call(removals_pending)
            .await
            .map_err(DbError::Sqlite)
    }

    /// Whether the removal of the container `id` is due ([`Self::removals_pending`]).
    pub async fn removal_pending(&self, id: &str) -> DbResult<bool> {
        let id = id.to_string();
        self.conn
            .call(move |conn| removal_pending(conn, &id))
            .await
            .map_err(DbError::Sqlite)
    }

    /// [`clear_removal`] of the container `id`.
    pub async fn clear_removal(&self, id: &str) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| clear_removal(conn, &id))
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn delete_container(&self, id: &str) -> DbResult<()> {
        let owned = id.to_string();
        let done = self
            .conn
            .call(move |conn| delete_container(conn, &owned))
            .await
            .map_err(|e| refusal(e, || format!("container {}", id)));
        done
    }

    /// The SELinux levels the containers have (`selinux_level`).
    pub async fn container_selinux_levels(&self) -> DbResult<Vec<String>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT selinux_level FROM containers WHERE selinux_level IS NOT NULL",
                )?;
                let levels = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(levels)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The ids of the other containers whose config refers to the container
    /// `id` named `name` (`container_deps`): by its id, its name, or a
    /// prefix of its id of 12 characters or more.
    pub async fn container_dependents(&self, id: &str, name: &str) -> DbResult<Vec<String>> {
        let (id, name) = (id.to_string(), name.to_string());
        self.conn
            .call(move |conn| container_dependents(conn, &id, &name))
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn rename_container(&self, id: &str, new_name: &str) -> DbResult<()> {
        let owned = id.to_string();
        let new_name = new_name.to_string();
        let done = self
            .conn
            .call(move |conn| {
                let rows = conn.execute(
                    "UPDATE containers SET name = ?2 WHERE id = ?1",
                    rusqlite::params![owned, new_name],
                )?;
                if rows == 0 {
                    return Err(no_row());
                }
                Ok(())
            })
            .await
            .map_err(|e| refusal(e, || format!("container {}", id)));
        done
    }

    pub async fn insert_network(&self, network: &NetworkRecord) -> DbResult<()> {
        let network = network.clone();
        self.conn
            .call(move |conn| {
                insert_network_in(conn, &network)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Insert the network `network`, but only if `check` accepts it given
    /// the networks there are: the check runs in the transaction that
    /// inserts (a write lock taken first), so two creations at once cannot
    /// both pass it.  `check` gives the reason when it refuses
    /// ([`DbError::AlreadyExists`]); the name is unique too.
    pub async fn insert_network_checked(
        &self,
        network: &NetworkRecord,
        check: impl FnOnce(&[NetworkRecord]) -> Result<(), String> + Send + 'static,
    ) -> DbResult<()> {
        let network = network.clone();
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let existing = list_networks_in(&tx)?;
                if existing.iter().any(|n| n.name == network.name) {
                    return Err(already_exists(format!(
                        "network name {} already used: network already exists",
                        network.name
                    )));
                }
                if let Err(why) = check(&existing) {
                    return Err(already_exists(why));
                }
                insert_network_in(&tx, &network)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| refusal(e, String::new))
    }

    /// Remove the network `id` (or name) unless containers use it (`force`:
    /// whatever uses it) in one transaction: a container that attaches
    /// meanwhile either is counted or finds the network gone
    /// ([`Database::net_attach`]).  Those that exited and are being removed
    /// (`--rm`) do not count.  [`DbError::AlreadyExists`] when it is used.
    pub async fn delete_network_unused(&self, id: &str, force: bool) -> DbResult<()> {
        let owned = id.to_string();
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let id: Option<String> = tx
                    .query_row(
                        "SELECT id FROM networks WHERE id = ?1 OR name = ?1",
                        [&owned],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(id) = id else {
                    return Err(no_row());
                };
                if !force {
                    let users: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM network_attachments a
                         JOIN containers c ON c.id = a.container_id
                         WHERE a.network_id = ?1
                           AND NOT (COALESCE(json_extract(c.config, '$.auto_remove'), 0)
                                    AND c.state IN ('stopped', 'exited'))",
                        [&id],
                        |r| r.get(0),
                    )?;
                    if users > 0 {
                        return Err(already_exists(format!("network {owned} is being used")));
                    }
                }
                tx.execute("DELETE FROM networks WHERE id = ?1", [&id])?;
                // (the last address given goes with it, whatever its driver)
                tx.execute("DELETE FROM network_ipam WHERE network_id = ?1", [&id])?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(|e| refusal(e, || format!("network {id}")))
    }

    pub async fn get_network(&self, id: &str) -> DbResult<NetworkRecord> {
        let owned = id.to_string();
        self.conn
            .call(move |conn| get_network(conn, &owned))
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(format!("network {}", id))
                }
                _ => DbError::Sqlite(e),
            })
    }

    pub async fn list_networks(&self) -> DbResult<Vec<NetworkRecord>> {
        self.conn
            .call(|conn| Ok(list_networks_in(conn)?))
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn insert_userns_allocation(&self, alloc: &UsernsAllocation) -> DbResult<()> {
        let alloc = alloc.clone();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO userns_allocations (id, label, uid_start, uid_count, gid_start, gid_count, container_id, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        alloc.id,
                        alloc.label,
                        alloc.uid_start,
                        alloc.uid_count,
                        alloc.gid_start,
                        alloc.gid_count,
                        alloc.container_id,
                        alloc.created_at,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_userns_allocations(&self) -> DbResult<Vec<UsernsAllocation>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, label, uid_start, uid_count, gid_start, gid_count, container_id, created_at
                     FROM userns_allocations ORDER BY created_at DESC",
                )?;
                let allocations = stmt
                    .query_map([], |row| {
                        Ok(UsernsAllocation {
                            id: row.get(0)?,
                            label: row.get(1)?,
                            uid_start: row.get(2)?,
                            uid_count: row.get(3)?,
                            gid_start: row.get(4)?,
                            gid_count: row.get(5)?,
                            container_id: row.get(6)?,
                            created_at: row.get(7)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(allocations)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn delete_userns_allocation(&self, id: &str) -> DbResult<()> {
        let owned = id.to_string();
        self.conn
            .call(move |conn| {
                let rows =
                    conn.execute("DELETE FROM userns_allocations WHERE id = ?1", [&owned])?;
                if rows == 0 {
                    return Err(no_row());
                }
                Ok(())
            })
            .await
            .map_err(|e| refusal(e, || format!("userns allocation {}", id)))
    }

    pub async fn get_allocated_uid_ranges(&self) -> DbResult<Vec<(u32, u32)>> {
        self.conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare("SELECT uid_start, uid_count FROM userns_allocations")?;
                let ranges = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ranges)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn get_allocated_gid_ranges(&self) -> DbResult<Vec<(u32, u32)>> {
        self.conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare("SELECT gid_start, gid_count FROM userns_allocations")?;
                let ranges = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(ranges)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Where the chunk can be found (the file digest and offset): in a file
    /// that has it.
    pub async fn get_chunk_location(
        &self,
        chunk_digest: &Digest,
    ) -> DbResult<Option<ChunkLocation>> {
        Ok(self
            .get_chunk_locations_batch(std::slice::from_ref(chunk_digest))
            .await?
            .remove(chunk_digest))
    }

    /// Batch get chunk locations (much faster than individual calls)
    /// Returns a HashMap from chunk_digest to ChunkLocation
    pub async fn get_chunk_locations_batch(
        &self,
        chunk_digests: &[Digest],
    ) -> DbResult<std::collections::HashMap<Digest, ChunkLocation>> {
        if chunk_digests.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let chunk_digests = chunk_digests.to_vec();
        self.conn
            .call(move |conn| {
                let mut result = std::collections::HashMap::new();
                // SQLite has a limit on query parameters, so batch in groups
                const BATCH_SIZE: usize = 500;
                for batch in chunk_digests.chunks(BATCH_SIZE) {
                    let placeholders: String = batch.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                    let query = format!(
                        "SELECT chunk_digest, file_digest, offset, size FROM chunk_locations WHERE chunk_digest IN ({})",
                        placeholders
                    );
                    let mut stmt = conn.prepare(&query)?;
                    let params: Vec<&dyn rusqlite::ToSql> = batch.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                    let rows = stmt.query_map(params.as_slice(), |row| {
                        Ok(ChunkLocation {
                            chunk_digest: row.get(0)?,
                            file_digest: row.get(1)?,
                            offset: row.get::<_, i64>(2)? as u64,
                            size: row.get::<_, i64>(3)? as u64,
                        })
                    })?;
                    for row in rows {
                        let loc = row?;
                        result.insert(loc.chunk_digest, loc);
                    }
                }
                Ok(result)
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The bytes of the manifest or of the configuration of an image that
    /// each of `digests` names, or of a kept index (as the store keeps
    /// them), in one call.
    pub async fn image_metadata(&self, digests: &[Digest]) -> DbResult<Vec<Option<String>>> {
        let digests = digests.to_vec();
        Ok(self
            .conn
            .call(move |conn| {
                use rusqlite::OptionalExtension;
                let mut stmt = conn.prepare_cached(
                    "SELECT CASE WHEN manifest_digest = ?1 THEN manifest ELSE config END
                     FROM images WHERE manifest_digest = ?1 OR config_digest = ?1
                     UNION ALL
                     SELECT value FROM store_settings WHERE key = 'index:' || ?1
                     LIMIT 1",
                )?;
                digests
                    .iter()
                    .map(|d| stmt.query_row([d], |r| r.get(0)).optional())
                    .collect::<Result<_, _>>()
                    .map_err(Into::into)
            })
            .await?)
    }

    /// The file of the database (none in memory).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref().map(|p| p.as_path())
    }

    /// The objects of the files `digests` that are recorded, asked by
    /// batches.
    pub(crate) async fn file_objects_here(
        &self,
        digests: Vec<String>,
    ) -> DbResult<std::collections::HashMap<String, Object>> {
        const BATCH: usize = 500;
        Ok(self
            .conn
            .call(move |conn| {
                let mut out = std::collections::HashMap::new();
                for batch in digests.chunks(BATCH) {
                    let marks = vec!["?"; batch.len()].join(",");
                    let mut stmt = conn.prepare_cached(&format!(
                        "SELECT digest, checked FROM files WHERE digest IN ({marks})"
                    ))?;
                    let rows = stmt.query_map(rusqlite::params_from_iter(batch.iter()), |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
                    })?;
                    for row in rows {
                        let (d, checked) = row?;
                        // (a name that is not a digest is not an object)
                        if let Some(o) = Object::new(&d, checked) {
                            out.insert(d, o);
                        }
                    }
                }
                Ok(out)
            })
            .await?)
    }

    /// The first of the files `(digest, size)` that the store records with
    /// another size: its digest, the size the store has and the one given.
    /// A digest names one content, which has one size.
    pub async fn file_size_conflict(
        &self,
        files: Vec<(String, u64)>,
    ) -> DbResult<Option<(String, u64, u64)>> {
        const BATCH: usize = 500;
        Ok(self
            .conn
            .call(move |conn| {
                for batch in files.chunks(BATCH) {
                    let marks = vec!["?"; batch.len()].join(",");
                    let mut stmt = conn.prepare_cached(&format!(
                        "SELECT digest, size FROM files WHERE digest IN ({marks})"
                    ))?;
                    let stored = stmt
                        .query_map(
                            rusqlite::params_from_iter(batch.iter().map(|f| &f.0)),
                            |r| Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?)),
                        )?
                        .collect::<Result<std::collections::HashMap<_, _>, _>>()?;
                    let conflict = batch.iter().find_map(|(digest, size)| {
                        let held = *stored.get(digest)?;
                        (held != *size).then(|| (digest.clone(), held, *size))
                    });
                    if conflict.is_some() {
                        return Ok(conflict);
                    }
                }
                Ok(None)
            })
            .await?)
    }

    /// The objects of all the files of this store.
    pub async fn all_file_objects(&self) -> DbResult<std::collections::HashMap<String, Object>> {
        Ok(self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT digest, checked FROM files")?;
                let rows =
                    stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))?;
                let mut out = std::collections::HashMap::new();
                for row in rows {
                    let (d, checked) = row?;
                    // (a row that names no object is a store of another
                    // velarx: its files are not taken for orphans)
                    let Some(o) = Object::new(&d, checked) else {
                        return Err(tokio_rusqlite::Error::Other(
                            format!(
                                "the store records the file `{d}`, which is no fs-verity digest of an object \
                                 (fsverity-sha256-12:HEX or fsverity-sha512-12:HEX): a store of another velarx \
                                 (remove it)"
                            )
                            .into(),
                        ));
                    };
                    out.insert(d, o);
                }
                Ok(out)
            })
            .await?)
    }

    /// Record that the image of manifest `digest` was pulled by
    /// `reference`, with the signatures found (JSON, `signatures`); a pull
    /// by the same reference replaces it.
    pub async fn set_pulled_image(
        &self,
        digest: &Digest,
        reference: &str,
        signatures: Vec<u8>,
    ) -> DbResult<()> {
        let (digest, reference) = (*digest, reference.to_string());
        self.conn
            .call(move |conn| {
                // (a pull that finds the same record writes nothing)
                conn.execute(
                    "INSERT INTO pulled_images (manifest_digest, reference, signatures)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(manifest_digest, reference)
                     DO UPDATE SET signatures = excluded.signatures
                     WHERE signatures IS NOT excluded.signatures",
                    rusqlite::params![digest, reference, signatures],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// The pulls of the image of manifest `digest`: the references and
    /// the signatures.
    pub async fn pulled_image(&self, digest: &Digest) -> DbResult<Vec<(String, Vec<u8>)>> {
        let digest = *digest;
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT reference, signatures FROM pulled_images WHERE manifest_digest = ?1
                     ORDER BY reference",
                )?;
                let rows = stmt
                    .query_map([&digest], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?)
    }

    /// The signatures kept with the pulls of `reference`: a manifest digest
    /// (the pulls of that image), or a name with a tag (the pulls of it, also
    /// by a digest).  For each manifest digest, its `os/arch` (as the
    /// configuration of the stored image says) and the signatures of all
    /// its pulls (JSON, `signatures`), at most `limit` digests, those first
    /// pulled last.
    pub async fn signed_pulls(&self, reference: &str, limit: usize) -> DbResult<Vec<SignedPull>> {
        let reference = reference.to_string();
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT p.manifest_digest, p.signatures,
                            json_extract(i.config, '$.os') || '/'
                                || json_extract(i.config, '$.architecture')
                     FROM pulled_images p
                     LEFT JOIN images i ON i.manifest_digest = p.manifest_digest
                     WHERE p.manifest_digest = ?1 OR p.reference = ?1
                        OR substr(p.reference, 1, length(?1) + 1) = ?1 || '@'
                     ORDER BY p.rowid DESC",
                )?;
                let rows = stmt
                    .query_map([&reference], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, Vec<u8>>(1)?,
                            r.get::<_, Option<String>>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let mut out: std::collections::BTreeMap<String, SignedPull> = Default::default();
                for (digest, signatures, platform) in rows {
                    if out.len() < limit || out.contains_key(&digest) {
                        out.entry(digest.clone())
                            .or_insert_with(|| SignedPull {
                                digest,
                                platform,
                                signatures: Vec::new(),
                            })
                            .signatures
                            .push(signatures);
                    }
                }
                Ok(out.into_values().collect())
            })
            .await?)
    }

    /// Remember that a registry has these blobs in a repository.
    pub async fn add_blob_sources(&self, sources: Vec<BlobSource>) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for source in &sources {
                    add_blob_source(&tx, source)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// The repositories of `registry` known to have `digest`.
    pub async fn blob_sources(&self, digest: &Digest, registry: &str) -> DbResult<Vec<String>> {
        let (digest, registry) = (digest.to_string(), registry.to_string());
        Ok(self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT repository FROM blob_sources WHERE digest = ?1 AND registry = ?2
                     ORDER BY rowid DESC",
                )?;
                let rows = stmt.query_map([&digest, &registry], |r| r.get(0))?;
                Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
            })
            .await?)
    }

    /// Record a whole pull in one transaction: the layers with their files,
    /// references and chunks, the image, its layers and its tags.  Nothing of
    /// the pull is visible before it commits.
    pub async fn commit_pull(&self, pull: PullCommit) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for layer in &pull.layers {
                    commit_layer(&tx, layer)?;
                }
                write_image(&tx, &pull)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Record the name `repository@digest` of the image `image_id` (another
    /// image that had it loses it).
    pub async fn insert_image_digest_name(
        &self,
        repository: &str,
        digest: &Digest,
        image_id: &str,
    ) -> DbResult<()> {
        self.import_image(image_id).await?;
        let (repository, digest, image_id) =
            (repository.to_string(), *digest, image_id.to_string());
        self.conn
            .call(move |c| {
                // (already the image's, and the last name it was given: see
                // `insert_image_tag`)
                let unchanged: bool = c.query_row(
                    "SELECT EXISTS (SELECT 1 FROM image_digest_names
                                    WHERE repository = ?1 AND digest = ?2 AND image_id = ?3)
                        AND COALESCE((SELECT repository = ?1 AND tag = '@' || ?2
                                      FROM image_name_history WHERE image_id = ?3
                                      ORDER BY rowid DESC LIMIT 1), 0)",
                    rusqlite::params![repository, digest, image_id],
                    |r| r.get(0),
                )?;
                if unchanged {
                    return Ok(());
                }
                c.execute(
                    "INSERT OR REPLACE INTO image_digest_names (repository, digest, image_id)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![repository, digest, image_id],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// The names `repository@digest` of the image, as (repository, digest),
    /// the newest first.
    pub async fn get_digest_names_for_image(
        &self,
        image_id: &str,
    ) -> DbResult<Vec<(String, Digest)>> {
        let image_id = image_id.to_string();
        self.conn
            .call(move |c| get_digest_names_for_image(c, &image_id))
            .await
            .map_err(DbError::Sqlite)
    }

    /// The image that has the name `repository@digest`.
    pub async fn get_image_by_digest_name(
        &self,
        repository: &str,
        digest: &Digest,
    ) -> DbResult<ImageRecord> {
        let (repository, digest) = (repository.to_string(), *digest);
        let what = format!("image {repository}@{digest}");
        self.conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT i.id, i.manifest_digest, i.config_digest, i.manifest, i.config, i.created_at
                     FROM images i
                     JOIN image_digest_names n ON i.id = n.image_id
                     WHERE n.repository = ?1 AND n.digest = ?2",
                )?;
                Ok(stmt.query_row(rusqlite::params![repository, digest], ImageRecord::from_row)?)
            })
            .await
            .map_err(|e| match e {
                tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows) => {
                    DbError::NotFound(what)
                }
                _ => DbError::Sqlite(e),
            })
    }

    /// Remove the name `repository@digest`.
    pub async fn delete_image_digest_name(
        &self,
        repository: &str,
        digest: &Digest,
    ) -> DbResult<()> {
        let (repository, digest) = (repository.to_string(), *digest);
        self.conn
            .call(move |c| delete_image_digest_name(c, &repository, &digest))
            .await
            .map_err(DbError::Sqlite)
    }

    /// Whether the image has a name: a tag, or a `repository@digest`.
    pub async fn image_is_named(&self, image_id: &str) -> DbResult<bool> {
        if !self.get_tags_for_image(image_id).await?.is_empty() {
            return Ok(true);
        }
        Ok(!self.get_digest_names_for_image(image_id).await?.is_empty())
    }

    /// Forget files whose objects are gone: their rows, the layers' references
    /// to them and the chunks they hold.
    pub async fn delete_files(&self, digests: Vec<String>) -> DbResult<()> {
        if digests.is_empty() {
            return Ok(());
        }
        self.conn
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                {
                    let mut chunks =
                        tx.prepare_cached("DELETE FROM chunk_locations WHERE file_digest = ?1")?;
                    let mut files = tx.prepare_cached("DELETE FROM files WHERE digest = ?1")?;
                    for d in &digests {
                        chunks.execute([d])?;
                        files.execute([d])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Record files of the store (their layers are recorded after).
    pub async fn record_files(&self, files: Vec<FileRecord>) -> DbResult<()> {
        if files.is_empty() {
            return Ok(());
        }
        self.conn
            .call(move |conn| {
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for file in &files {
                    tx.execute(
                        "INSERT INTO files (digest, size, created_at, checked) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(digest) DO UPDATE SET checked = files.checked OR excluded.checked",
                        rusqlite::params![file.digest, file.size, file.created_at, file.checked],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }
}

/// The image of a pull, its layers, the blobs' repositories, the names it
/// is given and the references it was pulled by, in the transaction of the
/// pull.
fn write_image(tx: &rusqlite::Transaction, pull: &PullCommit) -> rusqlite::Result<()> {
    let image = &pull.image;
    // (an image pulled again has the layers of this pull: the same
    // descriptor may have taken the other route, whole or by its TOC, and
    // be another layer; an image made again from the same configuration
    // has the manifest and the layers of the last one made, the one its
    // new names ask for)
    tx.execute(
        "INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET
             manifest_digest = excluded.manifest_digest, manifest = excluded.manifest",
        rusqlite::params![
            image.id,
            image.manifest_digest,
            image.config_digest,
            image.manifest,
            image.config,
            image.created_at,
        ],
    )?;
    for (index, key) in pull.image_layers.iter().enumerate() {
        tx.execute(
            "INSERT OR REPLACE INTO image_layers (image_id, layer_id, layer_index)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![image.id, key, index as i32],
        )?;
    }
    for source in &pull.sources {
        add_blob_source(tx, source)?;
    }
    for tag in &pull.tags {
        // A name is an image's or a manifest list's.
        tx.execute(
            "DELETE FROM manifest_list_names WHERE repository = ?1 AND tag = ?2",
            rusqlite::params![tag.repository, tag.tag],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO image_tags (repository, tag, image_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![tag.repository, tag.tag, tag.image_id],
        )?;
    }
    for (repository, digest) in &pull.digest_names {
        tx.execute(
            "INSERT OR REPLACE INTO image_digest_names (repository, digest, image_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![repository, digest, image.id],
        )?;
    }
    for (reference, signatures) in &pull.pulled {
        tx.execute(
            "INSERT OR REPLACE INTO pulled_images (manifest_digest, reference, signatures)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![image.manifest_digest, reference, signatures],
        )?;
    }
    Ok(())
}

/// Record a layer pulled or completed: the row, its files, their
/// references and its chunks.  A layer that is ready is never made lazy
/// again, and its diff id, once proven, is never replaced (a lazy layer has
/// none: what claims one is the configuration of an image).
fn add_blob_source(tx: &rusqlite::Transaction, source: &BlobSource) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO blob_sources (digest, registry, repository) VALUES (?1, ?2, ?3)",
        rusqlite::params![source.digest, source.registry, source.repository],
    )?;
    Ok(())
}

fn commit_layer(tx: &rusqlite::Transaction, layer: &LayerCommit) -> rusqlite::Result<()> {
    use rusqlite::OptionalExtension;
    let key = layer.record.key;
    // (a layer says the diff id it was verified against; a layer of a table
    // of contents that was verified by its table says none)
    if layer.record.diff_id.is_none() && !key.is_toc() {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "layer {key} has no diff id: nothing proved it"
        )));
    }
    let existing: Option<(Option<Digest>, Option<Digest>, bool)> = tx
        .query_row(
            "SELECT diff_id, diff_id_other, blob_checked FROM layers WHERE id = ?1",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    // (the diff id of the other algorithm the row gets after the insert)
    let mut other = None;
    if let (Some((Some(old), old_other, old_checked)), Some(new)) =
        (&existing, &layer.record.diff_id)
    {
        let recorded = [Some(*old), *old_other]
            .into_iter()
            .flatten()
            .find(|d| d.alg() == new.alg());
        if recorded != Some(*new) {
            // A layer of the blob that was hashed proves what the blob is:
            // a layer stored by it from what the peers had for the diff id
            // of another image's configuration, its blob never hashed, was
            // not it.  Its files go, and it is this one.
            let replaces = layer.blob_checked && !old_checked && !layer.record.key.is_toc();
            // A diff id of the other algorithm is another name of the same
            // tar when what the row holds is the tar of its key: a TOC (it
            // names the files and the tar-split), or a blob hashed by both
            // pulls.  The pull that brings it checked it against the stream.
            let same_tar = recorded.is_none()
                && (layer.record.key.is_toc() || (layer.blob_checked && *old_checked));
            if same_tar {
                other = Some(*new);
            } else if replaces {
                tx.execute("DELETE FROM file_refs WHERE layer_id = ?1", [&key])?;
                tx.execute(
                    "UPDATE layers SET diff_id = NULL, diff_id_other = NULL WHERE id = ?1",
                    [&key],
                )?;
            } else {
                return Err(rusqlite::Error::InvalidParameterName(format!(
                    "layer {key} exists with another diff id{}",
                    match recorded {
                        Some(_) => String::new(),
                        None => format!(
                            " ({old}, and nothing proves that the tar of {new} is the same: its blob was not hashed)"
                        ),
                    }
                )));
            }
        }
    }
    tx.execute(
        "INSERT INTO layers (id, diff_id, size, toc_digest, created_at, registry_ref,
                             tarsplit_digest, erofs, owners, blob, blob_checked, stream_size, sealed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(id) DO UPDATE SET
             diff_id = COALESCE(layers.diff_id, excluded.diff_id),
             blob_checked = MAX(layers.blob_checked, excluded.blob_checked),
             toc_digest = excluded.toc_digest,
             tarsplit_digest = excluded.tarsplit_digest,
             stream_size = excluded.stream_size,
             registry_ref = COALESCE(excluded.registry_ref, layers.registry_ref),
             -- (the blob the registry is asked for, of the pull that names
             -- the registry: the layer of a TOC is of any blob that names it)
             blob = CASE WHEN excluded.registry_ref IS NULL THEN layers.blob ELSE excluded.blob END,
             size = CASE WHEN excluded.registry_ref IS NULL THEN layers.size ELSE excluded.size END,
             erofs = COALESCE(excluded.erofs, layers.erofs),
             owners = COALESCE(excluded.owners, layers.owners),
             -- (an EROFS image made again says whether it has fs-verity, the
             -- one it replaces had it or not; a record without one says
             -- nothing of it)
             sealed = CASE WHEN excluded.erofs IS NULL THEN layers.sealed ELSE excluded.sealed END",
        rusqlite::params![
            key,
            layer.record.diff_id,
            layer.record.size,
            layer.toc_digest,
            layer.record.created_at,
            layer.record.registry_ref,
            // (a canonical layer has an empty one)
            layer.tarsplit.map(|d| d.to_string()).unwrap_or_default(),
            layer.record.erofs,
            layer.record.owners,
            layer.record.blob.map(|d| d.to_string()).unwrap_or_default(),
            layer.blob_checked,
            layer.record.stream_size,
            layer.sealed,
        ],
    )?;
    if let Some(other) = other {
        tx.execute(
            "UPDATE layers SET diff_id_other = ?2 WHERE id = ?1",
            rusqlite::params![key, other],
        )?;
    }
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO files (digest, size, created_at, checked)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(digest) DO UPDATE SET checked = files.checked OR excluded.checked",
        )?;
        // In the order of the keys: fewer pages of the B-trees touched.
        let mut files: Vec<_> = layer.files.iter().collect();
        files.sort_unstable_by(|a, b| a.digest.cmp(&b.digest));
        for f in files {
            stmt.execute(rusqlite::params![f.digest, f.size, f.created_at, f.checked])?;
        }
    }
    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO file_refs (layer_id, file_digest, ref_count)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(layer_id, file_digest) DO UPDATE SET ref_count = excluded.ref_count",
        )?;
        let mut refs: Vec<_> = layer.refs.iter().collect();
        refs.sort_unstable();
        for (digest, count) in refs {
            stmt.execute(rusqlite::params![key, digest, count])?;
        }
    }
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO chunk_locations (chunk_digest, file_digest, offset, size)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        let mut chunks: Vec<_> = layer.chunks.iter().collect();
        chunks.sort_unstable_by_key(|c| c.chunk_digest);
        for c in chunks {
            stmt.execute(rusqlite::params![
                c.chunk_digest,
                c.file_digest,
                c.offset as i64,
                c.size as i64
            ])?;
        }
    }
    Ok(())
}

/// The refusal of a write that conflicts with what is stored.
#[derive(Debug)]
struct AlreadyExists(String);

impl std::fmt::Display for AlreadyExists {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AlreadyExists {}

/// The refusal of a container whose SELinux level is taken (its text is
/// the level).
#[derive(Debug)]
struct LevelTaken(String);

impl std::fmt::Display for LevelTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LevelTaken {}

fn already_exists(why: String) -> tokio_rusqlite::Error {
    tokio_rusqlite::Error::Other(Box::new(AlreadyExists(why)))
}

/// The refusal of a write to a row that is not there.
#[derive(Debug)]
struct NoRow;

impl std::fmt::Display for NoRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no such row")
    }
}

impl std::error::Error for NoRow {}

fn no_row() -> tokio_rusqlite::Error {
    tokio_rusqlite::Error::Other(Box::new(NoRow))
}

/// The error of a call whose closure refused with [`no_row`] (`what` names
/// what was not there) or [`already_exists`]; any other is of the database.
fn refusal(e: tokio_rusqlite::Error, what: impl FnOnce() -> String) -> DbError {
    if let tokio_rusqlite::Error::Other(inner) = &e {
        if inner.is::<NoRow>() {
            return DbError::NotFound(what());
        }
        if let Some(AlreadyExists(why)) = inner.downcast_ref::<AlreadyExists>() {
            return DbError::AlreadyExists(why.clone());
        }
        if let Some(LevelTaken(level)) = inner.downcast_ref::<LevelTaken>() {
            return DbError::LevelTaken(level.clone());
        }
    }
    DbError::Sqlite(e)
}

fn list_networks_in(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<NetworkRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, driver, subnet, gateway, options, created_at, subnet6, gateway6
         FROM networks ORDER BY created_at DESC",
    )?;
    let networks = stmt
        .query_map([], |row| {
            Ok(NetworkRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                driver: row.get(2)?,
                subnet: row.get(3)?,
                gateway: row.get(4)?,
                options: row.get(5)?,
                created_at: row.get(6)?,
                subnet6: row.get(7)?,
                gateway6: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(networks)
}

fn insert_network_in(conn: &rusqlite::Connection, network: &NetworkRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO networks (id, name, driver, subnet, gateway, options, created_at,
                               subnet6, gateway6)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            network.id,
            network.name,
            network.driver,
            network.subnet,
            network.gateway,
            network.options,
            network.created_at,
            network.subnet6,
            network.gateway6,
        ],
    )?;
    Ok(())
}

/// The SQL of `Database::get_container`, for a connection of any kind.
pub fn get_container(
    conn: &mut rusqlite::Connection,
    owned: &str,
) -> Result<ContainerRecord, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(GET_CONTAINER)?;
    let name = owned.strip_prefix('/').unwrap_or(owned);
    let container = stmt.query_row([owned, name], ContainerRecord::from_row)?;
    Ok(container)
}

/// The SQL of `Database::list_containers`, for a connection of any kind.
pub fn list_containers(
    conn: &mut rusqlite::Connection,
    all: bool,
) -> Result<Vec<ContainerRecord>, tokio_rusqlite::Error> {
    let sql = if all {
        "SELECT id, name, image_id, config, state, pid, created_at, started_at, finished_at, exit_code
             FROM containers ORDER BY created_at DESC"
    } else {
        "SELECT id, name, image_id, config, state, pid, created_at, started_at, finished_at, exit_code
             FROM containers WHERE state = 'running' ORDER BY created_at DESC"
    };
    let mut stmt = conn.prepare(sql)?;
    let containers = stmt
        .query_map([], ContainerRecord::from_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(containers)
}

/// The SQL of `Database::containers_using_image`, for a connection of any kind.
pub fn containers_using_image(
    conn: &mut rusqlite::Connection,
    image_id: &str,
) -> Result<Vec<String>, tokio_rusqlite::Error> {
    // Those of the image, and those that mount a directory of it.
    let mut stmt = conn.prepare(
        "SELECT id FROM containers WHERE image_id = ?1
             UNION
             SELECT c.id FROM containers c, json_each(c.config, '$.mounts') m
             WHERE json_extract(m.value, '$.image.image') = ?1",
    )?;
    let ids = stmt
        .query_map([&image_id], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(ids)
}

/// The SQL of `Database::update_container_state`, for a connection of any kind.
pub fn update_container_state(
    conn: &mut rusqlite::Connection,
    id: &str,
    state: RecordState,
    pid: Option<i32>,
    started_at: Option<String>,
    finished_at: Option<String>,
    exit_code: Option<i32>,
) -> Result<(), tokio_rusqlite::Error> {
    let volatile = volatile::container(conn, id);
    volatile::run(conn, volatile, |conn| {
        update_container_state_in(conn, id, state, pid, started_at, finished_at, exit_code)
    })
}

fn update_container_state_in(
    conn: &mut rusqlite::Connection,
    id: &str,
    state: RecordState,
    pid: Option<i32>,
    started_at: Option<String>,
    finished_at: Option<String>,
    exit_code: Option<i32>,
) -> Result<(), tokio_rusqlite::Error> {
    conn.execute(
        "UPDATE containers SET state = ?2, pid = ?3, started_at = COALESCE(?4, started_at),
             finished_at = COALESCE(?5, finished_at), exit_code = COALESCE(?6, exit_code)
             WHERE id = ?1",
        rusqlite::params![id, state, pid, started_at, finished_at, exit_code],
    )?;
    Ok(())
}

/// The SQL of `Database::record_container_restarting`, for a connection of any kind.
pub fn record_container_restarting(
    conn: &mut rusqlite::Connection,
    id: &str,
    finished_at: &str,
    exit_code: i32,
    announce: Announce,
) -> Result<(), tokio_rusqlite::Error> {
    let volatile = volatile::container(conn, id);
    volatile::run(conn, volatile, |conn| {
        record_container_restarting_in(conn, id, finished_at, exit_code, announce)
    })
}

fn record_container_restarting_in(
    conn: &mut rusqlite::Connection,
    id: &str,
    finished_at: &str,
    exit_code: i32,
    announce: Announce,
) -> Result<(), tokio_rusqlite::Error> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE containers SET state = 'stopped', pid = NULL, finished_at = ?2,
             exit_code = ?3 WHERE id = ?1",
        rusqlite::params![id, finished_at, exit_code],
    )?;
    announce();
    tx.commit()?;
    Ok(())
}

/// The SQL of `Database::delete_container`, for a connection of any kind.
pub fn delete_container(
    conn: &mut rusqlite::Connection,
    owned: &str,
) -> Result<(), tokio_rusqlite::Error> {
    let volatile = volatile::container(conn, owned);
    volatile::run(conn, volatile, |conn| delete_container_in(conn, owned))
}

fn delete_container_in(
    conn: &mut rusqlite::Connection,
    owned: &str,
) -> Result<(), tokio_rusqlite::Error> {
    let tx = conn.transaction()?;
    delete_container_rows(&tx, owned)?;
    tx.commit()?;
    Ok(())
}

fn delete_container_rows(
    conn: &rusqlite::Connection,
    owned: &str,
) -> Result<(), tokio_rusqlite::Error> {
    conn.execute(
        "DELETE FROM container_deps WHERE container_id IN
                 (SELECT id FROM containers WHERE id = ?1 OR name = ?1)",
        [&owned],
    )?;
    let rows = conn.execute(
        "DELETE FROM containers WHERE id = ?1 OR name = ?1",
        [&owned],
    )?;
    if rows == 0 {
        return Err(no_row());
    }
    Ok(())
}

/// [`delete_container`] and, in the same transaction, what `then` does with
/// the connection (the image `--rmi` removes: a kill between the two would
/// lose it, the container's row is what says it was due).  `then`'s writes
/// are undone with the rows' when this fails; it takes its own savepoint to
/// give up only its own.
pub fn delete_container_then<R>(
    conn: &mut rusqlite::Connection,
    owned: &str,
    then: impl FnOnce(&mut rusqlite::Connection) -> R,
) -> Result<R, tokio_rusqlite::Error> {
    // (the rows of the container are as volatile as the container; what
    // `then` changes is not: a scope covers the rows only)
    let volatile = volatile::container(conn, owned);
    // (by hand: `then` needs the connection itself, which a `Transaction`
    // does not give)
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match volatile::run(conn, volatile, |conn| delete_container_rows(conn, owned)) {
        Ok(()) => {
            let out = then(conn);
            // (a commit that fails leaves the transaction open: the
            // connection is shared, it must not keep the write lock)
            if let Err(e) = conn.execute_batch("COMMIT") {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e.into());
            }
            Ok(out)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// The SQL of `Database::container_dependents`, for a connection of any kind.
pub fn container_dependents(
    conn: &mut rusqlite::Connection,
    id: &str,
    name: &str,
) -> Result<Vec<String>, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT container_id FROM container_deps
             WHERE container_id != ?1
               AND (target = ?1 OR (?2 != '' AND target = ?2)
                    OR (length(target) >= 12 AND substr(?1, 1, length(target)) = target))
             ORDER BY container_id",
    )?;
    let ids = stmt
        .query_map(rusqlite::params![id, name], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ids)
}

/// The SQL of `Database::delete_image`, for a connection of any kind.
pub fn delete_image(
    conn: &mut rusqlite::Connection,
    owned: &str,
) -> Result<(), tokio_rusqlite::Error> {
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    delete_image_rows(&tx, owned)?;
    tx.commit()?;
    Ok(())
}

/// [`delete_image`] in the transaction the caller made (or the savepoint).
pub fn delete_image_rows(
    tx: &rusqlite::Connection,
    owned: &str,
) -> Result<(), tokio_rusqlite::Error> {
    // a container needs its image (it has no foreign key: the
    // image of a container may be one that is being pulled)
    if tx
        .prepare_cached("SELECT 1 FROM containers WHERE image_id = ?1 LIMIT 1")?
        .exists([&owned])?
    {
        return Err(already_exists(format!(
            "image {owned} is used by a container"
        )));
    }
    // what was recorded of its pull goes with it (another
    // record of the same manifest keeps it)
    tx.execute(
        "DELETE FROM pulled_images WHERE manifest_digest IN
                (SELECT manifest_digest FROM images WHERE id = ?1)
             AND NOT EXISTS (SELECT 1 FROM images AS o WHERE o.id != ?1
                AND o.manifest_digest = pulled_images.manifest_digest)",
        [&owned],
    )?;
    let rows = tx.execute("DELETE FROM images WHERE id = ?1", [&owned])?;
    if rows == 0 {
        return Err(no_row());
    }
    Ok(())
}

/// The SQL of `Database::delete_image_tag`, for a connection of any kind.
pub fn delete_image_tag(
    c: &mut rusqlite::Connection,
    repository: &str,
    tag: &str,
) -> Result<(), tokio_rusqlite::Error> {
    c.execute(
        "DELETE FROM image_tags WHERE repository = ?1 AND tag = ?2",
        rusqlite::params![repository, tag],
    )?;
    Ok(())
}

/// The SQL of `Database::gc_pending`, for a connection of any kind.
pub fn gc_pending(conn: &mut rusqlite::Connection) -> Result<bool, tokio_rusqlite::Error> {
    Ok(conn
        .prepare_cached("SELECT 1 FROM store_settings WHERE key = 'gc_pending'")?
        .exists([])?)
}

/// The SQL of `Database::set_gc_pending`, for a connection of any kind.
pub fn set_gc_pending(
    conn: &mut rusqlite::Connection,
    pending: bool,
) -> Result<(), tokio_rusqlite::Error> {
    if pending {
        conn.execute(
            "INSERT OR IGNORE INTO store_settings (key, value) VALUES ('gc_pending', '1')",
            [],
        )?;
    } else {
        conn.execute("DELETE FROM store_settings WHERE key = 'gc_pending'", [])?;
    }
    Ok(())
}

/// The SQL of `Database::store_setting`, for a connection of any kind.
pub fn store_setting(
    conn: &mut rusqlite::Connection,
    key: &str,
    value: &str,
) -> Result<String, tokio_rusqlite::Error> {
    conn.execute(
        "INSERT OR IGNORE INTO store_settings (key, value) VALUES (?1, ?2)",
        rusqlite::params![key, value],
    )?;
    Ok(conn.query_row(
        "SELECT value FROM store_settings WHERE key = ?1",
        [&key],
        |r| r.get(0),
    )?)
}

/// The SQL of `Database::get_network`, for a connection of any kind.
pub fn get_network(
    conn: &mut rusqlite::Connection,
    owned: &str,
) -> Result<NetworkRecord, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, name, driver, subnet, gateway, options, created_at, subnet6, gateway6
             FROM networks WHERE id = ?1 OR name = ?1",
    )?;
    let network = stmt.query_row([&owned], |row| {
        Ok(NetworkRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            driver: row.get(2)?,
            subnet: row.get(3)?,
            gateway: row.get(4)?,
            options: row.get(5)?,
            created_at: row.get(6)?,
            subnet6: row.get(7)?,
            gateway6: row.get(8)?,
        })
    })?;
    Ok(network)
}

/// The SQL of `Database::get_digest_names_for_image`, for a connection of any kind.
pub fn get_digest_names_for_image(
    c: &mut rusqlite::Connection,
    image_id: &str,
) -> Result<Vec<(String, Digest)>, tokio_rusqlite::Error> {
    let mut stmt = c.prepare(
        "SELECT repository, digest FROM image_digest_names
             WHERE image_id = ?1 ORDER BY rowid DESC",
    )?;
    let names = stmt
        .query_map([&image_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names)
}

/// The SQL of `Database::delete_image_digest_name`, for a connection of any kind.
pub fn delete_image_digest_name(
    c: &mut rusqlite::Connection,
    repository: &str,
    digest: &Digest,
) -> Result<(), tokio_rusqlite::Error> {
    c.execute(
        "DELETE FROM image_digest_names WHERE repository = ?1 AND digest = ?2",
        rusqlite::params![repository, digest],
    )?;
    Ok(())
}

/// The SQL of [`Database::removals_pending`].
pub fn removals_pending(
    conn: &mut rusqlite::Connection,
) -> Result<Vec<String>, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare_cached("SELECT id FROM containers WHERE removing = 1")?;
    let ids = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(ids)
}

/// The SQL of [`Database::removal_pending`] (a missing row: false).
pub fn removal_pending(
    conn: &mut rusqlite::Connection,
    id: &str,
) -> Result<bool, tokio_rusqlite::Error> {
    Ok(conn
        .prepare_cached("SELECT removing FROM containers WHERE id = ?1")?
        .query_row([id], |row| row.get::<_, bool>(0))
        .optional()?
        .unwrap_or(false))
}

/// The container `id` no longer goes with its exit: its removal is done, or
/// it stays (others depend on it, a file could not be removed).
pub fn clear_removal(
    conn: &mut rusqlite::Connection,
    id: &str,
) -> Result<(), tokio_rusqlite::Error> {
    conn.prepare_cached("UPDATE containers SET removing = 0 WHERE id = ?1 AND removing = 1")?
        .execute([id])?;
    Ok(())
}

/// The SQL of [`Database::record_container_exit_announcing`].
pub fn record_container_exit_announcing(
    conn: &mut rusqlite::Connection,
    id: &str,
    finished_at: &str,
    exit_code: i32,
    started_at: Option<&str>,
    removal: bool,
    announce: Announce,
) -> Result<bool, tokio_rusqlite::Error> {
    let volatile = volatile::container(conn, id);
    volatile::run(conn, volatile, |conn| {
        record_container_exit_announcing_in(
            conn,
            id,
            finished_at,
            exit_code,
            started_at,
            removal,
            announce,
        )
    })
}

fn record_container_exit_announcing_in(
    conn: &mut rusqlite::Connection,
    id: &str,
    finished_at: &str,
    exit_code: i32,
    started_at: Option<&str>,
    removal: bool,
    announce: Announce,
) -> Result<bool, tokio_rusqlite::Error> {
    let time = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .and_then(|t| t.timestamp_nanos_opt())
    };
    let exit_run = started_at.and_then(time);
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let current: Option<Option<String>> = tx
        .query_row(
            "SELECT started_at FROM containers WHERE id = ?1 AND state != 'stopped'",
            [id],
            |r| r.get(0),
        )
        .optional()?;
    let Some(current) = current else {
        return Ok(false);
    };
    if let (Some(exit_run), Some(run)) = (exit_run, current.as_deref().and_then(time)) {
        if exit_run < run {
            return Ok(false);
        }
    }
    let n = tx.execute(
        "UPDATE containers SET state = 'stopped', pid = NULL, finished_at = ?2,
         exit_code = ?3, removing = ?4 WHERE id = ?1",
        rusqlite::params![id, finished_at, exit_code, removal],
    )?;
    if n > 0 {
        announce();
    }
    tx.commit()?;
    Ok(n > 0)
}

/// The names of the image, the newest first, as podman lists them (the SQL
/// of the tags of an image in this store).
pub fn image_tags(
    conn: &mut rusqlite::Connection,
    image_id: &str,
) -> Result<Vec<ImageTag>, tokio_rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT repository, tag, image_id FROM image_tags WHERE image_id = ?1
         ORDER BY rowid DESC",
    )?;
    let tags = stmt
        .query_map([image_id], |row| {
            Ok(ImageTag {
                repository: row.get(0)?,
                tag: row.get(1)?,
                image_id: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    /// The files of a table are checked against the store many at a time:
    /// the first that the store has with another size, in whichever query.
    #[tokio::test]
    async fn a_file_the_store_has_with_another_size_is_found() {
        let db = Database::open_in_memory().await.unwrap();
        let digest = |i: u64| format!("fsverity-sha256-12:{i:064x}");
        let files: Vec<(String, u64)> = (0..1200).map(|i| (digest(i), i)).collect();
        assert_eq!(db.file_size_conflict(files.clone()).await.unwrap(), None);
        let record = |i: u64, size: i64| FileRecord {
            digest: digest(i),
            size,
            created_at: "2026-01-01T00:00:00Z".into(),
            checked: false,
        };
        db.record_files(vec![record(3, 3), record(700, 70), record(1100, 11)])
            .await
            .unwrap();
        assert_eq!(
            db.file_size_conflict(files.clone()).await.unwrap(),
            Some((digest(700), 70, 700))
        );
        assert_eq!(
            db.file_size_conflict(files[..700].to_vec()).await.unwrap(),
            None
        );
    }

    fn m_digest() -> Digest {
        Digest::of(Algorithm::Sha256, b"m")
    }

    /// A layer commit that is the same but for its key and files.
    fn layer_commit(key: LayerKey, toc: Digest, tarsplit: Option<Digest>) -> LayerCommit {
        LayerCommit {
            record: LayerRecord {
                stream_size: Some(0),
                key,
                blob: None,
                diff_id: Some(Digest::of(Algorithm::Sha256, b"diff")),
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
            toc_digest: toc,
            tarsplit,
            blob_checked: false,
            sealed: false,
        }
    }

    /// The table of contents and the tar-split of a layer are files of its
    /// directory, checked against the digests of its row whenever they are
    /// read: a layer pulled by its table keeps the bytes the registry sent,
    /// a canonical layer has no tar-split file.
    #[tokio::test]
    async fn the_files_of_a_layer_are_checked_when_they_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        let (table, tarsplit) = (&b"sent"[..], &b"tar-split"[..]);
        let toc = LayerKey::Toc(sha(table));
        let canonical = LayerKey::Whole(sha(b"canonical"));
        let incomplete = LayerKey::Whole(sha(b"incomplete"));
        layer_files::write(dir.path(), &toc, layer_files::TOC, table).unwrap();
        layer_files::write(dir.path(), &toc, layer_files::TARSPLIT, tarsplit).unwrap();
        layer_files::write(dir.path(), &canonical, layer_files::TOC, b"json").unwrap();
        layer_files::write(dir.path(), &incomplete, layer_files::TOC, b"json").unwrap();
        db.commit_layers(
            vec![
                layer_commit(toc, sha(table), Some(sha(tarsplit))),
                layer_commit(canonical, sha(b"json"), None),
                layer_commit(incomplete, sha(b"json"), Some(sha(b"tar-split"))),
            ],
            vec![],
        )
        .await
        .unwrap();
        db.mark_layer_incomplete(&incomplete).await.unwrap();
        assert_eq!(db.get_layer_toc_z(&toc).await.unwrap().unwrap(), table);
        assert_eq!(
            db.get_layer_tarsplit(&toc).await.unwrap().unwrap(),
            tarsplit
        );
        assert_eq!(
            db.get_layer_tarsplit(&canonical).await.unwrap(),
            Some(Vec::new())
        );
        assert_eq!(db.get_layer_tarsplit(&incomplete).await.unwrap(), None);
        // a damaged file is refused, and so is a missing one
        let file = |kind, bytes: &[u8]| layer_files::file(dir.path(), &toc, kind, &sha(bytes));
        std::fs::write(file(layer_files::TOC, table), b"damaged").unwrap();
        assert!(db.get_layer_toc_z(&toc).await.is_err());
        std::fs::remove_file(file(layer_files::TARSPLIT, tarsplit)).unwrap();
        assert!(db.get_layer_tarsplit(&toc).await.is_err());
        // (a layer the store does not have has no table)
        let other = LayerKey::Whole(sha(b"other"));
        assert!(db.get_layer_toc_z(&other).await.unwrap().is_none());
    }

    /// A layer committed again with other bytes for its table of contents
    /// (another build encodes the JSON another way) does not replace the file
    /// its row names: the row reads the old file until the new row is
    /// committed, and the new file is there beside it.
    #[tokio::test]
    async fn a_layer_written_again_with_other_bytes_keeps_the_file_its_row_names() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        let key = LayerKey::Whole(sha(b"layer"));
        let (a, b) = (&b"json of a build"[..], &b"json of another"[..]);
        layer_files::write(dir.path(), &key, layer_files::TOC, a).unwrap();
        db.commit_layers(vec![layer_commit(key, sha(a), None)], vec![])
            .await
            .unwrap();
        // (the second pull writes before it commits)
        layer_files::write(dir.path(), &key, layer_files::TOC, b).unwrap();
        assert_eq!(db.get_layer_toc_z(&key).await.unwrap().unwrap(), a);
        assert!(layer_files::file(dir.path(), &key, layer_files::TOC, &sha(b)).is_file());
        db.commit_layers(vec![layer_commit(key, sha(b), None)], vec![])
            .await
            .unwrap();
        assert_eq!(db.get_layer_toc_z(&key).await.unwrap().unwrap(), b);
    }

    /// A layer marked incomplete has a row that says it has no tar-split
    /// (its files stay); its table of contents is read as before, and a
    /// commit that brings the tar-split again makes it complete.
    #[tokio::test]
    async fn a_layer_marked_incomplete_has_no_tarsplit_until_it_is_pulled_again() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        let key = LayerKey::Whole(sha(b"layer"));
        let write = |name: &str, bytes: &[u8]| {
            layer_files::write(dir.path(), &key, name, bytes).unwrap();
        };
        write(layer_files::TOC, b"json");
        write(layer_files::TARSPLIT, b"tar-split");
        let commit = || layer_commit(key, sha(b"json"), Some(sha(b"tar-split")));
        db.commit_layers(vec![commit()], vec![]).await.unwrap();
        assert_eq!(
            db.mark_layer_incomplete(&key).await.unwrap(),
            LayerMarking::Marked
        );
        assert_eq!(db.get_layer_tarsplit(&key).await.unwrap(), None);
        assert!(db.get_layer_toc_z(&key).await.unwrap().is_some());
        let states = db.get_own_layer_states(&[key]).await.unwrap();
        assert!(!states[0].has_tarsplit && states[0].has_toc);
        write(layer_files::TARSPLIT, b"tar-split");
        db.commit_layers(vec![commit()], vec![]).await.unwrap();
        assert_eq!(
            db.get_layer_tarsplit(&key).await.unwrap().unwrap(),
            b"tar-split"
        );
        // a layer made here has no registry to bring its tar-split back
        let made = LayerKey::Whole(sha(b"made"));
        let mut c = layer_commit(made, sha(b"json"), None);
        c.record.registry_ref = None;
        db.commit_layers(vec![c], vec![]).await.unwrap();
        assert_eq!(
            db.mark_layer_incomplete(&made).await.unwrap(),
            LayerMarking::NotPulled
        );
        assert_eq!(
            db.mark_layer_incomplete(&LayerKey::Whole(sha(b"none")))
                .await
                .unwrap(),
            LayerMarking::NotHere
        );
    }

    /// A chunk that two files have is found while one of them is there.
    #[tokio::test]
    async fn a_chunk_of_two_files_is_found_while_one_is_there() {
        use crate::{ChunkLocation, LayerCommit, LayerKey};
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let sha = |s: &str| Digest::of(Algorithm::Sha256, s.as_bytes());
        let commit = |n: &str, file: &str, chunks: &[&str]| LayerCommit {
            record: LayerRecord {
                stream_size: Some(1),
                key: LayerKey::Whole(sha(n)),
                blob: None,
                diff_id: Some(sha(n)),
                other_diff_id: None,
                size: 1,
                status: "ready".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                registry_ref: None,
                erofs: None,
                owners: None,
            },
            files: vec![FileRecord {
                digest: file.into(),
                size: 10,
                created_at: "2026-01-01T00:00:00Z".into(),
                checked: false,
            }],
            refs: vec![(file.into(), 1)],
            chunks: chunks
                .iter()
                .enumerate()
                .map(|(i, c)| ChunkLocation {
                    chunk_digest: sha(c),
                    file_digest: file.into(),
                    offset: i as u64 * 5,
                    size: 5,
                })
                .collect(),
            toc_digest: Digest::of(Algorithm::Sha256, b"json"),
            tarsplit: None,
            blob_checked: false,
            sealed: false,
        };
        // the old file is c1 c2; the new one c1 c3, committed after it
        db.commit_layers(
            vec![
                commit("old", "fsverity-sha256-12:old", &["c1", "c2"]),
                commit("new", "fsverity-sha256-12:new", &["c1", "c3"]),
            ],
            vec![],
        )
        .await
        .unwrap();
        // several in one call, the missing as none
        let found = db
            .get_chunk_locations_batch(&[sha("c3"), sha("c9"), sha("c2")])
            .await
            .unwrap();
        let files: Vec<Option<&str>> = [sha("c3"), sha("c9"), sha("c2")]
            .iter()
            .map(|d| found.get(d).map(|l| l.file_digest.as_str()))
            .collect();
        assert_eq!(
            files,
            [
                Some("fsverity-sha256-12:new"),
                None,
                Some("fsverity-sha256-12:old")
            ]
        );
        // a file is forgotten: c1 stays where the other has it
        db.delete_files(vec!["fsverity-sha256-12:new".into()])
            .await
            .unwrap();
        let at = db.get_chunk_location(&sha("c1")).await.unwrap().unwrap();
        assert_eq!(at.file_digest, "fsverity-sha256-12:old");
        assert!(db.get_chunk_location(&sha("c3")).await.unwrap().is_none());
    }

    /// The pages of `rows` rows of 4 KiB, written and removed.
    async fn free_pages(db: &Database, rows: u32) {
        db.conn()
            .call(move |conn| {
                conn.execute_batch("CREATE TABLE scratch (b BLOB);")?;
                for _ in 0..rows {
                    conn.execute("INSERT INTO scratch VALUES (zeroblob(4096))", [])?;
                }
                Ok(conn.execute_batch("DROP TABLE scratch;")?)
            })
            .await
            .unwrap();
    }

    fn file_bytes(path: &Path) -> u64 {
        ["", "-wal"]
            .iter()
            .filter_map(|s| std::fs::metadata(format!("{}{s}", path.display())).ok())
            .map(|m| m.len())
            .sum()
    }

    /// The pages of the rows a store removed go back to the file system, in
    /// steps, and the log is emptied.
    #[tokio::test]
    async fn shrink_gives_back_the_free_pages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        free_pages(&db, 3 * SHRINK_STEP).await;
        let big = file_bytes(&path);
        db.shrink().await.unwrap();
        let free: i64 = db
            .conn()
            .call(|conn| Ok(conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(free, 0);
        assert!(
            file_bytes(&path) * 4 < big,
            "{} of {big}",
            file_bytes(&path)
        );
    }

    /// One step of the shrink gives back its pages in one write, not one
    /// page: with 3 steps of pages to give back, a step leaves two.
    #[tokio::test]
    async fn a_step_of_the_shrink_gives_back_all_its_pages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        free_pages(&db, 3 * SHRINK_STEP).await;
        let before: i64 = db
            .conn()
            .call(|conn| Ok(conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?))
            .await
            .unwrap();
        let left = db.shrink_step().await.unwrap();
        assert_eq!(before - left, i64::from(SHRINK_STEP));
    }

    /// A store whose file has no auto_vacuum keeps its free pages: the
    /// shrink ends all the same.
    #[tokio::test]
    async fn shrink_of_a_file_without_auto_vacuum_ends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        db.conn()
            .call(|conn| Ok(conn.execute_batch("PRAGMA auto_vacuum = NONE; VACUUM;")?))
            .await
            .unwrap();
        free_pages(&db, 100).await;
        tokio::time::timeout(std::time::Duration::from_secs(30), db.shrink())
            .await
            .expect("the shrink does not end")
            .unwrap();
    }

    /// `PRAGMA data_version` of the connection: it moves when another
    /// connection commits.
    async fn data_version(db: &Database) -> i64 {
        db.conn()
            .call(|conn| Ok(conn.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap()
    }

    fn image(id: &str) -> ImageRecord {
        ImageRecord {
            id: id.into(),
            manifest_digest: Digest::of(Algorithm::Sha256, id.as_bytes()),
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        }
    }

    /// Wait for the next change, a failure when none comes (the bound is
    /// for a hung test, not a measure).
    async fn next_commit(watch: &mut ChangeWatch) {
        tokio::time::timeout(std::time::Duration::from_secs(10), watch.changed())
            .await
            .expect("the commit was announced")
            .unwrap();
    }

    /// Any commit that changes rows is announced to the watches of the
    /// other connections: an image, and a write made through the raw
    /// connection (the collector's).
    #[tokio::test]
    async fn any_commit_is_announced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let writer = Database::open(&path).await.unwrap();
        let reader = Database::open(&path).await.unwrap();
        let mut watch = reader.watch_changes().unwrap();
        writer.insert_image(&image("a")).await.unwrap();
        next_commit(&mut watch).await;
        writer
            .conn()
            .call(|conn| {
                let tx = conn.transaction()?;
                tx.execute("DELETE FROM images WHERE id = 'a'", [])?;
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
        next_commit(&mut watch).await;
    }

    /// Rows changed in a transaction left open by a call are told by the
    /// call that commits it, not before: the touch of the change file
    /// (its time, set back to the epoch here) waits for the commit.
    #[tokio::test]
    async fn a_transaction_is_told_at_its_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        let file = std::fs::File::options()
            .write(true)
            .open(changes::path_of(&path))
            .unwrap();
        let touched = || file.metadata().unwrap().modified().unwrap() != std::time::UNIX_EPOCH;
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
        db.conn()
            .call(|conn| {
                conn.execute_batch(
                    "BEGIN; INSERT INTO images (id, manifest_digest, config_digest, manifest, config, created_at) VALUES ('i','m','c','{}','{}','now');",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(!touched(), "told before the commit");
        db.conn()
            .call(|conn| Ok(conn.execute_batch("COMMIT")?))
            .await
            .unwrap();
        assert!(touched(), "the commit was not told");
    }

    /// The announcement comes after the commit is published: whoever wakes
    /// finds the rows, for each of many commits.
    #[tokio::test]
    async fn an_announced_commit_is_visible() {
        const COMMITS: usize = 200;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let writer = Database::open(&path).await.unwrap();
        let reader = Database::open(&path).await.unwrap();
        let mut watch = reader.watch_changes().unwrap();
        let writing = tokio::spawn(async move {
            for n in 0..COMMITS {
                writer.insert_image(&image(&format!("i{n}"))).await.unwrap();
            }
        });
        let mut seen = 0;
        while seen < COMMITS {
            next_commit(&mut watch).await;
            let now = reader.list_images().await.unwrap().len();
            assert!(now >= seen, "the images only grow: {now} after {seen}");
            seen = now;
        }
        writing.await.unwrap();
    }

    /// A row that is not there is told by its type, not by the words of
    /// an error: one of the database that says "not found" stays one.
    #[tokio::test]
    async fn a_missing_row_is_told_by_its_type() {
        let db = Database::open_in_memory().await.unwrap();
        for e in [
            db.delete_container("nope").await.unwrap_err(),
            db.rename_container("nope", "other").await.unwrap_err(),
            db.delete_network_unused("nope", false).await.unwrap_err(),
            db.delete_image("nope").await.unwrap_err(),
            db.delete_userns_allocation("nope").await.unwrap_err(),
        ] {
            assert!(matches!(e, DbError::NotFound(_)), "{e}");
        }
        let e = refusal(
            tokio_rusqlite::Error::Other("the file was not found".into()),
            || "row".into(),
        );
        assert!(matches!(e, DbError::Sqlite(_)), "{e}");
    }

    /// A task that still runs when the process closes the store finds it
    /// empty: the database says that it was closed, so that the task can
    /// tell that from a fault.
    #[tokio::test]
    async fn a_closed_database_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        assert!(!db.is_closed());
        db.close().await.unwrap();
        assert!(db.is_closed());
        // (the clones of the handle are closed with it)
        assert!(db.clone().is_closed());
        assert!(db.list_containers(true).await.is_err());
    }

    /// A journal mode that is not WAL is refused, not taken for WAL.
    #[test]
    fn only_wal_is_the_journal_mode_of_a_store() {
        assert!(check_wal("wal").is_ok());
        assert!(check_wal("WAL").is_ok());
        for mode in ["delete", "truncate", "memory"] {
            assert!(check_wal(mode).unwrap_err().to_string().contains(mode));
        }
        let dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(dir.path().join("db.sqlite")).unwrap();
        assert!(set_wal(&conn).is_ok());
        // (a database in memory cannot be in WAL)
        assert!(set_wal(&rusqlite::Connection::open_in_memory().unwrap()).is_err());
    }

    /// The directories and the file a new store makes are its user's alone;
    /// an existing directory keeps its mode.
    #[tokio::test]
    async fn a_new_store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = existing.join("a/b/db.sqlite");
        let db = Database::open(&path).await.unwrap();
        // (a connection makes the `-wal` file once it writes)
        db.insert_image(&ImageRecord {
            id: "img".into(),
            manifest_digest: m_digest(),
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        assert_eq!(mode(&existing), 0o755);
        assert_eq!(mode(&existing.join("a")), 0o700);
        assert_eq!(mode(&existing.join("a/b")), 0o700);
        assert_eq!(mode(&path), 0o600);
        let wal = existing.join("a/b/db.sqlite-wal");
        if wal.exists() {
            assert_eq!(mode(&wal), 0o600);
        }
    }

    /// The algorithm of an image is the one of its digests: the id of one
    /// named by a sha512 is its 128 hex digits, its record is found by the
    /// digest with the algorithm, and a sha256 of the same bytes is another
    /// image.
    #[tokio::test]
    async fn an_image_named_by_a_sha512_keeps_its_algorithm() {
        let db = Database::open_in_memory().await.unwrap();
        let sha512 = Digest::of(Algorithm::Sha512, b"manifest");
        let sha256 = Digest::of(Algorithm::Sha256, b"manifest");
        assert_eq!(
            db.image_id_for(&sha512, &sha512).await.unwrap(),
            sha512.hex()
        );
        assert_eq!(db.image_id_for(&sha512, &sha512).await.unwrap().len(), 128);
        assert_eq!(db.image_id_for(&sha256, &sha256).await.unwrap().len(), 64);
        db.insert_image(&ImageRecord {
            id: sha512.hex(),
            manifest_digest: sha512,
            config_digest: Digest::of(Algorithm::Sha512, b"config"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        let image = db.get_image_by_digest(&sha512).await.unwrap();
        assert_eq!(image.manifest_digest, sha512);
        assert_eq!(image.config_digest.alg(), Algorithm::Sha512);
        assert_eq!(db.image_id_for(&sha512, &sha512).await.unwrap(), image.id);
        assert!(db.get_image_by_digest(&sha256).await.is_err());
        // (the text kept is the digest with its algorithm)
        db.insert_image_digest_name("r.io/a", &sha512, &image.id)
            .await
            .unwrap();
        assert_eq!(
            db.get_digest_names_for_image(&image.id).await.unwrap(),
            [("r.io/a".to_string(), sha512)]
        );
        // the layers a sha512 names are keyed by it
        let key = velarx_types::LayerKey::parse(&format!("toc:{sha512}")).unwrap();
        assert_eq!(key.digest().alg(), Algorithm::Sha512);
        assert_eq!(key.to_string(), format!("toc:{sha512}"));
        assert_ne!(
            key.file_stem(),
            velarx_types::LayerKey::Toc(sha256).file_stem()
        );
    }

    /// An image a container uses is not removed, nor anything of it.
    #[tokio::test]
    async fn a_refused_image_removal_keeps_its_records() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_image(&ImageRecord {
            id: "img".into(),
            manifest_digest: m_digest(),
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        db.set_pulled_image(&m_digest(), "example.com/a:1", b"sigs".to_vec())
            .await
            .unwrap();
        db.insert_container(&ContainerRecord {
            id: "c1".into(),
            name: Some("c1".into()),
            image_id: "img".into(),
            config: "{}".into(),
            state: RecordState::Created,
            created_at: "now".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(db.delete_image("img").await.is_err());
        assert_eq!(db.pulled_image(&m_digest()).await.unwrap().len(), 1);
        assert!(db.get_image("img").await.is_ok());
    }

    /// Two handles of one file (two processes) that both read the levels in
    /// use and both choose the same one: the insert of the second is
    /// refused and leaves nothing, a level that is not checked (a pod's, the
    /// user's) is kept by any number of containers.
    #[tokio::test]
    async fn the_insert_refuses_a_level_another_handle_recorded() {
        fn same(a: &str, b: &str) -> bool {
            a == b
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let (one, two) = (
            Database::open(&path).await.unwrap(),
            Database::open(&path).await.unwrap(),
        );
        one.insert_image(&ImageRecord {
            id: "img".into(),
            manifest_digest: m_digest(),
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        let container = |id: &str| ContainerRecord {
            id: id.into(),
            name: Some(id.into()),
            image_id: "img".into(),
            config: r#"{"selinux":{"level":"s0:c1,c2"}}"#.into(),
            state: RecordState::Created,
            created_at: "now".into(),
            ..Default::default()
        };
        // both have read that nothing is in use
        assert!(one.container_selinux_levels().await.unwrap().is_empty());
        assert!(two.container_selinux_levels().await.unwrap().is_empty());
        one.insert_container_distinct(&container("a"), same)
            .await
            .unwrap();
        let err = two
            .insert_container_distinct(&container("b"), same)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::LevelTaken(l) if l == "s0:c1,c2"));
        assert!(two.get_container("b").await.is_err());
        // shared on purpose: not judged
        two.insert_container(&container("c")).await.unwrap();
        assert_eq!(two.container_selinux_levels().await.unwrap().len(), 2);
    }

    /// The signatures of a pull are found by the digest of its manifest, and
    /// by its name and tag (also when it was pulled by a digest as well), not
    /// by the name of another tag or of a longer one; each manifest comes
    /// with the platform of its image, when the image is stored.
    #[tokio::test]
    async fn signed_pulls_are_found_by_digest_and_by_name() {
        let db = Database::open_in_memory().await.unwrap();
        let (m, n) = (m_digest(), Digest::of(Algorithm::Sha256, b"n"));
        db.insert_image(&ImageRecord {
            id: "img".into(),
            manifest_digest: m,
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: "{}".into(),
            config: r#"{"os": "linux", "architecture": "arm64"}"#.into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        for (digest, reference, sigs) in [
            (&m, "r.io/a:1", "one"),
            (&m, "r.io/a:1@sha256:00", "two"),
            (&m, "r.io/a:2", "three"),
            (&n, "r.io/a:10", "four"),
            (&n, "r.io/a:1", "five"),
        ] {
            db.set_pulled_image(digest, reference, sigs.as_bytes().to_vec())
                .await
                .unwrap();
        }
        let by_name = db.signed_pulls("r.io/a:1", 8).await.unwrap();
        let shown: Vec<(String, Option<String>, Vec<String>)> = by_name
            .into_iter()
            .map(|p| {
                let mut sigs: Vec<String> = p
                    .signatures
                    .into_iter()
                    .map(|s| String::from_utf8(s).unwrap())
                    .collect();
                sigs.sort();
                (p.digest, p.platform, sigs)
            })
            .collect();
        let mut want = vec![
            (
                m.to_string(),
                Some("linux/arm64".to_string()),
                vec!["one".to_string(), "two".to_string()],
            ),
            (n.to_string(), None, vec!["five".to_string()]),
        ];
        want.sort();
        assert_eq!(shown, want);
        // by the digest: every pull of that manifest
        let by_digest = db.signed_pulls(&m.to_string(), 8).await.unwrap();
        assert_eq!(by_digest.len(), 1);
        assert_eq!(by_digest[0].signatures.len(), 3);
        // (the limit keeps the digest pulled last)
        let last = db.signed_pulls("r.io/a:1", 1).await.unwrap();
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].digest, n.to_string());
        assert!(db.signed_pulls("r.io/b:1", 8).await.unwrap().is_empty());
    }

    /// The name `repository@digest` of a pull by digest names the image
    /// (it is not dangling), is found by that name only, is in its history,
    /// moves to another image given it (podman: a name is of one image) and
    /// goes with the image.
    #[tokio::test]
    async fn an_image_pulled_by_digest_has_its_repository() {
        let db = Database::open_in_memory().await.unwrap();
        for id in ["img", "other"] {
            db.insert_image(&ImageRecord {
                id: id.into(),
                manifest_digest: Digest::of(Algorithm::Sha256, format!("m{id}").as_bytes()),
                config_digest: Digest::of(Algorithm::Sha256, format!("c{id}").as_bytes()),
                manifest: "{}".into(),
                config: "{}".into(),
                created_at: "now".into(),
                is_lazy: false,
            })
            .await
            .unwrap();
        }
        let history = |tags: Vec<ImageTag>| -> Vec<String> {
            tags.into_iter()
                .map(|t| format!("{}{}", t.repository, t.tag))
                .collect()
        };
        assert!(!db.image_is_named("img").await.unwrap());
        db.insert_image_digest_name("r.io/a", &m_digest(), "img")
            .await
            .unwrap();
        db.insert_image_digest_name("r.io/a", &m_digest(), "img")
            .await
            .unwrap();
        assert!(db.image_is_named("img").await.unwrap());
        assert_eq!(
            db.get_digest_names_for_image("img").await.unwrap(),
            [("r.io/a".to_string(), m_digest())]
        );
        assert_eq!(
            db.get_image_by_digest_name("r.io/a", &m_digest())
                .await
                .unwrap()
                .id,
            "img"
        );
        assert!(db
            .get_image_by_digest_name("r.io/b", &m_digest())
            .await
            .is_err());
        assert_eq!(
            history(db.get_name_history("img").await.unwrap()),
            [format!("r.io/a@{}", m_digest())]
        );
        // (the same list digest pulled for another platform)
        db.insert_image_digest_name("r.io/a", &m_digest(), "other")
            .await
            .unwrap();
        assert!(!db.image_is_named("img").await.unwrap());
        assert_eq!(
            db.get_image_by_digest_name("r.io/a", &m_digest())
                .await
                .unwrap()
                .id,
            "other"
        );
        assert_eq!(
            history(db.get_name_history("img").await.unwrap()),
            [format!("r.io/a@{}", m_digest())]
        );
        db.delete_image("other").await.unwrap();
        assert!(db
            .get_image_by_digest_name("r.io/a", &m_digest())
            .await
            .is_err());
    }

    /// An image keeps every name it had, the last one given first, also a
    /// name that moved to another image; the history goes with the image.
    #[tokio::test]
    async fn the_names_an_image_had_are_kept() {
        let db = Database::open_in_memory().await.unwrap();
        for id in ["old", "new"] {
            db.insert_image(&ImageRecord {
                id: id.into(),
                manifest_digest: Digest::of(Algorithm::Sha256, format!("m{id}").as_bytes()),
                config_digest: Digest::of(Algorithm::Sha256, format!("c{id}").as_bytes()),
                manifest: "{}".into(),
                config: "{}".into(),
                created_at: "now".into(),
                is_lazy: false,
            })
            .await
            .unwrap();
        }
        let tag = |repo: &str, tag: &str, id: &str| ImageTag {
            repository: repo.into(),
            tag: tag.into(),
            image_id: id.into(),
        };
        let names = |tags: Vec<ImageTag>| -> Vec<String> {
            tags.into_iter()
                .map(|t| format!("{}:{}", t.repository, t.tag))
                .collect()
        };
        db.insert_image_tag(&tag("a", "1", "old")).await.unwrap();
        db.insert_image_tag(&tag("b", "1", "old")).await.unwrap();
        // (given again: it is the last one given)
        db.insert_image_tag(&tag("a", "1", "old")).await.unwrap();
        assert_eq!(
            names(db.get_name_history("old").await.unwrap()),
            ["a:1", "b:1"]
        );
        // a:1 moves to the new image: the old one keeps it in its history
        db.insert_image_tag(&tag("a", "1", "new")).await.unwrap();
        assert_eq!(names(db.get_tags_for_image("old").await.unwrap()), ["b:1"]);
        assert_eq!(
            names(db.get_name_history("old").await.unwrap()),
            ["a:1", "b:1"]
        );
        assert_eq!(names(db.get_name_history("new").await.unwrap()), ["a:1"]);
        db.delete_image_tag("b", "1").await.unwrap();
        db.delete_image("old").await.unwrap();
        assert!(db.get_name_history("old").await.unwrap().is_empty());
    }

    /// A pull that finds the store as it would leave it writes nothing: the
    /// name, the record of the pull and the digest name that are there
    /// already do not commit (another connection sees no change).  Anything
    /// that does change still writes.
    #[tokio::test]
    async fn recording_what_is_recorded_already_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        let observer = Database::open(&path).await.unwrap();
        db.insert_image(&ImageRecord {
            id: "img".into(),
            manifest_digest: m_digest(),
            config_digest: Digest::of(Algorithm::Sha256, b"c"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "now".into(),
            is_lazy: false,
        })
        .await
        .unwrap();
        let tag = ImageTag {
            repository: "r.io/a".into(),
            tag: "1".into(),
            image_id: "img".into(),
        };
        async fn record(db: &Database, tag: &ImageTag, sigs: &[u8]) {
            db.insert_image_tag(tag).await.unwrap();
            db.set_pulled_image(&m_digest(), "r.io/a:1", sigs.to_vec())
                .await
                .unwrap();
        }
        record(&db, &tag, b"sigs").await;
        let before = data_version(&observer).await;
        record(&db, &tag, b"sigs").await;
        assert_eq!(
            data_version(&observer).await,
            before,
            "the same records were written again"
        );
        record(&db, &tag, b"other").await;
        let after = data_version(&observer).await;
        assert_ne!(after, before);
        assert_eq!(
            db.pulled_image(&m_digest()).await.unwrap(),
            [("r.io/a:1".to_string(), b"other".to_vec())]
        );
        // (a pull by digest: the name is new once)
        for _ in 0..2 {
            db.insert_image_digest_name("r.io/a", &m_digest(), "img")
                .await
                .unwrap();
        }
        assert_eq!(data_version(&observer).await, after + 1);
    }

    /// A setting of the store is the value it was first given.
    #[tokio::test]
    async fn a_store_setting_keeps_its_first_value() {
        let db = Database::open_in_memory().await.unwrap();
        assert_eq!(
            db.store_setting("runroot", "/run/a").await.unwrap(),
            "/run/a"
        );
        assert_eq!(
            db.store_setting("runroot", "/run/b").await.unwrap(),
            "/run/a"
        );
    }
    /// The collection forgets a kept index that lists no image of the store,
    /// and keeps one that lists an image or a pull in progress, itself or
    /// through another index.
    #[tokio::test]
    async fn the_indexes_that_list_no_image_are_forgotten() {
        let db = Database::open_in_memory().await.unwrap();
        let image = record("a");
        db.insert_image(&image).await.unwrap();
        let sha = |s: &str| Digest::of(Algorithm::Sha256, s.as_bytes());
        let lists = |d: &Digest| format!(r#"{{"manifests":[{{"digest":"{d}"}}]}}"#);
        let (inner, outer, gone) = (sha("inner"), sha("outer"), sha("gone"));
        db.set_index(&inner, &lists(&image.manifest_digest))
            .await
            .unwrap();
        db.set_index(&outer, &lists(&inner)).await.unwrap();
        db.set_index(&gone, &lists(&sha("other"))).await.unwrap();
        let staged = sha("staged");
        db.set_index(&sha("of a pull"), &lists(&staged))
            .await
            .unwrap();
        assert_eq!(db.forget_unlisted_indexes(vec![staged]).await.unwrap(), 1);
        assert!(db.index(&inner).await.unwrap().is_some());
        assert!(db.index(&outer).await.unwrap().is_some());
        assert!(db.index(&sha("of a pull")).await.unwrap().is_some());
        assert!(db.index(&gone).await.unwrap().is_none());
    }

    /// The manifest and the configuration of an image, and a kept index,
    /// are found by their digests.
    #[tokio::test]
    async fn the_metadata_of_an_image_is_found_by_its_digests() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("db.sqlite")).await.unwrap();
        let image = record("s");
        db.insert_image(&ImageRecord {
            manifest: "manifest s".into(),
            config: "config s".into(),
            ..image.clone()
        })
        .await
        .unwrap();
        let index = Digest::of(Algorithm::Sha256, b"s");
        db.set_index(&index, "an index").await.unwrap();
        let db = &db;
        let found =
            |d: Digest| async move { db.image_metadata(&[d]).await.unwrap().pop().unwrap() };
        assert_eq!(found(image.manifest_digest).await.unwrap(), "manifest s");
        assert_eq!(found(image.config_digest).await.unwrap(), "config s");
        assert_eq!(found(index).await.unwrap(), "an index");
        assert_eq!(found(Digest::of(Algorithm::Sha256, b"p")).await, None);
    }

    /// A layer is sealed only when its commit says so, a layer pulled again
    /// keeps what it had, and the seal of one layer can be set.
    #[tokio::test]
    async fn a_layer_is_sealed_when_its_commit_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        let (old, new, other) = (
            LayerKey::Whole(sha(b"old")),
            LayerKey::Whole(sha(b"new")),
            LayerKey::Whole(sha(b"other")),
        );
        let db = Database::open(&path).await.unwrap();
        for key in [old, other] {
            db.commit_layers(vec![layer_commit(key, sha(b"t"), None)], vec![])
                .await
                .unwrap();
        }
        assert!(!db.layers_sealed(&[old]).await.unwrap());
        let mut sealed = layer_commit(new, sha(b"t"), None);
        sealed.sealed = true;
        db.commit_layers(vec![sealed], vec![]).await.unwrap();
        assert!(db.layers_sealed(&[new]).await.unwrap());
        assert!(!db.layers_sealed(&[new, old]).await.unwrap());
        // (a layer pulled again without it keeps what it had; an unknown
        // layer is not sealed)
        db.commit_layers(vec![layer_commit(new, sha(b"t"), None)], vec![])
            .await
            .unwrap();
        assert!(db.layers_sealed(&[new]).await.unwrap());
        assert!(!db
            .layers_sealed(&[LayerKey::Whole(sha(b"none"))])
            .await
            .unwrap());
        db.set_layer_sealed(&old, true).await.unwrap();
        assert!(db.layers_sealed(&[old, new]).await.unwrap());
        assert!(!db.layers_sealed(&[other]).await.unwrap());
    }

    /// An EROFS image made again says whether it has fs-verity: one without
    /// it does not keep the seal of the image it replaces, whether it is
    /// made by a commit or by a repair.
    #[tokio::test]
    async fn an_erofs_image_made_again_has_its_own_seal() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("db.sqlite")).await.unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let toc = Digest::of(Algorithm::Sha256, b"t");
        let commit = |erofs: &str, sealed: bool| {
            let mut c = layer_commit(key, toc, None);
            c.record.erofs = Some(erofs.into());
            c.record.owners = Some("[]".into());
            c.sealed = sealed;
            c
        };
        db.commit_layers(vec![commit("sha256:a", true)], vec![])
            .await
            .unwrap();
        assert!(db.layers_sealed(&[key]).await.unwrap());
        db.commit_layers(vec![commit("sha256:b", false)], vec![])
            .await
            .unwrap();
        assert!(!db.layers_sealed(&[key]).await.unwrap());
        db.set_layer_sealed(&key, true).await.unwrap();
        assert!(db.layers_sealed(&[key]).await.unwrap());
        db.set_layer_sealed(&key, false).await.unwrap();
        assert!(!db.layers_sealed(&[key]).await.unwrap());
    }

    fn record(id: &str) -> ImageRecord {
        ImageRecord {
            id: id.into(),
            manifest_digest: Digest::of(Algorithm::Sha256, format!("m{id}").as_bytes()),
            config_digest: Digest::of(Algorithm::Sha256, format!("c{id}").as_bytes()),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            is_lazy: false,
        }
    }

    /// The files of the database in `dir` (the notice file of the changes
    /// is not SQLite's).
    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with("-changes"))
            .collect();
        names.sort();
        names
    }

    /// The open of a store writes nothing (no commit, which syncs): the
    /// settings of the file were written when it was made.
    #[tokio::test]
    async fn opening_a_store_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        db.close().await.unwrap();
        let db = Database::open(&path).await.unwrap();
        assert_eq!(db.wal_size(), 0);
        let mode: i64 = db
            .conn
            .call(|conn| Ok(conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(mode, AUTO_VACUUM_INCREMENTAL);
        db.close().await.unwrap();
    }

    /// A store that was written and closed is its main file alone.
    #[tokio::test]
    async fn a_closed_store_is_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        db.insert_image(&record("aaa")).await.unwrap();
        assert!(db.wal_size() > 0);
        let clone = db.clone();
        db.close().await.unwrap();
        // (what was written is in the file, and the clones are closed too)
        assert_eq!(files(dir.path()), ["db.sqlite"]);
        assert!(clone.list_images().await.is_err());
        assert!(Database::open_read_only(&path).await.is_ok());
        let db = Database::open(&path).await.unwrap();
        assert_eq!(db.list_images().await.unwrap().len(), 1);
        // closing twice, and a store that was only read
        db.close().await.unwrap();
        db.close().await.unwrap();
        assert_eq!(files(dir.path()), ["db.sqlite"]);
    }

    /// The last of two connections to close leaves nothing; the first leaves
    /// the files, and does not wait for the other.
    #[tokio::test]
    async fn the_last_connection_to_close_removes_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let first = Database::open(&path).await.unwrap();
        let second = Database::open(&path).await.unwrap();
        first.insert_image(&record("aaa")).await.unwrap();
        first.close().await.unwrap();
        assert!(first.wal_size() > 0);
        assert!(files(dir.path()).contains(&"db.sqlite-shm".to_string()));
        assert_eq!(second.list_images().await.unwrap().len(), 1);
        second.close().await.unwrap();
        assert_eq!(files(dir.path()), ["db.sqlite"]);
    }

    /// A process of this test that holds a store open until its input ends,
    /// after it wrote an image (`CLOSE_TEST_HOLDER`: the path).
    #[tokio::test]
    async fn holder_of_a_store() {
        let Some(path) = std::env::var_os("CLOSE_TEST_HOLDER") else {
            return;
        };
        let db = Database::open(&path).await.unwrap();
        db.insert_image(&record("bbb")).await.unwrap();
        println!("held");
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut Vec::new()).unwrap();
        // (this one ends as a command does: through `exit`)
        std::process::exit(0);
    }

    /// Start the holder in another process; it has written when this returns.
    fn hold(path: &Path) -> std::process::Child {
        use std::io::BufRead;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::holder_of_a_store", "--nocapture"])
            .env("CLOSE_TEST_HOLDER", path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        while line.trim() != "held" {
            line.clear();
            assert!(out.read_line(&mut line).unwrap() > 0, "the holder ended");
        }
        child
    }

    /// Two processes: the one that closes last cleans, whichever it is.
    #[tokio::test]
    async fn the_last_process_to_close_removes_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        let mut holder = hold(&path);
        db.insert_image(&record("aaa")).await.unwrap();
        // this one closes first: the other holds the store, so the files stay
        // (and the close does not wait for it)
        db.close().await.unwrap();
        assert!(files(dir.path()).contains(&"db.sqlite-shm".to_string()));
        // the holder ends through `exit`, the last: the files go
        drop(holder.stdin.take());
        assert!(holder.wait().unwrap().success());
        assert_eq!(files(dir.path()), ["db.sqlite"]);
        let db = Database::open(&path).await.unwrap();
        assert_eq!(db.list_images().await.unwrap().len(), 2);
        db.close().await.unwrap();
    }

    /// A process that is killed leaves its log, which the next open recovers.
    #[tokio::test]
    async fn a_killed_process_leaves_a_log_that_the_next_open_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let mut holder = hold(&path);
        holder.kill().unwrap();
        holder.wait().unwrap();
        assert!(files(dir.path()).contains(&"db.sqlite-wal".to_string()));
        assert!(Database::open_read_only(&path).await.is_err());
        let db = Database::open(&path).await.unwrap();
        assert_eq!(db.get_image("bbb").await.unwrap().id, "bbb");
        db.close().await.unwrap();
        assert_eq!(files(dir.path()), ["db.sqlite"]);
        assert!(Database::open_read_only(&path).await.is_ok());
    }
}

/// Whether a container of this configuration is removed when it ends.
fn config_removes(config: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(config)
        .ok()
        .and_then(|v| v.get("auto_remove").and_then(serde_json::Value::as_bool))
        .unwrap_or(false)
}

/// What the config of a container (its JSON) refers to: its SELinux level
/// (`selinux.level`, else `selinux.file_level`), and the containers it
/// names: those of `requires`, and every `container:TARGET` (the namespaces
/// it joins), as written.
fn config_refs(config: &str) -> (Option<String>, Vec<String>) {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => {
                if let Some(t) = s.strip_prefix("container:") {
                    out.push(t.to_string());
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config) else {
        return (None, Vec::new());
    };
    let level = ["level", "file_level"].iter().find_map(|k| {
        v.pointer(&format!("/selinux/{k}"))
            .and_then(|l| l.as_str())
            .map(str::to_string)
    });
    let mut targets: Vec<String> = v
        .get("requires")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str().map(str::to_string))
        .collect();
    walk(&v, &mut targets);
    targets.sort();
    targets.dedup();
    (level, targets)
}

#[cfg(test)]
mod lookup_tests {
    use super::*;

    /// A lookup of a container reads its row, not every container.
    #[tokio::test]
    async fn a_container_is_found_by_an_index() {
        let db = Database::open_in_memory().await.unwrap();
        let plan: Vec<String> = db
            .conn
            .call(|c| {
                let mut stmt = c.prepare(&format!("EXPLAIN QUERY PLAN {GET_CONTAINER}"))?;
                let plan = stmt
                    .query_map(["/c1", "c1"], |r| r.get(3))?
                    .collect::<Result<Vec<String>, _>>()?;
                Ok(plan)
            })
            .await
            .unwrap();
        assert!(!plan.iter().any(|p| p.starts_with("SCAN")), "{plan:?}");
    }
}

#[cfg(test)]
mod config_refs_tests {
    use super::config_refs;

    #[test]
    fn the_level_and_the_containers_a_config_names() {
        let (level, targets) = config_refs(
            r#"{"requires": ["aaa"], "selinux": {"level": null, "file_level": "s0:c1,c2"},
                "options": {"pid_ns": "container:bbb", "ipc_ns": ""},
                "network_mode": "container:ccc", "env": ["X=container:ddd"]}"#,
        );
        assert_eq!(level.as_deref(), Some("s0:c1,c2"));
        assert_eq!(targets, ["aaa", "bbb", "ccc"]);
        assert_eq!(config_refs("{}"), (None, Vec::new()));
    }
}
