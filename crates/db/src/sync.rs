// SPDX-License-Identifier: Apache-2.0
//! The store from a thread that blocks: one SQL for the engine's
//! [`Database`] and for a connection of its own.
//!
//! The monitor of a container records what happens to it and releases its
//! network itself.  It has no async runtime, so it opens [`Store`], a plain
//! connection to the existing store that lives while there is work.  The
//! engine reaches the same functions from `spawn_blocking` through
//! [`BlockingDb`].  Both are an [`Access`]; the orchestration is written
//! once against it, and the SQL lives in free functions that `Database`
//! calls too.

use crate::{apply_pragmas, changes, schema, volatile, Database, KEPT};
use rusqlite::Connection;
use std::path::Path;
use velarx_types::{DbError, DbResult};

/// The cache of the connection of a short-lived process (KiB).
const CACHE_KIB: u32 = 2000;

/// What runs a closure on a connection to the store: the monitor's own
/// connection, or the engine's [`Database`] from a thread that may block.
/// A write through it is told to the other processes (`-changes`).
pub trait Access {
    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> tokio_rusqlite::Result<R> + Send + 'static,
    ) -> DbResult<R>;
}

/// What a row call that refused says, as the methods of [`Database`] do.
fn refused(e: tokio_rusqlite::Error) -> DbError {
    // (a `query_row` that found nothing: the row is not there)
    if matches!(
        e,
        tokio_rusqlite::Error::Rusqlite(rusqlite::Error::QueryReturnedNoRows)
    ) {
        return DbError::NotFound("row".into());
    }
    if let tokio_rusqlite::Error::Other(inner) = &e {
        if inner.is::<crate::NoRow>() {
            return DbError::NotFound("row".into());
        }
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    return DbError::AlreadyExists(io.to_string());
                }
                std::io::ErrorKind::NotFound => return DbError::NotFound(io.to_string()),
                _ => {}
            }
        }
        if let Some(crate::AlreadyExists(why)) = inner.downcast_ref::<crate::AlreadyExists>() {
            return DbError::AlreadyExists(why.clone());
        }
    }
    DbError::Sqlite(e)
}

/// A connection of its own to an existing store: no schema is made, the
/// version is checked, the settings are those of every connection with a
/// small cache.
pub struct Store {
    conn: std::cell::RefCell<Connection>,
    changes: changes::Changes,
}

impl Store {
    /// Open the store at `path`.  A store that is not there is an error
    /// (the file is never created), and so is one of another schema
    /// version.  (It is not a cold open of the engine's trace: the monitor's
    /// threads open and close it as they work.)
    pub fn open(path: &Path) -> DbResult<Self> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| DbError::Sqlite(e.into()))?;
        apply_pragmas(&conn, true, CACHE_KIB).map_err(|e| DbError::Sqlite(e.into()))?;
        let found: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|e| DbError::Sqlite(e.into()))?;
        if found != schema::SCHEMA_VERSION {
            return Err(DbError::Sqlite(tokio_rusqlite::Error::Other(Box::new(
                schema::SchemaError::Version { found },
            ))));
        }
        let file = changes::open(path)
            .map_err(|e| DbError::Sqlite(tokio_rusqlite::Error::Other(Box::new(e))))?;
        KEPT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Self {
            conn: std::cell::RefCell::new(conn),
            changes: changes::Changes::new(file),
        })
    }
}

impl Store {
    /// Write the log of the store back into its file, passively (the other
    /// processes go on meanwhile): what the close of the last connection does
    /// under the exclusive lock of the file, which every process that opens
    /// the store waits for.  A process that is not the last to close, and has
    /// time, does it first, so that the close that is last finds nothing to
    /// write.
    pub fn write_back(&self) -> DbResult<()> {
        // (a process that made no write that must survive a crash has
        // nothing to sync, see `volatile`, unless the log is long or holds
        // the commits of another: then it is written back here, after the
        // clients were told, rather than by the close of a command)
        if !volatile::durable_writes() && !volatile::log_wants_write_back(&self.conn.borrow()) {
            return Ok(());
        }
        self.call(|conn| {
            conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
            Ok(())
        })
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        KEPT.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        let Ok(open) = Connection::open_in_memory()
            .map(|memory| std::mem::replace(self.conn.get_mut(), memory))
        else {
            return;
        };
        volatile::before_close(&open);
        let path = open.path().map(std::path::PathBuf::from);
        if open.close().is_ok() {
            if let Some(path) = path {
                volatile::after_close(&path);
            }
        }
    }
}

impl Access for Store {
    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> tokio_rusqlite::Result<R> + Send + 'static,
    ) -> DbResult<R> {
        let mut conn = self.conn.borrow_mut();
        let before = conn.total_changes();
        volatile::call_begins();
        let result = f(&mut conn);
        let changed = conn.total_changes().saturating_sub(before);
        volatile::call_ends(&conn, i64::try_from(changed).unwrap_or(i64::MAX));
        self.changes.changed(changed != 0, conn.is_autocommit());
        result.map_err(refused)
    }
}

/// The engine's [`Database`] from a thread that may block
/// (`spawn_blocking`): each call waits for the connection's thread.
pub struct BlockingDb<'a> {
    db: &'a Database,
    rt: tokio::runtime::Handle,
}

impl<'a> BlockingDb<'a> {
    /// For the thread of the current runtime's blocking pool.
    pub fn new(db: &'a Database) -> Self {
        Self {
            db,
            rt: tokio::runtime::Handle::current(),
        }
    }
}

impl Access for BlockingDb<'_> {
    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> tokio_rusqlite::Result<R> + Send + 'static,
    ) -> DbResult<R> {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "BlockingDb is used from a thread of a runtime's blocking pool"
        );
        self.rt.block_on(self.db.conn.call(f)).map_err(refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContainerRecord, RecordState};

    fn record(id: &str) -> ContainerRecord {
        ContainerRecord {
            id: id.into(),
            name: Some(id.into()),
            image_id: "-rootfs-".into(),
            config: "{}".into(),
            state: RecordState::Running,
            pid: Some(4),
            created_at: "2026-01-01T00:00:00Z".into(),
            ..Default::default()
        }
    }

    /// A store on a file with a container row, and the engine's handle on it.
    async fn store() -> (tempfile::TempDir, std::path::PathBuf, Database) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let db = Database::open(&path).await.unwrap();
        db.insert_container(&record("c1")).await.unwrap();
        (dir, path, db)
    }

    /// The rows of a container that is removed when it ends are written
    /// without a sync, the others as before, and the settings of the
    /// connection are the same after each.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_container_removed_at_its_end_is_written_in_a_scope() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let mut rm = record("rm");
        rm.config = r#"{"auto_remove": true}"#.into();
        db.insert_container(&rm).await.unwrap();
        db.insert_container(&record("kept")).await.unwrap();
        db.update_container_state("rm", crate::RecordState::Stopped, None, None, None, Some(3))
            .await
            .unwrap();
        db.delete_container("rm").await.unwrap();
        assert!(db.get_container("rm").await.is_err());
        assert_eq!(db.get_container("kept").await.unwrap().id, "kept");
        let (sync, auto) = db
            .conn()
            .call(|c| {
                Ok((
                    c.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))?,
                    c.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get::<_, i64>(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((sync, auto), (1, 1000));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn both_handles_give_the_same_rows() {
        let (_dir, path, db) = store().await;
        let via_db = db.get_container("c1").await.unwrap();
        let p = path.clone();
        let (via_store, via_blocking) = {
            let db2 = db.clone();
            tokio::task::spawn_blocking(move || {
                let store = Store::open(&p).unwrap();
                let a = store.call(|c| crate::get_container(c, "c1")).unwrap();
                let blocking = BlockingDb::new(&db2);
                let b = blocking.call(|c| crate::get_container(c, "c1")).unwrap();
                (a, b)
            })
            .await
            .unwrap()
        };
        assert_eq!(via_store.id, via_db.id);
        assert_eq!(via_blocking.id, via_db.id);
        assert_eq!(via_store.state, via_db.state);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_through_a_store_is_seen_and_told() {
        let (_dir, path, db) = store().await;
        let mut watch = db.watch_changes().unwrap();
        let p = path.clone();
        tokio::task::spawn_blocking(move || {
            let store = Store::open(&p).unwrap();
            store
                .call(|c| {
                    crate::update_container_state(
                        c,
                        "c1",
                        RecordState::Stopped,
                        None,
                        None,
                        Some("2026-01-01T00:00:01Z".into()),
                        Some(3),
                    )
                })
                .unwrap();
        })
        .await
        .unwrap();
        watch.changed().await.unwrap();
        let row = db.get_container("c1").await.unwrap();
        assert_eq!(row.state, RecordState::Stopped);
        assert_eq!(row.exit_code, Some(3));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_that_wrote_back_leaves_no_log_to_the_last_close() {
        let (_dir, path, db) = store().await;
        let p = path.clone();
        let (log, written) = tokio::task::spawn_blocking(move || {
            let store = Store::open(&p).unwrap();
            store
                .call(|c| {
                    crate::update_container_state(
                        c,
                        "c1",
                        RecordState::Stopped,
                        None,
                        None,
                        None,
                        Some(1),
                    )
                })
                .unwrap();
            store.write_back().unwrap();
            // (a passive checkpoint again: the frames of the log that are
            // not written back, and the ones that are)
            store
                .call(|c| {
                    let r = c.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                        Ok((r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
                    })?;
                    Ok(r)
                })
                .unwrap()
        })
        .await
        .unwrap();
        assert!(log > 0, "the write went to the log");
        assert_eq!(log, written, "every frame of the log is in the file");
        // (the engine's connection is open meanwhile: this was no last close)
        assert_eq!(
            db.get_container("c1").await.unwrap().state,
            RecordState::Stopped
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_that_is_not_there_is_not_made() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("none.sqlite");
        assert!(Store::open(&path).is_err());
        assert!(!path.exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_store_of_another_version_is_refused() {
        let (_dir, path, db) = store().await;
        db.close().await.unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 7;").unwrap();
        drop(conn);
        let err = Store::open(&path).err().expect("refused");
        assert!(err.to_string().contains("version 7"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_announcement_runs_inside_the_transaction() {
        let (_dir, path, db) = store().await;
        let p = path.clone();
        let seen = tokio::task::spawn_blocking(move || {
            let store = Store::open(&p).unwrap();
            let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
            let (q, s2) = (p.clone(), seen.clone());
            let recorded = store
                .call(move |c| {
                    crate::record_container_exit_announcing(
                        c,
                        "c1",
                        "2026-01-01T00:00:02Z",
                        5,
                        None,
                        false,
                        Box::new(move || {
                            // another connection does not see the exit yet
                            let other = Connection::open(&q).unwrap();
                            let state: String = other
                                .query_row(
                                    "SELECT state FROM containers WHERE id = 'c1'",
                                    [],
                                    |r| r.get(0),
                                )
                                .unwrap();
                            *s2.lock().unwrap() = Some(state);
                        }),
                    )
                })
                .unwrap();
            assert!(recorded);
            let seen = seen.lock().unwrap().clone();
            seen
        })
        .await
        .unwrap();
        assert_eq!(seen.as_deref(), Some("running"));
        assert_eq!(
            db.get_container("c1").await.unwrap().state,
            RecordState::Stopped
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_volume_row_is_read_and_deleted() {
        let (_dir, path, _db) = store().await;
        let store = Store::open(&path).unwrap();
        store
            .call(|c| {
                c.execute(
                    "INSERT INTO volumes (name, driver, mountpoint, labels, options, created_at, scope, state)
                     VALUES ('v', '\"local\"', '/x', '{}', '{}', 't', 'local', '{\"anonymous\":true}')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let row = store.call(|c| crate::volumes::get(c, "v")).unwrap();
        assert!(row.anonymous());
        assert_eq!(row.mountpoint, "/x");
        store.call(|c| crate::volumes::delete(c, "v")).unwrap();
        assert!(store.call(|c| crate::volumes::get(c, "v")).is_err());
    }
}
