// SPDX-License-Identifier: Apache-2.0
//! Writes that need not survive a crash of the machine.
//!
//! The rows of a container that is removed when it ends (`--rm`) are of no use
//! after a reboot or a crash: the container does not survive them (as an
//! overlay mounted `volatile`).  A process whose writes were all of that kind
//! does not sync the store; the rest of the store keeps its guarantees.
//!
//! The store is a WAL with `synchronous = NORMAL`: a commit appends frames to
//! the log and syncs nothing.  What syncs is a checkpoint (the log before the
//! pages are copied, the file after) and the header of a log that starts
//! (again), which SQLite syncs so that an out-of-order write after the restart
//! of a log cannot replay older frames over newer pages.  A scope changes no
//! setting of the connection (`synchronous = OFF` would skip that header sync,
//! and with it the guard of every table of the store): what makes its rows
//! volatile is what the process does at its end.
//!
//! Before, the close of the last connection always wrote the log back (a
//! checkpoint, which syncs it): the commits of a process were on disk once
//! the last process that had the store open was gone.  That stays so:
//!
//! - A process that made a durable write (any row changed outside of a scope,
//!   the tables, the header of the file) closes as before: when it is the
//!   last, its close writes the log back.  At its first durable write and
//!   again before its close it makes the mark [`UNSYNCED`] next to the
//!   database (a file, no sync: it is only of use while the machine runs),
//!   which says that the log may hold durable commits that no checkpoint
//!   synced.
//! - A process that made volatile writes and nothing durable closes without a
//!   checkpoint (`SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE`, no sync) and leaves the
//!   log to the next opener, unless the mark is there or the log grew past
//!   [`KEPT_LOG`] bytes: then it closes as before (the last job of a monitor
//!   writes such a log back after its clients were told, off the path of the
//!   command).  A crash of the machine may lose the commits of the log that
//!   were never synced, a suffix of it: the store is a prefix of its commits.
//! - A process that wrote nothing closes the store as before (it recovers and
//!   removes the log of a process that was killed).
//!
//! A close that removed the log (it was the last, and wrote it all back)
//! removes the mark, and makes it again when a log with frames is there by
//! then: a process that commits later makes it at its own close, after its
//! commits.
//!
//! A scope is one call on a connection (one function of the crate): [`run`].
//! What a function of the crate does outside of a [`run`] is durable.
//!
//! The namespaces of a boot (`namespaces`, `holders`) are volatile too: the
//! processes that join the namespaces of the rootless user write them before
//! they have a thread, through a plain connection of their own ([`open`]),
//! kept until the engine's connection is open ([`keep`]) so that the engine's
//! closes last.  It changes no setting either, and never writes the log back
//! while it is open (`wal_autocheckpoint = 0`: no checkpoint before a thread).

use crate::{apply_pragmas, schema};
use rusqlite::Connection as Sqlite;
use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use velarx_types::{DbError, DbResult};

/// The log a process that wrote nothing durable leaves for the next one,
/// at most: past it the close writes the log back (and syncs it).
pub const KEPT_LOG: u64 = 1 << 20;

/// Whether this process made a durable write to a store.
static DURABLE: AtomicBool = AtomicBool::new(false);

/// Whether this process made a volatile write to a store: the log it leaves
/// has rows in it.
static VOLATILE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The rows changed in scopes by the call being run on this thread.
    static SCOPED: Cell<i64> = const { Cell::new(0) };
    /// Whether a scope runs on this thread (one inside it is part of it).
    static IN_SCOPE: Cell<bool> = const { Cell::new(false) };
}

/// Whether this process made a write that must survive a crash.
pub fn durable_writes() -> bool {
    DURABLE.load(Ordering::Acquire)
}

/// Run `f` as a volatile scope when `volatile`: the rows it changes do not
/// make this process write the log back at its end.  Not volatile: `f` as it
/// is, durable.
pub fn run<R>(
    conn: &mut Sqlite,
    volatile: bool,
    f: impl FnOnce(&mut Sqlite) -> tokio_rusqlite::Result<R>,
) -> tokio_rusqlite::Result<R> {
    if !volatile || IN_SCOPE.with(Cell::get) {
        return f(conn);
    }
    struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            IN_SCOPE.with(|s| s.set(false));
        }
    }
    IN_SCOPE.with(|s| s.set(true));
    let scope = Scope;
    let before = conn.total_changes();
    let result = f(conn);
    drop(scope);
    let changed = i64::try_from(conn.total_changes().saturating_sub(before)).unwrap_or(i64::MAX);
    if changed > 0 {
        VOLATILE.store(true, Ordering::Release);
    }
    SCOPED.with(|c| c.set(c.get().saturating_add(changed)));
    result
}

/// Whether the container `id` (or named so) is removed when it ends: the
/// rows of it are volatile.
pub fn container(conn: &Sqlite, id: &str) -> bool {
    conn.prepare_cached(
        "SELECT json_extract(config, '$.auto_remove') FROM containers WHERE id = ?1 OR name = ?1",
    )
    .and_then(|mut s| s.query_row([id], |r| r.get::<_, Option<bool>>(0)))
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// A write that no row count shows (a table made, the header of the file) is
/// durable: it is told here.
pub(crate) fn mark_durable() {
    DURABLE.store(true, Ordering::Release);
}

/// What [`Conn`](crate::Conn) and the store of a monitor do around a call:
/// before it.
pub(crate) fn call_begins() {
    SCOPED.with(|c| c.set(0));
}

/// After the call on `conn`: the rows it changed (`changed`) that no scope
/// covered are durable writes.  The first one makes the mark (see the
/// module): a process killed before its close leaves it too.
pub(crate) fn call_ends(conn: &Sqlite, changed: i64) {
    if writes_durably(changed, SCOPED.with(Cell::get)) && !DURABLE.swap(true, Ordering::AcqRel) {
        velarx_base::trace::point("db durable write");
        let _ = mark(conn);
    }
}

/// Whether a call that changed `changed` rows, `scoped` of them in scopes,
/// wrote something that must survive a crash.
fn writes_durably(changed: i64, scoped: i64) -> bool {
    changed > scoped
}

/// The log of the database of `conn`, none in memory.
fn log_path(conn: &Sqlite) -> Option<std::path::PathBuf> {
    side(conn, "-wal")
}

/// The file next to the database of `conn` named with `suffix`.
fn side(conn: &Sqlite, suffix: &str) -> Option<std::path::PathBuf> {
    let path = conn.path().filter(|p| !p.is_empty())?;
    let mut side = std::ffi::OsString::from(path);
    side.push(suffix);
    Some(side.into())
}

/// The suffix of the mark of a log that may hold durable commits no
/// checkpoint synced (see the module).
pub const UNSYNCED: &str = "-unsynced";

/// Whether the log of `conn` is past [`KEPT_LOG`]: it is written back, by
/// whoever can do it off the path of a command first (the monitor).
pub(crate) fn log_is_long(conn: &Sqlite) -> bool {
    log_path(conn).is_some_and(|wal| std::fs::metadata(wal).map_or(0, |m| m.len()) > KEPT_LOG)
}

/// Whether the log of `conn` is to be written back by this process although
/// it made no durable write: it is long, or it may hold the durable commits
/// of another process.
pub(crate) fn log_wants_write_back(conn: &Sqlite) -> bool {
    log_is_long(conn) || side(conn, UNSYNCED).is_some_and(|m| m.exists())
}

/// Make the mark [`UNSYNCED`] of the store of `conn` (none in memory).
fn mark(conn: &Sqlite) -> std::io::Result<()> {
    let Some(mark) = side(conn, UNSYNCED) else {
        return Ok(());
    };
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(mark)
        .map(drop)
}

/// What a process does before it closes `conn` (see the module).
pub(crate) fn before_close(conn: &Sqlite) {
    before_close_when(conn, durable_writes(), VOLATILE.load(Ordering::Acquire));
}

fn before_close_when(conn: &Sqlite, durable: bool, volatile: bool) {
    if durable {
        if let Err(e) = mark(conn) {
            // (with no mark the next close may leave the log: it is synced
            // here instead)
            tracing::debug!("cannot mark the log of the store: {e}");
            if let Some(wal) = log_path(conn) {
                let _ = std::fs::File::open(wal).and_then(|f| f.sync_data());
            }
        }
        return;
    }
    if !volatile || log_wants_write_back(conn) {
        return;
    }
    let _ = conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    );
}

/// What a process does once it closed the database `path`: a close that
/// removed the log wrote it all back, and the mark goes (see the module).
pub(crate) fn after_close(path: &std::path::Path) {
    if path.as_os_str().is_empty() {
        return;
    }
    let with = |suffix: &str| {
        let mut p = path.as_os_str().to_os_string();
        p.push(suffix);
        std::path::PathBuf::from(p)
    };
    let (mark, wal) = (with(UNSYNCED), with("-wal"));
    let logged = || std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0);
    if !mark.exists() || logged() {
        return;
    }
    let _ = std::fs::remove_file(&mark);
    // (a log made meanwhile may hold the commits of a process that made the
    // mark before this removed it)
    if logged() {
        let _ = std::fs::File::create(&mark);
    }
}

/// The cache of the connection (KiB): it reads and writes a few rows.
const CACHE_KIB: u32 = 500;

fn sqlite(e: rusqlite::Error) -> DbError {
    DbError::Sqlite(e.into())
}

/// A connection of [`open`]: a plain connection to the store, which syncs
/// at its close only as the last connection of the store.
pub struct Connection(Option<rusqlite::Connection>);

impl Deref for Connection {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &rusqlite::Connection {
        self.0
            .as_ref()
            .expect("the connection is there until the drop")
    }
}

impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut rusqlite::Connection {
        self.0
            .as_mut()
            .expect("the connection is there until the drop")
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let Some(conn) = self.0.take() else {
            return;
        };
        // (its rows are volatile: a process that wrote nothing else leaves
        // the log to the next one, see the module)
        if conn.total_changes() > 0 {
            VOLATILE.store(true, Ordering::Release);
        }
        before_close(&conn);
        let path = conn.path().map(PathBuf::from);
        if conn.close().is_ok() {
            if let Some(path) = path {
                after_close(&path);
            }
        }
    }
}

/// A plain connection (for the code that runs before any thread) to the
/// store at `path`, made (with its directories, the user's alone) when it is
/// not there, by the code the engine makes it with: the same settings, the
/// same schema.  Its commits are volatile (see the module) and it does not
/// write the log back while it is open.
pub fn open(path: &Path) -> DbResult<Connection> {
    velarx_base::ipc::make_private_file(path).map_err(|e| {
        DbError::Sqlite(tokio_rusqlite::Error::Other(Box::new(
            std::io::Error::other(format!("{}: {e}", path.display())),
        )))
    })?;
    let mut conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(sqlite)?;
    apply_pragmas(&conn, true, CACHE_KIB).map_err(sqlite)?;
    // (a store that is not there is made by the engine's code, with the
    // syncs of the engine's connection)
    schema::init(&mut conn)
        .map_err(|e| DbError::Sqlite(tokio_rusqlite::Error::Other(Box::new(e))))?;
    conn.execute_batch("PRAGMA wal_autocheckpoint = 0;")
        .map_err(sqlite)?;
    Ok(Connection(Some(conn)))
}

/// The connection [`keep`] keeps, the process that kept it and its store.
static KEPT: Mutex<Option<(u32, PathBuf, Connection)>> = Mutex::new(None);

/// Keep `conn`, of the store at `path`, open until this process opens that
/// store with the engine's connection ([`crate::Database::open`]) or ends:
/// the engine's connection is then the one that closes last, and `conn`
/// closes with no sync.
pub fn keep(path: &Path, conn: Connection) {
    static AT_EXIT: std::sync::Once = std::sync::Once::new();
    AT_EXIT.call_once(|| velarx_sys::process::at_exit(release_at_exit));
    *KEPT.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((std::process::id(), path.to_path_buf(), conn));
}

/// Close the connection [`keep`] kept for the store at `path` (`None`: of
/// any store).  Only in the process that kept it: a child that forked from
/// it leaves it to its parent.
pub(crate) fn release(path: Option<&Path>) {
    let mut kept = KEPT.lock().unwrap_or_else(|e| e.into_inner());
    if kept
        .as_ref()
        .is_some_and(|(_, p, _)| path.is_none_or(|path| path == p))
    {
        match kept.take() {
            Some((pid, _, conn)) if pid == std::process::id() => drop(conn),
            other => std::mem::forget(other),
        }
    }
}

extern "C" fn release_at_exit() {
    release(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_in(dir: &std::path::Path) -> Sqlite {
        let conn = Sqlite::open(dir.join("db")).unwrap();
        crate::apply_pragmas(&conn, true, 2000).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS t (a INTEGER);
             CREATE TABLE IF NOT EXISTS containers (id TEXT, name TEXT, config TEXT);
             CREATE TABLE IF NOT EXISTS container_deps (container_id TEXT, target TEXT);",
        )
        .unwrap();
        conn
    }

    fn store() -> (tempfile::TempDir, Sqlite) {
        let dir = tempfile::tempdir().unwrap();
        let conn = store_in(dir.path());
        (dir, conn)
    }

    fn pragma(conn: &Sqlite, name: &str) -> i64 {
        conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
            .unwrap()
    }

    fn rows(conn: &Sqlite) -> i64 {
        conn.query_row("SELECT count(*) FROM t", [], |r| r.get(0))
            .unwrap()
    }

    /// A scope changes no setting of the connection: `synchronous = OFF`
    /// would also skip the sync of the header of a log that starts again,
    /// SQLite's guard against the replay of older frames after a crash.
    #[test]
    fn a_scope_keeps_the_settings_of_the_connection() {
        let (_dir, mut conn) = store();
        let auto = pragma(&conn, "wal_autocheckpoint");
        assert_eq!(pragma(&conn, "synchronous"), 1);
        run(&mut conn, true, |c| {
            assert_eq!(pragma(c, "synchronous"), 1);
            assert_eq!(pragma(c, "wal_autocheckpoint"), auto);
            c.execute("INSERT INTO t VALUES (1)", [])?;
            Ok(())
        })
        .unwrap();
        // (a failure is given back as it is)
        let failed: tokio_rusqlite::Result<()> = run(&mut conn, true, |c| {
            c.execute("INSERT INTO nowhere VALUES (1)", [])?;
            Ok(())
        });
        assert!(failed.is_err());
        assert_eq!(rows(&conn), 1);
    }

    /// The rows of a scope are counted once, also when a scope runs inside
    /// another; the rows changed outside of one are durable.
    #[test]
    fn the_rows_of_a_scope_are_counted_once() {
        let (_dir, mut conn) = store();
        call_begins();
        run(&mut conn, true, |c| {
            run(c, true, |c| {
                c.execute("INSERT INTO t VALUES (1)", [])?;
                Ok(())
            })?;
            c.execute("INSERT INTO t VALUES (2)", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(SCOPED.with(Cell::get), 2);
        assert!(!IN_SCOPE.with(Cell::get));
        run(&mut conn, false, |c| {
            c.execute("INSERT INTO t VALUES (3)", [])?;
            Ok(())
        })
        .unwrap();
        assert_eq!(SCOPED.with(Cell::get), 2);
        assert!(writes_durably(3, 2) && writes_durably(1, 0));
        assert!(!writes_durably(2, 2) && !writes_durably(0, 0));
    }

    #[test]
    fn a_container_that_is_removed_at_its_end_is_volatile() {
        let (_dir, conn) = store();
        for (id, config) in [
            ("rm", r#"{"auto_remove": true}"#),
            ("kept", r#"{"auto_remove": false}"#),
            ("plain", "{}"),
        ] {
            conn.execute("INSERT INTO containers VALUES (?1, ?1, ?2)", [id, config])
                .unwrap();
        }
        assert!(container(&conn, "rm"));
        assert!(!container(&conn, "kept") && !container(&conn, "plain"));
        assert!(!container(&conn, "none"));
    }

    /// The removal of an `--rm` container: its rows are volatile, what
    /// goes in their transaction (the image of `--rmi`) is not.
    #[test]
    fn the_rows_of_a_removed_container_are_volatile_and_what_goes_with_them_is_not() {
        let (_dir, mut conn) = store();
        for (writes, scoped) in [(false, 1), (true, 1)] {
            conn.execute(
                "INSERT INTO containers VALUES ('rm', 'rm', '{\"auto_remove\": true}')",
                [],
            )
            .unwrap();
            call_begins();
            let before = conn.total_changes();
            crate::delete_container_then(&mut conn, "rm", |c| {
                if writes {
                    c.execute("INSERT INTO t VALUES (1)", []).unwrap();
                }
            })
            .unwrap();
            let changed = i64::try_from(conn.total_changes() - before).unwrap();
            assert_eq!(SCOPED.with(Cell::get), scoped);
            assert_eq!(writes_durably(changed, scoped), writes, "{writes}");
        }
    }

    /// A process that wrote nothing at all does not leave a log.
    #[test]
    fn a_process_that_wrote_nothing_leaves_no_log() {
        let (dir, conn) = store();
        before_close_when(&conn, false, false);
        conn.close().unwrap();
        assert!(!dir.path().join("db-wal").exists());
    }

    /// The close of a process that wrote nothing that must survive leaves
    /// the log, and the next opener has the rows in it; the close of one that
    /// did leaves nothing.
    #[test]
    fn the_close_leaves_the_log_only_to_a_process_with_nothing_durable() {
        for durable in [false, true] {
            let (dir, mut conn) = store();
            run(&mut conn, true, |c| {
                c.execute("INSERT INTO t VALUES (1)", [])?;
                Ok(())
            })
            .unwrap();
            before_close_when(&conn, durable, true);
            conn.close().unwrap();
            let wal = dir.path().join("db-wal");
            assert_eq!(wal.exists(), !durable, "durable: {durable}");
            let again = Sqlite::open(dir.path().join("db")).unwrap();
            assert_eq!(rows(&again), 1, "durable: {durable}");
        }
    }

    /// Two processes on one store (a connection each): a durable writer that
    /// closes first leaves the mark, and the volatile-only process that
    /// closes last writes the log back because of it (as the last close
    /// always did) and removes the mark; with no durable writer it leaves
    /// the log.
    #[test]
    fn the_last_close_writes_back_the_commits_of_a_durable_writer() {
        for durable_writer in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let mut volatile = store_in(dir.path());
            let other = store_in(dir.path());
            other.execute("INSERT INTO t VALUES (1)", []).unwrap();
            run(&mut volatile, true, |c| {
                c.execute("INSERT INTO t VALUES (2)", [])?;
                Ok(())
            })
            .unwrap();
            before_close_when(&other, durable_writer, false);
            other.close().unwrap();
            after_close(&dir.path().join("db"));
            let mark = dir.path().join(format!("db{UNSYNCED}"));
            assert_eq!(
                mark.exists(),
                durable_writer,
                "not the last: the mark stays"
            );
            before_close_when(&volatile, false, true);
            volatile.close().unwrap();
            after_close(&dir.path().join("db"));
            let wal = dir.path().join("db-wal");
            assert_eq!(wal.exists(), !durable_writer, "{durable_writer}");
            assert!(!mark.exists());
            let again = Sqlite::open(dir.path().join("db")).unwrap();
            assert_eq!(rows(&again), 2);
        }
    }

    /// A durable process marks the log before it closes; a volatile-only
    /// one does not, and leaves the log only when no mark is there.
    #[test]
    fn a_durable_process_marks_the_log() {
        let (dir, mut conn) = store();
        let mark = dir.path().join(format!("db{UNSYNCED}"));
        run(&mut conn, true, |c| {
            c.execute("INSERT INTO t VALUES (1)", [])?;
            Ok(())
        })
        .unwrap();
        before_close_when(&conn, false, true);
        assert!(!mark.exists());
        before_close_when(&conn, true, true);
        assert!(mark.exists());
        assert!(log_wants_write_back(&conn));
    }

    /// A mark whose log is gone goes, and one comes back when a log with
    /// frames is there again.
    #[test]
    fn the_mark_goes_with_the_log() {
        let (dir, conn) = store();
        let mark = dir.path().join(format!("db{UNSYNCED}"));
        std::fs::write(&mark, b"").unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        after_close(&dir.path().join("db"));
        assert!(mark.exists(), "a log with frames: it stays");
        conn.close().unwrap();
        after_close(&dir.path().join("db"));
        assert!(!mark.exists());
    }

    fn side_files(path: &Path) -> Vec<bool> {
        ["-wal", "-shm"]
            .iter()
            .map(|ext| {
                let mut p = path.as_os_str().to_owned();
                p.push(ext);
                Path::new(&p).exists()
            })
            .collect()
    }

    fn holders(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM holders", [], |r| r.get(0))
            .unwrap()
    }

    fn insert(conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO holders (boot_id, scope, pid, start, role) VALUES ('b', 's', 1, 2, 'r')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn a_connection_makes_the_store_and_is_the_stores() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/db.sqlite");
        let conn = open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, schema::SCHEMA_VERSION);
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name IN ('namespaces', 'holders', 'containers')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 3);
    }

    /// What the connection wrote stays in the log while another connection
    /// of the store is open (its close writes nothing back), and the close of
    /// the last one writes it back and leaves no file next to the store.
    #[test]
    fn the_log_is_written_back_by_the_last_connection_to_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let store = open(&path).unwrap();
        // (a connection of the store as the engine has it)
        let mut engine = rusqlite::Connection::open(&path).unwrap();
        apply_pragmas(&engine, true, CACHE_KIB).unwrap();
        schema::init(&mut engine).unwrap();
        drop(store);
        let conn = open(&path).unwrap();
        insert(&conn);
        drop(conn);
        assert_eq!(side_files(&path), [true, true], "the engine's is open");
        assert!(
            std::fs::metadata(dir.path().join("db.sqlite-wal"))
                .unwrap()
                .len()
                > 0
        );
        assert_eq!(holders(&engine), 1);
        drop(engine);
        assert_eq!(side_files(&path), [false, false], "the last close");
        let file = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(holders(&file), 1, "the rows are in the file");
    }

    /// A connection that is the last to close writes the log back too.
    #[test]
    fn the_last_connection_leaves_no_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let conn = open(&path).unwrap();
        insert(&conn);
        drop(conn);
        assert_eq!(side_files(&path), [false, false]);
        assert_eq!(holders(&open(&path).unwrap()), 1);
    }

    /// A kept connection is closed by the open of the engine's.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_kept_connection_closes_when_the_engine_opens_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let conn = open(&path).unwrap();
        insert(&conn);
        keep(&path, conn);
        assert!(KEPT.lock().unwrap().is_some());
        let db = crate::Database::open(&path).await.unwrap();
        assert!(KEPT.lock().unwrap().is_none(), "closed by the open");
        assert_eq!(side_files(&path), [true, true], "and not the last");
        drop(db);
        assert_eq!(side_files(&path), [false, false]);
    }
}
