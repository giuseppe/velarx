// SPDX-License-Identifier: Apache-2.0
//! Leases: what a pull in progress uses of the store (`leases`,
//! `lease_items`), so that the garbage collection leaves it alone and can
//! tell the staging directory of a live pull from the leftover of a dead
//! one.  A lease is named after the staging session of the pull and lives
//! as long as the process of the pull holds an `flock` on its file in
//! `leases/` next to the database: the kernel drops the lock when the
//! process ends, however it ends, and whatever its pid becomes, so there is
//! nothing to renew and no pid to guess.

use super::Database;
use std::collections::HashMap;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;
use velarx_types::{DbError, DbResult};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS leases (
    id TEXT PRIMARY KEY,
    pid INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lease_items (
    lease_id TEXT NOT NULL REFERENCES leases(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY (lease_id, kind, digest)
);

CREATE INDEX IF NOT EXISTS idx_lease_items_digest ON lease_items(digest);
"#;

/// A lease item that pins a layer.
pub const LEASE_LAYER: &str = "layer";

/// A lease item that keeps an image from a prune (the intermediate images
/// of a build).
pub const LEASE_IMAGE: &str = "image";

#[derive(Debug, Clone, PartialEq)]
pub struct LeaseRecord {
    pub id: String,
    pub pid: i64,
}

/// Where the lock files of the leases live.
pub(super) enum LockDir {
    /// The `leases/` directory next to the database file
    Dir(PathBuf),
    /// A database in memory: nothing outside the process can see its leases,
    /// so their locks are anonymous files (`memfd`) that are never named in
    /// any directory and go with the process, however it ends.  Per lease id,
    /// the anonymous file whose locks are taken on fresh open file
    /// descriptions (`/proc/self/fd/N`), as a lock file of a directory is.
    Memory(Mutex<HashMap<String, OwnedFd>>),
}

/// The directory of the lock files of the leases of the database whose
/// file is `path` (none for a database in memory).
pub(super) fn lock_dir(path: Option<&std::path::Path>) -> LockDir {
    match path.and_then(std::path::Path::parent) {
        Some(dir) => LockDir::Dir(dir.join("leases")),
        None => LockDir::Memory(Mutex::new(HashMap::new())),
    }
}

/// Open the anonymous file `anon` on a new open file description.
fn reopen(anon: &OwnedFd, write: bool) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .open(velarx_sys::fd::proc_path(anon))
}

impl Database {
    fn lease_lock_path(&self, id: &str) -> PathBuf {
        match &*self.lease_dir {
            LockDir::Dir(dir) => dir.join(format!("{id}.lock")),
            LockDir::Memory(_) => PathBuf::from(format!("memory:{id}.lock")),
        }
    }

    /// Open the lock file of the lease `id` for a test of its lock
    /// (`NotFound` when there is none).
    fn open_lease_lock(&self, id: &str) -> std::io::Result<std::fs::File> {
        match &*self.lease_dir {
            LockDir::Dir(_) => std::fs::File::open(self.lease_lock_path(id)),
            LockDir::Memory(map) => {
                let map = map.lock().unwrap_or_else(|e| e.into_inner());
                match map.get(id) {
                    Some(anon) => reopen(anon, false),
                    None => Err(std::io::ErrorKind::NotFound.into()),
                }
            }
        }
    }

    /// Forget the lock file of the lease `id`.
    fn remove_lease_lock(&self, id: &str) {
        match &*self.lease_dir {
            LockDir::Dir(_) => {
                let _ = std::fs::remove_file(self.lease_lock_path(id));
            }
            LockDir::Memory(map) => {
                map.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
            }
        }
    }

    /// Create (or open) the lock file of the lease `id`, to be locked.
    fn create_lease_lock(&self, id: &str) -> DbResult<std::fs::File> {
        match &*self.lease_dir {
            LockDir::Dir(_) => {
                let lock_path = self.lease_lock_path(id);
                if let Some(dir) = lock_path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| super::io_error(dir, e))?;
                }
                std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&lock_path)
                    .map_err(|e| super::io_error(&lock_path, e))
            }
            LockDir::Memory(map) => {
                let path = self.lease_lock_path(id);
                let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
                // (the one of a lease of that id that is still there, as an
                // existing lock file is opened, not replaced)
                if let Some(anon) = map.get(id) {
                    return reopen(anon, true).map_err(|e| super::io_error(&path, e));
                }
                let anon =
                    rustix::fs::memfd_create("velarx-lease", rustix::fs::MemfdFlags::CLOEXEC)
                        .map_err(|e| super::io_error(&path, e.into()))?;
                let lock = reopen(&anon, true).map_err(|e| super::io_error(&path, e))?;
                map.insert(id.to_string(), anon);
                Ok(lock)
            }
        }
    }

    /// Whether the process that holds the lease `id` is alive: its lock
    /// cannot be taken.  A lease without a lock file is not held; one whose
    /// lock cannot be tested (an error other than "taken") is counted held:
    /// what a live pull uses is never taken for garbage.
    pub fn lease_is_held(&self, id: &str) -> bool {
        let file = match self.open_lease_lock(id) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => {
                warn!("Cannot test the lock of the lease {id}: {e}");
                return true;
            }
        };
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => false,
            Err(rustix::io::Errno::WOULDBLOCK) => true,
            Err(e) => {
                warn!("Cannot test the lock of the lease {id}: {e}");
                true
            }
        }
    }

    /// The leases split into those a process holds and those it dropped
    /// (the pull was killed): `(live, stale)`.
    pub async fn partition_leases(&self) -> DbResult<(Vec<LeaseRecord>, Vec<LeaseRecord>)> {
        Ok(self
            .list_leases()
            .await?
            .into_iter()
            .partition(|l| self.lease_is_held(&l.id)))
    }

    /// Create the lease `id` of this process with its items `(kind,
    /// digest)`: the lock file it holds, which the lease lives as long as.
    pub async fn create_lease(
        &self,
        id: &str,
        items: Vec<(String, String)>,
    ) -> DbResult<std::fs::File> {
        let lock_path = self.lease_lock_path(id);
        // (held before the lease is recorded: a collection that sees the
        // lease sees it held)
        let lock = self.create_lease_lock(id)?;
        velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|e| super::io_error(&lock_path, e))?;
        let id_for_cleanup = id;
        let (id, pid) = (id.to_string(), std::process::id());
        let recorded = self
            .conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT INTO leases (id, pid) VALUES (?1, ?2)",
                    rusqlite::params![id, pid],
                )?;
                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT OR IGNORE INTO lease_items (lease_id, kind, digest) VALUES (?1, ?2, ?3)",
                    )?;
                    for (kind, digest) in &items {
                        stmt.execute(rusqlite::params![id, kind, digest])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite);
        if recorded.is_err() {
            self.remove_lease_lock(id_for_cleanup);
        }
        recorded.map(|()| lock)
    }

    /// Add items to the lease `id`.
    pub async fn add_lease_items(&self, id: &str, items: Vec<(String, String)>) -> DbResult<()> {
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT OR IGNORE INTO lease_items (lease_id, kind, digest) VALUES (?1, ?2, ?3)",
                    )?;
                    for (kind, digest) in &items {
                        stmt.execute(rusqlite::params![id, kind, digest])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    /// Whether a lease a process still holds has `(kind, digest)`.
    pub async fn is_leased(&self, kind: &str, digest: &str) -> DbResult<bool> {
        let (kind, digest) = (kind.to_string(), digest.to_string());
        let holders: Vec<String> = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT l.id FROM lease_items li JOIN leases l ON l.id = li.lease_id
                     WHERE li.kind = ?1 AND li.digest = ?2",
                )?;
                let rows = stmt.query_map(rusqlite::params![kind, digest], |r| r.get(0))?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await
            .map_err(DbError::Sqlite)?;
        Ok(holders.iter().any(|id| self.lease_is_held(id)))
    }

    /// Remove the lease `id` and its items.
    pub async fn release_lease(&self, id: &str) -> DbResult<()> {
        self.remove_lease_lock(id);
        let id = id.to_string();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute("DELETE FROM lease_items WHERE lease_id = ?1", [&id])?;
                tx.execute("DELETE FROM leases WHERE id = ?1", [&id])?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::Sqlite)
    }

    pub async fn list_leases(&self) -> DbResult<Vec<LeaseRecord>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT id, pid FROM leases")?;
                let rows = stmt.query_map([], |r| {
                    Ok(LeaseRecord {
                        id: r.get(0)?,
                        pid: r.get(1)?,
                    })
                })?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await
            .map_err(DbError::Sqlite)
    }
}

/// The lease of a pull in progress: held while this lives, removed by
/// [`Lease::release`] (or when it is dropped; a lease that could not be
/// removed is dropped by the next collection, as the lock is gone).
pub struct Lease {
    db: Database,
    id: String,
    /// The lock file that keeps the lease alive
    _lock: std::fs::File,
    released: bool,
}

impl Lease {
    /// Lease the layers `layers` for the session `id`.
    pub async fn take(
        db: &Database,
        id: &str,
        layers: &[velarx_types::LayerKey],
    ) -> DbResult<Self> {
        let items = layers
            .iter()
            .map(|k| (LEASE_LAYER.to_string(), k.to_string()))
            .collect();
        Self::take_items(db, id, items).await
    }

    /// Lease the items `(kind, digest)` for `id`.
    pub async fn take_items(
        db: &Database,
        id: &str,
        items: Vec<(String, String)>,
    ) -> DbResult<Self> {
        let lock = db.create_lease(id, items).await?;
        Ok(Self {
            db: db.clone(),
            id: id.to_string(),
            _lock: lock,
            released: false,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub async fn release(mut self) -> DbResult<()> {
        self.released = true;
        self.db.release_lease(&self.id).await
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // (waited for, from a thread of its own: the database works in its
        // thread and needs nothing of this runtime, and a task spawned here
        // would not run in a process that ends with the error that dropped
        // the lease)
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let (db, id) = (&self.db, &self.id);
            std::thread::scope(|s| {
                s.spawn(|| {
                    if let Err(e) = rt.block_on(db.release_lease(id)) {
                        warn!("Cannot remove the lease {id}: {e}");
                    }
                });
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn leases_live_until_released() {
        let db = Database::open_in_memory().await.unwrap();
        let l1 = velarx_types::LayerKey::Toc(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
        );
        let lease = Lease::take(&db, "pull-a", std::slice::from_ref(&l1))
            .await
            .unwrap();
        let all = db.list_leases().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].pid, std::process::id() as i64);
        assert!(db.is_leased(LEASE_LAYER, &l1.to_string()).await.unwrap());
        // (a key of the other kind is not the same layer)
        assert!(!db
            .is_leased(LEASE_LAYER, &l1.digest().to_string())
            .await
            .unwrap());
        lease.release().await.unwrap();
        assert!(db.list_leases().await.unwrap().is_empty());
        assert!(!db.is_leased(LEASE_LAYER, &l1.to_string()).await.unwrap());
    }

    /// A lease that is dropped is gone when the drop returns: a process
    /// that ends with the error that dropped it leaves none behind.
    #[tokio::test]
    async fn a_dropped_lease_is_removed_at_once() {
        let db = Database::open_in_memory().await.unwrap();
        drop(Lease::take(&db, "pull-b", &[]).await.unwrap());
        assert!(db.list_leases().await.unwrap().is_empty());
    }

    /// A database in memory leaves nothing in the temporary directory: not
    /// when it is dropped, and not when it never is (a test that keeps its
    /// database in a `ManuallyDrop` or a static, a process that exits
    /// without unwinding), with or without a lease taken.  The databases are
    /// made by this test run again in a process of its own, whose temporary
    /// directory is one of this test: what other tests or test runs of the
    /// host put in theirs does not count.
    #[tokio::test]
    async fn a_database_in_memory_leaves_no_directory() {
        const IN_CHILD: &str = "VELARX_TEST_LEASES_CHILD";
        if std::env::var_os(IN_CHILD).is_some() {
            for i in 0..50 {
                let db = Database::open_in_memory().await.unwrap();
                let lease = Lease::take(&db, &format!("pull-{i}"), &[]).await.unwrap();
                assert!(db.lease_is_held(lease.id()));
                if i % 2 == 0 {
                    // (never dropped: neither the database nor the lease)
                    std::mem::forget(lease);
                    std::mem::forget(db);
                } else {
                    lease.release().await.unwrap();
                }
            }
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "leases::tests::a_database_in_memory_leaves_no_directory",
            ])
            .env(IN_CHILD, "1")
            .env("TMPDIR", tmp.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let left: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    /// The lock of a lease of a database in memory is held as long as the
    /// lease lives and no longer: dropping it makes the lease stale.  Its
    /// lock file is the same while it is held, as a lock file in a directory
    /// is: a second lock of it in this process waits.
    #[tokio::test]
    async fn the_lock_of_a_lease_in_memory_is_released_with_it() {
        let db = Database::open_in_memory().await.unwrap();
        let lock = db.create_lease("a", vec![]).await.unwrap();
        assert!(db.lease_is_held("a"));
        let again = db.create_lease_lock("a").unwrap();
        assert_eq!(
            rustix::fs::flock(&again, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(again);
        drop(lock);
        // (at once, but for the moment another thread of the test binary
        // that starts a program holds a copy of the lock until the program
        // is executed)
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while db.lease_is_held("a") {
            assert!(std::time::Instant::now() < deadline, "still held");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!db.lease_is_held("missing"));
    }

    /// A database in a file keeps its lock files in `leases/` beside it.
    #[tokio::test]
    async fn a_database_in_a_file_locks_beside_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("velarx.db")).await.unwrap();
        let lease = Lease::take(&db, "f", &[]).await.unwrap();
        assert!(dir.path().join("leases/f.lock").exists());
        assert!(db.lease_is_held("f"));
        lease.release().await.unwrap();
        assert!(!dir.path().join("leases/f.lock").exists());
    }

    /// A lease is stale when no lock holds it, whatever its pid is: here the
    /// pid is a live process (this one, as a reused pid would be).
    #[tokio::test]
    async fn a_lease_nobody_holds_is_stale() {
        let db = Database::open_in_memory().await.unwrap();
        let held = Lease::take(&db, "held", &[]).await.unwrap();
        // the lock of a pull that was killed is gone, the record and its
        // file are not (a lease taken and dropped here would not do: a
        // thread of the test binary that starts a program holds a copy of
        // the lock until the program is executed)
        let killed = "killed";
        drop(db.create_lease_lock(killed).unwrap());
        db.conn
            .call(move |conn| {
                Ok(conn.execute(
                    "INSERT INTO leases (id, pid) VALUES (?1, ?2)",
                    rusqlite::params![killed, std::process::id()],
                )?)
            })
            .await
            .unwrap();
        // (a record with no lock file at all)
        let id = "never";
        db.conn
            .call(move |conn| {
                Ok(conn.execute(
                    "INSERT INTO leases (id, pid) VALUES (?1, ?2)",
                    rusqlite::params![id, std::process::id()],
                )?)
            })
            .await
            .unwrap();
        let (live, stale) = db.partition_leases().await.unwrap();
        assert_eq!(
            live.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
            ["held"]
        );
        let mut stale: Vec<_> = stale.into_iter().map(|l| l.id).collect();
        stale.sort();
        assert_eq!(stale, ["killed", "never"]);
        drop(held);
    }

    /// The lock is the process's: a process killed with SIGKILL while it
    /// holds a lease leaves it stale at once.
    #[tokio::test]
    async fn the_lease_of_a_killed_process_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("velarx.db")).await.unwrap();
        // a child that takes the flock of the lease file and waits
        let lock = dir.path().join("leases").join("child.lock");
        std::fs::create_dir_all(lock.parent().unwrap()).unwrap();
        db.conn
            .call(|conn| Ok(conn.execute("INSERT INTO leases (id, pid) VALUES ('child', 1)", [])?))
            .await
            .unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exec 9>\"$1\" && flock -x 9 && echo locked && exec sleep 1000")
            .arg("sh")
            .arg(&lock)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // (it says so once it holds the lock)
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        assert_eq!(line, "locked\n");
        assert_eq!(db.partition_leases().await.unwrap().0.len(), 1);
        child.kill().unwrap();
        child.wait().unwrap();
        let (live, stale) = db.partition_leases().await.unwrap();
        assert!(live.is_empty() && stale.len() == 1);
    }
}
