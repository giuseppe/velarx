// SPDX-License-Identifier: Apache-2.0
//! The lock of the store (`<root>/storage.lock`), shared by every process
//! that uses the store (the daemon, its monitors, a daemonless command).
//!
//! What adds content to the store (a pull, the fetch of a lazy file) holds
//! it shared from the moment it decides what the store already has until
//! the content is recorded in the database; the garbage collection holds
//! it exclusive.  So the collection never runs between a pull moving files
//! into the store and recording them, nor removes a layer a pull found
//! stored and will reference.  It is an `flock`: the kernel releases it
//! when a process dies, and two opens of it in one process exclude each
//! other like two processes do.

use rustix::fs::{flock, FlockOperation};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use velarx_sys::flock::{flock_retrying, Held};

/// A held lock of the store, released when dropped (for every copy of its
/// descriptor: one a process forked meanwhile holds does not keep it).
#[derive(Debug)]
pub struct StorageLock {
    _file: Held,
}

impl StorageLock {
    /// The lock of the store whose root is `root`.
    pub fn path(root: &Path) -> PathBuf {
        root.join("storage.lock")
    }

    /// The lock of the store whose staging directory is `staging`
    /// (`<root>/staging`).
    pub fn path_of_staging(staging: &Path) -> PathBuf {
        Self::path(staging.parent().unwrap_or(staging))
    }

    fn open(path: &Path) -> io::Result<File> {
        if let Some(dir) = path.parent() {
            velarx_base::ipc::create_private_dirs(dir)?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    fn take(path: &Path, op: FlockOperation) -> io::Result<Option<Self>> {
        let file = Self::open(path)?;
        match flock_retrying(&file, op) {
            Ok(()) => Ok(Some(Self {
                _file: Held::new(file),
            })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Wait for the lock, shared: blocks while a collection runs.
    pub fn shared_blocking(path: &Path) -> io::Result<Self> {
        Self::take(path, FlockOperation::LockShared)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }

    /// Wait for the lock, exclusive: blocks while anything holds it.
    pub fn exclusive_blocking(path: &Path) -> io::Result<Self> {
        Self::take(path, FlockOperation::LockExclusive)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
    }

    /// The lock exclusive if nothing holds it.
    pub fn try_exclusive(path: &Path) -> io::Result<Option<Self>> {
        Self::take(path, FlockOperation::NonBlockingLockExclusive)
    }

    /// [`Self::shared_blocking`] off the async runtime.
    pub async fn shared(path: &Path) -> io::Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::shared_blocking(&path))
            .await
            .map_err(io::Error::other)?
    }

    /// [`Self::exclusive_blocking`] off the async runtime.
    pub async fn exclusive(path: &Path) -> io::Result<Self> {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || Self::exclusive_blocking(&path))
            .await
            .map_err(io::Error::other)?
    }
}

/// The exclusive locks on single things (`<root>/locks/<name>`: the file
/// being fetched, the commit of an image).  A lock file is removed once
/// nothing holds it ([`remove_unused`]), so a holder checks after it got the
/// lock that the path still names the file it holds, and takes it again if
/// not.
pub mod locks {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    pub(super) fn open(path: &Path, create: bool) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(create)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    /// Whether `path` is the file `file` is open on.
    pub(super) fn names(path: &Path, file: impl std::os::fd::AsFd) -> bool {
        match (std::fs::symlink_metadata(path), rustix::fs::fstat(file)) {
            (Ok(a), Ok(b)) => a.dev() == b.st_dev && a.ino() == b.st_ino,
            _ => false,
        }
    }

    /// The lock file `path`, created if need be and not locked: a holder
    /// that waits for it on a thread of its own takes it with this file,
    /// so that the file and its directory are not made again by a wait that
    /// outlives them.
    pub fn open_unlocked(path: &Path) -> io::Result<File> {
        if let Some(dir) = path.parent() {
            velarx_base::ipc::create_private_dirs(dir)?;
        }
        open(path, true)
    }

    /// The lock on `path`, created if need be; with `wait` false, None when
    /// another holds it.  Blocks with `wait`.  Dropped, it is let go for
    /// every copy of its descriptor.
    pub fn lock(path: &Path, wait: bool) -> io::Result<Option<Held>> {
        if let Some(dir) = path.parent() {
            velarx_base::ipc::create_private_dirs(dir)?;
        }
        loop {
            let file = open(path, true)?;
            let op = if wait {
                FlockOperation::LockExclusive
            } else {
                FlockOperation::NonBlockingLockExclusive
            };
            match flock_retrying(&file, op) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(e),
            }
            if names(path, &file) {
                return Ok(Some(Held::new(file)));
            }
        }
    }

    /// Remove the lock files of `dir` that nothing holds; how many.
    pub fn remove_unused(dir: &Path) -> usize {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file) = open(&path, false) else {
                continue;
            };
            // (removed while held: a holder that opened it before checks
            // the path after it has the lock)
            if flock(&file, FlockOperation::NonBlockingLockExclusive).is_ok()
                && std::fs::remove_file(&path).is_ok()
            {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The tests that take a lock again after its holder dropped it run in a
    // child of their own: a process another test of this binary starts
    // (`cp`, `sleep`) holds a copy of every descriptor between its fork and
    // its exec, and with it the lock of a file that was just closed.

    #[test]
    fn shared_excludes_exclusive() {
        velarx_base::testing::in_child(|| {
            let d = tempfile::tempdir().unwrap();
            let p = StorageLock::path(d.path());
            let a = StorageLock::shared_blocking(&p).unwrap();
            let b = StorageLock::shared_blocking(&p).unwrap();
            assert!(StorageLock::try_exclusive(&p).unwrap().is_none());
            drop(a);
            assert!(StorageLock::try_exclusive(&p).unwrap().is_none());
            drop(b);
            let ex = StorageLock::try_exclusive(&p).unwrap().unwrap();
            assert!(StorageLock::try_exclusive(&p).unwrap().is_none());
            drop(ex);
            assert!(StorageLock::try_exclusive(&p).unwrap().is_some());
        });
    }

    #[test]
    fn a_waiting_reader_gets_the_lock_after_the_writer() {
        let d = tempfile::tempdir().unwrap();
        let p = StorageLock::path(d.path());
        let ex = StorageLock::exclusive_blocking(&p).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = p.clone();
        let t = std::thread::spawn(move || {
            let _l = StorageLock::shared_blocking(&p2).unwrap();
            tx.send(()).unwrap();
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_err());
        drop(ex);
        rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        t.join().unwrap();
    }

    /// A lock let go is free at once, though a process forked while it was
    /// held (by another thread, to spawn a program) still has a copy of its
    /// descriptor: the lock is the open file's, which the copy shares.
    #[test]
    fn a_lock_let_go_is_free_while_a_forked_process_has_its_descriptor() {
        let d = tempfile::tempdir().unwrap();
        let (path, one) = (StorageLock::path(d.path()), d.path().join("one"));
        let store = StorageLock::shared_blocking(&path).unwrap();
        let single = locks::lock(&one, false).unwrap().unwrap();
        // a spawn whose child, forked with both locks held, waits between
        // its fork and its exec until it is told to go on
        let (forked_r, forked_w) = rustix::pipe::pipe().unwrap();
        let (go_r, go_w) = rustix::pipe::pipe().unwrap();
        let mut cmd = std::process::Command::new("true");
        velarx_sys::spawn::pre_exec(&mut cmd, move |_| {
            rustix::io::write(&forked_w, b"f")?;
            rustix::io::read(&go_r, &mut [0u8; 1])?;
            Ok(())
        });
        let spawn = std::thread::spawn(move || cmd.status().unwrap());
        rustix::io::read(&forked_r, &mut [0u8; 1]).unwrap();
        drop((store, single));
        let free = (
            StorageLock::try_exclusive(&path).unwrap().is_some(),
            locks::lock(&one, false).unwrap().is_some(),
        );
        rustix::io::write(&go_w, b"g").unwrap();
        assert!(spawn.join().unwrap().success());
        assert_eq!(free, (true, true), "a lock let go stays held by the fork");
    }

    #[test]
    fn the_lock_is_not_opened_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let p = StorageLock::path(d.path());
        std::os::unix::fs::symlink(d.path().join("elsewhere"), &p).unwrap();
        assert!(StorageLock::shared_blocking(&p).is_err());
        assert!(!d.path().join("elsewhere").exists());
    }

    #[test]
    fn lock_files_nothing_holds_are_removed() {
        velarx_base::testing::in_child(|| {
            let d = tempfile::tempdir().unwrap();
            let (a, b) = (d.path().join("a"), d.path().join("b"));
            let held = locks::lock(&a, false).unwrap().unwrap();
            // (another holder is refused)
            assert!(locks::lock(&a, false).unwrap().is_none());
            drop(locks::lock(&b, false).unwrap().unwrap());
            assert_eq!(locks::remove_unused(d.path()), 1);
            assert!(a.exists() && !b.exists());
            drop(held);
            assert_eq!(locks::remove_unused(d.path()), 1);
            assert!(!a.exists());
            // a lock is made again, whole
            assert!(locks::lock(&a, false).unwrap().is_some());
        });
    }

    #[test]
    fn a_lock_taken_on_a_removed_file_is_taken_again() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("l");
        let stale = locks::open(&path, true).unwrap();
        std::fs::remove_file(&path).unwrap();
        // the old file is not the one the path names
        assert!(!locks::names(&path, &stale));
        let fresh = locks::lock(&path, false).unwrap().unwrap();
        assert!(locks::names(&path, &fresh));
    }
}
