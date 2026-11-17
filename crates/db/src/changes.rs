// SPDX-License-Identifier: Apache-2.0
//! Telling the other processes that the database changed.
//!
//! The processes that share a store (the API server, the commands run with
//! no server, the monitors, the store service) write
//! and read the same database.  Each call on the connection that changed
//! rows (containers, images, layers, manifests: any of them) is followed,
//! once committed, by a touch of the file `db.sqlite-changes` (its times, no
//! data), and a process that waits for a change watches that file with
//! inotify: no timer, and no look between the write of the WAL and the
//! publication of the commit, which the files of the database cannot tell
//! apart.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn path_of(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push("-changes");
    PathBuf::from(p)
}

pub(super) fn open(db: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path_of(db))
}

/// Touch the file: its change time moves.
pub(super) fn signal(file: &File) {
    use rustix::fs::{futimens, Timespec, Timestamps, UTIME_NOW};
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: UTIME_NOW as _,
    };
    if let Err(e) = futimens(
        file,
        &Timestamps {
            last_access: now,
            last_modification: now,
        },
    ) {
        tracing::warn!("cannot tell the other processes of a change: {e}");
    }
}

/// What a database keeps for the changes: the file it touches, and the one
/// watch of it (in the inotify instance of the process: a host allows 128
/// instances to a user), shared by every [`ChangeWatch`].  The watch lives
/// while a [`ChangeWatch`] does.
pub(super) struct Changes {
    file: File,
    hub: Hub,
    /// Rows were changed in a transaction that is not over yet: they are
    /// told once it is (by the thread of the connection only)
    pending: std::sync::atomic::AtomicBool,
}

/// The sender of the watch, if there is one: the task that reads the watch
/// owns it, so a task that ended (an error, its runtime gone)
/// leaves none behind, and its watches are told (`changed` fails) instead
/// of waiting for ever.
type Hub = std::sync::Arc<std::sync::Mutex<std::sync::Weak<tokio::sync::watch::Sender<u64>>>>;

impl Changes {
    pub(super) fn new(file: File) -> Self {
        Self {
            file,
            hub: Hub::default(),
            pending: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(super) fn signal(&self) {
        signal(&self.file);
    }

    /// After a call on the connection: whether it `changed` rows, and
    /// whether the connection is out of any transaction (`committed`: what
    /// was changed is published, or rolled back).  The touch comes once
    /// both are true, never inside a transaction.
    pub(super) fn changed(&self, changed: bool, committed: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        if changed {
            self.pending.store(true, Relaxed);
        }
        if committed && self.pending.swap(false, Relaxed) {
            self.signal();
        }
    }
}

/// The commits to the database made by any process.
pub struct ChangeWatch(Option<tokio::sync::watch::Receiver<u64>>);

impl ChangeWatch {
    /// Watch the changes of the database at `db`, from now on.  Needs a
    /// tokio runtime.
    pub(super) fn new(db: Option<(&Path, &Changes)>) -> io::Result<Self> {
        let Some((db, changes)) = db else {
            return Ok(Self(None));
        };
        let mut hub = changes.hub.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tx) = hub.upgrade().filter(|tx| !tx.is_closed()) {
            return Ok(Self(Some(tx.subscribe())));
        }
        // (a watch of the instance of the process: one per process however
        // many databases or containers it watches)
        let watch = velarx_sys::watch::Watch::new()?;
        watch.add(&path_of(db), rustix::fs::inotify::WatchFlags::ATTRIB)?;
        let fd = velarx_sys::fd::register(
            watch.owned_fd()?,
            tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE,
        )?;
        let (tx, rx) = tokio::sync::watch::channel(0);
        let tx = std::sync::Arc::new(tx);
        *hub = std::sync::Arc::downgrade(&tx);
        let shared = changes.hub.clone();
        tokio::spawn(async move {
            // (a wake, whatever its event, a lost one too (IN_Q_OVERFLOW),
            // wakes every watch: they look at the database again)
            let _watch = watch;
            let mut buf = [0u8; 8];
            loop {
                tokio::select! {
                    () = tx.closed() => {
                        // nobody watches: the watch is ended, unless a
                        // watch joined meanwhile (they join under the lock)
                        let _hub = shared.lock().unwrap_or_else(|e| e.into_inner());
                        if tx.is_closed() {
                            return;
                        }
                    }
                    ready = fd.readable() => {
                        let Ok(mut guard) = ready else { return };
                        match rustix::io::read(guard.get_inner(), &mut buf) {
                            Ok(_) => {
                                tx.send_modify(|n| *n = n.wrapping_add(1));
                            }
                            Err(rustix::io::Errno::AGAIN) => guard.clear_ready(),
                            Err(e) => {
                                tracing::warn!("cannot watch the changes of the database: {e}");
                                return;
                            }
                        }
                    }
                }
            }
        });
        Ok(Self(Some(rx)))
    }

    /// Until the database changed after the last return (or after the watch
    /// was made).  A database that lives in memory has no other process:
    /// this never returns.
    pub async fn changed(&mut self) -> io::Result<()> {
        let Some(rx) = &mut self.0 else {
            return std::future::pending().await;
        };
        rx.changed()
            .await
            .map_err(|_| io::Error::other("the watch of the changes of the database ended"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Many watches share the one inotify instance of the process; each is
    /// told of a change made after it was made.
    /// (the tests that make instances count them: one at a time)
    static INSTANCES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn the_watches_of_a_process_share_one_inotify_instance() {
        let _one = INSTANCES.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite");
        let changes = Changes::new(open(&db).unwrap());
        let instances = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter(|l| l.to_string_lossy().contains("inotify"))
                .count()
        };
        let mut watches: Vec<ChangeWatch> = (0..50)
            .map(|_| ChangeWatch::new(Some((&db, &changes))).unwrap())
            .collect();
        assert_eq!(instances(), 1);
        changes.signal();
        for w in &mut watches {
            tokio::time::timeout(std::time::Duration::from_secs(10), w.changed())
                .await
                .unwrap()
                .unwrap();
        }
        drop(watches);
        let mut again = ChangeWatch::new(Some((&db, &changes))).unwrap();
        changes.signal();
        tokio::time::timeout(std::time::Duration::from_secs(10), again.changed())
            .await
            .unwrap()
            .unwrap();
    }

    /// The watch is read by a task: once that task is gone (its runtime
    /// ended) its watches are told, and a new watch gets a watch of its own
    /// rather than one nobody reads.
    #[test]
    fn a_watch_outlives_the_runtime_of_the_first() {
        let _one = INSTANCES.blocking_lock();
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite");
        let changes = Changes::new(open(&db).unwrap());
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        };
        let first = runtime();
        let mut orphan = first.block_on(async { ChangeWatch::new(Some((&db, &changes))).unwrap() });
        drop(first);
        runtime().block_on(async {
            let mut again = ChangeWatch::new(Some((&db, &changes))).unwrap();
            changes.signal();
            tokio::time::timeout(std::time::Duration::from_secs(10), again.changed())
                .await
                .expect("the new watch is read")
                .unwrap();
            assert!(orphan.changed().await.is_err(), "the orphan is told");
        });
    }
}
