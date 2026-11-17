// SPDX-License-Identifier: Apache-2.0
//! The network namespace of the rootless bridges, as the engine and the
//! monitors of the containers find and release it: its record in the
//! namespaces tables of the store, the locks of its users, where it is, and the stop of
//! its holder.  The holder itself is started by the runtime.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use velarx_nsid::{store, Holder, Kind, NamespaceId};

/// The file a setup holds (shared) while it uses the namespace, and a
/// release needs (exclusive).
pub const USERS: &str = "rootless-netns.users";

/// The role the holder is recorded with.
pub const ROLE: &str = "netns";

/// The role a monitor that holds the namespace (a descriptor of it) is
/// recorded with.
pub const MONITOR_ROLE: &str = "monitor";

/// The namespaces tables of the store `db`, and the boot they are read for.
pub fn with_store<T>(
    db: &Path,
    f: impl FnOnce(&rusqlite::Connection, &str) -> rusqlite::Result<T>,
) -> io::Result<T> {
    let boot = velarx_nsid::store::boot_id()?;
    let conn = store::open(db)?;
    f(&conn, &boot).map_err(io::Error::other)
}

/// What the database says: the namespace and its holder.
pub struct Record {
    pub id: NamespaceId,
    pub holder: Option<Holder>,
    /// The monitors that hold it, through a descriptor
    pub monitors: Vec<Holder>,
}

pub fn read_record(db: &Path) -> io::Result<Option<Record>> {
    let stored = with_store(db, |c, boot| store::load(c, boot, store::ROOTLESS_NETNS))?;
    let id = stored.namespace(Kind::Net).cloned();
    Ok(id.map(|id| {
        let (monitors, others): (Vec<Holder>, Vec<Holder>) = stored
            .holders
            .into_iter()
            .partition(|h| h.role == MONITOR_ROLE);
        Record {
            id,
            holder: others.into_iter().find(|h| h.role == ROLE),
            monitors,
        }
    }))
}

pub fn write_record(db: &Path, id: &NamespaceId, holder: &Holder) -> io::Result<()> {
    with_store(db, |c, boot| {
        // (the monitors that hold the namespace stay: a holder that joins
        // the namespace after a killed one is the same namespace's)
        let stored = store::load(c, boot, store::ROOTLESS_NETNS)?;
        let old: Vec<Holder> = stored
            .holders
            .into_iter()
            .filter(|h| h.role != MONITOR_ROLE)
            .collect();
        store::remove_holders(c, boot, store::ROOTLESS_NETNS, &old)?;
        store::store(c, boot, store::ROOTLESS_NETNS, Kind::Net, id)?;
        store::add_holder(c, boot, store::ROOTLESS_NETNS, holder)
    })
}

/// The monitor `pid` holds the namespace through a descriptor: the
/// namespace is found through it when the holder process is gone.
pub fn add_monitor_holder(db: &Path, pid: i32) -> io::Result<()> {
    let start = velarx_nsid::start_time(pid)
        .ok_or_else(|| io::Error::other("the monitor's start time is not known"))?;
    with_store(db, |c, boot| {
        store::add_holder(
            c,
            boot,
            store::ROOTLESS_NETNS,
            &Holder {
                pid,
                start,
                role: MONITOR_ROLE.into(),
            },
        )
    })
}

/// The monitor `pid` lets go of the namespace (its container's network is
/// released).
pub fn remove_monitor_holder(db: &Path, pid: i32) -> io::Result<()> {
    let Some(start) = velarx_nsid::start_time(pid) else {
        return Ok(());
    };
    with_store(db, |c, boot| {
        store::remove_holders(
            c,
            boot,
            store::ROOTLESS_NETNS,
            &[Holder {
                pid,
                start,
                role: MONITOR_ROLE.into(),
            }],
        )
    })
}

pub fn forget_record(db: &Path) -> io::Result<()> {
    with_store(db, |c, boot| {
        store::drop_scope(c, boot, store::ROOTLESS_NETNS)
    })
}

/// The pid file of the pasta of the namespace of `run`.
pub fn pasta_pid_file(run: &Path) -> PathBuf {
    run.join("rootless-netns.pasta.pid")
}

pub fn ns_path(pid: i32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/ns/net"))
}

/// Lock the use of the namespace of `run` for a setup of a container's
/// networks, until the file is dropped: between the namespace being made
/// and the bridge being in it nothing shows that it is used, and a release
/// (the cleanup of the last container of the others) would take it away.
pub fn keep(run: &Path) -> io::Result<std::fs::File> {
    let f = users_file(run)?;
    velarx_sys::flock::flock_retrying(&f, rustix::fs::FlockOperation::LockShared)?;
    Ok(f)
}

/// The lock a release holds while it looks whether the namespace is used:
/// it waits for the setups under way, then sees their bridges.  A release
/// that gave up instead would leave the namespace and its pasta to a setup
/// that fails, or to a `network create` that only looks at the routes.
/// Never taken while [`keep`] is held by the same task.
pub fn release_lock(run: &Path) -> io::Result<std::fs::File> {
    let f = users_file(run)?;
    velarx_sys::flock::flock_retrying(&f, rustix::fs::FlockOperation::LockExclusive)?;
    Ok(f)
}

pub fn users_file(run: &Path) -> io::Result<std::fs::File> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(run)?;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(run.join(USERS))
}

/// The network namespace at PATH, opened, if it is `recorded`.  The
/// descriptor is what is compared: the process may exit meanwhile, and the
/// namespace stays what it was while the descriptor is open.  A file that
/// is not a namespace (the pin of a crash, no longer a mount) or another
/// one is not it.
pub fn open_if(path: &Path, recorded: &NamespaceId) -> Option<OwnedFd> {
    let fd = OwnedFd::from(std::fs::File::open(path).ok()?);
    velarx_nsid::id_of(fd.as_fd())
        .ok()
        .filter(|id| id.is_same(recorded))
        .map(|_| fd)
}

/// A way to the rootless network namespace.
pub struct Found {
    /// Where it was opened: `/proc/PID/ns/net` of the holder or of a process
    /// in it.
    pub path: PathBuf,
    /// The namespace, open: it stays the recorded one whatever happens to
    /// the path.
    pub ns: OwnedFd,
    /// Whether the holder lives and is in it; else it is gone (or not in
    /// it) and the namespace was found by other means.
    pub holder: bool,
}

/// The namespace `run` records, if something keeps it: the holder, or the
/// first of `members` (a thunk: the database is read only when the holder
/// fails) that is in it.  None when nothing does: the namespace is gone,
/// whatever the records say.  Namespaces tables that cannot be read are an
/// error.
pub fn locate(
    run: &Path,
    db: &Path,
    members: impl FnOnce() -> io::Result<Vec<i32>>,
) -> io::Result<Option<Found>> {
    let Some(rec) = read_record(db)? else {
        return Ok(None);
    };
    let holder = rec
        .holder
        .filter(|h| velarx_nsid::start_time(h.pid) == Some(h.start))
        .and_then(|h| open_if(&ns_path(h.pid), &rec.id).map(|ns| (h.pid, ns)));
    if let Some((pid, ns)) = holder {
        return Ok(Some(Found {
            path: ns_path(pid),
            ns,
            holder: true,
        }));
    }
    // (a monitor that holds it through a descriptor)
    for m in rec
        .monitors
        .iter()
        .filter(|h| velarx_nsid::start_time(h.pid) == Some(h.start))
    {
        let Some(fd) = velarx_nsid::fd_of(m.pid as u32, Kind::Net, &rec.id) else {
            continue;
        };
        let path = PathBuf::from(format!("/proc/{}/fd/{fd}", m.pid));
        if let Some(ns) = open_if(&path, &rec.id) {
            return Ok(Some(Found {
                path,
                ns,
                holder: false,
            }));
        }
    }
    // (the pasta of the namespace is in it, and keeps it for as long as it
    // runs: it is no reason for the namespace to stay; it is told by what it
    // is, a pasta started with that pid file, not by a number in a file: a
    // stale file whose pid another process has is not it)
    let pid_file = pasta_pid_file(run);
    Ok(members()?
        .into_iter()
        .filter(|p| !crate::pasta::is_pasta_of(*p, &pid_file))
        .find_map(|pid| {
            open_if(&ns_path(pid), &rec.id).map(|ns| Found {
                path: ns_path(pid),
                ns,
                holder: false,
            })
        }))
}

/// The rootless network namespace of the networks in `run` (`<run>/networks`
/// of the state directory), if something keeps it: the holder, or when it is
/// gone another process of the tree that is in the same namespace.
pub fn path_in(
    run: &Path,
    db: &Path,
    members: impl FnOnce() -> io::Result<Vec<i32>>,
) -> io::Result<Option<PathBuf>> {
    Ok(locate(run, db, members)?.map(|f| f.path))
}

/// Stop the holder and forget the namespace: it ends with the last process
/// or descriptor in it.
pub fn stop(db: &Path) {
    match read_record(db) {
        Ok(Some(Record {
            holder: Some(h), ..
        })) => {
            // (the pidfd first, then the start time: a pid that was reused has
            // another one, and the pidfd is the process it was opened for)
            let holder = velarx_sys::pidfd::open(h.pid)
                .ok()
                .filter(|_| velarx_nsid::start_time(h.pid) == Some(h.start));
            if let Some(holder) = holder {
                match rustix::process::pidfd_send_signal(&holder, rustix::process::Signal::TERM) {
                    Ok(()) => {
                        // (it stops its pasta before it ends: wait for it
                        // while the caller holds the locks, else a holder
                        // and a pasta started next would be its late work's
                        // to stop; the bound is the poll's timeout)
                        if !crate::pasta::wait_exit(&holder, std::time::Duration::from_secs(10)) {
                            tracing::warn!("the holder of the network namespace does not end");
                        }
                    }
                    Err(rustix::io::Errno::SRCH) => {}
                    Err(e) => tracing::warn!("stop the holder of the network namespace: {e}"),
                }
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("read the record of the rootless network namespace: {e}"),
    }
    if let Err(e) = forget_record(db) {
        tracing::warn!("forget the rootless network namespace: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use velarx_nsid::{Kind, NamespaceId};

    /// The store of the directory of the test.
    fn db(run: &Path) -> PathBuf {
        run.parent().unwrap().join("db.sqlite")
    }

    fn located(run: &Path, members: impl FnOnce() -> Vec<i32>) -> Option<Found> {
        locate(run, &db(run), || Ok(members())).unwrap()
    }

    #[test]
    fn a_release_waits_for_the_setups_under_way() {
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("networks");
        drop(release_lock(&run).unwrap());
        let setup = keep(&run).unwrap();
        // (a second setup of the same process is not held back by it)
        let other = keep(&run).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let r = run.clone();
        let release = std::thread::spawn(move || {
            let lock = release_lock(&r).unwrap();
            tx.send(()).unwrap();
            lock
        });
        drop(other);
        // (an upper bound for a lock that must not come)
        let early = rx.recv_timeout(std::time::Duration::from_millis(200));
        assert!(early.is_err(), "the release overtook a setup");
        drop(setup);
        rx.recv().unwrap();
        let held = release.join().unwrap();
        // and a setup waits for the release
        let f = users_file(&run).unwrap();
        assert!(rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockShared).is_err());
        // (let go of before it is closed: a program another test starts
        // holds a copy of the descriptor, and the lock, until it is executed)
        rustix::fs::flock(&held, rustix::fs::FlockOperation::Unlock).unwrap();
        drop(held);
        assert!(rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockShared).is_ok());
    }

    fn mine() -> NamespaceId {
        let f = std::fs::File::open("/proc/self/ns/net").unwrap();
        velarx_nsid::id_of(f.as_fd()).unwrap()
    }

    fn write(run: &Path, pid: i32, start: u64, id: &NamespaceId) {
        write_record(
            &db(run),
            id,
            &Holder {
                pid,
                start,
                role: crate::rootless_netns::ROLE.into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn the_record_keeps_the_identity_of_the_namespace_and_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let run = &networks(&dir);
        assert!(read_record(&db(run)).unwrap().is_none());
        let id = mine();
        write(run, 42, 7, &id);
        let rec = read_record(&db(run)).unwrap().unwrap();
        assert!(rec.id.is_same(&id));
        let h = rec.holder.unwrap();
        assert_eq!((h.pid, h.start, h.role.as_str()), (42, 7, ROLE));
        // the next holder replaces the last
        write(run, 43, 8, &id);
        assert_eq!(
            read_record(&db(run)).unwrap().unwrap().holder.unwrap().pid,
            43
        );
        // the scope is its own: the tree's records are not touched
        with_store(&db(run), |c, boot| {
            store::store(c, boot, store::TREE, Kind::User, &mine())
        })
        .unwrap();
        forget_record(&db(run)).unwrap();
        assert!(read_record(&db(run)).unwrap().is_none());
        let tree_user = with_store(&db(run), |c, boot| store::load(c, boot, store::TREE)).unwrap();
        assert!(tree_user.namespace(Kind::User).is_some());
    }

    #[test]
    fn the_namespace_is_the_holder_s_while_it_lives() {
        let dir = tempfile::tempdir().unwrap();
        let run = &networks(&dir);
        let me = std::process::id() as i32;
        let start = velarx_nsid::start_time(me).unwrap();
        assert!(located(run, Vec::new).is_none(), "no holder yet");
        write(run, me, start, &mine());
        let found = located(run, Vec::new).unwrap();
        assert!(found.holder);
        assert_eq!(found.path, PathBuf::from(format!("/proc/{me}/ns/net")));
        // the pid of another process now
        write(run, me, start + 1, &mine());
        assert!(located(run, Vec::new).is_none());
        write(run, i32::MAX, 1, &mine());
        assert!(located(run, Vec::new).is_none());
        forget_record(&db(run)).unwrap();
        assert!(located(run, || vec![me]).is_none());
    }

    /// The pasta of the namespace is no member that keeps it, told by what
    /// it is: a pid file that names a process that is not a pasta (a pid
    /// reused) does not hide that process.
    #[test]
    fn a_stale_pid_file_does_not_hide_a_member() {
        let dir = tempfile::tempdir().unwrap();
        let run = &networks(&dir);
        let me = std::process::id() as i32;
        write(run, i32::MAX, 1, &mine());
        std::fs::write(pasta_pid_file(run), me.to_string()).unwrap();
        let found = located(run, || vec![me]).unwrap();
        assert!(!found.holder);
        assert_eq!(found.path, PathBuf::from(format!("/proc/{me}/ns/net")));
    }

    /// The members are read when nothing else keeps the namespace: a
    /// database that cannot be read is the error of the lookup, not "gone".
    #[test]
    fn a_database_that_cannot_be_read_is_an_error_of_the_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let run = &networks(&dir);
        write(run, i32::MAX, 1, &mine());
        let e = locate(run, &db(run), || Err(io::Error::other("unreadable")))
            .err()
            .unwrap();
        assert!(e.to_string().contains("unreadable"), "{e}");
    }

    #[test]
    fn a_namespace_whose_holder_died_is_found_through_a_process_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let run = &networks(&dir);
        let me = std::process::id() as i32;
        // the holder is gone; this process is in the namespace it made
        write(run, i32::MAX, 1, &mine());
        let found = located(run, || vec![i32::MAX - 1, me]).unwrap();
        assert!(!found.holder);
        assert_eq!(found.path, ns_path(me));
        // the thunk is not asked while the holder lives
        let start = velarx_nsid::start_time(me).unwrap();
        write(run, me, start, &mine());
        assert!(located(run, || unreachable!()).unwrap().holder);
        // no process in it: the namespace is gone
        write(run, i32::MAX, 1, &mine());
        assert!(located(run, || vec![i32::MAX - 1]).is_none());
        // a process in another namespace is not in it
        let mut other = mine();
        other.ino += 1;
        write(run, i32::MAX, 1, &other);
        assert!(located(run, || vec![me]).is_none(), "another namespace");
        let mut other = mine();
        if let Some(h) = other.handle.as_mut() {
            h.bytes[0] ^= 1;
            write(run, i32::MAX, 1, &other);
            assert!(located(run, || vec![me]).is_none(), "another handle");
        }
    }

    /// A monitor that holds the namespace through a descriptor keeps it when
    /// the holder is killed, and a holder started in it afterwards does not
    /// make it forget the monitor.
    #[test]
    fn a_namespace_whose_holder_was_killed_is_found_through_a_monitor_s_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let run = &networks(&dir);
        let me = std::process::id() as i32;
        let _held = std::fs::File::open("/proc/self/ns/net").unwrap();
        write(run, i32::MAX, 1, &mine());
        add_monitor_holder(&db(run), me).unwrap();
        // (no member of the tree: only the monitor's descriptor says)
        let found = located(run, Vec::new).unwrap();
        assert!(!found.holder);
        assert!(
            found.path.starts_with(format!("/proc/{me}/fd/")),
            "{:?}",
            found.path
        );
        // a new holder in the namespace: the monitor stays one of its users
        write(run, i32::MAX - 1, 1, &mine());
        let rec = read_record(&db(run)).unwrap().unwrap();
        assert_eq!(rec.monitors.len(), 1);
        assert_eq!(rec.holder.map(|h| h.pid), Some(i32::MAX - 1));
        // and lets go of it
        remove_monitor_holder(&db(run), me).unwrap();
        assert!(read_record(&db(run)).unwrap().unwrap().monitors.is_empty());
        assert!(located(run, Vec::new).is_none());
    }

    /// The networks directory of a state directory DIR.
    fn networks(dir: &tempfile::TempDir) -> PathBuf {
        let run = dir.path().join("networks");
        std::fs::create_dir_all(&run).unwrap();
        run
    }
}
