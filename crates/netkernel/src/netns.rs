// SPDX-License-Identifier: Apache-2.0
//! The network namespace of a container, held by a descriptor.
//!
//! Nothing is pinned for it: not by a mount, not by a file.  The engine
//! makes the namespace and holds its descriptor while it sets the network
//! up ([`Netns`]); the monitor of the container inherits one and holds it
//! as long as the container lives, and the runtime joins it by the path of
//! that descriptor in the monitor (`velarx_nsid::path_in`).  When the last
//! descriptor and the last process in it are gone, the kernel destroys the
//! namespace and the links in it.  What is recorded is who it is (the
//! namespaces tables of the store, one scope per container,
//! [`velarx_nsid::store::container_scope`]) and which processes hold it.
//!
//! A process that holds none opens it again through a holder that lives: the
//! process of the container (`/proc/PID/ns/net`, for any process of the
//! user's tree) or, for root, the handle of the namespace
//! (`open_by_handle_at`: the kernel answers `ESTALE` to everyone else, a
//! rootless process included).  What it opens is compared with the recorded
//! identity.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use velarx_nsid::store;
use velarx_nsid::{Holder, Kind, NamespaceId};

/// A network namespace open in this process.  Cloned, it is the same
/// descriptor; the namespace is let go with the last clone.
#[derive(Clone)]
pub struct Netns(Arc<OwnedFd>);

impl Netns {
    /// A new network namespace with its loopback up, made by a thread that
    /// leaves it again (the caller and its other threads stay where they
    /// are).
    pub fn create() -> io::Result<Self> {
        std::thread::spawn(|| -> io::Result<Netns> {
            velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNET).map_err(|e| {
                io::Error::new(e.kind(), format!("create a network namespace: {e}"))
            })?;
            let mut nl = crate::netlink::Netlink::open()?;
            let lo = nl.link_index("lo")?;
            if lo > 0 {
                nl.link_up(lo)?;
            }
            Ok(Netns::from(velarx_nsid::open_file(
                "/proc/thread-self/ns/net",
            )?))
        })
        .join()
        .map_err(|_| io::Error::other("the network namespace thread panicked"))?
    }

    /// The network namespace of process `pid`.
    pub fn of_process(pid: i32) -> io::Result<Self> {
        velarx_nsid::open_of(&pid.to_string(), Kind::Net).map(Self::from)
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// The descriptor, for what is passed on (the monitor).
    pub fn shared(&self) -> Arc<OwnedFd> {
        self.0.clone()
    }

    /// Which namespace it is.
    pub fn id(&self) -> io::Result<NamespaceId> {
        velarx_nsid::id_of(self.0.as_fd())
    }

    /// The path that opens it in this process and in the processes it
    /// starts (the plugins of CNI, pasta): `/proc/PID/fd/N`.  Valid while
    /// this process keeps the descriptor.
    pub fn path(&self) -> PathBuf {
        PathBuf::from(velarx_nsid::path_in(std::process::id(), self.0.as_raw_fd()))
    }

    /// The number of the descriptor of process `pid` that is this namespace,
    /// if it holds one: `/proc/PID/fd/N` names the namespace for as long as
    /// that process lives.
    pub fn fd_in(&self, pid: u32) -> Option<i32> {
        let ours = std::fs::read_link(self.path()).ok()?;
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()?
            .flatten()
            .find(|e| std::fs::read_link(e.path()).is_ok_and(|l| l == ours))
            .and_then(|e| e.file_name().to_str()?.parse().ok())
    }

    /// Another descriptor of the same namespace.
    pub fn duplicate(&self) -> io::Result<OwnedFd> {
        self.0.try_clone()
    }
}

impl From<OwnedFd> for Netns {
    fn from(fd: OwnedFd) -> Self {
        Self(Arc::new(fd))
    }
}

/// The records of the namespaces of the containers: the namespaces tables
/// of the store.
#[derive(Clone, Debug)]
pub struct Records {
    db: PathBuf,
    boot_id: Option<String>,
}

impl Records {
    /// The records of the store whose database is `db`.
    pub fn new(db: &Path) -> Self {
        Self {
            db: db.to_path_buf(),
            boot_id: velarx_nsid::store::boot_id().ok(),
        }
    }

    fn with<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection, &str) -> rusqlite::Result<T>,
    ) -> io::Result<T> {
        let boot = self
            .boot_id
            .as_deref()
            .ok_or_else(|| io::Error::other("the boot id is not known"))?;
        let conn = store::open(&self.db)?;
        f(&conn, boot).map_err(io::Error::other)
    }

    /// The namespace of container `id` is `ns`; the holders it had are
    /// not its holders.
    pub fn record(&self, id: &str, ns: &NamespaceId) -> io::Result<()> {
        let scope = store::container_scope(id);
        self.with(|c, boot| {
            store::clear_holders(c, boot, &scope)?;
            store::store(c, boot, &scope, Kind::Net, ns)
        })
    }

    /// Process `pid` lives in (holds) the namespace of container `id`.
    pub fn add_holder(&self, id: &str, pid: i32, role: &str) -> io::Result<()> {
        let scope = store::container_scope(id);
        let Some(start) = velarx_nsid::start_time(pid) else {
            return Ok(());
        };
        let holder = Holder {
            pid,
            start,
            role: role.to_string(),
        };
        self.with(|c, boot| store::add_holder(c, boot, &scope, &holder))
    }

    /// What is recorded of the namespace of container `id`.
    pub fn load(&self, id: &str) -> io::Result<velarx_nsid::Stored> {
        let scope = store::container_scope(id);
        self.with(|c, boot| store::load(c, boot, &scope))
    }

    /// Forget the namespace of container `id`: it is gone (or is not the
    /// container's any more).
    pub fn forget(&self, id: &str) -> io::Result<()> {
        let scope = store::container_scope(id);
        self.with(|c, boot| store::drop_scope(c, boot, &scope))
    }

    /// Whether a namespace of container `id` is recorded.
    pub fn exists(&self, id: &str) -> bool {
        self.load(id)
            .is_ok_and(|s| s.namespace(Kind::Net).is_some())
    }

    /// The namespace of container `id`, opened again: through a holder
    /// that lives (a process of the container, or the monitor, which
    /// holds a descriptor for root), else by its handle (root).  `None`
    /// when nothing the record names is there any more.
    pub fn open(&self, id: &str, pids: &[i32]) -> Option<Netns> {
        let stored = self.load(id).ok()?;
        let recorded = stored.namespace(Kind::Net)?;
        let live = |h: &Holder| velarx_nsid::start_time(h.pid) == Some(h.start);
        let is_it = |fd: OwnedFd| {
            velarx_nsid::id_of(fd.as_fd())
                .ok()
                .filter(|got| got.is_same(recorded))
                .map(|_| Netns::from(fd))
        };
        // (the holders first: a process that lives in it is not asked of the
        // kernel's rules, which say no to a rootless process)
        let holders = stored.holders.iter().filter(|h| live(h)).map(|h| h.pid);
        holders
            .chain(pids.iter().copied())
            .find_map(|pid| {
                velarx_nsid::open_of(&pid.to_string(), Kind::Net)
                    .ok()
                    .and_then(is_it)
            })
            .or_else(|| velarx_nsid::open(recorded).ok().and_then(is_it))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine() -> NamespaceId {
        velarx_nsid::own(Kind::Net).unwrap()
    }

    /// A new namespace is its own, with its descriptor named by a path that
    /// opens it in this process, and it lasts as long as one clone does.
    #[test]
    fn a_new_namespace_is_held_by_its_descriptor() {
        velarx_base::testing::in_child(|| {
            // (rootless, in a user namespace of its own: the child process
            // is the only one it changes)
            if !rustix::process::geteuid().is_root() {
                velarx_sys::namespace::unshare_user_mapped_to_root(
                    rustix::thread::UnshareFlags::empty(),
                )
                .unwrap();
            }
            let ns = Netns::create().unwrap();
            let id = ns.id().unwrap();
            assert!(!id.is_same(&mine()), "the namespace of the process");
            let path = ns.path();
            let opened = velarx_nsid::open_file(&path.to_string_lossy()).unwrap();
            assert!(velarx_nsid::id_of(opened.as_fd()).unwrap().is_same(&id));
            let clone = ns.clone();
            drop(ns);
            assert!(clone.path().exists());
            assert!(clone.duplicate().is_ok());
        });
    }

    #[test]
    fn the_namespace_of_a_process_is_its_own() {
        let ns = Netns::of_process(std::process::id() as i32).unwrap();
        assert!(ns.id().unwrap().is_same(&mine()));
        assert!(Netns::of_process(i32::MAX).is_err());
    }

    /// What is recorded for a container is its own: the namespace, its
    /// holders, and nothing of another container; forgetting it forgets it
    /// alone.
    #[test]
    fn a_container_has_a_record_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let records = Records::new(&dir.path().join("db.sqlite"));
        assert!(!records.exists("a"));
        records.record("a", &mine()).unwrap();
        records.record("b", &mine()).unwrap();
        let me = std::process::id() as i32;
        records.add_holder("a", me, "monitor").unwrap();
        // (no such process: no holder)
        records.add_holder("a", i32::MAX, "monitor").unwrap();
        let a = records.load("a").unwrap();
        assert!(a.namespace(Kind::Net).unwrap().is_same(&mine()));
        assert_eq!(a.holders.len(), 1);
        assert_eq!(a.holders[0].pid, me);
        assert!(records.load("b").unwrap().holders.is_empty());
        // a record replaced has no holder of the one before
        records.record("a", &mine()).unwrap();
        assert!(records.load("a").unwrap().holders.is_empty());
        records.forget("a").unwrap();
        assert!(!records.exists("a"));
        assert!(records.exists("b"));
    }

    /// The namespace of a container is opened again through a process in it,
    /// and only when it is the recorded one.
    #[test]
    fn a_recorded_namespace_opens_through_a_process_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let records = Records::new(&dir.path().join("db.sqlite"));
        let me = std::process::id() as i32;
        assert!(records.open("c", &[me]).is_none(), "nothing recorded");
        records.record("c", &mine()).unwrap();
        let ns = records.open("c", &[i32::MAX, me]).unwrap();
        assert!(ns.id().unwrap().is_same(&mine()));
        // a process in another namespace is not it
        let mut other = mine();
        other.ino += 1;
        if let Some(h) = other.handle.as_mut() {
            h.bytes[0] ^= 1;
        }
        records.record("d", &other).unwrap();
        assert!(records.open("d", &[me]).is_none());
        // (the handle of a namespace this process is in opens for any user)
        assert!(records.open("c", &[]).is_some() || mine().handle.is_none());
    }
}
