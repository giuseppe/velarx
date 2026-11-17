// SPDX-License-Identifier: Apache-2.0
//! The identity of namespaces, of any kind, and who lives in them.
//!
//! A namespace file (`/proc/PID/ns/KIND`) has a file handle
//! (`name_to_handle_at`, Linux 6.18): it carries the unique id of the
//! namespace, which an inode number does not (that one is reused).  So a
//! recorded [`NamespaceId`] tells whether a namespace is still the one that
//! was recorded, and [`open`] makes a descriptor of it from the handle
//! (`open_by_handle_at`) where the kernel lets the caller.  The processes
//! that live in the namespaces are [`Holder`]s with their start times, and
//! the [`store`] keeps both per boot in the store's database.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub mod store;
pub mod tree;

/// The kinds of namespace, named as in `/proc/PID/ns/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    User,
    Mnt,
    Net,
    Pid,
    Ipc,
    Uts,
    Cgroup,
    Time,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::User,
        Kind::Mnt,
        Kind::Net,
        Kind::Pid,
        Kind::Ipc,
        Kind::Uts,
        Kind::Cgroup,
        Kind::Time,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::User => "user",
            Kind::Mnt => "mnt",
            Kind::Net => "net",
            Kind::Pid => "pid",
            Kind::Ipc => "ipc",
            Kind::Uts => "uts",
            Kind::Cgroup => "cgroup",
            Kind::Time => "time",
        }
    }

    pub fn parse(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The namespace file of process `pid` (`self` for this one).
    pub fn file(self, pid: &str) -> String {
        format!("/proc/{pid}/ns/{}", self.name())
    }
}

/// A file handle of `name_to_handle_at` of a namespace file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub handle_type: i32,
    pub mount_id: i32,
    pub bytes: Vec<u8>,
}

/// Which namespace: the device and inode of its file, and its file handle
/// when the kernel gives one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceId {
    pub dev: u64,
    pub ino: u64,
    pub handle: Option<Handle>,
}

impl NamespaceId {
    /// Whether `other` is the same namespace.  The id of the mount that
    /// reports the handle is not compared: only the handle says which
    /// namespace it is.
    pub fn is_same(&self, other: &NamespaceId) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && match (&self.handle, &other.handle) {
                (Some(a), Some(b)) => a.handle_type == b.handle_type && a.bytes == b.bytes,
                (None, None) => true,
                _ => false,
            }
    }
}

/// A process that lives in the namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: i32,
    /// Field 22 of `/proc/PID/stat`: another process with the pid has
    /// another start time.
    pub start: u64,
    /// What it is, for whoever debugs: `monitor`, `pasta`, `engine`...
    pub role: String,
}

/// What is recorded for a boot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stored {
    pub namespaces: Vec<(Kind, NamespaceId)>,
    pub holders: Vec<Holder>,
}

impl Stored {
    pub fn namespace(&self, kind: Kind) -> Option<&NamespaceId> {
        self.namespaces
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, id)| id)
    }
}

/// Field 22 of `stat`, the time the process started (in clock ticks after
/// the boot): `stat` is `PID (COMM) STATE ...` and the name may hold
/// anything, spaces and parentheses included.
fn start_field(stat: &str) -> Option<u64> {
    let after_name = &stat[stat.rfind(')')? + 1..];
    after_name.split_whitespace().nth(19)?.parse().ok()
}

/// When process `pid` started; None when there is no such process.
pub fn start_time(pid: i32) -> Option<u64> {
    start_field(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// The handle of the namespace file `fd`; `None` on a kernel older than
/// 6.18, which has no handles of namespaces: they are told by their inode
/// only.
pub fn handle_of(fd: BorrowedFd<'_>) -> Option<Handle> {
    velarx_sys::fs::handle_of(fd).map(|h| Handle {
        handle_type: h.handle_type,
        mount_id: h.mount_id,
        bytes: h.bytes,
    })
}

/// Which namespace the file `fd` is.
pub fn id_of(fd: BorrowedFd<'_>) -> io::Result<NamespaceId> {
    let st = rustix::fs::fstat(fd)?;
    Ok(NamespaceId {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        handle: handle_of(fd),
    })
}

/// A descriptor of the namespace file at `path` (`/proc/PID/ns/KIND`, or a
/// pin of it).
pub fn open_file(path: &str) -> io::Result<OwnedFd> {
    std::fs::File::open(path).map(OwnedFd::from).map_err(|e| {
        let what = format!("open {path}: {e}");
        io::Error::new(e.kind(), what)
    })
}

/// The namespace of `kind` of process `pid` (`self` for this one).
pub fn open_of(pid: &str, kind: Kind) -> io::Result<OwnedFd> {
    open_file(&kind.file(pid))
}

/// Which namespace of `kind` this process is in.
pub fn own(kind: Kind) -> io::Result<NamespaceId> {
    id_of(open_of("self", kind)?.as_fd())
}

/// A descriptor of the namespace `id` is, made from its handle
/// (`open_by_handle_at`), whether or not a process or a file holds it open
/// now.  The kernel decides who may: root of the initial user namespace
/// and a process that is in the namespace already.  `ENOENT` when `id` has
/// no handle; `ESTALE` when the namespace is gone and also when the caller
/// may not open it (a rootless process that owns the namespace's user
/// namespace but is not in the namespace itself).  The namespace opened is
/// checked to be the one recorded.
pub fn open(id: &NamespaceId) -> io::Result<OwnedFd> {
    let h = id
        .handle
        .as_ref()
        .ok_or_else(|| io::Error::from_raw_os_error(rustix::io::Errno::NOENT.raw_os_error()))?;
    let fd = velarx_sys::fs::open_handle(
        velarx_sys::fs::NSFS_ROOT,
        &velarx_sys::fs::FileHandle {
            handle_type: h.handle_type,
            mount_id: h.mount_id,
            bytes: h.bytes.clone(),
        },
    )?;
    if id_of(fd.as_fd())?.is_same(id) {
        Ok(fd)
    } else {
        Err(io::Error::from_raw_os_error(
            rustix::io::Errno::STALE.raw_os_error(),
        ))
    }
}

/// Where the runtime process (`crun`, `runc`) of a container that
/// joins a network namespace finds it: the monitor places the descriptor
/// right after the `preserved` ones it hands to the container (3, 4, ...),
/// for the exec of the runtime only.  The spec names it as
/// [`runtime_path`], which the runtime inherits and opens.
pub fn runtime_fd(preserved: u32) -> i32 {
    3 + preserved as i32
}

/// The path of [`runtime_fd`] in the runtime process, for
/// `linux.namespaces[].path` of the OCI spec.
pub fn runtime_path(preserved: u32) -> String {
    velarx_sys::fd::proc_raw(runtime_fd(preserved))
}

/// The path with which another process opens the descriptor `raw` of
/// process `pid` (the same user's), for what must outlive the opener: a
/// `pasta` ends when the process of its `--netns` path does.
pub fn path_in(pid: u32, raw: i32) -> String {
    format!("/proc/{pid}/fd/{raw}")
}

/// The number of the descriptor of process `pid` that is the namespace `id`,
/// if it holds one: `/proc/PID/fd/N` names the namespace for as long as that
/// process lives.  Only the descriptors of a namespace of `kind` (their link
/// reads `KIND:[inode]`) are opened.
pub fn fd_of(pid: u32, kind: Kind, id: &NamespaceId) -> Option<i32> {
    let prefix = format!("{}:[", kind.name());
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()?
        .flatten()
        .filter(|e| {
            std::fs::read_link(e.path())
                .ok()
                .is_some_and(|l| l.to_string_lossy().starts_with(&prefix))
        })
        .find(|e| {
            open_file(&e.path().to_string_lossy())
                .and_then(|fd| id_of(fd.as_fd()))
                .is_ok_and(|found| found.is_same(id))
        })
        .and_then(|e| e.file_name().to_str()?.parse().ok())
}

/// Make `fd` survive the next exec of this process (clear `FD_CLOEXEC`).
pub fn inherit_on_exec(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = rustix::io::fcntl_getfd(fd)?;
    rustix::io::fcntl_setfd(fd, flags - rustix::io::FdFlags::CLOEXEC)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runtime_finds_the_namespace_after_the_preserved_descriptors() {
        assert_eq!(super::runtime_fd(0), 3);
        assert_eq!(super::runtime_fd(2), 5);
        assert_eq!(super::runtime_path(2), "/proc/self/fd/5");
        assert_eq!(super::path_in(7, 9), "/proc/7/fd/9");
    }

    #[test]
    fn a_descriptor_of_a_namespace_is_found_by_its_identity() {
        use std::os::fd::AsFd;
        let held = open_of("self", Kind::Net).unwrap();
        let id = id_of(held.as_fd()).unwrap();
        let me = std::process::id();
        let n = fd_of(me, Kind::Net, &id).expect("held by this process");
        assert!(n >= 0);
        let found = open_file(&path_in(me, n)).unwrap();
        assert!(id_of(found.as_fd()).unwrap().is_same(&id));
        // not another kind of namespace, not a process without it
        assert_eq!(fd_of(me, Kind::Mnt, &id), None);
        assert_eq!(fd_of(u32::MAX, Kind::Net, &id), None);
    }

    #[test]
    fn a_descriptor_is_inherited_once_asked() {
        use std::os::fd::AsFd;
        let fd = open_of("self", Kind::Net).unwrap();
        let cloexec = |fd: &OwnedFd| {
            rustix::io::fcntl_getfd(fd)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        };
        assert!(cloexec(&fd));
        let on = rustix::io::fcntl_dupfd_cloexec(fd.as_fd(), 0).unwrap();
        assert!(cloexec(&on));
        inherit_on_exec(on.as_fd()).unwrap();
        assert!(!cloexec(&on));
    }

    #[test]
    fn the_start_time_is_field_22_whatever_the_name_holds() {
        let stat = "123 (a) b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20";
        assert_eq!(start_field(stat), Some(99));
        assert_eq!(start_field("1 (x"), None);
        assert_eq!(start_field("1 (x) S 2"), None);
        assert_eq!(start_field("garbage"), None);
        assert!(start_time(std::process::id() as i32).is_some());
        assert_eq!(start_time(i32::MAX), None);
    }

    #[test]
    fn kinds_are_named_as_in_proc_and_parse_back() {
        for k in Kind::ALL {
            assert_eq!(Kind::parse(k.name()), Some(k));
            assert!(std::path::Path::new(&k.file("self")).exists() || k == Kind::Time);
        }
        assert_eq!(Kind::Net.file("12"), "/proc/12/ns/net");
        assert_eq!(Kind::parse("nope"), None);
    }

    fn id(ino: u64, with_handle: bool) -> NamespaceId {
        NamespaceId {
            dev: 4,
            ino,
            handle: with_handle.then(|| Handle {
                handle_type: 241,
                mount_id: 7,
                bytes: ino.to_le_bytes().to_vec(),
            }),
        }
    }

    #[test]
    fn the_same_namespace_has_the_same_handle() {
        let a = id(10, true);
        let mut b = a.clone();
        b.handle.as_mut().unwrap().mount_id = 99;
        assert!(a.is_same(&b));
        assert!(!a.is_same(&id(11, true)));
        // a reused inode number is another namespace when the handle says so
        let mut c = a.clone();
        c.handle.as_mut().unwrap().bytes[0] ^= 1;
        assert!(!a.is_same(&c));
        assert!(!a.is_same(&id(10, false)));
        assert!(id(10, false).is_same(&id(10, false)));
    }

    #[test]
    fn a_namespace_has_one_id_however_it_is_opened() {
        for kind in [Kind::User, Kind::Mnt, Kind::Net] {
            let a = id_of(open_of("self", kind).unwrap().as_fd()).unwrap();
            assert!(a.is_same(&own(kind).unwrap()));
            let pid = std::process::id();
            let b = id_of(open_of(&pid.to_string(), kind).unwrap().as_fd()).unwrap();
            assert!(a.is_same(&b));
        }
        assert!(open_of("self", Kind::Net).is_ok());
        assert!(open_file("/proc/self/ns/nope").is_err());
    }

    #[test]
    fn a_namespace_the_process_is_in_opens_from_its_handle() {
        let me = own(Kind::Net).unwrap();
        if me.handle.is_none() {
            return; // a kernel without handles of namespaces
        }
        let fd = open(&me).unwrap();
        assert!(id_of(fd.as_fd()).unwrap().is_same(&me));
        // a handle that names nothing is refused, and so is no handle
        let mut other = me.clone();
        other
            .handle
            .as_mut()
            .unwrap()
            .bytes
            .iter_mut()
            .for_each(|b| *b ^= 0xff);
        assert!(open(&other).is_err());
        let none = NamespaceId { handle: None, ..me };
        assert_eq!(open(&none).unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    /// A process that left a namespace for a new user namespace of its own
    /// (so with no privilege over the old one, root or not) cannot open the
    /// old one from its handle: `ESTALE`, as for a namespace that is gone.
    /// The namespace it is in now opens.
    #[test]
    fn a_namespace_the_process_is_not_in_does_not_open() {
        velarx_base::testing::in_child(|| {
            let before = own(Kind::Net).unwrap();
            if before.handle.is_none() {
                return; // a kernel without handles of namespaces
            }
            if velarx_sys::ns::unshare(
                rustix::thread::UnshareFlags::NEWUSER | rustix::thread::UnshareFlags::NEWNET,
            )
            .is_err()
            {
                return; // no user namespaces for this user
            }
            let e = open(&before).unwrap_err();
            assert_eq!(
                e.raw_os_error(),
                Some(rustix::io::Errno::STALE.raw_os_error()),
                "{e}"
            );
            let now = own(Kind::Net).unwrap();
            assert!(!now.is_same(&before));
            assert!(id_of(open(&now).unwrap().as_fd()).unwrap().is_same(&now));
        });
    }
}
