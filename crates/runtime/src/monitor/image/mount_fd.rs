// SPDX-License-Identifier: Apache-2.0
//! The root file system that the storage driver made as a detached mount
//! (`RootfsPlan::MountFd`).
//!
//! The engine passes the monitor the descriptors of the mounts of its
//! container when it starts it (`MonitorConfig::rootfs_fds`, after the
//! descriptors of the container and the fetchers), and the plan names one
//! by its place among them.  The monitor does not trust that descriptor to be
//! what the plan says: a descriptor of a directory of the host, of a mount
//! point that is attached, or of a file is not a mount that was made to be
//! attached, and `move_mount` of an attached mount would take it from where
//! it is.  So it checks the descriptor, makes a clone of the mount (the
//! driver's mount is left as it is, and what the monitor changes below is the
//! monitor's own mount), sets `nodev` and private propagation on the clone
//! while it is detached, attaches it, and looks at what came with it.  A bind
//! that the driver made with `open_tree(OPEN_TREE_CLONE)` in another mount
//! namespace is not cloned by the kernel from the monitor's: that mount (new
//! for this start and used once) gets the same attributes in place and is
//! attached itself (see `attach`); once attached it is in the monitor's
//! namespace, so the monitor clones it from there, detaches the driver's mount
//! object and attaches the clone (`own_mount`): the container runs on a mount
//! of the monitor's own, never on the object the driver made.  The driver
//! therefore makes a new mount for each answer
//! and closes every copy it holds after it has handed it over: a copy it kept
//! would pin the mount (and, for a FUSE root, its server) after the container
//! has stopped.
//! What is in the mount is the driver's, which is trusted as the OCI runtime
//! is: the checks are about the kind of the descriptor, not about its content.
//!
//! A descriptor is used once.  The plan holds for the start of the monitor
//! that got the descriptor; the monitor keeps the mount it attached for its
//! life (a restart of the container finds it mounted), and a monitor that is
//! started again gets a new descriptor from the engine or none, which is an
//! error that says so.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Mutex;

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

enum Slot {
    /// Passed and not used yet.
    Open(OwnedFd),
    /// Passed and attached.
    Used,
    /// The monitor was told of it and it was not open.
    Closed,
}

/// The descriptors the engine passed for the root file systems, by their
/// place.
pub(super) struct Held {
    slots: Mutex<Vec<Slot>>,
}

/// The descriptors of this monitor.
pub(super) static HELD: Held = Held::new();

impl Held {
    pub(super) const fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
        }
    }

    /// What the monitor found at the places the engine said it passed (a
    /// place that is not open is `None`).
    pub(super) fn keep(&self, fds: Vec<Option<OwnedFd>>) {
        *self.slots.lock().unwrap_or_else(|e| e.into_inner()) = fds
            .into_iter()
            .map(|f| f.map_or(Slot::Closed, Slot::Open))
            .collect();
    }

    /// The descriptor at `index`, once.
    fn take(&self, index: u32, what: &str) -> io::Result<OwnedFd> {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let passed = slots.len();
        let Some(slot) = slots.get_mut(index as usize) else {
            return Err(io_err(format!(
                "the plan of the {what} names the mount descriptor {index}, and the engine passed {passed} when it started this monitor: \
                 a mount-fd plan is used by the start of the monitor that got the descriptor, and the engine passes one at each start from a driver that makes it \
                 (none came: the engine was restarted since, or the driver made none); remove the container and create it again"
            )));
        };
        match std::mem::replace(slot, Slot::Used) {
            Slot::Open(fd) => Ok(fd),
            Slot::Used => Err(io_err(format!(
                "the mount descriptor {index} was attached already: a mount-fd plan is used once by each start of the monitor"
            ))),
            Slot::Closed => {
                *slot = Slot::Closed;
                Err(io_err(format!(
                    "the mount descriptor {index} that the engine passed is not open in the monitor"
                )))
            }
        }
    }
}

/// `STATX_ATTR_MOUNT_ROOT`: the file is the root of its mount.
fn is_mount_root(st: &rustix::fs::Statx) -> bool {
    st.stx_attributes_mask
        .contains(rustix::fs::StatxAttributes::MOUNT_ROOT)
        && st
            .stx_attributes
            .contains(rustix::fs::StatxAttributes::MOUNT_ROOT)
}

/// The mount table of the namespace of this thread: the one the attach is
/// made in (`/proc/self` is the main thread's, which can be another).
fn mount_table() -> io::Result<String> {
    std::fs::read_to_string("/proc/thread-self/mountinfo")
        .map_err(|e| io_err(format!("/proc/thread-self/mountinfo: {e}")))
}

/// The descriptor is a directory that is the root of a detached mount, and
/// not the host's `/` itself: the mount that `open_tree(OPEN_TREE_CLONE)`
/// or `fsmount` made, not a directory of this namespace.  Whatever passes
/// is still refused by the kernel if it is not one (`move_mount` of a mount
/// of another namespace is EINVAL), this makes the reason plain and keeps an
/// attached mount from being moved or cloned.
fn check_detached(fd: &OwnedFd) -> io::Result<()> {
    use rustix::fs::{AtFlags, FileType, StatxFlags};
    let st = rustix::fs::statx(
        fd,
        c"",
        AtFlags::EMPTY_PATH,
        StatxFlags::TYPE | StatxFlags::MNT_ID,
    )
    .map_err(|e| io_err(format!("statx: {e}")))?;
    if FileType::from_raw_mode(st.stx_mode.into()) != FileType::Directory {
        return Err(io_err(
            "it is not a directory: the root file system is the root of a mount",
        ));
    }
    if st.stx_mask & StatxFlags::MNT_ID.bits() == 0 || !is_mount_root(&st) {
        return Err(io_err(
            "it is not the root of a mount (a directory of a file system, as a descriptor of `open` gives): \
             the driver hands over a mount made with open_tree(OPEN_TREE_CLONE) or fsmount",
        ));
    }
    let table = mount_table()?;
    let id = u32::try_from(st.stx_mnt_id).map_err(|_| io_err("its mount id is too big"))?;
    if let Some(m) = velarx_base::mountinfo::parse(&table)
        .iter()
        .find(|m| m.id == id)
    {
        return Err(io_err(format!(
            "it is the mount at {} of this mount namespace, not a detached one: \
             attaching it would take that mount from where it is",
            m.point.display()
        )));
    }
    // the host's `/` itself, whatever the way it was reached
    let me = rustix::fs::fstat(fd).map_err(|e| io_err(format!("fstat: {e}")))?;
    let host = rustix::fs::stat("/").map_err(|e| io_err(format!("stat /: {e}")))?;
    if (me.st_dev, me.st_ino) == (host.st_dev, host.st_ino) {
        return Err(io_err(
            "it is a mount of the file system of the host's `/`: a container root is not the host",
        ));
    }
    Ok(())
}

/// How a held mount is attached.
pub(super) struct Way<'a> {
    /// What the mount is, for the errors: `root file system` or
    /// `image mount DESTINATION`.
    pub what: &'a str,
    /// The clone is read only: an image mount is, whatever the driver's
    /// mount was made with.
    pub read_only: bool,
    /// The container's id mapping, to put on the clone (`idmap` of the plan).
    pub idmap: Option<&'a Idmap<'a>>,
    /// The engine says that the driver measured the images of the layers and
    /// made an overlay with `verity=require` (`VerityDone::Kernel`, or
    /// `OnOpen` when a server checks the files the overlay does not): the
    /// attached mount must be that, whatever the descriptor was.
    pub kernel_verity: bool,
    /// A process that serves the mount checks the digests of the files it
    /// opens (`VerityDone::OnOpen`): the mount is not taken without it.
    pub on_open: bool,
    /// The pidfd of the process that serves the mount follows the mount's
    /// descriptor (`MountFd::server`).
    pub server: bool,
    /// The server goes to the cgroup of the monitor.
    pub in_cgroup: bool,
}

/// The mapping the monitor puts on a clone: the user namespace made from the
/// container's maps (`userns::create_userns_for_idmap`, the one of an
/// idmapped composefs image and of a `--rootfs`), made when it is needed.
pub(super) type Idmap<'a> = dyn Fn() -> io::Result<OwnedFd> + 'a;

/// Attach the mount of the descriptor `index` of this monitor at `target`
/// with the checks above; nothing is attached when one fails.
pub(super) fn attach_held(held: &Held, index: u32, target: &Path, way: &Way) -> io::Result<()> {
    let under = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", way.what));
    if way.on_open && !way.server {
        return Err(under(io_err(
            "the digests are checked by the process that serves the mount, and the engine passed none",
        )));
    }
    let fd = held.take(index, way.what).map_err(under)?;
    // (the server first: a mount whose server is gone answers nothing)
    if way.server {
        let pidfd = held.take(index + 1, way.what).map_err(under)?;
        adopt_server(pidfd, way.what, way.in_cgroup).map_err(under)?;
    }
    attach(fd, target, way).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("{}, mount descriptor {index}: {e}", way.what),
        )
    })
}

/// Take the server of a mount: put it in the cgroup of this monitor (it
/// serves the files of the container, so the container's limits and its
/// stop reach it as they reach the monitor), and say in the log when it ends.
/// A cgroup that cannot take it leaves it where it is.
fn adopt_server(pidfd: OwnedFd, what: &str, in_cgroup: bool) -> io::Result<()> {
    let pid = velarx_sys::pidfd::pid_of(&pidfd).map_err(|e| match e.raw_os_error() {
        Some(libc::ESRCH) => io_err("the server ended before the container started"),
        _ => io_err(format!("the server: {e}")),
    })?;
    let cgroup = match in_cgroup {
        true => velarx_base::cgroup::of_process(None).map_err(|e| e.to_string()),
        false => Err("the container has no cgroups".to_string()),
    };
    // (the server of a rootless container starts in the cgroup of its
    // engine, which is usually the monitor's: the write would change nothing
    // and costs the kernel a grace period)
    let placed = cgroup.and_then(|rel| {
        let dir = velarx_base::cgroup::dir(&rel);
        if velarx_base::cgroup::of_process(Some(pid)).is_ok_and(|now| now == rel) {
            return Ok(dir);
        }
        let procs = dir.join("cgroup.procs");
        std::fs::write(&procs, pid.to_string())
            .map(|()| dir)
            .map_err(|e| format!("{}: {e}", procs.display()))
    });
    match &placed {
        Ok(dir) => tracing::info!(
            "image server of the {what}: pid {pid}, in the cgroup {}",
            dir.display()
        ),
        Err(why) => tracing::info!(
            "image server of the {what}: pid {pid}, not moved to the cgroup of the monitor: {why}"
        ),
    }
    let what = what.to_string();
    std::thread::Builder::new()
        .name("image-server".into())
        .spawn(move || {
            // (a process that ended, or a pidfd that cannot be waited for)
            let _ = velarx_sys::pidfd::wait_ended(&pidfd);
            tracing::info!("image server of the {what}: pid {pid} ended");
        })
        .map(|_| ())
        .map_err(|e| io_err(format!("cannot watch the server: {e}")))
}

/// An image mount: the mount of the descriptor `index` at `target`, or the
/// directory `subpath` of it (looked up inside the mount, and what was looked
/// up is what is mounted) with the whole mount at `staging` meanwhile.
pub(super) fn attach_volume(
    held: &Held,
    index: u32,
    (target, staging): (&Path, &Path),
    subpath: Option<&str>,
    way: &Way,
) -> io::Result<()> {
    let Some(sub) = subpath else {
        return attach_held(held, index, target, way);
    };
    attach_held(held, index, staging, way)?;
    let under = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", way.what));
    let root = crate::fsdir::open_dir(staging).map_err(under)?;
    let dir = crate::fsdir::open_dir_in_root(root.as_fd(), sub)
        .map_err(under)?
        .ok_or_else(|| under(io_err(format!("the mount has no directory {sub}"))))?;
    let tree = rustix::mount::open_tree(
        &dir,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|e| under(io_err(format!("open_tree failed: {e}"))))?;
    velarx_fuse::detach_stale(target)?;
    let made = !target.exists();
    std::fs::create_dir_all(target)?;
    rustix::mount::move_mount(
        &tree,
        "",
        rustix::fs::CWD,
        target,
        rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(|e| {
        // (the target made for a refused attach goes again, as without
        // subpath; the whole mount at `staging` is the caller's to undo)
        if made {
            let _ = std::fs::remove_dir(target);
        }
        under(io_err(format!("move_mount failed: {e}")))
    })
}

fn attach(fd: OwnedFd, target: &Path, way: &Way) -> io::Result<()> {
    use rustix::mount::{move_mount, open_tree, MoveMountFlags, OpenTreeFlags};
    check_detached(&fd)?;
    // The clone is the monitor's own mount: `nodev` (a device node of the
    // driver's tree opens nothing through it, as through the monitor's mount
    // of a composefs root or a directory) and
    // private are set on it while it is detached, before anything of it is
    // visible, and read only for an image mount.  The clone is of the whole
    // tree, so that a driver that hands over mounts below the top one is
    // seen after the attach and refused (`no_submounts`), not silently given
    // the top mount alone.  The mount of the driver is not changed when the
    // clone is made.
    //
    // A mount that `open_tree(OPEN_TREE_CLONE)` made (a driver's bind of a
    // directory) is not cloned from another mount namespace than the one it
    // was made in: the kernel remembers the origin and answers EINVAL, and the
    // monitor has a mount namespace of its own by now.  Such a descriptor is
    // new for this start and used once (above), so it is the monitor's own:
    // its mount gets the same attributes in place and is attached, and then
    // `own_mount` replaces it by a clone made here (the kernel clones it now
    // that it is in this namespace), so the container does not run on the
    // object the driver made, and may still hold.
    let mut in_place = false;
    let tree = match open_tree(
        &fd,
        "",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_RECURSIVE
            | OpenTreeFlags::AT_EMPTY_PATH,
    ) {
        Ok(tree) => tree,
        Err(rustix::io::Errno::INVAL) => {
            in_place = true;
            fd
        }
        Err(e) => return Err(io_err(format!("open_tree failed: {e}"))),
    };
    let mut attr_set = libc::MOUNT_ATTR_NODEV;
    if way.read_only {
        attr_set |= libc::MOUNT_ATTR_RDONLY;
    }
    velarx_sys::mount::setattr_fd_recursive(
        tree.as_fd(),
        &velarx_sys::mount::MountAttr {
            attr_set,
            propagation: libc::MS_PRIVATE,
            ..Default::default()
        },
    )
    .map_err(|e| {
        if in_place {
            // (a mount of another namespace that is not a detached one made
            // there: the kernel changes neither)
            io_err(format!(
                "open_tree failed: Invalid argument, and so did mount_setattr ({e}): the descriptor is not a detached mount made for this start"
            ))
        } else {
            io_err(format!("mount_setattr failed: {e}"))
        }
    })?;
    // (after the flags: a clone that is refused the mapping was never read
    // write, and it is not recursive: the kernel maps one mount)
    if let Some(userns) = way.idmap {
        idmap_clone(tree.as_fd(), userns)?;
    }
    velarx_fuse::detach_stale(target)?;
    let made = !target.exists();
    std::fs::create_dir_all(target)?;
    let attached = move_mount(
        tree.as_fd(),
        "",
        rustix::fs::CWD,
        target,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(|e| io_err(format!("move_mount failed: {e}")));
    let result = attached
        .and_then(|()| no_submounts(target))
        .and_then(|()| if in_place { own_mount(target) } else { Ok(()) })
        .and_then(|()| match way.kernel_verity {
            true => overlay_requires_verity(target),
            false => Ok(()),
        });
    if result.is_err() {
        // (nothing of the refused tree stays)
        let _ = rustix::mount::unmount(target, rustix::mount::UnmountFlags::DETACH);
        if made {
            let _ = std::fs::remove_dir(target);
        }
    }
    result
}

/// Replace the mount attached at `target` in place (the driver's own mount
/// object, made in another namespace) by a clone of it made here: now that it
/// is in this namespace the kernel clones it, and the original is detached, so
/// that the container runs on a mount of the monitor's own and the driver's
/// object (which it may still hold a descriptor of) is no mount of the
/// container's.
fn own_mount(target: &Path) -> io::Result<()> {
    use rustix::mount::{move_mount, open_tree, MoveMountFlags, OpenTreeFlags};
    let own = open_tree(
        rustix::fs::CWD,
        target,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_RECURSIVE,
    )
    .map_err(|e| io_err(format!("open_tree of the attached mount failed: {e}")))?;
    rustix::mount::unmount(target, rustix::mount::UnmountFlags::DETACH)
        .map_err(|e| io_err(format!("umount of the driver's mount failed: {e}")))?;
    move_mount(
        own.as_fd(),
        "",
        rustix::fs::CWD,
        target,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(|e| io_err(format!("move_mount of the monitor's own mount failed: {e}")))
}

/// The mount attached at `target` is an overlay that checks the fs-verity
/// digest of every file it opens (`verity=require` among the options of its
/// super block), as the engine was told the driver made it: the monitor
/// looks at the mount it attached, not at what the driver says of it.
fn overlay_requires_verity(target: &Path) -> io::Result<()> {
    use rustix::fs::{AtFlags, StatxFlags};
    let st = rustix::fs::statx(
        rustix::fs::CWD,
        target,
        AtFlags::empty(),
        StatxFlags::MNT_ID,
    )
    .map_err(|e| io_err(format!("statx {}: {e}", target.display())))?;
    let id = u32::try_from(st.stx_mnt_id).map_err(|_| io_err("its mount id is too big"))?;
    let table = mount_table()?;
    let mounts = velarx_base::mountinfo::parse(&table);
    let mount = mounts
        .iter()
        .find(|m| m.id == id)
        .ok_or_else(|| io_err(format!("{} is not in the mount table", target.display())))?;
    if mount.fs_type != "overlay" {
        return Err(io_err(format!(
            "the digests are enforced and the mount is a {}, not an overlay with verity=require",
            mount.fs_type
        )));
    }
    match mount
        .super_options
        .split(',')
        .any(|o| o == "verity=require")
    {
        true => Ok(()),
        false => Err(io_err(format!(
            "the digests are enforced and the overlay is not mounted with verity=require ({})",
            mount.super_options
        ))),
    }
}

/// The container's id mapping on the detached clone `tree`, as
/// `MOUNT_ATTR_IDMAP` of the user namespace `userns` makes (the holder of the
/// container's maps).  The kernel refuses it for a file system that does not
/// take idmapped mounts, for one that is idmapped already and for a caller
/// that is not root of the initial user namespace: the start fails, with the
/// file system and what to do, rather than running with ids the container
/// did not ask for.
fn idmap_clone(tree: std::os::fd::BorrowedFd<'_>, userns: &Idmap<'_>) -> io::Result<()> {
    let name = fs_name(tree);
    let rootless = rustix::process::geteuid().as_raw() != 0
        || crate::userns::rootless::in_user_namespace().unwrap_or(false);
    let remedy = "the storage driver must deliver the container's ids itself (an idmap of `applied`: a copy made with them) or hand over a file system that takes idmapped mounts";
    if rootless {
        return Err(io_err(format!(
            "the container's id mapping cannot be put on a mount of {name}: idmapped mounts need root in the initial user namespace, and this monitor is rootless (EPERM on a host file system); {remedy}"
        )));
    }
    let userns = userns().map_err(|e| {
        io_err(format!(
            "the user namespace of the container's id mapping for the mount of {name}: {e}"
        ))
    })?;
    crate::userns::idmap_mount(tree, userns.as_fd()).map_err(|e| {
        let why = match e.raw_os_error() {
            Some(libc::EPERM) => "the mount is idmapped already (an idmapped mount cannot be idmapped again: hand over a plain mount) or this file system refuses idmapped mounts",
            Some(libc::EINVAL) => "this file system does not take idmapped mounts (an overlay as a whole does not: map its lower layers)",
            Some(libc::ENOSYS) => "the kernel has no idmapped mounts",
            _ => "unexpected",
        };
        io_err(format!(
            "the container's id mapping cannot be put on a mount of {name}: mount_setattr(MOUNT_ATTR_IDMAP) failed ({e}): {why}; {remedy}"
        ))
    })
}

/// The name of the file system of a mount (by the magic number `fstatfs`
/// gives), or the number.
fn fs_name(fd: std::os::fd::BorrowedFd<'_>) -> String {
    let Ok(st) = rustix::fs::fstatfs(fd) else {
        return "an unknown file system".to_string();
    };
    let magic = st.f_type as u64;
    let name = match magic {
        0x5846_5342 => "xfs",
        0x0102_1994 => "tmpfs",
        0xEF53 => "ext4",
        0x9123_683E => "btrfs",
        0x794c_7630 => "overlay",
        0x6969 => "nfs",
        0x6573_5546 => "fuse",
        0xE0F5_E1E2 => "erofs",
        0xF2F5_2010 => "f2fs",
        0x2FC1_2FC1 => "zfs",
        _ => return format!("the file system with magic {magic:#x}"),
    };
    name.to_string()
}

/// The mount at `target` has no mount below it: the root of a container is
/// one mount, and a driver that hands over a tree of mounts is refused
/// instead of having the part of it the kernel carries (the top mount, or all
/// of it) decided for it.
fn no_submounts(target: &Path) -> io::Result<()> {
    use rustix::fs::{AtFlags, StatxFlags};
    let st = rustix::fs::statx(
        rustix::fs::CWD,
        target,
        AtFlags::empty(),
        StatxFlags::MNT_ID,
    )
    .map_err(|e| io_err(format!("statx {}: {e}", target.display())))?;
    let id = u32::try_from(st.stx_mnt_id).map_err(|_| io_err("its mount id is too big"))?;
    let table = mount_table()?;
    let below: Vec<String> = velarx_base::mountinfo::parse(&table)
        .into_iter()
        .filter(|m| m.parent == id && m.id != id)
        .map(|m| m.point.display().to_string())
        .collect();
    if below.is_empty() {
        return Ok(());
    }
    Err(io_err(format!(
        "the mount has mounts below it ({}): the driver hands over one mount for the root file system",
        below.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::mount::{FsMountFlags, FsOpenFlags, MountAttrFlags};
    use std::path::PathBuf;

    const ROOT: Way = Way {
        what: "root file system",
        read_only: false,
        idmap: None,
        kernel_verity: false,
        on_open: false,
        server: false,
        in_cgroup: false,
    };

    /// A detached tmpfs, as `fsmount` makes it, with a file in it.
    fn detached_tmpfs() -> OwnedFd {
        let fs = rustix::mount::fsopen("tmpfs", FsOpenFlags::FSOPEN_CLOEXEC).unwrap();
        rustix::mount::fsconfig_create(fs.as_fd()).unwrap();
        let m = rustix::mount::fsmount(
            fs.as_fd(),
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::empty(),
        )
        .unwrap();
        let d = rustix::fs::openat(
            &m,
            ".",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let f = rustix::fs::openat(
            &d,
            "marker",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        rustix::io::write(&f, b"driver").unwrap();
        m
    }

    /// A mount namespace of the test's child (and a user namespace for an
    /// unprivileged user), with a private `/`: false where the kernel does
    /// not let this user have one.
    fn private_namespace() -> bool {
        use rustix::thread::UnshareFlags;
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let root = rustix::process::geteuid().is_root();
        let flags = if root {
            UnshareFlags::NEWNS
        } else {
            UnshareFlags::NEWNS | UnshareFlags::NEWUSER
        };
        if velarx_sys::ns::unshare(flags).is_err() {
            eprintln!("SKIPPED: no mount namespace for this user");
            return false;
        }
        if !root {
            std::fs::write("/proc/self/setgroups", "deny").unwrap();
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
            std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
        }
        rustix::mount::mount_change(
            "/",
            rustix::mount::MountPropagationFlags::PRIVATE
                | rustix::mount::MountPropagationFlags::REC,
        )
        .unwrap();
        true
    }

    fn mountinfo_line(p: &Path) -> Option<String> {
        std::fs::read_to_string("/proc/self/mountinfo")
            .unwrap()
            .lines()
            .rfind(|l| l.split(' ').nth(4) == Some(p.to_str().unwrap()))
            .map(str::to_string)
    }

    fn held(fds: Vec<Option<OwnedFd>>) -> Held {
        let h = Held::new();
        h.keep(fds);
        h
    }

    /// Refused: the error says `why`, and nothing is mounted at `target` or
    /// made for it.
    fn refused(h: &Held, index: u32, d: &Path, why: &str) {
        let target = d.join(format!("never{index}/{}", why.len()));
        let e = attach_held(h, index, &target, &ROOT)
            .unwrap_err()
            .to_string();
        assert!(e.contains(why), "{e} (wanted {why:?})");
        assert!(e.contains("root file system"), "{e}");
        assert!(mountinfo_line(&target).is_none(), "{e}: mounted");
        assert!(!target.exists(), "{e}: {} was made", target.display());
    }

    #[test]
    fn a_detached_mount_is_attached_as_a_private_nodev_clone() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let target = d.path().join("rootfs");
            let fd = detached_tmpfs();
            // the descriptor is a mount of its own: a mount of a file system
            // that is not the host's
            let h = held(vec![Some(fd)]);
            attach_held(&h, 0, &target, &ROOT).unwrap();
            assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"driver");
            let line = mountinfo_line(&target).expect("mounted");
            let opts = line.split(' ').nth(5).unwrap();
            assert!(opts.contains("nodev"), "{line}");
            // the suid bit works in a container root: only `nodev`
            assert!(!opts.contains("nosuid"), "{line}");
            assert!(
                !line.contains(" shared:") && !line.contains(" master:"),
                "private: {line}"
            );
            // what is written in the root is the driver's file system
            std::fs::write(target.join("new"), "x").unwrap();
            // the descriptor is used once
            let e = attach_held(&h, 0, &target, &ROOT).unwrap_err().to_string();
            assert!(e.contains("attached already"), "{e}");
        });
    }

    /// A plain overlay, detached, as `fsmount` makes it (no `verity`).
    fn detached_overlay(lowers: [&Path; 2]) -> OwnedFd {
        let fs = rustix::mount::fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).unwrap();
        for lower in lowers {
            rustix::mount::fsconfig_set_string(fs.as_fd(), "lowerdir+", lower.to_str().unwrap())
                .unwrap();
        }
        if !rustix::process::geteuid().is_root() {
            rustix::mount::fsconfig_set_flag(fs.as_fd(), "userxattr").unwrap();
        }
        rustix::mount::fsconfig_set_flag(fs.as_fd(), "ro").unwrap();
        rustix::mount::fsconfig_create(fs.as_fd()).unwrap();
        rustix::mount::fsmount(
            fs.as_fd(),
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::empty(),
        )
        .unwrap()
    }

    /// A mount the engine was told enforces the digests (`kernel_verity`) is
    /// looked at after it is attached: one that is not an overlay with
    /// `verity=require` is refused and detached, whatever the driver said,
    /// and a mount that is not asked to be one is attached as before.
    #[test]
    fn a_mount_said_to_enforce_digests_is_looked_at_after_the_attach() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let enforced = Way {
                kernel_verity: true,
                ..ROOT
            };
            let lowers = [d.path().join("lower1"), d.path().join("lower2")];
            lowers.iter().for_each(|l| std::fs::create_dir(l).unwrap());
            let overlay = detached_overlay([&lowers[0], &lowers[1]]);
            for (fd, why) in [
                (detached_tmpfs(), "a tmpfs, not an overlay"),
                (overlay, "not mounted with verity=require"),
            ] {
                let target = d.path().join(format!("rootfs{}", why.len()));
                let e = attach_held(&held(vec![Some(fd)]), 0, &target, &enforced)
                    .unwrap_err()
                    .to_string();
                assert!(e.contains(why), "{e}");
                assert!(mountinfo_line(&target).is_none(), "{e}: still mounted");
            }
            let target = d.path().join("plain");
            attach_held(&held(vec![Some(detached_tmpfs())]), 0, &target, &ROOT).unwrap();
            assert!(mountinfo_line(&target).is_some());
        });
    }

    /// A driver that clones a shared mount (`open_tree` of a mount of a
    /// systemd host) hands over a peer of it: the monitor's clone is no peer,
    /// so what is mounted in the root of the container does not reach the
    /// driver's mount and the other way round.
    #[test]
    fn a_clone_of_a_shared_mount_is_attached_private() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let src = d.path().join("shared");
            std::fs::create_dir(&src).unwrap();
            rustix::mount::mount(
                "tmpfs",
                &src,
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None,
            )
            .unwrap();
            rustix::mount::mount_change(&src, rustix::mount::MountPropagationFlags::SHARED)
                .unwrap();
            let peer = rustix::mount::open_tree(
                rustix::fs::CWD,
                &src,
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .unwrap();
            let target = d.path().join("rootfs");
            let h = held(vec![Some(peer)]);
            attach_held(&h, 0, &target, &ROOT).unwrap();
            let group = |p: &Path| {
                mountinfo_line(p)
                    .unwrap()
                    .split(' ')
                    .find(|f| f.starts_with("shared:"))
                    .map(str::to_string)
            };
            assert!(group(&src).is_some());
            assert_eq!(group(&target), None, "{:?}", mountinfo_line(&target));
        });
    }

    #[test]
    fn the_mount_of_the_driver_keeps_its_own_attributes() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let fd = detached_tmpfs();
            // a second descriptor of the same mount, as the driver keeps one
            let mine = rustix::io::dup(&fd).unwrap();
            let h = held(vec![Some(fd)]);
            attach_held(&h, 0, &d.path().join("rootfs"), &ROOT).unwrap();
            // the driver's mount is attached by the driver at its own place
            // and has no `nodev`: the monitor set it on its clone
            let own = d.path().join("driver");
            std::fs::create_dir(&own).unwrap();
            rustix::mount::move_mount(
                &mine,
                "",
                rustix::fs::CWD,
                &own,
                rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
            .unwrap();
            let line = mountinfo_line(&own).expect("mounted");
            assert!(!line.split(' ').nth(5).unwrap().contains("nodev"), "{line}");
        });
    }

    #[test]
    fn what_is_not_a_detached_mount_is_refused_and_nothing_is_attached() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let dir = |p: &Path| {
                rustix::fs::open(
                    p,
                    rustix::fs::OFlags::PATH
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .unwrap()
            };
            std::fs::create_dir_all(d.path().join("plain/sub")).unwrap();
            // a mount point of this namespace, which `move_mount` would take
            let point = d.path().join("point");
            std::fs::create_dir(&point).unwrap();
            rustix::mount::mount(
                "tmpfs",
                &point,
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None,
            )
            .unwrap();
            std::fs::write(d.path().join("file"), "x").unwrap();
            let file = rustix::fs::open(
                d.path().join("file"),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let sock = std::os::unix::net::UnixStream::pair().unwrap().0;
            let good = detached_tmpfs();
            let h = held(vec![
                Some(dir(&d.path().join("plain"))),     // 0
                Some(dir(&d.path().join("plain/sub"))), // 1
                Some(dir(&point)),                      // 2
                Some(file),                             // 3
                Some(OwnedFd::from(sock)),              // 4
                Some(dir(Path::new("/"))),              // 5
                None,                                   // 6
                Some(
                    rustix::fs::open("/", rustix::fs::OFlags::RDONLY, rustix::fs::Mode::empty())
                        .unwrap(),
                ), // 7
                Some(good),                             // 8
            ]);
            refused(&h, 0, d.path(), "not the root of a mount");
            refused(&h, 1, d.path(), "not the root of a mount");
            refused(&h, 2, d.path(), "not a detached one");
            refused(&h, 3, d.path(), "not a directory");
            refused(&h, 4, d.path(), "not a directory");
            refused(&h, 5, d.path(), "not a detached one");
            refused(&h, 6, d.path(), "is not open in the monitor");
            refused(&h, 7, d.path(), "not a detached one");
            // the mount point is where it was
            assert!(mountinfo_line(&point).is_some());
            // an index that is not there, and the message names the remedy
            let e = attach_held(&h, 9, &d.path().join("x"), &ROOT)
                .unwrap_err()
                .to_string();
            assert!(e.contains("names the mount descriptor 9"), "{e}");
            assert!(
                e.contains("remove the container and create it again"),
                "{e}"
            );
            // the descriptor that is a detached mount is attached after the
            // refusals of the others
            attach_held(&h, 8, &d.path().join("ok"), &ROOT).unwrap();
            assert!(mountinfo_line(&d.path().join("ok")).is_some());
            let none = Held::new();
            let e = attach_held(&none, 0, &d.path().join("y"), &ROOT)
                .unwrap_err()
                .to_string();
            assert!(e.contains("the engine passed 0"), "{e}");
        });
    }

    /// A descriptor of a mount of another mount namespace that is not
    /// detached is not cloned or moved: the kernel refuses it, and the error
    /// is the monitor's.
    #[test]
    fn a_mount_of_another_namespace_is_refused() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let point = d.path().join("foreign");
            std::fs::create_dir(&point).unwrap();
            rustix::mount::mount(
                "tmpfs",
                &point,
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None,
            )
            .unwrap();
            let fd = rustix::fs::open(
                &point,
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            // a new mount namespace: the descriptor is of the one left
            velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS).unwrap();
            let h = held(vec![Some(fd)]);
            let target = d.path().join("rootfs");
            let e = attach_held(&h, 0, &target, &ROOT).unwrap_err().to_string();
            assert!(e.contains("open_tree failed"), "{e}");
            assert!(mountinfo_line(&target).is_none());
        });
    }

    #[test]
    fn a_tree_of_mounts_is_refused_and_detached_again() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let top = d.path().join("top");
            std::fs::create_dir(&top).unwrap();
            rustix::mount::mount(
                "tmpfs",
                &top,
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None,
            )
            .unwrap();
            std::fs::create_dir(top.join("sub")).unwrap();
            rustix::mount::mount(
                "tmpfs",
                top.join("sub"),
                "tmpfs",
                rustix::mount::MountFlags::empty(),
                None,
            )
            .unwrap();
            // the whole tree, detached
            let tree = rustix::mount::open_tree(
                rustix::fs::CWD,
                &top,
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::AT_RECURSIVE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .unwrap();
            let h = held(vec![Some(tree)]);
            let target = d.path().join("rootfs");
            let e = attach_held(&h, 0, &target, &ROOT).unwrap_err().to_string();
            assert!(e.contains("has mounts below it"), "{e}");
            assert!(e.contains("sub"), "{e}");
            assert!(mountinfo_line(&target).is_none(), "still mounted: {e}");
            assert!(
                !std::fs::read_to_string("/proc/self/mountinfo")
                    .unwrap()
                    .lines()
                    .any(|l| l.contains(" /rootfs ")
                        || l.split(' ')
                            .nth(4)
                            .is_some_and(|p| p.starts_with(target.to_str().unwrap()))),
                "a mount of the refused tree is left"
            );
            // the same top mount alone is attached
            let one = rustix::mount::open_tree(
                rustix::fs::CWD,
                &top,
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
            )
            .unwrap();
            let h = held(vec![Some(one)]);
            attach_held(&h, 0, &target, &ROOT).unwrap();
        });
    }

    #[test]
    fn the_host_root_is_refused_even_as_a_detached_clone() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            // (the kernel does not clone the root of the namespace of a user
            // namespace: that case is for root)
            let Ok(clone) = rustix::mount::open_tree(
                rustix::fs::CWD,
                "/",
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
            ) else {
                eprintln!("SKIPPED: no clone of / for this user");
                return;
            };
            let h = held(vec![Some(clone)]);
            refused(&h, 0, d.path(), "host's `/`");
        });
    }

    #[test]
    fn a_stale_mount_at_the_target_is_replaced() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let target: PathBuf = d.path().join("rootfs");
            let h = held(vec![Some(detached_tmpfs()), Some(detached_tmpfs())]);
            attach_held(&h, 0, &target, &ROOT).unwrap();
            std::fs::write(target.join("left"), "x").unwrap();
            attach_held(&h, 1, &target, &ROOT).unwrap();
            assert!(!target.join("left").exists());
            assert_eq!(
                velarx_base::mountinfo::stacked_at(
                    &std::fs::read_to_string("/proc/self/mountinfo").unwrap(),
                    &target
                ),
                1
            );
        });
    }

    /// A new user and mount namespace of this process, with the user it is
    /// mapped to root (the monitor of a rootless engine).
    fn own_user_namespace() -> bool {
        use rustix::thread::UnshareFlags;
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        // (a process that changed its user may not write its own maps)
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable)
            .unwrap();
        if velarx_sys::ns::unshare(UnshareFlags::NEWNS | UnshareFlags::NEWUSER).is_err() {
            eprintln!("SKIPPED: no user namespace for this user");
            return false;
        }
        std::fs::write("/proc/self/setgroups", "deny").unwrap();
        std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
        std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
        rustix::mount::mount_change(
            "/",
            rustix::mount::MountPropagationFlags::PRIVATE
                | rustix::mount::MountPropagationFlags::REC,
        )
        .unwrap();
        true
    }

    /// The rootless attach: a mount made by root (the driver of a
    /// root daemon, in the namespaces of the host) is attached by the
    /// monitor of a user in the user and mount namespace it has made for
    /// itself.  Only root can make the mount, so the test is for root.
    #[test]
    fn a_mount_made_by_root_is_attached_by_a_user_in_its_own_namespace() {
        velarx_base::testing::in_child(|| {
            if !rustix::process::geteuid().is_root() {
                eprintln!("SKIPPED: the mount is made by root");
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let user = 65534;
            std::os::unix::fs::chown(d.path(), Some(user), Some(user)).unwrap();
            let (uid, gid) = (
                rustix::process::Uid::from_raw(user),
                rustix::process::Gid::from_raw(user),
            );
            let fd = detached_tmpfs();
            rustix::thread::set_thread_res_gid(gid, gid, gid).unwrap();
            rustix::thread::set_thread_groups(&[]).unwrap();
            rustix::thread::set_thread_res_uid(uid, uid, uid).unwrap();
            if !own_user_namespace() {
                return;
            }
            let target = d.path().join("rootfs");
            let h = held(vec![Some(fd)]);
            attach_held(&h, 0, &target, &ROOT).unwrap();
            assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"driver");
            let line = mountinfo_line(&target).expect("mounted");
            assert!(line.split(' ').nth(5).unwrap().contains("nodev"), "{line}");
        });
    }

    /// A bind of a directory made by `open_tree(OPEN_TREE_CLONE)` in the
    /// mount namespace of the driver (the engine) is attached by a monitor
    /// that has a mount namespace of its own: the kernel does not clone it from
    /// there, so its attributes are set in place; an image mount is read only.
    #[test]
    fn a_bind_made_by_open_tree_in_another_mount_namespace_is_attached() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let src = d.path().join("copy");
            std::fs::create_dir(&src).unwrap();
            std::fs::write(src.join("marker"), b"driver").unwrap();
            let dir = rustix::fs::open(
                &src,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            let fd = rustix::mount::open_tree(
                &dir,
                "",
                rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                    | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
                    | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
            )
            .unwrap();
            let mnt_id = |fd: &dyn AsFd, path: &str| {
                rustix::fs::statx(
                    fd,
                    path,
                    if path.is_empty() {
                        rustix::fs::AtFlags::EMPTY_PATH
                    } else {
                        rustix::fs::AtFlags::empty()
                    },
                    rustix::fs::StatxFlags::MNT_ID,
                )
                .unwrap()
                .stx_mnt_id
            };
            let drivers = mnt_id(&fd, "");
            // the driver keeps its descriptor, as a driver that does not close it
            let kept = rustix::io::fcntl_dupfd_cloexec(&fd, 100).unwrap();
            // the monitor's own mount namespace
            velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS).unwrap();
            let way = Way {
                what: "image mount /img",
                read_only: true,
                idmap: None,
                kernel_verity: false,
                on_open: false,
                server: false,
                in_cgroup: false,
            };
            let target = d.path().join("img");
            attach_held(&held(vec![Some(fd)]), 0, &target, &way).unwrap();
            assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"driver");
            let line = mountinfo_line(&target).expect("mounted");
            let options = line.split(' ').nth(5).unwrap();
            assert!(
                options.contains("nodev") && options.starts_with("ro"),
                "{line}"
            );
            // the container's mount is not the object the driver made, which
            // is no mount of this namespace and still has its own attributes
            let attached = mnt_id(&rustix::fs::CWD, target.to_str().unwrap());
            assert_ne!(attached, drivers);
            let table = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
            assert!(!velarx_base::mountinfo::parse(&table)
                .iter()
                .any(|m| u64::from(m.id) == drivers));
            drop(kept);
            assert_eq!(
                std::fs::write(target.join("new"), b"x")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EROFS)
            );
            // the directory itself is as it was
            assert!(!src.join("new").exists());
        });
    }

    /// A mount made in the user namespace of a driver is attached by a
    /// monitor in another one (here nested in it), and by one in the same
    /// user namespace with a mount namespace of its own.
    #[test]
    fn a_mount_made_in_a_user_namespace_is_attached_from_another() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let fd = detached_tmpfs();
            let other = rustix::io::dup(&fd).unwrap();
            // the same user namespace, a mount namespace of the monitor's own
            velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS).unwrap();
            let h = held(vec![Some(fd)]);
            attach_held(&h, 0, &d.path().join("same-user-ns"), &ROOT).unwrap();
            // (the first attach took the mount: a second made by the driver)
            let again = detached_tmpfs();
            let _ = other;
            if rustix::process::geteuid().is_root() {
                return;
            }
            // nested user namespace: the id 0 of this one is the only id
            // it maps
            if !own_user_namespace() {
                return;
            }
            let h = held(vec![Some(again)]);
            attach_held(&h, 0, &d.path().join("nested"), &ROOT).unwrap();
            assert_eq!(
                std::fs::read(d.path().join("nested/marker")).unwrap(),
                b"driver"
            );
        });
    }

    /// The descriptor `fd` sent on `sock` (SCM_RIGHTS), as a driver sends it.
    fn send_fd(sock: &std::os::unix::net::UnixStream, fd: &OwnedFd) {
        use rustix::net::{sendmsg, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fds = [fd.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        let sent = sendmsg(
            sock,
            &[io::IoSlice::new(b"m")],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();
        assert_eq!(sent, 1);
    }

    /// The descriptor that came on `sock`.
    fn recv_fd(sock: &std::os::unix::net::UnixStream) -> OwnedFd {
        use rustix::net::{recvmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut byte = [0u8; 1];
        recvmsg(
            sock,
            &mut [io::IoSliceMut::new(&mut byte)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )
        .unwrap();
        control
            .drain()
            .find_map(|m| match m {
                RecvAncillaryMessage::ScmRights(mut fds) => fds.next(),
                _ => None,
            })
            .expect("a descriptor")
    }

    /// A mount made by a driver in a user namespace of its own (a process
    /// forked from the test, mapped to an unprivileged user) reaches the
    /// monitor over a socket and is attached by it: as root, by a monitor of
    /// root in the namespaces it has (a rootful engine with a driver in a
    /// user namespace); as a user, by a monitor in a user namespace that is a
    /// sibling of the driver's.
    #[test]
    fn a_mount_made_in_a_user_namespace_reaches_a_monitor_outside_it() {
        velarx_base::testing::in_child(|| {
            let root = rustix::process::geteuid().is_root();
            let (mine, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            let driver = velarx_sys::process::fork_beside_idle_threads(|_| {
                if root {
                    let user = rustix::process::Uid::from_raw(65534);
                    let group = rustix::process::Gid::from_raw(65534);
                    rustix::thread::set_thread_res_gid(group, group, group).unwrap();
                    rustix::thread::set_thread_groups(&[]).unwrap();
                    rustix::thread::set_thread_res_uid(user, user, user).unwrap();
                }
                if !own_user_namespace() {
                    return 2;
                }
                send_fd(&theirs, &detached_tmpfs());
                0
            })
            .unwrap();
            drop(theirs);
            let (_, status) = rustix::process::waitpid(
                rustix::process::Pid::from_raw(driver),
                rustix::process::WaitOptions::empty(),
            )
            .unwrap()
            .unwrap();
            if status.exit_status() == Some(2) {
                eprintln!("SKIPPED: no user namespace for the driver");
                return;
            }
            assert_eq!(status.exit_status(), Some(0), "the driver");
            let fd = recv_fd(&mine);
            // as a user, a user namespace of the monitor's own: a sibling of
            // the driver's
            let ok = if root {
                private_namespace()
            } else {
                own_user_namespace()
            };
            if !ok {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let target = d.path().join("rootfs");
            attach_held(&held(vec![Some(fd)]), 0, &target, &ROOT).unwrap();
            assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"driver");
            let line = mountinfo_line(&target).expect("mounted");
            assert!(line.split(' ').nth(5).unwrap().contains("nodev"), "{line}");
            assert!(!line.contains(" shared:"), "{line}");
        });
    }

    const VOLUME: Way = Way {
        what: "image mount /data",
        read_only: true,
        idmap: None,
        kernel_verity: false,
        on_open: false,
        server: false,
        in_cgroup: false,
    };

    fn host_ids() -> io::Result<OwnedFd> {
        crate::userns::create_userns_for_idmap(&[(0, 100_000, 65_536)], &[(0, 100_000, 65_536)])
    }

    fn owner(path: &Path) -> (u32, u32) {
        let st = rustix::fs::stat(path).unwrap();
        (st.st_uid, st.st_gid)
    }

    /// The marker of a detached tmpfs owned by 1000 (an id of the container,
    /// as the files of an image are).
    fn owned_by_1000(fd: &OwnedFd) {
        rustix::fs::chownat(
            fd,
            "marker",
            Some(rustix::fs::Uid::from_raw(1000)),
            Some(rustix::fs::Gid::from_raw(1000)),
            rustix::fs::AtFlags::empty(),
        )
        .unwrap();
    }

    /// An image mount is read only and `nodev` whatever the driver's mount
    /// was made with, and the driver's mount stays as it was.
    #[test]
    fn an_image_mount_is_read_only_even_when_the_driver_handed_it_writable() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let target = d.path().join("data");
            let fd = detached_tmpfs();
            let mine = rustix::io::dup(&fd).unwrap();
            let h = held(vec![Some(fd)]);
            attach_held(&h, 0, &target, &VOLUME).unwrap();
            assert_eq!(std::fs::read(target.join("marker")).unwrap(), b"driver");
            let line = mountinfo_line(&target).unwrap();
            let opts = line.split(' ').nth(5).unwrap();
            assert!(
                opts.split(',').any(|o| o == "ro") && opts.contains("nodev"),
                "{line}"
            );
            assert!(
                !line.contains(" shared:") && !line.contains(" master:"),
                "{line}"
            );
            let e = std::fs::write(target.join("new"), "x").unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EROFS), "{e}");
            // the driver's own mount is writable still
            rustix::fs::openat(
                &mine,
                "by-driver",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
                rustix::fs::Mode::from_raw_mode(0o644),
            )
            .unwrap();
            // (and the root file system's way does not make it read only)
            let root = detached_tmpfs();
            attach_held(&held(vec![Some(root)]), 0, &d.path().join("root"), &ROOT).unwrap();
            std::fs::write(d.path().join("root/new"), "x").unwrap();
        });
    }

    /// With `idmap` the owners of the files, the container's ids, show as the
    /// host ids of its mapping (the holder user namespace of its maps: 1000
    /// of the container is 101000 of the host, and the container's own
    /// user namespace shows it as 1000 again); without it the ids are the
    /// driver's.
    #[test]
    fn the_idmap_of_a_volume_shows_the_container_ids() {
        velarx_base::testing::in_child(|| {
            if !rustix::process::geteuid().is_root() || !private_namespace() {
                eprintln!("SKIPPED: idmapped mounts need root");
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let fd = detached_tmpfs();
            owned_by_1000(&fd);
            if crate::userns::idmap_mount(
                rustix::io::dup(&fd).unwrap().as_fd(),
                host_ids().unwrap().as_fd(),
            )
            .is_err()
            {
                eprintln!("SKIPPED: tmpfs takes no idmapped mounts here");
                return;
            }
            // (the probe idmapped the driver's mount itself: use a new one)
            let plain = detached_tmpfs();
            owned_by_1000(&plain);
            let map = || host_ids();
            let mapped = Way {
                idmap: Some(&map),
                kernel_verity: false,
                ..VOLUME
            };
            let target = d.path().join("mapped");
            attach_held(&held(vec![Some(plain)]), 0, &target, &mapped).unwrap();
            assert_eq!(owner(&target.join("marker")), (101_000, 101_000));
            let as_is = detached_tmpfs();
            owned_by_1000(&as_is);
            let target = d.path().join("as-is");
            attach_held(&held(vec![Some(as_is)]), 0, &target, &VOLUME).unwrap();
            assert_eq!(owner(&target.join("marker")), (1000, 1000));
        });
    }

    /// An idmapped mount cannot be idmapped again: the error says so, names
    /// the file system and the remedy, and nothing is mounted.
    #[test]
    fn a_mount_that_is_idmapped_already_is_refused_by_name() {
        velarx_base::testing::in_child(|| {
            if !rustix::process::geteuid().is_root() || !private_namespace() {
                eprintln!("SKIPPED: idmapped mounts need root");
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let fd = detached_tmpfs();
            if crate::userns::idmap_mount(fd.as_fd(), host_ids().unwrap().as_fd()).is_err() {
                eprintln!("SKIPPED: tmpfs takes no idmapped mounts here");
                return;
            }
            let map = || host_ids();
            let mapped = Way {
                idmap: Some(&map),
                kernel_verity: false,
                ..VOLUME
            };
            let target = d.path().join("twice");
            let e = attach_held(&held(vec![Some(fd)]), 0, &target, &mapped)
                .unwrap_err()
                .to_string();
            assert!(e.contains("tmpfs") && e.contains("idmapped already"), "{e}");
            assert!(e.contains("image mount /data"), "{e}");
            assert!(e.contains("storage driver must deliver"), "{e}");
            assert!(mountinfo_line(&target).is_none() && !target.exists(), "{e}");
        });
    }

    /// An overlay as a whole cannot be idmapped (EINVAL): the message says
    /// that file system does not take it.
    #[test]
    fn an_overlay_is_refused_an_idmap_with_its_reason() {
        velarx_base::testing::in_child(|| {
            if !rustix::process::geteuid().is_root() || !private_namespace() {
                eprintln!("SKIPPED: an overlay needs root here");
                return;
            }
            let d = tempfile::tempdir().unwrap();
            for n in ["a", "b"] {
                std::fs::create_dir(d.path().join(n)).unwrap();
            }
            let fs = rustix::mount::fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).unwrap();
            rustix::mount::fsconfig_set_string(
                fs.as_fd(),
                "lowerdir",
                format!(
                    "{}:{}",
                    d.path().join("a").display(),
                    d.path().join("b").display()
                ),
            )
            .unwrap();
            rustix::mount::fsconfig_create(fs.as_fd()).unwrap();
            let fd = rustix::mount::fsmount(
                fs.as_fd(),
                rustix::mount::FsMountFlags::FSMOUNT_CLOEXEC,
                MountAttrFlags::empty(),
            )
            .unwrap();
            let map = || host_ids();
            let mapped = Way {
                idmap: Some(&map),
                kernel_verity: false,
                ..VOLUME
            };
            let target = d.path().join("ov");
            let e = attach_held(&held(vec![Some(fd)]), 0, &target, &mapped)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("overlay") && e.contains("does not take idmapped mounts"),
                "{e}"
            );
            assert!(mountinfo_line(&target).is_none(), "{e}");
        });
    }

    /// A rootless monitor cannot idmap a host file system: refused up front,
    /// naming the file system and what the driver can do instead.
    #[test]
    fn a_rootless_monitor_is_refused_an_idmap_with_the_remedy() {
        velarx_base::testing::in_child(|| {
            if rustix::process::geteuid().is_root() || !private_namespace() {
                eprintln!("SKIPPED: this is the rootless case");
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let map = || host_ids();
            let mapped = Way {
                idmap: Some(&map),
                kernel_verity: false,
                ..VOLUME
            };
            let target = d.path().join("rootless");
            let e = attach_held(&held(vec![Some(detached_tmpfs())]), 0, &target, &mapped)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("tmpfs") && e.contains("rootless") && e.contains("`applied`"),
                "{e}"
            );
            assert!(mountinfo_line(&target).is_none() && !target.exists(), "{e}");
        });
    }

    /// The directory `subpath` of the mount is what is mounted, read only,
    /// and the whole mount is at the staging place meanwhile.
    #[test]
    fn a_subpath_is_looked_up_inside_the_mount() {
        velarx_base::testing::in_child(|| {
            if !private_namespace() {
                return;
            }
            let d = tempfile::tempdir().unwrap();
            let fd = detached_tmpfs();
            let dir = rustix::fs::openat(
                &fd,
                ".",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            rustix::fs::mkdirat(&dir, "sub", rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
            let f = rustix::fs::openat(
                &dir,
                "sub/inner",
                rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE,
                rustix::fs::Mode::from_raw_mode(0o644),
            )
            .unwrap();
            rustix::io::write(&f, b"inside").unwrap();
            let (target, staging) = (d.path().join("data"), d.path().join("stage"));
            attach_volume(
                &held(vec![Some(fd)]),
                0,
                (&target, &staging),
                Some("sub"),
                &VOLUME,
            )
            .unwrap();
            assert_eq!(std::fs::read(target.join("inner")).unwrap(), b"inside");
            assert!(!target.join("marker").exists());
            let line = mountinfo_line(&target).unwrap();
            assert!(
                line.split(' ')
                    .nth(5)
                    .unwrap()
                    .split(',')
                    .any(|o| o == "ro"),
                "{line}"
            );
            let e = std::fs::write(target.join("new"), "x").unwrap_err();
            assert_eq!(e.raw_os_error(), Some(libc::EROFS));
            // a directory the mount lacks is an error that names it
            let e = attach_volume(
                &held(vec![Some(detached_tmpfs())]),
                0,
                (&d.path().join("t2"), &d.path().join("s2")),
                Some("missing"),
                &VOLUME,
            )
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("no directory missing") && e.contains("image mount /data"),
                "{e}"
            );
        });
    }
}
