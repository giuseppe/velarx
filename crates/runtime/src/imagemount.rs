// SPDX-License-Identifier: Apache-2.0
//! The kernel mounts of a composefs image, as detached mounts: the EROFS
//! file systems of the layers, the data-only directories of the store, and
//! the overlay over them (read only for an image mount, with the upper layer
//! of the container for a root file system).  A caller attaches the result
//! where it wants it.
//!
//! Two callers use the same code: the storage driver of the engine, which
//! mounts the EROFS images of a root engine's containers and hands the
//! overlay to the monitor as a mount descriptor, and the image server, for
//! the overlay over the layers it serves by FUSE.

use crate::container::IdMapping;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use velarx_fuse::erofs_tree::Stubs;

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// A system call of a mount that failed, with the error the kernel gave
/// ([`errno`] finds it again).
#[derive(Debug)]
struct Failed {
    what: &'static str,
    errno: rustix::io::Errno,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: {}", self.what, self.errno)
    }
}

impl std::error::Error for Failed {}

fn failed(what: &'static str, errno: rustix::io::Errno) -> io::Error {
    io::Error::new(io::Error::from(errno).kind(), Failed { what, errno })
}

/// The error the kernel gave to the call of the mount that `e` says failed
/// ([`mount_erofs`], [`erofs_of_file`]).
fn errno(e: &io::Error) -> Option<rustix::io::Errno> {
    e.get_ref()?.downcast_ref::<Failed>().map(|f| f.errno)
}

/// The error the kernel gave to the call of a mount, or to the opening of
/// what it is made of ([`velarx_fuse::composefs::open_layer_image`] too),
/// that failed with `e`.
fn kernel_errno(e: &io::Error) -> Option<rustix::io::Errno> {
    e.raw_os_error()
        .map(rustix::io::Errno::from_raw_os_error)
        .or_else(|| errno(e))
        .or_else(|| velarx_fuse::composefs::open_errno(e))
}

/// Whether `e` ([`kernel_errno`]) is the process having no more descriptors
/// (`EMFILE`: its limit of open files).
pub fn out_of_descriptors(e: &io::Error) -> bool {
    kernel_errno(e) == Some(rustix::io::Errno::MFILE)
}

/// Whether `e` ([`kernel_errno`]) is the system having no more open files
/// (`ENFILE`: `fs.file-max`) or no memory for one: nothing about the image.
pub fn out_of_system_files(e: &io::Error) -> bool {
    matches!(
        kernel_errno(e),
        Some(rustix::io::Errno::NFILE | rustix::io::Errno::NOMEM)
    )
}

/// Whether `e`, the failure of [`mount_erofs`] or [`erofs_of_file`], is the
/// kernel's refusal of an open file as the source of an EROFS: a kernel
/// before Linux 7.3 takes no descriptor there (`EINVAL`, `EOPNOTSUPP`), one
/// before 6.12 mounts only a block device (`ENOTBLK`), and a file system the
/// kernel cannot read the image through is `EINVAL` or `ENODEV`.  Any other
/// failure (no memory, no descriptor, no privilege) says nothing of it.
pub fn refuses_a_file(e: &io::Error) -> bool {
    use rustix::io::Errno;
    errno(e).is_some_and(|n| {
        matches!(
            n,
            Errno::NOTBLK | Errno::INVAL | Errno::NODEV | Errno::OPNOTSUPP
        )
    })
}

/// What a kernel mount is made of: the EROFS images of the layers, each
/// mounted, the top one first, and the directories of the files of the
/// store, the data-only layers; for a container with a user namespace, with
/// its mapping on all.  The descriptors that keep the idmapped mounts are
/// `keep`.
pub struct Parts {
    pub metas: Vec<OwnedFd>,
    pub files: Vec<PathBuf>,
    keep: Vec<OwnedFd>,
}

impl Parts {
    /// The mounts of the images `metas` (the top layer first) and the open
    /// directories `data` of the objects.
    pub fn new(metas: Vec<OwnedFd>, data: Vec<OwnedFd>) -> Self {
        let files = data.iter().map(velarx_sys::fd::proc_path).collect();
        Self {
            metas,
            files,
            keep: data,
        }
    }

    /// The mapping `t` on every image and every directory of objects: the
    /// owners of the files are ids of the container.
    pub fn idmapped(&mut self, t: &velarx_fuse::IdTranslate) -> io::Result<()> {
        let userns = holder_userns(t)?;
        for meta in &self.metas {
            crate::userns::idmap_mount(meta.as_fd(), userns.as_fd())
                .map_err(|e| io_err(format!("idmapping the image: {e}")))?;
        }
        for dir in self.files.iter_mut() {
            let fd = crate::userns::create_idmapped_mount_fd(dir, userns.as_fd())
                .map_err(|e| io_err(format!("idmapping the files of {}: {e}", dir.display())))?;
            *dir = velarx_sys::fd::proc_path(&fd);
            self.keep.push(fd);
        }
        Ok(())
    }

    /// The paths the overlay names the images by.
    pub fn meta_paths(&self) -> Vec<String> {
        self.metas
            .iter()
            .map(|f| velarx_sys::fd::proc_str(&f))
            .collect()
    }

    /// The paths the overlay names the data-only layers by.
    pub fn data_paths(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    }
}

/// The user namespace that holds the container's id mapping, for
/// `MOUNT_ATTR_IDMAP` (the container's own does not exist before its
/// runtime makes it).
pub fn holder_userns(t: &velarx_fuse::IdTranslate) -> io::Result<OwnedFd> {
    let tuples = |maps: &[IdMapping]| -> Vec<(u32, u32, u32)> {
        maps.iter()
            .map(|m| (m.container_id, m.host_id, m.size))
            .collect()
    };
    crate::userns::create_userns_for_idmap(&tuples(&t.uid), &tuples(&t.gid))
}

/// How the kernel is told which file is the EROFS image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErofsSource {
    /// The open file itself is the `source` (`FSCONFIG_SET_FD`, Linux 7.3):
    /// the kernel keeps that open file for as long as the file system
    /// exists, so the lock the image holds
    /// ([`velarx_fuse::composefs::open_layer_image`]) is held by the mount
    /// and the collection finds the layer in use.
    Descriptor,
    /// The name of the open file in `/proc/self/fd` is the `source` (any
    /// kernel that mounts an EROFS from a file, Linux 6.12): the kernel
    /// resolves it to the inode of that file and no other, and opens the
    /// image itself.  That open takes no lock: only the rows of the container
    /// tell the collection the layer is used.  The mount keeps its own reference to the file,
    /// so it works until it is unmounted even if the image is removed.
    ProcPath,
}

/// The EROFS image `image`, mounted read only and detached; with `share`
/// the mounts of the same image share one superblock (`erofs_of_file`).
pub fn mount_erofs(image: &std::fs::File, source: ErofsSource, share: bool) -> io::Result<OwnedFd> {
    use rustix::mount::{fsmount, FsMountFlags, MountAttrFlags};
    let erofs = erofs_of_file(image, source, share)?;
    fsmount(
        erofs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY,
    )
    .map_err(|e| failed("fsmount(erofs)", e))
}

/// The EROFS file system of the open image `image`, not yet mounted, with
/// the source given as `source` says.  A kernel that does not take it
/// refuses the call ([`refuses_a_file`]).  With `share` (the feature
/// `erofs-superblock-share`; a kernel without it refuses the option) the
/// mounts of the same image with the same options are one superblock, which
/// keeps the first open file (and its lock) until the last of them is
/// unmounted.
pub fn erofs_of_file(
    image: &std::fs::File,
    source: ErofsSource,
    share: bool,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::mount::{
        fsconfig_create, fsconfig_set_fd, fsconfig_set_flag, fsconfig_set_string, fsopen,
        FsOpenFlags,
    };
    let erofs =
        fsopen("erofs", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|e| failed("fsopen(erofs)", e))?;
    match source {
        ErofsSource::Descriptor => fsconfig_set_fd(erofs.as_fd(), "source", image.as_fd()),
        ErofsSource::ProcPath => {
            fsconfig_set_string(erofs.as_fd(), "source", velarx_sys::fd::proc_str(&image))
        }
    }
    .map_err(|e| failed("fsconfig(source)", e))?;
    if share {
        fsconfig_set_flag(erofs.as_fd(), "superblock_share")
            .map_err(|e| failed("fsconfig(superblock_share)", e))?;
    }
    fsconfig_create(erofs.as_fd()).map_err(|e| failed("fsconfig_create(erofs)", e))?;
    Ok(erofs)
}

/// The options of an overlay whose layers are stubs that redirect to
/// its data-only layers, which it checks with `verity` (off, on or
/// require): as root `metacopy=on` and `redirect_dir=on` make it follow
/// the stubs; with `userxattr` (a user namespace, which refuses those
/// two) it follows them without.
pub fn stub_options(verity: &str, userxattr: bool, followdata: bool) -> Vec<(&'static str, &str)> {
    let root = [("metacopy", "on"), ("redirect_dir", "on")];
    let mut options = if userxattr { Vec::new() } else { root.to_vec() };
    if userxattr && followdata {
        options.push(FOLLOWDATA);
    }
    options.push(("verity", verity));
    options
}

/// The option that makes the overlay of a user namespace follow the
/// redirect of a stub into a data-only layer from any lower layer (a
/// stock kernel does from the lowest only).
pub const FOLLOWDATA: (&str, &str) = ("redirect_dir", "followdata");

/// Whether the overlay of a user namespace needs `FOLLOWDATA`: it has a
/// data-only layer and several layers of stubs above it, which it
/// follows in every layer (`Stubs::Every`; with `Stubs::Lowest` the
/// layers above have no stubs).
pub fn needs_followdata(userxattr: bool, stubs: Stubs, lowers: usize, datas: usize) -> bool {
    userxattr && stubs == Stubs::Every && lowers > 1 && datas > 0
}

/// The error of an option the kernel refused: `FOLLOWDATA` is named,
/// with the reason, as it is the one a kernel may not know; that error
/// is `Unsupported` (the probe of the stubs takes it as the kernel's
/// answer).
pub fn option_error(key: &str, value: &str, e: rustix::io::Errno) -> io::Error {
    if (key, value) == FOLLOWDATA && e == rustix::io::Errno::INVAL {
        return io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "this image needs the overlay mount option {key}={value} (its layers are \
                 stubs that redirect into the data-only layer, which the overlay of a user \
                 namespace follows from the lowest layer only without it), which this \
                 kernel does not have: {e}"
            ),
        );
    }
    io_err(format!("fsconfig({key}) failed: {e}"))
}

/// A read-only overlay, detached: `lowers` the top one first, stubs that
/// redirect to the data-only layers `datas` (`stub_options`); with the
/// SELinux context `label`.
pub fn readonly_overlay(
    lowers: &[String],
    datas: &[String],
    verity: &str,
    userxattr: bool,
    stubs: Stubs,
    label: Option<&str>,
) -> io::Result<std::os::fd::OwnedFd> {
    use rustix::mount::{
        fsconfig_create, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, FsMountFlags,
        FsOpenFlags, MountAttrFlags,
    };
    use std::os::fd::AsFd;
    let fail = |what: &str, e: rustix::io::Errno| io_err(format!("{what} failed: {e}"));
    let fs =
        fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|e| fail("fsopen(overlay)", e))?;
    for (key, value) in lowers
        .iter()
        .map(|d| ("lowerdir+", d.as_str()))
        .chain(datas.iter().map(|d| ("datadir+", d.as_str())))
        .chain(stub_options(
            verity,
            userxattr,
            needs_followdata(userxattr, stubs, lowers.len(), datas.len()),
        ))
    {
        fsconfig_set_string(fs.as_fd(), key, value).map_err(|e| option_error(key, value, e))?;
    }
    if userxattr {
        fsconfig_set_flag(fs.as_fd(), "userxattr").map_err(|e| fail("fsconfig(userxattr)", e))?;
    }
    if let Some(label) = label {
        fsconfig_set_string(fs.as_fd(), "context", label)
            .map_err(|e| fail("fsconfig(context)", e))?;
    }
    fsconfig_set_flag(fs.as_fd(), "ro").map_err(|e| fail("fsconfig(ro)", e))?;
    fsconfig_create(fs.as_fd()).map_err(|e| fail("fsconfig_create(overlay)", e))?;
    let mounted = fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_RDONLY | MountAttrFlags::MOUNT_ATTR_NODEV,
    )
    .map_err(|e| fail("fsmount(overlay)", e))?;
    Ok(mounted)
}

/// The flags of the overlay of the root file system.
pub fn overlay_flags(userxattr: bool, volatile: bool) -> Vec<&'static str> {
    [(userxattr, "userxattr"), (volatile, "volatile")]
        .into_iter()
        .filter_map(|(on, flag)| on.then_some(flag))
        .collect()
}

/// podman's `/etc/mtab` in a root file system whose image has none: a
/// link to `/proc/mounts`, which `mount` in the container reads, owned
/// as `/etc` is.  A root without `/etc` is left as it is.
pub fn mtab_link(root: std::os::fd::BorrowedFd<'_>) -> rustix::io::Result<()> {
    use rustix::fs::{AtFlags, Gid, Mode, OFlags, ResolveFlags, Uid};
    let etc = match velarx_sys::fs::openat2_retry(
        root,
        "etc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::IN_ROOT,
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR) => return Ok(()),
        Err(e) => return Err(e),
    };
    match rustix::fs::symlinkat("/proc/mounts", &etc, "mtab") {
        Err(rustix::io::Errno::EXIST) => return Ok(()),
        r => r?,
    }
    let st = rustix::fs::fstat(&etc)?;
    let (uid, gid) = (Uid::from_raw(st.st_uid), Gid::from_raw(st.st_gid));
    match rustix::fs::chownat(
        &etc,
        "mtab",
        Some(uid),
        Some(gid),
        AtFlags::SYMLINK_NOFOLLOW,
    ) {
        // (a link of the user that may not give it away is the user's)
        Err(rustix::io::Errno::PERM) => Ok(()),
        r => r,
    }
}

/// The overlay of a container at its root file system: `lowers` the top one
/// first, with its upper layer; with `verity` (`stub_options`) the lower
/// layers are stubs that redirect to the data-only layers `datas`, else
/// plain directories.  With `volatile` the kernel does not sync the upper
/// layer: the container is thrown away.
pub struct RootOverlay<'a> {
    pub lowers: &'a [String],
    pub datas: &'a [String],
    pub upper: &'a Path,
    pub work: &'a Path,
    pub verity: Option<&'a str>,
    pub userxattr: bool,
    pub volatile: bool,
    pub stubs: Stubs,
    /// The SELinux context of every file of the overlay.
    pub label: Option<&'a str>,
}

/// The writable overlay of `o`, detached.
pub fn writable_overlay(o: &RootOverlay<'_>) -> io::Result<OwnedFd> {
    use rustix::mount::{
        fsconfig_create, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, FsMountFlags,
        FsOpenFlags, MountAttrFlags,
    };
    std::fs::create_dir_all(o.upper)?;
    std::fs::create_dir_all(o.work)?;
    // The kernel marks the work directory of a volatile overlay and
    // refuses to mount it again, after a clean unmount as well: the mark
    // goes before each mount, as containers/storage removes it.
    match velarx_base::tree::remove_dir_all(o.work.join("work/incompat/volatile")) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let fail = |what: &str, e: rustix::io::Errno| io_err(format!("{what} failed: {e}"));
    let fs_fd =
        fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).map_err(|e| fail("fsopen(overlay)", e))?;
    // The layers one by one, the top one first (a path is at most 256
    // bytes for fsconfig, and the overlay takes many); the data-only
    // layers last.
    let (upper, work) = (
        o.upper.to_string_lossy().into_owned(),
        o.work.to_string_lossy().into_owned(),
    );
    let single = o.lowers.len() == 1 && o.datas.is_empty();
    let lower_key = if single { "lowerdir" } else { "lowerdir+" };
    for (key, value) in o
        .lowers
        .iter()
        .map(|p| (lower_key, p.as_str()))
        .chain(o.datas.iter().map(|p| ("datadir+", p.as_str())))
        .chain([("upperdir", upper.as_str()), ("workdir", work.as_str())])
    {
        fsconfig_set_string(fs_fd.as_fd(), key, value)
            .map_err(|e| fail(&format!("fsconfig({key} {value})"), e))?;
    }
    let followdata = needs_followdata(o.userxattr, o.stubs, o.lowers.len(), o.datas.len());
    for (key, value) in o
        .verity
        .map(|v| stub_options(v, o.userxattr, followdata))
        .unwrap_or_default()
    {
        fsconfig_set_string(fs_fd.as_fd(), key, value).map_err(|e| option_error(key, value, e))?;
    }
    for flag in overlay_flags(o.userxattr, o.volatile) {
        fsconfig_set_flag(fs_fd.as_fd(), flag)
            .map_err(|e| fail(&format!("fsconfig({flag})"), e))?;
    }
    if let Some(label) = o.label {
        // every file of the overlay shows the label of the container
        fsconfig_set_string(fs_fd.as_fd(), "context", label)
            .map_err(|e| fail("fsconfig(context)", e))?;
    }
    fsconfig_create(fs_fd.as_fd()).map_err(|e| fail("fsconfig_create", e))?;
    fsmount(
        fs_fd.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NODEV,
    )
    .map_err(|e| fail("fsmount", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No descriptor left (`EMFILE`) is told apart from the system having
    /// none (`ENFILE`) and from what is wrong with an image, also when the
    /// opening of an image fails with it.
    #[test]
    fn no_descriptor_left_is_told_apart() {
        use rustix::io::Errno;
        let os = |e: Errno| io::Error::from_raw_os_error(e.raw_os_error());
        assert!(out_of_descriptors(&os(Errno::MFILE)));
        assert!(out_of_descriptors(&failed("fsopen(erofs)", Errno::MFILE)));
        for other in [Errno::NFILE, Errno::NOENT, Errno::INVAL, Errno::IO] {
            assert!(!out_of_descriptors(&os(other)), "{other}");
            assert!(!out_of_descriptors(&failed("fsmount", other)), "{other}");
        }
        assert!(out_of_system_files(&os(Errno::NFILE)));
        assert!(out_of_system_files(&failed("fsmount", Errno::NOMEM)));
        assert!(!out_of_system_files(&os(Errno::MFILE)));
        assert!(!out_of_system_files(&os(Errno::IO)));
        velarx_base::testing::in_child(|| {
            let dir = tempfile::tempdir().unwrap();
            let image = dir.path().join("layer.erofs");
            std::fs::write(&image, b"x").unwrap();
            // (the lowest free number is the limit: nothing more opens)
            let free = std::fs::File::open("/dev/null").unwrap();
            let limit = std::os::fd::AsRawFd::as_raw_fd(&free) as u64;
            drop(free);
            rustix::process::setrlimit(
                rustix::process::Resource::Nofile,
                rustix::process::Rlimit {
                    current: Some(limit),
                    maximum: rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum,
                },
            )
            .unwrap();
            let e = velarx_fuse::composefs::open_layer_image(&image).unwrap_err();
            assert!(out_of_descriptors(&e), "{e}");
            assert!(!out_of_system_files(&e), "{e}");
        });
    }

    /// An EROFS image of one file, `f`, in a directory of /var/tmp (not
    /// tmpfs: the kernel cannot mount an image from there); None where there
    /// is no root, no EROFS or no mkfs.erofs.
    fn image_with_a_file() -> Option<(tempfile::TempDir, PathBuf)> {
        if !rustix::process::geteuid().is_root() || erofs_unavailable() {
            eprintln!("skipped: needs root and the kernel's EROFS");
            return None;
        }
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::fs::write(tree.join("f"), b"contents").unwrap();
        let image = dir.path().join("layer.erofs");
        match std::process::Command::new("mkfs.erofs")
            .arg(&image)
            .arg(&tree)
            .output()
        {
            Ok(o) if o.status.success() => Some((dir, image)),
            _ => {
                eprintln!("skipped: no mkfs.erofs");
                None
            }
        }
    }

    fn mounted(erofs: &OwnedFd) -> OwnedFd {
        rustix::mount::fsmount(
            erofs.as_fd(),
            rustix::mount::FsMountFlags::FSMOUNT_CLOEXEC,
            rustix::mount::MountAttrFlags::MOUNT_ATTR_RDONLY,
        )
        .unwrap()
    }

    /// The contents of `f` read through the mount `root`.
    fn read_f(root: &OwnedFd) -> String {
        use std::io::Read;
        let fd = rustix::fs::openat(
            root,
            "f",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut out = String::new();
        std::fs::File::from(fd).read_to_string(&mut out).unwrap();
        out
    }

    fn exclusive_lock_of(f: &std::fs::File) -> rustix::io::Result<()> {
        rustix::fs::flock(f, rustix::fs::FlockOperation::NonBlockingLockExclusive)
    }

    /// The kernel mounts the open file, not its name, from the name of the
    /// descriptor in `/proc/self/fd`: the name is gone (renamed away,
    /// another file put in its place) when the mount is made.  The mount
    /// holds no lock of the image (so the collection does not see it), and
    /// it keeps working after the image is removed, until it is unmounted:
    /// the kernel has its own reference to the file.  As root only; the mount
    /// is detached and goes with its descriptor.
    /// (in a process of its own: a process that another test forks shares
    /// the open files, and their locks, until it runs its program)
    #[test]
    fn the_kernel_mounts_the_open_image_by_its_descriptor_name_without_a_lock() {
        velarx_base::testing::in_child(|| {
            let Some((dir, image)) = image_with_a_file() else {
                return;
            };
            let file = velarx_fuse::composefs::open_layer_image(&image).unwrap();
            let other = dir.path().join("other.erofs");
            std::fs::write(&other, b"not an image").unwrap();
            // (another open of the image, to ask its lock: the name is replaced)
            std::fs::hard_link(&image, dir.path().join("kept.erofs")).unwrap();
            let asker = std::fs::File::open(dir.path().join("kept.erofs")).unwrap();
            std::fs::rename(&other, &image).unwrap();
            let erofs = match erofs_of_file(&file, ErofsSource::ProcPath, false) {
                Ok(erofs) => erofs,
                Err(e) if refuses_a_file(&e) => {
                    return eprintln!("skipped: no file-backed EROFS: {e}")
                }
                Err(e) => panic!("{e}"),
            };
            let root = mounted(&erofs);
            assert_eq!(read_f(&root), "contents");
            // our own lock (taken by the open) goes with our descriptors; the
            // mount holds none
            drop(file);
            drop(erofs);
            assert_eq!(
                exclusive_lock_of(&asker),
                Ok(()),
                "a mount by name holds no lock"
            );
            // every name of the image is removed, the mount still reads it
            std::fs::remove_file(dir.path().join("kept.erofs")).unwrap();
            std::fs::remove_file(&image).unwrap();
            assert_eq!(read_f(&root), "contents");
        });
    }

    /// The kernel mounts the open file as the `source` itself where it takes
    /// a descriptor (Linux 7.3): the mount holds the lock of the image with
    /// every descriptor of ours closed, for as long as it exists.  A kernel
    /// that does not take it refuses the call.
    /// (in a process of its own: a process that another test forks shares
    /// the open files, and their locks, until it runs its program)
    #[test]
    fn the_kernel_mounts_the_open_image_and_keeps_its_lock_or_refuses() {
        velarx_base::testing::in_child(|| {
            let Some((dir, image)) = image_with_a_file() else {
                return;
            };
            let file = velarx_fuse::composefs::open_layer_image(&image).unwrap();
            std::fs::hard_link(&image, dir.path().join("kept.erofs")).unwrap();
            let asker = std::fs::File::open(dir.path().join("kept.erofs")).unwrap();
            let erofs = match erofs_of_file(&file, ErofsSource::Descriptor, false) {
                Ok(erofs) => erofs,
                Err(e) => {
                    assert!(refuses_a_file(&e), "{e}");
                    return eprintln!("this kernel takes no descriptor as the source: {e}");
                }
            };
            let root = mounted(&erofs);
            assert_eq!(read_f(&root), "contents");
            drop(file);
            drop(erofs);
            assert_eq!(
                exclusive_lock_of(&asker),
                Err(rustix::io::Errno::WOULDBLOCK)
            );
            drop(root);
            assert_eq!(exclusive_lock_of(&asker), Ok(()));
        });
    }

    /// Two mounts of one image with `superblock_share` are one superblock (one
    /// device), which keeps the lock of the image taken by the first open until
    /// the last of them is gone; a kernel without the option refuses it.
    /// (in a process of its own, as the tests of the lock)
    #[test]
    fn mounts_of_one_image_share_a_superblock_or_the_kernel_refuses() {
        velarx_base::testing::in_child(|| {
            let Some((dir, image)) = image_with_a_file() else {
                return;
            };
            std::fs::hard_link(&image, dir.path().join("kept.erofs")).unwrap();
            let asker = std::fs::File::open(dir.path().join("kept.erofs")).unwrap();
            let file = velarx_fuse::composefs::open_layer_image(&image).unwrap();
            let other = velarx_fuse::composefs::open_layer_image(&image).unwrap();
            let first = match mount_erofs(&file, ErofsSource::Descriptor, true) {
                Ok(first) => first,
                Err(e) if refuses_a_file(&e) => {
                    return eprintln!("skipped: no superblock_share or no descriptor source: {e}")
                }
                Err(e) => panic!("{e}"),
            };
            let second = mount_erofs(&other, ErofsSource::Descriptor, true).unwrap();
            assert_eq!(
                rustix::fs::fstat(&first).unwrap().st_dev,
                rustix::fs::fstat(&second).unwrap().st_dev
            );
            drop((file, other));
            drop(first);
            assert_eq!(read_f(&second), "contents");
            assert_eq!(
                exclusive_lock_of(&asker),
                Err(rustix::io::Errno::WOULDBLOCK)
            );
            drop(second);
            assert_eq!(exclusive_lock_of(&asker), Ok(()));
        });
    }

    fn erofs_unavailable() -> bool {
        rustix::mount::fsopen("erofs", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC).is_err()
    }

    /// As root the overlay follows the stubs with `metacopy` and
    /// `redirect_dir`, in a user namespace without; `verity` the same.
    #[test]
    fn the_options_of_an_overlay_of_stubs() {
        assert_eq!(
            stub_options("on", false, true),
            [("metacopy", "on"), ("redirect_dir", "on"), ("verity", "on")]
        );
        assert_eq!(
            stub_options("require", true, false),
            [("verity", "require")]
        );
        assert_eq!(
            stub_options("require", true, true),
            [("redirect_dir", "followdata"), ("verity", "require")]
        );
    }

    /// The option only where a user namespace has a data-only layer and
    /// several layers of stubs that the kernel follows.
    #[test]
    fn followdata_needs_a_data_layer_and_several_layers() {
        for (userxattr, stubs, lowers, datas, want) in [
            (true, Stubs::Every, 2, 1, true),
            (true, Stubs::Every, 5, 2, true),
            (true, Stubs::Every, 1, 1, false),
            (true, Stubs::Every, 3, 0, false),
            (true, Stubs::Lowest, 3, 1, false),
            (false, Stubs::Every, 3, 1, false),
        ] {
            assert_eq!(
                needs_followdata(userxattr, stubs, lowers, datas),
                want,
                "{userxattr} {stubs:?} {lowers} {datas}"
            );
        }
    }

    /// A kernel that does not know the option is told by name.
    #[test]
    fn followdata_refused_by_name() {
        let e = option_error("redirect_dir", "followdata", rustix::io::Errno::INVAL);
        assert!(e.to_string().contains("redirect_dir=followdata"), "{e}");
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        let e = option_error("verity", "on", rustix::io::Errno::INVAL);
        assert!(!e.to_string().contains("followdata"), "{e}");
        assert_ne!(e.kind(), io::ErrorKind::Unsupported);
    }

    /// Only the refusals of a file as the source of an EROFS are the kernel's
    /// answer that it mounts none; the failure of any other call, or of one
    /// that is no call of the mount, is not.
    #[test]
    fn the_refusal_of_a_file_is_told_from_other_failures() {
        use rustix::io::Errno;
        for no in [Errno::NOTBLK, Errno::INVAL, Errno::NODEV, Errno::OPNOTSUPP] {
            assert!(
                refuses_a_file(&failed("fsconfig_create(erofs)", no)),
                "{no}"
            );
        }
        for other in [
            Errno::NOMEM,
            Errno::MFILE,
            Errno::IO,
            Errno::PERM,
            Errno::NOSPC,
        ] {
            assert!(!refuses_a_file(&failed("fsopen(erofs)", other)), "{other}");
        }
        assert!(!refuses_a_file(&io::Error::other("x")));
        let e = failed("fsmount(erofs)", Errno::NOTBLK);
        assert_eq!(errno(&e), Some(Errno::NOTBLK));
        assert!(e.to_string().starts_with("fsmount(erofs) failed: "), "{e}");
    }

    /// `volatile` is only for the overlay of a container thrown away.
    #[test]
    fn the_flags_of_the_overlay_of_the_root() {
        assert_eq!(overlay_flags(false, false), Vec::<&str>::new());
        assert_eq!(overlay_flags(true, false), ["userxattr"]);
        assert_eq!(overlay_flags(false, true), ["volatile"]);
        assert_eq!(overlay_flags(true, true), ["userxattr", "volatile"]);
    }
}
