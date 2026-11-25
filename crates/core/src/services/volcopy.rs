// SPDX-License-Identifier: Apache-2.0
//! Copying the content of a directory of an image into a new volume
//! (copy-up) and changing the owner of a tree (`:U`).
//!
//! Both walk the tree by file descriptors, never following a symbolic link
//! and never leaving the file system of the starting directory, so that a
//! link planted in an image or in a volume cannot make them touch something
//! else.  The depth is limited.

use super::VolumeState;
use crate::container::IdMapping;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, RawMode, Stat, Timespec, Timestamps};
use rustix::io::Errno;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use tracing::debug;
use velarx_base::idmap;
use velarx_base::walk::{names, open_dir_path, Cursor, Visit, Walk};
use velarx_graph::imagecopy::{set_copied_xattr, RefusedXattrs};
pub use velarx_graph::imagecopy::{DirInfo, ImageSource};

/// Deeper trees are refused.
pub const MAX_DEPTH: usize = 512;

/// The walks of a copy and of a change of owner.
const WALK: Walk = Walk {
    max_depth: MAX_DEPTH,
    sorted: true,
    skip_gone: false,
    lenient: false,
};

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// `(uid_t)-1` means "no change" to chown: it is never an owner.
fn owner(uid: u32, gid: u32) -> io::Result<(fs::Uid, fs::Gid)> {
    if uid == u32::MAX || gid == u32::MAX {
        return Err(invalid("the owner is not a valid id".into()));
    }
    Ok((fs::Uid::from_raw(uid), fs::Gid::from_raw(gid)))
}

/// Whether an extended attribute is left behind: the ones of the overlay
/// file system belong to the mount, the label is the volume's.
fn skip_xattr(name: &OsStr) -> bool {
    let n = name.as_bytes();
    n.starts_with(b"trusted.overlay.")
        || n.starts_with(b"user.overlay.")
        || n.starts_with(b"security.selinux")
}

/// Copy the extended attributes of `from` to `to`, after the owner of `to`
/// (a chown clears `security.capability`): `imagecopy::set_copied_xattr`
/// says which failures are left out.
fn copy_xattrs(
    from: &File,
    to: &File,
    shown: &OsStr,
    refused: &mut RefusedXattrs,
) -> io::Result<()> {
    use xattr::FileExt;
    let shown = shown.to_string_lossy();
    let names = match from.list_xattr() {
        Ok(names) => names,
        // (a file system without extended attributes: none to copy)
        Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => return Ok(()),
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("the attributes of {shown} cannot be listed: {e}"),
            ))
        }
    };
    for name in names.filter(|n| !skip_xattr(n)) {
        let value = match from.get_xattr(&name) {
            Ok(Some(v)) => v,
            // (removed since it was listed)
            Ok(None) => continue,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "the attribute {} of {shown} cannot be read: {e}",
                        name.to_string_lossy()
                    ),
                ))
            }
        };
        if !set_copied_xattr(to, &name, &value, &shown)? {
            refused.add(&name, &shown);
        }
    }
    Ok(())
}

struct Copier {
    dev: u64,
    /// Turn the owners of the source (ids of the daemon) into container ids
    undo: Option<(Vec<IdMapping>, Vec<IdMapping>)>,
    /// Files with several names: where the first was written (the
    /// directories below the root of the copy, and the name), not a
    /// descriptor for each.
    links: HashMap<(u64, u64), (Vec<OsString>, OsString)>,
    /// the attributes this process may not set
    refused: RefusedXattrs,
}

fn set_times(dir: BorrowedFd<'_>, name: &OsStr, st: &Stat) -> io::Result<()> {
    let ts = Timestamps {
        last_access: Timespec {
            tv_sec: st.st_atime as _,
            tv_nsec: st.st_atime_nsec as _,
        },
        last_modification: Timespec {
            tv_sec: st.st_mtime as _,
            tv_nsec: st.st_mtime_nsec as _,
        },
    };
    fs::utimensat(dir, name, &ts, AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
}

impl Copier {
    /// The owner to give the copy of a file.
    fn owner_of(&self, st: &Stat) -> io::Result<(u32, u32)> {
        let Some((uids, gids)) = &self.undo else {
            return Ok((st.st_uid, st.st_gid));
        };
        match (
            idmap::to_container(uids, st.st_uid),
            idmap::to_container(gids, st.st_gid),
        ) {
            (Some(u), Some(g)) => Ok((u, g)),
            _ => Err(io::Error::other(format!(
                "the owner {}:{} of a file has no id in the user namespace of the container",
                st.st_uid, st.st_gid
            ))),
        }
    }

    fn set_owner(&self, dir: BorrowedFd<'_>, name: &OsStr, st: &Stat) -> io::Result<()> {
        let (uid, gid) = self.owner_of(st)?;
        let (u, g) = owner(uid, gid)?;
        fs::chownat(dir, name, Some(u), Some(g), AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
    }
}

/// The copy as a walk of the source: `dst` is the directory of the copy
/// that the walk is in.
struct CopyWalk<'c> {
    c: &'c mut Copier,
    /// the root of the copy
    root: OwnedFd,
    dst: Cursor,
}

impl Visit for CopyWalk<'_> {
    /// (the stat of the directory in the source)
    type Dir = Stat;

    fn entry(
        &mut self,
        src: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        _: &mut Stat,
    ) -> io::Result<Option<Stat>> {
        let dst = self.dst.fd();
        let kind = FileType::from_raw_mode(st.st_mode as RawMode);
        // A mount point inside the directory is not part of the image.
        // (Only directories say: an overlay shows the device of the lower
        // file system for the files it does not own.)
        if kind == FileType::Directory && st.st_dev != self.c.dev {
            return Ok(None);
        }
        let mode = Mode::from_raw_mode((st.st_mode as RawMode) & 0o7777);
        match kind {
            FileType::Directory => {
                fs::mkdirat(dst, name, Mode::from_raw_mode(0o700))?;
                self.dst.descend(name, None)?;
                return Ok(Some(*st));
            }
            FileType::RegularFile => {
                if st.st_nlink > 1 {
                    if let Some((path, first)) = self.c.links.get(&(st.st_dev, st.st_ino)) {
                        let dir = open_dir_path(self.root.as_fd(), path)?;
                        fs::linkat(&dir, first, dst, name, AtFlags::empty())?;
                        return Ok(None);
                    }
                }
                let from = fs::openat(
                    src,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
                    Mode::empty(),
                )?;
                let to = fs::openat(
                    dst,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?;
                let (from, to) = (File::from(from), File::from(to));
                velarx_storage::copy_file(&from, &to, u64::MAX, || Ok(()))?;
                self.c.set_owner(dst, name, st)?;
                fs::fchmod(&to, mode)?;
                copy_xattrs(&from, &to, name, &mut self.c.refused)?;
                set_times(dst, name, st)?;
                if st.st_nlink > 1 {
                    self.c.links.insert(
                        (st.st_dev, st.st_ino),
                        (self.dst.path(), name.to_os_string()),
                    );
                }
            }
            FileType::Symlink => {
                let target = fs::readlinkat(src, name, Vec::new())?;
                fs::symlinkat(target.as_c_str(), dst, name)?;
                self.c.set_owner(dst, name, st)?;
                set_times(dst, name, st)?;
            }
            FileType::Fifo | FileType::CharacterDevice | FileType::BlockDevice => {
                match fs::mknodat(dst, name, kind, mode, st.st_rdev as _) {
                    Ok(()) => {
                        self.c.set_owner(dst, name, st)?;
                        set_times(dst, name, st)?;
                    }
                    // Devices need privileges: they are not data.
                    Err(Errno::PERM | Errno::ACCESS) if kind != FileType::Fifo => {
                        debug!("copy-up: device {:?} skipped", name);
                    }
                    Err(e) => return Err(io::Error::from(e)),
                }
            }
            // Sockets are not content.
            _ => {}
        }
        Ok(None)
    }

    fn leave(
        &mut self,
        _: BorrowedFd<'_>,
        _: &mut Stat,
        name: &OsStr,
        src: OwnedFd,
        st: Stat,
    ) -> io::Result<()> {
        let (_, sub_dst) = self.dst.ascend()?;
        let dst = self.dst.fd();
        self.c.set_owner(dst, name, &st)?;
        let mode = Mode::from_raw_mode((st.st_mode as RawMode) & 0o7777);
        fs::fchmod(&sub_dst, mode)?;
        copy_xattrs(
            &File::from(src),
            &File::from(sub_dst.try_clone()?),
            name,
            &mut self.c.refused,
        )?;
        set_times(dst, name, &st)?;
        Ok(())
    }
}

/// Copy the content of the directory `src` into the directory `dst`, with
/// owners, modes, times and extended attributes, and without crossing file
/// systems.  Owners are those that `src` shows, or, with `undo`, the container
/// ids that the mappings (uids, gids) of an idmapped mount turn them into.
pub fn copy_tree_with(
    src: &OwnedFd,
    dst: &OwnedFd,
    undo: Option<(&[IdMapping], &[IdMapping])>,
) -> io::Result<()> {
    let st = fs::fstat(src)?;
    let mut c = Copier {
        dev: st.st_dev as u64,
        undo: undo.map(|(u, g)| (u.to_vec(), g.to_vec())),
        links: HashMap::new(),
        refused: RefusedXattrs::default(),
    };
    let mut copy = CopyWalk {
        c: &mut c,
        root: dst.try_clone()?,
        dst: Cursor::new(dst.try_clone()?)?,
    };
    let r = WALK.run(src.try_clone()?, st, &mut copy).map(|_| ());
    c.refused.report();
    r
}

#[cfg(test)]
pub fn copy_tree(src: &OwnedFd, dst: &OwnedFd) -> io::Result<()> {
    copy_tree_with(src, dst, None)
}

pub use velarx_sys::fs::read_in_root;

/// A mounted root file system.
pub struct FdSource<'a>(pub BorrowedFd<'a>);

impl ImageSource for FdSource<'_> {
    fn dir(&self, target: &str) -> io::Result<Option<DirInfo>> {
        let Some(fd) = open_dir_in_root(self.0, target)? else {
            return Ok(None);
        };
        let st = fs::fstat(&fd)?;
        Ok(Some(DirInfo {
            uid: st.st_uid,
            gid: st.st_gid,
            mode: (st.st_mode as RawMode) & 0o7777,
            empty: is_empty(fd.as_fd())?,
        }))
    }

    fn copy_into(
        &self,
        target: &str,
        dst: &OwnedFd,
        undo: Option<(&[IdMapping], &[IdMapping])>,
    ) -> io::Result<()> {
        match open_dir_in_root(self.0, target)? {
            Some(src) => copy_tree_with(&src, dst, undo),
            None => Ok(()),
        }
    }
}

/// What a volume gets from its first container.
pub struct FirstUse<'a> {
    /// the root file system of the container
    pub source: &'a dyn ImageSource,
    /// the directory of the volume
    pub volume: BorrowedFd<'a>,
    /// where the volume is mounted in the container
    pub target: &'a str,
    /// copy the content of the image directory (no `nocopy`)
    pub copy_up: bool,
    /// give the volume to this owner (ids as the volume stores them); none for
    /// a volume that is not ours to change
    pub owner: Option<(u32, u32)>,
    /// then give it the owner and the mode of the image directory (no `U`)
    pub follow_image: bool,
    /// the mappings of an idmapped mount of the volume: the ids of the volume
    /// are the ids of the container
    pub undo: Option<(&'a [IdMapping], &'a [IdMapping])>,
}

/// Copy-up and the first chown of a volume (podman `mountNamedVolume` and
/// `fixVolumePermissions`); the new state.
pub fn first_use(p: &FirstUse<'_>, mut state: VolumeState) -> io::Result<VolumeState> {
    let volume_empty = is_empty(p.volume)?;
    if state.needs_copy_up && p.copy_up {
        if let Some(src) = p.source.dir(p.target)? {
            // Never copy into a volume that has data (it may have been
            // changed from outside), nor from an empty directory.
            if volume_empty && !src.empty {
                let dst = p.volume.try_clone_to_owned()?;
                p.source.copy_into(p.target, &dst, p.undo)?;
                state.needs_copy_up = false;
                state.copied_up = true;
            }
        }
    }
    if !state.needs_chown {
        return Ok(state);
    }
    if !state.copied_up && !volume_empty {
        // Filled from outside: the owner is not ours to change.
        state.needs_chown = false;
        return Ok(state);
    }
    let Some((uid, gid)) = p.owner else {
        return Ok(state);
    };
    if state.copied_up {
        state.needs_chown = false;
    }
    state.copied_up = false;
    let (u, g) = owner(uid, gid)?;
    fs::fchown(p.volume, Some(u), Some(g))?;
    if p.follow_image {
        if let Some(dir) = p.source.dir(p.target)? {
            let (mut uid, mut gid) = (dir.uid, dir.gid);
            if let Some((uids, gids)) = p.undo {
                match (
                    idmap::to_container(uids, uid),
                    idmap::to_container(gids, gid),
                ) {
                    (Some(a), Some(b)) => (uid, gid) = (a, b),
                    _ => return Ok(state),
                }
            }
            let (u, g) = owner(uid, gid)?;
            fs::fchown(p.volume, Some(u), Some(g))?;
            fs::fchmod(p.volume, Mode::from_raw_mode(dir.mode))?;
            if uid == 0 && gid == 0 {
                // Root owns it: nothing left to change.
                state.needs_chown = false;
            }
        }
    }
    Ok(state)
}

/// The change of owner as a walk.
struct ChownWalk {
    dev: u64,
    owner: (fs::Uid, fs::Gid),
}

impl Visit for ChownWalk {
    type Dir = ();

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        _: &mut (),
    ) -> io::Result<Option<()>> {
        let is_dir = FileType::from_raw_mode(st.st_mode as RawMode) == FileType::Directory;
        if is_dir && st.st_dev != self.dev {
            return Ok(None);
        }
        let (u, g) = self.owner;
        fs::chownat(dir, name, Some(u), Some(g), AtFlags::SYMLINK_NOFOLLOW)?;
        Ok(is_dir.then_some(()))
    }
}

/// Change the owner of the directory and of everything below it, links
/// themselves and not what they point to, staying on the file system.
pub fn chown_tree(dir: &OwnedFd, uid: u32, gid: u32) -> io::Result<()> {
    let st = fs::fstat(dir)?;
    let (u, g) = owner(uid, gid)?;
    fs::fchown(dir, Some(u), Some(g))?;
    let mut chown = ChownWalk {
        dev: st.st_dev as u64,
        owner: (u, g),
    };
    // (an entry gone since the listing has no owner to change)
    Walk {
        skip_gone: true,
        lenient: false,
        ..WALK
    }
    .run(dir.try_clone()?, (), &mut chown)
}

/// Change the owner of a file or, for a directory, of everything below it;
/// a link itself and not what it points to.
pub fn chown_path(path: &std::path::Path, uid: u32, gid: u32) -> io::Result<()> {
    let st = fs::statat(fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(st.st_mode as RawMode) == FileType::Directory {
        return chown_tree(&open_dir(path)?, uid, gid);
    }
    let (u, g) = owner(uid, gid)?;
    fs::chownat(fs::CWD, path, Some(u), Some(g), AtFlags::SYMLINK_NOFOLLOW).map_err(io::Error::from)
}

pub use velarx_runtime::fsdir::{open_dir, open_dir_in_root, open_path_in_root};

/// Whether a directory has no entry.
pub fn is_empty(dir: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(names(dir)?.is_empty())
}

/// Roots of the system that `:U` refuses to give to a container: the
/// directories themselves, and everything below the ones that follow.
const CHOWN_FORBIDDEN_EXACT: &[&str] = &[
    "/", "/var", "/var/lib", "/home", "/root", "/run", "/srv", "/opt",
];
const CHOWN_FORBIDDEN_TREES: &[&str] = &[
    "/usr", "/etc", "/boot", "/proc", "/sys", "/dev", "/bin", "/sbin", "/lib", "/lib32", "/lib64",
];

/// Whether `:U` may change the owner of this absolute path.
pub fn chown_allowed(path: &std::path::Path) -> bool {
    let Some(p) = path.to_str() else {
        return false;
    };
    let p = if p.len() > 1 {
        p.trim_end_matches('/')
    } else {
        p
    };
    if CHOWN_FORBIDDEN_EXACT.contains(&p) {
        return false;
    }
    !CHOWN_FORBIDDEN_TREES
        .iter()
        .any(|t| p == *t || p.strip_prefix(t).is_some_and(|rest| rest.starts_with('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::Path;

    fn write(p: &Path, content: &str, mode: u32) {
        std::fs::write(p, content).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn test_copy_tree_preserves_content_and_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir_all(src.join("a/b/c")).unwrap();
        std::fs::create_dir(&dst).unwrap();
        write(&src.join("a/file"), "hello", 0o640);
        // not executed
        write(&src.join("a/b/exec"), "#!/bin/sh\n", 0o4755);
        write(&src.join("a/b/c/deep"), "deep", 0o600);
        std::fs::set_permissions(src.join("a/b"), std::fs::Permissions::from_mode(0o710)).unwrap();
        symlink("file", src.join("a/link")).unwrap();
        symlink("/etc/passwd", src.join("a/abs")).unwrap();
        symlink("missing", src.join("a/dangling")).unwrap();
        std::fs::hard_link(src.join("a/file"), src.join("a/b/hard")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            src.join("a/fifo"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        xattr::set(src.join("a/file"), "user.k", b"v").unwrap();
        xattr::set(src.join("a/file"), "user.overlay.skipped", b"x").unwrap();
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        File::options()
            .write(true)
            .open(src.join("a/file"))
            .unwrap()
            .set_modified(old)
            .unwrap();

        copy_tree(&open_dir(&src).unwrap(), &open_dir(&dst).unwrap()).unwrap();

        assert_eq!(
            std::fs::read_to_string(dst.join("a/file")).unwrap(),
            "hello"
        );
        let md = |p: &str| std::fs::symlink_metadata(dst.join(p)).unwrap();
        assert_eq!(md("a/file").mode() & 0o7777, 0o640);
        assert_eq!(md("a/b/exec").mode() & 0o7777, 0o4755);
        assert_eq!(md("a/b").mode() & 0o7777, 0o710);
        assert_eq!(
            std::fs::read_to_string(dst.join("a/b/c/deep")).unwrap(),
            "deep"
        );
        // Links are copied as links, not followed.
        assert_eq!(
            std::fs::read_link(dst.join("a/link")).unwrap(),
            Path::new("file")
        );
        assert_eq!(
            std::fs::read_link(dst.join("a/abs")).unwrap(),
            Path::new("/etc/passwd")
        );
        assert_eq!(
            std::fs::read_link(dst.join("a/dangling")).unwrap(),
            Path::new("missing")
        );
        // Hard links stay hard links.
        let (f, h) = (md("a/file"), md("a/b/hard"));
        assert_eq!((f.ino(), f.nlink()), (h.ino(), 2));
        assert!(md("a/fifo").file_type().is_fifo());
        assert_eq!(md("a/file").mtime(), 1_000_000_000);
        assert_eq!(
            xattr::get(dst.join("a/file"), "user.k").unwrap().as_deref(),
            Some(&b"v"[..])
        );
        assert_eq!(
            xattr::get(dst.join("a/file"), "user.overlay.skipped").unwrap(),
            None
        );
    }

    /// A file capability survives the copy of a mounted image into a volume:
    /// the attributes are set after the owner, as a chown clears it.  (In a
    /// user namespace of its own, where the capability can be set.)
    #[test]
    fn a_file_capability_survives_the_copy_of_a_tree() {
        const CAP: &[u8] = &[
            1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        velarx_base::testing::in_child(|| {
            if let Err(e) = velarx_sys::namespace::unshare_user_mapped_to_root(
                rustix::thread::UnshareFlags::empty(),
            ) {
                // (a host that allows no user namespace cannot hold the
                // capability of a file)
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                return;
            }
            let (src, dst) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let file = src.path().join("ping");
            std::fs::write(&file, "x").unwrap();
            rustix::fs::setxattr(
                &file,
                c"security.capability",
                CAP,
                rustix::fs::XattrFlags::empty(),
            )
            .unwrap();
            let want = xattr::get(&file, "security.capability").unwrap().unwrap();
            copy_tree(
                &open_dir(src.path()).unwrap(),
                &open_dir(dst.path()).unwrap(),
            )
            .unwrap();
            let got = xattr::get(dst.path().join("ping"), "security.capability").unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&want[..]),
                "the capability of the copy"
            );
        });
    }

    #[test]
    fn test_copy_tree_does_not_follow_links_out() {
        let tmp = tempfile::tempdir().unwrap();
        let (src, dst, outside) = (
            tmp.path().join("src"),
            tmp.path().join("dst"),
            tmp.path().join("outside"),
        );
        for d in [&src, &dst, &outside] {
            std::fs::create_dir(d).unwrap();
        }
        write(&outside.join("secret"), "secret", 0o600);
        symlink(&outside, src.join("dir")).unwrap();
        symlink(outside.join("secret"), src.join("file")).unwrap();
        copy_tree(&open_dir(&src).unwrap(), &open_dir(&dst).unwrap()).unwrap();
        assert!(std::fs::symlink_metadata(dst.join("dir"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(std::fs::symlink_metadata(dst.join("file"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!dst.join("secret").exists());
        // Copying into a destination that has the name already fails
        // instead of writing through whatever is there.
        write(&src.join("plain"), "x", 0o600);
        symlink(outside.join("secret"), dst.join("plain")).unwrap();
        assert!(copy_tree(&open_dir(&src).unwrap(), &open_dir(&dst).unwrap()).is_err());
        assert_eq!(
            std::fs::read_to_string(outside.join("secret")).unwrap(),
            "secret"
        );
    }

    #[test]
    fn test_copy_tree_depth_is_limited() {
        let tmp = tempfile::tempdir().unwrap();
        let (src, dst) = (tmp.path().join("src"), tmp.path().join("dst"));
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&dst).unwrap();
        // Build 520 levels with openat (a path that long would not resolve).
        let mut fd = open_dir(&src).unwrap();
        for _ in 0..520 {
            fs::mkdirat(&fd, "d", Mode::from_raw_mode(0o700)).unwrap();
            fd = velarx_base::walk::open_dir_at(fd.as_fd(), OsStr::new("d")).unwrap();
        }
        let e = copy_tree(&open_dir(&src).unwrap(), &open_dir(&dst).unwrap()).unwrap_err();
        assert!(e.to_string().contains("too deep"), "{e}");
    }

    #[test]
    fn test_chown_tree_does_not_follow_links() {
        let tmp = tempfile::tempdir().unwrap();
        let (tree, outside) = (tmp.path().join("tree"), tmp.path().join("outside"));
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        write(&tree.join("sub/f"), "x", 0o644);
        write(&outside.join("o"), "o", 0o644);
        symlink(&outside, tree.join("link")).unwrap();
        // The current owner is the only one a user may give: this checks
        // that the walk runs and reaches the files.
        let (uid, gid) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        chown_tree(&open_dir(&tree).unwrap(), uid, gid).unwrap();
        let md = std::fs::metadata(tree.join("sub/f")).unwrap();
        assert_eq!((md.uid(), md.gid()), (uid, gid));
        assert_eq!(std::fs::metadata(outside.join("o")).unwrap().uid(), uid);
        // A file refused the new owner makes the walk fail, not skip.
        if uid != 0 {
            assert!(chown_tree(&open_dir(&tree).unwrap(), uid + 1, gid).is_err());
        }
    }

    #[test]
    fn test_open_dir_in_root_stays_inside() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(root.join("data/sub")).unwrap();
        std::fs::create_dir(tmp.path().join("secret")).unwrap();
        // An absolute link resolves inside the root, `..` cannot leave it.
        symlink("/data", root.join("abs")).unwrap();
        symlink("../../secret", root.join("up")).unwrap();
        write(&root.join("data/file"), "x", 0o644);
        let fd = open_dir(&root).unwrap();
        let ino = |p: &str| {
            let d = open_dir_in_root(fd.as_fd(), p).unwrap().unwrap();
            fs::fstat(&d).unwrap().st_ino
        };
        let data = std::fs::metadata(root.join("data")).unwrap().ino();
        assert_eq!(ino("/data"), data);
        assert_eq!(ino("abs"), data);
        assert!(open_dir_in_root(fd.as_fd(), "/up").unwrap().is_none());
        assert!(open_dir_in_root(fd.as_fd(), "/data/file")
            .unwrap()
            .is_none());
        assert!(open_dir_in_root(fd.as_fd(), "/missing").unwrap().is_none());
        assert_eq!(ino("/"), std::fs::metadata(&root).unwrap().ino());
        assert_eq!(
            ino("/data/sub/../.."),
            std::fs::metadata(&root).unwrap().ino()
        );
    }

    #[test]
    fn test_first_use_copies_up_and_sets_the_owner_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (root, vol) = (tmp.path().join("root"), tmp.path().join("vol"));
        std::fs::create_dir_all(root.join("data")).unwrap();
        std::fs::create_dir(&vol).unwrap();
        write(&root.join("data/f"), "image", 0o640);
        std::fs::set_permissions(root.join("data"), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        let (r, v) = (open_dir(&root).unwrap(), open_dir(&vol).unwrap());
        let me = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let p = FirstUse {
            source: &FdSource(r.as_fd()),
            volume: v.as_fd(),
            target: "/data",
            copy_up: true,
            owner: Some(me),
            follow_image: true,
            undo: None,
        };
        let new = VolumeState {
            needs_copy_up: true,
            needs_chown: true,
            ..Default::default()
        };
        let st = first_use(&p, new.clone()).unwrap();
        assert_eq!(std::fs::read_to_string(vol.join("f")).unwrap(), "image");
        assert!(st.copied_up || !st.needs_chown, "{st:?}");
        assert!(!st.needs_copy_up);
        // the mode of the image directory
        assert_eq!(std::fs::metadata(&vol).unwrap().mode() & 0o777, 0o750);
        // A volume that has data is not copied into, and its owner is left.
        let vol2 = tmp.path().join("vol2");
        std::fs::create_dir(&vol2).unwrap();
        write(&vol2.join("mine"), "mine", 0o600);
        let v2 = open_dir(&vol2).unwrap();
        let st = first_use(
            &FirstUse {
                volume: v2.as_fd(),
                ..p
            },
            new.clone(),
        )
        .unwrap();
        assert!(!vol2.join("f").exists());
        assert!(!st.needs_chown && st.needs_copy_up);
        // nocopy
        let vol3 = tmp.path().join("vol3");
        std::fs::create_dir(&vol3).unwrap();
        let v3 = open_dir(&vol3).unwrap();
        let p3 = FirstUse {
            source: &FdSource(r.as_fd()),
            volume: v3.as_fd(),
            target: "/data",
            copy_up: false,
            owner: None,
            follow_image: false,
            undo: None,
        };
        first_use(&p3, new).unwrap();
        assert!(!vol3.join("f").exists());
        // A destination that is missing in the image copies nothing.
        let p4 = FirstUse {
            target: "/none",
            copy_up: true,
            ..p3
        };
        assert!(first_use(
            &p4,
            VolumeState {
                needs_copy_up: true,
                ..Default::default()
            }
        )
        .is_ok());
    }

    #[test]
    fn test_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let fd = open_dir(tmp.path()).unwrap();
        assert!(is_empty(fd.as_fd()).unwrap());
        std::fs::write(tmp.path().join("x"), "").unwrap();
        assert!(!is_empty(fd.as_fd()).unwrap());
    }

    #[test]
    fn test_chown_allowed() {
        for no in [
            "/",
            "/var",
            "/var/",
            "/usr",
            "/usr/share/x",
            "/etc/ssl",
            "/proc/1",
            "/home",
            "/lib64/x",
            "/dev",
        ] {
            assert!(!chown_allowed(Path::new(no)), "{no}");
        }
        for yes in [
            "/home/user",
            "/var/tmp/x",
            "/srv/data",
            "/tmp/x",
            "/mnt/data",
            "/usrlocal/x",
            "/var/lib/mine",
        ] {
            assert!(chown_allowed(Path::new(yes)), "{yes}");
        }
    }
}
