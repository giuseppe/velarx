// SPDX-License-Identifier: Apache-2.0
//! What is done to a whole directory tree by the walker ([`crate::walk`]):
//! the space it takes ([`usage`]) and its removal ([`remove_at`],
//! [`remove_tree`], [`empty`]).  Each holds a few descriptors whatever the
//! depth, never follows a symbolic link and does not recurse.

use crate::walk::{open_dir_at, Visit, Walk};
use rustix::fs::{
    chmodat, fstat, openat, statat, statx, unlinkat, AtFlags, FileType, Mode, OFlags, Stat,
    StatxFlags, CWD,
};
use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

/// The deepest directory a whole-tree operation walks into.  A path of a
/// descriptor has no length limit; this one only stops a tree made to be
/// endless.
pub const MAX_DEPTH: usize = 1 << 16;

fn kind(st: &Stat) -> FileType {
    FileType::from_raw_mode(st.st_mode)
}

/// The directory `path`, opened (a link at its end is followed, as a path
/// given by a caller is).
pub fn open_root(path: &Path) -> io::Result<OwnedFd> {
    openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOCTTY,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

// the space a tree takes

/// What a tree holds, below its root (which is not counted).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// every entry: files, directories, links, special files
    pub entries: u64,
    /// the regular files
    pub files: u64,
    /// the sizes of the regular files
    pub file_bytes: u64,
    /// the sizes of the other entries that are no directories (a link is
    /// the length of its target)
    pub other_bytes: u64,
    /// the sizes of the directories (as `st_size`)
    pub dir_bytes: u64,
    /// the 512 byte blocks allocated to every entry
    pub blocks: u64,
}

/// How a tree is measured.
#[derive(Clone, Copy, Debug, Default)]
pub struct Measure {
    /// What is on another file system than the root's is left out.
    pub one_fs: bool,
    /// The deepest directory listed (the root is at depth 0): one below it
    /// is counted, not listed.  Without it, a tree deeper than [`MAX_DEPTH`]
    /// is an error.
    pub listed_depth: Option<usize>,
    /// What cannot be read is left out, not an error ([`Walk::lenient`]).
    pub lenient: bool,
}

struct Measuring<'a> {
    m: &'a Measure,
    dev: u64,
    out: Usage,
}

impl Visit for Measuring<'_> {
    type Dir = ();

    fn entry(
        &mut self,
        _: BorrowedFd<'_>,
        _: &OsStr,
        st: &Stat,
        depth: usize,
        _: &mut (),
    ) -> io::Result<Option<()>> {
        if self.m.one_fs && st.st_dev != self.dev {
            return Ok(None);
        }
        let size = u64::try_from(st.st_size).unwrap_or(0);
        self.out.entries += 1;
        self.out.blocks = self
            .out
            .blocks
            .saturating_add(u64::try_from(st.st_blocks).unwrap_or(0));
        match kind(st) {
            FileType::Directory => {
                self.out.dir_bytes = self.out.dir_bytes.saturating_add(size);
                Ok(self.m.listed_depth.is_none_or(|l| depth < l).then_some(()))
            }
            FileType::RegularFile => {
                self.out.files += 1;
                self.out.file_bytes = self.out.file_bytes.saturating_add(size);
                Ok(None)
            }
            _ => {
                self.out.other_bytes = self.out.other_bytes.saturating_add(size);
                Ok(None)
            }
        }
    }
}

/// What the tree of the directory `root` holds.
pub fn usage_fd(root: OwnedFd, m: &Measure) -> io::Result<Usage> {
    let dev = fstat(&root)?.st_dev;
    let mut v = Measuring {
        m,
        dev,
        out: Usage::default(),
    };
    Walk {
        max_depth: MAX_DEPTH,
        sorted: false,
        skip_gone: true,
        lenient: m.lenient,
    }
    .run(root, (), &mut v)?;
    Ok(v.out)
}

/// What the tree at `path` holds.
pub fn usage(path: &Path, m: &Measure) -> io::Result<Usage> {
    usage_fd(open_root(path)?, m)
}

// removal

/// How a tree is removed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Remove {
    /// A directory that is not `rwx` for its owner is made so before it is
    /// entered (what `rm -rf` does): the trees a container made may hold
    /// directories without it.
    pub force_access: bool,
    /// A directory on another mount than the root's (a mount point, a bind
    /// mount of the same file system too) is an error, not entered.
    pub one_fs: bool,
}

/// Where a directory is mounted: its mount id where the kernel tells it (a
/// bind mount of the same file system has the device of the tree it is
/// in), else its device.
#[derive(Clone, Copy, Debug)]
pub struct MountOf {
    dev: u64,
    mnt_id: Option<u64>,
}

impl PartialEq for MountOf {
    fn eq(&self, o: &Self) -> bool {
        match (self.mnt_id, o.mnt_id) {
            (Some(a), Some(b)) => a == b,
            _ => self.dev == o.dev,
        }
    }
}

/// (an empty `name` is `dir` itself; `st` is its stat)
pub fn mount_of(dir: BorrowedFd<'_>, name: &OsStr, st: &Stat) -> io::Result<MountOf> {
    let flags = if name.is_empty() {
        AtFlags::EMPTY_PATH
    } else {
        AtFlags::SYMLINK_NOFOLLOW
    };
    let x = statx(dir, name, flags, StatxFlags::MNT_ID)?;
    Ok(MountOf {
        dev: st.st_dev,
        mnt_id: (x.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(x.stx_mnt_id),
    })
}

/// An entry gone since the listing is not an error: another removal of
/// the same tree took it (what `remove_dir_all` does too).
fn gone_is_done(r: rustix::io::Result<()>) -> io::Result<()> {
    match r {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        r => r.map_err(io::Error::from),
    }
}

struct Remover {
    opts: Remove,
    root: MountOf,
}

/// Make the directory `name` of `dir` (whose stat is `st`) `rwx` for its
/// owner, through a descriptor of the very directory that was seen: a name
/// replaced by a link is not followed.  A mode that cannot be changed (not
/// the owner, a read-only file system) is left: the removal then fails on
/// what it cannot do, as it would have.
fn make_accessible(dir: BorrowedFd<'_>, name: &OsStr, st: &Stat) -> io::Result<()> {
    if st.st_mode & 0o700 == 0o700 {
        return Ok(());
    }
    let fd = openat(
        dir,
        name,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let now = fstat(&fd)?;
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) {
        return Err(io::Error::other(format!(
            "the directory `{}` was replaced while it was removed",
            name.to_string_lossy()
        )));
    }
    let path = velarx_sys::fd::proc_str(&fd);
    match chmodat(
        CWD,
        path.as_str(),
        Mode::from_raw_mode((st.st_mode & 0o7777) | 0o700),
        AtFlags::empty(),
    ) {
        Err(rustix::io::Errno::PERM | rustix::io::Errno::ROFS) => Ok(()),
        r => r.map_err(io::Error::from),
    }
}

/// The error of a directory that is a mount below the tree removed.
fn a_mount(name: &OsStr) -> io::Error {
    io::Error::new(
        io::Error::from(rustix::io::Errno::XDEV).kind(),
        format!(
            "`{}` is a mount in the tree it is removed from",
            name.to_string_lossy()
        ),
    )
}

impl Visit for Remover {
    type Dir = ();

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        _: &mut (),
    ) -> io::Result<Option<()>> {
        if kind(st) != FileType::Directory {
            gone_is_done(unlinkat(dir, name, AtFlags::empty()))?;
            return Ok(None);
        }
        if self.opts.one_fs && mount_of(dir, name, st)? != self.root {
            return Err(a_mount(name));
        }
        if self.opts.force_access {
            make_accessible(dir, name, st)?;
        }
        Ok(Some(()))
    }

    fn leave(
        &mut self,
        parent: BorrowedFd<'_>,
        _: &mut (),
        name: &OsStr,
        dir: OwnedFd,
        _: (),
    ) -> io::Result<()> {
        drop(dir);
        gone_is_done(unlinkat(parent, name, AtFlags::REMOVEDIR))
    }
}

/// Remove what the directory `dir` (open for reading) holds, not the
/// directory.
pub fn empty(dir: OwnedFd, opts: &Remove) -> io::Result<()> {
    let st = fstat(&dir)?;
    let root = mount_of(dir.as_fd(), OsStr::new(""), &st)?;
    Walk {
        max_depth: MAX_DEPTH,
        sorted: false,
        // (another removal of the same tree took it)
        skip_gone: true,
        lenient: false,
    }
    .run(dir, (), &mut Remover { opts: *opts, root })
}

/// Remove `name` of `dir`, and what is below it for a directory, without
/// following a link.
pub fn remove_at(dir: BorrowedFd<'_>, name: &OsStr, opts: &Remove) -> io::Result<()> {
    let st = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if kind(&st) != FileType::Directory {
        return unlinkat(dir, name, AtFlags::empty()).map_err(io::Error::from);
    }
    if opts.one_fs {
        let here = fstat(dir)?;
        if mount_of(dir, name, &st)? != mount_of(dir, OsStr::new(""), &here)? {
            return Err(a_mount(name));
        }
    }
    if opts.force_access {
        make_accessible(dir, name, &st)?;
    }
    let sub = open_dir_at(dir, name)?;
    let now = fstat(&sub)?;
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) {
        return Err(io::Error::other(format!(
            "the directory `{}` was replaced while it was removed",
            name.to_string_lossy()
        )));
    }
    empty(sub, opts)?;
    unlinkat(dir, name, AtFlags::REMOVEDIR).map_err(io::Error::from)
}

/// Remove the tree at `path` (a link at its end is removed, not followed; a
/// path that is not there is a `NotFound` error, as `remove_dir_all`'s).
pub fn remove_tree(path: &Path, opts: &Remove) -> io::Result<()> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no name to remove it by", path.display()),
        ));
    };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let dir = openat(
        CWD,
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    remove_at(dir.as_fd(), name, opts)
}

/// What `std::fs::remove_dir_all` does, without its limits: the directory
/// (or the link) at `path` is removed with all it holds, a few descriptors at
/// any depth, no recursion, nothing followed.  A path that is not there is a
/// `NotFound` error, one that is a file an error (`ENOTDIR`).
pub fn remove_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    remove_dir_all_with(path.as_ref(), &Remove::default())
}

/// [`remove_dir_all`] for a tree that something else made, a container or a
/// build step: a directory without access is made accessible (`rm -rf`), and
/// a mount below it is an error, not entered (what is mounted there is not
/// the tree's to remove).
pub fn remove_dir_all_confined(path: impl AsRef<Path>) -> io::Result<()> {
    remove_dir_all_with(
        path.as_ref(),
        &Remove {
            force_access: true,
            one_fs: true,
        },
    )
}

fn remove_dir_all_with(path: &Path, opts: &Remove) -> io::Result<()> {
    let st = statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW)?;
    match kind(&st) {
        FileType::Directory => remove_tree(path, opts),
        FileType::Symlink => unlinkat(CWD, path, AtFlags::empty()).map_err(io::Error::from),
        _ => Err(io::Error::from(rustix::io::Errno::NOTDIR)),
    }
}

/// The tests that open descriptors or count them take this, one at a time.
#[cfg(test)]
pub(crate) static FDS: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A chain of `depth` directories `d` below `root`, made by descriptors.
    fn deep(root: &Path, depth: usize) {
        let mut fd = open_root(root).unwrap();
        for _ in 0..depth {
            rustix::fs::mkdirat(&fd, "d", Mode::from_raw_mode(0o700)).unwrap();
            fd = open_dir_at(fd.as_fd(), OsStr::new("d")).unwrap();
        }
        drop(std::fs::File::from(
            openat(
                &fd,
                "f",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .unwrap(),
        ));
    }

    /// The tree removed in a child test process whose limit of descriptors
    /// is 256, with a tree of 3000 levels (a descriptor per level could not
    /// do it), on a small stack.
    #[test]
    fn test_a_deep_tree_is_removed_with_a_few_descriptors_on_a_small_stack() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = std::env::var_os("VELARX_TREE_TEST_DIR") {
            let t = std::path::PathBuf::from(t);
            deep(&t, 3000);
            std::os::unix::fs::symlink("/", t.join("link")).unwrap();
            let t2 = t.clone();
            std::thread::Builder::new()
                .stack_size(64 << 10)
                .spawn(move || remove_tree(&t2, &Remove::default()).unwrap())
                .unwrap()
                .join()
                .unwrap();
            assert!(!t.exists());
            assert!(Path::new("/").exists());
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().join("t");
        std::fs::create_dir(&t).unwrap();
        let me = std::env::current_exe().unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                r#"ulimit -Sn 256 && exec "$0" --exact tree::tests::test_a_deep_tree_is_removed_with_a_few_descriptors_on_a_small_stack"#,
            )
            .arg(me)
            .env("VELARX_TREE_TEST_DIR", &t)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!t.exists());
    }

    #[test]
    fn test_removal_makes_directories_accessible_on_request() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path().join("t");
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        std::fs::write(t.join("a/b/f"), "x").unwrap();
        std::fs::set_permissions(t.join("a/b"), std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(t.join("a"), std::fs::Permissions::from_mode(0o500)).unwrap();
        if rustix::process::geteuid().is_root() {
            // (root passes every permission: nothing to see)
            std::fs::set_permissions(t.join("a"), std::fs::Permissions::from_mode(0o700)).unwrap();
        } else {
            assert!(remove_tree(&t, &Remove::default()).is_err());
        }
        remove_tree(
            &t,
            &Remove {
                force_access: true,
                one_fs: false,
            },
        )
        .unwrap();
        assert!(!t.exists());
        assert_eq!(
            remove_tree(&t, &Remove::default()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    /// A link to a directory without access in the tree: removed, and what
    /// it points to keeps its mode.
    #[test]
    fn test_making_accessible_follows_no_link() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("keep"), "").unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o500)).unwrap();
        let t = tmp.path().join("t");
        std::fs::create_dir(&t).unwrap();
        std::os::unix::fs::symlink(&out, t.join("link")).unwrap();
        let force = Remove {
            force_access: true,
            one_fs: true,
        };
        remove_tree(&t, &force).unwrap();
        assert!(!t.exists());
        let m = std::fs::metadata(&out).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o500);
        assert!(out.join("keep").exists());
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// A bind mount of a directory of the same file system in the tree: with
    /// `one_fs`, an error before anything below it is touched (run in a
    /// user and mount namespace of its own; skipped without one).
    #[test]
    fn test_a_bind_mount_in_the_tree_is_refused_with_one_fs() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = std::env::var_os("VELARX_TREE_MOUNT_DIR") {
            let t = std::path::PathBuf::from(t);
            let (tree, out) = (t.join("tree"), t.join("out"));
            let m = std::process::Command::new("mount")
                .args(["--bind"])
                .arg(&out)
                .arg(tree.join("a/m"))
                .status()
                .unwrap();
            assert!(m.success());
            let opts = Remove {
                force_access: true,
                one_fs: true,
            };
            let e = remove_tree(&tree, &opts).unwrap_err();
            assert!(e.to_string().contains("is a mount"), "{e}");
            assert!(out.join("keep").exists());
            // the mount itself as the root of a removal
            let e = remove_tree(&tree.join("a/m"), &opts).unwrap_err();
            assert!(e.to_string().contains("is a mount"), "{e}");
            let e = empty(open_root(&tree.join("a")).unwrap(), &opts).unwrap_err();
            assert!(e.to_string().contains("is a mount"), "{e}");
            let e = remove_dir_all_confined(&tree).unwrap_err();
            assert!(e.to_string().contains("is a mount"), "{e}");
            assert!(out.join("keep").exists());
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("tree/a/m")).unwrap();
        std::fs::create_dir(t.join("out")).unwrap();
        std::fs::write(t.join("out/keep"), "").unwrap();
        let me = std::env::current_exe().unwrap();
        let out = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(&me)
            .args([
                "--exact",
                "tree::tests::test_a_bind_mount_in_the_tree_is_refused_with_one_fs",
            ])
            .env("VELARX_TREE_MOUNT_DIR", t)
            .output();
        let Ok(out) = out else {
            return;
        };
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && err.contains("unshare") {
            // (no user namespaces here)
            return;
        }
        assert!(
            out.status.success(),
            "{}{err}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(t.join("out/keep").exists());
    }

    #[test]
    fn test_remove_dir_all_is_the_one_of_std() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        std::fs::write(t.join("a/b/f"), "").unwrap();
        std::os::unix::fs::symlink("/", t.join("a/link")).unwrap();
        std::os::unix::fs::symlink("a", t.join("toa")).unwrap();
        // a link is removed, not followed; a file and a missing path are errors
        remove_dir_all(t.join("toa")).unwrap();
        assert!(t.join("a").exists());
        std::fs::write(t.join("file"), "").unwrap();
        assert_eq!(
            remove_dir_all(t.join("file")).unwrap_err().raw_os_error(),
            Some(libc_enotdir())
        );
        assert_eq!(
            remove_dir_all(t.join("nothing")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        remove_dir_all(t.join("a")).unwrap();
        assert!(!t.join("a").exists());
        std::fs::create_dir_all(t.join("c/d")).unwrap();
        remove_dir_all_confined(t.join("c")).unwrap();
        assert!(!t.join("c").exists());
    }

    fn libc_enotdir() -> i32 {
        rustix::io::Errno::NOTDIR.raw_os_error()
    }

    #[test]
    fn test_emptying_keeps_the_directory_and_a_file_is_unlinked() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("x/y")).unwrap();
        std::fs::write(t.join("x/y/f"), "").unwrap();
        std::fs::write(t.join("x/g"), "").unwrap();
        empty(open_root(&t.join("x")).unwrap(), &Remove::default()).unwrap();
        assert_eq!(std::fs::read_dir(t.join("x")).unwrap().count(), 0);
        remove_tree(&t.join("x"), &Remove::default()).unwrap();
        std::fs::write(t.join("file"), "").unwrap();
        remove_tree(&t.join("file"), &Remove::default()).unwrap();
        assert!(!t.join("file").exists());
    }

    #[test]
    fn test_usage_counts_what_is_below_the_root_and_follows_nothing() {
        let _fds = FDS.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let t = tmp.path();
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        std::fs::write(t.join("a/f"), "12345").unwrap();
        std::fs::write(t.join("a/b/g"), "123").unwrap();
        std::os::unix::fs::symlink("/", t.join("a/link")).unwrap();
        let u = usage(t, &Measure::default()).unwrap();
        assert_eq!((u.entries, u.files, u.file_bytes), (5, 2, 8));
        assert_eq!(u.other_bytes, 1);
        // `a` is listed, `b` is counted and not listed
        let u = usage(
            t,
            &Measure {
                listed_depth: Some(1),
                ..Measure::default()
            },
        )
        .unwrap();
        assert_eq!((u.entries, u.files, u.file_bytes), (4, 1, 5));
        let u = usage(
            t,
            &Measure {
                listed_depth: Some(0),
                ..Measure::default()
            },
        )
        .unwrap();
        assert_eq!((u.entries, u.files), (1, 0));
        assert_eq!(
            usage(&t.join("nothing"), &Measure::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
