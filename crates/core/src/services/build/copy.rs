// SPDX-License-Identifier: Apache-2.0
//! The files of a COPY or ADD step, written to a new directory that
//! becomes the layer of the step; and the extraction of a build context.
//!
//! This runs in a confined worker (see `worker`): the sources are the
//! build context, a tar stream of the paths of an image (`COPY --from`),
//! or the context archive a client sent.  Nothing is followed out of a
//! root: a source is resolved with `RESOLVE_IN_ROOT` in the context, and
//! below it every entry is opened relative to its directory with
//! `O_NOFOLLOW`, its type checked before it is opened for reading.  The
//! destination is a directory the build created empty: its directories
//! are created one component at a time, a link or a file in the way is
//! replaced (never followed), files are created `O_EXCL`.  Copies keep
//! the modes and times of the sources; the owner is the root of the image
//! unless `--chown` says otherwise, and archives and the files of another
//! stage or image (`COPY --from`) keep theirs.

use crate::services::Cancel;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{
    chownat, fchmod, fchown, fstat, futimens, linkat, mkdirat, openat, readlinkat, statat,
    symlinkat, unlinkat, utimensat, AtFlags, Dir, FileType, Gid, Mode, OFlags, ResolveFlags, Stat,
    Timespec, Timestamps, Uid,
};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path};
use velarx_base::walk::{Cursor, Visit, Walk};
use velarx_sys::fs::openat2_retry;
use velarx_wire::cp::MAX_DEPTH;
use velarx_wire::parse::{fnmatch, has_glob, Ignore};

const IN_ROOT: ResolveFlags = ResolveFlags::IN_ROOT.union(ResolveFlags::NO_MAGICLINKS);
const BENEATH: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// The largest number of sources a glob may give.
const MAX_MATCHES: usize = 100_000;

/// Where the sources come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// The build context, a directory.
    Context,
    /// A tar stream whose first path component is the index of the item
    /// it is for (`COPY --from`).
    Tar,
    /// A tar stream extracted as it is: a build context sent by a client.
    Unpack,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Context: a path relative to the context, maybe a glob.  Tar: unused.
    pub src: String,
    /// The destination, absolute in the image and clean.
    pub dst: String,
    /// The destination is a directory to copy into (`/dst/`, several
    /// sources).
    pub dest_dir: bool,
    /// `COPY --parents`: what a source gives is placed in the destination
    /// with its path from this component on (the number of components of
    /// the source before the `/./` that marks the start, else all).
    #[serde(default)]
    pub pivot: Option<usize>,
    /// Tar: the path in the image of the source of the item, for the
    /// patterns that leave files out.
    #[serde(default)]
    pub origin: String,
}

/// The attributes the image has for a directory: the directories the step
/// creates on the way to its destinations get them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentDir {
    /// Absolute and clean.
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
}

/// What a job may write: decompression bombs stop there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Bytes of file content written, all files together (and the largest
    /// file).
    pub max_bytes: u64,
    /// Entries of the archives extracted.
    pub max_entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 64 << 30,
            max_entries: 4 << 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyJob {
    pub source: Source,
    pub items: Vec<Item>,
    /// `--chown`.
    pub chown: Option<(u32, u32)>,
    /// `--chmod`.
    pub chmod: Option<u32>,
    pub parents: Vec<ParentDir>,
    /// The `.containerignore` patterns of the context.
    pub ignore: Vec<String>,
    /// ADD: local archives are extracted.
    pub add: bool,
    #[serde(default)]
    pub limits: Limits,
    /// Nothing is copied: the job answers the digest of what it would copy
    /// from the context (see [`digest`]).
    #[serde(default)]
    pub digest: bool,
    /// A copy from a context answers that a node it copied had its status
    /// changed (its ctime) at or after this time (seconds, nanoseconds): what
    /// it copied may then not be what a digest taken from then on read.
    #[serde(default)]
    pub unchanged_since: Option<(i64, i64)>,
}

impl CopyJob {
    pub fn new(source: Source) -> Self {
        Self {
            source,
            items: Vec::new(),
            chown: None,
            chmod: None,
            parents: Vec::new(),
            ignore: Vec::new(),
            add: false,
            limits: Limits::default(),
            digest: false,
            unchanged_since: None,
        }
    }
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn not_found(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("`{what}`: no such file or directory"),
    )
}

fn kind(st: &Stat) -> FileType {
    FileType::from_raw_mode(st.st_mode)
}

fn stamp(sec: i64, nsec: i64) -> Timestamps {
    let t = Timespec {
        tv_sec: sec,
        tv_nsec: nsec as _,
    };
    Timestamps {
        last_access: t,
        last_modification: t,
    }
}

/// The components of a clean path (`/a/b` or `a/b`).
fn parts(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|c| !c.is_empty() && *c != ".")
}

/// Remove `name` from `dir`, a directory with all it has (nothing is an
/// error when it is not there).
pub(super) fn remove_tree(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    match velarx_base::tree::remove_at(dir, name, &velarx_base::tree::Remove::default()) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// The names of a directory opened for reading, sorted.
pub(super) fn list(dir: BorrowedFd<'_>) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    for e in Dir::read_from(dir)? {
        let e = e?;
        let n = e.file_name().to_bytes();
        if n != b"." && n != b".." {
            names.push(OsString::from_vec(n.to_vec()));
        }
    }
    names.sort();
    Ok(names)
}

/// What the destination side of a job does.
struct Dest<'a> {
    root: BorrowedFd<'a>,
    job: &'a CopyJob,
    ignore: Ignore,
    /// The directories of the image created on the way, whose times are
    /// set again at the end (what is written in them changes them).
    created: Vec<(String, i64)>,
    /// Bytes written and archive entries extracted so far.
    bytes: u64,
    entries: u64,
    /// The job stops with an error once this is asked
    cancel: &'a Cancel,
    /// A node copied changed at or after `job.unchanged_since`.
    changed: bool,
    /// The regular files with other links copied so far, by the node of
    /// the source: their copy (its directory, name and node), which a copy
    /// of another link of the source becomes a link of.
    linked: std::collections::HashMap<(u64, u64), (OwnedFd, OsString, u64)>,
}

/// A node to copy: opened with `O_PATH` (`open` opens it for reading), its
/// status, and `rel`, its path in the context, for the ignore patterns.
struct Node<'a> {
    src: &'a OwnedFd,
    open: &'a Opener<'a>,
    st: &'a Stat,
    rel: Option<&'a str>,
}

/// How to open the regular file of an entry for reading: by its name in
/// its directory, or by its path in the root of the context.
enum Opener<'a> {
    At(BorrowedFd<'a>, &'a OsStr),
    InRoot(BorrowedFd<'a>, &'a str),
}

impl Opener<'_> {
    /// The file that was seen as `st`, opened for reading without
    /// following a link and without blocking on a fifo planted meanwhile.
    fn open(&self, st: &Stat) -> io::Result<OwnedFd> {
        let flags = OFlags::RDONLY | OFlags::NOCTTY | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let fd = match self {
            Opener::At(dir, name) => openat(dir, *name, flags | OFlags::NOFOLLOW, Mode::empty())?,
            Opener::InRoot(root, rel) => openat2_retry(
                *root,
                if rel.is_empty() { "." } else { rel },
                flags,
                Mode::empty(),
                IN_ROOT,
            )?,
        };
        same_node(&fd, st)?;
        Ok(fd)
    }
}

fn same_node(fd: &OwnedFd, st: &Stat) -> io::Result<()> {
    let now = fstat(fd)?;
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) || kind(&now) != kind(st) {
        return Err(io::Error::other("a file changed while it was copied"));
    }
    Ok(())
}

/// A directory opened with `O_PATH`, opened again to be listed.
/// The xattrs a copy keeps: the user's and the file capabilities (not the
/// store's, SELinux labels, ACLs or the trusted ones).
fn copied_xattr(name: &[u8]) -> bool {
    (name.starts_with(b"user.") && !name.starts_with(b"user.overlay."))
        || name == b"security.capability"
}

const MAX_XATTR_LIST: usize = 64 * 1024;
const MAX_XATTR_VALUE: usize = 64 * 1024;

/// Copy the xattrs a copy keeps from `from` to `to` (after the owner is
/// set: a chown drops the file capabilities).  A file system without xattrs
/// on either side copies none.
fn copy_xattrs(from: BorrowedFd<'_>, to: BorrowedFd<'_>) -> io::Result<()> {
    for (name, value) in kept_xattrs(from)? {
        set_xattr(to, &name, &value)?;
    }
    Ok(())
}

/// The xattrs a copy keeps of `from`, in the order of their names.
fn kept_xattrs(from: BorrowedFd<'_>) -> io::Result<Xattrs> {
    use rustix::fs::{fgetxattr, flistxattr};
    let mut list = vec![0u8; 1024];
    let len = loop {
        match flistxattr(from, &mut list) {
            Ok(n) => break n,
            Err(rustix::io::Errno::RANGE) if list.len() < MAX_XATTR_LIST => {
                list.resize((list.len() * 8).min(MAX_XATTR_LIST), 0)
            }
            Err(rustix::io::Errno::NOTSUP) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        }
    };
    let mut kept = Vec::new();
    for name in list[..len].split(|b| *b == 0).filter(|n| copied_xattr(n)) {
        let cname =
            std::ffi::CString::new(name).map_err(|_| invalid("an xattr name has a NUL".into()))?;
        let mut value = vec![0u8; 256];
        let n = loop {
            match fgetxattr(from, &cname, &mut value) {
                Ok(n) => break Some(n),
                Err(rustix::io::Errno::RANGE) if value.len() < MAX_XATTR_VALUE => {
                    value.resize((value.len() * 8).min(MAX_XATTR_VALUE), 0)
                }
                Err(rustix::io::Errno::NODATA) => break None,
                Err(e) => return Err(e.into()),
            }
        };
        if let Some(n) = n {
            value.truncate(n);
            kept.push((name.to_vec(), value));
        }
    }
    kept.sort();
    Ok(kept)
}

fn set_xattr(to: BorrowedFd<'_>, name: &[u8], value: &[u8]) -> io::Result<()> {
    let cname =
        std::ffi::CString::new(name).map_err(|_| invalid("an xattr name has a NUL".into()))?;
    match rustix::fs::fsetxattr(to, &cname, value, rustix::fs::XattrFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOTSUP) => Ok(()),
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!(
                "cannot set the xattr {}: {e}",
                String::from_utf8_lossy(name)
            ),
        )),
    }
}

fn open_listing(src: &OwnedFd, st: &Stat) -> io::Result<OwnedFd> {
    let fd = openat(
        src,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    same_node(&fd, st)?;
    Ok(fd)
}

impl Dest<'_> {
    /// Open the directory `name` in `dir`, creating it (or replacing what
    /// is not a directory, never followed).  Whether it was created.
    fn open_dir(
        &self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        mode: u32,
    ) -> io::Result<(OwnedFd, bool)> {
        let mut created = false;
        match mkdirat(dir, name, Mode::from_raw_mode(mode)) {
            Ok(()) => created = true,
            Err(rustix::io::Errno::EXIST) => {
                let st = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
                if kind(&st) != FileType::Directory {
                    remove_tree(dir, name)?;
                    mkdirat(dir, name, Mode::from_raw_mode(mode))?;
                    created = true;
                }
            }
            Err(e) => return Err(e.into()),
        }
        let fd = openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok((fd, created))
    }

    /// The directory `path` (absolute in the image), the missing
    /// components created with the attributes the image has for them.
    fn open_path(&mut self, path: &str) -> io::Result<OwnedFd> {
        let mut cur = rustix::io::fcntl_dupfd_cloexec(self.root, 0)?;
        let mut so_far = String::new();
        for c in parts(path) {
            so_far.push('/');
            so_far.push_str(c);
            let (next, created) = self.open_dir(cur.as_fd(), OsStr::new(c), 0o755)?;
            if created {
                if let Some(p) = self.job.parents.iter().find(|p| p.path == so_far) {
                    fchown(
                        &next,
                        Some(Uid::from_raw_unchecked(p.uid)),
                        Some(Gid::from_raw_unchecked(p.gid)),
                    )?;
                    fchmod(&next, Mode::from_raw_mode(p.mode & 0o7777))?;
                    self.created.push((so_far.clone(), p.mtime));
                } else if let Some((uid, gid)) = self.job.chown {
                    // (a directory the image lacks gets the owner of
                    // `--chown`, not its mode, as buildah's)
                    fchown(
                        &next,
                        Some(Uid::from_raw_unchecked(uid)),
                        Some(Gid::from_raw_unchecked(gid)),
                    )?;
                }
            }
            cur = next;
        }
        Ok(cur)
    }

    /// The owner, mode and times of a node created by a copy.
    fn finish(&self, fd: BorrowedFd<'_>, st: &Stat, owner: Option<(u32, u32)>) -> io::Result<()> {
        if let Some((uid, gid)) = self.job.chown.or(owner) {
            fchown(
                fd,
                Some(Uid::from_raw_unchecked(uid)),
                Some(Gid::from_raw_unchecked(gid)),
            )?;
        }
        // After the owner: a chown drops the set-id bits.
        let mode = self.job.chmod.unwrap_or(st.st_mode & 0o7777);
        fchmod(fd, Mode::from_raw_mode(mode))?;
        futimens(fd, &stamp(st.st_mtime, st.st_mtime_nsec as i64))?;
        Ok(())
    }

    /// The owner and times of a node that is not opened (a link, a fifo),
    /// and its mode if `mode` (a link has none).
    fn finish_named(
        &self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        owner: Option<(u32, u32)>,
        mode: bool,
    ) -> io::Result<()> {
        if let Some((uid, gid)) = self.job.chown.or(owner) {
            chownat(
                dir,
                name,
                Some(Uid::from_raw_unchecked(uid)),
                Some(Gid::from_raw_unchecked(gid)),
                AtFlags::SYMLINK_NOFOLLOW,
            )?;
        }
        if mode {
            // The node was just made in the destination, which only this
            // worker writes: it is not a link.
            let mode = self.job.chmod.unwrap_or(st.st_mode & 0o7777);
            rustix::fs::chmodat(dir, name, Mode::from_raw_mode(mode), AtFlags::empty())?;
        }
        utimensat(
            dir,
            name,
            &stamp(st.st_mtime, st.st_mtime_nsec as i64),
            AtFlags::SYMLINK_NOFOLLOW,
        )?;
        Ok(())
    }

    fn spend(&mut self, bytes: u64, entries: u64) -> io::Result<()> {
        self.cancel.check()?;
        let b = self.bytes.saturating_add(bytes);
        let e = self.entries.saturating_add(entries);
        let limits = self.job.limits;
        if b > limits.max_bytes {
            return Err(invalid(format!(
                "more than {} bytes to write: refused",
                limits.max_bytes
            )));
        }
        if e > limits.max_entries {
            return Err(invalid(format!(
                "more than {} entries to extract: refused",
                limits.max_entries
            )));
        }
        self.bytes = b;
        self.entries = e;
        Ok(())
    }

    /// Whether the source node `fd` (a file, a link, or a directory whose
    /// listing was read) changed since `job.unchanged_since`: looked at
    /// once it is copied, so a change during the copy is seen too.
    fn note_change(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        if let (Some((sec, nsec)), false) = (self.job.unchanged_since, self.changed) {
            let st = fstat(fd)?;
            self.changed = (st.st_ctime, st.st_ctime_nsec as i64) >= (sec, nsec);
        }
        Ok(())
    }

    /// Copy the node `node` to `name` in `dst`.
    fn copy_node(&mut self, node: Node<'_>, dst: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
        let Node { src, open, st, rel } = node;
        match kind(st) {
            FileType::Directory => {
                let (out, _) = self.open_dir(dst, name, 0o700)?;
                self.copy_contents(src, st, rel, out.as_fd())?;
                self.finish(out.as_fd(), st, None)?;
                copy_xattrs(open_listing(src, st)?.as_fd(), out.as_fd())
            }
            _ => self.copy_leaf(Node { src, open, st, rel }, dst, name),
        }
    }

    /// Copy a node that is not a directory to `name` in `dst`.
    fn copy_leaf(&mut self, node: Node<'_>, dst: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
        let src = node.src;
        self.copy_leaf_node(node, dst, name)?;
        self.note_change(src.as_fd())
    }

    fn copy_leaf_node(
        &mut self,
        node: Node<'_>,
        dst: BorrowedFd<'_>,
        name: &OsStr,
    ) -> io::Result<()> {
        let Node { src, open, st, .. } = node;
        match kind(st) {
            FileType::RegularFile => {
                let source = (st.st_dev, st.st_ino);
                if let Some((dir, first, ino)) = self.linked.get(&source) {
                    // (unless its copy was replaced since)
                    if statat(dir, first.as_os_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .is_ok_and(|now| now.st_ino == *ino)
                    {
                        remove_tree(dst, name)?;
                        return Ok(linkat(dir, first.as_os_str(), dst, name, AtFlags::empty())?);
                    }
                }
                self.spend(st.st_size.max(0) as u64, 0)?;
                remove_tree(dst, name)?;
                let input = open.open(st)?;
                let out = openat(
                    dst,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?;
                let attrs = input.try_clone()?;
                // (the holes of the file stay holes)
                velarx_storage::copy_file(
                    &std::fs::File::from(input),
                    &std::fs::File::from(out.try_clone()?),
                    st.st_size.max(0) as u64,
                    || self.cancel.check(),
                )?;
                self.finish(out.as_fd(), st, None)?;
                copy_xattrs(attrs.as_fd(), out.as_fd())?;
                if st.st_nlink > 1 {
                    let dir = rustix::io::fcntl_dupfd_cloexec(dst, 0)?;
                    let copy = (dir, name.to_owned(), fstat(&out)?.st_ino);
                    self.linked.insert(source, copy);
                }
                Ok(())
            }
            FileType::Symlink => {
                remove_tree(dst, name)?;
                let target = readlinkat(src, "", Vec::new())?;
                symlinkat(target.as_c_str(), dst, name)?;
                self.finish_named(dst, name, st, None, false)
            }
            FileType::Fifo => {
                remove_tree(dst, name)?;
                make_fifo(dst, name)?;
                self.finish_named(dst, name, st, None, true)
            }
            // Devices are not created (the worker cannot: see the worker),
            // sockets are not copied.
            _ => Ok(()),
        }
    }

    /// Copy what the directory `src` (opened with `O_PATH`, seen as `st`)
    /// holds into the directory `out`, and all below it: the walk of the
    /// source, a [`Cursor`] on the destination.
    fn copy_contents(
        &mut self,
        src: &OwnedFd,
        st: &Stat,
        rel: Option<&str>,
        out: BorrowedFd<'_>,
    ) -> io::Result<()> {
        let mut w = CopyWalk {
            d: &mut *self,
            dst: Cursor::new(rustix::io::fcntl_dupfd_cloexec(out, 0)?)?,
        };
        let state = CopyDir {
            rel: rel.map(str::to_string),
            st: *st,
            ignored: false,
            created: false,
        };
        // (the depth is checked by the walk's entries: the message is ours)
        Walk {
            max_depth: MAX_DEPTH + 1,
            sorted: true,
            skip_gone: false,
            lenient: false,
        }
        .run(open_listing(src, st)?, state, &mut w)?;
        self.note_change(src.as_fd())
    }
}

/// What the walk of a source keeps of a directory it is in.
struct CopyDir {
    /// its path in the context, for the ignore patterns
    rel: Option<String>,
    st: Stat,
    /// An ignored directory that is walked for what a `!` pattern takes back
    /// from it, and whether the copy made it.
    ignored: bool,
    created: bool,
}

/// The copy of a source tree: the source is walked, the destination
/// follows with a cursor of its own.
struct CopyWalk<'d, 'a> {
    d: &'d mut Dest<'a>,
    dst: Cursor,
}

impl Visit for CopyWalk<'_, '_> {
    type Dir = CopyDir;

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        child: &OsStr,
        _: &Stat,
        depth: usize,
        parent: &mut CopyDir,
    ) -> io::Result<Option<CopyDir>> {
        if depth + 1 > MAX_DEPTH {
            return Err(invalid(format!(
                "the tree is nested deeper than {MAX_DEPTH} directories"
            )));
        }
        let d = &mut *self.d;
        let mut ignored = false;
        let child_rel = match &parent.rel {
            Some(r) => {
                let n = child.to_str().ok_or_else(|| {
                    invalid(format!("`{r}/{}` is not UTF-8", child.to_string_lossy()))
                })?;
                let p = if r.is_empty() {
                    n.to_string()
                } else {
                    format!("{r}/{n}")
                };
                ignored = d.ignore.ignored(&p);
                Some(p)
            }
            None => None,
        };
        let fd = openat(
            dir,
            child,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let cst = fstat(&fd)?;
        let is_dir = kind(&cst) == FileType::Directory;
        if !ignored && !is_dir {
            let open = Opener::At(dir, child);
            let node = Node {
                src: &fd,
                open: &open,
                st: &cst,
                rel: child_rel.as_deref(),
            };
            d.copy_leaf(node, self.dst.fd(), child)?;
            return Ok(None);
        }
        // An ignored directory: what a `!` pattern takes back from it is
        // copied, the directory kept only if something is.
        if !is_dir
            || child_rel
                .as_deref()
                .is_some_and(|p| ignored && !d.ignore.may_take_back(p))
        {
            return Ok(None);
        }
        let (sub, created) = d.open_dir(self.dst.fd(), child, 0o700)?;
        self.dst.adopt(child, sub)?;
        Ok(Some(CopyDir {
            rel: child_rel,
            st: cst,
            ignored,
            created,
        }))
    }

    fn leave(
        &mut self,
        _: BorrowedFd<'_>,
        _: &mut CopyDir,
        name: &OsStr,
        dir: OwnedFd,
        state: CopyDir,
    ) -> io::Result<()> {
        let (_, sub) = self.dst.ascend()?;
        self.d.note_change(dir.as_fd())?;
        if state.ignored {
            if state.created && list(sub.as_fd())?.is_empty() {
                drop(sub);
                unlinkat(self.dst.fd(), name, AtFlags::REMOVEDIR)?;
            } else {
                self.d.finish(sub.as_fd(), &state.st, None)?;
            }
            return Ok(());
        }
        self.d.finish(sub.as_fd(), &state.st, None)?;
        copy_xattrs(dir.as_fd(), sub.as_fd())
    }
}

/// The paths of the context that `pattern` matches, sorted; the glob
/// components are matched against the names of the directories, which
/// are resolved in the context.  The directories it lists go to `listed`: a name added to or removed
/// from one of them changes what the pattern matches.
fn expand_glob(
    root: BorrowedFd<'_>,
    pattern: &str,
    listed: &mut Vec<OwnedFd>,
) -> io::Result<Vec<String>> {
    let mut found = vec![String::new()];
    for c in parts(pattern) {
        if !has_glob(c) {
            for p in &mut found {
                if !p.is_empty() {
                    p.push('/');
                }
                p.push_str(c);
            }
            continue;
        }
        let mut next = Vec::new();
        for p in &found {
            let dir = match openat2_retry(
                root,
                if p.is_empty() { "." } else { p.as_str() },
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                IN_ROOT,
            ) {
                Ok(d) => d,
                Err(rustix::io::Errno::NOENT) | Err(rustix::io::Errno::NOTDIR) => continue,
                Err(e) => return Err(e.into()),
            };
            let names = list(dir.as_fd())?;
            listed.push(dir);
            for name in names {
                let Some(n) = name.to_str() else { continue };
                if fnmatch(c, n) {
                    next.push(if p.is_empty() {
                        n.to_string()
                    } else {
                        format!("{p}/{n}")
                    });
                    if next.len() > MAX_MATCHES {
                        return Err(invalid(format!("`{pattern}` matches too many files")));
                    }
                }
            }
        }
        found = next;
    }
    found.sort();
    Ok(found)
}

/// A fifo `name` in `dir`, mode 0600 until it is finished.
fn make_fifo(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    rustix::fs::mknodat(dir, name, FileType::Fifo, Mode::from_raw_mode(0o600), 0)?;
    Ok(())
}

/// Whether the first bytes are those of an archive ADD extracts.
pub(super) fn archive_kind(head: &[u8]) -> Option<&'static str> {
    if head.starts_with(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if head.starts_with(b"BZh") {
        Some("bzip2")
    } else if head.starts_with(b"\xfd7zXZ\0") {
        Some("xz")
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if head.len() >= 262 && &head[257..262] == b"ustar" {
        Some("tar")
    } else {
        None
    }
}

fn decompress<'a>(kind: &str, r: impl Read + 'a) -> io::Result<Box<dyn Read + 'a>> {
    use velarx_content::decompress::{Decoder, Kind};
    Ok(match kind {
        // the system programs (see `external`)
        "bzip2" | "xz" => return super::external::decompress(kind, r),
        "gzip" => Box::new(Decoder::new(Kind::Gzip, io::BufReader::new(r))?),
        "zstd" => Box::new(Decoder::new(Kind::Zstd, io::BufReader::new(r))?),
        _ => Box::new(io::BufReader::new(r)),
    })
}

/// The owner given to a node, if not the worker's.
type Owner = Option<(u32, u32)>;
/// The xattrs of an entry to set: names and values.
type Xattrs = Vec<(Vec<u8>, Vec<u8>)>;

/// How the paths of a tar stream are placed.
enum Placement<'a> {
    /// Below the root as they are.
    AsIs,
    /// Below the directory `dst` (absolute in the image).
    Under(&'a str),
    /// The first component is the index of the item whose destination
    /// replaces it.
    Indexed(&'a [Item]),
}

impl Dest<'_> {
    /// Extract a tar stream.  `keep_owners`: the owners of the archive,
    /// otherwise the worker's (or `--chown`).
    fn extract(&mut self, r: impl Read, place: Placement<'_>, keep_owners: bool) -> io::Result<()> {
        let mut ar = velarx_wire::sparse::archive(self.cancel.io(r));
        // Directories get their mode, owner and times once what they hold
        // is written.
        let mut dirs: Vec<(String, Stat, Owner, Xattrs)> = Vec::new();
        for entry in ar.entries()? {
            let mut entry = entry?;
            let raw = velarx_wire::sparse::path(&mut entry)?;
            let mut comps: Vec<String> = Vec::new();
            for c in raw.components() {
                match c {
                    Component::Normal(n) => comps.push(
                        n.to_str()
                            .ok_or_else(|| invalid(format!("`{}` is not UTF-8", raw.display())))?
                            .to_string(),
                    ),
                    Component::CurDir | Component::RootDir => {}
                    _ => {
                        return Err(invalid(format!(
                            "invalid path in the archive: {}",
                            raw.display()
                        )))
                    }
                }
            }
            // (the directory an item's source names: its destination)
            let mut item_root = false;
            let path = match &place {
                Placement::AsIs => comps.join("/"),
                Placement::Under(dst) => {
                    let mut p: Vec<&str> = parts(dst).collect();
                    p.extend(comps.iter().map(String::as_str));
                    p.join("/")
                }
                Placement::Indexed(items) => {
                    let Some((first, rest)) = comps.split_first() else {
                        continue;
                    };
                    let item = first
                        .parse::<usize>()
                        .ok()
                        .and_then(|i| items.get(i))
                        .ok_or_else(|| invalid(format!("unexpected entry `{}`", raw.display())))?;
                    if !self.ignore.is_empty() {
                        let mut origin: Vec<&str> = parts(&item.origin).collect();
                        origin.extend(rest.iter().map(String::as_str));
                        if self.ignore.ignored(&origin.join("/")) {
                            continue;
                        }
                    }
                    item_root = rest.is_empty();
                    let mut p: Vec<&str> = parts(&item.dst).collect();
                    p.extend(rest.iter().map(String::as_str));
                    p.join("/")
                }
            };
            if path.is_empty() || path.split('/').count() > MAX_DEPTH {
                continue;
            }
            let (parent, name) = match path.rsplit_once('/') {
                Some((p, n)) => (p, n),
                None => ("", path.as_str()),
            };
            let dir = self.open_path(parent)?;
            let name = OsStr::new(name);
            let size = match velarx_wire::sparse::real_size(&mut entry)? {
                Some(real) => real,
                None => entry.header().entry_size().unwrap_or(0),
            };
            self.spend(size, 1)?;
            let h = entry.header();
            // (a directory copied is its content: the directory it goes to
            // keeps what the image has for it, else is made as a missing
            // parent is, as for a directory of the context)
            if item_root && h.entry_type().is_dir() {
                self.open_path(&path)?;
                continue;
            }
            let owner = keep_owners
                .then(|| Some((h.uid().ok()? as u32, h.gid().ok()? as u32)))
                .flatten();
            let mtime = h.mtime().unwrap_or(0).min(i64::MAX as u64) as i64;
            let mode = h.mode().unwrap_or(0o644) & 0o7777;
            let st = fake_stat(mode, mtime);
            let mut xattrs = Vec::new();
            if let Some(exts) = entry.pax_extensions()? {
                for ext in exts {
                    let ext = ext?;
                    if let Some(n) = ext.key_bytes().strip_prefix(b"SCHILY.xattr.") {
                        if copied_xattr(n) && ext.value_bytes().len() <= MAX_XATTR_VALUE {
                            xattrs.push((n.to_vec(), ext.value_bytes().to_vec()));
                        }
                    }
                }
            }
            let h = entry.header();
            match h.entry_type() {
                tar::EntryType::Directory => {
                    self.open_dir(dir.as_fd(), name, 0o700)?;
                    dirs.push((path.clone(), st, owner, xattrs));
                }
                tar::EntryType::Regular
                | tar::EntryType::Continuous
                | tar::EntryType::GNUSparse => {
                    remove_tree(dir.as_fd(), name)?;
                    let out = openat(
                        &dir,
                        name,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )?;
                    velarx_wire::sparse::copy(
                        &mut entry,
                        &mut std::fs::File::from(out.try_clone()?),
                        self.job.limits.max_bytes,
                    )?;
                    self.finish(out.as_fd(), &st, owner)?;
                    for (n, v) in &xattrs {
                        set_xattr(out.as_fd(), n, v)?;
                    }
                }
                tar::EntryType::Symlink => {
                    let target = entry
                        .link_name_bytes()
                        .ok_or_else(|| invalid(format!("the link `{path}` has no target")))?
                        .into_owned();
                    remove_tree(dir.as_fd(), name)?;
                    symlinkat(OsStr::from_bytes(&target), &dir, name)?;
                    self.finish_named(dir.as_fd(), name, &st, owner, false)?;
                }
                tar::EntryType::Link => {
                    let target = entry
                        .link_name()?
                        .ok_or_else(|| invalid(format!("the link `{path}` has no target")))?
                        .into_owned();
                    self.hard_link(&target, &place, dir.as_fd(), name)?;
                }
                tar::EntryType::Fifo => {
                    remove_tree(dir.as_fd(), name)?;
                    make_fifo(dir.as_fd(), name)?;
                    self.finish_named(dir.as_fd(), name, &st, owner, true)?;
                }
                // Devices are not created (see the worker).
                _ => {}
            }
        }
        for (path, st, owner, xattrs) in dirs.iter().rev() {
            // Replaced by a later entry: nothing to do.
            if let Ok(fd) = openat2_retry(
                self.root,
                path.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                BENEATH,
            ) {
                self.finish(fd.as_fd(), st, *owner)?;
                for (n, v) in xattrs {
                    set_xattr(fd.as_fd(), n, v)?;
                }
            }
        }
        Ok(())
    }

    /// A hard link to a regular file the archive extracted already.
    fn hard_link(
        &self,
        target: &Path,
        place: &Placement<'_>,
        dir: BorrowedFd<'_>,
        name: &OsStr,
    ) -> io::Result<()> {
        let mut comps: Vec<String> = Vec::new();
        for c in target.components() {
            match c {
                Component::Normal(n) => comps.push(n.to_string_lossy().into_owned()),
                Component::CurDir | Component::RootDir => {}
                _ => {
                    return Err(invalid(format!(
                        "invalid link target `{}`",
                        target.display()
                    )))
                }
            }
        }
        let path = match place {
            Placement::AsIs => comps.join("/"),
            Placement::Under(dst) => format!("{}/{}", dst.trim_start_matches('/'), comps.join("/")),
            Placement::Indexed(items) => {
                let item = comps
                    .first()
                    .and_then(|f| f.parse::<usize>().ok())
                    .and_then(|i| items.get(i))
                    .ok_or_else(|| {
                        invalid(format!("invalid link target `{}`", target.display()))
                    })?;
                let mut p: Vec<&str> = parts(&item.dst).collect();
                p.extend(comps[1..].iter().map(String::as_str));
                p.join("/")
            }
        };
        let (parent, base) = match path.trim_start_matches('/').rsplit_once('/') {
            Some((p, b)) => (p.to_string(), b.to_string()),
            None => (String::new(), path.trim_start_matches('/').to_string()),
        };
        let from = openat2_retry(
            self.root,
            if parent.is_empty() {
                "."
            } else {
                parent.as_str()
            },
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            BENEATH,
        )?;
        let st = statat(&from, base.as_str(), AtFlags::SYMLINK_NOFOLLOW)?;
        if kind(&st) != FileType::RegularFile {
            return Err(invalid(format!(
                "the hard link target `{}` is not a file",
                target.display()
            )));
        }
        remove_tree(dir, name)?;
        linkat(&from, base.as_str(), dir, name, AtFlags::empty())?;
        Ok(())
    }
}

fn fake_stat(mode: u32, mtime: i64) -> Stat {
    let mut st: Stat = velarx_sys::fs::zeroed_stat();
    st.st_mode = mode as _;
    st.st_mtime = mtime as _;
    st
}

/// Run a job: `dest` is the new directory, `source` the context directory
/// or the tar stream.  Whether a node of the context it copied changed since
/// `job.unchanged_since`.
pub fn run(
    job: &CopyJob,
    dest: BorrowedFd<'_>,
    source: OwnedFd,
    cancel: &Cancel,
) -> io::Result<bool> {
    let mut d = Dest {
        root: dest,
        job,
        ignore: Ignore::parse(&job.ignore.join("\n")),
        created: Default::default(),
        bytes: Default::default(),
        entries: Default::default(),
        cancel,
        changed: false,
        linked: Default::default(),
    };
    run_dest(&mut d, source)?;
    for (path, mtime) in d.created.iter().rev() {
        let fd = openat2_retry(
            dest,
            path.trim_start_matches('/'),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            BENEATH,
        )?;
        futimens(&fd, &stamp(*mtime, 0))?;
    }
    Ok(d.changed)
}

fn run_dest(d: &mut Dest<'_>, source: OwnedFd) -> io::Result<()> {
    let job = d.job;
    match job.source {
        Source::Unpack => {
            // A context may come compressed; the stream is a pipe: its head
            // is read and put back in front of the rest.
            let mut file = std::fs::File::from(source);
            let mut head = Vec::with_capacity(512);
            (&mut file).take(512).read_to_end(&mut head)?;
            let kind = archive_kind(&head).filter(|k| *k != "tar");
            let stream = io::Cursor::new(head).chain(file);
            match kind {
                Some(k) => d.extract(decompress(k, stream)?, Placement::AsIs, false),
                None => d.extract(stream, Placement::AsIs, false),
            }
        }
        Source::Tar => {
            for item in &job.items {
                let parent = item.dst.rsplit_once('/').map_or("", |(p, _)| p);
                d.open_path(parent)?;
            }
            // (the files of another stage or image keep their owners, as
            // buildah's and BuildKit's `COPY --from`)
            d.extract(
                std::fs::File::from(source),
                Placement::Indexed(&job.items),
                true,
            )
        }
        Source::Context => {
            let mut listed = Vec::new();
            let matches = context_matches(job, &d.ignore, source.as_fd(), &mut listed)?;
            let several = matches.iter().map(|(_, f)| f.len()).sum::<usize>() > 1;
            for (item, found) in matches {
                for rel in found {
                    copy_source(d, source.as_fd(), item, &rel, several)?;
                }
            }
            // (a match of a glob removed since the digest is not copied:
            // its directory says it)
            for dir in &listed {
                d.note_change(dir.as_fd())?;
            }
            Ok(())
        }
    }
}

/// The paths of the context that each item of a job copies.
fn context_matches<'a>(
    job: &'a CopyJob,
    ignore: &Ignore,
    root: BorrowedFd<'_>,
    listed: &mut Vec<OwnedFd>,
) -> io::Result<Vec<(&'a Item, Vec<String>)>> {
    let mut matches = Vec::new();
    for item in &job.items {
        let found = if has_glob(&item.src) {
            expand_glob(root, &item.src, listed)?
        } else {
            vec![parts(&item.src).collect::<Vec<_>>().join("/")]
        };
        // What the ignore file leaves out is not in the context.
        let found: Vec<String> = found
            .into_iter()
            .filter(|r| r.is_empty() || !ignore.ignored(r))
            .collect();
        if found.is_empty() {
            return Err(not_found(&item.src));
        }
        matches.push((item, found));
    }
    Ok(matches)
}

/// The digest of what a job copies from the context, before it is copied:
/// the paths each item matches and, for every node a copy reads, its path,
/// type, mode, xattrs and content or target.  What a copy leaves out (the
/// ignored paths) is not read; what it may take back from an ignored
/// directory (a `!` pattern) is, whole.  Equal digests and equal jobs make
/// copies that differ in their times at most (the owners are the job's,
/// not the context's): the build cache does not tell them apart, as it
/// does not for a copy's tree, and the context a client sends is a new
/// directory each time.
pub fn digest(job: &CopyJob, source: OwnedFd) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    if job.source != Source::Context {
        return Err(invalid("only the files of a context have a digest".into()));
    }
    let ignore = Ignore::parse(&job.ignore.join("\n"));
    let mut h = Digester {
        hasher: Sha256::new(),
        ignore: &ignore,
        buf: vec![0u8; 256 * 1024],
    };
    let root = source.as_fd();
    for (_, found) in context_matches(job, &ignore, root, &mut Vec::new())? {
        h.field(&(found.len() as u64).to_le_bytes());
        for rel in found {
            let src = openat2_retry(
                root,
                if rel.is_empty() { "." } else { rel.as_str() },
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                IN_ROOT,
            )?;
            let st = fstat(&src)?;
            h.node(&src, &Opener::InRoot(root, &rel), &st, &rel)?;
        }
    }
    Ok(format!("sha256:{}", hex::encode(h.hasher.finalize())))
}

/// The digest is a walk of the context: the state of a directory is its
/// path.
impl Visit for Digester<'_> {
    type Dir = String;

    fn enter(&mut self, dir: BorrowedFd<'_>, _: &[OsString], _: &mut String) -> io::Result<()> {
        self.xattrs(dir)
    }

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        child: &OsStr,
        _: &Stat,
        depth: usize,
        parent: &mut String,
    ) -> io::Result<Option<String>> {
        if depth + 1 > MAX_DEPTH {
            return Err(invalid(format!(
                "the tree is nested deeper than {MAX_DEPTH} directories"
            )));
        }
        let rel = parent.as_str();
        let n = child
            .to_str()
            .ok_or_else(|| invalid(format!("`{rel}/{}` is not UTF-8", child.to_string_lossy())))?;
        let p = if rel.is_empty() {
            n.to_string()
        } else {
            format!("{rel}/{n}")
        };
        let fd = openat(
            dir,
            child,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let cst = fstat(&fd)?;
        // As a copy: an ignored path is left out, but for a directory a `!`
        // pattern may take something back from.
        if self.ignore.ignored(&p)
            && !(kind(&cst) == FileType::Directory && self.ignore.may_take_back(&p))
        {
            return Ok(None);
        }
        self.head(&cst, &p);
        if kind(&cst) == FileType::Directory {
            return Ok(Some(p));
        }
        self.leaf(&fd, &Opener::At(dir, child), &cst)?;
        Ok(None)
    }

    fn exit(&mut self, _: BorrowedFd<'_>, _: &mut String) -> io::Result<()> {
        self.field(b"");
        Ok(())
    }
}

struct Digester<'a> {
    hasher: sha2::Sha256,
    ignore: &'a Ignore,
    buf: Vec<u8>,
}

impl Digester<'_> {
    /// Each field with its length: no two different walks hash the same.
    fn field(&mut self, b: &[u8]) {
        use sha2::Digest;
        self.hasher.update((b.len() as u64).to_le_bytes());
        self.hasher.update(b);
    }

    /// The node `src` (opened with `O_PATH`, seen as `st`) at `rel`: a
    /// directory is walked, with the digest of its entries after its own.
    fn node(&mut self, src: &OwnedFd, open: &Opener<'_>, st: &Stat, rel: &str) -> io::Result<()> {
        self.head(st, rel);
        if kind(st) == FileType::Directory {
            // (the attributes of a directory are those of its listing, the
            // walk's `enter`)
            Walk {
                max_depth: MAX_DEPTH + 1,
                sorted: true,
                skip_gone: false,
                lenient: false,
            }
            .run(open_listing(src, st)?, rel.to_string(), self)?;
            return Ok(());
        }
        self.leaf(src, open, st)
    }

    /// The path and the mode of a node.
    fn head(&mut self, st: &Stat, rel: &str) {
        self.field(rel.as_bytes());
        self.field(&st.st_mode.to_le_bytes());
    }

    /// The content or the target of a node that is no directory.
    fn leaf(&mut self, src: &OwnedFd, open: &Opener<'_>, st: &Stat) -> io::Result<()> {
        use sha2::Digest;
        match kind(st) {
            FileType::RegularFile => {
                let input = open.open(st)?;
                self.xattrs(input.as_fd())?;
                let size = st.st_size.max(0) as u64;
                self.field(&size.to_le_bytes());
                let mut file = std::fs::File::from(input).take(size);
                let mut read = 0u64;
                loop {
                    let n = file.read(&mut self.buf)?;
                    if n == 0 {
                        break;
                    }
                    self.hasher.update(&self.buf[..n]);
                    read += n as u64;
                }
                if read != size {
                    return Err(io::Error::other("a file changed while it was read"));
                }
            }
            FileType::Symlink => {
                let target = readlinkat(src, "", Vec::new())?;
                self.field(target.as_bytes());
            }
            _ => {}
        }
        Ok(())
    }

    fn xattrs(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let kept = kept_xattrs(fd)?;
        self.field(&(kept.len() as u64).to_le_bytes());
        for (name, value) in kept {
            self.field(&name);
            self.field(&value);
        }
        Ok(())
    }
}

/// The links the path `rel` of the context goes through, opened as links:
/// those of its components, those they point to, and so on, as its
/// resolution in the context (`IN_ROOT`) follows them.
fn links_on_path(root: BorrowedFd<'_>, rel: &str) -> rustix::io::Result<Vec<OwnedFd>> {
    let mut links = Vec::new();
    // (the components left, the next one last, and the part resolved,
    // which has no link)
    let mut rest: Vec<OsString> = parts(rel).map(OsString::from).collect();
    rest.reverse();
    let mut at = std::path::PathBuf::new();
    while let Some(c) = rest.pop() {
        let next = at.join(&c);
        let fd = openat2_retry(
            root,
            next.as_path(),
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            IN_ROOT,
        )?;
        if kind(&fstat(&fd)?) != FileType::Symlink {
            at = next;
            continue;
        }
        // (as many as the kernel follows)
        if links.len() == 40 {
            return Err(rustix::io::Errno::LOOP);
        }
        let target = OsString::from_vec(readlinkat(&fd, "", Vec::new())?.into_bytes());
        links.push(fd);
        let target = Path::new(&target);
        if target.has_root() {
            at = std::path::PathBuf::new();
        }
        for c in target.components().rev() {
            match c {
                Component::Normal(n) => rest.push(n.to_os_string()),
                Component::ParentDir => rest.push("..".into()),
                _ => {}
            }
        }
    }
    Ok(links)
}

fn copy_source(
    d: &mut Dest<'_>,
    root: BorrowedFd<'_>,
    item: &Item,
    rel: &str,
    several: bool,
) -> io::Result<()> {
    let clean = format!("/{}", parts(&item.dst).collect::<Vec<_>>().join("/"));
    let item = &Item {
        dst: clean,
        ..item.clone()
    };
    let src = openat2_retry(
        root,
        if rel.is_empty() { "." } else { rel },
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        IN_ROOT,
    )
    .map_err(|e| match e {
        rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR => not_found(&item.src),
        e => e.into(),
    })?;
    let st = fstat(&src)?;
    // The links the path of the source goes through are nodes of the copy
    // too: a retargeted one changes what the path names, whatever the
    // times of what it names.
    if d.job.unchanged_since.is_some() && !d.changed && !rel.is_empty() {
        match links_on_path(root, rel) {
            Ok(links) => {
                for link in &links {
                    d.note_change(link.as_fd())?;
                }
            }
            // (a path that resolved when the source was opened and no
            // longer does changed meanwhile)
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
                d.changed = true
            }
            Err(e) => return Err(e.into()),
        }
    }
    let open = Opener::InRoot(root, rel);
    let mut dest_dir = item.dest_dir || several;
    // `COPY --parents`: the path of the source goes below the destination
    let placed;
    let item = match item.pivot {
        Some(pivot) => {
            let kept: Vec<&str> = parts(rel).skip(pivot).collect();
            if kept.is_empty() {
                item
            } else {
                dest_dir = false;
                placed = Item {
                    dst: format!("{}/{}", item.dst.trim_end_matches('/'), kept.join("/")),
                    ..item.clone()
                };
                &placed
            }
        }
        None => item,
    };
    if kind(&st) == FileType::Directory {
        // The content of a directory goes into the destination, which keeps
        // what the image has for it, else is made as a missing parent is:
        // the owner, mode and times of the source directory are not its,
        // as buildah's (`COPY dir /etc` left /etc with the mode of dir).
        if parts(&item.dst).next().is_none() {
            return d.copy_contents(&src, &st, Some(rel), d.root);
        }
        let out = d.open_path(&item.dst)?;
        return d.copy_contents(&src, &st, Some(rel), out.as_fd());
    }
    if d.job.add && kind(&st) == FileType::RegularFile {
        let file = std::fs::File::from(open.open(&st)?);
        let mut head = [0u8; 512];
        let n = std::os::unix::fs::FileExt::read_at(&file, &mut head, 0)?;
        if let Some(k) = archive_kind(&head[..n]) {
            d.open_path(&item.dst)?;
            d.extract(decompress(k, file)?, Placement::Under(&item.dst), true)?;
            return d.note_change(src.as_fd());
        }
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    let target = if dest_dir {
        format!("{}/{base}", item.dst.trim_end_matches('/'))
    } else {
        item.dst.clone()
    };
    let (parent, name) = target.rsplit_once('/').unwrap_or(("", &target));
    if name.is_empty() {
        return Err(invalid(format!("invalid destination `{}`", item.dst)));
    }
    let out = d.open_path(parent)?;
    let node = Node {
        src: &src,
        open: &open,
        st: &st,
        rel: Some(rel),
    };
    d.copy_node(node, out.as_fd(), OsStr::new(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    fn open(p: &Path) -> OwnedFd {
        openat(
            rustix::fs::CWD,
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn job(items: &[(&str, &str, bool)]) -> CopyJob {
        CopyJob {
            source: Source::Context,
            items: items
                .iter()
                .map(|(s, d, dir)| Item {
                    src: s.to_string(),
                    dst: d.to_string(),
                    dest_dir: *dir,
                    ..Default::default()
                })
                .collect(),
            chown: None,
            chmod: None,
            parents: Vec::new(),
            ignore: Vec::new(),
            add: false,
            limits: Default::default(),
            digest: false,
            unchanged_since: None,
        }
    }

    struct Setup {
        _tmp: tempfile::TempDir,
        ctx: std::path::PathBuf,
        out: std::path::PathBuf,
        outside: std::path::PathBuf,
    }

    fn setup() -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = tmp.path().join("ctx");
        let out = tmp.path().join("out");
        let outside = tmp.path().join("outside");
        for d in [&ctx, &out, &outside] {
            std::fs::create_dir(d).unwrap();
        }
        std::fs::write(outside.join("secret"), "SECRET").unwrap();
        std::fs::create_dir_all(ctx.join("a/sub")).unwrap();
        std::fs::write(ctx.join("a/one.txt"), "1").unwrap();
        std::fs::write(ctx.join("a/sub/two.log"), "2").unwrap();
        std::fs::write(ctx.join("top.txt"), "top").unwrap();
        std::fs::set_permissions(ctx.join("top.txt"), std::fs::Permissions::from_mode(0o751))
            .unwrap();
        symlink(&outside, ctx.join("link")).unwrap();
        symlink("one.txt", ctx.join("a/rel")).unwrap();
        Setup {
            _tmp: tmp,
            ctx,
            out,
            outside,
        }
    }

    fn run_job(s: &Setup, j: &CopyJob) -> io::Result<()> {
        let out = open(&s.out);
        run(j, out.as_fd(), open(&s.ctx), &Cancel::default()).map(drop)
    }

    #[test]
    fn test_copy_files_and_directories() {
        let s = setup();
        for j in [
            ("a", "/app", false),
            ("top.txt", "/bin/", true),
            ("top.txt", "/x/renamed", false),
        ] {
            run_job(&s, &job(&[j])).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(s.out.join("app/one.txt")).unwrap(),
            "1"
        );
        assert_eq!(
            std::fs::read_to_string(s.out.join("app/sub/two.log")).unwrap(),
            "2"
        );
        assert_eq!(
            std::fs::read_link(s.out.join("app/rel")).unwrap(),
            Path::new("one.txt")
        );
        let m = std::fs::metadata(s.out.join("bin/top.txt")).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o751);
        assert_eq!(
            m.mtime(),
            std::fs::metadata(s.ctx.join("top.txt")).unwrap().mtime()
        );
        assert_eq!(
            std::fs::read_to_string(s.out.join("x/renamed")).unwrap(),
            "top"
        );
    }

    #[test]
    fn the_links_of_a_file_copied_by_one_job_stay_links() {
        let s = setup();
        std::fs::hard_link(s.ctx.join("a/one.txt"), s.ctx.join("a/sub/also")).unwrap();
        std::fs::hard_link(s.ctx.join("a/one.txt"), s.ctx.join("again")).unwrap();
        run_job(&s, &job(&[("a", "/app/", true), ("again", "/app/", true)])).unwrap();
        let ino = |p: &str| std::fs::metadata(s.out.join(p)).unwrap().ino();
        assert_eq!(ino("app/one.txt"), ino("app/sub/also"));
        assert_eq!(ino("app/one.txt"), ino("app/again"));
        assert_ne!(ino("app/one.txt"), ino("app/sub/two.log"));
        // (a copy replaced since is not linked to)
        std::fs::create_dir(s.ctx.join("other")).unwrap();
        std::fs::write(s.ctx.join("other/one.txt"), "other").unwrap();
        run_job(
            &s,
            &job(&[
                ("a", "/b/", true),
                ("other/one.txt", "/b/", true),
                ("again", "/b/", true),
            ]),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(s.out.join("b/one.txt")).unwrap(),
            "other"
        );
        assert_eq!(std::fs::read_to_string(s.out.join("b/again")).unwrap(), "1");
        assert_ne!(ino("b/one.txt"), ino("b/again"));
    }

    #[test]
    fn test_symlinks_do_not_lead_out_of_the_context() {
        let s = setup();
        let err = run_job(&s, &job(&[("link/secret", "/leak", false)])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert!(run_job(&s, &job(&[("../outside/secret", "/leak", false)])).is_err());
        assert_eq!(
            run_job(&s, &job(&[("link", "/l", false)]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        // A link given as the source is resolved in the context: `/` is
        // the root of the context, not the one of the host.
        symlink("/", s.ctx.join("root")).unwrap();
        run_job(&s, &job(&[("root", "/l", false)])).unwrap();
        assert!(s.out.join("l/top.txt").exists());
        assert!(!s.out.join("l/etc").exists());
    }

    #[test]
    fn test_nothing_is_written_through_a_link() {
        let s = setup();
        // A first source makes /dst/etc a link out; the second writes
        // /dst/etc/victim: the link is replaced by a directory.
        std::fs::create_dir_all(s.ctx.join("p/etc")).unwrap();
        symlink(&s.outside, s.ctx.join("q")).unwrap();
        std::fs::create_dir_all(s.ctx.join("r/etc")).unwrap();
        std::fs::write(s.ctx.join("r/etc/victim"), "v").unwrap();
        std::fs::remove_dir(s.ctx.join("p/etc")).unwrap();
        symlink(&s.outside, s.ctx.join("p/etc")).unwrap();
        run_job(&s, &job(&[("p/", "/dst/", true), ("r/", "/dst/", true)])).unwrap();
        assert!(!s.outside.join("victim").exists());
        let m = std::fs::symlink_metadata(s.out.join("dst/etc")).unwrap();
        assert!(m.is_dir());
        assert_eq!(
            std::fs::read_to_string(s.out.join("dst/etc/victim")).unwrap(),
            "v"
        );
    }

    #[test]
    fn test_globs_ignore_and_modes() {
        let s = setup();
        let mut j = job(&[("a/*.txt", "/g/", true), ("a/sub", "/s", false)]);
        j.ignore = vec!["**/*.log".into()];
        j.chmod = Some(0o600);
        run_job(&s, &j).unwrap();
        assert!(s.out.join("g/one.txt").exists());
        assert!(!s.out.join("s/two.log").exists());
        let m = std::fs::metadata(s.out.join("g/one.txt")).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o600);
        assert_eq!(
            run_job(&s, &job(&[("nomatch*", "/x", false)]))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn test_parents_keep_the_path_of_the_source_from_the_mark() {
        let s = setup();
        let mut j = job(&[
            ("a/sub/two.log", "/p1", true),
            ("a/sub/two.log", "/p2", true),
            ("a/*.txt", "/p3", true),
        ]);
        j.items[0].pivot = Some(0);
        j.items[1].pivot = Some(1);
        j.items[2].pivot = Some(1);
        run_job(&s, &j).unwrap();
        assert!(s.out.join("p1/a/sub/two.log").exists());
        assert!(s.out.join("p2/sub/two.log").exists());
        assert!(s.out.join("p3/one.txt").exists());
        let mut j = job(&[("a", "/d", true)]);
        j.items[0].pivot = Some(0);
        run_job(&s, &j).unwrap();
        assert!(s.out.join("d/a/sub/two.log").exists());
    }

    #[test]
    fn test_excluded_files_of_an_archive_are_left_out() {
        let s = setup();
        let mut tar = tar::Builder::new(Vec::new());
        for (path, data) in [
            ("0/one.txt", "1"),
            ("0/sub/two.log", "2"),
            ("0/sub/x.txt", "3"),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            tar.append_data(&mut h, path, data.as_bytes()).unwrap();
        }
        let bytes = tar.into_inner().unwrap();
        let mut j = job(&[("", "/t", false)]);
        j.source = Source::Tar;
        j.items[0].origin = "src/dir".into();
        j.ignore = vec!["src/dir/sub/*.log".into(), "src/dir/one.txt".into()];
        let out = open(&s.out);
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        std::fs::File::from(w).write_all(&bytes).unwrap();
        run(&j, out.as_fd(), r, &Cancel::default()).unwrap();
        assert!(!s.out.join("t/one.txt").exists());
        assert!(!s.out.join("t/sub/two.log").exists());
        assert!(s.out.join("t/sub/x.txt").exists());
    }

    #[test]
    fn test_parents_get_the_attributes_of_the_image() {
        let s = setup();
        let mut j = job(&[("top.txt", "/usr/local/bin/", true)]);
        j.parents = vec![ParentDir {
            path: "/usr".into(),
            mode: 0o711,
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            mtime: 1_000_000,
        }];
        run_job(&s, &j).unwrap();
        let m = std::fs::metadata(s.out.join("usr")).unwrap();
        assert_eq!((m.mode() & 0o7777, m.mtime()), (0o711, 1_000_000));
        assert_eq!(
            std::fs::metadata(s.out.join("usr/local")).unwrap().mode() & 0o7777,
            0o755
        );
    }

    fn tar_of(entries: &[(&str, tar::EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, t, data, link) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*t);
            h.set_mode(if *t == tar::EntryType::Directory {
                0o750
            } else {
                0o640
            });
            h.set_mtime(1_600_000_000);
            h.set_size(data.len() as u64);
            match link {
                Some(l) => b.append_link(&mut h, name, l).unwrap(),
                None => b.append_data(&mut h, name, *data).unwrap(),
            }
        }
        b.into_inner().unwrap()
    }

    fn pipe_of(data: Vec<u8>) -> OwnedFd {
        let (r, mut w) = std::io::pipe().unwrap();
        std::thread::spawn(move || {
            let _ = io::Write::write_all(&mut w, &data);
        });
        r.into()
    }

    #[test]
    fn test_add_extracts_archives_and_tar_streams_are_confined() {
        let s = setup();
        let tar = tar_of(&[
            ("d/", tar::EntryType::Directory, b"", None),
            ("d/f", tar::EntryType::Regular, b"inner", None),
            ("d/h", tar::EntryType::Link, b"", Some("d/f")),
            ("d/l", tar::EntryType::Symlink, b"", Some("/etc/passwd")),
        ]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        io::Write::write_all(&mut gz, &tar).unwrap();
        std::fs::write(s.ctx.join("arch.tar.gz"), gz.finish().unwrap()).unwrap();
        let mut j = job(&[("arch.tar.gz", "/ex", false)]);
        j.add = true;
        run_job(&s, &j).unwrap();
        assert_eq!(
            std::fs::read_to_string(s.out.join("ex/d/f")).unwrap(),
            "inner"
        );
        assert_eq!(std::fs::metadata(s.out.join("ex/d/h")).unwrap().nlink(), 2);
        assert_eq!(
            std::fs::read_link(s.out.join("ex/d/l")).unwrap(),
            Path::new("/etc/passwd")
        );
        assert_eq!(
            std::fs::metadata(s.out.join("ex/d/f")).unwrap().mode() & 0o7777,
            0o640
        );

        // A tar stream: the index names the destination.  A link planted
        // by an entry is not written through, `..` is refused.
        let out2 = tempfile::tempdir().unwrap();
        let tar = tar_of(&[
            (
                "0",
                tar::EntryType::Symlink,
                b"",
                Some(s.outside.to_str().unwrap()),
            ),
            ("1/f", tar::EntryType::Regular, b"x", None),
        ]);
        let j = CopyJob {
            source: Source::Tar,
            items: vec![
                Item {
                    src: String::new(),
                    dst: "/esc".into(),
                    dest_dir: false,
                    ..Default::default()
                },
                Item {
                    src: String::new(),
                    dst: "/esc".into(),
                    dest_dir: false,
                    ..Default::default()
                },
            ],
            ..job(&[])
        };
        run(
            &j,
            open(out2.path()).as_fd(),
            pipe_of(tar),
            &Cancel::default(),
        )
        .unwrap();
        assert!(!s.outside.join("f").exists());
        assert_eq!(
            std::fs::read_to_string(out2.path().join("esc/f")).unwrap(),
            "x"
        );
        // The tar crate refuses to write `..`: the header is made by hand.
        let mut h = tar::Header::new_gnu();
        h.as_gnu_mut().unwrap().name[..4].copy_from_slice(b"../x");
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(1);
        h.set_cksum();
        let mut b = tar::Builder::new(Vec::new());
        b.append(&h, &b"x"[..]).unwrap();
        let j = CopyJob {
            source: Source::Unpack,
            ..job(&[])
        };
        let err = run(
            &j,
            open(out2.path()).as_fd(),
            pipe_of(b.into_inner().unwrap()),
            &Cancel::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid path"), "{err}");
    }

    /// A context with a file that has holes (the tar of the command line
    /// has it as a sparse entry) is unpacked whole, the holes kept; a file
    /// that is larger than the limits allow is refused.
    #[test]
    fn test_unpack_of_a_sparse_file_keeps_it_and_its_holes() {
        let src = tempfile::tempdir().unwrap();
        let f = src.path().join("big");
        let mut file = std::fs::File::create(&f).unwrap();
        file.set_len(32 << 20).unwrap();
        io::Seek::seek(&mut file, io::SeekFrom::Start(16 << 20)).unwrap();
        io::Write::write_all(&mut file, b"middle").unwrap();
        file.set_len(32 << 20).unwrap();
        std::fs::write(src.path().join("hole"), b"").unwrap();
        std::fs::File::options()
            .write(true)
            .open(src.path().join("hole"))
            .unwrap()
            .set_len(1 << 20)
            .unwrap();
        let mut b = tar::Builder::new(Vec::new());
        b.append_path_with_name(&f, "d/big").unwrap();
        b.append_path_with_name(src.path().join("hole"), "hole")
            .unwrap();
        let tar = b.into_inner().unwrap();
        assert_eq!(tar[156], b'S', "the tar has a sparse entry");
        let j = CopyJob {
            source: Source::Unpack,
            ..job(&[])
        };
        let out = tempfile::tempdir().unwrap();
        run(
            &j,
            open(out.path()).as_fd(),
            pipe_of(tar.clone()),
            &Cancel::default(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(out.path().join("d/big")).unwrap(),
            std::fs::read(&f).unwrap()
        );
        let m = std::fs::metadata(out.path().join("d/big")).unwrap();
        assert_eq!(m.len(), 32 << 20);
        assert!(m.blocks() * 512 < 1 << 20, "{} blocks", m.blocks());
        let m = std::fs::metadata(out.path().join("hole")).unwrap();
        assert_eq!((m.len(), m.blocks()), (1 << 20, 0));

        let mut j = j;
        j.limits.max_bytes = 16 << 20;
        let out = tempfile::tempdir().unwrap();
        let err = run(
            &j,
            open(out.path()).as_fd(),
            pipe_of(tar),
            &Cancel::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("to write: refused"), "{err}");
    }

    fn digest_of(s: &Setup, j: &CopyJob) -> io::Result<String> {
        digest(j, open(&s.ctx))
    }

    /// A copy says whether a node it copied (a file, a link, a directory's
    /// listing) had its status changed at or after `unchanged_since`.
    #[test]
    fn a_copy_says_whether_its_sources_changed_since() {
        let s = setup();
        let ctime = |p: &str| {
            let m = std::fs::symlink_metadata(s.ctx.join(p)).unwrap();
            (m.ctime(), m.ctime_nsec())
        };
        let copy = |since, src: &str| {
            let out = tempfile::tempdir_in(&s.out).unwrap();
            let j = CopyJob {
                unchanged_since: since,
                ..job(&[(src, "/dst", true)])
            };
            run(
                &j,
                open(out.path()).as_fd(),
                open(&s.ctx),
                &Cancel::default(),
            )
            .unwrap()
        };
        let newest = ["a", "a/sub", "a/one.txt", "a/sub/two.log", "a/rel"]
            .map(ctime)
            .into_iter()
            .max()
            .unwrap();
        assert!(!copy(None, "a"));
        assert!(!copy(Some((newest.0 + 1, 0)), "a"));
        assert!(copy(Some(newest), "a"));
        // a file written, a name removed from a directory
        std::fs::write(s.ctx.join("a/sub/two.log"), "changed").unwrap();
        assert!(copy(Some(ctime("a/sub/two.log")), "a"));
        std::fs::remove_file(s.ctx.join("a/sub/two.log")).unwrap();
        assert!(copy(Some(ctime("a/sub")), "a"));
        // (a link is a node too)
        assert!(copy(Some(ctime("a/rel")), "a/rel"));
    }

    /// The links a source path goes through are nodes of the copy: those of
    /// its components (a link to a directory), those they point to (a
    /// chain, an absolute link resolved in the context, a `..` that cannot
    /// leave it), each once as the resolution follows it.
    #[test]
    fn the_links_of_a_source_path_are_nodes_of_its_copy() {
        use std::os::unix::fs::MetadataExt;
        let s = setup();
        symlink("a", s.ctx.join("d")).unwrap();
        symlink("/a/l2", s.ctx.join("a/l1")).unwrap();
        symlink("../../../a/rel", s.ctx.join("a/l2")).unwrap();
        symlink("nothing", s.ctx.join("a/gone")).unwrap();
        let ino = |p: &str| std::fs::symlink_metadata(s.ctx.join(p)).unwrap().ino();
        let links = |rel: &str| {
            links_on_path(open(&s.ctx).as_fd(), rel).map(|l| {
                l.iter()
                    .map(|f| fstat(f).unwrap().st_ino)
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            links("d/l1").unwrap(),
            ["d", "a/l1", "a/l2", "a/rel"].map(ino)
        );
        assert!(links("a/one.txt").unwrap().is_empty());
        assert_eq!(links("d/sub/two.log").unwrap(), [ino("d")]);
        // (a dangling link, a link out of the context: no source)
        assert_eq!(links("a/gone").unwrap_err(), rustix::io::Errno::NOENT);
        assert_eq!(links("link").unwrap_err(), rustix::io::Errno::NOENT);
        // a copy notes each: the newest of them is a change
        let newest = ["d", "a/l1", "a/l2", "a/rel"]
            .map(|p| {
                let m = std::fs::symlink_metadata(s.ctx.join(p)).unwrap();
                (m.ctime(), m.ctime_nsec())
            })
            .into_iter()
            .max()
            .unwrap();
        let copy = |since, src: &str| {
            let out = tempfile::tempdir_in(&s.out).unwrap();
            let j = CopyJob {
                unchanged_since: Some(since),
                ..job(&[(src, "/dst", true)])
            };
            run(
                &j,
                open(out.path()).as_fd(),
                open(&s.ctx),
                &Cancel::default(),
            )
            .unwrap()
        };
        assert!(copy(newest, "d/l1"));
        assert!(!copy((newest.0 + 1, 0), "d/l1"));
        // (and a directory a glob listed: a match removed is a change)
        let m = std::fs::symlink_metadata(s.ctx.join("a")).unwrap();
        assert!(copy((m.ctime(), m.ctime_nsec()), "a/*.txt"));
    }

    /// The digest is what the copy reads: the same files (whatever their
    /// times) the same digest, another content, mode, name or link target
    /// another one.
    #[test]
    fn the_digest_follows_what_is_copied() {
        let s = setup();
        let j = job(&[("a", "/dst", false)]);
        let d = digest_of(&s, &j).unwrap();
        assert!(d.parse::<velarx_types::digest::Digest>().is_ok());
        std::fs::File::options()
            .write(true)
            .open(s.ctx.join("a/one.txt"))
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        assert_eq!(digest_of(&s, &j).unwrap(), d);
        // Not copied: no change.
        std::fs::write(s.ctx.join("top.txt"), "other").unwrap();
        assert_eq!(digest_of(&s, &j).unwrap(), d);

        let changes: [&dyn Fn(); 4] = [
            &|| std::fs::write(s.ctx.join("a/one.txt"), "x").unwrap(),
            &|| {
                std::fs::set_permissions(
                    s.ctx.join("a/one.txt"),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap()
            },
            &|| std::fs::rename(s.ctx.join("a/one.txt"), s.ctx.join("a/1.txt")).unwrap(),
            &|| {
                std::fs::remove_file(s.ctx.join("a/rel")).unwrap();
                symlink("1.txt", s.ctx.join("a/rel")).unwrap();
            },
        ];
        let mut seen = vec![d];
        for change in changes {
            change();
            let d = digest_of(&s, &j).unwrap();
            assert!(!seen.contains(&d));
            seen.push(d);
        }
    }

    /// What the ignore file leaves out does not count, but for what a `!`
    /// pattern may take back; a missing source is an error, as in a copy.
    #[test]
    fn the_digest_leaves_out_what_is_ignored() {
        let s = setup();
        let mut j = job(&[(".", "/dst", true)]);
        j.ignore = vec!["a/sub".into()];
        let d = digest_of(&s, &j).unwrap();
        std::fs::write(s.ctx.join("a/sub/two.log"), "changed").unwrap();
        assert_eq!(digest_of(&s, &j).unwrap(), d);

        j.ignore = vec!["a/sub".into(), "!a/sub/two.log".into()];
        let d = digest_of(&s, &j).unwrap();
        std::fs::write(s.ctx.join("a/sub/two.log"), "again").unwrap();
        assert_ne!(digest_of(&s, &j).unwrap(), d);

        assert!(digest_of(&s, &job(&[("nothere", "/dst", false)])).is_err());
        assert!(digest_of(&s, &job(&[("*.none", "/dst", false)])).is_err());
    }

    /// The paths a glob matches are part of the digest.
    #[test]
    fn the_digest_of_a_glob() {
        let s = setup();
        let j = job(&[("a/*.txt", "/dst/", true)]);
        let d = digest_of(&s, &j).unwrap();
        std::fs::write(s.ctx.join("a/three.txt"), "3").unwrap();
        assert_ne!(digest_of(&s, &j).unwrap(), d);
    }
}
