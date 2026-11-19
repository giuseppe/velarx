// SPDX-License-Identifier: Apache-2.0
//! The root file system of a container made from the layers of its image:
//! their tables of contents merged (`MergedTree`: whiteouts and opaque
//! directories applied, hard links resolved) and written as a directory with
//! the objects of the store (`from_merged`), the ids of a user namespace given
//! as the files are made, with hard links, holes and extended attributes.
//!
//! The data of a regular file is copied the cheapest way the file system has:
//! a reflink (`FICLONE`), else `copy_file_range`, else read and write; the
//! holes of the source stay holes.  The source is an object of the store
//! named by its digest, never a tree of the image, so nothing of the image is
//! followed; in the destination every directory and file is made by this walk
//! with `O_EXCL`/`O_NOFOLLOW` calls relative to the descriptor of its
//! directory (which this walk made and opened without following a link), and
//! the attributes are set through descriptors, so that the content of an
//! image cannot make a copy write outside of its destination.
//!
//! Nothing here knows what a driver is: the arguments are descriptors, tables
//! of contents, the store and the translation of ids.

use rustix::fd::{AsFd, BorrowedFd};
use rustix::fs::{
    fchmod, fchown, linkat, mkdirat, mknodat, openat, statat, symlinkat, utimensat, AtFlags,
    FileType, Mode, OFlags, Stat, Timespec, Timestamps,
};
use rustix::fs::{Gid, Uid};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::warn;
use velarx_base::walk::Cursor;
use velarx_fuse::IdTranslate;
use velarx_fuse::MergedTree;
use velarx_storage::{FileStore, Toc, TocEntry, TocEntryType, VerityMode};

/// How the data of a file was copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The file system shares the blocks (`FICLONE`).
    Reflink,
    /// The kernel copies the ranges (`copy_file_range`).
    Range,
    /// Read and write.
    Plain,
}

/// A fault a test injects: the error a method fails with, so that the one
/// below it is used.
pub type Fault = Arc<dyn Fn(Method) -> Option<rustix::io::Errno> + Send + Sync>;

/// The files copied by each method.
#[derive(Debug, Default)]
pub struct Counts {
    pub reflink: AtomicU64,
    pub range: AtomicU64,
    pub plain: AtomicU64,
}

impl Counts {
    /// (reflinked, ranged, plain)
    pub fn get(&self) -> (u64, u64, u64) {
        (
            self.reflink.load(Ordering::Relaxed),
            self.range.load(Ordering::Relaxed),
            self.plain.load(Ordering::Relaxed),
        )
    }
}

/// What copies the data of files: it remembers that a file system has no
/// reflinks or no `copy_file_range` (the next file does not ask again).
pub struct Copier {
    fault: Option<Fault>,
    reflink: AtomicBool,
    range: AtomicBool,
    pub counts: Counts,
    ignore_chown: bool,
    /// The SELinux label of every file the copy makes (`security.selinux`,
    /// set through the descriptor of the file as it is made): the files of an
    /// image mounted in a container, whose copy the engine cannot label
    /// afterwards.
    label: Option<Vec<u8>>,
    skipped_attrs: AtomicU64,
    skipped_nodes: AtomicU64,
}

impl Default for Copier {
    fn default() -> Self {
        Self::new()
    }
}

/// The most one `copy_file_range` call is asked for.
const RANGE_CHUNK: usize = 1 << 30;

fn is_unsupported(e: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    matches!(e, Errno::OPNOTSUPP | Errno::XDEV | Errno::NOSYS)
}

impl Copier {
    pub fn new() -> Self {
        Self {
            fault: None,
            reflink: AtomicBool::new(true),
            range: AtomicBool::new(true),
            counts: Counts::default(),
            ignore_chown: false,
            label: None,
            skipped_attrs: AtomicU64::new(0),
            skipped_nodes: AtomicU64::new(0),
        }
    }

    /// A copier that leaves the files with the owner of the process when it
    /// may not give them the one they have (`EPERM`, `EINVAL`: a process that
    /// is neither root nor in a user namespace that maps the id), as
    /// containers-storage's `ignore_chown_errors`.
    pub fn ignoring_chown_errors(mut self, ignore: bool) -> Self {
        self.ignore_chown = ignore;
        self
    }

    /// A copier that gives every file it makes the SELinux label `label`
    /// (none: the files keep what the image says).  A file system that has no
    /// SELinux attributes is left as it is; any other refusal fails the copy,
    /// since a file the container cannot read is worse than no container.
    pub fn labeling(mut self, label: Option<&str>) -> Self {
        self.label = label.map(|l| l.as_bytes().to_vec());
        self
    }

    /// Whether the files are labelled by this copier.
    pub fn labels(&self) -> bool {
        self.label.is_some()
    }

    fn chown_failed(&self, e: rustix::io::Errno) -> bool {
        self.ignore_chown && matches!(e, rustix::io::Errno::PERM | rustix::io::Errno::INVAL)
    }

    /// A copier whose methods fail as `fault` says (for tests).
    pub fn with_fault(fault: Fault) -> Self {
        Self {
            fault: Some(fault),
            ..Self::new()
        }
    }

    fn faulted(&self, m: Method) -> Option<rustix::io::Errno> {
        self.fault.as_ref().and_then(|f| f(m))
    }

    /// Whether the file system takes reflinks (as far as it is known).
    pub fn reflinks(&self) -> bool {
        self.reflink.load(Ordering::Relaxed)
    }

    /// Copy the first `len` bytes of `src` to the empty file `dst`, with
    /// its holes, by the first method that works.
    pub fn data(&self, src: &File, dst: &File, len: u64) -> io::Result<Method> {
        if len == 0 {
            return Ok(Method::Plain);
        }
        if self.reflink.load(Ordering::Relaxed) {
            let r = match self.faulted(Method::Reflink) {
                Some(e) => Err(e),
                None => rustix::fs::ioctl_ficlone(dst, src),
            };
            match r {
                Ok(()) => {
                    self.counts.reflink.fetch_add(1, Ordering::Relaxed);
                    return Ok(Method::Reflink);
                }
                Err(e) if is_unsupported(e) => self.reflink.store(false, Ordering::Relaxed),
                Err(_) => {}
            }
        }
        let mut ranged = true;
        let mut off = 0u64;
        while off < len {
            let from = match rustix::fs::seek(src, rustix::fs::SeekFrom::Data(off)) {
                Ok(d) => d,
                // (no data after the offset: the rest is a hole)
                Err(rustix::io::Errno::NXIO) => break,
                // (a file system that does not say: all of it is data)
                Err(_) => off,
            };
            let to =
                rustix::fs::seek(src, rustix::fs::SeekFrom::Hole(from)).map_or(len, |h| h.min(len));
            if from >= to {
                break;
            }
            ranged &= self.range_of(src, dst, from, to - from)?;
            off = to;
        }
        dst.set_len(len)?;
        let method = if ranged && self.range.load(Ordering::Relaxed) {
            self.counts.range.fetch_add(1, Ordering::Relaxed);
            Method::Range
        } else {
            self.counts.plain.fetch_add(1, Ordering::Relaxed);
            Method::Plain
        };
        Ok(method)
    }

    /// Copy `n` bytes at `start`; true when the kernel did all of it.
    fn range_of(&self, src: &File, dst: &File, start: u64, n: u64) -> io::Result<bool> {
        let (mut off, end) = (start, start + n);
        if self.range.load(Ordering::Relaxed) {
            while off < end {
                let want = (end - off).min(RANGE_CHUNK as u64) as usize;
                let (mut from, mut to) = (off, off);
                let r = match self.faulted(Method::Range) {
                    Some(e) => Err(e),
                    None => {
                        rustix::fs::copy_file_range(src, Some(&mut from), dst, Some(&mut to), want)
                    }
                };
                match r {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "a file is shorter than it was",
                        ))
                    }
                    Ok(done) => off += done as u64,
                    Err(e) => {
                        if is_unsupported(e) {
                            self.range.store(false, Ordering::Relaxed);
                        }
                        break;
                    }
                }
            }
            if off == end {
                return Ok(true);
            }
        }
        let mut buf = vec![0u8; 1 << 20];
        while off < end {
            let want = ((end - off) as usize).min(buf.len());
            let got = src.read_at(&mut buf[..want], off)?;
            if got == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "a file is shorter than it was",
                ));
            }
            dst.write_all_at(&buf[..got], off)?;
            off += got as u64;
        }
        Ok(false)
    }

    /// The nodes and attributes that could not be copied here (a device in a
    /// layer without privilege, an attribute the file system refuses).
    pub fn skipped(&self) -> (u64, u64) {
        (
            self.skipped_nodes.load(Ordering::Relaxed),
            self.skipped_attrs.load(Ordering::Relaxed),
        )
    }

    fn skip_attr(&self, name: &[u8], path: &str, why: rustix::io::Errno) {
        if self.skipped_attrs.fetch_add(1, Ordering::Relaxed) == 0 {
            warn!(
                "vfs: the attribute {} of {path} is not set ({why}); the other attributes the file system refuses are skipped without a message",
                String::from_utf8_lossy(name)
            );
        }
    }

    fn skip_node(&self, path: &str, why: rustix::io::Errno) {
        if self.skipped_nodes.fetch_add(1, Ordering::Relaxed) == 0 {
            warn!(
                "vfs: {path} is a device that cannot be made here ({why}); the others are skipped without a message"
            );
        }
    }
}

// the attributes of an entry

/// What the metadata of an entry is made of: owner, mode, times and
/// attributes.
struct Meta<'a> {
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: (i64, u32),
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    path: &'a str,
}

fn timestamps((sec, nsec): (i64, u32)) -> Timestamps {
    let t = Timespec {
        tv_sec: sec,
        tv_nsec: nsec as _,
    };
    Timestamps {
        last_access: t,
        last_modification: t,
    }
}

/// The owner must be one a file can have (`u32::MAX` is "no change").
fn owner(uid: u32, gid: u32, path: &str) -> io::Result<(Uid, Gid)> {
    if uid == u32::MAX || gid == u32::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("the owner {uid}:{gid} of {path} is not an id a file can have"),
        ));
    }
    Ok((Uid::from_raw_unchecked(uid), Gid::from_raw_unchecked(gid)))
}

fn chown_error(e: rustix::io::Errno, uid: u32, gid: u32, path: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{path} cannot be given the owner {uid}:{gid} ({e}): the id is not mapped in the user namespace of the store, or this is not root"
        ),
    )
}

fn set_attrs(c: &Copier, target: Target<'_>, xattrs: &[(Vec<u8>, Vec<u8>)], path: &str) {
    for (name, value) in xattrs {
        let Ok(cname) = std::ffi::CString::new(name.as_slice()) else {
            continue;
        };
        let r = match &target {
            Target::Fd(fd) => {
                rustix::fs::fsetxattr(fd, &cname, value, rustix::fs::XattrFlags::empty())
            }
            Target::At(dir, n) => match proc_path(*dir, n) {
                Ok(p) => rustix::fs::lsetxattr(&p, &cname, value, rustix::fs::XattrFlags::empty()),
                Err(_) => continue,
            },
        };
        if let Err(e) = r {
            c.skip_attr(name, path, e);
        }
    }
}

/// The SELinux label of the copier on the entry, when it has one.
fn set_label(c: &Copier, target: Target<'_>, path: &str) -> io::Result<()> {
    let Some(label) = &c.label else {
        return Ok(());
    };
    let name = c"security.selinux";
    let r = match &target {
        Target::Fd(fd) => rustix::fs::fsetxattr(fd, name, label, rustix::fs::XattrFlags::empty()),
        Target::At(dir, n) => {
            let p = proc_path(*dir, n)?;
            rustix::fs::lsetxattr(&p, name, label, rustix::fs::XattrFlags::empty())
        }
    };
    match r {
        Ok(()) => Ok(()),
        // (a file system without SELinux attributes: nothing to label)
        Err(e) if is_unsupported(e) => Ok(()),
        Err(e) => Err(io::Error::new(
            io::Error::from(e).kind(),
            LabelRefused(format!(
                "the SELinux label of {path} cannot be set ({e}): the files of an image mounted in a container are labelled as they are copied"
            )),
        )),
    }
}

/// What the host says to the label of a copy it refuses; the I/O error that
/// holds it is told by [`is_label_refused`].
#[derive(Debug)]
struct LabelRefused(String);

impl std::fmt::Display for LabelRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LabelRefused {}

/// Whether `e` is the refusal of the host to put the label of the copier on
/// a file.
pub fn is_label_refused(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|i| i.is::<LabelRefused>())
}

/// `e` with `what` before its message; still a refusal of the label
/// ([`is_label_refused`]) when it was one.
pub fn io_context(e: io::Error, what: impl std::fmt::Display) -> io::Error {
    let (kind, message) = (e.kind(), format!("{what}{e}"));
    if is_label_refused(&e) {
        return io::Error::new(kind, LabelRefused(message));
    }
    io::Error::new(kind, message)
}

/// What an attribute is set on: a descriptor of the entry, or a name of a
/// directory (for the entries that are no files: a link is not opened).
enum Target<'a> {
    Fd(BorrowedFd<'a>),
    At(BorrowedFd<'a>, &'a OsStr),
}

/// The path of `name` in `dir` for the `l*xattr` calls: the last component is
/// not followed.
fn proc_path(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<std::ffi::CString> {
    velarx_sys::fd::proc_child(&dir, name)
}

// directories, without following links

fn kind(st: &Stat) -> FileType {
    FileType::from_raw_mode(st.st_mode)
}

/// Remove the tree at `path` (nothing is an error when it is not there).
pub fn remove_all(path: &Path) -> io::Result<()> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} has no parent directory to remove it from",
                path.display()
            ),
        ));
    };
    let dir = match openat(
        rustix::fs::CWD,
        parent,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(io::Error::from(e)),
    };
    match velarx_base::tree::remove_at(dir.as_fd(), name, &REMOVE) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// How a tree of a container is removed: a directory it made without access
/// is made accessible first (`rm -rf`).
const REMOVE: velarx_base::tree::Remove = velarx_base::tree::Remove {
    force_access: true,
    one_fs: false,
};

// the merged layers of an image written as a directory

/// Where the files of an image come from, and what is checked of them.
pub struct TocSource<'a> {
    pub store: &'a FileStore,
    /// `Off`: the files are taken as they are.  `On`: the fs-verity digest of
    /// a file that has one is measured and must be the one the table says.
    /// `Require`: every file must have one.
    pub verity: VerityMode,
}

fn toc_meta(
    e: &TocEntry,
    path: &str,
    translate: Option<&IdTranslate>,
) -> io::Result<Meta<'static>> {
    use base64::Engine;
    let mut xattrs = Vec::new();
    for (k, v) in &e.xattrs {
        if velarx_fuse::hidden_xattr(k) {
            continue;
        }
        let v = base64::engine::general_purpose::STANDARD
            .decode(v)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("an attribute of {path} is not base64"),
                )
            })?;
        xattrs.push((k.as_bytes().to_vec(), v));
    }
    xattrs.sort();
    let (uid, gid) = match translate {
        Some(t) => {
            let (u, g) = (t.uid_of(e.uid), t.gid_of(e.gid));
            for (what, id, got) in [("uid", e.uid, u), ("gid", e.gid, g)] {
                if got == IdTranslate::NOBODY {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "the {what} {id} of {path} is not mapped in the user namespace of the container"
                        ),
                    ));
                }
            }
            (u, g)
        }
        None => (e.uid, e.gid),
    };
    Ok(Meta {
        uid,
        gid,
        mode: e.mode & 0o7777,
        mtime: e.mtime(),
        xattrs,
        path: "",
    })
}

/// The object of the store for a regular file with content, opened and, as
/// `verity` says, measured against the digest the table gives.
fn object(src: &TocSource<'_>, e: &TocEntry) -> io::Result<File> {
    let digest = e.verity().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("`{}` has no fs-verity digest in its layer", e.name),
        )
    })?;
    let file = match src.store.open_object(&digest) {
        Some(r) => r?,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("`{}`: {digest} is not in the store", e.name),
            ))
        }
    };
    if src.verity != VerityMode::Off {
        let want = velarx_types::digest::Digest::parse_fsverity(&digest)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            .hex();
        match velarx_storage::measure_file(&file) {
            Ok(m) if hex::encode(&m.digest) == want => {}
            Ok(m) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "`{}`: the file of the store has the fs-verity digest {}, its layer says {digest}",
                        e.name,
                        hex::encode(&m.digest)
                    ),
                ))
            }
            Err(err) if src.verity == VerityMode::Require => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("`{}` ({digest}) has no fs-verity: {err}", e.name),
                ))
            }
            // (the file system has none: the store wrote it without)
            Err(_) => {}
        }
    }
    Ok(file)
}

/// Check the files the layer `toc` names: each is in the store, of the size
/// the table says, and measured against its fs-verity digest as
/// `src.verity` says.  This is where vfs checks fs-verity: at pull.
pub fn verify_objects(toc: &Toc, src: &TocSource<'_>) -> io::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for e in &toc.entries {
        if e.entry_type != TocEntryType::Reg || e.size == 0 {
            continue;
        }
        if let Some(d) = e.verity() {
            if !seen.insert(d) {
                continue;
            }
        }
        let file = object(src, e)?;
        let len = file.metadata()?.len();
        if len != e.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "`{}` is {len} bytes in the store, its layer says {}",
                    e.name, e.size
                ),
            ));
        }
    }
    Ok(())
}

/// The files of the layer `toc` that the store lacks (the names of their
/// objects), the first `limit`.
pub fn missing_objects(toc: &Toc, store: &FileStore, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for e in &toc.entries {
        if e.entry_type != TocEntryType::Reg || e.size == 0 {
            continue;
        }
        match e.verity() {
            Some(d) if store.get_path(&d).is_some() => {}
            Some(d) => out.push(format!("{} ({d})", e.name)),
            None => out.push(format!("{} (no fs-verity digest)", e.name)),
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

struct Walk<'a> {
    copier: &'a Copier,
    tree: &'a MergedTree,
    src: &'a TocSource<'a>,
    translate: Option<&'a IdTranslate>,
    root: BorrowedFd<'a>,
    /// The files with several names, by node, and the path of the first one
    /// made, from the root.
    links: HashMap<usize, PathBuf>,
    path: Vec<OsString>,
}

impl Walk<'_> {
    fn shown(&self, name: &str) -> String {
        let mut p = String::from("/");
        for c in &self.path {
            p.push_str(&c.to_string_lossy());
            p.push('/');
        }
        p.push_str(name);
        p
    }

    /// The checks of a name a layer may have, and its children, sorted.
    fn children(&self, node: usize) -> io::Result<Vec<(String, usize)>> {
        let Some(n) = self.tree.node(node) else {
            return Ok(Vec::new());
        };
        for name in n.children.keys() {
            if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("`{name}` is not a name a layer may have"),
                ));
            }
        }
        Ok(n.children.iter().map(|(k, &v)| (k.clone(), v)).collect())
    }

    /// Write the tree below `node` into the directory `root`: an explicit
    /// stack and a [`Cursor`] on the destination, so a few descriptors
    /// whatever the depth, and no recursion.  The attributes of a directory
    /// come last: what was made in it changed its time.
    fn run(&mut self, node: usize) -> io::Result<()> {
        struct Frame {
            id: usize,
            shown: String,
            names: std::vec::IntoIter<(String, usize)>,
        }
        let mut cur = Cursor::new(self.root.try_clone_to_owned()?)?;
        let mut stack = vec![Frame {
            id: node,
            shown: String::new(),
            names: self.children(node)?.into_iter(),
        }];
        while let Some(top) = stack.last_mut() {
            let Some((name, child)) = top.names.next() else {
                let Some(done) = stack.pop() else { break };
                if stack.is_empty() {
                    break;
                }
                let (_, fd) = cur.ascend()?;
                self.path.pop();
                if let Some(n) = self.tree.node(done.id) {
                    let mut meta = toc_meta(&n.entry, &done.shown, self.translate)?;
                    meta.path = &done.shown;
                    self.apply_fd(&fd, &meta)?;
                }
                continue;
            };
            let oname = OsStr::new(&name);
            let Some(n) = self.tree.node(child) else {
                continue;
            };
            if n.entry.entry_type != TocEntryType::Dir {
                self.entry(child, cur.fd(), oname)?;
                continue;
            }
            let shown = self.shown(&name);
            mkdirat(cur.fd(), oname, Mode::from_raw_mode(0o700))?;
            if cur.depth() >= velarx_base::tree::MAX_DEPTH {
                return Err(velarx_base::walk::too_deep(velarx_base::tree::MAX_DEPTH));
            }
            cur.descend(oname, None)?;
            self.path.push(oname.to_os_string());
            let names = self.children(child)?.into_iter();
            stack.push(Frame {
                id: child,
                shown,
                names,
            });
        }
        Ok(())
    }

    /// The entry `id` that is no directory, as `name` of `dir`.
    fn entry(&mut self, id: usize, dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
        let Some(n) = self.tree.node(id) else {
            return Ok(());
        };
        let e = &n.entry;
        let shown = self.shown(&name.to_string_lossy());
        match e.entry_type {
            TocEntryType::Dir => Ok(()),
            TocEntryType::Reg => {
                if n.nlink > 1 {
                    if let Some(first) = self.links.get(&id).cloned() {
                        return self.link(dir, name, &first);
                    }
                    let mut p: PathBuf = self.path.iter().collect();
                    p.push(name);
                    self.links.insert(id, p);
                }
                let out = openat(
                    dir,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?;
                let to = File::from(out);
                if e.size > 0 {
                    let from = object(self.src, e)?;
                    let len = from.metadata()?.len();
                    if len != e.size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{shown} is {len} bytes in the store, its layer says {}",
                                e.size
                            ),
                        ));
                    }
                    self.copier
                        .data(&from, &to, len)
                        .map_err(|err| io::Error::new(err.kind(), format!("{shown}: {err}")))?;
                }
                let mut meta = toc_meta(e, &shown, self.translate)?;
                meta.path = &shown;
                self.apply_fd(&to, &meta)
            }
            TocEntryType::Symlink => {
                let target = e.link_name.as_deref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("the link {shown} has no target"),
                    )
                })?;
                symlinkat(target, dir, name)?;
                let meta = toc_meta(e, &shown, self.translate)?;
                self.apply_at(dir, name, &meta, &shown)
            }
            t @ (TocEntryType::Char | TocEntryType::Block | TocEntryType::Fifo) => {
                let ft = match t {
                    TocEntryType::Char => FileType::CharacterDevice,
                    TocEntryType::Block => FileType::BlockDevice,
                    _ => FileType::Fifo,
                };
                let rdev = rustix::fs::makedev(
                    e.dev_major.unwrap_or_default(),
                    e.dev_minor.unwrap_or_default(),
                );
                match mknodat(dir, name, ft, Mode::from_raw_mode(e.mode & 0o777), rdev) {
                    Ok(()) => {}
                    // (a device cannot be made without privilege)
                    Err(er @ (rustix::io::Errno::PERM | rustix::io::Errno::ACCESS))
                        if ft != FileType::Fifo =>
                    {
                        self.copier.skip_node(&shown, er);
                        return Ok(());
                    }
                    Err(er) => return Err(io::Error::from(er)),
                }
                let meta = toc_meta(e, &shown, self.translate)?;
                self.apply_at(dir, name, &meta, &shown)
            }
            // (a chunk, a hard link: the merged tree has resolved them)
            _ => Ok(()),
        }
    }

    /// Make `name` of `dst` another name of the file `first` (a path from the
    /// root of the destination).  A hard link is of the copy, never of the
    /// object of the store: the owner is the container's.
    fn link(&mut self, dst: BorrowedFd<'_>, name: &OsStr, first: &Path) -> io::Result<()> {
        let (Some(parent), Some(fname)) = (first.parent(), first.file_name()) else {
            return Err(io::Error::other("a link without a name"));
        };
        let dir = if parent.as_os_str().is_empty() {
            rustix::io::fcntl_dupfd_cloexec(self.root, 0)?
        } else {
            velarx_sys::fs::open_beneath(self.root, parent, velarx_sys::fs::Beneath::DirectoryPath)?
        };
        linkat(&dir, fname, dst, name, AtFlags::empty()).map_err(io::Error::from)
    }

    /// The attributes of an entry held by a descriptor.
    fn apply_fd(&self, fd: impl AsFd, m: &Meta<'_>) -> io::Result<()> {
        let fd = fd.as_fd();
        let (uid, gid) = owner(m.uid, m.gid, m.path)?;
        // (the owner first: chown clears the setuid and setgid bits)
        match fchown(fd, Some(uid), Some(gid)) {
            Err(e) if self.copier.chown_failed(e) => {}
            r => r.map_err(|e| chown_error(e, m.uid, m.gid, m.path))?,
        }
        fchmod(fd, Mode::from_raw_mode(m.mode))?;
        set_attrs(self.copier, Target::Fd(fd), &m.xattrs, m.path);
        set_label(self.copier, Target::Fd(fd), m.path)?;
        rustix::fs::futimens(fd, &timestamps(m.mtime)).map_err(io::Error::from)
    }

    /// The attributes of an entry that is not opened (a link, a device).
    fn apply_at(
        &self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        m: &Meta<'_>,
        shown: &str,
    ) -> io::Result<()> {
        let (uid, gid) = owner(m.uid, m.gid, shown)?;
        match rustix::fs::chownat(dir, name, Some(uid), Some(gid), AtFlags::SYMLINK_NOFOLLOW) {
            Err(e) if self.copier.chown_failed(e) => {}
            r => r.map_err(|e| chown_error(e, m.uid, m.gid, shown))?,
        }
        let st = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
        if kind(&st) != FileType::Symlink {
            rustix::fs::chmodat(dir, name, Mode::from_raw_mode(m.mode), AtFlags::empty())?;
        }
        set_attrs(self.copier, Target::At(dir, name), &m.xattrs, shown);
        set_label(self.copier, Target::At(dir, name), shown)?;
        utimensat(dir, name, &timestamps(m.mtime), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)
    }
}

/// Write the image `tree` (its layers merged: whiteouts and opaque
/// directories applied, hard links resolved) as the directory `root`, which
/// is empty: the files copied from the store by reflink, else
/// `copy_file_range`, else read and write, their holes kept; the owners,
/// modes, times, attributes, links and special files of the table, the ids
/// translated by `translate` (the user namespace of the container) when there
/// is one.  An id the translation does not cover is an error, never a wrong
/// id.  A name with several links is one file in the copy: a hard link of an
/// object of the store would give the container's owner to every user of
/// the object, so none is made.
pub fn from_merged(
    copier: &Copier,
    tree: &MergedTree,
    src: &TocSource<'_>,
    translate: Option<&IdTranslate>,
    root: BorrowedFd<'_>,
) -> io::Result<()> {
    let mut w = Walk {
        copier,
        tree,
        src,
        translate,
        root,
        links: HashMap::new(),
        path: Vec::new(),
    };
    w.run(velarx_fuse::ROOT)?;
    if let Some(n) = tree.node(velarx_fuse::ROOT) {
        let mut meta = toc_meta(&n.entry, "/", translate)?;
        meta.path = "/";
        w.apply_fd(root, &meta)?;
    }
    Ok(())
}

/// Whether the file system of `dir` takes reflinks: two files are made there
/// to see.
pub fn probe_reflink(dir: &Path) -> bool {
    let Ok(a) = tempfile::tempfile_in(dir) else {
        return false;
    };
    let Ok(b) = tempfile::tempfile_in(dir) else {
        return false;
    };
    use std::io::Write;
    let mut a = a;
    if a.write_all(&[1u8; 4096]).is_err() || a.sync_all().is_err() {
        return false;
    }
    rustix::fs::ioctl_ficlone(&b, &a).is_ok()
}

/// A directory being made next to where it will be, under a lock that says a
/// writer is at it: the directory is renamed to its name when it is done, and
/// one whose writer is gone is found by its lock (nobody holds it) and
/// removed.
pub struct Building {
    path: PathBuf,
    _lock: File,
    done: bool,
}

impl Building {
    /// A new directory in `parent` (made if it is missing) whose name starts
    /// with `.tmp-`.
    pub fn new(parent: &Path) -> io::Result<Self> {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(parent)?;
        let name = format!(
            ".tmp-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            COUNT.fetch_add(1, Ordering::Relaxed)
        );
        let path = parent.join(name);
        // (the lock first: a directory without one is taken for abandoned)
        let lock = File::create(lock_of(&path))?;
        velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)?;
        std::fs::create_dir(&path)?;
        Ok(Self {
            path,
            _lock: lock,
            done: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The directory is complete: it gets the name `to`.  An error with
    /// `AlreadyExists` or `DirectoryNotEmpty` when another writer was first
    /// (the directory is removed, what is there is the same).
    pub fn finish(mut self, to: &Path) -> io::Result<()> {
        match std::fs::rename(&self.path, to) {
            Ok(()) => {
                self.done = true;
                let _ = std::fs::remove_file(lock_of(&self.path));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for Building {
    fn drop(&mut self) {
        if !self.done {
            let _ = remove_all(&self.path);
        }
        let _ = std::fs::remove_file(lock_of(&self.path));
    }
}

fn lock_of(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    dir.with_file_name(name)
}

/// Remove the directories `.tmp-*` of `parent` whose writer is gone: the
/// bytes freed and the errors.
pub fn remove_abandoned(parent: &Path) -> (u64, Vec<String>) {
    let (mut freed, mut errors) = (0, Vec::new());
    let Ok(rd) = std::fs::read_dir(parent) else {
        return (0, errors);
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with(".tmp-") || name.ends_with(".lock") {
            continue;
        }
        let path = e.path();
        let lock = lock_of(&path);
        // (no lock file: no writer made it, or it ended and removed it)
        let held = match File::open(&lock) {
            Ok(f) => rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .is_err()
                .then_some(f),
            Err(_) => None,
        };
        if held.is_some() {
            continue;
        }
        freed += tree_size(&path);
        match remove_all(&path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&lock);
            }
            Err(err) => errors.push(format!("Failed to remove {}: {err}", path.display())),
        }
    }
    (freed, errors)
}

/// The bytes of the regular files below `dir`.
pub fn tree_size(dir: &Path) -> u64 {
    velarx_base::tree::usage(
        dir,
        &velarx_base::tree::Measure {
            lenient: true,
            ..Default::default()
        },
    )
    .map_or(0, |u| u.file_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fd::OwnedFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use velarx_proto::pod::IdMapping;
    use velarx_types::digest::Algorithm;

    fn me() -> (u32, u32) {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    }

    fn open(p: &Path) -> OwnedFd {
        rustix::fs::open(
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// A store with objects, and the layers that name them.
    struct Img {
        _dir: tempfile::TempDir,
        store: FileStore,
        dst: PathBuf,
    }

    impl Img {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = FileStore::new(dir.path().join("objects")).unwrap();
            let dst = dir.path().join("dst");
            std::fs::create_dir_all(&dst).unwrap();
            Self {
                _dir: dir,
                store,
                dst,
            }
        }

        /// An object of `data` (a hole where it is zeros, if `sparse`), and
        /// the value a table of contents gives for it.
        fn object(&self, data: &[u8], sparse: bool) -> String {
            let id = velarx_storage::fsverity_digest_of(Algorithm::Sha256, data);
            let path = self
                .store
                .root()
                .join(velarx_storage::Object::new(&id, false).unwrap().rel());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let f = File::create(path).unwrap();
            f.set_len(data.len() as u64).unwrap();
            if sparse {
                let end = data.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
                let start = data.iter().position(|b| *b != 0).unwrap_or(end);
                f.write_all_at(&data[start..end], start as u64).unwrap();
            } else {
                f.write_all_at(data, 0).unwrap();
            }
            velarx_storage::to_toc(&id).unwrap()
        }

        fn file(&self, name: &str, data: &[u8], mode: u32) -> TocEntry {
            let mut e = velarx_fuse::dir_entry(name);
            e.entry_type = TocEntryType::Reg;
            e.mode = mode;
            e.size = data.len() as u64;
            e.mod_time = Some("2017-07-14T02:40:00.123456789+00:00".into());
            if !data.is_empty() {
                e.fsverity = Some(self.object(data, false));
            }
            e
        }

        fn merged(&self, layers: &[Vec<TocEntry>]) -> MergedTree {
            let tocs: Vec<Toc> = layers
                .iter()
                .map(|entries| Toc {
                    version: 1,
                    entries: entries.clone(),
                    tar_split_digest: None,
                })
                .collect();
            let refs: Vec<&Toc> = tocs.iter().collect();
            MergedTree::build(&refs).unwrap()
        }

        fn write(
            &self,
            copier: &Copier,
            tree: &MergedTree,
            t: Option<&IdTranslate>,
        ) -> io::Result<()> {
            // (a failed write left what it made)
            for e in std::fs::read_dir(&self.dst).unwrap().flatten() {
                remove_all(&e.path()).unwrap();
            }
            from_merged(
                copier,
                tree,
                &TocSource {
                    store: &self.store,
                    verity: VerityMode::Off,
                },
                t,
                open(&self.dst).as_fd(),
            )
        }
    }

    fn dir(name: &str, mode: u32) -> TocEntry {
        let mut e = velarx_fuse::dir_entry(name);
        e.mode = mode;
        e
    }

    fn typed(name: &str, t: TocEntryType, link: Option<&str>) -> TocEntry {
        let mut e = velarx_fuse::dir_entry(name);
        e.entry_type = t;
        e.mode = 0o644;
        e.link_name = link.map(String::from);
        e
    }

    fn set_xattr_ok(dir: &Path) -> bool {
        let p = dir.join("probe");
        std::fs::write(&p, b"").unwrap();
        rustix::fs::lsetxattr(&p, "user.probe", b"1", rustix::fs::XattrFlags::empty()).is_ok()
    }

    #[test]
    fn the_image_is_written_with_links_holes_modes_times_attributes_and_nodes() {
        use base64::Engine;
        let img = Img::new();
        let sparse_data = {
            let mut d = vec![0u8; 8 << 20];
            let n = d.len();
            d[n - 3..].copy_from_slice(b"end");
            d
        };
        let mut sparse = img.file("a/sparse", &sparse_data, 0o644);
        sparse.fsverity = Some(img.object(&sparse_data, true));
        let mut one = img.file("a/one", b"one", 0o4750);
        let mut link = typed("a/b/two", TocEntryType::Hardlink, Some("a/one"));
        link.mode = 0o4750;
        one.xattrs.insert(
            "user.k".into(),
            base64::engine::general_purpose::STANDARD.encode("value"),
        );
        let layer = vec![
            dir("", 0o755),
            dir("a", 0o750),
            dir("a/b", 0o700),
            img.file("a/b/big", &vec![7u8; 3 << 20], 0o644),
            sparse,
            one,
            link,
            typed("a/b/link", TocEntryType::Symlink, Some("../one")),
            typed("a/fifo", TocEntryType::Fifo, None),
            img.file("a/empty", b"", 0o600),
        ];
        let tree = img.merged(&[layer]);
        let copier = Copier::new().ignoring_chown_errors(true);
        img.write(&copier, &tree, None).unwrap();
        let d = &img.dst;
        assert_eq!(
            std::fs::read(d.join("a/b/big")).unwrap(),
            vec![7u8; 3 << 20]
        );
        let m = std::fs::metadata(d.join("a/one")).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o4750);
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_500_000_000, 123_456_789));
        // hard links are one file in the copy, and not the object's
        let two = std::fs::metadata(d.join("a/b/two")).unwrap();
        assert_eq!((m.ino(), m.nlink()), (two.ino(), 2));
        let obj = img
            .store
            .get_path(&velarx_storage::from_toc(&tree_obj(&tree, "a/one")).unwrap())
            .unwrap();
        assert!(std::fs::metadata(obj).unwrap().ino() != m.ino());
        assert_eq!(
            std::fs::read_link(d.join("a/b/link")).unwrap(),
            Path::new("../one")
        );
        assert!(std::fs::symlink_metadata(d.join("a/fifo"))
            .unwrap()
            .file_type()
            .is_fifo());
        assert_eq!(std::fs::metadata(d.join("a/empty")).unwrap().len(), 0);
        assert_eq!(
            std::fs::metadata(d.join("a")).unwrap().mode() & 0o7777,
            0o750
        );
        // holes stay holes
        let s = std::fs::metadata(d.join("a/sparse")).unwrap();
        assert_eq!(s.len(), 8 << 20);
        assert!(s.blocks() * 512 < 1 << 20, "{} blocks", s.blocks());
        if set_xattr_ok(d) {
            let mut v = vec![0u8; 16];
            let n = rustix::fs::lgetxattr(d.join("a/one"), "user.k", &mut v).unwrap();
            assert_eq!(&v[..n], b"value");
        }
    }

    /// A tree as deep as a pull takes, written on a small stack (no
    /// recursion), with a hard link at the bottom to a file at the top and
    /// a directory without access on the way.
    #[test]
    fn a_deep_image_is_written_without_recursion() {
        const DEPTH: usize = 500;
        let img = Img::new();
        let mut layer = vec![dir("", 0o755), img.file("top", b"top", 0o644)];
        let mut p = String::new();
        for i in 0..DEPTH {
            if !p.is_empty() {
                p.push('/');
            }
            p.push('d');
            layer.push(dir(&p, if i == 1 { 0o500 } else { 0o755 }));
        }
        layer.push(typed(
            &format!("{p}/two"),
            TocEntryType::Hardlink,
            Some("top"),
        ));
        let tree = img.merged(&[layer]);
        let copier = Copier::new().ignoring_chown_errors(true);
        std::thread::scope(|s| {
            std::thread::Builder::new()
                .stack_size(128 << 10)
                .spawn_scoped(s, || img.write(&copier, &tree, None).unwrap())
                .unwrap()
                .join()
                .unwrap()
        });
        let two = img.dst.join(&p).join("two");
        let top = std::fs::metadata(img.dst.join("top")).unwrap();
        assert_eq!(std::fs::metadata(&two).unwrap().ino(), top.ino());
        assert_eq!(
            std::fs::metadata(img.dst.join("d/d")).unwrap().mode() & 0o7777,
            0o500
        );
        // (the removal of a test makes it accessible again)
        remove_all(&img.dst.join("d")).unwrap();
    }

    /// The attributes an image may not give the copy: the overlay's (the
    /// copy is no layer of an overlay) and its own SELinux label (the copy
    /// gets the container's).
    #[test]
    fn the_overlay_attributes_and_the_label_of_the_image_are_not_set() {
        use base64::Engine;
        let img = Img::new();
        let b64 = |v: &str| base64::engine::general_purpose::STANDARD.encode(v);
        let mut f = img.file("f", b"x", 0o644);
        for (k, v) in [
            ("user.overlay.opaque", "y"),
            ("trusted.overlay.redirect", "/etc"),
            ("security.selinux", "system_u:object_r:etc_t:s0"),
            ("user.kept", "v"),
        ] {
            f.xattrs.insert(k.into(), b64(v));
        }
        let tree = img.merged(&[vec![dir("", 0o755), f]]);
        let c = Copier::new().ignoring_chown_errors(true);
        img.write(&c, &tree, None).unwrap();
        let get = |n: &str| {
            let mut v = vec![0u8; 256];
            rustix::fs::lgetxattr(img.dst.join("f"), n, &mut v)
                .ok()
                .map(|len| v[..len].to_vec())
        };
        if !set_xattr_ok(&img.dst) {
            eprintln!("SKIPPED: the file system has no user xattrs");
            return;
        }
        assert_eq!(get("user.kept").as_deref(), Some(&b"v"[..]));
        assert_eq!(get("user.overlay.opaque"), None);
        assert_eq!(get("trusted.overlay.redirect"), None);
        assert_ne!(
            get("security.selinux").as_deref(),
            Some(&b"system_u:object_r:etc_t:s0"[..])
        );
    }

    fn tree_obj(tree: &MergedTree, path: &str) -> String {
        let id = tree.resolve(path).unwrap();
        tree.node(id).unwrap().entry.fsverity.clone().unwrap()
    }

    /// The data of the files go by the method the file system allows, and by
    /// the one below when one fails (a fault of a test stands for the file
    /// system that lacks the first).
    #[test]
    fn a_file_is_reflinked_else_ranged_else_copied() {
        let run = |name: &str, fault: Option<Fault>| {
            let img = Img::new();
            let mut sparse_data = vec![0u8; 8 << 20];
            let n = sparse_data.len();
            sparse_data[n - 3..].copy_from_slice(b"end");
            let mut sparse = img.file("sparse", &sparse_data, 0o644);
            sparse.fsverity = Some(img.object(&sparse_data, true));
            let tree = img.merged(&[vec![
                dir("", 0o755),
                img.file("a", &vec![1u8; 1 << 20], 0o644),
                img.file("b", b"small", 0o644),
                sparse,
            ]]);
            let c = match fault {
                Some(f) => Copier::with_fault(f),
                None => Copier::new(),
            }
            .ignoring_chown_errors(true);
            img.write(&c, &tree, None).unwrap();
            assert_eq!(std::fs::read(img.dst.join("b")).unwrap(), b"small");
            assert_eq!(std::fs::read(img.dst.join("a")).unwrap().len(), 1 << 20);
            let s = std::fs::metadata(img.dst.join("sparse")).unwrap();
            assert!(s.blocks() * 512 < 1 << 20, "{name}: sparse is kept");
            c.counts.get()
        };
        let probe = Img::new();
        let (re, ra, pl) = run("free", None);
        assert_eq!(re + ra + pl, 3, "{re} {ra} {pl}");
        // (on a file system with reflinks, they are what is used)
        if probe_reflink(probe.dst.parent().unwrap()) {
            assert_eq!((re, ra, pl), (3, 0, 0));
        }
        let no_reflink: Fault =
            Arc::new(|m| (m == Method::Reflink).then_some(rustix::io::Errno::OPNOTSUPP));
        assert_eq!(run("noreflink", Some(no_reflink)), (0, 3, 0));
        let neither: Fault = Arc::new(|m| match m {
            Method::Reflink => Some(rustix::io::Errno::XDEV),
            Method::Range => Some(rustix::io::Errno::NOSYS),
            Method::Plain => None,
        });
        assert_eq!(run("plain", Some(neither)), (0, 0, 3));
        // an error that is not "not supported" fails that file's reflink only
        let flaky: Fault = {
            let n = std::sync::atomic::AtomicU32::new(0);
            Arc::new(move |m| {
                (m == Method::Reflink && n.fetch_add(1, Ordering::Relaxed) == 0)
                    .then_some(rustix::io::Errno::IO)
            })
        };
        run("flaky", Some(flaky));
    }

    fn map(c: u32, h: u32, n: u32) -> Vec<IdMapping> {
        vec![IdMapping {
            container_id: c,
            host_id: h,
            size: n,
        }]
    }

    fn owned(mut e: TocEntry, uid: u32, gid: u32) -> TocEntry {
        e.uid = uid;
        e.gid = gid;
        e
    }

    #[test]
    fn an_owner_the_mapping_does_not_cover_is_an_error_never_a_wrong_id() {
        let img = Img::new();
        let (uid, gid) = me();
        let tree = img.merged(&[vec![
            dir("", 0o755),
            owned(img.file("f", b"x", 0o644), 50, 50),
        ]]);
        let c = Copier::new();
        let narrow = IdTranslate {
            uid: map(1000, 100_000, 10),
            gid: map(1000, 100_000, 10),
            squash: false,
        };
        let e = img.write(&c, &tree, Some(&narrow)).unwrap_err().to_string();
        assert!(e.contains("is not mapped in the user namespace"), "{e}");
        // an id that would be beyond the last one a file can have
        let overflow = IdTranslate {
            uid: map(0, u32::MAX - 5, 100),
            gid: map(0, u32::MAX - 5, 100),
            squash: false,
        };
        assert_eq!(overflow.uid_of(50), IdTranslate::NOBODY);
        let e = img
            .write(&c, &tree, Some(&overflow))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not mapped"), "{e}");
        // the id that means "no change" is never given
        assert!(owner(u32::MAX, 0, "/x").is_err());
        // squashed: the owner is the root of the container
        let squash = IdTranslate {
            uid: map(0, uid, 1),
            gid: map(0, gid, 1),
            squash: true,
        };
        assert_eq!(squash.uid_of(50), uid);
        let again = Img::new();
        let tree = again.merged(&[vec![
            dir("", 0o755),
            owned(again.file("f", b"x", 0o644), 50, 50),
        ]]);
        again.write(&c, &tree, Some(&squash)).unwrap();
        assert_eq!(std::fs::metadata(again.dst.join("f")).unwrap().uid(), uid);
    }

    #[test]
    fn the_ids_of_a_mapping_are_given_to_the_files() {
        if !rustix::process::geteuid().is_root() {
            eprintln!("SKIPPED: giving files other owners needs root");
            return;
        }
        let img = Img::new();
        let tree = img.merged(&[vec![
            owned(dir("", 0o755), 0, 0),
            owned(img.file("a", b"a", 0o644), 0, 0),
            owned(img.file("b", b"b", 0o644), 5, 5),
            owned(img.file("c", b"c", 0o644), 999, 999),
            owned(typed("l", TocEntryType::Symlink, Some("a")), 5, 5),
            owned(dir("d", 0o755), 7, 8),
        ]]);
        let t = IdTranslate {
            uid: map(0, 100_000, 1000),
            gid: map(0, 200_000, 1000),
            squash: false,
        };
        img.write(&Copier::new(), &tree, Some(&t)).unwrap();
        let own = |n: &str| {
            let m = std::fs::symlink_metadata(img.dst.join(n)).unwrap();
            (m.uid(), m.gid())
        };
        assert_eq!(own("a"), (100_000, 200_000));
        assert_eq!(own("b"), (100_005, 200_005));
        assert_eq!(own("c"), (100_999, 200_999));
        assert_eq!(own("l"), (100_005, 200_005), "the owner of a link");
        assert_eq!(own("d"), (100_007, 200_008));
        assert_eq!(std::fs::metadata(&img.dst).unwrap().uid(), 100_000);
    }

    #[test]
    fn the_layers_are_merged_with_their_whiteouts_applied() {
        let img = Img::new();
        let f = |n: &str, d: &[u8]| img.file(n, d, 0o644);
        let tree = img.merged(&[
            vec![
                dir("", 0o755),
                dir("e", 0o755),
                f("e/gone", b"low"),
                f("e/kept", b"low"),
                dir("o", 0o755),
                f("o/a", b"a"),
                f("o/b", b"b"),
                dir("d", 0o755),
                dir("d/x", 0o755),
                f("d/x/y", b"y"),
                f("f", b"file"),
                dir("g", 0o755),
                f("g/h", b"h"),
            ],
            vec![
                dir("e", 0o755),
                f("e/.wh.gone", b""),
                f("e/kept", b"replaced"),
                dir("o", 0o755),
                f("o/.wh..wh..opq", b""),
                f("o/c", b"up"),
                f(".wh.d", b""),
                f("f/inner", b"a directory over a file"),
            ],
            vec![f("g", b"a file over a directory")],
        ]);
        // (the second layer's `f/inner` makes `f` a directory)
        img.write(&Copier::new().ignoring_chown_errors(true), &tree, None)
            .unwrap();
        let d = &img.dst;
        assert!(!d.join("e/gone").exists());
        assert_eq!(std::fs::read(d.join("e/kept")).unwrap(), b"replaced");
        assert!(!d.join("o/a").exists() && !d.join("o/b").exists());
        assert_eq!(std::fs::read(d.join("o/c")).unwrap(), b"up");
        assert!(!d.join("d").exists());
        assert!(d.join("f").is_dir(), "a directory replaces a file");
        assert!(d.join("g").is_file(), "a file replaces a directory");
        for p in ["e/.wh.gone", "o/.wh..wh..opq", ".wh.d"] {
            assert!(!d.join(p).exists(), "{p}: no marker is left");
        }
    }

    /// The content of an image never makes the copy write outside of its
    /// destination: a link is made as a link, and a directory a name below a
    /// link needs replaces it.
    #[test]
    fn a_link_of_the_image_is_never_followed() {
        let t = tempfile::tempdir().unwrap();
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious"), b"mine").unwrap();
        let out = outside.to_str().unwrap().to_string();
        let img = Img::new();
        let link = |n: &str, to: &str| typed(n, TocEntryType::Symlink, Some(to));
        let tree = img.merged(&[
            vec![dir("", 0o755), link("escape", &out), link("up", "../../..")],
            vec![img.file("escape/pwned", b"x", 0o644)],
        ]);
        let c = Copier::new().ignoring_chown_errors(true);
        img.write(&c, &tree, None).unwrap();
        assert!(img.dst.join("escape").is_dir() && !img.dst.join("escape").is_symlink());
        assert_eq!(
            std::fs::read_link(img.dst.join("up")).unwrap(),
            Path::new("../../..")
        );
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            1,
            "nothing was made outside"
        );
        // in one layer too, as the image of the layer has it
        let same = Img::new();
        let tree = same.merged(&[vec![
            dir("", 0o755),
            link("escape", &out),
            same.file("escape/pwned", b"x", 0o644),
        ]]);
        same.write(&c, &tree, None).unwrap();
        assert!(same.dst.join("escape/pwned").is_file() && !same.dst.join("escape").is_symlink());
        // a path that goes up is refused
        let up = Toc {
            version: 1,
            entries: vec![dir("", 0o755), img.file("../x", b"x", 0o644)],
            tar_split_digest: None,
        };
        assert!(MergedTree::build(&[&up]).is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[test]
    fn the_objects_of_a_layer_are_checked_and_a_missing_one_is_named() {
        let img = Img::new();
        let toc = Toc {
            version: 1,
            entries: vec![
                dir("", 0o755),
                img.file("a", b"alpha", 0o644),
                img.file("b", b"beta", 0o644),
            ],
            tar_split_digest: None,
        };
        let src = TocSource {
            store: &img.store,
            verity: VerityMode::On,
        };
        verify_objects(&toc, &src).unwrap();
        assert!(missing_objects(&toc, &img.store, 5).is_empty());
        // an object of another size than the table says
        let mut wrong = toc.clone();
        wrong.entries[1].size = 99;
        assert!(verify_objects(&wrong, &src)
            .unwrap_err()
            .to_string()
            .contains("99"));
        // an object the store lacks
        let mut lost = toc.clone();
        lost.entries[2].fsverity = Some(
            velarx_storage::to_toc(&velarx_storage::fsverity_digest_of(
                Algorithm::Sha256,
                b"nothing",
            ))
            .unwrap(),
        );
        assert_eq!(missing_objects(&lost, &img.store, 5).len(), 1);
        assert_eq!(
            verify_objects(&lost, &src).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        // a file with content that names no digest
        let mut bare = toc;
        bare.entries[1].fsverity = None;
        assert!(verify_objects(&bare, &src).is_err());
    }

    #[test]
    fn removal_enters_directories_it_may_not_and_leaves_no_trace() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("tree");
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        std::fs::write(d.join("a/b/f"), b"x").unwrap();
        std::os::unix::fs::symlink("/", d.join("a/root")).unwrap();
        std::fs::set_permissions(d.join("a/b"), std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(d.join("a"), std::fs::Permissions::from_mode(0o500)).unwrap();
        remove_all(&d).unwrap();
        assert!(!d.exists());
        // (what a link names is not touched)
        assert!(Path::new("/usr").exists());
        remove_all(&d).unwrap();
    }

    #[test]
    fn a_directory_made_for_a_copy_is_removed_when_its_writer_is_gone() {
        let t = tempfile::tempdir().unwrap();
        let b = Building::new(t.path()).unwrap();
        std::fs::write(b.path().join("f"), vec![1u8; 4096]).unwrap();
        let path = b.path().to_path_buf();
        // a writer that lives: its directory stays
        let (freed, errors) = remove_abandoned(t.path());
        assert_eq!((freed, errors.len()), (0, 0));
        assert!(path.exists());
        // dropped: removed with its lock
        drop(b);
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 0);
        // one whose writer died (the lock is released, the directory is
        // left)
        let dead = t.path().join(".tmp-dead");
        std::fs::create_dir_all(dead.join("x")).unwrap();
        std::fs::write(dead.join("x/f"), vec![1u8; 8192]).unwrap();
        std::fs::write(lock_of(&dead), b"").unwrap();
        let (freed, errors) = remove_abandoned(t.path());
        assert!(freed >= 8192 && errors.is_empty(), "{freed} {errors:?}");
        assert!(!dead.exists());
        // renamed to its name when done
        let b = Building::new(t.path()).unwrap();
        std::fs::write(b.path().join("f"), b"x").unwrap();
        let to = t.path().join("layer");
        b.finish(&to).unwrap();
        assert!(to.join("f").exists());
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1);
    }
}
