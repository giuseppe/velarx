// SPDX-License-Identifier: Apache-2.0
//! The file system of a container that does not run, for `cp`: its upper
//! directory over its image, without mounting anything (the monitor mounts
//! the root file system only while the container runs).
//!
//! Opened by the storage driver (`stopped_view`), which says where the
//! upper directory is.
//!
//! Two layouts (`StoppedView::overlay` and `::directory`): the upper
//! directory of an overlay over the image, or the whole root of a container
//! of a driver that copies the layers, in which nothing is below and a 0:0
//! device is the device the container made.
//!
//! What the overlay would show: an entry of the upper directory hides the
//! image's, a whiteout (a character device 0:0) deletes it, an opaque
//! directory hides the image's directory under it.  Links are resolved in
//! the container root, never followed out of it: the upper directory is
//! walked with `openat` without following anything and the image is a
//! table of contents.  Copies into the container are written to the upper
//! directory, the directories on the way copied up from the image.

use crate::imagecopy::TreeSource;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{fstat, mkdirat, openat, readlinkat, FileType, Mode, OFlags, Stat};
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use velarx_base::tree::{mount_of, MountOf};
use velarx_fuse::{IdTranslate, ROOT};
use velarx_storage::TocEntryType;
use velarx_wire::cp::{self, IdMaps, MAX_DEPTH};

fn enoent() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOENT)
}

/// An entry of the merged view.
struct Entry {
    /// The entry of the upper directory (opened with `O_PATH`).
    upper: Option<(OwnedFd, Stat)>,
    /// The node of the image: hidden when the upper entry is not a
    /// directory or is an opaque one.  For a regular file of the upper
    /// directory that is metadata only (`meta`) it is the file, which has
    /// the data.
    lower: Option<usize>,
    meta: bool,
}

/// What `X-Docker-Container-Path-Stat` needs of an entry.
#[derive(Debug)]
pub struct EntryStat {
    pub mode: u32,
    pub size: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub is_dir: bool,
}

/// How the directory of a container's layer says what the container changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// The upper directory of an overlay over the image: an entry hides the
    /// image's, a 0:0 device is a deletion, an opaque directory hides the
    /// image's.
    Overlay,
    /// The whole root file system of the container (a copy of the image that
    /// the container wrote in): nothing is below it, and a 0:0 device is the
    /// device the container made.
    Directory,
}

pub struct StoppedView<'a> {
    /// The directory of the container's layer.
    upper: OwnedFd,
    /// The image below an overlay layout (not read for a directory).
    image: TreeSource<'a>,
    layout: Layout,
    /// The mount of `upper`: a directory below it on another mount (a
    /// mount point, a bind mount) is not walked into.
    mount: OnceLock<MountOf>,
}

fn is_dir(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::Directory
}

fn opaque(dir: BorrowedFd<'_>) -> bool {
    let path = velarx_sys::fd::proc_str(&dir);
    ["trusted.overlay.opaque", "user.overlay.opaque"]
        .iter()
        .any(|n| {
            let mut v = [0u8; 4];
            matches!(rustix::fs::getxattr(path.as_str(), *n, &mut v), Ok(1) if v[0] == b'y')
        })
}

/// Whether the empty regular file `fd` is a whiteout made with an extended
/// attribute (`overlay.whiteout`, what the engine writes where a device 0:0
/// cannot be made): the overlay hides the entry below as it hides it for a
/// device.
fn xattr_whiteout(fd: &OwnedFd, st: &Stat) -> bool {
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile || st.st_size != 0 {
        return false;
    }
    let path = velarx_sys::fd::proc_str(&fd);
    // (its presence is the mark, whatever its value: an empty buffer asks
    // only for the size, so a long value is no ERANGE)
    ["trusted.overlay.whiteout", "user.overlay.whiteout"]
        .iter()
        .any(|n| rustix::fs::getxattr(path.as_str(), *n, &mut [0u8; 0]).is_ok())
}

/// Whether an entry of the upper directory is a metadata only file of the
/// overlay (`metacopy`: its data are the file below's), and where the
/// overlay says the entry comes from (`redirect`).
fn overlay_attrs(fd: &OwnedFd, st: &Stat) -> (bool, Option<Vec<u8>>) {
    let kind = FileType::from_raw_mode(st.st_mode);
    if kind != FileType::RegularFile && kind != FileType::Directory {
        return (false, None);
    }
    let path = velarx_sys::fd::proc_str(&fd);
    let get = |suffix: &str| -> Option<Vec<u8>> {
        ["trusted.overlay.", "user.overlay."].iter().find_map(|p| {
            let mut v = vec![0u8; 4096];
            let n = rustix::fs::getxattr(path.as_str(), format!("{p}{suffix}"), &mut v).ok()?;
            v.truncate(n);
            Some(v)
        })
    };
    (get("metacopy").is_some(), get("redirect"))
}

/// The xattrs of an entry of the image (but those of overlay and SELinux,
/// the store's), as the PAX records of the next entry, sorted.
pub fn xattr_records(e: &velarx_storage::TocEntry) -> Vec<(String, Vec<u8>)> {
    use base64::Engine;
    let mut records = Vec::new();
    for (name, value) in &e.xattrs {
        if name.starts_with("trusted.overlay.")
            || name.starts_with("user.overlay.")
            || name.starts_with("security.selinux")
        {
            continue;
        }
        if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(value) {
            records.push((format!("SCHILY.xattr.{name}"), v));
        }
    }
    records.sort();
    records
}

/// [`xattr_records`] appended to `b` for the next entry.
pub fn append_xattrs<W: Write>(
    b: &mut tar::Builder<W>,
    e: &velarx_storage::TocEntry,
) -> io::Result<()> {
    let records = xattr_records(e);
    if records.is_empty() {
        return Ok(());
    }
    b.append_pax_extensions(records.iter().map(|(k, v)| (k.as_str(), v.as_slice())))
}

fn toc_kind(t: TocEntryType) -> FileType {
    match t {
        TocEntryType::Dir => FileType::Directory,
        TocEntryType::Symlink => FileType::Symlink,
        TocEntryType::Reg | TocEntryType::Chunk | TocEntryType::Hardlink => FileType::RegularFile,
        TocEntryType::Fifo => FileType::Fifo,
        TocEntryType::Char => FileType::CharacterDevice,
        TocEntryType::Block => FileType::BlockDevice,
    }
}

impl<'a> StoppedView<'a> {
    /// The upper directory `upper` of an overlay over `image`.
    pub fn overlay(upper: OwnedFd, image: TreeSource<'a>) -> Self {
        Self {
            upper,
            image,
            layout: Layout::Overlay,
            mount: OnceLock::new(),
        }
    }

    /// The root file system `root` of a container that is a plain directory
    /// (the layers copied and written in: nothing is merged with the image,
    /// which is only the source of the ids translation and is not read).
    pub fn directory(root: OwnedFd, image: TreeSource<'a>) -> Self {
        Self {
            upper: root,
            image,
            layout: Layout::Directory,
            mount: OnceLock::new(),
        }
    }

    fn overlay_layout(&self) -> bool {
        self.layout == Layout::Overlay
    }

    fn lower_kind(&self, n: usize) -> Option<FileType> {
        self.image
            .tree
            .node(n)
            .map(|n| toc_kind(n.entry.entry_type))
    }

    fn kind(&self, e: &Entry) -> Option<FileType> {
        match &e.upper {
            Some((_, st)) => Some(FileType::from_raw_mode(st.st_mode)),
            None => e.lower.and_then(|n| self.lower_kind(n)),
        }
    }

    fn root(&self) -> io::Result<Entry> {
        let fd = rustix::io::fcntl_dupfd_cloexec(&self.upper, 0)?;
        let st = fstat(&fd)?;
        // (the overlay never reads the attribute on its root)
        let lower = self.overlay_layout().then_some(ROOT);
        Ok(Entry {
            upper: Some((fd, st)),
            lower,
            meta: false,
        })
    }

    fn upper_mount(&self) -> io::Result<MountOf> {
        if let Some(m) = self.mount.get() {
            return Ok(*m);
        }
        let m = mount_of(self.upper.as_fd(), OsStr::new(""), &fstat(&self.upper)?)?;
        Ok(*self.mount.get_or_init(|| m))
    }

    /// The entry `name` of the directory `dir`, `None` if it does not
    /// exist (or was deleted).  A directory of the upper directory on
    /// another mount is an error: what the overlay shows there is the
    /// directory under the mount, which is out of reach.
    fn child(&self, dir: &Entry, name: &OsStr) -> io::Result<Option<Entry>> {
        let mut upper = None;
        if let Some((fd, st)) = &dir.upper {
            if is_dir(st) {
                match openat(
                    fd,
                    name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(c) => {
                        let st = fstat(&c)?;
                        if is_dir(&st)
                            && mount_of(c.as_fd(), OsStr::new(""), &st)? != self.upper_mount()?
                        {
                            return Err(io::Error::new(
                                io::Error::from_raw_os_error(libc::EXDEV).kind(),
                                format!(
                                    "`{}` is a mount in the container's directory",
                                    name.to_string_lossy()
                                ),
                            ));
                        }
                        if self.overlay_layout()
                            && (cp::is_whiteout(&st) || xattr_whiteout(&c, &st))
                        {
                            return Ok(None);
                        }
                        upper = Some((c, st));
                    }
                    Err(rustix::io::Errno::NOENT) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let (metacopy, redirect) = match &upper {
            Some((fd, st)) if self.overlay_layout() => overlay_attrs(fd, st),
            _ => (false, None),
        };
        // where it is below: by its name, or where the overlay says it was
        let mut lower = match &redirect {
            Some(r) => self.below(dir, r),
            None => dir
                .lower
                .zip(name.to_str())
                .and_then(|(l, n)| self.image.tree.lookup(l, n)),
        };
        if !self.overlay_layout() {
            lower = None;
        }
        let mut meta = false;
        if let Some((fd, st)) = &upper {
            if is_dir(st) {
                let merged = lower.and_then(|l| self.lower_kind(l)) == Some(FileType::Directory)
                    && !opaque(cp::reopen(fd, st, OFlags::RDONLY)?.as_fd());
                if !merged {
                    lower = None;
                }
            } else if metacopy
                && lower.and_then(|l| self.lower_kind(l)) == Some(FileType::RegularFile)
            {
                meta = true;
            } else {
                lower = None;
            }
        }
        if upper.is_none() && lower.is_none() {
            return Ok(None);
        }
        Ok(Some(Entry { upper, lower, meta }))
    }

    /// The node of the image that a `redirect` of an entry of `dir` says.
    fn below(&self, dir: &Entry, redirect: &[u8]) -> Option<usize> {
        let r = std::str::from_utf8(redirect).ok()?;
        match r.strip_prefix('/') {
            Some(abs) => self.image.tree.resolve(abs),
            None => self.image.tree.lookup(dir.lower?, r),
        }
    }

    /// The entry at the components `comps` (no links on the way).
    fn locate(&self, comps: &[String]) -> io::Result<Option<Entry>> {
        let mut cur = self.root()?;
        for c in comps {
            if self.kind(&cur) != Some(FileType::Directory) {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            match self.child(&cur, OsStr::new(c))? {
                Some(e) => cur = e,
                None => return Ok(None),
            }
        }
        Ok(Some(cur))
    }

    fn readlink(&self, e: &Entry) -> io::Result<String> {
        match &e.upper {
            Some((fd, _)) => Ok(String::from_utf8_lossy(
                readlinkat(fd, "", Vec::new())?.as_bytes(),
            )
            .into_owned()),
            None => Ok(e
                .lower
                .and_then(|n| self.image.tree.node(n))
                .and_then(|n| n.entry.link_name.clone())
                .unwrap_or_default()),
        }
    }

    /// Resolve `path` in the container root, links followed (the last
    /// one too when `follow_last`): the components and the entry, `None`
    /// if only the last component is missing.
    fn resolve(&self, path: &str, follow_last: bool) -> io::Result<(Vec<String>, Option<Entry>)> {
        let (out, missing) = cp::walk(path, follow_last, |comps, last, follow| {
            let Some(e) = self.locate(comps)? else {
                return if last {
                    Ok(cp::Probe::Missing)
                } else {
                    Err(enoent())
                };
            };
            if follow && self.kind(&e) == Some(FileType::Symlink) {
                return Ok(cp::Probe::Link(self.readlink(&e)?));
            }
            Ok(cp::Probe::Plain)
        })?;
        if missing {
            return Ok((out, None));
        }
        let e = self.locate(&out)?;
        Ok((out, e))
    }

    /// The stat of `path` (links followed) and the path it resolves to.
    pub fn stat(&self, path: &str) -> io::Result<(EntryStat, String)> {
        let (comps, e) = self.resolve(path, true)?;
        let e = e.ok_or_else(enoent)?;
        let resolved = format!("/{}", comps.join("/"));
        let st = match (&e.upper, e.lower.and_then(|n| self.image.tree.node(n))) {
            (Some((_, st)), below) => EntryStat {
                mode: st.st_mode,
                size: match (e.meta, below) {
                    (true, Some(n)) => n.entry.size as i64,
                    _ => st.st_size,
                },
                mtime: st.st_mtime,
                mtime_nsec: st.st_mtime_nsec as i64,
                is_dir: is_dir(st),
            },
            (None, Some(n)) => EntryStat {
                mode: (n.entry.mode & 0o7777) | toc_kind(n.entry.entry_type).as_raw_mode(),
                size: n.entry.size as i64,
                mtime: crate::imagecopy::mtime(&n.entry).tv_sec,
                mtime_nsec: 0,
                is_dir: n.entry.entry_type == TocEntryType::Dir,
            },
            (None, None) => return Err(enoent()),
        };
        Ok((st, resolved))
    }

    /// The content of the regular file `path`, at most `limit` bytes.
    pub fn read_file(&self, path: &str, limit: u64) -> io::Result<String> {
        let (_, e) = self.resolve(path, true)?;
        let e = e.ok_or_else(enoent)?;
        let mut out = String::new();
        match (&e.upper, e.lower.and_then(|n| self.image.tree.node(n))) {
            (Some(_), Some(n)) if e.meta => {
                if n.entry.size > 0 {
                    self.image
                        .content(&n)?
                        .take(limit)
                        .read_to_string(&mut out)?;
                }
            }
            (Some((fd, st)), _) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
                std::fs::File::from(cp::reopen(fd, st, OFlags::RDONLY)?)
                    .take(limit)
                    .read_to_string(&mut out)?;
            }
            (None, Some(n)) if toc_kind(n.entry.entry_type) == FileType::RegularFile => {
                if n.entry.size > 0 {
                    self.image
                        .content(&n)?
                        .take(limit)
                        .read_to_string(&mut out)?;
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("`{path}` is not a regular file"),
                ))
            }
        }
        Ok(out)
    }

    /// The tar of `path` (links followed), named `name`; `contents` writes
    /// only what a directory holds.  Owners are the container's.
    pub fn archive<W: Write>(
        &self,
        b: &mut tar::Builder<W>,
        path: &str,
        name: &Path,
        contents: bool,
        ids: &IdMaps,
    ) -> io::Result<()> {
        self.archive_excluding(b, path, name, contents, ids, &[])
    }

    /// [`Self::archive`] without the entries of the top directory named in
    /// `exclude` ([`cp::ROOT_EXCLUDES`] for a copy of the root).
    pub fn archive_excluding<W: Write>(
        &self,
        b: &mut tar::Builder<W>,
        path: &str,
        name: &Path,
        contents: bool,
        ids: &IdMaps,
        exclude: &[&str],
    ) -> io::Result<()> {
        let (_, e) = self.resolve(path, true)?;
        let e = e.ok_or_else(enoent)?;
        let contents = contents && self.kind(&e) == Some(FileType::Directory);
        let top = if contents {
            PathBuf::new()
        } else {
            name.to_path_buf()
        };
        // One entry (one descriptor) per level of the path being walked: the
        // names of a directory are listed, and each child is looked up when
        // the walk reaches it, so the descriptors do not grow with the width.
        let mut stack: Vec<(Entry, std::vec::IntoIter<OsString>, PathBuf)> = Vec::new();
        let top_dir = top.clone();
        if self.add(b, &e, &top, !contents, ids)? {
            let names = self.child_names(&e)?;
            stack.push((e, names.into_iter(), top));
        }
        while let Some((dir_entry, iter, dir)) = stack.last_mut() {
            let Some(n) = iter.next() else {
                stack.pop();
                continue;
            };
            if *dir == top_dir && exclude.iter().any(|x| OsStr::new(x) == n) {
                continue;
            }
            let Some(child) = self.child(dir_entry, &n)? else {
                continue;
            };
            let path = dir.join(&n);
            if self.add(b, &child, &path, true, ids)? {
                if stack.len() >= MAX_DEPTH {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the tree is nested too deeply",
                    ));
                }
                let names = self.child_names(&child)?;
                stack.push((child, names.into_iter(), path));
            }
        }
        Ok(())
    }

    /// The names in a directory, sorted: those of the upper directory (as
    /// they are, UTF-8 or not) and of the image below it (a deleted one is
    /// found out by `child`).
    fn child_names(&self, e: &Entry) -> io::Result<Vec<OsString>> {
        let mut names = std::collections::BTreeSet::new();
        if let Some((fd, st)) = &e.upper {
            let dir = cp::reopen(fd, st, OFlags::RDONLY)?;
            names.extend(velarx_base::walk::names(dir.as_fd())?);
        }
        if let Some(l) = e.lower {
            names.extend(
                self.image
                    .tree
                    .children(l)?
                    .into_iter()
                    .map(|(n, _)| OsString::from(n)),
            );
        }
        Ok(names.into_iter().collect())
    }

    /// Write the entry; `true` for a directory whose children follow.
    fn add<W: Write>(
        &self,
        b: &mut tar::Builder<W>,
        e: &Entry,
        path: &Path,
        header: bool,
        ids: &IdMaps,
    ) -> io::Result<bool> {
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        if let Some((fd, st)) = &e.upper {
            let (uid, gid) = ids.to_container(st.st_uid, st.st_gid);
            h.set_mode(st.st_mode & 0o7777);
            h.set_uid(uid.into());
            h.set_gid(gid.into());
            h.set_mtime(st.st_mtime.max(0) as u64);
            match FileType::from_raw_mode(st.st_mode) {
                FileType::Directory => {
                    if header {
                        h.set_entry_type(tar::EntryType::Directory);
                        b.append_data(&mut h, path, io::empty())?;
                    }
                    return Ok(true);
                }
                FileType::RegularFile => {
                    // (the data of a metadata only file are the image's)
                    let below = e
                        .lower
                        .and_then(|l| self.image.tree.node(l))
                        .filter(|_| e.meta);
                    let (f, size) = match below {
                        Some(n) if n.entry.size > 0 => (self.image.content(&n)?, n.entry.size),
                        Some(_) => (std::fs::File::open("/dev/null")?, 0),
                        None => (
                            std::fs::File::from(cp::reopen(fd, st, OFlags::RDONLY)?),
                            st.st_size.max(0) as u64,
                        ),
                    };
                    h.set_entry_type(tar::EntryType::Regular);
                    // (a file with holes is a sparse entry)
                    velarx_wire::sparse::append_file(b, &mut h, path, &f, size)?;
                }
                FileType::Symlink => {
                    h.set_entry_type(tar::EntryType::Symlink);
                    b.append_link(&mut h, path, self.readlink(e)?)?;
                }
                FileType::Fifo => {
                    h.set_entry_type(tar::EntryType::Fifo);
                    b.append_data(&mut h, path, io::empty())?;
                }
                kind @ (FileType::CharacterDevice | FileType::BlockDevice) => cp::append_device(
                    b,
                    &mut h,
                    path,
                    kind == FileType::BlockDevice,
                    (rustix::fs::major(st.st_rdev), rustix::fs::minor(st.st_rdev)),
                )?,
                _ => {}
            }
            return Ok(false);
        }
        let Some(n) = e.lower.and_then(|l| self.image.tree.node(l)) else {
            return Ok(false);
        };
        h.set_mode(n.entry.mode & 0o7777);
        h.set_uid(n.entry.uid.into());
        h.set_gid(n.entry.gid.into());
        h.set_mtime(crate::imagecopy::mtime(&n.entry).tv_sec.max(0) as u64);
        let kind = toc_kind(n.entry.entry_type);
        if kind != FileType::Symlink {
            append_xattrs(b, &n.entry)?;
        }
        match kind {
            FileType::Directory => {
                if header {
                    h.set_entry_type(tar::EntryType::Directory);
                    b.append_data(&mut h, path, io::empty())?;
                }
                Ok(true)
            }
            FileType::RegularFile => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(n.entry.size);
                if n.entry.size == 0 {
                    b.append_data(&mut h, path, io::empty())?;
                } else {
                    let f = self.image.content(&n)?;
                    velarx_wire::sparse::append_file(b, &mut h, path, &f, n.entry.size)?;
                }
                Ok(false)
            }
            FileType::Symlink => {
                h.set_entry_type(tar::EntryType::Symlink);
                b.append_link(&mut h, path, n.entry.link_name.as_deref().unwrap_or(""))?;
                Ok(false)
            }
            FileType::Fifo => {
                h.set_entry_type(tar::EntryType::Fifo);
                b.append_data(&mut h, path, io::empty())?;
                Ok(false)
            }
            FileType::CharacterDevice | FileType::BlockDevice => {
                cp::append_device(
                    b,
                    &mut h,
                    path,
                    kind == FileType::BlockDevice,
                    (
                        n.entry.dev_major.unwrap_or(0),
                        n.entry.dev_minor.unwrap_or(0),
                    ),
                )?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// The directory of the upper directory where a copy to `path` (a
    /// directory, links followed) goes: the directories on the way that
    /// are only in the image are copied up, with the image's mode and
    /// owner.
    pub fn upper_dir_for(&self, path: &str) -> io::Result<OwnedFd> {
        let (comps, e) = self.resolve(path, true)?;
        let e = e.ok_or_else(enoent)?;
        if self.kind(&e) != Some(FileType::Directory) {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        use velarx_sys::fs::{open_beneath, Beneath, BeneathError};
        let open = |dir: &OwnedFd, c: &str| {
            open_beneath(dir.as_fd(), Path::new(c), Beneath::DirectoryPath)
        };
        let mut cur = rustix::io::fcntl_dupfd_cloexec(&self.upper, 0)?;
        let mut lower = self.overlay_layout().then_some(ROOT);
        for c in &comps {
            lower = lower.and_then(|l| self.image.tree.lookup(l, c));
            cur = match open(&cur, c) {
                Ok(fd) => fd,
                Err(BeneathError::Errno(rustix::io::Errno::NOENT)) => {
                    let n = lower
                        .and_then(|l| self.image.tree.node(l))
                        .filter(|n| n.entry.entry_type == TocEntryType::Dir)
                        .ok_or_else(enoent)?;
                    mkdirat(&cur, c.as_str(), Mode::from_raw_mode(0o700))?;
                    let fd = open(&cur, c)?;
                    self.copy_up_attrs(fd.as_fd(), &n)?;
                    fd
                }
                Err(e) => return Err(e.into()),
            };
        }
        Ok(cur)
    }

    /// What makes a directory that a copy to `path` (a directory, as for
    /// `upper_dir_for`) creates below it like the image's, if the view has
    /// the image's there (not below an opaque directory): for
    /// `cp::extract_with`, given the directory's path below `path` and the
    /// directory.
    pub fn copy_up_below(
        &self,
        path: &str,
    ) -> io::Result<impl Fn(&Path, BorrowedFd<'_>) -> io::Result<()> + '_> {
        let (comps, _) = self.resolve(path, true)?;
        Ok(move |rel: &Path, fd: BorrowedFd<'_>| {
            let mut at = comps.clone();
            at.extend(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned()),
            );
            let lower = self.locate(&at)?.and_then(|e| e.lower);
            match lower.and_then(|l| self.image.tree.node(l)) {
                Some(n) if n.entry.entry_type == TocEntryType::Dir => self.copy_up_attrs(fd, &n),
                _ => Ok(()),
            }
        })
    }

    /// Give the directory `fd`, made in the upper directory, the owner and
    /// the mode of the image's directory `n`.
    fn copy_up_attrs(&self, fd: BorrowedFd<'_>, n: &velarx_fuse::view::ViewNode) -> io::Result<()> {
        let (uid, gid) = (
            self.image.translate.uid_of(n.entry.uid),
            self.image.translate.gid_of(n.entry.gid),
        );
        if uid != IdTranslate::NOBODY && gid != IdTranslate::NOBODY {
            rustix::fs::chownat(
                fd,
                "",
                Some(rustix::fs::Uid::from_raw_unchecked(uid)),
                Some(rustix::fs::Gid::from_raw_unchecked(gid)),
                rustix::fs::AtFlags::EMPTY_PATH,
            )?;
        }
        let p = velarx_sys::fd::proc_str(&fd);
        rustix::fs::chmod(p.as_str(), Mode::from_raw_mode(n.entry.mode & 0o7777))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use velarx_fuse::dir_entry;
    use velarx_fuse::view::ImageView;
    use velarx_proto::pod::IdMapping;
    use velarx_storage::{FileStore, Toc};

    struct Fx {
        _d: tempfile::TempDir,
        upper: PathBuf,
        tree: ImageView,
        store: FileStore,
        translate: IdTranslate,
        whiteouts: bool,
    }

    fn entry(name: &str, t: TocEntryType) -> velarx_storage::TocEntry {
        let mut e = dir_entry(name);
        e.entry_type = t;
        e.mode = 0o750;
        e
    }

    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let store = FileStore::new(d.path().join("files")).unwrap();
        let passwd = b"root:x:0:0::/root:/bin/sh\napp:x:1000:1001::/:/bin/sh\n";
        let pd = store
            .put(velarx_types::digest::Algorithm::Sha256, passwd)
            .unwrap();
        let fd = store
            .put(velarx_types::digest::Algorithm::Sha256, b"image file")
            .unwrap();
        let file = |name: &str, digest: &str, size: u64| {
            let mut e = entry(name, TocEntryType::Reg);
            e.fsverity = velarx_storage::to_toc(digest);
            e.size = size;
            e.mode = 0o644;
            e
        };
        let link = |name: &str, target: &str| {
            let mut e = entry(name, TocEntryType::Symlink);
            e.link_name = Some(target.to_string());
            e
        };
        let device = |name: &str, t: TocEntryType, major: u32, minor: u32| {
            let mut e = entry(name, t);
            (e.dev_major, e.dev_minor) = (Some(major), Some(minor));
            e
        };
        let toc = Toc {
            version: 1,
            entries: vec![
                entry("etc", TocEntryType::Dir),
                file("etc/passwd", &pd, passwd.len() as u64),
                link("etc/pw", "/etc/passwd"),
                link("esc", "../../../../../etc"),
                entry("d", TocEntryType::Dir),
                file("d/a", &fd, 10),
                file("d/b", &fd, 10),
                entry("o", TocEntryType::Dir),
                file("o/hidden", &fd, 10),
                entry("o/sub", TocEntryType::Dir),
                entry("dev2", TocEntryType::Dir),
                device("dev2/c", TocEntryType::Char, 5, 1),
                device("dev2/b", TocEntryType::Block, 7, 0),
            ],
            tar_split_digest: None,
        };
        let tree = ImageView::new(vec![velarx_fuse::erofs_tree::Layer::open(Box::new(
            velarx_fuse::layer_erofs::layer_image(&toc.entries)
                .unwrap()
                .image,
        ))
        .unwrap()]);
        let upper = d.path().join("upper");
        std::fs::create_dir_all(upper.join("d")).unwrap();
        std::fs::write(upper.join("d/c"), "upper file").unwrap();
        symlink("/etc", upper.join("out")).unwrap();
        std::fs::create_dir_all(upper.join("o")).unwrap();
        std::fs::write(upper.join("o/shown"), "x").unwrap();
        let p = format!("{}", upper.join("o").display());
        rustix::fs::setxattr(
            p.as_str(),
            "user.overlay.opaque",
            b"y",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        let whiteouts = rustix::fs::mknodat(
            rustix::fs::CWD,
            upper.join("d/b"),
            FileType::CharacterDevice,
            Mode::from_raw_mode(0),
            0,
        )
        .is_ok();
        // the image's root is this user
        let me = |id: u32| {
            vec![IdMapping {
                container_id: 0,
                host_id: id,
                size: 1,
            }]
        };
        Fx {
            _d: d,
            upper,
            tree,
            store,
            translate: IdTranslate {
                uid: me(rustix::process::getuid().as_raw()),
                gid: me(rustix::process::getgid().as_raw()),
                squash: false,
            },
            whiteouts,
        }
    }

    fn view(f: &Fx) -> StoppedView<'_> {
        StoppedView::overlay(
            rustix::fs::open(&f.upper, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap(),
            source(f),
        )
    }

    fn source(f: &Fx) -> TreeSource<'_> {
        TreeSource {
            tree: &f.tree,
            layers: &[],
            objects: &f.store,
            verity: f.store.verity(),
            fetcher: None,
            translate: &f.translate,
        }
    }

    fn names(v: &StoppedView<'_>, path: &str) -> Vec<String> {
        let mut b = tar::Builder::new(Vec::new());
        v.archive(&mut b, path, Path::new("t"), false, &IdMaps::default())
            .unwrap();
        let out = b.into_inner().unwrap();
        tar::Archive::new(&out[..])
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    /// `cp` out of a stopped container reads the files of the store itself:
    /// with `fsverity_require` a file without the fs-verity digest it is
    /// named by is not read (the scratch directory has no fs-verity); with
    /// `fsverity` only where the store has it.
    #[test]
    fn a_file_of_the_store_without_the_required_verity_is_not_read() {
        let mut f = fx();
        assert!(view(&f).read_file("/d/a", 1 << 20).is_ok());
        // `[storage] fsverity` on a store without it (the images of its
        // layers have none): nothing to check, as the overlay of a container
        f.store = f.store.with_verity(velarx_storage::VerityMode::On);
        assert!(view(&f).read_file("/d/a", 1 << 20).is_ok());
        f.store = f.store.with_verity(velarx_storage::VerityMode::Require);
        let err = view(&f).read_file("/d/a", 1 << 20).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        // a file of the upper directory is not the store's
        assert!(view(&f).read_file("/d/c", 1 << 20).is_ok());
    }

    /// The bytes that come from the driver are always held to the key the
    /// table of contents names them by, whatever `[storage] fsverity` says (a
    /// store with the mode off checked nothing of them before): a file of
    /// the store that is not its key's content is not read; a size that is not
    /// the index's is not either.
    #[test]
    fn what_the_driver_gives_is_checked_against_its_key_whatever_the_mode() {
        let f = fx();
        assert_eq!(f.store.verity(), velarx_storage::VerityMode::Off);
        assert!(view(&f).read_file("/d/a", 1 << 20).is_ok());
        let path = std::fs::read_dir(f.store.root())
            .unwrap()
            .flatten()
            .filter(|d| d.path().is_dir())
            .flat_map(|d| std::fs::read_dir(d.path()).unwrap().flatten())
            .map(|e| e.path())
            .find(|p| std::fs::metadata(p).unwrap().len() == 10)
            .expect("the file of d/a");
        // the same size, other bytes
        let keep = std::fs::read(&path).unwrap();
        let mut bad = keep.clone();
        bad[0] ^= 0xff;
        let mode = std::fs::metadata(&path).unwrap().permissions();
        let mut w = mode.clone();
        std::os::unix::fs::PermissionsExt::set_mode(&mut w, 0o644);
        std::fs::set_permissions(&path, w).unwrap();
        std::fs::write(&path, &bad).unwrap();
        let err = view(&f).read_file("/d/a", 1 << 20).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
        // another size is refused by the driver before the digest is looked at
        std::fs::write(&path, &keep[..9]).unwrap();
        assert!(view(&f).read_file("/d/a", 1 << 20).is_err());
        // the content of the key is read
        std::fs::write(&path, &keep).unwrap();
        assert!(view(&f).read_file("/d/a", 1 << 20).is_ok());
    }

    #[test]
    fn a_directory_layout_is_the_whole_root_and_reads_no_image() {
        let f = fx();
        let root = f.upper.join("copy");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/own"), "mine").unwrap();
        symlink("own", root.join("etc/link")).unwrap();
        // what the image has is not in the directory: it is not there
        // (a 0:0 device needs no privilege: it is the overlay's whiteout)
        let dev = rustix::fs::mknodat(
            rustix::fs::CWD,
            root.join("etc/zero"),
            rustix::fs::FileType::CharacterDevice,
            Mode::from_raw_mode(0o600),
            0,
        )
        .is_ok();
        let v = StoppedView::directory(
            rustix::fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap(),
            source(&f),
        );
        assert_eq!(v.read_file("/etc/own", 1 << 20).unwrap(), "mine");
        assert_eq!(v.stat("/etc/link").unwrap().1, "/etc/own");
        assert_eq!(
            v.stat("/etc/passwd").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        let mut want = vec!["t", "t/link", "t/own"];
        if dev {
            // a 0:0 device is a device here, not a deletion (`cp` copies no
            // device, so it is not in the archive); the same directory as the
            // upper of an overlay reads it as a whiteout
            want.push("t/zero");
            let (st, _) = v.stat("/etc/zero").unwrap();
            assert_eq!(st.mode & libc::S_IFMT, libc::S_IFCHR);
            let o = StoppedView::overlay(
                rustix::fs::open(&root, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap(),
                source(&f),
            );
            assert_eq!(
                o.stat("/etc/zero").unwrap_err().raw_os_error(),
                Some(libc::ENOENT)
            );
        } else {
            eprintln!("SKIPPED: no 0:0 device here");
        }
        let listed = names(&v, "/etc");
        assert!(want
            .iter()
            .filter(|n| **n != "t/zero")
            .all(|n| listed.iter().any(|l| l == n)));
        let d = v.upper_dir_for("/etc").unwrap();
        rustix::fs::statat(&d, "own", rustix::fs::AtFlags::SYMLINK_NOFOLLOW).unwrap();
    }

    #[test]
    fn merged_listing() {
        let f = fx();
        let v = view(&f);
        let mut want = vec!["t", "t/a", "t/c"];
        if !f.whiteouts {
            want.insert(2, "t/b");
        }
        assert_eq!(names(&v, "/d"), want);
        // an opaque directory hides the image's
        assert_eq!(names(&v, "/o"), ["t", "t/shown"]);
    }

    /// The root of the overlay is the merge of the roots of its layers: the
    /// attribute of an opaque directory on the upper root hides nothing.
    #[test]
    fn an_opaque_upper_root_hides_nothing() {
        let f = fx();
        if rustix::fs::setxattr(
            format!("{}", f.upper.display()).as_str(),
            "user.overlay.opaque",
            b"y",
            rustix::fs::XattrFlags::empty(),
        )
        .is_err()
        {
            return;
        }
        assert!(names(&view(&f), "/").contains(&"t/etc/passwd".to_string()));
    }

    /// The devices of the image are archived as headers with their numbers
    /// (podman's `tar.FileInfoHeader`), never opened, and the whiteouts of
    /// the upper directory (devices 0:0) are not entries.
    #[test]
    fn the_devices_of_the_image_are_archived_and_the_whiteouts_are_not() {
        let f = fx();
        let v = view(&f);
        let mut b = tar::Builder::new(Vec::new());
        v.archive(&mut b, "/dev2", Path::new("t"), false, &IdMaps::default())
            .unwrap();
        let out = b.into_inner().unwrap();
        let got: Vec<_> = tar::Archive::new(&out[..])
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                let device = matches!(h.entry_type(), tar::EntryType::Char | tar::EntryType::Block)
                    .then(|| (h.device_major().unwrap(), h.device_minor().unwrap()));
                (
                    e.path().unwrap().to_string_lossy().into_owned(),
                    h.entry_type(),
                    device,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("t".to_string(), tar::EntryType::Directory, None),
                (
                    "t/b".to_string(),
                    tar::EntryType::Block,
                    Some((Some(7), Some(0)))
                ),
                (
                    "t/c".to_string(),
                    tar::EntryType::Char,
                    Some((Some(5), Some(1)))
                ),
            ]
        );
        if f.whiteouts {
            assert!(!names(&v, "/d").contains(&"t/b".to_string()));
        }
    }

    /// A directory of many entries is archived whole; its children are
    /// looked up when the walk reaches them (one descriptor per level, not
    /// per entry).
    #[test]
    fn a_wide_directory_is_archived_whole() {
        let f = fx();
        let wide = f.upper.join("wide");
        std::fs::create_dir(&wide).unwrap();
        for i in 0..300 {
            std::fs::write(wide.join(format!("f{i:03}")), "x").unwrap();
        }
        let v = view(&f);
        let mut b = tar::Builder::new(Vec::new());
        v.archive(&mut b, "/wide", Path::new("w"), false, &IdMaps::default())
            .unwrap();
        let got = tar::Archive::new(&b.into_inner().unwrap()[..])
            .entries()
            .unwrap()
            .count();
        assert_eq!(got, 301);
    }

    /// The descriptors an archive holds follow the depth of the tree, not
    /// the width of its directories: a tree with directories of 300 entries
    /// is archived under a limit of descriptors far below that (in a
    /// process of its own: the limit is the whole process's).
    #[test]
    fn the_descriptors_of_an_archive_follow_the_depth_not_the_width() {
        velarx_base::testing::in_child(|| {
            let f = fx();
            let mut d = f.upper.join("wide");
            for level in 0..8 {
                std::fs::create_dir_all(&d).unwrap();
                for i in 0..300 {
                    std::fs::write(d.join(format!("f{i:03}")), "x").unwrap();
                }
                d = d.join(format!("d{level}"));
            }
            let v = view(&f);
            let highest = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u64>().ok())
                .max()
                .unwrap();
            use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
            // (8 levels and a few transient ones: far below 300)
            let lim = Rlimit {
                current: Some(highest + 1 + 32),
                maximum: getrlimit(Resource::Nofile).maximum,
            };
            setrlimit(Resource::Nofile, lim).unwrap();
            let mut b = tar::Builder::new(Vec::new());
            v.archive(&mut b, "/wide", Path::new("w"), false, &IdMaps::default())
                .unwrap();
            let got = tar::Archive::new(&b.into_inner().unwrap()[..])
                .entries()
                .unwrap()
                .count();
            // 8 directories, 300 files in each
            assert_eq!(got, 8 + 8 * 300);
        });
    }

    /// A name that is not UTF-8 is archived as it is, not dropped.
    #[test]
    fn a_name_that_is_not_utf8_is_archived() {
        let f = fx();
        let d = f.upper.join("bytes");
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join(OsStr::from_bytes(b"f\xff")), "x").unwrap();
        let v = view(&f);
        let mut b = tar::Builder::new(Vec::new());
        v.archive(&mut b, "/bytes", Path::new("b"), false, &IdMaps::default())
            .unwrap();
        let out = b.into_inner().unwrap();
        let mut a = tar::Archive::new(&out[..]);
        let names: Vec<Vec<u8>> = a
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path_bytes().into_owned())
            .collect();
        assert_eq!(names, vec![b"b".to_vec(), b"b/f\xff".to_vec()]);
    }

    /// A directory of the upper directory on another mount (a bind mount
    /// of the same file system too) is an error, not walked into (run in a
    /// user and mount namespace of its own; skipped without one).
    #[test]
    fn a_mount_below_the_upper_directory_is_refused() {
        const NAME: &str = "cpview::tests::a_mount_below_the_upper_directory_is_refused";
        if std::env::var_os("VELARX_CPVIEW_MOUNT").is_some() {
            let f = fx();
            let (m, other) = (f.upper.join("m"), f.upper.join("..").join("other"));
            std::fs::create_dir(&m).unwrap();
            std::fs::create_dir_all(&other).unwrap();
            std::fs::write(other.join("secret"), "x").unwrap();
            rustix::mount::mount_bind(&other, &m).unwrap();
            let v = view(&f);
            let mut b = tar::Builder::new(Vec::new());
            let e = v
                .archive(&mut b, "/", Path::new("r"), false, &IdMaps::default())
                .unwrap_err();
            assert!(e.to_string().contains("is a mount"), "{e}");
            let e = v.stat("/m/secret").unwrap_err();
            assert!(e.to_string().contains("is a mount"), "{e}");
            return;
        }
        // (the files of the child go in a directory removed here, once the
        // child and its mount are gone)
        let tmp = tempfile::tempdir().unwrap();
        let out = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("VELARX_CPVIEW_MOUNT", "1")
            .env("TMPDIR", tmp.path())
            .output();
        let Ok(out) = out else {
            return;
        };
        let err = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && err.contains("unshare") {
            // (no user namespaces here)
            return;
        }
        let text = format!("{}{err}", String::from_utf8_lossy(&out.stdout));
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    /// The names of the top directory that are left out of a copy of the
    /// root are those of the top only.
    #[test]
    fn the_top_names_left_out_are_those_of_the_top_only() {
        let f = fx();
        let v = view(&f);
        let mut b = tar::Builder::new(Vec::new());
        v.archive_excluding(
            &mut b,
            "/",
            Path::new(""),
            true,
            &IdMaps::default(),
            &["dev2", "d", "a"],
        )
        .unwrap();
        let out = b.into_inner().unwrap();
        let got: Vec<String> = tar::Archive::new(&out[..])
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(got.contains(&"etc/passwd".to_string()), "{got:?}");
        assert!(
            got.iter()
                .all(|p| !p.starts_with("dev2") && !p.starts_with("d/")),
            "{got:?}"
        );
        // (not by the name alone: `a` of `d` is gone with `d`; `etc` stays)
        assert!(got.contains(&"o/shown".to_string()), "{got:?}");
    }

    /// An empty file with `overlay.whiteout` is a deletion as a device 0:0
    /// is.
    #[test]
    fn a_whiteout_made_with_an_xattr_hides_the_entry_of_the_image() {
        let f = fx();
        let p = f.upper.join("d/a");
        std::fs::write(&p, "").unwrap();
        if rustix::fs::setxattr(
            &p,
            "user.overlay.whiteout",
            b"a value longer than a few bytes",
            rustix::fs::XattrFlags::empty(),
        )
        .is_err()
        {
            return;
        }
        let v = view(&f);
        assert!(v.stat("/d/a").is_err());
        assert!(!names(&v, "/d").contains(&"t/a".to_string()));
    }

    #[test]
    fn links_are_resolved_in_the_root() {
        let f = fx();
        let v = view(&f);
        let (st, target) = v.stat("/etc/pw").unwrap();
        assert_eq!(target, "/etc/passwd");
        assert!(!st.is_dir);
        // a link of the upper directory to /etc is the image's /etc
        assert_eq!(v.stat("/out").unwrap().1, "/etc");
        assert_eq!(v.stat("/esc/passwd").unwrap().1, "/etc/passwd");
        assert!(v
            .read_file("/out/passwd", 1 << 20)
            .unwrap()
            .contains("app:x:1000"));
        assert_eq!(v.stat("/../../etc").unwrap().1, "/etc");
        assert_eq!(
            v.stat("/nope").unwrap_err().raw_os_error(),
            Some(libc::ENOENT)
        );
        if f.whiteouts {
            assert!(v.stat("/d/b").is_err());
        }
        assert_eq!(
            cp::user_of("app", |p| v.read_file(p, 1 << 20)).unwrap(),
            (1000, 1001)
        );
    }

    #[test]
    fn copies_go_to_the_upper_directory() {
        let f = fx();
        let v = view(&f);
        let dir = v.upper_dir_for("/etc").unwrap();
        let mode = std::fs::metadata(f.upper.join("etc")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.permissions().mode() & 0o777, 0o750);
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, "new", &b"abc"[..]).unwrap();
        let t = b.into_inner().unwrap();
        cp::extract(&t[..], dir.as_fd(), &Default::default()).unwrap();
        assert_eq!(std::fs::read(f.upper.join("etc/new")).unwrap(), b"abc");
        assert_eq!(v.read_file("/etc/new", 10).unwrap(), "abc");
        // through the link of the upper directory: still in the root
        let dir = v.upper_dir_for("/out").unwrap();
        cp::extract(&t[..], dir.as_fd(), &Default::default()).unwrap();
        assert!(f.upper.join("etc/new").exists());
        assert!(v.upper_dir_for("/etc/passwd").is_err());
    }

    /// A directory that is only in the image and that a copy makes on the
    /// way to its entry gets the image's mode and owner, as when the copy
    /// goes into it; one the image has below an opaque directory is not
    /// there for the copy.  As root the image's root is another user than
    /// the copier; without root they are the same, and the owner is not
    /// checked.
    #[test]
    fn a_parent_only_in_the_image_is_copied_up_as_it_is() {
        use std::os::unix::fs::MetadataExt;
        let mut b = tar::Builder::new(Vec::new());
        for path in ["etc/sub/new", "o/sub/new"] {
            let mut h = tar::Header::new_gnu();
            h.set_size(3);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, path, &b"abc"[..]).unwrap();
        }
        let t = b.into_inner().unwrap();
        let root_user = rustix::process::geteuid().is_root();
        let fixture = || {
            let mut f = fx();
            if root_user {
                let other = vec![IdMapping {
                    container_id: 0,
                    host_id: 4321,
                    size: 1,
                }];
                f.translate.uid = other.clone();
                f.translate.gid = other;
            }
            f
        };

        let f = fixture();
        let v = view(&f);
        let root = v.upper_dir_for("/").unwrap();
        let up = v.copy_up_below("/").unwrap();
        let copier = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let opts = cp::ExtractOptions {
            owner: Some(copier),
            ..Default::default()
        };
        cp::extract_with(&t[..], root.as_fd(), &opts, &up).unwrap();
        let made = std::fs::metadata(f.upper.join("etc")).unwrap();
        assert_eq!(std::fs::read(f.upper.join("etc/sub/new")).unwrap(), b"abc");

        let g = fixture();
        view(&g).upper_dir_for("/etc").unwrap();
        let want = std::fs::metadata(g.upper.join("etc")).unwrap();
        assert_eq!(made.mode() & 0o7777, want.mode() & 0o7777);
        assert_eq!(made.mode() & 0o7777, 0o750);
        assert_eq!((made.uid(), made.gid()), (want.uid(), want.gid()));
        if root_user {
            assert_eq!((made.uid(), made.gid()), (4321, 4321));
        }
        // a directory that is not in the image is the copier's, and so is
        // one of the image hidden by an opaque directory
        for dir in ["etc/sub", "o/sub"] {
            let st = std::fs::metadata(f.upper.join(dir)).unwrap();
            assert_eq!(st.mode() & 0o7777, 0o755, "{dir}");
            assert_eq!((st.uid(), st.gid()), copier, "{dir}");
        }
    }
}
