// SPDX-License-Identifier: Apache-2.0
//! The changes in an overlay upper directory: as the tar stream of a layer,
//! or as the list of what was added, changed and deleted.
//!
//! Overlay whiteouts (0:0 character devices and `overlay.whiteout` xattrs)
//! become `.wh.` entries and opaque directories get a `.wh..wh..opq` entry.
//! Hard links are detected, overlay and SELinux xattrs are dropped.  The
//! directory may still be written by a container: nothing is followed, a
//! regular file is opened with `O_PATH`, checked and opened again, and a
//! file that changes while it is read is an error.  Entries are sorted, so
//! the same tree gives the same stream.
//!
//! This is the reading of the upper directory of an overlay: it is behind
//! `StorageDriver::diff` and `changes` of the `composefs` driver; the engine
//! calls it on a container's layer itself only for a squash (`record`, and
//! `overlay_marks` in the build's merge, on the directory that
//! `WritableDiff::directory` gives).  What does not depend on the
//! overlay (the options, hard links, the ids of the user namespace, the tar
//! writing, the walk of a plain directory as a build step's) is shared, and
//! is to be split from the overlay's marks (`overlay_marks`, `Lower`) when a
//! driver with another kind of layer needs it.  The image below is an
//! `ImageTree`.

use rustix::fd::{BorrowedFd, OwnedFd};
use rustix::fs::{fstat, lgetxattr, llistxattr, openat, readlinkat, FileType, Mode, OFlags, Stat};
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::io;

pub mod copydiff;

use super::holes::{changed, copy_file, pad, HoleWrite};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::Arc;
use velarx_base::walk::{Visit, Walk};

/// The longest path of an entry.
const MAX_PATH: usize = 4096;
const MAX_XATTR_LIST: usize = 64 * 1024;
const MAX_XATTR_VALUE: usize = 64 * 1024;

/// The files an engine puts in the root file system of a container: they
/// are not changes of the container.
pub const ENGINE_FILES: &[&str] = &[
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/mtab",
    "/run/.containerenv",
];

/// A range of ids: `container` is where `host` starts in the user namespace
/// of the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdRange {
    pub container: u32,
    pub host: u32,
    pub size: u32,
}

/// The image below the upper directory of a container whose overlay has
/// `metacopy=on`: a file the container changed the metadata of is in the
/// upper directory without its data, and one it renamed with the name of
/// the file below (`redirect`), as a directory it renamed is without what
/// it holds.  The images of the layers say what the files below are, the
/// objects ([`velarx_storage::ObjectOpener`]: the driver that holds the
/// layers, never a path of the engine's own store) have their data.
pub struct Lower {
    pub tree: Arc<dyn velarx_fuse::view::ImageTree>,
    pub objects: Arc<dyn velarx_storage::ObjectOpener>,
}

impl std::fmt::Debug for Lower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Lower")
    }
}

impl Lower {
    fn node(&self, path: &str) -> Option<(usize, velarx_fuse::view::ViewNode)> {
        let i = self.tree.resolve(path)?;
        Some((i, self.tree.node(i)?))
    }

    /// The object that has the content of the entry.
    fn content<'a>(&self, e: &velarx_storage::TocEntry, shown: &'a str) -> io::Result<Content<'a>> {
        let key = e
            .verity()
            .ok_or_else(|| io::Error::other(format!("`{}` has no fs-verity digest", e.name)))?;
        Ok(Content::Store {
            object: Object {
                objects: self.objects.clone(),
                key,
                size: e.size,
            },
            shown,
        })
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// The path below that a `redirect` attribute says, for an entry of the
/// directory `dir` below (absolute from the root of the layers, else a name
/// of the directory).
fn redirect_to(dir: &str, redirect: &[u8]) -> Option<String> {
    let r = std::str::from_utf8(redirect).ok()?;
    Some(match r.strip_prefix('/') {
        Some(abs) => abs.to_string(),
        None => join(dir, r),
    })
}

#[derive(Debug, Default, Clone)]
pub struct Options {
    /// The image below, when the upper directory has metadata only files
    /// and redirects.
    pub lower: Option<Arc<Lower>>,
    /// Paths (`/etc/hosts`, the mount points of a RUN) that are not
    /// changes: whatever is there (a file, a whiteout) is left out, and so
    /// are a directory and its parent directories when nothing else is in
    /// them.
    pub exclude: Vec<String>,
    /// The mappings of the container's user namespace, to give the files the
    /// ids the container sees.  Empty: the ids are used as they are.
    pub uid_map: Vec<IdRange>,
    pub gid_map: Vec<IdRange>,
    /// The times of the files of the layer.
    pub mtime: Mtime,
    /// The changes of a copy of an image (`copydiff`): the copy could not
    /// give its files the owners of the image, so those of this owner (the
    /// host's ids) are the image's, whatever it says.
    pub unowned: Option<(u32, u32)>,
    /// When the layer has an entry for the directory itself (`./`).
    pub root: Root,
    /// The root of the file system the changes are made on: the directory
    /// is not one (the files of a `COPY`), and what it has for `./` is this
    /// entry, the one the layers below leave visible.
    pub below: Option<Arc<velarx_storage::TocEntry>>,
}

/// When the layer of the changes in a directory has an entry for its root:
/// a layer without one has a plain root (0755, root, no time, no
/// attributes) in place of the one below it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    /// Never: the directory is not a root file system (the files of a
    /// `COPY`, the diff of a container).
    #[default]
    Never,
    /// When its mode, owner or attributes are not those of a plain root (the
    /// root of a build step's container, which has those of the step's base:
    /// the layer keeps them, as a layer without the entry has a plain root).
    Changed,
    /// Always, with its mode, owner, time and attributes (a commit).
    Always,
}

/// The time a file of a layer gets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Mtime {
    /// Its own
    #[default]
    Keep,
    /// This one, seconds since the epoch (`build --timestamp`)
    Fixed(i64),
    /// Its own, at most this one (`build --rewrite-timestamp`)
    Clamp(i64),
}

impl Mtime {
    /// The time of a file whose own is `t`.
    pub fn of(self, t: i64) -> u64 {
        match self {
            Self::Keep => t,
            Self::Fixed(f) => f,
            Self::Clamp(c) => t.min(c),
        }
        .max(0) as u64
    }
}

impl Options {
    /// The owner the container sees for the owner `uid:gid` of a file.
    pub fn to_container(&self, uid: u32, gid: u32) -> io::Result<(u32, u32)> {
        Ok((
            map_id(uid, &self.uid_map, "uid")?,
            map_id(gid, &self.gid_map, "gid")?,
        ))
    }

    pub fn excluded(&self, path: &str) -> bool {
        self.exclude
            .iter()
            .any(|x| x.trim_start_matches('/') == path)
    }

    /// Whether `dir` (`etc/`) is excluded or a parent of an excluded path:
    /// it is a change only with something else in it.
    pub fn holds_excluded(&self, dir: &str) -> bool {
        self.exclude.iter().any(|x| {
            let x = x.trim_start_matches('/');
            x.starts_with(dir) || dir.strip_suffix('/') == Some(x)
        })
    }
}

fn map_id(id: u32, ranges: &[IdRange], what: &str) -> io::Result<u32> {
    if ranges.is_empty() {
        return Ok(id);
    }
    ranges
        .iter()
        .find(|r| id >= r.host && (id - r.host) < r.size)
        .map(|r| r.container + (id - r.host))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the {what} {id} is not mapped in the user namespace of the container"),
            )
        })
}

/// What the xattrs of a node say.
#[derive(Default)]
struct Attrs {
    /// The ones that go in the layer, sorted.
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    opaque: bool,
    whiteout: bool,
    /// The overlay says the data is below, at this path if it says (`redirect`).
    metacopy: bool,
    redirect: Option<Vec<u8>>,
}

/// The path of `name` in `dir` for the `l*xattr` calls: the last component
/// is not followed.
fn proc_path(dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<CString> {
    velarx_sys::fd::proc_child(&dir, name)
}

fn get_xattr(path: &CString, name: &[u8], shown: &str) -> io::Result<Option<Vec<u8>>> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "an xattr name has a NUL"))?;
    let mut value = vec![0u8; 256];
    loop {
        match lgetxattr(path, &name, &mut value) {
            Ok(len) => {
                value.truncate(len);
                return Ok(Some(value));
            }
            Err(rustix::io::Errno::RANGE) if value.len() < MAX_XATTR_VALUE => {
                value.resize((value.len() * 8).min(MAX_XATTR_VALUE), 0)
            }
            Err(rustix::io::Errno::RANGE) => {
                return Err(io::Error::other(format!(
                    "an xattr of `{shown}` is too big"
                )))
            }
            // Removed meanwhile.
            Err(rustix::io::Errno::NODATA) => return Ok(None),
            Err(e) => return Err(io::Error::from(e)),
        }
    }
}

/// The xattrs of `name` in `dir`.
fn read_xattrs(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    shown: &str,
    lower: bool,
    plain: bool,
) -> io::Result<Attrs> {
    let mut out = Attrs::default();
    let path = proc_path(dir, name)?;
    let mut list = vec![0u8; 1024];
    let len = loop {
        match llistxattr(&path, &mut list) {
            Ok(n) => break n,
            Err(rustix::io::Errno::RANGE) if list.len() < MAX_XATTR_LIST => {
                list.resize((list.len() * 8).min(MAX_XATTR_LIST), 0)
            }
            Err(rustix::io::Errno::RANGE) => {
                return Err(io::Error::other(format!("too many xattrs for `{shown}`")))
            }
            Err(rustix::io::Errno::NOTSUP) => return Ok(out),
            Err(e) => return Err(io::Error::from(e)),
        }
    };
    let mut names: Vec<&[u8]> = list[..len]
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty())
        .collect();
    names.sort_unstable();
    for n in names {
        let overlay = n
            .strip_prefix(b"trusted.overlay.")
            .or_else(|| n.strip_prefix(b"user.overlay."));
        match overlay {
            // (a plain directory has no marks of an overlay: what a
            // container set with those names is not read as one)
            Some(_) if plain => {}
            Some(b"metacopy") if lower => out.metacopy = true,
            Some(b"redirect") if lower => out.redirect = get_xattr(&path, n, shown)?,
            Some(b"redirect") | Some(b"metacopy") => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "`{shown}` has the overlay xattr `{}`: not supported",
                        String::from_utf8_lossy(n)
                    ),
                ))
            }
            Some(b"whiteout") => out.whiteout = true,
            Some(b"opaque") => {
                out.opaque = get_xattr(&path, n, shown)?.as_deref() == Some(b"y".as_slice())
            }
            Some(_) => {}
            None if n == b"security.selinux" => {}
            None => {
                if let Some(v) = get_xattr(&path, n, shown)? {
                    out.xattrs.push((n.to_vec(), v));
                }
            }
        }
    }
    Ok(out)
}

fn utf8_name(prefix: &str, name: &OsStr) -> io::Result<String> {
    name.to_str().map(str::to_string).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("`{prefix}{}` is not UTF-8", name.to_string_lossy()),
        )
    })
}

/// Whether `name` of `dir` (whose stat is `st`) is an overlay whiteout,
/// and whether it is an opaque directory.
pub fn overlay_marks(dir: BorrowedFd<'_>, name: &OsStr, st: &Stat) -> io::Result<(bool, bool)> {
    if is_whiteout_device(st) {
        return Ok((true, false));
    }
    let a = read_xattrs(dir, name, &name.to_string_lossy(), false, false)?;
    let regular = FileType::from_raw_mode(st.st_mode) == FileType::RegularFile;
    Ok((a.whiteout && regular && st.st_size == 0, a.opaque))
}

fn is_whiteout_device(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::CharacterDevice && st.st_rdev == 0
}

/// A directory header that is written only if something goes below it.
struct Pending {
    header: tar::Header,
    path: String,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The content of an entry of the archive: where it is read from, when the
/// entry is written (or later, when it is only recorded).
pub enum Content<'a> {
    None,
    /// A regular file of the walked directory, as it was seen.
    Upper {
        dir: BorrowedFd<'a>,
        name: &'a OsStr,
        shown: &'a str,
        seen: &'a Stat,
    },
    /// An object of the image below.
    Store {
        object: Object,
        shown: &'a str,
    },
    /// A file the caller opened (the object of a tree a squash walks, a
    /// file of the changes it recorded); `seen`, when the file must be
    /// the one that was seen and not have changed while it was read.
    Opened {
        file: std::fs::File,
        size: u64,
        shown: &'a str,
        seen: Option<&'a Stat>,
    },
}

/// An object of the image below, opened when its content is written.
#[derive(Clone)]
pub struct Object {
    objects: Arc<dyn velarx_storage::ObjectOpener>,
    key: String,
    size: u64,
}

impl Object {
    /// The object `key` of `size` bytes, read through `objects`.
    pub fn new(objects: Arc<dyn velarx_storage::ObjectOpener>, key: String, size: u64) -> Self {
        Self { objects, key, size }
    }

    /// The object as a regular file of exactly its size (`NotFound` when
    /// the driver does not have it).
    fn open(&self) -> io::Result<std::fs::File> {
        self.objects.object_file(&self.key, self.size)
    }
}

/// Where the entries of the walk go.
pub trait Out {
    /// Extended header records for the next entry.
    fn pax(&mut self, records: &[(String, &[u8])]) -> io::Result<()>;
    /// The entry with the header `h` (its size is the size of the content).
    fn entry(&mut self, h: &mut tar::Header, path: &str, content: Content<'_>) -> io::Result<()>;
    fn link(&mut self, h: &mut tar::Header, path: &str, target: &OsStr) -> io::Result<()>;
}

/// Open the file of a regular entry for reading.
pub fn open_content(content: &Content<'_>) -> io::Result<Option<(std::fs::File, u64)>> {
    Ok(match content {
        Content::None => None,
        Content::Upper {
            dir,
            name,
            shown,
            seen,
        } => Some((
            std::fs::File::from(open_checked(*dir, name, seen, shown)?),
            seen.st_size.max(0) as u64,
        )),
        Content::Store { object, .. } => Some((object.open()?, object.size)),
        Content::Opened { file, size, .. } => Some((file.try_clone()?, *size)),
    })
}

/// Whether a file written while it was read: it has another size or time.
pub fn check_after(file: &std::fs::File, seen: &Stat, shown: &str) -> io::Result<()> {
    let after = fstat(file)?;
    if after.st_size != seen.st_size
        || (after.st_mtime, after.st_mtime_nsec) != (seen.st_mtime, seen.st_mtime_nsec)
    {
        return Err(changed(shown));
    }
    Ok(())
}

/// The tar stream: the content of a file is copied as it is read, its holes
/// as holes.
pub struct TarOut<W: HoleWrite> {
    builder: tar::Builder<W>,
}

impl<W: HoleWrite> TarOut<W> {
    pub fn new(out: W) -> Self {
        Self {
            builder: tar::Builder::new(out),
        }
    }

    /// The end of the archive, and the writer.
    pub fn finish(self) -> io::Result<W> {
        self.builder.into_inner()
    }
}

impl<W: HoleWrite> Out for TarOut<W> {
    fn pax(&mut self, records: &[(String, &[u8])]) -> io::Result<()> {
        self.builder
            .append_pax_extensions(records.iter().map(|(k, v)| (k.as_str(), *v)))
    }

    fn entry(&mut self, h: &mut tar::Header, path: &str, content: Content<'_>) -> io::Result<()> {
        let opened = open_content(&content)?;
        // (the header, and the content that follows it)
        self.builder.append_data(h, path, io::empty())?;
        let Some((file, size)) = opened else {
            return Ok(());
        };
        let shown = match &content {
            Content::Upper { shown, .. }
            | Content::Store { shown, .. }
            | Content::Opened { shown, .. } => *shown,
            Content::None => path,
        };
        let out: &mut dyn HoleWrite = self.builder.get_mut();
        copy_file(&file, size, out, shown)?;
        pad(out, size)?;
        match content {
            Content::Upper { seen, shown, .. }
            | Content::Opened {
                seen: Some(seen),
                shown,
                ..
            } => check_after(&file, seen, shown),
            _ => Ok(()),
        }
    }

    fn link(&mut self, h: &mut tar::Header, path: &str, target: &OsStr) -> io::Result<()> {
        self.builder.append_link(h, path, PathBuf::from(target))
    }
}

/// Where the content of a recorded entry is.
#[derive(Clone)]
pub enum Data {
    None,
    /// The regular file `path` of the walked directory, as it was seen.
    Upper {
        path: String,
        seen: Stat,
    },
    Store(Object),
}

impl Data {
    /// The size of the content.
    pub fn size(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Upper { seen, .. } => seen.st_size.max(0) as u64,
            Self::Store(object) => object.size,
        }
    }
}

/// An entry the walk recorded: what [`replay`] needs to give it to an
/// [`Out`] later, decoded (the header, its extended records, the target of
/// a link), and where its content is.
pub struct Recorded {
    pub path: String,
    pub kind: tar::EntryType,
    header: tar::Header,
    pax: Vec<(String, Vec<u8>)>,
    link: Option<PathBuf>,
    pub data: Data,
}

impl Recorded {
    /// The bytes the entry takes in the tar stream it stands for, header
    /// and extended header blocks, content and padding.
    pub fn stream_len(&self) -> u64 {
        let pax: usize = self.pax.iter().map(|(k, v)| k.len() + v.len() + 24).sum();
        let pax = if pax == 0 {
            0
        } else {
            512 + (pax as u64).div_ceil(512) * 512
        };
        pax + 512 + self.data.size().div_ceil(512) * 512
    }
}

/// The walk without the content: the entries are kept decoded, and what is
/// needed to read the content later is kept in memory.
struct Recorder {
    pax: Vec<(String, Vec<u8>)>,
    entries: Vec<Recorded>,
}

impl Recorder {
    fn record(
        &mut self,
        h: &tar::Header,
        path: &str,
        link: Option<PathBuf>,
        data: Data,
    ) -> io::Result<()> {
        // (an upper directory is not bounded: what is kept is)
        if self.entries.len() >= crate::pull::entry::MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the layer has too many entries (more than {})",
                    crate::pull::entry::MAX_ENTRIES
                ),
            ));
        }
        self.entries.push(Recorded {
            path: path.to_string(),
            kind: h.entry_type(),
            header: h.clone(),
            pax: std::mem::take(&mut self.pax),
            link,
            data,
        });
        Ok(())
    }
}

impl Out for Recorder {
    fn pax(&mut self, records: &[(String, &[u8])]) -> io::Result<()> {
        self.pax
            .extend(records.iter().map(|(k, v)| (k.clone(), v.to_vec())));
        Ok(())
    }

    fn entry(&mut self, h: &mut tar::Header, path: &str, content: Content<'_>) -> io::Result<()> {
        let data = match content {
            Content::None => Data::None,
            Content::Upper { shown, seen, .. } => Data::Upper {
                path: shown.to_string(),
                seen: *seen,
            },
            Content::Store { object, .. } => Data::Store(object),
            Content::Opened { .. } => {
                return Err(io::Error::other("an opened file is not recorded"))
            }
        };
        self.record(h, path, None, data)
    }

    fn link(&mut self, h: &mut tar::Header, path: &str, target: &OsStr) -> io::Result<()> {
        self.record(h, path, Some(PathBuf::from(target)), Data::None)
    }
}

struct Walker<'o> {
    out: &'o mut dyn Out,
    opts: Options,
    /// (dev, ino) of the files with more links than one, and their first path.
    links: HashMap<(u64, u64), String>,
    /// The same for the files of the image below that go in the layer.
    lower_links: HashMap<(usize, u64), String>,
    pending: Vec<Pending>,
}

impl Walker<'_> {
    /// The header and the attributes of the root `e` of a table of contents.
    fn root_of(&self, e: &velarx_storage::TocEntry) -> (tar::Header, Attrs) {
        use base64::Engine;
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(e.mode & 0o7777);
        h.set_uid(e.uid.into());
        h.set_gid(e.gid.into());
        h.set_mtime(self.opts.mtime.of(e.mtime().0));
        h.set_size(0);
        let xattrs = e
            .xattrs
            .iter()
            .filter(|(k, _)| !velarx_fuse::hidden_xattr(k))
            .filter_map(|(k, v)| {
                let v = base64::engine::general_purpose::STANDARD.decode(v).ok()?;
                Some((k.clone().into_bytes(), v))
            })
            .collect();
        (
            h,
            Attrs {
                xattrs,
                ..Attrs::default()
            },
        )
    }

    fn header(&self, st: &Stat, kind: tar::EntryType) -> io::Result<tar::Header> {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(st.st_mode & 0o7777);
        h.set_uid(u64::from(map_id(st.st_uid, &self.opts.uid_map, "uid")?));
        h.set_gid(u64::from(map_id(st.st_gid, &self.opts.gid_map, "gid")?));
        h.set_mtime(self.opts.mtime.of(st.st_mtime));
        h.set_size(0);
        Ok(h)
    }

    fn pax(&mut self, xattrs: &[(Vec<u8>, Vec<u8>)]) -> io::Result<()> {
        if xattrs.is_empty() {
            return Ok(());
        }
        let mut records = Vec::with_capacity(xattrs.len());
        for (k, v) in xattrs {
            let k = std::str::from_utf8(k).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "an xattr name is not UTF-8")
            })?;
            records.push((format!("SCHILY.xattr.{k}"), v.as_slice()));
        }
        self.out.pax(&records)
    }

    /// Write the directories that were waiting for an entry.
    fn flush_pending(&mut self) -> io::Result<()> {
        for mut p in std::mem::take(&mut self.pending) {
            self.pax(&p.xattrs)?;
            self.out.entry(&mut p.header, &p.path, Content::None)?;
        }
        Ok(())
    }

    fn append(
        &mut self,
        h: &mut tar::Header,
        path: &str,
        xattrs: &[(Vec<u8>, Vec<u8>)],
        content: Content<'_>,
    ) -> io::Result<()> {
        self.flush_pending()?;
        self.pax(xattrs)?;
        self.out.entry(h, path, content)
    }

    fn append_link(
        &mut self,
        h: &mut tar::Header,
        path: &str,
        xattrs: &[(Vec<u8>, Vec<u8>)],
        target: &OsStr,
    ) -> io::Result<()> {
        self.flush_pending()?;
        self.pax(xattrs)?;
        self.out.link(h, path, target)
    }

    /// A whiteout is a regular file that has the same mode, owner and time
    /// whatever device or mark it stands for.
    fn whiteout(&mut self, prefix: &str, name: &str) -> io::Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_size(0);
        self.append(&mut h, &format!("{prefix}.wh.{name}"), &[], Content::None)
    }

    /// The entry `name` of the directory `dir`, whose path in the layer is
    /// `at.prefix`; a directory gives what its walk needs.
    fn upper_entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        at: &UpperDir,
    ) -> io::Result<Option<UpperDir>> {
        let (prefix, below, renamed) = (at.prefix.as_str(), at.below.as_deref(), at.renamed);
        let name_str = utf8_name(prefix, name)?;
        let shown = format!("{prefix}{name_str}");
        let st = *st;
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind != FileType::Directory && self.opts.excluded(&shown) {
            // (but the removal of a file of the image there is a change: an
            // engine file the container deleted is gone from the image too)
            let in_image = match (&self.opts.lower, below) {
                (Some(l), Some(d)) => l.node(&join(d, &name_str)).is_some(),
                _ => false,
            };
            if renamed || !in_image || !overlay_marks(dir, name, &st)?.0 {
                return Ok(None);
            }
        }
        if is_whiteout_device(&st) {
            if !renamed {
                self.whiteout(prefix, &name_str)?;
            }
            return Ok(None);
        }
        if kind == FileType::Socket {
            return Ok(None);
        }
        let attrs = read_xattrs(dir, name, &shown, self.opts.lower.is_some(), false)?;
        if attrs.whiteout && kind == FileType::RegularFile && st.st_size == 0 {
            if !renamed {
                self.whiteout(prefix, &name_str)?;
            }
            return Ok(None);
        }
        // where the entry is below: its name in the directory, or where the
        // overlay says it came from
        let origin: Option<String> = match (&attrs.redirect, below) {
            (Some(r), d) => redirect_to(d.unwrap_or(""), r),
            (None, Some(d)) => Some(join(d, &name_str)),
            (None, None) => None,
        };
        if shown.len() + usize::from(kind == FileType::Directory) > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "path too long: `{}...`",
                    &shown[..shown.floor_char_boundary(64)]
                ),
            ));
        }
        match kind {
            FileType::RegularFile => {
                self.regular(dir, name, &shown, &st, &attrs, origin.as_deref())?;
            }
            FileType::Directory => {
                let mut h = self.header(&st, tar::EntryType::Directory)?;
                let child = format!("{shown}/");
                let mark = self.pending.len();
                // (an opaque directory the image does not have hides nothing:
                // a mount point the runtime made is one)
                let new_dir = match (&self.opts.lower, &origin) {
                    (Some(l), Some(o)) => l.node(o).is_none(),
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                let deferred = self.opts.holds_excluded(&child) && (!attrs.opaque || new_dir);
                // the directory below it is merged with it, unless it hides it
                let child_below = match (&self.opts.lower, &origin) {
                    (Some(l), Some(o)) if !attrs.opaque => l
                        .node(o)
                        .filter(|(_, n)| n.entry.entry_type == velarx_storage::TocEntryType::Dir)
                        .map(|_| o.clone()),
                    _ => None,
                };
                if deferred {
                    self.pending.push(Pending {
                        header: h,
                        path: child.clone(),
                        xattrs: attrs.xattrs,
                    });
                } else {
                    self.append(&mut h, &child, &attrs.xattrs, Content::None)?;
                    if attrs.opaque {
                        self.whiteout(&child, ".wh..opq")?;
                    }
                }
                // a directory the container renamed (the overlay does not copy
                // what is below it) has all of it in the layer: what the
                // image has below it and the upper does not is written when
                // the walk leaves it
                let redirected = attrs.redirect.is_some();
                return Ok(Some(UpperDir {
                    prefix: child,
                    lower_dir: child_below.clone().filter(|_| redirected),
                    below: child_below,
                    renamed: renamed || redirected,
                    upper_names: HashSet::new(),
                    deferred: deferred.then_some(mark),
                }));
            }
            FileType::Symlink => {
                let target = readlinkat(dir, name, Vec::new())?;
                let target = OsString::from_vec(target.into_bytes());
                let mut h = self.header(&st, tar::EntryType::Symlink)?;
                self.append_link(&mut h, &shown, &attrs.xattrs, &target)?;
            }
            FileType::CharacterDevice | FileType::BlockDevice => {
                let t = if kind == FileType::CharacterDevice {
                    tar::EntryType::Char
                } else {
                    tar::EntryType::Block
                };
                let mut h = self.header(&st, t)?;
                h.set_device_major(rustix::fs::major(st.st_rdev))?;
                h.set_device_minor(rustix::fs::minor(st.st_rdev))?;
                self.append(&mut h, &shown, &attrs.xattrs, Content::None)?;
            }
            FileType::Fifo => {
                let mut h = self.header(&st, tar::EntryType::Fifo)?;
                self.append(&mut h, &shown, &attrs.xattrs, Content::None)?;
            }
            _ => {}
        }
        Ok(None)
    }

    fn regular(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        shown: &str,
        st: &Stat,
        attrs: &Attrs,
        origin: Option<&str>,
    ) -> io::Result<()> {
        if attrs.metacopy {
            return self.metacopy(shown, st, attrs, origin);
        }
        if st.st_nlink > 1 {
            let key = (st.st_dev, st.st_ino);
            if let Some(first) = self.links.get(&key).cloned() {
                let mut h = self.header(st, tar::EntryType::Link)?;
                return self.append_link(&mut h, shown, &attrs.xattrs, OsStr::new(&first));
            }
            self.links.insert(key, shown.to_string());
        }
        let mut h = self.header(st, tar::EntryType::Regular)?;
        let size = st.st_size.max(0) as u64;
        h.set_size(size);
        if size == 0 {
            return self.append(&mut h, shown, &attrs.xattrs, Content::None);
        }
        let content = Content::Upper {
            dir,
            name,
            shown,
            seen: st,
        };
        self.append(&mut h, shown, &attrs.xattrs, content)
    }
}

impl Walker<'_> {
    /// A file the container changed the metadata of: its metadata are the
    /// upper file's, its data are the file below's.
    fn metacopy(
        &mut self,
        shown: &str,
        st: &Stat,
        attrs: &Attrs,
        origin: Option<&str>,
    ) -> io::Result<()> {
        let lower = self.opts.lower.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, format!("`{shown}` has no data"))
        })?;
        let entry = origin
            .and_then(|o| lower.node(o))
            .map(|(_, n)| n.entry.clone())
            .filter(|e| e.entry_type == velarx_storage::TocEntryType::Reg)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "`{shown}` has its data in `{}`, which the image does not have",
                        origin.unwrap_or("?")
                    ),
                )
            })?;
        let mut h = self.header(st, tar::EntryType::Regular)?;
        h.set_size(entry.size);
        if entry.size == 0 {
            return self.append(&mut h, shown, &attrs.xattrs, Content::None);
        }
        let content = lower.content(&entry, shown)?;
        self.append(&mut h, shown, &attrs.xattrs, content)
    }

    /// What the image has in the directory `below`, but the names of
    /// `skip`, as entries of the layer in `prefix` (`etc/`).
    fn lower_dir(&mut self, below: &str, prefix: &str, skip: &HashSet<String>) -> io::Result<()> {
        let Some(lower) = self.opts.lower.clone() else {
            return Ok(());
        };
        let Some((dir, _)) = lower.node(below) else {
            return Ok(());
        };
        for (name, child) in lower.tree.children(dir)? {
            if skip.contains(&name) {
                continue;
            }
            self.lower_entry(&lower, child, &format!("{prefix}{name}"))?;
        }
        Ok(())
    }

    /// The node `idx` of the image, as the entry `shown`.
    /// (a stack, not a recursion: the image may be as deep as a layer holds)
    fn lower_entry(&mut self, lower: &Arc<Lower>, idx: usize, shown: &str) -> io::Result<()> {
        let mut todo = vec![(idx, shown.to_string())];
        while let Some((idx, shown)) = todo.pop() {
            for (name, c) in self.lower_one(lower, idx, &shown)?.into_iter().rev() {
                todo.push((c, format!("{shown}/{name}")));
            }
        }
        Ok(())
    }

    /// The node `idx` of the image, as the entry `shown`; the children of a
    /// directory are given back.
    fn lower_one(
        &mut self,
        lower: &Arc<Lower>,
        idx: usize,
        shown: &str,
    ) -> io::Result<Vec<(String, usize)>> {
        use velarx_storage::TocEntryType as T;
        let Some(node) = lower.tree.node(idx) else {
            return Ok(Vec::new());
        };
        let e = &node.entry;
        if e.entry_type != T::Dir && self.opts.excluded(shown) {
            return Ok(Vec::new());
        }
        let mut h = tar::Header::new_gnu();
        h.set_mode(e.mode & 0o7777);
        h.set_uid(u64::from(e.uid));
        h.set_gid(u64::from(e.gid));
        h.set_mtime(self.opts.mtime.of(e.mtime().0));
        h.set_size(0);
        let xattrs = image_xattrs(e);
        let written = match e.entry_type {
            T::Dir => {
                h.set_entry_type(tar::EntryType::Directory);
                let child = format!("{shown}/");
                self.append(&mut h, &child, &xattrs, Content::None)?;
                return lower.tree.children(idx);
            }
            T::Reg | T::Chunk | T::Hardlink => {
                if node.nlink > 1 {
                    if let Some(first) = self.lower_links.get(&node.key).cloned() {
                        h.set_entry_type(tar::EntryType::Link);
                        return self
                            .append_link(&mut h, shown, &xattrs, OsStr::new(&first))
                            .map(|()| Vec::new());
                    }
                    self.lower_links.insert(node.key, shown.to_string());
                }
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(e.size);
                if e.size == 0 {
                    self.append(&mut h, shown, &xattrs, Content::None)
                } else {
                    let content = lower.content(e, shown)?;
                    self.append(&mut h, shown, &xattrs, content)
                }
            }
            T::Symlink => {
                h.set_entry_type(tar::EntryType::Symlink);
                self.append_link(
                    &mut h,
                    shown,
                    &[],
                    OsStr::new(e.link_name.as_deref().unwrap_or("")),
                )
            }
            T::Char | T::Block => {
                h.set_entry_type(if e.entry_type == T::Char {
                    tar::EntryType::Char
                } else {
                    tar::EntryType::Block
                });
                h.set_device_major(e.dev_major.unwrap_or(0))?;
                h.set_device_minor(e.dev_minor.unwrap_or(0))?;
                self.append(&mut h, shown, &xattrs, Content::None)
            }
            T::Fifo => {
                h.set_entry_type(tar::EntryType::Fifo);
                self.append(&mut h, shown, &xattrs, Content::None)
            }
        };
        written.map(|()| Vec::new())
    }
}

/// The xattrs of an entry of the image that go in a layer (not the overlay's
/// or SELinux's), sorted.
fn image_xattrs(e: &velarx_storage::TocEntry) -> Vec<(Vec<u8>, Vec<u8>)> {
    use base64::Engine;
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = e
        .xattrs
        .iter()
        .filter(|(k, _)| !velarx_fuse::hidden_xattr(k))
        .filter_map(|(k, v)| {
            base64::engine::general_purpose::STANDARD
                .decode(v)
                .ok()
                .map(|v| (k.as_bytes().to_vec(), v))
        })
        .collect();
    out.sort();
    out
}

/// Whether `st` is the regular file that was seen.
fn same_file(st: &Stat, seen: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::RegularFile
        && st.st_ino == seen.st_ino
        && st.st_dev == seen.st_dev
}

/// Open the regular file of the `O_PATH` descriptor `pfd` for reading, after
/// checking that it is the file that was seen.
fn reopen_checked(pfd: OwnedFd, seen: &Stat, shown: &str) -> io::Result<OwnedFd> {
    if !same_file(&fstat(&pfd)?, seen) {
        return Err(changed(shown));
    }
    let fd = openat(
        rustix::fs::CWD,
        velarx_sys::fd::proc_str(&pfd),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let st = fstat(&fd)?;
    if !same_file(&st, seen) || st.st_size != seen.st_size {
        return Err(changed(shown));
    }
    Ok(fd)
}

/// Open the regular file `name` for reading, after checking that it is the
/// file that was seen: the name could be replaced (by a device node, say) by
/// a container that still runs.
fn open_checked(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    seen: &Stat,
    shown: &str,
) -> io::Result<OwnedFd> {
    let pfd = openat(
        dir,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    reopen_checked(pfd, seen, shown)
}

/// The same for the file at the path `shown` under `root`, which no
/// symbolic link of the path can leave.
fn open_beneath(root: BorrowedFd<'_>, shown: &str, seen: &Stat) -> io::Result<OwnedFd> {
    use velarx_sys::fs::Beneath;
    let pfd = velarx_sys::fs::open_beneath(root, std::path::Path::new(shown), Beneath::Path)?;
    reopen_checked(pfd, seen, shown)
}

/// A directory of the upper being walked.
struct UpperDir {
    /// its path in the layer (`etc/`, empty for the root)
    prefix: String,
    /// the path of the directory below it in the image, when it has one
    below: Option<String>,
    /// it is one the container renamed, or under one: it is all new in the
    /// layer, what was deleted in it is not there
    renamed: bool,
    /// the directory of the image below it when the container renamed it:
    /// what that has and `upper_names` lack goes in the layer too
    lower_dir: Option<String>,
    upper_names: HashSet<String>,
    /// the place of its header among the pending ones, when it waits for an
    /// entry below it
    deferred: Option<usize>,
}

impl UpperDir {
    fn root(opts: &Options) -> Self {
        UpperDir {
            prefix: String::new(),
            // (the root of the container is the root of the image)
            below: opts.lower.as_ref().map(|_| String::new()),
            renamed: false,
            lower_dir: None,
            upper_names: HashSet::new(),
            deferred: None,
        }
    }
}

/// The walk of an upper directory.
struct UpperWalk<'w, 'o>(&'w mut Walker<'o>);

impl Visit for UpperWalk<'_, '_> {
    type Dir = UpperDir;

    fn enter(
        &mut self,
        _: BorrowedFd<'_>,
        names: &[OsString],
        at: &mut UpperDir,
    ) -> io::Result<()> {
        if at.lower_dir.is_some() {
            at.upper_names = names
                .iter()
                .filter_map(|n| n.to_str().map(str::to_string))
                .collect();
        }
        Ok(())
    }

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        at: &mut UpperDir,
    ) -> io::Result<Option<UpperDir>> {
        self.0.upper_entry(dir, name, st, at)
    }

    fn exit(&mut self, _: BorrowedFd<'_>, at: &mut UpperDir) -> io::Result<()> {
        if let Some(b) = &at.lower_dir {
            self.0.lower_dir(b, &at.prefix, &at.upper_names)?;
        }
        // Nothing was written below it (that would have written it first): it
        // is a directory the engine files changed only.
        if let Some(mark) = at.deferred {
            self.0.pending.truncate(mark);
        }
        Ok(())
    }
}

/// The walks of an upper or of a copy: as deep as `MAX_PATH` lets a path be
/// (a layer holds `MAX_PATH_DEPTH` components: its reader refuses deeper).
const WALK: Walk = Walk {
    max_depth: MAX_PATH / 2,
    sorted: true,
    skip_gone: false,
    lenient: false,
};

impl Walker<'_> {
    /// Write the entry for the root `dir` as `opts.root` says.
    fn write_root(&mut self, dir: BorrowedFd<'_>) -> io::Result<()> {
        if self.opts.root != Root::Never {
            let (mut h, attrs) = match self.opts.below.clone() {
                Some(e) => self.root_of(&e),
                None => {
                    let st = fstat(dir)?;
                    let h = self.header(&st, tar::EntryType::Directory)?;
                    (h, read_xattrs(dir, OsStr::new("."), "/", false, true)?)
                }
            };
            let plain = (h.mode()?, h.uid()?, h.gid()?) == (0o755, 0, 0) && attrs.xattrs.is_empty();
            if self.opts.root == Root::Always || !plain {
                self.append(&mut h, "./", &attrs.xattrs, Content::None)?;
            }
        }
        Ok(())
    }

    /// Walk the upper directory `dir`.
    fn walk_upper(&mut self, dir: BorrowedFd<'_>) -> io::Result<()> {
        self.write_root(dir)?;
        let root = UpperDir::root(&self.opts);
        WALK.run(dir.try_clone_to_owned()?, root, &mut UpperWalk(self))?;
        Ok(())
    }
}

fn walker<'o>(out: &'o mut dyn Out, opts: &Options) -> Walker<'o> {
    Walker {
        out,
        opts: opts.clone(),
        links: HashMap::new(),
        lower_links: HashMap::new(),
        pending: Vec::new(),
    }
}

/// Write the changes in `dir` as a tar stream to `out`: the holes of the
/// files are holes of the stream.
pub fn write<W: HoleWrite>(dir: BorrowedFd<'_>, opts: &Options, out: W) -> io::Result<()> {
    let mut tar = TarOut {
        builder: tar::Builder::new(out),
    };
    walker(&mut tar, opts).walk_upper(dir)?;
    tar.builder.into_inner()?.flush()
}

/// Walk the changes in `dir` without reading the content of the files: the
/// entries are given back in order, with what is needed to read the
/// content later ([`replay`]).
pub fn record(dir: BorrowedFd<'_>, opts: &Options) -> io::Result<Vec<Recorded>> {
    let mut recorder = Recorder {
        pax: Vec::new(),
        entries: Vec::new(),
    };
    walker(&mut recorder, opts).walk_upper(dir)?;
    Ok(recorder.entries)
}

/// Put the entries of a record in the order of a canonical tar: by the
/// components of their paths, each compared as bytes.  The walk gives an
/// entry in the place of the name it has in the directory, a whiteout in
/// that of the file it hides, and what an image below has of a renamed
/// directory after the rest.
pub fn sort_canonical(entries: &mut [Recorded]) {
    // (the root, `./`, has none: it is first)
    fn components(e: &Recorded) -> impl Iterator<Item = &str> {
        e.path
            .trim_end_matches('/')
            .split('/')
            .filter(|c| *c != ".")
    }
    entries.sort_by(|a, b| components(a).cmp(components(b)));
}

/// Give the entry `e` of a record to `out`, its content read now from
/// `root`, the directory that was walked, or from the store.  The file must
/// be the one that was seen.
pub fn replay(e: &Recorded, root: BorrowedFd<'_>, out: &mut dyn Out) -> io::Result<()> {
    let mut h = e.header.clone();
    if !e.pax.is_empty() {
        let records: Vec<(String, &[u8])> = e
            .pax
            .iter()
            .map(|(k, v)| (k.clone(), v.as_slice()))
            .collect();
        out.pax(&records)?;
    }
    if let Some(target) = &e.link {
        return out.link(&mut h, &e.path, target.as_os_str());
    }
    match &e.data {
        Data::None => out.entry(&mut h, &e.path, Content::None),
        Data::Upper { path, seen } => {
            let file = std::fs::File::from(open_beneath(root, path, seen)?);
            out.entry(
                &mut h,
                &e.path,
                Content::Opened {
                    file,
                    size: seen.st_size.max(0) as u64,
                    shown: path,
                    seen: Some(seen),
                },
            )
        }
        Data::Store(object) => out.entry(
            &mut h,
            &e.path,
            Content::Store {
                object: object.clone(),
                shown: &e.path,
            },
        ),
    }
}

/// A change of a container, as `podman diff` shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Change {
    Modified,
    Added,
    Deleted,
}

impl Change {
    /// The kind in Docker's `FilesystemChange`.
    pub fn kind(self) -> u8 {
        match self {
            Self::Modified => 0,
            Self::Added => 1,
            Self::Deleted => 2,
        }
    }

    pub fn letter(self) -> char {
        match self {
            Self::Modified => 'C',
            Self::Added => 'A',
            Self::Deleted => 'D',
        }
    }
}

/// The changes in `dir`, sorted by path (`/etc/motd`).  A path that is in
/// the image below (`opts.lower`) is modified, else added.
pub fn changes(dir: BorrowedFd<'_>, opts: &Options) -> io::Result<Vec<(String, Change)>> {
    let mut walk = ChangesWalk {
        opts,
        out: Vec::new(),
    };
    let root = ChangesDir {
        upper: UpperDir::root(opts),
        any: false,
        at: 0,
        change: Change::Modified,
    };
    WALK.run(dir.try_clone_to_owned()?, root, &mut walk)?;
    let mut out = walk.out;
    // (the parents first, the names of a directory in order)
    out.sort_by(|a, b| a.0.split('/').cmp(b.0.split('/')));
    Ok(out)
}

/// A directory of the upper in the list of changes.
struct ChangesDir {
    upper: UpperDir,
    /// something below it is a change
    any: bool,
    /// its place in the list, and what it is
    at: usize,
    change: Change,
}

/// The walk of the list of changes of an upper directory.
struct ChangesWalk<'a> {
    opts: &'a Options,
    out: Vec<(String, Change)>,
}

impl Visit for ChangesWalk<'_> {
    type Dir = ChangesDir;

    fn enter(
        &mut self,
        _: BorrowedFd<'_>,
        names: &[OsString],
        at: &mut ChangesDir,
    ) -> io::Result<()> {
        if at.upper.lower_dir.is_some() {
            at.upper.upper_names = names
                .iter()
                .filter_map(|n| n.to_str().map(str::to_string))
                .collect();
        }
        Ok(())
    }

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        parent: &mut ChangesDir,
    ) -> io::Result<Option<ChangesDir>> {
        let opts = self.opts;
        let (prefix, below, renamed) = (
            parent.upper.prefix.as_str(),
            parent.upper.below.as_deref(),
            parent.upper.renamed,
        );
        let name_str = utf8_name(prefix, name)?;
        let path = format!("{prefix}{name_str}");
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind != FileType::Directory && opts.excluded(&path) {
            return Ok(None);
        }
        let attrs = if is_whiteout_device(st) {
            Attrs {
                whiteout: true,
                ..Attrs::default()
            }
        } else {
            read_xattrs(dir, name, &path, opts.lower.is_some(), false)?
        };
        if attrs.whiteout && (kind != FileType::RegularFile || st.st_size == 0) {
            if !renamed {
                self.out.push((format!("/{path}"), Change::Deleted));
                parent.any = true;
            }
            return Ok(None);
        }
        let in_image = opts.lower.as_ref().is_some_and(|l| l.node(&path).is_some());
        let change = if in_image {
            Change::Modified
        } else {
            Change::Added
        };
        if kind != FileType::Directory {
            self.out.push((format!("/{path}"), change));
            parent.any = true;
            return Ok(None);
        }
        let at = self.out.len();
        self.out.push((format!("/{path}"), change));
        // the directory below it, which is merged with it unless it hides it
        let origin = match (&attrs.redirect, below) {
            (Some(r), d) => redirect_to(d.unwrap_or(""), r),
            (None, Some(d)) => Some(join(d, &name_str)),
            (None, None) => None,
        };
        let child_below = match (&opts.lower, &origin) {
            (Some(l), Some(o)) if !attrs.opaque => l
                .node(o)
                .filter(|(_, n)| n.entry.entry_type == velarx_storage::TocEntryType::Dir)
                .map(|_| o.clone()),
            _ => None,
        };
        let redirected = attrs.redirect.is_some();
        Ok(Some(ChangesDir {
            upper: UpperDir {
                prefix: format!("{path}/"),
                lower_dir: child_below
                    .clone()
                    .filter(|_| redirected && opts.lower.is_some()),
                below: child_below,
                renamed: renamed || redirected,
                upper_names: HashSet::new(),
                deferred: None,
            },
            any: false,
            at,
            change,
        }))
    }

    fn exit(&mut self, _: BorrowedFd<'_>, at: &mut ChangesDir) -> io::Result<()> {
        // a directory the container renamed has all of what it held
        if let (Some(b), Some(l)) = (&at.upper.lower_dir, &self.opts.lower) {
            if let Some((idx, _)) = l.node(b) {
                added_below(
                    l,
                    idx,
                    &at.upper.prefix,
                    &at.upper.upper_names,
                    self.opts,
                    &mut self.out,
                )?;
            }
        }
        Ok(())
    }

    fn leave(
        &mut self,
        _: BorrowedFd<'_>,
        parent: &mut ChangesDir,
        _: &OsStr,
        _: OwnedFd,
        at: ChangesDir,
    ) -> io::Result<()> {
        // A directory changed only by the engine files is not a change.
        if !at.any && at.change == Change::Modified && self.opts.holds_excluded(&at.upper.prefix) {
            self.out.remove(at.at);
        } else {
            parent.any = true;
        }
        Ok(())
    }
}

/// The paths below the node `idx` of the image, but the names of `skip`:
/// added.
fn added_below(
    l: &Lower,
    idx: usize,
    prefix: &str,
    skip: &HashSet<String>,
    opts: &Options,
    out: &mut Vec<(String, Change)>,
) -> io::Result<()> {
    // (a stack, not a recursion: the image may be as deep as a layer holds)
    let mut todo = vec![(idx, prefix.to_string(), skip)];
    let none = HashSet::new();
    while let Some((idx, prefix, skip)) = todo.pop() {
        for (name, c) in l.tree.children(idx)? {
            if skip.contains(&name) {
                continue;
            }
            let path = format!("{prefix}{name}");
            let Some(n) = l.tree.node(c) else { continue };
            let is_dir = n.entry.entry_type == velarx_storage::TocEntryType::Dir;
            if !is_dir && opts.excluded(&path) {
                continue;
            }
            if is_dir {
                todo.push((c, format!("{path}/"), &none));
            }
            out.push((format!("/{path}"), Change::Added));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fd::AsFd;
    use std::os::unix::fs::{symlink, MetadataExt};

    fn entries(tar: &[u8]) -> Vec<(String, tar::EntryType, Option<String>)> {
        tar::Archive::new(tar)
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path().unwrap().to_string_lossy().to_string(),
                    e.header().entry_type(),
                    e.link_name()
                        .unwrap()
                        .map(|l| l.to_string_lossy().to_string()),
                )
            })
            .collect()
    }

    fn open(dir: &std::path::Path) -> OwnedFd {
        openat(
            rustix::fs::CWD,
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap()
    }

    fn run(dir: &std::path::Path, opts: &Options) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        write(open(dir).as_fd(), opts, &mut out)?;
        Ok(out)
    }

    fn set_xattr(path: &std::path::Path, name: &str, value: &[u8]) -> bool {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let name = CString::new(name).unwrap();
        rustix::fs::lsetxattr(&path, &name, value, rustix::fs::XattrFlags::empty()).is_ok()
    }

    /// Objects that are no files of the engine's store to open by path:
    /// each is read back as a copy in an unnamed file, as the default
    /// `open_object` of a driver does, and counted.
    struct Spooled {
        store: Arc<velarx_storage::FileStore>,
        opened: std::sync::atomic::AtomicUsize,
    }

    impl velarx_storage::ObjectOpener for Spooled {
        fn object_file(&self, key: &str, size: u64) -> io::Result<std::fs::File> {
            use std::io::Seek;
            let mut file = self.store.object_file(key, size)?;
            let mut copy = tempfile::tempfile()?;
            io::copy(&mut file, &mut copy)?;
            copy.rewind()?;
            self.opened
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(copy)
        }
    }

    /// The image below: the files `etc/old` and `opt/d/{a,b}` (and an empty
    /// `run`), with their
    /// data in a store.
    fn lower(tmp: &std::path::Path) -> (Arc<Lower>, Vec<(&'static str, Vec<u8>)>) {
        let (lower, files, _) = lower_with(tmp);
        (lower, files)
    }

    /// [`lower`], and the objects it reads through.
    #[allow(clippy::type_complexity)]
    fn lower_with(
        tmp: &std::path::Path,
    ) -> (Arc<Lower>, Vec<(&'static str, Vec<u8>)>, Arc<Spooled>) {
        use velarx_storage::{Toc, TocEntryType};
        let store = Arc::new(velarx_storage::FileStore::new(tmp.join("files")).unwrap());
        let mut entries = Vec::new();
        let mut files = Vec::new();
        for (name, data) in [
            ("etc/old", b"old content".to_vec()),
            ("opt/d/a", b"aaa".to_vec()),
            ("opt/d/b", b"bbbb".to_vec()),
        ] {
            let digest = store
                .put(velarx_types::digest::Algorithm::Sha256, &data)
                .unwrap();
            let mut e = velarx_fuse::dir_entry(name);
            e.entry_type = TocEntryType::Reg;
            (e.mode, e.size, e.fsverity) =
                (0o644, data.len() as u64, velarx_storage::to_toc(&digest));
            entries.push(e);
            files.push((name, data));
        }
        for d in ["etc", "opt", "opt/d", "run"] {
            let mut e = velarx_fuse::dir_entry(d);
            e.mode = 0o755;
            entries.insert(0, e);
        }
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        let image = velarx_fuse::layer_erofs::layer_image(&toc.entries)
            .unwrap()
            .image;
        let tree = velarx_fuse::view::ImageView::new(vec![velarx_fuse::erofs_tree::Layer::open(
            Box::new(image),
        )
        .unwrap()]);
        let objects = Arc::new(Spooled {
            store,
            opened: Default::default(),
        });
        (
            Arc::new(Lower {
                tree: Arc::new(tree),
                objects: objects.clone(),
            }),
            files,
            objects,
        )
    }

    /// The upper directory of an overlay with metacopy: a file whose metadata
    /// changed and one renamed, without their data, and a directory renamed,
    /// without what it holds.
    fn metacopy_upper(p: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(p.join("etc")).unwrap();
        std::fs::create_dir_all(p.join("opt/ren")).unwrap();
        // chmod of etc/old: the data stays below
        std::fs::write(p.join("etc/old"), "").unwrap();
        std::fs::set_permissions(p.join("etc/old"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let mut ok = set_xattr(&p.join("etc/old"), "user.overlay.metacopy", b"");
        ok &= set_xattr(&p.join("etc/old"), "user.overlay.redirect", b"/etc/old");
        // etc/moved was etc/old, and etc/old is deleted
        std::fs::write(p.join("etc/moved"), "").unwrap();
        ok &= set_xattr(&p.join("etc/moved"), "user.overlay.metacopy", b"");
        ok &= set_xattr(&p.join("etc/moved"), "user.overlay.redirect", b"old");
        // opt/ren was opt/d, with a new file, and b deleted
        std::fs::write(p.join("opt/ren/new"), "n").unwrap();
        std::fs::write(p.join("opt/ren/b"), "").unwrap();
        ok &= set_xattr(&p.join("opt/ren/b"), "user.overlay.whiteout", b"y");
        ok & set_xattr(&p.join("opt/ren"), "user.overlay.redirect", b"/opt/d")
    }

    /// An engine file is no change of the container, but the removal of
    /// one the image has is.
    #[test]
    fn test_an_engine_file_removed_from_the_image_is_a_whiteout() {
        let d = tempfile::tempdir().unwrap();
        let upper = d.path().join("upper");
        std::fs::create_dir_all(upper.join("etc")).unwrap();
        let mut ok = true;
        for name in ["old", "hosts"] {
            std::fs::write(upper.join("etc").join(name), "").unwrap();
            ok &= set_xattr(&upper.join("etc").join(name), "user.overlay.whiteout", b"y");
        }
        std::fs::write(upper.join("etc/resolv.conf"), "nameserver 1.1.1.1").unwrap();
        if !ok {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let (lower, _) = lower(d.path());
        let opts = Options {
            lower: Some(lower),
            exclude: ["/etc/old", "/etc/hosts", "/etc/resolv.conf"]
                .map(String::from)
                .to_vec(),
            ..Default::default()
        };
        let names: Vec<String> = entries(&run(&upper, &opts).unwrap())
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(names, ["etc/", "etc/.wh.old"]);
    }

    #[test]
    fn test_the_data_of_metadata_only_files_and_the_content_of_renamed_directories() {
        let d = tempfile::tempdir().unwrap();
        let upper = d.path().join("upper");
        if !metacopy_upper(&upper) {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let (lower, _, objects) = lower_with(d.path());
        let opts = Options {
            lower: Some(lower),
            ..Default::default()
        };
        let tar = run(&upper, &opts).unwrap();
        // (the content of the image below is read through its objects)
        assert!(objects.opened.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        let mut got: Vec<(String, String)> = Vec::new();
        for e in tar::Archive::new(tar.as_slice()).entries().unwrap() {
            let mut e = e.unwrap();
            let mut data = String::new();
            std::io::Read::read_to_string(&mut e, &mut data).unwrap();
            got.push((e.path().unwrap().to_string_lossy().into_owned(), data));
        }
        let got: HashMap<_, _> = got.into_iter().collect();
        // the data comes from the store
        assert_eq!(got["etc/old"], "old content");
        assert_eq!(got["etc/moved"], "old content");
        // the directory renamed has what it held, but what was deleted in it
        assert_eq!(got["opt/ren/a"], "aaa");
        assert_eq!(got["opt/ren/new"], "n");
        assert!(!got.contains_key("opt/ren/b"));
        assert!(!got.contains_key("opt/ren/.wh.b"));
        // and the mode is the upper file's
        let mut a = tar::Archive::new(tar.as_slice());
        let old = a
            .entries()
            .unwrap()
            .map(|e| e.unwrap())
            .find(|e| e.path().unwrap().to_str() == Some("etc/old"))
            .unwrap();
        assert_eq!(old.header().mode().unwrap() & 0o7777, 0o600);
        // without the image they are not understood
        assert!(run(&upper, &Options::default()).is_err());

        // the changes
        let list = changes(open(&upper).as_fd(), &opts).unwrap();
        let list: Vec<String> = list
            .iter()
            .map(|(p, c)| format!("{} {p}", c.letter()))
            .collect();
        assert_eq!(
            list,
            [
                "C /etc",
                "A /etc/moved",
                "C /etc/old",
                "C /opt",
                "A /opt/ren",
                "A /opt/ren/a",
                "A /opt/ren/new",
            ]
        );
    }

    #[test]
    fn test_files_links_and_exclusions() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir(p.join("etc")).unwrap();
        std::fs::write(p.join("etc/a"), "hello").unwrap();
        std::fs::hard_link(p.join("etc/a"), p.join("etc/b")).unwrap();
        std::fs::write(p.join("etc/hosts"), "127.0.0.1 x\n").unwrap();
        symlink("a", p.join("etc/l")).unwrap();
        let opts = Options {
            exclude: vec!["/etc/hosts".into()],
            ..Default::default()
        };
        let tar = run(p, &opts).unwrap();
        let e = entries(&tar);
        let names: Vec<_> = e.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["etc/", "etc/a", "etc/b", "etc/l"]);
        assert_eq!(e[2].1, tar::EntryType::Link);
        assert_eq!(e[2].2.as_deref(), Some("etc/a"));
        assert_eq!(e[3].2.as_deref(), Some("a"));
        // The same tree gives the same stream.
        assert_eq!(tar, run(p, &opts).unwrap());
    }

    #[test]
    fn the_mount_points_of_a_step_are_not_changes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir_all(p.join("cache/dir")).unwrap();
        std::fs::create_dir_all(p.join("run/secrets")).unwrap();
        std::fs::write(p.join("run/secrets/token"), "").unwrap();
        std::fs::create_dir_all(p.join("src")).unwrap();
        std::fs::write(p.join("src/kept"), "k").unwrap();
        let opts = Options {
            exclude: ["/cache/dir", "/run/secrets/token", "/src"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            ..Default::default()
        };
        let e = entries(&run(p, &opts).unwrap());
        let names: Vec<_> = e.iter().map(|e| e.0.as_str()).collect();
        // (what else is in a directory keeps it)
        assert_eq!(names, ["src/", "src/kept"]);
    }

    #[test]
    fn an_opaque_mount_point_the_image_lacks_is_not_a_change() {
        let d = tempfile::tempdir().unwrap();
        let upper = d.path().join("upper");
        // the runtime made /mnt/point (/mnt is not in the image) and
        // /opt/point (/opt is, and the step made it opaque)
        std::fs::create_dir_all(upper.join("mnt/point")).unwrap();
        std::fs::create_dir_all(upper.join("opt/point")).unwrap();
        if !(set_xattr(&upper.join("mnt"), "user.overlay.opaque", b"y")
            && set_xattr(&upper.join("opt"), "user.overlay.opaque", b"y"))
        {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let (lower, _) = lower(d.path());
        let opts = Options {
            lower: Some(lower),
            exclude: vec!["/mnt/point".into(), "/opt/point".into()],
            ..Default::default()
        };
        let tar = run(&upper, &opts).unwrap();
        let e = entries(&tar);
        let names: Vec<_> = e.iter().map(|e| e.0.as_str()).collect();
        // (an opaque directory over one of the image hides it: a change)
        assert_eq!(names, ["opt/", "opt/.wh..wh..opq"]);
        // the marker has an owner, root, as every reader of a tar reads it
        let mut ar = tar::Archive::new(&tar[..]);
        let marker = ar.entries().unwrap().nth(1).unwrap().unwrap();
        assert_eq!(
            (
                marker.header().uid().unwrap(),
                marker.header().gid().unwrap()
            ),
            (0, 0)
        );
    }

    #[test]
    fn test_a_directory_with_only_engine_files_is_not_a_change() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir_all(p.join("etc")).unwrap();
        std::fs::create_dir_all(p.join("run")).unwrap();
        std::fs::write(p.join("etc/hosts"), "x").unwrap();
        std::fs::write(p.join("etc/resolv.conf"), "x").unwrap();
        std::fs::write(p.join("run/.containerenv"), "").unwrap();
        std::fs::write(p.join("new"), "n").unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let (below, _) = lower(store_dir.path());
        let opts = Options {
            exclude: ENGINE_FILES.iter().map(|s| s.to_string()).collect(),
            lower: Some(below),
            ..Default::default()
        };
        let e = entries(&run(p, &opts).unwrap());
        let names: Vec<_> = e.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["new"]);
        // Another file in /etc keeps the directory.
        std::fs::write(p.join("etc/motd"), "m").unwrap();
        let e = entries(&run(p, &opts).unwrap());
        let names: Vec<_> = e.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["etc/", "etc/motd", "new"]);

        let list = changes(open(p).as_fd(), &opts).unwrap();
        assert_eq!(
            list,
            [
                ("/etc".to_string(), Change::Modified),
                ("/etc/motd".to_string(), Change::Added),
                ("/new".to_string(), Change::Added)
            ]
        );
    }

    #[test]
    fn test_whiteouts_and_opaque_directories() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::create_dir(p.join("dir")).unwrap();
        // A whiteout is a 0:0 device; an unprivileged test cannot make one,
        // the xattr form is what is tried here.
        std::fs::write(p.join("dir/gone"), "").unwrap();
        let ok = set_xattr(&p.join("dir/gone"), "user.overlay.whiteout", b"y")
            && set_xattr(&p.join("dir"), "user.overlay.opaque", b"y");
        if !ok {
            eprintln!("user xattrs are not supported here: skipped");
            return;
        }
        let e = entries(&run(p, &Options::default()).unwrap());
        let names: Vec<_> = e.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["dir/", "dir/.wh..wh..opq", "dir/.wh.gone"]);
        let list = changes(open(p).as_fd(), &Options::default()).unwrap();
        assert_eq!(
            list,
            [
                ("/dir".to_string(), Change::Added),
                ("/dir/gone".to_string(), Change::Deleted)
            ]
        );
    }

    #[test]
    fn test_ids_are_mapped_back() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), "x").unwrap();
        let me = std::fs::metadata(d.path().join("f")).unwrap();
        let opts = Options {
            uid_map: vec![IdRange {
                container: 0,
                host: me.uid(),
                size: 1,
            }],
            gid_map: vec![IdRange {
                container: 5,
                host: me.gid(),
                size: 1,
            }],
            ..Default::default()
        };
        let tar = run(d.path(), &opts).unwrap();
        let mut a = tar::Archive::new(&tar[..]);
        let e = a.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(
            (e.header().uid().unwrap(), e.header().gid().unwrap()),
            (0, 5)
        );
        // An id outside the mapping is an error.
        let opts = Options {
            uid_map: vec![IdRange {
                container: 0,
                host: me.uid() + 1,
                size: 1,
            }],
            ..Default::default()
        };
        assert!(run(d.path(), &opts).is_err());
    }

    #[test]
    fn test_sockets_are_skipped_and_xattrs_kept() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        let _s = std::os::unix::net::UnixListener::bind(p.join("sock")).unwrap();
        std::fs::write(p.join("f"), "x").unwrap();
        let has = set_xattr(&p.join("f"), "user.test", b"v");
        let tar = run(p, &Options::default()).unwrap();
        let mut a = tar::Archive::new(&tar[..]);
        let mut names = Vec::new();
        for e in a.entries().unwrap() {
            let mut e = e.unwrap();
            names.push(e.path().unwrap().to_string_lossy().to_string());
            if has {
                let ext = e.pax_extensions().unwrap().unwrap();
                let found = ext
                    .flatten()
                    .any(|x| x.key() == Ok("SCHILY.xattr.user.test") && x.value_bytes() == b"v");
                assert!(found);
            }
        }
        assert_eq!(names, ["f"]);
    }

    #[test]
    fn test_long_names_and_the_layer_writer() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        let long = "d".repeat(120);
        std::fs::create_dir(p.join(&long)).unwrap();
        std::fs::write(p.join(&long).join("f".repeat(150)), "data").unwrap();
        symlink("t".repeat(200), p.join("link")).unwrap();
        let tar = run(p, &Options::default()).unwrap();
        let e = entries(&tar);
        assert_eq!(e[1].0, format!("{long}/{}", "f".repeat(150)));
        assert_eq!(e[2].2.as_deref(), Some("t".repeat(200).as_str()));
        // The stream is one the layer writer takes.
        let mut out = Vec::new();
        let w = crate::layer::writer::write_layer(
            &tar[..],
            velarx_types::digest::Algorithm::Sha256,
            crate::layer::writer::Compression::ZstdChunked,
            &mut out,
        )
        .unwrap();
        assert_eq!(w.diff_id, crate::sha256(&tar));
    }

    /// A directory the container renamed: what the image has below it is in
    /// the layer in the order of the image, the parents first.
    #[test]
    fn test_a_renamed_directory_has_the_entries_of_the_image_in_order() {
        let d = tempfile::tempdir().unwrap();
        let upper = d.path().join("upper");
        std::fs::create_dir_all(upper.join("ren")).unwrap();
        if !set_xattr(&upper.join("ren"), "user.overlay.redirect", b"/opt") {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let (lower, _) = lower(d.path());
        let opts = Options {
            lower: Some(lower),
            ..Default::default()
        };
        let names: Vec<String> = entries(&run(&upper, &opts).unwrap())
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(names, ["ren/", "ren/d/", "ren/d/a", "ren/d/b"]);
    }

    /// A directory of a copy that is the image's, with nothing changed below
    /// it, is not in the layer, even when something after it is.
    #[test]
    fn test_an_unchanged_directory_of_a_copy_is_not_in_the_layer() {
        let d = tempfile::tempdir().unwrap();
        let copy = d.path().join("copy");
        let (lower, files) = lower(d.path());
        for dir in ["etc", "run"] {
            std::fs::create_dir_all(copy.join(dir)).unwrap();
            std::fs::set_permissions(
                copy.join(dir),
                std::os::unix::fs::PermissionsExt::from_mode(0o755),
            )
            .unwrap();
        }
        let old = copy.join("etc/old");
        std::fs::write(&old, &files[0].1).unwrap();
        std::fs::set_permissions(&old, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
        let (_, node) = lower.node("etc/old").unwrap();
        let (sec, nsec) = node.entry.mtime();
        let t = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: sec,
                tv_nsec: nsec.into(),
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: sec,
                tv_nsec: nsec.into(),
            },
        };
        rustix::fs::utimensat(rustix::fs::CWD, &old, &t, rustix::fs::AtFlags::empty()).unwrap();
        let opts = Options {
            lower: Some(lower),
            unowned: Some((
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
            )),
            ..Default::default()
        };
        let mut tar = Vec::new();
        copydiff::write(open(&copy).as_fd(), &opts, &mut tar).unwrap();
        let names: Vec<String> = entries(&tar).into_iter().map(|e| e.0).collect();
        // (opt is gone: its whiteout comes after etc and run)
        assert_eq!(names, [".wh.opt"]);
    }

    /// A copy that kept none of the entries of the image's root, and has
    /// others: each is a whiteout, as a marker in the root hides nothing.
    #[test]
    fn test_a_copy_without_the_entries_of_the_root_whiteouts_each() {
        let d = tempfile::tempdir().unwrap();
        let copy = d.path().join("copy");
        std::fs::create_dir_all(&copy).unwrap();
        std::fs::write(copy.join("new"), b"new").unwrap();
        let (lower, _) = lower(d.path());
        let opts = Options {
            lower: Some(lower),
            ..Default::default()
        };
        let mut tar = Vec::new();
        copydiff::write(open(&copy).as_fd(), &opts, &mut tar).unwrap();
        let names: Vec<String> = entries(&tar).into_iter().map(|e| e.0).collect();
        assert_eq!(names, ["new", ".wh.etc", ".wh.opt", ".wh.run"]);
    }

    /// The tar of a copy has the entry for its root when the options ask for
    /// it: always, or when the root is not a plain one.
    #[test]
    fn test_the_tar_of_a_copy_has_its_root_when_asked() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let copy = d.path().join("copy");
        std::fs::create_dir_all(&copy).unwrap();
        let (lower, _) = lower(d.path());
        let names = |mode: u32, root: Root| {
            std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(mode)).unwrap();
            let own = |host| {
                vec![IdRange {
                    container: 0,
                    host,
                    size: 1,
                }]
            };
            let opts = Options {
                lower: Some(lower.clone()),
                uid_map: own(rustix::process::getuid().as_raw()),
                gid_map: own(rustix::process::getgid().as_raw()),
                root,
                ..Default::default()
            };
            let mut tar = Vec::new();
            copydiff::write(open(&copy).as_fd(), &opts, &mut tar).unwrap();
            entries(&tar)
                .into_iter()
                .map(|e| e.0)
                .filter(|n| n.starts_with("./"))
                .collect::<Vec<_>>()
        };
        assert_eq!(names(0o755, Root::Never), [] as [&str; 0]);
        assert_eq!(names(0o711, Root::Never), [] as [&str; 0]);
        assert_eq!(names(0o755, Root::Changed), [] as [&str; 0]);
        assert_eq!(names(0o711, Root::Changed), ["./"]);
        assert_eq!(names(0o755, Root::Always), ["./"]);
    }

    /// A tree the container made, deeper than a thread of the blocking pool
    /// (2 MiB of stack) would walk by recursion: the walks do not recurse.
    #[test]
    fn test_a_deep_tree_is_walked_on_a_small_stack() {
        const DEPTH: usize = 700;
        let tmp = tempfile::tempdir().unwrap();
        let mut fd = open(tmp.path());
        for _ in 0..DEPTH {
            rustix::fs::mkdirat(&fd, "d", Mode::from_raw_mode(0o755)).unwrap();
            fd = openat(&fd, "d", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        }
        drop(fd);
        let root = open(tmp.path());
        let opts = Options::default();
        let on_small_stack = |f: Box<dyn FnOnce() + Send + '_>| {
            std::thread::scope(|s| {
                std::thread::Builder::new()
                    .stack_size(2 << 20)
                    .spawn_scoped(s, f)
                    .unwrap()
                    .join()
                    .unwrap()
            })
        };
        on_small_stack(Box::new(|| {
            let mut tar = Vec::new();
            write(root.as_fd(), &opts, &mut tar).unwrap();
            assert_eq!(entries(&tar).len(), DEPTH);
            assert_eq!(changes(root.as_fd(), &opts).unwrap().len(), DEPTH);
            let recorded = record(root.as_fd(), &opts).unwrap();
            assert_eq!(recorded.len(), DEPTH);
        }));
    }
}
