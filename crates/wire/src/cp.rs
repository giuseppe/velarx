// SPDX-License-Identifier: Apache-2.0
//! Copies between the host and the root file system of a container (`cp`
//! and the archive endpoints): the tar of a tree and its extraction.
//!
//! The tree read is controlled by whoever owns it (the container on a copy
//! out), so is the tar extracted (the container's content on a copy out to
//! the host).  Every entry is looked up once, relative to its open parent
//! directory and without following links: a node is opened with `O_PATH`,
//! its type checked on that inode and only then is it opened for reading
//! (a fifo or a device planted in the tree is never opened).  Extraction
//! resolves directories below their parent without a link
//! (`velarx_sys::fs::open_beneath`),
//! refuses `..`, and writes every regular file to a new inode (`O_EXCL`
//! after removing what was there), so nothing is written through a link, a
//! device or a hard link.  Trees deeper than [`MAX_DEPTH`] are refused.

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{
    chmod, chownat, fchmod, fchown, fstat, futimens, mkdirat, openat, readlinkat, statat,
    symlinkat, unlinkat, AtFlags, FileType, Gid, Mode, OFlags, ResolveFlags, Stat, Timespec,
    Timestamps, Uid,
};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use velarx_base::walk::{Visit, Walk};
use velarx_overlay_core::{class, Class};
use velarx_sys::fs::{open_beneath, openat2_retry, Beneath};

/// The deepest directory tree archived or extracted.
pub const MAX_DEPTH: usize = 4096;

/// Symbolic links followed to resolve one path.
const MAX_LINKS: usize = 40;

/// Size of the `/etc/passwd` or `/etc/group` of a container that is read.
pub const MAX_ID_FILE: u64 = 4 << 20;

fn too_deep() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("the tree is nested deeper than {MAX_DEPTH} directories"),
    )
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// `path` cleaned lexically as an absolute path: no empty or `.`
/// components, `..` resolved (never above `/`).
pub fn clean_path(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    format!("/{}", out.join("/"))
}

/// The directory and the last component of a clean absolute path; `/` is
/// `("/", "")`.
pub fn split_path(clean: &str) -> (String, String) {
    match clean.rsplit_once('/') {
        Some(("", base)) => ("/".to_string(), base.to_string()),
        Some((dir, base)) => (dir.to_string(), base.to_string()),
        None => ("/".to_string(), clean.to_string()),
    }
}

/// What a resolved path is opened with: in the root, no link at all.
const RESOLVED: ResolveFlags = ResolveFlags::IN_ROOT
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Open `path` resolved in `root` as its root directory (links are followed
/// but never lead out of it); `follow_last` false keeps a link in the last
/// component.
///
/// The links are read and resolved here, as podman's copier does, and the
/// path opened has none left (`RESOLVE_NO_SYMLINKS`, inside the root): the
/// kernel follows no link for the engine, so `protected_symlinks` does not
/// refuse the links that a user of the container made in a sticky
/// directory, and a link swapped in meanwhile fails the open instead of
/// being followed.
pub fn open_in_root(
    root: BorrowedFd<'_>,
    path: &str,
    flags: OFlags,
    follow_last: bool,
) -> io::Result<OwnedFd> {
    let resolved = if follow_last {
        resolve_in_root(root, path)?
    } else {
        let (dir, base) = split_path(&clean_path(path));
        let dir = resolve_in_root(root, &dir)?;
        match base.as_str() {
            "" => dir,
            b => format!("{}/{b}", dir.trim_end_matches('/')),
        }
    };
    open_resolved(root, &resolved, flags)
}

/// Open the path `path` of `root` that has no link but maybe its last
/// component, which is not followed.
fn open_resolved(root: BorrowedFd<'_>, path: &str, flags: OFlags) -> io::Result<OwnedFd> {
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    let flags = flags | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    openat2_retry(root, rel, flags, Mode::empty(), RESOLVED).map_err(io::Error::from)
}

/// The path `path` designates in `root`, every link resolved as the
/// kernel resolves it with `RESOLVE_IN_ROOT`; the last component may be
/// missing.
pub fn resolve_in_root(root: BorrowedFd<'_>, path: &str) -> io::Result<String> {
    let (out, _) = walk(path, true, |comps, last, _| {
        let fd = match open_resolved(root, &comps.join("/"), OFlags::PATH) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) && last => return Ok(Probe::Missing),
            Err(e) => return Err(e),
        };
        let st = fstat(&fd)?;
        if FileType::from_raw_mode(st.st_mode) != FileType::Symlink {
            return Ok(Probe::Plain);
        }
        let target = readlinkat(&fd, "", Vec::new())?;
        Ok(Probe::Link(
            String::from_utf8_lossy(target.as_bytes()).into_owned(),
        ))
    })?;
    Ok(format!("/{}", out.join("/")))
}

/// What a path names so far, in a tree walked by [`walk`].
pub enum Probe {
    /// Nothing: allowed for the last component only.
    Missing,
    /// A node that is not a link (or a link that is not followed).
    Plain,
    /// A link, to this target.
    Link(String),
}

/// Resolve `path` in a root a component at a time, links followed as the
/// kernel does with `RESOLVE_IN_ROOT`: `..` never leaves the root, an
/// absolute target starts again from it, at most `MAX_LINKS` links.
/// `probe(components so far, is it the last, is it followed if a link)`
/// says what a component is, in the tree of the caller (descriptors, or an
/// image's table of contents); the last component is followed only if
/// `follow_last`.  Returns the components and whether the last is missing.
pub fn walk(
    path: &str,
    follow_last: bool,
    mut probe: impl FnMut(&[String], bool, bool) -> io::Result<Probe>,
) -> io::Result<(Vec<String>, bool)> {
    let mut todo: Vec<String> = clean_path(path)
        .split('/')
        .filter(|c| !c.is_empty())
        .rev()
        .map(str::to_string)
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut links = 0;
    while let Some(c) = todo.pop() {
        match c.as_str() {
            "" | "." => continue,
            ".." => {
                out.pop();
                continue;
            }
            _ => {}
        }
        out.push(c);
        let last = todo.is_empty();
        match probe(&out, last, follow_last || !last)? {
            Probe::Missing => return Ok((out, true)),
            Probe::Plain => {}
            Probe::Link(target) => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(io::Error::from_raw_os_error(libc::ELOOP));
                }
                out.pop();
                if target.starts_with('/') {
                    out.clear();
                }
                todo.extend(target.split('/').rev().map(str::to_string));
            }
        }
    }
    Ok((out, false))
}

/// Reopen the node of the `O_PATH` descriptor `fd` with `flags`; `st` is
/// its status, checked again on what is opened.
pub fn reopen(fd: &OwnedFd, st: &Stat, flags: OFlags) -> io::Result<OwnedFd> {
    let opened = if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
        openat(
            fd,
            ".",
            flags | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )?
    } else {
        // the magic link opens the inode itself, not a name that could
        // have been replaced
        let path = velarx_sys::fd::proc_str(&fd);
        openat(
            rustix::fs::CWD,
            path.as_str(),
            flags | OFlags::CLOEXEC,
            Mode::empty(),
        )?
    };
    let now = fstat(&opened)?;
    if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino) {
        return Err(io::Error::other("the file changed while it was opened"));
    }
    Ok(opened)
}

/// Translation of the owners of the entries of a container: the id
/// mappings of its user namespace, as `(container id, host id, size)`.
#[derive(Debug, Clone, Default)]
pub struct IdMaps {
    pub uids: Vec<(u32, u32, u32)>,
    pub gids: Vec<(u32, u32, u32)>,
}

fn map_id(maps: &[(u32, u32, u32)], id: u32, to_host: bool) -> Option<u32> {
    if maps.is_empty() {
        return Some(id);
    }
    maps.iter().find_map(|&(c, h, size)| {
        let (from, to) = if to_host { (c, h) } else { (h, c) };
        let off = id.checked_sub(from)?;
        (off < size).then(|| to.checked_add(off)).flatten()
    })
}

/// The id the user nobody has when an id is not mapped.
const OVERFLOW_ID: u32 = 65534;

impl IdMaps {
    pub fn to_host(&self, uid: u32, gid: u32) -> Option<(u32, u32)> {
        Some((
            map_id(&self.uids, uid, true)?,
            map_id(&self.gids, gid, true)?,
        ))
    }

    pub fn to_container(&self, uid: u32, gid: u32) -> (u32, u32) {
        (
            map_id(&self.uids, uid, false).unwrap_or(OVERFLOW_ID),
            map_id(&self.gids, gid, false).unwrap_or(OVERFLOW_ID),
        )
    }
}

/// The content of a regular file, cut or padded with zeros to the size
/// written in its header (the file may change while it is read).
pub struct Exact<R> {
    pub inner: R,
    pub left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let n = match self.inner.read(&mut buf[..want])? {
            0 => {
                buf[..want].fill(0);
                want
            }
            n => n,
        };
        self.left -= n as u64;
        Ok(n)
    }
}

/// Writes the tar of a tree; `ids` translates the owners to the ids of a
/// container.
pub struct TreeWriter<'a, W: Write> {
    pub builder: &'a mut tar::Builder<W>,
    pub ids: Option<&'a IdMaps>,
}

impl<W: Write> TreeWriter<'_, W> {
    fn header(&self, st: &Stat, kind: tar::EntryType) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(st.st_mode & 0o7777);
        let (uid, gid) = match self.ids {
            Some(m) => m.to_container(st.st_uid, st.st_gid),
            None => (st.st_uid, st.st_gid),
        };
        h.set_uid(uid.into());
        h.set_gid(gid.into());
        h.set_mtime(st.st_mtime.max(0) as u64);
        h.set_size(0);
        h
    }

    /// Add the node `fd` (opened with `O_PATH`) as `tar_path`; whether it is
    /// a directory (its header is added when `header`, its entries are the
    /// walk's).  A fifo and a device are archived (never opened), as the
    /// copy out of a stopped container does it; sockets are skipped.
    pub fn add_node(&mut self, fd: OwnedFd, tar_path: &Path, header: bool) -> io::Result<bool> {
        let st = fstat(&fd)?;
        match FileType::from_raw_mode(st.st_mode) {
            FileType::Directory => {
                if header {
                    let mut h = self.header(&st, tar::EntryType::Directory);
                    self.builder.append_data(&mut h, tar_path, io::empty())?;
                }
                Ok(true)
            }
            FileType::RegularFile => {
                let file = std::fs::File::from(reopen(&fd, &st, OFlags::RDONLY)?);
                let size = st.st_size.max(0) as u64;
                let mut h = self.header(&st, tar::EntryType::Regular);
                // (a file with holes is a sparse entry)
                crate::sparse::append_file(self.builder, &mut h, tar_path, &file, size)?;
                Ok(false)
            }
            FileType::Symlink => {
                let target = readlinkat(&fd, "", Vec::new())?;
                let mut h = self.header(&st, tar::EntryType::Symlink);
                self.builder.append_link(
                    &mut h,
                    tar_path,
                    Path::new(OsStr::from_bytes(target.as_bytes())),
                )?;
                Ok(false)
            }
            FileType::Fifo => {
                let mut h = self.header(&st, tar::EntryType::Fifo);
                self.builder.append_data(&mut h, tar_path, io::empty())?;
                Ok(false)
            }
            kind @ (FileType::CharacterDevice | FileType::BlockDevice) => {
                let mut h = self.header(&st, tar::EntryType::Regular);
                let (major, minor) = (rustix::fs::major(st.st_rdev), rustix::fs::minor(st.st_rdev));
                append_device(
                    self.builder,
                    &mut h,
                    tar_path,
                    kind == FileType::BlockDevice,
                    (major, minor),
                )?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Add the node `fd` (opened with `O_PATH`) named `tar_path`, and all
    /// below it; `contents` adds only what a directory holds, at the top of
    /// the archive.
    pub fn add_tree(&mut self, fd: OwnedFd, tar_path: &Path, contents: bool) -> io::Result<()> {
        self.add_tree_excluding(fd, tar_path, contents, &[])
    }

    /// [`Self::add_tree`] without the entries of the top directory named
    /// in `exclude` ([`ROOT_EXCLUDES`] for a copy of the root of a
    /// container).
    pub fn add_tree_excluding(
        &mut self,
        fd: OwnedFd,
        tar_path: &Path,
        contents: bool,
        exclude: &[&str],
    ) -> io::Result<()> {
        let contents =
            contents && FileType::from_raw_mode(fstat(&fd)?.st_mode) == FileType::Directory;
        let top = if contents { Path::new("") } else { tar_path };
        if !self.add_node(fd.try_clone()?, top, !contents)? {
            return Ok(());
        }
        let st = fstat(&fd)?;
        let root = reopen(&fd, &st, OFlags::RDONLY)?;
        drop(fd);
        Walk {
            // (the root is a level of the tree: MAX_DEPTH levels in all)
            max_depth: MAX_DEPTH - 1,
            sorted: true,
            skip_gone: true,
            lenient: false,
        }
        .run(root, top.to_path_buf(), &mut Archive { w: self, exclude })?;
        Ok(())
    }
}

/// What a copy out of the root of a container leaves out of it, as podman's
/// `copier.GetOptions.Excludes` does (`dev`, `proc`, `sys`: the devices and
/// the kernel's files are not the container's).
pub const ROOT_EXCLUDES: [&str; 3] = ["dev", "proc", "sys"];

/// Add a character or block device to a tar as a header with its numbers
/// (`major`, `minor`) and no content, as `tar.FileInfoHeader` makes it for
/// podman's copy: the device is never opened.  `h` has the mode, owner,
/// time and size 0 of the device.
pub fn append_device<W: Write>(
    b: &mut tar::Builder<W>,
    h: &mut tar::Header,
    path: &Path,
    block: bool,
    (major, minor): (u32, u32),
) -> io::Result<()> {
    h.set_entry_type(if block {
        tar::EntryType::Block
    } else {
        tar::EntryType::Char
    });
    h.set_device_major(major)?;
    h.set_device_minor(minor)?;
    b.append_data(h, path, io::empty())
}

/// The walk of a tree into a tar: the state of a directory is its path in
/// the archive.
struct Archive<'a, 'b, W: Write> {
    w: &'a mut TreeWriter<'b, W>,
    /// The names of the top directory that are left out.
    exclude: &'a [&'a str],
}

impl<W: Write> Visit for Archive<'_, '_, W> {
    type Dir = PathBuf;

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        _: &Stat,
        depth: usize,
        parent: &mut PathBuf,
    ) -> io::Result<Option<PathBuf>> {
        if depth == 0 && self.exclude.iter().any(|x| OsStr::new(x) == name) {
            return Ok(None);
        }
        let tar_path = parent.join(name);
        let fd = match openat(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            // removed since the directory was read
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(self.w.add_node(fd, &tar_path, true)?.then_some(tar_path))
    }
}

/// What the whiteouts of a layer become in the directory it is extracted
/// into.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Whiteouts {
    /// The marks of an overlay's upper directory: a character device 0:0,
    /// and `overlay.opaque` on a directory (the base is an upper directory).
    #[default]
    OverlayMarks,
    /// The files are removed: `.wh.name` removes `name`, `.wh..wh..opq`
    /// removes what its directory holds (the base is a plain directory, the
    /// root file system of a container that copies the layers).
    Remove,
}

/// How an archive is extracted.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// The first component of the entries renamed (podman's `rename`).
    pub rename: HashMap<String, String>,
    /// The owner of everything created; the caller's when `None`.
    pub owner: Option<(u32, u32)>,
    /// Keep the owners of the entries of the archive instead, ids of the
    /// container translated to the host by these maps (Docker's
    /// copyUIDGID=false); an entry whose owner is not mapped gets `owner`.
    pub archive_owners: Option<IdMaps>,
    /// The base is (in) the upper directory of an overlay: a whiteout is
    /// replaced by what the archive has, a directory made opaque.
    pub overlay_upper: bool,
    /// The archive is a layer (and the base an overlay upper directory):
    /// its `.wh.` entries become whiteouts, `.wh..wh..opq` makes the
    /// directory opaque, hard links are made (below the base), and the
    /// xattrs of its entries (`SCHILY.xattr.*`) are set (`set_xattrs`).
    pub layer: bool,
    /// With `layer`: what a `.wh.` entry and `.wh..wh..opq` do in the base.
    pub whiteouts: Whiteouts,
    /// A directory may be replaced by what is not one, and the other way
    /// round (podman cp --overwrite, Docker's noOverwriteDirNonDir=false).
    pub overwrite_dir_non_dir: bool,
    /// The setuid and setgid bits of the entries are not set.
    pub mask_setid: bool,
}

/// Remove `name` of `dir` and, for a directory, what is below it, without
/// leaving `dir` or following a link.
fn remove_tree_at(dir: &OwnedFd, name: &OsStr) -> io::Result<()> {
    velarx_base::tree::remove_at(dir.as_fd(), name, &velarx_base::tree::Remove::default())
}

/// Remove what the directory `dir` holds, without leaving it.
fn empty_dir(dir: &OwnedFd) -> io::Result<()> {
    // (a descriptor that can be read: the one of a path is not)
    let readable = openat(
        dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    velarx_base::tree::empty(readable, &velarx_base::tree::Remove::default())
}

/// An overlay whiteout: a character device 0:0.
pub fn is_whiteout(st: &Stat) -> bool {
    FileType::from_raw_mode(st.st_mode) == FileType::CharacterDevice && st.st_rdev == 0
}

/// Mark the directory `fd` opaque: the lower directories under it are not
/// seen.  The attribute of a privileged overlay or of a `userxattr` one.
fn set_opaque(fd: BorrowedFd<'_>) -> io::Result<()> {
    let path = velarx_sys::fd::proc_str(&fd);
    let trusted = rustix::fs::setxattr(
        path.as_str(),
        "trusted.overlay.opaque",
        b"y",
        rustix::fs::XattrFlags::empty(),
    );
    let user = rustix::fs::setxattr(
        path.as_str(),
        "user.overlay.opaque",
        b"y",
        rustix::fs::XattrFlags::empty(),
    );
    match (trusted, user) {
        (Err(e), Err(_)) => Err(e.into()),
        _ => Ok(()),
    }
}

/// The xattrs a layer's entry has (its `SCHILY.xattr.*` records) that an
/// extraction sets: not the overlay's own (a whiteout, an opaque directory,
/// a redirect or metacopy is the layer's `.wh.` entries or nothing, never an
/// attribute the archive sets) nor the SELinux label (the container's
/// context gives it), as the reading of a layer leaves them out.
fn layer_xattrs<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    if entry.header().entry_type().is_pax_global_extensions() {
        return Ok(out);
    }
    let Some(exts) = entry.pax_extensions()? else {
        return Ok(out);
    };
    for ext in exts {
        let ext = ext?;
        let Some(name) = ext.key_bytes().strip_prefix(b"SCHILY.xattr.") else {
            continue;
        };
        match class(name) {
            Class::Overlay | Class::Label => continue,
            Class::Refused(_) => {
                return Err(invalid(format!(
                    "invalid xattr name `{}` in the archive",
                    String::from_utf8_lossy(name)
                )))
            }
            Class::Plain => {}
        }
        out.push((name.to_vec(), ext.value_bytes().to_vec()));
    }
    Ok(out)
}

/// Set the xattrs of a layer's entry on `path` (a link is followed when
/// `follow`: the magic link of a descriptor), once its owner is set (a chown clears `security.capability`).  As
/// containers-storage's extraction of a layer: an attribute the file system
/// does not take, or one that a user who is not root may not set
/// (`trusted.*`, `security.capability`), is left out with a warning; any
/// other failure is an error.
fn set_xattrs(
    path: &Path,
    follow: bool,
    xattrs: &[(Vec<u8>, Vec<u8>)],
    rel: &Path,
) -> io::Result<()> {
    for (name, value) in xattrs {
        let shown = String::from_utf8_lossy(name);
        let name = OsStr::from_bytes(name);
        let flags = rustix::fs::XattrFlags::empty();
        let r = if follow {
            rustix::fs::setxattr(path, name, value, flags)
        } else {
            rustix::fs::lsetxattr(path, name, value, flags)
        };
        match r {
            Ok(()) => {}
            Err(e)
                if e == rustix::io::Errno::NOTSUP
                    || (e == rustix::io::Errno::PERM && !rustix::process::geteuid().is_root()) =>
            {
                tracing::warn!(
                    "the xattr `{shown}` of `/{}` is not set: {e}",
                    rel.display()
                );
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::Error::from(e).kind(),
                    format!("setting the xattr `{shown}` of `/{}`: {e}", rel.display()),
                ))
            }
        }
    }
    Ok(())
}

fn chown_fd(fd: BorrowedFd<'_>, owner: Option<(u32, u32)>) -> io::Result<()> {
    if let Some((uid, gid)) = owner {
        chownat(
            fd,
            "",
            Some(Uid::from_raw_unchecked(uid)),
            Some(Gid::from_raw_unchecked(gid)),
            AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        )?;
    }
    Ok(())
}

fn open_dir_beneath(dir: &OwnedFd, name: &OsStr) -> io::Result<OwnedFd> {
    Ok(open_beneath(
        dir.as_fd(),
        Path::new(name),
        Beneath::DirectoryPath,
    )?)
}

/// The directory below `base` that holds the entry `rel`, its missing
/// directories created; returns it and the last component.
fn parent_dir(
    base: BorrowedFd<'_>,
    rel: &Path,
    owner: Option<(u32, u32)>,
) -> io::Result<(OwnedFd, OsString)> {
    let name = rel
        .file_name()
        .ok_or_else(|| invalid(format!("invalid path `{}`", rel.display())))?
        .to_owned();
    let mut cur = rustix::io::fcntl_dupfd_cloexec(base, 0)?;
    if let Some(parent) = rel.parent() {
        for c in parent.components() {
            let Component::Normal(c) = c else {
                return Err(invalid(format!("invalid path `{}`", rel.display())));
            };
            cur = match open_dir_beneath(&cur, c) {
                Ok(fd) => fd,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    mkdirat(&cur, c, Mode::from_raw_mode(0o755))?;
                    let fd = open_dir_beneath(&cur, c)?;
                    chown_fd(fd.as_fd(), owner)?;
                    fd
                }
                Err(e) => return Err(e),
            };
        }
    }
    Ok((cur, name))
}

/// The path of an entry below the destination, its first component renamed.
fn entry_path(raw: &Path, rename: &HashMap<String, String>) -> io::Result<PathBuf> {
    let bad = || invalid(format!("invalid path in the archive: {}", raw.display()));
    let mut rel = PathBuf::new();
    let mut depth = 0;
    for c in raw.components() {
        match c {
            Component::Normal(n) => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(too_deep());
                }
                match rename.get(n.to_string_lossy().as_ref()) {
                    Some(new) if rel.as_os_str().is_empty() => {
                        if new.is_empty() || new == "." || new == ".." || new.contains('/') {
                            return Err(invalid(format!("invalid name `{new}` to rename to")));
                        }
                        rel.push(new)
                    }
                    _ => rel.push(n),
                }
            }
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return Err(bad()),
        }
    }
    Ok(rel)
}

/// Remove what is at `name` unless it is a directory; fails on a directory
/// when `kind` is not one.
fn make_room(
    dir: &OwnedFd,
    name: &OsStr,
    rel: &Path,
    kind: &str,
    overwrite_dir: bool,
) -> io::Result<()> {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(s) if FileType::from_raw_mode(s.st_mode) == FileType::Directory && overwrite_dir => {
            remove_tree_at(dir, name)
        }
        Ok(s) if FileType::from_raw_mode(s.st_mode) == FileType::Directory => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "error creating \"/{}\": cannot overwrite directory with {kind}: file exists",
                rel.display()
            ),
        )),
        Ok(_) => unlinkat(dir, name, AtFlags::empty()).map_err(io::Error::from),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Set the times of `name` of `dir` without following it (a symlink, a
/// whiteout).  A file system that keeps no times for a symlink (ENOSYS,
/// EOPNOTSUPP) does not fail the extraction, as with containers-storage's.
fn set_link_times(dir: &OwnedFd, name: &OsStr, stamp: &Timestamps) -> io::Result<()> {
    match rustix::fs::utimensat(dir, name, stamp, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(()) | Err(rustix::io::Errno::NOSYS | rustix::io::Errno::OPNOTSUPP) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Extract the tar read from `r` below the directory `base`.  Hard links,
/// devices and fifos are skipped with a warning, but for a layer
/// (`opts.layer`), whose hard links, fifos and devices are made (a device
/// only where this process may make one).  The directories get the times of
/// the archive at the end, when nothing more is made in them (as podman's
/// and Docker's extraction).
pub fn extract<R: Read>(r: R, base: BorrowedFd<'_>, opts: &ExtractOptions) -> io::Result<()> {
    for (rel, kind) in extract_with(r, base, opts)? {
        tracing::warn!("cp: entry {} of type {kind:?} skipped", rel.display());
    }
    Ok(())
}

/// `extract`, the entries it skips returned (their path below the base and
/// their type) instead of warned of.
pub fn extract_with<R: Read>(
    r: R,
    base: BorrowedFd<'_>,
    opts: &ExtractOptions,
) -> io::Result<Vec<(PathBuf, tar::EntryType)>> {
    let mut skipped = Vec::new();
    let mut ar = crate::sparse::archive(r);
    let mut dir_times: Vec<(PathBuf, i64)> = Vec::new();
    let mut root_time = None;
    for entry in ar.entries()? {
        let mut entry = entry?;
        let raw = crate::sparse::path(&mut entry)?;
        let rel = entry_path(&raw, &opts.rename)?;
        let xattrs = if opts.layer {
            layer_xattrs(&mut entry)?
        } else {
            Vec::new()
        };
        if rel.as_os_str().is_empty() {
            // (the root of a layer in an upper directory is the base)
            if opts.overlay_upper && entry.header().entry_type() == tar::EntryType::Directory {
                chown_fd(base, owner_of(entry.header(), opts))?;
                let magic = velarx_sys::fd::proc_str(&base);
                chmod(
                    magic.as_str(),
                    Mode::from_raw_mode(entry.header().mode().unwrap_or(0o755) & 0o7777),
                )?;
                set_xattrs(Path::new(&magic), true, &xattrs, &rel)?;
                root_time = Some(entry.header().mtime().unwrap_or(0).min(i64::MAX as u64) as i64);
            }
            continue;
        }
        let (dir, name) = parent_dir(base, &rel, opts.owner)?;
        let mtime = entry.header().mtime().unwrap_or(0).min(i64::MAX as u64) as i64;
        let stamp = Timestamps {
            last_access: Timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
            last_modification: Timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
        };
        if opts.layer {
            if let Some(hidden) = name.as_bytes().strip_prefix(b".wh.") {
                if hidden == b".wh..opq" {
                    if opts.whiteouts == Whiteouts::Remove {
                        empty_dir(&dir)?;
                    } else {
                        set_opaque(dir.as_fd())?;
                    }
                    continue;
                }
                let hidden = OsStr::from_bytes(hidden);
                if hidden.is_empty() || hidden == "." || hidden == ".." {
                    return Err(invalid(format!("invalid whiteout `{}`", rel.display())));
                }
                if opts.whiteouts == Whiteouts::Remove {
                    match remove_tree_at(&dir, hidden) {
                        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                        _ => continue,
                    }
                }
                make_room(&dir, hidden, &rel, "a whiteout", opts.overwrite_dir_non_dir)?;
                rustix::fs::mknodat(
                    &dir,
                    hidden,
                    FileType::CharacterDevice,
                    Mode::empty(),
                    rustix::fs::makedev(0, 0),
                )?;
                // (the walk of an upper directory writes the time of its
                // whiteouts in their `.wh.` entries)
                set_link_times(&dir, hidden, &stamp)?;
                continue;
            }
            if entry.header().entry_type() == tar::EntryType::Link {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| {
                        invalid(format!("hard link `{}` without target", rel.display()))
                    })?
                    .into_owned();
                let target = entry_path(&target, &opts.rename)?;
                let (tdir, tname) = parent_dir(base, &target, opts.owner)?;
                make_room(&dir, &name, &rel, "a hard link", opts.overwrite_dir_non_dir)?;
                // (no flag: a link at the target is linked, not followed)
                rustix::fs::linkat(&tdir, &tname, &dir, &name, AtFlags::empty())?;
                continue;
            }
        }
        let owner = owner_of(entry.header(), opts);
        let kept = if opts.mask_setid { 0o1777 } else { 0o7777 };
        let mode = Mode::from_raw_mode(entry.header().mode().unwrap_or(0o644) & kept);
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                let mut opaque = false;
                match statat(&dir, &name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(s) if FileType::from_raw_mode(s.st_mode) == FileType::Directory => {}
                    // a directory of the archive where one was deleted
                    Ok(s) if opts.overlay_upper && is_whiteout(&s) => {
                        unlinkat(&dir, &name, AtFlags::empty())?;
                        mkdirat(&dir, &name, Mode::from_raw_mode(0o700))?;
                        opaque = true;
                    }
                    Ok(_) if opts.overwrite_dir_non_dir => {
                        unlinkat(&dir, &name, AtFlags::empty())?;
                        mkdirat(&dir, &name, Mode::from_raw_mode(0o700))?;
                    }
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "error creating \"/{}\": cannot overwrite non-directory with a directory: file exists",
                                rel.display()
                            ),
                        ))
                    }
                    Err(rustix::io::Errno::NOENT) => {
                        mkdirat(&dir, &name, Mode::from_raw_mode(0o700))?
                    }
                    Err(e) => return Err(e.into()),
                }
                let fd = open_dir_beneath(&dir, &name)?;
                if opaque {
                    set_opaque(fd.as_fd())?;
                }
                chown_fd(fd.as_fd(), owner)?;
                // mkdir drops the setgid bit and an O_PATH descriptor cannot
                // be chmod'ed: through its magic link
                let magic = velarx_sys::fd::proc_str(&fd);
                chmod(magic.as_str(), mode)?;
                set_xattrs(Path::new(&magic), true, &xattrs, &rel)?;
                dir_times.push((rel.clone(), mtime));
            }
            tar::EntryType::Regular | tar::EntryType::Continuous | tar::EntryType::GNUSparse => {
                make_room(&dir, &name, &rel, "a file", opts.overwrite_dir_non_dir)?;
                let fd = openat(
                    &dir,
                    &name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )?;
                let mut f = std::fs::File::from(fd);
                crate::sparse::copy(&mut entry, &mut f, crate::sparse::MAX_REAL_SIZE)?;
                // chown clears the setuid and setgid bits: it comes first
                if let Some((uid, gid)) = owner {
                    fchown(
                        &f,
                        Some(Uid::from_raw_unchecked(uid)),
                        Some(Gid::from_raw_unchecked(gid)),
                    )?;
                }
                fchmod(&f, mode)?;
                set_xattrs(
                    Path::new(&velarx_sys::fd::proc_str(&f)),
                    true,
                    &xattrs,
                    &rel,
                )?;
                futimens(&f, &stamp)?;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "symlink without target")
                    })?
                    .into_owned();
                make_room(&dir, &name, &rel, "a link", opts.overwrite_dir_non_dir)?;
                symlinkat(&target, &dir, &name)?;
                if let Some((uid, gid)) = owner {
                    chownat(
                        &dir,
                        &name,
                        Some(Uid::from_raw_unchecked(uid)),
                        Some(Gid::from_raw_unchecked(gid)),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )?;
                }
                if !xattrs.is_empty() {
                    // (the link itself, in the directory that holds it)
                    let at = Path::new(&velarx_sys::fd::proc_str(&dir)).join(&name);
                    set_xattrs(&at, false, &xattrs, &rel)?;
                }
                // (the link's own time, not its target's: the archive of a
                // layer made of this copy keeps it)
                set_link_times(&dir, &name, &stamp)?;
            }
            // the fifos and devices of a layer are made: a container's layer
            // (an upper directory, a copy) and the directory of a squash hold
            // them as the container had them; a device this process may not
            // make (without privilege) is skipped with a warning
            t @ (tar::EntryType::Fifo | tar::EntryType::Char | tar::EntryType::Block)
                if opts.layer =>
            {
                let h = entry.header();
                let (kind, dev) = match t {
                    tar::EntryType::Fifo => (FileType::Fifo, 0),
                    _ => (
                        if t == tar::EntryType::Char {
                            FileType::CharacterDevice
                        } else {
                            FileType::BlockDevice
                        },
                        rustix::fs::makedev(
                            h.device_major()?.unwrap_or(0),
                            h.device_minor()?.unwrap_or(0),
                        ),
                    ),
                };
                // (in an upper directory a character device 0:0 is a whiteout)
                if kind == FileType::CharacterDevice
                    && dev == 0
                    && opts.whiteouts == Whiteouts::OverlayMarks
                {
                    tracing::warn!(
                        "cp: the device 0:0 `/{}` of the layer is skipped: it would be a whiteout",
                        rel.display()
                    );
                    continue;
                }
                make_room(
                    &dir,
                    &name,
                    &rel,
                    "a special file",
                    opts.overwrite_dir_non_dir,
                )?;
                match rustix::fs::mknodat(&dir, &name, kind, Mode::from_raw_mode(0o600), dev) {
                    Ok(()) => {}
                    Err(e @ (rustix::io::Errno::PERM | rustix::io::Errno::ACCESS))
                        if kind != FileType::Fifo =>
                    {
                        tracing::warn!(
                            "cp: the device `/{}` of the layer is not made here: {e}",
                            rel.display()
                        );
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
                if let Some((uid, gid)) = owner {
                    chownat(
                        &dir,
                        &name,
                        Some(Uid::from_raw_unchecked(uid)),
                        Some(Gid::from_raw_unchecked(gid)),
                        AtFlags::SYMLINK_NOFOLLOW,
                    )?;
                }
                // (the node that was made, not what its name is now: through
                // the magic link of a descriptor that does not open it)
                let fd = openat(
                    &dir,
                    &name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let magic = velarx_sys::fd::proc_str(&fd);
                chmod(magic.as_str(), mode)?;
                if let Err(e) = set_xattrs(Path::new(&magic), true, &xattrs, &rel) {
                    tracing::warn!("cp: {e}");
                }
                rustix::fs::utimensat(rustix::fs::CWD, magic.as_str(), &stamp, AtFlags::empty())?;
            }
            tar::EntryType::XGlobalHeader
            | tar::EntryType::XHeader
            | tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink => {}
            other => skipped.push((rel, other)),
        }
    }
    if let Some(mtime) = root_time {
        let at = Timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        };
        let stamp = Timestamps {
            last_access: at,
            last_modification: at,
        };
        futimens(base, &stamp)?;
    }
    // (a directory a later entry replaced is not one any more)
    for (rel, mtime) in dir_times.iter().rev() {
        let (dir, name) = parent_dir(base, rel, opts.owner)?;
        let Ok(fd) = open_dir_beneath(&dir, &name) else {
            continue;
        };
        let at = Timespec {
            tv_sec: *mtime,
            tv_nsec: 0,
        };
        let stamp = Timestamps {
            last_access: at,
            last_modification: at,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            velarx_sys::fd::proc_str(&fd).as_str(),
            &stamp,
            AtFlags::empty(),
        )?;
    }
    Ok(skipped)
}

/// The owner the entry with the header `h` is given: its own, translated to
/// the host, when the options keep the owners of the archive.
fn owner_of(h: &tar::Header, opts: &ExtractOptions) -> Option<(u32, u32)> {
    let Some(maps) = &opts.archive_owners else {
        return opts.owner;
    };
    match (h.uid(), h.gid()) {
        (Ok(u), Ok(g)) => u32::try_from(u)
            .ok()
            .zip(u32::try_from(g).ok())
            .and_then(|(u, g)| maps.to_host(u, g))
            .or(opts.owner),
        _ => opts.owner,
    }
}

/// The owner of the files copied into a container: its user (`uid[:gid]`
/// or names looked up in its `/etc/passwd` and `/etc/group`), root when it
/// has none.
pub fn container_user(root: BorrowedFd<'_>, user: &str) -> io::Result<(u32, u32)> {
    user_of(user, |path| read_id_file(root, path))
}

/// [`container_user`] with the files of the container read by `read`.
pub fn user_of(user: &str, read: impl Fn(&str) -> io::Result<String>) -> io::Result<(u32, u32)> {
    let (u, g) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let passwd = || read("/etc/passwd");
    let (uid, primary) = if u.is_empty() {
        (0, Some(0))
    } else if let Ok(uid) = u.parse::<u32>() {
        let primary = passwd()
            .ok()
            .and_then(|p| lookup(&p, |f| f[2] == u).and_then(|f| f[3].parse().ok()));
        (uid, primary)
    } else {
        let p = passwd()?;
        let f = lookup(&p, |f| f[0] == u)
            .ok_or_else(|| invalid(format!("no user `{u}` in the container")))?;
        let uid = f[2]
            .parse()
            .map_err(|_| invalid(format!("invalid uid of `{u}`")))?;
        (uid, f[3].parse().ok())
    };
    let gid = match g {
        None | Some("") => primary.unwrap_or(0),
        Some(g) => match g.parse::<u32>() {
            Ok(gid) => gid,
            Err(_) => {
                let groups = read("/etc/group")?;
                lookup(&groups, |f| f[0] == g)
                    .and_then(|f| f[2].parse().ok())
                    .ok_or_else(|| invalid(format!("no group `{g}` in the container")))?
            }
        },
    };
    if uid == u32::MAX || gid == u32::MAX {
        return Err(invalid(format!("invalid user `{user}`")));
    }
    Ok((uid, gid))
}

fn read_id_file(root: BorrowedFd<'_>, path: &str) -> io::Result<String> {
    let fd = open_in_root(root, path, OFlags::PATH, true)?;
    let st = fstat(&fd)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(invalid(format!("`{path}` is not a regular file")));
    }
    let mut out = String::new();
    std::fs::File::from(reopen(&fd, &st, OFlags::RDONLY)?)
        .take(MAX_ID_FILE)
        .read_to_string(&mut out)?;
    Ok(out)
}

/// The fields of the first line of a passwd or group file `pick` accepts.
fn lookup(content: &str, pick: impl Fn(&[&str]) -> bool) -> Option<Vec<&str>> {
    content
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .find(|f| f.len() >= 4 && pick(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (n, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, n, *d).unwrap();
        }
        b.into_inner().unwrap()
    }

    /// A tar whose first entry is named `name` (which the builder refuses).
    fn raw_tar_named(name: &[u8]) -> Vec<u8> {
        let mut raw = tar_of(&[("x", b"1")]);
        raw[..100].fill(0);
        raw[..name.len()].copy_from_slice(name);
        let mut h = tar::Header::new_old();
        h.as_mut_bytes().copy_from_slice(&raw[..512]);
        h.set_cksum();
        raw[..512].copy_from_slice(h.as_bytes());
        raw
    }

    fn dir_fd(dir: &Path) -> OwnedFd {
        openat(
            rustix::fs::CWD,
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .unwrap()
    }

    fn path_fd(p: &Path) -> OwnedFd {
        openat(rustix::fs::CWD, p, OFlags::PATH, Mode::empty()).unwrap()
    }

    fn names(tar: &[u8]) -> Vec<String> {
        tar::Archive::new(tar)
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().to_string())
            .collect()
    }

    fn archive(p: &Path, name: &str, contents: bool, ids: Option<&IdMaps>) -> io::Result<Vec<u8>> {
        let mut b = tar::Builder::new(Vec::new());
        TreeWriter {
            builder: &mut b,
            ids,
        }
        .add_tree(path_fd(p), Path::new(name), contents)?;
        b.into_inner()
    }

    #[test]
    fn clean_and_split() {
        assert_eq!(clean_path("a/../../b/./c//"), "/b/c");
        assert_eq!(clean_path("/.."), "/");
        assert_eq!(clean_path(""), "/");
        assert_eq!(split_path("/b/c"), ("/b".to_string(), "c".to_string()));
        assert_eq!(split_path("/c"), ("/".to_string(), "c".to_string()));
        assert_eq!(split_path("/"), ("/".to_string(), "".to_string()));
    }

    #[test]
    fn resolves_links_in_the_root() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/sub")).unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("abs")).unwrap();
        std::os::unix::fs::symlink("../../../etc/sub", d.path().join("etc/rel")).unwrap();
        std::os::unix::fs::symlink("loop", d.path().join("loop")).unwrap();
        let root = dir_fd(d.path());
        assert_eq!(
            resolve_in_root(root.as_fd(), "/abs/sub").unwrap(),
            "/etc/sub"
        );
        assert_eq!(
            resolve_in_root(root.as_fd(), "/etc/rel/new").unwrap(),
            "/etc/sub/new"
        );
        assert_eq!(resolve_in_root(root.as_fd(), "/../abs").unwrap(), "/etc");
        assert!(resolve_in_root(root.as_fd(), "/loop").is_err());
        assert!(resolve_in_root(root.as_fd(), "/nope/x").is_err());
    }

    #[test]
    fn open_in_root_stays_in_the_root() {
        let d = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("pw")).unwrap();
        std::os::unix::fs::symlink("../../../../etc", d.path().join("up")).unwrap();
        let root = dir_fd(d.path());
        assert!(open_in_root(root.as_fd(), "/pw", OFlags::RDONLY, true).is_err());
        assert!(open_in_root(root.as_fd(), "/up/passwd", OFlags::RDONLY, true).is_err());
        assert!(open_in_root(root.as_fd(), "/../../etc/passwd", OFlags::RDONLY, true).is_err());
    }

    #[test]
    fn open_in_root_follows_links_itself() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/f"), "x").unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("abs")).unwrap();
        std::os::unix::fs::symlink("abs/f", d.path().join("lf")).unwrap();
        let root = dir_fd(d.path());
        // through a link, to a link, and a link kept as the last component
        assert!(open_in_root(root.as_fd(), "/abs/f", OFlags::RDONLY, true).is_ok());
        assert!(open_in_root(root.as_fd(), "/lf", OFlags::RDONLY, true).is_ok());
        let l = open_in_root(root.as_fd(), "/lf", OFlags::PATH, false).unwrap();
        assert_eq!(
            FileType::from_raw_mode(fstat(&l).unwrap().st_mode),
            FileType::Symlink
        );
        // what is opened has no link left: a path with one fails
        assert!(open_resolved(root.as_fd(), "/abs/f", OFlags::RDONLY).is_err());
    }

    #[test]
    fn extracts_below_the_base() {
        let d = tempfile::tempdir().unwrap();
        let t = tar_of(&[("a/b/f", b"hi"), ("g", b"x")]);
        extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).unwrap();
        assert_eq!(std::fs::read(d.path().join("a/b/f")).unwrap(), b"hi");
        assert_eq!(std::fs::read(d.path().join("g")).unwrap(), b"x");
    }

    #[test]
    fn the_root_entry_of_a_layer_is_the_upper_directory() {
        let make = |overlay_upper| {
            let d = tempfile::tempdir().unwrap();
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Directory);
            h.set_mode(0o1750);
            h.set_size(0);
            h.set_mtime(1_000_000);
            b.append_data(&mut h, "./", &[][..]).unwrap();
            let t = b.into_inner().unwrap();
            let opts = ExtractOptions {
                overlay_upper,
                layer: true,
                ..Default::default()
            };
            extract(&t[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
            let m = std::fs::metadata(d.path()).unwrap();
            (m.mode() & 0o7777, m.mtime())
        };
        assert_eq!(make(true), (0o1750, 1_000_000));
        // (any other base is not the root of a layer: it keeps its own)
        assert_ne!(make(false).0, 0o1750);
    }

    #[test]
    fn directories_get_the_times_of_the_archive_after_their_content() {
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind, time) in [
            ("a/", tar::EntryType::Directory, 1_000_000),
            ("a/b/", tar::EntryType::Directory, 2_000_000),
            ("a/b/f", tar::EntryType::Regular, 3_000_000),
            ("a/g", tar::EntryType::Regular, 4_000_000),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_mode(0o755);
            h.set_size(0);
            h.set_mtime(time);
            b.append_data(&mut h, name, &[][..]).unwrap();
        }
        let t = b.into_inner().unwrap();
        extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).unwrap();
        let mtime = |p: &str| std::fs::metadata(d.path().join(p)).unwrap().mtime();
        assert_eq!(
            ["a", "a/b", "a/b/f", "a/g"].map(mtime),
            [1_000_000, 2_000_000, 3_000_000, 4_000_000]
        );
    }

    /// A symlink gets the time of the archive too (its own, not its
    /// target's), as it does from podman's and Docker's extraction: a layer
    /// made of a copy has the times the container left.
    #[test]
    fn a_symlink_gets_the_time_of_the_archive() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        h.set_mtime(1_000_000);
        b.append_data(&mut h, "a/", &[][..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0o644);
        h.set_size(0);
        h.set_mtime(2_000_000);
        b.append_data(&mut h, "a/target", &[][..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_mode(0o777);
        h.set_size(0);
        h.set_mtime(3_000_000);
        b.append_link(&mut h, "a/link", "target").unwrap();
        let t = b.into_inner().unwrap();
        extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).unwrap();
        let time = |p: &str| std::fs::symlink_metadata(d.path().join(p)).unwrap().mtime();
        assert_eq!(time("a/link"), 3_000_000);
        // (not the target's)
        assert_eq!(time("a/target"), 2_000_000);
        assert_eq!(time("a"), 1_000_000);
    }

    /// The whiteout made for a `.wh.` entry of a layer gets its time: the
    /// walk of the upper directory writes it back.
    #[test]
    fn a_whiteout_gets_the_time_of_the_archive() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_mode(0);
        h.set_size(0);
        h.set_mtime(4_000_000);
        b.append_data(&mut h, "a/.wh.gone", &[][..]).unwrap();
        let t = b.into_inner().unwrap();
        let opts = ExtractOptions {
            layer: true,
            ..Default::default()
        };
        extract(&t[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        let m = std::fs::symlink_metadata(d.path().join("a/gone")).unwrap();
        assert!(m.file_type().is_char_device());
        assert_eq!(m.mtime(), 4_000_000);
    }

    #[test]
    fn keeps_the_owners_of_the_archive_through_the_maps() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_uid(1042);
        h.set_gid(1043);
        h.set_cksum();
        b.append_data(&mut h, "f", &b"hi"[..]).unwrap();
        let t = b.into_inner().unwrap();
        let (uid, gid) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let opts = ExtractOptions {
            archive_owners: Some(IdMaps {
                uids: vec![(1042, uid, 1)],
                gids: vec![(1043, gid, 1)],
            }),
            ..Default::default()
        };
        extract(&t[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        let m = std::fs::metadata(d.path().join("f")).unwrap();
        assert_eq!((m.uid(), m.gid()), (uid, gid));
    }

    #[test]
    fn rename_and_overwrite() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("new"), "old").unwrap();
        let t = tar_of(&[("f", b"fresh")]);
        let mut opts = ExtractOptions::default();
        opts.rename.insert("f".to_string(), "new".to_string());
        extract(&t[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        assert_eq!(std::fs::read(d.path().join("new")).unwrap(), b"fresh");
    }

    #[test]
    fn renames_only_to_a_name() {
        let d = tempfile::tempdir().unwrap();
        let t = tar_of(&[("f", b"x")]);
        for bad in ["..", "a/b", ""] {
            let mut opts = ExtractOptions::default();
            opts.rename.insert("f".to_string(), bad.to_string());
            assert!(
                extract(&t[..], dir_fd(d.path()).as_fd(), &opts).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn nothing_is_created_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("l")).unwrap();
        std::fs::write(outside.path().join("target"), "keep").unwrap();
        std::os::unix::fs::symlink(outside.path().join("target"), d.path().join("f")).unwrap();
        let t = tar_of(&[("l/evil", b"x")]);
        assert!(extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).is_err());
        assert!(!outside.path().join("evil").exists());
        // a link in place of a file is replaced, not written through
        let t = tar_of(&[("f", b"new")]);
        extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).unwrap();
        assert_eq!(
            std::fs::read(outside.path().join("target")).unwrap(),
            b"keep"
        );
        assert_eq!(std::fs::read(d.path().join("f")).unwrap(), b"new");
    }

    /// An entry `a` that is not a directory (a file, a symlink to a
    /// directory outside the destination, to `..` or to `/`, a fifo, a hard
    /// link) and then `a/passwd`: the entry below is an error, nothing is
    /// made outside the destination, and what `a` is stays what it is.
    #[test]
    fn nothing_is_made_below_an_entry_that_is_not_a_directory() {
        let outside = tempfile::tempdir().unwrap();
        let out = outside.path().to_str().unwrap();
        let kinds: [(tar::EntryType, &str); 6] = [
            (tar::EntryType::Regular, ""),
            (tar::EntryType::Symlink, out),
            (tar::EntryType::Symlink, ".."),
            (tar::EntryType::Symlink, "/"),
            (tar::EntryType::Fifo, ""),
            (tar::EntryType::Link, "f"),
        ];
        for (kind, link) in kinds {
            for opts in [
                ExtractOptions::default(),
                ExtractOptions {
                    layer: true,
                    overlay_upper: true,
                    ..Default::default()
                },
            ] {
                let mut b = tar::Builder::new(Vec::new());
                let mut put = |name: &str, kind, link: &str| {
                    let mut h = tar::Header::new_gnu();
                    h.set_entry_type(kind);
                    h.set_mode(0o644);
                    let size = usize::from(kind == tar::EntryType::Regular && name != "a");
                    h.set_size(size as u64);
                    if !link.is_empty() {
                        h.set_link_name(link).unwrap();
                    }
                    b.append_data(&mut h, name, &b"x"[..size]).unwrap();
                };
                put("f", tar::EntryType::Regular, "");
                put("a", kind, link);
                put("a/passwd", tar::EntryType::Regular, "");
                let tar = b.into_inner().unwrap();
                let d = tempfile::tempdir().unwrap();
                let at = format!("{kind:?} to `{link}`, layer {}", opts.layer);
                let e = extract(&tar[..], dir_fd(d.path()).as_fd(), &opts);
                assert!(!outside.path().join("passwd").exists(), "{at}");
                assert!(!d.path().join("passwd").exists(), "{at}");
                // (a copy skips a fifo and a hard link: `a` is not made,
                // and `a/passwd` makes it a directory)
                if opts.layer || !matches!(kind, tar::EntryType::Fifo | tar::EntryType::Link) {
                    assert!(e.is_err(), "{at}");
                    let made = std::fs::symlink_metadata(d.path().join("a")).unwrap();
                    assert!(!made.is_dir(), "{at}");
                }
            }
        }
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_link_from_the_archive_is_not_followed_by_later_entries() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "esc", outside.path()).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(1);
        b.append_data(&mut h, "esc/pwned", &b"x"[..]).unwrap();
        let t = b.into_inner().unwrap();
        assert!(extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).is_err());
        assert!(!outside.path().join("pwned").exists());
    }

    #[test]
    fn a_hard_link_is_not_written_through() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("victim"), "keep").unwrap();
        if std::fs::hard_link(outside.path().join("victim"), d.path().join("f")).is_err() {
            return;
        }
        extract(
            &tar_of(&[("f", b"new")])[..],
            dir_fd(d.path()).as_fd(),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(outside.path().join("victim")).unwrap(),
            b"keep"
        );
    }

    /// A file with holes in the archive (GNU tar `--sparse`, the `tar`
    /// crate) is the whole file, its holes kept, not skipped.
    #[test]
    fn a_sparse_file_is_extracted_with_its_holes() {
        let src = tempfile::tempdir().unwrap();
        let p = src.path().join("f");
        let mut f = std::fs::File::create(&p).unwrap();
        f.set_len(16 << 20).unwrap();
        io::Seek::seek(&mut f, io::SeekFrom::Start(8 << 20)).unwrap();
        io::Write::write_all(&mut f, b"middle").unwrap();
        f.set_len(16 << 20).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        b.append_path_with_name(&p, "dir/f").unwrap();
        let t = b.into_inner().unwrap();
        assert_eq!(t[156], b'S');
        let d = tempfile::tempdir().unwrap();
        extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).unwrap();
        let got = d.path().join("dir/f");
        assert_eq!(std::fs::read(&got).unwrap(), std::fs::read(&p).unwrap());
        assert!(
            std::os::unix::fs::MetadataExt::blocks(&std::fs::metadata(&got).unwrap()) * 512
                < 1 << 20
        );
    }

    /// A file dated before 1970 is put in an archive at the epoch (the
    /// vendored `tar` crate: it wrote the time as an unsigned number).
    #[test]
    fn a_file_dated_before_1970_is_archived_at_the_epoch() {
        let src = tempfile::tempdir().unwrap();
        let p = src.path().join("f");
        std::fs::write(&p, b"old").unwrap();
        let t = rustix::fs::Timespec {
            tv_sec: -86_400,
            tv_nsec: 0,
        };
        let times = rustix::fs::Timestamps {
            last_access: t,
            last_modification: t,
        };
        rustix::fs::utimensat(rustix::fs::CWD, &p, &times, rustix::fs::AtFlags::empty()).unwrap();
        let mut b = tar::Builder::new(Vec::new());
        b.mode(tar::HeaderMode::Complete);
        b.append_path_with_name(&p, "f").unwrap();
        let t = b.into_inner().unwrap();
        let mut a = tar::Archive::new(&t[..]);
        let e = a.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.header().mtime().unwrap(), 0);
    }

    #[test]
    fn parent_references_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        for name in [&b"../x"[..], b"a/../../x", b"/../x"] {
            let raw = raw_tar_named(name);
            assert!(extract(&raw[..], dir_fd(&sub).as_fd(), &Default::default()).is_err());
        }
        assert!(!d.path().join("x").exists());
    }

    /// The real name of a sparse entry of a pax format is checked as any
    /// other name.
    #[test]
    fn the_real_name_of_a_sparse_file_is_checked() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        for name in ["../x", "a/../../x", "/../x"] {
            let mut records = Vec::new();
            for (k, v) in [
                ("GNU.sparse.name", name),
                ("GNU.sparse.size", "4096"),
                ("GNU.sparse.map", ""),
            ] {
                // (lengths of two digits)
                let r = format!(" {k}={v}\n");
                records.extend(format!("{}{r}", r.len() + 2).into_bytes());
            }
            let mut b = tar::Builder::new(Vec::new());
            let mut x = tar::Header::new_ustar();
            x.set_entry_type(tar::EntryType::XHeader);
            x.set_size(records.len() as u64);
            b.append_data(&mut x, "PaxHeaders/x", &records[..]).unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_size(0);
            b.append_data(&mut h, "GNUSparseFile.1/x", io::empty())
                .unwrap();
            let t = b.into_inner().unwrap();
            let err = extract(&t[..], dir_fd(&sub).as_fd(), &Default::default()).unwrap_err();
            assert!(err.to_string().contains("invalid path"), "{name}: {err}");
        }
        assert!(!d.path().join("x").exists());
    }

    #[test]
    fn depth_is_capped() {
        let d = tempfile::tempdir().unwrap();
        let deep = "d/".repeat(MAX_DEPTH + 1) + "f";
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(0);
        b.append_data(&mut h, &deep, io::empty()).unwrap();
        let t = b.into_inner().unwrap();
        let e = extract(&t[..], dir_fd(d.path()).as_fd(), &Default::default()).unwrap_err();
        assert!(e.to_string().contains("nested"), "{e}");
    }

    /// A tree deeper than the descriptors a process may have (the test is
    /// run with `ulimit -Sn 256` by `test_a_deep_tree_is_archived_...`).
    fn deep_tree(root: &Path, depth: usize) {
        let mut fd = dir_fd(root);
        for _ in 0..depth {
            mkdirat(&fd, "d", Mode::from_raw_mode(0o700)).unwrap();
            fd = openat(
                &fd,
                "d",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
        }
    }

    #[test]
    fn a_deep_tree_is_archived_with_a_few_descriptors_and_a_too_deep_one_is_refused() {
        if let Some(t) = std::env::var_os("VELARX_CP_TEST_DIR") {
            let t = PathBuf::from(t);
            deep_tree(&t, 1000);
            let out = archive(&t, "top", false, None).unwrap();
            assert_eq!(names(&out).len(), 1001);
            let d2 = t.join("deeper");
            std::fs::create_dir(&d2).unwrap();
            deep_tree(&d2, MAX_DEPTH);
            let e = archive(&d2, "top", false, None).unwrap_err();
            assert!(e.to_string().contains("too deep"), "{e}");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(
                r#"ulimit -Sn 256 && exec "$0" --exact cp::tests::a_deep_tree_is_archived_with_a_few_descriptors_and_a_too_deep_one_is_refused"#,
            )
            .arg(std::env::current_exe().unwrap())
            .env("VELARX_CP_TEST_DIR", d.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn archives_a_tree() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/f"), "data").unwrap();
        std::os::unix::fs::symlink("sub/f", d.path().join("l")).unwrap();
        let out = archive(d.path(), "top", false, None).unwrap();
        assert_eq!(names(&out), ["top", "top/l", "top/sub", "top/sub/f"]);
        let out = archive(d.path(), "top", true, None).unwrap();
        assert_eq!(names(&out), ["l", "sub", "sub/f"]);
        let out = archive(&d.path().join("sub/f"), "g", false, None).unwrap();
        let mut ar = tar::Archive::new(&out[..]);
        let mut e = ar.entries().unwrap().next().unwrap().unwrap();
        let mut s = String::new();
        e.read_to_string(&mut s).unwrap();
        assert_eq!(s, "data");
    }

    #[test]
    fn a_fifo_is_archived_and_not_opened() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            FileType::Fifo,
            Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        std::fs::write(d.path().join("f"), "x").unwrap();
        // (a reader of the fifo would block forever; the stopped container
        // archives its fifos too)
        let out = archive(d.path(), "t", false, None).unwrap();
        assert_eq!(names(&out), ["t", "t/f", "t/fifo"]);
        let mut ar = tar::Archive::new(&out[..]);
        let kinds: Vec<_> = ar
            .entries()
            .unwrap()
            .map(|e| e.unwrap().header().entry_type())
            .collect();
        assert_eq!(kinds[2], tar::EntryType::Fifo);
    }

    /// A device is archived as a header with its numbers and no content,
    /// as podman's `tar.FileInfoHeader` does, and is not opened.
    #[test]
    fn a_device_is_archived_and_not_opened() {
        // (the character device 1:3 of the host, whose mknod is not ours)
        let out = archive(Path::new("/dev/null"), "null", false, None).unwrap();
        let mut ar = tar::Archive::new(&out[..]);
        let entries: Vec<_> = ar.entries().unwrap().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 1);
        let h = entries[0].header();
        assert_eq!(h.entry_type(), tar::EntryType::Char);
        assert_eq!(
            (h.device_major().unwrap(), h.device_minor().unwrap()),
            (Some(1), Some(3))
        );
        assert_eq!(h.size().unwrap(), 0);

        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o660);
        h.set_size(0);
        append_device(&mut b, &mut h, Path::new("blk"), true, (8, 17)).unwrap();
        let out = b.into_inner().unwrap();
        let mut ar = tar::Archive::new(&out[..]);
        let e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(e.header().entry_type(), tar::EntryType::Block);
        assert_eq!(
            (
                e.header().device_major().unwrap(),
                e.header().device_minor().unwrap()
            ),
            (Some(8), Some(17))
        );
    }

    /// The copy of the root leaves out `dev`, `proc` and `sys` of the top
    /// directory, and those names deeper in the tree stay.
    #[test]
    fn the_top_names_left_out_are_those_of_the_top_only() {
        let d = tempfile::tempdir().unwrap();
        for dir in ["dev", "proc/1", "sys", "usr/dev", "etc"] {
            std::fs::create_dir_all(d.path().join(dir)).unwrap();
        }
        std::fs::write(d.path().join("dev/null"), "").unwrap();
        let mut b = tar::Builder::new(Vec::new());
        TreeWriter {
            builder: &mut b,
            ids: None,
        }
        .add_tree_excluding(path_fd(d.path()), Path::new(""), true, &ROOT_EXCLUDES)
        .unwrap();
        let out = b.into_inner().unwrap();
        assert_eq!(names(&out), ["etc", "usr", "usr/dev"]);
    }

    #[test]
    fn overwrite_replaces_a_directory_and_a_file() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("foo/sub")).unwrap();
        std::fs::write(d.path().join("foo/sub/x"), "x").unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(2);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "foo", &b"hi"[..]).unwrap();
        let file_tar = b.into_inner().unwrap();
        let base = dir_fd(d.path());
        assert!(extract(&file_tar[..], base.as_fd(), &ExtractOptions::default()).is_err());
        let over = ExtractOptions {
            overwrite_dir_non_dir: true,
            ..Default::default()
        };
        extract(&file_tar[..], base.as_fd(), &over).unwrap();
        assert_eq!(std::fs::read(d.path().join("foo")).unwrap(), b"hi");
        // and a directory over the file
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o755);
        h.set_size(0);
        h.set_cksum();
        b.append_data(&mut h, "foo", &b""[..]).unwrap();
        let dir_tar = b.into_inner().unwrap();
        assert!(extract(&dir_tar[..], base.as_fd(), &ExtractOptions::default()).is_err());
        extract(&dir_tar[..], base.as_fd(), &over).unwrap();
        assert!(d.path().join("foo").is_dir());
    }

    #[test]
    fn owners_are_translated() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), "x").unwrap();
        let me = std::fs::metadata(d.path().join("f")).unwrap();
        let ids = IdMaps {
            uids: vec![(0, me.uid(), 1)],
            gids: vec![(0, me.gid(), 1)],
        };
        let out = archive(&d.path().join("f"), "f", false, Some(&ids)).unwrap();
        let mut ar = tar::Archive::new(&out[..]);
        let e = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(
            (e.header().uid().unwrap(), e.header().gid().unwrap()),
            (0, 0)
        );
        assert_eq!(ids.to_host(0, 0), Some((me.uid(), me.gid())));
        assert_eq!(ids.to_host(1, 0), None);
        assert_eq!(IdMaps::default().to_host(5, 6), Some((5, 6)));
        assert_eq!(ids.to_container(me.uid() + 1, me.gid()).0, OVERFLOW_ID);
    }

    #[test]
    fn keeps_the_special_bits() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("s"), "x").unwrap();
        std::fs::set_permissions(src.join("s"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        std::fs::create_dir(src.join("g")).unwrap();
        std::fs::set_permissions(src.join("g"), std::fs::Permissions::from_mode(0o2775)).unwrap();
        let t = archive(&src, "src", false, None).unwrap();
        let dst = d.path().join("dst");
        std::fs::create_dir(&dst).unwrap();
        extract(&t[..], dir_fd(&dst).as_fd(), &Default::default()).unwrap();
        let mode = |p: &str| std::fs::metadata(dst.join(p)).unwrap().mode() & 0o7777;
        assert_eq!(mode("src/s"), 0o4755);
        assert_eq!(mode("src/g"), 0o2775);
    }

    #[test]
    fn users_of_the_container() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("etc")).unwrap();
        std::fs::write(
            d.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\napp:x:1000:1001::/:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(d.path().join("etc/group"), "root:x:0:\nwheel:x:10:\n").unwrap();
        let root = dir_fd(d.path());
        let r = root.as_fd();
        assert_eq!(container_user(r, "").unwrap(), (0, 0));
        assert_eq!(container_user(r, "app").unwrap(), (1000, 1001));
        assert_eq!(container_user(r, "1000").unwrap(), (1000, 1001));
        assert_eq!(container_user(r, "1000:wheel").unwrap(), (1000, 10));
        assert_eq!(container_user(r, "42").unwrap(), (42, 0));
        assert_eq!(container_user(r, "42:7").unwrap(), (42, 7));
        assert!(container_user(r, "nobody").is_err());
        assert!(container_user(r, "app:nogroup").is_err());
        // a link to the host's passwd is resolved in the root
        std::fs::remove_file(d.path().join("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("/../../../../etc/passwd", d.path().join("etc/passwd")).unwrap();
        assert!(container_user(r, "root").is_err());
    }

    #[test]
    fn a_layer_is_extracted_with_its_links_and_whiteouts() {
        let mut b = tar::Builder::new(Vec::new());
        let file = |b: &mut tar::Builder<Vec<u8>>,
                    name: &str,
                    kind: tar::EntryType,
                    data: &[u8],
                    link: Option<&str>| {
            let mut h = tar::Header::new_gnu();
            h.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
            h.set_entry_type(kind);
            h.set_mode(if kind == tar::EntryType::Directory {
                0o755
            } else {
                0o644
            });
            h.set_size(data.len() as u64);
            if let Some(l) = link {
                h.set_link_name(l).unwrap();
            }
            h.set_cksum();
            b.append(&h, data).unwrap();
        };
        file(&mut b, "d/", tar::EntryType::Directory, b"", None);
        file(&mut b, "d/a", tar::EntryType::Regular, b"content", None);
        file(&mut b, "d/hard", tar::EntryType::Link, b"", Some("d/a"));
        let tar = b.into_inner().unwrap();
        let d = tempfile::tempdir().unwrap();
        let opts = ExtractOptions {
            layer: true,
            overlay_upper: true,
            ..Default::default()
        };
        extract(&tar[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(d.path().join("d/a")).unwrap();
        let h = std::fs::metadata(d.path().join("d/hard")).unwrap();
        assert_eq!(a.ino(), h.ino());
        // a hard link out of the base is refused
        let mut b = tar::Builder::new(Vec::new());
        file(
            &mut b,
            "x",
            tar::EntryType::Link,
            b"",
            Some("../../etc/passwd"),
        );
        let tar = b.into_inner().unwrap();
        let d = tempfile::tempdir().unwrap();
        assert!(extract(&tar[..], dir_fd(d.path()).as_fd(), &opts).is_err());
        assert!(!d.path().join("x").exists());
        // whiteouts and opaque directories need root (mknod, trusted xattrs)
        if velarx_base::ids::host_uid().unwrap() != 0 {
            return;
        }
        let mut b = tar::Builder::new(Vec::new());
        file(&mut b, "e/", tar::EntryType::Directory, b"", None);
        file(&mut b, "e/.wh.gone", tar::EntryType::Regular, b"", None);
        file(&mut b, "e/.wh..wh..opq", tar::EntryType::Regular, b"", None);
        let tar = b.into_inner().unwrap();
        let d = tempfile::tempdir().unwrap();
        extract(&tar[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        let st = statat(
            rustix::fs::CWD,
            d.path().join("e/gone"),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert!(is_whiteout(&st));
        assert!(!d.path().join("e/.wh.gone").exists());
    }

    /// A layer keeps its fifos and devices (a squash through the tar of a
    /// copy, the restore of a checkpoint): a device only where this process
    /// may make one, and never a 0:0 device into an upper directory, where
    /// it would be a whiteout.
    #[test]
    fn a_layer_makes_its_fifos_and_devices() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        let node = |b: &mut tar::Builder<Vec<u8>>, name: &str, kind, dev: (u32, u32)| {
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(kind);
            h.set_mode(0o640);
            h.set_size(0);
            h.set_mtime(1_500_000_000);
            h.set_device_major(dev.0).unwrap();
            h.set_device_minor(dev.1).unwrap();
            b.append_data(&mut h, name, &[][..]).unwrap();
        };
        let root = rustix::process::geteuid().is_root();
        for whiteouts in [Whiteouts::Remove, Whiteouts::OverlayMarks] {
            let d = tempfile::tempdir().unwrap();
            let mut b = tar::Builder::new(Vec::new());
            node(&mut b, "fifo", tar::EntryType::Fifo, (0, 0));
            node(&mut b, "null", tar::EntryType::Char, (1, 3));
            node(&mut b, "zero", tar::EntryType::Char, (0, 0));
            let tar = b.into_inner().unwrap();
            let opts = ExtractOptions {
                layer: true,
                whiteouts,
                ..Default::default()
            };
            extract(&tar[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
            let m = std::fs::symlink_metadata(d.path().join("fifo")).unwrap();
            assert!(m.file_type().is_fifo(), "{whiteouts:?}");
            assert_eq!(m.permissions().mode() & 0o7777, 0o640);
            assert_eq!(m.mtime(), 1_500_000_000);
            match std::fs::symlink_metadata(d.path().join("null")) {
                Ok(m) => {
                    assert!(m.file_type().is_char_device() && m.rdev() == rustix::fs::makedev(1, 3))
                }
                Err(_) => assert!(!root, "root makes devices"),
            }
            // (a 0:0 device any user may make: the kernel's whiteout)
            let zero = d.path().join("zero").exists();
            match whiteouts {
                Whiteouts::OverlayMarks => assert!(!zero, "a whiteout in an upper"),
                Whiteouts::Remove => assert!(zero || !root, "a device of the layer"),
            }
        }
        // (and a copy of files, not a layer, makes none)
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        node(&mut b, "fifo", tar::EntryType::Fifo, (0, 0));
        let tar = b.into_inner().unwrap();
        extract(
            &tar[..],
            dir_fd(d.path()).as_fd(),
            &ExtractOptions::default(),
        )
        .unwrap();
        assert!(!d.path().join("fifo").exists());
    }

    #[test]
    fn a_layer_into_a_plain_directory_removes_what_its_whiteouts_name() {
        let file = |b: &mut tar::Builder<Vec<u8>>, name: &str, kind, data: &[u8]| {
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(kind);
            h.set_mode(0o755);
            h.set_size(data.len() as u64);
            b.append_data(&mut h, name, data).unwrap();
        };
        let d = tempfile::tempdir().unwrap();
        for p in ["e/gone", "e/kept", "o/a", "o/b", "dd/x/y"] {
            let p = d.path().join(p);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"old").unwrap();
        }
        let mut b = tar::Builder::new(Vec::new());
        file(&mut b, "e/.wh.gone", tar::EntryType::Regular, b"");
        // (a directory is removed with what it holds)
        file(&mut b, ".wh.dd", tar::EntryType::Regular, b"");
        // (the marker first, then what the directory has now)
        file(&mut b, "o/.wh..wh..opq", tar::EntryType::Regular, b"");
        file(&mut b, "o/c", tar::EntryType::Regular, b"new");
        // (a name that is not there)
        file(&mut b, ".wh.nothing", tar::EntryType::Regular, b"");
        let tar = b.into_inner().unwrap();
        let opts = ExtractOptions {
            layer: true,
            whiteouts: Whiteouts::Remove,
            ..Default::default()
        };
        extract(&tar[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        assert!(!d.path().join("e/gone").exists() && d.path().join("e/kept").exists());
        assert!(!d.path().join("dd").exists());
        assert!(!d.path().join("o/a").exists() && !d.path().join("o/b").exists());
        assert_eq!(std::fs::read(d.path().join("o/c")).unwrap(), b"new");
        // no mark is left, and no marker file
        for p in ["e/.wh.gone", "o/.wh..wh..opq", ".wh.dd"] {
            assert!(!d.path().join(p).exists(), "{p}");
        }
    }

    /// The attributes of an entry of a layer: the plain ones are kept, those
    /// of the overlay in any namespace and the label are skipped, and a
    /// name that is only a namespace is an error.
    #[test]
    fn the_xattrs_of_an_entry_of_a_layer_are_judged_by_their_names() {
        let xattrs = |names: &[&str]| {
            let mut b = tar::Builder::new(Vec::new());
            let x: Vec<_> = names
                .iter()
                .map(|n| (format!("SCHILY.xattr.{n}"), &b"v"[..]))
                .collect();
            b.append_pax_extensions(x.iter().map(|(k, v)| (k.as_str(), *v)))
                .unwrap();
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(0);
            b.append_data(&mut h, "f", &b""[..]).unwrap();
            let tar = b.into_inner().unwrap();
            let mut ar = tar::Archive::new(&tar[..]);
            let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
            layer_xattrs(&mut entry)
        };
        let kept = xattrs(&[
            "user.a",
            "security.overlay.x",
            "system.overlay.x",
            "security.selinux",
            "security.selinuxx",
        ])
        .unwrap();
        let names: Vec<_> = kept.iter().map(|(k, _)| &k[..]).collect();
        assert_eq!(names, [&b"user.a"[..], b"security.selinuxx"]);
        let e = xattrs(&["user."]).unwrap_err();
        assert!(e.to_string().contains("invalid xattr name `user.`"), "{e}");
    }

    #[test]
    fn a_layer_gets_the_xattrs_of_its_entries_and_a_copy_does_not() {
        let entry =
            |b: &mut tar::Builder<Vec<u8>>, name: &str, kind, data: &[u8], x: &[(&str, &[u8])]| {
                if !x.is_empty() {
                    b.append_pax_extensions(x.iter().map(|(k, v)| (*k, *v)))
                        .unwrap();
                }
                let mut h = tar::Header::new_ustar();
                h.set_entry_type(kind);
                h.set_mode(0o755);
                h.set_size(data.len() as u64);
                b.append_data(&mut h, name, data).unwrap();
            };
        let mut b = tar::Builder::new(Vec::new());
        entry(
            &mut b,
            "d/",
            tar::EntryType::Directory,
            b"",
            &[("SCHILY.xattr.user.dir", b"1")],
        );
        entry(
            &mut b,
            "d/f",
            tar::EntryType::Regular,
            b"data",
            &[
                ("SCHILY.xattr.user.a", b"va"),
                ("SCHILY.xattr.user.b", b""),
                // (the overlay's own and the label are never set from an archive)
                ("SCHILY.xattr.user.overlay.redirect", b"/x"),
                (
                    "SCHILY.xattr.security.selinux",
                    b"system_u:object_r:etc_t:s0",
                ),
            ],
        );
        let tar = b.into_inner().unwrap();
        let get = |p: &Path, n: &str| {
            let mut v = vec![0u8; 256];
            rustix::fs::lgetxattr(p, n, &mut v)
                .ok()
                .map(|l| v[..l].to_vec())
        };
        let d = tempfile::tempdir().unwrap();
        let probe = d.path().join("probe");
        std::fs::write(&probe, b"").unwrap();
        if rustix::fs::setxattr(&probe, "user.probe", b"1", rustix::fs::XattrFlags::empty())
            .is_err()
        {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let opts = ExtractOptions {
            layer: true,
            overlay_upper: true,
            ..Default::default()
        };
        extract(&tar[..], dir_fd(d.path()).as_fd(), &opts).unwrap();
        let f = d.path().join("d/f");
        assert_eq!(std::fs::read(&f).unwrap(), b"data");
        assert_eq!(get(&f, "user.a").as_deref(), Some(&b"va"[..]));
        assert_eq!(get(&f, "user.b").as_deref(), Some(&b""[..]));
        assert_eq!(get(&f, "user.overlay.redirect"), None);
        assert_eq!(
            get(&d.path().join("d"), "user.dir").as_deref(),
            Some(&b"1"[..])
        );
        // a copy into a container keeps its behaviour: no xattrs
        let c = tempfile::tempdir().unwrap();
        extract(
            &tar[..],
            dir_fd(c.path()).as_fd(),
            &ExtractOptions::default(),
        )
        .unwrap();
        assert_eq!(get(&c.path().join("d/f"), "user.a"), None);
        // a trusted xattr: root sets it, a user may not and is warned, the
        // file is made all the same (as containers-storage's extraction)
        let mut b = tar::Builder::new(Vec::new());
        entry(
            &mut b,
            "g",
            tar::EntryType::Regular,
            b"",
            &[("SCHILY.xattr.trusted.velarx-test", b"1")],
        );
        let tar = b.into_inner().unwrap();
        let t = tempfile::tempdir().unwrap();
        let r = extract(&tar[..], dir_fd(t.path()).as_fd(), &opts);
        if rustix::process::geteuid().is_root() {
            r.unwrap();
            assert_eq!(
                get(&t.path().join("g"), "trusted.velarx-test").as_deref(),
                Some(&b"1"[..])
            );
        } else {
            r.expect("a trusted xattr a user may not set is left out");
            assert!(t.path().join("g").is_file());
        }
    }
}
