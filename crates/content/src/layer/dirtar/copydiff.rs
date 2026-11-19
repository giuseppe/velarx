// SPDX-License-Identifier: Apache-2.0
//! The changes in a directory that is a copy of an image (the layer of a
//! storage driver that copies the layers, `vfs`): the tar stream of a layer,
//! or the list of what was added, changed and deleted, found by comparing the
//! directory with the image it was copied from.
//!
//! There are no marks in such a directory: a file that is not there any more
//! is a `.wh.` entry (a directory other than the root that kept none of the
//! image's entries, and has others, is opaque), and a file is a change when its kind, mode,
//! owner, size, time, link target, device, or the extended attributes that
//! can be set on the copy differ from the image's.  The times of the
//! directories are not compared: a directory changes its own when something
//! is made in it.  What is shared with the walk of an overlay's upper
//! directory is the rest: the ids of the user namespace, hard links, holes,
//! extended attributes, the exclusions, and the tar.

use super::*;
use velarx_fuse::view::VIEW_ROOT;
use velarx_storage::TocEntryType;

/// The id the container sees for an owner of the image: its own, or the
/// root's when the ranges of the container do not cover it (the owners that
/// are not mapped are the root's, as the squashed owners of the copy).
fn visible(id: u32, ranges: &[IdRange]) -> u32 {
    if ranges.is_empty()
        || ranges
            .iter()
            .any(|r| id >= r.container && id - r.container < r.size)
    {
        id
    } else {
        0
    }
}

fn kind_of(t: TocEntryType) -> FileType {
    match t {
        TocEntryType::Dir => FileType::Directory,
        TocEntryType::Symlink => FileType::Symlink,
        TocEntryType::Char => FileType::CharacterDevice,
        TocEntryType::Block => FileType::BlockDevice,
        TocEntryType::Fifo => FileType::Fifo,
        _ => FileType::RegularFile,
    }
}

/// Whether the entry of the copy is the one of the image.
fn same_entry(
    opts: &Options,
    st: &Stat,
    xattrs: &[(Vec<u8>, Vec<u8>)],
    link: Option<&OsStr>,
    node: &velarx_fuse::view::ViewNode,
) -> io::Result<bool> {
    let e = &node.entry;
    let kind = FileType::from_raw_mode(st.st_mode);
    if kind != kind_of(e.entry_type) || (st.st_mode & 0o7777) != (e.mode & 0o7777) {
        return Ok(false);
    }
    if opts.unowned != Some((st.st_uid, st.st_gid)) {
        let (uid, gid) = opts.to_container(st.st_uid, st.st_gid)?;
        if (uid, gid) != (visible(e.uid, &opts.uid_map), visible(e.gid, &opts.gid_map)) {
            return Ok(false);
        }
    }
    match kind {
        FileType::RegularFile => {
            if st.st_size.max(0) as u64 != e.size {
                return Ok(false);
            }
            let (sec, nsec) = e.mtime();
            if (st.st_mtime, st.st_mtime_nsec as u32) != (sec, nsec) {
                return Ok(false);
            }
        }
        FileType::Symlink => {
            if link.map(|l| l.as_bytes()) != e.link_name.as_deref().map(str::as_bytes) {
                return Ok(false);
            }
        }
        FileType::CharacterDevice | FileType::BlockDevice => {
            let rdev = rustix::fs::makedev(
                e.dev_major.unwrap_or_default(),
                e.dev_minor.unwrap_or_default(),
            );
            if st.st_rdev != rdev {
                return Ok(false);
            }
        }
        _ => {}
    }
    // every attribute of the copy is the image's; one of the image's that
    // the copy lacks is a change only for the `user.` ones (the others, the
    // `security.` and `trusted.` ones, may not be settable where the copy
    // was made)
    let image = image_xattrs(e);
    let same = xattrs.iter().all(|x| image.contains(x))
        && image
            .iter()
            .filter(|(k, _)| k.starts_with(b"user."))
            .all(|x| xattrs.contains(x));
    Ok(same)
}

/// A directory of the copy being walked.
struct CopyDir {
    /// its path in the layer (`etc/`, empty for the root)
    prefix: String,
    /// the directory of the image it was copied from, when it has one
    below: Option<usize>,
    /// the names it has, and those of the image's directory
    present: HashSet<String>,
    image: Vec<(String, usize)>,
    /// it hides the image's directory
    opaque: bool,
    /// the place of its header among the pending ones, when it waits for an
    /// entry below it
    deferred: Option<usize>,
}

impl CopyDir {
    fn new(prefix: String, below: Option<usize>) -> Self {
        CopyDir {
            prefix,
            below,
            present: HashSet::new(),
            image: Vec::new(),
            opaque: false,
            deferred: None,
        }
    }

    /// The names of the copy and of the image, when the directory is listed.
    fn list(&mut self, lower: &Lower, names: &[OsString]) -> io::Result<()> {
        for n in names {
            self.present.insert(utf8_name(&self.prefix, n)?);
        }
        if let Some(i) = self.below {
            self.image = lower.tree.children(i)?;
        }
        Ok(())
    }
}

/// The image below a copy: the changes of a copy are against it.
fn lower_of(opts: &Options) -> io::Result<Arc<Lower>> {
    opts.lower
        .clone()
        .ok_or_else(|| io::Error::other("the changes of a copy need the image below it"))
}

/// The walk of a copy as a layer.
struct CopyWalk<'w, 'o> {
    w: &'w mut Walker<'o>,
    lower: Arc<Lower>,
}

impl Visit for CopyWalk<'_, '_> {
    type Dir = CopyDir;

    fn enter(&mut self, _: BorrowedFd<'_>, names: &[OsString], at: &mut CopyDir) -> io::Result<()> {
        at.list(&self.lower, names)?;
        // a directory none of whose entries of the image is still there, and
        // that has others, hides the image's: one entry says it, not one
        // whiteout of each (not the root: a marker there hides nothing)
        at.opaque = !at.prefix.is_empty()
            && !at.image.is_empty()
            && !at.present.is_empty()
            && at.image.iter().all(|(n, _)| !at.present.contains(n));
        if at.opaque {
            self.w.flush_pending()?;
            self.w.whiteout(&at.prefix, ".wh..opq")?;
        }
        Ok(())
    }

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        at: &mut CopyDir,
    ) -> io::Result<Option<CopyDir>> {
        let (lower, prefix, below) = (&self.lower, at.prefix.as_str(), at.below);
        let w = &mut *self.w;
        let name_str = utf8_name(prefix, name)?;
        let shown = format!("{prefix}{name_str}");
        let st = *st;
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind == FileType::Socket || (kind != FileType::Directory && w.opts.excluded(&shown)) {
            return Ok(None);
        }
        if shown.len() + usize::from(kind == FileType::Directory) > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "path too long: `{}...`",
                    &shown[..shown.floor_char_boundary(64)]
                ),
            ));
        }
        let attrs = read_xattrs(dir, name, &shown, false, true)?;
        let (node_idx, node) = match below.and_then(|d| lower.tree.lookup(d, &name_str)) {
            Some(i) => (Some(i), lower.tree.node(i)),
            None => (None, None),
        };
        let same_as = |w: &Walker<'_>, link: Option<&OsStr>| -> io::Result<bool> {
            match &node {
                Some(n) => same_entry(&w.opts, &st, &attrs.xattrs, link, n),
                None => Ok(false),
            }
        };
        match kind {
            FileType::RegularFile => {
                if !same_as(w, None)? {
                    w.regular(dir, name, &shown, &st, &attrs, None)?;
                }
            }
            FileType::Directory => {
                let lower_dir = node_idx.filter(|_| {
                    node.as_ref()
                        .is_some_and(|n| n.entry.entry_type == TocEntryType::Dir)
                });
                let same = lower_dir.is_some() && same_as(w, None)?;
                let mut h = w.header(&st, tar::EntryType::Directory)?;
                let child = format!("{shown}/");
                let deferred = same || (lower_dir.is_none() && w.opts.holds_excluded(&child));
                let mark = w.pending.len();
                if deferred {
                    w.pending.push(Pending {
                        header: h,
                        path: child.clone(),
                        xattrs: attrs.xattrs,
                    });
                } else {
                    w.append(&mut h, &child, &attrs.xattrs, Content::None)?;
                }
                let mut sub = CopyDir::new(child, lower_dir);
                sub.deferred = deferred.then_some(mark);
                return Ok(Some(sub));
            }
            FileType::Symlink => {
                let target = readlinkat(dir, name, Vec::new()).map_err(errno)?;
                let target = OsString::from_vec(target.into_bytes());
                if !same_as(w, Some(&target))? {
                    let mut h = w.header(&st, tar::EntryType::Symlink)?;
                    w.append_link(&mut h, &shown, &attrs.xattrs, &target)?;
                }
            }
            FileType::CharacterDevice | FileType::BlockDevice | FileType::Fifo => {
                if same_as(w, None)? {
                    return Ok(None);
                }
                let t = match kind {
                    FileType::CharacterDevice => tar::EntryType::Char,
                    FileType::BlockDevice => tar::EntryType::Block,
                    _ => tar::EntryType::Fifo,
                };
                let mut h = w.header(&st, t)?;
                if kind != FileType::Fifo {
                    h.set_device_major(rustix::fs::major(st.st_rdev))?;
                    h.set_device_minor(rustix::fs::minor(st.st_rdev))?;
                }
                w.append(&mut h, &shown, &attrs.xattrs, Content::None)?;
            }
            _ => {}
        }
        Ok(None)
    }

    fn exit(&mut self, _: BorrowedFd<'_>, at: &mut CopyDir) -> io::Result<()> {
        if !at.opaque {
            for (name, _) in &at.image {
                if !at.present.contains(name) {
                    self.w.whiteout(&at.prefix, name)?;
                }
            }
        }
        if let Some(mark) = at.deferred {
            self.w.pending.truncate(mark);
        }
        Ok(())
    }
}

/// Write the changes of the copy `dir` against `opts.lower` (the image it was
/// copied from) as a tar stream to `out`: the holes of the files are holes of
/// the stream.
pub fn write<W: HoleWrite>(dir: BorrowedFd<'_>, opts: &Options, out: W) -> io::Result<()> {
    let mut tar = TarOut {
        builder: tar::Builder::new(out),
    };
    let lower = lower_of(opts)?;
    let mut w = walker(&mut tar, opts);
    let root = CopyDir::new(String::new(), Some(VIEW_ROOT));
    WALK.run(
        dir.try_clone_to_owned()?,
        root,
        &mut CopyWalk { w: &mut w, lower },
    )?;
    tar.builder.into_inner()?.flush()
}

/// A directory of the copy in the list of changes.
struct ChangedDir {
    dir: CopyDir,
    /// something below it is a change
    any: bool,
    /// its place in the list
    at: usize,
    /// it is a directory of the image, and the same
    quiet: bool,
}

/// The walk of the list of changes of a copy.
struct CopyChanges<'a> {
    opts: &'a Options,
    lower: Arc<Lower>,
    out: Vec<(String, Change)>,
}

impl Visit for CopyChanges<'_> {
    type Dir = ChangedDir;

    fn enter(
        &mut self,
        _: BorrowedFd<'_>,
        names: &[OsString],
        at: &mut ChangedDir,
    ) -> io::Result<()> {
        at.dir.list(&self.lower, names)
    }

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &OsStr,
        st: &Stat,
        _: usize,
        parent: &mut ChangedDir,
    ) -> io::Result<Option<ChangedDir>> {
        let (opts, lower) = (self.opts, &self.lower);
        let (prefix, below) = (parent.dir.prefix.as_str(), parent.dir.below);
        let name_str = utf8_name(prefix, name)?;
        let path = format!("{prefix}{name_str}");
        let kind = FileType::from_raw_mode(st.st_mode);
        if kind == FileType::Socket || (kind != FileType::Directory && opts.excluded(&path)) {
            return Ok(None);
        }
        let attrs = read_xattrs(dir, name, &path, false, true)?;
        let (node_idx, node) = match below.and_then(|d| lower.tree.lookup(d, &name_str)) {
            Some(i) => (Some(i), lower.tree.node(i)),
            None => (None, None),
        };
        let link = (kind == FileType::Symlink)
            .then(|| readlinkat(dir, name, Vec::new()).map_err(errno))
            .transpose()?
            .map(|t| OsString::from_vec(t.into_bytes()));
        let same = match &node {
            Some(n) => same_entry(opts, st, &attrs.xattrs, link.as_deref(), n)?,
            None => false,
        };
        let change = if node.is_some() {
            Change::Modified
        } else {
            Change::Added
        };
        if kind != FileType::Directory {
            if !same {
                self.out.push((format!("/{path}"), change));
                parent.any = true;
            }
            return Ok(None);
        }
        let lower_dir = node_idx.filter(|_| {
            node.as_ref()
                .is_some_and(|n| n.entry.entry_type == TocEntryType::Dir)
        });
        let at = self.out.len();
        self.out.push((format!("/{path}"), change));
        let child = format!("{path}/");
        // a directory is listed when it changed itself or holds a change
        // (not one that only holds the engine's files)
        let quiet =
            (lower_dir.is_some() && same) || (lower_dir.is_none() && opts.holds_excluded(&child));
        Ok(Some(ChangedDir {
            dir: CopyDir::new(child, lower_dir),
            any: false,
            at,
            quiet,
        }))
    }

    fn exit(&mut self, _: BorrowedFd<'_>, at: &mut ChangedDir) -> io::Result<()> {
        for (name, _) in &at.dir.image {
            if !at.dir.present.contains(name) {
                self.out
                    .push((format!("/{}{name}", at.dir.prefix), Change::Deleted));
                at.any = true;
            }
        }
        Ok(())
    }

    fn leave(
        &mut self,
        _: BorrowedFd<'_>,
        parent: &mut ChangedDir,
        _: &OsStr,
        _: OwnedFd,
        at: ChangedDir,
    ) -> io::Result<()> {
        if !at.any && at.quiet {
            self.out.remove(at.at);
        } else {
            parent.any = true;
        }
        Ok(())
    }
}

/// The changes of the copy `dir` against `opts.lower`, sorted by path
/// (`/etc/motd`).
pub fn changes(dir: BorrowedFd<'_>, opts: &Options) -> io::Result<Vec<(String, Change)>> {
    let mut walk = CopyChanges {
        opts,
        lower: lower_of(opts)?,
        out: Vec::new(),
    };
    let root = ChangedDir {
        dir: CopyDir::new(String::new(), Some(VIEW_ROOT)),
        any: false,
        at: 0,
        quiet: false,
    };
    WALK.run(dir.try_clone_to_owned()?, root, &mut walk)?;
    let mut out = walk.out;
    // (the parents first, the names of a directory in order)
    out.sort_by(|a, b| a.0.split('/').cmp(b.0.split('/')));
    Ok(out)
}
