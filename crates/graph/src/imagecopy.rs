// SPDX-License-Identifier: Apache-2.0
//! The content of an image read from the images of its layers and the file
//! store, for the volumes of a container whose root file system is not mounted
//! in the daemon (the monitor mounts it when the container starts).
//!
//! The owners are what the file system of the container shows: the owner of
//! the image translated by the user namespace.

use base64::Engine;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Timespec, Timestamps};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;
use velarx_base::walk::{open_dir_path, Cursor};
use velarx_fuse::view::{ImageTree, ViewNode};
use velarx_fuse::{IdTranslate, LazyFileFetcher};
use velarx_proto::pod::IdMapping;
use velarx_storage::{ObjectOpener, TocEntry, TocEntryType, VerityMode};

/// How deep the tree and the chain of links may go.
const MAX_DEPTH: usize = 512;
const MAX_LINKS: usize = 40;

/// A directory of the image, as `first_use` needs to know it.
pub struct DirInfo {
    /// the owner as the container's file system shows it (ids of the daemon's
    /// namespace)
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub empty: bool,
}

/// Where the content of the image is read from.
pub trait ImageSource {
    /// The directory `target` of the image, links followed inside the image.
    fn dir(&self, target: &str) -> io::Result<Option<DirInfo>>;
    /// Copy the content of that directory into `dst`.
    fn copy_into(
        &self,
        target: &str,
        dst: &OwnedFd,
        undo: Option<(&[IdMapping], &[IdMapping])>,
    ) -> io::Result<()>;
}

pub struct TreeSource<'a> {
    pub tree: &'a dyn ImageTree,
    /// the digest of each layer, for the lazy fetches
    pub layers: &'a [String],
    /// Where the bytes of the files are read back from: the storage driver
    /// that holds them ([`crate::DriverObjects`]), by the key the table of
    /// contents names them by.
    pub objects: &'a dyn ObjectOpener,
    /// What `[storage] fsverity` asks of the files read from `objects` (the
    /// digest of every file is checked whatever it says: see `checked`).
    pub verity: VerityMode,
    pub fetcher: Option<&'a dyn LazyFileFetcher>,
    pub translate: &'a IdTranslate,
}

fn err(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

impl TreeSource<'_> {
    /// The node at `path`, links followed inside the image.
    fn resolve(&self, path: &str) -> Option<usize> {
        let mut todo: Vec<String> = path
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .map(str::to_string)
            .rev()
            .collect();
        let mut cur = 0usize;
        // the directories on the way, for ".."
        let mut stack: Vec<usize> = Vec::new();
        let mut links = 0;
        while let Some(c) = todo.pop() {
            if c == ".." {
                cur = stack.pop().unwrap_or(0);
                continue;
            }
            let next = self.tree.lookup(cur, &c)?;
            let node = self.tree.node(next)?;
            if node.entry.entry_type == TocEntryType::Symlink {
                links += 1;
                if links > MAX_LINKS {
                    return None;
                }
                let target = node.entry.link_name.as_deref()?;
                if target.starts_with('/') {
                    cur = 0;
                    stack.clear();
                }
                todo.extend(
                    target
                        .split('/')
                        .filter(|c| !c.is_empty() && *c != ".")
                        .map(str::to_string)
                        .rev(),
                );
                continue;
            }
            stack.push(cur);
            cur = next;
        }
        Some(cur)
    }

    /// The content of the file `path` of the image, at most `limit` bytes.
    pub fn read_file(&self, path: &str, limit: u64) -> io::Result<Option<Vec<u8>>> {
        use std::io::Read;
        let Some(node) = self.resolve(path).and_then(|n| self.tree.node(n)) else {
            return Ok(None);
        };
        if !matches!(
            node.entry.entry_type,
            TocEntryType::Reg | TocEntryType::Chunk | TocEntryType::Hardlink
        ) {
            return Ok(None);
        }
        if node.entry.size == 0 {
            return Ok(Some(Vec::new()));
        }
        let mut buf = Vec::new();
        self.content(&node)?.take(limit).read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    fn ids(&self, e: &TocEntry, raw: bool) -> io::Result<(u32, u32)> {
        if raw {
            return Ok((e.uid, e.gid));
        }
        let (u, g) = (self.translate.uid_of(e.uid), self.translate.gid_of(e.gid));
        if u == IdTranslate::NOBODY || g == IdTranslate::NOBODY {
            return Err(io::Error::other(format!(
                "the owner {}:{} of {} has no id in the user namespace",
                e.uid, e.gid, e.name
            )));
        }
        Ok((u, g))
    }

    pub(crate) fn content(&self, node: &ViewNode) -> io::Result<File> {
        // (a tree over a mount opens its files: they have no digest)
        if let Some(file) = self.tree.open_content(node) {
            return file;
        }
        let Some(digest) = node.entry.verity() else {
            return Err(io::Error::other(format!(
                "{} has no content",
                node.entry.name
            )));
        };
        match self.objects.object_file(&digest, node.entry.size) {
            Ok(file) => {
                self.checked(&digest, &file, true)?;
                self.named(&digest, &file)?;
                return Ok(file);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let Some(fetcher) = self.fetcher else {
            return Err(io::Error::other(format!(
                "the file {digest} is not in the store"
            )));
        };
        let layer = self.layers.get(node.layer).cloned().unwrap_or_default();
        let path = fetcher
            .fetch_file_blocking(&digest, &layer, Some(fetch_limit(node.entry.size)))
            .map_err(io::Error::other)?;
        let file = File::open(path)?;
        self.checked(&digest, &file, false)?;
        Ok(file)
    }

    /// Err(EIO) when `file`, the content `digest`, lacks the fs-verity
    /// digest the store's mode asks of it (the check the overlay or the
    /// FUSE server makes when a container reads the file): `[storage]
    /// fsverity` checks the files of a store that has fs-verity, as the
    /// overlay of a container (`verity=on`), `fsverity_require` every file.
    /// The kernel gives the digest of an open file in constant time.
    fn checked(&self, digest: &str, file: &File, stored: bool) -> io::Result<()> {
        use velarx_storage::VerityMode;
        let mode = match self.verity {
            VerityMode::On if !self.tree.has_verity() => return Ok(()),
            VerityMode::Off => return Ok(()),
            mode => mode,
        };
        velarx_fuse::verity::Verity::new(Default::default(), mode)
            .check(digest, file, stored)
            .map_err(io::Error::from_raw_os_error)
    }
}

impl TreeSource<'_> {
    /// Err when the bytes of `file`, which came from the driver, are not the
    /// content its key `digest` names, whatever `[storage] fsverity` says: a
    /// driver is trusted to store, not to be right, and a file that is
    /// copied out of an image or read for `cp` is not checked by a container's
    /// overlay.  A file that has fs-verity is measured by the kernel in
    /// constant time; a file that has none is read and hashed (the digest it
    /// is named by is the fs-verity digest of its content).
    fn named(&self, digest: &str, file: &File) -> io::Result<()> {
        use std::io::Seek;
        let bad = |found: &str| {
            io::Error::from_raw_os_error({
                tracing::error!(
                    "{digest} of the store is not read: its content has the fs-verity digest {found}"
                );
                libc::EIO
            })
        };
        let Ok(key) = velarx_types::digest::Digest::parse_fsverity(digest) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("`{digest}` is no fs-verity digest"),
            ));
        };
        // (a digest of other parameters than the names of the objects, as
        // on a file system of blocks smaller than 4096 bytes, says nothing
        // of the name: the content is hashed below)
        let canonical = velarx_storage::canonical_digest(file, key.alg());
        if let Some(Ok(m)) = canonical.then(|| velarx_storage::measure_file(file)) {
            if let Some(found) = m.object() {
                return match found == key {
                    true => Ok(()),
                    false => Err(bad(&found.to_string())),
                };
            }
        }
        let found = velarx_storage::fsverity_digest_file(key.alg(), file)?;
        // (what reads the file next starts where it likes, not where the
        // hash stopped)
        let mut f = file;
        f.rewind()?;
        match found == digest {
            true => Ok(()),
            false => Err(bad(&found)),
        }
    }
}

/// The most a fetch of a file of `size` bytes may take (the fetch ends when
/// the file is there or a fetcher gives up; this only bounds the wait):
/// a minute, and a second for each MiB, so that a big file is not given up
/// on at a fixed time while it comes.
fn fetch_limit(size: u64) -> Duration {
    Duration::from_secs(60 + size / (1 << 20))
}

pub fn mtime(e: &TocEntry) -> Timespec {
    let (secs, nsec) = e.mtime();
    Timespec {
        tv_sec: secs,
        tv_nsec: nsec.into(),
    }
}

fn set_times(dir: BorrowedFd<'_>, name: &OsStr, e: &TocEntry) -> io::Result<()> {
    let t = mtime(e);
    let ts = Timestamps {
        last_access: t,
        last_modification: t,
    };
    fs::utimensat(dir, name, &ts, AtFlags::SYMLINK_NOFOLLOW).map_err(err)
}

/// Set the extended attribute `name` of `file`, the copy of `shown`, after its
/// owner (a chown clears `security.capability`).  A file system without
/// attributes of that kind (EOPNOTSUPP) has none to keep; an attribute this
/// process may not set (EPERM: a `trusted.` attribute, or a `security.` one
/// other than the capability, in a user namespace) is not data of the image
/// it can copy: it is not set and the result says so (false), for the caller
/// to say once.  Any other failure is an error naming the file.
pub fn set_copied_xattr(
    file: &File,
    name: &OsStr,
    value: &[u8],
    shown: &dyn std::fmt::Display,
) -> io::Result<bool> {
    use xattr::FileExt;
    match file.set_xattr(name, value) {
        Ok(()) => Ok(true),
        Err(x) if x.raw_os_error() == Some(libc::EOPNOTSUPP) => Ok(true),
        Err(x) if x.raw_os_error() == Some(libc::EPERM) => Ok(false),
        Err(x) => Err(io::Error::new(
            x.kind(),
            format!(
                "the attribute {} of {shown} cannot be set: {x}",
                name.to_string_lossy()
            ),
        )),
    }
}

/// The attributes a copy may not set ([`set_copied_xattr`]): said once, with
/// the first of them.
#[derive(Default)]
pub struct RefusedXattrs {
    first: Option<String>,
    count: usize,
}

impl RefusedXattrs {
    /// `name` of `shown` was not set.
    pub fn add(&mut self, name: &OsStr, shown: &dyn std::fmt::Display) {
        self.count += 1;
        if self.first.is_none() {
            self.first = Some(format!("{} of {shown}", name.to_string_lossy()));
        }
    }

    /// Say what was not set, if anything.
    pub fn report(&self) {
        if let Some(first) = &self.first {
            tracing::warn!(
                "copy into a volume: {} extended attributes are not set, this process may not set them (the first: {first})",
                self.count
            );
        }
    }
}

/// The extended attributes of the entry, set after its owner
/// ([`set_copied_xattr`]).
fn set_xattrs(file: &File, e: &TocEntry, refused: &mut RefusedXattrs) -> io::Result<()> {
    for (name, value) in &e.xattrs {
        if name.starts_with("trusted.overlay.")
            || name.starts_with("user.overlay.")
            || name.starts_with("security.selinux")
        {
            continue;
        }
        let v = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|x| {
                io::Error::other(format!(
                    "the attribute {name} of {} is not base64: {x}",
                    e.name
                ))
            })?;
        let name = OsStr::new(name.as_str());
        if !set_copied_xattr(file, name, &v, &e.name)? {
            refused.add(name, &e.name);
        }
    }
    Ok(())
}

fn chown_at(dir: BorrowedFd<'_>, name: &OsStr, ids: (u32, u32)) -> io::Result<()> {
    if ids.0 == u32::MAX || ids.1 == u32::MAX {
        return Err(io::Error::other("not a valid owner"));
    }
    fs::chownat(
        dir,
        name,
        Some(fs::Uid::from_raw(ids.0)),
        Some(fs::Gid::from_raw(ids.1)),
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .map_err(err)
}

struct Walk<'a> {
    src: &'a TreeSource<'a>,
    raw: bool,
    /// The files with several names, by key: the path of the first name made
    /// (from the root), not a descriptor kept for each.
    links: HashMap<(usize, u64), PathBuf>,
    /// the attributes this process may not set
    refused: RefusedXattrs,
}

impl Walk<'_> {
    /// Write the tree below `node` into the directory `root`: an explicit
    /// stack and a [`Cursor`] on the destination, a few descriptors
    /// whatever the depth.
    fn dir(&mut self, node: usize, root: &OwnedFd) -> io::Result<()> {
        struct Frame {
            id: usize,
            names: std::vec::IntoIter<(String, usize)>,
        }
        let mut cur = Cursor::new(root.try_clone()?)?;
        let mut stack = vec![Frame {
            id: node,
            names: self.src.tree.children(node)?.into_iter(),
        }];
        while let Some(top) = stack.last_mut() {
            let Some((name, child)) = top.names.next() else {
                let Some(done) = stack.pop() else { break };
                if stack.is_empty() {
                    break;
                }
                let (dname, fd) = cur.ascend()?;
                if let Some(c) = self.src.tree.node(done.id) {
                    let e = &c.entry;
                    let ids = self.src.ids(e, self.raw)?;
                    let f = File::from(fd);
                    chown_at(cur.fd(), &dname, ids)?;
                    fs::fchmod(&f, Mode::from_raw_mode(e.mode & 0o7777)).map_err(err)?;
                    set_xattrs(&f, e, &mut self.refused)?;
                    set_times(cur.fd(), &dname, e)?;
                }
                continue;
            };
            let Some(c) = self.src.tree.node(child) else {
                continue;
            };
            let dst = cur.fd();
            let e = &c.entry;
            let oname = OsStr::new(name.as_str());
            let ids = self.src.ids(e, self.raw)?;
            let mode = Mode::from_raw_mode(e.mode & 0o7777);
            match e.entry_type {
                TocEntryType::Dir => {
                    if cur.depth() >= MAX_DEPTH {
                        return Err(velarx_base::walk::too_deep(MAX_DEPTH));
                    }
                    fs::mkdirat(dst, oname, Mode::from_raw_mode(0o700)).map_err(err)?;
                    cur.descend(oname, None)?;
                    stack.push(Frame {
                        id: child,
                        names: self.src.tree.children(child)?.into_iter(),
                    });
                }
                TocEntryType::Reg | TocEntryType::Chunk | TocEntryType::Hardlink => {
                    if c.nlink > 1 {
                        if let Some(first) = self.links.get(&c.key) {
                            let (Some(parent), Some(fname)) = (first.parent(), first.file_name())
                            else {
                                return Err(io::Error::other("a link without a name"));
                            };
                            let parts: Vec<OsString> =
                                parent.iter().map(OsStr::to_os_string).collect();
                            let d = open_dir_path(root.as_fd(), &parts)?;
                            fs::linkat(&d, fname, dst, oname, AtFlags::empty()).map_err(err)?;
                            continue;
                        }
                    }
                    let to = fs::openat(
                        dst,
                        oname,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )
                    .map_err(err)?;
                    let to = File::from(to);
                    if e.size > 0 {
                        velarx_storage::copy_file(
                            &self.src.content(&c)?,
                            &to,
                            u64::MAX,
                            || Ok(()),
                        )?;
                    }
                    chown_at(dst, oname, ids)?;
                    fs::fchmod(&to, mode).map_err(err)?;
                    set_xattrs(&to, e, &mut self.refused)?;
                    set_times(dst, oname, e)?;
                    if c.nlink > 1 {
                        let mut p: PathBuf = cur.path().iter().collect();
                        p.push(oname);
                        self.links.insert(c.key, p);
                    }
                }
                TocEntryType::Symlink => {
                    let target = e.link_name.as_deref().unwrap_or("");
                    fs::symlinkat(target, dst, oname).map_err(err)?;
                    chown_at(dst, oname, ids)?;
                    set_times(dst, oname, e)?;
                }
                TocEntryType::Fifo | TocEntryType::Char | TocEntryType::Block => {
                    let (kind, dev) = match e.entry_type {
                        TocEntryType::Fifo => (FileType::Fifo, 0),
                        TocEntryType::Char => (
                            FileType::CharacterDevice,
                            libc::makedev(e.dev_major.unwrap_or(0), e.dev_minor.unwrap_or(0)),
                        ),
                        _ => (
                            FileType::BlockDevice,
                            libc::makedev(e.dev_major.unwrap_or(0), e.dev_minor.unwrap_or(0)),
                        ),
                    };
                    match fs::mknodat(dst, oname, kind, mode, dev) {
                        Ok(()) => {
                            chown_at(dst, oname, ids)?;
                            set_times(dst, oname, e)?;
                        }
                        // Devices need privileges: they are not data.
                        Err(rustix::io::Errno::PERM | rustix::io::Errno::ACCESS)
                            if kind != FileType::Fifo => {}
                        Err(x) => return Err(err(x)),
                    }
                }
            }
        }
        Ok(())
    }
}

impl ImageSource for TreeSource<'_> {
    fn dir(&self, target: &str) -> io::Result<Option<DirInfo>> {
        let Some(node) = self.resolve(target).and_then(|n| self.tree.node(n)) else {
            return Ok(None);
        };
        if node.entry.entry_type != TocEntryType::Dir {
            return Ok(None);
        }
        let (uid, gid) = self.ids(&node.entry, false)?;
        Ok(Some(DirInfo {
            uid,
            gid,
            mode: node.entry.mode & 0o7777,
            empty: match self.resolve(target) {
                Some(n) => self.tree.children(n)?.is_empty(),
                None => true,
            },
        }))
    }

    fn copy_into(
        &self,
        target: &str,
        dst: &OwnedFd,
        undo: Option<(&[IdMapping], &[IdMapping])>,
    ) -> io::Result<()> {
        let Some(node) = self.resolve(target) else {
            return Ok(());
        };
        // For an idmapped volume the ids stay those of the container.
        let mut w = Walk {
            src: self,
            raw: undo.is_some(),
            links: HashMap::new(),
            refused: RefusedXattrs::default(),
        };
        let r = w.dir(node, dst);
        w.refused.report();
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The user's entries come from /etc/passwd and /etc/group of the image
    /// read through its mount: links are followed inside it, and a FIFO, a
    /// link out of it or a file larger than the limit gives no more than
    /// nothing or the limit.
    #[test]
    fn a_hostile_image_gives_its_files_inside_the_limits() {
        use std::os::unix::fs::symlink;
        let (image, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let root = image.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::write(outside.path().join("secret"), "host\n").unwrap();
        std::fs::write(root.join("usr/lib/passwd"), "root:x:0:0::/:/bin/sh\n").unwrap();
        symlink("/usr/lib/passwd", root.join("etc/passwd")).unwrap();
        symlink(outside.path().join("secret"), root.join("etc/group")).unwrap();
        symlink(
            "../../../../../../../../proc/self/environ",
            root.join("etc/hosts"),
        )
        .unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.join("etc/shadow"),
            rustix::fs::Mode::RUSR,
        )
        .unwrap();
        let big = std::fs::File::create(root.join("etc/big")).unwrap();
        big.set_len(64 << 20).unwrap();
        let fd = fs::open(
            root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let tree = velarx_fuse::MountedImage::new(fd).unwrap();
        struct NoObjects;
        impl ObjectOpener for NoObjects {
            fn object_file(&self, _: &str, _: u64) -> io::Result<File> {
                Err(io::Error::other(
                    "no objects: the files are read from the mount",
                ))
            }
        }
        let translate = IdTranslate::default();
        let source = TreeSource {
            tree: &tree,
            layers: &[],
            objects: &NoObjects,
            verity: VerityMode::Off,
            fetcher: None,
            translate: &translate,
        };
        // a link inside the image is followed
        assert_eq!(
            source.read_file("etc/passwd", 1 << 20).unwrap().unwrap(),
            b"root:x:0:0::/:/bin/sh\n"
        );
        // a link to a path of the host, or of /proc, is nothing
        assert!(source.read_file("etc/group", 1 << 20).unwrap().is_none());
        assert!(source.read_file("etc/hosts", 1 << 20).unwrap().is_none());
        // a FIFO is not read (and does not hang)
        assert!(source.read_file("etc/shadow", 1 << 20).unwrap().is_none());
        // a big file is read up to the limit asked
        assert_eq!(
            source.read_file("etc/big", 4097).unwrap().unwrap().len(),
            4097
        );
        assert!(source.read_file("etc/nothing", 10).unwrap().is_none());
    }

    /// A file capability survives the copy of an image into a volume: the
    /// owner is set before the attributes, as a chown clears it.  (Run in a
    /// user namespace of its own, where the capability can be set.)
    #[test]
    fn a_file_capability_survives_the_copy_into_a_volume() {
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
            let (image, volume) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let file = image.path().join("ping");
            std::fs::write(&file, "x").unwrap();
            let name = c"security.capability";
            rustix::fs::setxattr(&file, name, CAP, rustix::fs::XattrFlags::empty()).unwrap();
            let want = xattr::get(&file, "security.capability").unwrap().unwrap();
            let open = |p: &std::path::Path| {
                fs::open(
                    p,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap()
            };
            let tree = velarx_fuse::MountedImage::new(open(image.path())).unwrap();
            struct NoObjects;
            impl ObjectOpener for NoObjects {
                fn object_file(&self, _: &str, _: u64) -> io::Result<File> {
                    Err(io::Error::other(
                        "no objects: the files are read from the mount",
                    ))
                }
            }
            let translate = IdTranslate::default();
            let source = TreeSource {
                tree: &tree,
                layers: &[],
                objects: &NoObjects,
                verity: VerityMode::Off,
                fetcher: None,
                translate: &translate,
            };
            source
                .copy_into("", &open(volume.path()), Some((&[], &[])))
                .unwrap();
            let got = xattr::get(volume.path().join("ping"), "security.capability").unwrap();
            assert_eq!(
                got.as_deref(),
                Some(&want[..]),
                "the capability of the copy"
            );
        });
    }

    /// An attribute this process may not set is left out and said (false), one
    /// it may is set, and any other failure is an error naming the file.  (In a
    /// user namespace of its own, where `trusted.` attributes are refused.)
    #[test]
    fn an_attribute_the_process_may_not_set_is_left_out() {
        velarx_base::testing::in_child(|| {
            if let Err(e) = velarx_sys::namespace::unshare_user_mapped_to_root(
                rustix::thread::UnshareFlags::empty(),
            ) {
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let f = File::create(dir.path().join("f")).unwrap();
            let set = |name: &str, value: &[u8]| {
                set_copied_xattr(&f, OsStr::new(name), value, &"f".to_string())
            };
            assert!(set("user.velarx", b"v").unwrap());
            assert!(!set("trusted.velarx", b"v").unwrap());
            // (larger than an attribute may be: E2BIG)
            let e = set("user.big", &vec![0u8; 1 << 17]).unwrap_err();
            assert!(e.to_string().contains("user.big of f"), "{e}");
        });
    }

    #[test]
    fn the_wait_for_a_fetch_grows_with_the_file() {
        assert_eq!(fetch_limit(0), Duration::from_secs(60));
        assert_eq!(fetch_limit(10 << 30), Duration::from_secs(60 + 10 * 1024));
    }
}
