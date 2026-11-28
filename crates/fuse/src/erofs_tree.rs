// SPDX-License-Identifier: Apache-2.0
//! The tree the FUSE file system serves: the EROFS images of the layers of
//! an image (`layer_erofs`), each read where it is mapped (the page cache's
//! pages, nothing built at the start: the inodes, the directories and the
//! attributes are found in the image when they are asked).  The root of the
//! file system has a directory per layer, `layer1` the lowest, which the
//! overlay of the container has as its lower layers; and, when the store
//! lacks files of the image, the data-only layer `data`: the files of the
//! layers by their digest, from the indexes of the layers (`Index`).
//!
//! The images are those the kernel mounts as root: an overlay mounted in a
//! user namespace (`userxattr`) reads its attributes as `user.overlay.*`,
//! which the attributes `trusted.overlay.*` of the images are served as.
//! The layers are metadata only: the regular files are stubs that redirect
//! to the data-only layers of the store, which the overlay opens itself to
//! read them, also to copy a file up.  The kernel opens a stub here only to
//! copy a file up: for its inode flags (`FS_IOC_GETFLAGS`, which this file
//! system does not have), not for its content.  An overlay of a user
//! namespace that follows the stubs of its lowest layer only (`Stubs`) has
//! the regular files of the layers above served whole here, their content
//! read from the store; with the digests enforced each is opened and
//! measured as the kernel would (`verity::Verity`, `enforced`).  A regular
//! file that an image holds itself (`layer_erofs::Inline`) is read from the
//! image file, at the place its inode gives, not through the mapping: an
//! error of the file system of the image (NFS) fails that read, where a
//! fault in the mapping would end the server.

use super::erofs_read::xattrs;
use super::tree::{Attr, FileRef, Tree};
use composefs::erofs::format::DataLayout;
use composefs::erofs::format::{
    FileType as ErofsFileType, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG,
    S_IFSOCK,
};
use composefs::erofs::reader::{DirectoryBlock, Image, InodeHeader, InodeOps, InodeType};
use fuser::FileType;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};
use velarx_overlay_core::major_minor;
use velarx_storage::FsVerityHashAlgorithm;
use velarx_types::digest::{Algorithm, Digest};
use zerocopy::FromBytes as _;

const MAGIC: &[u8; 8] = b"SHIDX002";
/// The magic and the byte of the fs-verity hash of the digests of the index:
/// a layer has the digests of one algorithm.
const HEADER: usize = MAGIC.len() + 1;
/// A size and the layer, after the digest (32 or 64 bytes).
const RECORD_TAIL: usize = 8 + 4;

/// The bytes of an image or of an index: mapped, or read.
pub type Bytes = Box<dyn AsRef<[u8]> + Send + Sync>;

/// The image or index at `path`, mapped: opened as the monitor opens the
/// images it mounts (`composefs::open_layer_image`, a name that is no
/// symlink).
pub fn map_file(path: &Path) -> io::Result<Bytes> {
    let file = crate::composefs::open_layer_image(path)?;
    Ok(Box::new(velarx_sys::mmap::map_file(&file)?))
}

/// The files of a layer, by digest, with their size.  Sorted and fixed in
/// size, so that it is searched where it is mapped.  The digests are those of
/// one algorithm, the one of the layer: its records are 44 bytes long for
/// SHA-256 and 76 for SHA-512.
pub struct Index {
    bytes: Bytes,
    alg: Algorithm,
}

/// The index of these files (digest, size, layer) with the digests of `alg`:
/// the first layer of a digest is kept.
pub fn write_index(alg: Algorithm, files: impl IntoIterator<Item = (Digest, u64, u32)>) -> Vec<u8> {
    let mut files: Vec<(Digest, u64, u32)> = files.into_iter().collect();
    // (the caller refuses a layer of files of both algorithms: a digest of
    // the other would be a file the data-only layer cannot find)
    debug_assert!(files
        .iter()
        .all(|(d, _, _)| d.alg() == alg && d.is_fsverity()));
    files.retain(|(d, _, _)| d.alg() == alg);
    files.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
    files.dedup_by(|b, a| a.0 == b.0);
    let record = alg.len() + RECORD_TAIL;
    let mut out = Vec::with_capacity(HEADER + files.len() * record);
    out.extend_from_slice(MAGIC);
    out.push(FsVerityHashAlgorithm::of(alg) as u8);
    for (d, size, layer) in files {
        out.extend_from_slice(d.raw());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&layer.to_le_bytes());
    }
    out
}

impl Index {
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::from_bytes(map_file(path)?)
    }

    /// The index in the open file `file`, mapped.
    pub fn open_file(file: &std::fs::File) -> io::Result<Self> {
        Self::from_bytes(Box::new(velarx_sys::mmap::map_file(file)?))
    }

    pub fn from_bytes(data: Bytes) -> io::Result<Self> {
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
        let b = (*data).as_ref();
        if !b.starts_with(MAGIC) || b.len() < HEADER {
            return Err(invalid("not the index of an image"));
        }
        let alg = match b[MAGIC.len()] {
            x if x == FsVerityHashAlgorithm::Sha256 as u8 => Algorithm::Sha256,
            x if x == FsVerityHashAlgorithm::Sha512 as u8 => Algorithm::Sha512,
            _ => return Err(invalid("the index of an image has an unknown hash")),
        };
        if !(b.len() - HEADER).is_multiple_of(alg.len() + RECORD_TAIL) {
            return Err(invalid("not the index of an image"));
        }
        Ok(Self { bytes: data, alg })
    }

    fn bytes(&self) -> &[u8] {
        (*self.bytes).as_ref()
    }

    /// The algorithm of the digests of its files.
    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    fn record(&self) -> usize {
        self.alg.len() + RECORD_TAIL
    }

    pub fn count(&self) -> usize {
        (self.bytes().len() - HEADER) / self.record()
    }

    /// Every file: its digest (`fsverity-<alg>-12:HEX`, the name of its
    /// object) and its size.
    pub fn files(&self) -> impl Iterator<Item = (String, u64)> + '_ {
        (0..self.count()).map(|i| {
            let (d, size) = self.at(i);
            (d.to_string(), size)
        })
    }

    fn at(&self, i: usize) -> (Digest, u64) {
        let n = self.alg.len();
        let r = &self.bytes()[HEADER + i * self.record()..][..self.record()];
        (
            Digest::fsverity(self.alg, &r[..n]).expect("a record has the digest of its algorithm"),
            u64::from_le_bytes(r[n..n + 8].try_into().unwrap()),
        )
    }

    /// The position of the first record whose digest is not below `key`.
    fn lower_bound(&self, key: &[u8]) -> usize {
        let (mut lo, mut hi) = (0, self.count());
        while lo < hi {
            let mid = (lo + hi) / 2;
            let r = &self.bytes()[HEADER + mid * self.record()..][..self.alg.len()];
            if r < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// The position of the file with this digest: none for the digest of
    /// the other algorithm, never the file of the same bytes.
    pub fn find(&self, digest: &Digest) -> Option<usize> {
        if digest.alg() != self.alg || !digest.is_fsverity() {
            return None;
        }
        let i = self.lower_bound(digest.raw());
        (i < self.count() && self.at(i).0 == *digest).then_some(i)
    }

    /// The records whose digest starts with the byte `b`.
    fn prefix(&self, b: u8) -> std::ops::Range<usize> {
        let lo = self.lower_bound(&[b]);
        let hi = if b == 255 {
            self.count()
        } else {
            self.lower_bound(&[b + 1])
        };
        lo..hi
    }
}

/// (a time past what the system can say, which only a corrupt image has,
/// is the epoch: never a panic of the thread that serves the kernel)
fn epoch(secs: u64, nsec: u32) -> SystemTime {
    // (the seconds are a signed number: a time before 1970 is kept)
    let secs = secs as i64;
    let at = if secs < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    } else {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    };
    at.and_then(|t| t.checked_add(Duration::from_nanos(u64::from(nsec.min(999_999_999)))))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// The kind of the node whose mode is `mode`; none for a type no file has.
fn kind_of(mode: u16) -> Option<FileType> {
    Some(match mode & S_IFMT {
        S_IFDIR => FileType::Directory,
        S_IFLNK => FileType::Symlink,
        S_IFCHR => FileType::CharDevice,
        S_IFBLK => FileType::BlockDevice,
        S_IFIFO => FileType::NamedPipe,
        S_IFSOCK => FileType::Socket,
        S_IFREG => FileType::RegularFile,
        _ => return None,
    })
}

/// A damaged image: what the kernel answers is an I/O error.
fn damaged(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("damaged image: {what}"))
}

fn plain_dir(perm: u16) -> Attr {
    Attr {
        kind: FileType::Directory,
        perm,
        nlink: 2,
        uid: 0,
        gid: 0,
        size: 0,
        rdev: 0,
        mtime: SystemTime::UNIX_EPOCH,
        atime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
    }
}

/// The image of one layer, mapped.  Its nodes are known by their nid.
pub struct Layer {
    bytes: Bytes,
    /// The image file that is mapped, when it is one: the content of the
    /// files the image holds is read from it (`read_held`).
    file: Option<std::fs::File>,
    root: u64,
    inos: u64,
}

/// The blocks of entries of a directory: those in blocks, then the one
/// after the inode.
fn dir_blocks<'a>(img: &'a Image, inode: &'a InodeType) -> Option<Vec<&'a DirectoryBlock>> {
    let mut out = Vec::new();
    for b in img.inode_blocks(inode).ok()? {
        out.push(img.directory_block(b).ok()?);
    }
    if let Some(inline) = inode.inline() {
        if let Ok(block) = DirectoryBlock::ref_from_bytes(inline) {
            out.push(block);
        }
    }
    Some(out)
}

impl Layer {
    pub fn open(bytes: Bytes) -> Result<Self, String> {
        let image = Image::open((*bytes).as_ref()).map_err(|e| e.to_string())?;
        if image.sb.blkszbits != 12 {
            return Err("not an image of 4096 bytes blocks".into());
        }
        let (root, inos) = (image.sb.root_nid.get() as u64, image.sb.inos.get());
        image
            .inode(root)
            .map_err(|e| format!("the root of the image: {e}"))?;
        Ok(Self {
            bytes,
            file: None,
            root,
            inos,
        })
    }

    /// The image at `path`, mapped.
    pub fn map(path: &Path) -> io::Result<Self> {
        let file = crate::composefs::open_layer_image(path)?;
        let map = velarx_sys::mmap::map_file(&file)?;
        let layer = Self::open(Box::new(map)).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        Ok(Self {
            file: Some(file),
            ..layer
        })
    }

    /// The image `file` (of `path`, for the errors), opened and checked by
    /// the caller (`composefs::open_checked_layer_image`), as the FUSE file
    /// system serves it: mapped from that descriptor, so that everything of
    /// the layer (superblock, inodes, directories, attributes, links) is read
    /// from that mapping, never from its path.
    pub fn of_checked_file(file: std::fs::File, path: &Path) -> io::Result<Self> {
        let map = velarx_sys::mmap::map_file(&file)?;
        let layer = Self::open(Box::new(map)).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the EROFS image {}: {e}", path.display()),
            )
        })?;
        Ok(Self {
            file: Some(file),
            ..layer
        })
    }

    fn image(&self) -> Image<'_> {
        // (checked when it was opened: a header is read, nothing more)
        Image::open((*self.bytes).as_ref()).expect("an image that opened")
    }

    pub fn root(&self) -> u64 {
        self.root
    }

    /// The number of its inodes.
    pub fn inodes(&self) -> u64 {
        self.inos
    }

    pub fn mode(&self, nid: u64) -> Option<u16> {
        let img = self.image();
        let inode = img.inode(nid).ok()?;
        Some(inode.mode().0.get())
    }

    pub fn is_dir(&self, nid: u64) -> bool {
        self.mode(nid).is_some_and(|m| m & S_IFMT == S_IFDIR)
    }

    /// A character device 0:0: what the overlay takes for a removed name.
    pub fn is_whiteout(&self, nid: u64) -> bool {
        let img = self.image();
        img.inode(nid)
            .is_ok_and(|i| i.mode().0.get() & S_IFMT == S_IFCHR && i.u() == 0)
    }

    /// A directory that hides those of the layers below.
    pub fn is_opaque(&self, nid: u64) -> bool {
        self.raw_xattrs(nid)
            .iter()
            .any(|(n, v)| n == super::layer_erofs::XATTR_OPAQUE.as_bytes() && v == b"y")
    }

    /// The nid of `name` in the directory `dir`.
    pub fn lookup(&self, dir: u64, name: &[u8]) -> Option<u64> {
        if name == b"." || name == b".." {
            return None;
        }
        self.entry(dir, name)
    }

    /// The nid of the directory `..` of the directory `dir`: the one that
    /// holds it, in an image the generator made (a directory reached from
    /// another is not under it in a corrupt image, whose directories may
    /// loop).
    pub fn parent(&self, dir: u64) -> Option<u64> {
        self.entry(dir, b"..")
    }

    fn entry(&self, dir: u64, name: &[u8]) -> Option<u64> {
        let img = self.image();
        let dir = img.inode(dir).ok()?;
        if dir.mode().0.get() & S_IFMT != S_IFDIR {
            return None;
        }
        let blocks = dir_blocks(&img, &dir)?;
        // the names are sorted: the block is the last that starts at or
        // before the name
        let first = |b: &DirectoryBlock| -> Option<Vec<u8>> {
            Some(b.entries().ok()?.next()?.ok()?.name.to_vec())
        };
        let mut lo = 0;
        let mut hi = blocks.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            match first(blocks[mid]) {
                Some(f) if f.as_slice() <= name => lo = mid + 1,
                _ => hi = mid,
            }
        }
        let block = blocks.get(lo.checked_sub(1)?)?;
        block
            .entries()
            .ok()?
            .flatten()
            .find(|e| e.name == name)
            .map(|e| e.nid())
    }

    pub fn attr(&self, nid: u64) -> Option<Attr> {
        let img = self.image();
        let inode = img.inode(nid).ok()?;
        let mode = inode.mode().0.get();
        let (uid, gid, mtime, nsec) = match &inode {
            InodeType::Extended(i) => (
                i.header.uid.get(),
                i.header.gid.get(),
                i.header.mtime.get(),
                i.header.mtime_nsec.get(),
            ),
            InodeType::Compact(i) => (
                u32::from(i.header.uid.get()),
                u32::from(i.header.gid.get()),
                img.sb.build_time.get(),
                0,
            ),
        };
        let kind = kind_of(mode)?;
        // (a directory's is the size of its entries, as the kernel says)
        let size = inode.size();
        let rdev = match kind {
            FileType::CharDevice | FileType::BlockDevice => {
                let (major, minor) = major_minor(inode.u());
                libc::makedev(major, minor) as u32
            }
            _ => 0,
        };
        let time = epoch(mtime, nsec);
        Some(Attr {
            kind,
            perm: mode & 0o7777,
            nlink: inode.nlink(),
            uid,
            gid,
            size,
            rdev,
            mtime: time,
            atime: time,
            ctime: time,
        })
    }

    /// The target of the link `nid`; an error when the image does not have
    /// it whole.
    pub fn readlink(&self, nid: u64) -> io::Result<Vec<u8>> {
        let img = self.image();
        let inode = img.inode(nid).map_err(|e| damaged(&e.to_string()))?;
        if inode.mode().0.get() & S_IFMT != S_IFLNK {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        if let Some(inline) = inode.inline() {
            return Ok(inline.to_vec());
        }
        // (a long target is in a block)
        let first = img
            .inode_blocks(&inode)
            .map_err(|e| damaged(&e.to_string()))?
            .next()
            .ok_or_else(|| damaged("a link without a target"))?;
        let block = img.block(first).map_err(|e| damaged(&e.to_string()))?;
        Ok(block[..(inode.size() as usize).min(block.len())].to_vec())
    }

    /// The content of the regular file `nid` that the image holds itself:
    /// its place in the image, in the block after its inode (a file under a
    /// block) or in blocks of its own.  None for a stub, and for a file
    /// that is not where its inode says it is.
    fn held_range(&self, nid: u64) -> Option<std::ops::Range<usize>> {
        let img = self.image();
        let inode = img.inode(nid).ok()?;
        if inode.mode().0.get() & S_IFMT != S_IFREG {
            return None;
        }
        let size = usize::try_from(inode.size()).ok()?;
        let start = match inode.data_layout().ok()? {
            DataLayout::FlatPlain => {
                usize::try_from(img.inode_blocks(&inode).ok()?.start).ok()? * img.block_size
            }
            DataLayout::FlatInline if size < img.block_size => {
                let tail = inode.inline()?;
                tail.as_ptr() as usize - img.image.as_ptr() as usize
            }
            _ => return None,
        };
        let end = start.checked_add(size)?;
        (end <= img.image.len()).then_some(start..end)
    }

    /// At most `len` bytes from `offset` of the file `nid` the image holds
    /// itself (none past its end): read from the image file when there is
    /// one, so that an error of its file system is the error of the read,
    /// else from the bytes of the image.  None for a stub, and for a file
    /// that is not where its inode says it is.
    pub fn read_held(&self, nid: u64, offset: u64, len: usize) -> Option<io::Result<Vec<u8>>> {
        let range = self.held_range(nid)?;
        let skip = usize::try_from(offset).map_or(range.len(), |o| o.min(range.len()));
        let start = range.start + skip;
        let end = start + len.min(range.end - start);
        Some(match &self.file {
            Some(file) => {
                use std::os::unix::fs::FileExt;
                let mut buf = vec![0; end - start];
                file.read_exact_at(&mut buf, start as u64).map(|()| buf)
            }
            None => Ok((*self.bytes).as_ref()[start..end].to_vec()),
        })
    }

    /// The content of the file `nid` the image holds itself, as a file of
    /// its own with no name, in memory: for what reads a file whole by its
    /// content, there being no digest to read it back by (the view of an
    /// image).  None for a stub, and for a file that is not where its inode
    /// says it is.
    pub fn open_held(&self, nid: u64) -> Option<io::Result<std::fs::File>> {
        let range = self.held_range(nid)?;
        let copy = || {
            use std::os::unix::fs::FileExt;
            let flags = rustix::fs::MemfdFlags::CLOEXEC;
            let copy = std::fs::File::from(rustix::fs::memfd_create("velarx-held", flags)?);
            let len = range.len() as u64;
            match &self.file {
                Some(file) => {
                    velarx_storage::copy_region(file, range.start as u64, &copy, 0, len, || Ok(()))?
                }
                None => copy.write_all_at(&(*self.bytes).as_ref()[range.clone()], 0)?,
            }
            Ok(copy)
        };
        Some(copy())
    }

    /// The digest of the file of the store a stub redirects to, and its size.
    pub fn content(&self, nid: u64) -> Option<(Option<String>, u64)> {
        let img = self.image();
        let inode = img.inode(nid).ok()?;
        if inode.mode().0.get() & S_IFMT != S_IFREG {
            return None;
        }
        let attrs = xattrs(&img, &inode);
        let get = |name: &str| {
            attrs
                .iter()
                .find(|(n, _)| n == name.as_bytes())
                .map(|(_, v)| v)
        };
        // The file of the stub is the one its redirect names, which must be
        // the one whose digest the stub states (`metacopy`, the digest the
        // kernel compares with the file it follows the redirect to): a stub
        // that says two things, or states no digest, names no file.
        let digest = get(super::layer_erofs::XATTR_REDIRECT)
            .and_then(|v| super::erofs_read::redirect_digest(v))
            .filter(|named| {
                get(super::layer_erofs::XATTR_METACOPY)
                    .and_then(|v| super::erofs_read::metacopy_digest(v))
                    .is_some_and(|stated| stated == *named)
            });
        Some((digest, inode.size()))
    }

    /// The attributes of a node as the image has them.
    pub fn raw_xattrs(&self, nid: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let img = self.image();
        match img.inode(nid) {
            Ok(inode) => xattrs(&img, &inode),
            Err(_) => Vec::new(),
        }
    }

    /// The entries of a directory but the first `skip` (`.` and `..` are
    /// not entries), in order, until `f` (the nid, the kind, the name) says
    /// it is enough.  An error when `nid` is not a directory or the image
    /// does not have its entries whole.
    pub fn readdir(
        &self,
        nid: u64,
        skip: usize,
        f: &mut dyn FnMut(u64, FileType, &[u8]) -> bool,
    ) -> io::Result<()> {
        let img = self.image();
        let dir = img.inode(nid).map_err(|e| damaged(&e.to_string()))?;
        if dir.mode().0.get() & S_IFMT != S_IFDIR {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let mut seen = 0;
        for block in dir_blocks(&img, &dir).ok_or_else(|| damaged("a directory block"))? {
            for e in block.entries().map_err(|e| damaged(&e.to_string()))? {
                let e = e.map_err(|e| damaged(&e.to_string()))?;
                if e.name == b"." || e.name == b".." {
                    continue;
                }
                if seen < skip {
                    seen += 1;
                    continue;
                }
                let kind = match ErofsFileType::from(e.header.file_type) {
                    ErofsFileType::Directory => FileType::Directory,
                    ErofsFileType::CharacterDevice => FileType::CharDevice,
                    ErofsFileType::BlockDevice => FileType::BlockDevice,
                    ErofsFileType::Fifo => FileType::NamedPipe,
                    ErofsFileType::Socket => FileType::Socket,
                    ErofsFileType::Symlink => FileType::Symlink,
                    ErofsFileType::RegularFile => FileType::RegularFile,
                    ErofsFileType::Unknown => return Err(damaged("an entry of unknown type")),
                };
                if f(e.nid(), kind, e.name) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// The inode of the root of the file system and of the directory of the
/// data-only layer; the nodes of the layer `i` are `(i + 1) << LAYER_SHIFT`
/// and their nid; the directories of the data-only layer (the first byte of
/// a digest) and its files are above `DATA_DIR_BASE` and `DATA_FILE_BASE`.
const ROOT: u64 = 1;
const DATA: u64 = 2;
const LAYER_SHIFT: u32 = 40;
const DATA_DIR_BASE: u64 = 1 << 62;
const DATA_FILE_BASE: u64 = 1 << 63;

/// The directory of the layer `i` (0 the lowest) in the root of the file
/// system: `layer1` is the lowest.
pub fn layer_dir(i: usize) -> String {
    format!("layer{}", i + 1)
}

/// The directory of the data-only layer in the root of the file system.
pub const DATA_DIR: &str = "data";

/// The layers whose stubs the overlay of a user namespace (`userxattr`)
/// follows into the data-only layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stubs {
    /// Every layer's.
    Every,
    /// The lowest layer's only: a stub of a layer above is refused (EPERM).
    /// The regular files of the layers above are served whole, without the
    /// attributes of a stub.
    Lowest,
}

/// The layers of an image, served by FUSE.
pub struct Layers {
    layers: Vec<Layer>,
    /// The indexes of the files of the layers, for the data-only layer.
    indexes: Option<Vec<Index>>,
    /// The overlay's attributes are `user.overlay.*`.
    userxattr: bool,
    /// Which stubs the overlay follows (with `userxattr`).
    stubs: Stubs,
}

/// The attributes of a stub, the overlay's (their suffix after `overlay.`).
fn stub_xattr(rest: &str) -> bool {
    matches!(rest, "metacopy" | "redirect")
}

impl Layers {
    pub fn new(
        layers: Vec<Layer>,
        indexes: Option<Vec<Index>>,
        userxattr: bool,
        stubs: Stubs,
    ) -> Self {
        Self {
            layers,
            indexes,
            userxattr,
            stubs,
        }
    }

    fn split(&self, ino: u64) -> Option<(usize, u64)> {
        if ino >= DATA_DIR_BASE || ino >> LAYER_SHIFT == 0 {
            return None;
        }
        let i = (ino >> LAYER_SHIFT) as usize - 1;
        let nid = ino & ((1 << LAYER_SHIFT) - 1);
        self.layers.get(i).map(|_| (i, nid))
    }

    fn ino(i: usize, nid: u64) -> u64 {
        ((i as u64 + 1) << LAYER_SHIFT) | nid
    }

    fn data_file(&self, ino: u64) -> Option<(usize, usize)> {
        let rest = ino.checked_sub(DATA_FILE_BASE)?;
        let (layer, i) = (
            (rest >> LAYER_SHIFT) as usize,
            (rest & ((1 << LAYER_SHIFT) - 1)) as usize,
        );
        let index = self.indexes.as_ref()?.get(layer)?;
        (i < index.count()).then_some((layer, i))
    }

    /// The digests that start with `b`, in order, each with the first layer
    /// that has it and its position in that index.
    fn data_files(&self, b: u8) -> Vec<(Digest, usize, usize)> {
        let Some(indexes) = &self.indexes else {
            return Vec::new();
        };
        let mut out: Vec<(Digest, usize, usize)> = Vec::new();
        for (l, index) in indexes.iter().enumerate() {
            for i in index.prefix(b) {
                out.push((index.at(i).0, l, i));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out.dedup_by(|b, a| a.0 == b.0);
        out
    }
}

impl Tree for Layers {
    fn len(&self) -> u64 {
        self.layers.iter().map(Layer::inodes).sum::<u64>() + 2
    }

    fn lookup(&self, parent: u64, name: &str) -> Option<u64> {
        match parent {
            ROOT => {
                if name == DATA_DIR && self.indexes.is_some() {
                    return Some(DATA);
                }
                let n: usize = name.strip_prefix("layer")?.parse().ok()?;
                let layer = self.layers.get(n.checked_sub(1)?)?;
                (layer_dir(n - 1) == name).then(|| Self::ino(n - 1, layer.root()))
            }
            DATA => {
                let b = u8::from_str_radix(name, 16)
                    .ok()
                    .filter(|_| name.len() == 2)?;
                (!self.data_files(b).is_empty()).then_some(DATA_DIR_BASE + u64::from(b))
            }
            d if (DATA_DIR_BASE..DATA_FILE_BASE).contains(&d) => {
                let b = (d - DATA_DIR_BASE) as u8;
                // (62 digits after the directory name a SHA-256 object, 126 a
                // SHA-512 one: a name of the other length finds nothing)
                let rest = hex::decode(name).ok()?;
                let alg = Algorithm::ALL
                    .into_iter()
                    .find(|a| a.len() == rest.len() + 1)?;
                let mut raw = vec![b];
                raw.extend_from_slice(&rest);
                let digest = Digest::fsverity(alg, &raw).ok()?;
                let indexes = self.indexes.as_ref()?;
                indexes.iter().enumerate().find_map(|(l, index)| {
                    let i = index.find(&digest)?;
                    Some(DATA_FILE_BASE + ((l as u64) << LAYER_SHIFT) + i as u64)
                })
            }
            _ => {
                let (i, nid) = self.split(parent)?;
                let child = self.layers[i].lookup(nid, name.as_bytes())?;
                Some(Self::ino(i, child))
            }
        }
    }

    fn attr(&self, ino: u64) -> Option<Attr> {
        match ino {
            ROOT => Some(plain_dir(0o755)),
            DATA if self.indexes.is_some() => Some(plain_dir(0o755)),
            d if (DATA_DIR_BASE..DATA_FILE_BASE).contains(&d) => Some(plain_dir(0o755)),
            f if f >= DATA_FILE_BASE => {
                let (l, i) = self.data_file(f)?;
                let size = self.indexes.as_ref()?[l].at(i).1;
                Some(Attr {
                    kind: FileType::RegularFile,
                    perm: 0o444,
                    nlink: 1,
                    size,
                    ..plain_dir(0o444)
                })
            }
            _ => {
                let (i, nid) = self.split(ino)?;
                self.layers[i].attr(nid)
            }
        }
    }

    fn readlink(&self, ino: u64) -> io::Result<Vec<u8>> {
        let (i, nid) = self
            .split(ino)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        self.layers[i].readlink(nid)
    }

    fn file(&self, ino: u64) -> Option<FileRef> {
        if ino >= DATA_FILE_BASE {
            let (l, i) = self.data_file(ino)?;
            let (digest, size) = self.indexes.as_ref()?[l].at(i);
            return Some(FileRef {
                digest: Some(digest.to_string()),
                size,
                layer: l,
                inline: false,
            });
        }
        let (i, nid) = self.split(ino)?;
        let (digest, size) = self.layers[i].content(nid)?;
        Some(FileRef {
            digest,
            size,
            layer: i,
            inline: self.layers[i].held_range(nid).is_some(),
        })
    }

    fn read_held(&self, ino: u64, offset: u64, len: usize) -> Option<io::Result<Vec<u8>>> {
        let (i, nid) = self.split(ino)?;
        self.layers[i].read_held(nid, offset, len)
    }

    fn readdir(
        &self,
        ino: u64,
        skip: usize,
        f: &mut dyn FnMut(u64, FileType, &[u8]) -> bool,
    ) -> io::Result<()> {
        let not_a_directory = || io::Error::from_raw_os_error(libc::ENOTDIR);
        match ino {
            ROOT => {
                let names = (0..self.layers.len())
                    .map(|i| (layer_dir(i), Self::ino(i, self.layers[i].root())))
                    .chain(self.indexes.is_some().then(|| (DATA_DIR.to_string(), DATA)));
                for (name, i) in names.skip(skip) {
                    if f(i, FileType::Directory, name.as_bytes()) {
                        break;
                    }
                }
                Ok(())
            }
            DATA => {
                self.indexes.as_ref().ok_or_else(not_a_directory)?;
                let present = (0..=255u8).filter(|b| !self.data_files(*b).is_empty());
                for b in present.skip(skip) {
                    if f(
                        DATA_DIR_BASE + u64::from(b),
                        FileType::Directory,
                        format!("{b:02x}").as_bytes(),
                    ) {
                        break;
                    }
                }
                Ok(())
            }
            d if (DATA_DIR_BASE..DATA_FILE_BASE).contains(&d) => {
                for (digest, l, i) in self
                    .data_files((d - DATA_DIR_BASE) as u8)
                    .into_iter()
                    .skip(skip)
                {
                    let ino = DATA_FILE_BASE + ((l as u64) << LAYER_SHIFT) + i as u64;
                    if f(
                        ino,
                        FileType::RegularFile,
                        hex::encode(&digest.raw()[1..]).as_bytes(),
                    ) {
                        break;
                    }
                }
                Ok(())
            }
            f_ino if f_ino >= DATA_FILE_BASE => Err(not_a_directory()),
            _ => {
                let (i, nid) = self.split(ino).ok_or_else(not_a_directory)?;
                self.layers[i].readdir(nid, skip, &mut |child, kind, name| {
                    f(Self::ino(i, child), kind, name)
                })
            }
        }
    }

    fn xattrs(&self, ino: u64) -> Option<Vec<(String, Vec<u8>)>> {
        let Some((i, nid)) = self.split(ino) else {
            return self.attr(ino).map(|_| Vec::new());
        };
        let mut out = Vec::new();
        for (name, value) in self.layers[i].raw_xattrs(nid) {
            let Ok(name) = String::from_utf8(name) else {
                continue;
            };
            // the overlay's attributes in the namespace of its mount, those
            // the generator writes only (an image that has others, or
            // `user.overlay.*`, is not one it made: they would steer the
            // overlay); the labels are the engine's
            let name = match name.strip_prefix("trusted.overlay.") {
                Some(rest) if !stub_xattr(rest) && rest != "opaque" => continue,
                Some(rest)
                    if self.userxattr
                        && i > 0
                        && self.stubs == Stubs::Lowest
                        && stub_xattr(rest) =>
                {
                    continue
                }
                Some(rest) if self.userxattr => format!("user.overlay.{rest}"),
                Some(_) => name,
                None if super::image_fs::hidden_xattr(&name) => continue,
                None => name,
            };
            out.push((name, value));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer_erofs::layer_image;
    use std::collections::HashMap;
    use velarx_storage::{TocEntry, TocEntryType};

    #[test]
    fn a_socket_is_a_socket_and_an_unknown_type_is_none() {
        assert_eq!(kind_of(S_IFSOCK | 0o755), Some(FileType::Socket));
        assert_eq!(kind_of(S_IFREG | 0o644), Some(FileType::RegularFile));
        assert_eq!(kind_of(0o644), None);
        assert_eq!(kind_of(0o030000), None);
    }

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        let mut e = crate::dir_entry(name);
        e.entry_type = t;
        e.mode = if t == TocEntryType::Dir { 0o755 } else { 0o644 };
        e.mod_time = Some("2024-01-02T03:04:05+00:00".into());
        e
    }

    fn file(name: &str, byte: u8, size: u64) -> TocEntry {
        let mut e = entry(name, TocEntryType::Reg);
        (e.size, e.fsverity) = (
            size,
            velarx_storage::to_toc(&format!(
                "fsverity-sha256-12:{}",
                format!("{byte:02x}").repeat(32)
            )),
        );
        e
    }

    fn mapped(entries: &[TocEntry]) -> (Layer, Index) {
        let built = layer_image(entries).unwrap();
        (
            Layer::open(Box::new(built.image)).unwrap(),
            Index::from_bytes(Box::new(built.index)).unwrap(),
        )
    }

    /// A time before 1970 is in the image as it is in the table: seconds
    /// before the epoch and the nanoseconds after them.
    #[test]
    fn a_time_before_1970_is_kept_by_the_image() {
        let mut old = entry("old", TocEntryType::Dir);
        old.mod_time = Some("1969-12-30T23:59:59.25+00:00".into());
        let mut recent = entry("recent", TocEntryType::Dir);
        recent.mod_time = Some("1970-01-01T00:00:01.5+00:00".into());
        let mut first = entry("first", TocEntryType::Dir);
        first.mod_time = Some("0001-01-01T00:00:00Z".into());
        let mut last = entry("last", TocEntryType::Dir);
        last.mod_time = Some("9999-12-31T23:59:59.999999999Z".into());
        let (layer, _) = mapped(&[old, recent, first, last]);
        let at = |name: &str| layer.attr(layer.lookup(layer.root(), name.as_bytes()).unwrap());
        let since = |t: SystemTime| match t.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_secs_f64(),
            Err(e) => -e.duration().as_secs_f64(),
        };
        assert_eq!(since(at("old").unwrap().mtime), -86400.75);
        assert_eq!(since(at("recent").unwrap().mtime), 1.5);
        let parts = |name: &str| crate::tree::unix_parts(at(name).unwrap().mtime);
        assert_eq!(parts("old"), (-86401, 250_000_000));
        assert_eq!(parts("first"), (-62_135_596_800, 0));
        assert_eq!(parts("last"), (253_402_300_799, 999_999_999));
    }

    /// A stub names the file of its redirect only when its metacopy states
    /// that digest (the one the kernel's overlay compares with): another
    /// digest, or one of another algorithm, names no file.
    #[test]
    fn a_stub_names_its_file_only_when_its_metacopy_states_the_same_digest() {
        let stub = |patch: &dyn Fn(&mut Vec<u8>)| {
            let mut image = layer_image(&[file("f", 0xab, 5)]).unwrap().image;
            patch(&mut image);
            let layer = Layer::open(Box::new(image)).unwrap();
            let f = layer.lookup(layer.root(), b"f").unwrap();
            layer.content(f).unwrap()
        };
        let named = format!("fsverity-sha256-12:{}", "ab".repeat(32));
        assert_eq!(stub(&|_| {}), (Some(named), 5));
        let at = |image: &[u8]| {
            let mut mc = vec![0u8, 36, 0, 1];
            mc.extend_from_slice(&[0xab; 32]);
            image.windows(mc.len()).position(|w| w == mc).unwrap()
        };
        let other_digest = |image: &mut Vec<u8>| {
            let i = at(image);
            image[i + 4] = 0xac;
        };
        let other_algorithm = |image: &mut Vec<u8>| {
            let i = at(image);
            image[i + 3] = 2;
        };
        assert_eq!(stub(&other_digest), (None, 5));
        assert_eq!(stub(&other_algorithm), (None, 5));
    }

    /// Where the overlay follows the stubs of its lowest layer only, the
    /// files of the layers above are served whole: no stub attributes, the
    /// size and the content (the file reference) are the same.
    #[test]
    fn the_files_of_the_layers_above_are_whole_where_only_the_lowest_stubs_are_followed() {
        for (stubs, above) in [(Stubs::Every, true), (Stubs::Lowest, false)] {
            let (l0, i0) = mapped(&[entry("usr", TocEntryType::Dir), file("usr/f", 1, 5)]);
            let (l1, i1) = mapped(&[file("usr/h", 0xab, 5)]);
            let tree = Layers::new(vec![l0, l1], Some(vec![i0, i1]), true, stubs);
            let at = |layer: &str, name: &str| {
                let usr = tree
                    .lookup(tree.lookup(ROOT, layer).unwrap(), "usr")
                    .unwrap();
                tree.lookup(usr, name).unwrap()
            };
            let names = |ino| -> Vec<String> {
                tree.xattrs(ino).unwrap().into_iter().map(|x| x.0).collect()
            };
            // the lowest layer's stub is the same in both
            let f = at("layer1", "f");
            assert!(names(f).contains(&"user.overlay.redirect".to_string()));
            let h = at("layer2", "h");
            let upper = names(h);
            assert_eq!(
                upper.contains(&"user.overlay.redirect".to_string()),
                above,
                "{stubs:?} {upper:?}"
            );
            assert_eq!(upper.contains(&"user.overlay.metacopy".to_string()), above);
            let r = tree.file(h).unwrap();
            assert_eq!((r.size, r.layer), (5, 1));
            assert_eq!(
                r.digest.unwrap(),
                format!("fsverity-sha256-12:{}", "ab".repeat(32))
            );
        }
    }

    fn file512(name: &str, byte: u8, size: u64) -> TocEntry {
        let mut e = entry(name, TocEntryType::Reg);
        (e.size, e.fsverity) = (
            size,
            velarx_storage::to_toc(&format!(
                "fsverity-sha512-12:{}",
                format!("{byte:02x}").repeat(64)
            )),
        );
        e
    }

    /// A layer of SHA-512 digests has stubs of 64-byte digests (metacopy of
    /// 4 + 64 bytes, algorithm byte 2, the redirect of 126 digits) and an
    /// index of its own algorithm; the data-only layer lists the files of
    /// both kinds of layers side by side, each under the name of its length,
    /// and the digest of one algorithm never finds the file of the other.
    #[test]
    fn a_layer_of_sha512_digests_and_one_of_sha256_share_the_data_layer() {
        let (l0, i0) = mapped(&[entry("usr", TocEntryType::Dir), file("usr/a", 0xab, 5)]);
        let (l1, i1) = mapped(&[entry("usr", TocEntryType::Dir), file512("usr/b", 0xab, 7)]);
        assert_eq!((i0.alg(), i1.alg()), (Algorithm::Sha256, Algorithm::Sha512));
        let tree = Layers::new(vec![l0, l1], Some(vec![i0, i1]), true, Stubs::Every);
        let at = |layer: &str, name: &str| {
            let usr = tree
                .lookup(tree.lookup(ROOT, layer).unwrap(), "usr")
                .unwrap();
            tree.lookup(usr, name).unwrap()
        };
        let b = at("layer2", "b");
        let x: HashMap<_, _> = tree.xattrs(b).unwrap().into_iter().collect();
        assert_eq!(
            x["user.overlay.redirect"],
            format!("/ab/{}", "ab".repeat(63)).into_bytes()
        );
        let mc = &x["user.overlay.metacopy"];
        assert_eq!((&mc[..4], mc.len()), (&[0u8, 68, 0, 2][..], 68));
        assert_eq!(&mc[4..], &[0xabu8; 64][..]);
        let r = tree.file(b).unwrap();
        assert_eq!(
            r.digest.unwrap(),
            format!("fsverity-sha512-12:{}", "ab".repeat(64))
        );
        // both are in the directory `ab` of the data, under their own names
        let ab = tree.lookup(DATA, "ab").unwrap();
        let mut names = Vec::new();
        tree.readdir(ab, 0, &mut |_, _, n| {
            names.push(String::from_utf8_lossy(n).into_owned());
            false
        })
        .unwrap();
        assert_eq!(names, ["ab".repeat(31), "ab".repeat(63)]);
        let small = tree.lookup(ab, &"ab".repeat(31)).unwrap();
        let big = tree.lookup(ab, &"ab".repeat(63)).unwrap();
        assert_ne!(small, big);
        assert_eq!(tree.attr(small).unwrap().size, 5);
        assert_eq!(tree.attr(big).unwrap().size, 7);
        // a name of the length of neither is no file
        assert!(tree.lookup(ab, &"ab".repeat(40)).is_none());
        // a SHA-256 digest does not find the SHA-512 index, nor the reverse
        let i512 = mapped(&[file512("f", 0xab, 7)]).1;
        let d256 = Digest::fsverity(Algorithm::Sha256, &[0xab; 32]).unwrap();
        let d512 = Digest::fsverity(Algorithm::Sha512, &[0xab; 64]).unwrap();
        assert!(i512.find(&d256).is_none() && i512.find(&d512).is_some());
        // a layer with both kinds of digests is refused
        let mixed = layer_image(&[file("a", 1, 1), file512("b", 2, 1)]);
        assert!(mixed.err().unwrap().contains("two algorithms"));
    }

    #[test]
    fn the_root_has_a_directory_per_layer_and_the_data() {
        let mut dev = entry("dev/null", TocEntryType::Char);
        (dev.dev_major, dev.dev_minor) = (Some(1), Some(3));
        let (l0, i0) = mapped(&[
            entry("usr", TocEntryType::Dir),
            file("usr/f", 1, 5),
            file("usr/g", 0xab, 5),
            dev,
        ]);
        let (l1, i1) = mapped(&[
            entry("usr/.wh.f", TocEntryType::Reg),
            file("usr/h", 0xab, 5),
            file("usr/i", 0xff, 1),
        ]);
        let tree = Layers::new(vec![l0, l1], Some(vec![i0, i1]), true, Stubs::Every);
        let mut names = Vec::new();
        tree.readdir(ROOT, 0, &mut |_, _, n| {
            names.push(String::from_utf8_lossy(n).into_owned());
            false
        })
        .unwrap();
        assert_eq!(names, ["layer1", "layer2", "data"]);
        assert!(tree.lookup(ROOT, "layer3").is_none() && tree.lookup(ROOT, "layer01").is_none());
        let usr1 = tree
            .lookup(tree.lookup(ROOT, "layer1").unwrap(), "usr")
            .unwrap();
        let usr2 = tree
            .lookup(tree.lookup(ROOT, "layer2").unwrap(), "usr")
            .unwrap();
        assert_ne!(usr1, usr2);
        // the whiteout of the upper layer
        let wh = tree.lookup(usr2, "f").unwrap();
        let a = tree.attr(wh).unwrap();
        assert_eq!((a.kind, a.rdev), (FileType::CharDevice, 0));
        // a stub: its attributes as the overlay of a user namespace reads them
        let f = tree.lookup(usr1, "f").unwrap();
        let x: HashMap<_, _> = tree.xattrs(f).unwrap().into_iter().collect();
        assert_eq!(
            x["user.overlay.redirect"],
            format!("/01/{}", "01".repeat(31)).into_bytes()
        );
        // (struct ovl_metacopy: version 0, length, flags 0, SHA-256, then the
        // digest the overlay checks with `verity=`)
        let mc = &x["user.overlay.metacopy"];
        assert_eq!((&mc[..4], mc.len()), (&[0u8, 36, 0, 1][..], 36));
        assert_eq!(&mc[4..], &[1u8; 32][..]);
        assert!(!x.keys().any(|k| k.starts_with("trusted.")));
        // a stub of a layer above the lowest has them too
        let h = tree.lookup(usr2, "h").unwrap();
        let x: HashMap<_, _> = tree.xattrs(h).unwrap().into_iter().collect();
        assert_eq!(
            x["user.overlay.redirect"],
            format!("/ab/{}", "ab".repeat(31)).into_bytes()
        );
        assert_eq!(&x["user.overlay.metacopy"][4..], &[0xabu8; 32][..]);
        assert_eq!(tree.file(h).unwrap().size, 5);
        let r = tree.file(f).unwrap();
        assert_eq!((r.size, r.layer), (5, 0));
        assert_eq!(
            r.digest.unwrap(),
            format!("fsverity-sha256-12:{}", "01".repeat(32))
        );
        assert_eq!(tree.file(tree.lookup(usr2, "i").unwrap()).unwrap().layer, 1);
        // the data-only layer: the files of both layers, each once
        let mut dirs = Vec::new();
        tree.readdir(DATA, 0, &mut |_, _, n| {
            dirs.push(String::from_utf8_lossy(n).into_owned());
            false
        })
        .unwrap();
        assert_eq!(dirs, ["01", "ab", "ff"]);
        let ab = tree.lookup(DATA, "ab").unwrap();
        let g = tree.lookup(ab, &"ab".repeat(31)).unwrap();
        let a = tree.attr(g).unwrap();
        assert_eq!((a.kind, a.size, a.perm), (FileType::RegularFile, 5, 0o444));
        assert_eq!(tree.file(g).unwrap().layer, 0);
        let mut files = Vec::new();
        tree.readdir(ab, 0, &mut |_, _, n| {
            files.push(n.len());
            false
        })
        .unwrap();
        assert_eq!(files, [62]);
        let ff = tree.lookup(DATA, "ff").unwrap();
        let i = tree.lookup(ff, &"ff".repeat(31)).unwrap();
        assert_eq!(tree.file(i).unwrap().layer, 1);
        // as root, the attributes are the image's
        let (l0, _) = mapped(&[file("a", 1, 1)]);
        let root = Layers::new(vec![l0], None, false, Stubs::Every);
        let a = root
            .lookup(root.lookup(ROOT, "layer1").unwrap(), "a")
            .unwrap();
        let x: HashMap<_, _> = root.xattrs(a).unwrap().into_iter().collect();
        assert!(x.contains_key("trusted.overlay.redirect"));
        assert!(root.lookup(ROOT, "data").is_none());
    }

    #[test]
    fn a_big_directory_is_read_from_an_offset() {
        let mut entries = vec![entry("big", TocEntryType::Dir)];
        for i in 0..3000 {
            entries.push(file(
                &format!("big/file-with-a-long-name-{i:05}"),
                (i % 250) as u8 + 1,
                1 + i as u64,
            ));
        }
        let (l, _) = mapped(&entries);
        let tree = Layers::new(vec![l], None, false, Stubs::Every);
        let big = tree
            .lookup(tree.lookup(ROOT, "layer1").unwrap(), "big")
            .unwrap();
        let mut names = Vec::new();
        tree.readdir(big, 2990, &mut |_, _, n| {
            names.push(String::from_utf8_lossy(n).into_owned());
            false
        })
        .unwrap();
        assert_eq!(names.len(), 10, "{names:?}");
        assert!(names.windows(2).all(|w| w[0] < w[1]));
        for i in [0, 1234, 2999] {
            let name = format!("file-with-a-long-name-{i:05}");
            let f = tree.lookup(big, &name).unwrap();
            assert_eq!(tree.attr(f).unwrap().size, 1 + i as u64, "{name}");
        }
        assert!(tree.lookup(big, "file-with-a-long-name-03000").is_none());
    }
}
