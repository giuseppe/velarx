// SPDX-License-Identifier: Apache-2.0
//! The object contract of the fetcher interface: how a fetcher writes a file
//! of a layer into the layer's staging directory.
//!
//! A file is written into a file with no name made beneath `incoming/`
//! (`O_TMPFILE`), each chunk checked against the sha256 the table of contents
//! gives for it; the file is closed for writing; fs-verity is enabled on it
//! (when the scope says so) and its measure must be the digest the table
//! gives (or, for a table with only content digests, the content must have
//! that digest); then it is given its name `files/ab/cd...`
//! with `linkat`, never replacing.  A name that exists is success.  Every
//! path is resolved beneath the staging directory the engine handed
//! (`openat2` with `RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS |
//! NO_XDEV`); nothing is synced, removed or written anywhere else, and the
//! store is never read.

use rustix::fs::{linkat, mkdirat, AtFlags, Mode, OFlags, ResolveFlags, CWD};
use rustix::io::Errno;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use velarx_storage::{measure_file, FsVerityManager};
use velarx_types::digest::Digest;

/// Why a file was not given its name.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// The bytes of a chunk are not the sha256 the table gives
    #[error("chunk at offset {offset} is not what the table of contents says")]
    BadChunk { offset: u64 },
    /// The file is not what its name says
    #[error("the file is not {0}")]
    Wrong(String),
    /// fs-verity was asked for and cannot be had
    #[error("fs-verity: {0}")]
    Verity(String),
    /// A write beyond the size the table gives
    #[error("a chunk reaches beyond the {0} bytes of the file")]
    TooLarge(u64),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// What the table of contents names a file by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Name {
    /// The fs-verity digest
    Verity(Digest),
    /// The digest of the content
    Content(Digest),
}

impl Name {
    fn digest(&self) -> &Digest {
        match self {
            Name::Verity(d) | Name::Content(d) => d,
        }
    }
}

/// The path below a staging directory of the file a table of contents names
/// by `key` (its fs-verity digest, or the digest of its content):
/// `files/ab/cd...`; none for a text that is no such digest.
pub fn staged_rel(key: &str) -> Option<String> {
    let d = Digest::parse_fsverity(key)
        .or_else(|_| key.parse::<Digest>())
        .ok()?;
    let hex = d.hex();
    Some(format!("files/{}/{}", &hex[..2], &hex[2..]))
}

/// Open the directory `rel` beneath `dir` (making it when `make`).
pub(crate) fn open_beneath(dir: BorrowedFd<'_>, rel: &str, make: bool) -> io::Result<OwnedFd> {
    let open = || {
        velarx_sys::fs::openat2_retry(
            dir,
            rel,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
    };
    match open() {
        Err(Errno::NOENT) if make => {
            match mkdirat(dir, rel, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
            open().map_err(Into::into)
        }
        r => r.map_err(Into::into),
    }
}

/// A file being written: no name, nobody else can open it.
pub struct Unnamed {
    file: File,
    size: u64,
    /// The digest of the content the table gives besides its fs-verity
    /// digest (none: the writer names the file by what it wrote), and the
    /// hash of what was written in order so far
    content: Option<(Option<Digest>, std::sync::Mutex<InOrder>)>,
}

/// The hash of the bytes of a file written from its start, while the
/// chunks come in order.
struct InOrder {
    hasher: velarx_types::digest::DigestWriter,
    next: u64,
    /// A chunk came out of order: the file is read again at the end
    broken: bool,
}

impl InOrder {
    fn of(alg: velarx_types::digest::Algorithm) -> std::sync::Mutex<Self> {
        std::sync::Mutex::new(Self {
            hasher: velarx_types::digest::DigestWriter::new(alg),
            next: 0,
            broken: false,
        })
    }
}

impl Unnamed {
    /// A file with no name in `incoming/` of the staging directory, for a
    /// file of `size` bytes.
    pub fn begin(staging: BorrowedFd<'_>, size: u64) -> io::Result<Self> {
        let incoming = open_beneath(staging, "incoming", true)?;
        let fd = rustix::fs::openat(
            &incoming,
            ".",
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            // (writable by its owner: the kernel wants write access to enable
            // fs-verity.  The mode is the engine's to make read-only, when it
            // opens the file: no fetcher's seccomp list has `chmod`, so one
            // that kept a descriptor cannot change it afterwards)
            Mode::from_raw_mode(0o600),
        )?;
        Ok(Self {
            file: File::from(fd),
            size,
            content: None,
        })
    }

    /// A file for a file of `size` bytes that is handed over to the engine
    /// ([`Unnamed::sealed`] and no name): one that is small and needs no
    /// fs-verity is written in memory, which costs no inode of the file
    /// system (a layer has tens of thousands of them, and the engine reads
    /// each once).
    pub fn for_handover(staging: BorrowedFd<'_>, size: u64, verity: bool) -> io::Result<Self> {
        if !in_memory(size, verity) {
            return Self::begin(staging, size);
        }
        // (the flags the filter of the fetchers allows)
        let fd = rustix::fs::memfd_create(
            "file",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )?;
        Ok(Self {
            file: File::from(fd),
            size,
            content: None,
        })
    }

    /// The table gives the digest of the content too (besides the fs-verity
    /// digest the file is named by): the file must have it.  Hashed as the
    /// chunks come in order; read again at the end where they did not.
    pub fn expect_content(mut self, digest: Digest) -> Self {
        self.content = Some((Some(digest), InOrder::of(digest.alg())));
        self
    }

    /// The file is written from its start to its end, in order, and named by
    /// the digest in `alg` of what was written ([`Unnamed::finish_written`]):
    /// a layer a fetcher unpacks has no table to say what its files are.
    pub fn hashed(mut self, alg: velarx_types::digest::Algorithm) -> Self {
        self.content = Some((None, InOrder::of(alg)));
        self
    }

    /// The chunk `data` at `offset`; `sha256` is the digest the table gives
    /// for it (the digest is of `data` as it is written).
    pub fn write_chunk(
        &self,
        offset: u64,
        data: &[u8],
        sha256: Option<&Digest>,
    ) -> Result<(), StageError> {
        if offset
            .checked_add(data.len() as u64)
            .is_none_or(|e| e > self.size)
        {
            return Err(StageError::TooLarge(self.size));
        }
        if let Some(want) = sha256 {
            if Digest::of(want.alg(), data) != *want {
                return Err(StageError::BadChunk { offset });
            }
        }
        write_holes(&self.file, offset, data)?;
        if let Some((_, order)) = &self.content {
            let mut order = order.lock().unwrap_or_else(|e| e.into_inner());
            if !order.broken && order.next == offset {
                order.hasher.update(data);
                order.next += data.len() as u64;
            } else {
                order.broken = true;
            }
        }
        Ok(())
    }

    /// The file is complete: close it for writing, seal it, check it against
    /// `name` and give it that name in `files/` of the staging directory.
    /// `verity`: fs-verity is enabled (an error where it cannot be);
    /// otherwise the digest is computed from the content.  Returns whether
    /// this call made the name (false: it was there).
    pub fn finish(
        self,
        staging: BorrowedFd<'_>,
        name: &Name,
        verity: bool,
    ) -> Result<bool, StageError> {
        self.finish_kept(staging, name, verity)
            .map(|(made, _)| made)
    }

    /// [`Self::finish`], and the file as it was named, read-only.
    pub fn finish_kept(
        self,
        staging: BorrowedFd<'_>,
        name: &Name,
        verity: bool,
    ) -> Result<(bool, File), StageError> {
        let ro = self.sealed(name, verity)?;
        let hex = name.digest().hex();
        let files = open_beneath(staging, "files", true)?;
        let prefix = open_beneath(files.as_fd(), &hex[..2], true)?;
        let made = link_new(&ro, prefix.as_fd(), &hex[2..])?;
        Ok((made, ro))
    }

    /// The file is complete: fs-verity is enabled on it when `verity` (which
    /// wants no writer: it is opened again read-only), and it is checked
    /// against `name`.  It has no name: what takes it from here gives it one,
    /// or reads it through the descriptor.
    pub fn sealed(mut self, name: &Name, verity: bool) -> Result<File, StageError> {
        let alg = name.digest().alg();
        // (the length is made only where the writes left it short, a file
        // that ends in a hole: a `ftruncate` is a transaction of the file
        // system, the most a file costs to stage)
        if self.file.metadata()?.len() != self.size {
            self.file.set_len(self.size)?;
        }
        let hashed = self.content.take().map(|(want, order)| {
            let order = order.into_inner().unwrap_or_else(|e| e.into_inner());
            let done = (!order.broken && order.next == self.size).then(|| order.hasher.finalize());
            (want, done)
        });
        // (without fs-verity nothing is gained by a second descriptor of the
        // file: whoever is given it copies what it reads)
        let file = if verity {
            let file = velarx_sys::fd::reopen_read_only(&self.file)?;
            drop(self.file);
            // (the mode stays: no fetcher can change one)
            FsVerityManager::new()
                .for_algorithm(alg)
                .enable_file_keeping_mode(&file, &velarx_sys::fd::proc_path(&file))
                .map_err(|e| StageError::Verity(e.to_string()))?;
            file
        } else {
            self.file
        };
        // the hash of the content made as it was written, else read again
        let content_of = |want: &Digest| -> Result<Digest, StageError> {
            match &hashed {
                Some((_, Some(d))) if d.alg() == want.alg() => Ok(*d),
                _ => {
                    io::Seek::rewind(&mut &file)?;
                    Ok(Digest::of_reader(want.alg(), &file)?)
                }
            }
        };
        match name {
            Name::Verity(want) => {
                let measured = match verity {
                    true => measure_file(&file)
                        .map_err(|e| StageError::Verity(e.to_string()))?
                        .object()
                        .map(|o| o.to_string())
                        .ok_or_else(|| StageError::Verity("not the digest of an object".into()))?,
                    false => velarx_storage::fsverity_digest_file(alg, &file)?,
                };
                if measured != want.to_string() {
                    return Err(StageError::Wrong(format!("the fs-verity digest {want}")));
                }
            }
            Name::Content(want) => {
                if content_of(want)? != *want {
                    return Err(StageError::Wrong(format!("the content digest {want}")));
                }
            }
        }
        if let Some((Some(want), _)) = &hashed {
            if content_of(want)? != *want {
                return Err(StageError::Wrong(format!("the content digest {want}")));
            }
        }
        Ok(file)
    }

    /// The file is complete and is handed over as it is: the engine that
    /// is given it reads it and knows it by what it read.  The content
    /// digest the table gives ([`Unnamed::expect_content`]) is checked here,
    /// as [`Unnamed::sealed`] does: the engine checks the name.
    pub fn handed(mut self) -> Result<File, StageError> {
        if self.file.metadata()?.len() != self.size {
            self.file.set_len(self.size)?;
        }
        if let Some((Some(want), order)) = self.content.take() {
            let order = order.into_inner().unwrap_or_else(|e| e.into_inner());
            let read = match !order.broken && order.next == self.size {
                true => order.hasher.finalize(),
                false => {
                    io::Seek::rewind(&mut &self.file)?;
                    Digest::of_reader(want.alg(), &self.file)?
                }
            };
            if read != want {
                return Err(StageError::Wrong(format!("the content digest {want}")));
            }
        }
        Ok(self.file)
    }

    /// The file, written in order from its start ([`Unnamed::hashed`]), is
    /// complete: sealed ([`Unnamed::sealed`]) as the digest of what was
    /// written.  Returns that digest and the file.
    pub fn finish_written(self, verity: bool) -> Result<(Digest, File), StageError> {
        let digest = {
            let Some((None, order)) = &self.content else {
                return Err(StageError::Wrong("a file written in order".into()));
            };
            let order = order.lock().unwrap_or_else(|e| e.into_inner());
            if order.broken || order.next != self.size {
                return Err(StageError::Wrong("a file written in order".into()));
            }
            order.hasher.clone().finalize()
        };
        let file = self.sealed(&Name::Content(digest), verity)?;
        Ok((digest, file))
    }
}

/// The most bytes of a file that is handed over in memory.
const IN_MEMORY: u64 = 256 << 10;

/// Whether a file of `size` bytes that is handed over is written in memory
/// ([`Unnamed::for_handover`]).
pub fn in_memory(size: u64, verity: bool) -> bool {
    !verity && size <= IN_MEMORY
}

/// The size of the blocks of zeros left as holes.
const HOLE: u64 = 4096;

/// Write `data` at `offset` of the new file `file`, but its blocks of zeros:
/// a hole costs no disk and reads as zeros.
fn write_holes(file: &File, offset: u64, data: &[u8]) -> io::Result<()> {
    let mut at = 0usize;
    // (the start of the run of blocks with data being gathered)
    let mut run: Option<usize> = None;
    while at < data.len() {
        let end = ((offset + at as u64) / HOLE + 1) * HOLE - offset;
        let end = usize::try_from(end).unwrap_or(usize::MAX).min(data.len());
        let zeros = data[at..end].iter().all(|b| *b == 0);
        match (zeros, run) {
            (true, Some(start)) => {
                file.write_all_at(&data[start..at], offset + start as u64)?;
                run = None;
            }
            (false, None) => run = Some(at),
            _ => {}
        }
        at = end;
    }
    if let Some(start) = run {
        file.write_all_at(&data[start..], offset + start as u64)?;
    }
    Ok(())
}

/// Give the file `file` the name `name` in `dir` with `linkat`, never
/// replacing: whether this call made it (false: the name was there).
pub(crate) fn link_new(file: &File, dir: BorrowedFd<'_>, name: &str) -> Result<bool, StageError> {
    match linkat(
        CWD,
        velarx_sys::fd::proc_path(file),
        dir,
        name,
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => Ok(true),
        Err(Errno::EXIST) => Ok(false),
        Err(e) => Err(io::Error::from(e).into()),
    }
}

/// Put `bytes` into the staging directory as `name` (a name of the layer's
/// staging the interface gives: `toc.claim`, `tarsplit`), by the object
/// contract: a file with no name in `incoming/`, written, made read-only,
/// then named, never replacing (a name that exists is an error: the layer
/// was unpacked by somebody else).
pub fn put_named(staging: BorrowedFd<'_>, name: &str, bytes: &[u8]) -> Result<(), StageError> {
    let file = Unnamed::begin(staging, bytes.len() as u64)?;
    file.file.write_all_at(bytes, 0)?;
    let ro = velarx_sys::fd::reopen_read_only(&file.file)?;
    drop(file);
    match link_new(&ro, staging, name)? {
        true => Ok(()),
        false => Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
    }
}

/// The digest of the content the table gives a file it names by its
/// fs-verity digest: the file must have both.
pub fn content_of(e: &velarx_storage::TocEntry) -> Option<Digest> {
    e.verity()?;
    e.digest.as_deref()?.parse().ok()
}

/// The name the table of contents gives a regular file: its fs-verity
/// digest when it has one, else the digest of its content.
pub fn name_of(e: &velarx_storage::TocEntry) -> Option<(String, Name)> {
    if let Some(v) = e.verity() {
        let d = Digest::parse_fsverity(&v).ok()?;
        return Some((v, Name::Verity(d)));
    }
    let text = e.digest.clone()?;
    let d: Digest = text.parse().ok()?;
    Some((text, Name::Content(d)))
}

/// Whether the file the table names by `key` is in the staging directory.
pub fn staged(staging: &File, key: &str) -> bool {
    let Some(rel) = staged_rel(key) else {
        return false;
    };
    velarx_sys::fs::openat2_retry(
        staging.as_fd(),
        rel.as_str(),
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .is_ok()
}

/// The table of contents of a layer, as the engine told it (`Layer` with
/// its table), and where each file is in it.
pub struct LayerToc {
    pub toc: velarx_storage::Toc,
    /// The entry of each regular file with content, by the digest the table
    /// names it by (the first entry of a name, as the engine plans it: its
    /// chunks are the ones checked)
    pub at: std::collections::HashMap<String, usize>,
}

impl LayerToc {
    /// The table of a layer, as the scope that told it gave it, parsed once
    /// and kept with the layer (another scope's table of the same layer is
    /// its own).  A call while it is parsed waits for that parse.
    pub fn kept(
        layer: &crate::serve_fetch::LayerScope,
    ) -> Result<std::sync::Arc<Self>, crate::fetcher::fetch::FetcherError> {
        type Kept = Result<std::sync::Arc<LayerToc>, crate::fetcher::fetch::FetcherError>;
        let kept = layer
            .kept
            .get_or_init(|| std::sync::Arc::new(Self::of(layer).map(std::sync::Arc::new)));
        match kept.downcast_ref::<Kept>() {
            Some(kept) => kept.clone(),
            None => Err(crate::fetcher::fetch::FetcherError::Refused {
                reason: "the layer keeps something else than its table".into(),
            }),
        }
    }

    /// The table the engine told with the layer (compressed), parsed.
    fn of(
        layer: &crate::serve_fetch::LayerScope,
    ) -> Result<Self, crate::fetcher::fetch::FetcherError> {
        use crate::fetcher::fetch::FetcherError;
        use std::io::Read;
        let bad = |reason: String| FetcherError::InvalidArgument { reason };
        let file = layer.toc.as_ref().ok_or_else(|| FetcherError::Refused {
            reason: "the layer was told without its table of contents".into(),
        })?;
        let toc_z = velarx_base::sealed::read_sealed_whole(
            file,
            crate::pull::chunked::MAX_METADATA_COMPRESSED,
        )
        .map_err(|w| bad(format!("the table of contents {w}")))?;
        let max = crate::pull::chunked::MAX_TOC_JSON;
        let mut json = Vec::new();
        crate::pull::zstd_decoder(&toc_z[..])
            .and_then(|d| d.take(max + 1).read_to_end(&mut json))
            .map_err(|e| bad(format!("the table of contents: {e}")))?;
        if json.len() as u64 > max {
            return Err(bad("the table of contents is too large".into()));
        }
        let toc: velarx_storage::Toc = serde_json::from_slice(&json)
            .map_err(|e| bad(format!("not a table of contents: {e}")))?;
        let mut at = std::collections::HashMap::new();
        for (i, e) in toc.entries.iter().enumerate() {
            if e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0 {
                if let Some((k, _)) = name_of(e) {
                    at.entry(k).or_insert(i);
                }
            }
        }
        Ok(Self { toc, at })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use velarx_types::digest::Algorithm;

    fn staging() -> (tempfile::TempDir, File) {
        let dir = tempfile::tempdir().unwrap();
        let f = File::open(dir.path()).unwrap();
        (dir, f)
    }

    fn verity_of(bytes: &[u8]) -> Digest {
        let f = tempfile::tempfile().unwrap();
        f.write_all_at(bytes, 0).unwrap();
        Digest::parse_fsverity(
            &velarx_storage::fsverity_digest_file(Algorithm::Sha256, &f).unwrap(),
        )
        .unwrap()
    }

    fn rel(d: &Digest) -> String {
        let hex = d.hex();
        format!("files/{}/{}", &hex[..2], &hex[2..])
    }

    #[test]
    fn a_file_is_named_only_when_it_is_what_the_table_says() {
        let (dir, st) = staging();
        let name = Name::Verity(verity_of(b"hello world"));
        let w = Unnamed::begin(st.as_fd(), 11).unwrap();
        let chunk = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        w.write_chunk(0, b"hello ", Some(&chunk(b"hello ")))
            .unwrap();
        w.write_chunk(6, b"world", Some(&chunk(b"world"))).unwrap();
        assert!(w.finish(st.as_fd(), &name, false).unwrap());
        let path = dir.path().join(rel(name.digest()));
        assert_eq!(std::fs::read(&path).unwrap(), b"hello world");
        // (the engine makes it read-only when it takes it)
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        // nothing else is in incoming/: the file had no name
        assert_eq!(
            std::fs::read_dir(dir.path().join("incoming"))
                .unwrap()
                .count(),
            0
        );
        // the same file again is success and replaces nothing
        let ino = std::fs::metadata(&path).unwrap().ino();
        let w = Unnamed::begin(st.as_fd(), 11).unwrap();
        w.write_chunk(0, b"hello world", None).unwrap();
        assert!(!w.finish(st.as_fd(), &name, false).unwrap());
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino);
    }

    #[test]
    fn a_wrong_chunk_is_never_written_and_a_wrong_file_gets_no_name() {
        let (dir, st) = staging();
        let w = Unnamed::begin(st.as_fd(), 5).unwrap();
        let bad = w.write_chunk(0, b"hellx", Some(&Digest::of(Algorithm::Sha256, b"hello")));
        assert!(matches!(bad, Err(StageError::BadChunk { offset: 0 })));
        // (the bytes were not written)
        assert_eq!(w.file.metadata().unwrap().len(), 0);
        assert!(matches!(
            w.write_chunk(3, b"abc", None),
            Err(StageError::TooLarge(5))
        ));
        // right chunks, other file than the name says
        let name = Name::Verity(verity_of(b"hello"));
        let w = Unnamed::begin(st.as_fd(), 5).unwrap();
        w.write_chunk(0, b"hellx", None).unwrap();
        assert!(matches!(
            w.finish(st.as_fd(), &name, false),
            Err(StageError::Wrong(_))
        ));
        assert!(!dir.path().join(rel(name.digest())).exists());
        let content = Name::Content(Digest::of(Algorithm::Sha256, b"hello"));
        let w = Unnamed::begin(st.as_fd(), 5).unwrap();
        w.write_chunk(0, b"hello", None).unwrap();
        assert!(w.finish(st.as_fd(), &content, false).unwrap());
        assert!(dir.path().join(rel(content.digest())).exists());
    }

    #[test]
    fn a_file_named_by_its_verity_must_have_the_content_digest_the_table_gives() {
        let (dir, st) = staging();
        let name = Name::Verity(verity_of(b"hello"));
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        // in order: hashed as written
        let w = Unnamed::begin(st.as_fd(), 5)
            .unwrap()
            .expect_content(sha(b"hellx"));
        w.write_chunk(0, b"hel", None).unwrap();
        w.write_chunk(3, b"lo", None).unwrap();
        assert!(matches!(
            w.finish(st.as_fd(), &name, false),
            Err(StageError::Wrong(_))
        ));
        assert!(!dir.path().join(rel(name.digest())).exists());
        // out of order: read again, and right
        let w = Unnamed::begin(st.as_fd(), 5)
            .unwrap()
            .expect_content(sha(b"hello"));
        w.write_chunk(3, b"lo", None).unwrap();
        w.write_chunk(0, b"hel", None).unwrap();
        assert!(w.finish(st.as_fd(), &name, false).unwrap());
        // handed over in memory: the same check
        let w = Unnamed::for_handover(st.as_fd(), 5, false)
            .unwrap()
            .expect_content(sha(b"hellx"));
        w.write_chunk(0, b"hello", None).unwrap();
        assert!(matches!(w.handed(), Err(StageError::Wrong(_))));
        let w = Unnamed::for_handover(st.as_fd(), 5, false)
            .unwrap()
            .expect_content(sha(b"hello"));
        w.write_chunk(3, b"lo", None).unwrap();
        w.write_chunk(0, b"hel", None).unwrap();
        w.handed().unwrap();
    }

    #[test]
    fn a_file_written_in_order_is_known_by_what_was_written() {
        let data = b"some content, then zeros".to_vec();
        let mut bytes = data.clone();
        bytes.extend_from_slice(&[0u8; 8192]);
        let (_tmp, dir) = staging();
        let file = Unnamed::begin(dir.as_fd(), bytes.len() as u64)
            .unwrap()
            .hashed(Algorithm::Sha256);
        file.write_chunk(0, &bytes[..10], None).unwrap();
        file.write_chunk(10, &bytes[10..], None).unwrap();
        let (d, file) = file.finish_written(false).unwrap();
        assert_eq!(d, Digest::of(Algorithm::Sha256, &bytes));
        let mut read = Vec::new();
        io::Read::read_to_end(&mut &file, &mut read).unwrap();
        assert_eq!(read, bytes);
        // (it has no name: nothing is in the staging but the directory of
        // the files with none)
        assert_eq!(std::fs::read_dir(_tmp.path()).unwrap().count(), 1);
        // (out of order: no digest it could not prove)
        let file = Unnamed::begin(dir.as_fd(), 4)
            .unwrap()
            .hashed(Algorithm::Sha256);
        file.write_chunk(2, b"cd", None).unwrap();
        file.write_chunk(0, b"ab", None).unwrap();
        assert!(file.finish_written(false).is_err());
    }

    #[test]
    fn a_small_file_handed_over_is_in_memory_and_a_big_one_is_on_the_disk() {
        let (tmp, dir) = staging();
        for (size, on_disk) in [(IN_MEMORY, false), (IN_MEMORY + 1, true)] {
            let file = Unnamed::for_handover(dir.as_fd(), size, false)
                .unwrap()
                .hashed(Algorithm::Sha256);
            file.write_chunk(0, &vec![7u8; size as usize], None)
                .unwrap();
            let (_, file) = file.finish_written(false).unwrap();
            assert_eq!(file.metadata().unwrap().len(), size);
            assert_eq!(tmp.path().join("incoming").exists(), on_disk);
        }
    }

    #[test]
    fn an_index_is_named_once() {
        let (tmp, dir) = staging();
        put_named(dir.as_fd(), "tarsplit", b"split").unwrap();
        assert_eq!(
            std::fs::read(tmp.path().join("tarsplit")).unwrap(),
            b"split"
        );
        assert!(put_named(dir.as_fd(), "tarsplit", b"other").is_err());
        assert_eq!(
            std::fs::read(tmp.path().join("tarsplit")).unwrap(),
            b"split"
        );
    }

    #[test]
    fn a_staging_directory_cannot_be_left_by_a_symlink() {
        let (dir, st) = staging();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("files")).unwrap();
        let name = Name::Verity(verity_of(b"x"));
        let w = Unnamed::begin(st.as_fd(), 1).unwrap();
        w.write_chunk(0, b"x", None).unwrap();
        assert!(w.finish(st.as_fd(), &name, false).is_err());
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
        let (dir, st) = staging();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("incoming")).unwrap();
        assert!(Unnamed::begin(st.as_fd(), 1).is_err());
    }

    /// The table of a layer is parsed once, and the layer keeps it.
    #[test]
    fn a_layers_table_is_parsed_once() {
        let (_tmp, dir) = staging();
        let toc_z = zstd::bulk::compress(br#"{"version":1,"entries":[]}"#, 1).unwrap();
        let toc = velarx_base::sealed::sealed_memory(&toc_z).unwrap();
        let layer = crate::serve_fetch::LayerScope {
            layer: "sha256:aa".into(),
            staging: dir,
            toc: Some(toc.into()),
            blob: None,
            cancel: Default::default(),
            kept: Default::default(),
        };
        let first = LayerToc::kept(&layer).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &first,
            &LayerToc::kept(&layer).unwrap()
        ));
    }
}
