// SPDX-License-Identifier: Apache-2.0
use super::fsverity_digest_of;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;
use velarx_base::sync::SyncMode;
use velarx_types::digest::{Algorithm, Digest};

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("file not found: {0}")]
    NotFound(String),
    #[error("`{0}` is not an fs-verity digest (fsverity-sha256-12:HEX or fsverity-sha512-12:HEX)")]
    InvalidDigest(String),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// The fs-verity digest of a file of the store, which is also its name in
/// the objects (`xx/yyyy...`, as the repository of composefs-rs has them):
/// with SHA-256 (`xx/` and 62 digits) or SHA-512 (`xx/` and 126), two
/// unrelated names even for the same content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Object {
    /// `fsverity-sha256-12:HEX` (64 lower case hexadecimal digits) or
    /// `fsverity-sha512-12:HEX` (128): [`Digest::parse_fsverity`].
    pub verity: String,
    /// Measured by the kernel on a file that has fs-verity (the overlay and
    /// the FUSE server check it), else computed from the content.
    pub checked: bool,
}

impl Object {
    /// The object with this fs-verity digest, if it is one: a name below
    /// the objects is never made of anything else.
    pub fn new(verity: &str, checked: bool) -> Option<Self> {
        let digest = Digest::parse_fsverity(verity).ok()?;
        Some(Self {
            verity: digest.to_string(),
            checked,
        })
    }

    /// The digest of the object.
    pub fn digest(&self) -> Digest {
        Digest::parse_fsverity(&self.verity).expect("an object has an fs-verity digest")
    }

    /// The algorithm of its digest.
    pub fn alg(&self) -> Algorithm {
        self.digest().alg()
    }

    /// Its path below the objects: `xx/yyyy...`.
    pub fn rel(&self) -> String {
        let hex = self.digest().hex();
        format!("{}/{}", &hex[..2], &hex[2..])
    }

    /// The object whose path below the objects is `rel` (`xx/yyyy...`), not
    /// `checked`: the algorithm is the one whose digests have that many
    /// digits (62 after the directory for SHA-256, 126 for SHA-512).
    pub fn from_rel(rel: &Path) -> Option<Self> {
        let name = rel.file_name()?.to_str()?;
        let prefix = rel.parent()?.file_name()?.to_str()?;
        if prefix.len() != 2 {
            return None;
        }
        let alg = Algorithm::ALL
            .into_iter()
            .find(|a| a.len() * 2 == prefix.len() + name.len())?;
        Self::new(&format!("fsverity-{alg}-12:{prefix}{name}"), false)
    }
}

/// FileStore stores files, each once, named by its fs-verity digest (SHA-256
/// or SHA-512, blocks of 4096 bytes: its id, `fsverity-sha256-12:HEX` or
/// `fsverity-sha512-12:HEX`), at `{root}/xx/yyyy...`, the layout of the
/// objects of composefs-rs: the store of the engine, the staging of a
/// container and the files of the tests are all such stores.  A file of one
/// algorithm is never found by the digest of the other.
pub struct FileStore {
    root: PathBuf,
    /// The files of read-only stores, read when this one does not
    /// have a file, never written.
    more: Vec<PathBuf>,
    /// What `barrier` does (`[storage] sync`).
    sync: SyncMode,
    /// What fs-verity the files of the store have (`[storage] fsverity`).
    verity: crate::VerityMode,
    /// Whether its file system gives files fs-verity, once known.
    gives_verity: std::sync::OnceLock<bool>,
    #[cfg(any(test, feature = "test-support"))]
    barriers: std::sync::atomic::AtomicUsize,
    /// The number (from 1) of the barrier that fails, 0: none
    #[cfg(any(test, feature = "test-support"))]
    failing_barrier: std::sync::atomic::AtomicUsize,
    /// The bytes of files a commit read to hash them (tests count them)
    #[cfg(any(test, feature = "test-support"))]
    hashed: std::sync::atomic::AtomicU64,
    /// The bytes of files a commit wrote to a copy (tests count them)
    #[cfg(any(test, feature = "test-support"))]
    copied: std::sync::atomic::AtomicU64,
}

impl FileStore {
    pub fn new<P: AsRef<Path>>(root: P) -> StoreResult<Self> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        // (absolute: the options of the overlay mount name it)
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()?.join(root)
        };
        Ok(Self {
            root,
            more: Vec::new(),
            sync: SyncMode::default(),
            verity: crate::VerityMode::Off,
            gives_verity: std::sync::OnceLock::new(),
            #[cfg(any(test, feature = "test-support"))]
            barriers: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            failing_barrier: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            hashed: std::sync::atomic::AtomicU64::new(0),
            #[cfg(any(test, feature = "test-support"))]
            copied: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// A durability barrier of a pull or a commit: write everything of the
    /// file system of `path` to the disk as `[storage] sync` says.
    pub fn barrier(&self, path: &Path) -> io::Result<()> {
        match self.sync {
            SyncMode::None => Ok(()),
            SyncMode::Syncfs => {
                #[cfg(any(test, feature = "test-support"))]
                {
                    let number = 1 + self
                        .barriers
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if number
                        == self
                            .failing_barrier
                            .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        return Err(io::Error::from(rustix::io::Errno::IO));
                    }
                }
                let dir = File::open(path)?;
                rustix::fs::syncfs(&dir).map_err(io::Error::from)
            }
        }
    }

    /// Make the names of the directory `dir` durable, as `[storage] sync`
    /// says.
    pub fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        match self.sync {
            SyncMode::None => Ok(()),
            SyncMode::Syncfs => File::open(dir)?.sync_all(),
        }
    }

    /// Make the `number`th barrier (counted from 1 since the store was made)
    /// fail with an I/O error, as a `syncfs` of a disk that fails does.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fail_barrier(&self, number: usize) {
        self.failing_barrier
            .store(number, std::sync::atomic::Ordering::Relaxed);
    }

    /// A commit read `bytes` of a file to hash them (counted in tests only:
    /// a file is read once).
    pub fn note_hashed(&self, bytes: usize) {
        #[cfg(any(test, feature = "test-support"))]
        self.hashed
            .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(any(test, feature = "test-support")))]
        let _ = bytes;
    }

    /// A commit wrote `bytes` of a file to a copy (counted in tests only).
    pub fn note_copied(&self, bytes: usize) {
        #[cfg(any(test, feature = "test-support"))]
        self.copied
            .fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
        #[cfg(not(any(test, feature = "test-support")))]
        let _ = bytes;
    }

    /// The bytes of files the commits of this store wrote to copies.
    #[cfg(any(test, feature = "test-support"))]
    pub fn copied(&self) -> u64 {
        self.copied.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The bytes of files the commits of this store read to hash them.
    #[cfg(any(test, feature = "test-support"))]
    pub fn hashed(&self) -> u64 {
        self.hashed.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn barriers(&self) -> usize {
        self.barriers.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The store, with the durability `sync` asks for.
    pub fn with_sync(mut self, sync: SyncMode) -> Self {
        self.sync = sync;
        self
    }

    /// The store, with the fs-verity its files have.
    pub fn with_verity(mut self, verity: crate::VerityMode) -> Self {
        self.verity = verity;
        self
    }

    /// What fs-verity the files of the store have.
    pub fn verity(&self) -> crate::VerityMode {
        self.verity
    }

    /// The store, with the files of read-only stores under it.
    pub fn with_additional(mut self, dirs: Vec<PathBuf>) -> Self {
        self.more = dirs;
        self
    }

    /// The directories of the files of the read-only stores.
    pub fn additional(&self) -> &[PathBuf] {
        &self.more
    }

    /// Where a file is: this store, or a read-only store.
    fn locate(&self, id: &str) -> Option<PathBuf> {
        let rel = Object::new(id, false)?.rel();
        let path = self.root.join(&rel);
        if path.exists() {
            return Some(path);
        }
        self.more.iter().map(|d| d.join(&rel)).find(|p| p.exists())
    }

    /// Where the file `id` is or would be in this store (not in a
    /// read-only one): none when `id` is no fs-verity digest.
    pub fn local_path(&self, id: &str) -> Option<PathBuf> {
        Some(self.object_path(&Object::new(id, false)?))
    }

    /// Where the object `object` is or would be in this store.
    pub fn object_path(&self, object: &Object) -> PathBuf {
        self.root.join(object.rel())
    }

    /// Whether this store itself has the file (not a read-only store).
    pub fn contains_local(&self, id: &str) -> bool {
        self.local_path(id).is_some_and(|p| p.exists())
    }

    /// Whether this store itself has the file `id` whole: `size` bytes
    /// long and, where the store keeps fs-verity, with fs-verity.  A file of
    /// that name that is not that is damaged (or was put there by another):
    /// it is not held, so that what a pull fetches replaces it.  One `statx`:
    /// a file with fs-verity cannot change, and it got its name after the
    /// kernel measured it, so it is not opened to be measured again (that
    /// reads its Merkle tree descriptor).  Of the same length, other bytes
    /// in a file without fs-verity are not seen.
    pub fn holds(&self, id: &str, size: u64) -> bool {
        use rustix::fs::{statx, AtFlags, FileType, StatxAttributes, StatxFlags, CWD};
        let Some(st) = self.local_path(id).and_then(|p| {
            statx(
                CWD,
                &p,
                AtFlags::empty(),
                StatxFlags::TYPE | StatxFlags::SIZE,
            )
            .ok()
        }) else {
            return false;
        };
        FileType::from_raw_mode(st.stx_mode.into()) == FileType::RegularFile
            && st.stx_size == size
            && (self.verity == crate::VerityMode::Off
                || st.stx_attributes.contains(StatxAttributes::VERITY)
                || !self.gives_verity(id))
    }

    /// Whether the file system of the store gives files fs-verity: the
    /// kernel's answer for a file of it that has none, once.
    fn gives_verity(&self, id: &str) -> bool {
        if let Some(gives) = self.gives_verity.get() {
            return *gives;
        }
        let measured = self.local_path(id).map(File::open);
        match measured.map(|f| f.map(|f| crate::measure_file(&f))) {
            Some(Ok(Err(crate::FsVerityError::NotSupported))) => {
                *self.gives_verity.get_or_init(|| false)
            }
            Some(Ok(Err(crate::FsVerityError::NotEnabled))) => {
                *self.gives_verity.get_or_init(|| true)
            }
            _ => true,
        }
    }

    /// The file in a read-only store, when only one of them has it.
    pub fn find_additional(&self, id: &str) -> Option<PathBuf> {
        if self.more.is_empty() || self.contains_local(id) {
            return None;
        }
        self.locate(id)
    }

    /// Whether this store or a read-only one has the file `id`.
    pub fn contains(&self, id: &str) -> bool {
        self.locate(id).is_some()
    }

    /// The path of the file `id`, if it exists (in this store or in a
    /// read-only one: never to be written)
    pub fn get_path(&self, id: &str) -> Option<PathBuf> {
        self.locate(id)
    }

    /// Open the file `id` for whoever serves its content under enforced
    /// digests: from the descriptor of the directory of the store that has
    /// it (this one, then the read-only ones), as a name that is no symlink
    /// and stays below it (`velarx_sys::fs::open_beneath`), a regular file
    /// only (a FIFO put there is refused, not waited on).  None: no store has it; Err: something else is there, or
    /// it cannot be opened.  What is measured on the descriptor is what is
    /// read from it.
    pub fn open_object(&self, id: &str) -> Option<io::Result<File>> {
        Object::new(id, false)?;
        std::iter::once(&self.root)
            .chain(&self.more)
            .find_map(|root| Self::open_in(root, id))
    }

    /// [`Self::open_object`] in the store whose objects are `root` alone.
    pub fn open_in(root: &Path, id: &str) -> Option<io::Result<File>> {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd;
        use velarx_sys::fs::{open_beneath, Beneath, BeneathError};
        let rel = Object::new(id, false)?.rel();
        let dir = match rustix::fs::open(
            root,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(dir) => dir,
            Err(rustix::io::Errno::NOENT) => return None,
            Err(e) => return Some(Err(e.into())),
        };
        match open_beneath(dir.as_fd(), Path::new(&rel), Beneath::File) {
            Ok(fd) => Some(Ok(File::from(fd))),
            Err(BeneathError::Errno(rustix::io::Errno::NOENT)) => None,
            Err(BeneathError::NotRegular) => {
                Some(Err(io::Error::other(format!("{id} is not a regular file"))))
            }
            Err(e) => Some(Err(e.into())),
        }
    }

    /// Store a file whose id is its fs-verity digest in `alg`; returns it.
    pub fn put(&self, alg: Algorithm, data: &[u8]) -> StoreResult<String> {
        let id = fsverity_digest_of(alg, data);
        self.put_with_digest(data, &id)?;
        Ok(id)
    }

    /// Store a file whose id must be `expected`.
    pub fn put_with_digest(&self, data: &[u8], expected: &str) -> StoreResult<PathBuf> {
        let object = Object::new(expected, false)
            .ok_or_else(|| StoreError::InvalidDigest(expected.to_string()))?;
        let path = self.object_path(&object);
        if path.exists() {
            debug!("File {} already exists in store", expected);
            return Ok(path);
        }
        let actual = fsverity_digest_of(object.alg(), data);
        if actual != expected {
            return Err(StoreError::DigestMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("a store path without a directory"))?;
        fs::create_dir_all(parent)?;
        // A temporary file of its own (concurrent puts of one digest), synced
        // and given fs-verity (where the store has it) before it has its
        // name, which is synced in turn: a name of the store is a file that
        // has the digest it is named by.
        // It is locked until it has its name: the check removes a
        // temporary file whose lock is free.
        let (mut file, _lock) = crate::create_locked(parent, ".tmp", 0o644)?;
        file.write_all(data)?;
        file.as_file().sync_all()?;
        // (closed for writing, which fs-verity wants)
        let file = file.into_temp_path();
        if let Some(manager) = self.verity.manager() {
            match manager.for_algorithm(object.alg()).enable(&file) {
                Ok(()) => {}
                Err(crate::FsVerityError::Io(e)) => return Err(e.into()),
                Err(crate::FsVerityError::NotSupported) if !manager.config().required => {}
                Err(e) if manager.config().required => {
                    return Err(std::io::Error::other(format!(
                        "fs-verity is required and cannot be enabled on {expected}: {e}"
                    ))
                    .into())
                }
                Err(e) => debug!("Cannot enable fs-verity on {expected}: {e}"),
            }
        }
        match file.persist_noclobber(&path) {
            Ok(()) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.error.into()),
        }
        File::open(parent)?.sync_all()?;
        debug!("Stored file {} ({} bytes)", expected, data.len());
        Ok(path)
    }

    /// Read the file `id`.
    pub fn get(&self, id: &str) -> StoreResult<Vec<u8>> {
        let path = self
            .locate(id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        let mut file = File::open(&path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    /// The size of the file `id`.
    pub fn size(&self, id: &str) -> StoreResult<u64> {
        let path = self
            .locate(id)
            .ok_or_else(|| StoreError::NotFound(id.to_string()))?;
        Ok(fs::metadata(&path)?.len())
    }

    /// The ids of the files of this store.
    #[cfg(test)]
    pub fn list(&self) -> StoreResult<Vec<String>> {
        let mut ids = Vec::new();
        if !self.root.exists() {
            return Ok(ids);
        }
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            for f in fs::read_dir(entry.path())? {
                let f = f?;
                let rel = Path::new(&entry.file_name()).join(f.file_name());
                if let (true, Some(o)) = (f.file_type()?.is_file(), Object::from_rel(&rel)) {
                    ids.push(o.verity);
                }
            }
        }
        Ok(ids)
    }

    /// Remove a file from this store.
    pub fn remove(&self, id: &str) -> StoreResult<()> {
        if let Some(path) = self.local_path(id) {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Get the root directory of the store
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Where the bytes of the objects of a store are read back from: the file
/// store itself, or a storage driver that holds them (the read-back seam of
/// `velarx_graph::StorageDriver::read_objects`).  What reads the content of
/// a stored layer (the tar of a push, a save, an export) takes this, never a
/// path of the engine's own store.
pub trait ObjectOpener: Send + Sync {
    /// The object `key` (its fs-verity digest, the key the table of contents
    /// of a layer names it by) as a regular file of exactly `size` bytes.
    /// An object that is not there is `NotFound`; a key that is no digest of
    /// an object, a name that is not a regular file, and a size that is not
    /// the stored one are errors too, whatever the key is.
    fn object_file(&self, key: &str, size: u64) -> io::Result<File>;

    /// The same objects for a reader that will ask for `order` (key and size,
    /// each once) in that order, or `None` when asking in that order is no
    /// cheaper than asking one by one (the default: the objects are local
    /// files).  A driver whose bytes are behind a socket reads the next ones
    /// of the list in one call while the reader takes the first: one call
    /// for many objects, not one for each.  An object not in the list, or
    /// asked for out of order, is read alone as `object_file` does.
    /// `order` is called only when the opener will use it.
    fn ordered(
        &self,
        _order: &mut dyn FnMut() -> Vec<(String, u64)>,
    ) -> Option<Arc<dyn ObjectOpener>> {
        None
    }
}

impl ObjectOpener for FileStore {
    fn object_file(&self, key: &str, size: u64) -> io::Result<File> {
        let file = FileStore::open_object(self, key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not in the store"))??;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored content has the wrong size",
            ));
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A file takes its name in the store with the fs-verity the store has
    /// (on a file system with it: VELARX_VERITY_DIR); where fs-verity is
    /// required and the file system has none, it takes no name.
    #[test]
    fn a_file_takes_its_name_with_fs_verity() {
        if let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") {
            let dir = tempfile::tempdir_in(dir).unwrap();
            let store = FileStore::new(dir.path().join("s"))
                .unwrap()
                .with_verity(crate::VerityMode::On);
            let digest = store.put(Algorithm::Sha256, b"sealed").unwrap();
            let file = File::open(store.local_path(&digest).unwrap()).unwrap();
            let measured = crate::measure_file(&file).unwrap();
            assert_eq!(measured.object().unwrap().to_string(), digest);
        } else {
            eprintln!("VELARX_VERITY_DIR not set: the file system of the sealed file skipped");
        }
        let dir = tempfile::tempdir_in("/dev/shm").unwrap();
        let store = FileStore::new(dir.path().join("s"))
            .unwrap()
            .with_verity(crate::VerityMode::Require);
        let digest = fsverity_digest_of(Algorithm::Sha256, b"no file system for it");
        let err = store
            .put_with_digest(b"no file system for it", &digest)
            .unwrap_err();
        assert!(err.to_string().contains("fs-verity is required"), "{err}");
        assert!(!store.contains_local(&digest));
        // (nor a temporary file is left)
        let left: Vec<_> = walk(dir.path());
        assert!(left.is_empty(), "{left:?}");
        let store = FileStore::new(dir.path().join("s"))
            .unwrap()
            .with_verity(crate::VerityMode::On);
        store
            .put_with_digest(b"no file system for it", &digest)
            .unwrap();
        assert!(store.contains_local(&digest));
    }

    #[test]
    fn a_file_is_held_only_if_it_is_whole() {
        let dir = tempfile::tempdir_in("/dev/shm").unwrap();
        let store = FileStore::new(dir.path().join("s"))
            .unwrap()
            .with_verity(crate::VerityMode::On);
        let digest = store.put(Algorithm::Sha256, b"whole").unwrap();
        assert!(store.holds(&digest, 5));
        assert!(!store.holds(&digest, 6));
        assert!(!store.holds(&fsverity_digest_of(Algorithm::Sha256, b"gone"), 4));
        let path = store.local_path(&digest).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"damaged").unwrap();
        assert!(!store.holds(&digest, 5));
        // (a file system that has fs-verity: a file of the right size is
        // held only if the kernel measures it as its name)
        if let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") {
            let dir = tempfile::tempdir_in(dir).unwrap();
            let store = FileStore::new(dir.path().join("s"))
                .unwrap()
                .with_verity(crate::VerityMode::On);
            let digest = store.put(Algorithm::Sha256, b"sealed").unwrap();
            assert!(store.holds(&digest, 6));
            let path = store.local_path(&digest).unwrap();
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"unseal").unwrap();
            assert!(!store.holds(&digest, 6));
        }
    }

    /// The files below `dir`.
    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    /// `open_object` opens a regular file below the store, nothing else:
    /// not a symlink (to the right file, or out of the store), not a FIFO
    /// (it does not wait), not a directory.
    #[test]
    fn an_object_is_opened_only_as_a_regular_file_below_the_store() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path().join("s")).unwrap();
        let other = FileStore::new(dir.path().join("o")).unwrap();
        let digest = store.put(Algorithm::Sha256, b"object").unwrap();
        let path = store.local_path(&digest).unwrap();
        let mut file = store.open_object(&digest).unwrap().unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "object");
        // not blocking: an open file is read as usual
        assert_eq!(
            rustix::fs::fcntl_getfl(&file).unwrap() & rustix::fs::OFlags::NONBLOCK,
            rustix::fs::OFlags::empty()
        );
        let missing = fsverity_digest_of(Algorithm::Sha256, b"missing");
        assert!(store.open_object(&missing).is_none());
        assert!(store.open_object("not a digest").is_none());
        let real = dir.path().join("real");
        fs::write(&real, b"object").unwrap();
        for what in ["symlink", "fifo", "directory"] {
            let _ = fs::remove_file(&path);
            match what {
                "symlink" => std::os::unix::fs::symlink(&real, &path).unwrap(),
                "fifo" => rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap(),
                _ => fs::create_dir(&path).unwrap(),
            }
            assert!(store.open_object(&digest).unwrap().is_err(), "{what}");
            let _ = fs::remove_dir(&path);
        }
        // a symlink as the directory of the object
        let _ = fs::remove_dir_all(path.parent().unwrap());
        std::os::unix::fs::symlink(dir.path(), path.parent().unwrap()).unwrap();
        fs::write(dir.path().join(path.file_name().unwrap()), b"object").unwrap();
        assert!(store.open_object(&digest).unwrap().is_err());
        // a read-only store has it
        let from_other = other.put(Algorithm::Sha256, b"in other").unwrap();
        let both = FileStore::new(dir.path().join("s2"))
            .unwrap()
            .with_additional(vec![dir.path().join("o")]);
        assert!(both.open_object(&from_other).unwrap().is_ok());
    }

    /// Puts of one digest at once never show a short file under its name,
    /// and leave no temporary file.
    #[test]
    fn concurrent_puts_of_one_digest_are_whole() {
        let dir = tempdir().unwrap();
        let store = std::sync::Arc::new(FileStore::new(dir.path().join("s")).unwrap());
        let data = vec![7u8; 8 << 20];
        let digest = fsverity_digest_of(Algorithm::Sha256, &data);
        let path = store.local_path(&digest).unwrap();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let watcher = {
            let (path, done) = (path.clone(), done.clone());
            std::thread::spawn(move || {
                while done.load(std::sync::atomic::Ordering::SeqCst) < 8 {
                    if let Ok(m) = fs::metadata(&path) {
                        assert_eq!(m.len(), 8 << 20, "a short file under its name");
                    }
                }
            })
        };
        let puts: Vec<_> = (0..8)
            .map(|_| {
                let (store, data, digest, done) =
                    (store.clone(), data.clone(), digest.clone(), done.clone());
                std::thread::spawn(move || {
                    let _ = fs::remove_file(store.local_path(&digest).unwrap());
                    store.put_with_digest(&data, &digest).unwrap();
                    done.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                })
            })
            .collect();
        for p in puts {
            p.join().unwrap();
        }
        watcher.join().unwrap();
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    /// Files are named by their fs-verity digest.
    #[test]
    fn objects_are_named_by_their_fsverity_digest() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path().join("objects")).unwrap();
        let id = store.put(Algorithm::Sha256, b"hello world").unwrap();
        assert_eq!(id, fsverity_digest_of(Algorithm::Sha256, b"hello world"));
        let object = Object::new(&id, false).unwrap();
        let path = store.local_path(&id).unwrap();
        assert_eq!(path, dir.path().join("objects").join(object.rel()));
        assert_eq!(fs::read(&path).unwrap(), b"hello world");
        assert_eq!(store.get(&id).unwrap(), b"hello world");
        assert_eq!(store.list().unwrap(), vec![id.clone()]);
        store.remove(&id).unwrap();
        assert!(!store.contains(&id));
        assert!(store.list().unwrap().is_empty());
    }

    /// A name below the objects is made of an fs-verity digest and of
    /// nothing else: 62 digits after the directory for SHA-256, 126 for
    /// SHA-512.
    #[test]
    fn only_digests_name_objects() {
        let good = format!("fsverity-sha256-12:{}", "ab".repeat(32));
        assert_eq!(
            Object::new(&good, true).unwrap().rel(),
            format!("ab/{}", "ab".repeat(31))
        );
        let good512 = format!("fsverity-sha512-12:{}", "ab".repeat(64));
        let object = Object::new(&good512, true).unwrap();
        assert_eq!(object.rel(), format!("ab/{}", "ab".repeat(63)));
        assert_eq!(object.alg(), Algorithm::Sha512);
        for bad in [
            "fsverity-sha256-12:../../etc/passwd",
            // an OCI digest names no object, nor does a digest of the
            // other length or of another algorithm
            &format!("sha256:{}", "ab".repeat(32)),
            &format!("sha512:{}", "ab".repeat(64)),
            &format!("fsverity-sha256-12:{}", "AB".repeat(32)),
            &format!("fsverity-sha256-12:{}", "ab".repeat(31)),
            &format!("fsverity-sha256-12:{}", "ab".repeat(64)),
            &format!("fsverity-sha512-12:{}", "ab".repeat(32)),
            &format!("fsverity-sha512-16:{}", "ab".repeat(64)),
            &format!("fsverity-sha256-12:{}/", "ab".repeat(31)),
        ] {
            assert!(Object::new(bad, false).is_none(), "{bad}");
        }
        assert_eq!(
            Object::from_rel(Path::new(&format!("ab/{}", "cd".repeat(31)))),
            Object::new(&format!("fsverity-sha256-12:ab{}", "cd".repeat(31)), false)
        );
        assert_eq!(
            Object::from_rel(Path::new(&format!("ab/{}", "cd".repeat(63)))),
            Object::new(&format!("fsverity-sha512-12:ab{}", "cd".repeat(63)), false)
        );
        // (a name of any other length is no object)
        assert_eq!(
            Object::from_rel(Path::new(&format!("ab/{}", "cd".repeat(40)))),
            None
        );
    }

    /// The same content under the two algorithms is two objects: two names,
    /// two files, and a digest never finds the file of the other.
    #[test]
    fn one_content_in_two_algorithms_is_two_objects() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path().join("objects")).unwrap();
        let sha256 = store.put(Algorithm::Sha256, b"same bytes").unwrap();
        assert!(!store.contains(&fsverity_digest_of(Algorithm::Sha512, b"same bytes")));
        let sha512 = store.put(Algorithm::Sha512, b"same bytes").unwrap();
        assert_ne!(sha256, sha512);
        assert!(sha256.starts_with("fsverity-sha256-12:"));
        assert!(sha512.starts_with("fsverity-sha512-12:"));
        let (p256, p512) = (
            store.local_path(&sha256).unwrap(),
            store.local_path(&sha512).unwrap(),
        );
        assert_ne!(p256, p512);
        assert_eq!(p256.file_name().unwrap().len(), 62);
        assert_eq!(p512.file_name().unwrap().len(), 126);
        assert_eq!(fs::read(&p256).unwrap(), fs::read(&p512).unwrap());
        let mut listed = store.list().unwrap();
        listed.sort();
        assert_eq!(listed, vec![sha256.clone(), sha512.clone()]);
        // the content is checked with the algorithm of the name
        let lie = format!(
            "fsverity-sha512-12:{}",
            &sha256["fsverity-sha256-12:".len()..]
        );
        assert!(matches!(
            store.put_with_digest(b"other", &lie),
            Err(StoreError::InvalidDigest(_))
        ));
        let wrong = fsverity_digest_of(Algorithm::Sha512, b"other");
        assert!(matches!(
            store.put_with_digest(b"same bytes", &wrong),
            Err(StoreError::DigestMismatch { .. })
        ));
        // removing one leaves the other
        store.remove(&sha256).unwrap();
        assert!(!store.contains(&sha256) && store.contains(&sha512));
    }

    /// The files of a read-only store are read, never written or listed.
    #[test]
    fn read_only_stores_are_read_through() {
        let dir = tempdir().unwrap();
        let ro = FileStore::new(dir.path().join("ro")).unwrap();
        let digest = ro.put(Algorithm::Sha256, b"of the other store").unwrap();
        let store = FileStore::new(dir.path().join("main"))
            .unwrap()
            .with_additional(vec![dir.path().join("ro")]);
        assert!(store.contains(&digest));
        assert!(!store.contains_local(&digest));
        assert_eq!(store.get(&digest).unwrap(), b"of the other store");
        assert_eq!(store.size(&digest).unwrap(), 18);
        assert!(store
            .get_path(&digest)
            .unwrap()
            .starts_with(dir.path().join("ro")));
        assert_eq!(store.find_additional(&digest), store.get_path(&digest));
        assert!(store.list().unwrap().is_empty());
        // removing it from this store does nothing to the other
        store.remove(&digest).unwrap();
        assert!(ro.contains(&digest));
        // a file of this store is found here first
        store.put(Algorithm::Sha256, b"of the other store").unwrap();
        assert!(store.contains_local(&digest));
        assert_eq!(store.find_additional(&digest), None);
        assert!(store
            .get_path(&digest)
            .unwrap()
            .starts_with(dir.path().join("main")));
    }

    #[test]
    fn test_file_store_put_get() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path()).unwrap();

        let data = b"hello world";
        let digest = store.put(Algorithm::Sha256, data).unwrap();

        assert!(store.contains(&digest));
        assert_eq!(store.get(&digest).unwrap(), data);
    }

    #[test]
    fn test_file_store_digest_mismatch() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path()).unwrap();

        let data = b"hello world";
        let result = store.put_with_digest(
            data,
            &fsverity_digest_of(Algorithm::Sha256, b"other content"),
        );

        assert!(matches!(result, Err(StoreError::DigestMismatch { .. })));
    }

    #[test]
    fn a_name_that_is_no_fs_verity_digest_is_refused_as_such() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path()).unwrap();
        for bad in [
            "fsverity-sha256-12:nothex".to_string(),
            "sha256:nothex".to_string(),
            // an OCI digest of either algorithm is not the name of an object
            format!("sha512:{}", "ab".repeat(64)),
        ] {
            let result = store.put_with_digest(b"x", &bad);
            assert!(matches!(result, Err(StoreError::InvalidDigest(_))), "{bad}");
        }
    }

    /// What reads a layer back opens its objects by key and size: a missing
    /// object, a key that is no object, and a size that is not the stored
    /// one are errors that say which.
    #[test]
    fn test_the_objects_are_opened_by_key_and_size() {
        let dir = tempdir().unwrap();
        let store = FileStore::new(dir.path().join("objects")).unwrap();
        std::fs::write(dir.path().join("secret"), b"secret").unwrap();
        let id = store.put(Algorithm::Sha256, b"hello").unwrap();
        let mut got = String::new();
        ObjectOpener::object_file(&store, &id, 5)
            .unwrap()
            .read_to_string(&mut got)
            .unwrap();
        assert_eq!(got, "hello");
        for size in [0, 4, 6] {
            let e = ObjectOpener::object_file(&store, &id, size).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{size}");
        }
        let absent = format!("fsverity-sha256-12:{}", "cd".repeat(32));
        for key in [
            absent.as_str(),
            "../secret",
            "/etc/passwd",
            "",
            "sha256:abc",
        ] {
            let e = ObjectOpener::object_file(&store, key, 6).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "{key:?}");
        }
    }
}
