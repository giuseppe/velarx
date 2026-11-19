// SPDX-License-Identifier: Apache-2.0
//! fs-verity Support for Content Store
//!
//! This module implements fs-verity for files stored in the file store.
//! fs-verity provides transparent integrity protection using Merkle trees,
//! ensuring that any tampering with file contents is detected at read time.
//!
//! Features:
//! - Enable fs-verity on files after they are stored
//! - Verify fs-verity status of existing files
//! - Measure fs-verity digest for stored files
//! - Support for both SHA-256 and SHA-512 hash algorithms

use std::fs::File;
use std::io::{self};
use std::os::fd::AsFd;
use std::path::Path;
use thiserror::Error;
use tracing::debug;
use velarx_types::digest::{Algorithm, Digest};

/// fs-verity ioctl commands
/// These are from linux/fsverity.h
pub const FS_IOC_ENABLE_VERITY: libc::c_ulong = 0x40806685;
pub const FS_IOC_MEASURE_VERITY: libc::c_ulong = 0xc0046686;
const FS_IOC_READ_VERITY_METADATA: libc::c_ulong = 0xc0286687;
const FS_VERITY_METADATA_TYPE_DESCRIPTOR: u64 = 2;

/// fs-verity hash algorithms
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FsVerityHashAlgorithm {
    #[default]
    Sha256 = 1,
    Sha512 = 2,
}

impl FsVerityHashAlgorithm {
    /// The fs-verity hash of the digest algorithm `alg`.
    pub fn of(alg: Algorithm) -> Self {
        match alg {
            Algorithm::Sha256 => Self::Sha256,
            Algorithm::Sha512 => Self::Sha512,
        }
    }

    /// The digest algorithm of this fs-verity hash.
    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::Sha256 => Algorithm::Sha256,
            Self::Sha512 => Algorithm::Sha512,
        }
    }

    /// The hash as people write it: `SHA-256`, `SHA-512`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
        }
    }

    /// Get the name of this algorithm
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

/// fs-verity enable arguments (fsverity_enable_arg)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct FsVerityEnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    sig_size: u32,
    reserved1: u32,
    sig_ptr: u64,
    reserved2: [u64; 11],
}

impl Default for FsVerityEnableArg {
    fn default() -> Self {
        Self {
            version: 1,
            hash_algorithm: FsVerityHashAlgorithm::Sha256 as u32,
            block_size: 4096,
            salt_size: 0,
            salt_ptr: 0,
            sig_size: 0,
            reserved1: 0,
            sig_ptr: 0,
            reserved2: [0; 11],
        }
    }
}

/// fs-verity digest structure (fsverity_digest)
#[repr(C)]
#[derive(Clone)]
struct FsVerityDigest {
    digest_algorithm: u16,
    digest_size: u16,
    digest: [u8; 64], // Max size for SHA-512
}

impl Default for FsVerityDigest {
    fn default() -> Self {
        Self {
            digest_algorithm: FsVerityHashAlgorithm::Sha256 as u16,
            // the size of the buffer: the kernel fails with EOVERFLOW when
            // the digest (64 bytes with SHA-512) does not fit
            digest_size: 64,
            digest: [0u8; 64],
        }
    }
}

#[derive(Error, Debug)]
pub enum FsVerityError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("fs-verity not supported by filesystem")]
    NotSupported,
    #[error("fs-verity is not enabled on the file")]
    NotEnabled,
    #[error("fs-verity enable failed: {0}")]
    EnableFailed(String),
    /// The kernel cannot make the Merkle tree of this hash: an image whose
    /// digests are made with it cannot be stored with fs-verity here, and
    /// is never stored without (no silent change to another hash).
    #[error(
        "fs-verity with {} is not available here (the kernel lacks the hash, or the file system does not take it)",
        .0.label()
    )]
    AlgorithmUnavailable(FsVerityHashAlgorithm),
    #[error("fs-verity measure failed: {0}")]
    MeasureFailed(String),
    #[error("file not found: {0}")]
    NotFound(String),
    #[error("permission denied")]
    PermissionDenied,
    /// A process has the file open for writing (one that forked while the
    /// writer was open and has not executed yet, say): fs-verity can be
    /// enabled once it is closed.
    #[error("the file is still open for writing by another process")]
    OpenForWriting,
}

pub type FsVerityResult<T> = Result<T, FsVerityError>;

/// fs-verity configuration
#[derive(Clone, Debug)]
pub struct FsVerityConfig {
    /// Hash algorithm to use
    pub hash_algorithm: FsVerityHashAlgorithm,
    /// Block size (must be power of 2, typically 4096)
    pub block_size: u32,
    /// Whether to fail if fs-verity is not supported
    pub required: bool,
}

impl Default for FsVerityConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: FsVerityHashAlgorithm::Sha256,
            block_size: 4096,
            required: false,
        }
    }
}

/// fs-verity measurement result
#[derive(Clone, Debug)]
pub struct FsVerityMeasurement {
    /// Hash algorithm used
    pub algorithm: FsVerityHashAlgorithm,
    /// The fs-verity digest
    pub digest: Vec<u8>,
}

impl FsVerityMeasurement {
    /// The name of the object with this digest (`fsverity-<alg>-12:HEX`):
    /// it is the one of the store when [`canonical_digest`] says the tree is
    /// made of blocks of 4096 bytes without a salt.
    pub fn object(&self) -> Option<Digest> {
        Digest::fsverity(self.algorithm.algorithm(), &self.digest).ok()
    }
}

impl std::fmt::Display for FsVerityMeasurement {
    /// The digest as a hex string with algorithm prefix (`sha256:HEX`, the
    /// form of `io.containers.composefs.digest`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.algorithm.name(), hex::encode(&self.digest))
    }
}

/// The Merkle tree block size for a file: `wanted` (4096 by default), or
/// the block size of its file system when that is smaller (an ext4 of 1 KiB
/// blocks refuses a bigger one with EINVAL), never more than the page size.
fn merkle_block_size(file: &File, wanted: u32) -> u32 {
    let page = u32::try_from(velarx_sys::system::page_size()).unwrap_or(4096);
    let fs = rustix::fs::fstatfs(file)
        .ok()
        .and_then(|s| u32::try_from(s.f_bsize).ok());
    block_size_for(wanted, fs, page)
}

/// [`merkle_block_size`] of the page size `page` and the block size `fs` of
/// the file system (None when it is not known).
fn block_size_for(wanted: u32, fs: Option<u32>, page: u32) -> u32 {
    let size = match fs.filter(|b| b.is_power_of_two() && *b >= 1024) {
        Some(b) if b < wanted => b,
        _ => wanted,
    };
    size.min(page)
}

/// fs-verity read metadata arguments (fsverity_read_metadata_arg)
#[repr(C)]
struct FsVerityReadMetadataArg {
    metadata_type: u64,
    offset: u64,
    length: u64,
    buf_ptr: u64,
    reserved: u64,
}

/// What a file's own fs-verity descriptor says about how its digest was
/// made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerityParameters {
    pub hash_algorithm: u8,
    /// log2 of the Merkle tree block size
    pub log_blocksize: u8,
    pub salt_size: u8,
}

impl VerityParameters {
    /// The ones of the digests that name the objects of `alg`: its hash,
    /// blocks of 4096 bytes, no salt.
    pub fn canonical(alg: Algorithm) -> Self {
        Self {
            hash_algorithm: FsVerityHashAlgorithm::of(alg) as u8,
            log_blocksize: 12,
            salt_size: 0,
        }
    }

    /// From the first bytes of the descriptor (version, hash algorithm, log
    /// of the block size, salt size); None for a version that is not 1.
    fn from_descriptor(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [1, hash_algorithm, log_blocksize, salt_size, ..] => Some(Self {
                hash_algorithm: *hash_algorithm,
                log_blocksize: *log_blocksize,
                salt_size: *salt_size,
            }),
            _ => None,
        }
    }
}

/// The parameters fs-verity was enabled on `file` with, from its descriptor
/// (FS_IOC_READ_VERITY_METADATA).
pub fn verity_parameters(file: &File) -> FsVerityResult<VerityParameters> {
    let mut buf = [0u8; 4];
    let arg = FsVerityReadMetadataArg {
        metadata_type: FS_VERITY_METADATA_TYPE_DESCRIPTOR,
        offset: 0,
        length: buf.len() as u64,
        buf_ptr: buf.as_mut_ptr() as u64,
        reserved: 0,
    };
    // (the ioctl writes at most `length` bytes to `buf_ptr`, which is `buf`)
    let ret = velarx_sys::ioctl::read_arg(file.as_fd(), FS_IOC_READ_VERITY_METADATA, &arg)
        .map_err(|err| match err.raw_os_error() {
            Some(libc::ENODATA) => FsVerityError::NotEnabled,
            Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) => FsVerityError::NotSupported,
            _ => FsVerityError::MeasureFailed(err.to_string()),
        })?;
    if ret as usize != buf.len() {
        return Err(FsVerityError::MeasureFailed("short descriptor".into()));
    }
    VerityParameters::from_descriptor(&buf)
        .ok_or_else(|| FsVerityError::MeasureFailed("unknown descriptor version".into()))
}

/// Whether the kernel's fs-verity digest of `file` is the canonical one that
/// names the objects of `alg`, by the parameters in the file's own
/// descriptor: false for another hash, a salt or Merkle blocks of another
/// size (also where the file system has smaller blocks than 4096 bytes).
pub fn canonical_digest(file: &File, alg: Algorithm) -> bool {
    verity_parameters(file).is_ok_and(|p| p == VerityParameters::canonical(alg))
}

/// The algorithm whose canonical digest the kernel's fs-verity digest of
/// `file` is, if it is the canonical one of either (a file whose digest is
/// not the name of an object has none).
pub fn canonical_algorithm(file: &File) -> Option<Algorithm> {
    let p = verity_parameters(file).ok()?;
    Algorithm::ALL
        .into_iter()
        .find(|a| p == VerityParameters::canonical(*a))
}

/// `fsverity_require` needs the kernel's fs-verity digest of a file to be
/// the one that names it (in `alg`): Err with why not when the fs-verity of
/// `file` is made otherwise, as on a file system whose blocks are smaller
/// than 4096 bytes (its Merkle tree has blocks of that size).
pub fn require_canonical(file: &File, alg: Algorithm) -> Result<(), String> {
    let canonical = VerityParameters::canonical(alg);
    match verity_parameters(file) {
        Ok(p) if p == canonical => Ok(()),
        Ok(p) if p.log_blocksize != canonical.log_blocksize => Err(format!(
            "the file system makes fs-verity with blocks of {} bytes, not the {} bytes of the digests that name the files",
            1u64 << p.log_blocksize,
            1u64 << canonical.log_blocksize
        )),
        Ok(p) if p.hash_algorithm != canonical.hash_algorithm => Err(format!(
            "the file has fs-verity with another hash than {}, the one of the digests that name the files",
            FsVerityHashAlgorithm::of(alg).label()
        )),
        Ok(_) => Err("its fs-verity digests are not those that name the files".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// What fs-verity the files of the store get.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerityMode {
    /// None.
    #[default]
    Off,
    /// Enabled where the file system has it, recorded, and checked when
    /// a file that has it is opened.
    On,
    /// Every file must have it.
    Require,
}

impl VerityMode {
    /// From `[storage] fsverity` and `fsverity_require`.
    pub fn from_config(fsverity: bool, require: bool) -> Self {
        match (fsverity, require) {
            (_, true) => VerityMode::Require,
            (true, false) => VerityMode::On,
            (false, false) => VerityMode::Off,
        }
    }

    /// The manager that enables it on committed files, if any (with the
    /// SHA-256 hash: [`FsVerityManager::for_algorithm`] has the others).
    pub fn manager(self) -> Option<FsVerityManager> {
        match self {
            VerityMode::Off => None,
            VerityMode::On => Some(FsVerityManager::with_config(FsVerityConfig::default())),
            VerityMode::Require => Some(FsVerityManager::with_config(FsVerityConfig {
                required: true,
                ..FsVerityConfig::default()
            })),
        }
    }
}

/// Whether fs-verity can be enabled on the files of `dir` (a file is made
/// there to see): Err with why not.
pub fn probe(dir: &Path) -> Result<(), String> {
    probe_algorithm(dir, Algorithm::Sha256, true)
}

/// [`probe`] for the hash of `alg`, the one the digests of the objects to
/// be made name.  `required`: a file system without fs-verity is an error
/// too; else it is not (its files get none), but one that takes fs-verity
/// without that hash is.
pub fn probe_algorithm(dir: &Path, alg: Algorithm, required: bool) -> Result<(), String> {
    use std::io::Write;
    let mut f = tempfile::Builder::new()
        .prefix(".verity-probe")
        .tempfile_in(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    f.write_all(b"probe").map_err(|e| e.to_string())?;
    let path = f.into_temp_path();
    let manager = FsVerityManager::with_config(FsVerityConfig {
        required,
        ..FsVerityConfig::default()
    })
    .for_algorithm(alg);
    manager.enable(&path).map_err(|e| e.to_string())?;
    let file = File::open(&path).map_err(|e| e.to_string())?;
    match measure_file(&file) {
        Ok(_) => {}
        Err(FsVerityError::NotEnabled | FsVerityError::NotSupported) if !required => return Ok(()),
        Err(e) => return Err(e.to_string()),
    }
    require_canonical(&file, alg)
}

/// The longest [`FsVerityManager::enable_file`] waits for the other writers
/// of a file to close it: an upper bound (a process that forked while the
/// file was open for writing holds it until it executes).
pub const WRITERS_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// The wait for the other writers of a file, which keep the kernel from
/// enabling fs-verity (ETXTBSY) until they close it: a process that forked
/// while the file was open for writing has it until it executes.  The
/// processes that hold the file share one open file, and the release of it
/// by the last of them is an event (`IN_CLOSE_WRITE`).
///
/// The kernel announces the release at its start and drops the write access
/// of the file at its end, in the same close of the same process: a try
/// between the two still finds a writer, and nothing announces the end, so
/// once the release was announced the next tries only yield to the process
/// that ends it.  The watch is made after the close of the writer of the
/// caller ([`Writers::new`]), so it can miss a release that started before
/// it: the wait ends at the deadline then, an error.
pub struct Writers {
    watch: Option<velarx_sys::watch::Watch>,
    released: bool,
    deadline: std::time::Instant,
}

impl Writers {
    /// The writers of a file whose own writer is closed already: the event
    /// is watched at the first refusal.
    pub fn new(deadline: std::time::Instant) -> Self {
        Self {
            watch: None,
            released: false,
            deadline,
        }
    }

    /// The kernel refused fs-verity on `file` for a writer: return when it
    /// may be tried again, Err(OpenForWriting) at the deadline.
    fn wait(&mut self, file: &File) -> FsVerityResult<()> {
        let now = std::time::Instant::now();
        if now >= self.deadline {
            return Err(FsVerityError::OpenForWriting);
        }
        let Some(watch) = &self.watch else {
            // (by its descriptor: the file whatever its name; tried again
            // once watched, so that a release after the watch is seen)
            let watch = velarx_sys::watch::Watch::new()?;
            let fd = velarx_sys::fd::proc_path(file);
            watch.add(&fd, rustix::fs::inotify::WatchFlags::CLOSE_WRITE)?;
            self.watch = Some(watch);
            return Ok(());
        };
        if self.released {
            std::thread::yield_now();
            return Ok(());
        }
        if !watch.wait_at_most(Some(self.deadline - now))? {
            return Err(FsVerityError::OpenForWriting);
        }
        self.released = true;
        Ok(())
    }
}

/// fs-verity manager for the file store
pub struct FsVerityManager {
    config: FsVerityConfig,
}

impl FsVerityManager {
    /// Create a new fs-verity manager with default configuration
    pub fn new() -> Self {
        Self {
            config: FsVerityConfig::default(),
        }
    }

    /// Create a new fs-verity manager with custom configuration
    pub fn with_config(config: FsVerityConfig) -> Self {
        Self { config }
    }

    /// What it was made with.
    pub fn config(&self) -> &FsVerityConfig {
        &self.config
    }

    /// The manager that is this one with the hash of `alg`: the files of a
    /// layer get the fs-verity of the algorithm of its digests.
    pub fn for_algorithm(&self, alg: Algorithm) -> Self {
        Self {
            config: FsVerityConfig {
                hash_algorithm: FsVerityHashAlgorithm::of(alg),
                ..self.config.clone()
            },
        }
    }

    /// Enable fs-verity on a file
    ///
    /// The file must be read-only (immutable) for fs-verity to be enabled.
    /// This is typically done after the file is written to the content store.
    pub fn enable(&self, path: &Path) -> FsVerityResult<()> {
        // (no is_enabled() first: the EEXIST below says it, without one more open
        // and ioctl for every new file)

        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(FsVerityError::NotFound(path.to_string_lossy().to_string()));
            }
            Err(e) => return Err(FsVerityError::Io(e)),
        };
        self.enable_file(&file, path)
    }

    /// [`enable`](Self::enable) on a file that is open read-only (and that
    /// no process has open for writing); `name` is what the logs call it.
    pub fn enable_file(&self, file: &File, name: &Path) -> FsVerityResult<()> {
        let deadline = std::time::Instant::now() + WRITERS_WAIT;
        self.enable_file_by(file, name, Writers::new(deadline))
    }

    /// [`Self::enable_file`], waiting for the other writers of the file
    /// with `writers` (see [`Writers`]).
    pub fn enable_file_by(&self, file: &File, name: &Path, writers: Writers) -> FsVerityResult<()> {
        self.enable_keeping_mode(file, name, writers)?;
        // its content cannot change now; its mode says so too
        let mut perms = file.metadata()?.permissions();
        if !perms.readonly() {
            perms.set_readonly(true);
            file.set_permissions(perms)?;
        }
        Ok(())
    }

    /// [`Self::enable_file`] without the change of mode that follows it, as
    /// [`Self::enable_keeping_mode`].
    pub fn enable_file_keeping_mode(&self, file: &File, name: &Path) -> FsVerityResult<()> {
        let deadline = std::time::Instant::now() + WRITERS_WAIT;
        self.enable_keeping_mode(file, name, Writers::new(deadline))
    }

    /// [`Self::enable_file_by`] without the change of mode that follows it:
    /// for a process that cannot change the mode of a file (a fetcher, whose
    /// seccomp filter has no `fchmod`: the engine makes the file read-only
    /// when it takes it).
    pub fn enable_keeping_mode(
        &self,
        file: &File,
        name: &Path,
        mut writers: Writers,
    ) -> FsVerityResult<()> {
        let path = name;
        // The file is made read-only after: the ioctl needs write access to
        // the inode (EACCES without, unless the caller can override it).

        let arg = FsVerityEnableArg {
            version: 1,
            hash_algorithm: self.config.hash_algorithm as u32,
            block_size: merkle_block_size(file, self.config.block_size),
            salt_size: 0,
            salt_ptr: 0,
            sig_size: 0,
            reserved1: 0,
            sig_ptr: 0,
            reserved2: [0; 11],
        };

        while let Err(err) = velarx_sys::ioctl::read_arg(file.as_fd(), FS_IOC_ENABLE_VERITY, &arg) {
            match err.raw_os_error() {
                // (the kernel lacks the hash: the file system has fs-verity)
                Some(libc::ENOPKG) => {
                    return Err(FsVerityError::AlgorithmUnavailable(
                        self.config.hash_algorithm,
                    ));
                }
                Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) => {
                    if self.config.required {
                        return Err(FsVerityError::NotSupported);
                    }
                    debug!("fs-verity not supported, skipping {:?}", path);
                    return Ok(());
                }
                Some(libc::EEXIST) => {
                    debug!("fs-verity already enabled on {:?}", path);
                    return Ok(());
                }
                Some(libc::EACCES) | Some(libc::EPERM) => {
                    return Err(FsVerityError::PermissionDenied);
                }
                // (a process has the file open for writing: until it closes it)
                Some(libc::ETXTBSY) => writers.wait(file)?,
                _ => {
                    return Err(FsVerityError::EnableFailed(err.to_string()));
                }
            }
        }

        debug!("fs-verity enabled on {:?}", path);
        Ok(())
    }
}

/// The fs-verity digest of an open file: NotEnabled when the file has no
/// fs-verity, NotSupported when its file system cannot have it.
pub fn measure_file(file: &File) -> FsVerityResult<FsVerityMeasurement> {
    let mut digest = FsVerityDigest::default();

    // (the ioctl writes at most `digest_size`, the size of `digest.digest`,
    // bytes into the struct)
    if let Err(err) = velarx_sys::ioctl::fill_arg(file.as_fd(), FS_IOC_MEASURE_VERITY, &mut digest)
    {
        match err.raw_os_error() {
            Some(libc::ENODATA) => return Err(FsVerityError::NotEnabled),
            Some(libc::EOPNOTSUPP) | Some(libc::ENOTTY) => {
                return Err(FsVerityError::NotSupported);
            }
            _ => {
                return Err(FsVerityError::MeasureFailed(err.to_string()));
            }
        }
    }

    let algorithm = match digest.digest_algorithm {
        1 => FsVerityHashAlgorithm::Sha256,
        2 => FsVerityHashAlgorithm::Sha512,
        _ => {
            return Err(FsVerityError::MeasureFailed(
                "unknown algorithm".to_string(),
            ))
        }
    };

    let digest_bytes = digest
        .digest
        .get(..usize::from(digest.digest_size))
        .ok_or_else(|| FsVerityError::MeasureFailed("invalid digest size".to_string()))?
        .to_vec();

    Ok(FsVerityMeasurement {
        algorithm,
        digest: digest_bytes,
    })
}

impl Default for FsVerityManager {
    fn default() -> Self {
        Self::new()
    }
}

const VERITY_BLOCK: usize = 4096;

/// A hash of the Merkle tree: the digest of the algorithm in the first
/// bytes (32 for SHA-256, 64 for SHA-512).
type Hash = [u8; 64];

fn hash_of(alg: Algorithm, data: &[u8]) -> Hash {
    use sha2::Digest as _;
    let mut out = [0u8; 64];
    match alg {
        Algorithm::Sha256 => out[..32].copy_from_slice(&sha2::Sha256::digest(data)),
        Algorithm::Sha512 => out.copy_from_slice(&sha2::Sha512::digest(data)),
    }
    out
}

/// The hash of a block of the tree that is all zeros, and of a block of
/// the next level made of the hashes of such blocks, level by level:
/// what a range of zeros is made of, whatever its length.
fn zero_hash(alg: Algorithm, level: usize) -> Hash {
    use std::sync::OnceLock;
    static SHA256: OnceLock<Vec<Hash>> = OnceLock::new();
    static SHA512: OnceLock<Vec<Hash>> = OnceLock::new();
    let hashes = match alg {
        Algorithm::Sha256 => &SHA256,
        Algorithm::Sha512 => &SHA512,
    };
    hashes.get_or_init(|| {
        // 4096 * 64^8 bytes is more than a file can have
        let n = alg.len();
        let fanout = VERITY_BLOCK / n;
        let mut hashes = vec![hash_of(alg, &[0u8; VERITY_BLOCK])];
        for _ in 0..8 {
            let last = hashes[hashes.len() - 1];
            hashes.push(hash_of(alg, &last[..n].repeat(fanout)));
        }
        hashes
    })[level]
}

/// The fs-verity digest (blocks of 4096 bytes, no salt) of the content fed
/// to it, in the algorithm it was made for, computed here: the one the
/// kernel measures of a file with that content and the name of an object of
/// the store (`fsverity-sha256-12:HEX` or `fsverity-sha512-12:HEX`; the
/// objects of composefs-rs are the SHA-256 ones).  A range of zeros (the
/// hole of a sparse file) is fed in time that does not depend on its length.
pub struct VerityHasher {
    alg: Algorithm,
    /// The bytes of the block in progress.
    partial: Vec<u8>,
    /// The hashes of the tree not in a full block yet: `tree[0]` those of
    /// data blocks.
    tree: Vec<Vec<u8>>,
    size: u64,
}

impl velarx_types::digest::Absorb for VerityHasher {
    fn absorb(&mut self, data: &[u8]) {
        self.update(data);
    }
}

impl VerityHasher {
    /// A hasher of the fs-verity digest with `alg`.
    pub fn new(alg: Algorithm) -> Self {
        Self {
            alg,
            partial: Vec::new(),
            tree: Vec::new(),
            size: 0,
        }
    }

    /// The hashes a block of the tree holds.
    fn fanout(&self) -> u64 {
        (VERITY_BLOCK / self.alg.len()) as u64
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.size += data.len() as u64;
        if !self.partial.is_empty() {
            let n = data.len().min(VERITY_BLOCK - self.partial.len());
            self.partial.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.partial.len() < VERITY_BLOCK {
                return;
            }
            let block = std::mem::take(&mut self.partial);
            self.push(0, hash_of(self.alg, &block));
        }
        let (blocks, rest) = data.as_chunks::<VERITY_BLOCK>();
        for block in blocks {
            self.push(0, hash_of(self.alg, block));
        }
        self.partial.extend_from_slice(rest);
    }

    /// The same as `update` with `len` bytes of zeros.
    pub fn update_zeros(&mut self, mut len: u64) {
        if !self.partial.is_empty() {
            let n = len.min((VERITY_BLOCK - self.partial.len()) as u64);
            self.update(&[0u8; VERITY_BLOCK][..n as usize]);
            len -= n;
        }
        let blocks = len / VERITY_BLOCK as u64;
        self.size += blocks * VERITY_BLOCK as u64;
        self.push_zero_hashes(0, blocks);
        let rest = (len % VERITY_BLOCK as u64) as usize;
        self.update(&[0u8; VERITY_BLOCK][..rest]);
    }

    fn push(&mut self, level: usize, hash: Hash) {
        let n = self.alg.len();
        while self.tree.len() <= level {
            self.tree.push(Vec::new());
        }
        self.tree[level].extend_from_slice(&hash[..n]);
        if self.tree[level].len() == VERITY_BLOCK {
            let up = hash_of(self.alg, &std::mem::take(&mut self.tree[level]));
            self.push(level + 1, up);
        }
    }

    /// `count` times the hash of zeros of `level`: the blocks that fill a
    /// level are one hash of the next level each.
    fn push_zero_hashes(&mut self, level: usize, mut count: u64) {
        let hash = zero_hash(self.alg, level);
        while count > 0 && self.tree.get(level).is_some_and(|t| !t.is_empty()) {
            self.push(level, hash);
            count -= 1;
        }
        let full = count / self.fanout();
        if full > 0 {
            self.push_zero_hashes(level + 1, full);
            count -= full * self.fanout();
        }
        for _ in 0..count {
            self.push(level, hash);
        }
    }

    /// The digest: the object name, `fsverity-<alg>-12:HEX`.
    pub fn finish(mut self) -> String {
        let n = self.alg.len();
        if !self.partial.is_empty() {
            let mut block = std::mem::take(&mut self.partial);
            block.resize(VERITY_BLOCK, 0);
            self.push(0, hash_of(self.alg, &block));
        }
        // The root is the hash of the block of the top level, or the one
        // hash of a single block of data.
        let mut root = [0u8; 64];
        let mut carry: Option<Hash> = None;
        for level in 0..self.tree.len() {
            let mut hashes = std::mem::take(&mut self.tree[level]);
            let above = self.tree[level + 1..].iter().any(|t| !t.is_empty());
            if hashes.len() == n && carry.is_none() && !above {
                root[..n].copy_from_slice(&hashes);
                break;
            }
            if let Some(c) = carry.take() {
                hashes.extend_from_slice(&c[..n]);
            }
            if hashes.is_empty() {
                continue;
            }
            hashes.resize(VERITY_BLOCK, 0);
            carry = Some(hash_of(self.alg, &hashes));
        }
        if let Some(c) = carry {
            root = c;
        }
        // struct fsverity_descriptor: version, hash algorithm, log of the
        // block size, salt size, 4 reserved bytes, the size of the data, the
        // root hash padded to 64 bytes, the salt (32) and 144 reserved bytes
        let mut descriptor = Vec::with_capacity(256);
        descriptor.extend_from_slice(&[1u8, FsVerityHashAlgorithm::of(self.alg) as u8, 12, 0]);
        descriptor.extend_from_slice(&[0u8; 4]);
        descriptor.extend_from_slice(&self.size.to_le_bytes());
        descriptor.extend_from_slice(&root);
        descriptor.extend_from_slice(&[0u8; 32 + 144]);
        let digest = hash_of(self.alg, &descriptor);
        object_name(self.alg, &digest[..n])
    }
}

/// The name of the object whose fs-verity digest in `alg` is `raw`.
fn object_name(alg: Algorithm, raw: &[u8]) -> String {
    Digest::fsverity(alg, raw)
        .expect("a hash has the length of its algorithm")
        .to_string()
}

/// The fs-verity digest of the content of `file` in `alg`: its holes are
/// not read, and cost nothing (`VerityHasher::update_zeros`).
pub fn fsverity_digest_file(alg: Algorithm, file: &std::fs::File) -> io::Result<String> {
    let mut hasher = VerityHasher::new(alg);
    crate::sparse::read_sparse(file, |piece| match piece {
        crate::sparse::Piece::Data(d) => hasher.update(d),
        crate::sparse::Piece::Zeros(n) => hasher.update_zeros(n),
    })?;
    Ok(hasher.finish())
}

/// The fs-verity digest of bytes in memory in `alg`.
pub fn fsverity_digest_of(alg: Algorithm, data: &[u8]) -> String {
    let mut hasher = VerityHasher::new(alg);
    hasher.update(data);
    hasher.finish()
}

/// The fs-verity digest of bytes in memory in `alg` as the annotation
/// `io.containers.composefs.digest` writes it (`sha256:HEX`, `sha512:HEX`):
/// the form of the digests of the EROFS images of layers.
pub fn composefs_digest_of(alg: Algorithm, data: &[u8]) -> String {
    Digest::parse_fsverity(&fsverity_digest_of(alg, data))
        .expect("a digest of the algorithm")
        .plain()
}

/// Whether `data` is what `digest` names: its hash in the algorithm of
/// `digest` (a chunk), or, for an fs-verity digest, its fs-verity digest in
/// that algorithm (a whole file is known by it).
pub fn digest_names(digest: &Digest, data: &[u8]) -> bool {
    match digest.is_fsverity() {
        true => fsverity_digest_of(digest.alg(), data) == digest.to_string(),
        false => digest.verify(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Merkle block size is the one asked for, or the smaller block size
    /// of the file system, never more than the page size: the same on hosts
    /// of 4, 16 and 64 KiB pages.
    #[test]
    fn the_merkle_block_size_follows_the_file_system_and_the_page() {
        for page in [4096, 16384, 65536] {
            assert_eq!(block_size_for(4096, Some(4096), page), 4096);
            assert_eq!(block_size_for(4096, None, page), 4096);
            assert_eq!(block_size_for(4096, Some(1024), page), 1024);
            assert_eq!(block_size_for(4096, Some(65536), page), 4096);
            // (not a block size: ignored)
            assert_eq!(block_size_for(4096, Some(512), page), 4096);
            assert_eq!(block_size_for(4096, Some(3000), page), 4096);
        }
        // a bigger block asked for: at most the page
        assert_eq!(block_size_for(65536, None, 4096), 4096);
        assert_eq!(block_size_for(65536, None, 16384), 16384);
        assert_eq!(block_size_for(65536, Some(65536), 65536), 65536);
        assert_eq!(block_size_for(16384, Some(4096), 65536), 4096);
    }

    #[test]
    fn the_descriptor_gives_the_parameters() {
        let canonical = [1, 1, 12, 0, 0, 0, 0, 0];
        assert_eq!(
            VerityParameters::from_descriptor(&canonical),
            Some(VerityParameters::canonical(Algorithm::Sha256))
        );
        assert_eq!(
            VerityParameters::from_descriptor(&[1, 2, 12, 0, 0, 0, 0, 0]),
            Some(VerityParameters::canonical(Algorithm::Sha512))
        );
        let salted = VerityParameters::from_descriptor(&[1, 1, 12, 4]).unwrap();
        assert_ne!(salted, VerityParameters::canonical(Algorithm::Sha256));
        assert_eq!(salted.salt_size, 4);
        let small = VerityParameters::from_descriptor(&[1, 1, 10, 0]).unwrap();
        assert_ne!(small, VerityParameters::canonical(Algorithm::Sha256));
        assert_ne!(
            VerityParameters::from_descriptor(&[1, 2, 12, 0]).unwrap(),
            VerityParameters::canonical(Algorithm::Sha256)
        );
        assert_eq!(VerityParameters::from_descriptor(&[2, 1, 12, 0]), None);
        assert_eq!(VerityParameters::from_descriptor(&[1, 1]), None);
    }

    /// With `VELARX_VERITY_DIR` on a file system with fs-verity
    /// (an ext4 made with `-O verity`, as root in a private mount
    /// namespace): the descriptor of a file tells a salt or blocks of 1 KiB
    /// from the canonical parameters, which the file system's block size
    /// does not.
    #[test]
    fn the_files_own_parameters_say_whether_its_digest_is_canonical() {
        let Ok(dir) = std::env::var("VELARX_VERITY_DIR") else {
            return;
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        let make = |name: &str, config: FsVerityConfig| {
            let path = dir.path().join(name);
            std::fs::write(&path, vec![7u8; 10_000]).unwrap();
            FsVerityManager::with_config(FsVerityConfig {
                required: true,
                ..config
            })
            .enable(&path)
            .unwrap();
            File::open(path).unwrap()
        };
        let plain = make("plain", FsVerityConfig::default());
        assert!(canonical_digest(&plain, Algorithm::Sha256));
        let small = make(
            "small",
            FsVerityConfig {
                block_size: 1024,
                ..FsVerityConfig::default()
            },
        );
        assert_eq!(verity_parameters(&small).unwrap().log_blocksize, 10);
        assert!(!canonical_digest(&small, Algorithm::Sha256));
        assert!(require_canonical(&plain, Algorithm::Sha256).is_ok());
        let why = require_canonical(&small, Algorithm::Sha256).unwrap_err();
        assert!(why.contains("blocks of 1024 bytes"), "{why}");
        let sha512 = make(
            "sha512",
            FsVerityConfig {
                hash_algorithm: FsVerityHashAlgorithm::Sha512,
                ..FsVerityConfig::default()
            },
        );
        assert!(!canonical_digest(&sha512, Algorithm::Sha256));
        assert!(canonical_digest(&sha512, Algorithm::Sha512));
        assert!(require_canonical(&sha512, Algorithm::Sha256)
            .unwrap_err()
            .contains("another hash"));
        let none = dir.path().join("none");
        std::fs::write(&none, b"x").unwrap();
        assert!(matches!(
            verity_parameters(&File::open(none).unwrap()),
            Err(FsVerityError::NotEnabled)
        ));
    }

    /// The object name composefs-rs computes of `data`.
    fn oracle(alg: Algorithm, data: &[u8]) -> String {
        use composefs::fsverity::{
            compute_verity, FsVerityHashValue, Sha256HashValue, Sha512HashValue,
        };
        let (name, hex) = match alg {
            Algorithm::Sha256 => ("sha256", compute_verity::<Sha256HashValue>(data).to_hex()),
            Algorithm::Sha512 => ("sha512", compute_verity::<Sha512HashValue>(data).to_hex()),
        };
        format!("fsverity-{name}-12:{hex}")
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) | 1)
            .collect()
    }

    /// The hasher gives what composefs-rs does, for sizes around the
    /// blocks of every level of the tree.
    #[test]
    fn the_verity_hasher_equals_composefs_rs() {
        for alg in Algorithm::ALL {
            the_verity_hasher_equals_composefs_rs_for(alg);
        }
    }

    fn the_verity_hasher_equals_composefs_rs_for(alg: Algorithm) {
        let b = VERITY_BLOCK;
        // (a block of the tree holds 128 SHA-256 hashes or 64 SHA-512 ones)
        let fanout = 4096 / alg.len();
        for len in [
            0,
            1,
            b - 1,
            b,
            b + 1,
            2 * b,
            fanout * b - 1,
            fanout * b,
            fanout * b + 1,
            (fanout + 1) * b,
            (fanout + 2) * b + 7,
            2 * fanout * b,
            fanout * fanout * b + 1,
        ] {
            let data = pattern(len, 3);
            let mut h = VerityHasher::new(alg);
            // odd pieces: the blocks do not line up with the writes
            for piece in data.chunks(1000) {
                h.update(piece);
            }
            assert_eq!(h.finish(), oracle(alg, &data), "{alg} {len} bytes");
        }
    }

    /// Zeros fed as a range give the digest of the zeros fed as data, at
    /// every alignment, and a range needs no data: ranges split anywhere
    /// give the same digest.
    #[test]
    fn ranges_of_zeros_equal_zeros() {
        for alg in Algorithm::ALL {
            ranges_of_zeros_equal_zeros_for(alg);
        }
    }

    fn ranges_of_zeros_equal_zeros_for(alg: Algorithm) {
        let b = VERITY_BLOCK as u64;
        let f = (4096 / alg.len()) as u64;
        let lens = [
            0,
            1,
            b - 1,
            b,
            b + 1,
            (f - 1) * b,
            f * b,
            f * b + 5,
            (f + 1) * b + 4095,
        ];
        for head in [0usize, 1, 4095, 4096, 5000] {
            for len in lens {
                for tail in [0usize, 3, 4096] {
                    let mut dense = pattern(head, 1);
                    dense.resize(head + len as usize, 0);
                    dense.extend(pattern(tail, 2));
                    let mut h = VerityHasher::new(alg);
                    h.update(&pattern(head, 1));
                    h.update_zeros(len);
                    h.update(&pattern(tail, 2));
                    assert_eq!(h.finish(), oracle(alg, &dense), "{alg} {head} {len} {tail}");
                }
            }
        }
        // the blocks of two levels and one more: the third level of the tree
        let len = f * f * b + b + 1;
        let mut h = VerityHasher::new(alg);
        h.update_zeros(len);
        assert_eq!(h.finish(), oracle(alg, &vec![0u8; len as usize]));
        // a hole of 8 TiB takes no time, and is the same in pieces
        let (mut whole, mut pieces) = (VerityHasher::new(alg), VerityHasher::new(alg));
        whole.update(b"x");
        whole.update_zeros(8 << 40);
        pieces.update(b"x");
        for n in [1u64, 4095, 1 << 30, (8 << 40) - 4096 - (1 << 30)] {
            pieces.update_zeros(n);
        }
        assert_eq!(whole.finish(), pieces.finish());
    }

    /// Random mixes of data and ranges of zeros, in random pieces, give
    /// what composefs-rs computes of the same bytes.
    #[test]
    fn random_mixes_of_data_and_zeros_equal_composefs_rs() {
        // (a small generator: the cases are the same at every run)
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % bound
        };
        for round in 0..200 {
            let alg = Algorithm::ALL[round % 2];
            let mut h = VerityHasher::new(alg);
            let mut dense = Vec::new();
            for _ in 0..next(6) {
                let len = match next(4) {
                    0 => next(16),
                    1 => next(2 * VERITY_BLOCK as u64),
                    2 => next(200 * VERITY_BLOCK as u64),
                    _ => VERITY_BLOCK as u64 * next(300),
                } as usize;
                if next(2) == 0 {
                    let data = pattern(len, next(256) as u8);
                    for piece in data.chunks(1 + next(9000) as usize) {
                        h.update(piece);
                    }
                    dense.extend(data);
                } else {
                    h.update_zeros(len as u64);
                    dense.resize(dense.len() + len, 0);
                }
            }
            assert_eq!(
                h.finish(),
                oracle(alg, &dense),
                "{alg} {} bytes",
                dense.len()
            );
        }
    }

    fn measure_path(path: &Path) -> FsVerityResult<FsVerityMeasurement> {
        measure_file(&File::open(path)?)
    }

    /// On a file system with fs-verity (VELARX_VERITY_DIR, e.g. an ext4
    /// made with `-O verity`): files are measured with both algorithms,
    /// SHA-512 included (64 bytes, which the buffer must hold).
    #[test]
    fn measures_on_a_verity_filesystem() {
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        for (algorithm, size) in [
            (FsVerityHashAlgorithm::Sha256, 32),
            (FsVerityHashAlgorithm::Sha512, 64),
        ] {
            let path = dir.path().join(algorithm.name());
            std::fs::write(&path, b"content of the file").unwrap();
            let m = FsVerityManager::with_config(FsVerityConfig {
                hash_algorithm: algorithm,
                ..FsVerityConfig::default()
            });
            assert!(measure_path(&path).is_err());
            m.enable(&path).unwrap();
            let measured = measure_path(&path).unwrap();
            assert_eq!(measured.algorithm, algorithm);
            assert_eq!(measured.digest.len(), size);
            // the same content measures the same
            let again = dir.path().join(format!("{}-again", algorithm.name()));
            std::fs::write(&again, b"content of the file").unwrap();
            m.enable(&again).unwrap();
            assert_eq!(measure_path(&again).unwrap().digest, measured.digest);
        }
    }

    /// The digest computed here does not depend on how the content is cut,
    /// is the one of composefs-rs, and the kernel's where there is fs-verity.
    #[test]
    fn computed_digests_are_the_ones_of_the_kernel() {
        let sizes = [
            0usize,
            1,
            4095,
            4096,
            4097,
            128 * 4096,
            128 * 4096 + 1,
            3 << 20,
        ];
        let content = |n: usize| -> Vec<u8> { (0..n).map(|i| (i * 31 % 251) as u8).collect() };
        for (alg, n) in Algorithm::ALL
            .into_iter()
            .flat_map(|a| sizes.map(|n| (a, n)))
        {
            let data = content(n);
            let whole = fsverity_digest_of(alg, &data);
            let mut hasher = VerityHasher::new(alg);
            for chunk in data.chunks(1237) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finish(), whole, "{alg} {n} bytes");
            let mut file = tempfile::tempfile().unwrap();
            io::Write::write_all(&mut file, &data).unwrap();
            assert_eq!(fsverity_digest_file(alg, &file).unwrap(), whole);
            assert_eq!(whole, oracle(alg, &data));
        }
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: the kernel's digest is not compared");
            return;
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        for (alg, n) in Algorithm::ALL
            .into_iter()
            .flat_map(|a| sizes.map(|n| (a, n)))
        {
            let m = FsVerityManager::with_config(FsVerityConfig::default()).for_algorithm(alg);
            let path = dir.path().join(format!("{alg}-{n}"));
            std::fs::write(&path, content(n)).unwrap();
            if m.enable(&path).is_err() {
                continue;
            }
            assert_eq!(
                measure_path(&path).unwrap().object().unwrap().to_string(),
                fsverity_digest_of(alg, &content(n)),
                "{alg} {n} bytes"
            );
        }
    }

    /// A process that holds the file open for writing (a fork of another
    /// thread before it executes) keeps fs-verity from being enabled: it is
    /// enabled once that process lets go; it is an error at the deadline while
    /// the process keeps it.
    #[test]
    fn fs_verity_waits_for_the_other_writers_of_the_file() {
        use std::os::fd::OwnedFd;
        use std::time::{Duration, Instant};
        let Some(dir) = std::env::var_os("VELARX_VERITY_DIR") else {
            eprintln!("VELARX_VERITY_DIR not set: skipped");
            return;
        };
        let dir = tempfile::tempdir_in(dir).unwrap();
        let m = FsVerityManager::with_config(FsVerityConfig::default());
        let held = |name: &str| {
            let path = dir.path().join(name);
            let writer = File::create(&path).unwrap();
            io::Write::write_all(&mut &writer, b"content").unwrap();
            let holder = std::process::Command::new("sleep")
                .arg("600")
                .stdin(OwnedFd::from(writer.try_clone().unwrap()))
                .spawn()
                .unwrap();
            (path, writer, holder)
        };
        let later = || Instant::now() + Duration::from_secs(120);
        let (path, writer, mut holder) = held("released");
        let writers = Writers::new(later());
        drop(writer);
        let ro = File::open(&path).unwrap();
        let (m2, ro2, p2) = (m.config.clone(), ro.try_clone().unwrap(), path.clone());
        let done = std::thread::spawn(move || {
            FsVerityManager::with_config(m2).enable_file_by(&ro2, &p2, writers)
        });
        // (the holder lives: the file cannot have fs-verity yet)
        assert!(matches!(measure_file(&ro), Err(FsVerityError::NotEnabled)));
        holder.kill().unwrap();
        holder.wait().unwrap();
        done.join().unwrap().unwrap();
        assert_eq!(
            measure_file(&ro).unwrap().object().unwrap().to_string(),
            fsverity_digest_of(Algorithm::Sha256, b"content")
        );
        let (path, writer, mut holder) = held("kept");
        drop(writer);
        let ro = File::open(&path).unwrap();
        let e = m.enable_file_by(&ro, &path, Writers::new(Instant::now()));
        assert!(matches!(e, Err(FsVerityError::OpenForWriting)), "{e:?}");
        holder.kill().unwrap();
        holder.wait().unwrap();
    }

    /// A sparse file has the digest of its content, holes read as zeros:
    /// the one of composefs-rs, and the kernel's where there is fs-verity.
    #[test]
    fn sparse_files_have_the_digest_of_their_content() {
        use std::os::unix::fs::FileExt;
        const B: u64 = 4096;
        let x = |n: usize| -> Vec<u8> { (0..n).map(|i| (i * 7 % 251 + 1) as u8).collect() };
        // (the size, and the bytes written where: the rest is a hole)
        type Case = (&'static str, u64, Vec<(u64, Vec<u8>)>);
        let cases: Vec<Case> = vec![
            ("empty", 0, vec![]),
            ("zeros, less than a block", 100, vec![]),
            ("zeros", 5 << 20, vec![]),
            ("hole at the start", 4 * B + 100, vec![(2 * B + 7, x(5000))]),
            (
                "hole in the middle",
                (1 << 20) + 10,
                vec![(0, x(5000)), ((1 << 20) + 3, x(7))],
            ),
            ("hole at the end", 2 << 20, vec![(0, x(5000))]),
            (
                "hole of one block",
                3 * B,
                vec![(0, x(B as usize)), (2 * B, x(B as usize))],
            ),
            (
                "tail of less than a block",
                3 * B + 100,
                vec![(0, x(10)), (3 * B, x(100))],
            ),
            ("hole in the tail", B + 100, vec![(0, x(B as usize))]),
            (
                "two levels of hole",
                66 << 20,
                vec![(33 << 20, x(3)), ((66 << 20) - 1, x(1))],
            ),
        ];
        let dir = std::env::var_os("VELARX_VERITY_DIR");
        let dir = match &dir {
            Some(d) => tempfile::tempdir_in(d).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let m = FsVerityManager::with_config(FsVerityConfig::default());
        for (name, size, writes) in cases {
            let path = dir.path().join(name);
            let file = std::fs::File::create(&path).unwrap();
            file.set_len(size).unwrap();
            let mut data = vec![0u8; size as usize];
            for (at, bytes) in &writes {
                file.write_all_at(bytes, *at).unwrap();
                data[*at as usize..*at as usize + bytes.len()].copy_from_slice(bytes);
            }
            drop(file);
            let file = std::fs::File::open(&path).unwrap();
            for alg in Algorithm::ALL {
                let want = fsverity_digest_of(alg, &data);
                assert_eq!(want, oracle(alg, &data), "{name}");
                assert_eq!(fsverity_digest_file(alg, &file).unwrap(), want, "{name}");
            }
            drop(file);
            if std::env::var_os("VELARX_VERITY_DIR").is_some() {
                m.enable(&path).unwrap();
                assert_eq!(
                    measure_path(&path).unwrap().object().unwrap().to_string(),
                    fsverity_digest_of(Algorithm::Sha256, &data),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn test_fsverity_config_default() {
        let config = FsVerityConfig::default();
        assert_eq!(config.hash_algorithm, FsVerityHashAlgorithm::Sha256);
        assert_eq!(config.block_size, 4096);
        assert!(!config.required);
    }

    #[test]
    fn test_hash_algorithm_name() {
        assert_eq!(FsVerityHashAlgorithm::Sha256.name(), "sha256");
        assert_eq!(FsVerityHashAlgorithm::Sha512.name(), "sha512");
    }

    #[test]
    fn test_fsverity_measurement_to_string() {
        let measurement = FsVerityMeasurement {
            algorithm: FsVerityHashAlgorithm::Sha256,
            digest: vec![0xab, 0xcd, 0xef],
        };
        assert_eq!(measurement.to_string(), "sha256:abcdef");
        // (not a digest of the algorithm: no object)
        assert!(measurement.object().is_none());
    }

    /// The object of a measurement is named by the algorithm of the hash
    /// and the digest of its length: one of each kind, never the other's.
    #[test]
    fn a_measurement_names_the_object_of_its_algorithm() {
        for (hash, len) in [
            (FsVerityHashAlgorithm::Sha256, 32),
            (FsVerityHashAlgorithm::Sha512, 64),
        ] {
            let measurement = FsVerityMeasurement {
                algorithm: hash,
                digest: vec![0xab; len],
            };
            let object = measurement.object().unwrap().to_string();
            assert_eq!(
                object,
                format!("fsverity-{}-12:{}", hash.name(), "ab".repeat(len))
            );
            assert_eq!(
                measurement.to_string(),
                format!("{}:{}", hash.name(), "ab".repeat(len))
            );
        }
        let wrong = FsVerityMeasurement {
            algorithm: FsVerityHashAlgorithm::Sha512,
            digest: vec![0xab; 32],
        };
        assert!(wrong.object().is_none());
    }

    #[test]
    fn test_fsverity_manager_not_found() {
        let manager = FsVerityManager::new();
        let result = manager.enable(Path::new("/nonexistent/file"));
        assert!(matches!(result, Err(FsVerityError::NotFound(_))));
    }

    #[test]
    fn test_fsverity_enable_arg_default() {
        let arg = FsVerityEnableArg::default();
        assert_eq!(arg.version, 1);
        assert_eq!(arg.hash_algorithm, 1); // SHA256
                                           // (a kernel without the hash: the error names it)
        let e = FsVerityError::AlgorithmUnavailable(FsVerityHashAlgorithm::Sha512).to_string();
        assert!(
            e.starts_with("fs-verity with SHA-512 is not available here"),
            "{e}"
        );
        let manager = FsVerityManager::new().for_algorithm(Algorithm::Sha512);
        assert_eq!(
            manager.config().hash_algorithm,
            FsVerityHashAlgorithm::Sha512
        );
        assert_eq!(manager.config().block_size, 4096);
        assert_eq!(arg.block_size, 4096);
    }
}
