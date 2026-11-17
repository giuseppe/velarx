// SPDX-License-Identifier: Apache-2.0
//! The commit of a layer: the files its staging holds are checked and given
//! their names in the store.  The one routine for every producer of files:
//! the staging of a layer a fetcher wrote (an eager or a lazy pull), and the
//! session of a pull or a build the engine wrote itself
//! ([`super::session::Session::commit`]).
//!
//! A commit has two parts.  [`verify_layers`] is the staging phase: every
//! file is verified, once, after it was completely written to its staging
//! (by the kernel's measure of its fs-verity digest where the file system has
//! one, else by one read of its bytes: an implementation detail of the one
//! check), and so is the staged image of a layer.  It needs no lock and
//! names nothing.  [`commit_verified`] is the part that runs under the locks
//! of the store: one `syncfs` of the staging file system, which makes all of
//! it durable (one barrier when `[storage] sync` asks), the names (a file
//! is linked into the store by its inode through [`Place`], the operation of
//! the storage driver that keeps it: no copy, no second write, whatever the
//! store's fs-verity; the staged images are renamed), and one `syncfs` of
//! the store.  It reads no content, hashes nothing and copies nothing.
//! Nothing has its name in the store before its bytes are on the disk.  A
//! failed barrier fails the commit.  [`commit_layer`] is the two in a row,
//! for a caller that holds no lock.
//!
//! The one copy that is left is a file of a staging in another file system
//! than the store's, which cannot be linked: it is copied under no name,
//! checked as it is copied, before the locked part.
//!
//! Each file is opened beneath its staging directory (`openat2` with
//! `RESOLVE_BENEATH`, no symlinks, no magic links, no crossing of a mount),
//! checked to be a regular file of the engine's user with one name and the
//! size expected, made
//! read-only, and measured (fs-verity is enabled on it first where the store
//! has it and the producer did not; a file a producer still has open for
//! writing is then refused); then what it claims is checked:
//!
//! * [`Check::Verity`]: the table of contents gives the fs-verity digest of
//!   the file.  The kernel's measure must be that digest; no byte of the
//!   file is read.
//! * [`Check::Content`]: only the content digest is known.  The file is
//!   read once, its digest must be that (unless a replay proved the
//!   measure it must have); the object is named by the measure.
//! * [`Check::Engine`]: the engine wrote the file and proves it otherwise
//!   (the diff id of the stream it was read from): named by its measure.
//!
//! A file is hashed once: by the kernel (fs-verity), or by one read of its
//! bytes where the kernel does not measure it (which also computes its
//! fs-verity digest, the name it is given); a file of the engine's that was
//! hashed as it was written is read not at all.  Without fs-verity nothing
//! keeps a producer that held a writable descriptor from changing a linked
//! file after the check (THREAT-MODEL, "A store without fs-verity").
//!
//! Nothing is named by its digest before that check and the measure.  The
//! file is then linked into the store with the descriptor that was measured
//! (never by a name a producer could replace), and a name the store has
//! already is left as it is.  A file that is missing or wrong is reported
//! and its name in the staging removed: the caller asks for it again, or
//! fails.

use rayon::prelude::*;
use rustix::fs::{linkat, renameat, unlinkat, AtFlags, Mode, OFlags, ResolveFlags, CWD};
use rustix::io::Errno;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, warn};
use velarx_storage::{
    measure_file, FileStore, FsVerityHashAlgorithm, FsVerityManager, Object, VerityHasher,
};
use velarx_types::digest::{Algorithm, Digest};

/// What a staged file must be shown to be before it is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// The kernel's measure must be this fs-verity digest
    Verity(String),
    /// The digest of its content must be the key of the file, or, when a
    /// replay read it and proved its fs-verity digest, its measure must be
    /// that one
    Content(Option<String>),
    /// The engine wrote it and proves it by other means: named by its
    /// measure
    Engine,
    /// The engine, which a driver trusts to have checked it, handed the file
    /// over with this fs-verity digest ([`verify_file`]): the file is named
    /// by it with no read of its bytes (the kernel's measure, where there is
    /// one, must be it)
    Verified(String),
}

/// A file the layer must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    /// What the file is known by (an OCI digest or an fs-verity digest)
    pub key: String,
    /// The algorithm of the key, and of the file's fs-verity digest
    pub alg: Algorithm,
    /// Its path below the staging directory
    pub rel: String,
    /// The size the table gives, when it is known
    pub size: Option<u64>,
    pub check: Check,
    /// The engine wrote the file itself, in a directory no producer can
    /// reach: nobody else holds its inode, so it is linked as it is, named
    /// by the digest it was written with (or read once to have one), never
    /// copied
    pub own: bool,
}

impl Want {
    /// A file of a fetcher's staging known by its fs-verity digest: staged
    /// as `ab/cdef...` of that digest.
    pub fn by_verity(digest: &Digest, size: Option<u64>) -> Self {
        Self {
            key: digest.to_string(),
            alg: digest.alg(),
            rel: rel_of(digest),
            size,
            check: Check::Verity(digest.to_string()),
            own: false,
        }
    }

    /// A file of a fetcher's staging known by the digest of its content.
    pub fn by_content(digest: &Digest, size: Option<u64>) -> Self {
        Self {
            key: digest.to_string(),
            alg: digest.alg(),
            rel: rel_of(digest),
            size,
            check: Check::Content(None),
            own: false,
        }
    }
}

/// The path of a file a fetcher staged, below the directory of the layer's
/// files: `ab/cdef...` of the hex of its digest.
pub fn rel_of(digest: &Digest) -> String {
    let hex = digest.hex();
    format!("{}/{}", &hex[..2], &hex[2..])
}

/// Why a file is not given its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The staging does not have it
    Missing,
    /// It is there and is not what its name says, or not a plain file
    /// (its name in the staging is removed, so that the next try fetches it
    /// again instead of meeting it)
    Wrong(String),
}

/// What the link step did with the files of one staging.
#[derive(Debug, Default)]
pub struct Linked {
    /// For each `Want` that is in the store now (index in the call): its
    /// object, `checked` when the kernel measured it
    pub objects: Vec<(usize, Object)>,
    /// Of those, the ones the store had already
    pub present: Vec<usize>,
    /// The ones that are not in the store
    pub refused: Vec<(usize, Refusal)>,
    /// What became of the layer's staged EROFS image (none asked for: none)
    pub image: Option<ImageStep>,
}

/// The EROFS image and index a lazy pull made for a layer while it was
/// staged, kept beside its staging (the stand-in for the store's `objects/`:
/// [`super::staged::Staging::objects_stand_in`]).
pub struct StagedImage<'a> {
    /// The stand-in `objects` directory of the staging area
    pub objects: &'a Path,
    /// The name of the layer ([`velarx_db::LayerKey::file_stem`])
    pub stem: &'a str,
    /// The algorithm of the layer's key, the one of the image's digest
    pub alg: velarx_types::digest::Algorithm,
    /// The fs-verity digest of the image the pull recorded for the layer
    pub recorded: &'a str,
}

/// What the commit did with the staged image of a layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageStep {
    /// Renamed into the store: the same bytes, so the containers that run
    /// on the staged one keep their mounts
    Moved,
    /// There is none (the layer's check makes it again)
    Missing,
    /// It is not the one the pull recorded
    Wrong,
}

/// What runs between the link step of a commit and the barrier of the store
/// ([`commit_layer`]).
pub type AfterLink<'a> = dyn FnMut(&[Linked]) -> io::Result<bool> + 'a;

/// The files of one staging directory to commit.
pub struct Staging<'a> {
    /// The directory the `rel` of each want is below
    pub dir: &'a Path,
    pub wants: Vec<Want>,
    /// The layer's image staged beside the files, renamed into the store
    /// with them (inside the same two barriers) once they are linked
    pub image: Option<StagedImage<'a>>,
}

/// Commit the files of `stagings` into `store` ([`verify_layers`], then
/// [`commit_verified`]): every file is opened, checked and verified, in
/// parallel and once; then one barrier of the staging file system (every
/// staging is on it), which makes all of it durable; then the links of the
/// same inodes (nothing has a name in the store before its bytes are
/// durable), `after_link`, and one barrier of the store.
///
/// `verity` is the fs-verity the store has: enabled on a file before it is
/// named; it is an error where the mode requires what is not possible.  A
/// staging directory that does not exist has every file missing.  The staged
/// image of a layer, when given, is checked against the digest recorded for
/// it and renamed into the store after its files are linked, before the
/// barrier of the store: it is made durable by it, not by a barrier of its
/// own.  `after_link` runs once every file is linked, before the barrier of
/// the store: what it writes in the store (the images of the layers) is made
/// durable by that barrier, which it asks for by returning `true` (it is
/// taken when files were linked too); its error ends the commit before the
/// barrier.  The barrier's own error ends it too: nothing is reported as
/// committed that is not on the disk.
pub fn commit_layer(
    stagings: &[Staging<'_>],
    store: &FileStore,
    verity: Option<&FsVerityManager>,
    after_link: Option<&mut AfterLink<'_>>,
) -> io::Result<Vec<Linked>> {
    let verified = verify_layers(stagings, store, verity)?;
    commit_verified(stagings, verified, store, after_link)
}

/// The files of some stagings, verified: what [`verify_layers`] gives
/// [`commit_verified`].
pub struct Verified {
    dirs: Vec<Option<File>>,
    prepared: Vec<Vec<Prepared>>,
    /// What the check of each staging's image found
    images: Vec<Option<ImageChecked>>,
    copies: CopyBudget,
}

/// The staging phase of a commit: every file of every staging is opened,
/// checked and verified (once: by the kernel's measure of its fs-verity
/// digest where the file system has one, else by one read of its bytes), in
/// parallel, and so is the staged image of a layer.  Nothing is named and
/// nothing is written, and no lock of the store is needed: the reads and
/// hashes of a commit are all here, so that the locked sections that follow
/// ([`commit_verified`]) only link, rename and sync.
pub fn verify_layers(
    stagings: &[Staging<'_>],
    store: &FileStore,
    verity: Option<&FsVerityManager>,
) -> io::Result<Verified> {
    let mut dirs = Vec::with_capacity(stagings.len());
    for staging in stagings {
        // (no directory: every file is missing; the image still moves, and
        // the staging area it is in is what the barrier syncs)
        // (a directory itself, never what a link of a producer points to)
        dirs.push(
            match rustix::fs::open(
                staging.dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(dir) => Some(File::from(dir)),
                Err(Errno::NOENT) => None,
                Err(e) => return Err(e.into()),
            },
        );
    }
    let store_dev = std::fs::metadata(store.root())?.dev();
    let copies = CopyBudget::new();
    let mut prepared = Vec::with_capacity(stagings.len());
    let mut images = Vec::with_capacity(stagings.len());
    for (staging, dir) in stagings.iter().zip(&dirs) {
        prepared.push(match dir {
            Some(dir) => prepare_files(
                dir.as_fd(),
                &staging.wants,
                (store, store_dev),
                verity,
                &copies,
            )?,
            None => staging.wants.iter().map(|_| missing()).collect(),
        });
        images.push(
            staging
                .image
                .as_ref()
                .map(|image| check_image(image, store))
                .transpose()?,
        );
    }
    Ok(Verified {
        dirs,
        prepared,
        images,
        copies,
    })
}

/// The locked part of a commit: one barrier of the staging file system
/// (which makes the files verified by [`verify_layers`] durable), the names
/// (links by inode, and the renames of the staged images), `after_link`, and
/// one barrier of the store.  It reads no content, hashes nothing and copies
/// nothing: what it does is link, rename and sync, whatever the file system
/// and whatever the stores' fs-verity.
pub fn commit_verified(
    stagings: &[Staging<'_>],
    verified: Verified,
    store: &FileStore,
    after_link: Option<&mut AfterLink<'_>>,
) -> io::Result<Vec<Linked>> {
    let started = std::time::Instant::now();
    let Verified {
        dirs,
        prepared,
        images,
        copies,
    } = verified;
    let store_dev = std::fs::metadata(store.root())?.dev();
    // the first staging that has anything to make durable: the barrier of its
    // file system is the barrier of them all
    let target =
        stagings
            .iter()
            .zip(&dirs)
            .find_map(|(staging, dir)| match (dir, &staging.image) {
                (Some(_), _) if !staging.wants.is_empty() || staging.image.is_some() => {
                    Some(staging.dir)
                }
                (None, Some(image)) => Some(image.objects.parent().unwrap_or(image.objects)),
                _ => None,
            });
    if let Some(target) = target {
        store.barrier(target)?;
        // (the copies are in the store's file system)
        if copies.held() > 0 && std::fs::metadata(target)?.dev() != store_dev {
            store.barrier(store.root())?;
        }
    }
    let mut done = Vec::with_capacity(stagings.len());
    for (((staging, dir), prepared), image_checked) in
        stagings.iter().zip(&dirs).zip(prepared).zip(images)
    {
        let mut linked = match dir {
            Some(dir) => place_files(dir.as_fd(), prepared, store)?,
            None => Linked {
                refused: (0..staging.wants.len())
                    .map(|i| (i, Refusal::Missing))
                    .collect(),
                ..Linked::default()
            },
        };
        if let (Some(image), Some(checked)) = (&staging.image, image_checked) {
            linked.image = Some(adopt_image(image, checked, store)?);
        }
        done.push(linked);
    }
    let wrote = match after_link {
        Some(after) => after(&done)?,
        None => false,
    };
    if target.is_some() || wrote {
        // the names are on disk before the rows that rely on them
        store.barrier(store.root())?;
    }
    debug!(
        "commit of {} files took {:?}",
        stagings.iter().map(|s| s.wants.len()).sum::<usize>(),
        started.elapsed()
    );
    Ok(done)
}

/// The digest of the EROFS image at `path` in `alg`, in the form the layer
/// records it: the kernel's measure when the file has fs-verity (nothing is
/// read), else the digest of its content read in blocks.
fn image_digest(path: &Path, alg: Algorithm, store: &FileStore) -> io::Result<String> {
    use std::io::Read;
    let mut file = File::open(path)?;
    let verity = match measure(&file, alg) {
        Some(measured) => measured,
        None => {
            let mut hasher = VerityHasher::new(alg);
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                store.note_hashed(n);
                hasher.update(&buf[..n]);
            }
            hasher.finish()
        }
    };
    Digest::parse_fsverity(&verity)
        .map(|d| d.plain())
        .map_err(io::Error::other)
}

/// What the check of a layer's staged image found ([`check_image`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageChecked {
    /// It is the recorded one, still staged (to be renamed) or already in
    /// the store (renamed by an earlier commit that stopped)
    Right { staged: bool },
    /// It is not the one the pull recorded
    Wrong,
    /// There is none
    Missing,
}

/// Check the staged image of a layer against the digest recorded for it
/// (what the staging area keeps is not believed): the one read of its
/// bytes, where the file system has no fs-verity, which is done before the
/// commit is locked.  An image already in the store (renamed by a commit that
/// stopped before it was recorded, or a replay that failed) is checked there.
fn check_image(image: &StagedImage<'_>, store: &FileStore) -> io::Result<ImageChecked> {
    use velarx_fuse::composefs::layer_image_path;
    let staged_at = layer_image_path(image.objects, image.stem);
    let staged = staged_at.is_file();
    let at = if staged {
        staged_at
    } else {
        layer_image_path(store.root(), image.stem)
    };
    if !at.is_file() {
        return Ok(ImageChecked::Missing);
    }
    if image_digest(&at, image.alg, store)? != image.recorded {
        return Ok(if staged {
            ImageChecked::Wrong
        } else {
            ImageChecked::Missing
        });
    }
    Ok(ImageChecked::Right { staged })
}

/// Rename the staged image and index of a layer into the store, when the
/// image is the one that was recorded ([`check_image`]).  Each file moves by
/// itself, so a commit that stopped between the two renames is finished by
/// the next try: the index that is still staged moves.
fn adopt_image(
    image: &StagedImage<'_>,
    checked: ImageChecked,
    store: &FileStore,
) -> io::Result<ImageStep> {
    use velarx_fuse::composefs::{layer_image_path, layer_index_path};
    match checked {
        ImageChecked::Missing => return Ok(ImageStep::Missing),
        ImageChecked::Wrong => return Ok(ImageStep::Wrong),
        ImageChecked::Right { .. } => {}
    }
    let moves = [
        (
            layer_image_path(image.objects, image.stem),
            layer_image_path(store.root(), image.stem),
        ),
        (
            layer_index_path(image.objects, image.stem),
            layer_index_path(store.root(), image.stem),
        ),
    ];
    for (from, to) in &moves {
        if from.is_file() {
            if let Some(dir) = to.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::rename(from, to)?;
        } else if !to.is_file() {
            return Ok(ImageStep::Missing);
        }
    }
    Ok(ImageStep::Moved)
}

/// Remove the name `rel` of `dir` when it is still the inode `was`.
fn drop_name(dir: BorrowedFd<'_>, rel: &str, was: &std::fs::Metadata) {
    let same = rustix::fs::statat(dir, rel, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|now| (now.st_dev, now.st_ino) == (was.dev(), was.ino()));
    if same {
        let _ = unlinkat(dir, rel, AtFlags::empty());
    }
}

fn storage_error(store: &FileStore, what: String) -> io::Error {
    io::Error::other(format!("{}: {what}", store.root().display()))
}

/// The object the store has under `verity`, `checked` when the kernel
/// measures it as its name; none when `verify` and it is not (it is replaced
/// by the file that is).
fn present(store: &FileStore, verity: &str, verify: bool) -> Option<Object> {
    let unchecked = Object::new(verity, false)?;
    let checked = File::open(store.object_path(&unchecked))
        .ok()
        .and_then(|f| measure_file(&f).ok())
        .and_then(|m| m.object())
        .is_some_and(|o| o.to_string() == verity);
    if verify && !checked {
        return None;
    }
    Object::new(verity, checked)
}

/// The kernel's measure of `file` in `alg`, of the canonical block size.
pub(super) fn measure(file: &File, alg: Algorithm) -> Option<String> {
    measure_file(file)
        .ok()
        .filter(|m| m.algorithm == FsVerityHashAlgorithm::of(alg))
        .filter(|_| velarx_storage::canonical_digest(file, alg))
        .and_then(|m| m.object())
        .map(|o| o.to_string())
}

/// Whether the content of a file known by its digest has to be read by the
/// commit: not when a replay read it and the kernel's measure now is the
/// one it had then (the file is immutable); an error when it is another.
fn content_read(replayed: Option<&str>, measured: Option<&str>) -> Result<bool, &'static str> {
    match (replayed, measured) {
        (Some(r), Some(m)) if r == m => Ok(false),
        (Some(_), Some(_)) => Err("not the content a replay read"),
        _ => Ok(true),
    }
}

/// How many copies of files this process holds open at once, for all its
/// commits (each is a descriptor until its link): the others are made
/// durable one by one and named at once, which is as safe and slower (one
/// `fdatasync` for each file).  One pool for the process, not one for each
/// commit: lazy completions, the pulls of other clients and the image
/// servers' connections of one engine service commit at the same time, and
/// their copies together must leave descriptors for the `O_TMPFILE` and the
/// `accept` that follow.
struct Pool {
    left: std::sync::atomic::AtomicUsize,
}

/// The copies the process may hold for a soft limit of `open` descriptors: a
/// quarter of it, and always the 256 descriptors the rest of the process
/// needs.
fn places_for(open: u64) -> usize {
    let open = usize::try_from(open).unwrap_or(1024);
    (open / 4).min(open.saturating_sub(256)).min(16 << 10)
}

static COPIES: std::sync::LazyLock<Arc<Pool>> = std::sync::LazyLock::new(|| {
    let open = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(1024);
    Arc::new(Pool {
        left: places_for(open).into(),
    })
});

/// The places a commit took from a pool of copies: given back when it ends.
struct CopyBudget {
    pool: Arc<Pool>,
    held: std::sync::atomic::AtomicUsize,
}

impl CopyBudget {
    /// A commit of this process: it takes its places from the pool of the
    /// process.
    fn new() -> Self {
        Self::from(COPIES.clone())
    }

    /// A budget of its own, of `places` (a test's).
    #[cfg(test)]
    fn of(places: usize) -> Self {
        Self::from(Arc::new(Pool {
            left: places.into(),
        }))
    }

    fn from(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            held: 0.into(),
        }
    }

    /// Take one place; whether there was one.
    fn take(&self) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let taken = self
            .pool
            .left
            .try_update(Relaxed, Relaxed, |n| n.checked_sub(1))
            .is_ok();
        if taken {
            self.held.fetch_add(1, Relaxed);
        }
        taken
    }

    fn held(&self) -> usize {
        self.held.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for CopyBudget {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.pool.left.fetch_add(self.held.load(Relaxed), Relaxed);
    }
}

/// A file checked and ready to be given its name once the barrier has made
/// its bytes durable.
enum Prepared {
    Done(Step),
    /// The staged file itself, opened again by its name when it is linked
    /// (no descriptor is kept for each of 100,000 files): it must still be
    /// the inode that was checked
    Staged {
        rel: String,
        meta: std::fs::Metadata,
        object: Object,
    },
    /// A copy that has no name, of the staged file `rel`
    Copy {
        rel: String,
        meta: std::fs::Metadata,
        file: File,
        object: Object,
    },
}

fn missing() -> Prepared {
    Prepared::Done(Step::Refused(Refusal::Missing))
}

/// Check the files `wants` of `dir` and make each ready, in parallel (the
/// first step of [`commit_layer`]).
fn prepare_files(
    dir: BorrowedFd<'_>,
    wants: &[Want],
    (store, store_dev): (&FileStore, u64),
    verity: Option<&FsVerityManager>,
    copies: &CopyBudget,
) -> io::Result<Vec<Prepared>> {
    let same_fs = rustix::fs::fstat(dir)
        .map(|st| st.st_dev == store_dev)
        .unwrap_or(false);
    wants
        .par_iter()
        .map(|want| prepare_one(dir, want, store, verity, (same_fs, copies)))
        .collect()
}

/// Give the names to the files that were made ready, after the barrier.
fn place_files(
    dir: BorrowedFd<'_>,
    prepared: Vec<Prepared>,
    store: &FileStore,
) -> io::Result<Linked> {
    let steps = prepared
        .into_par_iter()
        .enumerate()
        .map(|(i, p)| place_one(dir, p, store).map(|s| (i, s)))
        .collect::<io::Result<Vec<_>>>()?;
    let mut done = Linked::default();
    for (i, step) in steps {
        match step {
            Step::Linked(object) => done.objects.push((i, object)),
            Step::Present(object) => {
                done.objects.push((i, object));
                done.present.push(i);
            }
            Step::Refused(why) => done.refused.push((i, why)),
        }
    }
    Ok(done)
}

enum Step {
    Linked(Object),
    Present(Object),
    Refused(Refusal),
}

/// Open the staged file `rel` of `dir`: a regular file of the staging
/// itself, never what a symbolic link points to.
fn open_staged_file(dir: BorrowedFd<'_>, rel: &str) -> Result<File, Errno> {
    velarx_sys::fs::openat2_retry(
        dir,
        rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map(File::from)
}

/// The digests of the content of `file`, read once: the fs-verity digest of
/// its blocks (`merkle`) and the hash of the content (`content`), as asked.
fn read_digests(
    file: &File,
    alg: Algorithm,
    (merkle, content): (bool, bool),
    note: &dyn Fn(usize),
) -> io::Result<(Option<String>, Option<Digest>)> {
    use std::io::Read;
    let mut hasher = merkle.then(|| VerityHasher::new(alg));
    let mut digest = content.then(|| velarx_types::digest::DigestWriter::new(alg));
    let mut buf = vec![0u8; 256 << 10];
    let mut reader = file;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        note(n);
        if let Some(h) = &mut hasher {
            h.update(&buf[..n]);
        }
        if let Some(d) = &mut digest {
            d.update(&buf[..n]);
        }
    }
    Ok((hasher.map(|h| h.finish()), digest.map(|d| d.finalize())))
}

/// Verify the complete file `file`, staged as `key` (an OCI digest of its
/// content, or its fs-verity digest), and give its fs-verity digest: the one
/// check of a staged file, wherever the file goes next.  The kernel's measure
/// is compared where the file has one; a file it does not measure is read
/// once (`note` counts the bytes), which computes the fs-verity digest and,
/// for a key that is the hash of the content, that hash.  The engine never
/// trusts a digest a fetcher gave.  `Err` says why the file is not what its
/// key names.
pub fn verify_file(
    file: &File,
    key: &str,
    note: &dyn Fn(usize),
) -> io::Result<Result<String, String>> {
    let want = Digest::parse_key(key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{key}: {e}")))?;
    let alg = want.alg();
    let measured = measure(file, alg);
    let by_content = !want.is_fsverity();
    let (merkle, content) = match (&measured, by_content) {
        (Some(_), false) => (None, None),
        (Some(_), true) => read_digests(file, alg, (false, true), note)?,
        (None, content) => read_digests(file, alg, (true, content), note)?,
    };
    let verity = match measured.or(merkle) {
        Some(v) => v,
        None => return Ok(Err("it cannot be measured".into())),
    };
    if by_content && content.is_none_or(|c| c.to_string() != key) {
        return Ok(Err("not the content digest of its name".into()));
    }
    if !by_content && verity != key {
        return Ok(Err("not the fs-verity digest of its name".into()));
    }
    Ok(Ok(verity))
}

/// Check one file and make it ready (the first step of [`commit_layer`]):
/// nothing is named here.  The file's name in the staging, and its metadata
/// (to remove the name when it is still this inode), come with it.
fn prepare_one(
    dir: BorrowedFd<'_>,
    want: &Want,
    store: &FileStore,
    verity: Option<&FsVerityManager>,
    (same_fs, copies): (bool, &CopyBudget),
) -> io::Result<Prepared> {
    let rel = want.rel.as_str();
    let alg = want.alg;
    let key = want.key.as_str();
    let done = |step: Step| Ok(Prepared::Done(step));
    // the store's file is never replaced: it may have been optimized since
    // it was put there.  (A name in the store is a complete file: nothing
    // is given its name before its bytes are durable.)
    if let Check::Verity(v) = &want.check {
        if store.contains_local(v) {
            if let Some(object) = present(store, v, false) {
                let _ = unlinkat(dir, rel, AtFlags::empty());
                return done(Step::Present(object));
            }
        }
    }
    let mut file = match open_staged_file(dir, rel) {
        Ok(file) => file,
        Err(Errno::NOENT) => return done(Step::Refused(Refusal::Missing)),
        Err(Errno::LOOP | Errno::XDEV | Errno::NOTDIR | Errno::ISDIR | Errno::MLINK) => {
            warn!("The staged file {key} is not a regular file: not committed, removed");
            let _ = unlinkat(dir, rel, AtFlags::empty());
            return done(Step::Refused(Refusal::Wrong(
                "not a plain file of the staging".into(),
            )));
        }
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    let wrong = |why: &str| {
        warn!("The staged file {key} is not what its name says ({why}): not committed, removed");
        drop_name(dir, rel, &meta);
        done(Step::Refused(Refusal::Wrong(why.to_string())))
    };
    if !meta.file_type().is_file() {
        return wrong("not a regular file");
    }
    // (the fetcher runs as the engine's user: a file of another user is not
    // what it made)
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return wrong("not owned by the engine's user");
    }
    if want.size.is_some_and(|size| meta.len() != size) {
        return wrong("not the size the table of contents gives");
    }
    let manager = verity.map(|m| m.for_algorithm(alg));
    let required = verity.is_some_and(|m| m.config().required);
    // (a fetcher can neither change the mode of a file nor name it
    // elsewhere: its seccomp filter has no `chmod`, and it writes only
    // beneath its staging.  The one name is checked anyway: a file with
    // another is not what it was asked to stage)
    if !want.own && meta.nlink() != 1 {
        return wrong("it has another name");
    }
    let only_name = true;
    // what a producer wrote is not believed: the kernel measures its
    // fs-verity digest (enabled here where the producer did not, on a file
    // with no other name)
    let mut measured = measure(&file, alg);
    if measured.is_none() && only_name {
        if let Some(m) = &manager {
            match m.enable_file(&file, Path::new(rel)) {
                Ok(()) => measured = measure(&file, alg),
                Err(e @ velarx_storage::FsVerityError::AlgorithmUnavailable(_)) => {
                    return Err(storage_error(store, e.to_string()));
                }
                // (a file a producer still has open for writing cannot be
                // sealed, and the producer could change it: not what the
                // store, which has fs-verity, is given)
                Err(velarx_storage::FsVerityError::OpenForWriting) if !want.own => {
                    return wrong("a writer still has it open");
                }
                Err(e) => debug!("Cannot enable fs-verity on the staged file {key}: {e}"),
            }
        }
    }
    if required && measured.is_none() {
        // (fs-verity of other blocks than the digests name)
        if measure_file(&file).is_ok() {
            if let Err(e) = velarx_storage::require_canonical(&file, alg) {
                return Err(storage_error(
                    store,
                    format!("fsverity_require: {key}: {e}"),
                ));
            }
        }
    }
    // the file itself is linked when its inode can be: it is in the store's
    // file system with one name.  Whether the kernel measures it only says
    // how it is verified below (by the measure, or by one read of its
    // bytes), never whether it is linked or copied
    let links = same_fs && only_name;
    let mut content = None;
    match &want.check {
        Check::Verity(v) => {
            if measured.as_ref().is_some_and(|m| m != v) {
                return wrong("not the fs-verity digest of its name");
            }
        }
        Check::Content(replayed) => {
            let read = match content_read(replayed.as_deref(), measured.as_deref()) {
                Ok(read) => read,
                Err(why) => return wrong(why),
            };
            if read && measured.is_some() && links {
                // (fs-verity is enabled on it: nothing can change it between
                // this read and the link)
                let read = read_digests(&file, alg, (false, true), &|n| store.note_hashed(n))?.1;
                if read.is_none_or(|r| r.to_string() != key) {
                    return wrong("not the content digest of its name");
                }
                io::Seek::rewind(&mut file)?;
            } else if read && !links {
                // (a file in another file system: its content is hashed as
                // it is copied below, and the copy is what is checked)
                content = Some(velarx_types::digest::DigestWriter::new(alg));
            }
        }
        Check::Engine => {}
        Check::Verified(v) => {
            if measured.as_ref().is_some_and(|m| m != v) {
                return wrong("not the fs-verity digest the engine verified");
            }
        }
    }
    if let Some(m) = &measured {
        if !matches!(want.check, Check::Verity(_)) && store.contains_local(m) {
            if let Some(object) = present(store, m, manager.is_some()) {
                let _ = unlinkat(dir, rel, AtFlags::empty());
                return done(Step::Present(object));
            }
        }
    }
    if measured.is_none() && links {
        // the kernel does not measure it: verified by one read of its bytes
        // (the engine's own file named by the digest it was written with is
        // not read at all), and then linked as it is
        if required {
            return Err(storage_error(
                store,
                format!("fs-verity is required and the kernel does not measure {key} as its name"),
            ));
        }
        let (computed, hashed) = match &want.check {
            // (a replay of the engine read the whole file after it was
            // staged and proved this measure: that read was the check)
            Check::Content(Some(v)) | Check::Verified(v) => (v.clone(), None),
            check => {
                let content = matches!(check, Check::Content(_));
                let (merkle, hashed) =
                    read_digests(&file, alg, (true, content), &|n| store.note_hashed(n))?;
                (merkle.expect("asked for"), hashed)
            }
        };
        if hashed.is_some_and(|h| h.to_string() != key) {
            return wrong("not the content digest of its name");
        }
        match &want.check {
            Check::Verity(v) if *v != computed => {
                return wrong("not the fs-verity digest it is known by");
            }
            _ => {}
        }
        let Some(object) = Object::new(&computed, false) else {
            return wrong("not an fs-verity digest");
        };
        if store.contains_local(&object.verity) {
            if let Some(object) = present(store, &object.verity, false) {
                let _ = unlinkat(dir, rel, AtFlags::empty());
                return done(Step::Present(object));
            }
        }
        return settle_staged(rel, &file, meta, object, store);
    }
    if links {
        let Some(object) = measured.as_deref().and_then(|m| Object::new(m, true)) else {
            return wrong("not an fs-verity digest");
        };
        return settle_staged(rel, &file, meta, object, store);
    }
    // made with no name (nothing of a crash is left, and no collection
    // meets it), checked as it is written, then opened again read-only (no
    // writer: fs-verity wants none)
    io::Seek::rewind(&mut file)?;
    let mut writer = super::unnamed::unnamed_to_link(store.root())?;
    let mut verity = VerityHasher::new(alg);
    velarx_storage::copy_sparse(&mut file, &writer, |b| {
        store.note_hashed(b.len());
        store.note_copied(b.len());
        verity.update(b);
        if let Some(c) = &mut content {
            c.update(b);
        }
    })?;
    let computed = verity.finish();
    if content.is_some_and(|c| c.finalize().to_string() != key) {
        return wrong("not the content digest of its name");
    }
    let expected = match &want.check {
        Check::Verity(v) | Check::Content(Some(v)) | Check::Verified(v) => Some(v),
        _ => None,
    };
    if expected.is_some_and(|v| *v != computed) {
        return wrong("not the fs-verity digest it is known by");
    }
    io::Write::flush(&mut writer)?;
    let tmp = velarx_sys::fd::reopen_read_only(&writer)?;
    drop(writer);
    let enabled = match manager
        .as_ref()
        .map(|m| m.enable_file(&tmp, Path::new(rel)))
    {
        Some(Ok(())) => true,
        // (never a file of this hash without it: no change of hash, and
        // no file unverified where it is enforced)
        Some(Err(e @ velarx_storage::FsVerityError::AlgorithmUnavailable(_))) => {
            return Err(storage_error(store, e.to_string()));
        }
        // (where it is required no file takes its name without it)
        Some(Err(e)) if required => {
            return Err(storage_error(
                store,
                format!("fs-verity is required and cannot be enabled on {key}: {e}"),
            ));
        }
        Some(Err(_)) | None => false,
    };
    let kernel = enabled
        .then(|| measure_file(&tmp).ok())
        .flatten()
        .and_then(|m| m.object())
        .map(|o| o.to_string())
        .filter(|m| *m == computed)
        .and_then(|m| Object::new(&m, true));
    // read-only after: enabling fs-verity needs write access
    tmp.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    if required && kernel.is_none() {
        return Err(storage_error(
            store,
            format!("fs-verity is required and the kernel does not measure {key} as its name"),
        ));
    }
    let Some(object) = kernel.or_else(|| Object::new(&computed, false)) else {
        return wrong("not an fs-verity digest");
    };
    if store.contains_local(&object.verity) {
        if let Some(object) = present(store, &object.verity, object.checked) {
            drop_name(dir, rel, &meta);
            return done(Step::Present(object));
        }
    }
    if copies.take() {
        return Ok(Prepared::Copy {
            rel: rel.to_string(),
            meta,
            file: tmp,
            object,
        });
    }
    // (more copies than descriptors to keep: this one is made durable by
    // itself and named at once, which is no less safe)
    tmp.sync_data()?;
    done(link_copy(dir, rel, &tmp, &meta, &object, store)?)
}

/// The step of a file that is linked by its inode: kept for the link that
/// follows the barrier, after its mode is made read-only.
fn settle_staged(
    rel: &str,
    file: &File,
    meta: std::fs::Metadata,
    object: Object,
    store: &FileStore,
) -> io::Result<Prepared> {
    file.set_permissions(std::fs::Permissions::from_mode(0o444))
        .map_err(|e| storage_error(store, format!("cannot make {rel} read-only: {e}")))?;
    Ok(Prepared::Staged {
        rel: rel.to_string(),
        meta,
        object,
    })
}

/// Link the copy `file` as `object` and remove the staged name of what it
/// is the copy of.
fn link_copy(
    dir: BorrowedFd<'_>,
    rel: &str,
    file: &File,
    meta: &std::fs::Metadata,
    object: &Object,
    store: &FileStore,
) -> io::Result<Step> {
    let linked = link_into(store, file, object)?;
    drop_name(dir, rel, meta);
    Ok(match linked {
        true => Step::Linked(object.clone()),
        false => Step::Present(object.clone()),
    })
}

/// The operation of a storage driver that gives a verified file its name:
/// the commit hands each file, verified and durable, to the driver's own way
/// of keeping it.  The objects of the engine's own store (composefs and vfs,
/// which keep the same files by their fs-verity digest) are linked by their
/// inode; the `varlink` driver takes the file as a descriptor handed over its
/// typed interface (`org.velarx.StorageFeed`, event `staged`) and keeps it in
/// its own way.  Whether the name was made by this call: an object that is
/// there is kept.
pub trait Place: Sync {
    fn place(&self, file: &File, object: &Object) -> io::Result<bool>;
}

impl Place for FileStore {
    /// `linkat` of the file into `objects/` under the name of `object`: no
    /// second write of the bytes, no copy, no reflink.
    fn place(&self, file: &File, object: &Object) -> io::Result<bool> {
        let target = self.object_path(object);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        link_object(&velarx_sys::fd::proc_str(file), &target, object)
    }
}

/// Give the file `file` the place of `object` in the store; whether this
/// call made the name (an object that is there is kept, `false`).
fn link_into(store: &FileStore, file: &File, object: &Object) -> io::Result<bool> {
    store.place(file, object)
}

/// Give a file that was made ready its name (the step that follows the
/// barrier of [`commit_layer`]).
fn place_one(dir: BorrowedFd<'_>, prepared: Prepared, store: &FileStore) -> io::Result<Step> {
    match prepared {
        Prepared::Done(step) => Ok(step),
        Prepared::Copy {
            rel,
            meta,
            file,
            object,
        } => link_copy(dir, &rel, &file, &meta, &object, store),
        Prepared::Staged { rel, meta, object } => {
            let file = match open_staged_file(dir, &rel) {
                Ok(file) => file,
                Err(Errno::NOENT) => return Ok(Step::Refused(Refusal::Missing)),
                Err(e) => return Err(e.into()),
            };
            let now = file.metadata()?;
            if (now.dev(), now.ino()) != (meta.dev(), meta.ino()) {
                warn!("The staged file {rel} was replaced: not committed");
                return Ok(Step::Refused(Refusal::Wrong(
                    "replaced while it was committed".into(),
                )));
            }
            link_copy(dir, &rel, &file, &meta, &object, store)
        }
    }
}
/// Give the file at `from` (a name of its own or `/proc/self/fd/N`) the place
/// of `object`: never over an object that is there, unless that one is
/// checked and does not have the fs-verity digest it is named by.  Whether
/// the name was made by this call.
pub fn link_object(from: &str, target: &std::path::Path, object: &Object) -> io::Result<bool> {
    match linkat(CWD, from, CWD, target, AtFlags::SYMLINK_FOLLOW) {
        Ok(()) => Ok(true),
        Err(Errno::EXIST) => {
            let measures = |p: &std::path::Path| {
                File::open(p)
                    .ok()
                    .and_then(|f| measure_file(&f).ok())
                    .and_then(|m| m.object())
                    .is_some_and(|o| o.to_string() == object.verity)
            };
            if !object.checked || measures(target) {
                return Ok(false);
            }
            warn!(
                "{} does not have the fs-verity digest of its name: replaced",
                target.display()
            );
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let temporary = target.with_file_name(format!(
                ".link{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let _ = std::fs::remove_file(&temporary);
            linkat(CWD, from, CWD, &temporary, AtFlags::SYMLINK_FOLLOW)?;
            renameat(CWD, &temporary, CWD, target).map_err(|e| {
                let _ = std::fs::remove_file(&temporary);
                io::Error::from(e)
            })?;
            Ok(true)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;
    use velarx_storage::fsverity_digest_file;
    use velarx_storage::VerityMode;
    use velarx_types::digest::Algorithm;

    struct Layer {
        _dir: tempfile::TempDir,
        staging: File,
        store: FileStore,
        path: std::path::PathBuf,
    }

    fn layer() -> Layer {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("files");
        std::fs::create_dir_all(&path).unwrap();
        let store = FileStore::new(dir.path().join("objects")).unwrap();
        Layer {
            staging: File::open(&path).unwrap(),
            _dir: dir,
            store,
            path,
        }
    }

    /// A commit that stopped between the two renames of a layer's image and
    /// index is finished by the next one: the image already in the store is
    /// checked there, the index still staged moves.
    #[test]
    fn a_commit_that_stopped_between_the_renames_is_finished() {
        use velarx_fuse::composefs::{layer_image_path, layer_index_path};
        let layer = layer();
        let staged = layer.path.parent().unwrap().join("area/objects");
        let (stem, bytes) = ("layer", b"an image".as_slice());
        let recorded = velarx_storage::composefs_digest_of(Algorithm::Sha256, bytes);
        let write = |path: std::path::PathBuf, data: &[u8]| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, data).unwrap();
        };
        // (the image was renamed, the index was not)
        write(layer_image_path(layer.store.root(), stem), bytes);
        write(layer_index_path(&staged, stem), b"index");
        let image = StagedImage {
            objects: &staged,
            stem,
            alg: Algorithm::Sha256,
            recorded: &recorded,
        };
        let adopt = |image: &StagedImage<'_>| {
            adopt_image(
                image,
                check_image(image, &layer.store).unwrap(),
                &layer.store,
            )
            .unwrap()
        };
        assert_eq!(adopt(&image), ImageStep::Moved);
        assert!(layer_index_path(layer.store.root(), stem).is_file());
        // (again: nothing staged, both in the store)
        assert_eq!(adopt(&image), ImageStep::Moved);
        // (an image in the store that is not the recorded one is not one)
        write(layer_image_path(layer.store.root(), stem), b"another");
        assert_eq!(adopt(&image), ImageStep::Missing);
    }

    /// The two steps of a commit with no barrier between them.
    fn link_files(
        dir: BorrowedFd<'_>,
        wants: &[Want],
        store: &FileStore,
        verity: Option<&FsVerityManager>,
    ) -> io::Result<Linked> {
        link_files_with(dir, wants, store, verity, &CopyBudget::new())
    }

    fn link_files_with(
        dir: BorrowedFd<'_>,
        wants: &[Want],
        store: &FileStore,
        verity: Option<&FsVerityManager>,
        copies: &CopyBudget,
    ) -> io::Result<Linked> {
        let dev = std::fs::metadata(store.root())?.dev();
        let prepared = prepare_files(dir, wants, (store, dev), verity, copies)?;
        place_files(dir, prepared, store)
    }

    /// A want of the staging the engine wrote itself.
    fn own(w: Want) -> Want {
        Want { own: true, ..w }
    }

    fn staged_ino(l: &Layer, w: &Want) -> u64 {
        std::fs::metadata(l.path.join(&w.rel)).unwrap().ino()
    }

    fn verity_of(bytes: &[u8]) -> Digest {
        let f = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut &f, bytes).unwrap();
        let text = fsverity_digest_file(Algorithm::Sha256, &f).unwrap();
        Digest::parse_fsverity(&text).unwrap()
    }

    fn stage(layer: &Layer, want: &Want, bytes: &[u8]) {
        let p = layer.path.join(&want.rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn a(bytes: &[u8]) -> Want {
        Want::by_verity(&verity_of(bytes), Some(bytes.len() as u64))
    }

    fn b(bytes: &[u8]) -> Want {
        Want::by_content(
            &Digest::of(Algorithm::Sha256, bytes),
            Some(bytes.len() as u64),
        )
    }

    /// The two parts of a commit: [`verify_layers`] reads and hashes every
    /// byte once (and the image of a layer: once), [`commit_verified`], the
    /// part that runs under the locks of the store, moves no counter: it
    /// hashes nothing, reads no content and copies nothing, whatever the
    /// store's fs-verity.
    #[test]
    fn the_locked_part_of_a_commit_reads_hashes_and_copies_nothing() {
        let l = layer();
        let (wa, wb, wc) = (a(b"alpha"), b(b"bravo"), a(b"charlie"));
        stage(&l, &wa, b"alpha");
        stage(&l, &wb, b"bravo");
        stage(&l, &wc, b"charlie");
        let objects = l.path.parent().unwrap().join("area/objects");
        let stem = "layer";
        let image = b"an image of the layer".as_slice();
        let write = |path: std::path::PathBuf, data: &[u8]| {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, data).unwrap();
        };
        write(
            velarx_fuse::composefs::layer_image_path(&objects, stem),
            image,
        );
        write(
            velarx_fuse::composefs::layer_index_path(&objects, stem),
            b"i",
        );
        let recorded = velarx_storage::composefs_digest_of(Algorithm::Sha256, image);
        let stagings = [Staging {
            dir: &l.path,
            wants: vec![wa, wb, wc],
            image: Some(StagedImage {
                objects: &objects,
                stem,
                alg: Algorithm::Sha256,
                recorded: &recorded,
            }),
        }];
        let verified = verify_layers(&stagings, &l.store, None).unwrap();
        let total = (5 + 5 + 7 + image.len()) as u64;
        assert_eq!(l.store.hashed(), total, "every byte once, before the locks");
        assert_eq!(l.store.copied(), 0);
        let before = (l.store.hashed(), l.store.copied());
        let mut inside = None;
        let mut between = |_: &[Linked]| {
            inside = Some((l.store.hashed(), l.store.copied()));
            Ok(false)
        };
        let done = commit_verified(&stagings, verified, &l.store, Some(&mut between)).unwrap();
        assert_eq!(done[0].objects.len(), 3, "{:?}", done[0].refused);
        assert_eq!(done[0].image, Some(ImageStep::Moved));
        assert_eq!(
            inside,
            Some(before),
            "nothing moved before the last barrier"
        );
        assert_eq!(
            (l.store.hashed(), l.store.copied()),
            before,
            "the locked part reads, hashes and copies nothing"
        );
    }

    /// A file the engine wrote, in a staging on another file system than the
    /// store, is copied (its inode cannot be linked): the commit does not fail
    /// with EXDEV, and the copy is checked as it is made.
    #[test]
    fn a_file_the_engine_wrote_is_copied_when_the_store_is_on_another_file_system() {
        for (check, bytes_in) in [
            (Check::Engine, &b"own bytes"[..]),
            (Check::Content(None), &b"own bytes"[..]),
        ] {
            let l = layer();
            let bytes = b"own bytes";
            let w = Want {
                key: Digest::of(Algorithm::Sha256, bytes).to_string(),
                alg: Algorithm::Sha256,
                rel: "tmp-1".into(),
                size: Some(bytes.len() as u64),
                check,
                own: true,
            };
            std::fs::write(l.path.join(&w.rel), bytes_in).unwrap();
            // (another device number than the staging's: the store is elsewhere)
            let dev = std::fs::metadata(l.store.root()).unwrap().dev() + 1;
            let prepared = prepare_files(
                l.staging.as_fd(),
                std::slice::from_ref(&w),
                (&l.store, dev),
                None,
                &CopyBudget::new(),
            )
            .unwrap();
            let done = place_files(l.staging.as_fd(), prepared, &l.store).unwrap();
            assert!(done.refused.is_empty(), "{:?}", done.refused);
            let object = &done.objects[0].1;
            assert_eq!(std::fs::read(l.store.object_path(object)).unwrap(), bytes);
        }
        // (a copy of other bytes than the name says is refused as wrong)
        let l = layer();
        let w = Want {
            key: Digest::of(Algorithm::Sha256, b"the name").to_string(),
            alg: Algorithm::Sha256,
            rel: "tmp-1".into(),
            size: None,
            check: Check::Content(None),
            own: true,
        };
        std::fs::write(l.path.join(&w.rel), b"another").unwrap();
        let dev = std::fs::metadata(l.store.root()).unwrap().dev() + 1;
        let prepared = prepare_files(
            l.staging.as_fd(),
            std::slice::from_ref(&w),
            (&l.store, dev),
            None,
            &CopyBudget::new(),
        )
        .unwrap();
        let done = place_files(l.staging.as_fd(), prepared, &l.store).unwrap();
        assert!(matches!(done.refused[0].1, Refusal::Wrong(_)));
    }

    #[test]
    fn a_file_named_by_its_measure_is_linked_into_the_store_with_its_inode() {
        let l = layer();
        let w = a(b"hello");
        stage(&l, &w, b"hello");
        let done = link_files(l.staging.as_fd(), std::slice::from_ref(&w), &l.store, None).unwrap();
        assert!(done.refused.is_empty(), "{:?}", done.refused);
        let object = &done.objects[0].1;
        assert_eq!(object.verity, w.key);
        let target = l.store.object_path(object);
        // (the staged name goes: the file is the store's)
        assert!(!l.path.join(&w.rel).exists());
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }

    #[test]
    fn a_file_with_the_right_name_and_the_wrong_content_is_refused() {
        let l = layer();
        let (wa, wb) = (a(b"hello"), b(b"world"));
        stage(&l, &wa, b"hellx");
        stage(&l, &wb, b"worlx");
        let done = link_files(l.staging.as_fd(), &[wa, wb], &l.store, None).unwrap();
        assert!(done.objects.is_empty());
        assert_eq!(done.refused.len(), 2);
        assert!(done
            .refused
            .iter()
            .all(|(_, r)| matches!(r, Refusal::Wrong(_))));
        // nothing was named in the store
        assert!(!l.store.root().read_dir().unwrap().any(|e| e.is_ok()));
    }

    #[test]
    fn a_content_digest_is_checked_by_a_read_and_the_object_is_named_by_the_measure() {
        let l = layer();
        let w = b(b"world");
        stage(&l, &w, b"world");
        let done = link_files(l.staging.as_fd(), &[w], &l.store, None).unwrap();
        assert_eq!(done.objects[0].1.verity, verity_of(b"world").to_string());
    }

    /// A file a replay read, whose measure is the one the replay had, is not
    /// read again; any other is.
    #[test]
    fn a_file_a_replay_read_is_not_read_again() {
        assert_eq!(content_read(Some("v"), Some("v")), Ok(false));
        assert!(content_read(Some("v"), Some("w")).is_err());
        assert_eq!(content_read(Some("v"), None), Ok(true));
        assert_eq!(content_read(None, Some("v")), Ok(true));
        assert_eq!(content_read(None, None), Ok(true));
    }

    /// The store the tests make is on a file system with no fs-verity
    /// (`/tmp`): the kernel measures nothing.  A file the engine wrote is
    /// linked as it is (never copied), named by the digest it was written
    /// with and read not at all, or, with none, once.
    #[test]
    fn a_file_the_engine_wrote_is_linked_by_its_inode_and_read_at_most_once() {
        let bytes = b"engine bytes";
        let sha = Digest::of(Algorithm::Sha256, bytes);
        let verity = verity_of(bytes).to_string();
        let size = Some(bytes.len() as u64);
        let by = |check: Check, name: &str| Want {
            key: if matches!(check, Check::Verity(_)) {
                verity.clone()
            } else {
                sha.to_string()
            },
            alg: Algorithm::Sha256,
            rel: name.into(),
            size,
            check,
            own: true,
        };
        for (check, read) in [
            // (written and hashed in one pass: the commit trusts it)
            (Check::Content(Some(verity.clone())), 0),
            // (the name is a claim of the table: read once to prove it)
            (Check::Verity(verity.clone()), bytes.len() as u64),
            // (nothing is known: read once to name it)
            (Check::Engine, bytes.len() as u64),
            (Check::Content(None), bytes.len() as u64),
        ] {
            let l = layer();
            let w = by(check.clone(), "tmp-1");
            std::fs::write(l.path.join(&w.rel), bytes).unwrap();
            let ino = staged_ino(&l, &w);
            let done =
                link_files(l.staging.as_fd(), std::slice::from_ref(&w), &l.store, None).unwrap();
            assert!(done.refused.is_empty(), "{check:?}: {:?}", done.refused);
            let object = &done.objects[0].1;
            assert_eq!(object.verity, verity, "{check:?}");
            assert_eq!(
                std::fs::metadata(l.store.object_path(object))
                    .unwrap()
                    .ino(),
                ino,
                "{check:?}: linked, not copied"
            );
            assert_eq!(l.store.hashed(), read, "{check:?}: the bytes read to hash");
        }
    }

    /// A file of the engine's that is not what its claim says is refused.
    #[test]
    fn a_file_the_engine_wrote_with_another_content_than_its_claim_is_refused() {
        let l = layer();
        let w = own(Want {
            key: Digest::of(Algorithm::Sha256, b"claimed").to_string(),
            alg: Algorithm::Sha256,
            rel: "tmp-1".into(),
            size: Some(7),
            check: Check::Content(None),
            own: false,
        });
        std::fs::write(l.path.join(&w.rel), b"another").unwrap();
        let done = link_files(l.staging.as_fd(), &[w], &l.store, None).unwrap();
        assert!(done.objects.is_empty());
        assert!(matches!(done.refused[0].1, Refusal::Wrong(_)));
    }

    /// A file a fetcher made that the kernel does not measure is read once
    /// (its content checked by that read) and linked as it is: the store has
    /// the very inode, and the commit makes no copy and writes nothing.
    #[test]
    fn a_file_the_kernel_does_not_measure_is_read_once_and_linked() {
        let l = layer();
        let (wa, wb, wc) = (a(b"alpha"), b(b"bravo"), a(b"charlie"));
        stage(&l, &wa, b"alpha");
        stage(&l, &wb, b"bravo");
        stage(&l, &wc, b"charlie");
        let inos: Vec<u64> = [&wa, &wb, &wc].iter().map(|w| staged_ino(&l, w)).collect();
        let done = link_files(l.staging.as_fd(), &[wa, wb, wc], &l.store, None).unwrap();
        assert_eq!(done.objects.len(), 3, "{:?}", done.refused);
        for ((_, object), ino) in done.objects.iter().zip(inos) {
            let target = std::fs::metadata(l.store.object_path(object)).unwrap();
            assert_eq!(
                target.ino(),
                ino,
                "linked: the fetcher's inode is the store's"
            );
        }
        assert_eq!(l.store.hashed(), (5 + 5 + 7) as u64);
        assert_eq!(l.store.copied(), 0);
    }

    /// The trade-off of a store without fs-verity: the file is linked after
    /// one check, so a producer that kept a descriptor open for writing
    /// changes the file the store has (nothing seals it; with fs-verity
    /// enabling it fails while a writer holds it, and the file is refused).
    /// Documented in the threat model.
    #[test]
    fn a_producer_that_keeps_a_writable_descriptor_can_change_a_linked_file_without_verity() {
        use std::os::unix::fs::FileExt;
        let l = layer();
        let w = a(b"checked");
        stage(&l, &w, b"checked");
        let held = std::fs::OpenOptions::new()
            .write(true)
            .open(l.path.join(&w.rel))
            .unwrap();
        let dev = std::fs::metadata(l.store.root()).unwrap().dev();
        let prepared = prepare_files(
            l.staging.as_fd(),
            std::slice::from_ref(&w),
            (&l.store, dev),
            None,
            &CopyBudget::new(),
        )
        .unwrap();
        held.write_all_at(b"changed", 0).unwrap();
        let done = place_files(l.staging.as_fd(), prepared, &l.store).unwrap();
        let object = &done.objects[0].1;
        assert_eq!(
            std::fs::read(l.store.object_path(object)).unwrap(),
            b"changed"
        );
    }

    /// The copies of all the commits of a process come from one pool, sized
    /// by the descriptor limit: commits that run at the same time (two lazy
    /// completions) hold no more together than the pool has, and a commit
    /// gives its places back when it ends.
    #[test]
    fn the_copies_of_concurrent_commits_come_from_one_pool() {
        // (a hard limit of 1024 leaves a quarter to the copies; a small one
        // always leaves 256 descriptors to the rest of the process)
        assert_eq!(places_for(1024), 256);
        assert_eq!(places_for(4096), 1024);
        assert_eq!(places_for(1 << 30), 16 << 10);
        assert_eq!(places_for(300), 44);
        assert_eq!(places_for(100), 0);
        let pool = Arc::new(Pool { left: 5.into() });
        let (one, two) = (
            CopyBudget::from(pool.clone()),
            CopyBudget::from(pool.clone()),
        );
        let taken: Vec<bool> = (0..8).map(|i| [&one, &two][i % 2].take()).collect();
        // (the process holds five, whoever asks)
        assert_eq!(taken.iter().filter(|t| **t).count(), 5);
        assert_eq!(one.held() + two.held(), 5);
        assert!(!one.take() && !two.take());
        // (the places of a commit that ended are the next one's)
        let held = one.held();
        drop(one);
        let three = CopyBudget::from(pool);
        assert!((0..held).all(|_| three.take()));
        assert!(!three.take());
    }

    /// Beyond the copies a commit can hold open, a copy is made durable on
    /// its own and named at once: the result is the same.
    #[test]
    fn a_copy_without_a_place_to_wait_is_named_as_well() {
        let l = layer();
        let w = a(b"no place");
        stage(&l, &w, b"no place");
        let copies = CopyBudget::of(0);
        let done = link_files_with(
            l.staging.as_fd(),
            std::slice::from_ref(&w),
            &l.store,
            None,
            &copies,
        )
        .unwrap();
        assert_eq!(copies.held(), 0);
        assert_eq!(done.objects[0].1.verity, w.key);
        assert_eq!(
            std::fs::read(l.store.object_path(&done.objects[0].1)).unwrap(),
            b"no place"
        );
    }

    /// Nothing is named in the store before the first barrier: the copies
    /// and the files linked by their inode wait for the staging to be on the
    /// disk, and a barrier that fails ends the commit with no name made; one
    /// that fails after the links ends it too (nothing is reported as
    /// committed that is not durable).
    #[test]
    fn a_barrier_that_fails_ends_the_commit_and_the_first_names_nothing() {
        for failing in [1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let staging = dir.path().join("files");
            std::fs::create_dir_all(&staging).unwrap();
            let store = FileStore::new(dir.path().join("objects"))
                .unwrap()
                .with_sync(velarx_base::sync::SyncMode::Syncfs);
            store.fail_barrier(failing);
            let (copied, linked) = (b(b"copied"), own(a(b"linked")));
            for (w, bytes) in [(&copied, &b"copied"[..]), (&linked, b"linked")] {
                let p = staging.join(&w.rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, bytes).unwrap();
            }
            let result = commit_layer(
                &[Staging {
                    dir: &staging,
                    wants: vec![copied, linked],
                    image: None,
                }],
                &store,
                None,
                None,
            );
            let e = result.expect_err("the barrier failed");
            assert_eq!(e.raw_os_error(), Some(rustix::io::Errno::IO.raw_os_error()));
            let named = std::fs::read_dir(store.root())
                .unwrap()
                .flatten()
                .filter(|d| d.path().is_dir())
                .count();
            match failing {
                1 => assert_eq!(named, 0, "a name before the first barrier"),
                _ => assert_eq!(named, 2, "the links precede the second barrier"),
            }
        }
    }

    #[test]
    fn a_missing_file_is_reported_and_the_others_are_linked() {
        let l = layer();
        let (x, y) = (a(b"one"), a(b"two"));
        stage(&l, &y, b"two");
        let done = link_files(l.staging.as_fd(), &[x, y], &l.store, None).unwrap();
        assert_eq!(done.refused, vec![(0, Refusal::Missing)]);
        assert_eq!(done.objects.len(), 1);
    }

    #[test]
    fn a_symlink_a_second_name_and_a_wrong_size_are_refused() {
        let l = layer();
        let (s, h, z) = (a(b"sym"), a(b"hard"), a(b"size"));
        let target = l.path.join("elsewhere");
        std::fs::write(&target, b"sym").unwrap();
        std::fs::create_dir_all(l.path.join(&s.rel).parent().unwrap()).unwrap();
        symlink(&target, l.path.join(&s.rel)).unwrap();
        stage(&l, &h, b"hard");
        std::fs::hard_link(l.path.join(&h.rel), l.path.join("another")).unwrap();
        stage(&l, &z, b"size!");
        let done = link_files(l.staging.as_fd(), &[s, h, z], &l.store, None).unwrap();
        // (a file with a second name is refused: its holder could change
        // the mode or the owner of the object of the store)
        assert!(done.objects.is_empty());
        assert_eq!(done.refused.len(), 3);
        assert!(done
            .refused
            .iter()
            .all(|(_, r)| matches!(r, Refusal::Wrong(_))));
    }

    #[test]
    fn a_path_that_leaves_the_staging_is_not_followed() {
        let l = layer();
        let w = a(b"out");
        let hex = w.rel.replace('/', "");
        std::fs::write(l.path.join("secret"), b"out").unwrap();
        // <ab> is a link to the outside
        symlink("..", l.path.join(&hex[..2])).unwrap();
        let done = link_files(l.staging.as_fd(), &[w], &l.store, None).unwrap();
        assert!(done.objects.is_empty());
        assert!(matches!(done.refused[0].1, Refusal::Wrong(_)));
    }

    #[test]
    fn a_name_the_store_has_is_kept_and_a_file_without_verity_is_refused_when_required() {
        let l = layer();
        let w = a(b"kept");
        stage(&l, &w, b"kept");
        let object = Object::new(&w.key, false).unwrap();
        let target = l.store.object_path(&object);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, b"kept").unwrap();
        let before = std::fs::metadata(&target).unwrap().ino();
        let done = link_files(l.staging.as_fd(), std::slice::from_ref(&w), &l.store, None).unwrap();
        assert_eq!(done.present, vec![0]);
        assert_eq!(std::fs::metadata(&target).unwrap().ino(), before);
        // (a file system without fs-verity cannot satisfy `require_kernel`;
        // one that has it names the file by the kernel's measure: the
        // outcome is the file system's, and each is pinned)
        let l2 = layer();
        stage(&l2, &w, b"kept");
        let probe = l2.path.join("probe");
        std::fs::write(&probe, b"probe").unwrap();
        let _ = VerityMode::On
            .manager()
            .unwrap()
            .for_algorithm(Algorithm::Sha256)
            .enable(&probe);
        let works = measure_file(&File::open(&probe).unwrap()).is_ok();
        let done = link_files(
            l2.staging.as_fd(),
            &[w],
            &l2.store,
            VerityMode::Require.manager().as_ref(),
        );
        match (works, done) {
            (false, Err(e)) => assert!(e.to_string().contains("fs-verity is required"), "{e}"),
            (true, Ok(done)) => {
                assert_eq!(done.objects.len(), 1);
                assert!(done.objects[0].1.checked);
            }
            (works, done) => panic!("fs-verity works: {works}, the commit gave {done:?}"),
        }
    }
}
