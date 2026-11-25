// SPDX-License-Identifier: Apache-2.0
//! A read-only FUSE file system serving the layers of an image (`Tree`),
//! with the content of the files read from the store.
//!
//! It is served by the monitor of a container: its directories are the lower
//! layers of the container's overlay, and the data-only layer of an image
//! whose files the store lacks.

use super::idtranslate::IdTranslate;
use super::tree::{unix_parts, Attr, Tree};
use super::{FuseError, FuseResult, LazyFileFetcher};
use fuser::{
    consts, FileAttr, FileType, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyXattr, Request,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, warn};
use velarx_storage::FileStore;

/// Attributes never change: the kernel can keep them for good.
const TTL: Duration = Duration::from_secs(24 * 3600);

/// The handle of a file whose bytes are in the tree (`FileRef::inline`).
const INLINE_FH: u64 = u64::MAX;

/// Threads that wait for fetches: misses of different files proceed at the
/// same time, and nothing that is present waits for them.
const FETCH_THREADS: usize = 8;

/// Most threads that open and read the files of the store: the session
/// loop hands them its opens and reads, so readers do not wait for each
/// other (the lookups and attributes, in memory, stay on the loop).  The
/// session's thread makes them once it is confined: they have its
/// confinement.
const MAX_IO_THREADS: usize = 16;

/// The read-ahead asked of the kernel (it may allow less).
const MAX_READAHEAD: u32 = 1 << 20;

/// The content of an open file: the local file once there is one.
struct Handle {
    digest: String,
    /// The size the tree says the file has.
    size: u64,
    layer: String,
    local: Mutex<Option<Arc<File>>>,
    /// The inode it is a file of.
    ino: u64,
    /// The backing file of a passthrough open, shared by all the opens of
    /// the inode (the kernel wants one): kept until their release.
    backing: Option<Arc<fuser::BackingId>>,
}

/// How the files of an inode are open: the kernel refuses an inode open
/// both through passthrough and served, and two backing files for it.
#[derive(Default)]
struct InodeIo {
    backing: std::sync::Weak<fuser::BackingId>,
    /// Handles that serve their reads.
    served: usize,
}

type Job = Box<dyn FnOnce() + Send>;

/// What the file system shares with the threads that wait for fetches.
struct Shared {
    store: Arc<FileStore>,
    fetcher: Option<Arc<dyn LazyFileFetcher>>,
    handles: Mutex<HashMap<u64, Arc<Handle>>>,
    /// Reads waiting for the fetch of a digest; the fetch is under way while
    /// the digest is here.
    waiting: Mutex<HashMap<String, Vec<Waiter>>>,
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
    /// The opens and reads, run by the I/O threads (none until the session
    /// first has more than one request to serve or waits for a fetch:
    /// `start_io`).
    io: Mutex<Option<mpsc::Sender<Job>>>,
    /// The session's /dev/fuse (a duplicate), to see if requests wait.
    device: std::sync::OnceLock<std::os::fd::OwnedFd>,
    /// The kernel and this process can do FUSE passthrough.
    passthrough: AtomicBool,
    inodes: Mutex<HashMap<u64, InodeIo>>,
    next_fh: AtomicU64,
    /// The fs-verity digests the files must have.
    verity: Arc<super::verity::Verity>,
    /// The files fetched for this mount, apart from the store: a lookup of
    /// a file waits until it is in one of them (the kernel's overlay follows
    /// the redirect of a stub right after the lookup, and a file that is not
    /// there is an error it cannot wait out).
    staging: std::sync::OnceLock<Arc<FileStore>>,
    /// The lookups of files are noted for the startup profile of the image.
    recording: std::sync::OnceLock<Arc<super::profile::Recording>>,
}

/// A read that waits for a file: called with the outcome of the fetch.
type Waiter = Box<dyn FnOnce(Result<(), i32>) + Send>;

pub struct ImageFs {
    tree: Arc<dyn Tree>,
    translate: Option<IdTranslate>,
    /// Digest of each layer, for the lazy fetches.
    layers: Vec<String>,
    shared: Arc<Shared>,
}

/// Files of this size or less are not asked for the blocks their object
/// takes: a hole in them would be a few blocks at most.
const SPARSE_MIN: u64 = 64 * 1024;

/// The time as `fuser` gives it to the kernel: the seconds before the epoch
/// are `-secs` of the distance from it and the nanoseconds are added to
/// them (a time 1.25 s before the epoch is -2 s and 750 ms), where a
/// `SystemTime` before the epoch is that distance whole.
fn kernel_time(t: SystemTime) -> SystemTime {
    match unix_parts(t) {
        (secs, nanos) if secs < 0 => SystemTime::UNIX_EPOCH
            .checked_sub(Duration::new(secs.unsigned_abs(), nanos))
            .unwrap_or(t),
        _ => t,
    }
}

/// The attributes of a node, with the owners the container sees; `blocks`,
/// those of the object of a file (which keeps the holes of a sparse one).
fn file_attr(ino: u64, a: Attr, blocks: Option<u64>, translate: Option<&IdTranslate>) -> FileAttr {
    FileAttr {
        ino,
        size: a.size,
        blocks: blocks.unwrap_or(a.size.div_ceil(512)),
        atime: kernel_time(a.atime),
        mtime: kernel_time(a.mtime),
        ctime: kernel_time(a.ctime),
        crtime: kernel_time(a.mtime),
        kind: a.kind,
        perm: a.perm,
        nlink: a.nlink,
        uid: translate.map_or(a.uid, |t| t.uid_of(a.uid)),
        gid: translate.map_or(a.gid, |t| t.gid_of(a.gid)),
        rdev: a.rdev,
        blksize: 4096,
        flags: 0,
    }
}

impl ImageFs {
    /// The blocks the object of a file that is not small takes, when the
    /// store has it: a sparse file is not shown as fully allocated.
    fn stored_blocks(&self, ino: u64, a: &Attr) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        if a.kind != FileType::RegularFile || a.size <= SPARSE_MIN {
            return None;
        }
        let f = self.tree.file(ino).filter(|f| f.inline.is_none())?;
        let path = self.shared.find(f.digest.as_deref()?)?;
        std::fs::symlink_metadata(path).ok().map(|m| m.blocks())
    }

    pub fn new(
        tree: Arc<dyn Tree>,
        layers: Vec<String>,
        store: Arc<FileStore>,
        fetcher: Option<Arc<dyn LazyFileFetcher>>,
        translate: Option<IdTranslate>,
        verity: Arc<super::verity::Verity>,
    ) -> Self {
        let tx = match &fetcher {
            Some(f) => {
                let f = f.clone();
                workers("fetch", FETCH_THREADS, move || f.thread_started())
            }
            None => workers("fetch", 0, || Ok(())),
        };
        Self {
            tree,
            translate,
            layers,
            shared: Arc::new(Shared {
                store,
                fetcher,
                handles: Mutex::new(HashMap::new()),
                waiting: Mutex::new(HashMap::new()),
                jobs: Mutex::new(Some(tx)),
                io: Mutex::new(None),
                device: std::sync::OnceLock::new(),
                passthrough: AtomicBool::new(false),
                inodes: Mutex::new(HashMap::new()),
                next_fh: AtomicU64::new(1),
                verity,
                staging: std::sync::OnceLock::new(),
                recording: std::sync::OnceLock::new(),
            }),
        }
    }
}

/// Attributes of an image that are not shown: the overlay's own (an
/// image could make the overlay over it see opaque directories,
/// redirects or metacopies), the SELinux label (the engine labels) and
/// names that are none ([`velarx_overlay_core::class`]).
pub fn hidden_xattr(name: &str) -> bool {
    !matches!(
        velarx_overlay_core::class(name.as_bytes()),
        velarx_overlay_core::Class::Plain
    )
}

/// `count` threads named `name-N` that run the jobs sent to the channel
/// (and end when it is dropped), each after `start` (which ends the thread
/// when it fails: with no thread left, a job cannot be sent).
fn workers(
    name: &str,
    count: usize,
    start: impl Fn() -> Result<(), String> + Clone + Send + 'static,
) -> mpsc::Sender<Job> {
    let (tx, rx) = mpsc::channel::<Job>();
    let rx = Arc::new(Mutex::new(rx));
    for i in 0..count {
        let rx = rx.clone();
        let start = start.clone();
        let thread = format!("{name}-{i}");
        let spawned = std::thread::Builder::new()
            .name(thread.clone())
            .spawn(move || {
                if let Err(e) = start() {
                    warn!("The {thread} thread does not run: {e}");
                    return;
                }
                loop {
                    let job = match rx.lock() {
                        Ok(rx) => rx.recv(),
                        Err(_) => return,
                    };
                    match job {
                        Ok(job) => job(),
                        Err(_) => return,
                    }
                }
            });
        if let Err(e) = spawned {
            warn!("Cannot start a {name} thread: {e}");
        }
    }
    tx
}

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

impl Shared {
    /// Start the I/O threads if they are not: from the thread of the
    /// session, which is confined, so that they have its confinement.
    fn start_io(&self) {
        let mut io = self.io.lock().unwrap_or_else(|e| e.into_inner());
        if io.is_none() {
            let count = std::thread::available_parallelism()
                .map_or(4, |n| n.get())
                .clamp(2, MAX_IO_THREADS);
            *io = Some(workers("fuse-io", count, || Ok(())));
        }
    }

    /// Run `job` on an I/O thread (here when there is none).
    fn io(&self, job: Job) {
        // Nothing else asked meanwhile: done here, without the hand-over
        // to a thread (a single reader is not slowed down).
        if !self.more_requests() {
            return job();
        }
        self.start_io();
        self.on_io_thread(job);
    }

    /// Run `job` on an I/O thread, here when there is none.
    fn on_io_thread(&self, job: Job) {
        let job = match self.io.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(tx) => match tx.send(job) {
                Ok(()) => return,
                Err(mpsc::SendError(job)) => job,
            },
            None => job,
        };
        job();
    }

    /// Whether the kernel has more requests waiting on the session's device.
    fn more_requests(&self) -> bool {
        let Some(dev) = self.device.get() else {
            return true;
        };
        let mut fds = [rustix::event::PollFd::new(
            dev,
            rustix::event::PollFlags::IN,
        )];
        let now = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        matches!(rustix::event::poll(&mut fds, Some(&now)), Ok(n) if n > 0)
    }

    /// Where a file is: the store, or the staging of the mount.
    fn find(&self, digest: &str) -> Option<std::path::PathBuf> {
        self.store
            .get_path(digest)
            .or_else(|| self.staging.get().and_then(|s| s.get_path(digest)))
    }

    /// The local file for a digest, if the store has it.  Never remembered
    /// when it is missing: whoever wrote it, it is used as soon as it is
    /// there.  Err(EIO): the store has it, without the fs-verity digest it
    /// must have, or not of the `size` of the file.
    fn local(&self, digest: &str, size: u64) -> Result<Option<File>, i32> {
        if self.verity.is_enforced() {
            return self.enforced_local(digest, size).map(Some);
        }
        // (a file of the staging is opened beneath it, never through a
        // symlink, and what is checked is the descriptor that is served)
        let (file, stored) = match self.store.get_path(digest) {
            Some(path) => match File::open(path) {
                Ok(file) => (file, true),
                Err(_) => return Ok(None),
            },
            None => match self.staging.get().and_then(|s| s.open_object(digest)) {
                Some(Ok(file)) => (file, false),
                Some(Err(e)) => {
                    error!("The staged file {digest} is not served: {e}");
                    return Err(libc::EIO);
                }
                None => return Ok(None),
            },
        };
        self.verity.check(digest, &file, stored)?;
        let len = file.metadata().map_err(|e| errno_of(&e))?.len();
        if len != size {
            error!("The file {digest} has {len} bytes, the image says {size}");
            return Err(libc::EIO);
        }
        Ok(Some(file))
    }

    /// The file `digest` of an image whose digests are enforced, as the
    /// kernel's overlay with `verity=require` checks a stub: the object is
    /// opened once, strictly (`FileStore::open_object`), measured on that
    /// descriptor and compared with the digest the stub states (the
    /// `digest`), and the reads are served from the same descriptor.  A file
    /// that is not there, is not a regular file, has no fs-verity, another
    /// digest or another size is EIO, never served unchecked.
    fn enforced_local(&self, digest: &str, size: u64) -> Result<File, i32> {
        let opened = self
            .store
            .open_object(digest)
            .or_else(|| self.staging.get().and_then(|s| s.open_object(digest)));
        let file = match opened {
            Some(Ok(file)) => file,
            Some(Err(e)) => {
                error!("The file {digest} of the store is not served: {e}");
                self.verity.broken(digest, "a regular file", &e.to_string());
                return Err(libc::EIO);
            }
            None => {
                error!("The file {digest} of the image is not in the store");
                self.verity.broken(digest, "a file of the store", "none");
                return Err(libc::EIO);
            }
        };
        self.verity.check(digest, &file, true)?;
        let len = file.metadata().map_err(|e| errno_of(&e))?.len();
        if len != size {
            error!("The file {digest} has {len} bytes, the image says {size}");
            self.verity
                .broken(digest, &format!("{size} bytes"), &format!("{len} bytes"));
            return Err(libc::EIO);
        }
        Ok(file)
    }

    /// Make the fetch of `digest` happen, and call `waiter` with its
    /// outcome.  One fetch runs for all the waiters of a digest.
    fn wait_for(self: &Arc<Self>, digest: &str, layer: &str, waiter: Waiter) {
        let Some(fetcher) = self.fetcher.clone() else {
            return waiter(Err(libc::ENOENT));
        };
        // (the waiters are answered on the I/O threads, never on the
        // unconfined fetch thread: they are made here, on a confined one)
        self.start_io();
        {
            let mut waiting = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(list) = waiting.get_mut(digest) {
                list.push(waiter);
                return;
            }
            waiting.insert(digest.to_string(), vec![waiter]);
        }
        let this = self.clone();
        let key = digest.to_string();
        let (digest, layer) = (digest.to_string(), layer.to_string());
        let job: Job = Box::new(move || {
            // Somebody may have stored it since the read looked.
            let outcome = if this.find(&digest).is_some() {
                Ok(())
            } else {
                // (each waiter opens and checks the file it serves)
                fetcher
                    .fetch_file_blocking(&digest, &layer, None)
                    .map(|_| ())
                    .map_err(|e| {
                        error!("Lazy fetch of {} failed: {}", digest, e);
                        libc::EIO
                    })
            };
            let list = this
                .waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&digest)
                .unwrap_or_default();
            // (what they do with the file, open it, measure it, read it and
            // answer, is the confined I/O threads' work, not this thread's)
            for w in list {
                this.on_io_thread(Box::new(move || w(outcome)));
            }
        });
        let sent = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|tx| tx.send(job));
        if !matches!(sent, Some(Ok(()))) {
            // No thread to run it: nobody may wait for ever.
            let list = self
                .waiting
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key)
                .unwrap_or_default();
            for w in list {
                w(Err(libc::EIO));
            }
        }
    }

    /// The handle `fh`.
    fn handle(&self, fh: u64) -> Option<Arc<Handle>> {
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&fh)
            .cloned()
    }

    fn add_handle(
        &self,
        ino: u64,
        digest: &str,
        layer: &str,
        size: u64,
        file: Option<File>,
        backing: Option<Arc<fuser::BackingId>>,
    ) -> u64 {
        let fh = self.next_fh.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                fh,
                Arc::new(Handle {
                    digest: digest.to_string(),
                    size,
                    layer: layer.to_string(),
                    local: Mutex::new(file.map(Arc::new)),
                    ino,
                    backing,
                }),
            );
        fh
    }
}

/// Read from a file into a reply: what the file has of the `total` bytes
/// the image says it has, never more.  A file that ends before them (it
/// was cut after the open) is an error, not a short read.
fn read_into(file: &File, offset: u64, size: u32, total: u64, reply: ReplyData) {
    let want = total.saturating_sub(offset).min(size as u64) as usize;
    let mut buf = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        match file.read_at(&mut buf[filled..], offset + filled as u64) {
            Ok(0) => {
                error!(
                    "A file of the image ended at {} of {total} bytes",
                    offset + filled as u64
                );
                return reply.error(libc::EIO);
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return reply.error(errno_of(&e)),
        }
    }
    reply.data(&buf);
}

impl Shared {
    /// Open the file `digest` (of `layer`) of the image: through the
    /// kernel where it may, else a handle the reads use.
    fn open(self: &Arc<Self>, ino: u64, digest: &str, layer: &str, size: u64, reply: ReplyOpen) {
        let local = match self.local(digest, size) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        let Some(file) = local else {
            if self.fetcher.is_none() {
                error!("The file {digest} of the image is not in the store");
                return reply.error(libc::ENOENT);
            }
            // The open does not wait: the first read does, and takes the
            // local file if it has come meanwhile.
            let fh = self.add_served(ino, digest, layer, size, None);
            return reply.opened(fh, consts::FOPEN_KEEP_CACHE);
        };
        if self.passthrough.load(Ordering::Relaxed) {
            let mut inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
            let io = inodes.entry(ino).or_default();
            if io.served == 0 {
                let backing = match io.backing.upgrade() {
                    Some(b) => Ok(b),
                    None => reply.open_backing(&file).map(Arc::new),
                };
                match backing {
                    Ok(b) => {
                        io.backing = Arc::downgrade(&b);
                        drop(inodes);
                        let fh =
                            self.add_handle(ino, digest, layer, size, Some(file), Some(b.clone()));
                        // The kernel has the page cache of the backing file.
                        return reply.opened_passthrough(fh, 0, &b);
                    }
                    Err(e) => {
                        // Not allowed here (it needs privileges), or not
                        // there: files are served.
                        debug!("No passthrough: {e}");
                        self.passthrough.store(false, Ordering::Relaxed);
                    }
                }
            }
        }
        let fh = self.add_served(ino, digest, layer, size, Some(file));
        reply.opened(fh, consts::FOPEN_KEEP_CACHE);
    }

    /// A handle whose reads are served, counted for its inode.
    fn add_served(
        &self,
        ino: u64,
        digest: &str,
        layer: &str,
        size: u64,
        file: Option<File>,
    ) -> u64 {
        self.inodes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(ino)
            .or_default()
            .served += 1;
        self.add_handle(ino, digest, layer, size, file, None)
    }

    /// Forget the handle `fh` (the backing file of the inode goes with its
    /// last passthrough handle).
    fn release(&self, fh: u64) {
        let Some(h) = self
            .handles
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&fh)
        else {
            return;
        };
        let mut inodes = self.inodes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(io) = inodes.get_mut(&h.ino) {
            if h.backing.is_none() {
                io.served = io.served.saturating_sub(1);
            }
            let last = h.backing.as_ref().is_none_or(|b| Arc::strong_count(b) == 1);
            if io.served == 0 && last {
                inodes.remove(&h.ino);
            }
        }
    }

    /// Read `size` bytes at `offset` of the file of `handle`, waiting for
    /// its fetch if it is not there yet.
    fn read(self: &Arc<Self>, handle: &Arc<Handle>, offset: u64, size: u32, reply: ReplyData) {
        let have = handle
            .local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(file) = have {
            return read_into(&file, offset, size, handle.size, reply);
        }
        // The file was not there when it was opened: it may be now.
        let local = match self.local(&handle.digest, handle.size) {
            Ok(l) => l,
            Err(e) => return reply.error(e),
        };
        if let Some(file) = local {
            let file = Arc::new(file);
            *handle.local.lock().unwrap_or_else(|e| e.into_inner()) = Some(file.clone());
            return read_into(&file, offset, size, handle.size, reply);
        }
        let h = handle.clone();
        let waiter = self.clone();
        self.wait_for(
            &handle.digest,
            &handle.layer,
            Box::new(move |outcome| match outcome {
                Err(e) => reply.error(e),
                Ok(()) => match waiter.local(&h.digest, h.size) {
                    Ok(Some(file)) => {
                        let file = Arc::new(file);
                        *h.local.lock().unwrap_or_else(|e| e.into_inner()) = Some(file.clone());
                        read_into(&file, offset, size, h.size, reply);
                    }
                    Ok(None) => reply.error(libc::EIO),
                    Err(e) => reply.error(e),
                },
            }),
        );
    }
}

impl Filesystem for ImageFs {
    fn init(&mut self, _req: &Request<'_>, config: &mut KernelConfig) -> Result<(), libc::c_int> {
        // (without it the kernel runs the lookups of a directory one at a
        // time, and one waiting for a fetch holds up the others)
        let _ = config.add_capabilities(consts::FUSE_PARALLEL_DIROPS);
        // Large reads ahead: fewer, larger requests for the I/O threads.
        if let Err(max) = config.set_max_readahead(MAX_READAHEAD) {
            let _ = config.set_max_readahead(max);
        }
        // Files of the store are read by the kernel itself, where it can
        // (the backing files may be on a stacked file system: this one is
        // the lower layer of an overlay).
        // Not for the users of a user namespace: reading the backing file
        // through the overlay fails for them (EIO).
        if self.translate.is_none()
            && config.add_capabilities(consts::FUSE_PASSTHROUGH).is_ok()
            && config.set_max_stack_depth(1).is_ok()
        {
            self.shared.passthrough.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let found = name.to_str().and_then(|n| self.tree.lookup(parent, n));
        match found.and_then(|i| self.tree.attr(i).map(|a| (i, a))) {
            Some((i, a)) => {
                let kind = a.kind;
                let size = a.size;
                let blocks = self.stored_blocks(i, &a);
                let attr = file_attr(i, a, blocks, self.translate.as_ref());
                // A regular file of a mount with a staging is there when the
                // lookup answers: the overlay follows the redirect of the
                // stub in the same lookup.
                let missing = (self.shared.staging.get().is_some()
                    && kind == FileType::RegularFile
                    && size > 0)
                    .then(|| self.tree.file(i))
                    .flatten()
                    .and_then(|f| {
                        let d = f.digest?;
                        self.shared
                            .find(&d)
                            .is_none()
                            .then(|| (d, self.layers.get(f.layer).cloned().unwrap_or_default()))
                    });
                if let (Some(rec), FileType::RegularFile) = (self.shared.recording.get(), kind) {
                    if let Some(d) = self.tree.file(i).and_then(|f| f.digest) {
                        rec.note(&d);
                    }
                }
                match missing {
                    None => reply.entry(&TTL, &attr, 0),
                    Some((digest, layer)) => {
                        let shared = self.shared.clone();
                        self.shared.io(Box::new(move || {
                            let found = shared.clone();
                            let d = digest.clone();
                            let waiter: Waiter = Box::new(move |outcome| match outcome {
                                Ok(()) => {
                                    // (the blocks of the object, now that it is there)
                                    let mut attr = attr;
                                    if attr.size > SPARSE_MIN {
                                        use std::os::unix::fs::MetadataExt;
                                        if let Some(m) = found
                                            .find(&d)
                                            .and_then(|p| std::fs::symlink_metadata(p).ok())
                                        {
                                            attr.blocks = m.blocks();
                                        }
                                    }
                                    reply.entry(&TTL, &attr, 0)
                                }
                                Err(e) => reply.error(e),
                            });
                            shared.wait_for(&digest, &layer, waiter);
                        }));
                    }
                }
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.tree.attr(ino) {
            Some(a) => {
                let blocks = self.stored_blocks(ino, &a);
                reply.attr(&TTL, &file_attr(ino, a, blocks, self.translate.as_ref()))
            }
            None => reply.error(libc::ENOENT),
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        match self.tree.attr(ino) {
            Some(a) if a.kind == FileType::Symlink => match self.tree.readlink(ino) {
                Ok(target) => reply.data(&target),
                Err(e) => {
                    warn!("readlink of {ino}: {e}");
                    reply.error(e.raw_os_error().unwrap_or(libc::EIO));
                }
            },
            Some(_) => reply.error(libc::EINVAL),
            None => reply.error(libc::ENOENT),
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(attr) = self.tree.attr(ino) else {
            return reply.error(libc::ENOENT);
        };
        if attr.kind == FileType::Directory {
            return reply.error(libc::EISDIR);
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            return reply.error(libc::EROFS);
        }
        let Some(file) = self.tree.file(ino) else {
            return reply.error(libc::ENOENT);
        };
        if file.size == 0 {
            // Nothing to read: the content of an empty file is not needed.
            return reply.opened(0, consts::FOPEN_KEEP_CACHE);
        }
        if file.inline.is_some() {
            return reply.opened(INLINE_FH, consts::FOPEN_KEEP_CACHE);
        }
        let Some(digest) = file.digest else {
            // (enforced: a stub that names no file breaks the chain, as the
            // kernel's overlay refuses a stub without a digest)
            return reply.error(match self.shared.verity.is_enforced() {
                true => libc::EIO,
                false => libc::ENOENT,
            });
        };
        let layer = self.layers.get(file.layer).cloned().unwrap_or_default();
        let size = file.size;
        let shared = self.shared.clone();
        self.shared.io(Box::new(move || {
            shared.open(ino, &digest, &layer, size, reply)
        }));
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if fh == INLINE_FH {
            // a file the image holds: its bytes are the tree's
            let Some(data) = self.tree.file(ino).and_then(|f| f.inline) else {
                return reply.error(libc::ENOENT);
            };
            let Ok(start) = usize::try_from(offset) else {
                return reply.error(libc::EINVAL);
            };
            let start = start.min(data.len());
            let end = start.saturating_add(size as usize).min(data.len());
            return reply.data(&data[start..end]);
        }
        let Some(handle) = self.shared.handle(fh) else {
            return reply.data(&[]);
        };
        let Ok(offset) = u64::try_from(offset) else {
            return reply.error(libc::EINVAL);
        };
        let shared = self.shared.clone();
        self.shared
            .io(Box::new(move || shared.read(&handle, offset, size, reply)));
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.shared.release(fh);
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        match self.tree.attr(ino) {
            None => return reply.error(libc::ENOENT),
            Some(a) if a.kind != FileType::Directory => return reply.error(libc::ENOTDIR),
            Some(_) => {}
        }
        // The tree has no parent links: the kernel resolves ".." itself.
        let parent_ino = ino;
        let mut index = 0i64;
        let fixed = [(ino, "."), (parent_ino, "..")];
        for (i, name) in fixed {
            index += 1;
            if index > offset && reply.add(i, index, FileType::Directory, name) {
                return reply.ok();
            }
        }
        let skip = usize::try_from(offset.saturating_sub(index)).unwrap_or(0);
        index += skip as i64;
        let listed = self.tree.readdir(ino, skip, &mut |child, kind, name| {
            index += 1;
            reply.add(child, index, kind, OsStr::from_bytes(name))
        });
        match listed {
            Ok(()) => reply.ok(),
            Err(e) => {
                warn!("readdir of {ino}: {e}");
                reply.error(e.raw_os_error().unwrap_or(libc::EIO));
            }
        }
    }

    fn getxattr(&mut self, _req: &Request, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        let Some(xattrs) = self.tree.xattrs(ino) else {
            return reply.error(libc::ENOENT);
        };
        let value = name
            .to_str()
            .and_then(|n| xattrs.into_iter().find(|(k, _)| k == n))
            .map(|(_, v)| v);
        match value {
            None => reply.error(libc::ENODATA),
            Some(v) if size == 0 => reply.size(v.len() as u32),
            Some(v) if v.len() > size as usize => reply.error(libc::ERANGE),
            Some(v) => reply.data(&v),
        }
    }

    fn listxattr(&mut self, _req: &Request, ino: u64, size: u32, reply: ReplyXattr) {
        let Some(xattrs) = self.tree.xattrs(ino) else {
            return reply.error(libc::ENOENT);
        };
        let mut list = Vec::new();
        for (name, _) in &xattrs {
            list.extend_from_slice(name.as_bytes());
            list.push(0);
        }
        if size == 0 {
            reply.size(list.len() as u32);
        } else if list.len() > size as usize {
            reply.error(libc::ERANGE);
        } else {
            reply.data(&list);
        }
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, self.tree.len(), 0, 4096, 255, 4096);
    }
}

/// The mounts of the merged file systems of the images in use.
pub struct ImageMounts {
    store: Arc<FileStore>,
    fetcher: Mutex<Option<Arc<dyn LazyFileFetcher>>>,
    verity: Mutex<Arc<super::verity::Verity>>,
    /// Where the files fetched for the mapped trees are.
    staging: Mutex<Option<Arc<FileStore>>>,
    /// The startup profile that the mapped trees note their lookups for.
    recording: Mutex<Option<Arc<super::profile::Recording>>>,
    /// What the thread of each session does before it serves
    confine: Mutex<Option<Confine>>,
    /// The sessions of the detached mounts (`mount_tree_detached`), which end
    /// by themselves.
    detached: Mutex<Vec<std::thread::JoinHandle<fuser::Session<ImageFs>>>>,
    /// The mounts the tests make at a path (`path_mount`).
    #[cfg(test)]
    root: PathBuf,
    #[cfg(test)]
    mounts: Mutex<HashMap<String, path_mount::Mounted>>,
}

#[cfg(test)]
mod path_mount;

/// What the session of a mount reads beneath: the files of the stores and of
/// the staging.
fn read_dirs(store: &FileStore, staging: Option<&FileStore>) -> Vec<PathBuf> {
    std::iter::once(store.root().to_path_buf())
        .chain(store.additional().iter().cloned())
        .chain(staging.into_iter().flat_map(|f| {
            std::iter::once(f.root().to_path_buf()).chain(f.additional().iter().cloned())
        }))
        .collect()
}

/// What the thread of a FUSE session calls before it serves the kernel:
/// it confines itself, reading beneath the directories it is given only
/// (the store and the staging).
pub type Confine = Arc<dyn Fn(&[PathBuf]) -> std::io::Result<()> + Send + Sync>;

impl ImageMounts {
    pub fn new(store: Arc<FileStore>) -> Self {
        Self {
            store,
            fetcher: Mutex::new(None),
            verity: Mutex::new(Arc::default()),
            staging: Mutex::new(None),
            recording: Mutex::new(None),
            confine: Mutex::new(None),
            detached: Mutex::new(Vec::new()),
            #[cfg(test)]
            root: PathBuf::new(),
            #[cfg(test)]
            mounts: Mutex::new(HashMap::new()),
        }
    }

    /// The sessions mounted from now on confine their threads with
    /// `confine` before they serve.
    pub fn set_confinement(&self, confine: Confine) {
        *self.confine.lock().unwrap_or_else(|e| e.into_inner()) = Some(confine);
    }

    /// The trees mapped from now on (`mount_tree_detached`) note the files looked up
    /// in `recording`.
    pub fn set_recording(&self, recording: Arc<super::profile::Recording>) {
        *self.recording.lock().unwrap_or_else(|e| e.into_inner()) = Some(recording);
    }

    /// The trees mapped from now on (`mount_tree_detached`) wait at the lookup of a
    /// file until it is in the store or in `files`.
    pub fn set_staging(&self, files: Arc<FileStore>) {
        *self.staging.lock().unwrap_or_else(|e| e.into_inner()) = Some(files);
    }

    pub fn set_lazy_fetcher(&self, fetcher: Arc<dyn LazyFileFetcher>) {
        *self.fetcher.lock().unwrap_or_else(|e| e.into_inner()) = Some(fetcher);
    }

    /// The fs-verity digests the files of the mounts made from now on must
    /// have.
    pub fn set_verity(&self, verity: Arc<super::verity::Verity>) {
        *self.verity.lock().unwrap_or_else(|e| e.into_inner()) = verity;
    }

    /// The thread that serves `session` of `fs`, once it has confined itself
    /// (the threads it makes have the confinement); it gives the session back
    /// when it ends.  `shown` names the mount in the log.
    fn run_session(
        &self,
        session: fuser::Session<ImageFs>,
        shared: Arc<Shared>,
        shown: &str,
    ) -> FuseResult<std::thread::JoinHandle<fuser::Session<ImageFs>>> {
        let read = read_dirs(&shared.store, shared.staging.get().map(|f| &**f));
        let confine = self
            .confine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut session = session;
        match std::os::fd::AsFd::as_fd(&session).try_clone_to_owned() {
            Ok(dev) => {
                let _ = shared.device.set(dev);
            }
            Err(e) => warn!("No duplicate of the FUSE device: every read goes to a thread: {e}"),
        }
        let shown = shown.to_string();
        // (`ready` says why the thread cannot serve; it is dropped without
        // a word when the thread ends otherwise)
        let (ready, started) = mpsc::sync_channel::<Result<(), String>>(1);
        let name = shown.clone();
        let thread = std::thread::Builder::new()
            .name("fuse".into())
            .spawn(move || {
                if let Some(confine) = confine {
                    if let Err(e) = confine(&read) {
                        let _ =
                            ready.send(Err(format!("cannot confine the server of {name}: {e}")));
                        return session;
                    }
                }
                let _ = ready.send(Ok(()));
                if let Err(e) = session.run() {
                    warn!("The FUSE session of {name} ended: {e}");
                }
                session
            })
            .map_err(|e| FuseError::Mount(format!("cannot serve {shown}: {e}")))?;
        let why = match started.recv() {
            Ok(Ok(())) => return Ok(thread),
            Ok(Err(why)) => why,
            Err(_) => format!("cannot serve {shown}"),
        };
        // (the thread ended: its session is dropped here)
        drop(thread.join());
        Err(FuseError::Mount(why))
    }

    /// The layers of a tree that is read where it is mapped
    /// (`erofs_tree::Layers`) served as a detached mount, for the kernel
    /// overlay to read as its lower layers (`owners` are those of the files,
    /// `layers` the digests of the layers for the fetch of what the store
    /// lacks): no path names it, the descriptor is the only way to it, and
    /// its session ends by itself when the last reference to the file system goes (the mount
    /// descriptors, the mounts cloned from them, the processes in it).  The
    /// mount is read only, `nodev` and `nosuid`.  Nobody unmounts it:
    /// [`wait_detached`](Self::wait_detached) returns when it has ended.
    pub fn mount_tree_detached(
        &self,
        tree: Arc<dyn Tree>,
        layers: Vec<String>,
        owners: (Vec<u32>, Vec<u32>),
        translate: Option<&IdTranslate>,
    ) -> FuseResult<OwnedFd> {
        let fs = self.tree_fs(tree, layers, owners, translate)?;
        let shared = fs.shared.clone();
        let (mount, dev) = crate::detached::fuse_mount("velarx", translate.is_some())
            .map_err(|e| FuseError::Mount(format!("cannot mount the FUSE file system: {e}")))?;
        let acl = match translate.is_some() {
            true => fuser::SessionACL::All,
            false => fuser::SessionACL::Owner,
        };
        let session = fuser::Session::from_fd(fs, dev, acl);
        let thread = self.run_session(session, shared, "the image")?;
        self.detached
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(thread);
        Ok(mount)
    }

    /// Confine the calling thread as the thread of each session confines
    /// itself (`set_confinement`; none set: nothing is done): for a process
    /// whose other threads do no more than wait once its mounts are made.
    pub fn confine_caller(&self) -> std::io::Result<()> {
        let confine = self
            .confine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(confine) = confine else {
            return Ok(());
        };
        let staging = self
            .staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        confine(&read_dirs(&self.store, staging.as_deref()))
    }

    /// Wait until the sessions of the detached mounts have ended, and the
    /// startup profile, if one is noted, is saved by the thread that was made
    /// for it (the caller may be confined and unable to write it).
    pub fn wait_detached(&self) {
        let threads = std::mem::take(&mut *self.detached.lock().unwrap_or_else(|e| e.into_inner()));
        for t in threads {
            drop(t.join());
        }
        let recording = self
            .recording
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(recording) = recording {
            recording.finish();
        }
    }

    /// The file system of `tree`, for the mounts above.
    fn tree_fs(
        &self,
        tree: Arc<dyn Tree>,
        layers: Vec<String>,
        owners: (Vec<u32>, Vec<u32>),
        translate: Option<&IdTranslate>,
    ) -> FuseResult<ImageFs> {
        if let Some(why) = translate.and_then(|t| t.unmapped_owners_error(&owners)) {
            return Err(FuseError::Mount(why));
        }
        let fs = ImageFs::new(
            tree,
            layers,
            self.store.clone(),
            self.fetcher
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            translate.cloned(),
            self.verity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        );
        if let Some(files) = self
            .staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            let _ = fs.shared.staging.set(files);
        }
        if let Some(recording) = self
            .recording
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            let _ = fs.shared.recording.set(recording);
        }
        Ok(fs)
    }
}

/// Unmount `path`.  A mount that is busy (the mount namespace of a
/// container that just ended is released a moment after its last process,
/// and nothing says when) is detached at once: its file system lives on
/// until nothing uses it, and its server ends when the kernel releases it
/// (its device reads the end), so nothing waits for that here.
pub fn unmount_or_detach(path: &Path) {
    use rustix::io::Errno;
    use rustix::mount::{unmount, UnmountFlags};
    match unmount(path, UnmountFlags::empty()) {
        Ok(()) | Err(Errno::INVAL) | Err(Errno::NOENT) => return,
        Err(_) => {}
    }
    match unmount(path, UnmountFlags::DETACH) {
        Ok(()) => debug!("{} was busy: detached", path.display()),
        Err(Errno::INVAL) | Err(Errno::NOENT) => {}
        Err(e) => warn!("Cannot unmount {}: {}", path.display(), e),
    }
}

/// Detach every mount stacked on `path` (none is fine).
pub fn detach_stale(path: &Path) -> io::Result<()> {
    let n = velarx_base::mountinfo::detach_stacked(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot detach the stale mount on {}: {e}", path.display()),
        )
    })?;
    if n > 0 {
        debug!("Detached {n} stale mounts on {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_storage::{Toc, TocEntryType};

    #[test]
    fn a_time_before_the_epoch_is_given_as_the_kernel_adds_it() {
        let epoch = SystemTime::UNIX_EPOCH;
        let before = |s, n| kernel_time(epoch - Duration::new(s, n));
        // (86400.75 s before the epoch is -86401 s and 250 ms after them)
        assert_eq!(
            before(86400, 750_000_000),
            epoch - Duration::new(86401, 250_000_000)
        );
        assert_eq!(before(2, 0), epoch - Duration::new(2, 0));
        let after = epoch + Duration::new(5, 1);
        assert_eq!(kernel_time(after), after);
    }

    #[test]
    fn overlay_and_selinux_attributes_are_hidden() {
        for n in [
            "trusted.overlay.opaque",
            "user.overlay.redirect",
            "security.selinux",
            "system.overlay.x",
            "user.",
        ] {
            assert!(hidden_xattr(n), "{n}");
        }
        for n in [
            "user.k",
            "security.capability",
            "trusted.other",
            "security.selinuxx",
        ] {
            assert!(!hidden_xattr(n), "{n}");
        }
    }
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    use velarx_storage::TocEntry;

    fn entry(name: &str, t: TocEntryType) -> TocEntry {
        TocEntry {
            mode: 0o644,
            mod_time: Some("2023-11-14T22:13:20+00:00".into()),
            ..TocEntry::new(name, t)
        }
    }

    fn put(store: &FileStore, data: &[u8]) -> (String, u64) {
        let digest = store
            .put(velarx_types::digest::Algorithm::Sha256, data)
            .unwrap();
        (digest, data.len() as u64)
    }

    /// The layers `(digest, TOC)` as their images, mounted: the directory of
    /// the lowest layer.
    fn mount_tocs(
        mounts: &ImageMounts,
        image: &str,
        layers: &[(String, Toc)],
        translate: Option<&IdTranslate>,
    ) -> FuseResult<PathBuf> {
        let mut images = Vec::new();
        let mut indexes = Vec::new();
        let (mut uids, mut gids) = (Vec::new(), Vec::new());
        for (_, toc) in layers {
            let built = crate::layer_erofs::layer_image(&toc.entries).map_err(FuseError::Mount)?;
            uids.extend(built.owners.0);
            gids.extend(built.owners.1);
            images.push(crate::erofs_tree::Layer::open(Box::new(built.image)).unwrap());
            indexes.push(crate::erofs_tree::Index::from_bytes(Box::new(built.index)).unwrap());
        }
        let tree = crate::erofs_tree::Layers::new(
            images,
            Some(indexes),
            false,
            crate::erofs_tree::Stubs::Every,
        );
        let digests = layers.iter().map(|(d, _)| d.clone()).collect();
        let root = mounts.mount_tree(image, Arc::new(tree), digests, (uids, gids), translate)?;
        Ok(root.join("layer1"))
    }

    use velarx_proto::pod::IdMapping;

    fn owned(name: &str, uid: u32, gid: u32) -> TocEntry {
        let mut e = entry(name, TocEntryType::Reg);
        (e.uid, e.gid) = (uid, gid);
        e
    }

    fn m(c: u32, h: u32, n: u32) -> IdMapping {
        IdMapping {
            container_id: c,
            host_id: h,
            size: n,
        }
    }

    /// What stops a FUSE mount of the kind the tests make, found once by
    /// [`probe`] (an empty file system, not the image one): `allow_other` for
    /// the mounts that translate ids, `overlay` for an overlay of a user
    /// namespace over one.  None when the host can: a mount that fails then
    /// is an error.
    fn fuse_missing(kind: Probe) -> Option<&'static str> {
        use std::sync::OnceLock;
        static PLAIN: OnceLock<Option<String>> = OnceLock::new();
        static OTHER: OnceLock<Option<String>> = OnceLock::new();
        static OVERLAY: OnceLock<Option<String>> = OnceLock::new();
        let (cell, kind) = match kind {
            Probe::Plain => (&PLAIN, kind),
            Probe::AllowOther => (&OTHER, kind),
            Probe::Overlay => (&OVERLAY, kind),
        };
        // (in a process of its own: the threads of the sessions it mounts
        // end after it, among the tasks the tests look at.  This binary run
        // again for the probe alone, not a fork: the other tests of this
        // process hold locks at any time, and the session thread of a forked
        // probe waited for one forever, its mount with it)
        cell.get_or_init(|| {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "image_fs::tests::fuse_probe",
                    "--ignored",
                    "--nocapture",
                ])
                .env(PROBE_KIND, kind.name())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .status()
                .expect("run the probe of FUSE");
            match status.code() {
                Some(0) => None,
                Some(PROBE_CANNOT) => {
                    Some("FUSE cannot be mounted here this way (see above)".to_string())
                }
                _ => panic!("the probe of FUSE ended abnormally: {status:?}"),
            }
        })
        .as_deref()
    }

    #[derive(Clone, Copy)]
    enum Probe {
        Plain,
        AllowOther,
        Overlay,
    }

    impl Probe {
        fn name(self) -> &'static str {
            match self {
                Probe::Plain => "plain",
                Probe::AllowOther => "allow-other",
                Probe::Overlay => "overlay",
            }
        }
    }

    /// The kind of the probe [`fuse_probe`] makes, by [`Probe::name`].
    const PROBE_KIND: &str = "VELARX_TEST_FUSE_PROBE";
    /// The code of a probe that found the host cannot mount FUSE that way.
    const PROBE_CANNOT: i32 = 3;

    /// The probe of [`fuse_missing`], in a run of this binary of its own:
    /// it ends the process with 0 when the host can, [`PROBE_CANNOT`] when
    /// it cannot.  Run by itself, without the variable, it does nothing.
    #[test]
    #[ignore = "run by fuse_missing in a process of its own"]
    fn fuse_probe() {
        let Ok(name) = std::env::var(PROBE_KIND) else {
            return;
        };
        let kind = [Probe::Plain, Probe::AllowOther, Probe::Overlay]
            .into_iter()
            .find(|k| k.name() == name)
            .expect("a kind of probe");
        let code = match probe(kind) {
            Ok(()) => 0,
            Err(why) => {
                eprintln!("{why}");
                PROBE_CANNOT
            }
        };
        std::process::exit(code);
    }

    /// A file system of an empty directory and nothing else: what the probe
    /// mounts, so that it finds what the host allows and not what the image
    /// file system does.
    struct Empty;

    impl Filesystem for Empty {
        fn getattr(&mut self, _: &Request<'_>, ino: u64, _: Option<u64>, reply: ReplyAttr) {
            if ino != fuser::FUSE_ROOT_ID {
                return reply.error(libc::ENOENT);
            }
            let t = std::time::UNIX_EPOCH;
            reply.attr(
                &TTL,
                &FileAttr {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: t,
                    mtime: t,
                    ctime: t,
                    crtime: t,
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid: rustix::process::getuid().as_raw(),
                    gid: rustix::process::getgid().as_raw(),
                    rdev: 0,
                    blksize: 4096,
                    flags: 0,
                },
            );
        }

        fn lookup(&mut self, _: &Request<'_>, _: u64, _: &OsStr, reply: ReplyEntry) {
            reply.error(libc::ENOENT);
        }
    }

    /// Whether the host lets this process mount FUSE as the tests do: an
    /// empty file system, mounted with the options of [`ImageMounts::serve`]
    /// (`allow_other` for the mounts that translate ids), and for `Overlay` an
    /// overlay of a user namespace over it.  The image file system plays no
    /// part: a failure of its own is a failure of the test, never a skip.
    fn probe(kind: Probe) -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mnt = tmp.path().join("mnt");
        std::fs::create_dir(&mnt).map_err(|e| e.to_string())?;
        let mut options = vec![
            fuser::MountOption::RO,
            fuser::MountOption::FSName("velarx-probe".to_string()),
            fuser::MountOption::DefaultPermissions,
        ];
        if matches!(kind, Probe::AllowOther) {
            options.push(fuser::MountOption::AllowOther);
        }
        let session = fuser::spawn_mount2(Empty, &mnt, &options)
            .map_err(|e| format!("cannot mount FUSE here: {e}"))?;
        let r = std::fs::metadata(&mnt)
            .map_err(|e| format!("a FUSE mount here does not answer: {e}"))
            .and_then(|_| match kind {
                Probe::Overlay => overlay_probe(tmp.path(), &mnt),
                _ => Ok(()),
            });
        drop(session);
        r
    }

    /// An overlay of a user namespace whose lower layer is the FUSE mount
    /// `lower`, with the options the tests use.
    fn overlay_probe(tmp: &Path, lower: &Path) -> Result<(), String> {
        let dirs: Vec<PathBuf> = ["data", "upper", "work", "merged"]
            .iter()
            .map(|d| tmp.join(d))
            .collect();
        for d in &dirs {
            std::fs::create_dir(d).map_err(|e| e.to_string())?;
        }
        let mount = format!(
            "mount -t overlay overlay -o lowerdir+={},datadir+={},upperdir={},workdir={},userxattr {}",
            lower.display(),
            dirs[0].display(),
            dirs[1].display(),
            dirs[2].display(),
            dirs[3].display()
        );
        let done = std::process::Command::new("unshare")
            .args(["-Urm", "sh", "-ec", &mount])
            .output();
        // (the kernel made `work/work` without any access for the user)
        velarx_base::tree::remove_dir_all_confined(&dirs[2]).map_err(|e| e.to_string())?;
        match done {
            Ok(o) if o.status.success() => Ok(()),
            Ok(o) => Err(format!(
                "no overlay of a user namespace over FUSE here: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => Err(format!("cannot run unshare: {e}")),
        }
    }

    /// The result of a mount a test asked for: `None` (the test is skipped)
    /// when the host cannot mount FUSE this way, found by [`fuse_missing`];
    /// a mount that fails on a host that can fails the test.
    fn mounted<T>(kind: Probe, r: FuseResult<T>) -> Option<T> {
        if let Some(why) = fuse_missing(kind) {
            eprintln!("skipped: {why}");
            return None;
        }
        Some(r.unwrap_or_else(|e| panic!("the mount failed where FUSE can be mounted: {e}")))
    }

    /// The owners seen through the kernel are those of the mapping, and an
    /// image with an owner outside of it is refused.
    #[test]
    fn test_translated_mount() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let toc = Toc {
            version: 1,
            entries: vec![
                owned("root", 0, 0),
                owned("user", 1000, 100),
                owned("other", 5, 6),
            ],
            tar_split_digest: None,
        };
        let layers = vec![("l0".to_string(), toc)];
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store);
        let t = IdTranslate {
            uid: vec![m(0, 300000, 1001)],
            gid: vec![m(0, 400000, 101)],
            squash: false,
        };
        let Some(path) = mounted(
            Probe::AllowOther,
            mount_tocs(&mounts, "img", &layers, Some(&t)),
        ) else {
            return;
        };
        use std::os::unix::fs::MetadataExt;
        let st = |n: &str| {
            let md = std::fs::symlink_metadata(path.join(n)).unwrap();
            (md.uid(), md.gid())
        };
        assert_eq!(st("root"), (300000, 400000));
        assert_eq!(st("user"), (301000, 400100));
        assert_eq!(st("other"), (300005, 400006));
        // The same image with another mapping is another mount.
        let wide = IdTranslate {
            uid: vec![m(0, 1000, 10)],
            gid: vec![m(0, 1000, 10)],
            squash: false,
        };
        let e = mount_tocs(&mounts, "img", &layers, Some(&wide))
            .unwrap_err()
            .to_string();
        assert!(e.contains("uid 1000"), "{e}");
        let squashed = IdTranslate {
            squash: true,
            ..wide
        };
        let p2 = mount_tocs(&mounts, "img", &layers, Some(&squashed)).unwrap();
        assert_ne!(p2, path);
        let md = std::fs::symlink_metadata(p2.join("user")).unwrap();
        assert_eq!((md.uid(), md.gid()), (1000, 1000));
        mounts.unmount_all();
    }

    /// A sparse file has the blocks its object takes in the store, not
    /// those of its size.  Skipped where FUSE cannot be mounted.
    #[test]
    fn test_a_sparse_file_has_the_blocks_of_its_object() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let mut data = vec![1u8; 4096];
        data.extend(vec![0u8; 8 << 20]);
        let digest =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data);
        let object = store.object_path(&velarx_storage::Object::new(&digest, false).unwrap());
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        let f = File::create(&object).unwrap();
        velarx_storage::copy_sparse(&data[..], &f, |_| {}).unwrap();
        let stored = f.metadata().unwrap().blocks();
        if stored >= data.len() as u64 / 512 {
            eprintln!("skipped: the file system of the store has no holes");
            return;
        }
        let mut e = entry("sparse", TocEntryType::Reg);
        (e.fsverity, e.size) = (velarx_storage::to_toc(&digest), data.len() as u64);
        let toc = Toc {
            version: 1,
            entries: vec![e],
            tar_split_digest: None,
        };
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store);
        let Some(path) = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        ) else {
            return;
        };
        let md = std::fs::metadata(path.join("sparse")).unwrap();
        assert_eq!(md.len(), data.len() as u64);
        assert_eq!(md.blocks(), stored);
        mounts.unmount_all();
    }

    /// Opens of one file at the same time, and of files that share their
    /// content, all read it (passthrough wants one backing file an inode:
    /// root runs exercise it).
    #[test]
    fn a_file_shorter_than_the_image_says_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let data: Vec<u8> = (0..(64 << 10)).map(|i| (i % 251) as u8).collect();
        let (d, size) = put(&store, &data);
        let mut e = entry("f", TocEntryType::Reg);
        (e.fsverity, e.size) = (velarx_storage::to_toc(&d.clone()), size);
        let toc = Toc {
            version: 1,
            entries: vec![e],
            tar_split_digest: None,
        };
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
        let Some(path) = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        ) else {
            return;
        };
        assert!(std::fs::read(path.join("f")).unwrap() == data);
        let cut = std::fs::OpenOptions::new()
            .write(true)
            .open(store.local_path(&d).unwrap())
            .unwrap();
        cut.set_len(size / 2).unwrap();
        drop(cut);
        let err = std::fs::read(path.join("f")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
        mounts.unmount_all();
    }

    /// The fs-verity digest the kernel gives for a file of a store that has
    /// fs-verity: here made from its content.
    fn content_verity(file: &File) -> Result<Option<String>, String> {
        velarx_storage::fsverity_digest_file(velarx_types::digest::Algorithm::Sha256, file)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    /// Where the store has fs-verity, a file of the store replaced by
    /// another (of the same size) is not served: its digest is not the one
    /// it is named by.  Without fs-verity in the store it is.
    #[test]
    fn a_file_replaced_in_a_store_with_verity_is_not_served() {
        use velarx_storage::VerityMode;
        let data = pattern(100_000);
        let other: Vec<u8> = data.iter().map(|b| b ^ 1).collect();
        for (mode, served) in [(VerityMode::Off, true), (VerityMode::On, false)] {
            let tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
            let (d, size) = put(&store, &data);
            let mut e = entry("f", TocEntryType::Reg);
            (e.fsverity, e.size) = (velarx_storage::to_toc(&d.clone()), size);
            let toc = Toc {
                version: 1,
                entries: vec![e],
                tar_split_digest: None,
            };
            let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
            mounts.set_verity(Arc::new(super::super::verity::Verity::with_measure(
                HashMap::new(),
                mode,
                content_verity,
                |_, _| Err("not computed".into()),
            )));
            let Some(path) = mounted(
                Probe::Plain,
                mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
            ) else {
                return;
            };
            assert!(std::fs::read(path.join("f")).unwrap() == data);
            let object = store.local_path(&d).unwrap();
            std::fs::remove_file(&object).unwrap();
            std::fs::write(&object, &other).unwrap();
            match std::fs::read(path.join("f")) {
                Ok(_) => assert!(served, "{mode:?}: the replaced file is served"),
                Err(err) => {
                    assert!(!served, "{mode:?}: {err}");
                    assert_eq!(err.raw_os_error(), Some(libc::EIO), "{err}");
                }
            }
            mounts.unmount_all();
        }
    }

    /// Like `content_verity`, but a file that starts with `NOVERITY` has no
    /// fs-verity.
    fn content_or_none(file: &File) -> Result<Option<String>, String> {
        let mut head = [0u8; 8];
        std::os::unix::fs::FileExt::read_at(file, &mut head, 0).map_err(|e| e.to_string())?;
        match &head == b"NOVERITY" {
            true => Ok(None),
            false => content_verity(file),
        }
    }

    /// With the digests enforced the file system does the check of the
    /// kernel's overlay on each file it opens: whatever replaces the
    /// object, but a file that has the fs-verity digest of the stub, is
    /// EIO; the file already open keeps the content that was measured, and
    /// the next open measures again.
    #[test]
    fn an_enforced_open_measures_the_file_it_serves() {
        use std::io::Read as _;
        let data = pattern(100_000);
        let other: Vec<u8> = data.iter().map(|b| b ^ 1).collect();
        let mut unverified = b"NOVERITY".to_vec();
        unverified.extend_from_slice(&data[8..]);
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let (d, size) = put(&store, &data);
        let mut e = entry("f", TocEntryType::Reg);
        (e.fsverity, e.size) = (velarx_storage::to_toc(&d.clone()), size);
        let toc = Toc {
            version: 1,
            entries: vec![e],
            tar_split_digest: None,
        };
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
        mounts.set_verity(Arc::new(
            super::super::verity::Verity::with_measure(
                HashMap::new(),
                velarx_storage::VerityMode::Require,
                content_or_none,
                |_, _| Err("not computed".into()),
            )
            .enforced(),
        ));
        let Some(path) = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        ) else {
            return;
        };
        let eio = |r: std::io::Result<Vec<u8>>, what: &str| match r {
            Ok(_) => panic!("{what}: served"),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO), "{what}: {e}"),
        };
        assert!(std::fs::read(path.join("f")).unwrap() == data);
        let object = store.local_path(&d).unwrap();
        let mut open = File::open(path.join("f")).unwrap();
        let mut seen = vec![0u8; 10];
        open.read_exact(&mut seen).unwrap();
        for what in [
            "another content",
            "no fs-verity",
            "a symlink",
            "a FIFO",
            "a directory",
            "deleted",
        ] {
            std::fs::remove_file(&object)
                .or_else(|_| std::fs::remove_dir(&object))
                .ok();
            match what {
                "another content" => std::fs::write(&object, &other).unwrap(),
                "no fs-verity" => std::fs::write(&object, &unverified).unwrap(),
                "a symlink" => {
                    let real = tmp.path().join("real");
                    std::fs::write(&real, &data).unwrap();
                    std::os::unix::fs::symlink(&real, &object).unwrap();
                }
                "a FIFO" => rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &object,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR,
                    0,
                )
                .unwrap(),
                "a directory" => std::fs::create_dir(&object).unwrap(),
                _ => {}
            }
            eio(std::fs::read(path.join("f")), what);
        }
        // the file open before keeps what was measured
        let mut rest = Vec::new();
        open.read_to_end(&mut rest).unwrap();
        assert!([seen, rest].concat() == data);
        // put back: served again
        assert!(!object.exists());
        std::fs::write(&object, &data).unwrap();
        assert!(std::fs::read(path.join("f")).unwrap() == data);
        mounts.unmount_all();
    }

    /// The overlay of a user namespace (`userxattr`) over the layer of an
    /// image served here, the store its data-only layer, follows the stub
    /// of a file to the store and reads the file there itself: a read opens
    /// no file of the store here.  A write copies the file up: the kernel
    /// opens the stub here then (for its inode flags) and copies the
    /// content from the store, also the file cut, truncated or only its mode
    /// changed.
    #[test]
    fn the_overlay_reads_the_files_of_the_store_itself() {
        use std::process::Command;
        use std::sync::atomic::AtomicUsize;
        use velarx_storage::VerityMode;
        // (every file of the store this file system opens is measured, with
        // `Require`)
        static OPENED: AtomicUsize = AtomicUsize::new(0);
        fn counted(file: &File) -> Result<Option<String>, String> {
            OPENED.fetch_add(1, Ordering::SeqCst);
            content_verity(file)
        }
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let (uid, gid) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let mut entries = Vec::new();
        let mut contents = HashMap::new();
        for (i, name) in ["read", "append", "trunc", "cut", "mode"]
            .into_iter()
            .enumerate()
        {
            let data: Vec<u8> = pattern(50_000 + i).into_iter().rev().collect();
            let (d, size) = put(&store, &data);
            let mut e = entry(name, TocEntryType::Reg);
            (e.fsverity, e.size, e.uid, e.gid) = (velarx_storage::to_toc(&d), size, uid, gid);
            entries.push(e);
            contents.insert(name, data);
        }
        let built = crate::layer_erofs::layer_image(&entries).unwrap();
        let layer = crate::erofs_tree::Layer::open(Box::new(built.image)).unwrap();
        let tree = crate::erofs_tree::Layers::new(
            vec![layer],
            None,
            true,
            crate::erofs_tree::Stubs::Every,
        );
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
        mounts.set_verity(Arc::new(super::super::verity::Verity::with_measure(
            HashMap::new(),
            VerityMode::Require,
            counted,
            |_, _| Err("not computed".into()),
        )));
        let Some(root) = mounted(
            Probe::Overlay,
            mounts.mount_tree(
                "img",
                Arc::new(tree),
                vec!["l0".into()],
                (vec![uid], vec![gid]),
                None,
            ),
        ) else {
            return;
        };
        let (out, upper, work, merged) = (
            tmp.path().join("out"),
            tmp.path().join("upper"),
            tmp.path().join("work"),
            tmp.path().join("merged"),
        );
        for d in [&out, &upper, &work, &merged] {
            std::fs::create_dir(d).unwrap();
        }
        // (the kernel makes `work/work` without any access for the user: it
        // is made accessible and removed before the directory of the test is,
        // else that removal fails and leaves the tree behind)
        struct WorkDir(PathBuf);
        impl Drop for WorkDir {
            fn drop(&mut self) {
                let _ = velarx_base::tree::remove_dir_all_confined(&self.0);
            }
        }
        let _work = WorkDir(work.clone());
        // the overlay in a user namespace of its own, `script` run there
        let overlay = |script: &str| {
            let mount = format!(
                "mount -t overlay overlay -o lowerdir+={},datadir+={},upperdir={},workdir={},userxattr {}",
                root.join("layer1").display(),
                store.root().display(),
                upper.display(),
                work.display(),
                merged.display()
            );
            Command::new("unshare")
                .args([
                    "-Urm",
                    "sh",
                    "-ec",
                    &format!("{mount}\ncd {}\n{script}", merged.display()),
                ])
                .output()
        };
        let o = format!("{}/", out.display());
        let r = overlay(&format!("cat read > {o}read")).unwrap();
        assert!(r.status.success(), "{r:?}");
        assert!(std::fs::read(out.join("read")).unwrap() == contents["read"]);
        assert_eq!(
            OPENED.load(Ordering::SeqCst),
            0,
            "a read opened a file of the store"
        );
        let r = overlay(&format!(
            "echo more >> append\necho new > trunc\ntruncate -s 5 cut\nchmod 600 mode\ncp append trunc cut mode {o}"
        ))
        .unwrap();
        assert!(r.status.success(), "{r:?}");
        let mut appended = contents["append"].clone();
        appended.extend_from_slice(b"more\n");
        assert!(std::fs::read(out.join("append")).unwrap() == appended);
        assert_eq!(std::fs::read(out.join("trunc")).unwrap(), b"new\n");
        assert_eq!(
            std::fs::read(out.join("cut")).unwrap(),
            &contents["cut"][..5]
        );
        assert!(std::fs::read(out.join("mode")).unwrap() == contents["mode"]);
        // (the copies in the upper layer)
        assert!(std::fs::read(upper.join("append")).unwrap() == appended);
        assert!(std::fs::read(upper.join("mode")).unwrap() == contents["mode"]);
        assert!(
            OPENED.load(Ordering::SeqCst) > 0,
            "the copy-up opened no stub"
        );
        mounts.unmount_all();
    }

    /// The thread of a session confines itself, with the directories of
    /// the stores, before it serves: it reads the files beneath them.  A
    /// confinement that fails is a mount that fails.
    #[test]
    fn the_session_confines_its_thread_before_it_serves() {
        use std::os::fd::AsFd;
        use velarx_sys::confine as sys;
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let data = b"served by a confined thread".to_vec();
        let (d, size) = put(&store, &data);
        let mut e = entry("f", TocEntryType::Reg);
        (e.fsverity, e.size) = (velarx_storage::to_toc(&d.clone()), size);
        let toc = Toc {
            version: 1,
            entries: vec![e],
            tar_split_digest: None,
        };
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
        let given: Arc<Mutex<Vec<PathBuf>>> = Arc::default();
        mounts.set_confinement(Arc::new({
            let given = given.clone();
            move |read: &[PathBuf]| {
                *given.lock().unwrap() = read.to_vec();
                if let Some(r) = sys::Ruleset::new()? {
                    for d in read {
                        r.allow_beneath(
                            std::fs::File::open(d)?.as_fd(),
                            sys::fs::READ_FILE | sys::fs::READ_DIR,
                        )?;
                    }
                    r.restrict_thread()?;
                }
                sys::seccomp_thread(&sys::deny_filter(&[libc::SYS_execve], libc::EPERM as u32)?)
            }
        }));
        let Some(path) = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc.clone())], None),
        ) else {
            return;
        };
        assert_eq!(std::fs::read(path.join("f")).unwrap(), data);
        assert_eq!(*given.lock().unwrap(), [store.root().to_path_buf()]);
        mounts.unmount_all();

        // (a thread that confined itself half way, unable to unmount: the
        // mount still goes, by the thread that made it)
        let refused = ImageMounts::at(tmp.path().join("mnt2"), store.clone());
        refused.set_confinement(Arc::new(|_: &[PathBuf]| {
            sys::seccomp_thread(&sys::deny_filter(
                &[libc::SYS_umount2, libc::SYS_execve],
                libc::EPERM as u32,
            )?)?;
            Err(std::io::Error::other("no"))
        }));
        let e = mount_tocs(&refused, "img", &[("l0".to_string(), toc)], None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot confine"), "{e}");
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let left = tmp.path().join("mnt2");
        assert!(
            !mounts.contains(left.to_str().unwrap()),
            "a mount was left: {mounts}"
        );
    }

    /// Every thread of a session has its confinement: the session's, and
    /// the I/O threads, which it makes once confined and busy (a thread made before
    /// would not have it).  Seen by the kernel (`Seccomp`, `NoNewPrivs` of
    /// each task) and by what each I/O thread may read (Landlock).
    #[test]
    fn the_threads_of_a_session_have_its_confinement() {
        // (the tasks of this process are this test's alone)
        velarx_base::testing::in_child(|| {
            use std::os::fd::AsFd;
            use velarx_sys::confine as sys;
            let tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
            let data = b"served".to_vec();
            let (d, size) = put(&store, &data);
            let secret = tmp.path().join("secret");
            std::fs::write(&secret, b"s").unwrap();
            let mut e = entry("f", TocEntryType::Reg);
            (e.fsverity, e.size) = (velarx_storage::to_toc(&d.clone()), size);
            let toc = Toc {
                version: 1,
                entries: vec![e],
                tar_split_digest: None,
            };
            let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
            mounts.set_confinement(Arc::new(|read: &[PathBuf]| {
                if let Some(r) = sys::Ruleset::new()? {
                    for d in read {
                        r.allow_beneath(
                            std::fs::File::open(d)?.as_fd(),
                            sys::fs::READ_FILE | sys::fs::READ_DIR,
                        )?;
                    }
                    r.restrict_thread()?;
                }
                sys::seccomp_thread(&sys::deny_filter(&[libc::SYS_execve], libc::EPERM as u32)?)
            }));
            let built = crate::layer_erofs::layer_image(&toc.entries).unwrap();
            let tree = crate::erofs_tree::Layers::new(
                vec![crate::erofs_tree::Layer::open(Box::new(built.image)).unwrap()],
                None,
                false,
                crate::erofs_tree::Stubs::Every,
            );
            let fs = ImageFs::new(
                Arc::new(tree),
                vec!["l0".into()],
                store.clone(),
                None,
                None,
                Arc::default(),
            );
            let shared = fs.shared.clone();
            let path = tmp.path().join("mnt").join("img");
            let mut served = HashMap::new();
            let Some(_) = mounted(
                Probe::Plain,
                mounts.serve(fs, &path, false, &mut served, "img".into()),
            ) else {
                return;
            };
            assert_eq!(std::fs::read(path.join("layer1/f")).unwrap(), data);
            assert!(
                shared.io.lock().unwrap().is_none(),
                "one reader: no threads"
            );
            // (the I/O threads are made when requests come together)
            let readers: Vec<_> = (0..16)
                .map(|_| {
                    let (shared, file) = (shared.clone(), path.join("layer1/f"));
                    std::thread::Builder::new()
                        .name("reader".into())
                        .spawn(move || {
                            while shared.io.lock().unwrap().is_none() {
                                std::fs::read(&file).unwrap();
                            }
                        })
                        .unwrap()
                })
                .collect();
            for r in readers {
                r.join().unwrap();
            }

            // the kernel's view of each task: all but this one (and the
            // readers, which may not be gone yet) confined
            let me = rustix::thread::gettid().as_raw_nonzero().get().to_string();
            let mut io = 0;
            for task in std::fs::read_dir("/proc/self/task").unwrap() {
                let task = task.unwrap().path();
                let Ok(name) = std::fs::read_to_string(task.join("comm")) else {
                    continue;
                };
                if name.trim() == "reader" {
                    continue;
                }
                let status = std::fs::read_to_string(task.join("status")).unwrap();
                let confined = status.lines().any(|l| l == "Seccomp:\t2")
                    && status.lines().any(|l| l == "NoNewPrivs:\t1");
                let mine = task.file_name().is_some_and(|t| t == me.as_str());
                assert_eq!(confined, !mine, "{}: {status}", name.trim());
                io += usize::from(name.starts_with("fuse-io-"));
            }
            assert!(io >= 2, "{io} I/O threads");

            // what each I/O thread may read: one job on each, held until all
            // run
            let all = Arc::new(std::sync::Barrier::new(io));
            let (tx, rx) = mpsc::channel();
            for _ in 0..io {
                let (all, tx, secret) = (all.clone(), tx.clone(), secret.clone());
                let object = store.get_path(&d).unwrap();
                shared.on_io_thread(Box::new(move || {
                    all.wait();
                    let name = std::thread::current().name().map(str::to_string);
                    let read = (
                        std::fs::read(&object).is_ok(),
                        std::fs::read(&secret).is_err(),
                    );
                    tx.send((name, read)).unwrap();
                }));
            }
            drop(tx);
            let ran: Vec<_> = rx.iter().collect();
            let names: std::collections::HashSet<_> = ran.iter().map(|r| r.0.clone()).collect();
            assert_eq!(names.len(), io, "{ran:?}");
            let landlock = sys::landlock_abi() > 0;
            for (name, (object, no_secret)) in ran {
                assert!(name.as_deref().is_some_and(|n| n.starts_with("fuse-io-")));
                assert!(object, "{name:?}");
                assert!(no_secret || !landlock, "{name:?} read outside the store");
            }
            drop(served);
        });
    }

    /// A mount of the files `(name, content)` at the top of one layer:
    /// those in `present` are in the store, the others come from the
    /// fetcher.
    fn files_mount(files: &[(&str, Vec<u8>)], present: &[&str]) -> Option<Lazy> {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let mut entries = Vec::new();
        let mut content = HashMap::new();
        let mut list = Vec::new();
        for (name, data) in files {
            let digest =
                velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, data);
            let mut e = entry(name, TocEntryType::Reg);
            e.mode = 0o644;
            if !data.is_empty() {
                e.fsverity = velarx_storage::to_toc(&digest.clone());
            }
            e.size = data.len() as u64;
            entries.push(e);
            if present.contains(name) {
                if !data.is_empty() {
                    store.put_with_digest(data, &digest).unwrap();
                }
            } else {
                content.insert(digest.clone(), data.clone());
            }
            list.push((name.to_string(), digest, data.clone()));
        }
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        let fetcher = TestFetcher::new(store.clone(), content);
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
        mounts.set_lazy_fetcher(fetcher.clone());
        let path = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        )?;
        Some(Lazy {
            _tmp: tmp,
            store,
            mounts,
            path,
            fetcher,
            files: list,
        })
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn reads_at_and_past_the_end_of_a_file() {
        use std::os::unix::fs::FileExt;
        let data = pattern(10_000);
        let Some(l) = files_mount(&[("f", data.clone())], &["f"]) else {
            return;
        };
        let f = std::fs::File::open(l.path.join("f")).unwrap();
        let mut buf = vec![0u8; 4096];
        // straddling the end
        let n = f.read_at(&mut buf, 8000).unwrap();
        assert_eq!(&buf[..n], &data[8000..]);
        // at the end and far past it
        assert_eq!(f.read_at(&mut buf, 10_000).unwrap(), 0);
        assert_eq!(f.read_at(&mut buf, 1 << 30).unwrap(), 0);
        l.mounts.unmount_all();
    }

    #[test]
    fn a_file_cut_after_the_open_is_an_error_not_a_short_read() {
        use std::os::unix::fs::FileExt;
        let data = pattern(100_000);
        let Some(l) = files_mount(&[("f", data.clone())], &["f"]) else {
            return;
        };
        let f = std::fs::File::open(l.path.join("f")).unwrap();
        let mut buf = vec![0u8; 4096];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 4096);
        let (_, digest, _) = l.file("f").clone();
        let cut = std::fs::OpenOptions::new()
            .write(true)
            .open(l.store.local_path(&digest).unwrap())
            .unwrap();
        cut.set_len(5000).unwrap();
        // (the kernel may have the page cache of the first pages, and
        // serves a passthrough open itself)
        match f.read_at(&mut buf, 50_000) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
            Ok(n) => assert!(n == 0 || buf[..n] == data[50_000..50_000 + n]),
        }
        l.mounts.unmount_all();
    }

    #[test]
    fn a_file_replaced_after_the_open_is_read_whole() {
        let data = pattern(100_000);
        let Some(l) = files_mount(&[("f", data.clone())], &["f"]) else {
            return;
        };
        let mut f = std::fs::File::open(l.path.join("f")).unwrap();
        let (_, digest, _) = l.file("f").clone();
        let path = l.store.local_path(&digest).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, pattern(7)).unwrap();
        let mut got = Vec::new();
        match std::io::Read::read_to_end(&mut f, &mut got) {
            Ok(_) => assert!(got == data),
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
        }
        l.mounts.unmount_all();
    }

    #[test]
    fn a_file_in_the_making_under_another_name_is_not_served() {
        let data = pattern(50_000);
        let Some(l) = files_mount(&[("f", data.clone())], &[]) else {
            return;
        };
        let (_, digest, _) = l.file("f").clone();
        let final_path = l.store.local_path(&digest).unwrap();
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let tmp = final_path.with_extension("tmp");
        std::fs::write(&tmp, &data[..1000]).unwrap();
        let hidden = final_path.parent().unwrap().join(".tmpabc");
        std::fs::write(&hidden, &data[..2000]).unwrap();
        // the fetch fails: an error, none of the partial content
        l.fetcher.fail.store(true, Ordering::SeqCst);
        let err = std::fs::read(l.path.join("f")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        assert!(l.store.get_path(&digest).is_none());
        // the next read tries again, and gets the whole file
        l.fetcher.fail.store(false, Ordering::SeqCst);
        assert!(std::fs::read(l.path.join("f")).unwrap() == data);
        l.mounts.unmount_all();
    }

    #[test]
    fn a_lookup_of_a_staged_mount_does_not_see_a_file_in_the_making() {
        let tmp = tempfile::tempdir().unwrap();
        let staging = FileStore::new(tmp.path().join("staging/files")).unwrap();
        let data = pattern(1000);
        let digest =
            velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data);
        let path = staging.local_path(&digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path.with_extension("tmp"), &data[..10]).unwrap();
        std::fs::write(path.parent().unwrap().join(".tmpx"), &data[..10]).unwrap();
        assert!(staging.get_path(&digest).is_none());
        assert!(!staging.contains(&digest));
    }

    #[test]
    fn empty_and_small_files_are_not_affected() {
        let big = pattern(300);
        let files = [
            ("empty", Vec::new()),
            ("one", vec![1u8]),
            ("sixty-four", pattern(64)),
            ("sixty-five", pattern(65)),
            ("big", big),
        ];
        let Some(l) = files_mount(&files, &["empty", "one", "sixty-four"]) else {
            return;
        };
        for (name, data) in &files {
            assert!(&std::fs::read(l.path.join(name)).unwrap() == data, "{name}");
        }
        l.mounts.unmount_all();
    }

    #[test]
    fn a_failed_fetch_leaves_no_file_and_is_tried_again() {
        let data = pattern(20_000);
        let Some(l) = files_mount(&[("f", data.clone())], &[]) else {
            return;
        };
        let (_, digest, _) = l.file("f").clone();
        l.fetcher.fail.store(true, Ordering::SeqCst);
        for _ in 0..2 {
            let err = std::fs::read(l.path.join("f")).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EIO));
            assert!(l.store.get_path(&digest).is_none());
        }
        l.fetcher.fail.store(false, Ordering::SeqCst);
        assert!(std::fs::read(l.path.join("f")).unwrap() == data);
        assert!(l.store.get_path(&digest).is_some());
        l.mounts.unmount_all();
    }

    #[test]
    fn readers_racing_with_a_slow_writer_get_the_whole_file_or_an_error() {
        use std::io::Write;
        let data = pattern(8 << 20);
        let Some(l) = files_mount(&[("f", data.clone())], &["other"]) else {
            return;
        };
        let (_, digest, _) = l.file("f").clone();
        let want = hex::encode(Sha256::digest(&data));
        let final_path = l.store.local_path(&digest).unwrap();
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..6)
            .map(|_| {
                let (p, want, done) = (l.path.join("f"), want.clone(), done.clone());
                std::thread::spawn(move || {
                    let mut whole = 0;
                    while !done.load(Ordering::SeqCst) || whole == 0 {
                        match std::fs::read(&p) {
                            Ok(d) => {
                                assert_eq!(hex::encode(Sha256::digest(&d)), want);
                                whole += 1;
                            }
                            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
                        }
                    }
                })
            })
            .collect();
        // a writer that does not rename: the file is at its name while it
        // grows (slowly: the readers look at it meanwhile)
        l.fetcher.fail.store(true, Ordering::SeqCst);
        let mut out = std::fs::File::create(&final_path).unwrap();
        for chunk in data.chunks(1 << 20) {
            out.write_all(chunk).unwrap();
            out.sync_all().unwrap();
            std::thread::sleep(Duration::from_millis(30));
        }
        drop(out);
        done.store(true, Ordering::SeqCst);
        for r in readers {
            r.join().unwrap();
        }
        l.mounts.unmount_all();
    }

    #[test]
    fn readers_racing_with_the_fetch_get_the_whole_file() {
        let data = pattern(4 << 20);
        let Some(l) = files_mount(&[("f", data.clone())], &[]) else {
            return;
        };
        let want = hex::encode(Sha256::digest(&data));
        let readers: Vec<_> = (0..12)
            .map(|_| {
                let (p, want) = (l.path.join("f"), want.clone());
                std::thread::spawn(move || {
                    let d = std::fs::read(p).unwrap();
                    assert_eq!(hex::encode(Sha256::digest(&d)), want);
                })
            })
            .collect();
        for r in readers {
            r.join().unwrap();
        }
        l.mounts.unmount_all();
    }

    #[test]
    fn concurrent_opens_read_the_same_content() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let data: Vec<u8> = (0..(3 << 20)).map(|i| (i % 251) as u8).collect();
        let (d, size) = put(&store, &data);
        let mut entries = Vec::new();
        for name in ["a", "b"] {
            let mut e = entry(name, TocEntryType::Reg);
            (e.fsverity, e.size) = (velarx_storage::to_toc(&d.clone()), size);
            entries.push(e);
        }
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store);
        let Some(path) = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        ) else {
            return;
        };
        let readers: Vec<_> = (0..8)
            .map(|i| {
                let p = path.join(if i % 2 == 0 { "a" } else { "b" });
                std::thread::spawn(move || std::fs::read(p).unwrap())
            })
            .collect();
        for r in readers {
            assert!(r.join().unwrap() == data);
        }
        // And again, once the first opens are released.
        assert!(std::fs::read(path.join("a")).unwrap() == data);
        mounts.unmount_all();
    }

    /// A fetcher whose files appear in the store when it is released.
    struct TestFetcher {
        store: Arc<FileStore>,
        content: HashMap<String, Vec<u8>>,
        calls: Mutex<Vec<String>>,
        /// Digests that wait to be released.
        held: Mutex<std::collections::HashSet<String>>,
        released: std::sync::Condvar,
        /// Told of each call.
        called: std::sync::Condvar,
        fail: std::sync::atomic::AtomicBool,
    }

    impl TestFetcher {
        fn new(store: Arc<FileStore>, content: HashMap<String, Vec<u8>>) -> Arc<Self> {
            Arc::new(Self {
                store,
                content,
                calls: Mutex::new(Vec::new()),
                held: Mutex::new(Default::default()),
                released: std::sync::Condvar::new(),
                called: std::sync::Condvar::new(),
                fail: false.into(),
            })
        }

        fn hold(&self, digest: &str) {
            self.held.lock().unwrap().insert(digest.to_string());
        }

        fn release(&self, digest: &str) {
            self.held.lock().unwrap().remove(digest);
            self.released.notify_all();
        }

        fn calls_for(&self, digest: &str) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|d| *d == digest)
                .count()
        }

        /// Waits (10 s at most) until `digest` was asked for.
        fn wait_called(&self, digest: &str) {
            let calls = self.calls.lock().unwrap();
            let (calls, _) = self
                .called
                .wait_timeout_while(calls, Duration::from_secs(10), |c| {
                    !c.iter().any(|d| d == digest)
                })
                .unwrap();
            assert!(
                calls.iter().any(|d| d == digest),
                "{digest} was not asked for"
            );
        }
    }

    impl LazyFileFetcher for TestFetcher {
        fn fetch_file_blocking(
            &self,
            digest: &str,
            _layer: &str,
            _timeout: Option<Duration>,
        ) -> Result<PathBuf, String> {
            self.calls.lock().unwrap().push(digest.to_string());
            self.called.notify_all();
            let mut held = self.held.lock().unwrap();
            while held.contains(digest) {
                held = self.released.wait(held).unwrap();
            }
            drop(held);
            if self.fail.load(Ordering::SeqCst) {
                return Err("no source".into());
            }
            let data = self.content.get(digest).ok_or("unknown file")?;
            self.store
                .put_with_digest(data, digest)
                .map_err(|e| e.to_string())?;
            self.store
                .get_path(digest)
                .ok_or_else(|| "not stored".to_string())
        }
    }

    struct Lazy {
        _tmp: tempfile::TempDir,
        store: Arc<FileStore>,
        mounts: ImageMounts,
        path: PathBuf,
        fetcher: Arc<TestFetcher>,
        /// name -> (digest, content)
        files: Vec<(String, String, Vec<u8>)>,
    }

    /// An image of files that are not in the store, mounted; `None` where
    /// FUSE cannot be mounted.
    fn lazy_image(names: &[&str], present: &[&str]) -> Option<Lazy> {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let mut dir = entry("d", TocEntryType::Dir);
        dir.mode = 0o755;
        let mut entries = vec![dir];
        let mut files = Vec::new();
        let mut content = HashMap::new();
        for name in names {
            let data = format!("content of {name}, long enough to be a file").into_bytes();
            let digest =
                velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data);
            let mut e = entry(&format!("d/{name}"), TocEntryType::Reg);
            (e.fsverity, e.size) = (velarx_storage::to_toc(&digest.clone()), data.len() as u64);
            entries.push(e);
            if present.contains(name) {
                store.put_with_digest(&data, &digest).unwrap();
            } else {
                content.insert(digest.clone(), data.clone());
            }
            files.push((name.to_string(), digest, data));
        }
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        let fetcher = TestFetcher::new(store.clone(), content);
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store.clone());
        mounts.set_lazy_fetcher(fetcher.clone());
        let path = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        )?;
        Some(Lazy {
            _tmp: tmp,
            store,
            mounts,
            path,
            fetcher,
            files,
        })
    }

    impl Lazy {
        fn file(&self, name: &str) -> &(String, String, Vec<u8>) {
            self.files.iter().find(|f| f.0 == name).unwrap()
        }
    }

    #[test]
    fn a_file_that_comes_while_the_handle_is_open_is_read_locally() {
        let Some(l) = lazy_image(&["a"], &[]) else {
            return;
        };
        let (_, digest, data) = l.file("a").clone();
        // Opened while the object is missing: the open does not wait.
        let f = std::fs::File::open(l.path.join("d/a")).unwrap();
        assert_eq!(l.fetcher.calls_for(&digest), 0);
        // Somebody else (a pull, the other monitor) stores it.
        l.store.put_with_digest(&data, &digest).unwrap();
        let mut got = vec![0u8; data.len()];
        f.read_exact_at(&mut got, 0).unwrap();
        assert_eq!(got, data);
        assert_eq!(
            l.fetcher.calls_for(&digest),
            0,
            "a fetch was made for a local file"
        );
        // And a later open does not remember that it was missing.
        assert_eq!(std::fs::read(l.path.join("d/a")).unwrap(), data);
        l.mounts.unmount_all();
    }

    /// A mount with a staging: the lookup of a file that is neither in the
    /// store nor in the staging waits for it (the kernel's overlay follows
    /// the redirect of the stub right after the lookup), and answers at once
    /// for what is there.
    #[test]
    fn a_lookup_waits_for_the_file_of_a_staged_mount() {
        use crate::erofs_tree::{Index, Layer, Layers};
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let staging = Arc::new(FileStore::new(tmp.path().join("staging/files")).unwrap());
        let mut dir = entry("d", TocEntryType::Dir);
        dir.mode = 0o755;
        let mut entries = vec![dir];
        let mut content = HashMap::new();
        let mut digests = Vec::new();
        for (name, in_store) in [("missing", false), ("there", true)] {
            let data = format!("content of {name}, long enough to be a file").into_bytes();
            let digest =
                velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data);
            let mut e = entry(&format!("d/{name}"), TocEntryType::Reg);
            (e.fsverity, e.size) = (velarx_storage::to_toc(&digest.clone()), data.len() as u64);
            entries.push(e);
            if in_store {
                store.put_with_digest(&data, &digest).unwrap();
            } else {
                content.insert(digest.clone(), data);
            }
            digests.push(digest);
        }
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        let built = crate::layer_erofs::layer_image(&toc.entries).unwrap();
        let tree = Layers::new(
            vec![Layer::open(Box::new(built.image)).unwrap()],
            Some(vec![Index::from_bytes(Box::new(built.index)).unwrap()]),
            true,
            crate::erofs_tree::Stubs::Every,
        );
        // what the fetcher fetches appears in the staging
        let fetcher = TestFetcher::new(staging.clone(), content);
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store);
        mounts.set_lazy_fetcher(fetcher.clone());
        mounts.set_staging(staging.clone());
        let profile = tmp.path().join("profile.json");
        mounts.set_recording(crate::profile::Recording::start(
            profile.clone(),
            Duration::from_secs(3600),
            100,
        ));
        let Some(path) = mounted(
            Probe::Plain,
            mounts.mount_tree(
                "img",
                Arc::new(tree),
                vec!["l0".to_string()],
                Default::default(),
                None,
            ),
        ) else {
            return;
        };
        fetcher.hold(&digests[0]);
        let missing = path.join("layer1/d/missing");
        // (the time the lookup ended: not before the release, or it did not wait)
        let waiting = std::thread::spawn(move || {
            let found = std::fs::metadata(missing).map(|m| m.len());
            (found, std::time::Instant::now())
        });
        fetcher.wait_called(&digests[0]);
        // the file that is there is not waited for
        assert!(std::fs::metadata(path.join("layer1/d/there")).is_ok());
        assert!(staging.get_path(&digests[0]).is_none());
        assert!(!waiting.is_finished(), "the lookup did not wait");
        let released_at = std::time::Instant::now();
        fetcher.release(&digests[0]);
        let (found, ended_at) = waiting.join().unwrap();
        assert!(found.is_ok());
        assert!(ended_at >= released_at, "the lookup did not wait");
        assert!(staging.get_path(&digests[0]).is_some());
        assert_eq!(fetcher.calls_for(&digests[0]), 1);
        assert_eq!(fetcher.calls_for(&digests[1]), 0);
        // the lookups are the startup profile, in order, saved at the end
        mounts.unmount_all();
        assert_eq!(crate::profile::read(&profile, 100), digests);
    }

    /// A file of the staging was written by a fetcher: it is served only
    /// when the descriptor that is served has the fs-verity digest it is
    /// named by (computed from its content on a file system without
    /// fs-verity), and a symlink in its place is not followed.
    #[test]
    fn a_staged_file_is_served_only_when_it_is_its_name() {
        use crate::erofs_tree::{Index, Layer, Layers};
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let staging = Arc::new(FileStore::new(tmp.path().join("staging/files")).unwrap());
        let mut dir = entry("d", TocEntryType::Dir);
        dir.mode = 0o755;
        let mut entries = vec![dir];
        let mut files = Vec::new();
        for name in ["good", "wrong", "link"] {
            let data = format!("content of {name}, long enough to be a file").into_bytes();
            let digest =
                velarx_storage::fsverity_digest_of(velarx_types::digest::Algorithm::Sha256, &data);
            let mut e = entry(&format!("d/{name}"), TocEntryType::Reg);
            (e.fsverity, e.size) = (velarx_storage::to_toc(&digest.clone()), data.len() as u64);
            entries.push(e);
            let path = staging.local_path(&digest).unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            files.push((name, digest, data, path));
        }
        // a good file; one of the same size with other bytes; a symlink to a
        // file outside the staging that has the right content
        std::fs::write(&files[0].3, &files[0].2).unwrap();
        let mut bad = files[1].2.clone();
        bad[0] ^= 1;
        std::fs::write(&files[1].3, &bad).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, &files[2].2).unwrap();
        std::os::unix::fs::symlink(&outside, &files[2].3).unwrap();
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        let built = crate::layer_erofs::layer_image(&toc.entries).unwrap();
        let tree = Layers::new(
            vec![Layer::open(Box::new(built.image)).unwrap()],
            Some(vec![Index::from_bytes(Box::new(built.index)).unwrap()]),
            true,
            crate::erofs_tree::Stubs::Every,
        );
        let fetcher = TestFetcher::new(staging.clone(), HashMap::new());
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store);
        mounts.set_lazy_fetcher(fetcher.clone());
        mounts.set_staging(staging.clone());
        let Some(path) = mounted(
            Probe::Plain,
            mounts.mount_tree(
                "img",
                Arc::new(tree),
                vec!["l0".to_string()],
                Default::default(),
                None,
            ),
        ) else {
            return;
        };
        assert_eq!(
            std::fs::read(path.join("layer1/d/good")).unwrap(),
            files[0].2
        );
        for name in ["wrong", "link"] {
            let err = std::fs::read(path.join("layer1/d").join(name)).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EIO), "{name}");
        }
        mounts.unmount_all();
    }

    #[test]
    fn a_miss_is_fetched_once_for_all_the_readers() {
        let Some(l) = lazy_image(&["a"], &[]) else {
            return;
        };
        let (_, digest, data) = l.file("a").clone();
        l.fetcher.hold(&digest);
        let path = l.path.join("d/a");
        let readers: Vec<_> = (0..6)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || std::fs::read(p).unwrap())
            })
            .collect();
        // They all wait for the one fetch.
        l.fetcher.wait_called(&digest);
        // (no look at the calls here: one asked after the release would find
        // the file stored, one asked before is counted below)
        l.fetcher.release(&digest);
        for r in readers {
            assert_eq!(r.join().unwrap(), data);
        }
        assert_eq!(l.fetcher.calls_for(&digest), 1);
        l.mounts.unmount_all();
    }

    #[test]
    fn a_slow_miss_does_not_hold_up_other_misses_or_present_files() {
        let Some(l) = lazy_image(&["slow", "quick", "here"], &["here"]) else {
            return;
        };
        let (_, slow, slow_data) = l.file("slow").clone();
        let quick = l.file("quick").clone();
        let here = l.file("here").clone();
        l.fetcher.hold(&slow);
        let p = l.path.join("d/slow");
        let blocked = std::thread::spawn(move || std::fs::read(p).unwrap());
        l.fetcher.wait_called(&slow);
        let started = std::time::Instant::now();
        assert_eq!(std::fs::read(l.path.join("d/quick")).unwrap(), quick.2);
        assert_eq!(std::fs::read(l.path.join("d/here")).unwrap(), here.2);
        assert!(std::fs::metadata(l.path.join("d/slow")).is_ok());
        assert_eq!(std::fs::read_dir(l.path.join("d")).unwrap().count(), 3);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "other files waited for the slow miss"
        );
        assert!(!blocked.is_finished());
        l.fetcher.release(&slow);
        assert_eq!(blocked.join().unwrap(), slow_data);
        l.mounts.unmount_all();
    }

    #[test]
    fn a_failed_fetch_is_an_error_not_a_hang() {
        let Some(mut l) = lazy_image(&["a"], &[]) else {
            return;
        };
        // A fetcher that has nothing.
        let broken = {
            let store = l.store.clone();
            let mut f = Arc::try_unwrap(TestFetcher::new(store, HashMap::new()))
                .ok()
                .unwrap();
            f.fail = true.into();
            Arc::new(f)
        };
        l.mounts.set_lazy_fetcher(broken);
        // The mount made before keeps the fetcher it had: remount.
        l.mounts.unmount_all();
        let toc = Toc {
            version: 1,
            entries: {
                let mut dir = entry("d", TocEntryType::Dir);
                dir.mode = 0o755;
                let mut e = vec![dir];
                let (_, digest, data) = l.file("a").clone();
                let mut f = entry("d/a", TocEntryType::Reg);
                (f.fsverity, f.size) = (velarx_storage::to_toc(&digest), data.len() as u64);
                e.push(f);
                e
            },
            tar_split_digest: None,
        };
        l.path = mount_tocs(&l.mounts, "img2", &[("l0".to_string(), toc)], None).unwrap();
        let err = std::fs::read(l.path.join("d/a")).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        l.mounts.unmount_all();
    }

    #[test]
    fn an_image_that_is_all_local_needs_no_fetcher() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(FileStore::new(tmp.path().join("files")).unwrap());
        let (digest, size) = put(&store, b"all here");
        let mut f = entry("f", TocEntryType::Reg);
        (f.fsverity, f.size) = (velarx_storage::to_toc(&digest), size);
        let toc = Toc {
            version: 1,
            entries: vec![f],
            tar_split_digest: None,
        };
        // No fetcher at all: no threads, no source, the files are read.
        let mounts = ImageMounts::at(tmp.path().join("mnt"), store);
        let Some(path) = mounted(
            Probe::Plain,
            mount_tocs(&mounts, "img", &[("l0".to_string(), toc)], None),
        ) else {
            return;
        };
        assert_eq!(std::fs::read(path.join("f")).unwrap(), b"all here");
        mounts.unmount_all();
    }
}
