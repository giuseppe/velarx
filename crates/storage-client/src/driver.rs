// SPDX-License-Identifier: Apache-2.0
//! `StorageDriver` over a unix socket: every method is a call of
//! `org.velarx.Storage` on a connection of its own (or the engine-side form
//! that `docs/STORAGE.md` states for it), made with the rules of version 1.

use crate::conn::{Link, Session};
use crate::convert::{self, known};
use crate::feed::{Engine, Feed};
use crate::proto::{self, PullEventKind};
use crate::request;
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use velarx_content::layer::dirtar::{self, Change};
use velarx_content::layer::holes::HoleWrite;
use velarx_content::pull::sink::FilesSink;
use velarx_db::{ImageRecord, LayerRecord};
use velarx_fuse::view::ImageTree;
use velarx_graph::longcall::{read_pipe_ranges, IdleDeadline};
use velarx_graph::{
    new_pull_id, prove_with, spool_object_into, to_fetch, Capabilities, Collected, DiffOptions,
    DriverError, DriverErrorKind, DriverResult, FeedLayer, FilesIncoming, Keep, LayerArtifact,
    LayerRef, MountRequest, Mounts, MountsRequest, ObjectRange, ObjectSink, Planned, Problem,
    PullFeed, Pulled, Purpose, Remedy, Settled, StoppedView, StoreId, StoreInfo, TreeSource, Usage,
    Writable, WritableOptions, WritablePaths,
};
use velarx_storage::{ObjectOpener, Toc};
use velarx_types::digest::Digest;
use velarx_types::LayerKey;
use velarx_wire::varlink::Method;

/// What the engine opens the driver with.
#[derive(Debug, Clone)]
pub struct Options {
    /// The socket and the idle timeout of a call.
    pub link: Link,
    /// The graph root of the engine: the id of the store is in a file of it
    /// (`<root>/varlink/store-id`, made once), and the work directory of the
    /// store is `<root>/varlink/work` (the only place a `directory` root may
    /// be).
    pub graph_root: PathBuf,
}

/// The state of a driver, shared with what reads for a pull.
pub struct Inner {
    link: Link,
    name: String,
    version: String,
    store: StoreId,
    /// The work directory of the store (`<graph root>/varlink/work`, the
    /// engine's, 0700, its path without links): `CreateRoot` names it, and a
    /// `directory` root is a path beneath it, never anywhere else.
    workdir: PathBuf,
    /// A directory of the engine's (`<graph root>/varlink/scratch`, 0700)
    /// for the files with no name a fetch makes while it works.
    scratch: PathBuf,
    caps: Capabilities,
    wire_limits: crate::conn::Limits,
    /// The service answers `HasObjects` and applies the `copy` events of a
    /// `Fetch` (`objects` of its capabilities)
    objects: bool,
}

/// A storage driver that is a program of its own, behind a unix socket.
pub struct VarlinkDriver {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for VarlinkDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VarlinkDriver")
            .field("name", &self.name)
            .field("socket", &self.link.socket)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for VarlinkDriver {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}

/// What ends a pull that is dropped: the engine cancelled it (the future of
/// `pull` is dropped), and the driver sees the connection of `BeginPull` and
/// the feed closed, as the interface says ("closing the connection cancels
/// the pull").
struct Cancel {
    feed: Arc<Feed>,
    call: std::sync::Mutex<Option<std::os::unix::net::UnixStream>>,
    cancelled: std::sync::atomic::AtomicBool,
}

impl Cancel {
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.feed.shutdown();
        if let Some(s) = self.call.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }

    /// The connection of the call, to close when the pull is cancelled; false
    /// when it already is.
    fn attach(&self, socket: &std::os::unix::net::UnixStream) -> bool {
        let mut call = self.call.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        *call = socket.try_clone().ok();
        true
    }
}

struct CancelOnDrop(Arc<Cancel>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// The most bytes read in one call of the proof of a layer.
const PROOF_BATCH_BYTES: u64 = 32 << 20;
/// The most objects read in one call of the proof of a layer: each is a file
/// held open until the proof takes it.
const PROOF_BATCH_FILES: usize = 256;

/// The objects a pull staged and has not committed, read by the pull's id:
/// what the proof of a layer reads back; or, with no pull, the objects of the
/// store for a reader that takes a list of them in order (the tar of a push,
/// a save, an export, a squash: `ObjectOpener::ordered`).  The reader asks for
/// the files in the order of a list (a layer's table of contents), so the
/// objects are read ahead:
/// one call of `ReadObjects` brings the next ones (up to the driver's limit of
/// ranges, [`PROOF_BATCH_FILES`] and [`PROOF_BATCH_BYTES`]) into files with no
/// name in the engine's scratch directory, and an object that is asked for is
/// taken from them.  One call and one connection for each object cost more
/// than the pull itself on a layer of thousands of files.  What a read-ahead
/// brought and the proof did not take goes with the next one (at most one
/// batch of files is open), and an object asked for again (two files of the
/// same content) is read alone.  A batch reads each object as the `size`
/// bytes its index says, with no probe past its end (a probe that finds the
/// end is an error, which ends a call): an object the driver keeps longer
/// than its index is told by `open_object`, not by this proof.
struct StagedObjects {
    inner: Arc<Inner>,
    /// The pull whose staged objects are read; none for the objects of the
    /// store (nothing is measured then: the reader checks what it needs).
    pull: Option<String>,
    /// The fs-verity digest of each object the proof took that the table of
    /// contents names by the hash of its content, measured as the bytes
    /// arrived (the bytes the proof hashed, nothing read ahead and left):
    /// what the layer is recorded and its identity made with.
    measured: std::sync::Mutex<HashMap<String, String>>,
    /// The objects of the layer, in the order the proof reads them.
    order: Vec<(String, u64)>,
    /// The objects the driver was told to copy chunks into: nothing measured
    /// them when they were fetched, so they are checked against their keys
    /// when they are read back.
    copied: Arc<std::collections::HashSet<String>>,
    /// Where each object is in `order` (each is there once), and its size.
    at: HashMap<String, (usize, u64)>,
    ahead: std::sync::Mutex<Ahead>,
}

#[derive(Default)]
struct Ahead {
    files: HashMap<String, File>,
    /// The fs-verity digest of each of `files` known by the hash of its
    /// content: it is the layer's once the proof takes the file.
    verity: HashMap<String, String>,
    /// Where in `order` the next read-ahead begins.
    next: usize,
}

impl StagedObjects {
    fn new(
        inner: Arc<Inner>,
        pull: String,
        toc: &Toc,
        copied: Arc<std::collections::HashSet<String>>,
    ) -> Self {
        let order = velarx_content::pull::stream::FileUse::objects_of_toc(toc);
        let mut objects = Self::of(inner, Some(pull), order);
        objects.copied = copied;
        objects
    }

    /// The objects of `order` (each key once), in that order.
    fn of(inner: Arc<Inner>, pull: Option<String>, order: Vec<(String, u64)>) -> Self {
        let at = order
            .iter()
            .enumerate()
            .map(|(i, (k, s))| (k.clone(), (i, *s)))
            .collect();
        Self {
            inner,
            pull,
            measured: std::sync::Mutex::default(),
            order,
            copied: Arc::default(),
            at,
            ahead: std::sync::Mutex::default(),
        }
    }

    /// The table of contents with the fs-verity digest of every file it names
    /// by the hash of its content (the same table a pull in this process
    /// records), once the proof has read them all.  A file the proof did not
    /// read stays as it is.
    fn with_verity(&self, toc: &mut Toc) {
        let measured = self.measured.lock().unwrap_or_else(|e| e.into_inner());
        for e in &mut toc.entries {
            if e.verity().is_some() {
                continue;
            }
            if let Some(object) = e.digest.as_deref().and_then(|d| measured.get(d)) {
                e.fsverity = velarx_storage::to_toc(object);
            }
        }
    }

    /// The fs-verity digest of `file`, an object read alone that the table of
    /// contents names by the hash of its content and that has none measured
    /// yet (one the proof takes again was measured the first time).
    fn measure(&self, key: &str, file: &File) -> std::io::Result<()> {
        use std::io::{Read, Seek};
        let Some(alg) = Digest::parse(key)
            .ok()
            .filter(|d| !d.is_fsverity())
            .map(|d| d.alg())
        else {
            return Ok(());
        };
        if self
            .measured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key)
        {
            return Ok(());
        }
        let mut hasher = velarx_storage::VerityHasher::new(alg);
        let mut f = file;
        f.rewind()?;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        f.rewind()?;
        self.measured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string(), hasher.finish());
        Ok(())
    }

    /// The object `key` that the driver was told to copy chunks into is what
    /// its key names (its fs-verity digest, or the hash of its content): the
    /// engine measured it at no other time, and a driver keeps an object by
    /// its key.
    fn check_copied(&self, key: &str, file: &File) -> std::io::Result<()> {
        if !self.copied.contains(key) {
            return Ok(());
        }
        let kind = Digest::parse_key(key).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{key}: {e}"))
        })?;
        let actual =
            velarx_content::pull::sink::measure_place(file, 0, file.metadata()?.len(), &kind)?;
        if actual.to_string() != key {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the object {key}, with chunks the driver copied, reads back as {actual}"),
            ));
        }
        Ok(())
    }

    fn typed(e: DriverError) -> std::io::Error {
        let kind = match e.kind {
            DriverErrorKind::Missing { .. } | DriverErrorKind::NotFound => {
                std::io::ErrorKind::NotFound
            }
            DriverErrorKind::Corrupt { .. } => std::io::ErrorKind::InvalidData,
            _ => return e.into_io(),
        };
        std::io::Error::new(kind, e.message().to_string())
    }

    /// Read the objects from `from` on, as many as one call takes, into files.
    fn read_ahead(&self, from: usize, ahead: &mut Ahead) -> DriverResult<()> {
        /// The files the objects are written to, and the fs-verity digest of
        /// each one whose key is the hash of its content, hashed as it comes.
        struct Spool(Vec<File>, Vec<Option<velarx_storage::VerityHasher>>);
        impl ObjectSink for Spool {
            fn data(&mut self, range: usize, bytes: &[u8]) -> std::io::Result<()> {
                if let Some(h) = &mut self.1[range] {
                    h.update(bytes);
                }
                std::io::Write::write_all(&mut &self.0[range], bytes)
            }
        }
        let max = self.inner.caps.limits.ranges.clamp(1, PROOF_BATCH_FILES);
        // (what the proof skipped is not kept open)
        ahead.files.clear();
        ahead.verity.clear();
        let (mut ranges, mut bytes) = (Vec::new(), 0u64);
        let mut at = from;
        while at < self.order.len() && ranges.len() < max {
            let (key, size) = &self.order[at];
            if !ahead.files.contains_key(key) {
                if !ranges.is_empty() && bytes + size > PROOF_BATCH_BYTES {
                    break;
                }
                bytes += size;
                ranges.push(ObjectRange::whole(key.clone(), *size));
            }
            at += 1;
        }
        let name = &self.inner.name;
        let mut spool = Spool(
            (0..ranges.len())
                .map(|_| {
                    velarx_content::pull::unnamed::unnamed_file(&self.inner.scratch)
                        .map_err(|e| io_error(name, e))
                })
                .collect::<DriverResult<_>>()?,
            ranges
                .iter()
                .map(|r| {
                    // (only the proof of a pull measures)
                    self.pull.as_ref()?;
                    Digest::parse(&r.key)
                        .ok()
                        .filter(|d| !d.is_fsverity())
                        .map(|d| velarx_storage::VerityHasher::new(d.alg()))
                })
                .collect(),
        );
        let sizes = self
            .inner
            .read_with(self.pull.as_deref(), &ranges, &mut spool)?;
        // (the size of each object a driver tells: one longer than its index
        // is no object of the layer; a driver that tells none is not seen)
        for (r, size) in ranges.iter().zip(&sizes) {
            if size.is_some_and(|s| s != r.length) {
                return Err(DriverError::corrupt(
                    name,
                    format!(
                        "the object {} has {} bytes, its index says {}",
                        r.key,
                        size.unwrap_or_default(),
                        r.length
                    ),
                    Remedy::PullAgain,
                ));
            }
        }
        let Spool(files, hashers) = spool;
        for ((r, f), h) in ranges.iter().zip(files).zip(hashers) {
            if let Some(h) = h {
                ahead.verity.insert(r.key.clone(), h.finish());
            }
            ahead.files.insert(r.key.clone(), f);
        }
        ahead.next = at;
        Ok(())
    }
}

impl ObjectOpener for StagedObjects {
    fn object_file(&self, key: &str, size: u64) -> std::io::Result<File> {
        let mut ahead = self.ahead.lock().unwrap_or_else(|e| e.into_inner());
        let listed = self
            .at
            .get(key)
            .filter(|(_, s)| *s == size)
            .map(|(at, _)| *at);
        let file = match ahead.files.remove(key) {
            Some(f) => Some(f),
            None => match listed {
                // (the next objects of the layer, this one first; one read
                // already is asked for again: alone)
                Some(at) if at >= ahead.next => {
                    self.read_ahead(at, &mut ahead).map_err(Self::typed)?;
                    ahead.files.remove(key)
                }
                _ => None,
            },
        };
        if file.is_some() {
            if let Some(v) = ahead.verity.remove(key) {
                self.measured
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(key.to_string(), v);
            }
        }
        drop(ahead);
        match file {
            Some(f) if f.metadata()?.len() == size => {
                use std::io::Seek;
                let mut f = f;
                self.check_copied(key, &f)?;
                f.rewind()?;
                Ok(f)
            }
            Some(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the object {key} is not the {size} bytes its index says"),
            )),
            // (an object the table of contents does not list, or asked for
            // with another size: read alone, as a single read is)
            None => {
                let f = velarx_content::pull::unnamed::unnamed_file(&self.inner.scratch)
                    .map_err(|e| io_error(&self.inner.name, e))
                    .and_then(|file| {
                        spool_object_into(&self.inner.name, key, size, file, |ranges, sink| {
                            self.inner
                                .read_with(self.pull.as_deref(), ranges, sink)
                                .map(drop)
                        })
                    })
                    .map_err(Self::typed)?;
                if self.pull.is_some() {
                    self.measure(key, &f)?;
                }
                self.check_copied(key, &f)?;
                Ok(f)
            }
        }
    }
}

/// The work directory of the store, made once: `<graph root>/varlink/work`,
/// owned by the engine's user and closed to others (the monitor mounts a
/// `directory` root only beneath a base so held), named without links (the
/// monitor opens it without following one).
fn work_directory(graph_root: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = graph_root.join("varlink").join("work");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let dir = std::fs::canonicalize(&dir)?;
    if dir.to_str().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not UTF-8: the wire names it", dir.display()),
        ));
    }
    let meta = std::fs::symlink_metadata(&dir)?;
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is writable by its group or others: the roots of containers are made beneath it",
                dir.display()
            ),
        ));
    }
    Ok(dir)
}

fn refused(driver: &str, e: velarx_types::ImageError) -> DriverError {
    DriverError::refused(driver, e)
}

fn unsupported(driver: &str, why: impl Into<String>) -> DriverError {
    DriverError::of(driver, DriverErrorKind::Unsupported, why)
}

impl VarlinkDriver {
    /// Open the driver at `options.link`: the id of the store of the graph
    /// root (made once), and `GetInfo` with the version checked and the
    /// capabilities read.
    pub fn open(options: Options) -> DriverResult<Self> {
        // (the name the errors carry until the driver says its own)
        let store =
            StoreId::of_root(&options.graph_root).map_err(|e| DriverError::io("varlink", e))?;
        let workdir =
            work_directory(&options.graph_root).map_err(|e| DriverError::io("varlink", e))?;
        let scratch = options.graph_root.join("varlink").join("scratch");
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&scratch)
                .map_err(|e| DriverError::io("varlink", e))?;
        }
        let (_, info) = Session::connect(&options.link, "varlink", None)?;
        let name = convert::driver_name(&info.name)?;
        let objects = info.can(crate::proto::word::OBJECTS);
        let caps = convert::capabilities(&name, &info)?;
        let wire_limits = crate::conn::Limits {
            message: caps.limits.message as u64,
            fds: caps.limits.fds as u64,
            wants: caps.limits.wants as u64,
            ranges: caps.limits.ranges as u64,
        };
        Ok(Self {
            inner: Arc::new(Inner {
                link: options.link,
                name,
                version: info.version,
                store,
                workdir,
                scratch,
                caps,
                wire_limits,
                objects,
            }),
        })
    }

    /// The version of the driver, as it said at open.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The id of the store this driver is opened for.
    pub fn store(&self) -> &StoreId {
        &self.store
    }
}

impl Inner {
    /// A connection for one call, after its `GetInfo`.
    fn session(&self) -> DriverResult<Session<'_>> {
        Ok(Session::connect(&self.link, &self.name, Some(self.wire_limits))?.0)
    }

    fn store_id(&self) -> &str {
        self.store.as_str()
    }

    /// A call with one reply and no descriptor.
    fn call<M: Method>(&self, m: &M) -> DriverResult<M::Reply> {
        let (reply, _) = self.session()?.call(m, &[])?;
        Ok(reply)
    }

    /// Which of the objects `keys` the service holds (`HasObjects`, at most
    /// `limits.wants` in a call): one answer for each, in the order asked.
    fn has_objects(&self, keys: &[String]) -> DriverResult<Vec<bool>> {
        let mut have = Vec::with_capacity(keys.len());
        for batch in keys.chunks(self.caps.limits.wants.max(1)) {
            let reply: proto::ObjectsReply = self.call(&request::HasObjects {
                store: self.store_id(),
                objects: batch,
            })?;
            if reply.have.len() != batch.len() {
                return Err(DriverError::storage(
                    &self.name,
                    format!(
                        "the storage service answered {} objects for the {} asked: one answer for each, in the order asked",
                        reply.have.len(),
                        batch.len()
                    ),
                ));
            }
            have.extend(reply.have);
        }
        Ok(have)
    }

    /// A call that returns nothing.
    fn ack<M: Method<Reply = proto::Ack>>(&self, m: &M) -> DriverResult<()> {
        self.call(m).map(drop)
    }

    /// Read objects, those a pull staged when it is named (`ReadObjects`: the
    /// bytes on a pipe, the reply for each range before its bytes).
    fn read_with(
        &self,
        pull: Option<&str>,
        ranges: &[ObjectRange],
        sink: &mut dyn ObjectSink,
    ) -> DriverResult<Vec<Option<u64>>> {
        if ranges.is_empty() {
            return Ok(Vec::new());
        }
        let max = self.caps.limits.ranges;
        if ranges.len() > max {
            return Err(DriverError::storage(
                &self.name,
                format!(
                    "{} ranges in one read, and the storage service takes {max}: read_objects_in_batches splits a list",
                    ranges.len()
                ),
            ));
        }
        let wire: Vec<proto::Range> = ranges
            .iter()
            .map(|r| proto::Range {
                key: r.key.clone(),
                offset: r.offset,
                length: r.length,
            })
            .collect();
        let mut session = self.session()?;
        let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)
            .map_err(|e| DriverError::io(&self.name, e.into()))?;
        session.send(
            &request::ReadObjects {
                store: self.store_id(),
                pull,
                ranges: &wire,
            },
            &[write.as_fd()],
        )?;
        // (the driver's end is the only one open, so that the end of its
        // writing is the end of the pipe)
        drop(write);
        let pipe = File::from(read);
        let mut deadline = IdleDeadline::new(session.timeout());
        let mut failed: Option<DriverError> = None;
        // (the size of each object, for a driver that tells it)
        let mut sizes: Vec<Option<u64>> = Vec::with_capacity(ranges.len());
        let result = read_pipe_ranges(
            ranges,
            &mut |wait| match session.next::<request::ReadObjects<&str, &[proto::Range]>>(wait) {
                Ok(None) => Ok(None),
                Ok(Some((reply, _))) => {
                    sizes.push(reply.parameters.size);
                    Ok(Some(reply.parameters.index as usize))
                }
                Err(e) => {
                    failed = Some(e);
                    Err(std::io::Error::other("failed"))
                }
            },
            &pipe,
            &mut deadline,
            sink,
        );
        match result {
            Ok(()) => Ok(sizes),
            Err(e) => Err(failed.take().unwrap_or_else(|| match e.kind() {
                std::io::ErrorKind::TimedOut => {
                    DriverError::of(&self.name, DriverErrorKind::TimedOut, e.to_string())
                }
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
                    DriverError::storage(&self.name, e.to_string())
                }
                _ => DriverError::io(&self.name, e),
            })),
        }
    }

    /// `BeginPull`, with the feed served on the socket pair it hands over:
    /// replies `progress` until `staged`.  A driver that went away is
    /// connected to once more, with the same pull id (it resumes what it
    /// staged).
    fn begin_pull(
        &self,
        id: &str,
        layers: &[proto::PullLayer],
        feed: &Arc<Feed>,
        cancel: &Cancel,
    ) -> DriverResult<()> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let (mine, theirs) = std::os::unix::net::UnixStream::pair()
                .map_err(|e| DriverError::io(&self.name, e))?;
            feed.serve(mine)
                .map_err(|e| DriverError::io(&self.name, e))?;
            let result = self.session().and_then(|mut s| {
                if !cancel.attach(s.socket()) {
                    return Err(DriverError::storage(&self.name, "the pull was cancelled"));
                }
                s.send(
                    &request::BeginPull {
                        store: self.store_id(),
                        pull: id,
                        layers,
                    },
                    &[theirs.as_fd()],
                )?;
                // (so that the driver closing its end is seen by the feed)
                drop(theirs);
                let name = &self.name;
                s.follow::<request::BeginPull<&str, &[proto::PullLayer]>, ()>(
                    &mut |ev: proto::PullEvent, _fds, _continues| match known(
                        name,
                        "the kind of a reply of BeginPull",
                        ev.kind,
                    )? {
                        PullEventKind::Progress => Ok(None),
                        PullEventKind::Staged => Ok(Some(())),
                    },
                )
            });
            match result {
                Err(e) if attempt == 1 && matches!(e.kind, DriverErrorKind::Unavailable) => {
                    tracing::warn!("storage driver {}: {e}; asking once more", self.name);
                }
                other => return other,
            }
        }
    }

    fn abort(&self, id: &str) {
        let r = self.ack(&request::Abort(request::OfPull {
            store: self.store_id(),
            pull: id,
        }));
        if let Err(e) = r {
            tracing::warn!("storage driver {}: abort of the pull {id}: {e}", self.name);
        }
    }

    /// A new read-only mount of the image of `layers` (`MountImage`): the
    /// one descriptor of the reply, a directory.
    fn image_fd(&self, image_id: &str, layers: &[LayerRecord]) -> DriverResult<OwnedFd> {
        let refs = convert::wire_refs(&convert::refs_of_layers(layers));
        let (_, mut fds): (proto::Ack, _) = self.session()?.call(
            &request::MountImage {
                store: self.store_id(),
                layers: &refs,
            },
            &[],
        )?;
        if fds.len() != 1 {
            return Err(DriverError::storage(
                &self.name,
                format!(
                    "the storage service answered MountImage with {} descriptors, not one (image {image_id})",
                    fds.len()
                ),
            ));
        }
        let fd = fds.remove(0);
        let st = rustix::fs::fstat(&fd).ok();
        let is_dir = st.is_some_and(|st| rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir());
        if !is_dir {
            return Err(DriverError::storage(
                &self.name,
                "the storage service answered MountImage with a descriptor that is not a directory",
            ));
        }
        // (a service is the engine's user or root: what it hands over it
        // could read itself; the root of the host is no image, whatever
        // the service meant)
        let host = rustix::fs::stat("/").ok();
        if let (Some(st), Some(host)) = (st, host) {
            if (st.st_dev, st.st_ino) == (host.st_dev, host.st_ino) {
                return Err(DriverError::storage(
                    &self.name,
                    "the storage service answered MountImage with the root of the host",
                ));
            }
        }
        Ok(fd)
    }

    fn writable_fd(&self, w: &Writable) -> DriverResult<OwnedFd> {
        let (_, mut fds): (proto::Ack, _) = self.session()?.call(
            &request::WritableRoot(request::OfContainer {
                store: self.store_id(),
                container: w.id(),
            }),
            &[],
        )?;
        if fds.len() != 1 {
            return Err(DriverError::storage(
                &self.name,
                format!(
                    "the storage service answered WritableRoot with {} descriptors, not one",
                    fds.len()
                ),
            ));
        }
        let fd = fds.remove(0);
        // (the engine walks it and writes into it: a directory, or nothing)
        let is_dir = rustix::fs::fstat(&fd)
            .is_ok_and(|st| rustix::fs::FileType::from_raw_mode(st.st_mode).is_dir());
        if !is_dir {
            return Err(DriverError::storage(
                &self.name,
                "the storage service answered WritableRoot with a descriptor that is not a directory",
            ));
        }
        Ok(fd)
    }

    /// The reply of a long call: its last reply gives the result, the ones
    /// before are progress.
    fn long<M: Method, R>(
        &self,
        m: &M,
        fds: &[std::os::fd::BorrowedFd<'_>],
        mut result: impl FnMut(M::Reply) -> DriverResult<R>,
    ) -> DriverResult<R> {
        let method = M::NAME;
        let name = &self.name;
        self.session()?.long(m, fds, |t: M::Reply, got: Vec<OwnedFd>, continues| {
            if !got.is_empty() {
                return Err(DriverError::storage(
                    name,
                    format!("the storage service answered {method} with a descriptor, and it hands none over"),
                ));
            }
            if continues {
                return Ok(None);
            }
            result(t).map(Some)
        })
    }
}

/// An image that is being pulled lazily has files that are not stored yet:
/// the client does not serve it over the wire (the layers are not complete).
fn not_lazy(driver: &str, image: &ImageRecord) -> DriverResult<()> {
    if image.is_lazy {
        return Err(unsupported(
            driver,
            format!(
                "the image {} is being pulled lazily, and a storage service does not serve images whose files are partly missing yet",
                image.id
            ),
        ));
    }
    Ok(())
}

/// The owner a process that may not give files the owners of the image leaves
/// them: its own (the files of that owner are taken to have the image's in
/// the changes of a container, as the vfs driver does for the same process).
fn unowned() -> Option<(u32, u32)> {
    (!rustix::process::geteuid().is_root()).then(|| {
        (
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
        )
    })
}

fn io_error(driver: &str, e: std::io::Error) -> DriverError {
    DriverError::io(driver, e)
}

#[async_trait]
impl velarx_graph::StorageDriver for VarlinkDriver {
    fn name(&self) -> &str {
        &self.name
    }

    /// The kind of the driver, as `[storage] driver` and the store name it
    /// (the service says its own name in `status`).
    fn graph_name(&self) -> &str {
        "varlink"
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    /// Empty: the graph data of a container is the driver's own business, and
    /// the engine has no path of a remote store to report.
    fn graph_data(&self, _w: &Writable) -> Vec<(String, String)> {
        Vec::new()
    }

    fn status(&self) -> Vec<(String, String)> {
        let reply: DriverResult<proto::StatusReply> =
            self.call(&request::Status(request::OfStore {
                store: self.store_id(),
            }));
        let mut pairs = vec![
            ("socket".into(), self.link.socket.display().to_string()),
            ("service".into(), format!("{} {}", self.name, self.version)),
            ("store".into(), self.store_id().to_string()),
            ("capabilities".into(), self.caps.summary()),
        ];
        match reply {
            Ok(r) => pairs.extend(r.pairs.into_iter().map(|p| (p.name, p.value))),
            Err(e) => pairs.push(("status".into(), e.to_string())),
        }
        pairs
    }

    async fn pull(
        &self,
        feed: &Arc<dyn PullFeed>,
        layers: &[FeedLayer],
        settled: Settled,
    ) -> DriverResult<Pulled> {
        let name = &self.name;
        // (a random id for this attempt, which the engine's lease is named
        // by and the driver takes for the pull)
        let id = new_pull_id();
        // (the bytes go into files the driver passes with each fetch: this
        // has none until then)
        let into = FilesIncoming::of(&id, FilesSink::none(&id, &self.scratch));
        feed.begin(&into).await.map_err(|e| refused(name, e))?;
        let result = self.drive(feed, layers, settled, &id).await;
        feed.end();
        result
    }

    async fn has_layers(&self, layers: &[LayerRef]) -> DriverResult<Vec<bool>> {
        let wire = convert::wire_refs(layers);
        let inner = self.inner.clone();
        let reply: proto::HasReply = velarx_graph::blocking(|| {
            inner.call(&request::HasLayers {
                store: inner.store_id(),
                layers: &wire,
            })
        })?;
        if reply.have.len() != layers.len() {
            return Err(DriverError::storage(
                &self.name,
                format!(
                    "the storage service answered {} layers for the {} asked: one answer for each, in the order asked",
                    reply.have.len(),
                    layers.len()
                ),
            ));
        }
        Ok(reply.have)
    }

    async fn repair(&self, layers: &[LayerRef]) -> DriverResult<HashMap<LayerKey, LayerArtifact>> {
        let wire = convert::wire_refs(layers);
        let inner = self.inner.clone();
        let name = &self.name;
        velarx_graph::blocking(|| {
            inner.long(
                &request::Repair {
                    store: inner.store_id(),
                    layers: &wire,
                },
                &[],
                |r: proto::Repaired| {
                    let list = r.artifacts.ok_or_else(|| {
                        DriverError::storage(
                            name,
                            "the storage service ended Repair without its answer",
                        )
                    })?;
                    convert::artifacts(name, list)
                },
            )
        })
    }

    async fn remake_staged(&self, _pull: &str) -> DriverResult<()> {
        Err(unsupported(
            &self.name,
            "images whose files are partly missing (lazy) are not served by a storage service yet",
        ))
    }

    fn read_objects(&self, ranges: &[ObjectRange], sink: &mut dyn ObjectSink) -> DriverResult<()> {
        self.read_with(None, ranges, sink).map(drop)
    }

    /// The object read back with `ReadObjects` into a file without a name
    /// in the scratch directory of the graph root: on disk, not in `TMPDIR`
    /// (a tmpfs holds an object in memory, and may be smaller than it).
    fn open_object(&self, key: &str, size: u64) -> DriverResult<File> {
        let file = velarx_content::pull::unnamed::unnamed_file(&self.scratch)
            .map_err(|e| io_error(&self.name, e))?;
        spool_object_into(&self.name, key, size, file, |ranges, sink| {
            self.read_with(None, ranges, sink).map(drop)
        })
    }

    /// The next objects of the list in one `ReadObjects` (up to the limits of
    /// the proof of a pull: [`StagedObjects`]).
    fn objects_in_order(
        &self,
        order: &mut dyn FnMut() -> Vec<(String, u64)>,
    ) -> Option<Arc<dyn ObjectOpener>> {
        Some(Arc::new(StagedObjects::of(
            self.inner.clone(),
            None,
            order(),
        )))
    }

    fn remove_image(&self, image_id: &str) -> DriverResult<()> {
        self.ack(&request::RemoveImage(request::OfImage {
            store: self.store_id(),
            image: image_id,
        }))
    }

    fn image_volume_create(&self, req: &MountRequest<'_>) -> DriverResult<Planned> {
        let name = &self.name;
        not_lazy(name, req.image)?;
        let Purpose::Volume { index } = req.purpose else {
            return Err(DriverError::storage(
                name,
                "a request that is not for an image mount, to make one",
            ));
        };
        let refs = convert::wire_refs(&convert::refs_of(req.image, req.layers));
        let ask = convert::mount_ask(req);
        let volume = self.long(
            &request::CreateImageVolume {
                store: self.store_id(),
                container: req.container.id(),
                index,
                image: &req.image.id,
                layers: &refs,
                ask: &ask,
            },
            &[],
            |r: proto::VolumeCreated| {
                r.volume.ok_or_else(|| {
                    DriverError::storage(
                        name,
                        "the storage service made the image mount and did not say what it is",
                    )
                })
            },
        )?;
        convert::planned(name, &self.workdir, volume, false)
    }

    fn mounts(&self, req: &MountsRequest<'_>) -> DriverResult<Mounts> {
        let name = &self.name;
        // (the mounts of one container per call)
        let Some(container) = req.container(name)? else {
            return Ok(Mounts::default());
        };
        for m in req.root.iter().chain(&req.volumes) {
            not_lazy(name, m.image)?;
        }
        let root = req.root.as_ref().map(convert::mount_ask);
        let volumes: Vec<proto::VolumeAsk> = req
            .volumes
            .iter()
            .map(|m| match m.purpose {
                Purpose::Volume { index } => Ok(proto::VolumeAsk {
                    index,
                    ask: convert::mount_ask(m),
                }),
                Purpose::Root => Err(DriverError::storage(
                    name,
                    "the root file system asked for as one of the image mounts",
                )),
            })
            .collect::<DriverResult<_>>()?;
        let (reply, fds): (proto::MountsReply, _) = self.session()?.call(
            &request::Mounts {
                store: self.store_id(),
                container: container.id(),
                root: root.as_ref(),
                volumes: &volumes,
            },
            &[],
        )?;
        if reply.root.is_some() != req.root.is_some() {
            return Err(DriverError::storage(
                name,
                if reply.root.is_some() {
                    "the storage service answered a root that was not asked for"
                } else {
                    "the storage service answered no root"
                },
            ));
        }
        if reply.volumes.len() != req.volumes.len() {
            return Err(DriverError::storage(
                name,
                format!(
                    "the storage service answered {} image mounts for the {} asked",
                    reply.volumes.len(),
                    req.volumes.len()
                ),
            ));
        }
        let had_root = reply.root.is_some();
        let all: Vec<(proto::Mounted, bool)> = reply
            .root
            .into_iter()
            .map(|m| (m, true))
            .chain(reply.volumes.into_iter().map(|m| (m, false)))
            .collect();
        let mut list = convert::rootfs_list(name, &self.workdir, all, fds)?.into_iter();
        let root = if had_root { list.next() } else { None };
        Ok(Mounts {
            root,
            volumes: list.collect(),
        })
    }

    fn holds_objects(&self) -> bool {
        false
    }

    fn image_view(
        &self,
        image_id: &str,
        layers: &[LayerRecord],
    ) -> DriverResult<Arc<dyn ImageTree>> {
        // the image is read from a mount of it, the tables of contents of
        // its layers are not (they stay in the database)
        let fd = self.image_fd(image_id, layers)?;
        let view = velarx_fuse::MountedImage::new(fd)
            .map_err(|e| DriverError::storage(&self.name, format!("image {image_id}: {e}")))?;
        Ok(Arc::new(view))
    }

    async fn leftovers(&self, _grace: Duration) -> DriverResult<Vec<(PathBuf, String)>> {
        // (the files are the driver's, and the engine can name none of them;
        // what it holds is collected)
        Ok(Vec::new())
    }

    async fn check(
        &self,
        image: &ImageRecord,
        layers: &[LayerRecord],
        full: bool,
    ) -> DriverResult<Vec<Problem>> {
        let refs = convert::wire_refs(&convert::refs_of(image, layers));
        let inner = self.inner.clone();
        let name = &self.name;
        let image = image.id.clone();
        velarx_graph::blocking(|| {
            inner.long(
                &request::Check {
                    store: inner.store_id(),
                    image: &image,
                    layers: &refs,
                    full,
                },
                &[],
                |r: proto::Checked| {
                    r.problems
                        .ok_or_else(|| {
                            DriverError::storage(
                                name,
                                "the storage service ended Check without its answer",
                            )
                        })?
                        .into_iter()
                        .map(|p| convert::problem(name, p))
                        .collect()
                },
            )
        })
    }

    fn collect(&self, keep: &Keep) -> DriverResult<Collected> {
        let name = &self.name;
        let mut lines = Vec::new();
        keep.write_lines(&mut lines)
            .map_err(|e| io_error(name, e))?;
        if lines.len() as u64 > proto::MAX_KEEP {
            return Err(DriverError::storage(
                name,
                format!(
                    "the keep set is {} bytes, more than the {} a collection takes",
                    lines.len(),
                    proto::MAX_KEEP
                ),
            ));
        }
        // (a sealed memory file: the driver reads it as a stream, and no
        // process can change it while it does)
        let memfd = velarx_base::sealed::sealed_memory(&lines).map_err(|e| io_error(name, e))?;
        self.long(
            &request::Collect {
                store: self.store_id(),
                keep_length: lines.len() as u64,
            },
            &[memfd.as_fd()],
            |c: proto::Collection| {
                Ok(Collected {
                    bytes_freed: c.bytes_freed.ok_or_else(|| {
                        DriverError::storage(
                            name,
                            "the storage service ended Collect without its answer",
                        )
                    })?,
                    errors: c.errors,
                })
            },
        )
    }

    fn usage(&self) -> DriverResult<Usage> {
        let r: proto::UsageReply = self.call(&request::Usage(request::OfStore {
            store: self.store_id(),
        }))?;
        Ok(Usage {
            artifacts: (r.files, r.bytes),
        })
    }

    fn list_stores(&self) -> DriverResult<Vec<StoreInfo>> {
        let r: proto::StoresReply = self.session()?.call(&request::ListStores {}, &[])?.0;
        Ok(r.stores
            .into_iter()
            .map(|s| StoreInfo {
                store: s.store,
                bytes: s.bytes,
                last_open: s.last_open,
            })
            .collect())
    }

    fn drop_store(&self, store: &str) -> DriverResult<()> {
        // (a name is never a path: refused before it is sent)
        if !velarx_graph::stores::is_store_id(store) {
            return Err(DriverError::storage(
                &self.name,
                format!("{store:?} is not a store id (32 hex digits)"),
            ));
        }
        self.ack(&request::DropStore(request::OfStore { store }))
    }

    fn writable_create(
        &self,
        w: &Writable,
        owner: Option<(u32, u32)>,
        opts: &WritableOptions,
        base: Option<&MountRequest<'_>>,
    ) -> DriverResult<Option<Planned>> {
        let name = &self.name;
        if opts.size_limit.is_some() && !self.caps.writable_size_limit {
            return Err(unsupported(
                name,
                "the storage service has no size limit of the writable layer (--storage-opt size=)",
            ));
        }
        if let Some(b) = base {
            not_lazy(name, b.image)?;
            if b.mapping.is_some() && self.caps.root.idmap.is_empty() {
                return Err(unsupported(
                    name,
                    "the storage service cannot show the ids of a container with a user namespace of its own (its GetInfo has no idmap for a root)",
                ));
            }
        }
        let (image, refs, ask) = match base {
            Some(b) => (
                Some(b.image.id.as_str()),
                convert::wire_refs(&convert::refs_of(b.image, b.layers)),
                convert::mount_ask(b),
            ),
            None => (
                None,
                Vec::new(),
                proto::MountAsk {
                    mapping: None,
                    idmap_mount: false,
                    label: None,
                    verity: None,
                },
            ),
        };
        let had_image = base.is_some();
        let root = self.long(
            &request::CreateRoot {
                store: self.store_id(),
                container: w.id(),
                workdir: self.workdir.to_str().unwrap_or_default(),
                image,
                layers: &refs,
                owner: owner.map(|(uid, gid)| proto::Owner { uid, gid }),
                ask: &ask,
                size_limit: opts.size_limit,
            },
            &[],
            |r: proto::Created| Ok(r.root),
        )?;
        match (root, had_image) {
            (Some(m), true) => Ok(Some(convert::planned(name, &self.workdir, m, true)?)),
            (None, false) => Ok(None),
            (None, true) => Err(DriverError::storage(
                name,
                "the storage service made the root and did not say what it is",
            )),
            (Some(_), false) => Err(DriverError::storage(
                name,
                "the storage service answered a root for a container with no image",
            )),
        }
    }

    /// Empty: a store behind a socket has no path of the engine's to name its
    /// layer by (the engine reads `upper` only for `overlay_upper`, which such
    /// a store does not have), it hands the root over (`writable_root`).
    fn writable_paths(&self, _w: &Writable) -> WritablePaths {
        WritablePaths {
            upper: PathBuf::new(),
            work: None,
            merged: PathBuf::new(),
        }
    }

    fn writable_root(&self, w: &Writable) -> DriverResult<OwnedFd> {
        self.writable_fd(w)
    }

    fn writable_size(&self, w: &Writable) -> DriverResult<u64> {
        let r: proto::SizeReply = self.call(&request::Size(request::OfContainer {
            store: self.store_id(),
            container: w.id(),
        }))?;
        Ok(r.bytes)
    }

    fn writable_remove(&self, w: &Writable) -> DriverResult<()> {
        self.ack(&request::RemoveRoot(request::OfContainer {
            store: self.store_id(),
            container: w.id(),
        }))
    }

    fn writable_release(&self, _w: &Writable) -> velarx_graph::WritableRelease {
        velarx_graph::WritableRelease::Service {
            socket: self.link.socket.clone(),
            timeout_secs: self.link.timeout.as_secs().max(1),
            store: self.store_id().to_string(),
            pin: None,
        }
    }

    fn writable_exists(&self, w: &Writable) -> DriverResult<bool> {
        let r: proto::ExistsReply = self.call(&request::Exists(request::OfContainer {
            store: self.store_id(),
            container: w.id(),
        }))?;
        Ok(r.exists)
    }

    fn diff(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
        out: &mut dyn HoleWrite,
    ) -> DriverResult<()> {
        let fd = self.writable_fd(w)?;
        let mut walk = opts.walk(Some(self.lower(lower)?));
        walk.unowned = unowned();
        dirtar::copydiff::write(fd.as_fd(), &walk, out).map_err(|e| io_error(&self.name, e))
    }

    fn changes(
        &self,
        w: &Writable,
        lower: Option<Arc<dyn ImageTree>>,
        opts: &DiffOptions,
    ) -> DriverResult<Vec<(String, Change)>> {
        let fd = self.writable_fd(w)?;
        let mut walk = opts.walk(Some(self.lower(lower)?));
        walk.unowned = unowned();
        dirtar::copydiff::changes(fd.as_fd(), &walk).map_err(|e| io_error(&self.name, e))
    }

    fn apply(
        &self,
        w: &Writable,
        opts: &DiffOptions,
        tar: &mut dyn std::io::Read,
    ) -> DriverResult<()> {
        let fd = self.writable_fd(w)?;
        let ex = velarx_wire::cp::ExtractOptions {
            archive_owners: Some(opts.id_maps()),
            owner: Some(opts.root_owner()),
            layer: true,
            whiteouts: velarx_wire::cp::Whiteouts::Remove,
            overwrite_dir_non_dir: true,
            ..Default::default()
        };
        velarx_wire::cp::extract(tar, fd.as_fd(), &ex).map_err(|e| io_error(&self.name, e))
    }

    fn stopped_view<'a>(
        &self,
        w: &Writable,
        image: TreeSource<'a>,
    ) -> DriverResult<StoppedView<'a>> {
        Ok(StoppedView::directory(self.writable_fd(w)?, image))
    }

    /// No wire call: the engine tells that a process's root is the
    /// container's by the root the monitor attached, which a root that is a
    /// mount descriptor or a directory has (the monitor records it); a store
    /// behind a socket has no overlay whose mount table could be read.
    fn is_root_of(&self, _w: &Writable, _proc_dir: &Path) -> DriverResult<bool> {
        Err(unsupported(
            &self.name,
            "the root of a process is told apart by the root the monitor attached, not by the storage service",
        ))
    }
}

impl VarlinkDriver {
    pub(crate) fn lower(
        &self,
        tree: Option<Arc<dyn ImageTree>>,
    ) -> DriverResult<Arc<dirtar::Lower>> {
        tree.map(|tree| {
            Arc::new(dirtar::Lower {
                tree,
                // (the files of the image below are the service's: read back
                // through it)
                objects: Arc::new(velarx_graph::DriverObjects::new(Arc::new(Self {
                    inner: self.inner.clone(),
                }))),
            })
        })
        .ok_or_else(|| {
            DriverError::storage(
                &self.name,
                "the changes of the writable layer are found against the image: none was given",
            )
        })
    }

    /// The pull after the engine's feed is begun: the index of each layer,
    /// `BeginPull` with the feed served, the proof of each layer read back
    /// from the driver, the engine's check, `Commit`; `Abort` when any of it
    /// failed.
    async fn drive(
        &self,
        feed: &Arc<dyn PullFeed>,
        layers: &[FeedLayer],
        settled: Settled,
        id: &str,
    ) -> DriverResult<Pulled> {
        let name = &self.name;
        let fetch: Vec<FeedLayer> = to_fetch(layers).cloned().collect();
        // (a layer with no table of contents is read whole here, before the
        // driver is asked anything: it gets the index of the layer it would
        // have had, and asks for the files it lacks as for any other)
        let indexed: Vec<(FeedLayer, velarx_graph::LayerIndex)> =
            futures::stream::iter(fetch.iter().cloned())
                .map(|l| async move {
                    let index = feed.index(&l).await.map_err(|e| refused(name, e))?;
                    match index {
                        Some(index) => Ok((l, index)),
                        None => Err(unsupported(
                            name,
                            format!(
                                "the layer {} cannot be indexed: a lazy pull is not served by a storage service",
                                l.key
                            ),
                        )),
                    }
                })
                .buffered(feed.parallel().max(1))
                .try_collect()
                .await?;
        let engine = Engine {
            feed: feed.clone(),
            runtime: tokio::runtime::Handle::current(),
            scratch: self.scratch.clone(),
            // (a service that says it holds objects is asked which; one
            // that cannot be asked fetches everything)
            holds: self.inner.objects.then(|| {
                let inner = self.inner.clone();
                Arc::new(move |keys: &[String]| match inner.has_objects(keys) {
                    Ok(have) => Ok(have),
                    Err(e) => {
                        tracing::debug!(
                            "the storage service cannot say which objects it holds: {e}"
                        );
                        Ok(vec![false; keys.len()])
                    }
                }) as velarx_content::pull::sink::Holds
            }),
        };
        let served =
            Feed::new(id, engine, indexed.clone()).map_err(|e| DriverError::storage(name, e))?;
        // (dropped with this future: the engine cancels the pull, and the
        // driver sees its connections closed)
        let cancel = Arc::new(Cancel {
            feed: served.clone(),
            call: std::sync::Mutex::default(),
            cancelled: std::sync::atomic::AtomicBool::new(false),
        });
        let _guard = CancelOnDrop(cancel.clone());
        // (the key a layer is stored under is the engine's answer to its
        // index: a layer read whole is the layer of its blob)
        let stored_as: HashMap<(LayerKey, Digest), LayerKey> = indexed
            .iter()
            .map(|(l, i)| ((l.key, l.descriptor.digest), i.key))
            .collect();
        let wire: Vec<proto::PullLayer> = layers
            .iter()
            .map(|l| proto::PullLayer {
                key: stored_as
                    .get(&(l.key, l.descriptor.digest))
                    .filter(|_| !l.stored)
                    .unwrap_or(&l.key)
                    .to_string(),
                diff_id: l.diff_id.to_string(),
                chain_id: l.chain_id.to_string(),
                parent: l.parent.map(|p| p.to_string()),
                stored: l.stored,
            })
            .collect();
        let staged = {
            let (inner, served, id, wire, cancel) = (
                self.inner.clone(),
                served.clone(),
                id.to_string(),
                wire,
                cancel.clone(),
            );
            tokio::task::spawn_blocking(move || inner.begin_pull(&id, &wire, &served, &cancel))
                .await
                .map_err(|e| DriverError::storage(name, e.to_string()))?
        };
        // (a failed call ends the feed; one that staged the pull leaves it
        // open until the engine has decided, so that the driver sees it close
        // with the engine, and does not wait for a decision nobody will make)
        if staged.is_err() {
            served.shutdown();
        } else {
            served.abort_fetches();
        }
        // (what the engine's fetch failed with is why the pull failed, not
        // what the driver says after it)
        let staged = match served.take_failure() {
            Some(e) => Err(refused(name, e)),
            None => staged,
        };
        let result = self
            .finish_pull(feed, indexed, settled, id, staged, &served)
            .await;
        if result.is_err() {
            let inner = self.inner.clone();
            let id = id.to_string();
            let _ = tokio::task::spawn_blocking(move || inner.abort(&id)).await;
        }
        served.shutdown();
        result
    }

    async fn finish_pull(
        &self,
        feed: &Arc<dyn PullFeed>,
        indexed: Vec<(FeedLayer, velarx_graph::LayerIndex)>,
        settled: Settled,
        id: &str,
        staged: DriverResult<()>,
        served: &Arc<Feed>,
    ) -> DriverResult<Pulled> {
        let name = &self.name;
        staged?;
        let fetch: Vec<FeedLayer> = indexed
            .iter()
            .map(|(l, i)| FeedLayer {
                key: i.key,
                ..l.clone()
            })
            .collect();
        feed.finish().await.map_err(|e| refused(name, e))?;
        // The layers the driver brought in, as the engine's check sees them:
        // what the verified index says of each.
        let mut pulled = Vec::with_capacity(indexed.len());
        for (layer, index) in indexed {
            // (the regular files of the layer, by the key the table of
            // contents names them: what the engine records for the layer)
            let files = velarx_content::pull::stream::FileUse::of_toc(&index.toc);
            let (fetched_files, fetched_bytes) = served.fetched(&index.key.to_string());
            let total: u64 = files.iter().map(|f| f.size).sum();
            let report = velarx_content::pull::LayerReport {
                fetched_bytes,
                fetched_files,
                reused_bytes: total.saturating_sub(fetched_bytes),
                reused_files: (files.len() as u64).saturating_sub(fetched_files),
                ..Default::default()
            };
            pulled.push(velarx_content::pull::LayerDone {
                key: index.key,
                blob: layer.descriptor.digest,
                diff_id: layer.diff_id,
                size: layer.descriptor.size,
                toc: index.toc,
                files,
                chunks: Vec::new(),
                report,
                tarsplit: index.tarsplit,
                lazy: false,
                // (the engine did not fetch the bytes: nothing of the
                // layer is vouched for as coming from the registry)
                proven: false,
                blob_checked: false,
                checked: Default::default(),
                toc_z: None,
            });
        }
        // the proof: what the driver stored, read back from it
        let inner = self.inner.clone();
        let pull = id.to_string();
        let copied = Arc::new(served.copied());
        let served = served.clone();
        let pulled = tokio::task::spawn_blocking(move || {
            let mut pulled = pulled;
            for p in &mut pulled {
                // (the entries the engine checked the chunks of as it wrote
                // them in this layer: the first of each object, which is the
                // one its fetch is planned by, by the key the table gives it
                // now, which the proof changes for a table that gives none)
                let checked = served.checked(&p.key.to_string());
                let mut once = std::collections::HashSet::new();
                let sound: Vec<bool> = p
                    .toc
                    .entries
                    .iter()
                    .map(|e| {
                        e.content_key()
                            .is_some_and(|k| checked.contains(&k) && once.insert(k))
                    })
                    .collect();
                let objects = Arc::new(StagedObjects::new(
                    inner.clone(),
                    pull.clone(),
                    &p.toc,
                    copied.clone(),
                ));
                prove_with(&inner.name, objects.clone(), p)?;
                // (what the proof read tells the fs-verity digest of the
                // files the table of contents knows by their hash)
                objects.with_verity(Arc::make_mut(&mut p.toc));
                p.files = velarx_content::pull::stream::FileUse::of_toc(&p.toc);
                // (where the chunks of the layer are in the driver's objects,
                // by the keys it knows them by now: the next pull has the
                // driver copy a chunk it holds.  Only the objects the engine
                // checked chunk by chunk: a table of contents that names a
                // chunk for other bytes of an object the driver had, copied
                // or a job wrote would send every later pull of that chunk to
                // the wrong bytes)
                p.chunks =
                    velarx_content::pull::chunked::located_chunks_where(&p.toc, |i| sound[i]);
            }
            Ok::<_, DriverError>(pulled)
        })
        .await
        .map_err(|e| DriverError::storage(name, e.to_string()))??;
        // the engine's check, before the driver publishes (the driver keeps
        // the objects: the engine reads none)
        let (pulled, settlement) = tokio::task::spawn_blocking(move || {
            let mut pulled = pulled;
            settled(&mut pulled, &|_| None).map(|s| (pulled, s))
        })
        .await
        .map_err(|e| DriverError::storage(name, e.to_string()))?
        .map_err(|e| refused(name, e))?;
        let refs = convert::wire_refs(
            &fetch
                .iter()
                .map(|l| LayerRef {
                    key: l.key,
                    diff_id: l.diff_id,
                    chain_id: l.chain_id,
                })
                .collect::<Vec<_>>(),
        );
        let inner = self.inner.clone();
        let pull = id.to_string();
        tokio::task::spawn_blocking(move || {
            inner.ack(&request::Commit {
                store: inner.store_id(),
                pull: &pull,
                layers: &refs,
            })
        })
        .await
        .map_err(|e| DriverError::storage(name, e.to_string()))??;
        Ok(Pulled {
            layers: pulled,
            artifacts: settlement.identities.artifacts,
            verdict: settlement.verdict,
        })
    }
}
