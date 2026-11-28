// SPDX-License-Identifier: Apache-2.0
//! The registry as a fetcher: what `velarx-registry` serves, and
//! what a process that pulls runs in itself over a socket pair.
//!
//! * `GetFile` (manifests), `GetBlob`: a manifest by a tag or a digest, a blob by its
//!   digest, written into the file the engine hands over as it arrives.
//! * `Probe`: for each blob the call carries, whether it has a table of
//!   contents (zstd:chunked, by the annotations of its descriptor); when it has, the table and
//!   the tar-split come back in sealed memory files, so that the engine
//!   verifies and keeps them and nothing is fetched twice.  A layer with a
//!   table is pulled by it or not at all: the engine refuses a table that
//!   gives a regular file no fs-verity digest, and the files of a layer
//!   are by their fs-verity digests, which the kernel ties to the table.
//! * `Fetch`: the files a layer's table names, by the ranges of the blob
//!   (merged as a pull merges them), decompressed by the confined workers,
//!   each chunk checked against its sha256 and written by the object
//!   contract ([`velarx_content::stager`]) into the staging directory of the layer.
//!
//! The fetcher reads no store; what it writes is a claim the engine checks.

use crate::net::pool::Pool;
use crate::net::proto::ChunkSpec;
use crate::registry::{Reach, RegistryService};
use async_trait::async_trait;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::ops::Range;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use velarx_content::fetcher::fetch::{
    sealed, Blob, EventKind, Failure, FetchEvent as Event, FetcherError, FileKind, NotLazy, Parts,
    Probed, SignedRecord, TocSource, CAPABILITIES, MAX_FDS,
};
use velarx_content::pull::chunked::{
    self, fetch_with_tries, make_batches, Batch, MAX_METADATA_COMPRESSED,
};
use velarx_content::pull::ranges::{self, Piece, RangesError};
use velarx_content::serve_fetch::{
    BlobFile, Described, FetchCall, Gone, LayerScope, Out, Scope, StagingFetcher, UnpackCall,
};
use velarx_content::stager::{
    content_of, in_memory, name_of, staged, LayerToc, Name, StageError, Unnamed,
};
use velarx_registry::target::MAX_MANIFEST_SIZE;
use velarx_storage::Toc;
use velarx_types::digest::Digest;
use velarx_types::{ImageError, OciDescriptor};

/// The most objects of one `Fetch`.
pub const MAX_OBJECTS: u32 = 4096;

/// The registry as a fetcher.
pub struct RegistryFetch {
    service: Arc<RegistryService>,
    /// A directory of the staging, where the blobs read whole are kept in
    /// files with no name
    scratch: Arc<OwnedFd>,
}

fn failed(e: impl std::fmt::Display) -> FetcherError {
    FetcherError::failed(e.to_string())
}

fn bad(reason: impl Into<String>) -> FetcherError {
    FetcherError::InvalidArgument {
        reason: reason.into(),
    }
}

/// What the registry answered, for a call.
fn refused(e: ImageError) -> FetcherError {
    FetcherError::Failed {
        failure: registry_failure(&e),
    }
}

/// What the registry's own errors are, as the failure a fetcher tells: the
/// one place where the class of an error of the registry client is decided.
pub fn registry_failure(e: &ImageError) -> Failure {
    use velarx_proto::transfer::FailureClass as C;
    let class = match e {
        ImageError::Transfer { failure, .. } => return failure.clone(),
        ImageError::Unauthorized(_) => C::Unauthorized,
        ImageError::Forbidden(_) => C::Forbidden,
        ImageError::RegistryNotFound(_) | ImageError::NotFound(_) => C::NotFound,
        ImageError::DigestMismatch { .. } | ImageError::Contradicted(_) => C::Invalid,
        ImageError::Io(io)
            if io.raw_os_error() == Some(rustix::io::Errno::NOSPC.raw_os_error()) =>
        {
            C::NoSpace
        }
        // (a registry that is not there: the next source is asked, and
        // the same is not asked again)
        ImageError::Http(h) if h.is_connect_timeout() => C::Unavailable,
        e if e.is_transient() => C::Transient,
        _ => C::Failed,
    };
    Failure {
        class,
        reason: e.reason(),
    }
}

/// A file of a call being written: the object (positions in the call) and
/// its chunks still to come.
struct Writing {
    positions: Vec<u32>,
    /// The digest of its content too, when it is named by its fs-verity
    content: Option<Digest>,
    /// Its path in the layer, for the messages
    path: String,
    name: Name,
    size: u64,
    /// Shared by the writers of its chunks, which write outside the lock
    file: Option<Arc<Unnamed>>,
    /// Its file is in memory: its share of the budget of the process
    in_memory: Option<OwnedSemaphorePermit>,
    left: usize,
    /// A chunk of it was refused: it is told failed, its other chunks are
    /// not written
    failed: bool,
    done: bool,
}

/// The files of a call, each with a lock of its own: the writer of a chunk
/// holds none while it hashes and writes.
type Files = Vec<Mutex<Writing>>;

/// The chunks of a fetch: for each, its file, its place in it and its
/// sha256.
struct Planned {
    comps: Vec<Range<u64>>,
    sizes: Vec<u64>,
    owner: Vec<(usize, u64, Option<Digest>)>,
    got: Vec<AtomicBool>,
    /// The files of the call that are in memory go to the engine as
    /// descriptors, a few to an event
    hand: Option<Handing>,
}

/// The small files of a call that are handed over: the positions of the
/// objects and the files that wait for an event, and the budget of the
/// process for the files in memory.  The table of a layer decides in which
/// order the files come to their last chunk, so that the files that are
/// begun and not complete are not bounded by anything else.
struct Handing {
    waiting: Mutex<(Vec<u32>, Vec<OwnedFd>)>,
    memory: Arc<Semaphore>,
}

impl Handing {
    /// The share of the budget of a file of `size` bytes in memory, when it
    /// is small and the budget has the room: the other files are begun in
    /// the staging.
    fn reserve(&self, size: u64) -> Option<OwnedSemaphorePermit> {
        let kib = u32::try_from(size.div_ceil(1024)).ok()?;
        in_memory(size, false)
            .then(|| self.memory.clone().try_acquire_many_owned(kib).ok())
            .flatten()
    }

    /// Hand over `file` as the object `position`: sent with the ones that
    /// wait for it when they are as many as an event carries.
    async fn give(&self, position: u32, file: File, out: &Out<Event>) -> Result<(), Gone> {
        let full = {
            let mut waiting = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
            waiting.0.push(position);
            waiting.1.push(file.into());
            (waiting.1.len() == MAX_FDS).then(|| std::mem::take(&mut *waiting))
        };
        match full {
            Some(full) => Self::send(full, out).await,
            None => Ok(()),
        }
    }

    /// Send the files that wait.
    async fn flush(&self, out: &Out<Event>) -> Result<(), Gone> {
        let waiting = std::mem::take(&mut *self.waiting.lock().unwrap_or_else(|e| e.into_inner()));
        Self::send(waiting, out).await
    }

    async fn send((objects, fds): (Vec<u32>, Vec<OwnedFd>), out: &Out<Event>) -> Result<(), Gone> {
        if fds.is_empty() {
            return Ok(());
        }
        let event = Event {
            files: Some((0..fds.len() as u32).collect()),
            objects,
            ..Event::of(EventKind::Staged)
        };
        out.send_with(event, fds).await
    }
}

/// What [`Scope::kept`] holds the workers of the scope under (not the digest of
/// a layer).
const WORKERS: &str = "workers";

/// The workers of a scope.
struct Workers {
    pool: Arc<Pool>,
    host: String,
}

impl RegistryFetch {
    pub fn new(service: Arc<RegistryService>, scratch: Arc<OwnedFd>) -> Arc<Self> {
        Arc::new(Self { service, scratch })
    }

    /// The blob `digest` of `size` bytes, read from the registry once into a
    /// file with no name, for the registry that cannot give the ranges of
    /// it.  Every request of ranges is answered by reading that file, in
    /// the workers as it would be from the network.  It is kept with the
    /// scope until `Forget` of the layer; the digest is checked as it is
    /// written.
    async fn downloaded(
        &self,
        scope: &Scope,
        pool: &Arc<Pool>,
        digest: &Digest,
        size: u64,
    ) -> Result<Arc<File>, ImageError> {
        let once: Arc<tokio::sync::OnceCell<Arc<File>>> = scope
            .kept
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(digest.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::OnceCell::<Arc<File>>::new()))
            .clone()
            .downcast()
            .expect("what is kept for a blob is its download");
        once.get_or_try_init(|| async {
            read_whole(&self.scratch, pool, digest, size)
                .await
                .map(Arc::new)
        })
        .await
        .cloned()
    }

    /// Run `ask` with no file, or, for a registry that cannot give the
    /// ranges of a blob (it was found out earlier, or `ask` finds out), with
    /// the file the blob was read into.
    async fn sourced<T, Fut>(
        &self,
        scope: &Scope,
        (pool, host): (&Arc<Pool>, &str),
        (digest, size): (&Digest, u64),
        ask: impl Fn(Option<Arc<File>>) -> Fut,
    ) -> Result<T, RangesError>
    where
        Fut: std::future::Future<Output = Result<T, RangesError>>,
    {
        let mut known = ranges::learnt(host).whole;
        loop {
            let file = match known {
                true => Some(self.downloaded(scope, pool, digest, size).await?),
                false => None,
            };
            match ask(file).await {
                Err(RangesError::WholeBlob) if !known => {
                    ranges::ignores_ranges(host);
                    known = true;
                }
                r => return r,
            }
        }
    }

    /// The workers for the repository of the scope: the same for all its
    /// calls, so that their connections to the registry are reused.  (They
    /// are let go with the scope.)
    fn pool(&self, scope: &Scope) -> Result<(Arc<Pool>, String), FetcherError> {
        let repository = scope
            .source
            .as_deref()
            .ok_or_else(|| FetcherError::InvalidArgument {
                reason: "this scope names no repository".into(),
            })?;
        let mut kept = scope.kept.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(w) = kept
            .get(WORKERS)
            .and_then(|w| w.clone().downcast::<Workers>().ok())
        {
            return Ok((w.pool.clone(), w.host.clone()));
        }
        let (pool, host) = self
            .service
            .pool_for(
                repository,
                scope.tls_verify.unwrap_or(true),
                scope.access.as_deref().map(Vec::as_slice),
                Reach::Pull,
            )
            .map_err(failed)?;
        kept.insert(
            WORKERS.into(),
            Arc::new(Workers {
                pool: pool.clone(),
                host: host.clone(),
            }),
        );
        Ok((pool, host))
    }

    /// The compressed table of contents and tar-split of a zstd:chunked
    /// layer, as the registry has them: the `parts` asked for (empty: one
    /// that was not, or that the layer has not).
    async fn metadata(
        &self,
        scope: &Scope,
        (pool, host): (&Arc<Pool>, &str),
        layer: &OciDescriptor,
        (info, parts): (&chunked::Info, Parts),
    ) -> Result<(Vec<u8>, Vec<u8>), ImageError> {
        let span = |(o, l): (u64, u64)| -> Result<Range<u64>, ImageError> {
            let end = o.checked_add(l).filter(|&e| {
                l > 0 && l <= MAX_METADATA_COMPRESSED && (layer.size < 0 || e <= layer.size as u64)
            });
            end.map(|e| o..e)
                .ok_or_else(|| ImageError::Layer("metadata outside the blob".into()))
        };
        let toc = span((info.toc.0, info.toc.1))?;
        // (a canonical layer has no tar-split: its table of contents alone)
        let ts = info.tarsplit.map(|t| span((t.0, t.1))).transpose()?;
        let (toc, ts) = match (parts, ts) {
            (Parts::All, Some(ts)) => (toc, ts),
            (Parts::Tarsplit, Some(ts)) => {
                return Ok((
                    Vec::new(),
                    self.metadata_range(scope, (pool, host), layer, ts).await?,
                ))
            }
            _ => {
                return Ok((
                    self.metadata_range(scope, (pool, host), layer, toc).await?,
                    Vec::new(),
                ))
            }
        };
        let mut wanted = vec![toc.clone(), ts.clone()];
        let swapped = ts.start < toc.start;
        if swapped {
            wanted.swap(0, 1);
        }
        if wanted[0].end > wanted[1].start {
            return Err(ImageError::Layer(
                "the TOC and the tar-split overlap".into(),
            ));
        }
        let mut got: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        // (one request for both when they are close: the bytes between them
        // are read and dropped, as a pull does)
        let (a, b) = (wanted[0].clone(), wanted[1].clone());
        if b.start - a.end <= chunked::METADATA_GAP && b.end - a.start <= chunked::METADATA_TOGETHER
        {
            let mut one: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
            self.ranges_into(
                scope,
                (pool, host),
                layer,
                &[a.start..b.end],
                Some(0),
                &mut one,
            )
            .await
            .map_err(ranges_failed)?;
            let whole = std::mem::take(&mut one[0]);
            let at = |r: &Range<u64>| (r.start - a.start) as usize..(r.end - a.start) as usize;
            if whole.len() as u64 == b.end - a.start {
                got = [whole[at(&a)].to_vec(), whole[at(&b)].to_vec()];
            }
        } else {
            match self
                .ranges_into(scope, (pool, host), layer, &wanted, None, &mut got)
                .await
            {
                Ok(()) => {}
                Err(RangesError::Rejected(_)) => {
                    for (i, r) in wanted.clone().into_iter().enumerate() {
                        got[i].clear();
                        self.ranges_into(scope, (pool, host), layer, &[r], Some(i), &mut got)
                            .await
                            .map_err(ranges_failed)?;
                    }
                }
                Err(e) => return Err(ranges_failed(e)),
            }
        }
        let [a, b] = got;
        if a.len() as u64 != wanted[0].end - wanted[0].start
            || b.len() as u64 != wanted[1].end - wanted[1].start
        {
            return Err(ImageError::Layer("incomplete zstd:chunked metadata".into()));
        }
        Ok(if swapped { (b, a) } else { (a, b) })
    }

    /// The bytes of the range `r` of the blob of `layer`: the table of
    /// contents or the tar-split, on its own.
    async fn metadata_range(
        &self,
        scope: &Scope,
        (pool, host): (&Arc<Pool>, &str),
        layer: &OciDescriptor,
        r: Range<u64>,
    ) -> Result<Vec<u8>, ImageError> {
        let mut got: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        self.ranges_into(
            scope,
            (pool, host),
            layer,
            std::slice::from_ref(&r),
            Some(0),
            &mut got,
        )
        .await
        .map_err(ranges_failed)?;
        let [bytes, _] = got;
        if bytes.len() as u64 != r.end - r.start {
            return Err(ImageError::Layer("incomplete zstd:chunked metadata".into()));
        }
        Ok(bytes)
    }

    /// One request of ranges: each chunk, as the worker decompresses it, is
    /// checked and written into its file; a file whose last chunk came is
    /// given its name.  With `file` the ranges are read from it.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_batch(
        &self,
        pool: &Arc<Pool>,
        blob: &Digest,
        plan: &Arc<Planned>,
        files: &Arc<Files>,
        staging: &Arc<File>,
        verity: bool,
        (batch, file): (&Batch, Option<Arc<File>>),
        out: &Out<Event>,
    ) -> Result<(), RangesError> {
        let members: Vec<Vec<ChunkSpec>> = batch
            .members
            .iter()
            .zip(&batch.ranges)
            .map(|(m, range)| {
                let mut at = range.start;
                m.iter()
                    .map(|&idx| {
                        let comp = &plan.comps[idx];
                        let skip = comp.start.saturating_sub(at);
                        at = comp.end;
                        ChunkSpec {
                            idx,
                            compressed: comp.end - comp.start,
                            size: plan.sizes[idx],
                            skip,
                        }
                    })
                    .collect()
            })
            .collect();
        let limits = &self.service.limits;
        let mut chunks = pool
            .chunks(
                blob,
                &batch.ranges,
                &members,
                limits.max_chunk_bytes as usize,
                file.as_deref(),
            )
            .await?;
        let other = |e: ImageError| RangesError::Other(e);
        while let Some((idx, size)) = chunks.next().await? {
            let kib = (size as u64)
                .div_ceil(1024)
                .clamp(1, limits.memory_bytes / 1024);
            let _memory = self
                .service
                .memory
                .clone()
                .acquire_many_owned(kib as u32)
                .await
                .map_err(|_| other(ImageError::Layer("shut down".into())))?;
            let data = chunks.payload().await?;
            if plan.got[idx].swap(true, Ordering::AcqRel) {
                continue;
            }
            // (the chunk is claimed: it is not asked again, so what keeps
            // it from its file is the failure of that file)
            self.put(plan, files, staging, idx, data, verity, out)
                .await
                .map_err(|()| other(ImageError::Layer("the asker is gone".into())))?;
        }
        Ok(())
    }

    /// The bytes of `ranges` of the blob of `layer`, appended to `got` (the
    /// range at `only`, or each at its index).
    async fn ranges_into(
        &self,
        scope: &Scope,
        (pool, host): (&Arc<Pool>, &str),
        layer: &OciDescriptor,
        ranges: &[Range<u64>],
        only: Option<usize>,
        got: &mut [Vec<u8>; 2],
    ) -> Result<(), RangesError> {
        let size = u64::try_from(layer.size).map_err(|_| bad_size())?;
        let taken: Mutex<Vec<(usize, Vec<u8>)>> = Mutex::new(Vec::new());
        let taken_ref = &taken;
        let r = self
            .sourced(
                scope,
                (pool, host),
                (&layer.digest, size),
                |file| async move {
                    let mut sink = |p: Piece| {
                        let i = only.unwrap_or(p.range);
                        taken_ref
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push((i, p.data.to_vec()));
                        Box::pin(async { Ok(()) })
                            as futures::future::BoxFuture<'_, Result<(), ImageError>>
                    };
                    pool.ranges(&layer.digest, ranges, file.as_deref(), &mut sink)
                        .await
                },
            )
            .await;
        for (i, b) in taken.into_inner().unwrap_or_else(|e| e.into_inner()) {
            if let Some(slot) = got.get_mut(i) {
                slot.extend_from_slice(&b);
            }
        }
        r
    }

    /// Check and write a chunk (blocking: on a thread of its own), and
    /// give its file its name when it was the last one; a chunk that is
    /// refused fails its file only, which is told so ([`Self::fail`]).  An
    /// error when the asker is gone.
    #[allow(clippy::too_many_arguments)]
    async fn put(
        &self,
        plan: &Arc<Planned>,
        files: &Arc<Files>,
        staging: &Arc<File>,
        idx: usize,
        data: Vec<u8>,
        verity: bool,
        out: &Out<Event>,
    ) -> Result<(), ()> {
        let job = plan.owner[idx].0;
        let (p, f, s) = (plan.clone(), files.clone(), staging.clone());
        let written = tokio::task::spawn_blocking(move || write_chunk(&p, &f, &s, idx, &data))
            .await
            .unwrap_or_else(|e| Written::Refused(job, ImageError::Layer(format!("a write: {e}"))));
        match written {
            Written::Part => Ok(()),
            Written::Complete(done) => {
                let (file, name, positions, job) = *done;
                let hand = plan.hand.as_ref();
                self.finish(
                    staging,
                    file,
                    (name, verity, hand),
                    positions,
                    files,
                    job,
                    out,
                )
                .await
            }
            Written::Refused(job, e) => self.fail(files, job, &e, out).await,
        }
    }

    /// Tell that the file `job` failed, with the cause.
    async fn fail(
        &self,
        files: &Files,
        job: usize,
        e: &ImageError,
        out: &Out<Event>,
    ) -> Result<(), ()> {
        let positions = {
            let mut w = files[job].lock().unwrap_or_else(|e| e.into_inner());
            w.done = true;
            w.positions.clone()
        };
        out.send(Event::failed(positions, registry_failure(e)))
            .await
            .map_err(|_| ())
    }

    /// Give a complete file its name (blocking: fs-verity reads it) and say
    /// so, or say why not; an error when the asker is gone.
    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        staging: &File,
        file: Unnamed,
        (name, verity, hand): (Name, bool, Option<&Handing>),
        positions: Vec<u32>,
        files: &Files,
        job: usize,
        out: &Out<Event>,
    ) -> Result<(), ()> {
        let (path, size, in_memory) = {
            let mut w = files[job].lock().unwrap_or_else(|e| e.into_inner());
            (w.path.clone(), w.size, w.in_memory.take())
        };
        // (a file in memory, with one place in the call, is not named: the
        // engine is given it, and knows it by what it reads)
        if let (Some(hand), [position], Some(_)) = (hand, &positions[..], in_memory) {
            let handed = file.handed();
            files[job].lock().unwrap_or_else(|e| e.into_inner()).done = true;
            return match handed {
                Ok(file) => {
                    let _ = out.send(Event::progress(Some(*position), size)).await;
                    hand.give(*position, file, out).await.map_err(|_| ())
                }
                Err(e) => out
                    .send(Event::failed(
                        positions,
                        registry_failure(&stage_error(&path, e)),
                    ))
                    .await
                    .map_err(|_| ()),
            };
        }
        let named = match staging.try_clone() {
            Ok(dir) => tokio::task::spawn_blocking(move || file.finish(dir.as_fd(), &name, verity))
                .await
                .map_err(|e| ImageError::Layer(format!("a write: {e}")))
                .and_then(|r| r.map_err(|e| stage_error(&path, e))),
            Err(e) => Err(ImageError::Io(e)),
        };
        files[job].lock().unwrap_or_else(|e| e.into_inner()).done = true;
        let event = match named {
            Ok(_) => {
                // (the bytes of the object: the call's own, so far)
                if let Some(&first) = positions.first() {
                    let _ = out.send(Event::progress(Some(first), size)).await;
                }
                Event {
                    objects: positions,
                    ..Event::of(EventKind::Staged)
                }
            }
            Err(e) => Event::failed(positions, registry_failure(&e)),
        };
        out.send(event).await.map_err(|_| ())
    }
}

impl RegistryFetch {
    /// `Unpack`: the layer has no table of contents.  Its blob
    /// is read by the confined workers, which decompress it; its tar stream
    /// is unpacked into the staging directory of the layer as it goes by,
    /// each regular file by the object contract (named by the digest of its
    /// content in the algorithm of the blob, fs-verity enabled before the
    /// name when the scope says verity), and the table of contents of what
    /// went by (`toc.claim`) and its tar-split (`tarsplit`) get their names
    /// last: `indexed`.  All of it is a claim: the engine recreates the
    /// stream from the tar-split and the files and checks the diff id.
    async fn unpack_whole(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let blob = &layer.blob;
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| bad("not the digest of a blob"))?;
        if digest.to_string() != layer.layer {
            return Err(bad("the blob is not the layer's"));
        }
        let size = i64::try_from(blob.size).map_err(|_| bad("a size"))?;
        let (pool, _) = self.pool(scope)?;
        let staging = layer.staging.try_clone().map_err(failed)?;
        let max = self.service.limits.inflate_cap(size);
        let verity = scope.verity;
        let run = async {
            let mut frames = pool.layer(&digest, size, max).await?;
            let (tx, rx) = tokio::sync::mpsc::channel(velarx_content::pull::stream::CHANNEL_DEPTH);
            let dir = staging.try_clone()?;
            let files = velarx_content::unpack::Files::new(out.clone());
            let unpacking = tokio::task::spawn_blocking(move || {
                unpack(rx, &dir, (digest.alg(), verity), files)
            });
            let mut sent = 0u64;
            let mut network = None;
            loop {
                match frames.next().await {
                    Ok(Some(frame)) => {
                        let read = frames.progress().min(blob.size);
                        if read > sent {
                            let progress = Event::progress(None, read);
                            sent = read;
                            if out.send(progress).await.is_err() {
                                break;
                            }
                        }
                        if tx.send(Ok(frame)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let lost = std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            e.to_string(),
                        );
                        let _ = tx.send(Err(lost)).await;
                        network = Some(e);
                        break;
                    }
                }
            }
            drop(tx);
            let unpacked = unpacking
                .await
                .map_err(|e| ImageError::Layer(format!("the unpacking of the layer: {e}")))?;
            if let Some(e) = network {
                return Err(e);
            }
            let (toc, tarsplit) = unpacked?;
            // (the workers hashed the blob: a blob that is not the layer's
            // is no claim to make)
            let read = frames
                .trailer()
                .ok_or_else(|| ImageError::Layer("the workers did not say which blob".into()))?;
            if read.blob_digest == digest && read.blob_size != blob.size {
                return Err(ImageError::Layer(format!(
                    "layer {digest} has {} bytes, its descriptor says {}",
                    read.blob_size, blob.size
                )));
            }
            if read.blob_digest != digest {
                return Err(ImageError::DigestMismatch {
                    expected: digest.to_string(),
                    actual: read.blob_digest.to_string(),
                });
            }
            if blob.size > sent {
                let _ = out.send(Event::progress(None, blob.size)).await;
            }
            tokio::task::spawn_blocking(move || {
                velarx_content::unpack::put_claim(&staging, &toc, &tarsplit)
            })
            .await
            .map_err(|e| ImageError::Layer(format!("the index of the layer: {e}")))?
        };
        tokio::select! {
            r = run => r.map_err(refused),
            _ = call.cancel.cancelled() => Ok(()),
        }
    }
}

/// The names in the staging directory of a layer a fetcher unpacked whole:
/// its table of contents (a claim) and its tar-split.
pub use velarx_content::fetcher::fetch::{TARSPLIT, TOC_CLAIM};

/// Unpack the tar stream of `frames`, handing the files over to `files`
/// ([`velarx_content::unpack::unpack_tar`]).
fn unpack(
    frames: tokio::sync::mpsc::Receiver<velarx_content::pull::stream::Frame>,
    staging: &File,
    kind: (velarx_types::digest::Algorithm, bool),
    mut files: velarx_content::unpack::Files,
) -> Result<(Toc, Vec<u8>), ImageError> {
    let reader = velarx_content::pull::stream::ChannelReader::new(frames);
    velarx_content::unpack::unpack_tar(reader, staging, kind, &mut files)
}

fn bad_size() -> RangesError {
    RangesError::Other(ImageError::Layer("a negative size".into()))
}

/// The blob `digest` of `size` bytes, from the registry into a file with no
/// name beneath `scratch`, as it comes, opened anew read only.  A blob that
/// is longer or shorter than `size`, or has another digest, is an error, and
/// the file goes.
async fn read_whole(
    scratch: &OwnedFd,
    pool: &Arc<Pool>,
    digest: &Digest,
    size: u64,
) -> Result<File, ImageError> {
    use std::io::Write;
    let file = File::from(
        rustix::fs::openat(
            scratch,
            ".",
            rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)?,
    );
    let mut hash = velarx_types::digest::DigestWriter::for_digest(digest);
    let mut to = &file;
    pool.blob(digest, size, &mut |data| {
        hash.update(data);
        to.write_all(data)
    })
    .await?;
    let got = hash.finalize();
    if got != *digest {
        return Err(ImageError::DigestMismatch {
            expected: digest.to_string(),
            actual: got.to_string(),
        });
    }
    // (the workers are given it read only: what they read, nothing else)
    use std::os::fd::AsRawFd;
    Ok(File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))?)
}

/// The error of a request of ranges that cannot be asked another way.
fn ranges_failed(e: RangesError) -> ImageError {
    match e {
        RangesError::Rejected(s) => ImageError::Registry(format!("range request refused: {s}")),
        RangesError::WholeBlob => {
            ImageError::Registry("the registry answers ranges with the whole blob".into())
        }
        RangesError::Other(e) => e,
    }
}

/// The error of a file of the layer at `path`.
/// A file that has all its chunks: its unnamed file, name, positions in the
/// call and place in the files of the call.
type Finished = (Unnamed, Name, Vec<u32>, usize);

/// What writing a chunk came to.
enum Written {
    /// Not the last of its file (or its file failed already)
    Part,
    /// The last chunk of its file
    Complete(Box<Finished>),
    /// The chunk was refused: its file, and why
    Refused(usize, ImageError),
}

/// Write the claimed chunk `idx` of `plan` into its file (begun with its
/// first chunk).  The checking and the writing are done outside the lock of
/// the file, which is taken to see and to count.
fn write_chunk(plan: &Planned, files: &Files, staging: &File, idx: usize, data: &[u8]) -> Written {
    let (job, offset, sha) = &plan.owner[idx];
    let lock = || files[*job].lock().unwrap_or_else(|e| e.into_inner());
    let (file, path) = {
        let mut w = lock();
        if w.failed {
            return Written::Part;
        }
        let file = match &w.file {
            Some(file) => Ok(file.clone()),
            // (a file in memory has no name to link: one with several
            // places in the call is named, as `finish` does)
            None => match plan
                .hand
                .as_ref()
                .filter(|_| w.positions.len() == 1)
                .and_then(|hand| hand.reserve(w.size))
            {
                Some(held) => {
                    w.in_memory = Some(held);
                    Unnamed::for_handover(staging.as_fd(), w.size, false)
                }
                None => Unnamed::begin(staging.as_fd(), w.size),
            }
            .map_err(StageError::Io)
            .map(|file| {
                let file = Arc::new(match w.content {
                    Some(d) => file.expect_content(d),
                    None => file,
                });
                w.file = Some(file.clone());
                file
            }),
        };
        (file, w.path.clone())
    };
    let written = file.and_then(|file| {
        let r = file.write_chunk(*offset, data, sha.as_ref());
        // (its own share is let go before it is counted: the last chunk
        // finds the file alone)
        drop(file);
        r
    });
    let mut w = lock();
    if let Err(e) = written {
        w.failed = true;
        w.file = None;
        w.in_memory = None;
        return Written::Refused(*job, stage_error(&path, e));
    }
    if w.failed {
        return Written::Part;
    }
    w.left -= 1;
    if w.left > 0 {
        return Written::Part;
    }
    match w.file.take().map(Arc::try_unwrap) {
        Some(Ok(file)) => {
            Written::Complete(Box::new((file, w.name.clone(), w.positions.clone(), *job)))
        }
        _ => {
            w.in_memory = None;
            Written::Refused(
                *job,
                ImageError::Layer(format!("`{path}`: its file is still written")),
            )
        }
    }
}

/// The bytes of a chunk the engine's store holds, as a hint of the call
/// says, when they are the chunk (`sha`): read from the file the call
/// carries.  `None` when they are not, or cannot be read: the chunk is
/// fetched.
fn reused(source: &File, offset: u64, size: u64, sha: &Digest) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut data = vec![0u8; usize::try_from(size).ok()?];
    source.read_exact_at(&mut data, offset).ok()?;
    (Digest::of(sha.alg(), &data) == *sha).then_some(data)
}

use velarx_content::unpack::stage_error;

/// The descriptor of a layer of the manifest, as the engine sent it in a
/// `Probe`: the annotations of it are where a table of contents is.
fn descriptor_of(blob: &Blob) -> Result<OciDescriptor, FetcherError> {
    Ok(OciDescriptor {
        media_type: blob.media_type.clone(),
        digest: blob
            .digest
            .parse()
            .map_err(|_| bad("not the digest of a blob"))?,
        size: i64::try_from(blob.size).map_err(|_| bad("a size"))?,
        annotations: blob
            .annotations
            .iter()
            .flatten()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    })
}

#[async_trait]
impl StagingFetcher for RegistryFetch {
    fn described(&self) -> Described {
        Described {
            name: "registry".into(),
            capabilities: CAPABILITIES.map(String::from).to_vec(),
            max_objects: MAX_OBJECTS,
        }
    }

    async fn get_file(
        &self,
        scope: &Scope,
        kind: FileKind,
        reference: &str,
        max: u64,
    ) -> Result<(File, Option<String>), FetcherError> {
        let (pool, _) = self.pool(scope)?;
        match kind {
            FileKind::Manifest => {
                velarx_content::serve_registry::checked_reference(reference)
                    .map_err(|_| bad("not a tag or a digest"))?;
                let found = pool
                    .manifest_opt(reference, max.min(MAX_MANIFEST_SIZE))
                    .await
                    .map_err(refused)?;
                let (bytes, _) = found.ok_or_else(|| {
                    FetcherError::not_found(format!(
                        "{reference}: the registry has no such manifest"
                    ))
                })?;
                let media_type = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|v| v.get("mediaType")?.as_str().map(str::to_string));
                Ok((sealed(&bytes)?, media_type))
            }
            FileKind::Signatures => {
                let records = crate::signatures::of(&self.service, &pool, reference, max).await?;
                let bytes = SignedRecord::encoded(records, max).ok_or_else(|| {
                    FetcherError::unavailable(format!("{reference}: no signature"))
                })?;
                Ok((sealed(&bytes)?, None))
            }
            FileKind::Profile => Err(FetcherError::unavailable(format!(
                "{reference}: nobody has it"
            ))),
        }
    }

    // (`blob.size` is the size of the descriptor: a blob of another size is
    // not the one asked for)
    async fn get_blob(&self, scope: &Scope, blob: &Blob, file: File) -> Result<(), FetcherError> {
        let (pool, _) = self.pool(scope)?;
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| bad("not the digest of a blob"))?;
        let mut out = BlobFile::new(file, blob)?;
        let mut wrong = None;
        let got = pool
            .blob(&digest, blob.size, &mut |data| {
                out.write(data).map_err(|e| {
                    wrong = Some(e);
                    std::io::Error::other("the blob is not what was asked for")
                })
            })
            .await;
        got.map_err(|e| wrong.take().unwrap_or_else(|| refused(e)))?;
        out.finish()
    }

    fn registry(&self) -> Option<Arc<dyn velarx_content::serve_registry::RegistryCalls>> {
        Some(self.service.clone())
    }

    fn pusher(&self) -> Option<Arc<dyn velarx_content::serve_push::Pushing>> {
        Some(crate::registry_push::RegistryPush::new(
            self.service.clone(),
        ))
    }

    async fn probe(
        &self,
        scope: &Scope,
        layers: Vec<Blob>,
        (_, parts): (bool, Parts),
        out: &Out<Probed>,
    ) -> Result<(), FetcherError> {
        let (pool, host) = self.pool(scope)?;
        for (at, blob) in layers.iter().enumerate() {
            let at = at as u32;
            let reply = |toc, on_demand, reason| Probed {
                layer: at,
                toc,
                on_demand,
                reason,
                toc_file: None,
                tarsplit_file: None,
            };
            let layer = descriptor_of(blob)?;
            let layer = &layer;
            let info = match chunked::parse_info(layer) {
                Ok(Some(info)) => info,
                Ok(None) => {
                    let unpack = reply(TocSource::Unpack, false, Some(NotLazy::NoToc));
                    out.send(unpack).await.map_err(|_| failed("gone"))?;
                    continue;
                }
                Err(_) => {
                    let none = reply(TocSource::None, false, Some(NotLazy::Unsupported));
                    out.send(none).await.map_err(|_| failed("gone"))?;
                    continue;
                }
            };
            // (a layer with a table is pulled by it or not at all: no table
            // is an error of the layer, which no fetcher after this one
            // makes right)
            let (toc_z, ts_z) = self
                .metadata(scope, (&pool, &host), layer, (&info, parts))
                .await
                .map_err(|e| FetcherError::InvalidArgument {
                    reason: format!("layer {}: its table of contents: {e}", layer.digest),
                })?;
            // (the engine checks what it keeps against the descriptor, and
            // gives the error of a table it cannot use)
            let mut fds = Vec::new();
            let mut carry = |bytes: Vec<u8>| -> Result<Option<u32>, FetcherError> {
                if bytes.is_empty() {
                    return Ok(None);
                }
                fds.push(sealed(&bytes)?.into());
                Ok(Some(fds.len() as u32 - 1))
            };
            let (toc_file, tarsplit_file) = (carry(toc_z)?, carry(ts_z)?);
            out.send_with(
                Probed {
                    toc_file,
                    tarsplit_file,
                    ..reply(TocSource::Carried, true, None)
                },
                fds,
            )
            .await
            .map_err(|_| failed("gone"))?;
        }
        Ok(())
    }

    async fn unpack(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        self.unpack_whole(scope, layer, call, out).await
    }

    async fn fetch(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: FetchCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let gone = |_| failed("the asker is gone");
        let blob = &layer.blob;
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| bad("not the digest of a blob"))?;
        if digest.to_string() != layer.layer {
            return Err(bad("the blob is not the layer's"));
        }
        let size = i64::try_from(blob.size).map_err(|_| bad("a size"))?;
        let indexed = LayerToc::kept(layer)?;
        // the files of the call, once each, and those that are there
        let mut files: Vec<Writing> = Vec::new();
        let mut by_key: HashMap<&str, usize> = HashMap::new();
        let mut present: Vec<u32> = Vec::new();
        let mut chunks_of: Vec<Vec<velarx_content::fetcher::ChunkRef>> = Vec::new();
        for (i, key) in call.objects.iter().enumerate() {
            if let Some(&w) = by_key.get(key.as_str()) {
                files[w].positions.push(i as u32);
                continue;
            }
            let &at = indexed
                .at
                .get(key)
                .ok_or_else(|| FetcherError::InvalidArgument {
                    reason: format!("{key} is not a file of the layer's table of contents"),
                })?;
            let (_, name) = name_of(&indexed.toc.entries[at]).expect("indexed by its name");
            if staged(&layer.staging, key) {
                present.push(i as u32);
                continue;
            }
            let fc = chunked::file_chunks(
                &indexed.toc,
                digest.alg(),
                at,
                Some(size),
                self.service.limits.max_chunk_bytes,
            )
            .map_err(failed)?;
            by_key.insert(key, files.len());
            files.push(Writing {
                positions: vec![i as u32],
                path: indexed.toc.entries[at].name.clone(),
                content: content_of(&indexed.toc.entries[at]),
                name,
                size: fc.size,
                file: None,
                in_memory: None,
                left: fc.chunks.len(),
                failed: false,
                done: false,
            });
            chunks_of.push(fc.chunks);
        }
        if !present.is_empty() {
            out.send(Event {
                objects: present,
                ..Event::of(EventKind::Staged)
            })
            .await
            .map_err(gone)?;
        }
        let mut plan = Planned {
            comps: Vec::new(),
            sizes: Vec::new(),
            owner: Vec::new(),
            got: Vec::new(),
            hand: (call.handover && !scope.verity).then(|| Handing {
                waiting: Default::default(),
                memory: self.service.in_memory.clone(),
            }),
        };
        for (job, chunks) in chunks_of.into_iter().enumerate() {
            for c in chunks {
                let b = c
                    .blob
                    .ok_or_else(|| failed("a chunk with no place in the blob"))?;
                plan.comps.push(b.offset..b.offset + b.length);
                plan.sizes.push(c.size);
                plan.owner.push((
                    job,
                    c.offset,
                    (!c.digest.is_empty())
                        .then(|| c.digest.parse().ok())
                        .flatten(),
                ));
                plan.got.push(AtomicBool::new(false));
            }
        }
        let files: Arc<Files> = Arc::new(files.into_iter().map(Mutex::new).collect());
        // the files of zeros only: no chunk would end them
        let empty: Vec<usize> = files
            .iter()
            .enumerate()
            .filter(|(_, w)| w.lock().unwrap_or_else(|e| e.into_inner()).left == 0)
            .map(|(i, _)| i)
            .collect();
        for job in empty {
            let (name, size, positions, content) = {
                let f = files[job].lock().unwrap_or_else(|e| e.into_inner());
                (f.name.clone(), f.size, f.positions.clone(), f.content)
            };
            let file = Unnamed::begin(layer.staging.as_fd(), size).map_err(failed)?;
            let file = match content {
                Some(d) => file.expect_content(d),
                None => file,
            };
            self.finish(
                &layer.staging,
                file,
                (name, scope.verity, None),
                positions,
                &files,
                job,
                out,
            )
            .await
            .map_err(|()| failed("the asker is gone"))?;
        }
        let plan = Arc::new(plan);
        let staging = Arc::new(layer.staging.try_clone().map_err(failed)?);
        // the chunks the engine's store holds, as its hints say: taken from
        // the files the call carries once they are checked, the rest fetched
        let hints: HashMap<(&str, u64), (usize, u64)> = call
            .reuse
            .iter()
            .map(|r| ((r.chunk.as_str(), r.length), (r.fd as usize, r.offset)))
            .collect();
        for idx in 0..plan.comps.len() {
            let Some(sha) = plan.owner[idx].2 else {
                continue;
            };
            let Some(&(source, offset)) = hints.get(&(sha.to_string().as_str(), plan.sizes[idx]))
            else {
                continue;
            };
            let (Some(source), size) = (call.sources.get(source), plan.sizes[idx]) else {
                continue;
            };
            let source = source.try_clone().map_err(failed)?;
            let data = tokio::task::spawn_blocking(move || reused(&source, offset, size, &sha))
                .await
                .map_err(failed)?;
            let Some(data) = data else {
                continue;
            };
            plan.got[idx].store(true, Ordering::Release);
            self.put(&plan, &files, &staging, idx, data, scope.verity, out)
                .await
                .map_err(|()| failed("the asker is gone"))?;
        }
        let (pool, host) = self.pool(scope)?;
        let concurrency = self.service.limits.range_concurrency.max(1);
        let run = async {
            let mut error: Option<ImageError> = None;
            let all: Vec<usize> = (0..plan.comps.len())
                .filter(|&i| !plan.got[i].load(Ordering::Acquire))
                .collect();
            let mut queue: VecDeque<Batch> =
                make_batches(&plan.comps, &all, concurrency, ranges::learnt(&host)).into();
            let mut running = futures::stream::FuturesUnordered::new();
            loop {
                while running.len() < concurrency && error.is_none() {
                    let Some(batch) = queue.pop_front() else {
                        break;
                    };
                    let (pool, plan, files, staging) =
                        (pool.clone(), plan.clone(), files.clone(), staging.clone());
                    let host = host.clone();
                    running.push(async move {
                        fetch_with_tries(
                            batch,
                            &host,
                            &digest,
                            |i| plan.comps[i].clone(),
                            |i| plan.got[i].load(Ordering::Acquire),
                            || false,
                            |b| {
                                let (pool, plan, files, staging) =
                                    (pool.clone(), plan.clone(), files.clone(), staging.clone());
                                let host = host.clone();
                                async move {
                                    self.sourced(
                                        scope,
                                        (&pool, &host),
                                        (&digest, blob.size),
                                        |file| {
                                            self.fetch_batch(
                                                &pool,
                                                &digest,
                                                &plan,
                                                &files,
                                                &staging,
                                                scope.verity,
                                                (&b, file),
                                                out,
                                            )
                                        },
                                    )
                                    .await
                                }
                            },
                        )
                        .await
                    });
                }
                use futures::StreamExt;
                match running.next().await {
                    None => break,
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        error.get_or_insert(ranges_failed(e));
                    }
                }
            }
            if let Some(hand) = &plan.hand {
                hand.flush(out).await.map_err(gone)?;
            }
            // every file is answered once: those that were not named failed
            let left: Vec<u32> = files
                .iter()
                .map(|w| w.lock().unwrap_or_else(|e| e.into_inner()))
                .filter(|w| !w.done)
                .flat_map(|w| w.positions.clone())
                .collect();
            if !left.is_empty() {
                let e = error.unwrap_or_else(|| ImageError::Layer("a chunk did not come".into()));
                out.send(Event::failed(left, registry_failure(&e)))
                    .await
                    .map_err(gone)?;
            }
            Ok(())
        };
        tokio::select! {
            r = run => r,
            _ = call.cancel.cancelled() => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure is told under the name of the registry: its reason does
    /// not say `registry error` again.
    #[test]
    fn the_reason_of_a_failure_is_the_words_of_the_registry() {
        let e = ImageError::Registry("Failed to get manifest: 500".into());
        assert_eq!(registry_failure(&e).reason, "Failed to get manifest: 500");
    }

    /// A registry that does not answer the connection in time is not tried
    /// again by the same call: the failure is `unavailable`, not
    /// `transient`; one that cuts the connection still is.
    #[tokio::test]
    async fn a_connection_that_times_out_is_not_tried_again() {
        // (a server that takes the connection and never speaks: the TLS
        // handshake does not finish)
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}/v2/", silent.local_addr().unwrap());
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let e = ImageError::from(client.get(&url).send().await.unwrap_err());
        assert!(!e.is_transient(), "{e}");
        assert_eq!(
            registry_failure(&e).class,
            velarx_proto::transfer::FailureClass::Unavailable
        );
        let cut = ImageError::Io(std::io::ErrorKind::ConnectionReset.into());
        assert_eq!(
            registry_failure(&cut).class,
            velarx_proto::transfer::FailureClass::Transient
        );
    }

    /// The words the fetcher announces are those a client reads; a method it
    /// has is no word.
    #[test]
    fn the_fetcher_announces_only_the_words_a_client_reads() {
        let fetch = RegistryFetch::new(
            crate::registry::pool_tests::service(),
            Arc::new(OwnedFd::from(File::open("/").unwrap())),
        );
        assert_eq!(
            fetch.described().capabilities,
            ["reuse", "handover", "table"]
        );
    }

    /// The calls of a scope share their workers, with or without credentials
    /// of their own.
    #[test]
    fn the_calls_of_a_scope_share_the_workers() {
        let fetch = RegistryFetch::new(
            crate::registry::pool_tests::service(),
            Arc::new(OwnedFd::from(File::open("/").unwrap())),
        );
        let scope = |access: &[u8]| Scope {
            verity: false,
            source: Some("registry.invalid/r/app".into()),
            tls_verify: None,
            target: None,
            access: Some(access.to_vec().into()),
            idle: std::time::Duration::from_secs(1),
            kept: Arc::default(),
        };
        let creds = br#"{"creds":{"username":"u","password":"p"}}"#.as_slice();
        for access in [br#"{}"#.as_slice(), creds] {
            let scope = scope(access);
            let (first, _) = fetch.pool(&scope).unwrap();
            let (second, _) = fetch.pool(&scope).unwrap();
            assert!(Arc::ptr_eq(&first, &second));
        }
    }

    /// The files with no name beneath `dir` that this process has open.
    fn unnamed(dir: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .flatten()
            .filter_map(|fd| std::fs::read_link(fd.path()).ok())
            .filter(|t| t.starts_with(dir) && t.to_string_lossy().ends_with(" (deleted)"))
            .count()
    }

    /// A blob read whole from a worker that sends `frames` and then ends:
    /// what `read_whole` made of it, and whether a file with no name is
    /// left beneath the scratch directory.
    async fn read_of(
        blob: &[u8],
        size: u64,
        frames: Vec<Vec<u8>>,
    ) -> (Result<File, ImageError>, usize) {
        use crate::net::proto::{write_data, write_frame, Kind};
        let dir = tempfile::tempdir().unwrap();
        let scratch = OwnedFd::from(File::open(dir.path()).unwrap());
        let pool = crate::net::pool::tests::pool_with(move |mut w| async move {
            let mut at = 0;
            for frame in frames {
                write_data(&mut w, Kind::Data, &[], 0, at, &frame)
                    .await
                    .unwrap();
                at += frame.len() as u64;
            }
            write_frame(&mut w, Kind::Reply, b"{}", &[]).await.unwrap();
        })
        .await;
        let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, blob);
        let read = read_whole(&scratch, &pool, &digest, size).await;
        let open = unnamed(&std::fs::canonicalize(dir.path()).unwrap());
        (read, open)
    }

    /// The blob goes into a file with no name, as it comes; one of another
    /// size or digest is an error and leaves no file.
    #[tokio::test]
    async fn a_blob_read_whole_is_a_file_that_has_its_digest_and_its_size() {
        use std::os::unix::fs::FileExt;
        let blob = b"the blob of a registry".to_vec();
        let (half, rest) = blob.split_at(5);
        let (read, open) = read_of(&blob, 22, vec![half.to_vec(), rest.to_vec()]).await;
        let file = read.unwrap();
        assert_eq!(open, 1);
        let mut got = vec![0u8; blob.len()];
        file.read_exact_at(&mut got, 0).unwrap();
        assert_eq!(got, blob);
        // (read only: a worker it is given cannot change it)
        assert!(file.write_at(b"x", 0).is_err());
        // (a worker is refused for more than it was asked, the digest
        // for other bytes, and a short blob is an error)
        let (read, open) = read_of(&blob, 22, vec![b"another blob of a registry".to_vec()]).await;
        assert!(read.is_err());
        assert_eq!(open, 0);
        let (read, open) = read_of(&blob, 22, vec![b"the blob of a registrx".to_vec()]).await;
        assert!(
            matches!(read, Err(ImageError::DigestMismatch { .. })),
            "{read:?}"
        );
        assert_eq!(open, 0);
        let (read, open) = read_of(&blob, 22, vec![half.to_vec()]).await;
        assert!(read.is_err());
        assert_eq!(open, 0);
    }

    /// A blob that is being read when its call is dropped leaves no file.
    #[tokio::test]
    async fn a_blob_read_whole_that_is_given_up_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = OwnedFd::from(File::open(dir.path()).unwrap());
        let pool = crate::net::pool::tests::pool_with(|mut w| async move {
            crate::net::proto::write_data(&mut w, crate::net::proto::Kind::Data, &[], 0, 0, b"the")
                .await
                .unwrap();
            // (the rest never comes)
            std::future::pending::<()>().await;
        })
        .await;
        let digest = Digest::of(velarx_types::digest::Algorithm::Sha256, b"the blob");
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let read = read_whole(&scratch, &pool, &digest, 8);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), read)
                .await
                .is_err()
        );
        assert_eq!(unnamed(&root), 0);
    }

    /// `GetBlob` of a blob described as `size` bytes of the digest of
    /// `blob`, from a worker that sends `frames`: what it answered, and
    /// what it wrote into the file.
    async fn get_blob_of(
        blob: &[u8],
        size: u64,
        frames: Vec<Vec<u8>>,
    ) -> (Result<(), FetcherError>, Vec<u8>) {
        use crate::net::proto::{write_data, write_frame, Kind};
        let pool = crate::net::pool::tests::pool_with(move |mut w| async move {
            let mut at = 0;
            for frame in frames {
                write_data(&mut w, Kind::Data, &[], 0, at, &frame)
                    .await
                    .unwrap();
                at += frame.len() as u64;
            }
            write_frame(&mut w, Kind::Reply, b"{}", &[]).await.unwrap();
        })
        .await;
        let fetch = RegistryFetch::new(
            crate::registry::pool_tests::service(),
            Arc::new(OwnedFd::from(File::open("/").unwrap())),
        );
        let scope = Scope {
            verity: false,
            source: Some("registry.invalid/r/app".into()),
            tls_verify: None,
            target: None,
            access: None,
            idle: std::time::Duration::from_secs(1),
            kept: Arc::default(),
        };
        scope.kept.lock().unwrap().insert(
            WORKERS.into(),
            Arc::new(Workers {
                pool,
                host: "registry.invalid".into(),
            }),
        );
        let described = Blob {
            digest: Digest::of(velarx_types::digest::Algorithm::Sha256, blob).to_string(),
            size,
            media_type: "application/octet-stream".into(),
            annotations: None,
        };
        let file = tempfile::tempfile().unwrap();
        let got = fetch
            .get_blob(&scope, &described, file.try_clone().unwrap())
            .await;
        // (written at their offsets: the file is still at its start)
        let mut written = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut written).unwrap();
        (got, written)
    }

    /// `GetBlob` writes the blob into the file of the call as its frames
    /// come (more than one: it is not one piece held in memory); another
    /// size or digest is `invalid`.
    #[tokio::test]
    async fn a_blob_is_written_into_the_file_as_it_comes() {
        let invalid = |got: Result<(), FetcherError>| {
            got.unwrap_err().failure().unwrap().class
                == velarx_proto::transfer::FailureClass::Invalid
        };
        let blob: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8 + 1).collect();
        let frames: Vec<Vec<u8>> = blob.chunks(65536).map(<[u8]>::to_vec).collect();
        assert!(frames.len() > 1);
        let (got, written) = get_blob_of(&blob, blob.len() as u64, frames.clone()).await;
        got.unwrap();
        assert_eq!(written, blob);
        // (other bytes of the same size, and a blob longer than its
        // descriptor)
        let mut other = frames.clone();
        other[1][7] ^= 1;
        let (got, _) = get_blob_of(&blob, blob.len() as u64, other).await;
        assert!(invalid(got));
        let mut longer = frames.clone();
        longer.push(b"more".to_vec());
        let (got, _) = get_blob_of(&blob, blob.len() as u64, longer).await;
        assert!(got.is_err());
        let (got, _) = get_blob_of(&blob, blob.len() as u64, frames[..2].to_vec()).await;
        assert!(got.is_err());
    }

    /// A `GetFile` of signatures gives the sigstore attachment of a manifest as the
    /// base64 of the blob of a signature, for a registry whose registries.d
    /// asks for attachments (the storage of the signatures is a directory,
    /// which the engine reads); one that does not has no signature, and a
    /// reference with no digest is refused.
    #[tokio::test]
    async fn the_sigstore_attachment_of_a_manifest_is_its_signature() {
        use crate::net::proto::{read_bytes, read_header, write_data, write_frame, Kind};
        use base64::Engine;
        let payload = br#"{"critical":{}}"#.to_vec();
        let layer = Digest::of(velarx_types::digest::Algorithm::Sha256, &payload);
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": format!("sha256:{}", "0".repeat(64)),
                "size": 2,
            },
            "layers": [{
                "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                "digest": layer.to_string(),
                "size": payload.len(),
                "annotations": {"dev.cosignproject.cosign/signature": "c2ln"},
            }],
        })
        .to_string();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("e.yaml"),
            "docker:\n  registry.invalid:\n    lookaside: file:///signatures\n    use-sigstore-attachments: true\n",
        )
        .unwrap();
        let signed = payload.clone();
        let pool = crate::net::pool::tests::pool_with(move |mut w| async move {
            // (the manifest tagged `ALGO-HEX.sig`, then its layer)
            write_data(&mut w, Kind::Data, &[], 0, 0, manifest.as_bytes())
                .await
                .unwrap();
            write_frame(&mut w, Kind::Reply, b"{}", &[]).await.unwrap();
            let next = read_header(&mut w, 0).await.unwrap();
            read_bytes(&mut w, next.json_len).await.unwrap();
            write_data(&mut w, Kind::Data, &[], 0, 0, &signed)
                .await
                .unwrap();
            write_frame(&mut w, Kind::Reply, b"{}", &[]).await.unwrap();
        })
        .await;
        let fetch = RegistryFetch::new(
            crate::registry::pool_tests::service_of(velarx_config::PullConfig {
                registries_d: Some(dir.path().to_path_buf()),
                ..Default::default()
            }),
            Arc::new(OwnedFd::from(File::open("/").unwrap())),
        );
        let scope = Scope {
            verity: false,
            source: Some("registry.invalid/r/app".into()),
            tls_verify: None,
            target: None,
            access: None,
            idle: std::time::Duration::from_secs(1),
            kept: Arc::default(),
        };
        scope.kept.lock().unwrap().insert(
            WORKERS.into(),
            Arc::new(Workers {
                pool,
                host: "registry.invalid".into(),
            }),
        );
        let digest = format!("sha256:{}", "ab".repeat(32));
        let reference = format!("registry.invalid/r/app:v1@{digest}");
        let (file, _) = fetch
            .get_file(&scope, FileKind::Signatures, &reference, 1 << 20)
            .await
            .unwrap();
        let records: Vec<SignedRecord> = serde_json::from_slice(
            &velarx_base::sealed::read_sealed_whole(&file, 1 << 20).unwrap(),
        )
        .unwrap();
        let expected =
            velarx_signature::sigstore::Signature::Sigstore(velarx_signature::sigstore::Sigstore {
                mime_type: "application/vnd.dev.cosign.simplesigning.v1+json".into(),
                payload,
                annotations: [(
                    "dev.cosignproject.cosign/signature".to_string(),
                    "c2ln".to_string(),
                )]
                .into(),
            });
        assert_eq!(
            records,
            [SignedRecord {
                digest,
                platform: None,
                signatures: vec![
                    base64::engine::general_purpose::STANDARD.encode(expected.to_blob())
                ],
            }]
        );
        // (no digest: not a reference of a signature)
        let got = fetch
            .get_file(
                &scope,
                FileKind::Signatures,
                "registry.invalid/r/app:v1",
                1 << 20,
            )
            .await;
        assert!(matches!(got, Err(FetcherError::InvalidArgument { .. })));
    }

    /// The table of contents of a zstd:chunked layer is found through the
    /// annotations of the blob the engine sent in a `Probe`, and a blob
    /// without them has none.
    #[test]
    fn a_probe_finds_the_table_of_contents_by_the_annotations_of_the_blob() {
        let mut blob = Blob {
            digest: format!("sha256:{}", "a".repeat(64)),
            size: 1000,
            media_type: "application/vnd.oci.image.layer.v1.tar+zstd".into(),
            annotations: Some(
                [
                    (
                        "io.github.containers.zstd-chunked.manifest-position",
                        "100:50:200:1".to_string(),
                    ),
                    (
                        "io.github.containers.zstd-chunked.manifest-checksum",
                        format!("sha256:{}", "b".repeat(64)),
                    ),
                    (
                        "io.github.containers.zstd-chunked.tarsplit-position",
                        "400:20:60".to_string(),
                    ),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            ),
        };
        let info = chunked::parse_info(&descriptor_of(&blob).unwrap())
            .unwrap()
            .expect("a table of contents");
        assert_eq!(info.toc, (100, 50, 200));
        assert_eq!(info.tarsplit, Some((400, 20, 60)));
        blob.annotations = None;
        assert_eq!(
            chunked::parse_info(&descriptor_of(&blob).unwrap()).unwrap(),
            None
        );
    }

    /// A layer whose table puts the last chunk of every small file at the
    /// end of the blob has all its files begun and none complete: the files
    /// in memory stay in the budget, the files past it are begun in the
    /// staging, and a file that fails gives its share back.
    #[test]
    fn files_that_wait_for_their_last_chunk_stay_in_the_budget() {
        const FILES: usize = 40;
        const SIZE: u64 = 100 << 10;
        let budget = 10 * SIZE / 1024;
        let staging = tempfile::tempdir().unwrap();
        let staging = File::open(staging.path()).unwrap();
        let files: Files = (0..FILES)
            .map(|i| {
                Mutex::new(Writing {
                    positions: vec![i as u32],
                    content: None,
                    path: format!("f{i}"),
                    name: Name::Content(Digest::of(velarx_types::digest::Algorithm::Sha256, b"")),
                    size: SIZE,
                    file: None,
                    in_memory: None,
                    left: 2,
                    failed: false,
                    done: false,
                })
            })
            .collect();
        let memory = Arc::new(Semaphore::new(budget as usize));
        let wrong = Digest::of(velarx_types::digest::Algorithm::Sha256, b"other");
        let plan = Planned {
            comps: Vec::new(),
            sizes: Vec::new(),
            // (the chunks of the first half of each file come first, the
            // rest of it last; the last chunk of the first file is wrong)
            owner: (0..2 * FILES)
                .map(|c| {
                    let sha = (c == FILES).then_some(wrong);
                    (c % FILES, (c / FILES) as u64 * SIZE / 2, sha)
                })
                .collect(),
            got: Vec::new(),
            hand: Some(Handing {
                waiting: Default::default(),
                memory: memory.clone(),
            }),
        };
        let half = vec![1u8; (SIZE / 2) as usize];
        let held = || {
            files
                .iter()
                .filter(|w| w.lock().unwrap().in_memory.is_some())
                .count()
        };
        for c in 0..FILES {
            assert!(matches!(
                write_chunk(&plan, &files, &staging, c, &half),
                Written::Part
            ));
        }
        assert_eq!(held(), 10, "the budget is used, not more");
        assert_eq!(memory.available_permits(), 0);
        assert!(matches!(
            write_chunk(&plan, &files, &staging, FILES, &half),
            Written::Refused(0, _)
        ));
        assert_eq!(memory.available_permits(), (SIZE / 1024) as usize);
        for c in FILES + 1..2 * FILES {
            assert!(matches!(
                write_chunk(&plan, &files, &staging, c, &half),
                Written::Complete(_)
            ));
        }
    }
}
