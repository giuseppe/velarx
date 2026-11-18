// SPDX-License-Identifier: Apache-2.0
//! The registry as a fetcher: what `velarx-registry` serves, and
//! what a process that pulls runs in itself over a socket pair.
//!
//! * `GetManifest`, `GetBlob`: a manifest by a tag or a digest, a small blob
//!   (a configuration) by its digest.
//! * `Probe`: for each blob the call carries, whether it has a table of
//!   contents (zstd:chunked, by the annotations of its descriptor); when it has, the table and
//!   the tar-split come back in sealed memory files, so that the engine
//!   verifies and keeps them and nothing is fetched twice.  A layer is
//!   `on_demand` only when every regular file of its table has an fs-verity
//!   digest: the kernel can then tie a file fetched alone to the table.
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
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use velarx_content::fetcher::fetch::{
    Blob, EventKind, Failure, FetchEvent as Event, FetcherError, NotLazy, Probed, TocSource,
};
use velarx_content::pull::chunked::{
    self, fetch_with_tries, make_batches, Batch, MAX_METADATA_COMPRESSED,
};
use velarx_content::pull::ranges::{self, Piece, RangesError};
use velarx_content::serve_fetch::{
    Described, FetchCall, LayerScope, Out, Scope, StagingFetcher, UnpackCall,
};
use velarx_content::stager::{content_of, name_of, staged, LayerToc, Name, StageError, Unnamed};
use velarx_registry::target::MAX_MANIFEST_SIZE;
use velarx_storage::{Toc, TocEntryType};
use velarx_types::digest::Digest;
use velarx_types::{ImageError, OciDescriptor};

/// The most objects of one `Fetch`.
pub const MAX_OBJECTS: u32 = 4096;

/// The registry as a fetcher.
pub struct RegistryFetch {
    service: Arc<RegistryService>,
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
        e if e.is_transient() => C::Transient,
        _ => C::Failed,
    };
    Failure {
        class,
        reason: e.to_string(),
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
}

impl RegistryFetch {
    pub fn new(service: Arc<RegistryService>) -> Arc<Self> {
        Arc::new(Self { service })
    }

    /// The workers for the repository of the scope.
    fn pool(&self, scope: &Scope) -> Result<(Arc<Pool>, String), FetcherError> {
        let repository = scope
            .source
            .as_deref()
            .ok_or_else(|| FetcherError::Refused {
                reason: "this scope names no repository".into(),
            })?;
        self.service
            .pool_for(
                repository,
                scope.tls_verify.unwrap_or(true),
                scope.access.as_deref().map(Vec::as_slice),
                Reach::Pull,
            )
            .map_err(failed)
    }

    /// The parsed table of contents of a layer, as the scope that told it
    /// gave it: kept with the layer (another scope's table of the same
    /// layer is its own).
    fn toc_of(&self, layer: &LayerScope) -> Result<Arc<LayerToc>, FetcherError> {
        if let Some(t) = layer
            .kept
            .get()
            .and_then(|k| k.clone().downcast::<LayerToc>().ok())
        {
            return Ok(t);
        }
        let t = Arc::new(LayerToc::of(layer)?);
        let _ = layer.kept.set(t.clone());
        Ok(t)
    }

    /// The compressed table of contents and tar-split of a zstd:chunked
    /// layer, as the registry has them.
    async fn metadata(
        &self,
        pool: &Arc<Pool>,
        layer: &OciDescriptor,
        info: &chunked::Info,
        tarsplit: (u64, u64, u64),
    ) -> Result<(Vec<u8>, Vec<u8>), ImageError> {
        let span = |(o, l): (u64, u64)| -> Result<Range<u64>, ImageError> {
            let end = o.checked_add(l).filter(|&e| {
                l > 0 && l <= MAX_METADATA_COMPRESSED && (layer.size < 0 || e <= layer.size as u64)
            });
            end.map(|e| o..e)
                .ok_or_else(|| ImageError::Layer("metadata outside the blob".into()))
        };
        let (toc, ts) = (
            span((info.toc.0, info.toc.1))?,
            span((tarsplit.0, tarsplit.1))?,
        );
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
            ranges_into(pool, &layer.digest, &[a.start..b.end], Some(0), &mut one)
                .await
                .map_err(|e| match e {
                    RangesError::Rejected(s) => {
                        ImageError::Registry(format!("range request refused: {s}"))
                    }
                    RangesError::Other(e) => e,
                })?;
            let whole = std::mem::take(&mut one[0]);
            let at = |r: &Range<u64>| (r.start - a.start) as usize..(r.end - a.start) as usize;
            if whole.len() as u64 == b.end - a.start {
                got = [whole[at(&a)].to_vec(), whole[at(&b)].to_vec()];
            }
        } else {
            match ranges_into(pool, &layer.digest, &wanted, None, &mut got).await {
                Ok(()) => {}
                Err(RangesError::Rejected(_)) => {
                    for (i, r) in wanted.clone().into_iter().enumerate() {
                        got[i].clear();
                        ranges_into(pool, &layer.digest, &[r], Some(i), &mut got)
                            .await
                            .map_err(|e| match e {
                                RangesError::Rejected(s) => {
                                    ImageError::Registry(format!("range request refused: {s}"))
                                }
                                RangesError::Other(e) => e,
                            })?;
                    }
                }
                Err(RangesError::Other(e)) => return Err(e),
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

    /// One request of ranges: each chunk, as the worker decompresses it, is
    /// checked and written into its file; a file whose last chunk came is
    /// given its name.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_batch(
        &self,
        (pool, host): (&Arc<Pool>, &str),
        blob: &Digest,
        plan: &Arc<Planned>,
        files: &Arc<Files>,
        staging: &Arc<File>,
        verity: bool,
        batch: &Batch,
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
        if chunks.whole_blob {
            ranges::ignores_ranges(host);
        }
        Ok(())
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
                self.finish(staging, file, name, verity, positions, files, job, out)
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
        name: Name,
        verity: bool,
        positions: Vec<u32>,
        files: &Files,
        job: usize,
        out: &Out<Event>,
    ) -> Result<(), ()> {
        let (path, size) = {
            let w = files[job].lock().unwrap_or_else(|e| e.into_inner());
            (w.path.clone(), w.size)
        };
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
        let Some(blob) = &layer.blob else {
            return Err(FetcherError::unavailable(
                "the blob of the layer is not known",
            ));
        };
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

/// The bytes of `ranges` of the blob `digest`, appended to `got` (the
/// range at `only`, or each at its index).
async fn ranges_into(
    pool: &Arc<Pool>,
    digest: &Digest,
    ranges: &[Range<u64>],
    only: Option<usize>,
    got: &mut [Vec<u8>; 2],
) -> Result<(), RangesError> {
    let taken: Mutex<Vec<(usize, Vec<u8>)>> = Mutex::new(Vec::new());
    let mut sink = |p: Piece| {
        let i = only.unwrap_or(p.range);
        taken
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((i, p.data.to_vec()));
        Box::pin(async { Ok(()) }) as futures::future::BoxFuture<'_, Result<(), ImageError>>
    };
    let r = pool.ranges(digest, ranges, &mut sink).await;
    for (i, b) in taken.into_inner().unwrap_or_else(|e| e.into_inner()) {
        if let Some(slot) = got.get_mut(i) {
            slot.extend_from_slice(&b);
        }
    }
    r
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
            None => Unnamed::begin(staging.as_fd(), w.size)
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
        _ => Written::Refused(
            *job,
            ImageError::Layer(format!("`{path}`: its file is still written")),
        ),
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
            capabilities: [
                "objects", "unpack", "metadata", "lazy", "sha512", "reuse", "origin",
            ]
            .map(String::from)
            .to_vec(),
            max_objects: MAX_OBJECTS,
        }
    }

    async fn get_manifest(
        &self,
        scope: &Scope,
        reference: &str,
        max: u64,
    ) -> Result<(File, Option<String>), FetcherError> {
        let (pool, _) = self.pool(scope)?;
        velarx_content::serve_registry::checked_reference(reference)
            .map_err(|_| bad("not a tag or a digest"))?;
        let found = pool
            .manifest_opt(reference, max.min(MAX_MANIFEST_SIZE))
            .await
            .map_err(refused)?;
        let (bytes, _) = found.ok_or_else(|| {
            FetcherError::not_found(format!("{reference}: the registry has no such manifest"))
        })?;
        let media_type = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("mediaType")?.as_str().map(str::to_string));
        let fd = velarx_base::sealed::sealed_memory(&bytes).map_err(failed)?;
        Ok((fd.into(), media_type))
    }

    // (`blob.size` is the size of the descriptor: a blob of another size is
    // not the one asked for)
    async fn get_blob(&self, scope: &Scope, blob: &Blob) -> Result<File, FetcherError> {
        let (pool, _) = self.pool(scope)?;
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| bad("not the digest of a blob"))?;
        let size = i64::try_from(blob.size).map_err(|_| bad("a size"))?;
        let bytes = pool
            .small_blob(&digest, size, blob.size)
            .await
            .map_err(refused)?;
        let fd = velarx_base::sealed::sealed_memory(&bytes).map_err(failed)?;
        Ok(fd.into())
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
        out: &Out<Probed>,
    ) -> Result<(), FetcherError> {
        let pool = self.pool(scope)?.0;
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
            let Some(tarsplit) = info.tarsplit else {
                let unpack = reply(TocSource::Unpack, false, Some(NotLazy::NoToc));
                out.send(unpack).await.map_err(|_| failed("gone"))?;
                continue;
            };
            let (toc_z, ts_z) = match self.metadata(&pool, layer, &info, tarsplit).await {
                Ok(m) => m,
                // (the ranges of the blob cannot be had: the layer is read
                // whole, and is not one to serve on demand)
                Err(e) if !chunked::no_other_route(&e) => {
                    tracing::debug!("{}: no table of contents by ranges: {e}", layer.digest);
                    let unpack = reply(TocSource::Unpack, false, Some(NotLazy::NoRanges));
                    out.send(unpack).await.map_err(|_| failed("gone"))?;
                    continue;
                }
                Err(e) => return Err(refused(e)),
            };
            // (checked here for this fetcher's own use; the engine checks
            // what it keeps, and gives the error of a table that is not the
            // descriptor's)
            let checked = {
                let (info, toc_z, ts_z) = (info.clone(), toc_z.clone(), ts_z.clone());
                tokio::task::spawn_blocking(move || {
                    chunked::verify_metadata(&info, &toc_z, ts_z, tarsplit.2)
                })
                .await
                .map_err(failed)?
            };
            let on_demand = checked.is_ok_and(|meta| {
                meta.toc
                    .entries
                    .iter()
                    .filter(|e| e.entry_type == TocEntryType::Reg && e.size > 0)
                    .all(|e| e.verity().is_some())
            });
            let fds = vec![
                velarx_base::sealed::sealed_memory(&toc_z).map_err(failed)?,
                velarx_base::sealed::sealed_memory(&ts_z).map_err(failed)?,
            ];
            out.send_with(
                Probed {
                    toc_file: Some(0),
                    tarsplit_file: Some(1),
                    ..reply(
                        TocSource::Carried,
                        on_demand,
                        (!on_demand).then_some(NotLazy::NoFileDigests),
                    )
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
        let Some(blob) = &layer.blob else {
            out.send(Event {
                objects: (0..call.objects.len() as u32).collect(),
                ..Event::of(EventKind::Unavailable)
            })
            .await
            .map_err(gone)?;
            return Ok(());
        };
        let digest: Digest = blob
            .digest
            .parse()
            .map_err(|_| bad("not the digest of a blob"))?;
        if digest.to_string() != layer.layer {
            return Err(bad("the blob is not the layer's"));
        }
        let size = i64::try_from(blob.size).map_err(|_| bad("a size"))?;
        let indexed = self.toc_of(layer)?;
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
            let &at = indexed.at.get(key).ok_or_else(|| FetcherError::Refused {
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
                size,
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
                name,
                scope.verity,
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
        let all: Vec<usize> = (0..plan.comps.len())
            .filter(|&i| !plan.got[i].load(Ordering::Acquire))
            .collect();
        let concurrency = self.service.limits.range_concurrency.max(1);
        let batches = make_batches(&plan.comps, &all, concurrency, ranges::learnt(&host));
        let mut queue: VecDeque<Batch> = batches.into();
        let run = async {
            let mut running = futures::stream::FuturesUnordered::new();
            let mut error: Option<ImageError> = None;
            loop {
                while running.len() < concurrency && error.is_none() {
                    let Some(batch) = queue.pop_front() else {
                        break;
                    };
                    let bytes: u64 = batch.ranges.iter().map(|r| r.end - r.start).sum();
                    let (pool, plan, files, staging) =
                        (pool.clone(), plan.clone(), files.clone(), staging.clone());
                    let host = host.clone();
                    running.push(async move {
                        let r = fetch_with_tries(
                            batch,
                            &host,
                            &digest,
                            |i| plan.comps[i].clone(),
                            |i| plan.got[i].load(Ordering::Acquire),
                            || false,
                            |b| {
                                let (pool, plan, files, staging, host) = (
                                    pool.clone(),
                                    plan.clone(),
                                    files.clone(),
                                    staging.clone(),
                                    host.clone(),
                                );
                                async move {
                                    self.fetch_batch(
                                        (&pool, &host),
                                        &digest,
                                        &plan,
                                        &files,
                                        &staging,
                                        scope.verity,
                                        &b,
                                        out,
                                    )
                                    .await
                                }
                            },
                        )
                        .await;
                        (r, bytes)
                    });
                }
                use futures::StreamExt;
                match running.next().await {
                    None => break,
                    Some((Ok(()), _)) => {}
                    Some((Err(e), _)) => {
                        error.get_or_insert(e);
                    }
                }
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
}
