// SPDX-License-Identifier: Apache-2.0
//! A fetcher of items named by their digests: a directory of files named
//! by the hex of the sha256 of their content (with or without `sha256:`; a
//! chunk cache on a disk or an NFS mount, a mirror rsynced from elsewhere),
//! or any other [`Items`].  A file of a layer is staged from the item of
//! its content, or from the items of its chunks, by the object contract
//! ([`crate::stager`]): every chunk is checked against the sha256 the table
//! gives it, the file against its name.  A layer without a table of
//! contents is staged from its index (its table and tar-split, a claim the
//! engine replays) and the items of its files.  It answers only for itself;
//! what it lacks is `unavailable`.
//!
//! The engine serves a `dir` of `[[sources.external]]` with a confined
//! process of its own (`velarx-dir`: it reads the directory, writes the
//! staging and does nothing else); the example `dircache` serves it on a
//! socket.

use crate::fetcher::fetch::{
    Blob, EventKind, Failure, FailureClass, FetchEvent as Event, FetcherError, TARSPLIT, TOC_CLAIM,
};
use crate::serve_fetch::{
    Described, FetchCall, LayerScope, Out, Scope, StagingFetcher, UnpackCall,
};
use crate::stager::{self, content_of, name_of, LayerToc, Name, Unnamed};
use async_trait::async_trait;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use velarx_storage::TocEntryType;
use velarx_types::digest::Digest;

/// The most objects of one `Fetch`.
pub const MAX_OBJECTS: u32 = 4096;

/// Where the items come from.  Untrusted: what an item holds is checked as
/// it is written.
pub trait Items: Send + Sync {
    /// The bytes of the item `name` (a digest as text), when it has exactly
    /// `size` of them (none: at most `max`).
    fn item(&self, name: &str, size: Option<u64>, max: u64) -> Option<Vec<u8>>;

    /// The index of the layer of the blob `layer` (`pull::index`): its table
    /// and tar-split, when this source keeps one.
    fn index(&self, _layer: &str) -> Option<Vec<u8>> {
        None
    }
}

/// A directory of files named by the hex of the sha256 of their content.
pub struct Dir(pub PathBuf);

impl Items for Dir {
    fn item(&self, name: &str, size: Option<u64>, max: u64) -> Option<Vec<u8>> {
        // (only the hash of content names a file here; a FIFO is not waited
        // for)
        let digest: Digest = name.parse().ok()?;
        let (file, len) = [digest.hex().to_string(), digest.to_string()]
            .into_iter()
            .find_map(|name| {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    .open(self.0.join(name))
                    .ok()?;
                let meta = file.metadata().ok()?;
                meta.is_file().then_some((file, meta.len()))
            })?;
        if size.is_some_and(|s| s != len) || len > max {
            return None;
        }
        let mut data = Vec::with_capacity(usize::try_from(len).ok()?);
        // (a file that grows, on a mirror being written, is not read past
        // the size it had)
        file.take(len.saturating_add(1))
            .read_to_end(&mut data)
            .ok()?;
        (data.len() as u64 == len).then_some(data)
    }
}

/// A fetcher of [`Items`].
pub struct ItemFetch<I> {
    name: String,
    items: Arc<I>,
}

/// The fetcher of the directory `dir`.
pub type DirFetch = ItemFetch<Dir>;

impl DirFetch {
    pub fn new(name: &str, dir: impl Into<PathBuf>) -> Arc<Self> {
        ItemFetch::of(name, Dir(dir.into()))
    }
}

impl<I: Items + 'static> ItemFetch<I> {
    pub fn of(name: &str, items: I) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            items: Arc::new(items),
        })
    }
}

/// [`Items`] that count the bytes they gave.
struct Counted<'a>(&'a dyn Items, std::sync::atomic::AtomicU64);

impl Counted<'_> {
    /// The bytes given since the start, as a `progress` event of the blob
    /// of the layer.
    fn progress(&self) -> Option<Event> {
        let bytes = self.1.load(std::sync::atomic::Ordering::Relaxed);
        (bytes > 0).then(|| Event::progress(None, bytes))
    }
}

impl Items for Counted<'_> {
    fn item(&self, name: &str, size: Option<u64>, max: u64) -> Option<Vec<u8>> {
        let data = self.0.item(name, size, max)?;
        self.1
            .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Some(data)
    }

    fn index(&self, layer: &str) -> Option<Vec<u8>> {
        self.0.index(layer)
    }
}

/// The largest item: a file or a chunk a source may give.
const MAX_ITEM: u64 = velarx_storage::MAX_SERVED_BYTES as u64;

/// Stage the file at `at` of the table: whole from the item of its content,
/// else from the items of its chunks.  `Ok(false)`: the source has not got
/// it.
fn stage_file(
    items: &dyn Items,
    indexed: &LayerToc,
    (key, at): (&str, usize),
    staging: &std::fs::File,
    verity: bool,
) -> Result<bool, stager::StageError> {
    let entry = &indexed.toc.entries[at];
    let Some((_, name)) = name_of(entry) else {
        return Ok(false);
    };
    let begin = |size: u64| -> std::io::Result<Unnamed> {
        let file = Unnamed::begin(staging.as_fd(), size)?;
        Ok(match content_of(entry) {
            Some(d) => file.expect_content(d),
            None => file,
        })
    };
    let whole = items
        .item(key, Some(entry.size), MAX_ITEM)
        .or_else(|| items.item(entry.digest.as_deref()?, Some(entry.size), MAX_ITEM));
    if let Some(data) = whole {
        let file = begin(entry.size)?;
        file.write_chunk(0, &data, None)?;
        file.finish(staging.as_fd(), &name, verity)?;
        return Ok(true);
    }
    let Ok(fc) = crate::pull::chunked::file_chunks(
        &indexed.toc,
        velarx_types::digest::Algorithm::Sha256,
        at,
        i64::MAX,
        MAX_ITEM,
    ) else {
        return Ok(false);
    };
    let mut pieces = Vec::with_capacity(fc.chunks.len());
    for c in &fc.chunks {
        let Some((digest, data)) = c.digest.parse::<Digest>().ok().and_then(|d| {
            items
                .item(&c.digest, Some(c.size), MAX_ITEM)
                .map(|data| (d, data))
        }) else {
            return Ok(false);
        };
        pieces.push((c.offset, digest, data));
    }
    let file = begin(fc.size)?;
    for (offset, digest, data) in pieces {
        file.write_chunk(offset, &data, Some(&digest))?;
    }
    file.finish(staging.as_fd(), &name, verity)?;
    Ok(true)
}

/// Stage the layer of the blob `layer` from its index and the items of its
/// files it has: whether it did (`toc.claim` and `tarsplit` named last).
fn stage_whole(
    items: &dyn Items,
    layer: &str,
    blob_size: Option<u64>,
    staging: &std::fs::File,
    verity: bool,
) -> Result<bool, stager::StageError> {
    let Some(index) = items.index(layer) else {
        return Ok(false);
    };
    let cap = blob_size.map_or(i64::MAX, |s| i64::try_from(s).unwrap_or(i64::MAX));
    let Ok((toc, tarsplit)) = crate::pull::index::decode(&index, crate::pull::index::json_cap(cap))
    else {
        return Ok(false);
    };
    // (what an index makes this fetcher stage is bounded, before anything
    // is asked: each file by what a source may give, all of them by the
    // layer when its size is known)
    let files = toc
        .entries
        .iter()
        .filter(|e| e.entry_type == TocEntryType::Reg);
    if files.clone().any(|e| e.size > MAX_ITEM) {
        return Ok(false);
    }
    let total = files.map(|e| e.size).fold(0, u64::saturating_add);
    if blob_size.is_some_and(|s| total > s.saturating_mul(4).max(64 << 20)) {
        return Ok(false);
    }
    let mut seen = std::collections::HashSet::new();
    for e in &toc.entries {
        if e.entry_type != TocEntryType::Reg || e.size == 0 {
            continue;
        }
        let Some(content) = e.digest.as_deref().and_then(|d| d.parse::<Digest>().ok()) else {
            return Ok(false);
        };
        if !seen.insert(content) {
            continue;
        }
        let asked = e.verity().unwrap_or_else(|| content.to_string());
        // (a file it has not got is left out: the claim names it, the
        // engine may have it)
        let Some(data) = items
            .item(&asked, Some(e.size), MAX_ITEM)
            .or_else(|| items.item(&content.to_string(), Some(e.size), MAX_ITEM))
        else {
            continue;
        };
        let file = Unnamed::begin(staging.as_fd(), e.size)?;
        file.write_chunk(0, &data, None)?;
        file.finish(staging.as_fd(), &Name::Content(content), verity)?;
    }
    let json = serde_json::to_vec(&toc).map_err(std::io::Error::other)?;
    stager::put_named(staging.as_fd(), TOC_CLAIM, &json)?;
    stager::put_named(staging.as_fd(), TARSPLIT, &tarsplit)?;
    Ok(true)
}

impl<I: Items + 'static> ItemFetch<I> {
    /// The item `name` (of exactly `size` bytes when it says) as a sealed
    /// memory file, or `unavailable`.
    async fn item_file(
        &self,
        name: &str,
        size: Option<u64>,
        max: u64,
    ) -> Result<std::fs::File, FetcherError> {
        let failed = |e: String| FetcherError::failed(e);
        let (items, asked) = (self.items.clone(), name.to_string());
        let bytes = tokio::task::spawn_blocking(move || items.item(&asked, size, max))
            .await
            .map_err(|e| failed(e.to_string()))?
            .ok_or_else(|| FetcherError::unavailable(format!("{name}: not here")))?;
        let fd = velarx_base::sealed::sealed_memory(&bytes).map_err(|e| failed(e.to_string()))?;
        Ok(fd.into())
    }
}

#[async_trait]
impl<I: Items + 'static> StagingFetcher for ItemFetch<I> {
    fn described(&self) -> Described {
        Described {
            name: self.name.clone(),
            capabilities: vec!["objects".into(), "unpack".into()],
            max_objects: MAX_OBJECTS,
        }
    }

    /// A blob of exactly the bytes its descriptor says, by its digest.
    async fn get_blob(&self, _scope: &Scope, blob: &Blob) -> Result<std::fs::File, FetcherError> {
        self.item_file(&blob.digest, Some(blob.size), blob.size)
            .await
    }

    /// The startup profile of an image.
    async fn get_profile(
        &self,
        _scope: &Scope,
        image: &str,
        max: u64,
    ) -> Result<std::fs::File, FetcherError> {
        self.item_file(image, None, max).await
    }

    async fn unpack(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        _call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let failed = |e: String| FetcherError::failed(e);
        let staging = layer
            .staging
            .try_clone()
            .map_err(|e| failed(e.to_string()))?;
        let (items, verity) = (self.items.clone(), scope.verity);
        let (name, blob_size) = (layer.layer.clone(), layer.blob.as_ref().map(|b| b.size));
        let (staged, progress) = tokio::task::spawn_blocking(move || {
            let counted = Counted(&*items, Default::default());
            let staged = stage_whole(&counted, &name, blob_size, &staging, verity);
            // (only the bytes of what it staged count)
            let progress = match staged {
                Ok(true) => counted.progress(),
                _ => None,
            };
            (staged, progress)
        })
        .await
        .map_err(|e| failed(e.to_string()))?;
        if let Some(event) = progress {
            out.send(event)
                .await
                .map_err(|_| failed("the asker is gone".into()))?;
        }
        match staged {
            Ok(true) => Ok(()),
            Ok(false) => Err(FetcherError::unavailable("no such blob")),
            Err(e) => Err(FetcherError::Failed {
                failure: Failure {
                    class: FailureClass::Invalid,
                    reason: e.to_string(),
                },
            }),
        }
    }

    async fn fetch(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: FetchCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let failed = |e: String| FetcherError::failed(e);
        let staging = layer
            .staging
            .try_clone()
            .map_err(|e| failed(e.to_string()))?;
        let (items, verity) = (self.items.clone(), scope.verity);
        let indexed = LayerToc::of(layer)?;
        let objects = call.objects;
        let events = tokio::task::spawn_blocking(move || {
            let counted = Counted(&*items, Default::default());
            let (mut staged, mut nobody, mut events) = (Vec::new(), Vec::new(), Vec::new());
            for (i, key) in objects.iter().enumerate() {
                let Some(&at) = indexed.at.get(key) else {
                    return Err(FetcherError::Refused {
                        reason: format!("{key} is not a file of the layer's table of contents"),
                    });
                };
                if stager::staged(&staging, key) {
                    staged.push(i as u32);
                    continue;
                }
                // (only the bytes of what it staged count)
                let before = counted.1.load(std::sync::atomic::Ordering::Relaxed);
                let result = stage_file(&counted, &indexed, (key, at), &staging, verity);
                if !matches!(result, Ok(true)) {
                    counted
                        .1
                        .store(before, std::sync::atomic::Ordering::Relaxed);
                }
                match result {
                    Ok(true) => {
                        staged.push(i as u32);
                        // (the bytes this object took: its own, cumulative)
                        let moved = counted.1.load(std::sync::atomic::Ordering::Relaxed);
                        events.push(Event::progress(Some(i as u32), moved - before));
                    }
                    Ok(false) => nobody.push(i as u32),
                    Err(e) => events.push(Event::failed(
                        vec![i as u32],
                        Failure {
                            class: FailureClass::Invalid,
                            reason: format!("{}: {e}", indexed.toc.entries[at].name),
                        },
                    )),
                }
            }
            for (kind, objects) in [
                (EventKind::Staged, staged),
                (EventKind::Unavailable, nobody),
            ] {
                if !objects.is_empty() {
                    events.push(Event {
                        objects,
                        ..Event::of(kind)
                    });
                }
            }
            Ok(events)
        })
        .await
        .map_err(|e| failed(e.to_string()))??;
        for event in events {
            out.send(event)
                .await
                .map_err(|_| failed("the asker is gone".into()))?;
        }
        Ok(())
    }
}
