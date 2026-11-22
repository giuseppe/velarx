// SPDX-License-Identifier: Apache-2.0
//! A fetcher of items named by their digests: a directory of files named
//! by the hex of the sha256 of their content (with or without `sha256:`; a
//! chunk cache on a disk or an NFS mount, a mirror rsynced from elsewhere),
//! or any other [`Items`].  A file of a layer is staged from the item of
//! its content, or from the items of its chunks, by the object contract
//! ([`crate::stager`]): every chunk is checked against the sha256 the table
//! gives it, the file against its name.  A layer without a table of
//! contents is answered to `Probe` with its index (its table and tar-split, a
//! claim the engine replays), and its files are staged as those of a table.
//! It answers only for itself; what it lacks is `unavailable`.
//!
//! The engine serves a `dir` of `[[sources.external]]` with a confined
//! process of its own (`velarx-dir`: it reads the directory, writes the
//! staging and does nothing else); the example `dircache` serves it on a
//! socket.

use crate::fetcher::fetch::{
    Blob, EventKind, Failure, FailureClass, FetchEvent as Event, FetcherError, NotLazy, Parts,
    Probed, TocSource,
};
use crate::serve_fetch::{Described, FetchCall, LayerScope, Out, Scope, StagingFetcher};
use crate::stager::{self, content_of, name_of, LayerToc, Unnamed};
use async_trait::async_trait;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
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

impl Items for Counted<'_> {
    fn item(&self, name: &str, size: Option<u64>, max: u64) -> Option<Vec<u8>> {
        let data = self.0.item(name, size, max)?;
        self.1
            .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Some(data)
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
        None,
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
            capabilities: vec!["objects".into()],
            max_objects: MAX_OBJECTS,
        }
    }

    /// The index of each layer without a table of contents that the items
    /// keep (a claim, `no_toc`: not lazy); the others are `unreachable`, and
    /// all of them `again` (the items have one index of a layer).
    async fn probe(
        &self,
        _scope: &Scope,
        layers: Vec<Blob>,
        (again, _): (bool, Parts),
        out: &Out<Probed>,
    ) -> Result<(), FetcherError> {
        let gone = |_| FetcherError::failed("the asker is gone".to_string());
        for (at, blob) in layers.iter().enumerate() {
            let (items, layer) = (self.items.clone(), blob.digest.clone());
            let cap = crate::pull::index::json_cap(i64::try_from(blob.size).unwrap_or(i64::MAX));
            let whole = blob.toc_checksum().is_none() && !again;
            let index = tokio::task::spawn_blocking(move || {
                whole
                    .then(|| items.index(&layer))
                    .flatten()
                    .filter(|i| crate::pull::index::is_well_formed(i, cap))
            })
            .await
            .map_err(|e| FetcherError::failed(e.to_string()))?;
            let none = Probed {
                layer: at as u32,
                toc: TocSource::None,
                on_demand: false,
                reason: Some(NotLazy::Unreachable),
                toc_file: None,
                tarsplit_file: None,
            };
            let Some(index) = index else {
                out.send(none).await.map_err(gone)?;
                continue;
            };
            let (toc_z, tarsplit_z) =
                crate::pull::index::split(&index).map_err(FetcherError::failed)?;
            let fds = vec![
                velarx_base::sealed::sealed_memory(toc_z)
                    .map_err(|e| FetcherError::failed(e.to_string()))?,
                velarx_base::sealed::sealed_memory(tarsplit_z)
                    .map_err(|e| FetcherError::failed(e.to_string()))?,
            ];
            let reply = Probed {
                toc: TocSource::Carried,
                reason: Some(NotLazy::NoToc),
                toc_file: Some(0),
                tarsplit_file: Some(1),
                ..none
            };
            out.send_with(reply, fds).await.map_err(gone)?;
        }
        Ok(())
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
        let indexed = LayerToc::kept(layer)?;
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
                // (the bytes this object took)
                counted.1.store(0, std::sync::atomic::Ordering::Relaxed);
                match stage_file(&counted, &indexed, (key, at), &staging, verity) {
                    Ok(true) => {
                        staged.push(i as u32);
                        let moved = counted.1.load(std::sync::atomic::Ordering::Relaxed);
                        events.push(Event::progress(Some(i as u32), moved));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Indexes(HashMap<String, Vec<u8>>);

    impl Items for Indexes {
        fn item(&self, _: &str, _: Option<u64>, _: u64) -> Option<Vec<u8>> {
            None
        }
        fn index(&self, layer: &str) -> Option<Vec<u8>> {
            self.0.get(layer).cloned()
        }
    }

    /// The `Probe` of a layer carries the index the items keep for its blob
    /// (not lazy: `no_toc`) unless its tar-split is not the one its table
    /// names; a layer with none, or with a zstd:chunked table, is
    /// unreachable.
    #[tokio::test]
    async fn a_probe_carries_the_index_of_a_layer() {
        use crate::pull::index;
        let tarsplit = b"a tar-split".to_vec();
        let toc = format!(
            r#"{{"version":1,"entries":[],"tarSplitDigest":"{}"}}"#,
            Digest::of(velarx_types::digest::Algorithm::Sha256, &tarsplit)
        );
        let toc_z = zstd::encode_all(toc.as_bytes(), 3).unwrap();
        let right = index::encode_compressed(&toc_z, &tarsplit).unwrap();
        let wrong = index::encode_compressed(&toc_z, b"another tar-split").unwrap();
        let chunked = Blob {
            digest: format!("sha256:{}", "d".repeat(64)),
            size: 1 << 20,
            media_type: "application/vnd.oci.image.layer.v1.tar+zstd".into(),
            annotations: Some(
                [
                    (
                        "io.github.containers.zstd-chunked.manifest-checksum".to_string(),
                        format!("sha256:{}", "e".repeat(64)),
                    ),
                    (
                        "io.github.containers.zstd-chunked.manifest-position".to_string(),
                        "1:2:3:1".to_string(),
                    ),
                ]
                .into(),
            ),
        };
        let fetch = ItemFetch::of(
            "dir",
            Indexes(HashMap::from([
                ("sha256:aa".to_string(), right.clone()),
                ("sha256:bb".to_string(), wrong),
                (chunked.digest.clone(), right),
            ])),
        );
        let blob = |digest: &str| Blob {
            digest: digest.into(),
            size: 1 << 20,
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(),
            annotations: None,
        };
        let scope = Scope {
            verity: false,
            source: None,
            tls_verify: None,
            target: None,
            access: None,
            idle: std::time::Duration::from_secs(30),
            kept: Arc::default(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let layers = vec![
            blob("sha256:aa"),
            blob("sha256:bb"),
            blob("sha256:cc"),
            chunked,
        ];
        fetch
            .probe(&scope, layers, (false, Parts::All), &Out::new(tx))
            .await
            .unwrap();
        let mut got = Vec::new();
        while let Ok((reply, fds)) = rx.try_recv() {
            got.push((reply.toc, reply.on_demand, reply.reason, fds.len()));
        }
        assert_eq!(
            got,
            [
                (TocSource::Carried, false, Some(NotLazy::NoToc), 2),
                (TocSource::None, false, Some(NotLazy::Unreachable), 0),
                (TocSource::None, false, Some(NotLazy::Unreachable), 0),
                (TocSource::None, false, Some(NotLazy::Unreachable), 0),
            ]
        );
    }
}
