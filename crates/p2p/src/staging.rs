// SPDX-License-Identifier: Apache-2.0
//! The peers as a fetcher (`org.velarx.Fetcher`): what `velarx-p2p` serves to
//! the engine on its fetcher socket.  It answers only for itself: a file
//! whose chunks the peers have is `staged`, one they have not is
//! `unavailable`, one that could not be written is `failed`; it knows
//! nothing of the other fetchers of the engine's list.
//!
//! * `Fetch` of named files: the chunks the layer's table of contents (as
//!   the engine verified and told it) gives each file, asked of the peers
//!   by their sha256, each checked against it once, by the peers' client,
//!   as it arrives; the file is checked against its name (its fs-verity
//!   digest) by the object contract ([`velarx_content::stager`]) when it is
//!   complete.
//! * `Fetch` of a whole layer (one without a table of contents): the index
//!   of a peer that has it (its table and tar-split), and its files by
//!   their digests; the table and tar-split are a claim the engine replays
//!   against the diff id.
//! * `Get` of a `blob` by its digest (the pieces of a shared checkpoint)
//!   and of a `profile` (the startup profile of an image).
//!
//! It reads no store; what it writes is a claim the engine checks.

use crate::limits::{MAX_ITEM_BYTES, MAX_REQUEST_DIGESTS, MAX_RESPONSE_PAYLOAD};
use crate::provider::{Item, PeerSource, Sink};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::AsFd;
use velarx_content::fetcher::fetch::{
    Blob, EventKind, Failure, FailureClass, FetchEvent as Event, FetcherError, Urgency, TARSPLIT,
    TOC_CLAIM,
};
use velarx_content::serve_fetch::{
    Described, FetchCall, LayerScope, Out, Scope, StagingFetcher, UnpackCall,
};
use velarx_content::stager::{self, name_of, LayerToc, Name, Unnamed};
use velarx_storage::{Toc, TocEntryType};
use velarx_types::digest::Digest;

/// The most objects of one `Fetch`.
pub const MAX_OBJECTS: u32 = 4096;

fn failed(e: impl std::fmt::Display) -> FetcherError {
    FetcherError::failed(e.to_string())
}

/// `items` in groups of what one request answers: at most
/// [`MAX_REQUEST_DIGESTS`] of them and [`MAX_RESPONSE_PAYLOAD`] bytes (a
/// group is all in memory until it is checked and written).
fn groups(items: &[Item]) -> Vec<&[Item]> {
    let mut groups = Vec::new();
    let (mut from, mut bytes) = (0, 0u64);
    for (at, item) in items.iter().enumerate() {
        let size = item.size.unwrap_or(0);
        if at > from
            && (at - from == MAX_REQUEST_DIGESTS || bytes + size > MAX_RESPONSE_PAYLOAD as u64)
        {
            groups.push(&items[from..at]);
            (from, bytes) = (at, 0);
        }
        bytes += size;
    }
    groups.extend(items.get(from..).filter(|g| !g.is_empty()));
    groups
}

fn gone<T>(_: T) -> FetcherError {
    failed("the asker is gone")
}

/// A file of a `Fetch` assembled from the chunks the peers send.
struct Assembling {
    /// Its positions in the call
    positions: Vec<u32>,
    name: Name,
    size: u64,
    file: Option<Unnamed>,
    /// Chunks still to come
    left: usize,
    done: bool,
    /// Bytes of it that came, so far
    moved: u64,
    /// The chunks it holds that came: digest, offset, length
    held: Vec<(String, u64, u64)>,
}

/// A place of an item in the files of a call: the file and the offset.
type Place = (usize, u64);

/// Where the chunks the peers send go: written at their places in the
/// files of the call, each file named once it is complete.
struct Files<'a> {
    staging: &'a File,
    verity: bool,
    files: Vec<Assembling>,
    /// The places (file, offset) of each digest and size asked
    places: HashMap<(String, u64), Vec<Place>>,
    staged: Vec<u32>,
    failures: Vec<(Vec<u32>, String)>,
    /// A file could not be written
    failed: bool,
    /// The files whose `moved` changed since the last flush
    changed: std::collections::BTreeSet<usize>,
    out: &'a Out<Event>,
    /// Where the files that were named are kept for the peers, and how many
    /// came since it was looked at
    kept_in: Option<(std::sync::Arc<crate::staged::Staged>, Option<String>)>,
    kept: usize,
    /// A layer unpacked whole: the files that are complete are handed over
    /// to the engine, not named in the staging
    handing: bool,
    handed: Vec<File>,
}

impl<'a> Files<'a> {
    fn new(staging: &'a File, verity: bool, out: &'a Out<Event>) -> Self {
        Files {
            staging,
            verity,
            files: Vec::new(),
            places: HashMap::new(),
            staged: Vec::new(),
            failures: Vec::new(),
            failed: false,
            changed: Default::default(),
            out,
            kept_in: None,
            kept: 0,
            handing: false,
            handed: Vec::new(),
        }
    }

    /// The files it makes are handed over to the engine (a layer unpacked
    /// whole), each as a file with no name.
    fn handing(mut self) -> Self {
        self.handing = true;
        self
    }

    /// The same, giving the files it names to the peers through `staged`.
    fn keeping(mut self, staged: &std::sync::Arc<crate::staged::Staged>, layer: &str) -> Self {
        self.kept_in = Some((staged.clone(), Some(layer.to_string())));
        self
    }
}

impl Files<'_> {
    /// Write `data` at `offset` of the file `job` (checked already against
    /// the digest it was asked by), and name it when it is complete.
    fn write(&mut self, job: usize, offset: u64, data: &[u8]) {
        let f = &mut self.files[job];
        if f.done {
            return;
        }
        let result = (|| {
            if f.file.is_none() {
                f.file = Some(Unnamed::begin(self.staging.as_fd(), f.size)?);
            }
            if !data.is_empty() {
                f.file
                    .as_ref()
                    .expect("begun")
                    .write_chunk(offset, data, None)?;
            }
            f.left = f.left.saturating_sub(usize::from(!data.is_empty()));
            if f.left == 0 {
                f.done = true;
                let file = f.file.take().expect("begun");
                let (made, kept) = match self.handing {
                    true => {
                        let kept = file.sealed(&f.name, self.verity)?;
                        self.handed.push(velarx_sys::fd::reopen_read_only(&kept)?);
                        (true, kept)
                    }
                    false => file.finish_kept(self.staging.as_fd(), &f.name, self.verity)?,
                };
                // (a file that was there already is not this copy: it is not
                // kept)
                if let (Some((staged, layer)), true, false) =
                    (&self.kept_in, made, f.held.is_empty())
                {
                    staged.add(layer.as_deref(), kept, std::mem::take(&mut f.held));
                    self.kept += 1;
                }
                self.staged.extend(&f.positions);
            }
            Ok::<_, stager::StageError>(())
        })();
        if let Err(e) = result {
            f.done = true;
            f.file = None;
            self.failed = true;
            self.failures.push((f.positions.clone(), e.to_string()));
        }
    }
}

#[async_trait]
impl Sink for Files<'_> {
    async fn put(&mut self, digest: &str, data: &[u8]) -> Result<(), String> {
        let Some(places) = self.places.remove(&(digest.to_string(), data.len() as u64)) else {
            return Ok(());
        };
        for (job, offset) in places {
            self.files[job].moved += data.len() as u64;
            self.files[job]
                .held
                .push((digest.to_string(), offset, data.len() as u64));
            self.changed.insert(job);
            self.write(job, offset, data);
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), String> {
        // (the bytes of each object so far; of the blob, once, when there are
        // no objects)
        let mut blob = false;
        for job in std::mem::take(&mut self.changed) {
            let f = &self.files[job];
            let Some(&at) = f.positions.first() else {
                blob = true;
                continue;
            };
            self.out
                .send(Event::progress(Some(at), f.moved))
                .await
                .map_err(|_| "the asker is gone".to_string())?;
        }
        if blob {
            self.out
                .send(Event::progress(
                    None,
                    self.files.iter().map(|f| f.moved).sum(),
                ))
                .await
                .map_err(|_| "the asker is gone".to_string())?;
        }
        if !self.staged.is_empty() {
            let objects = std::mem::take(&mut self.staged);
            self.out
                .send(Event {
                    objects,
                    ..Event::of(EventKind::Staged)
                })
                .await
                .map_err(|_| "the asker is gone".to_string())?;
        }
        while !self.handed.is_empty() {
            let files: Vec<std::os::fd::OwnedFd> = self
                .handed
                .drain(
                    ..self
                        .handed
                        .len()
                        .min(velarx_content::fetcher::fetch::MAX_FDS),
                )
                .map(Into::into)
                .collect();
            self.out
                .send_with(
                    Event {
                        objects: (0..files.len() as u32).collect(),
                        ..Event::of(EventKind::Staged)
                    },
                    files,
                )
                .await
                .map_err(|_| "the asker is gone".to_string())?;
        }
        for (objects, reason) in std::mem::take(&mut self.failures) {
            self.out
                .send(Event::failed(
                    objects,
                    Failure {
                        class: FailureClass::Failed,
                        reason,
                    },
                ))
                .await
                .map_err(|_| "the asker is gone".to_string())?;
        }
        Ok(())
    }
}

/// The groups of a call asked at the same time.
const GROUPS_AT_ONCE: usize = 2;

/// The [`Files`] of a call, written by the groups that are under way.
struct Shared<'a, 'b, 'c>(&'a tokio::sync::Mutex<&'b mut Files<'c>>);

#[async_trait]
impl Sink for Shared<'_, '_, '_> {
    async fn put(&mut self, digest: &str, data: &[u8]) -> Result<(), String> {
        self.0.lock().await.put(digest, data).await
    }

    async fn flush(&mut self) -> Result<(), String> {
        self.0.lock().await.flush().await
    }
}

/// A chunk to ask the peers for: its digest, its place in its file, its
/// size.
type PeerChunk = (String, u64, u64);

/// The chunks of a file to ask the peers for, by its entry `at` of the
/// table: (digest, place in the file, size); none when one has no digest of
/// its own (only the origin can serve it).
fn chunks_of(toc: &Toc, at: usize) -> Option<(u64, Vec<PeerChunk>)> {
    let fc = velarx_content::pull::chunked::file_chunks(
        toc,
        velarx_types::digest::Algorithm::Sha256,
        at,
        i64::MAX,
        MAX_ITEM_BYTES as u64,
    )
    .ok()?;
    let mut chunks = Vec::with_capacity(fc.chunks.len());
    for c in fc.chunks {
        if !crate::limits::is_digest(&c.digest) {
            return None;
        }
        chunks.push((c.digest, c.offset, c.size));
    }
    Some((fc.size, chunks))
}

impl PeerSource {
    /// Ask the peers for every place of `files` and write what they send.
    /// What is left (the positions of the files no peer gave) is for the
    /// caller to tell the engine, and whether no file failed to be written.
    async fn assemble(
        &self,
        layer: Option<&str>,
        urgency: Urgency,
        files: &mut Files<'_>,
    ) -> Result<(bool, Vec<u32>), FetcherError> {
        // the files with no chunk (zeros only) are complete already
        for job in 0..files.files.len() {
            if files.files[job].left == 0 {
                files.write(job, 0, &[]);
            }
        }
        // The chunks go file by file, from a file that differs from node to
        // node: the files are complete (and given to the peers) one after
        // the other, and the nodes of a rollout hold different ones at a
        // time, which they exchange.
        let count = files.files.len().max(1);
        let start = self.knowledge().below(count);
        let mut order: Vec<(usize, u64, Item)> = files
            .places
            .iter()
            .map(|((digest, size), places)| {
                let (job, offset) = places.iter().min_by_key(|p| (p.0, p.1)).expect("a place");
                (
                    (job + count - start) % count,
                    *offset,
                    Item {
                        digest: digest.clone(),
                        size: Some(*size),
                    },
                )
            })
            .collect();
        order.sort_by(|a, b| (a.0, a.1, &a.2.digest).cmp(&(b.0, b.1, &b.2.digest)));
        let items: Vec<Item> = order.into_iter().map(|(_, _, item)| item).collect();
        // two groups at a time: the next one is on its way while the files
        // of the last are written
        let shared = tokio::sync::Mutex::new(&mut *files);
        let mut under_way = futures::stream::FuturesUnordered::new();
        for group in groups(&items) {
            if under_way.len() == GROUPS_AT_ONCE {
                futures::StreamExt::next(&mut under_way).await.transpose()?;
            }
            under_way.push(self.fetch_shared(group, layer, urgency, &shared));
        }
        while futures::StreamExt::next(&mut under_way)
            .await
            .transpose()?
            .is_some()
        {}
        drop(under_way);
        let files = shared.into_inner();
        files.flush().await.map_err(gone)?;
        let left: Vec<u32> = files
            .files
            .iter()
            .filter(|f| !f.done)
            .flat_map(|f| f.positions.clone())
            .collect();
        Ok((!files.failed, left))
    }

    /// The chunks of `group` into `files`, which the groups under way share.
    async fn fetch_shared(
        &self,
        group: &[Item],
        layer: Option<&str>,
        urgency: Urgency,
        files: &tokio::sync::Mutex<&mut Files<'_>>,
    ) -> Result<(), FetcherError> {
        self.fetch_group_as(group, layer, urgency, &mut Shared(files))
            .await
            .map_err(failed)?;
        let kept = {
            let mut files = files.lock().await;
            files.flush().await.map_err(gone)?;
            std::mem::take(&mut files.kept)
        };
        self.holding(layer, kept).await;
        Ok(())
    }

    /// Tell the peers that this node holds files of `layer`, the first time
    /// a file of it was staged (`kept` files came since it was looked at):
    /// they ask it for them while the pull goes on.
    async fn holding(&self, layer: Option<&str>, kept: usize) {
        if let Some(layer) = layer.filter(|_| kept > 0) {
            if self.staged.first_of(layer) {
                self.peers.holding(layer).await;
            }
        }
    }

    /// The files of a call that no peer gave are `unavailable`.
    async fn unavailable(out: &Out<Event>, objects: Vec<u32>) -> Result<(), FetcherError> {
        if objects.is_empty() {
            return Ok(());
        }
        out.send(Event {
            objects,
            ..Event::of(EventKind::Unavailable)
        })
        .await
        .map_err(gone)
    }

    /// The files of a layer without a table of contents: the index of a
    /// peer (its table and tar-split, a claim), then its files by digest.
    async fn unpack_whole(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        urgency: Urgency,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let mut index = One(None);
        let item = [Item {
            digest: layer.layer.clone(),
            size: Some(velarx_content::pull::index::MAX_INDEX),
        }];
        let max_json = layer
            .blob
            .as_ref()
            .map_or(i64::MAX, |b| i64::try_from(b.size).unwrap_or(i64::MAX));
        let cap = velarx_content::pull::index::json_cap(max_json);
        self.fetch_indexes(
            &item,
            false,
            &|bytes| velarx_content::pull::index::decode(bytes, cap).is_ok(),
            &mut index,
        )
        .await
        .map_err(failed)?;
        let Some(index) = index.0 else {
            return Err(FetcherError::unavailable(
                self.nobody("no peer has the index of the layer").await,
            ));
        };
        let (toc, tarsplit) = velarx_content::pull::index::decode(&index, cap).map_err(failed)?;
        // each file once, by the digest of its content (what the engine
        // knows it by), asked of the peers by the digest they serve it by
        let mut files = Files::new(&layer.staging, scope.verity, out)
            .keeping(&self.staged, &layer.layer)
            .handing();
        let mut seen = std::collections::HashSet::new();
        let mut total = 0u64;
        for e in &toc.entries {
            if e.entry_type != TocEntryType::Reg || e.size == 0 {
                continue;
            }
            let Some(content) = e.digest.as_deref().and_then(|d| d.parse::<Digest>().ok()) else {
                return Err(FetcherError::unavailable(
                    "the index of the layer names a file without a digest",
                ));
            };
            if !seen.insert(content) {
                continue;
            }
            let asked = e.verity().unwrap_or_else(|| content.to_string());
            if e.size > MAX_ITEM_BYTES as u64 || !crate::limits::is_digest(&asked) {
                return Err(FetcherError::unavailable(
                    "the index of the layer names a file that cannot be had",
                ));
            }
            total = total.saturating_add(e.size);
            files
                .places
                .entry((asked, e.size))
                .or_default()
                .push((files.files.len(), 0));
            files.files.push(Assembling {
                positions: Vec::new(),
                name: Name::Content(content),
                size: e.size,
                file: None,
                left: 1,
                done: false,
                moved: 0,
                held: Vec::new(),
            });
        }
        // (what an index makes this node fetch is bounded by the layer)
        let cap = layer
            .blob
            .as_ref()
            .map_or(u64::MAX, |b| b.size.saturating_mul(4).max(64 << 20));
        if total > cap {
            tracing::debug!("P2P: the index of {} asks for too much", layer.layer);
            return Err(FetcherError::unavailable(
                "the index of the layer asks for too much",
            ));
        }
        // (the claim is named last; the files no peer had are left out: the
        // claim names them, the engine may have them)
        let (sound, left) = self
            .assemble(Some(&layer.layer), urgency, &mut files)
            .await?;
        Self::unavailable(out, left).await?;
        let json = serde_json::to_vec(&toc).map_err(failed)?;
        if !sound {
            return Err(failed("a file of the layer could not be written"));
        }
        let staging = layer.staging.as_fd();
        for (name, bytes) in [
            (TOC_CLAIM, json.as_slice()),
            (TARSPLIT, tarsplit.as_slice()),
        ] {
            stager::put_named(staging, name, bytes).map_err(|e| FetcherError::Failed {
                failure: Failure {
                    class: FailureClass::Failed,
                    reason: e.to_string(),
                },
            })?;
        }
        Ok(())
    }
}

/// The first item the peers send.
struct One(Option<Vec<u8>>);

#[async_trait]
impl Sink for One {
    async fn put(&mut self, _: &str, data: &[u8]) -> Result<(), String> {
        self.0.get_or_insert_with(|| data.to_vec());
        Ok(())
    }
}

/// The checksum of the table of contents the descriptor of `blob` names.
fn checksum_of(blob: &Blob) -> Option<Digest> {
    let desc = velarx_types::OciDescriptor {
        media_type: blob.media_type.clone(),
        digest: blob.digest.parse().ok()?,
        size: i64::try_from(blob.size).ok()?,
        annotations: blob
            .annotations
            .iter()
            .flatten()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    velarx_types::layer::chunked_checksum(&desc)
}

impl PeerSource {
    /// The compressed table of contents `checksum` names and its tar-split,
    /// from the index of a peer: one whose table is not that one, or whose
    /// tar-split is not the one the table names, is not taken (`cap`: the
    /// largest JSON of the table).
    pub(crate) async fn toc_of(&self, checksum: &Digest, cap: u64) -> Option<(Vec<u8>, Vec<u8>)> {
        use velarx_content::pull::index;
        let mut one = One(None);
        let item = [Item {
            digest: checksum.to_string(),
            size: Some(index::MAX_INDEX),
        }];
        let well_formed = |bytes: &[u8]| {
            let Ok((toc_z, tarsplit)) = index::split(bytes) else {
                return false;
            };
            Digest::of(checksum.alg(), toc_z) == *checksum
                && index::decode(bytes, cap).is_ok_and(|(toc, _)| match toc.tar_split_digest {
                    Some(d) => d
                        .parse::<Digest>()
                        .is_ok_and(|d| Digest::of(d.alg(), tarsplit) == d),
                    None => tarsplit.is_empty(),
                })
        };
        self.fetch_indexes(&item, true, &well_formed, &mut one)
            .await
            .ok()?;
        let index = one.0?;
        let (toc, tarsplit) = index::split(&index).ok()?;
        Some((toc.to_vec(), tarsplit.to_vec()))
    }

    /// What the peers gave for `name` as a sealed memory file, or
    /// `unavailable`.
    async fn given(&self, one: One, name: &str) -> Result<std::fs::File, FetcherError> {
        let Some(bytes) = one.0 else {
            return Err(FetcherError::unavailable(
                self.nobody(&format!("{name}: no peer has it")).await,
            ));
        };
        Ok(velarx_base::sealed::sealed_memory(&bytes)
            .map_err(failed)?
            .into())
    }
}

#[async_trait]
impl StagingFetcher for PeerSource {
    fn described(&self) -> Described {
        Described {
            name: "p2p".into(),
            capabilities: vec!["objects".into(), "unpack".into()],
            max_objects: MAX_OBJECTS,
        }
    }

    /// A blob by its digest, of exactly the bytes its descriptor says (a
    /// piece of a shared checkpoint).
    async fn get_blob(&self, _scope: &Scope, blob: &Blob) -> Result<std::fs::File, FetcherError> {
        let mut one = One(None);
        let item = [Item {
            digest: blob.digest.clone(),
            size: Some(blob.size),
        }];
        if crate::limits::is_digest(&blob.digest) && blob.size <= MAX_ITEM_BYTES as u64 {
            self.fetch_group(&item, None, &mut one)
                .await
                .map_err(failed)?;
        }
        self.given(one, &blob.digest).await
    }

    /// The table of contents and tar-split of the zstd:chunked layers whose
    /// descriptor's checksum a peer's index has the compressed bytes of;
    /// what no peer has is `unreachable`, for the next fetcher.  A peer's
    /// bytes are used only when they have the checksum (the engine checks
    /// them against the descriptor again).
    async fn probe(
        &self,
        _scope: &Scope,
        layers: Vec<Blob>,
        out: &Out<velarx_content::fetcher::fetch::Probed>,
    ) -> Result<(), FetcherError> {
        use futures::StreamExt;
        use velarx_content::fetcher::fetch::{NotLazy, Probed, TocSource};
        // (all the layers at once, answered as each one is found)
        let mut asking: futures::stream::FuturesUnordered<_> = layers
            .iter()
            .enumerate()
            .map(|(at, blob)| async move {
                let cap = velarx_content::pull::index::json_cap(
                    i64::try_from(blob.size).unwrap_or(i64::MAX),
                );
                let found = match checksum_of(blob) {
                    Some(checksum) => self.toc_of(&checksum, cap).await,
                    None => None,
                };
                (at, found)
            })
            .collect();
        while let Some((at, found)) = asking.next().await {
            let none = Probed {
                layer: at as u32,
                toc: TocSource::None,
                on_demand: false,
                reason: Some(NotLazy::Unreachable),
                toc_file: None,
                tarsplit_file: None,
            };
            let Some((toc, tarsplit)) = found else {
                out.send(none).await.map_err(gone)?;
                continue;
            };
            let mut fds = vec![velarx_base::sealed::sealed_memory(&toc).map_err(failed)?];
            if !tarsplit.is_empty() {
                fds.push(velarx_base::sealed::sealed_memory(&tarsplit).map_err(failed)?);
            }
            let reply = Probed {
                toc: TocSource::Carried,
                on_demand: true,
                reason: None,
                toc_file: Some(0),
                tarsplit_file: (!tarsplit.is_empty()).then_some(1),
                ..none
            };
            out.send_with(reply, fds).await.map_err(gone)?;
        }
        Ok(())
    }

    /// The manifest a digest names: what the peers send is checked against
    /// it (a tag is not one: nobody here says what it names).
    async fn get_manifest(
        &self,
        _scope: &Scope,
        reference: &str,
        max: u64,
    ) -> Result<(std::fs::File, Option<String>), FetcherError> {
        let mut one = One(None);
        let item = [Item {
            digest: reference.to_string(),
            size: None,
        }];
        if crate::limits::is_digest(reference) {
            self.fetch_group(&item, None, &mut one)
                .await
                .map_err(failed)?;
        }
        if one.0.as_ref().is_some_and(|b| b.len() as u64 > max) {
            return Err(FetcherError::unavailable(format!("{reference}: too large")));
        }
        Ok((self.given(one, reference).await?, None))
    }

    /// The startup profile of the image `image`.
    async fn get_profile(
        &self,
        _scope: &Scope,
        image: &str,
        max: u64,
    ) -> Result<std::fs::File, FetcherError> {
        let mut one = One(None);
        let item = [Item {
            digest: image.to_string(),
            size: Some(max),
        }];
        self.fetch_profiles(&item, None, &mut one)
            .await
            .map_err(failed)?;
        self.given(one, image).await
    }

    async fn unpack(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: UnpackCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        self.unpack_whole(scope, layer, call.urgency, out).await
    }

    async fn fetch(
        &self,
        scope: &Scope,
        layer: &LayerScope,
        call: FetchCall,
        out: &Out<Event>,
    ) -> Result<(), FetcherError> {
        let urgency = call.urgency;
        let run = async {
            let indexed = LayerToc::kept(layer)?;
            let mut files =
                Files::new(&layer.staging, scope.verity, out).keeping(&self.staged, &layer.layer);
            // (for each file of `files`: the key and size it is asked whole
            // by when the peers do not have its chunks, with its name)
            let mut whole_by: Vec<Option<(String, u64, Name)>> = Vec::new();
            let mut by_key: HashMap<&str, usize> = HashMap::new();
            let (mut present, mut nobody) = (Vec::new(), Vec::new());
            for (i, key) in call.objects.iter().enumerate() {
                if let Some(&w) = by_key.get(key.as_str()) {
                    files.files[w].positions.push(i as u32);
                    continue;
                }
                let &at = indexed.at.get(key).ok_or_else(|| FetcherError::Refused {
                    reason: format!("{key} is not a file of the layer's table of contents"),
                })?;
                if stager::staged(&layer.staging, key) {
                    present.push(i as u32);
                    continue;
                }
                let entry = &indexed.toc.entries[at];
                let Some((_, name)) = name_of(entry) else {
                    nobody.push(i as u32);
                    continue;
                };
                // (a file of one chunk, or one with a chunk that has no digest
                // of its own, is asked whole by its fs-verity digest: the
                // name of the object of a peer's store)
                let whole = match &name {
                    Name::Verity(_) if entry.size <= MAX_ITEM_BYTES as u64 => {
                        Some((entry.size, vec![(key.clone(), 0, entry.size)]))
                    }
                    _ => None,
                };
                let chunked = chunks_of(&indexed.toc, at).filter(|(_, c)| c.len() > 1);
                // (a file of many chunks is asked by them first, the way the
                // peers that pulled the same layer have them; a peer that
                // has the file by another cutting, or from a layer it made
                // some other way, has it by its fs-verity digest)
                let again = (chunked.is_some() && whole.is_some())
                    .then(|| (key.clone(), entry.size, name.clone()));
                let Some((size, chunks)) =
                    chunked.or(whole).or_else(|| chunks_of(&indexed.toc, at))
                else {
                    nobody.push(i as u32);
                    continue;
                };
                let job = files.files.len();
                by_key.insert(key, job);
                for (digest, offset, size) in &chunks {
                    files
                        .places
                        .entry((digest.clone(), *size))
                        .or_default()
                        .push((job, *offset));
                }
                whole_by.push(again);
                files.files.push(Assembling {
                    positions: vec![i as u32],
                    name,
                    size,
                    file: None,
                    left: chunks.len(),
                    done: false,
                    moved: 0,
                    held: Vec::new(),
                });
            }
            for (kind, objects) in [
                (EventKind::Staged, present),
                (EventKind::Unavailable, nobody),
            ] {
                if !objects.is_empty() {
                    out.send(Event {
                        objects,
                        ..Event::of(kind)
                    })
                    .await
                    .map_err(gone)?;
                }
            }
            let (_, mut left) = self
                .assemble(Some(&layer.layer), urgency, &mut files)
                .await?;
            // the files whose chunks the peers lack, by their fs-verity
            // digests
            let mut whole_files =
                Files::new(&layer.staging, scope.verity, out).keeping(&self.staged, &layer.layer);
            let mut again = Vec::new();
            for (job, f) in files.files.iter().enumerate() {
                let Some((key, size, name)) = whole_by[job].take() else {
                    continue;
                };
                if f.done {
                    continue;
                }
                let at = whole_files.files.len();
                whole_files
                    .places
                    .entry((key, size))
                    .or_default()
                    .push((at, 0));
                whole_files.files.push(Assembling {
                    positions: f.positions.clone(),
                    name,
                    size,
                    file: None,
                    left: 1,
                    done: false,
                    // (the progress of an object only grows: the chunks
                    // that came before count, the engine adds what is new)
                    moved: f.moved,
                    held: Vec::new(),
                });
                again.extend(&f.positions);
            }
            if !again.is_empty() {
                left.retain(|p| !again.contains(p));
                // (no layer: the peers that lacked its chunks may have the
                // file)
                let (_, more) = self.assemble(None, urgency, &mut whole_files).await?;
                left.extend(more);
            }
            Self::unavailable(out, left).await
        };
        tokio::select! {
            result = run => result,
            _ = call.cancel.cancelled() => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{PeerError, Peers, Strikes};
    use crate::Presence;
    use libp2p::PeerId;
    use std::sync::Arc;

    fn items(sizes: &[u64]) -> Vec<Item> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, s)| Item {
                digest: format!("sha256:{i:064x}"),
                size: Some(*s),
            })
            .collect()
    }

    /// What a group holds is bounded by the bytes one request answers as
    /// well as by their number: 200 files of 10 MiB are not one group.
    #[test]
    fn a_group_is_cut_by_bytes_and_by_count() {
        let big = items(&[10 << 20; 200]);
        let cut = groups(&big);
        assert_eq!(cut.len(), 200);
        assert!(cut.iter().all(|g| g.len() == 1));
        let small = items(&[4096; 600]);
        let lens: Vec<usize> = groups(&small).iter().map(|g| g.len()).collect();
        assert_eq!(lens, [256, 256, 88]);
        // a file of a request's payload is alone, and a small one joins the next
        let mixed = items(&[1, 16 << 20, 1, 1]);
        let lens: Vec<usize> = groups(&mixed).iter().map(|g| g.len()).collect();
        assert_eq!(lens, [1, 1, 2]);
        assert!(groups(&[]).is_empty());
    }

    /// A peer whose index of a layer is answered only when the indexes of
    /// all the layers of the call are asked at once.
    struct Together(tokio::sync::Barrier, PeerId);

    #[async_trait]
    impl Peers for Together {
        async fn connected(&self) -> Vec<PeerId> {
            vec![self.1]
        }
        async fn layer_providers(&self, _: &str) -> Vec<PeerId> {
            Vec::new()
        }
        async fn request(
            &self,
            _: PeerId,
            _: &[(String, Option<u64>)],
            _: Urgency,
            _: crate::ChunkTx,
        ) -> Result<(), PeerError> {
            Ok(())
        }
        async fn index(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            self.0.wait().await;
            Ok(None)
        }
        async fn has(&self, _: PeerId, _: &str) -> Result<Presence, String> {
            Ok(Presence::Lacks)
        }
        async fn profile(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
    }

    /// The layers of a `Probe` are asked of the peers all at once, not one
    /// after another.
    #[tokio::test]
    async fn a_probe_asks_its_layers_at_once() {
        let layers: Vec<Blob> = (0..6)
            .map(|i| Blob {
                digest: format!("sha256:{i:064x}"),
                size: 1,
                media_type: "application/vnd.oci.image.layer.v1.tar+zstd".into(),
                annotations: Some(
                    [
                        (
                            "io.github.containers.zstd-chunked.manifest-checksum".to_string(),
                            format!("sha256:{:064x}", i + 100),
                        ),
                        (
                            "io.github.containers.zstd-chunked.manifest-position".to_string(),
                            "1:2:3:1".to_string(),
                        ),
                    ]
                    .into(),
                ),
            })
            .collect();
        let source = PeerSource::with_peers(
            Arc::new(Together(
                tokio::sync::Barrier::new(layers.len()),
                PeerId::random(),
            )),
            Arc::new(Strikes::default()),
        );
        let scope = Scope {
            verity: false,
            source: None,
            tls_verify: None,
            target: None,
            access: None,
            idle: std::time::Duration::from_secs(30),
            kept: Arc::default(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            source.probe(&scope, layers, &Out::new(tx)),
        )
        .await
        .expect("the layers are asked at once")
        .unwrap();
        let mut answered = 0;
        while rx.try_recv().is_ok() {
            answered += 1;
        }
        assert_eq!(answered, 6);
    }

    /// A peer that answers a request only when another is under way, and
    /// has `chunks`.
    struct Meeting(tokio::sync::Barrier, PeerId, HashMap<String, Vec<u8>>);

    #[async_trait]
    impl Peers for Meeting {
        async fn connected(&self) -> Vec<PeerId> {
            vec![self.1]
        }
        async fn layer_providers(&self, _: &str) -> Vec<PeerId> {
            Vec::new()
        }
        async fn request(
            &self,
            _: PeerId,
            items: &[(String, Option<u64>)],
            _: Urgency,
            out: crate::ChunkTx,
        ) -> Result<(), PeerError> {
            self.0.wait().await;
            for (digest, _) in items {
                let _ = out.send((digest.clone(), self.2[digest].clone())).await;
            }
            Ok(())
        }
        async fn index(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
        async fn has(&self, _: PeerId, _: &str) -> Result<Presence, String> {
            Ok(Presence::Has)
        }
        async fn profile(&self, _: PeerId, _: &str, _: u64) -> Result<Option<Vec<u8>>, PeerError> {
            Ok(None)
        }
    }

    /// Two groups of a call are asked at the same time, and the files they
    /// bring are all staged.
    #[tokio::test]
    async fn two_groups_are_in_flight_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let staging = File::open(dir.path()).unwrap();
        let contents: Vec<Vec<u8>> = (0..300u16).map(|i| i.to_be_bytes().to_vec()).collect();
        let bytes: HashMap<String, Vec<u8>> = contents
            .iter()
            .map(|c| {
                (
                    Digest::of(velarx_types::digest::Algorithm::Sha256, c).to_string(),
                    c.clone(),
                )
            })
            .collect();
        let source = PeerSource::with_peers(
            Arc::new(Meeting(
                tokio::sync::Barrier::new(2),
                PeerId::random(),
                bytes.clone(),
            )),
            Arc::new(Strikes::default()),
        );
        let (tx, mut events) = tokio::sync::mpsc::channel(1024);
        let out = Out::new(tx);
        let mut files = Files::new(&staging, false, &out);
        for (job, (digest, data)) in bytes.iter().enumerate() {
            files.places.insert((digest.clone(), 2), vec![(job, 0)]);
            files.files.push(Assembling {
                positions: vec![job as u32],
                name: Name::Content(digest.parse().unwrap()),
                size: data.len() as u64,
                file: None,
                left: 1,
                done: false,
                moved: 0,
                held: Vec::new(),
            });
        }
        let (sound, left) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            source.assemble(None, Urgency::Wait, &mut files),
        )
        .await
        .expect("the groups were asked one after the other")
        .unwrap();
        assert!(sound && left.is_empty());
        let mut staged = 0;
        while let Ok((event, _)) = events.try_recv() {
            if event.kind == EventKind::Staged {
                staged += event.objects.len();
            }
        }
        assert_eq!(staged, 300);
    }
}
