// SPDX-License-Identifier: Apache-2.0
//! Lazy layers: the metadata of a zstd:chunked layer without its files.
//!
//! The TOC and the tar-split are fetched and checked against the digests the
//! manifest and the TOC give.  The stored TOC is made from the tar headers of
//! the tar-split (the same data a full pull stores) with, for each file, the
//! position of its chunks in the blob.  The files are fetched later, one at a
//! time as they are read or all of them when the image is completed, with the
//! same planner and the same checks as a partial pull.  Each file is proved by
//! the commit of the completion (its bytes against the TOC, its fs-verity
//! digest by the kernel); a TOC layer has no diff id and no replay of the
//! stream.

use super::chunked::{self, Info};
use super::entry::{self, MAX_ENTRIES};
use super::tar::{normalize_path, Kind, TarReader};
use super::tarsplit::{self, Contents, Entries, Replay};
use super::{LayerReport, PullCtx};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::sync::{Arc, Mutex};
use tracing::debug;
use velarx_storage::{Toc, TocEntry, TocEntryType, TOC_VERSION};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{ImageError, ImageResult, OciDescriptor};

fn fail(msg: impl Into<String>) -> ImageError {
    ImageError::Layer(msg.into())
}

fn io_fail(e: io::Error) -> ImageError {
    ImageError::Layer(e.to_string())
}

/// The metadata of a lazy layer.
pub struct LazyLayer {
    /// The TOC to store: tar headers and chunk positions.
    pub toc: Arc<Toc>,
    /// The verified, zstd compressed tar-split.
    pub tarsplit: bytes::Bytes,
    pub report: LayerReport,
}

/// File contents made of zeros: the headers of a tar-split are read without
/// the files.
struct Zeros;

impl Contents for Zeros {
    fn open(&mut self, _: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(io::repeat(0).take(size)))
    }
}

/// The first regular file with content to which `toc` gives no fs-verity
/// digest: a layer that has one is not pulled lazily (a lazy file is known,
/// fetched and checked by its fs-verity digest), but whole, its files
/// checked by their sha256 (containers/storage writes such TOCs).
pub fn without_verity(toc: &Toc) -> Option<&TocEntry> {
    toc.entries
        .iter()
        .find(|e| e.entry_type == TocEntryType::Reg && e.size > 0 && e.verity().is_none())
}

/// The TOC of a layer pulled by its table of contents: the entries of the
/// tar headers of `tarsplit_z`, with the digests and the chunks of each file
/// from the TOC of the registry, which must give each file an fs-verity
/// digest or the digest of its content (a lazy layer needs the first: see
/// [`without_verity`]).
pub fn merge_toc(registry: &Toc, alg: Algorithm, tarsplit_z: bytes::Bytes) -> ImageResult<Toc> {
    // The files of the registry TOC by name, with the chunk entries that
    // follow each.
    let mut files: HashMap<String, VecDeque<usize>> = HashMap::new();
    for (i, e) in registry.entries.iter().enumerate() {
        if e.entry_type == TocEntryType::Reg && e.size > 0 {
            if let Some(name) = normalize_path(&e.name) {
                files.entry(name).or_default().push_back(i);
            }
        }
    }
    let input = tarsplit::decoder(tarsplit_z, tarsplit::MAX_SIZE).map_err(io_fail)?;
    let mut tar = TarReader::new(Replay::new(Entries::new(input), Zeros));
    let mut entries: Vec<TocEntry> = Vec::new();
    while let Some(h) = tar.next_entry().map_err(io_fail)? {
        if entries.len() >= MAX_ENTRIES {
            return Err(fail("the layer has too many entries"));
        }
        let content = match h.kind {
            Kind::Regular if h.size == 0 => Some(Digest::empty(alg).to_string()),
            Kind::Regular => {
                let name = normalize_path(&h.path)
                    .ok_or_else(|| fail(format!("invalid path `{}` in the layer", h.path)))?;
                let i = files
                    .get_mut(&name)
                    .and_then(|q| q.pop_front())
                    .ok_or_else(|| fail(format!("no content for `{name}` in the TOC")))?;
                let reg = &registry.entries[i];
                if reg.size != h.size {
                    return Err(fail(format!(
                        "`{name}` has {} bytes in the TOC and {} in the tar-split",
                        reg.size, h.size
                    )));
                }
                let id = reg
                    .verity()
                    .or_else(|| reg.digest.clone().filter(|d| d.parse::<Digest>().is_ok()))
                    .ok_or_else(|| {
                        fail(format!("the TOC of the layer has no digest for `{name}`"))
                    })?;
                let Some(mut e) = entry::from_header(&h, Some(&id)).map_err(io_fail)? else {
                    continue;
                };
                e.digest = reg.digest.clone().filter(|d| d.parse::<Digest>().is_ok());
                e.fsverity = reg.fsverity.clone();
                e.offset = reg.offset;
                e.end_offset = reg.end_offset;
                e.chunk_digest = reg.chunk_digest.clone();
                e.chunk_size = reg.chunk_size;
                e.chunk_offset = 0;
                e.chunk_type = reg.chunk_type.clone();
                entries.push(e);
                for c in registry.entries[i + 1..]
                    .iter()
                    .take_while(|c| c.entry_type == TocEntryType::Chunk)
                {
                    entries.push(c.clone());
                }
                continue;
            }
            _ => None,
        };
        if let Some(e) = entry::from_header(&h, content.as_deref()).map_err(io_fail)? {
            entries.push(e);
        }
    }
    if files.values().any(|q| !q.is_empty()) {
        return Err(fail("the TOC has files the tar-split does not"));
    }
    Ok(Toc {
        version: TOC_VERSION,
        entries,
        tar_split_digest: registry.tar_split_digest.clone(),
    })
}

/// Why a layer is not pulled lazily.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotLazy {
    /// The descriptor does not state zstd:chunked metadata.
    NotChunked,
    /// The descriptor states a table of contents and no tar-split.
    NoTarSplit,
    /// The table of contents gives no fs-verity digest for this file.
    NoVerity(String),
}

impl std::fmt::Display for NotLazy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotChunked => f.write_str("it is not a zstd:chunked layer"),
            Self::NoTarSplit => f.write_str("it is a zstd:chunked layer without a tar-split"),
            Self::NoVerity(name) => write!(
                f,
                "its table of contents has no fs-verity digest for `{name}`"
            ),
        }
    }
}

/// The metadata of a layer that can be pulled lazily, with the zstd:chunked
/// information of its descriptor.
pub type Found = (Info, LazyLayer);

/// Fetch and verify the metadata of a zstd:chunked layer, with the
/// zstd:chunked metadata of its descriptor.  Not lazy (and why) if the layer
/// is not one with a tar-split, or its TOC does not give the fs-verity
/// digests of its files: it has to be pulled otherwise.
pub async fn pull_metadata(
    ctx: &PullCtx,
    layer: &OciDescriptor,
) -> ImageResult<Result<Found, NotLazy>> {
    let Some(info) = chunked::parse_info(layer)? else {
        return Ok(Err(NotLazy::NotChunked));
    };
    let Some(tarsplit) = info.tarsplit else {
        return Ok(Err(NotLazy::NoTarSplit));
    };
    // (the fetcher finds them: `Probe`; what it gives is verified below)
    let (toc_z, ts_z) = chunked::metadata(ctx, layer).await?;
    found_of(info, tarsplit, (toc_z, ts_z), layer.digest).await
}

/// The lazy layer of `layer` from its table of contents and tar-split as
/// the fetcher gave them (compressed), verified against the descriptor's
/// `info`; why not, when its table lacks a file's fs-verity digest.
async fn found_of(
    info: Info,
    tarsplit: (u64, u64, u64),
    (toc_z, ts_z): (Vec<u8>, Vec<u8>),
    layer_digest: Digest,
) -> ImageResult<Result<Found, NotLazy>> {
    let fetched = (toc_z.len() + ts_z.len()) as u64;
    let layer_info: Info = info.clone();
    let lazy = tokio::task::spawn_blocking(move || -> ImageResult<Result<LazyLayer, NotLazy>> {
        let meta = chunked::verify_metadata(&layer_info, &toc_z, ts_z, tarsplit.2)?;
        if let Some(e) = without_verity(&meta.toc) {
            debug!(
                "Layer {layer_digest}: pulled whole, its TOC has no fs-verity digest for `{}`",
                e.name
            );
            return Ok(Err(NotLazy::NoVerity(e.name.clone())));
        }
        let toc = merge_toc(
            &meta.toc,
            layer_info.checksum.alg(),
            meta.tarsplit_z.clone(),
        )?;
        Ok(Ok(LazyLayer {
            toc: Arc::new(toc),
            tarsplit: meta.tarsplit_z,
            report: LayerReport {
                fetched_bytes: fetched,
                ..LayerReport::default()
            },
        }))
    })
    .await
    .map_err(|e| fail(format!("metadata task: {e}")))??;
    Ok(lazy.map(|l| (info, l)))
}

/// Whether `layer` can be pulled lazily through the fetchers that answered
/// `reply` to `Probe` (with `metadata`, the table of contents and tar-split
/// it carried): the layer, verified against its descriptor, or the word of
/// `ImageNotLazy` that says why not (`no_toc`, `no_file_digests`,
/// `no_ranges`, `unsupported`, `unreachable`).  A table that is not the
/// descriptor's is an error, not a reason.
pub async fn accept(
    layer: &OciDescriptor,
    reply: &crate::fetcher::fetch::Probed,
    metadata: Option<(Vec<u8>, Vec<u8>)>,
) -> ImageResult<Result<Found, crate::fetcher::fetch::NotLazy>> {
    use crate::fetcher::fetch::{NotLazy as Why, TocSource};
    let Some(info) = chunked::parse_info(layer)? else {
        return Ok(Err(Why::NoToc));
    };
    let Some(tarsplit) = info.tarsplit else {
        return Ok(Err(Why::Unsupported));
    };
    let (TocSource::Carried, Some(metadata)) = (reply.toc, metadata) else {
        return Ok(Err(reply.reason.unwrap_or(Why::Unreachable)));
    };
    match found_of(info, tarsplit, metadata, layer.digest).await? {
        Err(NotLazy::NoVerity(_)) => Ok(Err(Why::NoFileDigests)),
        Err(_) => Ok(Err(Why::NoToc)),
        Ok(_) if !reply.on_demand => Ok(Err(reply.reason.unwrap_or(Why::NoRanges))),
        Ok(found) => Ok(Ok(found)),
    }
}

/// The TOCs of lazy layers last parsed, by layer digest: a file read on
/// demand needs the TOC of its layer, and the files of a layer are read
/// one after the other.  A layer's TOC is that of its blob: it does
/// not change.
static TOCS: Mutex<VecDeque<(String, Arc<Toc>)>> = Mutex::new(VecDeque::new());
const KEEP_TOCS: usize = 4;

/// The stored TOC `json` of the layer `digest`, parsed once.
pub fn parsed_toc(digest: &str, json: &str) -> ImageResult<Arc<Toc>> {
    let lock = || TOCS.lock().unwrap_or_else(|e| e.into_inner());
    {
        let mut tocs = lock();
        if let Some(i) = tocs.iter().position(|(d, _)| d == digest) {
            let hit = tocs.remove(i).expect("a position of the list");
            let toc = hit.1.clone();
            tocs.push_front(hit);
            return Ok(toc);
        }
    }
    let toc: Arc<Toc> = Arc::new(serde_json::from_str(json)?);
    let mut tocs = lock();
    if !tocs.iter().any(|(d, _)| d == digest) {
        tocs.push_front((digest.to_string(), toc.clone()));
        tocs.truncate(KEEP_TOCS);
    }
    Ok(toc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull::window;

    fn entry(name: &str, kind: TocEntryType, size: u64, d: Option<&str>) -> TocEntry {
        TocEntry {
            name: name.into(),
            entry_type: kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            digest: d.map(|d| d.replace("fsverity-sha256-12:", "sha256:")),
            fsverity: d.and_then(velarx_storage::to_toc),
            offset: 100,
            end_offset: 200,
            chunk_digest: None,
            chunk_size: 0,
            chunk_offset: 0,
            chunk_type: None,
            link_name: None,
            mod_time: None,
            access_time: None,
            change_time: None,
            dev_major: None,
            dev_minor: None,
            xattrs: Default::default(),
        }
    }

    /// The tar-split of a tar of a directory, a file of 5 bytes and a symlink,
    /// and the digest of the file.
    fn sample() -> (Vec<u8>, String) {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_size(0);
        h.set_mode(0o755);
        b.append_data(&mut h, "d/", io::empty()).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(5);
        h.set_mode(0o600);
        h.set_uid(7);
        b.append_data(&mut h, "d/f", &b"hello"[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "d/l", "f").unwrap();
        let tar = b.into_inner().unwrap();

        // The tar-split of it, with the layer writer's recorder.
        let mut r = TarReader::with_sink(&tar[..], tarsplit::Recorder::new().unwrap());
        while r.next_entry().unwrap().is_some() {}
        let (_, rec) = r.finish().unwrap();
        (
            rec.finish().unwrap().compressed,
            crate::verity_text(b"hello"),
        )
    }

    #[test]
    fn test_merge_takes_metadata_from_the_tar_headers_and_chunks_from_the_toc() {
        let (ts, hello) = sample();
        let mut file = entry("d/f", TocEntryType::Reg, 5, Some(&hello));
        file.chunk_digest = Some(hello.clone());
        file.chunk_size = 3;
        let mut chunk = entry("d/f", TocEntryType::Chunk, 0, None);
        chunk.chunk_digest = Some(hello.clone());
        chunk.chunk_offset = 3;
        chunk.chunk_size = 2;
        // The registry lies about the mode: the tar header is what counts.
        file.mode = 0o777;
        let registry = Toc {
            version: 1,
            entries: vec![
                entry("d", TocEntryType::Dir, 0, None),
                file,
                chunk,
                entry("d/l", TocEntryType::Symlink, 0, None),
            ],
            tar_split_digest: None,
        };
        let toc = merge_toc(&registry, Algorithm::Sha256, ts.into()).unwrap();
        let names: Vec<_> = toc
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.entry_type))
            .collect();
        assert_eq!(
            names,
            [
                ("d", TocEntryType::Dir),
                ("d/f", TocEntryType::Reg),
                ("d/f", TocEntryType::Chunk),
                ("d/l", TocEntryType::Symlink)
            ]
        );
        let f = &toc.entries[1];
        assert_eq!((f.mode, f.uid), (0o600, 7));
        assert_eq!(
            f.digest.as_deref(),
            Some(hello.replace("fsverity-sha256-12:", "sha256:").as_str())
        );
        assert_eq!((f.offset, f.end_offset, f.chunk_size), (100, 200, 3));
        assert_eq!(toc.entries[3].link_name.as_deref(), Some("f"));
    }

    #[test]
    fn test_merge_refuses_a_toc_that_does_not_match_the_tar_split() {
        let (ts, hello) = sample();
        let good = entry("d/f", TocEntryType::Reg, 5, Some(&hello));
        // Wrong size, no digest, missing file, an extra file.
        let mut wrong_size = good.clone();
        wrong_size.size = 6;
        let mut no_digest = good.clone();
        no_digest.fsverity = None;
        no_digest.digest = None;
        let extra = entry("d/g", TocEntryType::Reg, 1, Some(&hello));
        for entries in [
            vec![wrong_size],
            vec![no_digest],
            vec![],
            vec![good.clone(), extra],
        ] {
            let registry = Toc {
                version: 1,
                entries,
                tar_split_digest: None,
            };
            assert!(merge_toc(&registry, Algorithm::Sha256, ts.clone().into()).is_err());
        }
    }

    #[test]
    fn test_file_entries_slice() {
        let d = crate::verity_text(b"x");
        let toc = Toc {
            version: 1,
            entries: vec![
                entry("a", TocEntryType::Reg, 2, Some(&d)),
                entry("a", TocEntryType::Chunk, 0, None),
                entry("b", TocEntryType::Reg, 2, Some(&crate::verity_text(b"y"))),
            ],
            tar_split_digest: None,
        };
        let at = window::file_index(&toc, &d).unwrap();
        assert_eq!(window::entries_of(&toc, &[at]).entries.len(), 2);
        assert!(window::file_index(&toc, &crate::verity_text(b"z")).is_none());
    }
}
