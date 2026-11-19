// SPDX-License-Identifier: Apache-2.0
//! Lazy layers: the metadata of a zstd:chunked layer without its files.
//!
//! The TOC and the tar-split are fetched and checked against the digests the
//! manifest and the TOC give.  The stored TOC is the table the manifest
//! vouches for (the tar-split is kept to make the layer's tar again, never to
//! tell what the layer holds), with, for each file, the position of its
//! chunks in the blob.  The files are fetched later, one at a
//! time as they are read or all of them when the image is completed, with the
//! same planner and the same checks as a partial pull.  Each file is proved by
//! the commit of the completion (its bytes against the TOC, its fs-verity
//! digest by the kernel); a TOC layer has no diff id and no replay of the
//! stream.

use super::chunked::{self, Info};
use super::entry;
use super::tar::TarReader;
use super::tarsplit::{self, Contents, Entries, Replay};
use super::{LayerReport, PullCtx};
use std::io::{self, Read};
use std::sync::Arc;
use velarx_storage::{Toc, TocEntry, TocEntryType, TOC_VERSION};
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::{ImageError, ImageResult, OciDescriptor};

fn fail(msg: impl Into<String>) -> ImageError {
    ImageError::Layer(msg.into())
}

/// The metadata of a lazy layer.
pub struct LazyLayer {
    /// The TOC to store: tar headers and chunk positions.
    pub toc: Arc<Toc>,
    /// The verified, zstd compressed tar-split.
    pub tarsplit: bytes::Bytes,
    pub report: LayerReport,
}

/// The first regular file with content to which `toc` gives no fs-verity
/// digest: a layer that has one is refused (a file is known, fetched and
/// checked by its fs-verity digest, which is not computed here).
pub fn without_verity(toc: &Toc) -> Option<&TocEntry> {
    toc.entries
        .iter()
        .find(|e| e.entry_type == TocEntryType::Reg && e.size > 0 && e.verity().is_none())
}

/// File contents made of zeros: the headers of a tar-split are read without
/// the files.
struct Zeros;

impl Contents for Zeros {
    fn open(&mut self, _: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(io::repeat(0).take(size)))
    }
}

/// The TOC the layer `layer` pulled by its table of contents is stored by:
/// the entries of the table the descriptor vouches for.  Each file needs an
/// fs-verity digest or the digest of its content (see [`without_verity`]).
/// The tar-split (`tarsplit_z`, verified against the table) makes the tar of
/// the layer again, so it must describe the same entries in the same order,
/// contents aside: a table and a tar stream that describe two filesystems
/// are refused.
pub fn toc_view(
    registry: &Toc,
    alg: Algorithm,
    tarsplit_z: bytes::Bytes,
    layer: &Digest,
) -> ImageResult<Toc> {
    let refused =
        |e: &dyn std::fmt::Display| ImageError::Contradicted(format!("layer {layer}: {e}"));
    let entries = registry
        .entries
        .iter()
        .map(|e| entry::from_toc(e, alg))
        .collect::<io::Result<Vec<_>>>()
        .map_err(|e| refused(&e))?;
    let input = tarsplit::decoder(tarsplit_z, tarsplit::MAX_SIZE).map_err(|e| refused(&e))?;
    let mut tar = TarReader::new(Replay::new(Entries::new(input), Zeros));
    let mut table = entries
        .iter()
        .filter(|e| e.entry_type != TocEntryType::Chunk);
    loop {
        let header = tar.next_entry().map_err(|e| refused(&e))?;
        let header = header
            .map(|h| entry::header_entry(&h))
            .transpose()
            .map_err(|e| refused(&e))?;
        match (header, table.next()) {
            (None, None) => break,
            (Some(h), Some(t)) if entry::same_entry(&h, t) => {}
            (h, t) => {
                let name = t.or(h.as_ref()).map_or("", |e| e.name.as_str());
                return Err(refused(&format!(
                    "its table of contents and its tar-split differ at `{name}`"
                )));
            }
        }
    }
    Ok(Toc {
        version: TOC_VERSION,
        entries,
        tar_split_digest: registry.tar_split_digest.clone(),
    })
}

/// The metadata of a layer that can be pulled lazily, with the zstd:chunked
/// information of its descriptor.
pub type Found = (Info, LazyLayer);

/// Fetch and verify the metadata of a zstd:chunked layer, with the
/// zstd:chunked metadata of its descriptor.  None if the layer is not
/// zstd:chunked; a table that cannot be used is an error
/// ([`chunked::verify_metadata`]).
pub async fn pull_metadata(ctx: &PullCtx, layer: &OciDescriptor) -> ImageResult<Option<Found>> {
    let max_tar = ctx.limits.max_layer_bytes;
    let Some(info) = chunked::parse_info(layer)? else {
        return Ok(None);
    };
    // (the fetcher finds them: `Probe`; what it gives is verified below)
    let (toc_z, ts_z) = chunked::metadata(ctx, layer).await?;
    found_of(info, (toc_z, ts_z), layer.digest, max_tar)
        .await
        .map(Some)
}

/// The lazy layer of `layer` from its table of contents and tar-split as
/// the fetcher gave them (compressed), verified against the descriptor's
/// `info`.
async fn found_of(
    info: Info,
    (toc_z, ts_z): (Vec<u8>, Vec<u8>),
    layer_digest: Digest,
    max_tar: u64,
) -> ImageResult<Found> {
    let fetched = (toc_z.len() + ts_z.len()) as u64;
    let layer_info: Info = info.clone();
    let lazy = tokio::task::spawn_blocking(move || -> ImageResult<LazyLayer> {
        let meta = chunked::verify_metadata(&layer_info, &toc_z, ts_z, &layer_digest, max_tar)?;
        Ok(LazyLayer {
            toc: meta.stored,
            tarsplit: meta.tarsplit_z,
            report: LayerReport {
                fetched_bytes: fetched,
                ..LayerReport::default()
            },
        })
    })
    .await
    .map_err(|e| fail(format!("metadata task: {e}")))??;
    Ok((info, lazy))
}

/// Whether `layer` can be pulled lazily through the fetchers that answered
/// `reply` to `Probe` (with `metadata`, the table of contents and tar-split
/// it carried): the layer, verified against its descriptor, or the word of
/// `ImageNotLazy` that says why not (`no_toc`, `no_ranges`, `unsupported`,
/// `unreachable`).  A table that cannot be used is an error, not a reason.
pub async fn accept(
    layer: &OciDescriptor,
    reply: &crate::fetcher::fetch::Probed,
    metadata: Option<(Vec<u8>, Vec<u8>)>,
    max_tar: u64,
) -> ImageResult<Result<Found, crate::fetcher::fetch::NotLazy>> {
    use crate::fetcher::fetch::{NotLazy as Why, TocSource};
    let Some(info) = chunked::parse_info(layer)? else {
        return Ok(Err(Why::NoToc));
    };
    let (TocSource::Carried, Some(metadata)) = (reply.toc, metadata) else {
        return Ok(Err(reply.reason.unwrap_or(Why::Unreachable)));
    };
    let found = found_of(info, metadata, layer.digest, max_tar).await?;
    Ok(match reply.on_demand {
        true => Ok(found),
        false => Err(reply.reason.unwrap_or(Why::NoRanges)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The tar-split of a tar of the root, a directory, a file of 5 bytes
    /// (mode 04777) and a symbolic link to it.
    fn tarsplit() -> bytes::Bytes {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Directory);
        h.set_mode(0o644);
        for dir in ["./", "d/"] {
            b.append_data(&mut h.clone(), dir, io::empty()).unwrap();
        }
        let mut h = tar::Header::new_gnu();
        h.set_size(5);
        h.set_mode(0o4777);
        b.append_data(&mut h, "d/f", &b"hello"[..]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_mode(0o644);
        b.append_link(&mut h, "d/l", "f").unwrap();
        let tar = b.into_inner().unwrap();
        let mut r = TarReader::with_sink(&tar[..], tarsplit::Recorder::new().unwrap());
        while r.next_entry().unwrap().is_some() {}
        let (_, rec) = r.finish().unwrap();
        rec.finish().unwrap().compressed.into()
    }

    /// The table of contents of [`tarsplit`], as another tool may write it.
    fn table() -> Toc {
        let hello = crate::verity_text(b"hello");
        let mut file = entry("d/f", TocEntryType::Reg, 5, Some(&hello));
        file.chunk_digest = Some(hello.clone());
        file.chunk_size = 3;
        file.mode = 0o104777;
        file.xattrs
            .insert("trusted.overlay.redirect".into(), "eA==".into());
        let mut chunk = entry("d/f", TocEntryType::Chunk, 0, None);
        chunk.chunk_digest = Some(hello.clone());
        chunk.chunk_offset = 3;
        chunk.chunk_size = 2;
        let mut link = entry("d/l", TocEntryType::Symlink, 0, None);
        link.link_name = Some("f".into());
        Toc {
            version: 1,
            entries: vec![
                entry("./", TocEntryType::Dir, 0, None),
                entry("./d/", TocEntryType::Dir, 7, Some(&hello)),
                file,
                chunk,
                link,
            ],
            tar_split_digest: None,
        }
    }

    fn view(table: &Toc) -> ImageResult<Toc> {
        toc_view(
            table,
            Algorithm::Sha256,
            tarsplit(),
            &Digest::empty(Algorithm::Sha256),
        )
    }

    #[test]
    fn test_view_is_the_table_kept_to_what_a_layer_is() {
        let toc = view(&table()).unwrap();
        let names: Vec<_> = toc
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.entry_type))
            .collect();
        assert_eq!(
            names,
            [
                ("./", TocEntryType::Dir),
                ("d", TocEntryType::Dir),
                ("d/f", TocEntryType::Reg),
                ("d/f", TocEntryType::Chunk),
                ("d/l", TocEntryType::Symlink)
            ]
        );
        let f = &toc.entries[2];
        assert_eq!(f.mode, 0o4777);
        assert!(f.xattrs.is_empty());
        assert_eq!((f.offset, f.end_offset, f.chunk_size), (100, 200, 3));
        assert_eq!((toc.entries[1].size, &toc.entries[1].digest), (0, &None));
        assert_eq!(toc.entries[4].link_name.as_deref(), Some("f"));
    }

    #[test]
    fn test_view_refuses_a_table_the_tar_split_contradicts() {
        type Edit = fn(&mut Toc);
        let edits: [(&str, Edit); 7] = [
            ("d/f", |t| t.entries[2].mode = 0o755),
            ("d/f", |t| t.entries[2].uid = 1),
            ("d/f", |t| {
                t.entries[2].xattrs.insert("user.k".into(), "eA==".into());
            }),
            ("d/g", |t| t.entries[2].name = "d/g".into()),
            ("d/l", |t| {
                t.entries[4].link_name = Some("/etc/shadow".into())
            }),
            ("d/l", |t| {
                t.entries.pop();
            }),
            ("x", |t| {
                let mut x = t.entries[0].clone();
                x.name = "x".into();
                t.entries.push(x);
            }),
        ];
        for (at, edit) in edits {
            let mut t = table();
            edit(&mut t);
            let e = view(&t).unwrap_err();
            assert!(matches!(e, ImageError::Contradicted(_)), "{e}");
            assert!(e.to_string().contains(&format!("differ at `{at}`")), "{e}");
        }
    }

    #[test]
    fn test_view_refuses_a_file_without_a_digest() {
        let mut t = table();
        t.entries[2].digest = None;
        t.entries[2].fsverity = None;
        let e = view(&t).unwrap_err();
        assert!(e.to_string().contains("no digest for `d/f`"), "{e}");
    }
}
