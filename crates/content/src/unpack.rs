// SPDX-License-Identifier: Apache-2.0
//! A layer read whole and unpacked: what a fetcher does for `Unpack` (the
//! registry fetcher from the stream its workers decompressed, the directory
//! fetcher as an origin from the blob of an archive).  Each regular file is
//! handed over to the engine as a descriptor of a reply (a file with no name,
//! fs-verity enabled when the scope says verity); the table of contents of
//! what went by and its tar-split are a claim, which the engine replays and
//! checks against the diff id.

use crate::fetcher::fetch::{EventKind, FetchEvent, MAX_FDS, TARSPLIT, TOC_CLAIM};
use crate::pull::chunked::io_fail;
use crate::pull::entry::{from_header, MAX_ENTRIES};
use crate::pull::tar::{Kind as TarKind, TarReader};
use crate::serve_fetch::Out;
use crate::stager::{put_named, StageError, Unnamed};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use velarx_storage::Toc;
use velarx_types::digest::{Algorithm, Digest};
use velarx_types::ImageError;

/// A staging failure as the error of the layer: what the content
/// contradicts is `Contradicted`.
pub fn stage_error(path: &str, e: StageError) -> ImageError {
    match e {
        StageError::BadChunk { .. } | StageError::Wrong(_) | StageError::TooLarge(_) => {
            ImageError::Contradicted(format!("`{path}`: {e}"))
        }
        StageError::Io(e) => ImageError::Io(e),
        e => ImageError::Layer(format!("`{path}`: {e}")),
    }
}

/// The bytes of files after which a reply is sent, however few they are: a
/// big file is copied by the engine while the rest of the layer unpacks.
const SEND_AFTER: u64 = 1 << 20;

/// The files of a layer handed over to the engine in the replies of an
/// `Unpack`, as many to a reply as one carries.
pub struct Files {
    out: Out<FetchEvent>,
    waiting: Vec<OwnedFd>,
    bytes: u64,
}

impl Files {
    pub fn new(out: Out<FetchEvent>) -> Self {
        Self {
            out,
            waiting: Vec::new(),
            bytes: 0,
        }
    }

    /// Hand over `file` of `size` bytes: sent with the ones that wait for it
    /// when they are enough.
    pub fn give(&mut self, file: File, size: u64) -> io::Result<()> {
        self.waiting.push(file.into());
        self.bytes += size;
        if self.waiting.len() == MAX_FDS || self.bytes >= SEND_AFTER {
            self.send()?;
        }
        Ok(())
    }

    /// Send the files that wait.
    pub fn send(&mut self) -> io::Result<()> {
        if self.waiting.is_empty() {
            return Ok(());
        }
        self.bytes = 0;
        let files = std::mem::take(&mut self.waiting);
        let event = FetchEvent {
            objects: (0..files.len() as u32).collect(),
            ..FetchEvent::of(EventKind::Staged)
        };
        self.out
            .blocking_send_with(event, files)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the asker is gone"))
    }
}

/// Unpack the tar stream `reader`: each regular file is written to a file with
/// no name in `staging`, and handed over once (`files`), and the table of
/// contents of what went by, which names each by its digest in `alg`, and the
/// compressed tar-split are returned.
pub fn unpack_tar<R: Read>(
    reader: R,
    staging: &File,
    (alg, verity): (Algorithm, bool),
    files: &mut Files,
) -> Result<(Toc, Vec<u8>), ImageError> {
    let recorder = crate::pull::tarsplit::Recorder::new().map_err(io_fail)?;
    let mut tar = TarReader::with_sink(reader, recorder);
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut buf = vec![0u8; 256 * 1024];
    while let Some(h) = tar.next_entry().map_err(io_fail)? {
        if entries.len() >= MAX_ENTRIES {
            return Err(ImageError::Layer(format!(
                "the layer has too many entries (more than {MAX_ENTRIES})"
            )));
        }
        let digest = match (h.kind == TarKind::Regular, h.size) {
            (true, 0) => Some(Digest::empty(alg)),
            (true, size) => {
                let file = Unnamed::for_handover(staging.as_fd(), size, verity)
                    .map_err(io_fail)?
                    .hashed(alg);
                let mut at = 0u64;
                while at < size {
                    let want = buf
                        .len()
                        .min(usize::try_from(size - at).unwrap_or(usize::MAX));
                    let n = tar.read(&mut buf[..want]).map_err(io_fail)?;
                    if n == 0 {
                        return Err(ImageError::Layer("the archive ends in a file".into()));
                    }
                    file.write_chunk(at, &buf[..n], None)
                        .map_err(|e| stage_error(&h.path, e))?;
                    at += n as u64;
                }
                let (d, file) = file
                    .finish_written(verity)
                    .map_err(|e| stage_error(&h.path, e))?;
                if seen.insert(d) {
                    files.give(file, size).map_err(io_fail)?;
                }
                Some(d)
            }
            _ => None,
        };
        let digest = digest.map(|d| d.to_string());
        entries.push(from_header(&h, digest.as_deref()).map_err(io_fail)?);
    }
    files.send().map_err(io_fail)?;
    let (_, recorder) = tar.finish().map_err(io_fail)?;
    let tarsplit = recorder.finish().map_err(io_fail)?.compressed;
    let toc = Toc {
        version: velarx_storage::TOC_VERSION,
        entries,
        tar_split_digest: None,
    };
    Ok((toc, tarsplit))
}

/// Give the table of contents `toc` and the tar-split their names in the
/// staging of the layer, last: the names say the layer was unpacked
/// (`indexed`).
pub fn put_claim(staging: &File, toc: &Toc, tarsplit: &[u8]) -> Result<(), ImageError> {
    let claim = serde_json::to_vec(toc)?;
    put_named(staging.as_fd(), TOC_CLAIM, &claim)
        .and_then(|()| put_named(staging.as_fd(), TARSPLIT, tarsplit))
        .map_err(|e| stage_error("the index of the layer", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pull::testnames::{digest_names, is_digest_name, Names};
    use tokio::sync::mpsc;

    /// A tar of the files `files` (name, content).
    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut header, name, *data).unwrap();
        }
        tar.into_inner().unwrap()
    }

    /// Unpack `tar` into `staging`: the claim, and the number of files handed
    /// over.
    async fn unpacked(tar: Vec<u8>, staging: &std::path::Path) -> Result<(Toc, usize), ImageError> {
        let (tx, mut rx) = mpsc::channel(64);
        let staging = File::open(staging).unwrap();
        let work = tokio::task::spawn_blocking(move || {
            let mut files = Files::new(Out::new(tx));
            unpack_tar(&tar[..], &staging, (Algorithm::Sha256, false), &mut files)
        });
        let mut handed = 0;
        while let Some((_, fds)) = rx.recv().await {
            handed += fds.len();
        }
        work.await.unwrap().map(|(toc, _)| (toc, handed))
    }

    /// A plain tar keeps the order of its entries and has no rule of order
    /// (the table of a layer unpacked is the one of version 1): a file and a
    /// path below it, in either order, is read, and it is the image of the
    /// layer that refuses it, at the pull, naming the path.
    #[tokio::test]
    async fn a_path_below_a_file_of_a_tar_is_read_and_refused_by_its_image() {
        for files in [
            [("a", &b"x"[..]), ("a/b", &b"y"[..])],
            [("a/b", &b"y"[..]), ("a", &b"x"[..])],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (toc, handed) = unpacked(tar_of(&files), dir.path()).await.unwrap();
            assert_eq!((toc.entries.len(), handed), (2, 2));
            let e = velarx_fuse::layer_erofs::layer_image(&toc.entries)
                .err()
                .unwrap();
            assert!(e.contains("`a`"), "{files:?}: {e}");
        }
    }

    /// A content that is twice in a layer is handed over once, and an empty
    /// file is none.
    #[tokio::test]
    async fn a_content_is_handed_over_once() {
        let dir = tempfile::tempdir().unwrap();
        let files: [(&str, &[u8]); 4] =
            [("a", b"same"), ("b", b"same"), ("c", b""), ("d", b"other")];
        let (toc, handed) = unpacked(tar_of(&files), dir.path()).await.unwrap();
        assert_eq!((toc.entries.len(), handed), (4, 2));
    }

    /// While a layer is unpacked nothing in the staging appears under a name
    /// made of a digest, one that stops included: a process that looks a file
    /// up by its digest finds nothing it cannot trust; the names are given by
    /// the engine, after the replay.
    #[tokio::test]
    async fn no_name_of_a_digest_appears_while_a_layer_is_unpacked() {
        let big: Vec<u8> = (0..300 * 1024u32).map(|i| (i * 7 + 3) as u8).collect();
        let tar = tar_of(&[("big", &big), ("small", b"a small file"), ("again", &big)]);
        for cut in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let names = Names::watching(&[dir.path()]);
            let tar = if cut {
                tar[..tar.len() * 3 / 4].to_vec()
            } else {
                tar.clone()
            };
            let done = unpacked(tar, dir.path()).await;
            assert_eq!(done.is_err(), cut);
            let (seen, _) = names.finish();
            let named: Vec<&String> = seen.iter().filter(|n| is_digest_name(n)).collect();
            assert!(named.is_empty(), "named by a digest: {named:?}");
            assert_eq!(digest_names(dir.path()), Vec::<std::path::PathBuf>::new());
        }
    }
}
