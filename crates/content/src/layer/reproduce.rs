// SPDX-License-Identifier: Apache-2.0
//! The tar stream of a stored layer.

use crate::pull::tarsplit::{self, ContentFile, ContentIndex, Contents, Entries, Replay};
use std::io::{self, Read};
use std::sync::Arc;
use velarx_db::{Database, LayerKey};
use velarx_storage::{ObjectOpener, Toc};
use velarx_types::digest::{Digest, DigestWriter};

/// The content of the files of a layer, read back through `objects` (the
/// storage driver that holds them), each object by the key its table of
/// contents names it by.
pub struct StoreContents {
    index: ContentIndex,
    objects: Arc<dyn ObjectOpener>,
}

impl Contents for StoreContents {
    fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
        let ContentFile {
            name: norm,
            key: digest,
            ..
        } = self.index.take(name, size)?;
        let file = self.objects.object_file(&digest, size).map_err(|e| {
            let what = match e.kind() {
                io::ErrorKind::InvalidData => {
                    format!("the stored content of `{norm}` has the wrong size")
                }
                _ => format!("{norm} ({digest}): {e}"),
            };
            io::Error::new(e.kind(), what)
        })?;
        Ok(Box::new(file))
    }
}

/// The tar stream of a layer, from its TOC and its compressed tar-split.
pub fn stream(
    toc: &Toc,
    tarsplit_z: impl AsRef<[u8]> + Send + 'static,
    objects: Arc<dyn ObjectOpener>,
) -> io::Result<impl Read + Send> {
    let input = tarsplit::decoder(tarsplit_z, tarsplit::MAX_SIZE)?;
    // (the files are read in the order of the table of contents: a driver
    // behind a socket reads the next ones in the same call)
    let objects = objects
        .ordered(&mut || crate::pull::entry::FileUse::objects_of_toc(toc))
        .unwrap_or(objects);
    let contents = StoreContents {
        index: tarsplit::content_index(toc),
        objects,
    };
    Ok(Replay::new(Entries::new(input), contents))
}

/// A stored layer, ready to be read as a tar stream.
pub struct StoredLayer {
    pub key: LayerKey,
    pub diff_id: Digest,
    toc: Toc,
    tarsplit: Vec<u8>,
}

/// The size of the uncompressed tar stream a zstd compressed tar-split
/// describes: what a layer records at the pull, so that nothing decodes the
/// tar-split again to know it.
pub fn tarsplit_stream_size(compressed: impl AsRef<[u8]> + Send + 'static) -> io::Result<u64> {
    let input = tarsplit::decoder(compressed, tarsplit::MAX_SIZE)?;
    let mut size = 0u64;
    for item in Entries::new(input) {
        let n = match item? {
            tarsplit::Item::Segment(s) => s.len() as u64,
            tarsplit::Item::File { size, .. } => size,
        };
        size = size
            .checked_add(n)
            .ok_or_else(|| io::Error::other("the layer is too large"))?;
    }
    Ok(size)
}

impl StoredLayer {
    /// Load a layer that is ready.  A layer pulled before tar-splits were
    /// kept has to be pulled again.
    pub async fn load(db: &Database, key: &LayerKey) -> io::Result<Self> {
        Self::load_as(db, key, None).await
    }

    /// Load a layer that is ready, as the layer of an image whose diff ids
    /// are of `alg`: its stream is the one of the diff id of that algorithm
    /// (a layer of images of both algorithms has one of each), else of the
    /// one it has, which the caller compares with the image's.
    pub async fn load_as(
        db: &Database,
        key: &LayerKey,
        alg: Option<velarx_types::digest::Algorithm>,
    ) -> io::Result<Self> {
        Self::load_expecting(db, key, alg, None).await
    }

    /// [`Self::load_as`] for a layer that may have been verified by its table
    /// of contents alone, with no diff id of its own: the stream is then
    /// the one of `expected`, the diff id the image's configuration gives,
    /// which whoever reads the stream through [`Self::verified_stream`] (or
    /// hashes it) checks it against.
    pub async fn load_expecting(
        db: &Database,
        key: &LayerKey,
        alg: Option<velarx_types::digest::Algorithm>,
        expected: Option<&Digest>,
    ) -> io::Result<Self> {
        let other = |e: &dyn std::fmt::Display| io::Error::other(format!("layer {key}: {e}"));
        // (what the layer lacks is NotFound: the store does not have it)
        let lacks = |e: &dyn std::fmt::Display| {
            io::Error::new(io::ErrorKind::NotFound, format!("layer {key}: {e}"))
        };
        let record = db.get_layer(key).await.map_err(|e| match e {
            velarx_types::DbError::NotFound(_) => lacks(&"the store has no such layer"),
            e => other(&e),
        })?;
        if record.status != "ready" {
            return Err(lacks(&format!("it is {}, not ready", record.status)));
        }
        let diff_id = alg
            .and_then(|a| record.diff_id_in(a).copied())
            .or(record.diff_id)
            .or_else(|| expected.copied().filter(|_| key.is_toc()))
            .ok_or_else(|| lacks(&"it has no diff id"))?;
        let toc = record
            .toc
            .ok_or_else(|| lacks(&"it has no table of contents"))?;
        let toc: Toc = serde_json::from_str(&toc).map_err(|e| other(&e))?;
        let tarsplit = db
            .get_layer_tarsplit(key)
            .await
            .map_err(|e| other(&e))?
            .ok_or_else(|| {
                // (a canonical layer has an empty one once it is complete)
                lacks(&if toc.is_canonical() {
                    "it is not complete"
                } else {
                    "it has no tar-split"
                })
            })?;
        Ok(Self {
            key: *key,
            diff_id,
            toc,
            tarsplit,
        })
    }

    /// The size of the uncompressed stream, from the tar-split alone.
    pub fn stream_size(&self) -> io::Result<u64> {
        tarsplit_stream_size(self.tarsplit.clone())
    }

    /// The uncompressed tar stream.
    pub fn stream(&self, objects: Arc<dyn ObjectOpener>) -> io::Result<impl Read + Send> {
        stream(&self.toc, self.tarsplit.clone(), objects)
    }

    /// The stream, which ends with an error unless its digest is the diff id.
    pub fn verified_stream(&self, objects: Arc<dyn ObjectOpener>) -> io::Result<impl Read + Send> {
        Ok(Verified {
            inner: self.stream(objects)?,
            hasher: Some(DigestWriter::for_digest(&self.diff_id)),
            expected: self.diff_id,
        })
    }
}

/// A reader that checks the digest of what it read when it reaches the end.
struct Verified<R> {
    inner: R,
    hasher: Option<DigestWriter>,
    expected: Digest,
}

impl<R: Read> Read for Verified<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            if let Some(h) = &mut self.hasher {
                h.update(&buf[..n]);
            }
            return Ok(n);
        }
        if let Some(h) = self.hasher.take() {
            let actual = h.finalize();
            if actual != self.expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "the stored layer has the digest {actual}, its diff id is {}",
                        self.expected
                    ),
                ));
            }
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    #[test]
    fn test_verified_reader_checks_the_digest_at_the_end() {
        let data = b"some tar stream".to_vec();
        let good = Digest::of(Algorithm::Sha256, &data);
        let mut ok = Vec::new();
        Verified {
            inner: io::Cursor::new(data.clone()),
            hasher: Some(DigestWriter::new(Algorithm::Sha256)),
            expected: good,
        }
        .read_to_end(&mut ok)
        .unwrap();
        assert_eq!(ok, data);

        let mut bad = Vec::new();
        let err = Verified {
            inner: io::Cursor::new(data),
            hasher: Some(DigestWriter::new(Algorithm::Sha256)),
            expected: Digest::of(Algorithm::Sha256, b"other"),
        }
        .read_to_end(&mut bad)
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
