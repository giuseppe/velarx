// SPDX-License-Identifier: Apache-2.0
//! The chunks of the store, for the store service (`crate::store_service`)
//! to hand over to the services that give them to others.
//!
//! Chunks can be served from:
//! 1. File store (complete files stored by file digest)
//! 2. Database chunk_locations (extract chunk from stored file at offset)
//!
//! A file of a layer whose EROFS image holds it (`layers.inline`) is served
//! as a range of that image, as an object is a file: the content of a digest
//! is found as `velarx_graph::objects::find_content` does, store by store.

use std::sync::Arc;
use velarx_db::{ChunkLocation, Database};
use velarx_graph::objects::find_content;
use velarx_storage::{ChunkFile, FileStore, MAX_SERVED_BYTES};
use velarx_types::digest::Digest;

/// The chunks and files of the stores, as the store service gives them
pub struct StorageChunkProvider {
    file_store: Arc<FileStore>,
    db: Database,
}

impl StorageChunkProvider {
    /// Create a new StorageChunkProvider
    pub fn new(file_store: Arc<FileStore>, db: Database) -> Self {
        Self { file_store, db }
    }

    /// The files that hold `digests` (a file, or a chunk of a file), if the
    /// stores have them and they are small enough to serve, one for each:
    /// one call to the database for where the chunks
    /// are, and the files opened on one blocking thread (the files of a wave
    /// a peer asks for are a round trip, not one for each).
    pub async fn open_all(&self, digests: Vec<Digest>) -> Vec<Option<ChunkFile>> {
        // (the fs-verity digest of a file names an object, never a chunk)
        let chunks: Vec<Digest> = digests
            .iter()
            .filter(|d| !d.is_fsverity())
            .copied()
            .collect();
        let located = self
            .db
            .get_chunk_locations_batch(&chunks)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("The places of {} chunks are not known: {e}", chunks.len());
                Default::default()
            });
        let wanted: Vec<(Digest, Option<ChunkLocation>)> = digests
            .into_iter()
            .map(|d| {
                let location = located.get(&d).cloned();
                (d, location)
            })
            .collect();
        let (files, db) = (self.file_store.clone(), self.db.clone());
        tokio::task::spawn_blocking(move || {
            wanted
                .into_iter()
                .map(|(digest, location)| Self::opened(&db, &files, &digest, location))
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// The range of a file that is the content of the file `key`, if the
    /// stores have it.
    fn held(db: &Database, files: &FileStore, key: &str) -> Option<ChunkFile> {
        find_content("chunks", db, files, key)
            .and_then(|content| content.range("chunks"))
            .ok()
    }

    /// The file of `digest`: the whole file the stores have by that digest
    /// (an object, or the file of the image of a layer), else the piece of a
    /// file `location` says.  Blocking.
    fn opened(
        db: &Database,
        files: &FileStore,
        digest: &Digest,
        location: Option<ChunkLocation>,
    ) -> Option<ChunkFile> {
        let max = MAX_SERVED_BYTES as u64;
        let whole = Self::held(db, files, &digest.to_string()).filter(|w| w.len <= max);
        if whole.is_some() {
            return whole;
        }
        let loc = location.filter(|loc| loc.size <= max)?;
        let held = Self::held(db, files, &loc.file_digest)?;
        let end = loc.offset.checked_add(loc.size)?;
        (held.len >= end).then_some(ChunkFile {
            file: held.file,
            offset: held.offset + loc.offset,
            len: loc.size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::tempdir;

    /// The file that holds `digest`.
    async fn open(provider: &StorageChunkProvider, digest: &str) -> Option<ChunkFile> {
        let parsed = Digest::parse_key(digest).ok()?;
        provider.open_all(vec![parsed]).await.pop().flatten()
    }

    /// The bytes `open` gives for `digest`.
    async fn read(provider: &StorageChunkProvider, digest: &str) -> Option<Vec<u8>> {
        let mut found = open(provider, digest).await?;
        found.file.seek(SeekFrom::Start(found.offset)).ok()?;
        let mut bytes = vec![0u8; found.len as usize];
        found.file.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }

    #[tokio::test]
    async fn test_storage_chunk_provider() {
        let dir = tempdir().unwrap();
        let file_store = Arc::new(FileStore::new(dir.path()).unwrap());
        let db = Database::open(dir.path().join("test.db")).await.unwrap();

        let provider = StorageChunkProvider::new(file_store.clone(), db);

        let data = b"Hello, world!";
        let digest = file_store
            .put(velarx_types::digest::Algorithm::Sha256, data)
            .unwrap();

        assert_eq!(read(&provider, &digest).await.unwrap(), data);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_chunk_not_found() {
        let dir = tempdir().unwrap();
        let file_store = Arc::new(FileStore::new(dir.path()).unwrap());
        let db = Database::open(dir.path().join("test.db")).await.unwrap();

        let provider = StorageChunkProvider::new(file_store, db);

        assert!(read(&provider, "sha256:nonexistent").await.is_none());
    }

    /// What a peer sends names nothing below the stores.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_only_a_digest_is_looked_up() {
        let dir = tempdir().unwrap();
        let files = dir.path().join("files");
        std::fs::create_dir_all(dir.path().join("secret")).unwrap();
        std::fs::write(dir.path().join("secret").join("x"), b"secret").unwrap();
        let file_store = Arc::new(FileStore::new(&files).unwrap());
        let db = Database::open(dir.path().join("test.db")).await.unwrap();
        let provider = StorageChunkProvider::new(file_store, db);
        for bad in [
            "../secret",
            "sha256:../secret",
            "..//secret",
            "sha256:../../secret0000000000000000000000000000000000000000000000",
            "x",
            "",
            "é",
            "sha256:é",
        ] {
            assert!(open(&provider, bad).await.is_none(), "{bad:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_what_is_too_big_for_a_peer_is_not_read() {
        let dir = tempdir().unwrap();
        let file_store = Arc::new(FileStore::new(dir.path().join("files")).unwrap());
        let db = Database::open(dir.path().join("test.db")).await.unwrap();
        let provider = StorageChunkProvider::new(file_store.clone(), db);
        let big = vec![3u8; MAX_SERVED_BYTES + 1];
        let in_store = file_store
            .put(velarx_types::digest::Algorithm::Sha256, &big)
            .unwrap();
        assert!(open(&provider, &in_store).await.is_none());
        let ok = file_store
            .put(
                velarx_types::digest::Algorithm::Sha256,
                &big[..MAX_SERVED_BYTES],
            )
            .unwrap();
        assert_eq!(read(&provider, &ok).await.unwrap().len(), MAX_SERVED_BYTES);
    }

    /// A file the EROFS image of a layer holds is served as a range of the
    /// image, and so is a chunk of it, as an object and a chunk of an object
    /// are: the peer is told nothing about where the file is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_a_file_an_image_holds_is_served_as_a_range_of_the_image() {
        use velarx_db::{InlinedFile, LayerCommit, LayerKey, LayerRecord};
        use velarx_storage::VerityHasher;
        use velarx_types::digest::Algorithm;
        let dir = tempdir().unwrap();
        let objects = dir.path().join("objects");
        let file_store = Arc::new(FileStore::new(&objects).unwrap());
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let sha = |b: &[u8]| Digest::of(Algorithm::Sha256, b);
        let mut hasher = VerityHasher::new(Algorithm::Sha256);
        hasher.update(b"hello world");
        let file = hasher.finish();
        let layer = LayerKey::Whole(sha(b"layer"));
        let mut image = vec![b'.'; 64];
        image[20..31].copy_from_slice(b"hello world");
        let path = velarx_fuse::composefs::layer_image_path(&objects, &layer.file_stem());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, image).unwrap();
        let chunk = sha(b"world");
        db.commit_layers(
            vec![LayerCommit {
                record: LayerRecord {
                    stream_size: Some(0),
                    inline: -1,
                    key: layer,
                    blob: None,
                    diff_id: Some(sha(b"diff")),
                    other_diff_id: None,
                    size: 1,
                    status: "ready".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    registry_ref: None,
                    erofs: Some("sha256:a".into()),
                    owners: Some("[]".into()),
                },
                files: vec![],
                refs: vec![],
                chunks: vec![ChunkLocation {
                    chunk_digest: chunk,
                    file_digest: file.clone(),
                    offset: 6,
                    size: 5,
                }],
                toc_digest: sha(b"toc"),
                tarsplit: None,
                blob_checked: false,
                sealed: false,
                inlined: vec![InlinedFile {
                    digest: file.clone(),
                    offset: 20,
                    size: 11,
                }],
            }],
            vec![],
        )
        .await
        .unwrap();
        let provider = StorageChunkProvider::new(file_store, db);
        assert_eq!(read(&provider, &file).await.unwrap(), b"hello world");
        assert_eq!(read(&provider, &chunk.to_string()).await.unwrap(), b"world");
    }
}
