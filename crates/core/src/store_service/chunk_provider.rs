// SPDX-License-Identifier: Apache-2.0
//! The chunks of the store, for the store service (`crate::store_service`)
//! to hand over to the services that give them to others.
//!
//! Chunks can be served from:
//! 1. File store (complete files stored by file digest)
//! 2. Database chunk_locations (extract chunk from stored file at offset)

use std::sync::Arc;
use velarx_db::{ChunkLocation, Database};
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
        let files = self.file_store.clone();
        tokio::task::spawn_blocking(move || {
            wanted
                .into_iter()
                .map(|(digest, location)| Self::opened(&files, &digest, location))
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    /// The file of `digest`: the whole file the file store has by that
    /// digest, else the piece of a file `location` says.  Blocking.
    fn opened(
        files: &FileStore,
        digest: &Digest,
        location: Option<ChunkLocation>,
    ) -> Option<ChunkFile> {
        let max = MAX_SERVED_BYTES as u64;
        let whole = files.get_path(&digest.to_string()).and_then(|path| {
            let file = std::fs::File::open(path).ok()?;
            let len = file.metadata().ok()?.len();
            (len <= max).then_some(ChunkFile {
                file,
                offset: 0,
                len,
            })
        });
        if whole.is_some() {
            return whole;
        }
        let loc = location.filter(|loc| loc.size <= max)?;
        let file = std::fs::File::open(files.get_path(&loc.file_digest)?).ok()?;
        let end = loc.offset.checked_add(loc.size)?;
        (file.metadata().ok()?.len() >= end).then_some(ChunkFile {
            file,
            offset: loc.offset,
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
}
