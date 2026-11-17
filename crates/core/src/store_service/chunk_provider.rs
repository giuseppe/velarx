// SPDX-License-Identifier: Apache-2.0
//! The chunks of the store, for the store service (`crate::store_service`)
//! to hand over to the services that give them to others.
//!
//! Chunks can be served from:
//! 1. File store (complete files stored by file digest)
//! 2. Database chunk_locations (extract chunk from stored file at offset)

use std::sync::Arc;
use velarx_db::Database;
use velarx_storage::{ChunkFile, FileStore, MAX_SERVED_BYTES};

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

    /// The file that holds `digest` (a cached chunk, a file, or a chunk of a
    /// file), if the stores have it and it is small enough to serve.
    pub async fn open(&self, digest: &str) -> Option<ChunkFile> {
        let parsed = velarx_types::digest::Digest::parse_key(digest).ok()?;
        let files = self.file_store.clone();
        let d = digest.to_string();
        let whole = tokio::task::spawn_blocking(move || {
            let max = MAX_SERVED_BYTES as u64;
            let path = files.get_path(&d)?;
            let file = std::fs::File::open(path).ok()?;
            let len = file.metadata().ok()?.len();
            (len <= max).then_some(ChunkFile {
                file,
                offset: 0,
                len,
            })
        })
        .await
        .ok()
        .flatten();
        if whole.is_some() || parsed.is_fsverity() {
            // (the fs-verity digest of a file names an object, never a chunk)
            return whole;
        }
        let loc = self.db.get_chunk_location(&parsed).await.ok().flatten()?;
        if loc.size > MAX_SERVED_BYTES as u64 {
            return None;
        }
        let path = self.file_store.get_path(&loc.file_digest)?;
        tokio::task::spawn_blocking(move || {
            let file = std::fs::File::open(path).ok()?;
            let end = loc.offset.checked_add(loc.size)?;
            (file.metadata().ok()?.len() >= end).then_some(ChunkFile {
                file,
                offset: loc.offset,
                len: loc.size,
            })
        })
        .await
        .ok()
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};
    use tempfile::tempdir;

    /// The bytes `open` gives for `digest`.
    async fn read(provider: &StorageChunkProvider, digest: &str) -> Option<Vec<u8>> {
        let mut found = provider.open(digest).await?;
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
            assert!(provider.open(bad).await.is_none(), "{bad:?}");
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
        assert!(provider.open(&in_store).await.is_none());
        let ok = file_store
            .put(
                velarx_types::digest::Algorithm::Sha256,
                &big[..MAX_SERVED_BYTES],
            )
            .unwrap();
        assert_eq!(read(&provider, &ok).await.unwrap().len(), MAX_SERVED_BYTES);
    }
}
