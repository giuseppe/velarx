// SPDX-License-Identifier: Apache-2.0
//! `velarx-p2p serve --dir DIR`: a node that gives the files of a directory
//! to its peers, with no engine and no store service.  Each regular file
//! under the directory is a chunk, asked for by the sha256 of its bytes.

use crate::ChunkProvider;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use velarx_storage::ChunkFile;
use velarx_types::digest::{Algorithm, Digest};

/// The files of a directory by the sha256 of their bytes.
pub struct Directory {
    files: HashMap<String, PathBuf>,
}

impl Directory {
    /// Read `dir`: every regular file under it (links are not followed) is
    /// hashed; a file larger than a peer may take is left out.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let mut files = HashMap::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(d) = todo.pop() {
            for entry in std::fs::read_dir(&d)? {
                let entry = entry?;
                let path = entry.path();
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    todo.push(path);
                } else if kind.is_file()
                    && entry.metadata()?.len() <= crate::limits::MAX_ITEM_BYTES as u64
                {
                    let digest = Digest::of_reader(Algorithm::Sha256, std::fs::File::open(&path)?)?;
                    files.insert(digest.to_string(), path);
                }
            }
        }
        Ok(Self { files })
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The digests of the files.
    pub fn digests(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }
}

impl ChunkProvider for Directory {
    fn get_chunk(&self, digest: &str) -> io::Result<Option<Vec<u8>>> {
        match self.files.get(digest) {
            Some(path) => std::fs::read(path).map(Some),
            None => Ok(None),
        }
    }

    fn open_chunks(&self, digests: &[String]) -> io::Result<Vec<Option<ChunkFile>>> {
        digests
            .iter()
            .map(|d| match self.files.get(d) {
                Some(path) => {
                    let file = std::fs::File::open(path)?;
                    let len = file.metadata()?.len();
                    Ok(Some(ChunkFile {
                        file,
                        offset: 0,
                        len,
                    }))
                }
                None => Ok(None),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_are_given_by_the_digest_of_their_bytes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("a"), b"alpha").unwrap();
        std::fs::write(dir.path().join("sub/b"), b"beta").unwrap();
        // (too large for a peer: left out)
        std::fs::File::create(dir.path().join("big"))
            .unwrap()
            .set_len(crate::limits::MAX_ITEM_BYTES as u64 + 1)
            .unwrap();
        let d = Directory::open(dir.path()).unwrap();
        assert_eq!(d.len(), 2);
        let alpha = Digest::of(Algorithm::Sha256, b"alpha").to_string();
        assert_eq!(d.get_chunk(&alpha).unwrap().unwrap(), b"alpha");
        assert_eq!(d.get_chunk("sha256:00").unwrap(), None);
        let opened = d.open_chunks(&[alpha, "sha256:00".into()]).unwrap();
        assert_eq!(opened[0].as_ref().map(|c| c.len), Some(5));
        assert!(opened[1].is_none());
    }
}
