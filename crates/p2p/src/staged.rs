// SPDX-License-Identifier: Apache-2.0
//! The files this node staged for a pull that is still going on, given to
//! the peers as they are complete: each chunk of them was hashed when it
//! arrived and the file was named (and measured) before it is listed here,
//! and the asker checks every chunk again.  The nodes of a rollout then
//! serve each other what they have while the seed serves the rest, instead
//! of everyone waiting for a layer to be complete.
//!
//! Only the files of the most recent pulls are kept (a descriptor each, at
//! most [`MAX_FILES`]); the store service gives the rest once the layer is
//! in the store.

use crate::ChunkProvider;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::{Arc, Mutex};
use velarx_storage::ChunkFile;

/// The files kept, at most (a descriptor each).
pub const MAX_FILES: usize = 128;

/// The layers told to the peers as held, at most.
const MAX_LAYERS: usize = 1024;

/// A file kept: its id, its layer and the digests of the chunks it holds.
struct Kept {
    id: u64,
    layer: Option<String>,
    digests: Vec<String>,
}

#[derive(Default)]
struct Inner {
    /// The files kept, the oldest first, with the digests they hold
    files: VecDeque<Kept>,
    /// Where each digest is: the file, the offset and the length
    chunks: HashMap<String, (u64, Arc<File>, u64, u64)>,
    next: u64,
    layers: HashSet<String>,
}

impl Inner {
    fn drop_oldest(&mut self) {
        if let Some(id) = self.files.front().map(|f| f.id) {
            self.drop_file(id);
        }
    }

    fn drop_file(&mut self, id: u64) {
        let Some(at) = self.files.iter().position(|f| f.id == id) else {
            return;
        };
        let Some(kept) = self.files.remove(at) else {
            return;
        };
        for d in kept.digests {
            if self.chunks.get(&d).is_some_and(|c| c.0 == id) {
                self.chunks.remove(&d);
            }
        }
    }
}

#[derive(Default)]
pub struct Staged(Mutex<Inner>);

impl Staged {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `file` of `layer` is staged and holds the chunks `held` (digest,
    /// offset, length).
    pub fn add(&self, layer: Option<&str>, file: File, held: Vec<(String, u64, u64)>) {
        let mut inner = self.lock();
        let id = inner.next;
        inner.next += 1;
        let file = Arc::new(file);
        let mut digests = Vec::with_capacity(held.len());
        for (digest, offset, len) in held {
            inner
                .chunks
                .insert(digest.clone(), (id, file.clone(), offset, len));
            digests.push(digest);
        }
        inner.files.push_back(Kept {
            id,
            layer: layer.map(str::to_string),
            digests,
        });
        while inner.files.len() > MAX_FILES {
            inner.drop_oldest();
        }
    }

    /// The files kept for `layers` are not needed (the store has them or
    /// lost them).
    pub fn release(&self, layers: &[String]) {
        let mut inner = self.lock();
        let gone: Vec<u64> = inner
            .files
            .iter()
            .filter(|f| f.layer.as_ref().is_some_and(|l| layers.contains(l)))
            .map(|f| f.id)
            .collect();
        for id in gone {
            inner.drop_file(id);
        }
    }

    /// Whether `layer` is told as held now for the first time.
    pub fn first_of(&self, layer: &str) -> bool {
        let mut inner = self.lock();
        if inner.layers.len() >= MAX_LAYERS {
            inner.layers.clear();
        }
        inner.layers.insert(layer.to_string())
    }

    /// The file of the chunk `digest`, if it is kept.
    pub fn open(&self, digest: &str) -> Option<ChunkFile> {
        let (_, file, offset, len) = self.lock().chunks.get(digest).cloned()?;
        Some(ChunkFile {
            file: file.try_clone().ok()?,
            offset,
            len,
        })
    }
}

/// What this node gives the peers: the files it staged, then the store.
pub struct Given {
    pub store: Arc<dyn ChunkProvider>,
    pub staged: Arc<Staged>,
}

impl ChunkProvider for Given {
    fn get_chunk(&self, digest: &str) -> io::Result<Option<Vec<u8>>> {
        match self.staged.open(digest) {
            Some(c) if c.len <= crate::limits::MAX_ITEM_BYTES as u64 => {
                let mut bytes = vec![0u8; c.len as usize];
                c.file.read_exact_at(&mut bytes, c.offset)?;
                Ok(Some(bytes))
            }
            _ => self.store.get_chunk(digest),
        }
    }

    fn get_index(&self, layer: &str) -> io::Result<Option<Vec<u8>>> {
        self.store.get_index(layer)
    }

    fn release(&self, layers: &[String]) {
        self.staged.release(layers);
    }

    fn get_profile(&self, image: &str) -> io::Result<Option<Vec<u8>>> {
        self.store.get_profile(image)
    }

    fn open_chunks(&self, digests: &[String]) -> io::Result<Vec<Option<ChunkFile>>> {
        let mut found: Vec<Option<ChunkFile>> =
            digests.iter().map(|d| self.staged.open(d)).collect();
        let missing: Vec<String> = digests
            .iter()
            .zip(&found)
            .filter(|(_, f)| f.is_none())
            .map(|(d, _)| d.clone())
            .collect();
        if missing.is_empty() {
            return Ok(found);
        }
        let mut more = self.store.open_chunks(&missing)?.into_iter();
        for slot in found.iter_mut().filter(|f| f.is_none()) {
            *slot = more.next().flatten();
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Store;
    impl ChunkProvider for Store {
        fn get_chunk(&self, digest: &str) -> io::Result<Option<Vec<u8>>> {
            Ok((digest == "in-store").then(|| b"store".to_vec()))
        }
    }

    fn file_of(bytes: &[u8]) -> File {
        let mut f = tempfile::tempfile().unwrap();
        io::Write::write_all(&mut f, bytes).unwrap();
        f
    }

    #[test]
    fn a_staged_file_is_given_before_the_store_and_the_oldest_go() {
        let staged = Arc::new(Staged::default());
        let given = Given {
            store: Arc::new(Store),
            staged: staged.clone(),
        };
        staged.add(
            Some("layer-1"),
            file_of(b"aaaabbbb"),
            vec![("a".into(), 0, 4), ("b".into(), 4, 4)],
        );
        assert_eq!(given.get_chunk("b").unwrap().unwrap(), b"bbbb");
        assert_eq!(given.get_chunk("in-store").unwrap().unwrap(), b"store");
        assert_eq!(given.get_chunk("none").unwrap(), None);
        let opened = given
            .open_chunks(&["a".into(), "none".into(), "b".into()])
            .unwrap();
        assert_eq!(
            opened.iter().map(|c| c.is_some()).collect::<Vec<_>>(),
            [true, false, true]
        );
        for n in 0..MAX_FILES {
            staged.add(None, file_of(b"x"), vec![(format!("n{n}"), 0, 1)]);
        }
        assert!(staged.open("a").is_none() && staged.open("b").is_none());
        assert!(staged.open("n0").is_some());
        assert!(staged.first_of("layer") && !staged.first_of("layer"));
    }

    #[test]
    fn the_files_of_a_layer_go_when_the_store_has_it() {
        let staged = Staged::default();
        staged.add(Some("one"), file_of(b"11"), vec![("a".into(), 0, 2)]);
        staged.add(Some("two"), file_of(b"22"), vec![("b".into(), 0, 2)]);
        staged.release(&["one".to_string()]);
        assert!(staged.open("a").is_none());
        assert!(staged.open("b").is_some());
    }
}
