// SPDX-License-Identifier: Apache-2.0
//! The files of a layer: its table of contents (`toc-<hex>.zst`) and its
//! tar-split (`tarsplit-<hex>.zst`), in the directory
//! `<store>/layers/<stem>/` (the stem is [`LayerKey::file_stem`]).  A file
//! is named by its digest (`<hex>`, in the algorithm of the layer), so a
//! name is only ever written with the bytes it says: the file a row names is
//! never replaced, and a layer committed again with other bytes (another
//! build encodes its JSON another way) has the new file beside the old one,
//! which goes with the layer.  They are made before the row that names the
//! layer; the row keeps their digests (`layers.toc_digest`,
//! `layers.tarsplit_digest`), and a file is checked against its digest
//! whenever it is read.

use std::collections::HashSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use velarx_types::digest::Digest;
use velarx_types::LayerKey;

/// The directory of the layers' directories, in the store.
pub const DIR: &str = "layers";
/// The compressed table of contents.
pub const TOC: &str = "toc";
/// The compressed tar-split of a layer that has one.
pub const TARSPLIT: &str = "tarsplit";

/// The directory of the layers' directories in the store `root`.
pub fn layers_dir(root: &Path) -> PathBuf {
    root.join(DIR)
}

/// The directory of the layer `key` in the store `root`.
pub fn layer_dir(root: &Path, key: &LayerKey) -> PathBuf {
    layers_dir(root).join(key.file_stem())
}

/// The directory of the store whose objects are `objects`: where its
/// database and the files of its layers are.
pub fn root_of(objects: &Path) -> &Path {
    objects
        .parent()
        .expect("the objects of a store are in its directory")
}

/// The file of the kind `kind` ([`TOC`] or [`TARSPLIT`]) of the layer `key`
/// that has the digest `digest`.
pub fn file(root: &Path, key: &LayerKey, kind: &str, digest: &Digest) -> PathBuf {
    layer_dir(root, key).join(format!("{kind}-{}.zst", digest.hex()))
}

/// Write the file of the kind `kind` of the layer `key` in the store `root`,
/// whole or not at all, and say its digest (in the algorithm of the layer),
/// which names it.  The caller makes the layer's files durable with the
/// barrier of the store before a row names the layer.
pub fn write(root: &Path, key: &LayerKey, kind: &str, bytes: &[u8]) -> io::Result<Digest> {
    let digest = Digest::of(key.digest().alg(), bytes);
    let dir = layer_dir(root, key);
    velarx_base::ipc::create_private_dirs(&dir)?;
    // (made in `layers/`, where `sweep` finds what a writer that died left)
    let mut tmp = tempfile::Builder::new()
        .prefix(".tmp")
        .tempfile_in(layers_dir(root))?;
    tmp.write_all(bytes)?;
    tmp.persist(file(root, key, kind, &digest))
        .map_err(|e| e.error)?;
    Ok(digest)
}

/// Where the files of the layers of a store are read from: its directory,
/// or the storage driver that keeps them (a service of another process).
/// What a source gives is not trusted: the reader checks it against the
/// digest of the row.
pub trait Source: Send + Sync {
    /// The bytes of the file of the kind `kind` of the layer `key` that has
    /// the digest `digest`.
    fn read(&self, key: &LayerKey, kind: &str, digest: &Digest) -> io::Result<Vec<u8>>;
}

/// The files of the layers in the directory of the store `root`.
pub struct Directory(pub PathBuf);

impl Source for Directory {
    fn read(&self, key: &LayerKey, kind: &str, digest: &Digest) -> io::Result<Vec<u8>> {
        std::fs::read(file(&self.0, key, kind, digest))
    }
}

/// The source of the files in the directory of the store `root`, shared by
/// the clones of a database.
pub(crate) fn of_directory(
    root: Option<&Path>,
) -> std::sync::Arc<std::sync::RwLock<Option<std::sync::Arc<dyn Source>>>> {
    let source: Option<std::sync::Arc<dyn Source>> =
        root.map(|r| std::sync::Arc::new(Directory(r.to_path_buf())) as _);
    std::sync::Arc::new(std::sync::RwLock::new(source))
}

/// `bytes`, if their digest is `expected`.
pub fn checked(bytes: Vec<u8>, expected: &Digest) -> io::Result<Vec<u8>> {
    match Digest::of(expected.alg(), &bytes) == *expected {
        true => Ok(bytes),
        false => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not the file with the digest {expected}"),
        )),
    }
}

/// Remove what `<store>/layers/` has that no layer of `keep` (the names of
/// the directories of the layers the store has rows for) owns: a directory
/// of a layer that no row names (a pull that wrote its files and was not
/// committed) and the temporary file of a writer that died.  Returns the
/// bytes freed.  The caller holds the lock of the store exclusive: no pull is
/// between writing the files of a layer and committing its row.
pub fn sweep(root: &Path, keep: &HashSet<String>) -> io::Result<u64> {
    let entries = match std::fs::read_dir(layers_dir(root)) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut freed = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep.contains(&name) {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            for file in std::fs::read_dir(&path)? {
                freed += file?.metadata()?.len();
            }
            velarx_base::tree::remove_dir_all(&path)?;
        } else {
            freed += entry.metadata()?.len();
            std::fs::remove_file(&path)?;
        }
    }
    Ok(freed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    /// What no row names, and a writer's temporary file, go; what a row
    /// names stays; a store with no `layers/` has nothing to sweep.
    #[test]
    fn the_sweep_removes_what_no_row_names() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(sweep(root.path(), &HashSet::new()).unwrap(), 0);
        let key = |s: &str| LayerKey::Whole(Digest::of(Algorithm::Sha256, s.as_bytes()));
        let (named, orphan) = (key("named"), key("orphan"));
        let table = write(root.path(), &named, TOC, b"table").unwrap();
        write(root.path(), &orphan, TOC, b"table").unwrap();
        write(root.path(), &orphan, TARSPLIT, b"tar-split").unwrap();
        std::fs::write(layers_dir(root.path()).join(".tmpabc"), b"half").unwrap();
        let keep = HashSet::from([named.file_stem()]);
        assert_eq!(sweep(root.path(), &keep).unwrap(), 5 + 9 + 4);
        assert!(file(root.path(), &named, TOC, &table).is_file());
        assert!(!layer_dir(root.path(), &orphan).exists());
        assert_eq!(
            std::fs::read_dir(layers_dir(root.path())).unwrap().count(),
            1
        );
        assert_eq!(sweep(root.path(), &keep).unwrap(), 0);
    }

    #[test]
    fn a_file_is_read_only_with_its_digest() {
        let root = tempfile::tempdir().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let bytes = b"table";
        let good = write(root.path(), &key, TOC, bytes).unwrap();
        assert_eq!(good, Digest::of(Algorithm::Sha256, bytes));
        let source = Directory(root.path().to_path_buf());
        let read = |expected: &Digest| checked(source.read(&key, TOC, expected)?, expected);
        assert_eq!(read(&good).unwrap(), bytes);
        // (a name is the digest of the bytes it holds: damage is found)
        let path = file(root.path(), &key, TOC, &good);
        std::fs::write(&path, b"damaged").unwrap();
        let e = read(&good).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let wrong = Digest::of(Algorithm::Sha256, b"other");
        let e = read(&wrong).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    /// A layer committed again with other bytes (another build encodes the
    /// JSON another way) leaves the file its row names as it is.
    #[test]
    fn other_bytes_for_a_layer_are_another_file() {
        let root = tempfile::tempdir().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let source = Directory(root.path().to_path_buf());
        let a = write(root.path(), &key, TOC, b"json of a build").unwrap();
        let b = write(root.path(), &key, TOC, b"json of another").unwrap();
        assert_ne!(a, b);
        assert_eq!(source.read(&key, TOC, &a).unwrap(), b"json of a build");
        assert_eq!(source.read(&key, TOC, &b).unwrap(), b"json of another");
        // (the same bytes are the same name)
        assert_eq!(
            write(root.path(), &key, TOC, b"json of a build").unwrap(),
            a
        );
        assert_eq!(source.read(&key, TOC, &a).unwrap(), b"json of a build");
    }
}
