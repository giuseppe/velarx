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
    let mut tmp = tempfile::Builder::new().prefix(".tmp").tempfile_in(&dir)?;
    tmp.write_all(bytes)?;
    tmp.persist(file(root, key, kind, &digest))
        .map_err(|e| e.error)?;
    Ok(digest)
}

/// The bytes of the file of the kind `kind` of the layer `key` that has the
/// digest `expected`, if they have it.
pub fn read(root: &Path, key: &LayerKey, kind: &str, expected: &Digest) -> io::Result<Vec<u8>> {
    let path = file(root, key, kind, expected);
    let bytes = std::fs::read(&path)?;
    if Digest::of(expected.alg(), &bytes) != *expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: not the file with the digest {expected}",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Remove the directory of the layer `key`, if it is there.
pub fn remove_layer(root: &Path, key: &LayerKey) -> io::Result<()> {
    match velarx_base::tree::remove_dir_all(layer_dir(root, key)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_types::digest::Algorithm;

    #[test]
    fn a_file_is_read_only_with_its_digest() {
        let root = tempfile::tempdir().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let bytes = b"table";
        let good = write(root.path(), &key, TOC, bytes).unwrap();
        assert_eq!(good, Digest::of(Algorithm::Sha256, bytes));
        assert_eq!(read(root.path(), &key, TOC, &good).unwrap(), bytes);
        // (a name is the digest of the bytes it holds: damage is found)
        let path = file(root.path(), &key, TOC, &good);
        std::fs::write(&path, b"damaged").unwrap();
        let e = read(root.path(), &key, TOC, &good).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let wrong = Digest::of(Algorithm::Sha256, b"other");
        let e = read(root.path(), &key, TOC, &wrong).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        remove_layer(root.path(), &key).unwrap();
        assert!(!layer_dir(root.path(), &key).exists());
        remove_layer(root.path(), &key).unwrap();
    }

    /// A layer committed again with other bytes (another build encodes the
    /// JSON another way) leaves the file its row names as it is.
    #[test]
    fn other_bytes_for_a_layer_are_another_file() {
        let root = tempfile::tempdir().unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let a = write(root.path(), &key, TOC, b"json of a build").unwrap();
        let b = write(root.path(), &key, TOC, b"json of another").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            read(root.path(), &key, TOC, &a).unwrap(),
            b"json of a build"
        );
        assert_eq!(
            read(root.path(), &key, TOC, &b).unwrap(),
            b"json of another"
        );
        // (the same bytes are the same name)
        assert_eq!(
            write(root.path(), &key, TOC, b"json of a build").unwrap(),
            a
        );
        assert_eq!(
            read(root.path(), &key, TOC, &a).unwrap(),
            b"json of a build"
        );
    }
}
