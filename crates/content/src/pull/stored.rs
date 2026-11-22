// SPDX-License-Identifier: Apache-2.0
//! What a layer keeps of its metadata, as files of its directory
//! ([`velarx_db::layer_files`]): the compressed table of contents and the
//! compressed tar-split.
//!
//! A layer pulled by its table (a `toc:` key) keeps the table as the registry
//! sent it, which its checksum covers, a binary table or the JSON; any
//! other layer keeps the zstd of the JSON of its table of contents (so does
//! a layer of a table that the engine only knows by the view it stores).  The
//! view of the filesystem a layer is stored by is made from the file by
//! [`stored_view`], whichever it holds.

use super::chunked::{decompress_bounded, parse_toc};
use super::LayerDone;
use std::path::Path;
use velarx_db::{layer_files, Database};
use velarx_storage::{table, Toc};
use velarx_types::digest::Digest;
use velarx_types::{ImageError, ImageResult, LayerKey};

/// The zstd of the JSON of `toc`: what the file of a layer that is not
/// pulled by its table holds.
pub fn json_z(toc: &Toc) -> bytes::Bytes {
    let json = serde_json::to_vec(toc).expect("a table of contents is JSON");
    zstd::encode_all(&json[..], velarx_tarsplit::ZSTD_LEVEL)
        .expect("zstd compresses memory")
        .into()
}

impl LayerDone {
    /// The digest of `toc.zst`, in the algorithm of the layer.
    pub fn toc_digest(&self) -> Digest {
        Digest::of(self.key.digest().alg(), &self.toc_z)
    }

    /// The digest of `tarsplit.zst`; none for a canonical layer, which has
    /// no such file.
    pub fn tarsplit_digest(&self) -> Option<Digest> {
        (!self.tarsplit.is_empty()).then(|| Digest::of(self.key.digest().alg(), &self.tarsplit))
    }

    /// Write the files of the layer into the store `root`, to be made
    /// durable by the barrier of the store before a row names the layer.
    pub fn write_files(&self, root: &Path) -> std::io::Result<()> {
        layer_files::write(root, &self.key, layer_files::TOC, &self.toc_z)?;
        if !self.tarsplit.is_empty() {
            layer_files::write(root, &self.key, layer_files::TARSPLIT, &self.tarsplit)?;
        }
        Ok(())
    }
}

/// The table of contents the layer `key` is stored by, made from the content
/// of its `toc.zst`: a table is read as it is (it gives the stored view), and
/// a JSON table of contents of a layer that is not canonical is made the
/// stored view of the layer if it is a layer of a table (the JSON of any
/// other is its view already).
pub fn stored_view(toc_z: &[u8], key: &LayerKey) -> ImageResult<Toc> {
    let raw = decompress_bounded(toc_z, velarx_tarsplit::MAX_SIZE, 0, "table of contents")?;
    if raw.starts_with(table::MAGIC) {
        return table::decode(&raw, u64::MAX)
            .map_err(|e| ImageError::Layer(format!("layer {key}: its table: {e}")));
    }
    let toc =
        parse_toc(&raw).map_err(|e| ImageError::Layer(format!("layer {key}: its table: {e}")))?;
    if toc.is_canonical() || !key.is_toc() {
        return Ok(toc);
    }
    let digest = key.digest();
    super::lazy::toc_view(toc, digest.alg(), digest)
}

/// The table of contents the layer `key` is stored by, read from its file
/// (checked against its digest): none if the layer keeps none.
pub async fn stored_toc(db: &Database, key: &LayerKey) -> ImageResult<Option<Toc>> {
    let Some(toc_z) = db.get_layer_toc_z(key).await? else {
        return Ok(None);
    };
    let key = *key;
    tokio::task::spawn_blocking(move || stored_view(&toc_z, &key).map(Some))
        .await
        .map_err(|e| ImageError::Layer(format!("the table of layer {key}: {e}")))?
}

/// The tables of contents the layers `keys` are stored by, in their order:
/// a layer that keeps none is an error.
pub async fn stored_tocs(db: &Database, keys: &[LayerKey]) -> ImageResult<Vec<Toc>> {
    let mut tocs = Vec::new();
    for key in keys {
        tocs.push(stored_toc(db, key).await?.ok_or_else(|| {
            ImageError::Layer(format!("the layer {key} has no table of contents"))
        })?);
    }
    Ok(tocs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use velarx_types::digest::Algorithm;

    fn toc_of(json: &str) -> Toc {
        serde_json::from_str(json).unwrap()
    }

    fn file() -> String {
        format!("sha256-12:{}", "cd".repeat(32))
    }

    /// The file of a layer pulled by its table holds the table as it was
    /// sent, which gives the stored view as it is.
    #[test]
    fn a_table_file_gives_the_stored_view() {
        let toc = toc_of(r#"{"version":2,"entries":[{"name":"etc","type":"dir","mode":493}]}"#);
        let table = table::encode(&toc, Algorithm::Sha256).unwrap();
        let toc_z = zstd::encode_all(&table[..], 3).unwrap();
        let key = LayerKey::Toc(Digest::of(Algorithm::Sha256, &toc_z));
        let view = stored_view(&toc_z, &key).unwrap();
        assert!(view.is_canonical());
        assert_eq!(view.entries.len(), toc.entries.len());
        assert_eq!(view.entries[0].name, "./etc/");
    }

    /// The file of any other layer holds the JSON of its stored view; the
    /// JSON the registry sent for a layer of a table is made its view.
    #[test]
    fn a_json_file_gives_the_stored_view() {
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"layer"));
        let stored = toc_of(&format!(
            r#"{{"version":1,"entries":[{{"name":"f","type":"reg","size":4,"fsverity":"{}"}}]}}"#,
            file()
        ));
        let toc_z = zstd::encode_all(&serde_json::to_vec(&stored).unwrap()[..], 3).unwrap();
        let view = stored_view(&toc_z, &key).unwrap();
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            serde_json::to_value(&stored).unwrap(),
            "a stored view is its own view"
        );
        // (a canonical table is read as it is)
        let canonical = toc_of(r#"{"version":2,"entries":[]}"#);
        let toc_z = zstd::encode_all(&serde_json::to_vec(&canonical).unwrap()[..], 3).unwrap();
        assert!(stored_view(&toc_z, &key).unwrap().is_canonical());
        // a file that is not compressed is no table
        assert!(stored_view(b"{}", &key).is_err());
    }

    /// The files of a layer are written before its row, read back by the
    /// row's digests, and a damaged one is refused.
    #[tokio::test]
    async fn the_files_of_a_layer_are_written_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(dir.path().join("db.sqlite")).await.unwrap();
        let key = LayerKey::Whole(Digest::of(Algorithm::Sha256, b"blob"));
        let toc = toc_of(&format!(
            r#"{{"version":1,"entries":[{{"name":"f","type":"reg","size":4,"fsverity":"{}"}}]}}"#,
            file()
        ));
        let done = LayerDone {
            key,
            blob: Digest::of(Algorithm::Sha256, b"blob"),
            diff_id: Digest::of(Algorithm::Sha256, b"stream"),
            size: 4,
            toc_z: json_z(&toc),
            toc: Arc::new(toc.clone()),
            files: Vec::new(),
            chunks: Vec::new(),
            report: Default::default(),
            tarsplit: bytes::Bytes::from(zstd::encode_all(&b""[..], 0).unwrap()),
            lazy: false,
            blob_checked: true,
            checked: Default::default(),
        };
        done.write_files(dir.path()).unwrap();
        db.commit_layers(
            vec![super::super::layer_commit(&done, None).unwrap()],
            vec![],
        )
        .await
        .unwrap();
        let read = stored_toc(&db, &key).await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&read).unwrap(),
            serde_json::to_value(&toc).unwrap()
        );
        assert_eq!(
            db.get_layer_tarsplit(&key).await.unwrap().unwrap(),
            done.tarsplit.to_vec()
        );
        let path = layer_files::file(dir.path(), &key, layer_files::TOC, &done.toc_digest());
        std::fs::write(&path, b"damaged").unwrap();
        assert!(stored_toc(&db, &key).await.is_err());
        // a layer of a table keeps the table as it was sent, whose digest
        // is the checksum of its key
        let table = LayerDone {
            key: LayerKey::Toc(Digest::of(Algorithm::Sha256, b"table")),
            toc_z: bytes::Bytes::from_static(b"table"),
            ..done
        };
        assert_eq!(table.toc_digest(), *table.key.digest());
    }
}
