// SPDX-License-Identifier: Apache-2.0
//! The tar-split of a zstd:chunked layer, and its replay: the package
//! `velarx-tarsplit`, and the one thing that ties it to the TOC of the
//! store.

pub use velarx_tarsplit::*;

use velarx_storage::Toc;

/// The regular files of `toc`, in the order of the layer, by the key their
/// content is found by: the fs-verity digest of the file, or the sha256 of
/// its content where the TOC gives no fs-verity digest (a layer being
/// pulled).  The slot of a file is the index of its TOC entry.
pub fn content_index(toc: &Toc) -> ContentIndex {
    ContentIndex::new(toc.entries.iter().enumerate().filter_map(|(slot, e)| {
        if !e.has_content() {
            return None;
        }
        Some(ContentFile {
            name: e.name.clone(),
            size: e.size,
            key: e.content_key()?,
            slot,
        })
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toc(entries: &str) -> Toc {
        serde_json::from_str(&format!(r#"{{"version":1,"entries":[{entries}]}}"#)).unwrap()
    }

    #[test]
    fn the_index_of_a_toc_has_its_regular_files_by_slot() {
        let toc = toc(concat!(
            r#"{"type":"dir","name":"d/"},"#,
            r#"{"type":"reg","name":"./d/a","size":3,"digest":"sha256:aa"},"#,
            r#"{"type":"reg","name":"d/empty","size":0},"#,
            r#"{"type":"symlink","name":"d/l","linkName":"a"},"#,
            r#"{"type":"reg","name":"d/a","size":4,"digest":"sha256:bb"}"#,
        ));
        let mut index = content_index(&toc);
        // the same name twice: in the order of the layer
        let file = |size, key: &str, slot| ContentFile {
            name: "d/a".into(),
            size,
            key: key.into(),
            slot,
        };
        assert_eq!(index.take("d/a", 3).unwrap(), file(3, "sha256:aa", 1));
        assert_eq!(index.take("./d/a", 4).unwrap(), file(4, "sha256:bb", 4));
        assert!(index.take("d/a", 4).is_err());
        assert!(index.take("d/empty", 0).is_err());
    }
}
