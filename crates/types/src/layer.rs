// SPDX-License-Identifier: Apache-2.0
//! The identity of a stored layer.
//!
//! A layer is known by what verified it.  A layer pulled whole is checked
//! against the digest of its blob and its diff id: it is `Whole(blob)`.  A
//! layer of a descriptor with zstd:chunked labels is pulled through its table
//! of contents, which the descriptor vouches for (`manifest-checksum`); its
//! blob is never checked: it is `Toc(toc digest)`.  The two are never
//! mixed: a lookup of one kind never finds a layer of the other, so a store
//! never claims a blob it did not check, nor a TOC it did not read.

use crate::digest::Digest;
use crate::OciDescriptor;

/// The prefixes of the zstd:chunked annotations (containers/storage writes
/// the first, older writers the second).
pub const CHUNKED_PREFIXES: [&str; 2] = [
    "io.github.containers.zstd-chunked.",
    "io.containers.zstd-chunked.",
];

const TOC_PREFIX: &str = "toc:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LayerKey {
    /// Pulled whole: the blob digest and the diff id were checked.
    Whole(Digest),
    /// Pulled through the table of contents the descriptor names: the TOC
    /// digest (`manifest-checksum`), checked against the TOC bytes.
    Toc(Digest),
}

impl LayerKey {
    /// The key of `text`, as [`std::fmt::Display`] writes it: `sha256:<hex>`
    /// or `toc:sha256:<hex>`.
    pub fn parse(text: &str) -> Option<Self> {
        match text.strip_prefix(TOC_PREFIX) {
            Some(d) => d.parse().ok().map(Self::Toc),
            None => text.parse().ok().map(Self::Whole),
        }
    }

    /// The key a layer of `desc` is stored under when the route the
    /// descriptor asks for is taken: its TOC digest when it has
    /// zstd:chunked labels, else its blob.
    pub fn expected(desc: &OciDescriptor) -> Self {
        match chunked_checksum(desc) {
            Some(toc) => Self::Toc(toc),
            None => Self::Whole(desc.digest),
        }
    }

    /// Whether a layer stored under this key may stand for `desc`: its blob
    /// pulled whole, or the TOC its labels name.
    pub fn stands_for(&self, desc: &OciDescriptor) -> bool {
        match self {
            Self::Whole(d) => *d == desc.digest,
            Self::Toc(t) => chunked_checksum(desc) == Some(*t),
        }
    }

    /// The digest in the key.
    pub fn digest(&self) -> &Digest {
        match self {
            Self::Whole(d) | Self::Toc(d) => d,
        }
    }

    pub fn is_toc(&self) -> bool {
        matches!(self, Self::Toc(_))
    }

    /// The name of the files of the layer (its EROFS image, its chunk map):
    /// `<alg>-<hex>`, `toc-<alg>-<hex>`.
    pub fn file_stem(&self) -> String {
        match self {
            Self::Whole(d) => d.file_name(),
            Self::Toc(d) => format!("toc-{}", d.file_name()),
        }
    }
}

impl std::fmt::Display for LayerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Whole(d) => write!(f, "{d}"),
            Self::Toc(d) => write!(f, "{TOC_PREFIX}{d}"),
        }
    }
}

#[cfg(feature = "sqlite")]
impl rusqlite::types::ToSql for LayerKey {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.to_string().into())
    }
}

/// A text that is no key is an error of the row, never another kind of key.
#[cfg(feature = "sqlite")]
impl rusqlite::types::FromSql for LayerKey {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let text = value.as_str()?;
        Self::parse(text).ok_or_else(|| {
            rusqlite::types::FromSqlError::Other(format!("{text:?} is no layer key").into())
        })
    }
}

/// The OCI ChainIDs of the layers of an image, one per layer, in the order of
/// its `rootfs.diff_ids` (image-spec, `layer.md`, "ChainID"):
/// `ChainID(L0) = DiffID(L0)` and
/// `ChainID(Ln) = Digest(ChainID(Ln-1) + " " + DiffID(Ln))`, the digest made
/// with the algorithm of `DiffID(Ln)` (sha256 for every image in use).
///
/// A layer's chain id names the layer *as the top of that stack*: the same
/// content (one diff id) at another position, or on another base, has
/// another chain id.  The engine computes them (a driver is never trusted
/// with it, and nothing stores them: they come from the configuration of the
/// image); a driver whose layers are chained by parent (a snapshot of the
/// parent layer) keys on them, the others (composefs, vfs: content keyed)
/// ignore them.
pub fn chain_ids(diff_ids: &[Digest]) -> Vec<Digest> {
    let mut out: Vec<Digest> = Vec::with_capacity(diff_ids.len());
    for diff in diff_ids {
        let chain = match out.last() {
            None => *diff,
            Some(parent) => Digest::of(diff.alg(), format!("{parent} {diff}").as_bytes()),
        };
        out.push(chain);
    }
    out
}

/// The value of the zstd:chunked annotation `name` of `desc`.
pub fn chunked_annotation<'a>(desc: &'a OciDescriptor, name: &str) -> Option<&'a String> {
    CHUNKED_PREFIXES
        .iter()
        .find_map(|p| desc.annotations.get(&format!("{p}{name}")))
}

/// Whether `media_type` is a zstd layer, which may be zstd:chunked.
pub fn is_zstd(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.layer.v1.tar+zstd"
            | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
    )
}

/// The TOC digest of a descriptor with zstd:chunked labels: a zstd layer
/// with `manifest-checksum` and `manifest-position` (the two that podman
/// requires), the position of a TOC (its fourth field is 1: another kind
/// of manifest is no TOC to pull by).  None for any other: a descriptor
/// with one of the two is a layer pulled whole, and the blob is never
/// looked at to decide.
pub fn chunked_checksum(desc: &OciDescriptor) -> Option<Digest> {
    if !is_zstd(&desc.media_type) {
        return None;
    }
    let checksum = chunked_annotation(desc, "manifest-checksum")?;
    let position = chunked_annotation(desc, "manifest-position")?;
    (position.rsplit(':').next() == Some("1") && position.split(':').count() == 4)
        .then(|| checksum.parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const T: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn desc(media_type: &str, annotations: &[(&str, &str)]) -> OciDescriptor {
        OciDescriptor {
            media_type: media_type.into(),
            digest: D.parse().unwrap(),
            size: 1,
            annotations: annotations
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
    const CHECKSUM: &str = "io.github.containers.zstd-chunked.manifest-checksum";
    const POSITION: &str = "io.github.containers.zstd-chunked.manifest-position";

    #[test]
    fn a_key_is_written_and_read_in_its_namespace() {
        let whole = LayerKey::Whole(D.parse().unwrap());
        let toc = LayerKey::Toc(D.parse().unwrap());
        assert_eq!(whole.to_string(), D);
        assert_eq!(toc.to_string(), format!("toc:{D}"));
        assert_ne!(whole.to_string(), toc.to_string());
        assert_eq!(LayerKey::parse(&whole.to_string()), Some(whole));
        assert_eq!(LayerKey::parse(&toc.to_string()), Some(toc));
        assert_eq!(whole.file_stem(), format!("sha256-{}", &D[7..]));
        assert_eq!(toc.file_stem(), format!("toc-sha256-{}", &D[7..]));
        for bad in [
            "",
            "toc:",
            "toc:sha256:12",
            "sha256:12",
            "sha384:12",
            "toc:toc:x",
            "blob:sha256:1",
        ] {
            assert_eq!(LayerKey::parse(bad), None, "{bad}");
        }
        assert_eq!(LayerKey::parse(&format!("toc:toc:{D}")), None);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn a_key_is_stored_as_its_text() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE t (k TEXT)").unwrap();
        let (whole, toc) = (
            LayerKey::Whole(D.parse().unwrap()),
            LayerKey::Toc(T.parse().unwrap()),
        );
        for key in [whole, toc] {
            db.execute("DELETE FROM t", []).unwrap();
            db.execute("INSERT INTO t VALUES (?1)", [&key]).unwrap();
            // (the text of the rows written before the key mapped itself)
            let text: String = db.query_row("SELECT k FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(text, key.to_string());
            let back: LayerKey = db.query_row("SELECT k FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(back, key);
        }
        // a text that is no key, or no text, is an error of the row
        for bad in ["'blob:x'", "NULL", "1"] {
            db.execute_batch(&format!("DELETE FROM t; INSERT INTO t VALUES ({bad})"))
                .unwrap();
            let read = db.query_row("SELECT k FROM t", [], |r| r.get::<_, LayerKey>(0));
            assert!(read.is_err(), "{bad}");
        }
    }

    #[test]
    fn the_labels_of_the_descriptor_decide() {
        let labelled = desc(ZSTD, &[(CHECKSUM, T), (POSITION, "1:2:3:1")]);
        assert_eq!(
            LayerKey::expected(&labelled),
            LayerKey::Toc(T.parse().unwrap())
        );
        // the older prefix is a label too
        let older = desc(
            ZSTD,
            &[
                ("io.containers.zstd-chunked.manifest-checksum", T),
                ("io.containers.zstd-chunked.manifest-position", "1:2:3:1"),
            ],
        );
        assert_eq!(
            LayerKey::expected(&older),
            LayerKey::Toc(T.parse().unwrap())
        );
        // stripped, or half labelled, or not the position of a TOC, or not
        // zstd: whole
        for d in [
            desc(ZSTD, &[]),
            desc(ZSTD, &[(CHECKSUM, T)]),
            desc(ZSTD, &[(POSITION, "1:2:3:1")]),
            desc(ZSTD, &[(CHECKSUM, T), (POSITION, "1:2:3:2")]),
            desc(ZSTD, &[(CHECKSUM, T), (POSITION, "1:2:1")]),
            desc(
                "application/vnd.oci.image.layer.v1.tar+gzip",
                &[(CHECKSUM, T), (POSITION, "1:2:3:1")],
            ),
        ] {
            assert_eq!(LayerKey::expected(&d), LayerKey::Whole(D.parse().unwrap()));
        }
    }

    #[test]
    fn a_key_stands_for_the_descriptors_of_its_route_only() {
        let labelled = desc(ZSTD, &[(CHECKSUM, T), (POSITION, "1:2:3:1")]);
        let plain = desc(ZSTD, &[]);
        // a labelled layer that fell back is whole
        assert!(LayerKey::Whole(D.parse().unwrap()).stands_for(&labelled));
        assert!(LayerKey::Toc(T.parse().unwrap()).stands_for(&labelled));
        assert!(LayerKey::Whole(D.parse().unwrap()).stands_for(&plain));
        // a TOC never stands for a descriptor without its labels, nor a
        // blob for another blob, nor a TOC for its blob
        assert!(!LayerKey::Toc(T.parse().unwrap()).stands_for(&plain));
        assert!(!LayerKey::Toc(D.parse().unwrap()).stands_for(&labelled));
        assert!(!LayerKey::Whole(T.parse().unwrap()).stands_for(&labelled));
    }

    fn dig(s: &str) -> Digest {
        s.parse().unwrap()
    }

    /// The formula of the image-spec, computed outside this code (`printf
    /// "%s %s" PARENT DIFF | sha256sum`) for the diff ids sha256("a"),
    /// sha256("b") and sha256("c").
    #[test]
    fn chain_ids_are_the_oci_chain_ids() {
        let diffs = [
            dig("sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            dig("sha256:3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"),
            dig("sha256:2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"),
        ];
        let want = [
            "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "sha256:51c0c8ace48498d6f5fee6b0592cc06f2da0f3cbe09c5a34a97dce85c3889676",
            "sha256:2fce7f8ce91bcf0a1428b36e1024639fdbd9469eea762dba98aa749631885106",
        ];
        let got: Vec<String> = chain_ids(&diffs).iter().map(|d| d.to_string()).collect();
        assert_eq!(got, want);
        assert!(chain_ids(&[]).is_empty());
        // a prefix of the layers has the prefix of the chain
        assert_eq!(chain_ids(&diffs[..2]), chain_ids(&diffs)[..2]);
    }

    #[test]
    fn chain_ids_follow_the_algorithm_of_the_diff_ids() {
        let a = dig("sha512:1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
        let b = dig("sha512:5267768822ee624d48fce15ec5ca79cbd602cb7f4c2157a516556991f22ef8c7b5ef7b18d1ff41c59370efb0858651d44a936c11b7b144c48fe04df3c6a3e8da");
        let chain = chain_ids(&[a, b]);
        assert_eq!(chain[0], a);
        assert_eq!(chain[1].to_string(), "sha512:d0b215be4682c4225fccb233e7534001eb187f88d62b6efa871af384a6ba9a33c56fcb3022cec2fc217c68be741a9de2fecd8c636ed29018ff5c914b9c8b0c66");
    }

    /// The same content at another position is another chain: the point of
    /// a chain id.
    #[test]
    fn the_same_diff_id_at_another_position_has_another_chain_id() {
        let (a, b) = (dig(D), dig(T));
        let one = chain_ids(&[a, b, a]);
        assert_eq!(one[0], a);
        assert_ne!(one[0], one[2]);
        assert_ne!(chain_ids(&[b, a])[1], chain_ids(&[a, b])[1]);
    }
}
