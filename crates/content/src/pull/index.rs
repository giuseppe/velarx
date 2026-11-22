// SPDX-License-Identifier: Apache-2.0
//! The index of a layer: its TOC and its tar-split, what a node that
//! has the layer can give a peer pulling it, so that the peer takes the
//! files from nodes by digest instead of the whole blob from the registry.
//!
//! An index is named by the digest of its layer, not by its own: nothing in
//! it is trusted.  Its size and what it decodes to are bounded, the files
//! it names are checked against their digests when they arrive, and the
//! layer they make is checked against the diff id of the image's
//! configuration by replaying the tar-split: an index that lies makes a
//! pull fall back to the registry, nothing else.
//!
//! The encoding: `SHIDX1\n`, the length of the compressed TOC (8 bytes,
//! little endian), the TOC (JSON, or the binary table of a layer that has
//! one, as its descriptor vouches for it; zstd), the tar-split (zstd).

use super::entry::MAX_ENTRIES;
use std::io::Read;
use velarx_storage::Toc;

const MAGIC: &[u8] = b"SHIDX1\n";

/// The largest index: what a peer may send.
pub const MAX_INDEX: u64 = velarx_storage::MAX_SERVED_BYTES as u64;

/// The largest TOC JSON an index decodes to, whatever the layer.
const MAX_TOC_JSON: u64 = 32 * 1024 * 1024;

/// The largest TOC JSON of the index of a layer of `layer_size` bytes:
/// 16 times its size, at least 4 MiB, at most 32 MiB.
pub fn json_cap(layer_size: i64) -> u64 {
    (layer_size.max(0) as u64)
        .saturating_mul(16)
        .clamp(4 * 1024 * 1024, MAX_TOC_JSON)
}

/// A TOC whose entries are counted as they are read.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BoundedToc {
    version: i32,
    #[serde(deserialize_with = "bounded_entries")]
    entries: Vec<velarx_storage::TocEntry>,
    #[serde(default)]
    tar_split_digest: Option<String>,
}

fn bounded_entries<'de, D>(d: D) -> Result<Vec<velarx_storage::TocEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Entries;
    impl<'de> serde::de::Visitor<'de> for Entries {
        type Value = Vec<velarx_storage::TocEntry>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("the entries of a TOC")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(e) = seq.next_element()? {
                if out.len() >= MAX_ENTRIES {
                    return Err(serde::de::Error::custom("the TOC has too many entries"));
                }
                out.push(e);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Entries)
}

/// The index of a layer whose TOC (JSON) and compressed tar-split are
/// these; None when it would be larger than [`MAX_INDEX`].
pub fn encode(toc_json: &[u8], tarsplit_z: &[u8]) -> Option<Vec<u8>> {
    encode_compressed(&zstd::encode_all(toc_json, 3).ok()?, tarsplit_z)
}

/// [`encode`] of a TOC that is compressed already (the bytes of a
/// descriptor's checksum, which the index gives back as they were).
pub fn encode_compressed(toc_z: &[u8], tarsplit_z: &[u8]) -> Option<Vec<u8>> {
    let total = MAGIC.len() + 8 + toc_z.len() + tarsplit_z.len();
    if total as u64 > MAX_INDEX {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(toc_z.len() as u64).to_le_bytes());
    out.extend_from_slice(toc_z);
    out.extend_from_slice(tarsplit_z);
    Some(out)
}

/// The compressed TOC and the compressed tar-split of an index as they
/// are, for the caller to check them.
pub fn split(data: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if data.len() as u64 > MAX_INDEX {
        return Err("the index is too large".into());
    }
    let rest = data
        .strip_prefix(MAGIC)
        .ok_or_else(|| "not an index".to_string())?;
    if rest.len() < 8 {
        return Err("a truncated index".into());
    }
    let (len, rest) = rest.split_at(8);
    let len = u64::from_le_bytes(len.try_into().expect("8 bytes"));
    let len = usize::try_from(len)
        .ok()
        .filter(|&l| l <= rest.len())
        .ok_or_else(|| "a truncated index".to_string())?;
    Ok(rest.split_at(len))
}

/// The TOC and the compressed tar-split of an index, checked for their
/// sizes and their form only: its TOC decodes to at most `max_json` bytes
/// of JSON, its entries are counted as they are read.
pub fn decode(data: &[u8], max_json: u64) -> Result<(Toc, Vec<u8>), String> {
    let (toc_z, tarsplit_z) = split(data)?;
    decode_parts(toc_z, tarsplit_z.to_vec(), max_json)
}

/// [`decode`] of the two parts of an index, as [`split`] gives them.
pub fn decode_parts(
    toc_z: &[u8],
    tarsplit_z: Vec<u8>,
    max_json: u64,
) -> Result<(Toc, Vec<u8>), String> {
    let max_json = max_json.min(MAX_TOC_JSON);
    let mut json = Vec::new();
    super::zstd_decoder(toc_z)
        .map_err(|e| format!("the TOC of the index: {e}"))?
        .take(max_json + 1)
        .read_to_end(&mut json)
        .map_err(|e| format!("the TOC of the index: {e}"))?;
    if json.len() as u64 > max_json {
        return Err("the TOC of the index is too large".into());
    }
    let toc: BoundedToc =
        serde_json::from_slice(&json).map_err(|e| format!("the TOC of the index: {e}"))?;
    let toc = Toc {
        version: toc.version,
        entries: toc.entries,
        tar_split_digest: toc.tar_split_digest,
    };
    // (a canonical layer has no tar-split: its table has the tar)
    if toc.is_canonical() != tarsplit_z.is_empty() {
        return Err("an index with a tar-split that does not match its table".into());
    }
    Ok((toc, tarsplit_z))
}

/// The fields of a TOC an index is checked by: its entries are skipped,
/// not built.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TocHead {
    version: i32,
    #[allow(
        dead_code,
        reason = "a TOC has entries: only their presence is checked"
    )]
    entries: serde::de::IgnoredAny,
    #[serde(default)]
    tar_split_digest: Option<String>,
}

/// Whether `data` is an index whose tar-split is the one its table names
/// (a canonical table has none), its table at most `max_json` bytes of
/// JSON or a binary table of at most that many bytes.  It filters junk,
/// and reads the table for those fields alone: nothing in an index is
/// trusted, the puller verifies all of it.
pub fn is_well_formed(data: &[u8], max_json: u64) -> bool {
    let Ok((toc_z, tarsplit_z)) = split(data) else {
        return false;
    };
    let max_json = max_json.min(MAX_TOC_JSON);
    let mut json = Vec::new();
    let read = super::zstd_decoder(toc_z).and_then(|d| d.take(max_json + 1).read_to_end(&mut json));
    if read.is_err() || json.len() as u64 > max_json {
        return false;
    }
    if json.starts_with(velarx_storage::table::MAGIC) {
        return velarx_storage::table::head(&json).is_ok_and(|head| match head.tarsplit {
            Some(d) => velarx_types::digest::Digest::of(d.alg(), tarsplit_z) == d,
            None => tarsplit_z.is_empty(),
        });
    }
    let Ok(head) = serde_json::from_slice::<TocHead>(&json) else {
        return false;
    };
    if (head.version == velarx_storage::TOC_VERSION_CANONICAL) != tarsplit_z.is_empty() {
        return false;
    }
    match head.tar_split_digest {
        Some(d) => d
            .parse::<velarx_types::digest::Digest>()
            .is_ok_and(|d| velarx_types::digest::Digest::of(d.alg(), tarsplit_z) == d),
        None => tarsplit_z.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compressed_table_comes_back_as_it_was_given() {
        let toc_z = zstd::encode_all(&br#"{"version":1,"entries":[]}"#[..], 19).unwrap();
        let index = encode_compressed(&toc_z, b"tarsplit").unwrap();
        assert_eq!(split(&index).unwrap(), (&toc_z[..], &b"tarsplit"[..]));
        assert!(split(&index[..10]).is_err());
        assert!(decode(&index, MAX_TOC_JSON).is_ok());
    }

    #[test]
    fn an_index_is_decoded_and_bounded() {
        let toc = r#"{"version":1,"entries":[]}"#;
        let index = encode(toc.as_bytes(), b"tarsplit").unwrap();
        let (t, ts) = decode(&index, MAX_TOC_JSON).unwrap();
        assert!(t.entries.is_empty());
        assert_eq!(ts, b"tarsplit");
        // a canonical layer has a table of version 2 and no tar-split, and
        // only such a table has none
        let canonical = r#"{"version":2,"entries":[]}"#;
        let index = encode(canonical.as_bytes(), b"").unwrap();
        assert!(decode(&index, MAX_TOC_JSON).unwrap().1.is_empty());
        assert!(decode(&encode(canonical.as_bytes(), b"ts").unwrap(), MAX_TOC_JSON).is_err());
        // not one, cut, lengths that lie, no tar-split, not a TOC
        assert!(decode(b"garbage", MAX_TOC_JSON).is_err());
        assert!(decode(&index[..index.len() - 8 - 9], MAX_TOC_JSON).is_err());
        let mut lie = index.clone();
        lie[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode(&lie, MAX_TOC_JSON).is_err());
        assert!(decode(&encode(toc.as_bytes(), b"").unwrap(), MAX_TOC_JSON).is_err());
        assert!(decode(&encode(b"[1, 2]", b"ts").unwrap(), MAX_TOC_JSON).is_err());
        // a TOC that decompresses to a bomb is cut
        let bomb = vec![b' '; (MAX_TOC_JSON + 10) as usize];
        let mut big = MAGIC.to_vec();
        let z = zstd::encode_all(&bomb[..], 19).unwrap();
        big.extend_from_slice(&(z.len() as u64).to_le_bytes());
        big.extend_from_slice(&z);
        big.extend_from_slice(b"ts");
        assert!(decode(&big, MAX_TOC_JSON).is_err());
        // too large to give
        assert!(encode(b"{}", &vec![0u8; MAX_INDEX as usize]).is_none());
        // a TOC larger than the cap of the layer
        let entries: Vec<String> = (0..2000)
            .map(|i| format!(r#"{{"type":"reg","name":"f{i}","size":1}}"#))
            .collect();
        let long = format!(r#"{{"version":1,"entries":[{}]}}"#, entries.join(","));
        let index = encode(long.as_bytes(), b"ts").unwrap();
        assert!(decode(&index, MAX_TOC_JSON).is_ok());
        assert!(decode(&index, 1000).is_err());
        assert_eq!(json_cap(1), 4 * 1024 * 1024);
        assert_eq!(json_cap(i64::MAX), MAX_TOC_JSON);
    }

    #[test]
    fn an_index_is_well_formed_when_its_table_names_its_tar_split() {
        let ts = b"tarsplit";
        let named = velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, ts);
        let toc = format!(
            r#"{{"version":1,"entries":[{{"type":"dir","name":"a"}}],"tarSplitDigest":"{named}"}}"#
        );
        assert!(is_well_formed(
            &encode(toc.as_bytes(), ts).unwrap(),
            MAX_TOC_JSON
        ));
        assert!(!is_well_formed(
            &encode(toc.as_bytes(), b"another").unwrap(),
            MAX_TOC_JSON
        ));
        assert!(!is_well_formed(&encode(toc.as_bytes(), ts).unwrap(), 10));
        let canonical = r#"{"version":2,"entries":[]}"#;
        assert!(is_well_formed(
            &encode(canonical.as_bytes(), b"").unwrap(),
            MAX_TOC_JSON
        ));
        assert!(!is_well_formed(
            &encode(canonical.as_bytes(), ts).unwrap(),
            MAX_TOC_JSON
        ));
        for junk in [r#"{"version":1}"#, "[1, 2]", "not json"] {
            assert!(!is_well_formed(
                &encode(junk.as_bytes(), ts).unwrap(),
                MAX_TOC_JSON
            ));
        }
        assert!(!is_well_formed(b"garbage", MAX_TOC_JSON));
    }

    /// The layer index travels between nodes: its bytes must not change.
    #[test]
    fn the_encoding_of_an_index_is_fixed() {
        // the frame of `{"version":1,"entries":[]}` made by zstd -3
        let toc_z =
            hex::decode("28b52ffd0058d100007b2276657273696f6e223a312c22656e7472696573223a5b5d7d")
                .unwrap();
        let mut golden = b"SHIDX1\n".to_vec();
        golden.extend_from_slice(&[toc_z.len() as u8, 0, 0, 0, 0, 0, 0, 0]);
        golden.extend_from_slice(&toc_z);
        golden.extend_from_slice(b"TARSPLIT");
        assert_eq!(&golden[..15], b"SHIDX1\n\x23\0\0\0\0\0\0\0");
        let (toc, tarsplit) = decode(&golden, MAX_TOC_JSON).unwrap();
        assert_eq!((toc.version, toc.entries.len()), (1, 0));
        assert_eq!(tarsplit, b"TARSPLIT");
        // and what is encoded has the same framing: magic, the length of
        // the compressed TOC (8 bytes, little endian), the TOC, the tar-split
        let index = encode(br#"{"version":1,"entries":[]}"#, b"TARSPLIT").unwrap();
        let len = u64::from_le_bytes(index[7..15].try_into().unwrap()) as usize;
        assert_eq!(&index[..7], b"SHIDX1\n");
        assert_eq!(&index[15 + len..], b"TARSPLIT");
        let json = zstd::decode_all(&index[15..15 + len]).unwrap();
        assert_eq!(json, br#"{"version":1,"entries":[]}"#);
    }

    /// The index of a layer with a binary table carries the table: it is
    /// well formed when the table's header names its tar-split (or none,
    /// canonical), whatever the algorithm.
    #[test]
    fn an_index_of_a_binary_table_is_well_formed_when_its_table_names_its_tar_split() {
        use velarx_types::digest::{Algorithm, Digest};
        for alg in Algorithm::ALL {
            let ts = b"tar-split".to_vec();
            for canonical in [true, false] {
                let toc = Toc {
                    version: if canonical { 2 } else { 1 },
                    entries: Vec::new(),
                    tar_split_digest: (!canonical).then(|| Digest::of(alg, &ts).to_string()),
                };
                let table = velarx_storage::table::encode(&toc, alg).unwrap();
                let table_z = zstd::encode_all(&table[..], 3).unwrap();
                let good: &[u8] = if canonical { b"" } else { &ts };
                let index = encode_compressed(&table_z, good).unwrap();
                assert!(is_well_formed(&index, 1 << 20), "{alg} {canonical}");
                let other = encode_compressed(&table_z, b"other").unwrap();
                assert!(!is_well_formed(&other, 1 << 20), "{alg} {canonical}");
            }
        }
    }
}
