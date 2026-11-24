// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use velarx_types::digest::Digest;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TocEntryType {
    Dir,
    Reg,
    Symlink,
    Hardlink,
    Char,
    Block,
    Fifo,
    Chunk,
}

/// Chunk type constants matching Go implementation
/// ChunkTypeZeros is "zeros" for zero-filled chunks (sparse file holes)
pub const CHUNK_TYPE_ZEROS: &str = "zeros";

/// A field of a TOC entry that is not written when it is zero, as
/// containers/storage does (`omitempty`): a reader takes a missing number
/// as 0.
fn is_zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TocEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: TocEntryType,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub mode: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub uid: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gid: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: u64,
    /// The digest of the content of a regular file, in the algorithm of the
    /// layer, which old readers check.  A pull checks it where a fetcher
    /// writes the file, and as the digest of the one chunk of a file that has
    /// no chunk entries.  A file made of chunks the store holds is checked by
    /// the digests of its chunks and by its fs-verity digest, not by this one:
    /// a file is named and found by its fs-verity digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The fs-verity digest of a regular file with content, read once from
    /// the `sha256-12:HEX` of the TOC (see [`crate::from_toc`]).
    #[serde(
        default,
        with = "crate::toc_verity::field",
        skip_serializing_if = "Option::is_none"
    )]
    pub fsverity: Option<Digest>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub offset: u64,
    #[serde(default, rename = "endOffset", skip_serializing_if = "is_zero")]
    pub end_offset: u64,
    #[serde(skip_serializing_if = "Option::is_none", rename = "chunkDigest")]
    pub chunk_digest: Option<String>,
    #[serde(default, rename = "chunkSize", skip_serializing_if = "is_zero")]
    pub chunk_size: u64,
    #[serde(default, rename = "chunkOffset", skip_serializing_if = "is_zero")]
    pub chunk_offset: u64,
    /// Chunk type: "" for data chunks, "zeros" for zero-filled chunks
    /// Matches Go's ChunkTypeData and ChunkTypeZeros constants
    #[serde(skip_serializing_if = "Option::is_none", rename = "chunkType")]
    pub chunk_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "linkName")]
    pub link_name: Option<String>,
    /// Modification time - Go uses lowercase "modtime"
    #[serde(skip_serializing_if = "Option::is_none", rename = "modtime")]
    pub mod_time: Option<String>,
    /// Access time - Go uses lowercase "accesstime"
    #[serde(skip_serializing_if = "Option::is_none", rename = "accesstime")]
    pub access_time: Option<String>,
    /// Change time - Go uses lowercase "changetime"
    #[serde(skip_serializing_if = "Option::is_none", rename = "changetime")]
    pub change_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "devMajor")]
    pub dev_major: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "devMinor")]
    pub dev_minor: Option<u32>,
    /// (written sorted by name: a table of contents has one JSON, and the
    /// blob of a layer is the same at every push)
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        serialize_with = "sorted"
    )]
    pub xattrs: HashMap<String, String>,
}

fn sorted<S: serde::Serializer>(map: &HashMap<String, String>, s: S) -> Result<S::Ok, S::Error> {
    s.collect_map(map.iter().collect::<std::collections::BTreeMap<_, _>>())
}

impl TocEntry {
    /// An entry of the kind `entry_type` with every other field empty.
    pub fn new(name: impl Into<String>, entry_type: TocEntryType) -> Self {
        Self {
            name: name.into(),
            entry_type,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            digest: None,
            fsverity: None,
            offset: 0,
            end_offset: 0,
            chunk_digest: None,
            chunk_size: 0,
            chunk_offset: 0,
            chunk_type: None,
            link_name: None,
            mod_time: None,
            access_time: None,
            change_time: None,
            dev_major: None,
            dev_minor: None,
            xattrs: HashMap::new(),
        }
    }
}

/// A time of a table of contents (RFC 3339) as seconds since the epoch
/// (negative before it) and nanoseconds (0 to 999 999 999, after the
/// seconds); none when there is none or it is not RFC 3339.  A leap second
/// (`23:59:60`) is the first second of the next minute.
pub fn toc_time(t: Option<&str>) -> Option<(i64, u32)> {
    const SECOND: u32 = 1_000_000_000;
    let d = chrono::DateTime::parse_from_rfc3339(t?).ok()?;
    let nanos = d.timestamp_subsec_nanos();
    Some((d.timestamp() + i64::from(nanos / SECOND), nanos % SECOND))
}

/// The RFC 3339 text of a time of a table of contents: seconds since the
/// epoch and nanoseconds, as [`toc_time`] reads them back.
pub fn rfc3339((secs, nanos): (i64, u32)) -> Option<String> {
    // RFC 3339 has four digit years: a time outside of them is clamped
    // (chrono would write `+10000-...`, which the Go parsers refuse)
    const FIRST: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
    const LAST: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    let (secs, nanos) = match secs {
        ..FIRST => (FIRST, 0),
        _ if secs > LAST => (LAST, 0),
        _ => (secs, nanos),
    };
    chrono::DateTime::from_timestamp(secs, nanos).map(|t| t.to_rfc3339())
}

impl TocEntry {
    /// The modification time: seconds since the epoch (before it for a
    /// time before 1970) and nanoseconds; `(0, 0)` when the entry has none
    /// or it is not RFC 3339.  The one reading of the times of a table of
    /// contents.
    pub fn mtime(&self) -> (i64, u32) {
        toc_time(self.mod_time.as_deref()).unwrap_or((0, 0))
    }

    /// A regular file with content: the kind of entry a pull fetches.
    pub fn has_content(&self) -> bool {
        self.entry_type == TocEntryType::Reg && self.size > 0
    }

    /// The object digest (`sha256:HEX`) the TOC gives for the file, if it
    /// gives one of the kind the store uses.
    pub fn verity(&self) -> Option<String> {
        self.fsverity.map(|d| d.to_string())
    }

    /// What a pull knows the content of a regular file by: its fs-verity
    /// digest, or the sha256 the TOC gives when it gives no fs-verity digest
    /// (the pull finds the fs-verity digest of the content it checked).
    pub fn content_key(&self) -> Option<String> {
        self.verity().or_else(|| self.digest.clone())
    }

    /// Returns true if this is a zero-filled chunk (sparse file hole)
    pub fn is_zeros_chunk(&self) -> bool {
        self.chunk_type.as_deref() == Some(CHUNK_TYPE_ZEROS)
    }
}

/// TOC version
pub const TOC_VERSION: i32 = 1;

/// The version of a table of contents whose layer is a canonical tar
/// ([`crate::canonical`]): it needs no tar-split.
pub const TOC_VERSION_CANONICAL: i32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Toc {
    pub version: i32,
    pub entries: Vec<TocEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tar_split_digest: Option<String>,
}

impl AsRef<[TocEntry]> for Toc {
    fn as_ref(&self) -> &[TocEntry] {
        &self.entries
    }
}

impl Toc {
    /// Whether the layer is a canonical tar that the entries describe.
    pub fn is_canonical(&self) -> bool {
        self.version == TOC_VERSION_CANONICAL
    }

    /// The files with content, by fs-verity digest, each once.
    pub fn files(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .filter(|e| e.has_content())
            .filter_map(|e| e.verity())
            .filter(|d| seen.insert(d.clone()))
            .collect()
    }

    pub fn find_by_name(&self, name: &str) -> Option<&TocEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn get_file_chunks(&self, name: &str) -> Vec<&TocEntry> {
        let mut chunks = Vec::new();
        let mut found = false;

        for entry in &self.entries {
            if entry.name == name && entry.entry_type == TocEntryType::Reg {
                chunks.push(entry);
                found = true;
            } else if found && entry.entry_type == TocEntryType::Chunk && entry.name == name {
                chunks.push(entry);
            } else if found && entry.name != name {
                break;
            }
        }

        chunks
    }
}

/// The first regular file of `entries` whose content (its fs-verity digest)
/// is listed with a size other than the one before it: the position of the
/// entry and what is wrong.  A digest names one content, which has one size.
pub fn size_conflict(entries: &[TocEntry]) -> Option<(usize, String)> {
    let mut sizes: HashMap<Digest, u64> = HashMap::new();
    entries.iter().enumerate().find_map(|(i, e)| {
        if !e.has_content() {
            return None;
        }
        let key = e.fsverity?;
        let first = *sizes.entry(key).or_insert(e.size);
        (first != e.size).then(|| {
            (
                i,
                format!("{key} is listed with two sizes: {first} and {}", e.size),
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toc_times() {
        let t = |s: &str| toc_time(Some(s));
        assert_eq!(t("1970-01-01T00:00:01.5Z"), Some((1, 500_000_000)));
        assert_eq!(t("1969-12-31T23:59:59.25Z"), Some((-1, 250_000_000)));
        assert_eq!(t("2016-12-31T23:59:60.5Z"), t("2017-01-01T00:00:00.5Z"));
        assert_eq!(t("yesterday"), None);
    }

    /// Test FileMetadata fields match the Go struct
    /// Go struct: Type, Name, Linkname, Mode, Size, UID, GID, ModTime, AccessTime, ChangeTime,
    ///            Devmajor, Devminor, Xattrs, Digest, Offset, EndOffset, ChunkSize, ChunkOffset, ChunkDigest, ChunkType
    #[test]
    fn test_file_metadata_fields_match_go() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "reg",
                    "name": "/usr/bin/test",
                    "linkName": "",
                    "mode": 493,
                    "size": 12345,
                    "uid": 1000,
                    "gid": 1000,
                    "modtime": "2024-01-15T10:30:00Z",
                    "accesstime": "2024-01-15T11:00:00Z",
                    "changetime": "2024-01-15T10:30:00Z",
                    "devMajor": 0,
                    "devMinor": 0,
                    "xattrs": {
                        "security.selinux": "dW5jb25maW5lZF91Om9iamVjdF9yOnVzZXJfaG9tZV90OnMw"
                    },
                    "digest": "sha256:abc123def456",
                    "offset": 100,
                    "endOffset": 12445,
                    "chunkSize": 1048576,
                    "chunkOffset": 0,
                    "chunkDigest": "sha256:chunk123"
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        assert_eq!(toc.entries.len(), 1);

        let entry = &toc.entries[0];
        assert_eq!(entry.entry_type, TocEntryType::Reg);
        assert_eq!(entry.name, "/usr/bin/test");
        assert_eq!(entry.mode, 493);
        assert_eq!(entry.size, 12345);
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
        assert_eq!(entry.mod_time, Some("2024-01-15T10:30:00Z".to_string()));
        assert_eq!(entry.access_time, Some("2024-01-15T11:00:00Z".to_string()));
        assert_eq!(entry.change_time, Some("2024-01-15T10:30:00Z".to_string()));
        assert_eq!(entry.dev_major, Some(0));
        assert_eq!(entry.dev_minor, Some(0));
        assert_eq!(
            entry.xattrs.get("security.selinux"),
            Some(&"dW5jb25maW5lZF91Om9iamVjdF9yOnVzZXJfaG9tZV90OnMw".to_string())
        );
        assert_eq!(entry.digest, Some("sha256:abc123def456".to_string()));
        assert_eq!(entry.offset, 100);
        assert_eq!(entry.end_offset, 12445);
        assert_eq!(entry.chunk_size, 1048576);
        assert_eq!(entry.chunk_offset, 0);
        assert_eq!(entry.chunk_digest, Some("sha256:chunk123".to_string()));
    }

    /// Test symlink entry with linkName field
    #[test]
    fn test_symlink_entry() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "symlink",
                    "name": "/usr/bin/python",
                    "linkName": "/usr/bin/python3",
                    "mode": 511,
                    "uid": 0,
                    "gid": 0
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        let entry = &toc.entries[0];
        assert_eq!(entry.entry_type, TocEntryType::Symlink);
        assert_eq!(entry.name, "/usr/bin/python");
        assert_eq!(entry.link_name, Some("/usr/bin/python3".to_string()));
    }

    /// Test hardlink entry with linkName field
    #[test]
    fn test_hardlink_entry() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "hardlink",
                    "name": "/usr/bin/link",
                    "linkName": "/usr/bin/original",
                    "mode": 493,
                    "uid": 0,
                    "gid": 0
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        let entry = &toc.entries[0];
        assert_eq!(entry.entry_type, TocEntryType::Hardlink);
        assert_eq!(entry.name, "/usr/bin/link");
        assert_eq!(entry.link_name, Some("/usr/bin/original".to_string()));
    }

    /// Test device entries with devMajor/devMinor
    #[test]
    fn test_device_entries() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "char",
                    "name": "/dev/null",
                    "mode": 438,
                    "uid": 0,
                    "gid": 0,
                    "devMajor": 1,
                    "devMinor": 3
                },
                {
                    "type": "block",
                    "name": "/dev/sda",
                    "mode": 432,
                    "uid": 0,
                    "gid": 6,
                    "devMajor": 8,
                    "devMinor": 0
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();

        let char_dev = &toc.entries[0];
        assert_eq!(char_dev.entry_type, TocEntryType::Char);
        assert_eq!(char_dev.dev_major, Some(1));
        assert_eq!(char_dev.dev_minor, Some(3));

        let block_dev = &toc.entries[1];
        assert_eq!(block_dev.entry_type, TocEntryType::Block);
        assert_eq!(block_dev.dev_major, Some(8));
        assert_eq!(block_dev.dev_minor, Some(0));
    }

    /// Test chunk entries (TypeChunk in Go)
    /// Chunks represent portions of large files for deduplication
    #[test]
    fn test_chunk_entries() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "reg",
                    "name": "/large_file",
                    "mode": 420,
                    "size": 3145728,
                    "uid": 0,
                    "gid": 0,
                    "digest": "sha256:wholefile",
                    "offset": 0,
                    "endOffset": 1048576,
                    "chunkSize": 1048576,
                    "chunkOffset": 0,
                    "chunkDigest": "sha256:chunk1"
                },
                {
                    "type": "chunk",
                    "name": "/large_file",
                    "offset": 1048576,
                    "endOffset": 2097152,
                    "chunkSize": 1048576,
                    "chunkOffset": 1048576,
                    "chunkDigest": "sha256:chunk2"
                },
                {
                    "type": "chunk",
                    "name": "/large_file",
                    "offset": 2097152,
                    "endOffset": 3145728,
                    "chunkSize": 1048576,
                    "chunkOffset": 2097152,
                    "chunkDigest": "sha256:chunk3"
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        assert_eq!(toc.entries.len(), 3);

        assert_eq!(toc.entries[0].entry_type, TocEntryType::Reg);
        assert_eq!(toc.entries[0].size, 3145728);
        assert_eq!(
            toc.entries[0].chunk_digest,
            Some("sha256:chunk1".to_string())
        );

        assert_eq!(toc.entries[1].entry_type, TocEntryType::Chunk);
        assert_eq!(toc.entries[1].chunk_offset, 1048576);

        assert_eq!(toc.entries[2].entry_type, TocEntryType::Chunk);
        assert_eq!(toc.entries[2].chunk_offset, 2097152);

        let chunks = toc.get_file_chunks("/large_file");
        assert_eq!(chunks.len(), 3);
    }

    /// Test TOC with tarSplitDigest field
    #[test]
    fn test_toc_with_tarsplit_digest() {
        let toc_json = r#"{
            "version": 1,
            "entries": [],
            "tarSplitDigest": "sha256:tarsplit123"
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        assert_eq!(toc.version, 1);
        assert_eq!(toc.tar_split_digest, Some("sha256:tarsplit123".to_string()));
    }

    /// Test the lookup of an entry by name
    #[test]
    fn test_find_by_name() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {"type": "reg", "name": "/usr/bin/test", "mode": 493, "uid": 0, "gid": 0, "size": 100}
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();

        let found = toc.find_by_name("/usr/bin/test");
        assert!(found.is_some());
        assert_eq!(found.unwrap().entry_type, TocEntryType::Reg);

        let not_found = toc.find_by_name("/nonexistent");
        assert!(not_found.is_none());
    }

    /// Test parsing TOC with empty optional fields (defaults)
    #[test]
    fn test_toc_optional_field_defaults() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "reg",
                    "name": "/minimal"
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        let entry = &toc.entries[0];

        assert_eq!(entry.mode, 0);
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert_eq!(entry.size, 0);
        assert_eq!(entry.offset, 0);
        assert_eq!(entry.end_offset, 0);
        assert_eq!(entry.chunk_size, 0);
        assert_eq!(entry.chunk_offset, 0);

        assert!(entry.digest.is_none());
        assert!(entry.chunk_digest.is_none());
        assert!(entry.link_name.is_none());
        assert!(entry.mod_time.is_none());
        assert!(entry.access_time.is_none());
        assert!(entry.change_time.is_none());
        assert!(entry.dev_major.is_none());
        assert!(entry.dev_minor.is_none());

        assert!(entry.xattrs.is_empty());
    }

    /// Fields that are zero are not written, and an entry that has them
    /// written (an older writer) reads as the same entry.
    #[test]
    fn test_zero_fields_are_not_written() {
        let entry = TocEntry::new("d/", TocEntryType::Dir);
        assert_eq!(
            serde_json::to_string(&entry).unwrap(),
            r#"{"name":"d/","type":"dir"}"#
        );
        let written = r#"{"name":"d/","type":"dir","mode":0,"uid":0,"gid":0,"size":0,
            "offset":0,"endOffset":0,"chunkSize":0,"chunkOffset":0}"#;
        let old: TocEntry = serde_json::from_str(written).unwrap();
        assert_eq!(
            serde_json::to_string(&old).unwrap(),
            serde_json::to_string(&entry).unwrap()
        );
    }

    /// Test serialization roundtrip
    #[test]
    fn test_toc_serialization_roundtrip() {
        let original = Toc {
            version: 1,
            entries: vec![TocEntry {
                name: "/test/file".to_string(),
                entry_type: TocEntryType::Reg,
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                size: 1234,
                digest: Some("sha256:abc".to_string()),
                fsverity: None,
                offset: 100,
                end_offset: 1334,
                chunk_digest: None,
                chunk_size: 0,
                chunk_offset: 0,
                chunk_type: None,
                link_name: None,
                mod_time: Some("2024-01-15T10:30:00Z".to_string()),
                access_time: None,
                change_time: None,
                dev_major: None,
                dev_minor: None,
                xattrs: HashMap::new(),
            }],
            tar_split_digest: Some("sha256:tarsplit".to_string()),
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: Toc = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.entries.len(), original.entries.len());
        assert_eq!(parsed.entries[0].name, original.entries[0].name);
        assert_eq!(parsed.entries[0].digest, original.entries[0].digest);
        assert_eq!(parsed.tar_split_digest, original.tar_split_digest);
    }

    // the chunk types, as Go's containers/storage has them

    /// Test parsing TOC with zeros chunk type (sparse file holes)
    /// This matches Go's handling of ChunkTypeZeros in containers/storage
    #[test]
    fn test_zeros_chunk_type_parsing() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "reg",
                    "name": "/sparse_file",
                    "mode": 420,
                    "size": 10485760,
                    "uid": 0,
                    "gid": 0,
                    "digest": "sha256:sparsedigest",
                    "offset": 0,
                    "endOffset": 1048576,
                    "chunkSize": 1048576,
                    "chunkOffset": 0,
                    "chunkDigest": "sha256:datachunk1"
                },
                {
                    "type": "chunk",
                    "name": "/sparse_file",
                    "chunkSize": 8388608,
                    "chunkOffset": 1048576,
                    "chunkType": "zeros"
                },
                {
                    "type": "chunk",
                    "name": "/sparse_file",
                    "offset": 1048576,
                    "endOffset": 2097152,
                    "chunkSize": 1048576,
                    "chunkOffset": 9437184,
                    "chunkDigest": "sha256:datachunk2"
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        assert_eq!(toc.entries.len(), 3);

        let file_entry = &toc.entries[0];
        assert_eq!(file_entry.entry_type, TocEntryType::Reg);
        assert_eq!(file_entry.size, 10485760); // 10MB file
        assert!(!file_entry.is_zeros_chunk());

        let zeros_chunk = &toc.entries[1];
        assert_eq!(zeros_chunk.entry_type, TocEntryType::Chunk);
        assert_eq!(zeros_chunk.chunk_type, Some("zeros".to_string()));
        assert_eq!(zeros_chunk.chunk_size, 8388608); // 8MB of zeros
        assert_eq!(zeros_chunk.chunk_offset, 1048576); // starts at 1MB
        assert!(zeros_chunk.is_zeros_chunk());

        let data_chunk = &toc.entries[2];
        assert_eq!(data_chunk.entry_type, TocEntryType::Chunk);
        assert!(!data_chunk.is_zeros_chunk());
        assert_eq!(
            data_chunk.chunk_digest,
            Some("sha256:datachunk2".to_string())
        );
    }

    /// Test that chunkType is not serialized when None (matching Go omitempty behavior)
    #[test]
    fn test_chunk_type_omit_empty() {
        let entry = TocEntry {
            name: "test".to_string(),
            entry_type: TocEntryType::Reg,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 100,
            digest: None,
            fsverity: None,
            offset: 0,
            end_offset: 100,
            chunk_digest: None,
            chunk_size: 100,
            chunk_offset: 0,
            chunk_type: None, // Should not appear in JSON
            link_name: None,
            mod_time: None,
            access_time: None,
            change_time: None,
            dev_major: None,
            dev_minor: None,
            xattrs: HashMap::new(),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            !json.contains("chunkType"),
            "chunkType should be omitted when None"
        );

        let entry_with_zeros = TocEntry {
            chunk_type: Some("zeros".to_string()),
            ..entry
        };
        let json_with_zeros = serde_json::to_string(&entry_with_zeros).unwrap();
        assert!(json_with_zeros.contains("\"chunkType\":\"zeros\""));
    }

    /// The JSON of an entry is one: its extended attributes sorted.
    #[test]
    fn test_the_json_of_an_entry_is_one() {
        let mut e = TocEntry::new("f", TocEntryType::Reg);
        for k in ["user.c", "user.a", "security.b", "user.b", "trusted.z"] {
            e.xattrs.insert(k.to_string(), "eA==".to_string());
        }
        let json = serde_json::to_string(&e).unwrap();
        let keys: Vec<usize> = ["security.b", "trusted.z", "user.a", "user.b", "user.c"]
            .iter()
            .map(|k| json.find(k).unwrap())
            .collect();
        assert!(keys.is_sorted(), "{json}");
    }

    /// Test get_file_chunks returns all chunks including zeros chunks
    #[test]
    fn test_get_file_chunks_with_zeros() {
        let toc_json = r#"{
            "version": 1,
            "entries": [
                {
                    "type": "reg",
                    "name": "/sparse",
                    "mode": 420,
                    "size": 4096,
                    "uid": 0,
                    "gid": 0,
                    "chunkSize": 1024,
                    "chunkOffset": 0
                },
                {
                    "type": "chunk",
                    "name": "/sparse",
                    "chunkSize": 2048,
                    "chunkOffset": 1024,
                    "chunkType": "zeros"
                },
                {
                    "type": "chunk",
                    "name": "/sparse",
                    "chunkSize": 1024,
                    "chunkOffset": 3072
                }
            ]
        }"#;

        let toc: Toc = serde_json::from_str(toc_json).unwrap();
        let chunks = toc.get_file_chunks("/sparse");

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].entry_type, TocEntryType::Reg);
        assert_eq!(chunks[1].entry_type, TocEntryType::Chunk);
        assert!(chunks[1].is_zeros_chunk());
        assert_eq!(chunks[2].entry_type, TocEntryType::Chunk);
    }
}
