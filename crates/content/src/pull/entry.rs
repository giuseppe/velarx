// SPDX-License-Identifier: Apache-2.0
//! Table of contents entries built from the headers of a verified tar stream.

use super::tar::{normalize_path, Header, Kind};
use base64::Engine;
use std::collections::HashMap;
use std::io;
use velarx_storage::{Toc, TocEntry, TocEntryType};

/// Entries of one layer accepted.
pub const MAX_ENTRIES: usize = 4 * 1024 * 1024;

/// What is wrong with the size of a table of contents: too many entries, or
/// a name with too many components.
pub fn toc_problem(entries: &[TocEntry]) -> Option<&'static str> {
    if entries.len() > MAX_ENTRIES {
        Some("the TOC has too many entries")
    } else if entries.iter().any(|e| super::tar::too_deep(&e.name)) {
        Some("the TOC has a name that is too deep")
    } else {
        None
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Largest value of an extended attribute kept.
const MAX_XATTR_VALUE: usize = 64 * 1024;

/// Extended attributes of the overlay file system, in any of its namespaces.
fn is_overlay_xattr(name: &str) -> bool {
    ["trusted.", "user.", "security.", "system."]
        .iter()
        .any(|ns| {
            name.strip_prefix(ns)
                .is_some_and(|n| n.starts_with("overlay."))
        })
}

pub fn rfc3339((secs, nanos): (i64, u32)) -> Option<String> {
    // RFC 3339 has four digit years: a time outside of them is clamped
    // (chrono would write `+10000-...`, which the Go parsers refuse)
    const FIRST: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
    const LAST: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
    let (secs, nanos) = match secs {
        ..FIRST => (FIRST, 0),
        LAST.. => (LAST, 0),
        _ => (secs, nanos),
    };
    chrono::DateTime::from_timestamp(secs, nanos).map(|t| t.to_rfc3339())
}

/// The TOC entry of a tar header.  `file_digest` is the digest of the
/// content of a regular file (the callers that know its fs-verity digest
/// set the digests of the entry after).  `None` for the root directory, which has no entry.
pub fn from_header(h: &Header, file_digest: Option<&str>) -> io::Result<Option<TocEntry>> {
    let name = match normalize_path(&h.path) {
        Some(n) => n,
        None if h.kind == Kind::Directory && matches!(h.path.as_str(), "." | "./" | "/") => {
            return Ok(None)
        }
        None => return Err(invalid(format!("invalid path `{}` in the layer", h.path))),
    };

    let entry_type = match h.kind {
        Kind::Regular => TocEntryType::Reg,
        Kind::Directory => TocEntryType::Dir,
        Kind::Symlink => TocEntryType::Symlink,
        Kind::Hardlink => TocEntryType::Hardlink,
        Kind::Char => TocEntryType::Char,
        Kind::Block => TocEntryType::Block,
        Kind::Fifo => TocEntryType::Fifo,
    };

    let link_name = match h.kind {
        Kind::Symlink => Some(
            h.link
                .clone()
                .ok_or_else(|| invalid(format!("symbolic link `{name}` has no target")))?,
        ),
        Kind::Hardlink => {
            let target = h
                .link
                .as_deref()
                .ok_or_else(|| invalid(format!("hard link `{name}` has no target")))?;
            Some(normalize_path(target).ok_or_else(|| {
                invalid(format!(
                    "hard link `{name}` has an invalid target `{target}`"
                ))
            })?)
        }
        _ => None,
    };

    // The attributes the overlay file system acts on are its own: an image
    // that carries them could redirect lookups to other files of the store.
    let xattrs: HashMap<String, String> = h
        .xattrs
        .iter()
        .filter(|(k, v)| !is_overlay_xattr(k) && v.len() <= MAX_XATTR_VALUE)
        .map(|(k, v)| {
            (
                k.clone(),
                base64::engine::general_purpose::STANDARD.encode(v),
            )
        })
        .collect();

    let (size, digest, chunk_digest) = match (h.kind, file_digest) {
        (Kind::Regular, Some(d)) => (h.size, Some(d.to_string()), Some(d.to_string())),
        (Kind::Regular, None) => {
            return Err(invalid(format!("no content digest for `{name}`")));
        }
        _ => (0, None, None),
    };
    // (the key of a file: the hash of its content, or its fs-verity digest)
    debug_assert!(digest
        .as_deref()
        .is_none_or(|d| velarx_types::digest::Digest::parse_key(d).is_ok()));

    Ok(Some(TocEntry {
        name,
        entry_type,
        mode: h.mode,
        uid: h.uid,
        gid: h.gid,
        size,
        digest,
        fsverity: None,
        offset: 0,
        end_offset: 0,
        chunk_digest,
        chunk_size: size,
        chunk_offset: 0,
        chunk_type: None,
        link_name,
        mod_time: rfc3339(h.mtime),
        access_time: None,
        change_time: None,
        dev_major: matches!(h.kind, Kind::Char | Kind::Block).then_some(h.dev_major),
        dev_minor: matches!(h.kind, Kind::Char | Kind::Block).then_some(h.dev_minor),
        xattrs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn header(path: &str, kind: Kind) -> Header {
        Header {
            path: path.to_string(),
            kind,
            size: 3,
            mode: 0o755,
            uid: 1,
            gid: 2,
            mtime: (1_700_000_000, 0),
            link: None,
            dev_major: 0,
            dev_minor: 0,
            xattrs: BTreeMap::new(),
        }
    }

    #[test]
    fn test_a_toc_with_a_name_that_is_too_deep() {
        let entry = |name: &str| {
            from_header(&header(name, Kind::Directory), None)
                .unwrap()
                .unwrap()
        };
        let deep = vec!["d"; super::super::tar::MAX_PATH_DEPTH + 1].join("/");
        assert_eq!(toc_problem(&[entry("a/b")]), None);
        assert_eq!(
            toc_problem(&[entry("a"), entry(&deep)]),
            Some("the TOC has a name that is too deep")
        );
    }

    #[test]
    fn test_the_nanoseconds_of_a_time_are_kept() {
        let mut h = header("f", Kind::Directory);
        h.mtime = (1_700_000_000, 123_456_789);
        let e = from_header(&h, None).unwrap().unwrap();
        assert_eq!(e.mtime(), (1_700_000_000, 123_456_789));
        h.mtime = (-2, 500_000_000);
        let e = from_header(&h, None).unwrap().unwrap();
        assert_eq!(e.mtime(), (-2, 500_000_000));
    }

    #[test]
    fn test_regular_file() {
        let d = crate::sha256_text(b"abc");
        let e = from_header(&header("./usr/bin/x", Kind::Regular), Some(&d))
            .unwrap()
            .unwrap();
        assert_eq!(e.name, "usr/bin/x");
        assert_eq!(e.digest.as_deref(), Some(d.as_str()));
        assert_eq!(e.size, 3);
        assert_eq!(e.mode, 0o755);
        assert!(e.mod_time.is_some());
        assert_eq!(
            rfc3339((i64::MAX, 7)).as_deref(),
            Some("9999-12-31T23:59:59+00:00")
        );
        assert_eq!(
            rfc3339((i64::MIN, 7)).as_deref(),
            Some("0001-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn test_root_is_skipped_and_escapes_are_refused() {
        assert!(from_header(&header("./", Kind::Directory), None)
            .unwrap()
            .is_none());
        assert!(from_header(
            &header("../x", Kind::Regular),
            Some(&crate::sha256_text(b""))
        )
        .is_err());
        assert!(from_header(&header("a/../../x", Kind::Directory), None).is_err());
    }

    #[test]
    fn test_links() {
        let mut h = header("l", Kind::Symlink);
        assert!(from_header(&h, None).is_err());
        h.link = Some("../target".to_string());
        assert_eq!(
            from_header(&h, None).unwrap().unwrap().link_name.as_deref(),
            Some("../target")
        );
        let mut h = header("hl", Kind::Hardlink);
        h.link = Some("./a/b".to_string());
        assert_eq!(
            from_header(&h, None).unwrap().unwrap().link_name.as_deref(),
            Some("a/b")
        );
        h.link = Some("../a".to_string());
        assert!(from_header(&h, None).is_err());
    }

    #[test]
    fn test_overlay_xattrs_are_dropped() {
        let mut h = header("f", Kind::Regular);
        for k in [
            "trusted.overlay.redirect",
            "user.overlay.metacopy",
            "trusted.overlay.opaque",
            "user.keep",
            "security.capability",
        ] {
            h.xattrs.insert(k.into(), b"x".to_vec());
        }
        h.xattrs
            .insert("user.huge".into(), vec![0; MAX_XATTR_VALUE + 1]);
        let e = from_header(&h, Some(&crate::sha256_text(b"")))
            .unwrap()
            .unwrap();
        let mut keys: Vec<_> = e.xattrs.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["security.capability", "user.keep"]);
    }

    #[test]
    fn test_xattrs_are_base64() {
        let mut h = header("f", Kind::Regular);
        h.xattrs.insert("security.capability".into(), vec![1, 2, 3]);
        let e = from_header(&h, Some(&crate::sha256_text(b"")))
            .unwrap()
            .unwrap();
        assert_eq!(e.xattrs["security.capability"], "AQID");
    }
}

/// A file of the layer, as the next stages need it.
#[derive(Clone)]
pub struct FileUse {
    pub digest: String,
    pub size: u64,
}

impl FileUse {
    /// The regular files with content a table of contents names, in its
    /// order, by the key it gives them (a file it gives no digest has none).
    pub fn of_toc(toc: &Toc) -> Vec<FileUse> {
        toc.entries
            .iter()
            .filter(|e| e.entry_type == velarx_storage::TocEntryType::Reg && e.size > 0)
            .filter_map(|e| {
                e.content_key().map(|digest| FileUse {
                    digest,
                    size: e.size,
                })
            })
            .collect()
    }

    /// The objects ([`FileUse::of_toc`]) as (key, size), each key once, in
    /// the order of the table of contents: the order a layer is read in, to
    /// read the next ones ahead (`ObjectOpener::ordered`).
    pub fn objects_of_toc(toc: &Toc) -> Vec<(String, u64)> {
        let mut seen = std::collections::HashSet::new();
        Self::of_toc(toc)
            .into_iter()
            .filter(|f| seen.insert(f.digest.clone()))
            .map(|f| (f.digest, f.size))
            .collect()
    }
}
