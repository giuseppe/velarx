// SPDX-License-Identifier: Apache-2.0
//! Table of contents entries built from the headers of a verified tar stream.

use super::tar::{normalize_path, Header, Kind, MAX_NAME_LEN, MAX_XATTRS, MAX_XATTR_BYTES};
use base64::Engine;
use std::collections::HashMap;
use std::io;
use velarx_storage::{rfc3339, toc_time, Toc, TocEntry, TocEntryType};
use velarx_types::digest::{Algorithm, Digest};

/// Entries of one layer accepted.
pub use velarx_storage::canonical::MAX_ENTRIES;

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

/// The name a layer gives the entry at `path` (the root directory of the
/// layer is `./`).
pub fn layer_name(path: &str, dir: bool) -> io::Result<String> {
    match normalize_path(path) {
        Some(n) => Ok(n),
        None if dir && matches!(path, "." | "./" | "/") => Ok("./".to_string()),
        None => Err(invalid(format!("invalid path `{path}` in the layer"))),
    }
}

/// What a layer keeps of `e`, an entry that a tar header or a table of
/// contents gives: one set of rules for both, so that a layer has the same
/// entries whichever describes it.  The name of the layer and a link target
/// (no NUL, at most the length a tar name has), the extended attributes that
/// are not the overlay file system's (an image that carries those could
/// redirect lookups to other files of the store) within the bounds of a tar
/// header, the permission bits, the time, a device number for a device only,
/// and no size or content for what has none.
fn layer_entry(e: TocEntry) -> io::Result<TocEntry> {
    use base64::engine::general_purpose::STANDARD;
    use TocEntryType::*;
    let bad_text = |s: &str| s.len() > MAX_NAME_LEN || s.contains('\0');
    if bad_text(&e.name) {
        return Err(invalid(format!(
            "invalid path `{}` in the layer",
            e.name.escape_debug()
        )));
    }
    let name = layer_name(&e.name, e.entry_type == Dir)?;
    let link_name = match e.entry_type {
        Symlink | Hardlink => {
            let what = match e.entry_type {
                Symlink => "symbolic link",
                _ => "hard link",
            };
            let target = e
                .link_name
                .as_deref()
                .filter(|t| !t.is_empty())
                .ok_or_else(|| invalid(format!("{what} `{name}` has no target")))?;
            let target = match e.entry_type {
                Hardlink => normalize_path(target).filter(|t| !bad_text(t)),
                _ => Some(target.to_string()).filter(|t| !bad_text(t)),
            };
            Some(target.ok_or_else(|| invalid(format!("{what} `{name}` has an invalid target")))?)
        }
        _ => None,
    };
    let mut xattrs = HashMap::new();
    let mut bytes = 0;
    for (i, (k, v)) in e.xattrs.iter().enumerate() {
        let value = STANDARD
            .decode(v)
            .ok()
            .filter(|_| !k.is_empty() && !k.contains('\0'));
        let Some(value) = value else {
            return Err(invalid(format!(
                "`{name}` has an invalid extended attribute `{}`",
                k.escape_debug()
            )));
        };
        bytes += k.len() + value.len();
        if i >= MAX_XATTRS || bytes > MAX_XATTR_BYTES {
            return Err(invalid(format!(
                "`{name}` has too many extended attributes"
            )));
        }
        if !is_overlay_xattr(k) && value.len() <= MAX_XATTR_VALUE {
            xattrs.insert(k.clone(), STANDARD.encode(value));
        }
    }
    let device = matches!(e.entry_type, Char | Block);
    let mut out = TocEntry {
        name,
        link_name,
        xattrs,
        mode: e.mode & 0o7777,
        mod_time: toc_time(e.mod_time.as_deref()).and_then(rfc3339),
        access_time: None,
        change_time: None,
        dev_major: device.then_some(e.dev_major.unwrap_or(0)),
        dev_minor: device.then_some(e.dev_minor.unwrap_or(0)),
        ..e
    };
    if out.entry_type != Reg {
        out.size = 0;
        out.digest = None;
        out.fsverity = None;
        out.offset = 0;
        out.end_offset = 0;
        out.chunk_digest = None;
        out.chunk_size = 0;
        out.chunk_offset = 0;
        out.chunk_type = None;
    }
    Ok(out)
}

/// Whether `a` and `b`, entries [`layer_entry`] made, describe the same
/// entry of a layer, its content aside.
pub fn same_entry(a: &TocEntry, b: &TocEntry) -> bool {
    let key = |e: &TocEntry| {
        (
            e.entry_type,
            e.mode,
            e.uid,
            e.gid,
            e.size,
            e.mtime(),
            e.dev_major,
            e.dev_minor,
        )
    };
    a.name == b.name && key(a) == key(b) && a.link_name == b.link_name && a.xattrs == b.xattrs
}

/// The entry of a tar header, its content aside (see [`from_header`]).
pub fn header_entry(h: &Header) -> io::Result<TocEntry> {
    use base64::engine::general_purpose::STANDARD;
    let entry_type = match h.kind {
        Kind::Regular => TocEntryType::Reg,
        Kind::Directory => TocEntryType::Dir,
        Kind::Symlink => TocEntryType::Symlink,
        Kind::Hardlink => TocEntryType::Hardlink,
        Kind::Char => TocEntryType::Char,
        Kind::Block => TocEntryType::Block,
        Kind::Fifo => TocEntryType::Fifo,
    };
    layer_entry(TocEntry {
        name: h.path.clone(),
        entry_type,
        mode: h.mode,
        uid: h.uid,
        gid: h.gid,
        size: h.size,
        digest: None,
        fsverity: None,
        offset: 0,
        end_offset: 0,
        chunk_digest: None,
        chunk_size: 0,
        chunk_offset: 0,
        chunk_type: None,
        link_name: h.link.clone(),
        mod_time: rfc3339(h.mtime),
        access_time: None,
        change_time: None,
        dev_major: Some(h.dev_major),
        dev_minor: Some(h.dev_minor),
        xattrs: h
            .xattrs
            .iter()
            .map(|(k, v)| (k.clone(), STANDARD.encode(v)))
            .collect(),
    })
}

/// The TOC entry of a tar header.  `file_digest` is the digest of the
/// content of a regular file (the callers that know its fs-verity digest
/// set the digests of the entry after).  The root directory of the layer
/// is the entry `./`.
pub fn from_header(h: &Header, file_digest: Option<&str>) -> io::Result<TocEntry> {
    let mut e = header_entry(h)?;
    if e.entry_type == TocEntryType::Reg {
        let d =
            file_digest.ok_or_else(|| invalid(format!("no content digest for `{}`", e.name)))?;
        // (the key of a file: the hash of its content, or its fs-verity digest)
        debug_assert!(Digest::parse_key(d).is_ok());
        e.digest = Some(d.to_string());
        e.chunk_digest = Some(d.to_string());
        e.chunk_size = e.size;
    }
    Ok(e)
}

/// The entry a layer is stored by for `e`, an entry of the table of
/// contents the descriptor vouches for: what that table says, kept to what
/// a layer keeps of any entry ([`layer_entry`]), with the place of the
/// content of a regular file in the blob.
pub fn from_toc(e: TocEntry, alg: Algorithm) -> io::Result<TocEntry> {
    if e.entry_type == TocEntryType::Chunk {
        return Ok(e);
    }
    let mut entry = layer_entry(e)?;
    if entry.entry_type != TocEntryType::Reg {
        return Ok(entry);
    }
    entry.chunk_offset = 0;
    if entry.size == 0 {
        let empty = Digest::empty(alg).to_string();
        entry.digest = Some(empty.clone());
        entry.chunk_digest = Some(empty);
        entry.fsverity = None;
        entry.offset = 0;
        entry.end_offset = 0;
        entry.chunk_size = 0;
        entry.chunk_type = None;
    } else {
        if entry.fsverity.is_none()
            && entry
                .digest
                .as_deref()
                .is_none_or(|d| Digest::parse_key(d).is_err())
        {
            return Err(invalid(format!(
                "the table has no digest for `{}`",
                entry.name
            )));
        }
        entry.digest = entry.digest.filter(|d| d.parse::<Digest>().is_ok());
    }
    Ok(entry)
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
        let entry = |name: &str| from_header(&header(name, Kind::Directory), None).unwrap();
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
        let e = from_header(&h, None).unwrap();
        assert_eq!(e.mtime(), (1_700_000_000, 123_456_789));
        h.mtime = (-2, 500_000_000);
        let e = from_header(&h, None).unwrap();
        assert_eq!(e.mtime(), (-2, 500_000_000));
    }

    #[test]
    fn test_regular_file() {
        let d = crate::sha256_text(b"abc");
        let e = from_header(&header("./usr/bin/x", Kind::Regular), Some(&d)).unwrap();
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
            rfc3339((253_402_300_799, 500_000_000)).as_deref(),
            Some("9999-12-31T23:59:59.500+00:00")
        );
        assert_eq!(
            rfc3339((i64::MIN, 7)).as_deref(),
            Some("0001-01-01T00:00:00+00:00")
        );
    }

    #[test]
    fn test_the_root_is_an_entry_and_escapes_are_refused() {
        for path in [".", "./", "/"] {
            let e = from_header(&header(path, Kind::Directory), None).unwrap();
            assert_eq!((e.name.as_str(), e.entry_type), ("./", TocEntryType::Dir));
            assert_eq!((e.mode, e.uid, e.gid), (0o755, 1, 2));
        }
        assert!(from_header(&header("./", Kind::Regular), Some("sha256:x")).is_err());
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
            from_header(&h, None).unwrap().link_name.as_deref(),
            Some("../target")
        );
        let mut h = header("hl", Kind::Hardlink);
        h.link = Some("./a/b".to_string());
        assert_eq!(
            from_header(&h, None).unwrap().link_name.as_deref(),
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
        let e = from_header(&h, Some(&crate::sha256_text(b""))).unwrap();
        let mut keys: Vec<_> = e.xattrs.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["security.capability", "user.keep"]);
    }

    #[test]
    fn test_xattrs_are_base64() {
        let mut h = header("f", Kind::Regular);
        h.xattrs.insert("security.capability".into(), vec![1, 2, 3]);
        let e = from_header(&h, Some(&crate::sha256_text(b""))).unwrap();
        assert_eq!(e.xattrs["security.capability"], "AQID");
    }

    /// A table of contents entry is kept to what a layer keeps of a tar
    /// header with the same fields, by the same rules.
    #[test]
    fn test_a_table_entry_is_kept_as_a_tar_header_is() {
        let alg = Algorithm::Sha256;
        let mut h = header("./usr//bin/./x", Kind::Regular);
        h.size = 0;
        h.mode = 0o4755;
        h.xattrs
            .insert("trusted.overlay.redirect".into(), b"x".to_vec());
        h.xattrs
            .insert("user.k".into(), vec![0; MAX_XATTR_VALUE + 1]);
        h.xattrs.insert("security.capability".into(), vec![1, 2]);
        let of_header = from_header(&h, Some(&Digest::empty(alg).to_string())).unwrap();
        let mut raw = of_header.clone();
        raw.name = h.path.clone();
        raw.mode = 0o104755;
        raw.mod_time = Some("2023-11-14T22:13:20Z".into());
        raw.access_time = raw.mod_time.clone();
        raw.dev_major = Some(8);
        raw.xattrs = h
            .xattrs
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    base64::engine::general_purpose::STANDARD.encode(v),
                )
            })
            .collect();
        let of_toc = from_toc(raw.clone(), alg).unwrap();
        assert!(same_entry(&of_header, &of_toc));
        assert_eq!(
            serde_json::to_value(&of_toc).unwrap(),
            serde_json::to_value(&of_header).unwrap()
        );

        // no size, digest or place for what has no content, no device
        // number for what is not a device
        let mut d = raw.clone();
        d.entry_type = TocEntryType::Dir;
        d.size = 9;
        d.offset = 4;
        let d = from_toc(d.clone(), alg).unwrap();
        assert_eq!(
            (d.size, d.offset, &d.digest, d.dev_major),
            (0, 0, &None, None)
        );
        let mut c = raw.clone();
        c.entry_type = TocEntryType::Char;
        c.dev_minor = None;
        let c = from_toc(c.clone(), alg).unwrap();
        assert_eq!((c.dev_major, c.dev_minor), (Some(8), Some(0)));
    }

    #[test]
    fn test_a_table_entry_a_tar_header_could_not_be_is_refused() {
        let alg = Algorithm::Sha256;
        let base = from_header(&header("d", Kind::Directory), None).unwrap();
        let long = "a".repeat(MAX_NAME_LEN + 1);
        let refused: [fn(&mut TocEntry); 10] = [
            |e| e.name = "a\0b".into(),
            |e| e.name = "../x".into(),
            |e| e.name = "a/../../x".into(),
            |e| e.name = String::new(),
            |e| {
                e.entry_type = TocEntryType::Symlink;
                e.link_name = Some(String::new());
            },
            |e| {
                e.entry_type = TocEntryType::Symlink;
                e.link_name = Some("a\0b".into());
            },
            |e| {
                e.entry_type = TocEntryType::Hardlink;
                e.link_name = Some("../x".into());
            },
            |e| {
                e.xattrs.insert("user.k".into(), "not base64!".into());
            },
            |e| {
                e.xattrs.insert(String::new(), "eA==".into());
            },
            |e| {
                for i in 0..=MAX_XATTRS {
                    e.xattrs.insert(format!("user.{i}"), "eA==".into());
                }
            },
        ];
        for (i, edit) in refused.iter().enumerate() {
            let mut e = base.clone();
            edit(&mut e);
            assert!(from_toc(e.clone(), alg).is_err(), "{i}: {e:?}");
        }
        let mut e = base.clone();
        e.name = long.clone();
        assert!(from_toc(e.clone(), alg).is_err());
        e.name = "d".into();
        e.entry_type = TocEntryType::Symlink;
        e.link_name = Some(long);
        assert!(from_toc(e.clone(), alg).is_err());
        // a regular file with content and no digest of it
        let mut e = base.clone();
        e.entry_type = TocEntryType::Reg;
        e.size = 1;
        assert!(from_toc(e.clone(), alg).is_err());
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
