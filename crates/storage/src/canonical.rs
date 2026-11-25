// SPDX-License-Identifier: Apache-2.0
//! The canonical tar of a layer: the one tar stream a table of contents
//! describes, so that a layer needs no record of how its tar was made.
//!
//! The function from the entries of a table of contents (and the contents
//! of its files) to the bytes of the tar is fixed here, rule by rule.
//! [`write`] makes the tar, [`validate`] says whether a table of contents is
//! one that has a canonical tar, and [`validate_tar`] says whether a tar is
//! the canonical tar of what it holds.
//!
//! This is the draft of composefs-rs (`canonical_tar_spec.rs`) made precise
//! for the layers of an image, which are partial trees with whiteouts.
//!
//! # The entries
//!
//! * The tar has one entry for each entry of the table of contents (`chunk`
//!   entries only say where the parts of the previous file are) and no
//!   other: the ancestors of a path that is not in the layer are not made.
//! * An entry is named `./` and the components of its path joined by `/`,
//!   a directory ends with `/`, and the root `./` is the first entry when
//!   the layer has it.  No component is empty, `.` or `..`, and no byte is
//!   NUL.
//! * The entries are in the order of their paths as sequences of
//!   components, each component compared as bytes (a directory before what
//!   it holds, `./a/b` before `./a-c`).  A path is in the layer once.
//! * A regular file has the type `0`, and its content follows its header
//!   padded with zeros to a block.
//! * A hard link is to a regular file, a symbolic link, a device or a fifo
//!   that is an earlier entry of the layer (the first path of the file in
//!   the order above), with the mode, owner and time of that entry, no
//!   size and no extended attributes (those are the file's).
//! * A whiteout is the regular file `.wh.NAME` (or `.wh..wh..opq`) without
//!   content, of mode 0644, owner 0:0, time 0 and no extended attributes.
//!   A character device 0/0 is never in a layer, nor are the extended
//!   attributes `trusted.overlay.*` and `user.overlay.*`: the overlay file
//!   system gives them a meaning.
//! * The times are seconds and nanoseconds since the epoch (negative before
//!   it), years 1 to 9999.  The ids are 32 bits, the mode is the permission
//!   bits with setuid, setgid and the sticky bit (07777), the numbers of a
//!   device are at most 2097151.
//! * An extended attribute has a name of 1 to 255 bytes without `=` and
//!   NUL and a value of at most 65536 bytes.
//! * The PAX records of an entry (below) are at most 1 MiB, an entry has at
//!   most 1024 xattrs, a path and a link target are at most 4096 bytes, and a layer
//!   has at most 4194304 entries and 128 MiB of names in all: what a reader
//!   of the tar holds in memory.
//!
//! # The headers
//!
//! * A header is ustar (`ustar\0`, version `00`).  A number is its octal
//!   digits padded with zeros, then one NUL (`0000755\0`); the checksum is
//!   six digits, a NUL and a space.  Every byte that nothing sets is NUL:
//!   the names of the owner and the group, the prefix, the numbers of the
//!   devices of what is not a device, the link name of what is not a link.
//! * Types: `0` file, `1` hard link, `2` symbolic link, `3` character
//!   device, `4` block device, `5` directory, `6` fifo.
//! * `name` and `linkname` are the first 100 bytes of the path and of the
//!   target (the cut may be inside a character).  The rest is in a PAX
//!   record, `path` and `linkpath`, when there are more than 100 bytes.
//! * The records, when a header needs any, are in an `x` entry before the
//!   header, named `PaxHeaders.0/` and the last component of the path
//!   (`.` for the root) cut to 87 bytes, of mode 0644, owner 0:0, time 0,
//!   and in this order, each as `LENGTH KEY=VALUE\n` (the length of the
//!   whole record in decimal, without leading zeros):
//!   1. `comment=canonical-tar=1`, on the first entry of the stream only:
//!      it marks the stream as canonical (version 1 of these rules), and the
//!      first entry has an `x` header for it even when nothing else needs
//!      one;
//!   2. `path`, `linkpath`;
//!   3. `size` when it is 8^11 or more, `uid` and `gid` when they are 2^21
//!      or more: their fields in the header are 0;
//!   4. `mtime` when the time is before 1970, 8^11 seconds or later, or has
//!      nanoseconds: the seconds, and when the nanoseconds are not 0 a `.`
//!      and them as nine digits without the trailing zeros; a time before
//!      1970 is `-` and the absolute value of the instant, so 1.5 seconds
//!      before the epoch is `-1.5`.  The field of the header has the
//!      seconds (rounded down) when they are in 0 to 8^11-1, else 0;
//!   5. `SCHILY.xattr.NAME`, with the value as it is, by key as bytes.
//!
//!   No other record is ever written.
//! * The stream ends with two blocks of zeros, and nothing follows them.
//!   A layer without entries is these 1024 bytes.
//!
//! The mapping from the entries of a foreign tar to a table of contents
//! (what it keeps, clamps or refuses) is not part of these rules.

use crate::{content_size, size_conflict, toc_time, TocEntry, TocEntryType};
use base64::Engine;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use velarx_overlay_core::{class, rdev, whiteout, Class};
use velarx_tarsplit_header::emit::{
    path_order, put_decimal, put_octal, put_time, record_len, seal,
};
use velarx_tarsplit_header::{cstr, decimal, number, pax_time, PaxError};

const BLOCK: usize = 512;
/// The value of the PAX record that marks a canonical stream.
const MARKER: (&str, &str) = ("comment", "canonical-tar=1");
/// The largest number of the octal field of 11 digits (sizes and times).
const MAX_OCTAL_11: u64 = 0o77_777_777_777;
/// The ids of the header go up to this, 7 digits.
const MAX_ID_FIELD: u32 = 0o7_777_777;
/// What a `name` or a `linkname` of the header holds.
const NAME_FIELD: usize = 100;
/// What of the last component goes in the name of an `x` header.
const PAX_BASE_MAX: usize = NAME_FIELD - "PaxHeaders.0/".len();
const MAX_XATTR_NAME: usize = 255;
const MAX_XATTR_VALUE: usize = 65536;
/// The most bytes of the PAX records of one entry, the most xattrs of an
/// entry and the longest path or link target: what the tar reader of a pull
/// takes, so that every canonical tar can be pulled whole.
pub const MAX_PAX_DATA: u64 = 1 << 20;
const MAX_XATTRS: usize = 1024;
const MAX_PATH: usize = 4096;
/// The most entries of a layer, as many as a pull takes.
pub const MAX_ENTRIES: usize = 4 << 20;
/// The most bytes of the names of a layer together: a table of contents
/// with more is larger than a pull takes (128 MiB).  With `MAX_ENTRIES` it
/// bounds what a reader of a tar remembers of the entries before.
const MAX_NAMES: usize = 128 << 20;
const FIRST_TIME: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
const LAST_TIME: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
const END: [u8; 2 * BLOCK] = [0; 2 * BLOCK];

/// What is wrong with a table of contents that has no canonical tar: the
/// entry (its position in the table and its name) and the reason.
#[derive(Debug, thiserror::Error)]
#[error("{reason} (entry {index} `{name}`)")]
pub struct Invalid {
    pub index: usize,
    pub name: String,
    pub reason: String,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// An entry of the tar as the headers say it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fields {
    name: String,
    kind: TocEntryType,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    link: Option<String>,
    mtime: (i64, u32),
    device: (u32, u32),
    xattrs: BTreeMap<String, Vec<u8>>,
}

impl Fields {
    fn of(e: &TocEntry) -> Result<Fields, String> {
        let mtime = match &e.mod_time {
            None => (0, 0),
            Some(t) => toc_time(Some(t)).ok_or("modtime is not RFC 3339")?,
        };
        let mut xattrs = BTreeMap::new();
        for (k, v) in &e.xattrs {
            let v = base64::engine::general_purpose::STANDARD
                .decode(v)
                .map_err(|_| format!("the value of xattr `{k}` is not base64"))?;
            xattrs.insert(k.clone(), v);
        }
        Ok(Fields {
            name: e.name.clone(),
            kind: e.entry_type,
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            size: e.size,
            link: e.link_name.clone(),
            mtime,
            device: (e.dev_major.unwrap_or(0), e.dev_minor.unwrap_or(0)),
            xattrs,
        })
    }

    /// The path without `./` and the `/` of a directory: the components
    /// joined by `/`, empty for the root.
    fn key(&self) -> Result<&str, String> {
        path_key(&self.name)
    }
}

fn path_key(name: &str) -> Result<&str, String> {
    let rest = name
        .strip_prefix("./")
        .ok_or("the name does not start with `./`")?;
    let key = rest.strip_suffix('/').unwrap_or(rest);
    if name.contains('\0') {
        return Err("the name has a NUL".into());
    }
    if !rest.is_empty() && key.split('/').any(|c| matches!(c, "" | "." | "..")) {
        return Err("the name has an empty, `.` or `..` component".into());
    }
    Ok(key)
}

fn components(key: &str) -> impl Iterator<Item = &str> {
    (!key.is_empty())
        .then(|| key.split('/'))
        .into_iter()
        .flatten()
}

/// What the entries before a hard link say of what it can link to.
struct Seen {
    kind: TocEntryType,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, u32),
}

/// The rules of the entries one after the other.
struct Checker {
    previous: Option<String>,
    seen: HashMap<String, Seen>,
    names: usize,
    /// The bytes of the tar so far, and the most it may have.
    tar: u64,
    max_tar: u64,
}

impl Checker {
    fn new(max_tar: u64) -> Self {
        Checker {
            previous: None,
            seen: HashMap::new(),
            names: 0,
            tar: END.len() as u64,
            max_tar,
        }
    }

    fn push(&mut self, f: &Fields) -> Result<(), String> {
        let key = f.key()?;
        self.names += f.name.len();
        if self.seen.len() >= MAX_ENTRIES || self.names > MAX_NAMES {
            return Err(format!(
                "the layer has more than {MAX_ENTRIES} entries or {MAX_NAMES} bytes of names"
            ));
        }
        if f.name.ends_with('/') != (f.kind == TocEntryType::Dir) {
            return Err("a directory is named with a final `/` and nothing else is".into());
        }
        if let Some(previous) = &self.previous {
            match path_order(previous.as_bytes(), key.as_bytes()) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err("the path is in the layer twice".into()),
                std::cmp::Ordering::Greater => {
                    return Err(format!(
                        "the path sorts before the one of the entry before it, `{previous}`"
                    ))
                }
            }
        }
        if f.mode > 0o7777 {
            return Err("the mode has more than the permission bits".into());
        }
        if !(FIRST_TIME..=LAST_TIME).contains(&f.mtime.0) {
            return Err("the time is not in the years 1 to 9999".into());
        }
        if f.size != 0 && f.kind != TocEntryType::Reg {
            return Err("only a regular file has a size".into());
        }
        let is_link = matches!(f.kind, TocEntryType::Symlink | TocEntryType::Hardlink);
        match (&f.link, is_link) {
            (Some(l), true) if !l.is_empty() && !l.contains('\0') => {}
            (None, false) => {}
            (_, true) => return Err("a link needs a target without NUL".into()),
            (_, false) => return Err("only a link has a target".into()),
        }
        let is_device = matches!(f.kind, TocEntryType::Char | TocEntryType::Block);
        if !is_device && f.device != (0, 0) {
            return Err("only a device has device numbers".into());
        }
        if rdev(f.device.0, f.device.1).is_none() {
            return Err("a device number does not fit the header".into());
        }
        if whiteout(f.kind == TocEntryType::Char, f.device.0, f.device.1) {
            return Err("the character device 0/0 is a whiteout of the overlay file system".into());
        }
        if f.xattrs.len() > MAX_XATTRS {
            return Err(format!("the entry has more than {MAX_XATTRS} xattrs"));
        }
        if f.name.len() > MAX_PATH || f.link.as_ref().is_some_and(|l| l.len() > MAX_PATH) {
            return Err(format!("a path is longer than {MAX_PATH} bytes"));
        }
        for (k, v) in &f.xattrs {
            if k.len() > MAX_XATTR_NAME
                || k.contains('=')
                || matches!(class(k.as_bytes()), Class::Refused(_))
            {
                return Err(format!("`{k}` is not a name an xattr can have"));
            }
            if v.len() > MAX_XATTR_VALUE {
                return Err(format!("the value of xattr `{k}` is too large"));
            }
            if matches!(class(k.as_bytes()), Class::Overlay) {
                return Err(format!("the overlay xattr `{k}` is not allowed"));
            }
        }
        if pax_data(f, self.previous.is_none()).len() as u64 > MAX_PAX_DATA {
            return Err(format!(
                "the PAX records of the entry are more than {MAX_PAX_DATA} bytes"
            ));
        }
        let base = components(key).last().unwrap_or("");
        if base.starts_with(".wh.") {
            let whiteout = f.kind == TocEntryType::Reg
                && (f.mode, f.uid, f.gid, f.mtime, f.size) == (0o644, 0, 0, (0, 0), 0)
                && f.xattrs.is_empty();
            if !whiteout {
                return Err(
                    "a whiteout is a regular file of mode 0644, owner 0:0, time 0, \
                            without content and extended attributes"
                        .into(),
                );
            }
        }
        if f.kind == TocEntryType::Hardlink {
            let target = f.link.as_deref().unwrap_or("");
            let canonical = path_key(target).is_ok() && !target.ends_with('/');
            let seen = canonical.then(|| self.seen.get(target)).flatten();
            let Some(t) = seen else {
                return Err(format!(
                    "the target `{target}` of the hard link is not an earlier entry"
                ));
            };
            if matches!(t.kind, TocEntryType::Dir | TocEntryType::Hardlink) {
                return Err("a hard link is not to a directory or to a hard link".into());
            }
            if (t.mode, t.uid, t.gid, t.mtime) != (f.mode, f.uid, f.gid, f.mtime) {
                return Err("a hard link has the mode, owner and time of its target".into());
            }
            if !f.xattrs.is_empty() {
                return Err("a hard link has no xattrs: they are the target's".into());
            }
        }
        let mut head = Vec::new();
        headers(f, self.previous.is_none(), &mut head)?;
        // (what `stream_size` adds up)
        self.tar = content_size(f.kind, f.size)
            .checked_next_multiple_of(BLOCK as u64)
            .and_then(|n| n.checked_add(head.len() as u64))
            .and_then(|n| n.checked_add(self.tar))
            .filter(|&n| n <= self.max_tar)
            .ok_or_else(|| format!("the tar is larger than {} bytes", self.max_tar))?;
        self.seen.insert(
            f.name.clone(),
            Seen {
                kind: f.kind,
                mode: f.mode,
                uid: f.uid,
                gid: f.gid,
                mtime: f.mtime,
            },
        );
        self.previous = Some(key.to_string());
        Ok(())
    }
}

/// The file whose chunks the entries after it are.
struct OpenFile {
    index: usize,
    name: String,
    size: u64,
    covered: u64,
}

/// Says whether the entries have a canonical tar: the rules of the tar
/// alone, for the table of a layer that is not in a blob yet (no place of
/// the data, no chunks).
pub fn validate_entries(entries: &[TocEntry]) -> Result<(), Invalid> {
    let mut checker = Checker::new(u64::MAX);
    for (i, e) in tar_entries(entries).enumerate() {
        let bad = |reason| Invalid {
            index: i,
            name: e.name.clone(),
            reason,
        };
        let f = Fields::of(e).map_err(bad)?;
        checker.push(&f).map_err(bad)?;
    }
    Ok(())
}

/// Says whether the entries of a table of contents have a canonical tar,
/// and the table is one a reader can use: the entries of a file with
/// content have its fs-verity digest and the place of its data in the
/// blob, and its `chunk` entries follow it and cover it.  The tar is at most
/// 2^64-1 bytes.
pub fn validate(entries: &[TocEntry]) -> Result<(), Invalid> {
    validate_within(entries, u64::MAX)
}

/// [`validate`] for a table whose tar has at most `max_tar` bytes: a table
/// that is accepted has a [`stream_size`], and it is at most `max_tar`.
pub fn validate_within(entries: &[TocEntry], max_tar: u64) -> Result<(), Invalid> {
    let bad = |index: usize, reason: String| Invalid {
        index,
        name: entries[index].name.clone(),
        reason,
    };
    let mut checker = Checker::new(max_tar);
    let mut open: Option<OpenFile> = None;
    let finish = |open: &mut Option<OpenFile>| match open.take() {
        Some(f) if f.covered != f.size => Err(Invalid {
            index: f.index,
            name: f.name,
            reason: "its chunks do not cover the file".into(),
        }),
        _ => Ok(()),
    };
    for (i, e) in entries.iter().enumerate() {
        if e.entry_type == TocEntryType::Chunk {
            let Some(f) = open.as_mut().filter(|f| f.name == e.name) else {
                return Err(bad(i, "a chunk does not follow its file".into()));
            };
            if e.chunk_offset != f.covered || e.chunk_size == 0 {
                return Err(bad(i, "the chunk does not continue the file".into()));
            }
            f.covered = f.covered.saturating_add(e.chunk_size);
            if f.covered > f.size {
                return Err(bad(i, "its chunks are more than the file".into()));
            }
            continue;
        }
        finish(&mut open)?;
        let f = Fields::of(e).map_err(|r| bad(i, r))?;
        checker.push(&f).map_err(|r| bad(i, r))?;
        if content_size(f.kind, f.size) > 0 {
            if e.verity().is_none() {
                return Err(bad(i, "a file with content has no fs-verity digest".into()));
            }
            if e.end_offset <= e.offset {
                return Err(bad(
                    i,
                    "a file with content has no place in the blob".into(),
                ));
            }
            if e.chunk_offset != 0 || e.chunk_size > f.size {
                return Err(bad(i, "the first chunk of a file does not start it".into()));
            }
            let covered = if e.chunk_size == 0 {
                f.size
            } else {
                e.chunk_size
            };
            open = Some(OpenFile {
                index: i,
                name: e.name.clone(),
                size: f.size,
                covered,
            });
        }
    }
    finish(&mut open)?;
    match size_conflict(entries) {
        Some((i, reason)) => Err(bad(i, reason)),
        None => Ok(()),
    }
}

struct Block([u8; BLOCK]);

impl Block {
    fn new() -> Block {
        let mut b = Block([0; BLOCK]);
        b.0[257..263].copy_from_slice(b"ustar\0");
        b.0[263..265].copy_from_slice(b"00");
        b
    }

    fn bytes(&mut self, at: usize, v: &[u8]) {
        self.0[at..at + v.len()].copy_from_slice(v);
    }

    /// `v` as octal digits in a field of `len` bytes, padded with zeros,
    /// then a NUL; an error when the digits are more than the field has.
    fn octal(&mut self, at: usize, len: usize, v: u64) -> Result<(), String> {
        if put_octal(&mut self.0[at..at + len], v) {
            Ok(())
        } else {
            Err(format!(
                "{v} does not fit the {} digits of a field",
                len - 1
            ))
        }
    }

    fn finish(mut self) -> [u8; BLOCK] {
        seal(&mut self.0);
        self.0
    }
}

fn pax_record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    // (the space, `=` and the newline are the 3)
    let len = record_len(key.len() + value.len() + 3).expect("a record fits in memory");
    put_decimal(out, len as u64);
    out.push(b' ');
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn pax_number(out: &mut Vec<u8>, key: &str, n: u64) {
    let mut value = Vec::new();
    put_decimal(&mut value, n);
    pax_record(out, key, &value);
}

fn type_flag(kind: TocEntryType) -> u8 {
    match kind {
        TocEntryType::Reg => b'0',
        TocEntryType::Hardlink => b'1',
        TocEntryType::Symlink => b'2',
        TocEntryType::Char => b'3',
        TocEntryType::Block => b'4',
        TocEntryType::Dir => b'5',
        TocEntryType::Fifo => b'6',
        TocEntryType::Chunk => unreachable!("a chunk has no entry in the tar"),
    }
}

fn pax_data(f: &Fields, first: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if first {
        pax_record(&mut out, MARKER.0, MARKER.1.as_bytes());
    }
    if f.name.len() > NAME_FIELD {
        pax_record(&mut out, "path", f.name.as_bytes());
    }
    if let Some(l) = f.link.as_ref().filter(|l| l.len() > NAME_FIELD) {
        pax_record(&mut out, "linkpath", l.as_bytes());
    }
    if f.size > MAX_OCTAL_11 {
        pax_number(&mut out, "size", f.size);
    }
    if f.uid > MAX_ID_FIELD {
        pax_number(&mut out, "uid", u64::from(f.uid));
    }
    if f.gid > MAX_ID_FIELD {
        pax_number(&mut out, "gid", u64::from(f.gid));
    }
    let (secs, nanos) = f.mtime;
    if secs < 0 || secs as u64 > MAX_OCTAL_11 || nanos != 0 {
        let mut value = Vec::new();
        put_time(&mut value, secs, nanos);
        pax_record(&mut out, "mtime", &value);
    }
    for (k, v) in &f.xattrs {
        pax_record(&mut out, &format!("SCHILY.xattr.{k}"), v);
    }
    out
}

fn pad(out: &mut Vec<u8>) {
    out.resize(out.len().next_multiple_of(BLOCK), 0);
}

/// The headers of an entry: the `x` entry when it needs records, then the
/// header of the entry itself.  `first` is for the first entry of the
/// stream.  A number that does not fit its field is an error.
fn headers(f: &Fields, first: bool, out: &mut Vec<u8>) -> Result<(), String> {
    let pax = pax_data(f, first);
    if !pax.is_empty() {
        let key = f.key().unwrap_or("");
        let base = components(key).last().unwrap_or(".").as_bytes();
        let base = &base[..base.len().min(PAX_BASE_MAX)];
        let mut b = Block::new();
        b.bytes(0, b"PaxHeaders.0/");
        b.bytes(13, base);
        b.octal(100, 8, 0o644)?;
        b.octal(108, 8, 0)?;
        b.octal(116, 8, 0)?;
        b.octal(124, 12, pax.len() as u64)?;
        b.octal(136, 12, 0)?;
        b.0[156] = b'x';
        out.extend_from_slice(&b.finish());
        out.extend_from_slice(&pax);
        pad(out);
    }
    let mut b = Block::new();
    let name = f.name.as_bytes();
    b.bytes(0, &name[..name.len().min(NAME_FIELD)]);
    b.octal(100, 8, u64::from(f.mode))?;
    b.octal(
        108,
        8,
        u64::from(if f.uid > MAX_ID_FIELD { 0 } else { f.uid }),
    )?;
    b.octal(
        116,
        8,
        u64::from(if f.gid > MAX_ID_FIELD { 0 } else { f.gid }),
    )?;
    b.octal(124, 12, if f.size > MAX_OCTAL_11 { 0 } else { f.size })?;
    let secs = f.mtime.0;
    b.octal(
        136,
        12,
        if (0..=MAX_OCTAL_11 as i64).contains(&secs) {
            secs as u64
        } else {
            0
        },
    )?;
    b.0[156] = type_flag(f.kind);
    if let Some(l) = &f.link {
        let l = l.as_bytes();
        b.bytes(157, &l[..l.len().min(NAME_FIELD)]);
    }
    if matches!(f.kind, TocEntryType::Char | TocEntryType::Block) {
        b.octal(329, 8, u64::from(f.device.0))?;
        b.octal(337, 8, u64::from(f.device.1))?;
    }
    out.extend_from_slice(&b.finish());
    Ok(())
}

/// The entries that are in the tar.
fn tar_entries(entries: &[TocEntry]) -> impl Iterator<Item = &TocEntry> {
    entries
        .iter()
        .filter(|e| e.entry_type != TocEntryType::Chunk)
}

/// The number of bytes of the canonical tar of the entries.
pub fn stream_size(entries: &[TocEntry]) -> io::Result<u64> {
    let mut size = END.len() as u64;
    for (i, e) in tar_entries(entries).enumerate() {
        let head = header(e, i == 0)?;
        // (the sizes of a table that was pulled are anything a u64 holds)
        size = content_size(e.entry_type, e.size)
            .checked_next_multiple_of(BLOCK as u64)
            .and_then(|n| n.checked_add(head.len() as u64))
            .and_then(|n| n.checked_add(size))
            .ok_or_else(|| invalid("the tar is larger than 2^64 bytes"))?;
    }
    Ok(size)
}

/// The bytes of the headers of the entry `e` in the canonical tar, `first`
/// for the first entry of the stream.
pub fn header(e: &TocEntry, first: bool) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    headers(&Fields::of(e).map_err(invalid)?, first, &mut head).map_err(invalid)?;
    Ok(head)
}

/// The number of zeros that follow the content of `size` bytes.
fn padding(size: u64) -> usize {
    (size.wrapping_neg() % BLOCK as u64) as usize
}

/// The tar without its contents, in parts: `part(i, bytes)` for what belongs
/// to the entry `i` (the padding of the entry before it, its headers, and for
/// a file with content its size as 8 bytes, little endian, in place of the
/// content), then the padding of the last entry and the end of the stream as
/// the part of the entry after the last.  Two writers of a tar agree on
/// everything but the contents when they give the same parts, and the
/// contents are what the digests of the table of contents are of.
pub fn skeleton(entries: &[TocEntry], mut part: impl FnMut(usize, &[u8])) -> io::Result<()> {
    let mut pad = 0;
    let mut n = 0;
    for (i, e) in tar_entries(entries).enumerate() {
        part(i, &END[..pad]);
        part(i, &header(e, i == 0)?);
        let size = content_size(e.entry_type, e.size);
        if size > 0 {
            part(i, &size.to_le_bytes());
        }
        pad = padding(size);
        n = i + 1;
    }
    part(n, &END[..pad]);
    part(n, &END);
    Ok(())
}

/// The canonical tar of the table of contents `toc` as a stream: `open`
/// gives the content of the regular file it is called with (only the ones
/// with a size), which is read as far as its size.  The table is one that
/// [`validate`] accepts.
pub fn reader<O>(toc: std::sync::Arc<crate::Toc>, open: O) -> impl Read + Send
where
    O: FnMut(&TocEntry) -> io::Result<Box<dyn Read + Send>> + Send,
{
    Tar {
        toc,
        at: 0,
        count: 0,
        buf: Vec::new(),
        pos: 0,
        content: None,
        open,
        ended: false,
    }
}

struct Tar<O> {
    toc: std::sync::Arc<crate::Toc>,
    /// The next entry of the table, and how many entries of the tar came
    at: usize,
    count: usize,
    /// What is given before anything else
    buf: Vec<u8>,
    pos: usize,
    /// The content in progress, what is left of it and its padding
    content: Option<(Box<dyn Read + Send>, u64, usize)>,
    open: O,
    ended: bool,
}

impl<O> Read for Tar<O>
where
    O: FnMut(&TocEntry) -> io::Result<Box<dyn Read + Send>> + Send,
{
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if let Some((r, left, pad)) = &mut self.content {
                if *left == 0 {
                    self.buf = END[..*pad].to_vec();
                    self.pos = 0;
                    self.content = None;
                    continue;
                }
                let max = out.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
                let n = r.read(&mut out[..max])?;
                if n == 0 && max > 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                *left -= n as u64;
                return Ok(n);
            }
            let toc = self.toc.clone();
            let mut entries = toc.entries[self.at..].iter();
            let Some(e) = entries.find(|e| e.entry_type != TocEntryType::Chunk) else {
                if self.ended {
                    return Ok(0);
                }
                self.ended = true;
                self.buf = END.to_vec();
                self.pos = 0;
                continue;
            };
            self.at = toc.entries.len() - entries.len();
            self.buf = header(e, self.count == 0)?;
            self.pos = 0;
            self.count += 1;
            let size = content_size(e.entry_type, e.size);
            if size > 0 {
                self.content = Some(((self.open)(e)?, size, padding(size)));
            }
        }
    }
}

struct Counted<'a> {
    out: &'a mut dyn Write,
    written: u64,
}

impl Write for Counted<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Write the canonical tar of the entries to `out`.  `content` writes the
/// content of the regular file it is given (only the ones with a size), as
/// many bytes as its size.  The entries are the ones of a table of
/// contents that [`validate`] accepts.
pub fn write<W: Write>(
    entries: &[TocEntry],
    mut out: W,
    mut content: impl FnMut(&TocEntry, &mut dyn Write) -> io::Result<()>,
) -> io::Result<()> {
    for (i, e) in tar_entries(entries).enumerate() {
        out.write_all(&header(e, i == 0)?)?;
        let size = content_size(e.entry_type, e.size);
        if size > 0 {
            let mut counted = Counted {
                out: &mut out,
                written: 0,
            };
            content(e, &mut counted)?;
            if counted.written != size {
                return Err(invalid(format!(
                    "`{}` has {} bytes of content, not {size}",
                    e.name, counted.written
                )));
            }
            out.write_all(&END[..padding(size)])?;
        }
    }
    out.write_all(&END)
}

/// The records of an `x` entry the stream can have.
#[derive(Default)]
struct Pax {
    path: Option<String>,
    link: Option<String>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<(i64, u32)>,
    xattrs: BTreeMap<String, Vec<u8>>,
}

fn parse_pax(mut data: &[u8]) -> Result<Pax, String> {
    let mut pax = Pax::default();
    let text = |v: &[u8]| {
        String::from_utf8(v.to_vec()).map_err(|_| "a PAX value is not UTF-8".to_string())
    };
    while !data.is_empty() {
        let record = velarx_tarsplit_header::pax_record(data).map_err(|e| match e {
            PaxError::Length => "bad PAX record length",
            PaxError::Record => "bad PAX record",
        })?;
        let (key, value) = (&data[record.key], &data[record.value]);
        data = &data[record.len..];
        let key = std::str::from_utf8(key).map_err(|_| "a PAX key is not UTF-8")?;
        let number = |v: &[u8]| decimal(v).map_err(|_| format!("bad PAX {key}"));
        match key {
            "comment" if value == MARKER.1.as_bytes() => {}
            "path" => pax.path = Some(text(value)?),
            "linkpath" => pax.link = Some(text(value)?),
            "size" => pax.size = Some(number(value)?),
            "uid" => pax.uid = Some(number(value)?),
            "gid" => pax.gid = Some(number(value)?),
            "mtime" => pax.mtime = Some(pax_time(value).map_err(|_| "bad PAX mtime")?),
            _ => match key.strip_prefix("SCHILY.xattr.") {
                Some(name) => {
                    pax.xattrs.insert(name.to_string(), value.to_vec());
                }
                None => return Err(format!("the PAX record `{key}` is not allowed")),
            },
        }
    }
    Ok(pax)
}

/// A number field as `number` reads it, which takes more spellings than the
/// writer makes (spaces, base 256): the check that the headers are what the
/// rules make refuses them all, as it does any other byte that differs.
fn header_number(field: &[u8], what: &str) -> Result<u64, String> {
    number(field).map_err(|_| format!("{what} is not a number"))
}

/// The entry a header describes, with the records before it.
fn decode(h: &[u8; BLOCK], pax: &Pax) -> Result<Fields, String> {
    let kind = match h[156] {
        b'0' => TocEntryType::Reg,
        b'1' => TocEntryType::Hardlink,
        b'2' => TocEntryType::Symlink,
        b'3' => TocEntryType::Char,
        b'4' => TocEntryType::Block,
        b'5' => TocEntryType::Dir,
        b'6' => TocEntryType::Fifo,
        t => return Err(format!("the type {:?} is not allowed", t as char)),
    };
    let text =
        |v: &[u8]| String::from_utf8(v.to_vec()).map_err(|_| "a name is not UTF-8".to_string());
    let id = |p: Option<u64>, at: usize, what: &str| {
        let v = match p {
            Some(v) => v,
            None => header_number(&h[at..at + 8], what)?,
        };
        u32::try_from(v).map_err(|_| format!("{what} is too large"))
    };
    let mtime = match pax.mtime {
        Some(t) => t,
        None => (header_number(&h[136..148], "the time")? as i64, 0),
    };
    let link = match (&pax.link, kind) {
        (Some(l), _) => Some(l.clone()),
        (None, TocEntryType::Symlink | TocEntryType::Hardlink) => Some(text(cstr(&h[157..257]))?),
        _ => None,
    };
    let device = if matches!(kind, TocEntryType::Char | TocEntryType::Block) {
        (
            id(None, 329, "the major number")?,
            id(None, 337, "the minor number")?,
        )
    } else {
        (0, 0)
    };
    Ok(Fields {
        name: match &pax.path {
            Some(p) => p.clone(),
            None => text(cstr(&h[..NAME_FIELD]))?,
        },
        kind,
        mode: u32::try_from(header_number(&h[100..108], "the mode")?)
            .map_err(|_| "the mode is too large")?,
        uid: id(pax.uid, 108, "the uid")?,
        gid: id(pax.gid, 116, "the gid")?,
        size: match pax.size {
            Some(s) => s,
            None => header_number(&h[124..136], "the size")?,
        },
        link,
        mtime,
        device,
        xattrs: pax.xattrs.clone(),
    })
}

fn read_block(r: &mut impl Read, b: &mut [u8; BLOCK]) -> io::Result<()> {
    r.read_exact(b).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => invalid("the archive ends before its two zero blocks"),
        _ => e,
    })
}

/// Read `n` bytes, which must be the padding of a content or of records.
fn zeros(r: &mut impl Read, n: u64) -> io::Result<()> {
    let mut pad = Vec::new();
    r.take(n).read_to_end(&mut pad)?;
    if pad.len() as u64 != n || pad.iter().any(|&b| b != 0) {
        return Err(invalid("the padding is not zeros"));
    }
    Ok(())
}

/// Says whether a tar stream is canonical: that it is exactly the tar
/// [`write`] makes for the entries it holds, and that these have a canonical
/// tar (the rules of [`validate`] that do not need the table of contents).
/// The content of the files is not read into memory and not checked.
pub fn validate_tar(mut r: impl Read) -> io::Result<()> {
    let mut checker = Checker::new(u64::MAX);
    let mut raw = Vec::new();
    let mut expected = Vec::new();
    let mut block = [0u8; BLOCK];
    for index in 0.. {
        read_block(&mut r, &mut block)?;
        if block == [0; BLOCK] {
            read_block(&mut r, &mut block)?;
            if block != [0; BLOCK] {
                return Err(invalid("the archive ends with one zero block"));
            }
            return match r.read(&mut block[..1])? {
                0 => Ok(()),
                _ => Err(invalid("there is data after the two zero blocks")),
            };
        }
        let at = |reason: String, name: &str| {
            invalid(format!("not canonical: {reason} (entry {index} `{name}`)"))
        };
        raw.clear();
        raw.extend_from_slice(&block);
        let mut pax = Pax::default();
        if block[156] == b'x' {
            let size = header_number(&block[124..136], "the size of the records")
                .map_err(|e| at(e, ""))?;
            if size > MAX_PAX_DATA {
                return Err(at("the PAX records are too large".into(), ""));
            }
            let padded = size.next_multiple_of(BLOCK as u64) as usize;
            raw.resize(BLOCK + padded, 0);
            r.read_exact(&mut raw[BLOCK..])?;
            pax = parse_pax(&raw[BLOCK..BLOCK + size as usize]).map_err(|e| at(e, ""))?;
            read_block(&mut r, &mut block)?;
            raw.extend_from_slice(&block);
        }
        let f = decode(&block, &pax).map_err(|e| at(e, ""))?;
        expected.clear();
        headers(&f, index == 0, &mut expected).map_err(|e| at(e, &f.name))?;
        if raw != expected {
            return Err(at(
                "the headers are not what the rules make".into(),
                &f.name,
            ));
        }
        checker.push(&f).map_err(|e| at(e, &f.name))?;
        let size = content_size(f.kind, f.size);
        let copied = io::copy(&mut r.by_ref().take(size), &mut io::sink())?;
        if copied != size {
            return Err(at("the content is cut".into(), &f.name));
        }
        zeros(&mut r, padding(size) as u64).map_err(|e| at(e.to_string(), &f.name))?;
    }
    unreachable!("the loop returns at the end of the archive")
}

#[cfg(test)]
mod tests;
