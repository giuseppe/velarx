// SPDX-License-Identifier: Apache-2.0
//! The binary table of a zstd:chunked layer: what its table of contents
//! says, in records of fixed size that are read without a parser.
//!
//! A layer written with one has it in a zstd skippable frame of its own,
//! named by the annotations `table-position` and `table-checksum` (which a
//! reader of the JSON table of contents does not know and ignores).  Every
//! digest of the table is of the algorithm of the layer's digests (its
//! descriptor and its diff id), as are the digests of the table of contents.
//!
//! Little endian, no alignment; `D` is the length of a digest (32 for
//! sha256, 64 for sha512):
//!
//! ```text
//! header
//!   0     magic "ZCTABLE1"
//!   8     version u32 = 1
//!   12    required features u32  (none known: any bit is refused)
//!   16    optional features u32  (none known: ignored)
//!   20    digest algorithm u8    (1 sha256, 2 sha512)
//!   21    flags u8               (1: a canonical tar, no tar-split)
//!   22    zero[10]
//!   32    tar-split digest[D]    (zeros for a canonical tar)
//!   32+D  8 x { offset u64, length u64 }: the sections, in order, which
//!         tile the rest of the table
//! sections
//!   0 entries, 32 bytes each, breadth first from the root (entry 0); the
//!     children of a directory are one run, sorted by name as bytes
//!       0 name offset u32, 4 name length u16   (in section 1)
//!       6 kind u8 (0 dir, 1 file, 2 symlink, 3 hard link, 4 char, 5 block,
//!         6 fifo), 7 flags u8 (1: a directory the layer does not have)
//!       8 mode u16 (07777), 10 owner u16, 12 time u32, 16 parent u32
//!       20 a u32, 24 b u32: dir: first child, children | file: file + 1
//!         (0 when empty) | symlink: offset and length in section 2 |
//!         hard link: the entry it links to | device: major, minor
//!       28 extended attributes u32           (set + 1 in section 5, or 0)
//!   1 names: the last component of each path, in entry order
//!   2 symlink targets, in entry order
//!   3 owners: { uid u32, gid u32 }, sorted
//!   4 times: { seconds i64, nanoseconds u32 }, sorted
//!   5 sets of extended attributes, in the order the entries first use them:
//!     count u16, then { name length u16, value length u32, name, value },
//!     sorted by name
//!   6 files, D + 32 bytes each, sorted by fs-verity digest:
//!       fs-verity digest[D], size u64, blob offset u64, blob length u64,
//!       first chunk u32, chunks u32 (0: one zstd frame, checked by the
//!       fs-verity digest of the file)
//!   7 chunks, D + 16 bytes each, the chunks of each file in file order:
//!       blob offset u64, length u64 (bit 63: zeros), digest[D]
//! ```
//!
//! A table has one valid encoding: what [`decode`] accepts, [`encode`]
//! gives back byte for byte (the optional features aside).  So the table is
//! a function of the table of contents a layer is stored by, and anything
//! that is not that function (a gap, a duplicate, an unused record, a loop)
//! is refused before anything of it is used.

use crate::{rfc3339, toc_time, Toc, TocEntry, TocEntryType, TOC_VERSION, TOC_VERSION_CANONICAL};
use base64::Engine;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use velarx_types::digest::{Algorithm, Digest};

pub const MAGIC: &[u8; 8] = b"ZCTABLE1";
pub const VERSION: u32 = 1;
const SECTIONS: usize = 8;
const ENTRY: usize = 32;
const OWNER: usize = 8;
const TIME: usize = 12;
const CANONICAL: u8 = 1;
const IMPLIED: u8 = 1;
const ROOT_PARENT: u32 = u32::MAX;
const ZEROS: u64 = 1 << 63;
const MAX_NAME: usize = 255;
const MAX_PATH: usize = 4096;
const MAX_XATTRS: usize = 1024;
const MAX_XATTR_VALUE: usize = 65536;
/// The most bytes of the names and values of the extended attributes of an
/// entry, as a tar header has (`velarx_tarsplit`).
const MAX_XATTR_BYTES: usize = 1 << 20;
/// The most components of a path, as a tar header has (`velarx_tarsplit`).
pub const MAX_DEPTH: usize = 512;
const MAX_DEVICE: u32 = 0o7_777_777;
const FIRST_TIME: i64 = -62_135_596_800; // 0001-01-01T00:00:00Z
const LAST_TIME: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
/// The most entries of a table, as many as a layer has.
const MAX_ENTRIES: usize = crate::canonical::MAX_ENTRIES;
/// The most bytes of the names of the table of contents a table decodes to
/// (paths, link targets, the names of chunk entries).
const MAX_NAMES: usize = 128 << 20;

/// The length of the header of a table of digests of `alg`.
fn header_len(alg: Algorithm) -> usize {
    32 + alg.len() + 16 * SECTIONS
}

fn alg_byte(alg: Algorithm) -> u8 {
    match alg {
        Algorithm::Sha256 => 1,
        Algorithm::Sha512 => 2,
    }
}

fn file_record(alg: Algorithm) -> usize {
    alg.len() + 32
}

fn chunk_record(alg: Algorithm) -> usize {
    alg.len() + 16
}

/// What the header of a table says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub alg: Algorithm,
    /// The digest of the tar-split; none for a canonical tar.
    pub tarsplit: Option<Digest>,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// The header of `table` and its sections.
fn sections(table: &[u8]) -> Result<(Head, [&[u8]; SECTIONS]), String> {
    if table.len() < 32 || &table[..8] != MAGIC {
        return Err("not a table".into());
    }
    if u32_at(table, 8) != VERSION {
        return Err(format!("version {} of the table", u32_at(table, 8)));
    }
    if u32_at(table, 12) != 0 {
        return Err(format!(
            "the table requires the features {:#x}",
            u32_at(table, 12)
        ));
    }
    let alg = match table[20] {
        1 => Algorithm::Sha256,
        2 => Algorithm::Sha512,
        n => return Err(format!("digest algorithm {n} of the table")),
    };
    let flags = table[21];
    if flags & !CANONICAL != 0 || table[22..32].iter().any(|&b| b != 0) {
        return Err("reserved bits of the header are set".into());
    }
    let header = header_len(alg);
    if table.len() < header {
        return Err("the header of the table is truncated".into());
    }
    let ts = &table[32..32 + alg.len()];
    let canonical = flags & CANONICAL != 0;
    if canonical != ts.iter().all(|&b| b == 0) {
        return Err("a table has a tar-split digest if and only if it is not canonical".into());
    }
    let tarsplit = (!canonical)
        .then(|| Digest::from_bytes(alg, ts))
        .transpose()
        .map_err(|e| e.to_string())?;
    let mut out = [&table[..0]; SECTIONS];
    let mut at = header as u64;
    for (i, slot) in out.iter_mut().enumerate() {
        let d = 32 + alg.len() + 16 * i;
        let (offset, length) = (u64_at(table, d), u64_at(table, d + 8));
        let end = offset
            .checked_add(length)
            .filter(|&e| e <= table.len() as u64);
        let Some(end) = end.filter(|_| offset == at) else {
            return Err(format!(
                "section {i} of the table is not where it should be"
            ));
        };
        *slot = &table[offset as usize..end as usize];
        at = end;
    }
    if at != table.len() as u64 {
        return Err("bytes after the last section of the table".into());
    }
    Ok((Head { alg, tarsplit }, out))
}

/// The header of `table`, checked: its algorithm and its tar-split digest.
pub fn head(table: &[u8]) -> Result<Head, String> {
    sections(table).map(|(head, _)| head)
}

/// An entry of section 0.
#[derive(Clone, Copy)]
struct Raw {
    name: (u32, u16),
    kind: u8,
    flags: u8,
    mode: u16,
    owner: u16,
    time: u32,
    parent: u32,
    a: u32,
    b: u32,
    xattrs: u32,
}

impl Raw {
    fn read(b: &[u8]) -> Raw {
        Raw {
            name: (u32_at(b, 0), u16_at(b, 4)),
            kind: b[6],
            flags: b[7],
            mode: u16_at(b, 8),
            owner: u16_at(b, 10),
            time: u32_at(b, 12),
            parent: u32_at(b, 16),
            a: u32_at(b, 20),
            b: u32_at(b, 24),
            xattrs: u32_at(b, 28),
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend(self.name.0.to_le_bytes());
        out.extend(self.name.1.to_le_bytes());
        out.extend([self.kind, self.flags]);
        out.extend(self.mode.to_le_bytes());
        out.extend(self.owner.to_le_bytes());
        out.extend(self.time.to_le_bytes());
        out.extend(self.parent.to_le_bytes());
        out.extend(self.a.to_le_bytes());
        out.extend(self.b.to_le_bytes());
        out.extend(self.xattrs.to_le_bytes());
    }
}

const KINDS: [TocEntryType; 7] = [
    TocEntryType::Dir,
    TocEntryType::Reg,
    TocEntryType::Symlink,
    TocEntryType::Hardlink,
    TocEntryType::Char,
    TocEntryType::Block,
    TocEntryType::Fifo,
];

fn kind_byte(kind: TocEntryType) -> Option<u8> {
    KINDS.iter().position(|&k| k == kind).map(|i| i as u8)
}

/// A file of section 6.
struct File<'a> {
    verity: &'a [u8],
    size: u64,
    blob: (u64, u64),
    chunks: (u32, u32),
}

/// A chunk of section 7.
struct Chunk<'a> {
    blob: u64,
    length: u64,
    zeros: bool,
    digest: &'a [u8],
}

fn is_overlay_xattr(name: &str) -> bool {
    ["trusted.", "user.", "security.", "system."]
        .iter()
        .any(|ns| {
            name.strip_prefix(ns)
                .is_some_and(|n| n.starts_with("overlay."))
        })
}

/// The sets of extended attributes of section 5, checked: sorted, distinct,
/// of names a layer keeps, of at most `MAX_XATTR_BYTES` of names and
/// values each.  The extent of each in the section.
fn xattr_sets(b: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    let bad = |why: &str| Err(format!("extended attributes: {why}"));
    let mut sets = Vec::new();
    let mut seen = BTreeSet::new();
    let mut at = 0;
    while at < b.len() {
        let start = at;
        if b.len() - at < 2 {
            return bad("a truncated set");
        }
        let count = u16_at(b, at) as usize;
        at += 2;
        if count == 0 || count > MAX_XATTRS {
            return bad("a set of no attribute or of too many");
        }
        let (mut last, mut bytes): (Option<&[u8]>, usize) = (None, 0);
        for _ in 0..count {
            if b.len() - at < 6 {
                return bad("a truncated attribute");
            }
            let (n, v) = (u16_at(b, at) as usize, u32_at(b, at + 2) as usize);
            if n == 0 || n > MAX_NAME || v > MAX_XATTR_VALUE || b.len() - at - 6 < n + v {
                return bad("an attribute of an invalid length");
            }
            let name = &b[at + 6..at + 6 + n];
            at += 6 + n + v;
            bytes += n + v;
            if last.is_some_and(|l| l >= name) {
                return bad("the names of a set are not sorted");
            }
            last = Some(name);
            let kept =
                std::str::from_utf8(name).is_ok_and(|n| !n.contains('\0') && !is_overlay_xattr(n));
            if !kept {
                return bad("an attribute a layer does not have");
            }
        }
        if bytes > MAX_XATTR_BYTES {
            return bad("a set of too many bytes");
        }
        if !seen.insert(&b[start..at]) {
            return bad("a set is there twice");
        }
        sets.push((start, at));
    }
    Ok(sets)
}

/// A set of extended attributes that [`xattr_sets`] checked, as a table of
/// contents has it (values in base64).
fn xattr_map(b: &[u8]) -> HashMap<String, String> {
    let count = u16_at(b, 0) as usize;
    let mut set = HashMap::with_capacity(count);
    let mut at = 2;
    for _ in 0..count {
        let (n, v) = (u16_at(b, at) as usize, u32_at(b, at + 2) as usize);
        let (name, value) = (&b[at + 6..at + 6 + n], &b[at + 6 + n..at + 6 + n + v]);
        at += 6 + n + v;
        set.insert(
            utf8(name).to_string(),
            base64::engine::general_purpose::STANDARD.encode(value),
        );
    }
    set
}

/// The text of bytes the table checked to be UTF-8.
fn utf8(b: &[u8]) -> &str {
    std::str::from_utf8(b).unwrap_or_default()
}

/// Whether `name` is a component of a path a table can have.
fn component_ok(name: &[u8]) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name != b"."
        && name != b".."
        && !name.iter().any(|&c| c == b'/' || c == 0)
}

/// A table that [`Table::open`] checked, read where it is.
pub struct Table<'a> {
    head: Head,
    s: [&'a [u8]; SECTIONS],
    /// Where each set of extended attributes is in section 5.
    sets: Vec<(usize, usize)>,
    /// The entries in the order of their paths: depth first, the children
    /// of a directory in their order.
    order: Vec<u32>,
    /// The bytes of the files of the entries (of a file once per entry).
    file_bytes: u64,
}

impl<'a> Table<'a> {
    /// `table` checked (see the module), for a blob whose data ends at
    /// `data_end` (where its metadata starts): every range of a file is
    /// before it.  Nothing is allocated by a count the table claims, and
    /// nothing of it is used before all of it is checked.
    pub fn open(table: &'a [u8], data_end: u64) -> Result<Self, String> {
        let (head, s) = sections(table)?;
        let alg = head.alg;
        let (fr, cr) = (file_record(alg), chunk_record(alg));
        let records = [(0, ENTRY), (3, OWNER), (4, TIME), (6, fr), (7, cr)];
        if let Some((i, _)) = records.iter().find(|(i, n)| s[*i].len() % n != 0) {
            return Err(format!("section {i} of the table is not whole records"));
        }
        let n = s[0].len() / ENTRY;
        if n == 0 || n > MAX_ENTRIES {
            return Err("the table has no entries or too many".into());
        }
        let (n_owners, n_times) = (s[3].len() / OWNER, s[4].len() / TIME);
        let owner = |i: usize| (u32_at(s[3], i * OWNER), u32_at(s[3], i * OWNER + 4));
        let time = |i: usize| (u64_at(s[4], i * TIME) as i64, u32_at(s[4], i * TIME + 8));
        if n_owners > 1 << 16 || (1..n_owners).any(|i| owner(i - 1) >= owner(i)) {
            return Err("the owners are not sorted or too many".into());
        }
        if (1..n_times).any(|i| time(i - 1) >= time(i))
            || (0..n_times)
                .map(time)
                .any(|(s, ns)| !(FIRST_TIME..=LAST_TIME).contains(&s) || ns >= 1_000_000_000)
        {
            return Err("the times are not sorted or out of range".into());
        }
        let mut t = Table {
            sets: xattr_sets(s[5])?,
            head,
            s,
            order: Vec::new(),
            file_bytes: 0,
        };
        let n_files = s[6].len() / fr;
        t.check_files(data_end)?;
        let n_sets = t.sets.len();
        let (names, targets) = (s[1], s[2]);

        // The tree: every entry but the root is in the run of children of a
        // directory before it, so each has one parent, before it, and the
        // runs tile the entries (no loop, no orphan).
        let mut parent = vec![ROOT_PARENT; n];
        // (the length of the path of each entry, `/` before each
        // component, and the number of its components)
        let mut path_len = vec![0usize; n];
        let mut depth = vec![0usize; n];
        let mut next = 1usize;
        let (mut name_at, mut target_at) = (0usize, 0usize);
        let (mut owner_used, mut time_used) = (vec![false; n_owners], vec![false; n_times]);
        let mut file_used = vec![false; n_files];
        let mut sets_used = 0usize;
        let mut prev_name: &[u8] = &[];
        for i in 0..n {
            let e = t.entry(i);
            let bad = |why: &str| Err(format!("entry {i} of the table: {why}"));
            if i > 0 && i >= next {
                return bad("it is in no directory");
            }
            if e.parent != parent[i] {
                return bad("its parent is not the directory it is in");
            }
            let (off, len) = (e.name.0 as usize, e.name.1 as usize);
            if off != name_at || names.len() - name_at < len {
                return bad("its name is not the next one of the names");
            }
            let name = &names[off..off + len];
            name_at += len;
            if i == 0 {
                if len != 0 || e.kind != 0 {
                    return bad("the root is a directory without a name");
                }
            } else {
                if !component_ok(name) {
                    return bad("an invalid name");
                }
                if std::str::from_utf8(name).is_err() {
                    return bad("a name that is not UTF-8");
                }
                let p = parent[i] as usize;
                if parent[i - 1] == parent[i] && prev_name >= name {
                    return bad("the names of a directory are not sorted");
                }
                path_len[i] = path_len[p] + 1 + len;
                depth[i] = depth[p] + 1;
                // (the name of the table of contents: `./`, the path
                // without its first `/`, and `/` for a directory)
                if path_len[i] + 1 + usize::from(e.kind == 0) > MAX_PATH {
                    return bad("its path is too long");
                }
                if depth[i] > MAX_DEPTH {
                    return bad("its path is too deep");
                }
            }
            prev_name = name;
            let implied = e.flags == IMPLIED;
            if e.flags & !IMPLIED != 0 || (implied && e.kind != 0) {
                return bad("invalid flags");
            }
            if implied {
                if (e.mode, e.owner, e.time, e.xattrs) != (0, 0, 0, 0) || (e.b == 0 && i > 0) {
                    return bad(
                        "a directory the layer does not have has attributes or no children",
                    );
                }
            } else {
                if e.mode > 0o7777 {
                    return bad("a mode with more than the permission bits");
                }
                let (o, tm) = (e.owner as usize, e.time as usize);
                if o >= n_owners || tm >= n_times {
                    return bad("an owner or a time that is not in the table");
                }
                owner_used[o] = true;
                time_used[tm] = true;
                match e.xattrs as usize {
                    0 => {}
                    x if x <= sets_used => {}
                    x if x == sets_used + 1 && x <= n_sets => sets_used = x,
                    _ => return bad("extended attributes out of order or not in the table"),
                }
            }
            let (a, b) = (e.a as usize, e.b as usize);
            match e.kind {
                0 if b == 0 && a == 0 => {}
                0 if b > 0 && a == next && b <= n - next => {
                    parent[a..a + b].fill(i as u32);
                    next += b;
                }
                1 if b == 0 && a == 0 => {}
                1 if b == 0 && a <= n_files => file_used[a - 1] = true,
                2 if a == target_at && (1..=MAX_PATH).contains(&b) && targets.len() - a >= b => {
                    let target = &targets[a..a + b];
                    if target.contains(&0) {
                        return bad("an invalid symlink target");
                    }
                    if std::str::from_utf8(target).is_err() {
                        return bad("a symlink target that is not UTF-8");
                    }
                    target_at += b;
                }
                3 if a < n && b == 0 => {}
                4 | 5 if e.a <= MAX_DEVICE && e.b <= MAX_DEVICE => {}
                6 if a == 0 && b == 0 => {}
                _ => return bad("an invalid kind or fields of its kind"),
            }
        }
        if next != n || name_at != names.len() || target_at != targets.len() {
            return Err("the table has entries, names or targets that no entry has".into());
        }
        if owner_used.contains(&false) || time_used.contains(&false) || sets_used != n_sets {
            return Err("the table has owners, times or attributes that no entry has".into());
        }
        if file_used.contains(&false) {
            return Err("the table has files that no entry has".into());
        }

        // The order of the paths.  A hard link is to an entry before it in
        // that order that is not a directory nor a hard link.
        let mut order = Vec::with_capacity(n);
        let mut stack = vec![0u32];
        while let Some(i) = stack.pop() {
            order.push(i);
            let e = t.entry(i as usize);
            if e.kind == 0 {
                stack.extend((e.a..e.a + e.b).rev());
            }
        }
        let mut position = vec![0u32; n];
        for (p, &i) in order.iter().enumerate() {
            position[i as usize] = p as u32;
        }
        // (and what the table of contents of the table holds: its entries
        // and the bytes of their names, which a layer bounds)
        let (mut out_entries, mut out_names) = (0usize, 0usize);
        for i in 0..n {
            let e = t.entry(i);
            let path = path_len[i] + 3;
            let (entries, names) = match e.kind {
                0 if e.flags == IMPLIED => (0, 0),
                1 if e.a > 0 => {
                    let f = t.file(e.a as usize - 1);
                    t.file_bytes = t.file_bytes.saturating_add(f.size);
                    let chunks = (f.chunks.1 as usize).max(1);
                    (chunks, path * chunks)
                }
                2 => (1, path + e.b as usize),
                3 => {
                    let target = e.a as usize;
                    let kind = t.entry(target).kind;
                    if kind == 0 || kind == 3 || position[target] >= position[i] {
                        return Err(format!(
                            "entry {i} of the table: a hard link to a directory, a hard link \
                             or an entry after it"
                        ));
                    }
                    (1, path + path_len[target] + 3)
                }
                _ => (1, path),
            };
            out_entries += entries;
            out_names += names;
            if out_entries > MAX_ENTRIES || out_names > MAX_NAMES {
                return Err("the table has too many entries or bytes of names".into());
            }
        }
        t.order = order;
        Ok(t)
    }

    /// What the header of the table says.
    pub fn head(&self) -> &Head {
        &self.head
    }

    /// The bytes of the files of the entries, a file counted once for each
    /// entry that has it (as many as a tar of the layer holds).
    pub fn file_bytes(&self) -> u64 {
        self.file_bytes
    }

    fn entry(&self, i: usize) -> Raw {
        Raw::read(&self.s[0][i * ENTRY..])
    }

    fn name(&self, e: &Raw) -> &'a str {
        utf8(&self.s[1][e.name.0 as usize..][..e.name.1 as usize])
    }

    fn file(&self, i: usize) -> File<'a> {
        let d = self.head.alg.len();
        let f = &self.s[6][i * file_record(self.head.alg)..];
        File {
            verity: &f[..d],
            size: u64_at(f, d),
            blob: (u64_at(f, d + 8), u64_at(f, d + 16)),
            chunks: (u32_at(f, d + 24), u32_at(f, d + 28)),
        }
    }

    fn chunk(&self, i: usize) -> Chunk<'a> {
        let c = &self.s[7][i * chunk_record(self.head.alg)..][..chunk_record(self.head.alg)];
        Chunk {
            blob: u64_at(c, 0),
            length: u64_at(c, 8) & !ZEROS,
            zeros: u64_at(c, 8) & ZEROS != 0,
            digest: &c[16..],
        }
    }

    /// The files and their chunks: sorted and distinct, in the data of the
    /// blob, the chunks of each in order inside its range and adding up to
    /// it.
    fn check_files(&self, data_end: u64) -> Result<(), String> {
        let n_files = self.s[6].len() / file_record(self.head.alg);
        let n_chunks = self.s[7].len() / chunk_record(self.head.alg);
        let mut at = 0usize;
        for i in 0..n_files {
            let bad = |why: &str| Err(format!("file {i} of the table: {why}"));
            let f = self.file(i);
            if i > 0 && self.file(i - 1).verity >= f.verity {
                return bad("the files are not sorted by digest");
            }
            let end = f.blob.0.checked_add(f.blob.1);
            if f.size == 0 || f.blob.1 == 0 || end.is_none_or(|e| e > data_end) {
                return bad("an empty file or a range outside of the data of the blob");
            }
            let end = f.blob.0 + f.blob.1;
            let (first, count) = (f.chunks.0 as usize, f.chunks.1 as usize);
            if first != at || count == 1 || count > n_chunks - at {
                return bad("its chunks are not the next ones");
            }
            at += count;
            let (mut size, mut last) = (0u64, 0u64);
            for k in first..first + count {
                let c = self.chunk(k);
                let in_order = match k == first {
                    true => c.blob == f.blob.0,
                    false => c.blob > last && c.blob < end,
                };
                last = c.blob;
                size = size
                    .checked_add(c.length)
                    .filter(|_| c.length > 0 && in_order)
                    .ok_or(format!(
                        "file {i} of the table: its chunks are not in order in its range"
                    ))?;
            }
            if count > 0 && size != f.size {
                return bad("its chunks do not add up to it");
            }
        }
        if at != n_chunks {
            return Err("the table has chunks that no file has".into());
        }
        Ok(())
    }

    /// The table of contents of the table, as a layer pulled by it is
    /// stored: the entries in the order of their paths (a directory before
    /// what it holds), the directories that the layer does not have left
    /// out, a file with its fs-verity digest and no content digest.  The
    /// names of a canonical tar are those of its headers (`./` and the
    /// path, a directory with a final `/`); the others are the paths, the
    /// root `./`, and an empty file has the digest of no bytes (as
    /// `velarx_content`'s `toc_view` keeps a table of contents).
    pub fn toc(&self) -> Toc {
        let alg = self.head.alg;
        let canonical = self.head.tarsplit.is_none();
        // (what the names of the entries of each directory start with: the
        // directories come before what they hold)
        let mut dirs = vec![String::new(); self.order.len()];
        if canonical {
            dirs[0] = "./".to_string();
        }
        for &i in &self.order[1..] {
            let e = self.entry(i as usize);
            if e.kind == 0 {
                dirs[i as usize] = format!("{}{}/", dirs[e.parent as usize], self.name(&e));
            }
        }
        let path = |i: usize| {
            let e = self.entry(i);
            match (i, e.kind) {
                (0, _) => "./".to_string(),
                (_, 0) if canonical => dirs[i].clone(),
                _ => format!("{}{}", dirs[e.parent as usize], self.name(&e)),
            }
        };
        let times: Vec<String> = (0..self.s[4].len() / TIME)
            .map(|i| {
                let t = &self.s[4][i * TIME..];
                rfc3339((u64_at(t, 0) as i64, u32_at(t, 8))).unwrap_or_default()
            })
            .collect();
        let digest = |r: &[u8]| Digest::from_bytes(alg, r).expect("a digest of the algorithm");
        let entry_of = |i: usize| {
            let e = self.entry(i);
            let o = &self.s[3][e.owner as usize * OWNER..];
            let mut entry = TocEntry {
                mode: e.mode.into(),
                uid: u32_at(o, 0),
                gid: u32_at(o, 4),
                mod_time: Some(times[e.time as usize].clone()),
                ..TocEntry::new(path(i), KINDS[e.kind as usize])
            };
            if e.xattrs > 0 {
                let (from, to) = self.sets[e.xattrs as usize - 1];
                entry.xattrs = xattr_map(&self.s[5][from..to]);
            }
            let mut chunk_entries = Vec::new();
            match e.kind {
                1 if e.a > 0 => {
                    let f = self.file(e.a as usize - 1);
                    entry.size = f.size;
                    entry.fsverity = Digest::fsverity(alg, f.verity).ok();
                    entry.offset = f.blob.0;
                    entry.end_offset = f.blob.0 + f.blob.1;
                    let (first, count) = (f.chunks.0 as usize, f.chunks.1 as usize);
                    let mut at = 0;
                    for k in first..first + count {
                        let c = self.chunk(k);
                        let kind = c.zeros.then(|| crate::CHUNK_TYPE_ZEROS.to_string());
                        let d = Some(digest(c.digest).to_string());
                        if k == first {
                            (entry.chunk_size, entry.chunk_digest, entry.chunk_type) =
                                (c.length, d, kind);
                        } else {
                            chunk_entries.push(TocEntry {
                                offset: c.blob,
                                chunk_digest: d,
                                chunk_size: c.length,
                                chunk_offset: at,
                                chunk_type: kind,
                                ..TocEntry::new(entry.name.clone(), TocEntryType::Chunk)
                            });
                        }
                        at += c.length;
                    }
                }
                1 if !canonical => {
                    let empty = Digest::empty(alg).to_string();
                    (entry.digest, entry.chunk_digest) = (Some(empty.clone()), Some(empty));
                }
                2 => {
                    let at = e.a as usize..e.a as usize + e.b as usize;
                    entry.link_name = Some(utf8(&self.s[2][at]).to_string());
                }
                3 => entry.link_name = Some(path(e.a as usize)),
                4 | 5 => (entry.dev_major, entry.dev_minor) = (Some(e.a), Some(e.b)),
                _ => {}
            }
            let mut out = Vec::with_capacity(1 + chunk_entries.len());
            out.push(entry);
            out.extend(chunk_entries);
            out
        };
        // (the entries on all the threads, as they are freed)
        let entries: Vec<TocEntry> = self
            .order
            .par_iter()
            .with_min_len(256)
            .filter(|&&i| self.entry(i as usize).flags != IMPLIED)
            .flat_map_iter(|&i| entry_of(i as usize))
            .collect();
        Toc {
            version: if canonical {
                TOC_VERSION_CANONICAL
            } else {
                TOC_VERSION
            },
            entries,
            tar_split_digest: self.head.tarsplit.map(|d| d.to_string()),
        }
    }
}

/// The table of contents `table` describes ([`Table::open`], [`Table::toc`]).
pub fn decode(table: &[u8], data_end: u64) -> Result<Toc, String> {
    Table::open(table, data_end).map(|t| t.toc())
}

/// A node of the tree [`encode`] makes.
#[derive(Default)]
struct Node {
    name: Vec<u8>,
    children: BTreeMap<Vec<u8>, usize>,
    /// The entry of the table of contents, none for a directory the layer
    /// does not have.
    entry: Option<usize>,
}

/// The components of the path `name` of a table of contents: `./`, `/` or
/// nothing before them, a `/` after them for a directory; the root has
/// none.
fn components(name: &str) -> Result<Vec<&[u8]>, String> {
    let rest = name
        .strip_prefix("./")
        .or_else(|| name.strip_prefix('/'))
        .unwrap_or(name);
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest == "." {
        return Ok(Vec::new());
    }
    let parts: Vec<&[u8]> = rest.split('/').map(str::as_bytes).collect();
    match parts.iter().all(|c| component_ok(c)) {
        true => Ok(parts),
        false => Err(format!("`{name}` is not a path a table can have")),
    }
}

/// A file as [`encode`] writes it: its size, its range of the blob and
/// its chunks (blob offset, length with the zeros bit, digest).
type Placed = (u64, (u64, u64), Vec<(u64, u64, Vec<u8>)>);

/// The table of `toc`, the table of contents of a layer with digests of
/// `alg`; an error when it cannot have one: a path twice, the entries not
/// in the order of their paths (see [`decode`]), a file without its
/// fs-verity digest, a hard link that is not to an earlier entry that is
/// not a directory nor a hard link, digests of another algorithm.  The
/// content digests of the files are not in the table.
pub fn encode(toc: &Toc, alg: Algorithm) -> Result<Vec<u8>, String> {
    let entries = &toc.entries;
    let mut nodes = vec![Node::default()];
    let mut by_path: HashMap<Vec<&[u8]>, usize> = HashMap::new();
    let mut tar_order = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if e.entry_type == TocEntryType::Chunk {
            continue;
        }
        let parts = components(&e.name)?;
        // (as `./`, the path and a `/` for a directory: see `Table::open`)
        let dir = usize::from(e.entry_type == TocEntryType::Dir);
        if parts.iter().map(|p| p.len() + 1).sum::<usize>() + 1 + dir > MAX_PATH {
            return Err(format!("`{}` is too long", e.name));
        }
        let mut node = 0;
        for part in &parts {
            if nodes[node]
                .entry
                .is_some_and(|d| entries[d].entry_type != TocEntryType::Dir)
            {
                return Err(format!(
                    "`{}` is in something that is not a directory",
                    e.name
                ));
            }
            let next = nodes.len();
            node = *nodes[node].children.entry(part.to_vec()).or_insert(next);
            if node == next {
                nodes.push(Node {
                    name: part.to_vec(),
                    ..Node::default()
                });
            }
        }
        if nodes[node].entry.replace(i).is_some() {
            return Err(format!("`{}` is in the layer twice", e.name));
        }
        if e.entry_type != TocEntryType::Dir && !nodes[node].children.is_empty() {
            return Err(format!("`{}` has entries and is not a directory", e.name));
        }
        by_path.insert(parts, node);
        tar_order.push(i);
    }
    // (the order of the paths must be the one of the table of contents)
    let mut depth_first = Vec::with_capacity(tar_order.len());
    let mut stack = vec![0usize];
    while let Some(node) = stack.pop() {
        depth_first.extend(nodes[node].entry);
        stack.extend(nodes[node].children.values().rev());
    }
    if depth_first != tar_order {
        return Err("the entries are not in the order of their paths".into());
    }
    let mut position = vec![usize::MAX; entries.len()];
    for (p, &i) in tar_order.iter().enumerate() {
        position[i] = p;
    }

    // Breadth first: the index of each node in the table.
    let mut bfs = vec![0usize];
    let mut k = 0;
    while k < bfs.len() {
        bfs.extend(nodes[bfs[k]].children.values().copied());
        k += 1;
    }
    let mut index = vec![0u32; nodes.len()];
    for (t, &node) in bfs.iter().enumerate() {
        index[node] = t as u32;
    }

    // The side tables.
    let time = |e: &TocEntry| toc_time(e.mod_time.as_deref()).unwrap_or((0, 0));
    let mut owners = BTreeSet::new();
    let mut times = BTreeSet::new();
    for &i in &tar_order {
        owners.insert((entries[i].uid, entries[i].gid));
        times.insert(time(&entries[i]));
    }
    if owners.len() > 1 << 16 {
        return Err("the layer has too many owners".into());
    }
    let owners: Vec<_> = owners.into_iter().collect();
    let times: Vec<_> = times.into_iter().collect();
    let verity = |e: &TocEntry| {
        e.fsverity
            .filter(|d| d.alg() == alg && d.is_fsverity())
            .ok_or_else(|| format!("`{}` has no fs-verity digest of {alg}", e.name))
    };
    let chunk_digest = |name: &str, d: &Option<String>| -> Result<Vec<u8>, String> {
        d.as_deref()
            .and_then(|d| d.parse::<Digest>().ok())
            .filter(|d| d.alg() == alg && !d.is_fsverity())
            .map(|d| d.raw().to_vec())
            .ok_or_else(|| format!("a chunk of `{name}` has no digest of {alg}"))
    };
    // (the files by digest, each with the place and the chunks of its first
    // entry)
    let mut files: BTreeMap<Vec<u8>, Placed> = BTreeMap::new();
    for &i in &tar_order {
        let e = &entries[i];
        if e.entry_type != TocEntryType::Reg || e.size == 0 {
            continue;
        }
        let key = verity(e)?.raw().to_vec();
        if let Some((size, ..)) = files.get(&key) {
            if *size != e.size {
                return Err(format!("`{}` has two sizes", e.name));
            }
            continue;
        }
        let mut list = Vec::new();
        if e.chunk_digest.is_some() {
            let zeros = |c: &TocEntry| if c.is_zeros_chunk() { ZEROS } else { 0 };
            list.push((
                e.offset,
                e.chunk_size | zeros(e),
                chunk_digest(&e.name, &e.chunk_digest)?,
            ));
            for c in entries[i + 1..]
                .iter()
                .take_while(|c| c.entry_type == TocEntryType::Chunk)
            {
                list.push((
                    c.offset,
                    c.chunk_size | zeros(c),
                    chunk_digest(&e.name, &c.chunk_digest)?,
                ));
            }
        }
        if list.len() == 1 {
            list.clear();
        }
        let blob_len = e
            .end_offset
            .checked_sub(e.offset)
            .ok_or_else(|| format!("`{}` ends before it starts", e.name))?;
        files.insert(key, (e.size, (e.offset, blob_len), list));
    }
    let file_index: HashMap<&[u8], u32> = files
        .keys()
        .enumerate()
        .map(|(i, k)| (k.as_slice(), i as u32))
        .collect();

    // The entries, breadth first.
    let mut out_entries = Vec::with_capacity(bfs.len() * ENTRY);
    let (mut names, mut targets, mut xattrs) = (Vec::new(), Vec::new(), Vec::new());
    let mut sets: HashMap<Vec<u8>, u32> = HashMap::new();
    let mut parent = vec![ROOT_PARENT; nodes.len()];
    for (node_i, &node) in bfs.iter().enumerate() {
        let n = &nodes[node];
        let name = n.name.as_slice();
        let mut raw = Raw {
            name: (names.len() as u32, name.len() as u16),
            kind: 0,
            flags: IMPLIED,
            mode: 0,
            owner: 0,
            time: 0,
            parent: parent[node],
            a: 0,
            b: 0,
            xattrs: 0,
        };
        names.extend_from_slice(name);
        if let Some(&first) = n.children.values().next() {
            raw.a = index[first];
            raw.b = n.children.len() as u32;
            for &c in n.children.values() {
                parent[c] = node_i as u32;
            }
        }
        if let Some(i) = n.entry {
            let e = &entries[i];
            let bad = |why: &str| Err(format!("`{}` {why}", e.name));
            raw.kind = kind_byte(e.entry_type).expect("not a chunk");
            raw.flags = 0;
            if e.mode > 0o7777 {
                return bad("has a mode with more than the permission bits");
            }
            raw.mode = e.mode as u16;
            raw.owner = owners.binary_search(&(e.uid, e.gid)).expect("an owner") as u16;
            raw.time = times.binary_search(&time(e)).expect("a time") as u32;
            if !e.xattrs.is_empty() {
                let mut set: Vec<(&String, Vec<u8>)> = Vec::new();
                for (k, v) in &e.xattrs {
                    let v = base64::engine::general_purpose::STANDARD
                        .decode(v)
                        .ok()
                        .filter(|v| {
                            v.len() <= MAX_XATTR_VALUE
                                && (1..=MAX_NAME).contains(&k.len())
                                && !k.contains('\0')
                                && !is_overlay_xattr(k)
                        })
                        .ok_or_else(|| format!("`{}` has the xattr `{k}`", e.name))?;
                    set.push((k, v));
                }
                if set.len() > MAX_XATTRS {
                    return bad("has too many xattrs");
                }
                set.sort();
                let mut bytes = (set.len() as u16).to_le_bytes().to_vec();
                for (k, v) in set {
                    bytes.extend((k.len() as u16).to_le_bytes());
                    bytes.extend((v.len() as u32).to_le_bytes());
                    bytes.extend(k.as_bytes());
                    bytes.extend(v);
                }
                let next = sets.len() as u32 + 1;
                raw.xattrs = *sets.entry(bytes.clone()).or_insert_with(|| {
                    xattrs.extend(&bytes);
                    next
                });
            }
            match e.entry_type {
                TocEntryType::Dir => {}
                TocEntryType::Reg if e.size > 0 => raw.a = file_index[verity(e)?.raw()] + 1,
                TocEntryType::Reg => {}
                TocEntryType::Symlink => {
                    let t = e.link_name.as_deref().unwrap_or("");
                    if t.is_empty() || t.len() > MAX_PATH || t.contains('\0') {
                        return bad("is a symlink with an invalid target");
                    }
                    raw.a = targets.len() as u32;
                    raw.b = t.len() as u32;
                    targets.extend(t.as_bytes());
                }
                TocEntryType::Hardlink => {
                    let target = components(e.link_name.as_deref().unwrap_or(""))
                        .ok()
                        .and_then(|p| by_path.get(&p).copied())
                        .filter(|&t| {
                            nodes[t].entry.is_some_and(|ti| {
                                position[ti] < position[i]
                                    && !matches!(
                                        entries[ti].entry_type,
                                        TocEntryType::Dir | TocEntryType::Hardlink
                                    )
                            })
                        });
                    let Some(t) = target else {
                        return bad("is a hard link that is not to an earlier file");
                    };
                    raw.a = index[t];
                }
                TocEntryType::Char | TocEntryType::Block => {
                    raw.a = e.dev_major.unwrap_or(0);
                    raw.b = e.dev_minor.unwrap_or(0);
                    if raw.a > MAX_DEVICE || raw.b > MAX_DEVICE {
                        return bad("has a device number that is too large");
                    }
                }
                TocEntryType::Fifo | TocEntryType::Chunk => {}
            }
        }
        raw.write(&mut out_entries);
    }

    // The table.
    let mut sections: [Vec<u8>; SECTIONS] = Default::default();
    sections[0] = out_entries;
    sections[1] = names;
    sections[2] = targets;
    for (uid, gid) in &owners {
        sections[3].extend(uid.to_le_bytes());
        sections[3].extend(gid.to_le_bytes());
    }
    for (secs, nanos) in &times {
        sections[4].extend(secs.to_le_bytes());
        sections[4].extend(nanos.to_le_bytes());
    }
    sections[5] = xattrs;
    let mut first = 0u32;
    for (verity, (size, (off, len), list)) in &files {
        sections[6].extend(verity);
        for v in [*size, *off, *len] {
            sections[6].extend(v.to_le_bytes());
        }
        sections[6].extend(first.to_le_bytes());
        sections[6].extend((list.len() as u32).to_le_bytes());
        first += list.len() as u32;
        for (off, len, digest) in list {
            sections[7].extend(off.to_le_bytes());
            sections[7].extend(len.to_le_bytes());
            sections[7].extend(digest);
        }
    }
    let canonical = toc.is_canonical();
    let tarsplit = match (&toc.tar_split_digest, canonical) {
        (None, true) => vec![0; alg.len()],
        (Some(d), false) => d
            .parse::<Digest>()
            .ok()
            .filter(|d| d.alg() == alg && !d.is_fsverity())
            .map(|d| d.raw().to_vec())
            .ok_or("the tar-split digest is not one of the layer")?,
        _ => {
            return Err("a table has a tar-split digest if and only if it is not canonical".into())
        }
    };
    let mut out =
        Vec::with_capacity(header_len(alg) + sections.iter().map(Vec::len).sum::<usize>());
    out.extend(MAGIC);
    out.extend(VERSION.to_le_bytes());
    out.extend([0; 8]);
    out.extend([alg_byte(alg), if canonical { CANONICAL } else { 0 }]);
    out.extend([0; 10]);
    out.extend(tarsplit);
    let mut at = header_len(alg) as u64;
    for s in &sections {
        out.extend(at.to_le_bytes());
        out.extend((s.len() as u64).to_le_bytes());
        at += s.len() as u64;
    }
    for s in sections {
        out.extend(s);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(secs: i64, nanos: u32) -> Option<String> {
        rfc3339((secs, nanos))
    }

    fn e(name: &str, kind: TocEntryType) -> TocEntry {
        TocEntry {
            mode: 0o755,
            mod_time: time(1_700_000_000, 0),
            ..TocEntry::new(name, kind)
        }
    }

    fn verity(alg: Algorithm, content: &[u8]) -> Digest {
        Digest::fsverity(alg, Digest::of(alg, content).raw()).unwrap()
    }

    fn file(alg: Algorithm, name: &str, content: &[u8], blob: (u64, u64)) -> TocEntry {
        TocEntry {
            size: 3000,
            fsverity: Some(verity(alg, content)),
            offset: blob.0,
            end_offset: blob.1,
            ..e(name, TocEntryType::Reg)
        }
    }

    /// A table of contents of every kind of entry, as the writer of a
    /// layer makes it (canonical names, chunks after their file).
    fn sample(alg: Algorithm, canonical: bool) -> Toc {
        let chunk = |d: &[u8]| Some(Digest::of(alg, d).to_string());
        let mut dir = e("./a/", TocEntryType::Dir);
        dir.xattrs.insert("user.k".into(), "dg==".into());
        let mut chunked = file(alg, "./a/g", b"g", (150, 300));
        (chunked.chunk_size, chunked.chunk_digest) = (1000, chunk(b"g1"));
        let zeros = TocEntry {
            offset: 200,
            chunk_size: 2000,
            chunk_offset: 1000,
            chunk_digest: chunk(b"g2"),
            chunk_type: Some(crate::CHUNK_TYPE_ZEROS.into()),
            ..TocEntry::new("./a/g", TocEntryType::Chunk)
        };
        let mut link = e("./a/h", TocEntryType::Hardlink);
        link.link_name = Some("./a/f".into());
        let mut sym = e("./a/l", TocEntryType::Symlink);
        sym.link_name = Some("../b".into());
        let mut dev = e("./b", TocEntryType::Char);
        (dev.dev_major, dev.dev_minor) = (Some(1), Some(3));
        let mut owned = e("./c/", TocEntryType::Dir);
        (owned.uid, owned.gid, owned.mod_time) = (1000, 1000, time(-5, 500));
        let mut entries = vec![
            e("./", TocEntryType::Dir),
            dir,
            file(alg, "./a/f", b"f", (100, 150)),
            chunked,
            zeros,
            link,
            sym,
            dev,
            owned,
            e("./c/e", TocEntryType::Reg),
            e("./d", TocEntryType::Fifo),
            file(alg, "./e", b"f", (100, 150)),
        ];
        if !canonical {
            entries.remove(0);
        }
        Toc {
            version: if canonical { 2 } else { 1 },
            entries,
            tar_split_digest: (!canonical).then(|| Digest::of(alg, b"ts").to_string()),
        }
    }

    fn json(toc: &Toc) -> String {
        serde_json::to_string(toc).unwrap()
    }

    /// `toc` as a layer is stored by it: a canonical one as it is, another
    /// with the names of its paths and the digest of no bytes for an empty
    /// file.
    fn stored(alg: Algorithm, mut toc: Toc) -> Toc {
        if toc.is_canonical() {
            return toc;
        }
        let path = |n: &str| match n.trim_start_matches("./").trim_end_matches('/') {
            "" => "./".to_string(),
            p => p.to_string(),
        };
        for e in &mut toc.entries {
            e.name = path(&e.name);
            if e.entry_type == TocEntryType::Hardlink {
                e.link_name = e.link_name.as_deref().map(path);
            }
            if e.entry_type == TocEntryType::Reg && e.size == 0 {
                let empty = Some(Digest::empty(alg).to_string());
                (e.digest, e.chunk_digest) = (empty.clone(), empty);
            }
        }
        toc
    }

    #[test]
    fn test_a_table_is_its_table_of_contents() {
        for alg in Algorithm::ALL {
            for canonical in [true, false] {
                let toc = sample(alg, canonical);
                let table = encode(&toc, alg).unwrap();
                assert_eq!(table[20], alg_byte(alg));
                let back = decode(&table, 300).unwrap();
                assert_eq!(json(&back), json(&stored(alg, toc)), "{alg} {canonical}");
                assert_eq!(encode(&back, alg).unwrap(), table);
                let head = head(&table).unwrap();
                assert_eq!(head.alg, alg);
                assert_eq!(head.tarsplit.is_none(), canonical);
            }
        }
    }

    /// The names of the entries may have any of the forms of a tar, and
    /// the content digest of a file is not in the table.
    #[test]
    fn test_the_forms_of_a_name_are_one_path() {
        let alg = Algorithm::Sha256;
        let toc = sample(alg, false);
        let mut other = toc.clone();
        for e in &mut other.entries {
            e.name = e.name.trim_start_matches("./").to_string();
            e.digest = Some(Digest::of(alg, b"content").to_string());
        }
        other.entries[0].name = "/a".into();
        assert_eq!(encode(&other, alg).unwrap(), encode(&toc, alg).unwrap());
    }

    #[test]
    fn test_a_table_of_contents_that_cannot_have_a_table() {
        let alg = Algorithm::Sha256;
        type Edit = fn(&mut Toc);
        let cases: [(&str, Edit); 8] = [
            ("twice", |t| {
                let d = t.entries[10].clone();
                t.entries.push(d);
            }),
            ("order", |t| t.entries.swap(9, 10)),
            ("fs-verity", |t| t.entries[2].fsverity = None),
            ("hard link", |t| {
                t.entries[5].link_name = Some("./c/".into())
            }),
            ("hard link", |t| t.entries[5].link_name = Some("./e".into())),
            ("permission", |t| t.entries[1].mode = 0o40755),
            ("not a path", |t| t.entries[10].name = "./x/../d".into()),
            ("sha512", |t| {
                t.entries[2].fsverity = Some(verity(Algorithm::Sha512, b"f"))
            }),
        ];
        for (what, edit) in cases {
            let mut toc = sample(alg, true);
            edit(&mut toc);
            let e = encode(&toc, alg).unwrap_err();
            let what = if what == "sha512" { "fs-verity" } else { what };
            assert!(e.contains(what), "{what}: {e}");
        }
    }

    #[test]
    fn test_an_empty_layer_has_a_table() {
        for canonical in [true, false] {
            let mut toc = sample(Algorithm::Sha256, canonical);
            toc.entries.clear();
            let table = encode(&toc, Algorithm::Sha256).unwrap();
            assert_eq!(json(&decode(&table, 0).unwrap()), json(&toc));
        }
    }

    /// What a layer bounds and the table can say: a path deeper than a tar
    /// name, more bytes of extended attributes than a tar header holds.
    #[test]
    fn test_a_table_beyond_the_bounds_of_a_layer_is_refused() {
        let alg = Algorithm::Sha256;
        let mut deep = sample(alg, true);
        let mut name = "./".to_string();
        for _ in 0..=MAX_DEPTH {
            name.push_str("x/");
            deep.entries.push(e(&name, TocEntryType::Dir));
        }
        let table = encode(&deep, alg).unwrap();
        assert!(decode(&table, 300).unwrap_err().contains("too deep"));
        deep.entries.pop();
        assert!(decode(&encode(&deep, alg).unwrap(), 300).is_ok());

        let mut big = sample(alg, true);
        let value = base64::engine::general_purpose::STANDARD.encode([7u8; MAX_XATTR_VALUE]);
        for i in 0..MAX_XATTR_BYTES / MAX_XATTR_VALUE {
            big.entries[1]
                .xattrs
                .insert(format!("user.k{i}"), value.clone());
        }
        let table = encode(&big, alg).unwrap();
        assert!(decode(&table, 300).unwrap_err().contains("too many bytes"));
    }

    /// Where field `at` of entry `i` is.
    fn entry_at(alg: Algorithm, i: usize, at: usize) -> usize {
        header_len(alg) + i * ENTRY + at
    }

    fn section(table: &[u8], alg: Algorithm, i: usize) -> usize {
        u64_at(table, 32 + alg.len() + 16 * i) as usize
    }

    /// The table of [`sample`] with `bytes` at `at`, decoded.
    fn patched(at: impl Fn(&[u8]) -> usize, bytes: &[u8]) -> Result<Toc, String> {
        let alg = Algorithm::Sha256;
        let mut table = encode(&sample(alg, true), alg).unwrap();
        let at = at(&table);
        table[at..at + bytes.len()].copy_from_slice(bytes);
        decode(&table, 300)
    }

    /// The entries of [`sample`], breadth first: 0 root, 1 a, 2 b, 3 c,
    /// 4 d, 5 e, 6 a/f, 7 a/g, 8 a/h, 9 a/l, 10 c/e.
    #[test]
    fn test_a_hostile_table_is_refused() {
        let alg = Algorithm::Sha256;
        let s = move |i| move |t: &[u8]| section(t, alg, i);
        let ent = move |i, at| move |_: &[u8]| entry_at(alg, i, at);
        let names = move |k| move |t: &[u8]| section(t, alg, 1) + k;
        let file = move |i, at| move |t: &[u8]| section(t, alg, 6) + i * file_record(alg) + at;
        let chunk = move |i, at| move |t: &[u8]| section(t, alg, 7) + i * chunk_record(alg) + at;
        type At = Box<dyn Fn(&[u8]) -> usize>;
        let cases: Vec<(&str, At, Vec<u8>)> = vec![
            ("not a table", Box::new(|_| 0), b"ZCTABLE2".to_vec()),
            ("version", Box::new(|_| 8), vec![2]),
            ("requires", Box::new(|_| 12), vec![1]),
            ("algorithm", Box::new(|_| 20), vec![3]),
            ("reserved", Box::new(|_| 21), vec![2]),
            ("reserved", Box::new(|_| 25), vec![1]),
            ("tar-split", Box::new(|_| 40), vec![1]),
            ("section 1", Box::new(|_| 32 + 32 + 16), vec![1]),
            ("not sorted", Box::new(names(0)), b"b".to_vec()),
            ("name", Box::new(names(1)), b"/".to_vec()),
            ("name", Box::new(names(1)), b".".to_vec()),
            ("name", Box::new(names(1)), b"\0".to_vec()),
            ("not UTF-8", Box::new(names(1)), vec![0xff]),
            (
                "fields of its kind",
                Box::new(ent(1, 20)),
                1u32.to_le_bytes().to_vec(),
            ),
            ("parent", Box::new(ent(6, 16)), 3u32.to_le_bytes().to_vec()),
            (
                "next one of the names",
                Box::new(ent(2, 0)),
                0u32.to_le_bytes().to_vec(),
            ),
            (
                "hard link",
                Box::new(ent(8, 20)),
                1u32.to_le_bytes().to_vec(),
            ),
            (
                "hard link",
                Box::new(ent(8, 20)),
                8u32.to_le_bytes().to_vec(),
            ),
            (
                "hard link",
                Box::new(ent(8, 20)),
                10u32.to_le_bytes().to_vec(),
            ),
            (
                "permission",
                Box::new(ent(4, 8)),
                0o10000u16.to_le_bytes().to_vec(),
            ),
            ("owner", Box::new(ent(4, 10)), 9u16.to_le_bytes().to_vec()),
            (
                "no entry has",
                Box::new(ent(3, 10)),
                0u16.to_le_bytes().to_vec(),
            ),
            (
                "attributes",
                Box::new(ent(4, 28)),
                2u32.to_le_bytes().to_vec(),
            ),
            ("flags", Box::new(ent(4, 7)), vec![2]),
            ("kind", Box::new(ent(4, 6)), vec![7]),
            ("kind", Box::new(ent(4, 20)), 1u32.to_le_bytes().to_vec()),
            (
                "kind",
                Box::new(ent(2, 20)),
                (MAX_DEVICE + 1).to_le_bytes().to_vec(),
            ),
            (
                "sorted",
                Box::new(move |t| s(4)(t) + TIME),
                (-10i64).to_le_bytes().to_vec(),
            ),
            ("sorted by digest", Box::new(file(1, 0)), vec![0; 32]),
            (
                "data of the blob",
                Box::new(file(0, 40)),
                251u64.to_le_bytes().to_vec(),
            ),
            (
                "next ones",
                Box::new(file(1, 60)),
                1u32.to_le_bytes().to_vec(),
            ),
            (
                "in order",
                Box::new(chunk(1, 0)),
                150u64.to_le_bytes().to_vec(),
            ),
            (
                "add up",
                Box::new(chunk(1, 8)),
                1999u64.to_le_bytes().to_vec(),
            ),
        ];
        for (what, at, bytes) in cases {
            let Err(e) = patched(at, &bytes) else {
                panic!("{what}: accepted");
            };
            assert!(e.contains(what), "{what}: {e}");
        }
        // a byte after the last section
        let mut table = encode(&sample(alg, true), alg).unwrap();
        table.push(0);
        assert!(decode(&table, 300)
            .unwrap_err()
            .contains("after the last section"));
    }
}
