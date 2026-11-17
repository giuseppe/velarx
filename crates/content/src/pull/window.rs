// SPDX-License-Identifier: Apache-2.0
//! The files fetched together with the one a container missed.
//!
//! A program that starts reads many small files, and the files of a layer
//! that are neighbours in the tar are neighbours in the blob: asking for them
//! in one plan makes one batch to a peer, or one merged range to the registry,
//! instead of one round trip each.  The window is the files that follow the
//! missed one in the order of the table of contents, bounded in number and in
//! bytes, leaving out the ones the store has and the ones somebody else is
//! fetching.

use std::collections::HashSet;
use velarx_storage::{Toc, TocEntryType};

/// How much is fetched with a missed file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub files: usize,
    pub bytes: u64,
}

impl Window {
    pub fn from_config(config: &velarx_config::PullConfig) -> Self {
        Self {
            files: config.lazy_window_files,
            bytes: config.lazy_window_kib.saturating_mul(1024),
        }
    }

    pub fn is_off(&self) -> bool {
        self.files == 0 || self.bytes == 0
    }
}

/// Entries looked at for each file of the window: the table is not walked
/// for ever when the store has most of what follows.
const LOOK_FACTOR: usize = 8;

/// The position of the regular file of this fs-verity digest in the table.
pub fn file_index(toc: &Toc, file_digest: &str) -> Option<usize> {
    toc.entries
        .iter()
        .position(|e| is_file(e) && e.verity().as_deref() == Some(file_digest))
}

fn is_file(e: &velarx_storage::TocEntry) -> bool {
    e.entry_type == TocEntryType::Reg && e.size > 0
}

/// The contents of the regular files of the table that `wanted` accepts
/// (asked once for each, with its first entry), in the order of the table,
/// in groups of at most `files` files and `bytes` bytes (a bigger file is a
/// group of its own): the groups to fetch together.  A file whose digest the
/// table does not give as an fs-verity digest is an error.
pub fn groups(
    toc: &Toc,
    files: usize,
    bytes: u64,
    mut wanted: impl FnMut(&str, &velarx_storage::TocEntry) -> bool,
) -> Result<Vec<Vec<String>>, String> {
    let mut groups = Vec::new();
    let mut group: Vec<String> = Vec::new();
    let mut size = 0u64;
    let mut seen: HashSet<String> = HashSet::new();
    for e in toc.entries.iter().filter(|e| is_file(e)) {
        let d = e
            .verity()
            .ok_or_else(|| format!("`{}` has no fs-verity digest in the table", e.name))?;
        if !seen.insert(d.clone()) || !wanted(&d, e) {
            continue;
        }
        if !group.is_empty() && (group.len() >= files.max(1) || size.saturating_add(e.size) > bytes)
        {
            groups.push(std::mem::take(&mut group));
            size = 0;
        }
        size = size.saturating_add(e.size);
        group.push(d);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    Ok(groups)
}

/// The position of each of these contents in the table, in the order of the
/// table; contents it has no file of are left out.
pub fn positions_of(toc: &Toc, digests: &[&str]) -> Vec<usize> {
    let wanted: HashSet<&str> = digests.iter().copied().collect();
    let mut taken: HashSet<String> = HashSet::new();
    toc.entries
        .iter()
        .enumerate()
        .filter(|(_, e)| is_file(e))
        .filter_map(|(i, e)| {
            let d = e.verity()?;
            (wanted.contains(d.as_str()) && taken.insert(d)).then_some(i)
        })
        .collect()
}

/// The positions of the files that follow the one at `first`, up to the
/// limits, that `wanted` accepts (it is asked once for each content, and
/// may take a claim on it).  A content is taken once, however many names it
/// has.  The file at `first` is not in the answer.
pub fn select(
    toc: &Toc,
    first: usize,
    window: Window,
    mut wanted: impl FnMut(&str) -> bool,
) -> Vec<usize> {
    let mut out = Vec::new();
    if window.is_off() {
        return out;
    }
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(d) = toc.entries.get(first).and_then(|e| e.verity()) {
        seen.insert(d);
    }
    let mut bytes = 0u64;
    let look = window.files.saturating_mul(LOOK_FACTOR);
    for (i, e) in toc
        .entries
        .iter()
        .enumerate()
        .skip(first.saturating_add(1))
        .take(look)
    {
        if out.len() >= window.files {
            break;
        }
        if !is_file(e) {
            continue;
        }
        let Some(d) = e.verity() else {
            continue;
        };
        if !seen.insert(d.clone()) {
            continue;
        }
        let total = bytes.saturating_add(e.size);
        if total > window.bytes {
            // a bigger file may be followed by small ones
            continue;
        }
        if !wanted(&d) {
            continue;
        }
        bytes = total;
        out.push(i);
    }
    out
}

/// The entries of the files at these positions, each with the chunks that
/// follow it, in the order given.
pub fn entries_of(toc: &Toc, positions: &[usize]) -> Toc {
    let mut entries = Vec::new();
    for &i in positions {
        let Some(file) = toc.entries.get(i) else {
            continue;
        };
        entries.push(file.clone());
        entries.extend(
            toc.entries[i + 1..]
                .iter()
                .take_while(|c| c.entry_type == TocEntryType::Chunk)
                .cloned(),
        );
    }
    Toc {
        version: toc.version,
        entries,
        tar_split_digest: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_storage::TocEntry;

    fn entry(name: &str, kind: TocEntryType, size: u64, d: Option<&str>) -> TocEntry {
        TocEntry {
            name: name.into(),
            entry_type: kind,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size,
            digest: d.map(|d| d.replace("fsverity-sha256-12:", "sha256:")),
            fsverity: d.and_then(velarx_storage::to_toc),
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
            xattrs: Default::default(),
        }
    }

    /// Files `f0..` of the given sizes, a directory and a symlink between
    /// them, a chunk entry after each file bigger than 100.
    fn toc(sizes: &[u64]) -> Toc {
        let mut entries = vec![entry("d", TocEntryType::Dir, 0, None)];
        for (i, s) in sizes.iter().enumerate() {
            let d = format!("fsverity-sha256-12:{i:064x}");
            entries.push(entry(&format!("f{i}"), TocEntryType::Reg, *s, Some(&d)));
            if *s > 100 {
                entries.push(entry(&format!("f{i}"), TocEntryType::Chunk, 0, None));
            }
            entries.push(entry(&format!("l{i}"), TocEntryType::Symlink, 0, None));
        }
        Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        }
    }

    fn names(toc: &Toc, at: &[usize]) -> Vec<String> {
        at.iter().map(|&i| toc.entries[i].name.clone()).collect()
    }

    const W: Window = Window {
        files: 3,
        bytes: 1000,
    };

    #[test]
    fn the_window_follows_the_file_in_the_order_of_the_table() {
        let t = toc(&[10, 20, 30, 40, 50]);
        let first = file_index(&t, &format!("fsverity-sha256-12:{:064x}", 1)).unwrap();
        let got = select(&t, first, W, |_| true);
        assert_eq!(names(&t, &got), ["f2", "f3", "f4"]);
        let got = select(&t, first, Window { files: 2, ..W }, |_| true);
        assert_eq!(names(&t, &got), ["f2", "f3"]);
    }

    #[test]
    fn a_window_of_zero_files_or_bytes_is_off() {
        let t = toc(&[10, 20, 30]);
        assert!(select(&t, 1, Window { files: 0, ..W }, |_| true).is_empty());
        assert!(select(&t, 1, Window { bytes: 0, ..W }, |_| true).is_empty());
    }

    #[test]
    fn the_bytes_bound_skips_what_does_not_fit_and_goes_on() {
        let t = toc(&[10, 900, 500, 60, 30]);
        let got = select(
            &t,
            1,
            Window {
                files: 4,
                bytes: 600,
            },
            |_| true,
        );
        // 900 does not fit, 500 does, 60 does, 30 would make 590 + ...
        assert_eq!(names(&t, &got), ["f2", "f3", "f4"]);
        let got = select(
            &t,
            1,
            Window {
                files: 4,
                bytes: 520,
            },
            |_| true,
        );
        assert_eq!(names(&t, &got), ["f2"]);
    }

    #[test]
    fn what_the_store_has_or_is_claimed_is_left_out_and_not_counted() {
        let t = toc(&[10, 20, 30, 40, 50, 60]);
        let skip = format!("fsverity-sha256-12:{:064x}", 2);
        let got = select(&t, 1, W, |d| d != skip);
        assert_eq!(names(&t, &got), ["f1", "f3", "f4"]);
    }

    #[test]
    fn a_content_with_several_names_is_taken_once() {
        let mut t = toc(&[10, 20]);
        let d = t.entries[1].digest.clone();
        t.entries
            .push(entry("again", TocEntryType::Reg, 10, d.as_deref()));
        t.entries.push(entry(
            "last",
            TocEntryType::Reg,
            5,
            Some(&format!("fsverity-sha256-12:{}", "f".repeat(64))),
        ));
        let got = select(&t, 1, W, |_| true);
        assert_eq!(names(&t, &got), ["f1", "last"]);
    }

    #[test]
    fn the_table_is_not_walked_for_ever() {
        let t = toc(&vec![10; 500]);
        let mut asked = 0;
        let got = select(
            &t,
            1,
            Window {
                files: 2,
                bytes: 1000,
            },
            |_| {
                asked += 1;
                false
            },
        );
        assert!(got.is_empty());
        assert!(asked <= 16, "{asked}");
    }

    #[test]
    fn the_last_file_has_no_window_and_an_unknown_one_is_none() {
        let t = toc(&[10, 20]);
        assert!(select(&t, t.entries.len() - 2, W, |_| true).is_empty());
        assert!(file_index(&t, "fsverity-sha256-12:nope").is_none());
        assert!(select(&t, usize::MAX, W, |_| true).is_empty());
    }

    #[test]
    fn the_entries_of_files_come_with_their_chunks() {
        let t = toc(&[10, 200, 30]);
        let at = [
            file_index(&t, &format!("fsverity-sha256-12:{:064x}", 1)).unwrap(),
            1,
        ];
        let mini = entries_of(&t, &at);
        let kinds: Vec<_> = mini
            .entries
            .iter()
            .map(|e| (e.name.as_str(), e.entry_type))
            .collect();
        assert_eq!(
            kinds,
            [
                ("f1", TocEntryType::Reg),
                ("f1", TocEntryType::Chunk),
                ("f0", TocEntryType::Reg)
            ]
        );
        assert!(entries_of(&t, &[usize::MAX]).entries.is_empty());
    }
}
