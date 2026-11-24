// SPDX-License-Identifier: Apache-2.0
//! The files fetched together with the one a container missed.
//!
//! A program that starts reads many small files, and the files of a layer
//! that are neighbours in the tar are neighbours in the blob: asking for them
//! in one plan makes one batch to a peer, or one merged range to the registry,
//! instead of one round trip each.  The window is the files of the directory
//! of the missed one that follow it in the order of the table of contents,
//! bounded in number and in bytes, leaving out the ones the store has and the
//! ones somebody else is fetching.  What a container reads follows what it
//! has read: the bytes of the window start small and double with each miss of
//! the layer, up to the setting.

use std::collections::{HashMap, HashSet};
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

    /// The window of the layer after `misses` windows: [`FIRST_KIB`], then
    /// twice that for each, up to the bytes of the setting.
    pub fn grown(self, misses: u32) -> Self {
        let first = FIRST_KIB * 1024;
        Self {
            bytes: self
                .bytes
                .min(first.saturating_mul(1u64.checked_shl(misses).unwrap_or(u64::MAX))),
            ..self
        }
    }

    pub fn is_off(&self) -> bool {
        self.files == 0 || self.bytes == 0
    }
}

/// The bytes of the first window of a layer.
const FIRST_KIB: u64 = 256;

/// Entries looked at for each file of the window: the table is not walked
/// for ever when the store has most of what follows.
const LOOK_FACTOR: usize = 8;

/// The position of each regular file of the table by its fs-verity digest
/// (its first entry): a file found at once, not by walking the table.
pub fn file_positions(toc: &Toc) -> HashMap<String, usize> {
    let mut at = HashMap::new();
    for (i, e) in toc.entries.iter().enumerate().filter(|(_, e)| is_file(e)) {
        if let Some(d) = e.verity() {
            at.entry(d).or_insert(i);
        }
    }
    at
}

fn is_file(e: &velarx_storage::TocEntry) -> bool {
    e.entry_type == TocEntryType::Reg && e.size > 0
}

/// The directory of an entry.
fn parent(name: &str) -> &str {
    name.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The positions of the files of the directory of the one at `first` that
/// follow it, up to the limits, that `wanted` accepts (it is asked once for
/// each content, and may take a claim on it).  A content is taken once, however many names it
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
    let Some(missed) = toc.entries.get(first) else {
        return out;
    };
    let dir = parent(&missed.name);
    let mut seen: HashSet<String> = missed.verity().into_iter().collect();
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
        if !is_file(e) || parent(&e.name) != dir {
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

/// The positions of the files that follow `digest` in `profile` (the files
/// a start read, in the order it read them), among the files of the table
/// (`at`: where each is, see [`file_positions`]), up to the limits, that
/// `wanted` accepts.  None when `digest` is not in the profile: the window
/// of the directory is the answer then.
pub fn follow(
    profile: &[String],
    at: &HashMap<String, usize>,
    digest: &str,
    window: Window,
    mut wanted: impl FnMut(&str) -> bool,
    toc: &Toc,
) -> Option<Vec<usize>> {
    let first = profile.iter().position(|d| d == digest)?;
    let mut out = Vec::new();
    let mut seen: HashSet<&str> = HashSet::from([digest]);
    let mut bytes = 0u64;
    for d in &profile[first + 1..] {
        if out.len() >= window.files {
            break;
        }
        let Some(&i) = at.get(d).filter(|_| seen.insert(d)) else {
            continue;
        };
        let total = bytes.saturating_add(toc.entries[i].size);
        if total > window.bytes || !wanted(d) {
            continue;
        }
        bytes = total;
        out.push(i);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_storage::TocEntry;

    fn entry(name: &str, kind: TocEntryType, size: u64, d: Option<&str>) -> TocEntry {
        TocEntry {
            mode: 0o644,
            size,
            digest: d.map(|d| d.replace("fsverity-sha256-12:", "sha256:")),
            fsverity: d.and_then(velarx_storage::to_toc),
            ..TocEntry::new(name, kind)
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
        let first = file_positions(&t)[&format!("fsverity-sha256-12:{:064x}", 1)];
        let got = select(&t, first, W, |_| true);
        assert_eq!(names(&t, &got), ["f2", "f3", "f4"]);
        let got = select(&t, first, Window { files: 2, ..W }, |_| true);
        assert_eq!(names(&t, &got), ["f2", "f3"]);
    }

    #[test]
    fn the_window_follows_the_profile_when_the_file_is_in_it() {
        let toc = toc(&[10, 20, 30, 40, 50]);
        let at = file_positions(&toc);
        let d = |i: usize| format!("fsverity-sha256-12:{i:064x}");
        let profile = vec![d(3), d(0), d(9), d(2), d(0), d(4), d(1)];
        let window = Window {
            files: 3,
            bytes: 1 << 20,
        };
        let names = |got: Option<Vec<usize>>| -> Option<Vec<String>> {
            got.map(|at| at.iter().map(|&i| toc.entries[i].name.clone()).collect())
        };
        // (what the profile names that the table lacks, and what repeats,
        // is left out)
        assert_eq!(
            names(follow(&profile, &at, &d(3), window, |_| true, &toc)),
            Some(vec!["f0".into(), "f2".into(), "f4".into()])
        );
        assert_eq!(
            names(follow(&profile, &at, &d(3), window, |x| x != d(0), &toc)),
            Some(vec!["f2".into(), "f4".into(), "f1".into()])
        );
        assert_eq!(follow(&profile, &at, &d(8), window, |_| true, &toc), None);
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
        assert!(!file_positions(&t).contains_key("fsverity-sha256-12:nope"));
        assert!(select(&t, usize::MAX, W, |_| true).is_empty());
    }

    #[test]
    fn the_window_is_the_directory_of_the_file() {
        let mut t = toc(&[10, 20, 30, 40]);
        for (i, e) in t.entries.iter_mut().enumerate() {
            if e.entry_type == TocEntryType::Reg {
                let dir = if i < 7 { "a" } else { "b" };
                e.name = format!("{dir}/{}", e.name);
            }
        }
        let got = select(&t, 1, W, |_| true);
        assert_eq!(names(&t, &got), ["a/f1", "a/f2"]);
    }

    #[test]
    fn the_window_grows_with_the_misses_to_the_setting() {
        let w = Window {
            files: 64,
            bytes: 4096 * 1024,
        };
        let kib = |misses| w.grown(misses).bytes / 1024;
        assert_eq!(
            (kib(0), kib(1), kib(2), kib(4), kib(5), kib(50), kib(1000)),
            (256, 512, 1024, 4096, 4096, 4096, 4096)
        );
        assert_eq!(Window { bytes: 100, ..w }.grown(0).bytes, 100);
    }
}
