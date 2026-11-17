// SPDX-License-Identifier: Apache-2.0
//! Reading the lines of a log with a bounded memory: the files of a log
//! (the rotated ones, compressed or not, and the current one) are read
//! line by line, never as a whole, and the start of a `tail` is found by
//! reading from the end.
//!
//! Rules (the log is data a container wrote, it is never trusted to be
//! small):
//!
//! * a raw line (one record) longer than [`RAW_MAX`] is cut to that length
//!   (velarx writes records of at most `MAX_RECORD` bytes);
//! * a plain file is read from its end in blocks, a compressed rotated file
//!   cannot be: it is decompressed as a stream (once to count its lines
//!   when a tail reaches it, once to read it), never kept;
//! * the position where a tail starts is two integers, not data.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::Path;

use super::logfmt::{self, LogFile, ReadAt};

/// The longest line of output the readers hand over in one piece: a longer
/// line is split in pieces of this size (the engine) or its records are
/// given one by one (the CLI).
pub const LINE_CAP: usize = 1 << 20;

/// The longest raw line (record) read; the rest of a longer one is dropped.
pub const RAW_MAX: usize = LINE_CAP + 256;

/// How far back from the start of a tail to look for the lines that were
/// begun before it.
const LOOKBACK: usize = 2 * LINE_CAP;

const BLOCK: usize = 64 * 1024;

/// A position in the files of a log: the file (0 is the oldest), the byte
/// offset in it and, in a compressed file (no offsets), the number of raw
/// lines to skip from its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos {
    pub idx: usize,
    pub off: u64,
    pub skip: u64,
}

impl Pos {
    pub const START: Pos = Pos {
        idx: 0,
        off: 0,
        skip: 0,
    };
}

/// What a line is for the counting of a tail.
#[derive(Debug, Clone, Copy)]
pub struct Class {
    /// The stream it belongs to (0 or 1): lines of a stream are continued
    /// by the next one of the same lane.
    pub lane: usize,
    /// It ends a line of output.
    pub end: bool,
}

pub type Classify<'a> = &'a mut dyn FnMut(&[u8]) -> Option<Class>;

struct SnapFile {
    file: LogFile,
    /// Read no further than this (the length when the snapshot was taken).
    limit: Option<u64>,
}

/// The files of a log, open.
pub struct Snapshot {
    files: Vec<SnapFile>,
}

impl Snapshot {
    /// The log at `path`, its rotated files too, as it is now: what is
    /// appended later is not read.  Empty when there is no log.  With
    /// `allow` (the directory of the allowlist the path is below) the
    /// directory is opened beneath it, as [`logfmt::open_log_dir`] says.
    pub fn open(path: &Path, allow: Option<&Path>) -> io::Result<Self> {
        let (dir, name) = match logfmt::open_log_dir(path, allow) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::empty()),
            Err(e) => return Err(e),
        };
        let mut files = Vec::new();
        for file in logfmt::log_files(&dir, &name)? {
            let limit = match &file {
                LogFile::Plain(f) => Some(f.metadata()?.len()),
                LogFile::Gzip(_) => None,
            };
            files.push(SnapFile { file, limit });
        }
        Ok(Self { files })
    }

    /// The log in `dir` as it is now, to the last complete record of its
    /// newest file, and that file with the offset where the snapshot ends:
    /// a reader that goes on from there gets what is written later, once.
    pub(super) fn following(
        dir: &std::os::fd::OwnedFd,
        name: &str,
    ) -> io::Result<(Self, Option<(File, u64)>)> {
        let mut files = Vec::new();
        for file in logfmt::log_files(dir, name)? {
            let limit = match &file {
                LogFile::Plain(f) => Some(logfmt::complete_prefix(f, f.metadata()?.len())?),
                LogFile::Gzip(_) => None,
            };
            files.push(SnapFile { file, limit });
        }
        let cur = match files.last() {
            Some(SnapFile {
                file: LogFile::Plain(f),
                limit: Some(end),
            }) => Some((f.try_clone()?, *end)),
            _ => None,
        };
        Ok((Self { files }, cur))
    }

    /// The given files (oldest first), read to their end whenever that is.
    pub(super) fn from_files(files: Vec<LogFile>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|file| SnapFile { file, limit: None })
                .collect(),
        }
    }

    pub fn empty() -> Self {
        Self { files: Vec::new() }
    }

    fn end(&self, i: usize) -> io::Result<u64> {
        let f = &self.files[i];
        match (&f.file, f.limit) {
            (LogFile::Plain(_), Some(l)) => Ok(l),
            (LogFile::Plain(p), None) => Ok(p.metadata()?.len()),
            (LogFile::Gzip(_), _) => Ok(u64::MAX),
        }
    }

    fn reader(&self, i: usize, off: u64) -> Box<dyn Read + '_> {
        let f = &self.files[i];
        match &f.file {
            LogFile::Plain(p) => {
                let r = ReadAt { file: p, pos: off };
                match f.limit {
                    Some(l) => Box::new(r.take(l.saturating_sub(off))),
                    None => Box::new(r),
                }
            }
            LogFile::Gzip(g) => Box::new(flate2::read::GzDecoder::new(ReadAt { file: g, pos: 0 })),
        }
    }

    /// The line ends of a (compressed) file.
    fn count_ends(&self, i: usize, classify: Classify) -> io::Result<u64> {
        let mut n = 0;
        each_line(&mut *self.reader(i, 0), true, &mut |l| {
            if classify(l).is_some_and(|c| c.end) {
                n += 1;
            }
            Ok(true)
        })?;
        Ok(n)
    }

    /// The raw lines to skip in the compressed file `i` to pass its first
    /// `ends` line ends.
    fn skip_in(&self, i: usize, ends: u64, classify: Classify) -> io::Result<u64> {
        if ends == 0 {
            return Ok(0);
        }
        let (mut r, mut seen) = (0u64, 0u64);
        each_line(&mut *self.reader(i, 0), true, &mut |l| {
            r += 1;
            if classify(l).is_some_and(|c| c.end) {
                seen += 1;
            }
            Ok(seen < ends)
        })?;
        Ok(r)
    }

    /// The lines still open after the first `upto` raw lines (all of them
    /// if None) of the compressed file `i`: for each lane, the raw line
    /// where its open line begins.
    fn open_at(
        &self,
        i: usize,
        upto: Option<u64>,
        classify: Classify,
    ) -> io::Result<[Option<u64>; 2]> {
        let mut open = [None, None];
        if upto == Some(0) {
            return Ok(open);
        }
        let mut r = 0u64;
        each_line(&mut *self.reader(i, 0), true, &mut |l| {
            if let Some(c) = classify(l) {
                if c.end {
                    open[c.lane] = None;
                } else {
                    open[c.lane].get_or_insert(r);
                }
            }
            r += 1;
            Ok(upto.is_none_or(|u| r < u))
        })?;
        Ok(open)
    }

    /// `clean` in a compressed file: move back to the first record of the
    /// lines open at `pos`, until none is (each step is a pass over the
    /// file: time, no memory).
    fn clean_in(&self, mut pos: Pos, classify: Classify) -> io::Result<Pos> {
        loop {
            match self
                .open_at(pos.idx, Some(pos.skip), classify)?
                .iter()
                .flatten()
                .min()
            {
                Some(&s) if s < pos.skip => pos.skip = s,
                _ => return Ok(pos),
            }
        }
    }

    /// Call `f` with every line from `pos` on, until it returns false.  A
    /// last line cut (no newline) is a line when `flush_tail`.
    pub fn lines_from(
        &self,
        pos: &Pos,
        flush_tail: bool,
        f: &mut dyn FnMut(&[u8]) -> io::Result<bool>,
    ) -> io::Result<()> {
        for i in pos.idx..self.files.len() {
            let (off, mut skip) = if i == pos.idx {
                (pos.off, pos.skip)
            } else {
                (0, 0)
            };
            let mut go = true;
            each_line(&mut *self.reader(i, off), flush_tail, &mut |l| {
                if skip > 0 {
                    skip -= 1;
                    return Ok(true);
                }
                go = f(l)?;
                Ok(go)
            })?;
            if !go {
                return Ok(());
            }
        }
        Ok(())
    }

    /// The lines before `from`, the nearest first, until `f` returns false,
    /// the start of the log or a compressed file (it cannot be read back):
    /// then the index of that file.
    fn walk_back(
        &self,
        from: &Pos,
        f: &mut dyn FnMut(Pos, &[u8]) -> bool,
    ) -> io::Result<Option<usize>> {
        for i in (0..=from.idx.min(self.files.len().saturating_sub(1))).rev() {
            if self.files.is_empty() {
                break;
            }
            let LogFile::Plain(file) = &self.files[i].file else {
                if i == from.idx && from.skip == 0 {
                    // (at its start: nothing of it is before)
                    continue;
                }
                return Ok(Some(i));
            };
            let mut end = self.end(i)?;
            if i == from.idx {
                end = end.min(from.off);
            }
            let mut go = true;
            rev_lines(file, end, &mut |start, line| {
                go = f(
                    Pos {
                        idx: i,
                        off: start,
                        skip: 0,
                    },
                    line,
                );
                go
            })?;
            if !go {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Where the last `keep` line ends and what follows them start: the
    /// position after the `keep + 1`th line end from the end of the log.
    /// `last_rule`: the last line of the log ends a line, whatever it is.
    /// `clean`: move the start back to where no line of any lane is begun
    /// before it (the lines of the other lane that cross it would start
    /// with a continuation), looking back at most [`LOOKBACK`] bytes in the
    /// plain files (a compressed one is read forward: time, not memory); a
    /// line begun further back, or before a whole compressed file, is
    /// given from where the tail starts.
    pub fn locate(
        &self,
        keep: u64,
        classify: Classify,
        last_rule: bool,
        clean: bool,
    ) -> io::Result<Pos> {
        let mut seen = 0u64;
        let mut first = last_rule;
        let mut found: Option<Pos> = None;
        for i in (0..self.files.len()).rev() {
            match &self.files[i].file {
                LogFile::Plain(file) => {
                    let end = self.end(i)?;
                    rev_lines(file, end, &mut |start, line| {
                        let Some(c) = classify(line) else {
                            return true;
                        };
                        let was_first = std::mem::replace(&mut first, false);
                        if c.end || was_first {
                            seen += 1;
                            if seen > keep {
                                found = Some(Pos {
                                    idx: i,
                                    off: (start + line.len() as u64 + 1).min(end),
                                    skip: 0,
                                });
                                return false;
                            }
                        }
                        true
                    })?;
                }
                LogFile::Gzip(_) => {
                    let total = self.count_ends(i, classify)?;
                    if seen + total > keep {
                        let skip = self.skip_in(i, total - (keep - seen), classify)?;
                        found = Some(Pos {
                            idx: i,
                            off: 0,
                            skip,
                        });
                    } else {
                        seen += total;
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        let pos = found.unwrap_or(Pos::START);
        if clean {
            return self.clean(pos, classify);
        }
        Ok(pos)
    }

    fn clean(&self, mut pos: Pos, classify: Classify) -> io::Result<Pos> {
        if self.files.is_empty() {
            return Ok(pos);
        }
        if pos.skip > 0 {
            return self.clean_in(pos, classify);
        }
        loop {
            let mut chain: [Option<Pos>; 2] = [None; 2];
            let mut done = [false; 2];
            let mut spent = 0usize;
            let stopped = self.walk_back(&pos, &mut |p, line| {
                spent += line.len() + 1;
                if let Some(c) = classify(line) {
                    if !done[c.lane] {
                        if c.end {
                            done[c.lane] = true;
                        } else {
                            chain[c.lane] = Some(p);
                        }
                    }
                }
                !(done[0] && done[1]) && spent < LOOKBACK
            })?;
            if let Some(&new) = chain.iter().flatten().min() {
                if new < pos {
                    pos = new;
                    continue;
                }
            }
            // (a line still open may begin in a compressed file before:
            // it is read forward)
            if let Some(j) = stopped {
                let open = self.open_at(j, None, classify)?;
                let begin = (0..2).filter(|&l| !done[l]).filter_map(|l| open[l]).min();
                if let Some(skip) = begin {
                    return self.clean_in(
                        Pos {
                            idx: j,
                            off: 0,
                            skip,
                        },
                        classify,
                    );
                }
            }
            return Ok(pos);
        }
    }
}

/// Call `f` with every line (without its newline) read from `r`, until it
/// returns false.  A line longer than [`RAW_MAX`] is cut.  A last line
/// without newline is given when `flush_tail`.  Returns the bytes up to
/// the last newline.
pub(super) fn each_line(
    r: &mut dyn Read,
    flush_tail: bool,
    f: &mut dyn FnMut(&[u8]) -> io::Result<bool>,
) -> io::Result<u64> {
    let mut buf = vec![0u8; BLOCK];
    let mut line: Vec<u8> = Vec::new();
    let mut base = 0u64;
    let mut consumed = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        let mut s = 0;
        while let Some(i) = buf[s..n].iter().position(|&c| c == b'\n') {
            let seg = &buf[s..s + i];
            let go = if line.is_empty() {
                f(&seg[..seg.len().min(RAW_MAX)])?
            } else {
                let room = RAW_MAX.saturating_sub(line.len()).min(seg.len());
                line.extend_from_slice(&seg[..room]);
                let go = f(&line)?;
                line.clear();
                go
            };
            s += i + 1;
            consumed = base + s as u64;
            if !go {
                return Ok(consumed);
            }
        }
        let room = RAW_MAX.saturating_sub(line.len()).min(n - s);
        line.extend_from_slice(&buf[s..s + room]);
        base += n as u64;
    }
    if flush_tail && !line.is_empty() {
        f(&line)?;
    }
    Ok(consumed)
}

/// Call `f` with the lines of the first `end` bytes of `file`, the last
/// first, with the offset where each starts, until it returns false.  A
/// line longer than [`RAW_MAX`] is skipped (its start, which says what it
/// is, is not read).
fn rev_lines(file: &File, end: u64, f: &mut dyn FnMut(u64, &[u8]) -> bool) -> io::Result<()> {
    let mut pos = end;
    let mut carry: Vec<u8> = Vec::new();
    let mut overlong = false;
    let mut first = true;
    let mut block = vec![0u8; BLOCK];
    let mut data: Vec<u8> = Vec::new();
    while pos > 0 {
        let len = (block.len() as u64).min(pos) as usize;
        pos -= len as u64;
        file.read_exact_at(&mut block[..len], pos)?;
        data.clear();
        data.extend_from_slice(&block[..len]);
        data.extend_from_slice(&carry);
        let mut stop = data.len();
        // A trailing newline ends the last line, it does not start an empty one.
        if first && data.last() == Some(&b'\n') {
            stop -= 1;
        }
        first = false;
        while let Some(nl) = data[..stop].iter().rposition(|&c| c == b'\n') {
            if overlong {
                overlong = false;
            } else if !f(pos + nl as u64 + 1, &data[nl + 1..stop]) {
                return Ok(());
            }
            stop = nl;
        }
        carry.clear();
        if stop > RAW_MAX {
            overlong = true;
        } else {
            carry.extend_from_slice(&data[..stop]);
        }
    }
    if !first && !overlong {
        f(0, &carry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn file_with(content: &[u8]) -> File {
        let mut f = tempfile::tempfile_in("/var/tmp").unwrap();
        f.write_all(content).unwrap();
        f
    }

    fn rev(content: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let f = file_with(content);
        let mut out = Vec::new();
        rev_lines(&f, content.len() as u64, &mut |o, l| {
            out.push((o, l.to_vec()));
            true
        })
        .unwrap();
        out
    }

    #[test]
    fn rev_lines_cases() {
        assert!(rev(b"").is_empty());
        assert_eq!(rev(b"a\nb\n"), vec![(2, b"b".to_vec()), (0, b"a".to_vec())]);
        // no trailing newline
        assert_eq!(rev(b"a\nbc"), vec![(2, b"bc".to_vec()), (0, b"a".to_vec())]);
        // CRLF stays in the line
        assert_eq!(
            rev(b"a\r\nb\r\n"),
            vec![(3, b"b\r".to_vec()), (0, b"a\r".to_vec())]
        );
        // empty lines
        assert_eq!(
            rev(b"\n\nx\n"),
            vec![(2, b"x".to_vec()), (1, b"".to_vec()), (0, b"".to_vec())]
        );
    }

    #[test]
    fn rev_lines_across_blocks() {
        // lines of every length around the block size
        for len in [BLOCK - 2, BLOCK - 1, BLOCK, BLOCK + 1, BLOCK + 2, 3 * BLOCK] {
            let l1 = vec![b'a'; len];
            let l2 = vec![b'b'; len];
            let mut content = l1.clone();
            content.push(b'\n');
            content.extend_from_slice(&l2);
            content.push(b'\n');
            content.extend_from_slice(b"end");
            let got = rev(&content);
            assert_eq!(got.len(), 3, "{len}");
            assert_eq!(got[0].1, b"end");
            assert_eq!(got[1], (len as u64 + 1, l2));
            assert_eq!(got[2], (0, l1));
        }
    }

    #[test]
    fn rev_lines_skips_overlong() {
        let mut content = b"first\n".to_vec();
        content.extend(std::iter::repeat_n(b'x', 10 << 20));
        content.extend_from_slice(b"\nlast\n");
        let got = rev(&content);
        assert_eq!(got.len(), 2, "the 10 MiB line is skipped");
        assert_eq!(got[0].1, b"last");
        assert_eq!(got[1].1, b"first");
    }

    #[test]
    fn each_line_cuts_and_counts() {
        let mut content = b"ab\ncd".to_vec();
        let mut got = Vec::new();
        let n = each_line(&mut &content[..], false, &mut |l| {
            got.push(l.to_vec());
            Ok(true)
        })
        .unwrap();
        assert_eq!((got.len(), n), (1, 3));
        got.clear();
        each_line(&mut &content[..], true, &mut |l| {
            got.push(l.to_vec());
            Ok(true)
        })
        .unwrap();
        assert_eq!(got, vec![b"ab".to_vec(), b"cd".to_vec()]);
        // a 10 MiB line is cut, the next one is whole
        content = std::iter::repeat_n(b'x', 10 << 20).collect();
        content.extend_from_slice(b"\nnext\n");
        got.clear();
        each_line(&mut &content[..], false, &mut |l| {
            got.push(l.to_vec());
            Ok(true)
        })
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].len(), RAW_MAX);
        assert_eq!(got[1], b"next");
    }

    // the snapshot of a log below the allowlist does not follow a link
    // there: the engine reads the log of `--log-opt path` as the user it
    // runs as
    #[test]
    fn a_snapshot_below_the_allowlist_follows_no_link() {
        let allow = tempfile::tempdir_in("/var/tmp").unwrap();
        let elsewhere = tempfile::tempdir_in("/var/tmp").unwrap();
        std::fs::write(elsewhere.path().join("ctr.log"), b"secret\n").unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), allow.path().join("d")).unwrap();
        let through = allow.path().join("d/ctr.log");
        assert!(Snapshot::open(&through, Some(allow.path())).is_err());
        assert_eq!(Snapshot::open(&through, None).unwrap().files.len(), 1);
        std::fs::create_dir(allow.path().join("real")).unwrap();
        std::fs::write(allow.path().join("real/ctr.log"), b"x\n").unwrap();
        let snap = Snapshot::open(&allow.path().join("real/ctr.log"), Some(allow.path())).unwrap();
        assert_eq!(snap.files.len(), 1);
    }
}
