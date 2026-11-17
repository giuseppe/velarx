// SPDX-License-Identifier: Apache-2.0
//! Container logs in the CRI (`k8s-file`) format, one record per line:
//!
//! ```text
//! <RFC 3339 timestamp, nanoseconds> <stdout|stderr> <F|P> <content>
//! ```
//!
//! `F` ends a line, `P` is a partial line that the next record of the same
//! stream continues.  The writer rotates the file by size; the reader
//! follows the rotations.  With compression the rotated files but the
//! newest (`.1`, which a reader that follows the log may still be reading)
//! are gzip files, `<name>.<n>.gz`.
//!
//! Reading a log never holds it in memory (see `logsel`): a tail finds its
//! start from the end of the files (a compressed file is counted as a
//! stream), the rest is streamed line by line, a line longer than 1 MiB is
//! cut (records) or given in pieces (the engine's lines).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{Mode, OFlags};
pub use velarx_proto::time::Toward;
use velarx_proto::time::{format_rfc3339, parse_input_time, Fraction};

/// The longest content of one record: a longer line is split in partial
/// records.
pub const MAX_RECORD: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    fn name(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// `2026-10-10T14:36:53.881627123Z`
pub fn format_rfc3339_ns(ns: i64) -> String {
    format_rfc3339(ns, Fraction::Nine)
}

/// `2026-10-10T16:36:53.881627123+02:00`: the local time with its offset, as
/// conmon writes the records of a log file (`+00:00` for UTC).
pub fn format_local_rfc3339_ns(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let Some(t) = velarx_sys::time::local_time(secs) else {
        return format_rfc3339_ns(ns);
    };
    let nanos = ns.rem_euclid(1_000_000_000);
    let (sign, off) = if t.utc_offset < 0 {
        ('-', -t.utc_offset)
    } else {
        ('+', t.utc_offset)
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{nanos:09}{sign}{:02}:{:02}",
        t.year,
        t.month,
        t.day,
        t.hour,
        t.minute,
        t.second,
        off / 3600,
        off % 3600 / 60
    )
}

pub use velarx_proto::time::parse_rfc3339 as parse_rfc3339_ns;

/// The time of `--since` (a duration is how long ago) or `--until` (how
/// long from now, as podman's) of the logs: podman's `ParseInputTime`, and
/// the days and weeks and the blanks the command line takes besides.
pub fn parse_log_time(spec: &str, now_ns: i64, toward: Toward) -> Option<i64> {
    parse_input_time(spec, now_ns, toward, true)
}

/// The `--since` or `--until` (`what`) of the logs of a pod, in
/// nanoseconds since the epoch: none when it is not given; podman's words
/// when it does not parse.
pub fn parse_pod_log_time(
    what: &str,
    spec: Option<&str>,
    now_ns: i64,
) -> Result<Option<i64>, String> {
    let Some(s) = spec else {
        return Ok(None);
    };
    let toward = if what == "until" {
        Toward::Future
    } else {
        Toward::Past
    };
    parse_log_time(s, now_ns, toward)
        .map(Some)
        .ok_or_else(|| format!("parsing --{what} \"{s}\": unable to interpret time value"))
}

/// A line of the journal of a container, joined from its partial entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalLine {
    /// RFC 3339, when the line began
    pub timestamp: String,
    pub stderr: bool,
    pub message: String,
}

/// The lines of `journalctl -o json`, one object per entry: the partial
/// entries of a stream are joined (`CONTAINER_PARTIAL_MESSAGE`).
#[derive(Default)]
pub struct JournalLines {
    pending: [Option<(String, String)>; 2],
    cursor: Option<String>,
}

impl JournalLines {
    /// The line an entry ends, if it ends one.
    pub fn push(&mut self, entry: &[u8]) -> Option<JournalLine> {
        let text = |v: &serde_json::Value| -> Option<String> {
            match v {
                serde_json::Value::String(s) => Some(s.clone()),
                // A value that is not UTF-8 is an array of bytes.
                serde_json::Value::Array(a) => {
                    let bytes: Vec<u8> = a
                        .iter()
                        .filter_map(|b| b.as_u64().map(|b| b as u8))
                        .collect();
                    Some(String::from_utf8_lossy(&bytes).into_owned())
                }
                _ => None,
            }
        };
        let v = serde_json::from_slice::<serde_json::Value>(entry).ok()?;
        if let Some(c) = v.get("__CURSOR").and_then(text) {
            self.cursor = Some(c);
        }
        let message = v.get("MESSAGE").and_then(text)?;
        let stderr = v.get("PRIORITY").and_then(text).as_deref() == Some("3");
        let ts = v
            .get("__REALTIME_TIMESTAMP")
            .and_then(text)
            .and_then(|us| us.parse::<i64>().ok())
            .map(|us| format_rfc3339_ns(us.saturating_mul(1000)));
        let partial = ["CONTAINER_PARTIAL_MESSAGE", "PARTIAL_MESSAGE"]
            .iter()
            .any(|k| v.get(*k).and_then(text).as_deref() == Some("true"));
        let slot = &mut self.pending[usize::from(stderr)];
        let (first_ts, mut joined) = slot
            .take()
            .unwrap_or((ts.unwrap_or_default(), String::new()));
        joined.push_str(&message);
        if partial {
            *slot = Some((first_ts, joined));
            return None;
        }
        Some(JournalLine {
            timestamp: first_ts,
            stderr,
            message: joined,
        })
    }

    /// The cursor of the last entry pushed (`journalctl --after-cursor`):
    /// every entry up to it is in a line given or in one still pending.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

/// How big the log of a container may grow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    /// Rotate when the file would grow past this (0: never).
    pub max_size: u64,
    /// How many files to keep, the current one included (at least 1).
    pub max_files: u32,
    /// The most all the files together may take (0: no limit).
    pub global_max: u64,
    /// Compress the rotated files (but the newest).
    pub compress: bool,
}

fn rotated_name(name: &str, n: u32) -> String {
    format!("{name}.{n}")
}

fn compressed_name(name: &str, n: u32) -> String {
    format!("{name}.{n}.gz")
}

/// The lock of the files of a log: the writer holds it exclusive while it
/// shifts the rotated files, a reader shared while it opens them, so that it
/// sees each one once, and all of them.  A reader finds no lock when no
/// writer made it yet: there is nothing to shift, and it goes without; any
/// other failure is an error.
fn lock_files(dir: &OwnedFd, name: &str, exclusive: bool) -> io::Result<Option<OwnedFd>> {
    let lock = format!("{name}.lock");
    let fd = if exclusive {
        rustix::fs::openat(
            dir,
            &lock,
            OFlags::RDONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
    } else {
        rustix::fs::openat(
            dir,
            &lock,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    };
    let fd = match fd {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) if !exclusive => return Ok(None),
        Err(e) => return Err(io::Error::new(e.kind(), format!("{lock}: {e}"))),
    };
    let op = if exclusive {
        rustix::fs::FlockOperation::LockExclusive
    } else {
        rustix::fs::FlockOperation::LockShared
    };
    match velarx_sys::flock::flock_retrying(&fd, op) {
        Ok(()) => Ok(Some(fd)),
        Err(e) => Err(io::Error::new(e.kind(), format!("{lock}: {e}"))),
    }
}

/// The name of the `n`th rotated file of a log in `dir`, plain or
/// compressed, if there is one.
fn existing_rotated(dir: &OwnedFd, name: &str, n: u32) -> Option<String> {
    [rotated_name(name, n), compressed_name(name, n)]
        .into_iter()
        .find(|f| rustix::fs::statat(dir, f, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).is_ok())
}

/// The directory of the log at `path` and the name of the file in it.
/// With `allow` (a directory of the allowlist of log paths) `path` must be
/// below it, and the directory is opened below it without following any
/// symbolic link (`velarx_sys::fs::open_beneath`): a link put
/// there cannot lead the logs elsewhere.
pub fn open_log_dir(path: &Path, allow: Option<&Path>) -> io::Result<(OwnedFd, String)> {
    let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidInput, m);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && *n != "." && *n != "..")
        .ok_or_else(|| invalid(format!("invalid log path {}", path.display())))?
        .to_string();
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let flags = OFlags::DIRECTORY | OFlags::PATH | OFlags::CLOEXEC;
    let Some(allow) = allow else {
        return Ok((rustix::fs::open(parent, flags, Mode::empty())?, name));
    };
    let rel = parent
        .strip_prefix(allow)
        .ok()
        .filter(|r| {
            r.components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        })
        .ok_or_else(|| {
            invalid(format!(
                "the log path {} is not below {}",
                path.display(),
                allow.display()
            ))
        })?;
    let base = rustix::fs::open(allow, flags, Mode::empty())?;
    if rel.as_os_str().is_empty() {
        return Ok((base, name));
    }
    let beneath = velarx_sys::fs::Beneath::DirectoryPath;
    let dir = velarx_sys::fs::open_beneath(base.as_fd(), rel, beneath).map_err(|e| {
        let e = io::Error::from(e);
        io::Error::new(
            e.kind(),
            format!(
                "cannot open {} below {} without symbolic links: {e}",
                parent.display(),
                allow.display()
            ),
        )
    })?;
    Ok((dir, name))
}

pub struct LogWriter {
    dir: OwnedFd,
    name: String,
    file: Option<File>,
    size: u64,
    limits: Limits,
    /// Whether the last record of each stream was partial.
    partial: [bool; 2],
    /// The size the file may grow to before the next rotation is tried:
    /// past `max_size` once a rotation could not take its lock
    rotate_at: u64,
    /// The error of a rotation that left the file as it was, for the caller
    unrotated: Option<io::Error>,
}

impl LogWriter {
    pub fn open(path: &Path, limits: Limits) -> io::Result<Self> {
        Self::open_in(path, None, limits)
    }

    /// The writer of the log at `path`, below `allow` (see `open_log_dir`).
    pub fn open_in(path: &Path, allow: Option<&Path>, limits: Limits) -> io::Result<Self> {
        let (dir, name) = open_log_dir(path, allow)?;
        let mut w = Self {
            dir,
            name,
            file: None,
            size: 0,
            limits: Limits {
                max_files: limits.max_files.max(1),
                ..limits
            },
            partial: [false; 2],
            rotate_at: limits.max_size,
            unrotated: None,
        };
        w.open_file()?;
        Ok(w)
    }

    fn open_file(&mut self) -> io::Result<()> {
        let fd = rustix::fs::openat(
            &self.dir,
            &self.name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let file = File::from(fd);
        self.size = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    /// Close and open the file again, after somebody renamed it.
    pub fn reopen(&mut self) -> io::Result<()> {
        self.file = None;
        self.open_file()
    }

    fn rotate(&mut self) -> io::Result<()> {
        let _lock = lock_files(&self.dir, &self.name, true)?;
        self.file = None;
        let keep = self.limits.max_files;
        if keep > 1 {
            for old in [
                rotated_name(&self.name, keep - 1),
                compressed_name(&self.name, keep - 1),
            ] {
                let _ = rustix::fs::unlinkat(&self.dir, old, rustix::fs::AtFlags::empty());
            }
            for n in (1..keep - 1).rev() {
                let Some(from) = existing_rotated(&self.dir, &self.name, n) else {
                    continue;
                };
                let to = if from.ends_with(".gz") {
                    compressed_name(&self.name, n + 1)
                } else {
                    rotated_name(&self.name, n + 1)
                };
                let _ = rustix::fs::renameat(&self.dir, from, &self.dir, to);
            }
            match rustix::fs::renameat(
                &self.dir,
                &self.name,
                &self.dir,
                rotated_name(&self.name, 1),
            ) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
            if self.limits.compress && keep > 2 {
                // (in the monitor's loop: a file of at most max-size, at
                // the fastest level)
                if let Err(e) = self.compress(2) {
                    eprintln!("cannot compress the rotated log: {e}");
                }
            }
        } else {
            match rustix::fs::unlinkat(&self.dir, &self.name, rustix::fs::AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.enforce_global_max();
        self.open_file()
    }

    /// Replace the `n`th rotated file with its gzip, written aside first.
    fn compress(&self, n: u32) -> io::Result<()> {
        let plain = rotated_name(&self.name, n);
        let Some(mut src) = open_nofollow(&self.dir, &plain)? else {
            return Ok(());
        };
        let tmp = format!("{}.tmp", compressed_name(&self.name, n));
        let fd = rustix::fs::openat(
            &self.dir,
            &tmp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?;
        let result = (|| {
            let mut gz = flate2::write::GzEncoder::new(File::from(fd), flate2::Compression::fast());
            io::copy(&mut src, &mut gz)?;
            gz.finish()?;
            rustix::fs::renameat(&self.dir, &tmp, &self.dir, compressed_name(&self.name, n))?;
            rustix::fs::unlinkat(&self.dir, &plain, rustix::fs::AtFlags::empty())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(&self.dir, &tmp, rustix::fs::AtFlags::empty());
        }
        result
    }

    /// Remove the oldest rotated files until the logs fit in the global
    /// limit.
    fn enforce_global_max(&self) {
        if self.limits.global_max == 0 {
            return;
        }
        let mut sizes = Vec::new();
        for n in 1..self.limits.max_files {
            let Some(name) = existing_rotated(&self.dir, &self.name, n) else {
                continue;
            };
            if let Ok(st) =
                rustix::fs::statat(&self.dir, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            {
                sizes.push((name, st.st_size as u64));
            }
        }
        let mut total: u64 = sizes.iter().map(|(_, s)| s).sum();
        // The newest file is ".1": remove from the oldest.
        while total + self.limits.max_size.min(self.limits.global_max) > self.limits.global_max {
            let Some((name, size)) = sizes.pop() else {
                break;
            };
            let _ = rustix::fs::unlinkat(&self.dir, &name, rustix::fs::AtFlags::empty());
            total -= size;
        }
    }

    fn write_record(&mut self, stream: Stream, content: &[u8], partial: bool) -> io::Result<()> {
        let mut line = Vec::with_capacity(content.len() + 48);
        line.extend_from_slice(format_local_rfc3339_ns(now_ns()).as_bytes());
        line.push(b' ');
        line.extend_from_slice(stream.name().as_bytes());
        line.extend_from_slice(if partial { b" P " } else { b" F " });
        line.extend_from_slice(content);
        line.push(b'\n');

        if self.limits.max_size > 0
            && self.size > 0
            && self.size + line.len() as u64 > self.rotate_at
        {
            match self.rotate() {
                Ok(()) => self.rotate_at = self.limits.max_size,
                // (the lock: nothing moved, the file is open still) The
                // output of the container is not lost for it: it goes on
                // into the file, and the rotation is tried again once the
                // file grew by another max-size.
                Err(e) if self.file.is_some() => {
                    self.rotate_at = self.size + self.limits.max_size;
                    self.unrotated = Some(io::Error::new(
                        e.kind(),
                        format!("cannot rotate the log: {e}"),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("the log file is closed"))?;
        file.write_all(&line)?;
        self.size += line.len() as u64;
        self.partial[stream.index()] = partial;
        Ok(())
    }

    /// Log what a stream of the container produced.  A rotation that
    /// cannot take its lock moves nothing: the data goes into the current
    /// file all the same, and the error is returned once it is written.
    pub fn write(&mut self, stream: Stream, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let (line, rest, complete) = match data.iter().position(|&c| c == b'\n') {
                Some(i) => (&data[..i], &data[i + 1..], true),
                None => (data, &data[data.len()..], false),
            };
            let mut line = line;
            while line.len() > MAX_RECORD {
                self.write_record(stream, &line[..MAX_RECORD], true)?;
                line = &line[MAX_RECORD..];
            }
            if complete || !line.is_empty() {
                self.write_record(stream, line, !complete)?;
            }
            data = rest;
        }
        self.unrotated.take().map_or(Ok(()), Err)
    }

    /// End the lines the container left unfinished.
    pub fn finish(&mut self) -> io::Result<()> {
        for stream in [Stream::Stdout, Stream::Stderr] {
            if self.partial[stream.index()] {
                self.write_record(stream, b"", false)?;
            }
        }
        Ok(())
    }
}

/// One record of a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub ts_ns: i64,
    pub stream: Stream,
    pub partial: bool,
    pub content: Vec<u8>,
}

/// Parse a line of a log (without its newline).
pub fn parse_record(line: &[u8]) -> Option<Record> {
    let sp1 = line.iter().position(|&c| c == b' ')?;
    let ts_ns = parse_rfc3339_ns(std::str::from_utf8(&line[..sp1]).ok()?)?;
    let rest = &line[sp1 + 1..];
    let sp2 = rest.iter().position(|&c| c == b' ')?;
    let stream = match &rest[..sp2] {
        b"stdout" => Stream::Stdout,
        b"stderr" => Stream::Stderr,
        _ => return None,
    };
    let rest = &rest[sp2 + 1..];
    let partial = match rest.first()? {
        b'F' => false,
        b'P' => true,
        _ => return None,
    };
    let content = match rest.get(1) {
        None => &[][..],
        Some(b' ') => &rest[2..],
        Some(_) => return None,
    };
    Some(Record {
        ts_ns,
        stream,
        partial,
        content: content.to_vec(),
    })
}

/// Where the lines (records) of a log read go.
type RawSink<'a> = &'a mut dyn FnMut(&[u8]) -> io::Result<()>;

/// What `read_logs` selects.
#[derive(Debug, Clone, Default)]
pub struct ReadOptions {
    /// Only the records at or after this time.
    pub since_ns: Option<i64>,
    /// Only the records at or before this time.
    pub until_ns: Option<i64>,
    /// Only the last lines.
    pub tail: Option<usize>,
    /// Wait for more output.
    pub follow: bool,
    /// The directory of the allowlist the log is below (see
    /// `open_log_dir`).
    pub allow_dir: Option<PathBuf>,
}

fn open_nofollow(dir: &OwnedFd, name: &str) -> io::Result<Option<File>> {
    match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A file of the log: plain, or a compressed rotated file, decompressed
/// when it is read.
pub(super) enum LogFile {
    Plain(File),
    Gzip(File),
}

impl LogFile {
    pub(super) fn file(&self) -> &File {
        match self {
            LogFile::Plain(f) | LogFile::Gzip(f) => f,
        }
    }
}

/// The `n`th rotated file of the log, plain or compressed.
fn open_rotated(dir: &OwnedFd, name: &str, n: u32) -> io::Result<Option<LogFile>> {
    if let Some(f) = open_nofollow(dir, &rotated_name(name, n))? {
        return Ok(Some(LogFile::Plain(f)));
    }
    Ok(open_nofollow(dir, &compressed_name(name, n))?.map(LogFile::Gzip))
}

/// The files of the log, the oldest first.
pub(super) fn log_files(dir: &OwnedFd, name: &str) -> io::Result<Vec<LogFile>> {
    let mut lock = lock_files(dir, name, false)?;
    loop {
        let mut files = Vec::new();
        // The current file first: a rotation in between moves it to `.1`,
        // which is then skipped as the same file.
        let current = open_nofollow(dir, name)?;
        let mut n = 1;
        let mut older = Vec::new();
        while let Some(f) = open_rotated(dir, name, n)? {
            older.push(f);
            n += 1;
        }
        if let Some(c) = &current {
            older.retain(|o| !same_file(o.file(), c));
        }
        older.reverse();
        files.extend(older);
        files.extend(current.map(LogFile::Plain));
        // (opened without the lock, which the first rotation makes before
        // it moves anything: still none, and no rotation began; one now,
        // and the first rotations may have moved the files while they were
        // opened: again, under the lock)
        if lock.is_none() {
            lock = lock_files(dir, name, false)?;
            if lock.is_some() {
                continue;
            }
        }
        return Ok(files);
    }
}

/// Read the log at `path` (and its rotated files), calling `sink` for every
/// record selected by `opts`.  With `opts.follow`, keep going as the log
/// grows until `stop` is readable (or forever).
pub fn read_logs(
    path: &Path,
    opts: &ReadOptions,
    stop: Option<&dyn AsFd>,
    sink: &mut dyn FnMut(&Record) -> io::Result<()>,
) -> io::Result<()> {
    read_logs_with(path, opts, stop, sink, &mut || {})
}

/// [`read_logs`] that calls `caught_up` once, when what the log held
/// already has been given to `sink` and the following starts.
pub fn read_logs_with(
    path: &Path,
    opts: &ReadOptions,
    stop: Option<&dyn AsFd>,
    sink: &mut dyn FnMut(&Record) -> io::Result<()>,
    caught_up: &mut dyn FnMut(),
) -> io::Result<()> {
    let (dir, name) = open_log_dir(path, opts.allow_dir.as_deref())?;
    let selected = |r: &Record| {
        opts.since_ns.is_none_or(|s| r.ts_ns >= s) && opts.until_ns.is_none_or(|u| r.ts_ns <= u)
    };

    // Watch before reading so that nothing written in between is missed.
    let watch = if opts.follow {
        Some(super::logwatch::DirWatch::new(&dir)?)
    } else {
        None
    };

    let mut files = log_files(&dir, &name)?;
    let mut cur: Option<(File, u64)> = None;
    let mut emit = |l: &[u8]| match parse_record(l) {
        Some(r) if selected(&r) => sink(&r),
        _ => Ok(()),
    };
    match opts.tail {
        Some(n) => {
            // the newest file, where a follower goes on (it is not
            // compressed: the current file, or `.1`)
            let newest = match files.last() {
                Some(f) => Some(f.file().try_clone()?),
                None => None,
            };
            // (the start of the last `n` lines is found from the end of
            // the files; nothing but the lines themselves is held)
            let snap = super::logsel::Snapshot::from_files(files);
            let mut class = |l: &[u8]| {
                parse_record(l).map(|r| super::logsel::Class {
                    lane: 0,
                    end: !r.partial,
                })
            };
            let pos = snap.locate(n as u64, &mut class, true, false)?;
            snap.lines_from(&pos, true, &mut |l| {
                emit(l)?;
                Ok(true)
            })?;
            if let Some(f) = newest {
                // Only complete lines were read: go on after the last newline.
                let off = complete_prefix(&f, f.metadata()?.len())?;
                cur = Some((f, off));
            }
        }
        None => {
            let mut last = None;
            for f in files.drain(..) {
                match f {
                    LogFile::Plain(mut f) => {
                        let off = read_forward(&mut f, 0, &mut emit)?;
                        last = Some((f, off));
                    }
                    LogFile::Gzip(g) => {
                        read_gzip(&g, &mut emit)?;
                        last = None;
                    }
                }
            }
            cur = last;
        }
    }
    caught_up();
    let Some(watch) = watch else {
        return Ok(());
    };

    loop {
        // (what changes after this is told again: the log is read after)
        watch.clear();
        follow_pump(&dir, &name, &mut cur, &mut emit)?;
        let mut fds = vec![rustix::event::PollFd::from_borrowed_fd(
            watch.fd(),
            rustix::event::PollFlags::IN,
        )];
        if let Some(stop) = stop {
            fds.push(rustix::event::PollFd::from_borrowed_fd(
                stop.as_fd(),
                rustix::event::PollFlags::IN,
            ));
        }
        // --until: the following ends at that time
        let timeout = match opts.until_ns {
            None => -1,
            Some(u) => {
                let left = u.saturating_sub(now_ns());
                if left <= 0 {
                    return follow_pump(&dir, &name, &mut cur, &mut emit);
                }
                (left / 1_000_000 + 1).min(i32::MAX as i64) as i32
            }
        };
        super::proto::poll(&mut fds, timeout)?;
        if fds.get(1).is_some_and(|f| !f.revents().is_empty()) {
            // The container is gone: read what it wrote last.
            return follow_pump(&dir, &name, &mut cur, &mut emit);
        }
    }
}

/// A reader of a log that goes on as the log grows: the files it held when
/// it was opened ([`Follower::snapshot`]), then the lines appended to the
/// file where the snapshot ended, in order and once each, across rotations
/// (the position is a file and an offset in it, not a count).
pub struct Follower {
    dir: OwnedFd,
    name: String,
    watch: super::logwatch::DirWatch,
    cur: Option<(File, u64)>,
}

impl Follower {
    /// Watch the directory of the log at `path`; `NotFound` when it is not
    /// there.
    pub fn open(path: &Path, allow_dir: Option<&Path>) -> io::Result<Self> {
        let (dir, name) = open_log_dir(path, allow_dir)?;
        // (before the snapshot: what is written after it makes the
        // descriptor readable)
        let watch = super::logwatch::DirWatch::new(&dir)?;
        Ok(Self {
            dir,
            name,
            watch,
            cur: None,
        })
    }

    /// The log as it is now, to its last complete record: [`Follower::pump`]
    /// gives what follows.
    pub fn snapshot(&mut self) -> io::Result<super::logsel::Snapshot> {
        let (snap, cur) = super::logsel::Snapshot::following(&self.dir, &self.name)?;
        self.cur = cur;
        Ok(snap)
    }

    /// Give `sink` the lines appended since the last call (or the snapshot),
    /// the rotated files included; an error of `sink` ends the call.
    pub fn pump(&mut self, sink: RawSink) -> io::Result<()> {
        // (a change after this is told again by `wait`)
        self.watch.clear();
        follow_pump(&self.dir, &self.name, &mut self.cur, sink)
    }

    /// Wait until the log changes, one of `stops` is readable (the first
    /// that is: its index) or `timeout_ms` passes (-1: never; None).
    pub fn wait(&self, stops: &[&dyn AsFd], timeout_ms: i32) -> io::Result<Option<usize>> {
        let mut fds = vec![rustix::event::PollFd::from_borrowed_fd(
            self.watch.fd(),
            rustix::event::PollFlags::IN,
        )];
        for s in stops {
            fds.push(rustix::event::PollFd::from_borrowed_fd(
                s.as_fd(),
                rustix::event::PollFlags::IN,
            ));
        }
        let ready = super::proto::poll(&mut fds, timeout_ms)?;
        if ready == 0 {
            return Ok(None);
        }
        let stopped = fds[1..].iter().position(|f| !f.revents().is_empty());
        Ok(stopped)
    }
}

fn same_file(a: &File, b: &File) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (a.metadata(), b.metadata()) {
        (Ok(x), Ok(y)) => (x.ino(), x.dev()) == (y.ino(), y.dev()),
        _ => false,
    }
}

/// Read what was appended to the file being followed, and the files that
/// replaced it if the log was rotated.
/// The rotated files the retention deleted before they were read are lost.
fn follow_pump(
    dir: &OwnedFd,
    name: &str,
    cur: &mut Option<(File, u64)>,
    sink: RawSink,
) -> io::Result<()> {
    loop {
        let (mut file, off) = match cur.take() {
            Some(c) => c,
            None => match open_nofollow(dir, name)? {
                Some(f) => (f, 0),
                None => return Ok(()),
            },
        };
        // (truncated in place: its lines begin again)
        let off = if file.metadata()?.len() < off { 0 } else { off };
        let off = read_forward(&mut file, off, sink)?;
        match open_nofollow(dir, name)? {
            Some(now) if !same_file(&file, &now) => {
                // Rotated: what was appended before the rename, then the
                // files rotated since, then the new file.
                read_forward(&mut file, off, sink)?;
                // The files rotated since, by the time of their first
                // record: the writer may shift them while they are looked
                // at (one is seen twice), and compress the one being read
                // (a new file, which starts with the same record).
                let mut missed: Vec<(i64, LogFile)> = Vec::new();
                let start = first_ts(&mut ReadAt {
                    file: &file,
                    pos: 0,
                });
                let lock = lock_files(dir, name, false)?;
                // (the current file again, under the lock: the files are
                // those of one moment)
                let now = open_nofollow(dir, name)?.unwrap_or(now);
                let mut n = 1;
                while let Some(f) = open_rotated(dir, name, n)? {
                    n += 1;
                    if same_file(f.file(), &file) {
                        break;
                    }
                    let ts = match &f {
                        LogFile::Plain(p) => first_ts(&mut ReadAt { file: p, pos: 0 }),
                        LogFile::Gzip(g) => first_ts(&mut flate2::read::GzDecoder::new(ReadAt {
                            file: g,
                            pos: 0,
                        })),
                    };
                    let Some(ts) = ts else { continue };
                    if start.is_some_and(|s| ts <= s) {
                        break;
                    }
                    if !same_file(f.file(), &now) && !missed.iter().any(|(t, _)| *t == ts) {
                        missed.push((ts, f));
                    }
                }
                drop(lock);
                missed.sort_by_key(|(ts, _)| *ts);
                for (_, f) in missed {
                    match f {
                        LogFile::Plain(mut p) => {
                            read_forward(&mut p, 0, sink)?;
                        }
                        LogFile::Gzip(g) => read_gzip(&g, sink)?,
                    }
                }
                *cur = Some((now, 0));
            }
            _ => {
                *cur = Some((file, off));
                return Ok(());
            }
        }
    }
}

/// Reads a file from an offset of its own (not the file's).
pub(super) struct ReadAt<'a> {
    pub(super) file: &'a File,
    pub(super) pos: u64,
}

impl Read for ReadAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let n = self.file.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// The time of the first record of a log file.
fn first_ts(r: &mut dyn Read) -> Option<i64> {
    let mut line = Vec::new();
    let mut buf = [0u8; 512];
    while !line.contains(&b'\n') && line.len() < MAX_RECORD + 128 {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        line.extend_from_slice(&buf[..n]);
    }
    let end = line.iter().position(|&c| c == b'\n').unwrap_or(line.len());
    parse_record(&line[..end]).map(|r| r.ts_ns)
}

/// The offset after the last newline in the first `len` bytes of `file`.
pub(super) fn complete_prefix(file: &File, len: u64) -> io::Result<u64> {
    let mut f = file.try_clone()?;
    let mut pos = len;
    let mut block = vec![0u8; 4096];
    while pos > 0 {
        let n = (block.len() as u64).min(pos) as usize;
        pos -= n as u64;
        f.seek(SeekFrom::Start(pos))?;
        f.read_exact(&mut block[..n])?;
        if let Some(i) = block[..n].iter().rposition(|&c| c == b'\n') {
            return Ok(pos + i as u64 + 1);
        }
    }
    Ok(0)
}

fn read_forward(file: &mut File, offset: u64, sink: RawSink) -> io::Result<u64> {
    file.seek(SeekFrom::Start(offset))?;
    let consumed = super::logsel::each_line(file, false, &mut |l| {
        sink(l)?;
        Ok(true)
    })?;
    Ok(offset + consumed)
}

/// The records of a compressed file, decompressed as a stream.
fn read_gzip(file: &File, sink: RawSink) -> io::Result<()> {
    let mut r = flate2::read::GzDecoder::new(ReadAt { file, pos: 0 });
    super::logsel::each_line(&mut r, false, &mut |l| {
        sink(l)?;
        Ok(true)
    })?;
    Ok(())
}

/// Prints records the way `logs` shows them: the content, a newline at the
/// end of a line, a timestamp at the start of each line when asked.
pub struct Printer<'a> {
    pub timestamps: bool,
    line_start: [bool; 2],
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl<'a> Printer<'a> {
    pub fn new(timestamps: bool, out: &'a mut dyn Write, err: &'a mut dyn Write) -> Self {
        Self {
            timestamps,
            line_start: [true; 2],
            out,
            err,
        }
    }

    pub fn print(&mut self, rec: &Record) -> io::Result<()> {
        let w: &mut dyn Write = match rec.stream {
            Stream::Stdout => self.out,
            Stream::Stderr => self.err,
        };
        let start = &mut self.line_start[rec.stream.index()];
        if self.timestamps && *start {
            w.write_all(format_local_rfc3339_ns(rec.ts_ns).as_bytes())?;
            w.write_all(b" ")?;
        }
        w.write_all(&rec.content)?;
        if !rec.partial {
            w.write_all(b"\n")?;
        }
        w.flush()?;
        *start = !rec.partial;
        Ok(())
    }
}

/// Joins the partial records of a stream into lines.
#[derive(Default)]
pub struct LineAssembler {
    pending: [Option<(i64, Vec<u8>)>; 2],
}

impl LineAssembler {
    /// The finished line this record ends, if it does: timestamp (of the
    /// first record of the line), stream and content.
    pub fn push(&mut self, rec: &Record) -> Option<(i64, Stream, Vec<u8>)> {
        let slot = &mut self.pending[rec.stream.index()];
        let (ts, mut content) = slot.take().unwrap_or((rec.ts_ns, Vec::new()));
        content.extend_from_slice(&rec.content);
        if rec.partial {
            *slot = Some((ts, content));
            None
        } else {
            Some((ts, rec.stream, content))
        }
    }

    /// The lines still open.
    pub fn finish(&mut self) -> Vec<(i64, Stream, Vec<u8>)> {
        let mut out = Vec::new();
        for (i, slot) in self.pending.iter_mut().enumerate() {
            if let Some((ts, c)) = slot.take() {
                out.push((
                    ts,
                    if i == 0 {
                        Stream::Stdout
                    } else {
                        Stream::Stderr
                    },
                    c,
                ));
            }
        }
        out
    }
}

/// The path of the `n`th rotated file of a log.
pub fn rotated_path(path: &Path, n: u32) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let mut name: OsString = OsString::from_vec(path.as_os_str().as_bytes().to_vec());
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records(path: &Path, opts: &ReadOptions) -> Vec<(Stream, bool, String)> {
        let mut out = Vec::new();
        read_logs(path, opts, None, &mut |r| {
            out.push((
                r.stream,
                r.partial,
                String::from_utf8_lossy(&r.content).into_owned(),
            ));
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn timestamps_round_trip() {
        for ns in [
            0i64,
            1_760_106_000_123_456_789,
            951_782_400_000_000_001,
            4_102_444_800_000_000_000,
        ] {
            let s = format_rfc3339_ns(ns);
            assert_eq!(parse_rfc3339_ns(&s), Some(ns), "{s}");
        }
        assert_eq!(format_rfc3339_ns(0), "1970-01-01T00:00:00.000000000Z");
        for ns in [0i64, 1_760_106_000_123_456_789, 4_102_444_800_000_000_001] {
            let s = format_local_rfc3339_ns(ns);
            assert_eq!(parse_rfc3339_ns(&s), Some(ns), "{s}");
            assert!(matches!(s.as_bytes()[29], b'+' | b'-'), "{s}");
        }
        assert_eq!(
            parse_rfc3339_ns("2026-10-10T16:36:53+02:00"),
            parse_rfc3339_ns("2026-10-10T14:36:53Z")
        );
        assert_eq!(
            parse_rfc3339_ns("2026-10-10T14:36:53.5Z"),
            parse_rfc3339_ns("2026-10-10T14:36:53.500000000Z")
        );
        for bad in [
            "",
            "yesterday",
            "2026-13-10T00:00:00Z",
            "2026-10-10T14:36:53",
            "2026-10-10T14:36:53.Z",
        ] {
            assert_eq!(parse_rfc3339_ns(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_times_of_the_logs_of_a_pod_are_checked_in_podman_s_words() {
        let now = 1_000_000_000_000;
        assert_eq!(parse_pod_log_time("since", None, now), Ok(None));
        assert_eq!(
            parse_pod_log_time("since", Some("10s"), now),
            Ok(Some(now - 10_000_000_000))
        );
        // (a duration of `until` is from now)
        assert_eq!(
            parse_pod_log_time("until", Some("10s"), now),
            Ok(Some(now + 10_000_000_000))
        );
        assert_eq!(
            parse_pod_log_time("since", Some("garbage"), now),
            Err("parsing --since \"garbage\": unable to interpret time value".to_string())
        );
    }

    #[test]
    fn time_specs() {
        let now = 1_000_000_000_000_000_000;
        assert_eq!(
            parse_log_time("1h30m", now, Toward::Past),
            Some(now - 5400 * 1_000_000_000)
        );
        assert_eq!(
            parse_log_time("10s", now, Toward::Past),
            Some(now - 10_000_000_000)
        );
        assert_eq!(
            parse_log_time("2d", now, Toward::Past),
            Some(now - 2 * 86400 * 1_000_000_000)
        );
        assert_eq!(
            parse_log_time("1700000000", now, Toward::Past),
            Some(1_700_000_000_000_000_000)
        );
        assert_eq!(
            parse_log_time("1700000000.5", now, Toward::Past),
            Some(1_700_000_000_500_000_000)
        );
        assert_eq!(
            parse_log_time("2026-01-01T00:00:00Z", now, Toward::Past),
            parse_rfc3339_ns("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_log_time("0.1s", now, Toward::Past),
            Some(now - 100_000_000)
        );
        assert_eq!(
            parse_log_time("-1s", now, Toward::Past),
            Some(now + 1_000_000_000)
        );
        assert_eq!(
            parse_log_time("3s", now, Toward::Future),
            Some(now + 3_000_000_000)
        );
        assert_eq!(
            parse_log_time("1700000000", now, Toward::Future),
            parse_log_time("1700000000", now, Toward::Past)
        );
        assert_eq!(
            parse_log_time("2026-10-12T00:46:56,644543720+02:00", now, Toward::Past),
            parse_rfc3339_ns("2026-10-12T00:46:56.644543720+02:00")
        );
        assert!(parse_rfc3339_ns("2026-10-12T00:46:56.644543720+02:00").is_some());
        // podman's other forms: no zone is UTC, a date alone is its midnight
        let utc = parse_rfc3339_ns("2026-11-01T10:00:00Z");
        assert_eq!(
            parse_log_time("2026-11-01T10:00:00", now, Toward::Past),
            utc
        );
        assert_eq!(
            parse_log_time("2026-11-01T10:00:00.5", now, Toward::Past),
            parse_rfc3339_ns("2026-11-01T10:00:00.5Z")
        );
        assert_eq!(
            parse_log_time("2026-11-01", now, Toward::Past),
            parse_rfc3339_ns("2026-11-01T00:00:00Z")
        );
        assert_eq!(
            parse_log_time("2026-11-01Z", now, Toward::Past),
            parse_rfc3339_ns("2026-11-01T00:00:00Z")
        );
        assert_eq!(
            parse_log_time("2026-11-01+01:00", now, Toward::Past),
            parse_rfc3339_ns("2026-11-01T00:00:00+01:00")
        );
        for bad in [
            "2026-11-01T",
            "2026-11-01X",
            "2026-13-45",
            "2026-11-01T10:00",
        ] {
            assert_eq!(parse_log_time(bad, now, Toward::Past), None, "{bad}");
        }
        for bad in [
            "",
            "h",
            "10x",
            "abc",
            "1h x",
            "99999999999999999999d",
            "-",
            "1.2.3s",
        ] {
            assert_eq!(parse_log_time(bad, now, Toward::Past), None, "{bad}");
        }
    }

    #[test]
    fn records_parse() {
        let r = parse_record(b"2026-10-10T14:36:53.000000001Z stderr P some text").unwrap();
        assert_eq!(
            (r.stream, r.partial, r.content.as_slice()),
            (Stream::Stderr, true, &b"some text"[..])
        );
        let r = parse_record(b"2026-10-10T14:36:53.000000001Z stdout F ").unwrap();
        assert!(r.content.is_empty() && !r.partial);
        assert!(parse_record(b"2026-10-10T14:36:53.000000001Z stdin F x").is_none());
        assert!(parse_record(b"garbage").is_none());
        assert!(parse_record(b"2026-10-10T14:36:53.000000001Z stdout X x").is_none());
    }

    #[test]
    fn partial_lines_and_the_final_terminator() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        w.write(Stream::Stdout, b"one\ntw").unwrap();
        w.write(Stream::Stderr, b"err\n").unwrap();
        w.write(Stream::Stdout, b"o\nthree").unwrap();
        w.finish().unwrap();
        assert_eq!(
            records(&path, &ReadOptions::default()),
            vec![
                (Stream::Stdout, false, "one".to_string()),
                (Stream::Stdout, true, "tw".to_string()),
                (Stream::Stderr, false, "err".to_string()),
                (Stream::Stdout, false, "o".to_string()),
                (Stream::Stdout, true, "three".to_string()),
                (Stream::Stdout, false, String::new()),
            ]
        );
    }

    #[test]
    fn long_lines_are_split() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        let line = vec![b'x'; MAX_RECORD * 2 + 5];
        w.write(Stream::Stdout, &line).unwrap();
        w.write(Stream::Stdout, b"\n").unwrap();
        let recs = records(&path, &ReadOptions::default());
        let sizes: Vec<_> = recs.iter().map(|r| (r.1, r.2.len())).collect();
        assert_eq!(
            sizes,
            vec![
                (true, MAX_RECORD),
                (true, MAX_RECORD),
                (true, 5),
                (false, 0)
            ]
        );
    }

    #[test]
    fn rotation_keeps_the_newest_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 200,
            max_files: 3,
            global_max: 0,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        for i in 0..30 {
            w.write(Stream::Stdout, format!("line {i:02}\n").as_bytes())
                .unwrap();
        }
        assert!(rotated_path(&path, 1).exists());
        assert!(rotated_path(&path, 2).exists());
        assert!(!rotated_path(&path, 3).exists());
        let all = records(&path, &ReadOptions::default());
        assert!(all.last().unwrap().2 == "line 29");
        // Records are in order and contiguous, the oldest ones are gone.
        let nums: Vec<u32> = all.iter().map(|r| r.2[5..].parse().unwrap()).collect();
        assert!(nums.windows(2).all(|w| w[1] == w[0] + 1));
        assert!(nums[0] > 0);
        for f in [&path, &rotated_path(&path, 1), &rotated_path(&path, 2)] {
            assert!(std::fs::metadata(f).unwrap().len() <= 200);
        }
    }

    /// A rotation that cannot take its lock does not shift the files under
    /// the readers, and loses no output: the lines go into the current
    /// file, the error is told, and the rotation is tried again once the
    /// file grew by another max-size.
    #[test]
    fn a_rotation_without_its_lock_keeps_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        // (the lock cannot be made: a directory has its name)
        let lock = dir.path().join("ctr.log.lock");
        std::fs::create_dir(&lock).unwrap();
        let limits = Limits {
            max_size: 300,
            max_files: 3,
            global_max: 0,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        // (a record of a line is 130 to 140 bytes: the third is over the
        // limit, the fourth not over the next one)
        let line = |i: usize| format!("{i:02}{}\n", "x".repeat(88));
        let mut failed = 0;
        for i in 0..4 {
            if let Err(e) = w.write(Stream::Stdout, line(i).as_bytes()) {
                assert!(e.to_string().contains("cannot rotate"), "{e}");
                failed += 1;
            }
        }
        assert_eq!(failed, 1);
        assert!(!rotated_path(&path, 1).exists());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 4, "{text}");
        // the lock can be made again: the next rotation goes
        std::fs::remove_dir(&lock).unwrap();
        for i in 4..6 {
            w.write(Stream::Stdout, line(i).as_bytes()).unwrap();
        }
        assert!(rotated_path(&path, 1).exists());
    }

    #[test]
    fn a_single_file_is_truncated_by_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let mut w = LogWriter::open(
            &path,
            Limits {
                max_size: 100,
                max_files: 1,
                global_max: 0,
                compress: false,
            },
        )
        .unwrap();
        for i in 0..20 {
            w.write(Stream::Stdout, format!("line {i:02}\n").as_bytes())
                .unwrap();
        }
        assert!(!rotated_path(&path, 1).exists());
        assert!(std::fs::metadata(&path).unwrap().len() <= 100);
    }

    #[test]
    fn the_global_limit_drops_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 100,
            max_files: 10,
            global_max: 300,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        for i in 0..100 {
            w.write(Stream::Stdout, format!("line {i:03}\n").as_bytes())
                .unwrap();
        }
        let mut total = std::fs::metadata(&path).unwrap().len();
        for n in 1..10 {
            total += std::fs::metadata(rotated_path(&path, n))
                .map(|m| m.len())
                .unwrap_or(0);
        }
        assert!(total <= 300, "{total}");
        assert!(rotated_path(&path, 1).exists());
    }

    #[test]
    fn tail_counts_lines_not_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 150,
            max_files: 5,
            global_max: 0,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        for i in 0..10 {
            w.write(Stream::Stdout, format!("l{i}\n").as_bytes())
                .unwrap();
        }
        w.write(Stream::Stdout, b"par").unwrap();
        w.write(Stream::Stdout, b"tial\n").unwrap();
        let opts = ReadOptions {
            tail: Some(3),
            ..Default::default()
        };
        let got: Vec<String> = records(&path, &opts).into_iter().map(|r| r.2).collect();
        assert_eq!(got, vec!["l8", "l9", "par", "tial"]);
        let opts = ReadOptions {
            tail: Some(0),
            ..Default::default()
        };
        assert!(records(&path, &opts).is_empty());
        let opts = ReadOptions {
            tail: Some(1000),
            ..Default::default()
        };
        assert!(records(&path, &opts).len() >= 12);
    }

    #[test]
    fn since_and_until_select_by_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        std::fs::write(
            &path,
            "2026-01-01T00:00:01.000000000Z stdout F a\n\
             2026-01-01T00:00:02.000000000Z stdout F b\n\
             2026-01-01T00:00:03.000000000Z stdout F c\n",
        )
        .unwrap();
        let opts = ReadOptions {
            since_ns: parse_rfc3339_ns("2026-01-01T00:00:02Z"),
            until_ns: parse_rfc3339_ns("2026-01-01T00:00:02Z"),
            ..Default::default()
        };
        let got: Vec<String> = records(&path, &opts).into_iter().map(|r| r.2).collect();
        assert_eq!(got, vec!["b"]);
    }

    #[test]
    fn garbage_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        std::fs::write(
            &path,
            "not a record\n2026-01-01T00:00:01.000000000Z stdout F a\n",
        )
        .unwrap();
        assert_eq!(records(&path, &ReadOptions::default()).len(), 1);
        let opts = ReadOptions {
            tail: Some(5),
            ..Default::default()
        };
        assert_eq!(records(&path, &opts).len(), 1);
    }

    #[test]
    fn reopen_after_an_external_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        w.write(Stream::Stdout, b"before\n").unwrap();
        std::fs::rename(&path, dir.path().join("ctr.log.old")).unwrap();
        w.write(Stream::Stdout, b"lost-to-the-old-file\n").unwrap();
        w.reopen().unwrap();
        w.write(Stream::Stdout, b"after\n").unwrap();
        let got: Vec<String> = records(&path, &ReadOptions::default())
            .into_iter()
            .map(|r| r.2)
            .collect();
        assert_eq!(got, vec!["after"]);
    }

    #[test]
    fn printer_and_assembler() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        w.write(Stream::Stdout, b"a").unwrap();
        w.write(Stream::Stdout, b"b\nc\n").unwrap();
        w.write(Stream::Stderr, b"e\n").unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut asm = LineAssembler::default();
        let mut lines = Vec::new();
        {
            let mut p = Printer::new(false, &mut out, &mut err);
            read_logs(&path, &ReadOptions::default(), None, &mut |r| {
                if let Some((_, s, c)) = asm.push(r) {
                    lines.push((s, c));
                }
                p.print(r)
            })
            .unwrap();
        }
        assert_eq!(out, b"ab\nc\n");
        assert_eq!(err, b"e\n");
        assert_eq!(
            lines,
            vec![
                (Stream::Stdout, b"ab".to_vec()),
                (Stream::Stdout, b"c".to_vec()),
                (Stream::Stderr, b"e".to_vec())
            ]
        );
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut p = Printer::new(true, &mut out, &mut err);
        read_logs(&path, &ReadOptions::default(), None, &mut |r| p.print(r)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text
            .lines()
            .all(|l| l.len() > 35 && matches!(l.as_bytes()[29], b'+' | b'-')));
    }

    #[test]
    fn follow_sees_new_records_across_a_rotation_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 120,
            max_files: 4,
            global_max: 0,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        w.write(Stream::Stdout, b"first\n").unwrap();
        let (stop_r, stop_w) = rustix::pipe::pipe().unwrap();
        let reader_path = path.clone();
        let (seen_tx, seen) = std::sync::mpsc::channel::<String>();
        let (up_tx, up) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let mut got = Vec::new();
            read_logs_with(
                &reader_path,
                &ReadOptions {
                    follow: true,
                    ..Default::default()
                },
                Some(&stop_r),
                &mut |r| {
                    let text = String::from_utf8_lossy(&r.content).into_owned();
                    got.push(text.clone());
                    let _ = seen_tx.send(text);
                    Ok(())
                },
                &mut || {
                    let _ = up_tx.send(());
                },
            )
            .unwrap();
            got
        });
        // A record is written when the follower has read the one before:
        // a follower that falls behind by more than the files that are
        // kept loses records, which is not what is tested.
        let limit = std::time::Duration::from_secs(30);
        up.recv_timeout(limit).unwrap();
        assert_eq!(seen.recv_timeout(limit).unwrap(), "first");
        for i in 0..12 {
            let line = format!("n{i:02}");
            w.write(Stream::Stdout, format!("{line}\n").as_bytes())
                .unwrap();
            assert_eq!(seen.recv_timeout(limit).unwrap(), line);
        }
        rustix::io::write(&stop_w, b"x").unwrap();
        let got = handle.join().unwrap();
        assert_eq!(got.first().map(String::as_str), Some("first"));
        let expect: Vec<String> = std::iter::once("first".to_string())
            .chain((0..12).map(|i| format!("n{i:02}")))
            .collect();
        assert_eq!(got, expect);
    }

    #[test]
    fn a_follower_held_back_across_several_rotations_loses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 120,
            max_files: 10,
            global_max: 0,
            compress: false,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        w.write(Stream::Stdout, b"first\n").unwrap();
        let (stop_r, stop_w) = rustix::pipe::pipe().unwrap();
        let reader_path = path.clone();
        let (seen_tx, seen) = std::sync::mpsc::channel::<String>();
        let (gate_tx, gate) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let mut got = Vec::new();
            read_logs(
                &reader_path,
                &ReadOptions {
                    follow: true,
                    ..Default::default()
                },
                Some(&stop_r),
                &mut |r| {
                    let text = String::from_utf8_lossy(&r.content).into_owned();
                    if got.is_empty() {
                        // (held back until the writer is done)
                        gate.recv().unwrap();
                    }
                    got.push(text.clone());
                    let _ = seen_tx.send(text);
                    Ok(())
                },
            )
            .unwrap();
            got
        });
        for i in 0..12 {
            w.write(Stream::Stdout, format!("n{i:02}\n").as_bytes())
                .unwrap();
        }
        gate_tx.send(()).unwrap();
        let limit = std::time::Duration::from_secs(30);
        let mut last = String::new();
        while last != "n11" {
            last = seen.recv_timeout(limit).unwrap();
        }
        rustix::io::write(&stop_w, b"x").unwrap();
        let expect: Vec<String> = std::iter::once("first".to_string())
            .chain((0..12).map(|i| format!("n{i:02}")))
            .collect();
        assert_eq!(handle.join().unwrap(), expect);
    }

    fn pumped(f: &mut Follower) -> Vec<String> {
        let mut got = Vec::new();
        f.pump(&mut |l| {
            got.push(parse_record(l).map(|r| String::from_utf8_lossy(&r.content).into_owned()));
            Ok(())
        })
        .unwrap();
        got.into_iter().flatten().collect()
    }

    /// A log truncated in place (by something that copies it and empties
    /// it) is read from its start again.
    #[test]
    fn a_follower_reads_a_log_truncated_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let mut w = LogWriter::open(&path, Limits::default()).unwrap();
        w.write(Stream::Stdout, b"one\ntwo\n").unwrap();
        let mut f = Follower::open(&path, None).unwrap();
        f.snapshot().unwrap();
        assert!(pumped(&mut f).is_empty());
        w.write(Stream::Stdout, b"three\n").unwrap();
        assert_eq!(pumped(&mut f), ["three"]);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(0)
            .unwrap();
        // (the writer appends: its offset is the end of the file)
        let mut again = LogWriter::open(&path, Limits::default()).unwrap();
        again.write(Stream::Stdout, b"four\n").unwrap();
        again.write(Stream::Stdout, b"five\n").unwrap();
        assert_eq!(pumped(&mut f), ["four", "five"]);
        assert!(pumped(&mut f).is_empty());
    }

    /// Many followers, one inotify instance; each is woken by its own log.
    #[test]
    fn followers_share_one_inotify_instance() {
        let instances = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
                .filter(|l| l.to_string_lossy().contains("inotify"))
                .count()
        };
        let dirs: Vec<_> = (0..100).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut writers = Vec::new();
        let mut followers = Vec::new();
        let first = {
            let path = dirs[0].path().join("ctr.log");
            writers.push(LogWriter::open(&path, Limits::default()).unwrap());
            Follower::open(&path, None).unwrap()
        };
        let before = instances();
        followers.push(first);
        for d in &dirs[1..] {
            let path = d.path().join("ctr.log");
            writers.push(LogWriter::open(&path, Limits::default()).unwrap());
            followers.push(Follower::open(&path, None).unwrap());
        }
        assert_eq!(instances(), before);
        writers[42].write(Stream::Stdout, b"hello\n").unwrap();
        for (i, f) in followers.iter_mut().enumerate() {
            f.wait(&[], if i == 42 { 10_000 } else { 0 }).unwrap();
            if i == 42 {
                assert_eq!(pumped(f), ["hello"]);
            } else {
                assert!(pumped(f).is_empty());
            }
        }
    }

    #[test]
    fn rotated_files_are_compressed_but_the_newest_and_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 200,
            max_files: 5,
            global_max: 0,
            compress: true,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        for i in 0..60 {
            w.write(Stream::Stdout, format!("line {i:02}\n").as_bytes())
                .unwrap();
        }
        let gz = |n: u32| PathBuf::from(format!("{}.{n}.gz", path.display()));
        assert!(rotated_path(&path, 1).exists());
        for n in 2..5 {
            assert!(gz(n).exists(), "{n}");
            assert!(!rotated_path(&path, n).exists(), "{n}");
        }
        assert!(!gz(5).exists());
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
        let all = records(&path, &ReadOptions::default());
        assert_eq!(all.last().unwrap().2, "line 59");
        let nums: Vec<u32> = all.iter().map(|r| r.2[5..].parse().unwrap()).collect();
        assert!(nums.windows(2).all(|w| w[1] == w[0] + 1), "{nums:?}");
        assert!(nums[0] > 0 && nums.len() >= 15, "{nums:?}");
        let tail = records(
            &path,
            &ReadOptions {
                tail: Some(all.len() - 1),
                ..Default::default()
            },
        );
        assert_eq!(tail[..], all[1..]);
    }

    #[test]
    fn the_global_limit_counts_the_compressed_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 300,
            max_files: 50,
            global_max: 1200,
            compress: true,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        for i in 0..400 {
            w.write(Stream::Stdout, format!("line {i:03}\n").as_bytes())
                .unwrap();
        }
        let total: u64 = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert!(total <= 1200, "{total}");
        let all = records(&path, &ReadOptions::default());
        assert_eq!(all.last().unwrap().2, "line 399");
    }

    #[test]
    fn follow_goes_across_rotations_that_compress_the_file_it_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ctr.log");
        let limits = Limits {
            max_size: 100,
            max_files: 40,
            global_max: 0,
            compress: true,
        };
        let mut w = LogWriter::open(&path, limits).unwrap();
        w.write(Stream::Stdout, b"first\n").unwrap();
        let (stop_r, stop_w) = rustix::pipe::pipe().unwrap();
        let reader_path = path.clone();
        // (each record the reader got, as it gets it)
        let (seen, seen_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let mut got = Vec::new();
            read_logs(
                &reader_path,
                &ReadOptions {
                    follow: true,
                    ..Default::default()
                },
                Some(&stop_r),
                &mut |r| {
                    got.push(String::from_utf8_lossy(&r.content).into_owned());
                    let _ = seen.send(());
                    // a slow reader: rotations pile up meanwhile
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    Ok(())
                },
            )
            .unwrap();
            got
        });
        // the reader follows once it got the first line
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let left = || limit.saturating_duration_since(std::time::Instant::now());
        assert!(seen_rx.recv_timeout(left()).is_ok(), "the first line");
        for i in 0..60 {
            w.write(Stream::Stdout, format!("n{i:02}\n").as_bytes())
                .unwrap();
        }
        // and a last line: what the reader gets before it is all that it
        // gets of the others (a line twice comes before it, the reader goes
        // in order)
        w.write(Stream::Stdout, b"last\n").unwrap();
        // until it got them all (or the time is up: the comparison says what is missing)
        for _ in 0..61 {
            if seen_rx.recv_timeout(left()).is_err() {
                break;
            }
        }
        rustix::io::write(&stop_w, b"x").unwrap();
        let got = handle.join().unwrap();
        let expect: Vec<String> = std::iter::once("first".to_string())
            .chain((0..60).map(|i| format!("n{i:02}")))
            .chain(std::iter::once("last".to_string()))
            .collect();
        assert_eq!(got, expect);
    }

    #[test]
    fn a_log_below_an_allowlisted_directory_cannot_go_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("allow");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(allow.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, allow.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("f.log"), allow.join("sub/l.log")).unwrap();
        let limits = Limits::default();
        // below it: fine
        let mut w = LogWriter::open_in(&allow.join("sub/ok.log"), Some(&allow), limits).unwrap();
        w.write(Stream::Stdout, b"in\n").unwrap();
        assert!(allow.join("sub/ok.log").exists());
        let opts = ReadOptions {
            allow_dir: Some(allow.clone()),
            ..Default::default()
        };
        assert_eq!(records(&allow.join("sub/ok.log"), &opts).len(), 1);
        // a directory that is a link, a file that is a link, a path elsewhere
        assert!(LogWriter::open_in(&allow.join("link/x.log"), Some(&allow), limits).is_err());
        assert!(LogWriter::open_in(&allow.join("sub/l.log"), Some(&allow), limits).is_err());
        assert!(LogWriter::open_in(&outside.join("x.log"), Some(&allow), limits).is_err());
        assert!(!outside.join("x.log").exists() && !outside.join("f.log").exists());
        let mut sink = |_: &Record| Ok(());
        assert!(read_logs(&allow.join("link/x.log"), &opts, None, &mut sink).is_err());
        // without the allowlist the link is followed
        assert!(LogWriter::open(&allow.join("link/x.log"), limits).is_ok());
    }

    #[test]
    fn tail_reads_back_through_compressed_files_and_long_lines() {
        use flate2::{write::GzEncoder, Compression};
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let path = dir.path().join("c.log");
        let rec = |s: u32, flag: char, d: &str| {
            format!(
                "{} stdout {flag} {d}\n",
                format_rfc3339_ns(s as i64 * 1_000_000_000)
            )
        };
        let gz = |s: &str| {
            let mut e = GzEncoder::new(Vec::new(), Compression::fast());
            e.write_all(s.as_bytes()).unwrap();
            e.finish().unwrap()
        };
        let mut old = String::new();
        for i in 1..=5 {
            old += &rec(i, 'F', &format!("o{i}"));
        }
        std::fs::write(format!("{}.2.gz", path.display()), gz(&old)).unwrap();
        let mut mid = rec(6, 'P', "a");
        mid += &rec(6, 'P', "b\r");
        mid += &rec(7, 'F', "c");
        std::fs::write(format!("{}.1", path.display()), mid).unwrap();
        // 10 MiB in records of 16 KiB, no trailing newline in the last line
        let mut cur = String::new();
        let chunk = "z".repeat(MAX_RECORD);
        for _ in 0..640 {
            cur += &rec(8, 'P', &chunk);
        }
        cur += &rec(8, 'F', "end");
        cur += &rec(9, 'F', "last");
        std::fs::write(&path, cur.trim_end_matches('\n')).unwrap();
        let text = |opts: &ReadOptions| -> Vec<String> {
            records(&path, opts)
                .into_iter()
                .map(|(_, _, c)| {
                    if c.len() > 20 {
                        format!("<{}>", c.len())
                    } else {
                        c
                    }
                })
                .collect()
        };
        let tail = |n| ReadOptions {
            tail: Some(n),
            ..Default::default()
        };
        assert_eq!(text(&tail(1)), ["last"]);
        assert_eq!(text(&tail(2)).len(), 641 + 1);
        assert_eq!(text(&tail(3)).len(), 3 + 641 + 1);
        assert_eq!(text(&tail(4))[0], "o5");
        assert_eq!(text(&tail(7))[0], "o2");
        assert_eq!(text(&tail(8))[0], "o1");
        assert_eq!(text(&tail(100))[0], "o1");
        assert_eq!(text(&ReadOptions::default())[0], "o1");
    }
}
