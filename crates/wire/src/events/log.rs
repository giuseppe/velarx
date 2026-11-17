// SPDX-License-Identifier: Apache-2.0
//! Where events are kept (`[server] events_logger` of the configuration):
//! the systemd journal, a file, or nowhere but in memory.  What is kept
//! outlives the server: `events --since` lists the events of the processes
//! before it and of the engine run by units.
//!
//! - journald: one entry per event through the native protocol, with
//!   `SYSLOG_IDENTIFIER=velarx` and podman's `PODMAN_*` fields, read back
//!   with `journalctl -o json` (the entries of this user only).
//! - file: JSON lines in `events.log` (the root directory), with one
//!   rotated file `events.log.1` when it grows past its size.
//!
//! A reader that follows them (`events --stream` of a command) keeps a
//! [`Position`]: the journal's cursor or the offset in the file, so each
//! read returns what was kept after the last one, in the order it was kept.

use super::Event;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";
pub const IDENTIFIER: &str = "velarx";
/// podman's default `events_logfile_max_size`.
pub const DEFAULT_MAX_SIZE: u64 = 1024 * 1024;

/// The backend of the events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventLog {
    /// The journal; `root` is the root directory of the store, a field of
    /// its entries: the events of the other stores of the user (another
    /// daemon with a configuration of its own) are not this one's.
    Journald {
        root: String,
    },
    File {
        path: PathBuf,
        max_size: u64,
    },
    None,
}

/// An event as it is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    #[serde(rename = "Type")]
    pub kind: String,
    #[serde(rename = "Status")]
    pub action: String,
    #[serde(rename = "ID", default)]
    pub id: String,
    #[serde(rename = "Name", default)]
    pub name: String,
    #[serde(rename = "Image", default)]
    pub image: String,
    #[serde(rename = "Attributes", default)]
    pub attributes: BTreeMap<String, String>,
    #[serde(rename = "TimeNano")]
    pub time_nano: i64,
}

impl Stored {
    pub fn of(ev: &Event) -> Self {
        Self {
            kind: ev.kind.word().to_string(),
            action: ev.action.clone(),
            id: ev.id.clone(),
            name: ev.name.clone(),
            image: ev.image.clone(),
            attributes: ev.attributes.clone(),
            time_nano: ev.time_nano,
        }
    }
}

impl EventLog {
    /// The backend that the configuration names (`events_logger`): by default
    /// the journal when it is there, else the file.
    pub fn from_config(logger: &str, path: &str, max_size: u64, root_dir: &Path) -> Self {
        let file = || EventLog::File {
            path: if path.is_empty() {
                root_dir.join("events").join("events.log")
            } else {
                PathBuf::from(path)
            },
            max_size: if max_size == 0 {
                DEFAULT_MAX_SIZE
            } else {
                max_size
            },
        };
        let journald = || EventLog::Journald {
            root: root_dir.to_string_lossy().into_owned(),
        };
        match logger {
            "journald" => journald(),
            "file" => file(),
            "none" => EventLog::None,
            _ if Path::new(JOURNAL_SOCKET).exists() => journald(),
            _ => file(),
        }
    }

    /// podman's name of the backend (`info`'s eventLogger).
    pub fn name(&self) -> &'static str {
        match self {
            EventLog::Journald { .. } => "journald",
            EventLog::File { .. } => "file",
            EventLog::None => "none",
        }
    }

    /// The directories whose files change when an event is kept: the one of
    /// the file, the journal's (its roots and the directory of each machine
    /// in them).  A directory that is not there yet (no event was kept
    /// there) is waited for in the nearest one above it that is: its
    /// creation wakes the watch, and the next watch is made deeper.
    pub fn watch_dirs(&self) -> Vec<PathBuf> {
        fn add(dirs: &mut Vec<PathBuf>, dir: &Path) {
            let found = dir.ancestors().find(|d| d.is_dir()).map(Path::to_path_buf);
            if let Some(d) = found.filter(|d| !dirs.contains(d)) {
                dirs.push(d);
            }
        }
        let mut dirs: Vec<PathBuf> = Vec::new();
        match self {
            EventLog::File { path, .. } => {
                if let Some(dir) = path.parent() {
                    add(&mut dirs, dir);
                }
            }
            EventLog::Journald { .. } => {
                const ROOTS: [&str; 2] = ["/run/log/journal", "/var/log/journal"];
                let roots = ROOTS.iter().map(Path::new).filter(|r| r.is_dir());
                for root in roots {
                    add(&mut dirs, root);
                    // (the journal of each machine: where its files are)
                    for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
                        if e.file_type().is_ok_and(|t| t.is_dir()) {
                            add(&mut dirs, &e.path());
                        }
                    }
                }
                // (no journal yet: where it will be made; a root made later
                // is used by journald only from its next start or flush)
                if dirs.is_empty() {
                    ROOTS.iter().for_each(|r| add(&mut dirs, Path::new(r)));
                }
            }
            EventLog::None => {}
        }
        dirs
    }

    /// Keep an event.  The one writer: the engine's hub and the monitors
    /// of the containers call it.
    pub fn write(&self, ev: &Event) -> io::Result<()> {
        match self {
            EventLog::Journald { root } => {
                write_journal(Path::new(JOURNAL_SOCKET), root, &Stored::of(ev))
            }
            EventLog::File { path, max_size } => write_file(path, *max_size, &Stored::of(ev)),
            EventLog::None => Ok(()),
        }
    }
}

/// Where a reader of the events kept is (see [`EventLog::read_after`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Position {
    /// Nothing read yet: the events from a time on.
    #[default]
    Start,
    /// After the journal entry of this cursor.
    Journal(String),
    /// At `offset` (after its last whole line) in the file `(dev, ino)`.
    File { dev: u64, ino: u64, offset: u64 },
}

/// Add `name=value` to a journal entry (the length prefixed form for a
/// value with a newline).
fn field(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    if value.contains('\n') {
        out.push(b'\n');
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    } else {
        out.push(b'=');
    }
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
}

/// The entry of an event: podman's fields.
fn journal_entry(root: &str, ev: &Stored) -> Vec<u8> {
    let mut out = Vec::new();
    let what = if ev.name.is_empty() {
        ev.id.as_str()
    } else {
        ev.name.as_str()
    };
    field(
        &mut out,
        "MESSAGE",
        &format!("{} {} {} ({})", ev.kind, ev.action, ev.id, what),
    );
    field(&mut out, "SYSLOG_IDENTIFIER", IDENTIFIER);
    field(&mut out, "VELARX_ROOT", root);
    field(&mut out, "PODMAN_EVENT", &ev.action);
    field(&mut out, "PODMAN_TYPE", &ev.kind);
    field(
        &mut out,
        "PODMAN_TIME",
        &crate::monitor::logfmt::format_rfc3339_ns(ev.time_nano),
    );
    field(&mut out, "VELARX_TIME_NANO", &ev.time_nano.to_string());
    if !ev.id.is_empty() {
        field(&mut out, "PODMAN_ID", &ev.id);
    }
    if !ev.name.is_empty() {
        field(&mut out, "PODMAN_NAME", &ev.name);
    }
    if !ev.image.is_empty() {
        field(&mut out, "PODMAN_IMAGE", &ev.image);
    }
    if let Some(code) = ev.attributes.get("containerExitCode") {
        field(&mut out, "PODMAN_EXIT_CODE", code);
    }
    if let Some(status) = ev.attributes.get("health_status") {
        field(&mut out, "PODMAN_HEALTH_STATUS", status);
    }
    if !ev.attributes.is_empty() {
        if let Ok(labels) = serde_json::to_string(&ev.attributes) {
            field(&mut out, "PODMAN_LABELS", &labels);
        }
    }
    out
}

fn write_journal(socket: &Path, root: &str, ev: &Stored) -> io::Result<()> {
    let sock = std::os::unix::net::UnixDatagram::unbound()?;
    sock.send_to(&journal_entry(root, ev), socket)?;
    Ok(())
}

/// The cursor of the last entry of `journalctl -o json` output.
pub fn last_cursor(data: &[u8]) -> Option<String> {
    data.split(|b| *b == b'\n')
        .rev()
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .find_map(|e| e.get("__CURSOR")?.as_str().map(str::to_string))
}

/// The events of `journalctl -o json` output.
pub fn parse_journal(data: &[u8]) -> Vec<Stored> {
    let text = |v: &serde_json::Value| v.as_str().map(str::to_string);
    data.split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .filter_map(|e| {
            let get = |k: &str| e.get(k).and_then(text);
            let time_nano = get("VELARX_TIME_NANO")
                .and_then(|t| t.parse().ok())
                .or_else(|| {
                    get("PODMAN_TIME")
                        .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
                        .and_then(|t| t.timestamp_nanos_opt())
                })?;
            Some(Stored {
                kind: get("PODMAN_TYPE")?,
                action: get("PODMAN_EVENT")?,
                id: get("PODMAN_ID").unwrap_or_default(),
                name: get("PODMAN_NAME").unwrap_or_default(),
                image: get("PODMAN_IMAGE").unwrap_or_default(),
                attributes: get("PODMAN_LABELS")
                    .and_then(|l| serde_json::from_str(&l).ok())
                    .unwrap_or_default(),
                time_nano,
            })
        })
        .collect()
}

fn write_file(path: &Path, max_size: u64, ev: &Stored) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut line = serde_json::to_vec(ev).map_err(io::Error::other)?;
    line.push(b'\n');
    // Writers of other processes (a server, the engine of units) append to
    // the same file; one rotates it at a time.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path.with_extension("lock"))?;
    velarx_sys::flock::flock_retrying(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    if std::fs::metadata(path).is_ok_and(|m| m.len() + line.len() as u64 > max_size) {
        std::fs::rename(path, rotated(path))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(&line)
}

pub fn rotated(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".1");
    PathBuf::from(p)
}

/// The events of the file `path` (and of its rotated file) after `from`,
/// and where they end.  The file read last, rotated meanwhile, is read to
/// its end before the new one; a file rotated twice between two reads is
/// lost but for its rotated part, as for any reader.
pub fn read_file_after(path: &Path, from: &Position) -> io::Result<(Vec<Stored>, Position)> {
    let open = |p: &Path| -> io::Result<Option<(std::fs::File, (u64, u64))>> {
        match std::fs::File::open(p) {
            Ok(f) => {
                let m = f.metadata()?;
                Ok(Some((f, (m.dev(), m.ino()))))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    };
    // (the rotated file first: it has the older events)
    let (old, current) = (open(&rotated(path))?, open(path)?);
    let read = |file: &(std::fs::File, (u64, u64)), at: &Position, out: &mut Vec<Stored>| {
        let (f, (dev, ino)) = file;
        let start = match at {
            Position::File {
                dev: d,
                ino: i,
                offset,
            } if (*d, *i) == (*dev, *ino) => *offset,
            _ => 0,
        };
        let offset = read_lines_from(f, start, out)?;
        io::Result::Ok(Position::File {
            dev: *dev,
            ino: *ino,
            offset,
        })
    };
    let mut out = Vec::new();
    // (after the first read the reader is never at the start again: a file
    // made later is read whole, whatever the times of its events)
    let mut at = match from {
        Position::Start => Position::File {
            dev: 0,
            ino: 0,
            offset: 0,
        },
        _ => from.clone(),
    };
    // (the rotated file was read already when the reader is in the current)
    let in_current = matches!(from, Position::File { dev, ino, .. }
        if current.as_ref().is_some_and(|c| c.1 == (*dev, *ino)));
    if let Some(old) = old.as_ref().filter(|_| !in_current) {
        at = read(old, &at, &mut out)?;
    }
    if let Some(current) = &current {
        at = read(current, &at, &mut out)?;
    }
    Ok((out, at))
}

/// Add the events of the whole lines of `f` from `start` on (from its
/// beginning when it is shorter: a new file that took the number of an old
/// one) to `out`: where the last whole line ends.
fn read_lines_from(mut f: &std::fs::File, start: u64, out: &mut Vec<Stored>) -> io::Result<u64> {
    let start = if f.metadata()?.len() < start {
        0
    } else {
        start
    };
    f.seek(io::SeekFrom::Start(start))?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    // (a line being written is read with the next one)
    let whole = data.iter().rposition(|b| *b == b'\n').map_or(0, |n| n + 1);
    out.extend(
        data[..whole]
            .split(|b| *b == b'\n')
            .filter_map(|l| serde_json::from_slice::<Stored>(l).ok()),
    );
    Ok(start + whole as u64)
}

pub fn read_file(path: &Path) -> io::Result<Vec<Stored>> {
    let mut out = Vec::new();
    for p in [rotated(path), path.to_path_buf()] {
        let data = match std::fs::read(&p) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        out.extend(
            data.split(|b| *b == b'\n')
                .filter_map(|l| serde_json::from_slice::<Stored>(l).ok()),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use velarx_proto::workload::EventKind;

    fn ev(action: &str, t: i64) -> Event {
        let mut e = Event::new(EventKind::Container, action, "abc123", "web")
            .image("img")
            .attr("containerExitCode", "3");
        e.time_nano = t;
        e
    }

    #[test]
    fn the_cursor_of_the_last_journal_entry() {
        let out = b"{\"MESSAGE\":\"a\",\"__CURSOR\":\"s=1;i=1\"}\n{\"MESSAGE\":\"b\",\"__CURSOR\":\"s=1;i=2\"}\n";
        assert_eq!(last_cursor(out).as_deref(), Some("s=1;i=2"));
        assert_eq!(last_cursor(b""), None);
    }

    #[test]
    fn a_journal_entry_has_podman_fields_and_reads_back() {
        let s = Stored::of(&ev("died", 1_700_000_000_123_456_789));
        let entry = String::from_utf8(journal_entry("/r", &s)).unwrap();
        for f in [
            "SYSLOG_IDENTIFIER=velarx",
            "VELARX_ROOT=/r",
            "PODMAN_EVENT=died",
            "PODMAN_TYPE=container",
            "PODMAN_ID=abc123",
            "PODMAN_NAME=web",
            "PODMAN_EXIT_CODE=3",
            "PODMAN_TIME=2023-11-14T22:13:20.123456789Z",
        ] {
            assert!(entry.lines().any(|l| l == f), "{f} in {entry}");
        }
        // what journalctl -o json gives back
        let json = serde_json::json!({
            "PODMAN_EVENT": "died", "PODMAN_TYPE": "container", "PODMAN_ID": "abc123",
            "PODMAN_NAME": "web", "PODMAN_IMAGE": "img",
            "PODMAN_TIME": "2023-11-14T22:13:20.123456789Z",
            "PODMAN_LABELS": "{\"containerExitCode\":\"3\"}",
            "MESSAGE": "x"
        });
        let back = parse_journal(format!("{json}\n{{\"MESSAGE\":\"other\"}}\n").as_bytes());
        assert_eq!(back, vec![s]);
    }

    #[test]
    fn the_backend_of_the_configuration() {
        let root = Path::new("/r");
        assert_eq!(EventLog::from_config("none", "", 0, root), EventLog::None);
        assert_eq!(
            EventLog::from_config("journald", "", 0, root),
            EventLog::Journald { root: "/r".into() }
        );
        assert_eq!(
            EventLog::from_config("file", "", 0, root),
            EventLog::File {
                path: PathBuf::from("/r/events/events.log"),
                max_size: DEFAULT_MAX_SIZE
            }
        );
        assert_eq!(
            EventLog::from_config("file", "/x/e.log", 10, root),
            EventLog::File {
                path: PathBuf::from("/x/e.log"),
                max_size: 10
            }
        );
    }
}
