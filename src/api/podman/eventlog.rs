// SPDX-License-Identifier: Apache-2.0
//! The readers of the events kept (see `velarx_wire::events::log` for what
//! keeps them): the engine reads the journal with `journalctl` and the file
//! off the async threads, and waits for a change of either.

use std::io;
use std::path::PathBuf;
use velarx_wire::events::log::{
    last_cursor, parse_journal, read_file, read_file_after, EventLog, Position, Stored, IDENTIFIER,
};

/// The events kept between `since` and `until` (nanoseconds since the
/// epoch), oldest first; `None` when this backend keeps none.
pub async fn read(
    log: &EventLog,
    since: Option<i64>,
    until: Option<i64>,
) -> io::Result<Option<Vec<Stored>>> {
    let mut events = match log {
        EventLog::Journald { root } => read_journal(root, since, until, None).await?.0,
        EventLog::File { path, .. } => {
            let path = path.clone();
            tokio::task::spawn_blocking(move || read_file(&path))
                .await
                .map_err(io::Error::other)??
        }
        EventLog::None => return Ok(None),
    };
    events.retain(|e| {
        since.is_none_or(|s| e.time_nano >= s) && until.is_none_or(|u| e.time_nano <= u)
    });
    events.sort_by_key(|e| e.time_nano);
    Ok(Some(events))
}

/// The events kept after `pos`, in the order they were kept (at the
/// first read, with `pos` at [`Position::Start`], those of `since` on);
/// `pos` moves past them.  An event of another process kept after a
/// later one is returned by the read that follows its write, whatever
/// its time.  `None` when this backend keeps none.
pub async fn read_after(
    log: &EventLog,
    since: Option<i64>,
    pos: &mut Position,
) -> io::Result<Option<Vec<Stored>>> {
    let (mut events, next) = match log {
        EventLog::Journald { root } => {
            let cursor = match &*pos {
                Position::Journal(c) => Some(c.clone()),
                _ => None,
            };
            // (the end of the journal before the first read: what is
            // kept after it is new, whatever its time, also when the
            // first read finds nothing to take a cursor from)
            let tail = match cursor {
                None => journal_tail().await?,
                Some(_) => None,
            };
            // (with a cursor, what comes after it, whatever its time)
            let since = since.filter(|_| cursor.is_none());
            let (events, last) = read_journal(root, since, None, cursor.as_deref()).await?;
            let next = last.or(tail).map_or_else(|| pos.clone(), Position::Journal);
            (events, next)
        }
        EventLog::File { path, .. } => {
            let (path, from) = (path.clone(), pos.clone());
            tokio::task::spawn_blocking(move || read_file_after(&path, &from))
                .await
                .map_err(io::Error::other)??
        }
        EventLog::None => return Ok(None),
    };
    if *pos == Position::Start {
        events.retain(|e| since.is_none_or(|s| e.time_nano >= s));
    }
    *pos = next;
    Ok(Some(events))
}

/// A watch of the places where events are kept: [`ChangeWatch::wait`]
/// returns when something was written there (or the time is up), with no
/// timer in between.  Made before the events are read, so that none that
/// is kept after the read is missed.
pub struct ChangeWatch(velarx_sys::watch::Watch);

impl ChangeWatch {
    /// Watch `dirs`; the error of the last that cannot be watched when none
    /// can.
    pub fn new(dirs: &[PathBuf]) -> io::Result<Self> {
        use rustix::fs::inotify::WatchFlags;
        // (a watch of the instance of the process: a stream holds none of
        // its own)
        let watch = velarx_sys::watch::Watch::new()?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no place keeps the events");
        let mut watching = 0;
        for dir in dirs {
            let flags = WatchFlags::MODIFY
                | WatchFlags::CREATE
                | WatchFlags::MOVED_TO
                | WatchFlags::MOVED_FROM
                | WatchFlags::CLOSE_WRITE;
            match watch.add(dir, flags) {
                Ok(()) => watching += 1,
                Err(e) => last = e,
            }
        }
        if watching == 0 {
            return Err(last);
        }
        Ok(Self(watch))
    }

    /// Wait for a change, at most `limit` (none: for ever): the runtime
    /// waits, no thread blocks.
    pub async fn changed(&self, limit: Option<std::time::Duration>) -> io::Result<()> {
        let fd = velarx_sys::fd::register(self.0.owned_fd()?, tokio::io::Interest::READABLE)?;
        let came = async {
            if let Ok(mut ready) = fd.readable().await {
                ready.clear_ready();
            }
        };
        match limit {
            Some(limit) => {
                let _ = tokio::time::timeout(limit, came).await;
            }
            None => came.await,
        }
        self.0.clear();
        Ok(())
    }
}

/// The events of this user in the journal (with `after`, those kept after
/// the entry of that cursor), and the cursor of the last entry read.
async fn read_journal(
    root: &str,
    since: Option<i64>,
    until: Option<i64>,
    after: Option<&str>,
) -> io::Result<(Vec<Stored>, Option<String>)> {
    let uid = velarx_runtime::userns::rootless::host_uid().map_err(io::Error::other)?;
    let matches = [
        format!("SYSLOG_IDENTIFIER={IDENTIFIER}"),
        format!("VELARX_ROOT={root}"),
        format!("_UID={uid}"),
    ];
    let output = velarx_core::services::journalctl(&matches, since, until, after).await?;
    // No entry at all is an exit status of 1 for some versions.
    if !output.status.success() && !output.stdout.is_empty() {
        return Err(io::Error::other(format!(
            "journalctl: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok((parse_journal(&output.stdout), last_cursor(&output.stdout)))
}

/// The cursor of the end of the journal (of all the entries this user sees).
async fn journal_tail() -> io::Result<Option<String>> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new("journalctl")
            .args(["--no-pager", "--quiet", "-n", "0", "--show-cursor"])
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "journalctl took too long"))??;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("-- cursor: "))
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use velarx_proto::workload::EventKind;
    use velarx_wire::events::Event;

    fn ev(action: &str, t: i64) -> Event {
        let mut e = Event::new(EventKind::Container, action, "abc123", "web")
            .image("img")
            .attr("containerExitCode", "3");
        e.time_nano = t;
        e
    }

    #[test]
    fn a_watch_wakes_for_what_is_kept_and_refuses_no_place() {
        assert!(ChangeWatch::new(&[]).is_err());
        assert!(ChangeWatch::new(&[PathBuf::from("/nonexistent/events")]).is_err());
        let d = tempfile::tempdir().unwrap();
        // (the directory of the file is not made before the first event:
        // its parent is watched, and the next watch is the directory's)
        let log = EventLog::File {
            path: d.path().join("events").join("events.log"),
            max_size: 1 << 20,
        };
        assert_eq!(log.watch_dirs(), vec![d.path().to_path_buf()]);
        let watch = ChangeWatch::new(&log.watch_dirs()).unwrap();
        // (kept after the watch was made, before it is waited for: not lost)
        log.write(&ev("died", 1)).unwrap();
        woken(&watch);
        assert_eq!(log.watch_dirs(), vec![d.path().join("events")]);
        let watch = ChangeWatch::new(&log.watch_dirs()).unwrap();
        log.write(&ev("died", 2)).unwrap();
        woken(&watch);
    }

    /// The watch wakes at once for what was kept (not at the end of its
    /// limit).
    fn woken(watch: &ChangeWatch) {
        let started = std::time::Instant::now();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(watch.changed(Some(std::time::Duration::from_secs(30))))
            .unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(20));
    }

    #[test]
    fn the_file_keeps_the_events_and_rotates() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("events/events.log");
        let log = EventLog::File {
            path: path.clone(),
            max_size: 400,
        };
        for t in 1..=6 {
            log.write(&ev("died", t)).unwrap();
        }
        assert!(velarx_wire::events::log::rotated(&path).exists());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let all = rt.block_on(read(&log, None, None)).unwrap().unwrap();
        // what the rotation kept, in order
        assert!(all.len() >= 2 && all.len() <= 6, "{}", all.len());
        assert!(all.windows(2).all(|w| w[0].time_nano < w[1].time_nano));
        assert_eq!(all.last().unwrap().time_nano, 6);
        let some = rt.block_on(read(&log, Some(5), Some(5))).unwrap().unwrap();
        assert_eq!(some.len(), 1);
        assert_eq!(some[0], Stored::of(&ev("died", 5)));
        assert_eq!(
            rt.block_on(read(&EventLog::None, None, None)).unwrap(),
            None
        );
    }

    /// A reader that follows the file gets each event once, in the order
    /// it was kept: one kept late (its time before those shown) too, the
    /// rest of a file rotated between two reads, and a line being written
    /// only once it is whole.
    #[test]
    fn a_follower_of_the_file_gets_each_event_once_in_the_order_kept() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("events.log");
        let log = EventLog::File {
            path: path.clone(),
            max_size: 1000,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut pos = Position::Start;
        let next = |pos: &mut Position| {
            rt.block_on(read_after(&log, Some(10), pos))
                .unwrap()
                .unwrap()
                .iter()
                .map(|e| e.time_nano)
                .collect::<Vec<_>>()
        };
        // (before `since`: not shown at the first read)
        log.write(&ev("died", 5)).unwrap();
        log.write(&ev("died", 20)).unwrap();
        assert_eq!(next(&mut pos), [20]);
        assert_eq!(next(&mut pos), Vec::<i64>::new());
        // kept after an event later than it: shown, however late
        log.write(&ev("died", 30)).unwrap();
        log.write(&ev("died", 15)).unwrap();
        assert_eq!(next(&mut pos), [30, 15]);
        // a half written line waits for its end
        let half = b"{\"Type\":\"container\",\"Status\":\"di";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(half)
            .unwrap();
        assert_eq!(next(&mut pos), Vec::<i64>::new());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"ed\",\"TimeNano\":40}\n")
            .unwrap();
        assert_eq!(next(&mut pos), [40]);
        // the file rotates between two reads: its rest, then the new one
        for t in 50..56 {
            log.write(&ev("died", t)).unwrap();
        }
        assert!(velarx_wire::events::log::rotated(&path).exists());
        assert_eq!(next(&mut pos), (50..56).collect::<Vec<_>>());
        log.write(&ev("died", 60)).unwrap();
        assert_eq!(next(&mut pos), [60]);
    }

    /// The file made after the first read is new to the reader: all of it
    /// is shown, an event kept late first too.
    #[test]
    fn a_file_made_after_the_first_read_is_read_whole() {
        let d = tempfile::tempdir().unwrap();
        let log = EventLog::File {
            path: d.path().join("events.log"),
            max_size: velarx_wire::events::log::DEFAULT_MAX_SIZE,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut pos = Position::Start;
        assert!(rt
            .block_on(read_after(&log, Some(10), &mut pos))
            .unwrap()
            .unwrap()
            .is_empty());
        log.write(&ev("died", 5)).unwrap();
        let got = rt
            .block_on(read_after(&log, Some(10), &mut pos))
            .unwrap()
            .unwrap();
        assert_eq!(got.iter().map(|e| e.time_nano).collect::<Vec<_>>(), [5]);
    }
}
