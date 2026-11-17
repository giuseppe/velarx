// SPDX-License-Identifier: Apache-2.0
//! The lines a container wrote to the journal (the `journald` log driver),
//! read with `journalctl`: one reader for the engine, the REST frontend, the
//! logs of a pod and the command line, followed or not.
//!
//! Only the entries of the user's own monitors are read (`_UID`, which the
//! journal sets itself): another user cannot put lines in the log of a
//! container with its fields, as with podman.  The journal takes in what a
//! monitor sends it on its own time, so before it is read for the lines a
//! container wrote until now it is synchronized (`journalctl --sync`): what
//! was sent before is then in it, and the `logs` of a container that ended
//! has all of its lines.

use std::io::{self, Read as _};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};

use super::logfmt::{self, JournalLine, JournalLines};

/// Which lines of the journal are read.
#[derive(Debug, Clone)]
pub struct Query {
    /// The program that reads the journal: `journalctl` (another in tests)
    pub program: PathBuf,
    /// The full id of the container
    pub id: String,
    /// The user on the host whose monitors wrote the lines
    pub uid: u32,
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
    /// The last lines of what the journal holds
    pub tail: Option<usize>,
}

/// A time of `journalctl --since`/`--until`, from nanoseconds.
pub fn epoch(ns: i64) -> String {
    format!(
        "@{}.{:06}",
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000) / 1000
    )
}

impl Query {
    fn command(&self, extra: &[String]) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(["--no-pager", "-o", "json"])
            .args(extra)
            .arg(format!("CONTAINER_ID_FULL={}", self.id))
            .arg(format!("_UID={}", self.uid))
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        cmd
    }

    /// What the journal holds of `self` with `extra`, once it took in what
    /// was sent to it.
    fn output(&self, extra: &[String]) -> io::Result<Vec<u8>> {
        sync(&self.program)?;
        let out = self.command(extra).stderr(Stdio::piped()).output()?;
        if !out.status.success() {
            return Err(failed(&self.program, &out.stderr));
        }
        Ok(out.stdout)
    }

    /// The lines the journal holds, after it took in what was sent to it.
    pub fn read(&self) -> io::Result<Vec<JournalLine>> {
        let mut extra = Vec::new();
        if let Some(ns) = self.since_ns {
            extra.push(format!("--since={}", epoch(ns)));
        }
        if let Some(ns) = self.until_ns {
            extra.push(format!("--until={}", epoch(ns)));
        }
        let out = self.output(&extra)?;
        let mut lines = JournalLines::default();
        let mut got: Vec<JournalLine> = entries(&out).filter_map(|e| lines.push(e)).collect();
        if let Some(n) = self.tail {
            got.drain(..got.len().saturating_sub(n));
        }
        Ok(got)
    }

    /// Start to follow the lines (`journalctl --follow`): what the journal
    /// holds (the tail asked for) and the lines that come.  An error is that
    /// the program could not run (`NotFound`: it is not installed).
    pub fn follow(self) -> io::Result<Follow> {
        let mut first = vec![
            "--follow".to_string(),
            match self.tail {
                Some(n) => format!("--lines={n}"),
                None => "--lines=all".to_string(),
            },
        ];
        if let Some(ns) = self.since_ns {
            first.push(format!("--since={}", epoch(ns)));
        }
        let mut child = self.command(&first).stderr(Stdio::null()).spawn()?;
        let Some(out) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("journalctl: no output"));
        };
        Ok(Follow {
            query: self,
            child,
            out,
        })
    }
}

/// Ask the journal to take in, and store, what was sent to it before.
pub fn sync(program: &std::path::Path) -> io::Result<()> {
    let out = Command::new(program)
        .arg("--sync")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(failed(program, &out.stderr));
    }
    Ok(())
}

fn failed(program: &std::path::Path, stderr: &[u8]) -> io::Error {
    io::Error::other(format!(
        "{}: {}",
        program.display(),
        String::from_utf8_lossy(stderr).trim()
    ))
}

fn entries(out: &[u8]) -> impl Iterator<Item = &[u8]> {
    out.split(|&b| b == b'\n').filter(|l| !l.is_empty())
}

/// The lines of a container being followed in the journal.
pub struct Follow {
    query: Query,
    child: Child,
    out: ChildStdout,
}

impl Follow {
    /// Give the lines as they come, until `stop` is readable (or closed:
    /// the container ended), the time `until_ns` came or `give` says no
    /// more.  When told to stop, what the journal got after the last entry
    /// read comes too, once the journal took in what was sent to it before:
    /// every line once, in the order of the journal.
    pub fn run(
        mut self,
        stop: BorrowedFd<'_>,
        give: &mut dyn FnMut(JournalLine) -> bool,
    ) -> io::Result<()> {
        let until = self.query.until_ns;
        let mut lines = JournalLines::default();
        // whether a line goes on (a line past the time limit ends it, as
        // the end of the container)
        let mut take = |lines: &mut JournalLines, entry: &[u8]| -> bool {
            let Some(l) = lines.push(entry) else {
                return true;
            };
            if let (Some(u), Some(t)) = (until, logfmt::parse_rfc3339_ns(&l.timestamp)) {
                if t > u {
                    return false;
                }
            }
            give(l)
        };
        let mut pending: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut rest = true;
        'follow: loop {
            let timeout = match until {
                None => -1,
                Some(u) => {
                    let left = u.saturating_sub(logfmt::now_ns());
                    if left <= 0 {
                        rest = false;
                        break;
                    }
                    (left / 1_000_000 + 1).min(i32::MAX as i64) as i32
                }
            };
            let mut fds = [
                rustix::event::PollFd::new(&self.out, rustix::event::PollFlags::IN),
                rustix::event::PollFd::from_borrowed_fd(stop.as_fd(), rustix::event::PollFlags::IN),
            ];
            if super::proto::poll(&mut fds, timeout).is_err() || !fds[1].revents().is_empty() {
                break;
            }
            if fds[0].revents().is_empty() {
                continue;
            }
            match self.out.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
            while let Some(nl) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=nl).collect();
                if !take(&mut lines, &line[..line.len() - 1]) {
                    rest = false;
                    break 'follow;
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !rest {
            return Ok(());
        }
        // (an entry read in part is read again after the cursor)
        let mut extra = Vec::new();
        match lines.cursor() {
            Some(c) => extra.push(format!("--after-cursor={c}")),
            None => {
                if let Some(ns) = self.query.since_ns {
                    extra.push(format!("--since={}", epoch(ns)));
                }
                if let Some(n) = self.query.tail {
                    extra.push(format!("--lines={n}"));
                }
            }
        }
        if let Some(ns) = until {
            extra.push(format!("--until={}", epoch(ns)));
        }
        let out = self.query.output(&extra)?;
        for entry in entries(&out) {
            if !take(&mut lines, entry) {
                break;
            }
        }
        Ok(())
    }
}

impl Drop for Follow {
    fn drop(&mut self) {
        // (a follow that is not run does not leave its reader behind)
        if let Ok(None) = self.child.try_wait() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(msg: &str, cursor: &str, partial: bool) -> String {
        format!(
            r#"{{"MESSAGE":"{msg}","PRIORITY":"6","__REALTIME_TIMESTAMP":"1700000000000001","__CURSOR":"{cursor}"{}}}"#,
            if partial {
                r#","CONTAINER_PARTIAL_MESSAGE":"true""#
            } else {
                ""
            }
        )
    }

    /// A `journalctl` that writes its arguments to `calls`: when it follows
    /// it gives a line and the first part of another and waits; asked for
    /// what came after either entry, it gives the rest.
    fn stub(dir: &std::path::Path) -> Query {
        let (a, b1, b2, c) = (
            entry("a", "c1", false),
            entry("b1", "c2", true),
            entry("b2", "c3", false),
            entry("c", "c4", false),
        );
        let script = format!(
            r#"echo "$*" >> {calls}
case "$*" in
  --sync) exit 0 ;;
  *--follow*)
    echo '{a}'
    echo '{b1}'
    exec sleep 300 ;;
  *--after-cursor=c1*CONTAINER_ID_FULL=id1\ _UID=7)
    echo '{b1}'; echo '{b2}'; echo '{c}' ;;
  *--after-cursor=c2*CONTAINER_ID_FULL=id1\ _UID=7)
    echo '{b2}'; echo '{c}' ;;
  *--since=@1.000002*CONTAINER_ID_FULL=id1\ _UID=7)
    echo '{a}'; echo '{b1}'; echo '{b2}'; echo '{c}' ;;
  *) exit 1 ;;
esac
"#,
            calls = dir.join("calls").display()
        );
        let program = dir.join("journalctl");
        // (written by a process of its own: a test of this process that forks
        // while it is open for writing here would make its exec fail, ETXTBSY)
        velarx_base::testing::write_script(&program, &script);
        Query {
            program,
            id: "id1".into(),
            uid: 7,
            since_ns: None,
            until_ns: None,
            tail: None,
        }
    }

    fn calls(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("calls"))
            .unwrap()
            .lines()
            .map(|l| l.split(' ').next().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn a_follow_gives_every_line_once_and_syncs_before_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let follow = stub(dir.path()).follow().unwrap();
        let (stop, mut ended) = rustix::pipe::pipe().map(|(r, w)| (r, Some(w))).unwrap();
        let mut got = Vec::new();
        follow
            .run(stop.as_fd(), &mut |l| {
                // (the container ends once the first line came)
                ended = None;
                got.push(l.message);
                true
            })
            .unwrap();
        assert_eq!(got, ["a", "b1b2", "c"]);
        assert_eq!(calls(dir.path()), ["--no-pager", "--sync", "--no-pager"]);
    }

    #[test]
    fn a_read_syncs_and_keeps_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = stub(dir.path());
        q.since_ns = Some(1_000_002_000);
        q.tail = Some(2);
        let got: Vec<String> = q.read().unwrap().into_iter().map(|l| l.message).collect();
        assert_eq!(got, ["b1b2", "c"]);
        assert_eq!(calls(dir.path()), ["--sync", "--no-pager"]);
    }

    #[test]
    fn a_missing_journalctl_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let mut q = stub(dir.path());
        q.program = dir.path().join("none");
        assert_eq!(
            q.follow().err().map(|e| e.kind()),
            Some(io::ErrorKind::NotFound)
        );
    }
}
