// SPDX-License-Identifier: Apache-2.0
//! The talk with a confined helper process: a request on its standard
//! input, a short answer on its standard output, a time limit, and a way
//! to stop it.

use std::io::{self, Read, Write};
use std::os::fd::BorrowedFd;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// The most of the answer that is read.
const MAX_ANSWER: u64 = 64 * 1024;

/// How the talk ended.
pub(super) enum Talked {
    /// The helper ended: its status and what it wrote.
    Done(ExitStatus, String),
    /// It ran longer than the time limit, and was killed.
    TimedOut,
    /// The other end of `stop` was written to or closed, and the helper
    /// was killed.
    Stopped,
}

/// Send `body` to `child` and read its answer until it ends, at most
/// `timeout`, or until `stop` is readable (its write end closed).  Nothing
/// is polled: the helper's pidfd, `stop` and the limit are waited for
/// together.
pub(super) fn talk(
    mut child: Child,
    body: Vec<u8>,
    timeout: Duration,
    stop: BorrowedFd<'_>,
) -> io::Result<Talked> {
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::process::{pidfd_open, Pid, PidfdFlags};
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no stdin"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let reader = std::thread::spawn(move || {
        let mut answer = String::new();
        let _ = (&mut stdout).take(MAX_ANSWER).read_to_string(&mut answer);
        answer
    });
    let pid = Pid::from_child(&child);
    let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.into());
        }
    };
    let start = Instant::now();
    let ended = loop {
        let left = timeout.saturating_sub(start.elapsed());
        let mut fds = [
            PollFd::new(&pidfd, PollFlags::IN),
            PollFd::new(&stop, PollFlags::IN),
        ];
        let limit = rustix::event::Timespec {
            tv_sec: left.as_secs() as _,
            tv_nsec: left.subsec_nanos() as _,
        };
        match poll(&mut fds, Some(&limit)) {
            Ok(0) => break None,
            Ok(_) if !fds[0].revents().is_empty() => break Some(true),
            Ok(_) => break Some(false),
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        }
    };
    let Some(true) = ended else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = writer.join();
        let _ = reader.join();
        return Ok(match ended {
            None => Talked::TimedOut,
            _ => Talked::Stopped,
        });
    };
    let status = child.wait()?;
    let _ = writer.join();
    let answer = reader.join().unwrap_or_default();
    Ok(Talked::Done(status, answer.trim().to_string()))
}

/// Run `job` on a thread of its own, given the read end of a stop that
/// [`talk`] waits for: once the operation is cancelled the stop is closed,
/// the helper killed and reaped, and the error is the cancellation's.
pub(super) async fn stoppable<T: Send + 'static>(
    cancel: &crate::services::Cancel,
    job: impl FnOnce(BorrowedFd<'_>) -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    use std::os::fd::AsFd;
    let (writer, reader) = std::io::pipe()?;
    let mut run = tokio::task::spawn_blocking(move || job(reader.as_fd()));
    let mut cancel = cancel.clone();
    tokio::select! {
        r = &mut run => r.map_err(io::Error::other)?,
        () = cancel.wait() => {
            drop(writer);
            let _ = run.await;
            Err(crate::services::Cancel::error())
        }
    }
}
