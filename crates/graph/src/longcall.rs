// SPDX-License-Identifier: Apache-2.0
//! The client side of the two rules that keep a call to a driver in another
//! process from hanging or being cut when it is slow (`docs/STORAGE.md`, "Long
//! calls"): the engine talks to the driver on one connection per call, and a
//! connection that says nothing for `[storage.varlink] timeout_secs` is
//! failed.
//!
//! * **Progress.**  A call that can take longer than the idle deadline
//!   (`CreateRoot`, `CreateImageVolume`, `BeginPull`, `Collect`, `Repair`,
//!   `Check`) is made with `more`, and the driver sends a `progress` reply at
//!   least every `timeout_secs / 2`; each reply resets the deadline
//!   ([`wait_for_call`], [`IdleDeadline`]).  A pull's `BeginPull` keeps sending
//!   progress while the driver's own calls to the feed run.
//! * **`ReadObjects` in pipe form.**  The reply for range *i* is sent
//!   **before** its bytes are written to the pipe.  A driver that writes more
//!   than the pipe holds (`F_GETPIPE_SZ`, 64 KiB by default) before its reply
//!   blocks on a full pipe while an engine that waits for the reply never reads
//!   it: a deadlock that only shows on large files.  [`read_pipe_ranges`]
//!   reads in that order, polls the pipe under the deadline instead of
//!   blocking, and says which rule the driver broke when the deadline passes
//!   with bytes in the pipe.
//!
//! The wire client (`velarx-storage-client`) makes its calls through these
//! functions, and the conformance suite reads a range larger than a pipe
//! through [`read_pipe_ranges`].

use crate::{ObjectRange, ObjectSink};
use std::fs::File;
use std::io::{self, Read};
use std::time::{Duration, Instant};

/// The longest a driver may be silent in a long call: half the idle deadline
/// (`timeout`), so that a reply that is late by a scheduling delay or a slow
/// disk does not cut the call.
pub fn progress_interval(timeout: Duration) -> Duration {
    timeout / 2
}

/// The longest a call lasts whatever progress the driver sends, a day (or
/// four times the idle deadline, when that is longer): a driver that keeps
/// sending progress and never ends cannot hold a call, and what the engine
/// holds while it waits (the lock of the store, a container being made), for
/// ever.
pub fn call_cap(timeout: Duration) -> Duration {
    Duration::from_secs(24 * 3600).max(timeout.saturating_mul(4))
}

/// The idle deadline of a call: it passes when nothing came for `timeout`, and
/// every reply (progress or bytes) starts it again, but never past the
/// [`call_cap`] counted from the start of the call.
#[derive(Debug, Clone)]
pub struct IdleDeadline {
    timeout: Duration,
    last: Instant,
    started: Instant,
    cap: Duration,
}

impl IdleDeadline {
    pub fn new(timeout: Duration) -> Self {
        Self::with_cap(timeout, call_cap(timeout))
    }

    /// The deadline with another overall cap than [`call_cap`] (tests).
    pub fn with_cap(timeout: Duration, cap: Duration) -> Self {
        let now = Instant::now();
        Self {
            timeout,
            last: now,
            started: now,
            cap,
        }
    }

    /// Something came: the deadline starts again.
    pub fn reset(&mut self) {
        self.last = Instant::now();
    }

    /// How long until the deadline (zero once it has passed).
    pub fn remaining(&self) -> Duration {
        self.timeout
            .saturating_sub(self.last.elapsed())
            .min(self.cap.saturating_sub(self.started.elapsed()))
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The error of the deadline that passed in `call`: the call went silent,
    /// or it reached its overall cap.
    fn passed(&self, call: &str) -> io::Error {
        if self.started.elapsed() >= self.cap {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the call {call} of the storage driver did not end in {}s, however much progress it sent: no call lasts longer (a day, or four times [storage.varlink] timeout_secs)",
                    self.cap.as_secs()
                ),
            )
        } else {
            timed_out(call, self.timeout)
        }
    }
}

/// The error of a call that went silent: `TimedOut`, naming the call and the
/// knob.
fn timed_out(call: &str, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "the call {call} of the storage driver had no reply for {}s: a call that can take longer sends progress at least every timeout_secs / 2 ([storage.varlink] timeout_secs raises the deadline)",
            timeout.as_secs_f64()
        ),
    )
}

/// What the next reply of a call is.
#[derive(Debug, PartialEq, Eq)]
pub enum Step<T> {
    /// A `progress` reply (`continues`): the call goes on.
    Progress,
    /// The last reply.
    Done(T),
}

/// Wait for the end of a call made with `more`: `next(wait)` waits at most
/// `wait` for the next reply (`None`: none came), every reply starts the idle
/// deadline again, and the call is `TimedOut` when none came for `timeout`.
/// The call lasts as long as the driver says it does, as long as it keeps
/// sending progress, up to [`call_cap`].
pub fn wait_for_call<T>(
    call: &str,
    timeout: Duration,
    next: impl FnMut(Duration) -> io::Result<Option<Step<T>>>,
) -> io::Result<T> {
    wait_for_call_by(call, IdleDeadline::new(timeout), next)
}

/// [`wait_for_call`] under `deadline`.
pub fn wait_for_call_by<T>(
    call: &str,
    mut deadline: IdleDeadline,
    mut next: impl FnMut(Duration) -> io::Result<Option<Step<T>>>,
) -> io::Result<T> {
    loop {
        let wait = deadline.remaining();
        if wait.is_zero() {
            return Err(deadline.passed(call));
        }
        match next(wait)? {
            Some(Step::Done(v)) => return Ok(v),
            Some(Step::Progress) => deadline.reset(),
            None => {}
        }
    }
}

fn readable(pipe: &File, wait: Duration) -> io::Result<bool> {
    let mut fds = [rustix::event::PollFd::new(
        pipe,
        rustix::event::PollFlags::IN,
    )];
    let ts = rustix::time::Timespec {
        tv_sec: wait.as_secs() as _,
        tv_nsec: wait.subsec_nanos() as _,
    };
    // (a signal does not make the wait longer than `wait`: the next poll
    // waits for what is left)
    let start = Instant::now();
    let mut ts = ts;
    loop {
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(n) => return Ok(n > 0),
            Err(rustix::io::Errno::INTR) => {
                let left = wait.saturating_sub(start.elapsed());
                ts = rustix::time::Timespec {
                    tv_sec: left.as_secs() as _,
                    tv_nsec: left.subsec_nanos() as _,
                };
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Read the bytes of `ranges` that a driver writes to `pipe` (`ReadObjects`
/// without a `region`), in the order asked: for each range the engine waits for
/// its reply (`reply(wait)` gives the index of the next reply, `None` when none
/// came within `wait`), and only then reads its bytes.  The pipe is polled under
/// the deadline, so a driver that stops writing is `TimedOut` and not a hang;
/// a deadline that passes while the pipe holds bytes of a range whose reply has
/// not come names the driver's mistake (the bytes before the reply).  `sink` gets
/// the bytes of each range in pieces of at most 64 KiB.
pub fn read_pipe_ranges(
    ranges: &[ObjectRange],
    reply: &mut dyn FnMut(Duration) -> io::Result<Option<usize>>,
    mut pipe: &File,
    deadline: &mut IdleDeadline,
    sink: &mut dyn ObjectSink,
) -> io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    for (i, range) in ranges.iter().enumerate() {
        // the reply of range i
        loop {
            let wait = deadline.remaining();
            if wait.is_zero() {
                let early = readable(pipe, Duration::ZERO)?;
                return Err(match early {
                    true => io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "the storage driver wrote the bytes of range {i} before its reply (the pipe holds them): the reply of a range is sent before its bytes, or a range larger than the pipe buffer blocks the driver and the engine alike"
                        ),
                    ),
                    false => deadline.passed(&format!("ReadObjects (reply for range {i})")),
                });
            }
            match reply(wait)? {
                Some(j) if j == i => {
                    deadline.reset();
                    break;
                }
                Some(j) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("the storage driver answered range {j} when range {i} was next: the ranges are answered in the order asked"),
                    ))
                }
                None => {}
            }
        }
        // its bytes
        let mut left = range.length;
        while left > 0 {
            let wait = deadline.remaining();
            if wait.is_zero() || !readable(pipe, wait)? {
                return Err(
                    deadline.passed(&format!("ReadObjects (bytes of range {i}, {left} short)"))
                );
            }
            let want = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
            let n = match pipe.read(&mut buf[..want]) {
                Ok(n) => n,
                // (a signal before any byte: the pipe is polled again)
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("the pipe of ReadObjects closed {left} bytes short in range {i}"),
                ));
            }
            sink.data(i, &buf[..n])?;
            left -= n as u64;
            deadline.reset();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::mpsc;

    const T: Duration = Duration::from_millis(400);

    #[test]
    fn a_call_that_sends_progress_outlives_the_deadline() {
        let (tx, rx) = mpsc::channel::<Step<u32>>();
        let started = Instant::now();
        let driver = std::thread::spawn(move || {
            // five deadlines' worth of work, a progress reply every quarter
            // of a deadline
            while started.elapsed() < T * 5 {
                tx.send(Step::Progress).unwrap();
                std::thread::sleep(T / 4);
            }
            tx.send(Step::Done(7)).unwrap();
        });
        let v = wait_for_call("Collect", T, |wait| Ok(rx.recv_timeout(wait).ok())).unwrap();
        assert_eq!(v, 7);
        assert!(started.elapsed() > T * 4, "{:?}", started.elapsed());
        driver.join().unwrap();
    }

    #[test]
    fn a_silent_call_is_timed_out_naming_the_call_and_the_knob() {
        let (_tx, rx) = mpsc::channel::<Step<u32>>();
        let started = Instant::now();
        let e = wait_for_call("Repair", T, |wait| Ok(rx.recv_timeout(wait).ok())).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        let m = e.to_string();
        assert!(m.contains("Repair") && m.contains("timeout_secs"), "{m}");
        assert!(started.elapsed() >= T && started.elapsed() < T * 3);
        // a driver that gives up with an error ends the call with it
        let e = wait_for_call::<u32>("Check", T, |_| Err(io::Error::other("gone"))).unwrap_err();
        assert_eq!(e.to_string(), "gone");
    }

    /// Progress keeps a call going only up to its overall cap: a driver that
    /// sends progress for ever is `TimedOut`, saying so.
    #[test]
    fn progress_does_not_hold_a_call_past_its_cap() {
        let started = Instant::now();
        let e = wait_for_call_by::<u32>("Check", IdleDeadline::with_cap(T, T * 3), |wait| {
            std::thread::sleep(wait.min(Duration::from_millis(20)));
            Ok(Some(Step::Progress))
        })
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        let m = e.to_string();
        assert!(m.contains("Check") && m.contains("did not end"), "{m}");
        assert!(started.elapsed() >= T * 3 && started.elapsed() < T * 6);
        assert_eq!(
            call_cap(Duration::from_secs(60)),
            Duration::from_secs(86400)
        );
        assert_eq!(
            call_cap(Duration::from_secs(86400)),
            Duration::from_secs(4 * 86400)
        );
    }

    #[test]
    fn the_progress_interval_is_half_the_deadline() {
        assert_eq!(
            progress_interval(Duration::from_secs(30)),
            Duration::from_secs(15)
        );
    }

    fn pipe() -> (File, File) {
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        // a small pipe: ranges of a few pages are larger than it
        rustix::pipe::fcntl_setpipe_size(&w, 4096).unwrap();
        (File::from(r), File::from(w))
    }

    struct Got(std::collections::BTreeMap<usize, Vec<u8>>);
    impl ObjectSink for Got {
        fn data(&mut self, range: usize, bytes: &[u8]) -> io::Result<()> {
            self.0.entry(range).or_default().extend_from_slice(bytes);
            Ok(())
        }
    }

    fn ranges(sizes: &[u64]) -> Vec<ObjectRange> {
        sizes.iter().map(|n| ObjectRange::whole("k", *n)).collect()
    }

    /// A driver thread: for each range its reply, then its bytes (the order
    /// the rule asks), or the bytes then the reply (`early`).
    fn driver(
        sizes: Vec<u64>,
        mut w: File,
        replies: mpsc::Sender<usize>,
        early: bool,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            for (i, n) in sizes.iter().enumerate() {
                let bytes = vec![i as u8 + 1; *n as usize];
                if !early {
                    let _ = replies.send(i);
                }
                if w.write_all(&bytes).is_err() {
                    return;
                }
                if early {
                    let _ = replies.send(i);
                }
            }
        })
    }

    #[test]
    fn a_range_larger_than_the_pipe_is_read_when_the_reply_comes_first() {
        let (r, w) = pipe();
        let size = rustix::pipe::fcntl_getpipe_size(&w).unwrap() as u64;
        let sizes = vec![size * 5, 0, 10, size + 1];
        let (tx, rx) = mpsc::channel();
        let d = driver(sizes.clone(), w, tx, false);
        let mut got = Got(Default::default());
        read_pipe_ranges(
            &ranges(&sizes),
            &mut |wait| Ok(rx.recv_timeout(wait).ok()),
            &r,
            &mut IdleDeadline::new(T),
            &mut got,
        )
        .unwrap();
        d.join().unwrap();
        for (i, n) in sizes.iter().enumerate().filter(|(_, n)| **n > 0) {
            assert!(got.0[&i].iter().all(|b| *b == i as u8 + 1) && got.0[&i].len() as u64 == *n);
        }
        assert!(!got.0.contains_key(&1), "an empty range gives nothing");
    }

    #[test]
    fn bytes_before_the_reply_are_named_as_the_drivers_mistake() {
        let (r, w) = pipe();
        let size = rustix::pipe::fcntl_getpipe_size(&w).unwrap() as u64;
        let sizes = vec![size * 3];
        let (tx, rx) = mpsc::channel();
        // the driver blocks on the full pipe before it sends the reply
        let d = driver(sizes.clone(), w, tx, true);
        let mut got = Got(Default::default());
        let e = read_pipe_ranges(
            &ranges(&sizes),
            &mut |wait| Ok(rx.recv_timeout(wait).ok()),
            &r,
            &mut IdleDeadline::new(T),
            &mut got,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(e.to_string().contains("before its reply"), "{e}");
        // (the driver is released when the engine lets go of the pipe)
        drop(r);
        d.join().unwrap();
        // a driver that is only silent is a timeout of the call
        let (r, w) = pipe();
        let (_tx, rx) = mpsc::channel::<usize>();
        let e = read_pipe_ranges(
            &ranges(&[10]),
            &mut |wait| Ok(rx.recv_timeout(wait).ok()),
            &r,
            &mut IdleDeadline::new(T),
            &mut Got(Default::default()),
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("no reply") && e.to_string().contains("range 0"),
            "{e}"
        );
        drop(w);
    }

    #[test]
    fn replies_out_of_order_and_a_short_pipe_are_errors() {
        let (r, mut w) = pipe();
        let e = read_pipe_ranges(
            &ranges(&[1, 1]),
            &mut |_| Ok(Some(1)),
            &r,
            &mut IdleDeadline::new(T),
            &mut Got(Default::default()),
        )
        .unwrap_err();
        assert!(e.to_string().contains("in the order asked"), "{e}");
        w.write_all(b"abc").unwrap();
        drop(w);
        let mut n = 0;
        let e = read_pipe_ranges(
            &ranges(&[10]),
            &mut |_| {
                n += 1;
                Ok(Some(0))
            },
            &r,
            &mut IdleDeadline::new(T),
            &mut Got(Default::default()),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert!(e.to_string().contains("7 bytes short"), "{e}");
    }
}
