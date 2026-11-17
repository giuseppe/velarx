// SPDX-License-Identifier: Apache-2.0
//! What is read from the pipes of a child process.

use std::io::Read;
use std::sync::mpsc;

/// The first `max` bytes (and one more, so that a caller sees an excess)
/// that come out of `pipe`, read by a thread of its own; they arrive on the
/// receiver (none: `pipe` is `None`).
pub fn drain<R: Read + Send + 'static>(pipe: Option<R>, max: u64) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = pipe {
            let _ = pipe.take(max.saturating_add(1)).read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// The standard output of COMMAND when it succeeds within TIMEOUT; none
/// when it cannot be run, fails, or takes longer (then it is killed).  Its
/// standard input and error are null.
pub fn output_within(
    mut command: std::process::Command,
    timeout: std::time::Duration,
) -> Option<String> {
    use std::process::Stdio;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let out = drain(child.stdout.take(), u64::MAX);
    let deadline = std::time::Instant::now() + timeout;
    // (asleep in the kernel until the child exits or the time is over)
    let exited = crate::pidfd::open_child(child.id() as i32)
        .and_then(|fd| crate::pidfd::wait_exit(&fd, timeout));
    if !matches!(exited, Ok(true)) {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let ok = child.wait().is_ok_and(|s| s.success());
    // (a child of the child that keeps the output open is not waited for
    // past the deadline)
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    let text = out.recv_timeout(left).ok()?;
    ok.then(|| String::from_utf8_lossy(&text).into_owned())
}
