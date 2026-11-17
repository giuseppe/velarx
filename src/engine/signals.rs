// SPDX-License-Identifier: Apache-2.0
//! The signals that end a command (Ctrl-C, the terminal hanging up, a
//! TERM): taken, not suffered, while the engine of the command has work to
//! clean up.  The command that asks the engine service of its own process
//! takes them for the length of the command ([`end_on_signals`]).

use crate::client::{ClientError, ClientResult};
use std::sync::atomic::{AtomicI32, Ordering};

/// The signals that end a command.
const ENDING: [i32; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// The signal that drops what is still cleaning up when the command was
/// told to end (the first tells it, the second is the same signal from the
/// other process of the command).
const DROP_AT: usize = 3;

/// The signals that end the command, held: they are handled (whatever the
/// thread they come to) and written to a pipe, instead of ending the
/// process; the dispositions before are restored when it is dropped.
struct Ending {
    read: std::os::fd::OwnedFd,
    _write: std::os::fd::OwnedFd,
    before: Vec<velarx_sys::catch::Saved>,
}

impl Ending {
    fn hold() -> ClientResult<Self> {
        let failed =
            |e: std::io::Error| ClientError::Request(format!("the signals of the command: {e}"));
        let (read, write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .map_err(|e| failed(e.into()))?;
        velarx_sys::catch::set_pipe(std::os::fd::AsRawFd::as_raw_fd(&write));
        let before = ENDING
            .into_iter()
            .filter_map(velarx_sys::catch::catch_into_pipe)
            .collect();
        Ok(Self {
            read,
            _write: write,
            before,
        })
    }

    /// The signals that came since asked last.
    fn came(&self) -> Vec<i32> {
        let mut b = [0u8; 16];
        let mut out = Vec::new();
        while let Ok(n @ 1..) = rustix::io::read(&self.read, &mut b) {
            out.extend(b[..n].iter().map(|s| i32::from(*s)));
        }
        out
    }
}

impl Drop for Ending {
    fn drop(&mut self) {
        for saved in &self.before {
            saved.restore();
        }
        velarx_sys::catch::set_pipe(-1);
    }
}

/// The signal that ended the command (0: none yet).
static ENDED: AtomicI32 = AtomicI32::new(0);

/// Take the signals that end the command until it is done.  The first one
/// runs `leave` (the engine stops serving and cleans up what the calls under
/// way left) on a thread of its own, then the process ends with the status of
/// a process the signal killed; the third ends it at once.  A call under way
/// sees its connection close, as the engine service sees a client that was
/// killed.  [`wait_if_ended`] keeps the thread of the command from ending it
/// otherwise meanwhile.
pub fn end_on_signals(leave: impl FnOnce() + Send + 'static) -> ClientResult<()> {
    let failed = |e: &dyn std::fmt::Display| {
        ClientError::Request(format!("the signals of the command: {e}"))
    };
    let (held, taken) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            // (the guard of the signals stays on this thread)
            let ending = match Ending::hold() {
                Ok(ending) => ending,
                Err(e) => {
                    let _ = held.send(Err(e));
                    return;
                }
            };
            let _ = held.send(Ok(()));
            let mut leave = Some(leave);
            let mut seen = 0;
            loop {
                let mut fds = [rustix::event::PollFd::new(
                    &ending.read,
                    rustix::event::PollFlags::IN,
                )];
                if let Err(e) = rustix::event::poll(&mut fds, None) {
                    if e != rustix::io::Errno::INTR {
                        // (the command is left without a thread to end it
                        // on a signal)
                        tracing::error!("polling for the signals that end the command: {e}");
                        return;
                    }
                }
                for sig in ending.came() {
                    seen += 1;
                    if let Some(leave) = leave.take() {
                        ENDED.store(sig, Ordering::SeqCst);
                        let _ = std::thread::Builder::new()
                            .name("leave".into())
                            .spawn(move || {
                                leave();
                                std::process::exit(128 + sig);
                            });
                    } else if seen >= DROP_AT {
                        std::process::exit(128 + sig);
                    }
                }
            }
        })
        .map_err(|e| failed(&e))?;
    taken.recv().map_err(|e| failed(&e))?
}

/// Return at once if no signal ended the command; otherwise never: the
/// thread that leaves ends the process with the status of the signal, and the
/// command (whose call failed because the engine stopped) is not to end it
/// with another.
pub fn wait_if_ended() {
    if ENDED.load(Ordering::SeqCst) != 0 {
        loop {
            std::thread::park();
        }
    }
}
