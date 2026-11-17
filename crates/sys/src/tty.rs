// SPDX-License-Identifier: Apache-2.0
//! The terminal of a process.

use std::io;
use std::os::fd::BorrowedFd;

/// Puts a terminal in raw mode, restores it on drop.
pub struct RawTerminal<'a> {
    fd: BorrowedFd<'a>,
    saved: rustix::termios::Termios,
}

impl<'a> RawTerminal<'a> {
    pub fn new(fd: BorrowedFd<'a>) -> io::Result<Self> {
        let saved = rustix::termios::tcgetattr(fd)?;
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Flush, &raw)?;
        Ok(Self { fd, saved })
    }
}

impl Drop for RawTerminal<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            self.fd,
            rustix::termios::OptionalActions::Flush,
            &self.saved,
        );
    }
}

/// What the terminal `fd` looks like now: its rows and columns.
pub fn window_size(fd: BorrowedFd<'_>) -> Option<(u16, u16)> {
    let ws = rustix::termios::tcgetwinsize(fd).ok()?;
    Some((ws.ws_row, ws.ws_col))
}

/// Whether `fd` is a terminal.
pub fn is_terminal(fd: BorrowedFd<'_>) -> bool {
    rustix::termios::isatty(fd)
}
