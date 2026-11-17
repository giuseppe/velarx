// SPDX-License-Identifier: Apache-2.0
//! Descriptors received on a unix socket (`SCM_RIGHTS`).
//!
//! A receive whose control buffer is too short does not fail: the kernel
//! closes the descriptors that do not fit and sets `MSG_CTRUNC`, and the
//! message arrives with fewer descriptors than it was sent with.  Every
//! receiver goes through [`recv`], where that is an error.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::net::{
    recvmsg, sendmsg, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
};

/// What the kernel passes in one message at most (`SCM_MAX_FD`).
const MAX_PER_MESSAGE: usize = 253;

/// A message: its bytes (the first `bytes` of the buffer given) and its
/// descriptors.
#[derive(Debug)]
pub struct Received {
    pub bytes: usize,
    pub fds: Vec<OwnedFd>,
}

/// One message from `sock` into `buf`, with at most `max_fds` descriptors
/// (close-on-exec).  More than that, or descriptors the kernel had to drop
/// (`MSG_CTRUNC`), or a message longer than `buf` (`MSG_TRUNC`, of a
/// datagram or packet socket), is an `InvalidData` error and the
/// descriptors received are closed.  `flags` is `RecvFlags::empty()` or, for example,
/// `DONTWAIT`.  An interrupted call is repeated; no data is `bytes == 0`.
pub fn recv(
    sock: impl AsFd,
    buf: &mut [u8],
    max_fds: usize,
    flags: RecvFlags,
) -> io::Result<Received> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_PER_MESSAGE))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let got = loop {
        match recvmsg(
            sock.as_fd(),
            &mut [IoSliceMut::new(buf)],
            &mut control,
            flags | RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(rustix::io::Errno::INTR) => {}
            r => break r.map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?,
        }
    };
    let mut fds = Vec::new();
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = m {
            fds.extend(received);
        }
    }
    if got.flags.contains(ReturnFlags::TRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too long",
        ));
    }
    if got.flags.contains(ReturnFlags::CTRUNC) || fds.len() > max_fds {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("more than {max_fds} descriptors in a message"),
        ));
    }
    Ok(Received {
        bytes: got.bytes,
        fds,
    })
}

/// One message of `bytes` with the descriptors `fds` (at most
/// `SCM_MAX_FD`, 253) to `sock`, which is a socket of messages or a stream.
pub fn send(sock: impl AsFd, bytes: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.len() > MAX_PER_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("more than {MAX_PER_MESSAGE} descriptors in a message"),
        ));
    }
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_PER_MESSAGE))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        control.push(SendAncillaryMessage::ScmRights(fds));
    }
    loop {
        match sendmsg(
            sock.as_fd(),
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::NOSIGNAL,
        ) {
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
            Ok(n) if n == bytes.len() => return Ok(()),
            Ok(n) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("only {n} of {} bytes were sent", bytes.len()),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::BorrowedFd;
    use std::os::unix::net::UnixStream;

    fn send(sock: &UnixStream, fds: &[BorrowedFd<'_>]) {
        super::send(sock, b"x", fds).unwrap();
    }

    #[test]
    fn the_descriptors_of_a_message_arrive_with_it() {
        let (a, b) = UnixStream::pair().unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        send(&a, &[null.as_fd(), null.as_fd()]);
        let mut buf = [0u8; 8];
        let r = recv(&b, &mut buf, 2, RecvFlags::empty()).unwrap();
        assert_eq!((r.bytes, r.fds.len()), (1, 2));
    }

    #[test]
    fn more_descriptors_than_asked_for_are_an_error() {
        let (a, b) = UnixStream::pair().unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        send(&a, &[null.as_fd(), null.as_fd(), null.as_fd()]);
        let e = recv(&b, &mut [0u8; 8], 1, RecvFlags::empty()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_message_without_descriptors_and_the_end_of_the_stream() {
        let (a, b) = UnixStream::pair().unwrap();
        std::io::Write::write_all(&mut &a, b"hi").unwrap();
        let r = recv(&b, &mut [0u8; 8], 0, RecvFlags::empty()).unwrap();
        assert_eq!((r.bytes, r.fds.len()), (2, 0));
        drop(a);
        assert_eq!(
            recv(&b, &mut [0u8; 8], 0, RecvFlags::empty())
                .unwrap()
                .bytes,
            0
        );
    }
}
