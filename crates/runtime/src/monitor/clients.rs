// SPDX-License-Identifier: Apache-2.0
//! The connections of the monitor's socket (`org.velarx.Monitor`): what is
//! read of them (calls ended by a NUL), what is sent on them (replies, some
//! with descriptors), and the pipes of their streams, all without blocking:
//! the poll loop of the monitor drives them.
//!
//! The last reply of a stream (the exit of an attach or exec session) goes
//! once everything queued for its pipes is written and the pipes are
//! closed: a client that has the last reply reads its pipes to their end.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Instant;

use rustix::net::{self, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
use velarx_wire::varlink::MAX_FDS;

use velarx_wire::monitor::iface::MAX_CALL;
use velarx_wire::monitor::logfmt::Stream;
use velarx_wire::monitor::proto::Attach;

/// The send buffer asked for the streams of the output (the kernel caps it
/// at `net.core.wmem_max`).
const STREAM_BUFFER: usize = 256 * 1024;
/// Bytes of replies waiting for a client above which its calls are not
/// read: a client that calls and does not read cannot grow them.
const MAX_REPLY_QUEUE: usize = 256 * 1024;

/// What a connection is for.
pub(super) enum Kind {
    /// Calls, or nothing yet.
    Fresh,
    Attach(Attach),
    /// The engine, which follows the events once it subscribed.
    Daemon,
    /// The owner of an exec session.
    Exec,
}

/// One direction of a pipe toward a client: what does not fit is queued.
pub(super) struct Sink {
    fd: OwnedFd,
    queue: VecDeque<Vec<u8>>,
    queued: usize,
}

/// What a write did.
enum Wrote {
    All,
    Some,
    /// The reader is gone.
    Broken,
}

fn write_some(fd: BorrowedFd<'_>, data: &[u8]) -> Result<usize, rustix::io::Errno> {
    loop {
        match rustix::io::write(fd, data) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(rustix::io::Errno::AGAIN) => return Ok(0),
            other => return other,
        }
    }
}

impl Sink {
    fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            queue: VecDeque::new(),
            queued: 0,
        }
    }

    fn pending(&self) -> bool {
        !self.queue.is_empty()
    }

    fn push(&mut self, data: &[u8]) -> Wrote {
        let mut at = 0;
        if self.queue.is_empty() {
            match write_some(self.fd.as_fd(), data) {
                Ok(n) if n == data.len() => return Wrote::All,
                Ok(n) => at = n,
                Err(_) => return Wrote::Broken,
            }
        }
        self.queued += data.len() - at;
        self.queue.push_back(data[at..].to_vec());
        Wrote::Some
    }

    /// Write what is queued, as far as the reader takes it: whether
    /// something moved, or the reader is gone.
    fn flush(&mut self) -> Result<bool, ()> {
        let mut moved = false;
        while let Some(front) = self.queue.front_mut() {
            match write_some(self.fd.as_fd(), front) {
                Ok(0) => break,
                Ok(n) => {
                    moved = true;
                    self.queued -= n;
                    if n == front.len() {
                        self.queue.pop_front();
                    } else {
                        front.drain(..n);
                        break;
                    }
                }
                Err(_) => return Err(()),
            }
        }
        Ok(moved)
    }
}

/// A reply on its way, with its descriptors (sent with its first byte).
struct Outgoing {
    bytes: Vec<u8>,
    sent: usize,
    fds: Vec<OwnedFd>,
}

pub(super) struct Client {
    pub id: u64,
    conn: OwnedFd,
    pub kind: Kind,
    /// When it connected, or made its last call.
    pub since: Instant,
    inbuf: Vec<u8>,
    replies: VecDeque<Outgoing>,
    out: Option<Sink>,
    err: Option<Sink>,
    /// The read end of the pipe of the client's input.
    pub input: Option<OwnedFd>,
    /// The client said its input ends (`CloseStdin`).
    pub input_eof_asked: bool,
    /// The client hung up: the rest of its input is read before it goes.
    pub hung_up: bool,
    /// A call with `more` is being answered.
    pub stream: bool,
    /// The descriptors that came with its calls, taken by [`Self::take_received`].
    received: Vec<OwnedFd>,
    /// The last reply of the stream, once the pipes are written out.
    last: Option<Vec<u8>>,
    /// When something queued stopped moving.
    pub stalled: Option<Instant>,
    /// The client did not read its output: its streams ended early (its
    /// last reply says so).
    pub output_dropped: bool,
    pub gone: bool,
    /// Hang up once everything queued was sent.
    close_when_flushed: bool,
    /// Everything was sent: since when, until the client hangs up.
    pub closing: Option<Instant>,
}

/// The connection of a stream of a client, one way: (the monitor's end, the
/// client's end).  A socket, not a pipe: a full pipe is writable again
/// once a page of it is read, so a fast stream would go a page at a time;
/// a socket is writable once a good part of its buffer is free.
fn stream_pipe(client_writes: bool) -> io::Result<(OwnedFd, OwnedFd)> {
    use rustix::net::{AddressFamily, Shutdown, SocketFlags, SocketType};
    let (ours, theirs) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    // (one way only)
    let (our_way, their_way) = if client_writes {
        (Shutdown::Write, Shutdown::Read)
    } else {
        (Shutdown::Read, Shutdown::Write)
    };
    net::shutdown(&ours, our_way)?;
    net::shutdown(&theirs, their_way)?;
    rustix::fs::fcntl_setfl(&ours, rustix::fs::OFlags::NONBLOCK)?;
    if !client_writes {
        let _ = net::sockopt::set_socket_send_buffer_size(&ours, STREAM_BUFFER);
    }
    Ok((ours, theirs))
}

/// The pipes a client asked for, and the descriptors to send it.
pub(super) struct Pipes {
    pub input: Option<OwnedFd>,
    pub out: Option<OwnedFd>,
    pub err: Option<OwnedFd>,
    /// Theirs, in this order, and their positions (stdin, stdout, stderr).
    pub theirs: Vec<OwnedFd>,
    pub positions: [Option<u32>; 3],
}

impl Pipes {
    /// Pass `fd` as the client's input (instead of a stream of the monitor).
    pub fn pass_first(&mut self, fd: OwnedFd) {
        for p in self.positions.iter_mut().flatten() {
            *p += 1;
        }
        self.positions[0] = Some(0);
        self.theirs.insert(0, fd);
    }

    pub fn new(stdin: bool, stdout: bool, stderr: bool) -> io::Result<Self> {
        let mut p = Pipes {
            input: None,
            out: None,
            err: None,
            theirs: Vec::new(),
            positions: [None; 3],
        };
        for (i, want) in [stdin, stdout, stderr].into_iter().enumerate() {
            if !want {
                continue;
            }
            let (ours, theirs) = stream_pipe(i == 0)?;
            p.positions[i] = Some(p.theirs.len() as u32);
            p.theirs.push(theirs);
            match i {
                0 => p.input = Some(ours),
                1 => p.out = Some(ours),
                _ => p.err = Some(ours),
            }
        }
        Ok(p)
    }
}

impl Client {
    pub fn new(id: u64, conn: OwnedFd, now: Instant) -> Self {
        Self {
            id,
            conn,
            kind: Kind::Fresh,
            since: now,
            inbuf: Vec::new(),
            replies: VecDeque::new(),
            out: None,
            err: None,
            input: None,
            input_eof_asked: false,
            hung_up: false,
            stream: false,
            received: Vec::new(),
            last: None,
            stalled: None,
            output_dropped: false,
            gone: false,
            close_when_flushed: false,
            closing: None,
        }
    }

    pub fn conn(&self) -> BorrowedFd<'_> {
        self.conn.as_fd()
    }

    /// The monitor's ends of the pipes of a stream.
    pub fn set_pipes(
        &mut self,
        out: Option<OwnedFd>,
        err: Option<OwnedFd>,
        input: Option<OwnedFd>,
    ) {
        self.out = out.map(Sink::new);
        self.err = err.map(Sink::new);
        self.input = input;
    }

    pub fn wants(&self, stream: Stream) -> bool {
        match stream {
            Stream::Stdout => self.out.is_some(),
            Stream::Stderr => self.err.is_some(),
        }
    }

    /// Bytes of the streams waiting for the client.
    pub fn data_queued(&self) -> usize {
        self.out.as_ref().map_or(0, |s| s.queued) + self.err.as_ref().map_or(0, |s| s.queued)
    }

    /// Bytes waiting for the client, replies included.
    pub fn queued(&self) -> usize {
        self.data_queued()
            + self
                .replies
                .iter()
                .map(|r| r.bytes.len() - r.sent)
                .sum::<usize>()
    }

    pub fn replies_pending(&self) -> bool {
        !self.replies.is_empty()
    }

    /// Whether to read the calls of the client: it is there, and reads
    /// its replies.
    pub fn wants_calls(&self) -> bool {
        !self.hung_up
            && self
                .replies
                .iter()
                .map(|r| r.bytes.len() - r.sent)
                .sum::<usize>()
                < MAX_REPLY_QUEUE
    }

    /// The descriptor of a stream with bytes waiting.
    pub fn pending_sink(&self, stream: Stream) -> Option<BorrowedFd<'_>> {
        let s = match stream {
            Stream::Stdout => self.out.as_ref(),
            Stream::Stderr => self.err.as_ref(),
        }?;
        s.pending().then(|| s.fd.as_fd())
    }

    fn mark_queued(&mut self, now: Instant) {
        if self.queued() > 0 {
            self.stalled.get_or_insert(now);
        } else {
            self.stalled = None;
        }
    }

    /// Queue a reply (with its descriptors) and send what can be.
    pub fn reply_with(&mut self, bytes: Vec<u8>, fds: Vec<OwnedFd>, now: Instant) {
        if self.gone {
            return;
        }
        self.replies.push_back(Outgoing {
            bytes,
            sent: 0,
            fds,
        });
        self.advance(now);
    }

    pub fn reply(&mut self, bytes: Vec<u8>, now: Instant) {
        self.reply_with(bytes, Vec::new(), now);
    }

    /// The last reply of the stream: after what is queued for its pipes,
    /// which close; then the connection.
    pub fn finish(&mut self, bytes: Vec<u8>, now: Instant) {
        if self.gone || self.last.is_some() || self.close_when_flushed {
            return;
        }
        self.last = Some(bytes);
        self.close_when_flushed = true;
        self.stream = false;
        self.advance(now);
    }

    /// Answer and hang up.
    pub fn refuse(&mut self, bytes: Vec<u8>, now: Instant) {
        self.reply(bytes, now);
        self.close_when_flushed = true;
        self.advance(now);
    }

    /// Bytes of a stream of the container for the client.  A client that
    /// holds more than `max_queue` bytes does not read: its output is
    /// dropped ([`drop_output`](Self::drop_output)).
    pub fn send_data(&mut self, stream: Stream, data: &[u8], max_queue: usize, now: Instant) {
        if self.gone || self.last.is_some() {
            return;
        }
        let sink = match stream {
            Stream::Stdout => self.out.as_mut(),
            Stream::Stderr => self.err.as_mut(),
        };
        let Some(sink) = sink else { return };
        if let Wrote::Broken = sink.push(data) {
            self.output_broken();
            return;
        }
        self.mark_queued(now);
        if self.queued() > max_queue {
            self.drop_output(now);
        }
    }

    /// The client closed its end of a stream of the output: an attach
    /// client is gone; the owner of an exec, whose streams went to someone
    /// else (a frontend), stays for the status of the command, which goes on
    /// without the reader of its output (as podman's), that output dropped.
    fn output_broken(&mut self) {
        if !matches!(self.kind, Kind::Exec) {
            self.gone = true;
            return;
        }
        self.out = None;
        self.err = None;
        // (what is left, the replies, has its own time to be read)
        self.stalled = None;
    }

    /// The client does not read the output it has: drop what is queued for
    /// it and end its streams (it reads what its pipes hold); the session
    /// goes on, its input too, and its last reply says that its output was
    /// dropped (unless that reply was made already).  False when it has no
    /// output waiting (it does not read its replies).
    pub fn drop_output(&mut self, now: Instant) -> bool {
        if self.gone || self.data_queued() == 0 {
            return false;
        }
        self.out = None;
        self.err = None;
        self.output_dropped = true;
        // (what is left, the replies, has its own time to be read)
        self.stalled = None;
        self.advance(now);
        true
    }

    /// Send what is queued, as far as the client takes it, and go on to the
    /// last reply and the end once that is all.
    pub fn advance(&mut self, now: Instant) {
        if self.gone {
            return;
        }
        let mut moved = false;
        let mut broken = false;
        for sink in [&mut self.out, &mut self.err].into_iter().flatten() {
            match sink.flush() {
                Ok(m) => moved |= m,
                Err(()) => {
                    broken = true;
                    break;
                }
            }
        }
        if broken {
            self.output_broken();
            if self.gone {
                return;
            }
        }
        if self.last.is_some() && self.data_queued() == 0 {
            // (the client reads its pipes to their end once it has this)
            self.out = None;
            self.err = None;
            self.input = None;
            if let Some(bytes) = self.last.take() {
                self.replies.push_back(Outgoing {
                    bytes,
                    sent: 0,
                    fds: Vec::new(),
                });
            }
        }
        match self.send_replies() {
            Ok(m) => moved |= m,
            Err(()) => {
                self.gone = true;
                return;
            }
        }
        if moved {
            self.stalled = Some(now);
        }
        self.mark_queued(now);
        if self.close_when_flushed && self.last.is_none() && self.queued() == 0 {
            self.closing.get_or_insert(now);
        }
    }

    fn send_replies(&mut self) -> Result<bool, ()> {
        let mut moved = false;
        while let Some(front) = self.replies.front_mut() {
            let fds: Vec<BorrowedFd<'_>> = front.fds.iter().map(|f| f.as_fd()).collect();
            let mut space = [std::mem::MaybeUninit::uninit();
                rustix::cmsg_space!(ScmRights(velarx_wire::varlink::MAX_FDS))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if front.sent == 0
                && !fds.is_empty()
                && !control.push(SendAncillaryMessage::ScmRights(&fds))
            {
                return Err(());
            }
            let r = net::sendmsg(
                &self.conn,
                &[io::IoSlice::new(&front.bytes[front.sent..])],
                &mut control,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            );
            drop(fds);
            match r {
                Ok(n) => {
                    moved = true;
                    front.sent += n;
                    // (the descriptors went with the first bytes)
                    front.fds.clear();
                    if front.sent == front.bytes.len() {
                        self.replies.pop_front();
                    }
                }
                Err(rustix::io::Errno::AGAIN) | Err(rustix::io::Errno::INTR) => break,
                Err(_) => return Err(()),
            }
        }
        Ok(moved)
    }

    /// Read what the client sent: the messages it ended, and whether it
    /// hung up.  A message longer than [`MAX_CALL`] ends the connection.
    pub fn read_calls(&mut self) -> (Vec<Vec<u8>>, bool) {
        let mut buf = [0u8; 16 * 1024];
        let mut hung_up = false;
        // (a few reads per turn: the other descriptors wait too)
        for _ in 0..4 {
            let mut got = velarx_sys::scm::recv(&self.conn, &mut buf, MAX_FDS, RecvFlags::DONTWAIT);
            if let Ok(r) = &mut got {
                // (what a client that is closing sends is not wanted)
                if self.closing.is_none() && self.received.len() < 4 * MAX_FDS {
                    self.received.append(&mut r.fds);
                }
            }
            match got {
                Ok(r) if r.bytes == 0 => {
                    hung_up = true;
                    break;
                }
                Ok(r) => {
                    if self.closing.is_none() {
                        self.inbuf.extend_from_slice(&buf[..r.bytes]);
                    }
                    if r.bytes < buf.len() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // (more descriptors than a message may carry: the client
                // is not one of ours)
                Err(_) => {
                    hung_up = true;
                    break;
                }
            }
        }
        let mut calls = Vec::new();
        while let Some(end) = self.inbuf.iter().position(|&b| b == 0) {
            // (the limit holds for a call that ends in the same turn as the
            // bytes that make it too long, too)
            if end > MAX_CALL {
                break;
            }
            let rest = self.inbuf.split_off(end + 1);
            let mut call = std::mem::replace(&mut self.inbuf, rest);
            call.pop();
            calls.push(call);
        }
        if self.inbuf.len() > MAX_CALL {
            self.inbuf.clear();
            self.gone = true;
        }
        (calls, hung_up)
    }

    /// The descriptors that came with the calls read so far.
    pub fn take_received(&mut self) -> Vec<OwnedFd> {
        std::mem::take(&mut self.received)
    }

    /// The descriptors to wait on for writing.
    pub fn write_fds(&self) -> Vec<BorrowedFd<'_>> {
        let mut v = Vec::new();
        if self.replies_pending() {
            v.push(self.conn.as_fd());
        }
        for s in [&self.out, &self.err].into_iter().flatten() {
            if s.pending() {
                v.push(s.fd.as_fd());
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn client() -> (Client, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        (Client::new(1, OwnedFd::from(a), Instant::now()), b)
    }

    #[test]
    fn calls_are_split_at_their_nul_and_a_long_one_ends_the_client() {
        use std::io::Write;
        let (mut c, mut peer) = client();
        // (a copy of the peer held elsewhere, as by a child between fork and
        // exec, must not keep the end from coming)
        let _held = peer.try_clone().unwrap();
        peer.write_all(b"{\"method\":\"a\"}\0{\"method\"").unwrap();
        let (calls, hung_up) = c.read_calls();
        assert_eq!(calls, vec![b"{\"method\":\"a\"}".to_vec()]);
        assert!(!hung_up);
        peer.write_all(b":\"b\"}\0").unwrap();
        assert_eq!(c.read_calls().0, vec![b"{\"method\":\"b\"}".to_vec()]);
        // The end is the peer shutting down its sending side: closing it would
        // wait for every copy of the descriptor.
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(c.read_calls().1);

        // A call longer than the limit ends the client, however the bytes are
        // spread over the reads: write and read in turn on this thread.
        let (mut c, mut peer) = client();
        peer.set_nonblocking(true).unwrap();
        let big = vec![b' '; MAX_CALL + 1];
        let mut sent = 0;
        for _ in 0..1000 {
            if c.gone {
                break;
            }
            match peer.write(&big[sent..]) {
                Ok(n) => sent += n,
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
            }
            let _ = c.read_calls();
        }
        assert!(c.gone);
    }

    /// Send `stream` to a new client in pieces of the given sizes, reading
    /// after each piece: the calls read and whether the client went.
    fn send_in_pieces(stream: &[u8], mut sizes: impl FnMut() -> usize) -> (Vec<Vec<u8>>, bool) {
        use std::io::Write;
        let (mut c, mut peer) = client();
        peer.set_nonblocking(true).unwrap();
        let mut calls: Vec<Vec<u8>> = Vec::new();
        let mut at = 0;
        // (every turn writes or reads at least a byte: the bound is only an
        // upper limit)
        for _ in 0..2 * stream.len() + 2 {
            let read = calls.iter().map(|c| c.len() + 1).sum::<usize>() + c.inbuf.len();
            if c.gone || read == stream.len() {
                break;
            }
            if at < stream.len() {
                let end = stream.len().min(at + sizes().max(1));
                match peer.write(&stream[at..end]) {
                    Ok(n) => at += n,
                    Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
                }
            }
            calls.extend(c.read_calls().0);
        }
        (calls, c.gone)
    }

    /// The calls come out the same however the stream is split over the
    /// reads, and a call longer than the limit ends the client however its
    /// bytes arrive (also in one piece with its end).
    #[test]
    fn calls_do_not_depend_on_how_the_stream_is_split() {
        // (a fixed pseudo-random sequence: the same cases on every run)
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |below: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % below as u64) as usize
        };
        for _ in 0..50 {
            let want: Vec<Vec<u8>> = (0..next(8))
                .map(|i| vec![b'a' + i as u8; next(300)])
                .collect();
            let stream: Vec<u8> = want.iter().flat_map(|c| [&c[..], b"\0"].concat()).collect();
            let piece = 1 + next(100);
            let (calls, gone) = send_in_pieces(&stream, || next(piece));
            assert_eq!(calls, want);
            assert!(!gone);
        }

        let mut at_limit = vec![b' '; MAX_CALL];
        at_limit.push(0);
        let (calls, gone) = send_in_pieces(&at_limit, || 64 * 1024);
        assert_eq!(calls, vec![vec![b' '; MAX_CALL]]);
        assert!(!gone);

        // a call at the limit is read, then its last byte and its end come
        // in one read
        use std::io::Write;
        let (mut c, mut peer) = client();
        peer.set_nonblocking(true).unwrap();
        let start = vec![b' '; MAX_CALL];
        let mut at = 0;
        for _ in 0..1000 {
            if c.inbuf.len() == MAX_CALL {
                break;
            }
            match peer.write(&start[at..]) {
                Ok(n) => at += n,
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
            }
            assert!(c.read_calls().0.is_empty());
        }
        assert_eq!(c.inbuf.len(), MAX_CALL);
        assert!(!c.gone);
        peer.write_all(b" \0{}\0").unwrap();
        assert!(c.read_calls().0.is_empty());
        assert!(c.gone);
    }

    /// The descriptors that come with a call are kept for it, and only those
    /// of one call (they go with the first bytes).
    #[test]
    fn descriptors_that_come_with_a_call_are_kept() {
        use std::os::fd::AsFd;
        let (mut c, peer) = client();
        let f = std::fs::File::open("/dev/null").unwrap();
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fds = [f.as_fd(), f.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        rustix::net::sendmsg(
            &peer,
            &[io::IoSlice::new(b"{\"method\":\"a\"}\0")],
            &mut control,
            SendFlags::empty(),
        )
        .unwrap();
        let (calls, _) = c.read_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(c.take_received().len(), 2);
        assert!(c.take_received().is_empty());
    }

    /// The last reply of a stream comes after the bytes of its pipes, which
    /// are closed by then.
    #[test]
    fn the_last_reply_follows_the_streams() {
        use std::io::Read;
        let (mut c, mut peer) = client();
        let pipes = Pipes::new(false, true, false).unwrap();
        assert_eq!(pipes.positions, [None, Some(0), None]);
        let mut theirs = pipes.theirs.into_iter();
        let mut out = std::fs::File::from(theirs.next().unwrap());
        c.set_pipes(pipes.out, pipes.err, pipes.input);
        let now = Instant::now();
        // more than the pipe takes: some of it is queued
        let data = vec![7u8; 8 * STREAM_BUFFER];
        c.send_data(Stream::Stdout, &data, usize::MAX, now);
        assert!(c.data_queued() > 0);
        c.finish(b"last\0".to_vec(), now);
        // nothing on the connection while the pipe is not written out
        peer.set_nonblocking(true).unwrap();
        let mut b = [0u8; 16];
        assert!(peer.read(&mut b).is_err());
        let mut got = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            c.advance(now);
            match out.read(&mut chunk).unwrap() {
                0 => break,
                n => got.extend_from_slice(&chunk[..n]),
            }
        }
        assert_eq!(got.len(), data.len());
        peer.set_nonblocking(false).unwrap();
        let n = peer.read(&mut b).unwrap();
        assert_eq!(&b[..n], b"last\0");
        assert!(c.closing.is_some());
    }

    /// A client that does not read its output loses what is queued for
    /// it: its pipes end, the session goes on to its last reply.
    #[test]
    fn a_client_that_does_not_read_its_output_loses_it() {
        use std::io::Read;
        let (mut c, mut peer) = client();
        let pipes = Pipes::new(false, true, false).unwrap();
        let mut theirs = pipes.theirs.into_iter();
        let mut out = std::fs::File::from(theirs.next().unwrap());
        c.set_pipes(pipes.out, pipes.err, pipes.input);
        let now = Instant::now();
        let data = vec![7u8; 64 * 1024];
        while !c.output_dropped && !c.gone {
            c.send_data(Stream::Stdout, &data, 1024 * 1024, now);
        }
        assert!(!c.gone && c.closing.is_none());
        assert_eq!(c.data_queued(), 0);
        // (what the pipe took is still there, then the end)
        let mut got = Vec::new();
        out.read_to_end(&mut got).unwrap();
        assert!(got.len() <= 1024 * 1024);
        // more output is not queued; the last reply comes as ever
        c.send_data(Stream::Stdout, &data, 1024 * 1024, now);
        assert_eq!(c.data_queued(), 0);
        c.finish(b"last\0".to_vec(), now);
        peer.set_nonblocking(false).unwrap();
        let mut b = [0u8; 16];
        let n = peer.read(&mut b).unwrap();
        assert_eq!(&b[..n], b"last\0");
        assert!(c.closing.is_some());
    }

    /// A client that calls and does not read its replies is not read
    /// any more once they pile up.
    #[test]
    fn the_calls_of_a_client_that_does_not_read_wait() {
        let (mut c, _peer) = client();
        let now = Instant::now();
        assert!(c.wants_calls());
        while c.queued() < MAX_REPLY_QUEUE {
            c.reply(vec![b'x'; 16 * 1024], now);
        }
        assert!(!c.wants_calls());
    }

    /// A reply carries its descriptors.
    #[test]
    fn a_reply_carries_its_descriptors() {
        let (mut c, peer) = client();
        let file = tempfile::tempfile().unwrap();
        c.reply_with(
            b"{\"parameters\":{}}\0".to_vec(),
            vec![OwnedFd::from(file)],
            Instant::now(),
        );
        let mut conn = velarx_wire::varlink::Conn::from_stream(peer);
        conn.set_deadline(Instant::now() + std::time::Duration::from_secs(5));
        conn.reply::<serde_json::Value>().unwrap();
        assert_eq!(conn.take_fds().len(), 1);
    }
}
